//! Zero-Knowledge Encryption Module
//! 
//! This module provides encryption for data that the server stores but cannot read.
//! All sensitive content is encrypted client-side, and the server only stores opaque blobs.

use serde::{Deserialize, Serialize};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand::{RngCore, rngs::OsRng};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;

/// Key Encryption Key (KEK) - used to encrypt user data at rest
/// This key should be rotated periodically and stored separately from the app
#[derive(Clone, zeroize::Zeroize)]
#[zeroize(drop)]
pub struct KeyEncryptionKey {
    key: [u8; 32],
}

impl KeyEncryptionKey {
    pub fn new() -> Self {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        Self { key }
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self { key: *bytes }
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.key
    }

    /// Derive a KEK from a password using PBKDF2
    /// Uses 600,000 iterations as recommended for high-security applications
    pub fn from_password(password: &str, salt: &[u8]) -> Self {
        let mut key = [0u8; 32];
        
        // Use battle-tested PBKDF2-HMAC-SHA256 with 600k iterations
        pbkdf2_hmac::<Sha256>(
            password.as_bytes(),
            salt,
            600_000,
            &mut key,
        );
        
        Self { key }
    }
}

impl Default for KeyEncryptionKey {
    fn default() -> Self {
        Self::new()
    }
}

/// Encrypted blob with metadata for zero-knowledge storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedBlob {
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; 12],
    pub version: u8,
}

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("Invalid key size")]
    InvalidKeySize,
    #[error("Encryption failed")]
    EncryptionFailed,
    #[error("Decryption failed")]
    DecryptionFailed,
}

impl EncryptedBlob {
    /// Encrypt data with the KEK
    pub fn encrypt(plaintext: &[u8], kek: &KeyEncryptionKey) -> Result<Self, CryptoError> {
        let cipher = ChaCha20Poly1305::new_from_slice(kek.as_bytes())
            .map_err(|_| CryptoError::InvalidKeySize)?;
        
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| CryptoError::EncryptionFailed)?;
        
        Ok(Self {
            ciphertext,
            nonce: nonce_bytes,
            version: 2,
        })
    }

    /// Decrypt data with the KEK
    pub fn decrypt(&self, kek: &KeyEncryptionKey) -> Result<Vec<u8>, CryptoError> {
        let cipher = ChaCha20Poly1305::new_from_slice(kek.as_bytes())
            .map_err(|_| CryptoError::InvalidKeySize)?;
        
        let nonce = Nonce::from_slice(&self.nonce);
        
        cipher
            .decrypt(nonce, self.ciphertext.as_ref())
            .map_err(|_| CryptoError::DecryptionFailed)
    }
}

/// Search token for encrypted search
/// Uses deterministic encryption so the same search term produces the same token
pub struct SearchToken {
    pub token: Vec<u8>,
}

impl SearchToken {
    /// Generate a deterministic search token from a keyword
    /// This allows searching without revealing the plaintext
    /// Note: The token itself is still encrypted/hashed so server can't reverse it
    pub fn generate(keyword: &str, search_key: &[u8]) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(keyword.as_bytes());
        hasher.update(search_key);
        
        Self {
            token: hasher.finalize().as_bytes().to_vec(),
        }
    }

    /// Generate multiple tokens from text (for listing titles, descriptions)
    pub fn generate_from_text(text: &str, search_key: &[u8]) -> Vec<Self> {
        text.split_whitespace()
            .map(|word| Self::generate(word, search_key))
            .collect()
    }
}

/// Client-side content encryption key (never sent to server)
/// This key is generated and stored by the client
#[derive(Clone, zeroize::Zeroize)]
#[zeroize(drop)]
pub struct ContentKey {
    key: [u8; 32],
}

impl ContentKey {
    pub fn new() -> Self {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        Self { key }
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self { key: *bytes }
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.key
    }
}

impl Default for ContentKey {
    fn default() -> Self {
        Self::new()
    }
}

/// Hash a public key for identification (never the full pubkey in logs)
pub fn hash_pubkey_for_id(pubkey: &[u8]) -> [u8; 32] {
    blake3::hash(pubkey).into()
}

/// Constant-time comparison for sensitive data
/// Uses subtle crate for timing-safe comparison
pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    
    // Use subtle's ConstantTimeEq for timing-safe comparison
    a.ct_eq(b).unwrap_u8() == 1
}

/// Floor a Unix timestamp to the nearest 6-hour bucket.
/// Prevents temporal correlation between events — all events within
/// a 6-hour window appear to happen at the same time.
pub fn floor_timestamp_6h(ts: i64) -> i64 {
    (ts / 21600) * 21600
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypted_blob() {
        let kek = KeyEncryptionKey::new();
        let plaintext = b"Hello, World!";
        
        let blob = EncryptedBlob::encrypt(plaintext, &kek).unwrap();
        let decrypted = blob.decrypt(&kek).unwrap();
        
        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_encrypted_blob_error_on_wrong_key() {
        let kek1 = KeyEncryptionKey::new();
        let kek2 = KeyEncryptionKey::new();
        let plaintext = b"Hello, World!";
        
        let blob = EncryptedBlob::encrypt(plaintext, &kek1).unwrap();
        // Decrypting with different key should fail
        let result = blob.decrypt(&kek2);
        assert!(result.is_err());
    }

    #[test]
    fn test_search_token() {
        let search_key = b"test-key-12345";
        
        let token1 = SearchToken::generate("electronics", search_key);
        let token2 = SearchToken::generate("electronics", search_key);
        
        // Same keyword + same key = same token
        assert_eq!(token1.token, token2.token);
        
        let token3 = SearchToken::generate("different", search_key);
        // Different keyword = different token
        assert_ne!(token1.token, token3.token);
    }

    #[test]
    fn test_constant_time_compare() {
        assert!(constant_time_compare(b"test", b"test"));
        assert!(!constant_time_compare(b"test", b"other"));
        assert!(!constant_time_compare(b"test", b"test longer"));
    }

    #[test]
    fn test_pbkdf2_key_derivation() {
        let password = "secure_password_123";
        let salt = b"unique_salt_for_this_key";
        
        let kek = KeyEncryptionKey::from_password(password, salt);
        
        // Same password + salt should produce same key
        let kek2 = KeyEncryptionKey::from_password(password, salt);
        assert_eq!(kek.as_bytes(), kek2.as_bytes());
        
        // Different salt should produce different key
        let kek3 = KeyEncryptionKey::from_password(password, b"different_salt");
        assert_ne!(kek.as_bytes(), kek3.as_bytes());
    }
}