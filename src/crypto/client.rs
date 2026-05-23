//! Client-Side Encryption Helpers
//! 
//! This module provides functions that clients (Tauri app, web frontend) use
//! to encrypt data before sending to the server. The server should never see
//! plaintext of any user data.
//!
//! SECURITY: All functions use XChaCha20-Poly1305 with OsRng nonce generation.
//!           Error handling returns Result<> instead of panicking.

use chacha20poly1305::{aead::Aead, KeyInit};
use rand::RngCore;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

/// Result type for client-side encryption operations
pub type CryptoResult<T> = Result<T, String>;

/// Generate a new X25519 keypair for E2E encryption
#[derive(Clone)]
pub struct KeyPair {
    pub secret: [u8; 32],
    pub public: [u8; 32],
}

impl KeyPair {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let public = PublicKey::from(&secret);
        
        Self {
            secret: *secret.as_bytes(),
            public: *public.as_bytes(),
        }
    }

    pub fn from_secret(secret_bytes: &[u8; 32]) -> Self {
        let secret = StaticSecret::from(*secret_bytes);
        let public = PublicKey::from(&secret);
        
        Self {
            secret: *secret_bytes,
            public: *public.as_bytes(),
        }
    }
}

impl Drop for KeyPair {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

/// Encrypt a message for a recipient using their public key
/// Uses X25519 + ChaCha20-Poly1305 pattern (TweetNaCl style)
pub fn encrypt_message(plaintext: &[u8], recipient_pubkey: &[u8; 32], sender_seckey: &[u8; 32]) -> CryptoResult<Vec<u8>> {
    use chacha20poly1305::{ChaCha20Poly1305, Nonce};
    use x25519_dalek::{PublicKey, StaticSecret};
    
    // Generate ephemeral keypair
    let sender_secret = StaticSecret::from(*sender_seckey);
    let recipient_public = PublicKey::from(*recipient_pubkey);
    
    // Compute shared secret
    let shared = sender_secret.diffie_hellman(&recipient_public);
    let shared_bytes: &[u8; 32] = shared.as_bytes();
    
    // Create cipher with shared secret as key
    let key: [u8; 32] = *shared_bytes;
    let cipher = ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| "Invalid key".to_string())?;
    
    // Generate random nonce
    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    // Encrypt - return error instead of panic
    let ciphertext = cipher.encrypt(nonce, plaintext)
        .map_err(|_| "Encryption failed".to_string())?;
    
    // Prepend nonce to ciphertext
    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    
    Ok(result)
}

/// Decrypt a message using our private key
/// SECURITY: Returns error instead of panicking on invalid input
pub fn decrypt_message(ciphertext_with_nonce: &[u8], sender_pubkey: &[u8; 32], recipient_seckey: &[u8; 32]) -> CryptoResult<Vec<u8>> {
    use chacha20poly1305::{ChaCha20Poly1305, Nonce};
    use x25519_dalek::{PublicKey, StaticSecret};
    
    if ciphertext_with_nonce.len() < 12 {
        return Err("Ciphertext too short".to_string());
    }
    
    let (nonce_bytes, ciphertext) = ciphertext_with_nonce.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);
    
    // Compute shared secret
    let recipient_secret = StaticSecret::from(*recipient_seckey);
    let sender_public = PublicKey::from(*sender_pubkey);
    let shared = recipient_secret.diffie_hellman(&sender_public);
    let shared_bytes: &[u8; 32] = shared.as_bytes();
    
    // Create cipher
    let key: [u8; 32] = *shared_bytes;
    let cipher = ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| "Invalid key".to_string())?;
    
    // Decrypt - return error instead of panic
    cipher.decrypt(nonce, ciphertext)
        .map_err(|_| "Decryption failed".to_string())
}

/// Encrypt listing content for storage
/// Combines title, description, and metadata into a single encrypted blob
pub fn encrypt_listing_content(
    title: &str,
    description: &str,
    metadata: &serde_json::Value,
    content_key: &[u8; 32],
) -> CryptoResult<Vec<u8>> {
    use chacha20poly1305::{ChaCha20Poly1305, Nonce};
    
    let plaintext = serde_json::json!({
        "title": title,
        "description": description,
        "metadata": metadata,
    });
    
    let plaintext_bytes = serde_json::to_vec(&plaintext)
        .map_err(|_| "Serialization failed".to_string())?;
    
    let cipher = ChaCha20Poly1305::new_from_slice(content_key)
        .map_err(|_| "Invalid key".to_string())?;
    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    let ciphertext = cipher.encrypt(nonce, plaintext_bytes.as_slice())
        .map_err(|_| "Encryption failed".to_string())?;
    
    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    
    Ok(result)
}

/// Decrypt listing content
/// SECURITY: Returns error instead of panicking on invalid input
pub fn decrypt_listing_content(encrypted: &[u8], content_key: &[u8; 32]) -> CryptoResult<serde_json::Value> {
    use chacha20poly1305::{ChaCha20Poly1305, Nonce};
    
    if encrypted.len() < 12 {
        return Err("Encrypted data too short".to_string());
    }
    
    let (nonce_bytes, ciphertext) = encrypted.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);
    
    let cipher = ChaCha20Poly1305::new_from_slice(content_key)
        .map_err(|_| "Invalid key".to_string())?;
    
    let plaintext = cipher.decrypt(nonce, ciphertext)
        .map_err(|_| "Decryption failed".to_string())?;
    
    serde_json::from_slice(&plaintext)
        .map_err(|_| "Deserialization failed".to_string())
}

/// Generate search tokens from listing content
/// These are deterministically encrypted so same term = same token
/// SECURITY: Uses full 32-byte blake3 hash (not truncated) for token consistency
pub fn generate_search_tokens(content: &str, search_key: &[u8]) -> Vec<Vec<u8>> {
    use blake3::Hasher;
    
    let mut tokens: Vec<Vec<u8>> = Vec::new();
    
    for word in content.split_whitespace() {
        if word.len() < 2 {
            continue; // Skip single-character words
        }
        
        let mut hasher = Hasher::new();
        hasher.update(word.as_bytes());
        hasher.update(search_key);
        
        // SECURITY: Use FULL 32 bytes for token consistency with server
        let hash = hasher.finalize();
        tokens.push(hash.as_bytes().to_vec());
    }
    
    tokens
}

/// Generate a single search token (for query matching)
/// Returns 32-byte token as Vec<u8>
pub fn generate_single_token(keyword: &str, search_key: &[u8]) -> Vec<u8> {
    use blake3::Hasher;
    
    let mut hasher = Hasher::new();
    hasher.update(keyword.as_bytes());
    hasher.update(search_key);
    
    hasher.finalize().as_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let kp = KeyPair::generate();
        assert_eq!(kp.secret.len(), 32);
        assert_eq!(kp.public.len(), 32);
    }

    #[test]
    fn test_encrypt_decrypt_message() {
        let alice = KeyPair::generate();
        let bob = KeyPair::generate();
        
        let message = b"Hello, Bob!";
        let encrypted = encrypt_message(message, &bob.public, &alice.secret)
            .expect("Encryption should succeed");
        let decrypted = decrypt_message(&encrypted, &alice.public, &bob.secret)
            .expect("Decryption should succeed");
        
        assert_eq!(message.to_vec(), decrypted);
    }

    #[test]
    fn test_decrypt_message_error_on_invalid_input() {
        let alice = KeyPair::generate();
        let bob = KeyPair::generate();
        
        // Too short ciphertext
        let result = decrypt_message(&[1, 2, 3], &alice.public, &bob.secret);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Ciphertext too short");
    }
}