use anyhow::{anyhow, Result};
use rand::RngCore;

use super::zk::{KeyEncryptionKey, EncryptedBlob};

const MASTER_SEED_SIZE: usize = 32;

/// Generate a new master seed for owner BTC multi-sig key derivation.
/// Should be stored encrypted with KEK in config.
pub fn generate_master_seed() -> [u8; MASTER_SEED_SIZE] {
    let mut seed = [0u8; MASTER_SEED_SIZE];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    seed
}

/// Derive a deterministic per-order secp256k1 private key from the master seed and order ID.
/// Uses HMAC-SHA256(master_seed, "order:" || order_id) for key separation.
/// The resulting secret key is zeroized on drop.
pub fn derive_order_key(master_seed: &[u8; MASTER_SEED_SIZE], order_id: &[u8]) -> Result<secp256k1::SecretKey> {
    use hmac::Mac;
    let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(master_seed)
        .map_err(|_| anyhow!("HMAC init failed"))?;
    mac.update(b"order:");
    mac.update(order_id);
    let result = mac.finalize().into_bytes();
    secp256k1::SecretKey::from_slice(&result)
        .map_err(|e| anyhow!("Invalid derived key: {}", e))
}

/// Derive a domain-specific 32-byte key from the master seed.
///
/// Uses HMAC-SHA256(seed, "domain:" || domain) for key separation.
/// Each domain (auth, orders, chat, disputes) gets an independent key
/// so that compromise of one domain key does not affect others.
pub fn derive_domain_key(seed: &[u8; MASTER_SEED_SIZE], domain: &str) -> [u8; 32] {
    use hmac::Mac;
    let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(seed)
        .expect("HMAC key length is valid for SHA-256");
    mac.update(b"domain:");
    mac.update(domain.as_bytes());
    let result = mac.finalize().into_bytes();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

/// Get the secp256k1 public key corresponding to a private key.
pub fn order_public_key(sk: &secp256k1::SecretKey) -> secp256k1::PublicKey {
    let secp = secp256k1::Secp256k1::signing_only();
    secp256k1::PublicKey::from_secret_key(&secp, sk)
}

/// Encrypt an owner's secp256k1 private key with the KEK for storage.
/// Returns serialized encrypted blob bytes.
pub fn encrypt_owner_key(sk: &secp256k1::SecretKey, kek: &KeyEncryptionKey) -> Result<Vec<u8>> {
    let blob = EncryptedBlob::encrypt(&sk[..], kek)?;
    serde_json::to_vec(&blob).map_err(|e| anyhow!("Serialize failed: {}", e))
}

/// Decrypt an owner's secp256k1 private key from KEK-encrypted storage.
pub fn decrypt_owner_key(encrypted: &[u8], kek: &KeyEncryptionKey) -> Result<secp256k1::SecretKey> {
    let blob: EncryptedBlob = serde_json::from_slice(encrypted)
        .map_err(|e| anyhow!("Deserialize failed: {}", e))?;
    let plaintext = blob.decrypt(kek)?;
    secp256k1::SecretKey::from_slice(&plaintext)
        .map_err(|e| anyhow!("Invalid key: {}", e))
}

/// Encrypt the master seed with KEK and return a hex-encoded string suitable
/// for storing in the config file (TOML).
pub fn encrypt_master_seed(seed: &[u8; 32], kek: &KeyEncryptionKey) -> Result<String> {
    let blob = EncryptedBlob::encrypt(&seed[..], kek)
        .map_err(|e| anyhow!("Master seed encrypt failed: {}", e))?;
    let json = serde_json::to_vec(&blob)
        .map_err(|e| anyhow!("Serialize failed: {}", e))?;
    Ok(hex::encode(json))
}

/// Decrypt a hex-encoded master seed (previously encrypted with KEK).
pub fn decrypt_master_seed(hex_str: &str, kek: &KeyEncryptionKey) -> Result<[u8; 32]> {
    let data = hex::decode(hex_str)
        .map_err(|e| anyhow!("Master seed hex decode failed: {}", e))?;
    let blob: EncryptedBlob = serde_json::from_slice(&data)
        .map_err(|e| anyhow!("Deserialize master seed failed: {}", e))?;
    let plaintext = blob.decrypt(kek)?;
    if plaintext.len() != 32 {
        return Err(anyhow!("Master seed wrong length: {}", plaintext.len()));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&plaintext);
    Ok(seed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_master_seed_generation() {
        let seed = generate_master_seed();
        assert_eq!(seed.len(), 32);
        // Ensure it's not all zeros
        assert!(seed.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_derive_order_key_deterministic() {
        let seed = generate_master_seed();
        let order_id = b"test-order-123";
        let key1 = derive_order_key(&seed, order_id).unwrap();
        let key2 = derive_order_key(&seed, order_id).unwrap();
        assert_eq!(key1[..], key2[..]);
    }

    #[test]
    fn test_different_orders_different_keys() {
        let seed = generate_master_seed();
        let key1 = derive_order_key(&seed, b"order-1").unwrap();
        let key2 = derive_order_key(&seed, b"order-2").unwrap();
        assert_ne!(key1[..], key2[..]);
    }

    #[test]
    fn test_public_key_derivation() {
        let seed = generate_master_seed();
        let sk = derive_order_key(&seed, b"test").unwrap();
        let pk = order_public_key(&sk);
        // Verify the public key is valid by checking its serialization
        let serialized = pk.serialize();
        assert_eq!(serialized.len(), 33); // compressed
    }

    #[test]
    fn test_encrypt_decrypt_owner_key() {
        let kek = KeyEncryptionKey::new();
        let seed = generate_master_seed();
        let sk = derive_order_key(&seed, b"test-key").unwrap();
        let original_bytes: Vec<u8> = sk[..].to_vec();

        let encrypted = encrypt_owner_key(&sk, &kek).unwrap();
        let decrypted = decrypt_owner_key(&encrypted, &kek).unwrap();
        let decrypted_bytes: Vec<u8> = decrypted[..].to_vec();

        assert_eq!(original_bytes, decrypted_bytes);
    }

    #[test]
    fn test_decrypt_wrong_kek_fails() {
        let kek1 = KeyEncryptionKey::new();
        let kek2 = KeyEncryptionKey::new();
        let seed = generate_master_seed();
        let sk = derive_order_key(&seed, b"test").unwrap();

        let encrypted = encrypt_owner_key(&sk, &kek1).unwrap();
        assert!(decrypt_owner_key(&encrypted, &kek2).is_err());
    }

    #[test]
    fn test_encrypt_decrypt_master_seed() {
        let kek = KeyEncryptionKey::new();
        let seed = generate_master_seed();

        let encrypted = encrypt_master_seed(&seed, &kek).unwrap();
        let decrypted = decrypt_master_seed(&encrypted, &kek).unwrap();

        assert_eq!(seed, decrypted);
    }

    #[test]
    fn test_decrypt_master_seed_wrong_kek_fails() {
        let kek1 = KeyEncryptionKey::new();
        let kek2 = KeyEncryptionKey::new();
        let seed = generate_master_seed();

        let encrypted = encrypt_master_seed(&seed, &kek1).unwrap();
        assert!(decrypt_master_seed(&encrypted, &kek2).is_err());
    }

    #[test]
    fn test_derive_domain_key_deterministic() {
        let seed = generate_master_seed();
        let k1 = derive_domain_key(&seed, "auth");
        let k2 = derive_domain_key(&seed, "auth");
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_derive_domain_key_different_domains_differ() {
        let seed = generate_master_seed();
        let auth_key = derive_domain_key(&seed, "auth");
        let orders_key = derive_domain_key(&seed, "orders");
        assert_ne!(auth_key, orders_key);
    }

    #[test]
    fn test_derive_domain_key_different_seeds_differ() {
        let s1 = generate_master_seed();
        let s2 = generate_master_seed();
        let k1 = derive_domain_key(&s1, "chat");
        let k2 = derive_domain_key(&s2, "chat");
        assert_ne!(k1, k2);
    }

    #[test]
    fn test_encrypt_master_seed_output_format() {
        let kek = KeyEncryptionKey::new();
        let seed = generate_master_seed();

        let encrypted = encrypt_master_seed(&seed, &kek).unwrap();
        // Must be valid hex (for TOML config storage)
        assert!(hex::decode(&encrypted).is_ok());
        // Must not be empty
        assert!(!encrypted.is_empty());
    }
}
