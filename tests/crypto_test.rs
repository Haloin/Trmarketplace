#[cfg(test)]
mod tests {
    use tor_marketplace::crypto::encryption::EncryptionKey;
    use tor_marketplace::crypto::wallet::WalletVerifier;
    use tor_marketplace::crypto::hash;

    #[test]
    fn test_encryption_roundtrip() {
        let key = EncryptionKey::generate();
        let plaintext = b"Hello, marketplace! This is a secret message with some length to it.";
        let encrypted = key.encrypt(plaintext).unwrap();
        let decrypted = key.decrypt(&encrypted).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_encryption_large_payload() {
        let key = EncryptionKey::generate();
        let plaintext = vec![0xABu8; 10240]; // 10KB
        let encrypted = key.encrypt(&plaintext).unwrap();
        let decrypted = key.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encryption_empty() {
        let key = EncryptionKey::generate();
        let encrypted = key.encrypt(b"").unwrap();
        let decrypted = key.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted.len(), 0);
    }

    #[test]
    fn test_encryption_different_keys_fail() {
        let key1 = EncryptionKey::generate();
        let key2 = EncryptionKey::generate();
        let plaintext = b"Secret data";
        let encrypted = key1.encrypt(plaintext).unwrap();
        let result = key2.decrypt(&encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_encryption_tampered_ciphertext_fails() {
        let key = EncryptionKey::generate();
        let plaintext = b"Important message";
        let mut encrypted = key.encrypt(plaintext).unwrap();
        // Flip a bit in the ciphertext
        if let Some(byte) = encrypted.last_mut() {
            *byte ^= 0x01;
        }
        let result = key.decrypt(&encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_ed25519_sign_verify() {
        use ed25519_dalek::{Signer, SigningKey, SecretKey};
        use rand::rngs::OsRng;
        use rand::RngCore;

        let mut secret = [0u8; 32];
        OsRng.fill_bytes(&mut secret);
        let secret_key = SecretKey::from(secret);
        let signing_key = SigningKey::from_bytes(&secret_key);
        let verifying_key = signing_key.verifying_key();

        let message = b"test challenge message for authentication";
        let signature = signing_key.sign(message);

        let result = WalletVerifier::verify_ed25519(
            &verifying_key.to_bytes(),
            message,
            &signature.to_bytes(),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_ed25519_wrong_key_fails() {
        use ed25519_dalek::{Signer, SigningKey, SecretKey};
        use rand::rngs::OsRng;
        use rand::RngCore;

        let mut secret = [0u8; 32];
        OsRng.fill_bytes(&mut secret);
        let secret_key = SecretKey::from(secret);
        let signing_key = SigningKey::from_bytes(&secret_key);

        let mut wrong_secret = [0u8; 32];
        OsRng.fill_bytes(&mut wrong_secret);
        let wrong_secret_key = SecretKey::from(wrong_secret);
        let wrong_key = SigningKey::from_bytes(&wrong_secret_key);

        let message = b"test message";
        let signature = signing_key.sign(message);

        let result = WalletVerifier::verify_ed25519(
            &wrong_key.verifying_key().to_bytes(),
            message,
            &signature.to_bytes(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_ed25519_wrong_message_fails() {
        use ed25519_dalek::{Signer, SigningKey, SecretKey};
        use rand::rngs::OsRng;
        use rand::RngCore;

        let mut secret = [0u8; 32];
        OsRng.fill_bytes(&mut secret);
        let secret_key = SecretKey::from(secret);
        let signing_key = SigningKey::from_bytes(&secret_key);
        let verifying_key = signing_key.verifying_key();

        let message = b"real message";
        let wrong_message = b"fake message";
        let signature = signing_key.sign(message);

        let result = WalletVerifier::verify_ed25519(
            &verifying_key.to_bytes(),
            wrong_message,
            &signature.to_bytes(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_pubkey_hash_consistency() {
        let pubkey = b"test_public_key_bytes_32_bytes_long!";
        let hash1 = hash::hash_pubkey(pubkey);
        let hash2 = hash::hash_pubkey(pubkey);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_pubkey_hash_different_keys_differ() {
        let key1 = b"key1_public_key_bytes_32_bytes_long!!";
        let key2 = b"key2_public_key_bytes_32_bytes_long!!";
        let hash1 = hash::hash_pubkey(key1);
        let hash2 = hash::hash_pubkey(key2);
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_challenge_hash() {
        let challenge = b"random_challenge_bytes_here";
        let secret = b"server_secret";
        let hash1 = hash::hash_challenge(challenge, secret);
        let hash2 = hash::hash_challenge(challenge, secret);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_secp256k1_sign_verify() {
        use k256::ecdsa::{signature::Signer, Signature, SigningKey, VerifyingKey};
        use rand::rngs::OsRng;

        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = VerifyingKey::from(&signing_key);

        let message = b"Ethereum-style message for signing";
        let signature: Signature = signing_key.sign(message);

        let result = WalletVerifier::verify_secp256k1(
            &verifying_key.to_sec1_bytes(),
            message,
            &signature.to_vec(),
        );
        assert!(result.is_ok());
    }
}
