#[cfg(test)]
mod tests {
    use tor_marketplace::crypto::escrow;
    
    
    
    use tor_marketplace::crypto::client;
    use tor_marketplace::crypto::oblivious;
    use tor_marketplace::crypto::zk;

    // ── Encryption tampering (6 tests) ──

    #[test]
    fn test_tamper_first_byte_fails() {
        let kek = zk::KeyEncryptionKey::new();
        let pt = b"important-plaintext-data";
        let mut ct = zk::encrypt_test(pt, &kek).unwrap();
        ct[0] ^= 0xFF;
        assert!(zk::decrypt_test(&ct, &kek).is_err());
    }

    #[test]
    fn test_tamper_last_byte_fails() {
        let kek = zk::KeyEncryptionKey::new();
        let pt = b"important-plaintext-data";
        let mut ct = zk::encrypt_test(pt, &kek).unwrap();
        *ct.last_mut().unwrap() ^= 0x01;
        assert!(zk::decrypt_test(&ct, &kek).is_err());
    }

    #[test]
    fn test_tamper_middle_byte_fails() {
        let kek = zk::KeyEncryptionKey::new();
        let pt = b"important-plaintext-data";
        let mut ct = zk::encrypt_test(pt, &kek).unwrap();
        let mid = ct.len() / 2;
        ct[mid] ^= 0x80;
        assert!(zk::decrypt_test(&ct, &kek).is_err());
    }

    #[test]
    fn test_tamper_nonce_region_fails() {
        let kek = zk::KeyEncryptionKey::new();
        let pt = b"test-data";
        let mut ct = zk::encrypt_test(pt, &kek).unwrap();
        for i in 0..4.min(ct.len()) {
            ct[i] ^= 0xFF;
        }
        assert!(zk::decrypt_test(&ct, &kek).is_err());
    }

    #[test]
    fn test_truncated_ciphertext_fails() {
        let kek = zk::KeyEncryptionKey::new();
        let pt = b"data-that-will-be-truncated";
        let ct = zk::encrypt_test(pt, &kek).unwrap();
        if ct.len() > 10 {
            assert!(zk::decrypt_test(&ct[..ct.len()-5], &kek).is_err());
            assert!(zk::decrypt_test(&ct[..10], &kek).is_err());
        }
    }

    #[test]
    fn test_appended_bytes_fails() {
        let kek = zk::KeyEncryptionKey::new();
        let pt = b"data";
        let mut ct = zk::encrypt_test(pt, &kek).unwrap();
        ct.extend_from_slice(&[0xDE, 0xAD]);
        assert!(zk::decrypt_test(&ct, &kek).is_err());
    }

    // ── Wrong key / no key (4 tests) ──

    #[test]
    fn test_different_key_decryption_fails() {
        let kek1 = zk::KeyEncryptionKey::new();
        let kek2 = zk::KeyEncryptionKey::new();
        let pt = b"secret-for-one-key-only";
        let ct = zk::encrypt_test(pt, &kek1).unwrap();
        assert!(zk::decrypt_test(&ct, &kek2).is_err());
    }

    #[test]
    fn test_multiple_keys_no_cross_decrypt() {
        let keks: Vec<_> = (0..5).map(|_| zk::KeyEncryptionKey::new()).collect();
        let pt = b"cross-key-decryption-test";
        for (i, k1) in keks.iter().enumerate() {
            let ct = zk::encrypt_test(pt, k1).unwrap();
            for (j, k2) in keks.iter().enumerate() {
                if i == j {
                    assert_eq!(&zk::decrypt_test(&ct, k2).unwrap(), pt);
                } else {
                    assert!(zk::decrypt_test(&ct, k2).is_err(), "Key {} must not decrypt key {}'s ciphertext", j, i);
                }
            }
        }
    }

    #[test]
    fn test_empty_ciphertext_rejected() {
        let kek = zk::KeyEncryptionKey::new();
        assert!(zk::decrypt_test(&[], &kek).is_err());
    }

    #[test]
    fn test_garbage_ciphertext_rejected() {
        let kek = zk::KeyEncryptionKey::new();
        let garbage = vec![0xFFu8; 256];
        assert!(zk::decrypt_test(&garbage, &kek).is_err());
    }

    // ── Escrow crypto (4 tests) ──

    #[test]
    fn test_master_seed_encrypt_decrypt_roundtrip() {
        let master_seed = [0xABu8; 32];
        let kek = zk::KeyEncryptionKey::new();
        let encrypted = escrow::encrypt_master_seed(&master_seed, &kek).unwrap();
        let decrypted = escrow::decrypt_master_seed(&encrypted, &kek).unwrap();
        assert_eq!(decrypted, master_seed);
    }

    #[test]
    fn test_master_seed_wrong_kek_fails() {
        let master_seed = [0x42u8; 32];
        let kek1 = zk::KeyEncryptionKey::new();
        let kek2 = zk::KeyEncryptionKey::new();
        let encrypted = escrow::encrypt_master_seed(&master_seed, &kek1).unwrap();
        assert!(escrow::decrypt_master_seed(&encrypted, &kek2).is_err());
    }

    #[test]
    fn test_owner_key_encrypt_decrypt_roundtrip() {
        use secp256k1::rand::rngs::OsRng;
        let owner_key = secp256k1::SecretKey::new(&mut OsRng);
        let kek = zk::KeyEncryptionKey::new();
        let encrypted = escrow::encrypt_owner_key(&owner_key, &kek).unwrap();
        let decrypted = escrow::decrypt_owner_key(&encrypted, &kek).unwrap();
        assert_eq!(decrypted[..], owner_key[..]);
    }

    #[test]
    fn test_owner_key_wrong_kek_fails() {
        use secp256k1::rand::rngs::OsRng;
        let owner_key = secp256k1::SecretKey::new(&mut OsRng);
        let kek1 = zk::KeyEncryptionKey::new();
        let kek2 = zk::KeyEncryptionKey::new();
        let encrypted = escrow::encrypt_owner_key(&owner_key, &kek1).unwrap();
        assert!(escrow::decrypt_owner_key(&encrypted, &kek2).is_err());
    }

    // ── Oblivious crypto (3 tests) ──

    #[test]
    fn test_oblivious_order_encrypt_decrypt_roundtrip() {
        let secret = b"server-secret-for-oblivious-test-32bytes!";
        let order_id = b"test-order-id-12345";
        let pt = b"oblivious-order-data";

        let blob = oblivious::encrypt_order_blob(pt, secret, order_id).unwrap();
        let decrypted = oblivious::decrypt_order_blob(&blob, secret, order_id).unwrap();
        assert_eq!(&decrypted, pt);
    }

    #[test]
    fn test_oblivious_order_wrong_secret_fails() {
        let secret1 = b"correct-server-secret-32-bytes-long!!";
        let secret2 = b"wrong-server-secret---32-bytes-long!!";
        let order_id = b"order-id-for-wrong-secret-test";
        let pt = b"oblivious-data";

        let blob = oblivious::encrypt_order_blob(pt, secret1, order_id).unwrap();
        assert!(oblivious::decrypt_order_blob(&blob, secret2, order_id).is_none());
    }

    #[test]
    fn test_oblivious_order_wrong_id_fails() {
        let secret = b"server-secret-for-oblivious-wrong-id-";
        let order_id = b"correct-order-id-001";
        let wrong_id = b"wrong-order-id-002";
        let pt = b"data-tied-to-correct-order-id";

        let blob = oblivious::encrypt_order_blob(pt, secret, order_id).unwrap();
        assert!(oblivious::decrypt_order_blob(&blob, secret, wrong_id).is_none());
        assert_eq!(&oblivious::decrypt_order_blob(&blob, secret, order_id).unwrap(), pt);
    }

    // ── ZK / search tokens (2 tests) ──

    #[test]
    fn test_search_token_generation_consistent() {
        let search_key = b"test-search-key-32-bytes-long-for-test!!!";
        let token1 = zk::SearchToken::generate("test-keyword", search_key);
        let token2 = zk::SearchToken::generate("test-keyword", search_key);
        assert_eq!(token1.token, token2.token);
    }

    #[test]
    fn test_search_token_different_keywords_differ() {
        let search_key = b"test-search-key-32-bytes-long-for-test!!!";
        let t1 = zk::SearchToken::generate("keyword-one", search_key);
        let t2 = zk::SearchToken::generate("keyword-two", search_key);
        assert_ne!(t1.token, t2.token);
    }

    // ── Client crypto (1 test) ──

    #[test]
    fn test_client_keypair_encrypt_decrypt() {
        let alice = client::KeyPair::generate();
        let bob = client::KeyPair::generate();
        let msg = b"hello from alice to bob";

        let ct = client::encrypt_message(msg, &bob.public, &alice.secret).unwrap();
        let pt = client::decrypt_message(&ct, &alice.public, &bob.secret).unwrap();
        assert_eq!(&pt, msg);
    }
}
