#[cfg(test)]
mod tests {
    use tor_marketplace::crypto::zk;
    use tor_marketplace::crypto::hmac_auth;
    use tor_marketplace::gateway::ratelimit::RateLimiter;

    #[tokio::test]
    async fn test_rate_limiter_prevents_oracle_bruteforce() {
        let limiter = RateLimiter::new(5, 10);
        let key = "oracle_target_user";

        for _ in 0..5 {
            assert!(limiter.check(key).await);
        }
        // 6th attempt blocked — prevents brute-force oracle
        assert!(!limiter.check(key).await);
    }

    #[tokio::test]
    async fn test_rate_limiter_recovery_after_window() {
        let limiter = RateLimiter::new(2, 1);
        let key = "recovery_user";

        assert!(limiter.check(key).await);
        assert!(limiter.check(key).await);
        assert!(!limiter.check(key).await);

        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

        assert!(limiter.check(key).await, "Must recover after window reset");
    }

    #[test]
    fn test_decryption_failure_no_plaintext_leak() {
        let kek = zk::KeyEncryptionKey::new();
        let pt = b"sensitive-order-plaintext-12345";
        let mut ct = zk::encrypt_test(pt, &kek).unwrap();

        // Corrupt the ciphertext
        ct[12] ^= 0xFF;
        let result = zk::decrypt_test(&ct, &kek);
        assert!(result.is_err());

        // Error should not contain plaintext content
        let err_str = format!("{}", result.err().unwrap());
        assert!(!err_str.contains("sensitive"));
        assert!(!err_str.contains("order"));
        assert!(!err_str.contains("12345"));
    }

    #[test]
    fn test_invalid_signature_no_pubkey_leak() {
        let (sk, pk) = hmac_auth::generate_ephemeral_keypair();
        let challenge = b"test-challenge-for-signature-test";
        let valid_sig = hmac_auth::sign_challenge(&sk, challenge);

        assert!(hmac_auth::verify_challenge(&pk, challenge, &valid_sig));
        assert!(!hmac_auth::verify_challenge(&pk, b"wrong-challenge", &valid_sig));

        let mut tampered_sig = valid_sig.clone();
        tampered_sig[5] ^= 0x01;
        assert!(!hmac_auth::verify_challenge(&pk, challenge, &tampered_sig));

        assert!(!hmac_auth::verify_challenge(&pk, challenge, &[]));
    }

    #[test]
    fn test_verify_wrong_key_no_info_leak() {
        let (sk, pk) = hmac_auth::generate_ephemeral_keypair();
        let (_, wrong_pk) = hmac_auth::generate_ephemeral_keypair();
        let challenge = b"test-challenge-for-wrong-key-test";

        let sig = hmac_auth::sign_challenge(&sk, challenge);
        assert!(hmac_auth::verify_challenge(&pk, challenge, &sig));
        assert!(!hmac_auth::verify_challenge(&wrong_pk, challenge, &sig),
            "Wrong key must fail verification");
    }

    #[test]
    fn test_empty_inputs_handled_gracefully() {
        let kek = zk::KeyEncryptionKey::new();

        // Empty ciphertext
        assert!(zk::decrypt_test(&[], &kek).is_err());

        // Only nonce, no ciphertext
        assert!(zk::decrypt_test(&[0u8; 12], &kek).is_err());
        assert!(zk::decrypt_test(&[0u8; 24], &kek).is_err());

        // Garbage bytes
        assert!(zk::decrypt_test(&[0xFFu8; 128], &kek).is_err());
    }

    #[test]
    fn test_encrypt_empty_plaintext_succeeds() {
        let kek = zk::KeyEncryptionKey::new();
        let ct = zk::encrypt_test(b"", &kek).unwrap();
        assert!(!ct.is_empty(), "Encryption of empty plaintext must produce non-empty ciphertext (nonce+tag)");
        let pt = zk::decrypt_test(&ct, &kek).unwrap();
        assert_eq!(pt.len(), 0, "Decrypted empty plaintext must be empty");
    }

    #[test]
    fn test_large_plaintext_roundtrip() {
        let kek = zk::KeyEncryptionKey::new();
        let pt = vec![0xABu8; 65536];
        let ct = zk::encrypt_test(&pt, &kek).unwrap();
        let decrypted = zk::decrypt_test(&ct, &kek).unwrap();
        assert_eq!(decrypted, pt);
    }

    #[test]
    fn test_auth_token_wrong_hour_bucket_fails() {
        let auth_key = b"test-auth-key-oracle-attack-test-32";
        let pubkey = b"pubkey-for-hour-bucket-oracle-123";
        let correct_bucket = 1000u64;

        let token = hmac_auth::generate_auth_token(auth_key, pubkey, correct_bucket, "/api/orders").unwrap();

        // Different hour bucket must fail
        assert!(!hmac_auth::verify_auth_token(auth_key, &token, pubkey, 999, "/api/orders"));
        assert!(!hmac_auth::verify_auth_token(auth_key, &token, pubkey, 1001, "/api/orders"));

        // But correct bucket must still pass
        assert!(hmac_auth::verify_auth_token(auth_key, &token, pubkey, correct_bucket, "/api/orders"));
    }
}
