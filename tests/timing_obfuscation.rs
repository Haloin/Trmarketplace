#[cfg(test)]
mod tests {
    use tor_marketplace::crypto::hmac_auth;
    use tor_marketplace::crypto::zk;
    
    use tor_marketplace::gateway::ratelimit::RateLimiter;

    #[test]
    fn test_constant_time_auth_token_verification_different_lengths() {
        let auth_key = b"test-auth-key-32-bytes-long-constant-time";
        let pubkey = b"pubkey-for-ct-test-32bytes-long!!!";
        let bucket = 50000u64;

        let token = hmac_auth::generate_auth_token(auth_key, pubkey, bucket, "/api/orders").unwrap();
        let result = hmac_auth::verify_auth_token(auth_key, &token, pubkey, bucket, "/api/orders");
        assert!(result);

        // Wrong length token should not panic
        let short_token = &token[..15];
        let result_short = hmac_auth::verify_auth_token(auth_key, short_token, pubkey, bucket, "/api/orders");
        assert!(!result_short);

        // Too long token should not panic
        let mut long_token = token.clone();
        long_token.push(0x00);
        let result_long = hmac_auth::verify_auth_token(auth_key, &long_token, pubkey, bucket, "/api/orders");
        assert!(!result_long);
    }

    #[test]
    fn test_auth_token_verify_wrong_path_constant_time() {
        let auth_key = b"test-auth-key-32-bytes-long-constant-time";
        let pubkey = b"pubkey-for-ct-path-test-32bytes!!";
        let bucket = 60000u64;

        let token = hmac_auth::generate_auth_token(auth_key, pubkey, bucket, "/api/orders").unwrap();
        let paths = ["/api/listings", "/api/admin", "/api/chat", "/api/disputes", "/api/settings"];

        for path in &paths {
            let result = hmac_auth::verify_auth_token(auth_key, &token, pubkey, bucket, path);
            assert!(!result, "Path {} must fail verification", path);
        }
    }

    #[tokio::test]
    async fn test_rate_limiter_window_boundary_consistent() {
        let limiter = RateLimiter::new(5, 2);

        // Exhaust the bucket
        for _ in 0..5 {
            assert!(limiter.check("user_window_boundary").await);
        }
        assert!(!limiter.check("user_window_boundary").await);

        // Wait for window to partially pass
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        assert!(!limiter.check("user_window_boundary").await,
            "Should still be blocked before window fully resets");
    }

    #[tokio::test]
    async fn test_rate_limiter_window_reset_at_boundary() {
        let limiter = RateLimiter::new(3, 1);

        for _ in 0..3 {
            assert!(limiter.check("user_reset_test").await);
        }
        assert!(!limiter.check("user_reset_test").await);

        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        assert!(limiter.check("user_reset_test").await, "Should reset after window expiry");
    }

    #[tokio::test]
    async fn test_rate_limiter_independent_buckets() {
        let limiter = RateLimiter::new(3, 60);

        for i in 0..3 {
            assert!(limiter.check("user_a").await, "User A request {} should pass", i);
        }
        assert!(!limiter.check("user_a").await, "User A should be blocked");

        for i in 0..3 {
            assert!(limiter.check("user_b").await, "User B request {} should pass", i);
        }
        assert!(!limiter.check("user_b").await, "User B should be blocked");
    }

    #[test]
    fn test_hour_bucket_consistency() {
        let ts = 1234567890i64;
        let bucket1 = hmac_auth::compute_hour_bucket(ts);
        let bucket2 = hmac_auth::compute_hour_bucket(ts);
        assert_eq!(bucket1, bucket2);
    }

    #[test]
    fn test_hour_bucket_boundaries() {
        assert_eq!(hmac_auth::compute_hour_bucket(0), 0);
        assert_eq!(hmac_auth::compute_hour_bucket(3599), 0);
        assert_eq!(hmac_auth::compute_hour_bucket(3600), 1);
        assert_eq!(hmac_auth::compute_hour_bucket(7199), 1);
        assert_eq!(hmac_auth::compute_hour_bucket(7200), 2);
        assert_eq!(hmac_auth::compute_hour_bucket(-1), 0);
        assert_eq!(hmac_auth::compute_hour_bucket(-3600), 0);
    }

    #[test]
    fn test_signature_deterministic_same_input() {
        

        let (sk, pk) = hmac_auth::generate_ephemeral_keypair();
        let challenge = b"deterministic-challenge-for-testing";

        let sig1 = hmac_auth::sign_challenge(&sk, challenge);
        let sig2 = hmac_auth::sign_challenge(&sk, challenge);

        assert_eq!(sig1, sig2, "Ed25519 must produce deterministic signatures for same input");
        assert!(hmac_auth::verify_challenge(&pk, challenge, &sig1));
    }

    #[test]
    fn test_encryption_key_generation_unique() {
        let kek1 = zk::KeyEncryptionKey::new();
        let kek2 = zk::KeyEncryptionKey::new();
        let kek3 = zk::KeyEncryptionKey::new();

        let pt = b"test-plaintext";
        let ct1 = zk::encrypt_test(pt, &kek1).unwrap();
        let ct2 = zk::encrypt_test(pt, &kek2).unwrap();
        let ct3 = zk::encrypt_test(pt, &kek3).unwrap();

        assert_ne!(ct1, ct2, "Different keys must produce different ciphertexts");
        assert_ne!(ct1, ct3, "Different keys must produce different ciphertexts");
        assert_ne!(ct2, ct3, "Different keys must produce different ciphertexts");
    }
}
