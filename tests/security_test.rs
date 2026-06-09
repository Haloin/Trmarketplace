#[cfg(test)]
mod tests {
    use tor_marketplace::gateway::ratelimit::RateLimiter;

    #[tokio::test]
    async fn test_rate_limiter_allows_first_requests() {
        let limiter = RateLimiter::new(10, 60);
        for i in 0..5 {
            assert!(limiter.check("test_user").await, "Request {} should be allowed", i);
        }
    }

    #[tokio::test]
    async fn test_rate_limiter_blocks_after_limit() {
        let limiter = RateLimiter::new(3, 60);
        assert!(limiter.check("test_user").await);
        assert!(limiter.check("test_user").await);
        assert!(limiter.check("test_user").await);
        assert!(!limiter.check("test_user").await, "4th request should be blocked");
    }

    #[tokio::test]
    async fn test_rate_limiter_separate_buckets() {
        let limiter = RateLimiter::new(2, 60);
        assert!(limiter.check("user_a").await);
        assert!(limiter.check("user_a").await);
        assert!(!limiter.check("user_a").await);

        // Different user should not be affected
        assert!(limiter.check("user_b").await);
    }

    #[tokio::test]
    async fn test_rate_limiter_window_resets() {
        let limiter = RateLimiter::new(2, 1); // 1 second window
        assert!(limiter.check("test_user").await);
        assert!(limiter.check("test_user").await);
        assert!(!limiter.check("test_user").await);

        // Wait for window to reset
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        assert!(limiter.check("test_user").await, "Should reset after window");
    }

    #[test]
    fn test_encryption_tamper_resistance() {
        use tor_marketplace::crypto::zk;
        let kek = zk::KeyEncryptionKey::new();
        let plaintext = b"test data";
        let mut encrypted = zk::encrypt_test(plaintext, &kek).unwrap();
        encrypted[0] ^= 0xFF;
        assert!(zk::decrypt_test(&encrypted, &kek).is_err());
    }

    #[test]
    fn test_empty_encrypted_data_fails() {
        use tor_marketplace::crypto::zk;
        let kek = zk::KeyEncryptionKey::new();
        assert!(zk::decrypt_test(&[], &kek).is_err());
        assert!(zk::decrypt_test(&[0u8; 10], &kek).is_err());
    }

    #[test]
    fn test_short_encrypted_data_fails() {
        use tor_marketplace::crypto::zk;
        let kek = zk::KeyEncryptionKey::new();
        let short = vec![0u8; 20];
        assert!(zk::decrypt_test(&short, &kek).is_err());
    }
}
