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
        use tor_marketplace::crypto::encryption::EncryptionKey;
        let key = EncryptionKey::generate();
        let plaintext = b"test data";
        let mut encrypted = key.encrypt(plaintext).unwrap();
        // Flip a bit in the nonce
        encrypted[0] ^= 0xFF;
        assert!(key.decrypt(&encrypted).is_err());
    }

    #[test]
    fn test_empty_encrypted_data_fails() {
        use tor_marketplace::crypto::encryption::EncryptionKey;
        let key = EncryptionKey::generate();
        assert!(key.decrypt(&[]).is_err());
        assert!(key.decrypt(&[0u8; 10]).is_err());
    }

    #[test]
    fn test_short_encrypted_data_fails() {
        use tor_marketplace::crypto::encryption::EncryptionKey;
        let key = EncryptionKey::generate();
        // Only nonce without data
        let short = vec![0u8; 20];
        assert!(key.decrypt(&short).is_err());
    }
}
