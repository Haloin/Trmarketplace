#[cfg(test)]
mod tests {
    use tor_marketplace::gateway::ratelimit::RateLimiter;
    use tor_marketplace::crypto::zk;
    use tor_marketplace::crypto::hash;

    #[test]
    fn test_hash_output_length_constant() {
        let input1 = b"short";
        let input2 = b"a-much-longer-input-that-exceeds-32-bytes!";
        let input3 = b"";

        let h1 = hash::hash_pubkey(input1);
        let h2 = hash::hash_pubkey(input2);
        let h3 = hash::hash_pubkey(input3);

        assert_eq!(h1.len(), h2.len(), "Hash outputs must be same length regardless of input");
        assert_eq!(h1.len(), h3.len(), "Hash outputs must be same length regardless of input");
    }

    #[test]
    fn test_encryption_output_varies_by_nonce() {
        let kek = zk::KeyEncryptionKey::new();
        let pt = b"fixed-plaintext-for-nonce-variation-test";

        let ct1 = zk::encrypt_test(pt, &kek).unwrap();
        let ct2 = zk::encrypt_test(pt, &kek).unwrap();
        let ct3 = zk::encrypt_test(pt, &kek).unwrap();

        // Each encryption uses a fresh random nonce, so ciphertexts differ
        assert_ne!(ct1, ct2, "Same plaintext+key must produce different ciphertexts (random nonce)");
        assert_ne!(ct1, ct3, "Same plaintext+key must produce different ciphertexts (random nonce)");
        assert_ne!(ct2, ct3, "Same plaintext+key must produce different ciphertexts (random nonce)");

        // But all must decrypt correctly
        let d1 = zk::decrypt_test(&ct1, &kek).unwrap();
        let d2 = zk::decrypt_test(&ct2, &kek).unwrap();
        let d3 = zk::decrypt_test(&ct3, &kek).unwrap();
        assert_eq!(&d1, pt);
        assert_eq!(&d2, pt);
        assert_eq!(&d3, pt);
    }

    #[test]
    fn test_encryption_output_length_consistent_for_same_plaintext() {
        let kek = zk::KeyEncryptionKey::new();
        let pt = b"fixed-length-plaintext!";

        let ct1 = zk::encrypt_test(pt, &kek).unwrap();
        let ct2 = zk::encrypt_test(pt, &kek).unwrap();

        // Encryption output length is determined by plaintext length + overhead (nonce + MAC tag)
        assert_eq!(ct1.len(), ct2.len(), "Ciphertext length must be consistent for same plaintext length");
    }

    #[test]
    fn test_encryption_overhead_constant() {
        let kek = zk::KeyEncryptionKey::new();

        let pt1 = b"";
        let pt2 = b"1234567890123456";
        let pt3 = b"12345678901234567890123456789012345678901234567890";

        let ct1 = zk::encrypt_test(pt1, &kek).unwrap();
        let ct2 = zk::encrypt_test(pt2, &kek).unwrap();
        let ct3 = zk::encrypt_test(pt3, &kek).unwrap();

        // Overhead = ciphertext_len - plaintext_len (nonce + MAC)
        let overhead1 = ct1.len() - pt1.len();
        let overhead2 = ct2.len() - pt2.len();
        let overhead3 = ct3.len() - pt3.len();

        assert_eq!(overhead1, overhead2, "Encryption overhead must be constant");
        assert_eq!(overhead1, overhead3, "Encryption overhead must be constant");
    }

    #[test]
    fn test_error_response_no_stack_trace_visible() {
        // Test that decryption failures don't leak info through error messages
        let kek = zk::KeyEncryptionKey::new();
        let pt = b"valid-plaintext";
        let mut ct = zk::encrypt_test(pt, &kek).unwrap();

        // Tamper ciphertext
        let last_idx = ct.len() - 1;
        ct[last_idx] ^= 0x01;
        let result = zk::decrypt_test(&ct, &kek);
        assert!(result.is_err());

        // Error should not contain the plaintext or key material
        let err = result.err().unwrap();
        let err_str = format!("{}", err);
        assert!(!err_str.contains("valid-plaintext"), "Error must not leak plaintext");
    }

    #[tokio::test]
    async fn test_rate_limiter_consistent_blocked_response() {
        let limiter = RateLimiter::new(3, 60);

        for _ in 0..3 {
            assert!(limiter.check("consistent_user").await);
        }
        assert!(!limiter.check("consistent_user").await);
        assert!(!limiter.check("consistent_user").await);
        assert!(!limiter.check("consistent_user").await);

        // Multiple blocked requests should all return false consistently
        for _ in 0..5 {
            assert!(!limiter.check("consistent_user").await, "All blocked requests must return false");
        }
    }

    #[test]
    fn test_challenge_hash_consistency() {
        let challenge = b"test-challenge-for-hash-consistency";
        let secret = b"test-secret-for-challenge-hashing";

        let h1 = hash::hash_challenge(challenge, secret);
        let h2 = hash::hash_challenge(challenge, secret);
        let h3 = hash::hash_challenge(challenge, secret);

        assert_eq!(h1, h2);
        assert_eq!(h1, h3);
    }

    #[test]
    fn test_challenge_hash_different_secrets_differ() {
        let challenge = b"same-challenge-different-secrets";
        let secret1 = b"secret-number-one-for-hashing-test";
        let secret2 = b"secret-number-two-for-hashing-test";

        let h1 = hash::hash_challenge(challenge, secret1);
        let h2 = hash::hash_challenge(challenge, secret2);

        assert_ne!(h1, h2);
    }
}
