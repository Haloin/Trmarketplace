#[cfg(test)]
mod tests {
    use tor_marketplace::crypto::hmac_auth;
    use tor_marketplace::crypto::zk;
    use tor_marketplace::crypto::hash;

    #[test]
    fn test_auth_token_replay_across_hours_fails() {
        let auth_key = b"test-auth-key-replay-test-32-bytes";
        let pubkey = b"pubkey-for-replay-test-32-bytes-long";
        let path = "/api/orders";

        let token_hour_1 = hmac_auth::generate_auth_token(auth_key, pubkey, 1, path).unwrap();
        let token_hour_2 = hmac_auth::generate_auth_token(auth_key, pubkey, 2, path).unwrap();

        assert_ne!(token_hour_1, token_hour_2, "Tokens for different hours must differ");

        // Token from hour 1 cannot be used in hour 2
        assert!(!hmac_auth::verify_auth_token(auth_key, &token_hour_1, pubkey, 2, path));
        assert!(hmac_auth::verify_auth_token(auth_key, &token_hour_1, pubkey, 1, path));
    }

    #[test]
    fn test_auth_token_replay_across_paths_fails() {
        let auth_key = b"test-auth-key-replay-path-32-bytes";
        let pubkey = b"pubkey-for-path-replay-32-bytes-lo";
        let hour = 5000u64;

        let token_orders = hmac_auth::generate_auth_token(auth_key, pubkey, hour, "/api/orders").unwrap();

        assert!(hmac_auth::verify_auth_token(auth_key, &token_orders, pubkey, hour, "/api/orders"));
        assert!(!hmac_auth::verify_auth_token(auth_key, &token_orders, pubkey, hour, "/api/listings"));
        assert!(!hmac_auth::verify_auth_token(auth_key, &token_orders, pubkey, hour, "/auth/verify"));
        assert!(!hmac_auth::verify_auth_token(auth_key, &token_orders, pubkey, hour, "/api/admin/orders"));
    }

    #[test]
    fn test_auth_token_replay_across_users_fails() {
        let auth_key = b"test-auth-key-replay-user-32-bytes";
        let user1 = b"pubkey-user-001-for-replay-testing";
        let user2 = b"pubkey-user-002-for-replay-testing";
        let hour = 7000u64;
        let path = "/api/orders";

        let token_user1 = hmac_auth::generate_auth_token(auth_key, user1, hour, path).unwrap();

        assert!(hmac_auth::verify_auth_token(auth_key, &token_user1, user1, hour, path));
        assert!(!hmac_auth::verify_auth_token(auth_key, &token_user1, user2, hour, path));
    }

    #[test]
    fn test_challenge_signature_cannot_be_reused_across_challenges() {
        

        let (sk, pk) = hmac_auth::generate_ephemeral_keypair();
        let challenge_a = b"challenge-alpha-001-unique-nonce";
        let challenge_b = b"challenge-beta-002-unique-nonce";

        let sig_for_a = hmac_auth::sign_challenge(&sk, challenge_a);

        // Signature for A must not be valid for B
        assert!(hmac_auth::verify_challenge(&pk, challenge_a, &sig_for_a));
        assert!(!hmac_auth::verify_challenge(&pk, challenge_b, &sig_for_a),
            "Signature from challenge A must not verify challenge B");
    }

    #[test]
    fn test_tampered_auth_token_rejected() {
        let auth_key = b"test-auth-key-tamper-test-32-bytes";
        let pubkey = b"pubkey-for-tamper-test-32-bytes-l";
        let hour = 8000u64;
        let path = "/api/orders";

        let token = hmac_auth::generate_auth_token(auth_key, pubkey, hour, path).unwrap();

        // Flip individual bytes
        for i in [0, 5, 15, 31] {
            let mut tampered = token.clone();
            tampered[i] ^= 0x01;
            assert!(!hmac_auth::verify_auth_token(auth_key, &tampered, pubkey, hour, path),
                "Tampered token at byte {} must fail verification", i);
        }
    }

    #[test]
    fn test_same_message_signed_by_different_users_different_sigs() {
        let (sk1, pk1) = hmac_auth::generate_ephemeral_keypair();
        let (sk2, pk2) = hmac_auth::generate_ephemeral_keypair();
        let message = b"same-message-for-two-different-users";

        let sig1 = hmac_auth::sign_challenge(&sk1, message);
        let sig2 = hmac_auth::sign_challenge(&sk2, message);

        assert_ne!(sig1, sig2, "Different users signing same message must produce different signatures");
        assert!(hmac_auth::verify_challenge(&pk1, message, &sig1));
        assert!(hmac_auth::verify_challenge(&pk2, message, &sig2));

        // Cross-verification must fail
        assert!(!hmac_auth::verify_challenge(&pk1, message, &sig2));
        assert!(!hmac_auth::verify_challenge(&pk2, message, &sig1));
    }

    #[test]
    fn test_encryption_replay_fails_with_different_nonce() {
        let kek = zk::KeyEncryptionKey::new();
        let pt = b"order-encrypted-data-that-cannot-be-replayed";

        // Each encryption gets a fresh nonce → different ciphertext even for same plaintext
        let ct1 = zk::encrypt_test(pt, &kek).unwrap();
        let ct2 = zk::encrypt_test(pt, &kek).unwrap();

        assert_ne!(ct1, ct2, "Each encryption must produce unique ciphertext");

        // Both decrypt correctly
        assert_eq!(&zk::decrypt_test(&ct1, &kek).unwrap(), pt);
        assert_eq!(&zk::decrypt_test(&ct2, &kek).unwrap(), pt);
    }

    #[test]
    fn test_challenge_hash_different_inputs_differ() {
        let secret = b"server-secret-for-challenge-hashing";
        let c1 = hash::hash_challenge(b"challenge-1", secret);
        let c2 = hash::hash_challenge(b"challenge-2", secret);
        let c3 = hash::hash_challenge(b"different-challenge-3", secret);

        assert_ne!(c1, c2);
        assert_ne!(c1, c3);
        assert_ne!(c2, c3);
    }
}
