#[cfg(test)]
mod tests {
    use tor_marketplace::crypto::hmac_auth;
    use tor_marketplace::crypto::hash;

    #[test]
    fn test_same_user_different_domains_different_ids() {
        let secret = b"test-secret-key-32-bytes-long-for-test-";
        let pubkey = b"user-pubkey-32-bytes-long-for-domain-t";
        let id_orders = hmac_auth::derive_domain_identity(secret, hmac_auth::domains::ORDERS, pubkey).unwrap();
        let id_chat = hmac_auth::derive_domain_identity(secret, hmac_auth::domains::CHAT, pubkey).unwrap();
        let id_disputes = hmac_auth::derive_domain_identity(secret, hmac_auth::domains::DISPUTES, pubkey).unwrap();
        let id_auth = hmac_auth::derive_domain_identity(secret, hmac_auth::domains::AUTH, pubkey).unwrap();
        let id_admin = hmac_auth::derive_domain_identity(secret, hmac_auth::domains::ADMIN, pubkey).unwrap();

        assert_ne!(id_orders, id_chat);
        assert_ne!(id_orders, id_disputes);
        assert_ne!(id_orders, id_auth);
        assert_ne!(id_orders, id_admin);
        assert_ne!(id_chat, id_disputes);
        assert_ne!(id_chat, id_auth);
        assert_ne!(id_chat, id_admin);
        assert_ne!(id_disputes, id_auth);
        assert_ne!(id_disputes, id_admin);
        assert_ne!(id_auth, id_admin);
    }

    #[test]
    fn test_different_users_same_domain_different_ids() {
        let secret = b"test-secret-key-32-bytes-long-for-test-";
        let user1 = b"pubkey-user-1-32-bytes-long-for-domain-";
        let user2 = b"pubkey-user-2-32-bytes-long-for-domain-";
        let user3 = b"pubkey-user-3-32-bytes-long-for-domain-";

        let ids: Vec<_> = [user1, user2, user3].iter().map(|&u| {
            hmac_auth::derive_domain_identity(secret, hmac_auth::domains::ORDERS, u).unwrap()
        }).collect();

        for i in 0..ids.len() {
            for j in (i+1)..ids.len() {
                assert_ne!(ids[i], ids[j], "Users {} and {} must have different domain identities", i, j);
            }
        }
    }

    #[test]
    fn test_domain_identity_deterministic() {
        let secret = b"test-secret-key-32-bytes-long-for-test-";
        let pubkey = b"consistent-pubkey-for-testing-1234";
        let id1 = hmac_auth::derive_domain_identity(secret, hmac_auth::domains::ORDERS, pubkey).unwrap();
        let id2 = hmac_auth::derive_domain_identity(secret, hmac_auth::domains::ORDERS, pubkey).unwrap();
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_wrong_secret_identity_differs() {
        let secret1 = b"correct-secret-key-32-bytes-long-for-";
        let secret2 = b"wrong-secret-key----32-bytes-long-for";
        let pubkey = b"pubkey-for-testing-identity-secrets";
        let id1 = hmac_auth::derive_domain_identity(secret1, hmac_auth::domains::ORDERS, pubkey).unwrap();
        let id2 = hmac_auth::derive_domain_identity(secret2, hmac_auth::domains::ORDERS, pubkey).unwrap();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_auth_token_path_locked() {
        let auth_key = b"test-auth-key-32-bytes-long-for-token";
        let pubkey = b"pubkey-for-path-lock-test-data";
        let hour_bucket = 10000u64;

        let token = hmac_auth::generate_auth_token(auth_key, pubkey, hour_bucket, "/api/orders").unwrap();
        assert!(hmac_auth::verify_auth_token(auth_key, &token, pubkey, hour_bucket, "/api/orders"));
        assert!(!hmac_auth::verify_auth_token(auth_key, &token, pubkey, hour_bucket, "/api/listings"));
        assert!(!hmac_auth::verify_auth_token(auth_key, &token, pubkey, hour_bucket, "/api/admin"));
        assert!(!hmac_auth::verify_auth_token(auth_key, &token, pubkey, hour_bucket, "/api/chat"));
    }

    #[test]
    fn test_auth_token_key_separation() {
        let key1 = b"auth-key-number-one-32-bytes-long!!";
        let key2 = b"auth-key-number-two-32-bytes-long!!";
        let pubkey = b"pubkey-for-key-separation-tests";
        let hour_bucket = 20000u64;

        let token1 = hmac_auth::generate_auth_token(key1, pubkey, hour_bucket, "/api/orders").unwrap();
        assert!(hmac_auth::verify_auth_token(key1, &token1, pubkey, hour_bucket, "/api/orders"));
        assert!(!hmac_auth::verify_auth_token(key2, &token1, pubkey, hour_bucket, "/api/orders"));
    }

    #[test]
    fn test_challenge_signing_different_keys_different_sigs() {
        let (sk1, pk1) = hmac_auth::generate_ephemeral_keypair();
        let (sk2, pk2) = hmac_auth::generate_ephemeral_keypair();
        let challenge = b"same-challenge-for-both-keys-test-123";

        let sig1 = hmac_auth::sign_challenge(&sk1, challenge);
        let sig2 = hmac_auth::sign_challenge(&sk2, challenge);

        assert_ne!(sig1, sig2, "Different keys must produce different signatures on same challenge");
        assert!(hmac_auth::verify_challenge(&pk1, challenge, &sig1));
        assert!(hmac_auth::verify_challenge(&pk2, challenge, &sig2));
    }

    #[test]
    fn test_uniform_auth_error_no_info_leak() {
        let (sk, pk) = hmac_auth::generate_ephemeral_keypair();
        let challenge = b"test-challenge-for-error-testing";

        // Valid signature
        let valid_sig = hmac_auth::sign_challenge(&sk, challenge);

        // Wrong signature (signed different message)
        let wrong_sig = hmac_auth::sign_challenge(&sk, b"different-message");

        assert!(hmac_auth::verify_challenge(&pk, challenge, &valid_sig));
        assert!(!hmac_auth::verify_challenge(&pk, challenge, &wrong_sig));

        // Signature verification fails for wrong challenge
        assert!(!hmac_auth::verify_challenge(&pk, b"wrong-challenge", &valid_sig));
    }

    #[test]
    fn test_challenge_id_uniqueness_via_different_signed_outputs() {
        let (sk, pk) = hmac_auth::generate_ephemeral_keypair();
        let challenge1 = b"challenge-id-001-unique-data-here";
        let challenge2 = b"challenge-id-002-unique-data-here";
        let challenge3 = b"challenge-id-003-unique-data-here";

        let sig1 = hmac_auth::sign_challenge(&sk, challenge1);
        let sig2 = hmac_auth::sign_challenge(&sk, challenge2);
        let sig3 = hmac_auth::sign_challenge(&sk, challenge3);

        assert_ne!(sig1, sig2);
        assert_ne!(sig1, sig3);
        assert_ne!(sig2, sig3);

        assert!(hmac_auth::verify_challenge(&pk, challenge1, &sig1));
        assert!(hmac_auth::verify_challenge(&pk, challenge2, &sig2));
        assert!(hmac_auth::verify_challenge(&pk, challenge3, &sig3));
    }

    #[test]
    fn test_pubkey_hash_unlinkability() {
        let pubkey1 = b"first-pubkey-for-hash-unlink-00001";
        let pubkey2 = b"second-pubkey-for-hash-unlink-0002";

        let hash1 = hash::hash_pubkey(pubkey1);
        let hash2 = hash::hash_pubkey(pubkey2);

        assert_ne!(hash1, hash2, "Different pubkeys must produce different hashes");
        assert_eq!(hash1.len(), hash2.len(), "Hashes must be same length");
    }
}
