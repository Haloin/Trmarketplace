#[cfg(test)]
mod tests {
    use tor_marketplace::crypto::hmac_auth;

    #[test]
    fn test_two_users_have_different_domain_identities() {
        let secret = b"test-secret-key-32-bytes-long-for-test-";
        let user1 = b"pubkey-user-1-32-bytes-long-for-domain-";
        let user2 = b"pubkey-user-2-32-bytes-long-for-domain-";

        let id1 = hmac_auth::derive_domain_identity(secret, hmac_auth::domains::ORDERS, user1).unwrap();
        let id2 = hmac_auth::derive_domain_identity(secret, hmac_auth::domains::ORDERS, user2).unwrap();

        assert_ne!(id1, id2, "Different users must have different domain identities");
    }

    #[test]
    fn test_user_cannot_impersonate_another_via_domain_id() {
        let secret = b"test-secret-key-32-bytes-long-for-test-";
        let user1 = b"pubkey-user-1-32-bytes-long-for-domain-";
        let user2 = b"pubkey-user-2-32-bytes-long-for-domain-";

        let id_user1 = hmac_auth::derive_domain_identity(secret, hmac_auth::domains::ORDERS, user1).unwrap();
        let id_user2 = hmac_auth::derive_domain_identity(secret, hmac_auth::domains::ORDERS, user2).unwrap();

        // User2's domain identity should not match User1's
        let claimed_as_user1 = hmac_auth::derive_domain_identity(secret, hmac_auth::domains::ORDERS, user2).unwrap();
        assert_ne!(claimed_as_user1, id_user1,
            "User2's domain identity must not match User1's");
        assert_eq!(claimed_as_user1, id_user2,
            "User2 must consistently derive their own identity");
    }

    #[test]
    fn test_user_cannot_use_other_users_auth_key() {
        let _secret = b"test-secret-key-32-bytes-long-for-test-";
        let user1 = b"pubkey-user-1-32-bytes-long-for-domain-";
        let user2 = b"pubkey-user-2-32-bytes-long-for-domain-";

        let auth_key1 = b"auth-key-for-user-1-32-bytes-long!!";
        let auth_key2 = b"auth-key-for-user-2-32-bytes-long!!";
        let hour_bucket = 10000u64;
        let path = "/api/orders";

        // User1 generates token with their own auth_key + pubkey
        let token_user1 = hmac_auth::generate_auth_token(auth_key1, user1, hour_bucket, path).unwrap();
        assert!(hmac_auth::verify_auth_token(auth_key1, &token_user1, user1, hour_bucket, path));

        // User2 trying to use User1's token fails
        assert!(!hmac_auth::verify_auth_token(auth_key1, &token_user1, user2, hour_bucket, path));

        // User2 must generate their own token
        let token_user2 = hmac_auth::generate_auth_token(auth_key2, user2, hour_bucket, path).unwrap();
        assert!(hmac_auth::verify_auth_token(auth_key2, &token_user2, user2, hour_bucket, path));

        // Cross-verification fails
        assert!(!hmac_auth::verify_auth_token(auth_key1, &token_user2, user2, hour_bucket, path));
        assert!(!hmac_auth::verify_auth_token(auth_key2, &token_user1, user1, hour_bucket, path));
    }

    #[test]
    fn test_same_user_different_domains_have_different_ids() {
        let secret = b"test-secret-key-32-bytes-long-for-test-";
        let user = b"single-user-pubkey-for-all-domains!!";

        let id_orders = hmac_auth::derive_domain_identity(secret, hmac_auth::domains::ORDERS, user).unwrap();
        let id_chat = hmac_auth::derive_domain_identity(secret, hmac_auth::domains::CHAT, user).unwrap();
        let id_disputes = hmac_auth::derive_domain_identity(secret, hmac_auth::domains::DISPUTES, user).unwrap();

        assert_ne!(id_orders, id_chat, "Same user in ORDERS vs CHAT must produce different IDs");
        assert_ne!(id_orders, id_disputes, "Same user in ORDERS vs DISPUTES must produce different IDs");
        assert_ne!(id_chat, id_disputes, "Same user in CHAT vs DISPUTES must produce different IDs");
    }

    #[test]
    fn test_same_user_same_domain_consistent_id() {
        let secret = b"test-secret-key-32-bytes-long-for-test-";
        let user = b"test-user-for-consistency-check!!";

        let id1 = hmac_auth::derive_domain_identity(secret, hmac_auth::domains::ORDERS, user).unwrap();
        let id2 = hmac_auth::derive_domain_identity(secret, hmac_auth::domains::ORDERS, user).unwrap();
        let id3 = hmac_auth::derive_domain_identity(secret, hmac_auth::domains::ORDERS, user).unwrap();

        assert_eq!(id1, id2);
        assert_eq!(id1, id3);
    }
}
