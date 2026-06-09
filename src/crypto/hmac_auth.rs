use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use rand::{rngs::OsRng, RngCore};
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

pub fn generate_auth_token(auth_key: &[u8], pubkey: &[u8], hour_bucket: u64, path: &str) -> Option<Vec<u8>> {
    let mut mac = HmacSha256::new_from_slice(auth_key).ok()?;
    mac.update(b"auth-token-v1");
    mac.update(pubkey);
    mac.update(&hour_bucket.to_le_bytes());
    mac.update(path.as_bytes());
    Some(mac.finalize().into_bytes().to_vec())
}

pub fn verify_auth_token(auth_key: &[u8], token: &[u8], pubkey: &[u8], hour_bucket: u64, path: &str) -> bool {
    match generate_auth_token(auth_key, pubkey, hour_bucket, path) {
        Some(expected) => expected.len() == token.len() && expected.ct_eq(token).into(),
        None => false,
    }
}

pub fn generate_ephemeral_keypair() -> (SigningKey, VerifyingKey) {
    let mut sk_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut sk_bytes);
    let signing_key = SigningKey::from_bytes(&sk_bytes);
    let verifying_key = signing_key.verifying_key();
    (signing_key, verifying_key)
}

pub fn sign_challenge(sk: &SigningKey, challenge: &[u8]) -> Vec<u8> {
    sk.sign(challenge).to_bytes().to_vec()
}

pub fn verify_challenge(pk: &VerifyingKey, challenge: &[u8], signature: &[u8]) -> bool {
    let sig = match Signature::from_slice(signature) {
        Ok(s) => s,
        Err(_) => return false,
    };
    pk.verify(challenge, &sig).is_ok()
}

pub fn compute_hour_bucket(timestamp: i64) -> u64 {
    if timestamp < 0 { return 0; }
    (timestamp / 3600) as u64
}

/// Derive a domain-scoped ephemeral identity from a pubkey hash.
/// Uses HMAC(server_secret, domain || pubkey_hash) so that:
///   - Same user in different domains (orders vs chat) gets different IDs
///   - Server with secret can verify, but without secret cannot link
/// Full Layer 0 (per-interaction random nonces) requires WASM client crypto.
pub fn derive_domain_identity(server_secret: &[u8], domain: &[u8], pubkey_hash: &[u8]) -> Option<Vec<u8>> {
    let mut mac = HmacSha256::new_from_slice(server_secret).ok()?;
    mac.update(b"domain-identity-v1");
    mac.update(domain);
    mac.update(pubkey_hash);
    Some(mac.finalize().into_bytes().to_vec())
}

/// Domain constants for Layer 0 identity separation.
pub mod domains {
    /// Orders domain — identity used for order creation and access.
    pub const ORDERS: &[u8] = b"orders";
    /// Chat domain — identity used for chat messages.
    pub const CHAT: &[u8] = b"chat";
    /// Disputes domain — identity used for dispute resolution.
    pub const DISPUTES: &[u8] = b"disputes";
    /// Auth domain — identity used for API authentication.
    pub const AUTH: &[u8] = b"auth";
    /// Admin domain — identity used for admin actions.
    pub const ADMIN: &[u8] = b"admin";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_roundtrip() {
        let auth_key = b"test-auth-key-32-bytes-long!!";
        let pubkey = b"test-pubkey-bytes";
        let hour_bucket = 12345u64;
        let path = "/api/orders";
        let token = generate_auth_token(auth_key, pubkey, hour_bucket, path).unwrap();
        assert!(verify_auth_token(auth_key, &token, pubkey, hour_bucket, path));
    }

    #[test]
    fn test_wrong_key_rejection() {
        let key1 = b"this-is-key-one-32-bytes-long!";
        let key2 = b"this-is-key-two-32-bytes-long!";
        let pubkey = b"test-pubkey-bytes";
        let hour_bucket = 12345u64;
        let path = "/api/orders";
        let token = generate_auth_token(key1, pubkey, hour_bucket, path).unwrap();
        assert!(!verify_auth_token(key2, &token, pubkey, hour_bucket, path));
    }

    #[test]
    fn test_keypair_sign_verify() {
        let (sk, pk) = generate_ephemeral_keypair();
        let challenge = b"test-challenge-data-32-bytes!!";
        let sig = sign_challenge(&sk, challenge);
        assert!(verify_challenge(&pk, challenge, &sig));
    }

    #[test]
    fn test_key_separation() {
        let auth_key = b"test-auth-key-32-bytes-long!!";
        let pubkey1 = b"pubkey-one-data-here-0001";
        let pubkey2 = b"pubkey-two-data-here-0002";
        let hour_bucket = 12345u64;
        let path = "/api/orders";
        let token1 = generate_auth_token(auth_key, pubkey1, hour_bucket, path).unwrap();
        let token2 = generate_auth_token(auth_key, pubkey2, hour_bucket, path).unwrap();
        assert_ne!(token1, token2);
    }

    #[test]
    fn test_wrong_path_rejection() {
        let auth_key = b"test-auth-key-32-bytes-long!!";
        let pubkey = b"test-pubkey-bytes";
        let hour_bucket = 12345u64;
        let token = generate_auth_token(auth_key, pubkey, hour_bucket, "/api/orders").unwrap();
        assert!(!verify_auth_token(auth_key, &token, pubkey, hour_bucket, "/api/listings"));
    }

    #[test]
    fn test_compute_hour_bucket() {
        let ts = 3600 * 5 + 30;
        assert_eq!(compute_hour_bucket(ts), 5);
        assert_eq!(compute_hour_bucket(0), 0);
        assert_eq!(compute_hour_bucket(3599), 0);
        assert_eq!(compute_hour_bucket(3600), 1);
    }

    #[test]
    fn test_domain_identity_separation() {
        let secret = b"test-secret-key-32-bytes-long!!!!!";
        let pubkey = b"test-pubkey-bytes-for-testing";
        let id_orders = derive_domain_identity(secret, domains::ORDERS, pubkey).unwrap();
        let id_chat = derive_domain_identity(secret, domains::CHAT, pubkey).unwrap();
        assert_ne!(id_orders, id_chat, "Same pubkey in different domains must produce different IDs");
    }

    #[test]
    fn test_domain_identity_consistent() {
        let secret = b"test-secret-key-32-bytes-long!!!!!";
        let pubkey = b"test-pubkey";
        let id = derive_domain_identity(secret, domains::ORDERS, pubkey).unwrap();
        let id2 = derive_domain_identity(secret, domains::ORDERS, pubkey).unwrap();
        assert_eq!(id, id2, "Same domain+pubkey must produce same ID");
    }

    #[test]
    fn test_domain_identity_different_pubkeys() {
        let secret = b"test-secret-key-32-bytes-long!!!!!";
        let id1 = derive_domain_identity(secret, domains::ORDERS, b"pubkey-1").unwrap();
        let id2 = derive_domain_identity(secret, domains::ORDERS, b"pubkey-2").unwrap();
        assert_ne!(id1, id2, "Different pubkeys in same domain must produce different IDs");
    }

    #[test]
    fn test_domain_identity_wrong_secret_fails() {
        let secret = b"correct-secret-key-32-bytes-long!";
        let wrong = b"wrong-secret-key----32-bytes-long!";
        let pubkey = b"test-pubkey";
        let id1 = derive_domain_identity(secret, domains::ORDERS, pubkey).unwrap();
        let id2 = derive_domain_identity(wrong, domains::ORDERS, pubkey).unwrap();
        assert_ne!(id1, id2, "Different secrets must produce different IDs");
    }
}
