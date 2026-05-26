use crate::crypto::hash::hash_pubkey;
use crate::crypto::zk::constant_time_compare;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Derive an HMAC auth key from the server secret and a user's pubkey.
/// Used by both the challenge/auth service and the stateless auth middleware.
pub fn derive_auth_key(server_secret: &str, pubkey: &[u8]) -> Option<Vec<u8>> {
    let mut mac = HmacSha256::new_from_slice(server_secret.as_bytes()).ok()?;
    mac.update(b"auth_key_derivation_v1");
    mac.update(pubkey);
    Some(mac.finalize().into_bytes().to_vec())
}

#[derive(Clone, Debug)]
pub struct AuthPubkey(pub Vec<u8>);

pub fn is_admin(config: &crate::config::Config, pubkey_hash: &[u8]) -> bool {
    if let Some(ref admin_pubkey) = config.security.admin_pubkey {
        if let Ok(bytes) = hex::decode(admin_pubkey) {
            let hashed = hash_pubkey(&bytes);
            return constant_time_compare(&hashed, pubkey_hash);
        }
    }
    false
}
