use crate::crypto::hash::hash_pubkey;
use crate::crypto::zk::constant_time_compare;

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
