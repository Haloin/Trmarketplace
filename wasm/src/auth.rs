use hmac::{Hmac, Mac};
use sha2::Sha256;
use wasm_bindgen::prelude::*;

type HmacSha256 = Hmac<Sha256>;

/// Compute an HMAC auth token for stateless API authentication.
///
/// Matches the algorithm in the server's `hmac_auth.rs`:
/// `token = HMAC-SHA256(auth_key, pubkey || hour_le_8 || path || nonce)`
#[wasm_bindgen]
pub fn compute_hmac_token(
    auth_key: &[u8],
    pubkey: &[u8],
    hour: u64,
    path: &str,
    nonce: &[u8],
) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(auth_key)
        .expect("HMAC key length is valid");

    mac.update(pubkey);
    mac.update(&hour.to_le_bytes());
    mac.update(path.as_bytes());
    mac.update(nonce);

    mac.finalize().into_bytes().to_vec()
}
