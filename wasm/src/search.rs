use blake3::Hasher;
use wasm_bindgen::prelude::*;

/// Build an opaque search token: BLAKE3(keyword || search_key).
/// Matches `crypto::client::generate_single_token`.
#[wasm_bindgen]
pub fn search_token(keyword: &str, search_key: &[u8]) -> Vec<u8> {
    let mut hasher = Hasher::new();
    hasher.update(keyword.as_bytes());
    hasher.update(search_key);
    hasher.finalize().as_bytes().to_vec()
}
