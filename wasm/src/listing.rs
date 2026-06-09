use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand::rngs::OsRng;
use rand::RngCore;
use wasm_bindgen::prelude::*;

const NONCE_SIZE: usize = 12;
const KEY_SIZE: usize = 32;

/// Encrypt listing content with a random 32-byte content key.
/// Returns `nonce (12B) || ciphertext`.
#[wasm_bindgen]
pub fn encrypt_listing(plaintext: &[u8], content_key: &[u8]) -> Result<Vec<u8>, JsValue> {
    if content_key.len() != KEY_SIZE {
        return Err(JsValue::from_str("content_key must be 32 bytes"));
    }
    let cipher = ChaCha20Poly1305::new_from_slice(content_key)
        .map_err(|_| JsValue::from_str("invalid content key"))?;
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| JsValue::from_str("listing encryption failed"))?;
    let mut out = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt listing content encrypted with `encrypt_listing`.
#[wasm_bindgen]
pub fn decrypt_listing(ciphertext: &[u8], content_key: &[u8]) -> Result<Vec<u8>, JsValue> {
    if content_key.len() != KEY_SIZE {
        return Err(JsValue::from_str("content_key must be 32 bytes"));
    }
    if ciphertext.len() < NONCE_SIZE + 1 {
        return Err(JsValue::from_str("ciphertext too short"));
    }
    let (nonce_bytes, encrypted) = ciphertext.split_at(NONCE_SIZE);
    let cipher = ChaCha20Poly1305::new_from_slice(content_key)
        .map_err(|_| JsValue::from_str("invalid content key"))?;
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, encrypted)
        .map_err(|_| JsValue::from_str("listing decryption failed"))
}

/// Generate a random 32-byte content key for listing encryption.
#[wasm_bindgen]
pub fn generate_content_key() -> Vec<u8> {
    let mut key = [0u8; KEY_SIZE];
    OsRng.fill_bytes(&mut key);
    key.to_vec()
}
