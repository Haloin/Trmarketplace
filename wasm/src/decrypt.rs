use wasm_bindgen::prelude::*;
use x25519_dalek::{PublicKey, StaticSecret};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use sha2::Sha256;

const PUBKEY_SIZE: usize = 32;
const NONCE_SIZE: usize = 12;

/// Decrypt order data that was encrypted with `encrypt_order`.
///
/// Input: `ephemeral_pk (32B) || nonce (12B) || ciphertext`
/// Returns the decrypted plaintext on success.
#[wasm_bindgen]
pub fn decrypt_order(ciphertext: &[u8], secret_key: &[u8]) -> Result<Vec<u8>, JsValue> {
    if secret_key.len() != PUBKEY_SIZE {
        return Err(JsValue::from_str("secret_key must be 32 bytes"));
    }
    if ciphertext.len() < PUBKEY_SIZE + NONCE_SIZE {
        return Err(JsValue::from_str("ciphertext too short"));
    }

    let ephemeral_pk_arr: [u8; PUBKEY_SIZE] = ciphertext[..PUBKEY_SIZE].try_into()
        .map_err(|_| JsValue::from_str("failed to parse ephemeral pubkey"))?;
    let nonce_arr: [u8; NONCE_SIZE] = ciphertext[PUBKEY_SIZE..PUBKEY_SIZE + NONCE_SIZE].try_into()
        .map_err(|_| JsValue::from_str("failed to parse nonce"))?;
    let encrypted = &ciphertext[PUBKEY_SIZE + NONCE_SIZE..];

    let secret_key_arr: [u8; PUBKEY_SIZE] = secret_key.try_into()
        .map_err(|_| JsValue::from_str("invalid secret key length"))?;
    let secret = StaticSecret::from(secret_key_arr);
    let ephemeral_pk = PublicKey::from(ephemeral_pk_arr);

    let shared_secret = secret.diffie_hellman(&ephemeral_pk);
    let hk = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
    let mut key = [0u8; 32];
    hk.expand(b"tor-marketplace-order-key-v1", &mut key)
        .map_err(|_| JsValue::from_str("HKDF expand failed"))?;

    let cipher = ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| JsValue::from_str("invalid key"))?;
    let nonce = Nonce::from_slice(&nonce_arr);

    cipher.decrypt(nonce, encrypted)
        .map_err(|_| JsValue::from_str("decryption failed"))
}
