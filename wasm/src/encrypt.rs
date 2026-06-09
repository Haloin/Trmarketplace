use rand::rngs::OsRng;
use wasm_bindgen::prelude::*;
use x25519_dalek::{EphemeralSecret, PublicKey};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use sha2::Sha256;

const PUBKEY_SIZE: usize = 32;
const NONCE_SIZE: usize = 12;

/// Encrypt order data using X25519 ECDH + ChaCha20-Poly1305.
///
/// 1. Generates an ephemeral X25519 keypair
/// 2. Computes shared secret = X25519(ephemeral_sk, recipient_pk)
/// 3. Derives encryption key via HKDF-SHA256
/// 4. Encrypts plaintext with ChaCha20-Poly1305 + random nonce
///
/// Returns: `ephemeral_pk (32B) || nonce (12B) || ciphertext`
#[wasm_bindgen]
pub fn encrypt_order(plaintext: &[u8], recipient_pubkey: &[u8]) -> Vec<u8> {
    if recipient_pubkey.len() != PUBKEY_SIZE {
        wasm_bindgen::throw_str("recipient_pubkey must be 32 bytes");
    }

    let recipient = {
        let arr: [u8; PUBKEY_SIZE] = recipient_pubkey.try_into()
            .expect("recipient_pubkey length checked above");
        PublicKey::from(arr)
    };
    let ephemeral_sk = EphemeralSecret::random_from_rng(OsRng);
    let ephemeral_pk = PublicKey::from(&ephemeral_sk);

    let shared_secret = ephemeral_sk.diffie_hellman(&recipient);
    let shared_secret_bytes = shared_secret.as_bytes();

    let hk = Hkdf::<Sha256>::new(None, shared_secret_bytes);
    let mut key = [0u8; 32];
    hk.expand(b"tor-marketplace-order-key-v1", &mut key)
        .expect("HKDF expand must not fail");

    let cipher = ChaCha20Poly1305::new_from_slice(&key)
        .expect("Key is 32 bytes");
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    getrandom::getrandom(&mut nonce_bytes)
        .expect("RNG must not fail");
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, plaintext)
        .expect("Encryption must not fail");

    let mut output = Vec::with_capacity(PUBKEY_SIZE + NONCE_SIZE + ciphertext.len());
    output.extend_from_slice(ephemeral_pk.as_bytes());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);
    output
}
