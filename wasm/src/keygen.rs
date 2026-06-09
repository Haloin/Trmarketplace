use rand::rngs::OsRng;
use wasm_bindgen::prelude::*;
use x25519_dalek::{PublicKey, StaticSecret};

/// A WASM-accessible X25519 keypair.
#[wasm_bindgen]
pub struct WasmKeypair {
    secret_key: Vec<u8>,
    public_key: Vec<u8>,
}

#[wasm_bindgen]
impl WasmKeypair {
    /// The 32-byte secret (private) key.
    pub fn secret_key(&self) -> Vec<u8> {
        self.secret_key.clone()
    }

    /// The 32-byte public key.
    pub fn public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }
}

/// Generate a fresh ephemeral X25519 keypair.
#[wasm_bindgen]
pub fn generate_keypair() -> WasmKeypair {
    let sk = StaticSecret::random_from_rng(OsRng);
    let pk = PublicKey::from(&sk);
    WasmKeypair {
        secret_key: sk.to_bytes().to_vec(),
        public_key: pk.as_bytes().to_vec(),
    }
}
