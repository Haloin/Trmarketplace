use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};

type HmacSha256 = Hmac<Sha256>;

/// Length of an X25519 public key (32 bytes).
const ECDH_PUBKEY_SIZE: usize = 32;
/// Length of the ChaCha20-Poly1305 nonce (12 bytes).
const ECDH_NONCE_SIZE: usize = 12;
/// Minimum valid ECDH blob size: pubkey + nonce + 1 byte of ciphertext.
const ECDH_BLOB_MIN: usize = ECDH_PUBKEY_SIZE + ECDH_NONCE_SIZE + 1;

fn derive_blob_key(server_secret: &[u8], label: &[u8], id: &[u8]) -> Option<[u8; 32]> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(server_secret).ok()?;
    mac.update(label);
    mac.update(id);
    let result = mac.finalize().into_bytes();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    Some(key)
}

fn derive_order_key(server_secret: &[u8], order_id: &[u8]) -> Option<[u8; 32]> {
    derive_blob_key(server_secret, b"oblivious-order-v1", order_id)
}

pub fn encrypt_order_blob(plaintext: &[u8], server_secret: &[u8], order_id: &[u8]) -> Option<Vec<u8>> {
    let key = derive_order_key(server_secret, order_id)?;
    let cipher = ChaCha20Poly1305::new_from_slice(&key).ok()?;
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, plaintext).ok()?;
    let mut blob = Vec::with_capacity(12 + ciphertext.len());
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);
    Some(blob)
}

pub fn decrypt_order_blob(blob: &[u8], server_secret: &[u8], order_id: &[u8]) -> Option<Vec<u8>> {
    if blob.len() < 13 {
        return None;
    }
    let (nonce_bytes, ciphertext) = blob.split_at(12);
    let key = derive_order_key(server_secret, order_id)?;
    let cipher = ChaCha20Poly1305::new_from_slice(&key).ok()?;
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher.decrypt(nonce, ciphertext).ok()
}

pub fn reencrypt_order_blob(
    old_blob: &[u8],
    new_plaintext: &[u8],
    server_secret: &[u8],
    order_id: &[u8],
) -> Option<Vec<u8>> {
    decrypt_order_blob(old_blob, server_secret, order_id)?;
    encrypt_order_blob(new_plaintext, server_secret, order_id)
}

/// Decrypt a blob that was encrypted with the WASM client's `encrypt_order`.
///
/// The WASM output format is: `ephemeral_pk (32B) || nonce (12B) || ciphertext`
/// where the ephemeral public key belongs to the client and the ciphertext
/// is ChaCha20-Poly1305 with a key derived from X25519 ECDH + HKDF-SHA256.
///
/// `server_secret_key` acts as the X25519 static secret key on the server side.
/// This is typically a domain-specific key from `escrow::derive_domain_key()`.
pub fn decrypt_ecdh_blob(blob: &[u8], server_secret_key: &[u8; 32]) -> Option<Vec<u8>> {
    if blob.len() < ECDH_BLOB_MIN {
        return None;
    }

    let (ephemeral_pk_bytes, rest) = blob.split_at(ECDH_PUBKEY_SIZE);
    let (nonce_bytes, ciphertext) = rest.split_at(ECDH_NONCE_SIZE);

    let ephemeral_pk_arr: [u8; ECDH_PUBKEY_SIZE] = ephemeral_pk_bytes.try_into().ok()?;
    let ephemeral_pk = XPublicKey::from(ephemeral_pk_arr);

    let server_sk = StaticSecret::from(*server_secret_key);
    let shared_secret = server_sk.diffie_hellman(&ephemeral_pk);

    let hk = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
    let mut key = [0u8; 32];
    hk.expand(b"tor-marketplace-order-key-v1", &mut key).ok()?;

    let cipher = ChaCha20Poly1305::new_from_slice(&key).ok()?;
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher.decrypt(nonce, ciphertext).ok()
}

/// Encrypt plaintext using the same ECDH + ChaCha20-Poly1305 scheme
/// that the WASM client uses, so the server can produce test vectors.
///
/// Format: `ephemeral_pk (32B) || nonce (12B) || ciphertext`
/// The recipient (e.g. WASM client) can decrypt with the corresponding secret key.
pub fn encrypt_ecdh_blob(plaintext: &[u8], recipient_pubkey: &[u8; 32]) -> Option<Vec<u8>> {
    let recipient = XPublicKey::from(*recipient_pubkey);

    let ephemeral_sk = x25519_dalek::EphemeralSecret::random_from_rng(OsRng);
    let ephemeral_pk = XPublicKey::from(&ephemeral_sk);
    let shared_secret = ephemeral_sk.diffie_hellman(&recipient);

    let hk = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
    let mut key = [0u8; 32];
    hk.expand(b"tor-marketplace-order-key-v1", &mut key).ok()?;

    let cipher = ChaCha20Poly1305::new_from_slice(&key).ok()?;
    let mut nonce_bytes = [0u8; ECDH_NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, plaintext).ok()?;

    let mut output = Vec::with_capacity(ECDH_PUBKEY_SIZE + ECDH_NONCE_SIZE + ciphertext.len());
    output.extend_from_slice(ephemeral_pk.as_bytes());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);
    Some(output)
}

fn derive_listing_key(server_secret: &[u8], listing_id: &[u8]) -> Option<[u8; 32]> {
    derive_blob_key(server_secret, b"oblivious-listing-v1", listing_id)
}

pub fn encrypt_listing_blob(plaintext: &[u8], server_secret: &[u8], listing_id: &[u8]) -> Option<Vec<u8>> {
    let key = derive_listing_key(server_secret, listing_id)?;
    let cipher = ChaCha20Poly1305::new_from_slice(&key).ok()?;
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, plaintext).ok()?;
    let mut blob = Vec::with_capacity(12 + ciphertext.len());
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);
    Some(blob)
}

pub fn decrypt_listing_blob(blob: &[u8], server_secret: &[u8], listing_id: &[u8]) -> Option<Vec<u8>> {
    if blob.len() < 13 {
        return None;
    }
    let (nonce_bytes, ciphertext) = blob.split_at(12);
    let key = derive_listing_key(server_secret, listing_id)?;
    let cipher = ChaCha20Poly1305::new_from_slice(&key).ok()?;
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher.decrypt(nonce, ciphertext).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> Vec<u8> {
        b"test-server-secret-32-bytes-long!".to_vec()
    }

    fn test_order_id() -> Vec<u8> {
        b"test-order-id-00000000001".to_vec()
    }

    #[test]
    fn test_roundtrip() {
        let plaintext = b"{\"state\":\"pending\",\"currency\":\"BTC\"}";
        let blob = encrypt_order_blob(plaintext, &test_key(), &test_order_id()).unwrap();
        let decrypted = decrypt_order_blob(&blob, &test_key(), &test_order_id());
        assert_eq!(decrypted, Some(plaintext.to_vec()));
    }

    #[test]
    fn test_wrong_key_fails() {
        let plaintext = b"test-data";
        let key1 = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let key2 = b"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let blob = encrypt_order_blob(plaintext, key1, &test_order_id()).unwrap();
        let result = decrypt_order_blob(&blob, key2, &test_order_id());
        assert!(result.is_none());
    }

    #[test]
    fn test_wrong_order_id_fails() {
        let plaintext = b"test-data";
        let blob = encrypt_order_blob(plaintext, &test_key(), b"order-1").unwrap();
        let result = decrypt_order_blob(&blob, &test_key(), b"order-2");
        assert!(result.is_none());
    }

    #[test]
    fn test_tampered_blob_fails() {
        let plaintext = b"sensitive-order-data";
        let mut blob = encrypt_order_blob(plaintext, &test_key(), &test_order_id()).unwrap();
        blob[12] ^= 0x01;
        let result = decrypt_order_blob(&blob, &test_key(), &test_order_id());
        assert!(result.is_none());
    }

    #[test]
    fn test_reencrypt() {
        let old = b"{\"state\":\"pending\"}";
        let new = b"{\"state\":\"funded\"}";
        let blob = encrypt_order_blob(old, &test_key(), &test_order_id()).unwrap();
        let reblob = reencrypt_order_blob(&blob, new, &test_key(), &test_order_id());
        assert!(reblob.is_some());
        let decrypted = decrypt_order_blob(&reblob.unwrap(), &test_key(), &test_order_id());
        assert_eq!(decrypted, Some(new.to_vec()));
    }

    #[test]
    fn test_reencrypt_wrong_old_key_fails() {
        let old = b"old-data";
        let blob = encrypt_order_blob(old, b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", &test_order_id()).unwrap();
        let result = reencrypt_order_blob(&blob, b"new-data", &test_key(), &test_order_id());
        assert!(result.is_none());
    }

    #[test]
    fn test_empty_plaintext() {
        let blob = encrypt_order_blob(b"", &test_key(), &test_order_id()).unwrap();
        let decrypted = decrypt_order_blob(&blob, &test_key(), &test_order_id());
        assert_eq!(decrypted, Some(vec![]));
    }

    #[test]
    fn test_different_nonces() {
        let plaintext = b"same-data";
        let blob1 = encrypt_order_blob(plaintext, &test_key(), &test_order_id()).unwrap();
        let blob2 = encrypt_order_blob(plaintext, &test_key(), &test_order_id()).unwrap();
        assert_ne!(blob1, blob2);
    }

    #[test]
    fn test_short_blob() {
        let result = decrypt_order_blob(b"too-short", &test_key(), &test_order_id());
        assert!(result.is_none());
    }

    #[test]
    fn test_listing_roundtrip() {
        let plaintext = b"{\"status\":\"active\",\"currency\":\"BTC\"}";
        let lid = b"test-listing-id-0000001";
        let blob = encrypt_listing_blob(plaintext, &test_key(), lid).unwrap();
        let decrypted = decrypt_listing_blob(&blob, &test_key(), lid);
        assert_eq!(decrypted, Some(plaintext.to_vec()));
    }

    #[test]
    fn test_listing_wrong_key_fails() {
        let plaintext = b"test-data";
        let key1 = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let key2 = b"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let lid = b"test-listing-id-0000001";
        let blob = encrypt_listing_blob(plaintext, key1, lid).unwrap();
        let result = decrypt_listing_blob(&blob, key2, lid);
        assert!(result.is_none());
    }

    #[test]
    fn test_listing_wrong_id_fails() {
        let plaintext = b"test-data";
        let blob = encrypt_listing_blob(plaintext, &test_key(), b"listing-1").unwrap();
        let result = decrypt_listing_blob(&blob, &test_key(), b"listing-2");
        assert!(result.is_none());
    }

    #[test]
    fn test_listing_empty_plaintext() {
        let lid = b"test-listing-id-0000001";
        let blob = encrypt_listing_blob(b"", &test_key(), lid).unwrap();
        let decrypted = decrypt_listing_blob(&blob, &test_key(), lid);
        assert_eq!(decrypted, Some(vec![]));
    }

    #[test]
    fn test_listing_tampered_fails() {
        let plaintext = b"sensitive-data";
        let lid = b"test-listing-id-0000001";
        let mut blob = encrypt_listing_blob(plaintext, &test_key(), lid).unwrap();
        blob[12] ^= 0x01;
        let result = decrypt_listing_blob(&blob, &test_key(), lid);
        assert!(result.is_none());
    }

    #[test]
    fn test_listing_different_nonces() {
        let plaintext = b"same-data";
        let lid = b"test-listing-id-0000001";
        let blob1 = encrypt_listing_blob(plaintext, &test_key(), lid).unwrap();
        let blob2 = encrypt_listing_blob(plaintext, &test_key(), lid).unwrap();
        assert_ne!(blob1, blob2);
    }

    #[test]
    fn test_ecdh_roundtrip() {
        let server_sk_bytes = [42u8; 32];
        let server_sk = StaticSecret::from(server_sk_bytes);
        let server_pk = XPublicKey::from(&server_sk);
        let server_pk_arr: [u8; 32] = *server_pk.as_bytes();

        let plaintext = b"{\"state\":\"pending\",\"currency\":\"BTC\"}";
        let blob = encrypt_ecdh_blob(plaintext, &server_pk_arr).unwrap();
        let decrypted = decrypt_ecdh_blob(&blob, &server_sk_bytes);
        assert_eq!(decrypted, Some(plaintext.to_vec()));
    }

    #[test]
    fn test_ecdh_wrong_key_fails() {
        let alice_sk = StaticSecret::random_from_rng(OsRng);
        let alice_pk = XPublicKey::from(&alice_sk);
        let alice_pk_arr: [u8; 32] = *alice_pk.as_bytes();

        let bob_sk_bytes = [99u8; 32];

        let plaintext = b"secret-order-data";
        let blob = encrypt_ecdh_blob(plaintext, &alice_pk_arr).unwrap();
        let result = decrypt_ecdh_blob(&blob, &bob_sk_bytes);
        assert!(result.is_none(), "wrong key must not decrypt");
    }

    #[test]
    fn test_ecdh_short_blob_rejected() {
        let too_short = [0u8; ECDH_BLOB_MIN - 1];
        let result = decrypt_ecdh_blob(&too_short, &[42u8; 32]);
        assert!(result.is_none(), "short blob must be rejected");
    }

    #[test]
    fn test_listing_short_blob() {
        let lid = b"test-listing-id-0000001";
        let result = decrypt_listing_blob(b"too-short", &test_key(), lid);
        assert!(result.is_none());
    }
}
