use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

fn derive_order_key(server_secret: &[u8], order_id: &[u8]) -> Option<[u8; 32]> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(server_secret).ok()?;
    mac.update(b"oblivious-order-v1");
    mac.update(order_id);
    let result = mac.finalize().into_bytes();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    Some(key)
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

fn derive_listing_key(server_secret: &[u8], listing_id: &[u8]) -> Option<[u8; 32]> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(server_secret).ok()?;
    mac.update(b"oblivious-listing-v1");
    mac.update(listing_id);
    let result = mac.finalize().into_bytes();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    Some(key)
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
}
