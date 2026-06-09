//! Chaum blind RSA signatures for unlinkable admin authorization.

use num_bigint_dig::{BigUint, BigInt, Sign};
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use sha2::{Digest, Sha256};
use rand::RngCore;

/// Label prefix for admin action token messages.
pub const ADMIN_ACTION_LABEL: &str = "tor-mkt:admin:v1";

/// Minimum RSA key size for blind signatures.
pub const BLIND_SIG_MIN_BITS: usize = 2048;
pub const BLIND_SIG_MAX_BITS: usize = 4096;

#[derive(Clone)]
pub struct AdminKeypair {
    pub private: rsa::RsaPrivateKey,
    pub public: rsa::RsaPublicKey,
}

impl AdminKeypair {
    /// Load an AdminKeypair from a PKCS#1 DER hex-encoded private key.
    pub fn from_hex(hex_str: &str) -> Result<Self, String> {
        use rsa::pkcs1::DecodeRsaPrivateKey;
        let der = hex::decode(hex_str).map_err(|e| format!("invalid hex: {e}"))?;
        let private = rsa::RsaPrivateKey::from_pkcs1_der(&der)
            .map_err(|e| format!("invalid PKCS#1 DER: {e}"))?;
        let public = rsa::RsaPublicKey::from(&private);
        Ok(Self { private, public })
    }

    /// Serialize the private key to PKCS#1 DER hex.
    pub fn privkey_hex(&self) -> Result<String, String> {
        use rsa::pkcs1::EncodeRsaPrivateKey;
        let der = self.private.to_pkcs1_der()
            .map_err(|e| format!("PKCS#1 DER encoding: {e}"))?;
        Ok(hex::encode(der.as_bytes()))
    }

    /// Serialize the public key to PKCS#1 DER hex.
    pub fn pubkey_hex(&self) -> Result<String, String> {
        use rsa::pkcs1::EncodeRsaPublicKey;
        let der = self.public.to_pkcs1_der()
            .map_err(|e| format!("public key DER encoding: {e}"))?;
        Ok(hex::encode(der.as_bytes()))
    }
}

/// Compose the 32-byte SHA256 token message for an admin action.
pub fn compose_token_message(
    domain: &str,
    action_id: &str,
    nonce: &[u8],
    expiry_hour: u64,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ADMIN_ACTION_LABEL.as_bytes());
    hasher.update(b":");
    hasher.update(domain.as_bytes());
    hasher.update(b":");
    hasher.update(action_id.as_bytes());
    hasher.update(b":");
    hasher.update(nonce);
    hasher.update(b":");
    hasher.update(expiry_hour.to_string().as_bytes());
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Generate a fresh RSA keypair for blind signing.
pub fn generate_admin_keypair(bits: usize) -> AdminKeypair {
    let bits = bits.clamp(BLIND_SIG_MIN_BITS, BLIND_SIG_MAX_BITS);
    let mut rng = rand::rngs::OsRng;
    let private = rsa::RsaPrivateKey::new(&mut rng, bits)
        .expect("RSA key generation failed");
    let public = rsa::RsaPublicKey::from(&private);
    AdminKeypair { private, public }
}

/// Blind a token message hash (returns blinded bytes and secret blinding factor).
pub fn blind_message(
    message_hash: &[u8; 32],
    pub_key: &rsa::RsaPublicKey,
) -> (Vec<u8>, Vec<u8>) {
    let n = pub_key.n();
    let e = pub_key.e();
    let m = BigUint::from_bytes_be(message_hash);

    // Generate random r in [1, n-1].
    let n_bits = n.bits();
    let n_bytes = n_bits.div_ceil(8);
    let mut r_bytes = vec![0u8; n_bytes];
    rand::rngs::OsRng.fill_bytes(&mut r_bytes);
    let excess = n_bytes * 8 - n_bits;
    r_bytes[0] &= 0xff >> excess;
    if r_bytes.iter().all(|&b| b == 0) {
        r_bytes[n_bytes - 1] = 1;
    }
    let r = BigUint::from_bytes_be(&r_bytes);

    // blinded = m * r^e mod n
    let r_e = r.modpow(e, n);
    let blinded = (&m * &r_e) % n;

    (blinded.to_bytes_be(), r.to_bytes_be())
}

/// Sign a blinded message (server never sees plaintext).
pub fn sign_blinded(
    blinded: &[u8],
    priv_key: &rsa::RsaPrivateKey,
) -> Vec<u8> {
    let d = priv_key.d();
    let n = priv_key.n();
    let b = BigUint::from_bytes_be(blinded);
    b.modpow(d, n).to_bytes_be()
}

/// Recover the true signature using the blinding factor.
pub fn unblind_signature(
    blinded_sig: &[u8],
    blinding_factor: &[u8],
    pub_key: &rsa::RsaPublicKey,
) -> Vec<u8> {
    let n = pub_key.n();
    let s_prime = BigUint::from_bytes_be(blinded_sig);
    let r = BigUint::from_bytes_be(blinding_factor);
    let r_inv = modinv(&r, n).expect("blinding factor must be coprime to RSA modulus n");
    let sig = (&s_prime * &r_inv) % n;
    sig.to_bytes_be()
}

/// Verify that `signature` is a valid RSA signature on `message_hash`.
pub fn verify_token(
    message_hash: &[u8; 32],
    signature: &[u8],
    pub_key: &rsa::RsaPublicKey,
) -> bool {
    let e = pub_key.e();
    let n = pub_key.n();
    let sig = BigUint::from_bytes_be(signature);
    let m = BigUint::from_bytes_be(message_hash);

    if sig >= *n {
        return false;
    }

    let recovered = sig.modpow(e, n);
    recovered == m
}

/// Compute `a^(-1) mod m` using Extended Euclidean (Stein's variant).
///
/// Returns None if `gcd(a, m) != 1`.
fn modinv(a: &BigUint, m: &BigUint) -> Option<BigUint> {
    let a_s = BigInt::from_bytes_be(Sign::Plus, &a.to_bytes_be());
    let m_s = BigInt::from_bytes_be(Sign::Plus, &m.to_bytes_be());

    let result = num_integer::Integer::extended_gcd(&a_s, &m_s);
    let one = BigInt::from(1u32);
    if result.gcd != one {
        return None;
    }
    let x = result.x;
    if x.sign() == Sign::Minus {
        let (_, x_abs) = x.to_bytes_be();
        let x_abs = BigUint::from_bytes_be(&x_abs);
        Some(m - (&x_abs % m))
    } else {
        let (_, x_bytes) = x.to_bytes_be();
        Some(BigUint::from_bytes_be(&x_bytes) % m)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blind_signature_roundtrip() {
        let kp = generate_admin_keypair(2048);
        let action_id = "order-abc-123";
        let nonce = b"test-nonce-001";
        let msg_hash = compose_token_message("test:domain", action_id, nonce, 1234567890);

        let (blinded, factor) = blind_message(&msg_hash, &kp.public);
        assert!(!blinded.is_empty(), "blinded message must not be empty");
        assert!(!factor.is_empty(), "blinding factor must not be empty");

        let blinded_sig = sign_blinded(&blinded, &kp.private);
        assert!(!blinded_sig.is_empty(), "blinded signature must not be empty");
        assert_ne!(blinded_sig, blinded, "signature must differ from blinded message");

        let sig = unblind_signature(&blinded_sig, &factor, &kp.public);

        let ok = verify_token(&msg_hash, &sig, &kp.public);
        assert!(ok, "valid blind signature round-trip must verify");
    }

    #[test]
    fn test_wrong_key_rejected() {
        let kp1 = generate_admin_keypair(2048);
        let kp2 = generate_admin_keypair(2048);

        let msg_hash = compose_token_message("test:domain", "order-2", b"nonce-x", 999999);
        let (blinded, factor) = blind_message(&msg_hash, &kp1.public);
        let blinded_sig = sign_blinded(&blinded, &kp1.private);
        let sig = unblind_signature(&blinded_sig, &factor, &kp1.public);

        // Verify with WRONG public key
        let ok = verify_token(&msg_hash, &sig, &kp2.public);
        assert!(!ok, "wrong key must NOT verify");
    }

    #[test]
    fn test_tampered_message_rejected() {
        let kp = generate_admin_keypair(2048);

        let msg_hash = compose_token_message("test:domain", "order-3", b"nonce-y", 555555);
        let (blinded, factor) = blind_message(&msg_hash, &kp.public);
        let blinded_sig = sign_blinded(&blinded, &kp.private);
        let sig = unblind_signature(&blinded_sig, &factor, &kp.public);

        // Tamper with the message hash
        let mut tampered = msg_hash;
        tampered[0] ^= 0x01;

        let ok = verify_token(&tampered, &sig, &kp.public);
        assert!(!ok, "tampered message must NOT verify");
    }

    #[test]
    fn test_tampered_signature_rejected() {
        let kp = generate_admin_keypair(2048);
        let msg_hash = compose_token_message("test:domain", "order-4", b"nonce-z", 777777);

        let (blinded, factor) = blind_message(&msg_hash, &kp.public);
        let blinded_sig = sign_blinded(&blinded, &kp.private);
        let mut sig = unblind_signature(&blinded_sig, &factor, &kp.public);

        if !sig.is_empty() {
            sig[0] ^= 0xff;
        }

        let ok = verify_token(&msg_hash, &sig, &kp.public);
        assert!(!ok, "tampered signature must NOT verify");
    }

    #[test]
    fn test_compose_token_message_deterministic() {
        let h1 = compose_token_message("dispute:resolve", "abc", b"nonce1", 1000);
        let h2 = compose_token_message("dispute:resolve", "abc", b"nonce1", 1000);
        assert_eq!(h1, h2, "same inputs must produce same hash");

        let h3 = compose_token_message("dispute:resolve", "abc", b"nonce1", 1001);
        assert_ne!(h1, h3, "different expiry must produce different hash");

        let h4 = compose_token_message("dispute:resolve", "abd", b"nonce1", 1000);
        assert_ne!(h1, h4, "different action_id must produce different hash");
    }
}
