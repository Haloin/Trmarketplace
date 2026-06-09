//! Ed25519 signatures over canonical CBOR for blind order updates.

use anyhow::{anyhow, Result};
use ciborium::value::Value as CborValue;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Wire-format version; bumping breaks deployed clients.
pub const TRANSITION_SIG_VERSION: u8 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransitionPayload {
    pub version: u8,
    pub order_id: Vec<u8>,
    /// Must match DB version before update (TOCTOU guard).
    pub prev_version: i64,
    pub new_blob_sha256: [u8; 32],
    pub nonce: Vec<u8>,
    pub hour_bucket: u64,
}

impl TransitionPayload {
    pub fn new(
        order_id: Vec<u8>,
        prev_version: i64,
        new_blob_sha256: [u8; 32],
        nonce: Vec<u8>,
        hour_bucket: u64,
    ) -> Self {
        Self {
            version: TRANSITION_SIG_VERSION,
            order_id,
            prev_version,
            new_blob_sha256,
            nonce,
            hour_bucket,
        }
    }

    /// Encode as canonical CBOR.
    /// We construct the CBOR map explicitly with sorted keys (integer
    /// tags) to guarantee deterministic output across implementations.
    pub fn to_cbor(&self) -> Result<Vec<u8>> {
        // Build CBOR map with integer keys (1..6) for compactness and
        // unambiguous field identification. Values are in canonical
        // order matching the field declaration order in the struct.
        let mut map: std::collections::BTreeMap<i64, CborValue> = std::collections::BTreeMap::new();
        map.insert(1, CborValue::Integer(ciborium::value::Integer::from(self.version as i64)));
        map.insert(2, CborValue::Bytes(self.order_id.clone()));
        map.insert(3, CborValue::Integer(ciborium::value::Integer::from(self.prev_version)));
        map.insert(4, CborValue::Bytes(self.new_blob_sha256.to_vec()));
        map.insert(5, CborValue::Bytes(self.nonce.clone()));
        map.insert(6, CborValue::Integer(ciborium::value::Integer::from(self.hour_bucket as i64)));

        let mut buf = Vec::new();
        ciborium::into_writer(&CborValue::Map(map.into_iter().map(|(k, v)| (CborValue::Integer(ciborium::value::Integer::from(k)), v)).collect()), &mut buf)
            .map_err(|e| anyhow!("CBOR encode: {e}"))?;
        Ok(buf)
    }
}

/// Result of a successful transition signature verification.
#[derive(Debug, Clone)]
pub struct VerifiedTransition {
    pub payload: TransitionPayload,
}

/// Sign a transition payload with an ed25519 key.
pub fn sign_transition(signing_key: &SigningKey, payload: &TransitionPayload) -> Result<[u8; 64]> {
    let cbor = payload.to_cbor()?;
    let sig = signing_key.sign(&cbor);
    Ok(sig.to_bytes())
}

/// Verify a transition signature over canonical CBOR.
pub fn verify_transition(
    verifying_key_bytes: &[u8; 32],
    payload: &TransitionPayload,
    signature_bytes: &[u8; 64],
) -> Result<VerifiedTransition> {
    let pk = VerifyingKey::from_bytes(verifying_key_bytes)
        .map_err(|e| anyhow!("Invalid verifying key: {e}"))?;
    let sig = Signature::from_bytes(signature_bytes);
    let cbor = payload.to_cbor()?;
    pk.verify(&cbor, &sig)
        .map_err(|_| anyhow!("Transition signature verification failed"))?;
    Ok(VerifiedTransition {
        payload: payload.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use rand::RngCore;
    use sha2::{Digest, Sha256};

    fn keypair() -> (SigningKey, VerifyingKey) {
        let mut secret = [0u8; 32];
        OsRng.fill_bytes(&mut secret);
        let sk = SigningKey::from_bytes(&secret);
        let vk = sk.verifying_key();
        (sk, vk)
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let (sk, vk) = keypair();

        let order_id = vec![1u8; 16];
        let new_blob = b"some opaque client-encrypted blob";
        let mut hasher = Sha256::new();
        hasher.update(new_blob);
        let new_blob_hash: [u8; 32] = hasher.finalize().into();
        let nonce = vec![0xABu8; 32];

        let payload = TransitionPayload::new(
            order_id.clone(),
            5,
            new_blob_hash,
            nonce.clone(),
            12345,
        );

        let sig_bytes = sign_transition(&sk, &payload).unwrap();
        let result = verify_transition(&vk.to_bytes(), &payload, &sig_bytes);
        assert!(result.is_ok(), "Valid signature should verify: {:?}", result.err());
    }

    #[test]
    fn test_tampered_prev_version_fails() {
        let (sk, vk) = keypair();
        let mut hasher = Sha256::new();
        hasher.update(b"blob");
        let hash: [u8; 32] = hasher.finalize().into();

        let payload = TransitionPayload::new(vec![1; 16], 5, hash, vec![1; 32], 100);
        let sig = sign_transition(&sk, &payload).unwrap();

        // Attacker changes prev_version
        let tampered = TransitionPayload::new(vec![1; 16], 6, hash, vec![1; 32], 100);
        let result = verify_transition(&vk.to_bytes(), &tampered, &sig);
        assert!(result.is_err(), "Tampered prev_version must fail");
    }

    #[test]
    fn test_tampered_blob_hash_fails() {
        let (sk, vk) = keypair();
        let mut hasher1 = Sha256::new();
        hasher1.update(b"blob A");
        let hash_a: [u8; 32] = hasher1.finalize().into();

        let payload = TransitionPayload::new(vec![1; 16], 5, hash_a, vec![1; 32], 100);
        let sig = sign_transition(&sk, &payload).unwrap();

        let mut hasher2 = Sha256::new();
        hasher2.update(b"blob B");
        let hash_b: [u8; 32] = hasher2.finalize().into();

        let tampered = TransitionPayload::new(vec![1; 16], 5, hash_b, vec![1; 32], 100);
        let result = verify_transition(&vk.to_bytes(), &tampered, &sig);
        assert!(result.is_err(), "Tampered blob hash must fail");
    }

    #[test]
    fn test_wrong_key_fails() {
        let (sk, _) = keypair();
        let (_, wrong_vk) = keypair();
        let mut hasher = Sha256::new();
        hasher.update(b"blob");
        let hash: [u8; 32] = hasher.finalize().into();

        let payload = TransitionPayload::new(vec![1; 16], 5, hash, vec![1; 32], 100);
        let sig = sign_transition(&sk, &payload).unwrap();

        let result = verify_transition(&wrong_vk.to_bytes(), &payload, &sig);
        assert!(result.is_err(), "Signature must not verify under wrong key");
    }

    #[test]
    fn test_canonical_cbor_is_deterministic() {
        // Same payload must produce same CBOR bytes (no random field
        // ordering). This is the property that makes signatures stable.
        let mut hasher = Sha256::new();
        hasher.update(b"blob");
        let hash: [u8; 32] = hasher.finalize().into();

        let p1 = TransitionPayload::new(vec![1; 16], 5, hash, vec![1; 32], 100);
        let p2 = TransitionPayload::new(vec![1; 16], 5, hash, vec![1; 32], 100);
        assert_eq!(p1.to_cbor().unwrap(), p2.to_cbor().unwrap());
    }
}
