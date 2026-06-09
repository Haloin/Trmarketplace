use ciborium::value::Value as CborValue;
use ed25519_dalek::{Signer, SigningKey};
use wasm_bindgen::prelude::*;

const TRANSITION_SIG_VERSION: u8 = 1;

fn transition_to_cbor(
    order_id: &[u8],
    prev_version: i64,
    new_blob_sha256: &[u8],
    nonce: &[u8],
    hour_bucket: u64,
) -> Result<Vec<u8>, JsValue> {
    if new_blob_sha256.len() != 32 {
        return Err(JsValue::from_str("new_blob_sha256 must be 32 bytes"));
    }
    let mut map: std::collections::BTreeMap<i64, CborValue> = std::collections::BTreeMap::new();
    map.insert(
        1,
        CborValue::Integer(ciborium::value::Integer::from(
            TRANSITION_SIG_VERSION as i64,
        )),
    );
    map.insert(2, CborValue::Bytes(order_id.to_vec()));
    map.insert(
        3,
        CborValue::Integer(ciborium::value::Integer::from(prev_version)),
    );
    map.insert(4, CborValue::Bytes(new_blob_sha256.to_vec()));
    map.insert(5, CborValue::Bytes(nonce.to_vec()));
    map.insert(
        6,
        CborValue::Integer(ciborium::value::Integer::from(hour_bucket as i64)),
    );

    let mut buf = Vec::new();
    ciborium::into_writer(
        &CborValue::Map(
            map.into_iter()
                .map(|(k, v)| {
                    (
                        CborValue::Integer(ciborium::value::Integer::from(k)),
                        v,
                    )
                })
                .collect(),
        ),
        &mut buf,
    )
    .map_err(|e| JsValue::from_str(&format!("CBOR encode failed: {e}")))?;
    Ok(buf)
}

/// Sign a state transition over canonical CBOR.
/// `secret_key` is a 32-byte ed25519 seed. Returns 64-byte signature.
#[wasm_bindgen]
pub fn sign_transition(
    secret_key: &[u8],
    order_id: &[u8],
    prev_version: i64,
    new_blob_sha256: &[u8],
    nonce: &[u8],
    hour_bucket: u64,
) -> Result<Vec<u8>, JsValue> {
    if secret_key.len() != 32 {
        return Err(JsValue::from_str("secret_key must be 32 bytes"));
    }
    let seed: [u8; 32] = secret_key
        .try_into()
        .map_err(|_| JsValue::from_str("invalid secret key"))?;
    let signing_key = SigningKey::from_bytes(&seed);
    let cbor = transition_to_cbor(order_id, prev_version, new_blob_sha256, nonce, hour_bucket)?;
    Ok(signing_key.sign(&cbor).to_bytes().to_vec())
}
