use axum::{
    extract::Request,
    middleware::Next,
    response::{IntoResponse, Response},
};
use ed25519_dalek::VerifyingKey;
use hmac::{Hmac, Mac};
use once_cell::sync::Lazy;
use sha2::Sha256;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use subtle::ConstantTimeEq;

use crate::crypto::hash::hash_pubkey;
use crate::gateway::auth_common::{self, AuthPubkey};
use crate::gateway::state::AppState;
use crate::error::AppError;

type HmacSha256 = Hmac<Sha256>;

static REPLAY_CACHE: Lazy<Mutex<HashMap<u64, HashSet<Vec<u8>>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

fn compute_hmac(auth_key: &[u8], pubkey: &[u8], hour_bucket: u64, path: &str, nonce: &[u8]) -> Option<Vec<u8>> {
    let mut mac = HmacSha256::new_from_slice(auth_key).ok()?;
    mac.update(pubkey);
    mac.update(&hour_bucket.to_le_bytes());
    mac.update(path.as_bytes());
    mac.update(nonce);
    Some(mac.finalize().into_bytes().to_vec())
}

fn build_challenge(hmac: &[u8], pubkey: &[u8], hour_bucket: u64, nonce: &[u8]) -> Vec<u8> {
    let mut challenge = Vec::with_capacity(hmac.len() + pubkey.len() + 8 + nonce.len());
    challenge.extend_from_slice(hmac);
    challenge.extend_from_slice(pubkey);
    challenge.extend_from_slice(&hour_bucket.to_le_bytes());
    challenge.extend_from_slice(nonce);
    challenge
}

fn verify_hmac(auth_key: &[u8], pubkey: &[u8], hour_bucket: u64, path: &str, nonce: &[u8], expected: &[u8]) -> bool {
    match compute_hmac(auth_key, pubkey, hour_bucket, path, nonce) {
        Some(computed) => computed.len() == expected.len() && computed.ct_eq(expected).into(),
        None => false,
    }
}

fn verify_signature(pk_bytes: &[u8; 32], hmac: &[u8], pubkey: &[u8], hour_bucket: u64, nonce: &[u8], sig_bytes: &[u8]) -> bool {
    let challenge = build_challenge(hmac, pubkey, hour_bucket, nonce);
    let pk = match VerifyingKey::from_bytes(pk_bytes) {
        Ok(pk) => pk,
        Err(_) => return false,
    };
    let sig = match ed25519_dalek::Signature::from_slice(sig_bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };
    use ed25519_dalek::Verifier;
    pk.verify(&challenge, &sig).is_ok()
}

fn check_replay(hour_bucket: u64, nonce: &[u8]) -> bool {
    let mut cache = REPLAY_CACHE.lock().unwrap_or_else(|e| e.into_inner());
    cache.retain(|&bucket, _| bucket >= hour_bucket.saturating_sub(1));
    let entry = cache.entry(hour_bucket).or_insert_with(HashSet::new);
    entry.insert(nonce.to_vec())
}

pub async fn stateless_auth_middleware(
    mut request: Request,
    next: Next,
    state: Arc<AppState>,
) -> Response {
    let path = request.uri().path().to_string();

    if path.starts_with("/auth/") || path.starts_with("/api/auth/") {
        return next.run(request).await;
    }

    let (pubkey_hex, hmac_hex, hour_str, nonce_hex, sig_hex) = {
        let headers = request.headers();
        let pk = match headers.get("x-auth-pubkey").and_then(|v| v.to_str().ok()) {
            Some(v) => v,
            None => return AppError::AuthFailed("missing pubkey".into()).into_response(),
        };
        let hmac = match headers.get("x-auth-hmac").and_then(|v| v.to_str().ok()) {
            Some(v) => v,
            None => return AppError::AuthFailed("missing hmac".into()).into_response(),
        };
        let hour = match headers.get("x-auth-hour").and_then(|v| v.to_str().ok()) {
            Some(v) => v,
            None => return AppError::AuthFailed("missing hour".into()).into_response(),
        };
        let nonce = match headers.get("x-auth-nonce").and_then(|v| v.to_str().ok()) {
            Some(v) => v,
            None => return AppError::AuthFailed("missing nonce".into()).into_response(),
        };
        let sig = match headers.get("x-auth-signature").and_then(|v| v.to_str().ok()) {
            Some(v) => v,
            None => return AppError::AuthFailed("missing signature".into()).into_response(),
        };
        (pk.to_string(), hmac.to_string(), hour.to_string(), nonce.to_string(), sig.to_string())
    };

    let pk_bytes = match hex::decode(&pubkey_hex) {
        Ok(b) => b,
        Err(_) => return AppError::AuthFailed("invalid pubkey hex".into()).into_response(),
    };
    let pk_array: [u8; 32] = match pk_bytes.clone().try_into() {
        Ok(a) => a,
        Err(_) => return AppError::AuthFailed("invalid pubkey length".into()).into_response(),
    };
    let hmac_bytes = match hex::decode(&hmac_hex) {
        Ok(b) => b,
        Err(_) => return AppError::AuthFailed("invalid hmac hex".into()).into_response(),
    };
    let hour_bucket: u64 = match hour_str.parse() {
        Ok(h) => h,
        Err(_) => return AppError::AuthFailed("invalid hour".into()).into_response(),
    };
    let nonce_bytes = match hex::decode(&nonce_hex) {
        Ok(b) => b,
        Err(_) => return AppError::AuthFailed("invalid nonce hex".into()).into_response(),
    };
    let sig_bytes = match hex::decode(&sig_hex) {
        Ok(b) => b,
        Err(_) => return AppError::AuthFailed("invalid sig hex".into()).into_response(),
    };

    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let current_hour = (now / 3600) as u64;
    if hour_bucket > current_hour || hour_bucket < current_hour.saturating_sub(1) {
        return AppError::AuthFailed("stale hour bucket".into()).into_response();
    }

    let auth_key = match auth_common::derive_auth_key(&state.config.server.server_secret, &pk_bytes) {
        Some(k) => k,
        None => return AppError::AuthFailed("key derivation failed".into()).into_response(),
    };

    if !verify_hmac(&auth_key, &pk_bytes, hour_bucket, &path, &nonce_bytes, &hmac_bytes) {
        return AppError::AuthFailed("hmac mismatch".into()).into_response();
    }

    if !verify_signature(&pk_array, &hmac_bytes, &pk_bytes, hour_bucket, &nonce_bytes, &sig_bytes) {
        return AppError::AuthFailed("signature mismatch".into()).into_response();
    }

    if !check_replay(hour_bucket, &nonce_bytes) {
        return AppError::AuthFailed("replay detected".into()).into_response();
    }

    let pubkey_hash = hash_pubkey(&pk_bytes);
    request.extensions_mut().insert(AuthPubkey(pubkey_hash.to_vec()));

    next.run(request).await
}
