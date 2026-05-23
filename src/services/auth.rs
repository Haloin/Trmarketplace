use axum::{
    extract::State,
    Json, Router,
    routing::post,
};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use once_cell::sync::Lazy;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::Mutex;

use crate::error::AppError;
use crate::gateway::state::AppState;

type HmacSha256 = Hmac<Sha256>;

const CHALLENGE_TTL_SECS: i64 = 300;

#[derive(Deserialize)]
pub struct ChallengeRequest {
    pub pubkey: String,
}

#[derive(Serialize)]
pub struct ChallengeResponse {
    pub challenge_id: String,
    pub challenge: String,
}

#[derive(Deserialize)]
pub struct VerifyRequest {
    pub pubkey: String,
    pub challenge_id: String,
    pub signature: String,
}

#[derive(Serialize)]
pub struct VerifyResponse {
    pub auth_key: String,
}

static CHALLENGES: Lazy<Mutex<HashMap<String, (Vec<u8>, i64)>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

fn cleanup_challenges() {
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let mut store = CHALLENGES.lock().unwrap_or_else(|e| e.into_inner());
    store.retain(|_, (_, exp)| *exp > now);
}

fn derive_auth_key(server_secret: &str, pubkey: &[u8]) -> Option<Vec<u8>> {
    let mut mac = HmacSha256::new_from_slice(server_secret.as_bytes()).ok()?;
    mac.update(b"auth_key_derivation_v1");
    mac.update(pubkey);
    Some(mac.finalize().into_bytes().to_vec())
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/auth/challenge", post(challenge))
        .route("/auth/verify", post(verify))
}

async fn challenge(
    State(_state): State<AppState>,
    Json(req): Json<ChallengeRequest>,
) -> Result<Json<ChallengeResponse>, AppError> {
    let pk_bytes = hex::decode(&req.pubkey)
        .map_err(|_| AppError::BadRequest("invalid pubkey hex".into()))?;
    if pk_bytes.len() != 32 {
        return Err(AppError::BadRequest("invalid pubkey length".into()));
    }

    let mut challenge_bytes = vec![0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut challenge_bytes);

    let mut id_bytes = vec![0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut id_bytes);
    let challenge_id = hex::encode(&id_bytes);

    let expires_at = time::OffsetDateTime::now_utc().unix_timestamp() + CHALLENGE_TTL_SECS;

    cleanup_challenges();
    let mut store = CHALLENGES.lock().unwrap_or_else(|e| e.into_inner());
    store.insert(challenge_id.clone(), (challenge_bytes.clone(), expires_at));

    Ok(Json(ChallengeResponse {
        challenge_id,
        challenge: hex::encode(&challenge_bytes),
    }))
}

async fn verify(
    State(state): State<AppState>,
    Json(req): Json<VerifyRequest>,
) -> Result<Json<VerifyResponse>, AppError> {
    let pk_bytes = hex::decode(&req.pubkey)
        .map_err(|_| AppError::BadRequest("invalid pubkey hex".into()))?;
    let pk_array: [u8; 32] = pk_bytes
        .try_into()
        .map_err(|_| AppError::BadRequest("invalid pubkey length".into()))?;

    let sig_bytes = hex::decode(&req.signature)
        .map_err(|_| AppError::BadRequest("invalid signature hex".into()))?;

    cleanup_challenges();

    let challenge_bytes = {
        let mut store = CHALLENGES.lock().unwrap_or_else(|e| e.into_inner());
        store
            .remove(&req.challenge_id)
            .ok_or(AppError::BadRequest("challenge not found or expired".into()))?
            .0
    };

    let pk = VerifyingKey::from_bytes(&pk_array)
        .map_err(|_| AppError::BadRequest("invalid pubkey".into()))?;

    let sig = Signature::from_slice(&sig_bytes)
        .map_err(|_| AppError::BadRequest("invalid signature encoding".into()))?;

    pk.verify(&challenge_bytes, &sig)
        .map_err(|_| AppError::BadRequest("signature verification failed".into()))?;

    let auth_key = derive_auth_key(&state.config.server.server_secret, &pk_array)
        .ok_or(AppError::Internal("auth key derivation failed".into()))?;

    Ok(Json(VerifyResponse {
        auth_key: hex::encode(&auth_key),
    }))
}
