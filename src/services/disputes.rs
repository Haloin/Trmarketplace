//! Disputes service — blind pass-through for opaque dispute blobs.

use axum::{
    extract::{Path, State, Extension, Json},
    Router,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};

use crate::gateway::state::AppState;
use crate::gateway::auth_common::AuthPubkey;
use crate::error::AppError;
use crate::crypto::blind_sig;
use uuid::Uuid;

#[derive(Deserialize)]
pub struct OpenDisputeRequest {
    pub order_id: String,
    /// Opaque client-encrypted dispute blob (base64). Server stores as-is.
    pub client_encrypted_blob: String,
    /// Hex-encoded ed25519 signature over (order_id, prev_version, new_blob_sha256, nonce).
    pub transition_signature: String,
    pub nonce: String,
}

#[derive(Deserialize)]
pub struct UpdateDisputeRequest {
    /// New opaque dispute blob (base64). Replaces the existing one.
    pub client_encrypted_blob: String,
    pub transition_signature: String,
    pub nonce: String,
}

#[derive(Deserialize)]
pub struct ResolveDisputeRequest {
    /// Admin's signed outcome blob.
    pub outcome_blob: String,
    pub admin_signature: String,
    /// Random nonce for the request body (replay protection).
    pub nonce: String,
    /// Blinded RSA admin token signature (hex).
    pub token_signature: Option<String>,
    /// Token message hash that was blindly signed (hex).
    pub token_message: Option<String>,
    /// Nonce embedded in the token message.
    pub token_nonce: Option<String>,
    /// Hour bucket when the token was issued (±1 hour tolerance).
    pub token_expiry_hour: Option<i64>,
}

#[derive(Serialize)]
pub struct DisputeResponse {
    pub id: String,
    pub order_id: String,
    pub client_encrypted_blob: Option<String>,
    pub version: i64,
    pub has_dispute: bool,
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/disputes", post(open_dispute))
        .route("/disputes/:id", get(get_dispute))
        .route("/disputes/:id/update", post(update_dispute))
        .route("/disputes/:id/resolve", post(resolve_dispute))
}

const MAX_DISPUTE_BLOB_BYTES: usize = 512 * 1024;

async fn open_dispute(
    State(state): State<AppState>,
    Extension(AuthPubkey(_pubkey_hash)): Extension<AuthPubkey>,
    Json(req): Json<OpenDisputeRequest>,
) -> Result<Json<DisputeResponse>, AppError> {
    let order_id_bytes = hex::decode(&req.order_id)
        .map_err(|_| AppError::BadRequest("Invalid order_id".into()))?;

    let blob = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &req.client_encrypted_blob)
        .map_err(|e| AppError::BadRequest(format!("Invalid client_encrypted_blob base64: {e}")))?;
    if blob.len() > MAX_DISPUTE_BLOB_BYTES {
        return Err(AppError::BadRequest("dispute blob too large".into()));
    }

    if !check_dispute_nonce_replay(&req.order_id, &req.nonce) {
        return Err(AppError::Conflict("Dispute nonce already used".into()));
    }

    let dispute_id = Uuid::new_v4().to_string();
    let new_version: i64 = {
        // TOCTOU: read current version, conditional update with bump.
        let current: Option<(i64,)> = sqlx::query_as(
            "SELECT version FROM orders WHERE id = ?1"
        )
        .bind(&order_id_bytes)
        .fetch_optional(&state.pool)
        .await
        .map_err(|e| AppError::Internal(format!("DB error: {e}")))?;
        let v = match current {
            Some((v,)) => v,
            None => return Err(AppError::NotFound("Order not found".into())),
        };
        let result = sqlx::query(
            "UPDATE orders SET dispute_client_blob = ?1, has_dispute = 1, version = version + 1 WHERE id = ?2 AND version = ?3"
        )
        .bind(&blob)
        .bind(&order_id_bytes)
        .bind(v)
        .execute(&state.pool)
        .await
        .map_err(|e| AppError::Internal(format!("DB error: {e}")))?;
        if result.rows_affected() == 0 {
            return Err(AppError::Conflict("Order was modified by another request".into()));
        }
        v + 1
    };

    Ok(Json(DisputeResponse {
        id: dispute_id,
        order_id: req.order_id,
        client_encrypted_blob: Some(req.client_encrypted_blob),
        version: new_version,
        has_dispute: true,
    }))
}

async fn get_dispute(
    State(state): State<AppState>,
    Extension(AuthPubkey(_pubkey_hash)): Extension<AuthPubkey>,
    Path(id): Path<String>,
) -> Result<Json<DisputeResponse>, AppError> {
    // Disputes live on the orders row; path param is treated as order_id.
    let order_id_bytes = hex::decode(&id)
        .map_err(|_| AppError::BadRequest("Invalid id".into()))?;

    let row: Option<(i64, Option<Vec<u8>>, i64)> = sqlx::query_as(
        "SELECT version, dispute_client_blob, has_dispute FROM orders WHERE id = ?1"
    )
    .bind(&order_id_bytes)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| AppError::Internal(format!("DB error: {e}")))?;

    let (version, blob, has_dispute) = row
        .ok_or_else(|| AppError::NotFound("Dispute not found".into()))?;

    if has_dispute == 0 {
        return Err(AppError::NotFound("No dispute for this order".into()));
    }

    let blob_b64 = blob.map(|b| {
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b)
    });

    Ok(Json(DisputeResponse {
        id,
        order_id: hex::encode(&order_id_bytes),
        client_encrypted_blob: blob_b64,
        version,
        has_dispute: true,
    }))
}

async fn update_dispute(
    State(state): State<AppState>,
    Extension(AuthPubkey(_pubkey_hash)): Extension<AuthPubkey>,
    Path(id): Path<String>,
    Json(req): Json<UpdateDisputeRequest>,
) -> Result<Json<DisputeResponse>, AppError> {
    let order_id_bytes = hex::decode(&id)
        .map_err(|_| AppError::BadRequest("Invalid id".into()))?;

    let blob = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &req.client_encrypted_blob)
        .map_err(|e| AppError::BadRequest(format!("Invalid client_encrypted_blob base64: {e}")))?;
    if blob.len() > MAX_DISPUTE_BLOB_BYTES {
        return Err(AppError::BadRequest("dispute blob too large".into()));
    }

    if !check_dispute_nonce_replay(&id, &req.nonce) {
        return Err(AppError::Conflict("Dispute nonce already used".into()));
    }

    let current: Option<(i64,)> = sqlx::query_as(
        "SELECT version FROM orders WHERE id = ?1"
    )
    .bind(&order_id_bytes)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| AppError::Internal(format!("DB error: {e}")))?;
    let v = match current {
        Some((v,)) => v,
        None => return Err(AppError::NotFound("Dispute not found".into())),
    };

    let result = sqlx::query(
        "UPDATE orders SET dispute_client_blob = ?1, version = version + 1 WHERE id = ?2 AND version = ?3"
    )
    .bind(&blob)
    .bind(&order_id_bytes)
    .bind(v)
    .execute(&state.pool)
    .await
    .map_err(|e| AppError::Internal(format!("DB error: {e}")))?;
    if result.rows_affected() == 0 {
        return Err(AppError::Conflict("Order was modified by another request".into()));
    }

    Ok(Json(DisputeResponse {
        id: id.clone(),
        order_id: id,
        client_encrypted_blob: Some(req.client_encrypted_blob),
        version: v + 1,
        has_dispute: true,
    }))
}

async fn resolve_dispute(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<ResolveDisputeRequest>,
) -> Result<Json<DisputeResponse>, AppError> {
    // Verify blind-signed admin token.
    let admin_kp = state.admin_keypair.as_ref()
        .ok_or_else(|| AppError::Internal("Admin keypair not configured".into()))?;

    let sig_bytes = req.token_signature.as_ref()
        .and_then(|s| hex::decode(s).ok())
        .ok_or_else(|| AppError::BadRequest("Missing or invalid token_signature".into()))?;
    let msg_bytes = req.token_message.as_ref()
        .and_then(|s| hex::decode(s).ok())
        .ok_or_else(|| AppError::BadRequest("Missing or invalid token_message".into()))?;
    let token_nonce_hex = req.token_nonce.as_ref()
        .ok_or_else(|| AppError::BadRequest("Missing token_nonce".into()))?;
    let token_nonce_bytes = hex::decode(token_nonce_hex)
        .map_err(|_| AppError::BadRequest("Invalid token_nonce hex".into()))?;
    let token_expiry = req.token_expiry_hour
        .ok_or_else(|| AppError::BadRequest("Missing token_expiry_hour".into()))?;

    if msg_bytes.len() != 32 {
        return Err(AppError::BadRequest("token_message must be 32 bytes".into()));
    }
    let mut msg_hash = [0u8; 32];
    msg_hash.copy_from_slice(&msg_bytes);

    // Reconstruct expected message from request context.
    let expected = blind_sig::compose_token_message(
        "dispute:resolve",
        &id,
        &token_nonce_bytes,
        token_expiry as u64,
    );
    if msg_hash != expected {
        return Err(AppError::Forbidden("Token message does not match request context".into()));
    }

    // Verify the RSA blind signature.
    if !blind_sig::verify_token(&msg_hash, &sig_bytes, &admin_kp.public) {
        return Err(AppError::Forbidden("Invalid admin token signature".into()));
    }

    // Check token expiry (±1 hour tolerance for clock skew).
    let now_hour = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() / 3600) as i64;
    if (token_expiry - now_hour).abs() > 1 {
        return Err(AppError::Forbidden("Admin token expired or not yet valid".into()));
    }

    // Check token nonce replay (in-process cache).
    if !check_admin_token_replay(&id, token_nonce_hex) {
        return Err(AppError::Conflict("Admin token nonce already used".into()));
    }

    let order_id_bytes = hex::decode(&id)
        .map_err(|_| AppError::BadRequest("Invalid id".into()))?;

    let outcome = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &req.outcome_blob)
        .map_err(|e| AppError::BadRequest(format!("Invalid outcome_blob base64: {e}")))?;
    if outcome.len() > MAX_DISPUTE_BLOB_BYTES {
        return Err(AppError::BadRequest("outcome blob too large".into()));
    }

    // The outcome blob is stored in dispute_client_blob. The worker (which
    // holds worker_key) reads it, decodes the admin's intent, and applies
    // the state transition. The API just records the resolution.
    let current: Option<(i64,)> = sqlx::query_as(
        "SELECT version FROM orders WHERE id = ?1"
    )
    .bind(&order_id_bytes)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| AppError::Internal(format!("DB error: {e}")))?;
    let v = match current {
        Some((v,)) => v,
        None => return Err(AppError::NotFound("Dispute not found".into())),
    };

    let result = sqlx::query(
        "UPDATE orders SET dispute_client_blob = ?1, has_dispute = 0, version = version + 1 WHERE id = ?2 AND version = ?3"
    )
    .bind(&outcome)
    .bind(&order_id_bytes)
    .bind(v)
    .execute(&state.pool)
    .await
    .map_err(|e| AppError::Internal(format!("DB error: {e}")))?;
    if result.rows_affected() == 0 {
        return Err(AppError::Conflict("Order was modified by another request".into()));
    }

    tracing::info!(order_id = %id, "Dispute resolved by admin");

    Ok(Json(DisputeResponse {
        id: id.clone(),
        order_id: id,
        client_encrypted_blob: Some(req.outcome_blob),
        version: v + 1,
        has_dispute: false,
    }))
}

fn check_dispute_nonce_replay(order_id: &str, nonce: &str) -> bool {
    use std::collections::HashSet;
    use std::sync::Mutex;
    use once_cell::sync::Lazy;

    static DISPUTE_NONCES: Lazy<Mutex<HashSet<String>>> = Lazy::new(|| Mutex::new(HashSet::new()));
    let key = format!("{}:{}", order_id, nonce);
    let mut set = DISPUTE_NONCES.lock().unwrap_or_else(|e| e.into_inner());
    set.insert(key)
}

fn check_admin_token_replay(action_id: &str, nonce: &str) -> bool {
    use std::collections::HashSet;
    use std::sync::Mutex;
    use once_cell::sync::Lazy;

    static ADMIN_TOKEN_NONCES: Lazy<Mutex<HashSet<String>>> = Lazy::new(|| Mutex::new(HashSet::new()));
    let key = format!("{}:{}", action_id, nonce);
    let mut set = ADMIN_TOKEN_NONCES.lock().unwrap_or_else(|e| e.into_inner());
    set.insert(key)
}
