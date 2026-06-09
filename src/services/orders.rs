//! Orders service — blind pass-through for opaque client-encrypted blobs.

use axum::{
    extract::{Path, State, Extension, Json},
    Router,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use crate::crypto::transition_sig::{verify_transition, TransitionPayload};
use crate::crypto::zk::floor_timestamp_6h;
use crate::gateway::state::AppState;
use crate::gateway::auth_common::{AuthPubkey, AuthPubkeyBytes};
use crate::error::AppError;

#[derive(Deserialize)]
pub struct CreateOrderRequest {
    /// Opaque client-encrypted order blob (base64). Server stores as-is.
    pub client_encrypted_blob: String,
    /// Lock period in days. Used to compute expiry_bucket.
    /// Default if omitted: 7 days.
    pub time_lock_days: Option<u64>,
    /// Random nonce. Server rejects duplicates within a 1-hour bucket.
    pub nonce: String,
}

#[derive(Deserialize)]
pub struct UpdateOrderRequest {
    /// New opaque client-encrypted order blob (base64). Replaces the existing.
    pub client_encrypted_blob: String,
    /// Ed25519 signature over canonical CBOR transition payload (hex).
    pub transition_signature: String,
    pub nonce: String,
    /// Hour bucket used in the signature payload. Must match the
    /// `x-auth-hour` header. Passed explicitly to avoid server/client
    /// clock skew causing signature mismatches at hour boundaries.
    pub hour_bucket: u64,
}

#[derive(Serialize)]
pub struct OrderResponse {
    pub id: String,
    pub client_encrypted_blob: Option<String>,
    pub day_bucket: i64,
    pub expiry_bucket: Option<i64>,
    pub version: i64,
    pub has_dispute: bool,
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/orders", post(create_order))
        .route("/orders/:id", get(get_order))
        .route("/orders/:id/update", post(update_order))
}

const MAX_ORDER_BLOB_BYTES: usize = 256 * 1024;

async fn create_order(
    State(state): State<AppState>,
    Extension(AuthPubkey(_pubkey_hash)): Extension<AuthPubkey>,
    Json(req): Json<CreateOrderRequest>,
) -> Result<Json<OrderResponse>, AppError> {
    let blob = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &req.client_encrypted_blob)
        .map_err(|e| AppError::BadRequest(format!("Invalid client_encrypted_blob base64: {e}")))?;
    if blob.is_empty() {
        return Err(AppError::BadRequest("client_encrypted_blob is empty".into()));
    }
    if blob.len() > MAX_ORDER_BLOB_BYTES {
        return Err(AppError::BadRequest("client_encrypted_blob too large".into()));
    }

    if !check_create_nonce_replay(&req.nonce) {
        return Err(AppError::Conflict("Create-order nonce already used".into()));
    }

    let now = floor_timestamp_6h(OffsetDateTime::now_utc().unix_timestamp());
    let lock_days = req.time_lock_days.unwrap_or(state.config.server.default_lock_days);
    let lock_seconds = (lock_days as i64).saturating_mul(86400);
    let expiry_bucket = floor_timestamp_6h(now.saturating_add(lock_seconds));

    let order_id = uuid::Uuid::new_v4().as_bytes().to_vec();

    sqlx::query(
        "INSERT INTO orders (id, encrypted_order_blob, day_bucket, expiry_bucket) VALUES (?1, ?2, ?3, ?4)"
    )
    .bind(&order_id)
    .bind(&blob)
    .bind(now)
    .bind(Some(expiry_bucket))
    .execute(&state.pool)
    .await
    .map_err(|e| AppError::Internal(format!("DB error: {e}")))?;

    Ok(Json(OrderResponse {
        id: hex::encode(&order_id),
        client_encrypted_blob: Some(req.client_encrypted_blob),
        day_bucket: now,
        expiry_bucket: Some(expiry_bucket),
        version: 1,
        has_dispute: false,
    }))
}

async fn get_order(
    State(state): State<AppState>,
    Extension(AuthPubkey(_pubkey_hash)): Extension<AuthPubkey>,
    Path(id): Path<String>,
) -> Result<Json<OrderResponse>, AppError> {
    let id_bytes = hex::decode(&id)
        .map_err(|_| AppError::BadRequest("Invalid order_id".into()))?;

    let row: Option<(Vec<u8>, i64, Option<i64>, i64, i64)> = sqlx::query_as(
        "SELECT encrypted_order_blob, day_bucket, expiry_bucket, version, has_dispute FROM orders WHERE id = ?1"
    )
    .bind(&id_bytes)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| AppError::Internal(format!("DB error: {e}")))?;

    let (blob, day_bucket, expiry_bucket, version, has_dispute) = row
        .ok_or_else(|| AppError::NotFound("Order not found".into()))?;

    let blob_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &blob);

    Ok(Json(OrderResponse {
        id,
        client_encrypted_blob: Some(blob_b64),
        day_bucket,
        expiry_bucket,
        version,
        has_dispute: has_dispute != 0,
    }))
}

async fn update_order(
    State(state): State<AppState>,
    Extension(AuthPubkey(_pubkey_hash)): Extension<AuthPubkey>,
    Extension(AuthPubkeyBytes(pubkey_bytes)): Extension<AuthPubkeyBytes>,
    Path(id): Path<String>,
    Json(req): Json<UpdateOrderRequest>,
) -> Result<Json<OrderResponse>, AppError> {
    let id_bytes = hex::decode(&id)
        .map_err(|_| AppError::BadRequest("Invalid order_id".into()))?;

    let blob = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &req.client_encrypted_blob)
        .map_err(|e| AppError::BadRequest(format!("Invalid client_encrypted_blob base64: {e}")))?;
    if blob.is_empty() {
        return Err(AppError::BadRequest("client_encrypted_blob is empty".into()));
    }
    if blob.len() > MAX_ORDER_BLOB_BYTES {
        return Err(AppError::BadRequest("client_encrypted_blob too large".into()));
    }

    if !check_update_nonce_replay(&id, &req.nonce) {
        return Err(AppError::Conflict("Update-order nonce already used".into()));
    }

    // TOCTOU: read version, conditional UPDATE with version bump.
    let current: Option<(i64, i64, Option<i64>)> = sqlx::query_as(
        "SELECT version, day_bucket, expiry_bucket FROM orders WHERE id = ?1"
    )
    .bind(&id_bytes)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| AppError::Internal(format!("DB error: {e}")))?;
    let (v, day_bucket, expiry_bucket) = match current {
        Some(v) => v,
        None => return Err(AppError::NotFound("Order not found".into())),
    };

    // Verify transition signature over canonical CBOR payload.
    let nonce_bytes = hex::decode(&req.nonce)
        .map_err(|_| AppError::BadRequest("Invalid nonce hex".into()))?;
    let sig_bytes = hex::decode(&req.transition_signature)
        .map_err(|_| AppError::BadRequest("Invalid transition_signature hex".into()))?;
    if sig_bytes.len() != 64 {
        return Err(AppError::BadRequest("Transition signature must be 64 bytes".into()));
    }
    let mut sig_array = [0u8; 64];
    sig_array.copy_from_slice(&sig_bytes);

    let mut hasher = Sha256::new();
    hasher.update(&blob);
    let new_blob_hash: [u8; 32] = hasher.finalize().into();

    let hour_bucket = req.hour_bucket;

    let payload = TransitionPayload::new(
        id_bytes.clone(),
        v,
        new_blob_hash,
        nonce_bytes,
        hour_bucket,
    );

    verify_transition(&pubkey_bytes, &payload, &sig_array)
        .map_err(|e| AppError::AuthFailed(format!("Transition signature invalid: {e}")))?;

    let result = sqlx::query(
        "UPDATE orders SET encrypted_order_blob = ?1, version = version + 1 WHERE id = ?2 AND version = ?3"
    )
    .bind(&blob)
    .bind(&id_bytes)
    .bind(v)
    .execute(&state.pool)
    .await
    .map_err(|e| AppError::Internal(format!("DB error: {e}")))?;
    if result.rows_affected() == 0 {
        return Err(AppError::Conflict("Order was modified by another request".into()));
    }

    Ok(Json(OrderResponse {
        id,
        client_encrypted_blob: Some(req.client_encrypted_blob),
        day_bucket,
        expiry_bucket,
        version: v + 1,
        has_dispute: false,
    }))
}

fn check_create_nonce_replay(nonce: &str) -> bool {
    use std::collections::HashSet;
    use std::sync::Mutex;
    use once_cell::sync::Lazy;

    static CREATE_NONCES: Lazy<Mutex<HashSet<String>>> = Lazy::new(|| Mutex::new(HashSet::new()));
    let mut set = CREATE_NONCES.lock().unwrap_or_else(|e| e.into_inner());
    set.insert(nonce.to_string())
}

fn check_update_nonce_replay(order_id: &str, nonce: &str) -> bool {
    use std::collections::HashSet;
    use std::sync::Mutex;
    use once_cell::sync::Lazy;

    static UPDATE_NONCES: Lazy<Mutex<HashSet<String>>> = Lazy::new(|| Mutex::new(HashSet::new()));
    let key = format!("{}:{}", order_id, nonce);
    let mut set = UPDATE_NONCES.lock().unwrap_or_else(|e| e.into_inner());
    set.insert(key)
}
