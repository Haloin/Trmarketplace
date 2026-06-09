//! Chat service — blind pass-through for opaque chat blobs.

use axum::{
    extract::{Path, State, Extension, Json},
    Router,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};

use crate::gateway::state::AppState;
use crate::gateway::auth_common::AuthPubkey;
use crate::error::AppError;

#[derive(Deserialize)]
pub struct SendMessageRequest {
    /// New opaque chat blob. Replaces the existing one entirely.
    /// The client maintains a ratchet — it decrypts the old blob, appends
    /// the new message, re-encrypts, and sends the result here.
    pub chat_encrypted_blob: String,
    pub transition_signature: String,
    pub nonce: String,
}

#[derive(Serialize)]
pub struct ChatResponse {
    pub order_id: String,
    /// Current opaque chat blob (base64). May be empty if no chat yet.
    pub chat_encrypted_blob: Option<String>,
    /// Current version for the next transition signature.
    pub version: i64,
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/chat/:order_id", get(get_chat))
        .route("/chat/:order_id", post(update_chat))
}

async fn get_chat(
    State(state): State<AppState>,
    Extension(AuthPubkey(_pubkey_hash)): Extension<AuthPubkey>,
    Path(order_id): Path<String>,
) -> Result<Json<ChatResponse>, AppError> {
    let id_bytes = hex::decode(&order_id)
        .map_err(|_| AppError::BadRequest("Invalid order_id".into()))?;

    // Read the order row. We need version + chat_encrypted_blob only.
    // The server does not check that the order exists — if it does not, the
    // chat blob is just None. The client knows whether the order exists.
    let row: Option<(Vec<u8>, i64)> = sqlx::query_as(
        "SELECT id, version FROM orders WHERE id = ?1"
    )
    .bind(&id_bytes)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| AppError::Internal(format!("DB error: {e}")))?;

    let (version, chat_blob) = match row {
        Some((_id, v)) => {
            let blob: Option<(Option<Vec<u8>>,)> = sqlx::query_as(
                "SELECT chat_encrypted_blob FROM orders WHERE id = ?1"
            )
            .bind(&id_bytes)
            .fetch_optional(&state.pool)
            .await
            .map_err(|e| AppError::Internal(format!("DB error: {e}")))?;
            (v, blob.and_then(|b| b.0))
        }
        None => (0, None),
    };

    let blob_b64 = chat_blob.map(|b| {
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b)
    });

    Ok(Json(ChatResponse {
        order_id,
        chat_encrypted_blob: blob_b64,
        version,
    }))
}

async fn update_chat(
    State(state): State<AppState>,
    Extension(AuthPubkey(_pubkey_hash)): Extension<AuthPubkey>,
    Path(order_id): Path<String>,
    Json(req): Json<SendMessageRequest>,
) -> Result<Json<ChatResponse>, AppError> {
    let id_bytes = hex::decode(&order_id)
        .map_err(|_| AppError::BadRequest("Invalid order_id".into()))?;

    let new_blob = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &req.chat_encrypted_blob)
        .map_err(|e| AppError::BadRequest(format!("Invalid chat_encrypted_blob base64: {e}")))?;

    // Size cap only — server does not validate blob content.
    const MAX_CHAT_BLOB_BYTES: usize = 256 * 1024;
    if new_blob.len() > MAX_CHAT_BLOB_BYTES {
        return Err(AppError::BadRequest("chat_encrypted_blob too large".into()));
    }

    // TOCTOU guard: read version, then conditional UPDATE.
    let current: Option<(i64,)> = sqlx::query_as(
        "SELECT version FROM orders WHERE id = ?1"
    )
    .bind(&id_bytes)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| AppError::Internal(format!("DB error: {e}")))?;

    let current_version = match current {
        Some((v,)) => v,
        None => return Err(AppError::NotFound("Order not found".into())),
    };

    // Replay-cache the chat nonce (separate from auth nonce).
    if !check_chat_nonce_replay(&order_id, &req.nonce) {
        return Err(AppError::Conflict("Chat nonce already used".into()));
    }

    let result = sqlx::query(
        "UPDATE orders SET chat_encrypted_blob = ?1, version = version + 1 WHERE id = ?2 AND version = ?3"
    )
    .bind(&new_blob)
    .bind(&id_bytes)
    .bind(current_version)
    .execute(&state.pool)
    .await
    .map_err(|e| AppError::Internal(format!("DB error: {e}")))?;

    if result.rows_affected() == 0 {
        return Err(AppError::Conflict("Order was modified by another request".into()));
    }

    // pubkey_hash is logged at debug only; never at info or warn, to avoid
    // emitting user-identifying strings to logs.
    tracing::debug!(order_id = %order_id, "Chat blob updated");

    Ok(Json(ChatResponse {
        order_id,
        chat_encrypted_blob: Some(req.chat_encrypted_blob),
        version: current_version + 1,
    }))
}

fn check_chat_nonce_replay(order_id: &str, nonce: &str) -> bool {
    use std::collections::HashSet;
    use std::sync::Mutex;
    use once_cell::sync::Lazy;

    static CHAT_NONCES: Lazy<Mutex<HashSet<String>>> = Lazy::new(|| Mutex::new(HashSet::new()));
    let key = format!("{}:{}", order_id, nonce);
    let mut set = CHAT_NONCES.lock().unwrap_or_else(|e| e.into_inner());
    set.insert(key)
}
