use axum::{
    extract::{Path, State, Extension},
    Json, Router,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::db::models::{Order, OrderData, ChatMessageData};
use crate::crypto::oblivious;
use crate::crypto::hmac_auth::{derive_domain_identity, domains};
use crate::crypto::zk::{constant_time_compare, floor_timestamp_6h};
use crate::gateway::state::AppState;
use crate::gateway::auth_common::AuthPubkey;
use crate::error::AppError;

#[derive(Deserialize)]
pub struct SendMessageRequest {
    pub encrypted_body: String,
}

#[derive(Serialize)]
pub struct MessageResponse {
    pub id: String,
    pub order_id: String,
    pub sender_pubkey_hash: String,
    pub encrypted_body: String,
    pub created_at: i64,
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/chat/{order_id}", get(get_messages))
        .route("/chat/{order_id}", post(send_message))
}

fn order_domain_id(secret: &str, pk_hash: &[u8]) -> Result<Vec<u8>, AppError> {
    derive_domain_identity(secret.as_bytes(), domains::ORDERS, pk_hash)
        .ok_or_else(|| AppError::Internal("Domain identity derivation failed".into()))
}

fn chat_domain_id(secret: &str, pk_hash: &[u8]) -> Result<Vec<u8>, AppError> {
    derive_domain_identity(secret.as_bytes(), domains::CHAT, pk_hash)
        .ok_or_else(|| AppError::Internal("Domain identity derivation failed".into()))
}

async fn read_order_data(state: &AppState, order_id: &str) -> Result<(Vec<u8>, OrderData), AppError> {
    let id_bytes = hex::decode(order_id)
        .map_err(|_| AppError::BadRequest("Invalid order_id".into()))?;

    let order = sqlx::query_as::<_, Order>(
        "SELECT * FROM orders WHERE id = ?1"
    )
    .bind(&id_bytes)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| AppError::Internal(format!("DB error: {e}")))?
    .ok_or_else(|| AppError::NotFound("Order not found".into()))?;

    let raw = oblivious::decrypt_order_blob(&order.encrypted_order_blob, &state.master_seed[..], &order.id)
        .ok_or_else(|| AppError::Internal("Failed to decrypt order".into()))?;
    let data = serde_json::from_slice(&raw)
        .map_err(|e| AppError::Internal(format!("Corrupt order data: {e}")))?;

    Ok((order.id, data))
}

async fn write_order_data(state: &AppState, id: &[u8], data: &OrderData) -> Result<(), AppError> {
    let json = serde_json::to_vec(data)
        .map_err(|e| AppError::Internal(format!("Serialize: {e}")))?;
    let blob = oblivious::encrypt_order_blob(&json, &state.master_seed[..], id)
        .ok_or_else(|| AppError::Internal("Encryption failed".into()))?;
    let expiry_bucket = data.expires_at.map(floor_timestamp_6h);
    sqlx::query("UPDATE orders SET encrypted_order_blob = ?1, expiry_bucket = ?2 WHERE id = ?3")
        .bind(&blob)
        .bind(expiry_bucket)
        .bind(id)
        .execute(&state.pool)
        .await
        .map_err(|e| AppError::Internal(format!("DB error: {e}")))?;
    Ok(())
}

async fn send_message(
    State(state): State<AppState>,
    Extension(AuthPubkey(sender_pk_hash)): Extension<AuthPubkey>,
    Path(order_id): Path<String>,
    Json(req): Json<SendMessageRequest>,
) -> Result<Json<MessageResponse>, AppError> {
    let now = floor_timestamp_6h(OffsetDateTime::now_utc().unix_timestamp());
    let ttl = 7 * 86400;

    let (row_id, mut data) = read_order_data(&state, &order_id).await?;

    let user_order_id = order_domain_id(&state.config.server.server_secret, &sender_pk_hash)?;
    if !constant_time_compare(&data.buyer_pubkey_hash, &user_order_id)
        && !constant_time_compare(&data.seller_pubkey_hash, &user_order_id)
    {
        return Err(AppError::Forbidden("Not part of this order".into()));
    }

    let encrypted_body = hex::decode(&req.encrypted_body)
        .map_err(|_| AppError::BadRequest("Invalid encrypted_body hex".into()))?;

    let sender_chat_id = chat_domain_id(&state.config.server.server_secret, &sender_pk_hash)?;
    let msg = ChatMessageData {
        id: ChatMessageData::new_id(),
        sender_pubkey_hash: sender_chat_id,
        encrypted_body,
        created_at: now,
        expires_at: now + ttl,
    };

    data.chat_messages.push(msg);

    write_order_data(&state, &row_id, &data).await?;

    let msg = data.chat_messages.last().unwrap();
    Ok(Json(MessageResponse {
        id: hex::encode(&msg.id),
        order_id,
        sender_pubkey_hash: hex::encode(&msg.sender_pubkey_hash),
        encrypted_body: hex::encode(&msg.encrypted_body),
        created_at: msg.created_at,
    }))
}

async fn get_messages(
    State(state): State<AppState>,
    Extension(AuthPubkey(user_pk_hash)): Extension<AuthPubkey>,
    Path(order_id): Path<String>,
) -> Result<Json<Vec<MessageResponse>>, AppError> {
    let now = floor_timestamp_6h(OffsetDateTime::now_utc().unix_timestamp());

    let (row_id, mut data) = read_order_data(&state, &order_id).await?;

    let user_order_id = order_domain_id(&state.config.server.server_secret, &user_pk_hash)?;
    if !constant_time_compare(&data.buyer_pubkey_hash, &user_order_id)
        && !constant_time_compare(&data.seller_pubkey_hash, &user_order_id)
    {
        return Err(AppError::Forbidden("Not part of this order".into()));
    }

    let before = data.chat_messages.len();
    data.chat_messages.retain(|m| m.expires_at > now);
    if data.chat_messages.len() < before {
        write_order_data(&state, &row_id, &data).await?;
    }

    Ok(Json(
        data.chat_messages
            .iter()
            .map(|m| MessageResponse {
                id: hex::encode(&m.id),
                order_id: order_id.clone(),
                sender_pubkey_hash: hex::encode(&m.sender_pubkey_hash),
                encrypted_body: hex::encode(&m.encrypted_body),
                created_at: m.created_at,
            })
            .collect(),
    ))
}
