use axum::{
    extract::{Path, State, Extension, Query},
    Json, Router,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::db::models::{Order, OrderData, DisputeData, DisputeEvidenceEntry};
use crate::crypto::oblivious;
use crate::crypto::hmac_auth::{derive_domain_identity, domains};
use crate::crypto::zk::{constant_time_compare, floor_timestamp_6h};
use crate::gateway::state::AppState;
use crate::gateway::auth_common::AuthPubkey;
use crate::error::AppError;

#[derive(Deserialize)]
pub struct OpenDisputeRequest {
    pub order_id: String,
    pub reason: String,
}

#[derive(Deserialize)]
pub struct SubmitEvidenceRequest {
    pub encrypted_content: String,
    pub content_type: String,
}

#[derive(Deserialize)]
pub struct ResolveDisputeRequest {
    pub resolution: String,
}

#[derive(Serialize)]
pub struct DisputeResponse {
    pub id: String,
    pub order_id: String,
    pub opened_by: String,
    pub reason: String,
    pub resolution: Option<String>,
    pub resolved_by: Option<String>,
    pub resolved_at: Option<i64>,
    pub created_at: i64,
}

#[derive(Serialize)]
pub struct DisputeListResponse {
    pub disputes: Vec<DisputeResponse>,
    pub total: i64,
}

#[derive(Deserialize)]
pub struct DisputeQuery {
    pub state: Option<String>,
    pub offset: Option<i64>,
    pub limit: Option<i64>,
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/disputes", post(open_dispute))
        .route("/disputes/{id}", get(get_dispute))
        .route("/disputes/order/{order_id}", get(get_dispute_by_order))
        .route("/disputes/{id}/evidence", post(submit_evidence))
        .route("/disputes/{id}/resolve", post(resolve_dispute))
        .route("/disputes", get(list_disputes))
}

fn order_domain_id(secret: &str, pk_hash: &[u8]) -> Result<Vec<u8>, AppError> {
    derive_domain_identity(secret.as_bytes(), domains::ORDERS, pk_hash)
        .ok_or_else(|| AppError::Internal("Domain identity derivation failed".into()))
}

fn to_response(order_id: &str, d: &DisputeData) -> DisputeResponse {
    DisputeResponse {
        id: d.id.clone(),
        order_id: order_id.to_string(),
        opened_by: d.opened_by.clone(),
        reason: d.reason.clone(),
        resolution: d.resolution.clone(),
        resolved_by: d.resolved_by.clone(),
        resolved_at: d.resolved_at,
        created_at: d.created_at,
    }
}

async fn read_order_data(state: &AppState, order_id: &str) -> Result<(Vec<u8>, OrderData), AppError> {
    let id_bytes = hex::decode(order_id)
        .map_err(|_| AppError::BadRequest("Invalid id".into()))?;

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

async fn open_dispute(
    State(state): State<AppState>,
    Extension(AuthPubkey(pubkey_hash)): Extension<AuthPubkey>,
    Json(req): Json<OpenDisputeRequest>,
) -> Result<Json<DisputeResponse>, AppError> {
    let now = floor_timestamp_6h(OffsetDateTime::now_utc().unix_timestamp());
    let (row_id, mut data) = read_order_data(&state, &req.order_id).await?;

    let user_order_id = order_domain_id(&state.config.server.server_secret, &pubkey_hash)?;
    if !constant_time_compare(&data.buyer_pubkey_hash, &user_order_id) {
        return Err(AppError::Forbidden("Only buyer can open dispute".into()));
    }

    if !data.can_transition_to("disputed") {
        return Err(AppError::BadRequest(
            format!("Invalid state transition: {} -> disputed", data.state)
        ));
    }

    let dispute = DisputeData {
        id: uuid::Uuid::new_v4().to_string(),
        opened_by: hex::encode(&user_order_id),
        reason: req.reason,
        resolution: None,
        resolved_by: None,
        resolved_at: None,
        created_at: now,
        evidence: vec![],
    };

    data.dispute = Some(dispute);
    data.dispute_id = data.dispute.as_ref().map(|d| d.id.clone());
    data.state = "disputed".to_string();
    data.disputed_at = Some(now);

    write_order_data(&state, &row_id, &data).await?;

    let dispute = data.dispute.as_ref()
        .ok_or_else(|| AppError::Internal("Dispute data missing".into()))?;
    Ok(Json(to_response(&req.order_id, dispute)))
}

async fn get_dispute(
    State(state): State<AppState>,
    Extension(AuthPubkey(pubkey_hash)): Extension<AuthPubkey>,
    Path(id): Path<String>,
) -> Result<Json<DisputeResponse>, AppError> {
    let disputes = scan_disputes(&state).await?;
    let (d, order_id) = disputes.into_iter().find(|(d, _)| d.id == id)
        .ok_or_else(|| AppError::NotFound("Dispute not found".into()))?;

    let (_, data) = read_order_data(&state, &order_id).await?;
    let user_order_id = order_domain_id(&state.config.server.server_secret, &pubkey_hash)?;
    if !constant_time_compare(&data.buyer_pubkey_hash, &user_order_id)
        && !constant_time_compare(&data.seller_pubkey_hash, &user_order_id)
        && !is_admin(&state, &pubkey_hash).await
    {
        return Err(AppError::Forbidden("Not authorized".into()));
    }

    Ok(Json(to_response(&order_id, &d)))
}

async fn get_dispute_by_order(
    State(state): State<AppState>,
    Extension(AuthPubkey(pubkey_hash)): Extension<AuthPubkey>,
    Path(order_id): Path<String>,
) -> Result<Json<DisputeResponse>, AppError> {
    let (_, data) = read_order_data(&state, &order_id).await?;

    let user_order_id = order_domain_id(&state.config.server.server_secret, &pubkey_hash)?;
    if !constant_time_compare(&data.buyer_pubkey_hash, &user_order_id)
        && !constant_time_compare(&data.seller_pubkey_hash, &user_order_id)
        && !is_admin(&state, &pubkey_hash).await
    {
        return Err(AppError::Forbidden("Not authorized".into()));
    }

    let dispute = data.dispute.as_ref()
        .ok_or_else(|| AppError::NotFound("No dispute for this order".into()))?;

    Ok(Json(to_response(&order_id, dispute)))
}

async fn submit_evidence(
    State(state): State<AppState>,
    Extension(AuthPubkey(pubkey_hash)): Extension<AuthPubkey>,
    Path(dispute_id): Path<String>,
    Json(req): Json<SubmitEvidenceRequest>,
) -> Result<Json<DisputeResponse>, AppError> {
    let now = floor_timestamp_6h(OffsetDateTime::now_utc().unix_timestamp());

    let disputes = scan_disputes(&state).await?;
    let (_, order_id) = disputes.into_iter().find(|(d, _)| d.id == dispute_id)
        .ok_or_else(|| AppError::NotFound("Dispute not found".into()))?;

    let (row_id, mut data) = read_order_data(&state, &order_id).await?;

    let opened_by_hex;
    let is_dispute_resolved;
    let evidence_len;
    {
        let dispute = data.dispute.as_mut()
            .ok_or_else(|| AppError::Internal("Dispute data missing".into()))?;
        is_dispute_resolved = dispute.resolved_at.is_some();
        opened_by_hex = dispute.opened_by.clone();
        evidence_len = dispute.evidence.len();
    }

    if is_dispute_resolved {
        return Err(AppError::BadRequest("Dispute already resolved".into()));
    }

    let user_order_id = order_domain_id(&state.config.server.server_secret, &pubkey_hash)?;
    if !constant_time_compare(&hex::decode(&opened_by_hex).unwrap_or_default(), &user_order_id)
        && !constant_time_compare(&data.seller_pubkey_hash, &user_order_id)
    {
        return Err(AppError::Forbidden("Only buyer or seller can submit evidence".into()));
    }

    let content_bytes = hex::decode(&req.encrypted_content)
        .map_err(|_| AppError::BadRequest("Invalid encrypted_content hex".into()))?;

    const MAX_EVIDENCE: usize = 50;
    if evidence_len >= MAX_EVIDENCE {
        return Err(AppError::BadRequest("Maximum evidence submissions reached".into()));
    }

    {
        let dispute = data.dispute.as_mut()
            .ok_or_else(|| AppError::Internal("Dispute data missing".into()))?;
        dispute.evidence.push(DisputeEvidenceEntry {
            id: uuid::Uuid::new_v4().to_string(),
            submitted_by: hex::encode(&user_order_id),
            encrypted_content: content_bytes,
            content_type: req.content_type,
            created_at: now,
        });
    }

    write_order_data(&state, &row_id, &data).await?;

    let dispute = data.dispute.as_ref()
        .ok_or_else(|| AppError::Internal("Dispute data missing".into()))?;
    Ok(Json(to_response(&order_id, dispute)))
}

async fn resolve_dispute(
    State(state): State<AppState>,
    Extension(AuthPubkey(pubkey_hash)): Extension<AuthPubkey>,
    Path(dispute_id): Path<String>,
    Json(req): Json<ResolveDisputeRequest>,
) -> Result<Json<DisputeResponse>, AppError> {
    let now = floor_timestamp_6h(OffsetDateTime::now_utc().unix_timestamp());

    if !is_admin(&state, &pubkey_hash).await {
        return Err(AppError::Forbidden("Only admin can resolve disputes".into()));
    }

    let disputes = scan_disputes(&state).await?;
    let (_, order_id) = disputes.into_iter().find(|(d, _)| d.id == dispute_id)
        .ok_or_else(|| AppError::NotFound("Dispute not found".into()))?;

    let (row_id, mut data) = read_order_data(&state, &order_id).await?;

    let is_resolved;
    {
        let dispute = data.dispute.as_mut()
            .ok_or_else(|| AppError::Internal("Dispute data missing".into()))?;
        is_resolved = dispute.resolved_at.is_some();
    }

    if is_resolved {
        return Err(AppError::BadRequest("Dispute already resolved".into()));
    }

    if req.resolution != "release" && req.resolution != "refund" {
        return Err(AppError::BadRequest("Resolution must be 'release' or 'refund'".into()));
    }

    {
        let dispute = data.dispute.as_mut()
            .ok_or_else(|| AppError::Internal("Dispute data missing".into()))?;
        dispute.resolution = Some(req.resolution.clone());
        let admin_order_id = order_domain_id(&state.config.server.server_secret, &pubkey_hash)?;
        dispute.resolved_by = Some(hex::encode(&admin_order_id));
        dispute.resolved_at = Some(now);
    }

    if req.resolution == "release" {
        data.state = "released".to_string();
        data.released_at = Some(now);
    } else {
        data.state = "refunded".to_string();
        data.refunded_at = Some(now);
    }
    data.dispute_id = None;
    data.disputed_at = None;

    write_order_data(&state, &row_id, &data).await?;

    let dispute = data.dispute.as_ref()
        .ok_or_else(|| AppError::Internal("Dispute data missing".into()))?;
    Ok(Json(to_response(&order_id, dispute)))
}

async fn list_disputes(
    State(state): State<AppState>,
    Extension(AuthPubkey(pubkey_hash)): Extension<AuthPubkey>,
    Query(query): Query<DisputeQuery>,
) -> Result<Json<DisputeListResponse>, AppError> {
    if !is_admin(&state, &pubkey_hash).await {
        return Err(AppError::Forbidden("Only admin can list all disputes".into()));
    }

    let offset = query.offset.unwrap_or(0) as usize;
    let limit = query.limit.unwrap_or(50).min(100) as usize;
    let filter_state = query.state.as_deref();

    let all = scan_disputes(&state).await?;

    let filtered: Vec<_> = match filter_state {
        Some("open") => all.into_iter().filter(|(d, _)| d.resolved_at.is_none()).collect(),
        Some("resolved") => all.into_iter().filter(|(d, _)| d.resolved_at.is_some()).collect(),
        _ => all,
    };

    let total = filtered.len() as i64;
    let disputes: Vec<_> = filtered.into_iter().skip(offset).take(limit).collect();

    Ok(Json(DisputeListResponse {
        disputes: disputes.into_iter().map(|(d, oid)| to_response(&oid, &d)).collect(),
        total,
    }))
}

async fn scan_disputes(state: &AppState) -> Result<Vec<(DisputeData, String)>, AppError> {
    let orders = sqlx::query_as::<_, Order>(
        "SELECT * FROM orders"
    )
    .fetch_all(&state.pool)
    .await
    .map_err(|e| AppError::Internal(format!("DB error: {e}")))?;

    let mut result = Vec::new();
    for order in orders {
        if let Some(raw) = oblivious::decrypt_order_blob(&order.encrypted_order_blob, &state.master_seed[..], &order.id) {
            if let Ok(data) = serde_json::from_slice::<OrderData>(&raw) {
                if let Some(dispute) = data.dispute {
                    result.push((dispute, hex::encode(&order.id)));
                }
            }
        }
    }

    Ok(result)
}

async fn is_admin(state: &AppState, pubkey_hash: &[u8]) -> bool {
    crate::gateway::auth_common::is_admin(&state.config, pubkey_hash)
}
