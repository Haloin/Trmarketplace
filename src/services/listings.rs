use axum::{
    extract::{Path, Query, State, Extension},
    Json, Router,
    routing::{get, post, delete, put},
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::db::models::{Listing, ListingData};
use crate::crypto::oblivious;
use crate::crypto::zk::{constant_time_compare, floor_timestamp_6h};
use crate::gateway::state::AppState;
use crate::gateway::auth_common::AuthPubkey;
use crate::error::AppError;

#[derive(Deserialize)]
pub struct CreateListingRequest {
    pub encrypted_data: String,
    pub encrypted_search: Option<String>,
    pub currency: Option<String>,
    pub price_amount: String,
    pub seller_pubkey: String,
    pub expires_in_days: Option<u64>,
}

#[derive(Serialize)]
pub struct ListingResponse {
    pub id: String,
    pub seller_pubkey_hash: String,
    pub seller_pubkey: Option<String>,
    pub encrypted_data: String,
    pub encrypted_search: Option<String>,
    pub currency: String,
    pub price_amount: String,
    pub status: String,
    pub created_at: i64,
}

#[derive(Deserialize)]
pub struct SearchQuery {
    pub q: Option<String>,
    pub currency: Option<String>,
    pub status: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Serialize)]
pub struct ListingsResponse {
    pub listings: Vec<ListingResponse>,
    pub total: i64,
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/listings", get(list_listings))
        .route("/listings", post(create_listing))
        .route("/listings/{id}", get(get_listing))
        .route("/listings/{id}", put(update_listing))
        .route("/listings/{id}", delete(delete_listing))
}

fn decrypt_listing(listing: &Listing, server_secret: &[u8]) -> Option<ListingData> {
    let raw = oblivious::decrypt_listing_blob(
        &listing.encrypted_listing_blob,
        server_secret,
        &listing.id,
    )?;
    serde_json::from_slice::<ListingData>(&raw).ok()
}

fn encrypt_listing_data(data: &ListingData, server_secret: &[u8], listing_id: &[u8]) -> Option<Vec<u8>> {
    let json = serde_json::to_vec(data).ok()?;
    oblivious::encrypt_listing_blob(&json, server_secret, listing_id)
}

async fn create_listing(
    State(state): State<AppState>,
    Extension(AuthPubkey(seller_pk_hash)): Extension<AuthPubkey>,
    Json(req): Json<CreateListingRequest>,
) -> Result<Json<ListingResponse>, AppError> {
    let now = floor_timestamp_6h(OffsetDateTime::now_utc().unix_timestamp());

    let encrypted_data = hex::decode(&req.encrypted_data)
        .map_err(|_| AppError::BadRequest("Invalid encrypted_data hex".into()))?;

    let encrypted_search = parse_search_tokens(&req.encrypted_search)?;

    let expiry_days = req.expires_in_days.unwrap_or(7);
    let expires_at = Some(now + (expiry_days as i64 * 86400));
    let listing_id = Listing::new_id();

    let data = ListingData {
        seller_pubkey_hash: seller_pk_hash.clone(),
        seller_pubkey: Some(req.seller_pubkey.clone()),
        encrypted_data,
        encrypted_search: encrypted_search.clone(),
        currency: req.currency.unwrap_or_else(|| "XMR".to_string()),
        price_amount: req.price_amount,
        status: "active".to_string(),
        created_at: now,
        expires_at,
        updated_at: now,
    };

    let blob = encrypt_listing_data(&data, &state.master_seed, &listing_id)
        .ok_or_else(|| AppError::Internal("encryption failed".into()))?;

    sqlx::query(
        "INSERT INTO listings (id, encrypted_listing_blob, day_bucket, search_token) VALUES (?1, ?2, ?3, ?4)"
    )
    .bind(&listing_id)
    .bind(&blob)
    .bind(now)
    .bind(&encrypted_search)
    .execute(&state.pool)
    .await
    .map_err(|e| AppError::Internal(format!("DB error: {}", e)))?;

    Ok(Json(to_response(&listing_id, &data)))
}

async fn list_listings(
    State(state): State<AppState>,
    Query(query): Query<SearchQuery>,
) -> Result<Json<ListingsResponse>, AppError> {
    let limit = query.limit.unwrap_or(50).min(100);
    let offset = query.offset.unwrap_or(0);
    let filter_status = query.status.as_deref();
    let filter_currency = query.currency.as_deref();

    let listings = sqlx::query_as::<_, Listing>(
        "SELECT * FROM listings ORDER BY rowid DESC"
    )
    .fetch_all(&state.pool)
    .await
    .map_err(|e| AppError::Internal(format!("DB error: {}", e)))?;

    let mut matching: Vec<(Listing, ListingData)> = Vec::new();
    for listing in listings {
        let Some(data) = decrypt_listing(&listing, &state.master_seed) else { continue };

        if let Some(st) = filter_status {
            if data.status != st { continue; }
        }
        if let Some(cur) = filter_currency {
            if data.currency != cur { continue; }
        }

        matching.push((listing, data));
    }

    let total = matching.len() as i64;
    let page: Vec<_> = matching.into_iter().skip(offset as usize).take(limit as usize).collect();

    Ok(Json(ListingsResponse {
        total,
        listings: page.iter().map(|(l, d)| to_response(&l.id, d)).collect(),
    }))
}

async fn get_listing(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<ListingResponse>, AppError> {
    let id_bytes = hex::decode(&id)
        .map_err(|_| AppError::BadRequest("Invalid id".into()))?;

    let listing = sqlx::query_as::<_, Listing>(
        "SELECT * FROM listings WHERE id = ?1"
    )
    .bind(&id_bytes)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| AppError::Internal(format!("DB error: {}", e)))?
    .ok_or_else(|| AppError::NotFound("Listing not found".into()))?;

    let data = decrypt_listing(&listing, &state.master_seed)
        .ok_or_else(|| AppError::Internal("decryption failed".into()))?;

    Ok(Json(to_response(&listing.id, &data)))
}

async fn update_listing(
    State(state): State<AppState>,
    Extension(AuthPubkey(seller_pk_hash)): Extension<AuthPubkey>,
    Path(id): Path<String>,
    Json(req): Json<CreateListingRequest>,
) -> Result<Json<ListingResponse>, AppError> {
    let id_bytes = hex::decode(&id)
        .map_err(|_| AppError::BadRequest("Invalid id".into()))?;

    let existing = sqlx::query_as::<_, Listing>(
        "SELECT * FROM listings WHERE id = ?1"
    )
    .bind(&id_bytes)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| AppError::Internal(format!("DB error: {}", e)))?
    .ok_or_else(|| AppError::NotFound("Listing not found".into()))?;

    let mut data = decrypt_listing(&existing, &state.master_seed)
        .ok_or_else(|| AppError::Internal("decryption failed".into()))?;

    if !constant_time_compare(&data.seller_pubkey_hash, &seller_pk_hash) {
        return Err(AppError::Forbidden("Not your listing".into()));
    }

    let now = floor_timestamp_6h(OffsetDateTime::now_utc().unix_timestamp());

    data.encrypted_data = hex::decode(&req.encrypted_data)
        .map_err(|_| AppError::BadRequest("Invalid hex".into()))?;
    data.encrypted_search = parse_search_tokens(&req.encrypted_search)?;
    data.currency = req.currency.unwrap_or(data.currency);
    data.price_amount = req.price_amount;
    data.updated_at = now;

    let blob = encrypt_listing_data(&data, &state.master_seed, &existing.id)
        .ok_or_else(|| AppError::Internal("encryption failed".into()))?;

    sqlx::query(
        "UPDATE listings SET encrypted_listing_blob = ?1, search_token = ?2 WHERE id = ?3"
    )
    .bind(&blob)
    .bind(&data.encrypted_search)
    .bind(&id_bytes)
    .execute(&state.pool)
    .await
    .map_err(|e| AppError::Internal(format!("DB error: {}", e)))?;

    Ok(Json(to_response(&existing.id, &data)))
}

async fn delete_listing(
    State(state): State<AppState>,
    Extension(AuthPubkey(seller_pk_hash)): Extension<AuthPubkey>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    let id_bytes = hex::decode(&id)
        .map_err(|_| AppError::BadRequest("Invalid id".into()))?;

    let existing = sqlx::query_as::<_, Listing>(
        "SELECT * FROM listings WHERE id = ?1"
    )
    .bind(&id_bytes)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| AppError::Internal(format!("DB error: {}", e)))?
    .ok_or_else(|| AppError::NotFound("Listing not found".into()))?;

    let mut data = decrypt_listing(&existing, &state.master_seed)
        .ok_or_else(|| AppError::Internal("decryption failed".into()))?;

    if !constant_time_compare(&data.seller_pubkey_hash, &seller_pk_hash) {
        return Err(AppError::Forbidden("Not your listing".into()));
    }

    data.status = "removed".to_string();
    data.updated_at = floor_timestamp_6h(OffsetDateTime::now_utc().unix_timestamp());

    let blob = encrypt_listing_data(&data, &state.master_seed, &existing.id)
        .ok_or_else(|| AppError::Internal("encryption failed".into()))?;

    sqlx::query(
        "UPDATE listings SET encrypted_listing_blob = ?1 WHERE id = ?2"
    )
    .bind(&blob)
    .bind(&id_bytes)
    .execute(&state.pool)
    .await
    .map_err(|e| AppError::Internal(format!("DB error: {}", e)))?;

    Ok(Json(serde_json::json!({"status": "removed"})))
}

fn to_response(id: &[u8], data: &ListingData) -> ListingResponse {
    ListingResponse {
        id: hex::encode(id),
        seller_pubkey_hash: hex::encode(&data.seller_pubkey_hash),
        seller_pubkey: data.seller_pubkey.clone(),
        encrypted_data: hex::encode(&data.encrypted_data),
        encrypted_search: data.encrypted_search.as_ref().map(|v| hex::encode(v)),
        currency: data.currency.clone(),
        price_amount: data.price_amount.clone(),
        status: data.status.clone(),
        created_at: data.created_at,
    }
}

fn parse_search_tokens(encrypted_search: &Option<String>) -> Result<Option<Vec<u8>>, AppError> {
    match encrypted_search {
        None => Ok(None),
        Some(tokens_str) => {
            let tokens_str = tokens_str.trim();
            if tokens_str.starts_with('[') {
                let token_strs: Vec<String> = serde_json::from_str(tokens_str)
                    .map_err(|_| AppError::BadRequest("Invalid search tokens JSON".into()))?;
                let mut combined = Vec::new();
                for hex_str in token_strs {
                    let token_bytes = hex::decode(&hex_str)
                        .map_err(|_| AppError::BadRequest("Invalid token hex".into()))?;
                    combined.extend(token_bytes);
                }
                Ok(Some(combined))
            } else {
                let token_bytes = hex::decode(tokens_str)
                    .map_err(|_| AppError::BadRequest("Invalid search token hex".into()))?;
                Ok(Some(token_bytes))
            }
        }
    }
}
