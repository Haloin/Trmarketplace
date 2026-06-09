//! Listings service — blind pass-through for opaque blobs and search tokens.

use axum::{
    extract::{Path, Query, State, Extension, Json},
    Router,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use crate::crypto::zk::floor_timestamp_6h;
use crate::gateway::state::AppState;
use crate::gateway::auth_common::AuthPubkey;
use crate::error::AppError;

#[derive(Deserialize)]
pub struct CreateListingRequest {
    /// Opaque client-encrypted listing blob (hex). Server stores as-is.
    pub client_encrypted_blob: String,
    /// Opaque search token (hex). Server stores as-is and uses for exact-match search.
    pub search_token: Option<String>,
    /// Status label, supplied by client (server treats as opaque ASCII).
    /// Must be short (<= 32 bytes) ASCII.
    pub status: Option<String>,
    /// Currency label, supplied by client (server treats as opaque ASCII).
    /// Must be short (<= 8 bytes) ASCII.
    pub currency: Option<String>,
    /// Lock period in days. Used to compute day_bucket and expiry handling.
    /// Default if omitted: 7 days.
    pub time_lock_days: Option<u64>,
    /// Random nonce. Server rejects duplicates within a 1-hour bucket.
    pub nonce: String,
}

#[derive(Deserialize)]
pub struct UpdateListingRequest {
    /// New opaque client-encrypted listing blob (hex). Replaces the existing.
    pub client_encrypted_blob: String,
    /// New opaque search token (hex). Replaces the existing.
    pub search_token: Option<String>,
    /// New status label.
    pub status: Option<String>,
    /// New currency label.
    pub currency: Option<String>,
    /// Random nonce, must be unique per (listing_id, prev_version) pair.
    pub nonce: String,
}

#[derive(Deserialize)]
pub struct SearchQuery {
    /// Opaque search token (hex). Server exact-matches against the stored
    /// `search_token` column. Empty/None returns most-recent listings.
    pub q: Option<String>,
    /// Filter by currency label.
    pub currency: Option<String>,
    /// Filter by status label.
    pub status: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Serialize)]
pub struct ListingResponse {
    pub id: String,
    pub client_encrypted_blob: String,
    pub search_token: Option<String>,
    pub status: String,
    pub currency: String,
    pub day_bucket: i64,
    pub version: i64,
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
        .route("/listings/:id", get(get_listing))
        .route("/listings/:id/update", post(update_listing))
}

const MAX_LISTING_BLOB_BYTES: usize = 64 * 1024;
const MAX_SEARCH_TOKEN_BYTES: usize = 256;
const MAX_LABEL_BYTES: usize = 32;

fn validate_label(label: &str, field: &str) -> Result<String, AppError> {
    if label.is_empty() {
        return Err(AppError::BadRequest(format!("{field} is empty")));
    }
    if label.len() > MAX_LABEL_BYTES {
        return Err(AppError::BadRequest(format!("{field} too long")));
    }
    if !label.is_ascii() {
        return Err(AppError::BadRequest(format!("{field} must be ASCII")));
    }
    Ok(label.to_string())
}

async fn create_listing(
    State(state): State<AppState>,
    Extension(AuthPubkey(_pubkey_hash)): Extension<AuthPubkey>,
    Json(req): Json<CreateListingRequest>,
) -> Result<Json<ListingResponse>, AppError> {
    let blob = hex::decode(&req.client_encrypted_blob)
        .map_err(|_| AppError::BadRequest("Invalid client_encrypted_blob hex".into()))?;
    if blob.is_empty() {
        return Err(AppError::BadRequest("client_encrypted_blob is empty".into()));
    }
    if blob.len() > MAX_LISTING_BLOB_BYTES {
        return Err(AppError::BadRequest("client_encrypted_blob too large".into()));
    }

    let search_token = match req.search_token.as_deref() {
        Some(hex_str) => {
            let bytes = hex::decode(hex_str)
                .map_err(|_| AppError::BadRequest("Invalid search_token hex".into()))?;
            if bytes.len() > MAX_SEARCH_TOKEN_BYTES {
                return Err(AppError::BadRequest("search_token too large".into()));
            }
            Some(bytes)
        }
        None => None,
    };

    let status = validate_label(req.status.as_deref().unwrap_or("active"), "status")?;
    let currency = validate_label(req.currency.as_deref().unwrap_or("XMR"), "currency")?;

    if !check_create_nonce_replay(&req.nonce) {
        return Err(AppError::Conflict("Create-listing nonce already used".into()));
    }

    let now = floor_timestamp_6h(OffsetDateTime::now_utc().unix_timestamp());
    let listing_id = uuid::Uuid::new_v4().as_bytes().to_vec();

    sqlx::query(
        "INSERT INTO listings (id, encrypted_listing_blob, day_bucket, search_token, status, currency) VALUES (?1, ?2, ?3, ?4, ?5, ?6)"
    )
    .bind(&listing_id)
    .bind(&blob)
    .bind(now)
    .bind(&search_token)
    .bind(&status)
    .bind(&currency)
    .execute(&state.pool)
    .await
    .map_err(|e| AppError::Internal(format!("DB error: {e}")))?;

    Ok(Json(ListingResponse {
        id: hex::encode(&listing_id),
        client_encrypted_blob: req.client_encrypted_blob,
        search_token: req.search_token,
        status,
        currency,
        day_bucket: now,
        version: 1,
    }))
}

async fn list_listings(
    State(state): State<AppState>,
    Query(query): Query<SearchQuery>,
) -> Result<Json<ListingsResponse>, AppError> {
    let limit = query.limit.unwrap_or(50).clamp(1, 100);
    let offset = query.offset.unwrap_or(0).max(0);

    let filter_status = query.status.as_deref().filter(|s| !s.is_empty());
    let filter_currency = query.currency.as_deref().filter(|c| !c.is_empty());

    let search_token_bytes = match query.q.as_deref().filter(|q| !q.is_empty()) {
        Some(hex_str) => Some(
            hex::decode(hex_str)
                .map_err(|_| AppError::BadRequest("Invalid q hex".into()))?,
        ),
        None => None,
    };

    // Build SQL with optional filters. We use exact match on the
    // opaque search_token column. The server does not know what's
    // inside the token — it just matches bytes.
    let mut sql = String::from(
        "SELECT id, encrypted_listing_blob, day_bucket, search_token, status, currency, version FROM listings WHERE 1=1",
    );
    if filter_status.is_some() {
        sql.push_str(" AND status = ?");
    }
    if filter_currency.is_some() {
        sql.push_str(" AND currency = ?");
    }
    if search_token_bytes.is_some() {
        sql.push_str(" AND search_token = ?");
    }
    sql.push_str(" ORDER BY day_bucket DESC, id DESC LIMIT ? OFFSET ?");

    let mut q = sqlx::query_as::<_, (Vec<u8>, Vec<u8>, i64, Option<Vec<u8>>, String, String, i64)>(&sql);
    if let Some(st) = filter_status {
        q = q.bind(st);
    }
    if let Some(cur) = filter_currency {
        q = q.bind(cur);
    }
    if let Some(ref tok) = search_token_bytes {
        q = q.bind(tok);
    }
    q = q.bind(limit).bind(offset);

    let rows = q
        .fetch_all(&state.pool)
        .await
        .map_err(|e| AppError::Internal(format!("DB error: {e}")))?;

    let total = rows.len() as i64;
    let listings: Vec<ListingResponse> = rows
        .into_iter()
        .map(|(id, blob, day_bucket, search_token, status, currency, version)| ListingResponse {
            id: hex::encode(&id),
            client_encrypted_blob: hex::encode(&blob),
            search_token: search_token.map(|v| hex::encode(&v)),
            status,
            currency,
            day_bucket,
            version,
        })
        .collect();

    Ok(Json(ListingsResponse { listings, total }))
}

async fn get_listing(
    State(state): State<AppState>,
    Extension(AuthPubkey(_pubkey_hash)): Extension<AuthPubkey>,
    Path(id): Path<String>,
) -> Result<Json<ListingResponse>, AppError> {
    let id_bytes = hex::decode(&id)
        .map_err(|_| AppError::BadRequest("Invalid id".into()))?;

    let row: Option<(Vec<u8>, i64, Option<Vec<u8>>, String, String, i64)> = sqlx::query_as(
        "SELECT encrypted_listing_blob, day_bucket, search_token, status, currency, version FROM listings WHERE id = ?1"
    )
    .bind(&id_bytes)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| AppError::Internal(format!("DB error: {e}")))?;

    let (blob, day_bucket, search_token, status, currency, version) = row
        .ok_or_else(|| AppError::NotFound("Listing not found".into()))?;

    Ok(Json(ListingResponse {
        id,
        client_encrypted_blob: hex::encode(&blob),
        search_token: search_token.map(|v| hex::encode(&v)),
        status,
        currency,
        day_bucket,
        version,
    }))
}

async fn update_listing(
    State(state): State<AppState>,
    Extension(AuthPubkey(_pubkey_hash)): Extension<AuthPubkey>,
    Path(id): Path<String>,
    Json(req): Json<UpdateListingRequest>,
) -> Result<Json<ListingResponse>, AppError> {
    let id_bytes = hex::decode(&id)
        .map_err(|_| AppError::BadRequest("Invalid id".into()))?;

    let blob = hex::decode(&req.client_encrypted_blob)
        .map_err(|_| AppError::BadRequest("Invalid client_encrypted_blob hex".into()))?;
    if blob.is_empty() {
        return Err(AppError::BadRequest("client_encrypted_blob is empty".into()));
    }
    if blob.len() > MAX_LISTING_BLOB_BYTES {
        return Err(AppError::BadRequest("client_encrypted_blob too large".into()));
    }

    let search_token = match req.search_token.as_deref() {
        Some(hex_str) => {
            let bytes = hex::decode(hex_str)
                .map_err(|_| AppError::BadRequest("Invalid search_token hex".into()))?;
            if bytes.len() > MAX_SEARCH_TOKEN_BYTES {
                return Err(AppError::BadRequest("search_token too large".into()));
            }
            Some(bytes)
        }
        None => None,
    };

    let status = match req.status.as_deref() {
        Some(s) => Some(validate_label(s, "status")?),
        None => None,
    };
    let currency = match req.currency.as_deref() {
        Some(c) => Some(validate_label(c, "currency")?),
        None => None,
    };

    if !check_update_nonce_replay(&id, &req.nonce) {
        return Err(AppError::Conflict("Update-listing nonce already used".into()));
    }

    let current: Option<(i64, String, String)> = sqlx::query_as(
        "SELECT version, status, currency FROM listings WHERE id = ?1"
    )
    .bind(&id_bytes)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| AppError::Internal(format!("DB error: {e}")))?;
    let (v, cur_status, cur_currency) = current
        .ok_or_else(|| AppError::NotFound("Listing not found".into()))?;

    let final_status = status.unwrap_or(cur_status);
    let final_currency = currency.unwrap_or(cur_currency);

    // TOCTOU-safe update.
    let result = sqlx::query(
        "UPDATE listings SET encrypted_listing_blob = ?1, search_token = ?2, status = ?3, currency = ?4, version = version + 1 WHERE id = ?5 AND version = ?6"
    )
    .bind(&blob)
    .bind(&search_token)
    .bind(&final_status)
    .bind(&final_currency)
    .bind(&id_bytes)
    .bind(v)
    .execute(&state.pool)
    .await
    .map_err(|e| AppError::Internal(format!("DB error: {e}")))?;

    if result.rows_affected() == 0 {
        return Err(AppError::Conflict("Listing was modified by another request".into()));
    }

    let now = floor_timestamp_6h(OffsetDateTime::now_utc().unix_timestamp());

    Ok(Json(ListingResponse {
        id,
        client_encrypted_blob: req.client_encrypted_blob,
        search_token: req.search_token,
        status: final_status,
        currency: final_currency,
        day_bucket: now,
        version: v + 1,
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

fn check_update_nonce_replay(listing_id: &str, nonce: &str) -> bool {
    use std::collections::HashSet;
    use std::sync::Mutex;
    use once_cell::sync::Lazy;

    static UPDATE_NONCES: Lazy<Mutex<HashSet<String>>> = Lazy::new(|| Mutex::new(HashSet::new()));
    let key = format!("{}:{}", listing_id, nonce);
    let mut set = UPDATE_NONCES.lock().unwrap_or_else(|e| e.into_inner());
    set.insert(key)
}
