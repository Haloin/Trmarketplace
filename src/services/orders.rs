use axum::{
    extract::{Path, State, Extension},
    Json, Router,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::db::models::{Order, OrderData, Listing, ListingData};
use crate::crypto::oblivious;
use crate::crypto::hmac_auth::{derive_domain_identity, domains};
use crate::crypto::zk::{constant_time_compare, floor_timestamp_6h};
use crate::gateway::state::AppState;
use crate::gateway::auth_common::AuthPubkey;
use crate::error::AppError;
use crate::crypto::escrow;
use crate::services::escrow::btc::{create_multisig_p2wsh, import_multisig_watchonly, parse_secp_pubkey};
use crate::services::payments::btc::BitcoinClient;

#[derive(Deserialize)]
pub struct CreateOrderRequest {
    pub listing_id: String,
    pub currency: Option<String>,
    pub time_lock_days: Option<u64>,
    pub buyer_pubkey: String,
}

#[derive(Serialize)]
pub struct OrderResponse {
    pub id: String,
    pub listing_id: String,
    pub buyer_pubkey_hash: String,
    pub seller_pubkey_hash: String,
    pub buyer_pubkey: Option<String>,
    pub seller_pubkey: Option<String>,
    pub state: String,
    pub currency: String,
    pub escrow_address: Option<String>,
    pub escrow_amount: Option<String>,
    pub time_lock_seconds: i64,
    pub created_at: i64,
    pub funded_at: Option<i64>,
    pub shipped_at: Option<i64>,
    pub confirmed_at: Option<i64>,
    pub released_at: Option<i64>,
    pub refunded_at: Option<i64>,
    pub expires_at: Option<i64>,
    pub disputed_at: Option<i64>,
    pub dispute_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_pubkey: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fee_percent: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fee_address: Option<String>,
}

#[derive(Deserialize)]
pub struct FundOrderRequest {
    pub currency: String,
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/orders", post(create_order))
        .route("/orders/{id}", get(get_order))
        .route("/orders/{id}/fund", post(fund_order))
        .route("/orders/{id}/ship", post(ship_order))
        .route("/orders/{id}/confirm", post(confirm_order))
        .route("/orders/{id}/cancel", post(cancel_order))
        .route("/orders/{id}/refund", post(refund_order))
}

fn to_response(order: &Order, data: &OrderData) -> OrderResponse {
    OrderResponse {
        id: hex::encode(&order.id),
        listing_id: hex::encode(&data.listing_id),
        buyer_pubkey_hash: hex::encode(&data.buyer_pubkey_hash),
        seller_pubkey_hash: hex::encode(&data.seller_pubkey_hash),
        buyer_pubkey: data.buyer_pubkey.clone(),
        seller_pubkey: data.seller_pubkey.clone(),
        state: data.state.clone(),
        currency: data.currency.clone(),
        escrow_address: data.escrow_address.clone(),
        escrow_amount: data.escrow_amount.clone(),
        time_lock_seconds: data.time_lock_seconds,
        created_at: data.created_at,
        funded_at: data.funded_at,
        shipped_at: data.shipped_at,
        confirmed_at: data.confirmed_at,
        released_at: data.released_at,
        refunded_at: data.refunded_at,
        expires_at: data.expires_at,
        disputed_at: data.disputed_at,
        dispute_id: data.dispute_id.clone(),
        owner_pubkey: data.owner_pubkey.clone(),
        fee_percent: data.fee_percent,
        fee_address: data.fee_address.clone(),
    }
}

fn order_domain_id(secret: &str, pk_hash: &[u8]) -> Result<Vec<u8>, AppError> {
    derive_domain_identity(secret.as_bytes(), domains::ORDERS, pk_hash)
        .ok_or_else(|| AppError::Internal("Domain identity derivation failed".into()))
}

fn decrypt_listing_data(listing: &Listing, master_seed: &[u8]) -> Option<ListingData> {
    let raw = oblivious::decrypt_listing_blob(
        &listing.encrypted_listing_blob,
        master_seed,
        &listing.id,
    )?;
    serde_json::from_slice(&raw).ok()
}

async fn decrypt_order_data(order: &Order, state: &AppState) -> Result<OrderData, AppError> {
    let raw = oblivious::decrypt_order_blob(&order.encrypted_order_blob, &state.master_seed[..], &order.id)
        .ok_or_else(|| AppError::Internal("Failed to decrypt order".into()))?;
    serde_json::from_slice(&raw)
        .map_err(|e| AppError::Internal(format!("Corrupt order data: {e}")))
}

async fn read_order(state: &AppState, id: &[u8]) -> Result<(Order, OrderData), AppError> {
    let order = sqlx::query_as::<_, Order>(
        "SELECT id, encrypted_order_blob, day_bucket, expiry_bucket, version FROM orders WHERE id = ?1"
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| AppError::Internal(format!("DB error: {e}")))?
    .ok_or_else(|| AppError::NotFound("Order not found".into()))?;
    let data = decrypt_order_data(&order, state).await?;
    Ok((order, data))
}

async fn write_order(state: &AppState, order: &Order, data: &OrderData) -> Result<(), AppError> {
    let json = serde_json::to_vec(data)
        .map_err(|e| AppError::Internal(format!("Serialize: {e}")))?;
    let blob = oblivious::encrypt_order_blob(&json, &state.master_seed[..], &order.id)
        .ok_or_else(|| AppError::Internal("Encryption failed".into()))?;
    let expiry_bucket = data.expires_at.map(floor_timestamp_6h);
    let result = sqlx::query(
        "UPDATE orders SET encrypted_order_blob = ?1, expiry_bucket = ?2, version = version + 1 WHERE id = ?3 AND version = ?4"
    )
    .bind(&blob)
    .bind(expiry_bucket)
    .bind(&order.id)
    .bind(order.version)
    .execute(&state.pool)
    .await
    .map_err(|e| AppError::Internal(format!("DB error: {e}")))?;
    if result.rows_affected() == 0 {
        return Err(AppError::Conflict("Order was modified by another request".into()));
    }
    Ok(())
}

async fn create_order(
    State(state): State<AppState>,
    Extension(AuthPubkey(buyer_pk_hash)): Extension<AuthPubkey>,
    Json(req): Json<CreateOrderRequest>,
) -> Result<Json<OrderResponse>, AppError> {
    let now = floor_timestamp_6h(OffsetDateTime::now_utc().unix_timestamp());

    let listing_id = hex::decode(&req.listing_id)
        .map_err(|_| AppError::BadRequest("Invalid listing_id".into()))?;

    let listing = sqlx::query_as::<_, Listing>(
        "SELECT * FROM listings WHERE id = ?1"
    )
    .bind(&listing_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| AppError::Internal(format!("DB error: {e}")))?
    .ok_or_else(|| AppError::NotFound("Listing not found".into()))?;

    let listing_data = decrypt_listing_data(&listing, &state.master_seed)
        .ok_or_else(|| AppError::Internal("listing decryption failed".into()))?;

    if listing_data.status != "active" {
        return Err(AppError::NotFound("Listing not active".into()));
    }

    let buyer_order_id = order_domain_id(&state.config.server.server_secret, &buyer_pk_hash)?;
    let seller_order_id = order_domain_id(&state.config.server.server_secret, &listing_data.seller_pubkey_hash)?;

    if constant_time_compare(&seller_order_id, &buyer_order_id) {
        return Err(AppError::BadRequest("Cannot buy your own listing".into()));
    }

    let lock_days = req.time_lock_days.unwrap_or(state.config.server.default_lock_days);
    let lock_seconds = (lock_days * 86400) as i64;
    let order_id_bytes = Order::new_id();
    let escrow_amount = Some(listing_data.price_amount.clone());
    let currency = req.currency.unwrap_or(listing_data.currency);
    let currency_upper = currency.to_uppercase();

    if currency_upper != "XMR" && currency_upper != "BTC" {
        return Err(AppError::BadRequest("Currency must be XMR or BTC".into()));
    }

    let (owner_pubkey, fee_percent, fee_address) =
        if currency_upper == "BTC" {
            let sk = escrow::derive_order_key(&state.master_seed, &order_id_bytes)
                .map_err(|e| AppError::Internal(format!("Key derivation failed: {e}")))?;
            let pk = escrow::order_public_key(&sk);
            (
                Some(hex::encode(pk.serialize())),
                Some(state.config.escrow.fee_percent as i64),
                state.config.escrow.fee_address_btc.clone(),
            )
        } else {
            (None, None, None)
        };

    let data = OrderData {
        listing_id: listing_id.clone(),
        buyer_pubkey_hash: buyer_order_id,
        seller_pubkey_hash: seller_order_id,
        buyer_pubkey: Some(req.buyer_pubkey.clone()),
        seller_pubkey: listing_data.seller_pubkey.clone(),
        state: "pending".to_string(),
        currency,
        escrow_address: None,
        escrow_amount,
        time_lock_seconds: lock_seconds,
        created_at: now,
        funded_at: None,
        shipped_at: None,
        confirmed_at: None,
        released_at: None,
        refunded_at: None,
        expires_at: Some(now + lock_seconds),
        disputed_at: None,
        dispute_id: None,
        owner_pubkey,
        fee_percent,
        fee_address,
        dispute: None,
        chat_messages: vec![],
    };

    let json = serde_json::to_vec(&data)
        .map_err(|e| AppError::Internal(format!("Serialize: {e}")))?;
    let blob = oblivious::encrypt_order_blob(&json, &state.master_seed[..], &order_id_bytes)
        .ok_or_else(|| AppError::Internal("Encryption failed".into()))?;
    let day_bucket = now;
    let expiry_bucket = Some(floor_timestamp_6h(now + lock_seconds));

    sqlx::query(
        "INSERT INTO orders (id, encrypted_order_blob, day_bucket, expiry_bucket) VALUES (?1, ?2, ?3, ?4)"
    )
    .bind(&order_id_bytes)
    .bind(&blob)
    .bind(day_bucket)
    .bind(expiry_bucket)
    .execute(&state.pool)
    .await
    .map_err(|e| AppError::Internal(format!("DB error: {e}")))?;

    let order = Order { id: order_id_bytes, encrypted_order_blob: blob, day_bucket, expiry_bucket, version: 1 };
    Ok(Json(to_response(&order, &data)))
}

async fn fund_order(
    State(state): State<AppState>,
    Extension(AuthPubkey(user_pk_hash)): Extension<AuthPubkey>,
    Path(id): Path<String>,
    Json(req): Json<FundOrderRequest>,
) -> Result<Json<OrderResponse>, AppError> {
    let id_bytes = hex::decode(&id)
        .map_err(|_| AppError::BadRequest("Invalid id".into()))?;

    let (order, mut data) = read_order(&state, &id_bytes).await?;

    let user_order_id = order_domain_id(&state.config.server.server_secret, &user_pk_hash)?;
    if !constant_time_compare(&data.buyer_pubkey_hash, &user_order_id) {
        return Err(AppError::Forbidden("Only buyer can fund order".into()));
    }

    if !data.can_transition_to("funded") {
        return Err(AppError::BadRequest(
            format!("Invalid state transition: {} -> funded", data.state)
        ));
    }

    let listing = sqlx::query_as::<_, Listing>(
        "SELECT * FROM listings WHERE id = ?1"
    )
    .bind(&data.listing_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| AppError::Internal(format!("DB error: {e}")))?
    .ok_or_else(|| AppError::NotFound("Listing not found".into()))?;

    let listing_data = decrypt_listing_data(&listing, &state.master_seed)
        .ok_or_else(|| AppError::Internal("listing decryption failed".into()))?;

    let currency_upper = req.currency.to_uppercase();
    if currency_upper != "XMR" && currency_upper != "BTC" {
        return Err(AppError::BadRequest("Currency must be XMR or BTC".into()));
    }

    if listing_data.currency != currency_upper {
        return Err(AppError::BadRequest(
            format!("Listing {} only accepts {}, not {}", hex::encode(&listing.id), listing_data.currency, currency_upper)
        ));
    }

    let now = floor_timestamp_6h(OffsetDateTime::now_utc().unix_timestamp());

    let (escrow_address, _multi_sig_key, _multi_sig_redeem_script) =
        if currency_upper == "BTC" {
            let buyer_pk_hex = data.buyer_pubkey.as_ref()
                .ok_or_else(|| AppError::BadRequest("Missing buyer pubkey for BTC multi-sig".into()))?;
            let seller_pk_hex = data.seller_pubkey.as_ref()
                .ok_or_else(|| AppError::BadRequest("Missing seller pubkey for BTC multi-sig".into()))?;
            let owner_pk_hex = data.owner_pubkey.as_ref()
                .ok_or_else(|| AppError::BadRequest("Missing owner pubkey".into()))?;

            let buyer_pk = parse_secp_pubkey(buyer_pk_hex)
                .map_err(|_| AppError::BadRequest("Invalid buyer pubkey".into()))?;
            let seller_pk = parse_secp_pubkey(seller_pk_hex)
                .map_err(|_| AppError::BadRequest("Invalid seller pubkey".into()))?;
            let owner_pk = parse_secp_pubkey(owner_pk_hex)
                .map_err(|_| AppError::BadRequest("Invalid owner pubkey".into()))?;

            let network = state.config.bitcoin.btc_network()
                .map_err(|e| AppError::Internal(format!("Config error: {e}")))?;

            let ms = create_multisig_p2wsh(&buyer_pk, &seller_pk, &owner_pk, network)
                .map_err(|e| AppError::Internal(format!("Multi-sig creation failed: {e}")))?;

            let rpc = BitcoinClient::new(state.config.bitcoin.clone())
                .map_err(|e| AppError::Internal(format!("BTC RPC client: {e}")))?;
            let label = format!("order:{}", hex::encode(&id_bytes));
            import_multisig_watchonly(&ms.address, &ms.redeem_script_hex, &label, &rpc)
                .await
                .map_err(|e| AppError::Internal(format!("BTC import failed: {e}")))?;

            (Some(ms.address.clone()), Some(ms.address.into_bytes()), Some(ms.redeem_script_hex))
        } else {
            let xmr_client = crate::services::payments::xmr::MoneroViewOnlyClient::new(state.config.monero.clone());
            match xmr_client.create_subaddress(&hex::encode(&id_bytes)).await {
                Ok(addr) => (Some(addr), None, None),
                Err(_) => {
                    return Err(AppError::Internal("Failed to create XMR payment address".into()));
                }
            }
        };

    data.state = "funded".to_string();
    data.currency = currency_upper;
    data.escrow_address = escrow_address;
    data.funded_at = Some(now);

    write_order(&state, &order, &data).await?;

    Ok(Json(to_response(&order, &data)))
}

async fn get_order(
    State(state): State<AppState>,
    Extension(AuthPubkey(user_pk_hash)): Extension<AuthPubkey>,
    Path(id): Path<String>,
) -> Result<Json<OrderResponse>, AppError> {
    let id_bytes = hex::decode(&id)
        .map_err(|_| AppError::BadRequest("Invalid id".into()))?;

    let (order, data) = read_order(&state, &id_bytes).await?;

    let user_order_id = order_domain_id(&state.config.server.server_secret, &user_pk_hash)?;
    if !constant_time_compare(&data.buyer_pubkey_hash, &user_order_id)
        && !constant_time_compare(&data.seller_pubkey_hash, &user_order_id)
    {
        return Err(AppError::Forbidden("Not your order".into()));
    }

    Ok(Json(to_response(&order, &data)))
}

async fn ship_order(
    State(state): State<AppState>,
    Extension(AuthPubkey(user_pk_hash)): Extension<AuthPubkey>,
    Path(id): Path<String>,
) -> Result<Json<OrderResponse>, AppError> {
    let id_bytes = hex::decode(&id)
        .map_err(|_| AppError::BadRequest("Invalid id".into()))?;

    let (order, mut data) = read_order(&state, &id_bytes).await?;

    let user_order_id = order_domain_id(&state.config.server.server_secret, &user_pk_hash)?;
    if !constant_time_compare(&data.seller_pubkey_hash, &user_order_id) {
        return Err(AppError::Forbidden("Only seller can ship".into()));
    }

    if data.state == "disputed" {
        return Err(AppError::BadRequest("Cannot ship disputed order".into()));
    }

    if !data.can_transition_to("shipped") {
        return Err(AppError::BadRequest(
            format!("Invalid state transition: {} -> shipped", data.state)
        ));
    }

    let now = floor_timestamp_6h(OffsetDateTime::now_utc().unix_timestamp());
    data.state = "shipped".to_string();
    data.shipped_at = Some(now);
    write_order(&state, &order, &data).await?;

    Ok(Json(to_response(&order, &data)))
}

async fn confirm_order(
    State(state): State<AppState>,
    Extension(AuthPubkey(user_pk_hash)): Extension<AuthPubkey>,
    Path(id): Path<String>,
) -> Result<Json<OrderResponse>, AppError> {
    let id_bytes = hex::decode(&id)
        .map_err(|_| AppError::BadRequest("Invalid id".into()))?;

    let (order, mut data) = read_order(&state, &id_bytes).await?;

    let user_order_id = order_domain_id(&state.config.server.server_secret, &user_pk_hash)?;
    if !constant_time_compare(&data.buyer_pubkey_hash, &user_order_id) {
        return Err(AppError::Forbidden("Only buyer can confirm".into()));
    }

    if data.state == "disputed" {
        return Err(AppError::BadRequest("Cannot confirm disputed order".into()));
    }

    if !data.can_transition_to("confirmed") {
        return Err(AppError::BadRequest(
            format!("Invalid state transition: {} -> confirmed", data.state)
        ));
    }

    let now = floor_timestamp_6h(OffsetDateTime::now_utc().unix_timestamp());

    if data.can_transition_to("released") {
        data.state = "released".to_string();
        data.released_at = Some(now);
        data.confirmed_at = Some(now);
    } else {
        data.state = "confirmed".to_string();
        data.confirmed_at = Some(now);
    }
    write_order(&state, &order, &data).await?;

    Ok(Json(to_response(&order, &data)))
}

async fn cancel_order(
    State(state): State<AppState>,
    Extension(AuthPubkey(user_pk_hash)): Extension<AuthPubkey>,
    Path(id): Path<String>,
) -> Result<Json<OrderResponse>, AppError> {
    let id_bytes = hex::decode(&id)
        .map_err(|_| AppError::BadRequest("Invalid id".into()))?;

    let (order, mut data) = read_order(&state, &id_bytes).await?;

    let user_order_id = order_domain_id(&state.config.server.server_secret, &user_pk_hash)?;
    if !constant_time_compare(&data.seller_pubkey_hash, &user_order_id) {
        return Err(AppError::Forbidden("Only seller can cancel".into()));
    }

    if data.state == "disputed" {
        return Err(AppError::BadRequest("Cannot cancel disputed order".into()));
    }

    if !data.can_transition_to("cancelled") {
        return Err(AppError::BadRequest(
            format!("Invalid state transition: {} -> cancelled", data.state)
        ));
    }

    data.state = "cancelled".to_string();
    write_order(&state, &order, &data).await?;

    Ok(Json(to_response(&order, &data)))
}

async fn refund_order(
    State(state): State<AppState>,
    Extension(AuthPubkey(user_pk_hash)): Extension<AuthPubkey>,
    Path(id): Path<String>,
) -> Result<Json<OrderResponse>, AppError> {
    let id_bytes = hex::decode(&id)
        .map_err(|_| AppError::BadRequest("Invalid id".into()))?;

    let (order, mut data) = read_order(&state, &id_bytes).await?;

    let user_order_id = order_domain_id(&state.config.server.server_secret, &user_pk_hash)?;
    if !constant_time_compare(&data.buyer_pubkey_hash, &user_order_id) {
        return Err(AppError::Forbidden("Only buyer can request refund".into()));
    }

    let now = floor_timestamp_6h(OffsetDateTime::now_utc().unix_timestamp());

    if data.state != "disputed" {
        return Err(AppError::BadRequest("Refund not available: open a dispute first".into()));
    }

    if !data.can_transition_to("refunded") {
        return Err(AppError::BadRequest(
            format!("Invalid state transition: {} -> refunded", data.state)
        ));
    }

    data.state = "refunded".to_string();
    data.refunded_at = Some(now);
    write_order(&state, &order, &data).await?;

    Ok(Json(to_response(&order, &data)))
}
