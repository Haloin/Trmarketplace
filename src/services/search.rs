use axum::{
    extract::{Query, State},
    Json, Router,
    routing::get,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use crate::db::models::{Listing, ListingData};
use crate::crypto::oblivious;
use crate::crypto::zk::constant_time_compare;
use crate::gateway::state::AppState;
use crate::error::AppError;
#[cfg(test)]
use crate::crypto::client::generate_single_token;

#[derive(Deserialize)]
pub struct SearchRequest {
    pub q: String,
    pub search_tokens: Option<String>,
    pub encrypted_token: Option<String>,
    pub currency: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Serialize)]
pub struct SearchResponse {
    pub listings: Vec<ListingSearchResult>,
    pub total: i64,
}

#[derive(Serialize)]
pub struct ListingSearchResult {
    pub id: String,
    pub seller_pubkey_hash: String,
    pub encrypted_data: String,
    pub encrypted_search: Option<String>,
    pub currency: String,
    pub price_amount: String,
    pub status: String,
    pub created_at: i64,
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/search", get(search_listings))
}

async fn search_listings(
    State(state): State<AppState>,
    Query(req): Query<SearchRequest>,
) -> Result<Json<SearchResponse>, AppError> {
    let limit = req.limit.unwrap_or(50).min(100);
    let offset = req.offset.unwrap_or(0);

    let search_tokens: Vec<Vec<u8>> = if let Some(ref tokens_json) = req.search_tokens {
        let token_strs: Vec<String> = serde_json::from_str(tokens_json)
            .map_err(|_| AppError::BadRequest("Invalid search tokens format".into()))?;

        token_strs.into_iter()
            .map(|hex_str| hex::decode(&hex_str))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| AppError::BadRequest("Invalid token hex encoding".into()))?
    } else if let Some(ref enc_token_hex) = req.encrypted_token {
        vec![hex::decode(enc_token_hex)
            .map_err(|_| AppError::BadRequest("Invalid encrypted token".into()))?]
    } else {
        return Err(AppError::BadRequest("Search tokens required".into()));
    };

    if search_tokens.is_empty() {
        return Err(AppError::BadRequest("No search tokens provided".into()));
    }

    let listings = sqlx::query_as::<_, Listing>(
        "SELECT * FROM listings"
    )
    .fetch_all(&state.pool)
    .await
    .map_err(|e| AppError::Internal(format!("DB error: {}", e)))?;

    let mut seen_ids: HashSet<Vec<u8>> = HashSet::new();
    let mut matching: Vec<(Listing, ListingData)> = Vec::new();

    for listing in listings {
        if seen_ids.contains(&listing.id) {
            continue;
        }

        let Some(data) = (|| -> Option<ListingData> {
            let raw = oblivious::decrypt_listing_blob(
                &listing.encrypted_listing_blob,
                &state.master_seed,
                &listing.id,
            )?;
            serde_json::from_slice::<ListingData>(&raw).ok()
        })() else { continue };

        if data.status == "removed" {
            continue;
        }

        let matched = match &listing.search_token {
            Some(stored) => search_tokens.iter().any(|t| constant_time_compare(stored, t)),
            None => false,
        };

        if !matched {
            continue;
        }

        if let Some(ref cur) = req.currency {
            if &data.currency != cur { continue; }
        }

        seen_ids.insert(listing.id.clone());
        matching.push((listing, data));
    }

    let total = matching.len() as i64;
    let page: Vec<_> = matching.into_iter().skip(offset as usize).take(limit as usize).collect();

    Ok(Json(SearchResponse {
        listings: page.iter().map(|(l, d)| ListingSearchResult {
            id: hex::encode(&l.id),
            seller_pubkey_hash: hex::encode(&d.seller_pubkey_hash),
            encrypted_data: hex::encode(&d.encrypted_data),
            encrypted_search: d.encrypted_search.as_ref().map(|v| hex::encode(v)),
            currency: d.currency.clone(),
            price_amount: d.price_amount.clone(),
            status: d.status.clone(),
            created_at: d.created_at,
        }).collect(),
        total,
    }))
}

#[cfg(test)]
pub fn generate_server_token_for_test(keyword: &str, search_key: &[u8]) -> Vec<u8> {
    generate_single_token(keyword, search_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_generation_consistency() {
        let keyword = "electronics";
        let search_key = b"test-key-12345";

        let token1 = generate_single_token(keyword, search_key);
        let token2 = generate_single_token(keyword, search_key);

        assert_eq!(token1, token2);
        assert_eq!(token1.len(), 32);
    }

    #[test]
    fn test_different_keywords_different_tokens() {
        let search_key = b"test-key-12345";

        let token1 = generate_single_token("electronics", search_key);
        let token2 = generate_single_token("furniture", search_key);

        assert_ne!(token1, token2);
    }
}
