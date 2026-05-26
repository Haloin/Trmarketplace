pub mod tor_guard;
pub mod ratelimit;
pub mod rate_limit_middleware;
pub mod security;
pub mod auth_common;
pub mod state;
pub mod validation;
pub mod response_padding;
pub mod stateless_auth;
pub mod error_unifier;

use axum::{
    middleware,
    Router,
};
use std::sync::Arc;
use sqlx::sqlite::SqlitePool;

use crate::config::Config;
use crate::crypto::zk::KeyEncryptionKey;
use crate::gateway::ratelimit::RateLimiter;
use state::AppState;

async fn fallback_500() -> impl axum::response::IntoResponse {
    (axum::http::StatusCode::INTERNAL_SERVER_ERROR, axum::Json(serde_json::json!({"error":"error"})))
}

pub fn build_router(
    pool: SqlitePool,
    config: Arc<Config>,
    kek: KeyEncryptionKey,
    master_seed: [u8; 32],
    rate_limiter: RateLimiter,
) -> Router {
    let app_state = AppState {
        pool,
        config: Arc::new(config.as_ref().clone()),
        rate_limiter,
        kek: kek.clone(),
        master_seed,
        xmr_client: Default::default(),
        btc_client: Default::default(),
    };

    let state_for_auth = Arc::new(app_state.clone());
    let state_for_rate_limit = Arc::new(app_state.clone());
    let stateless_auth = move |req, next| {
        let state = state_for_auth.clone();
        async move {
            stateless_auth::stateless_auth_middleware(req, next, state).await
        }
    };

    let rate_limit_middleware = move |req, next| {
        let state = state_for_rate_limit.clone();
        async move {
            rate_limit_middleware::rate_limit_middleware(req, next, state).await
        }
    };

    let validation_middleware = |req, next| {
        async move {
            validation::validation_middleware(req, next).await
        }
    };

    Router::new()
        .merge(crate::services::auth::routes())
        .merge(crate::services::listings::routes())
        .merge(crate::services::orders::routes())
        .merge(crate::services::chat::routes())
        .merge(crate::services::search::routes())
        .merge(crate::services::admin::routes())
        .merge(crate::services::disputes::routes())
        .fallback(fallback_500)
        .layer(middleware::from_fn(security::security_headers_middleware))
        .layer(middleware::from_fn(tor_guard::tor_guard_middleware))
        .layer(middleware::from_fn(validation_middleware))
        .layer(middleware::from_fn(rate_limit_middleware))
        .layer(middleware::from_fn(stateless_auth))
        .layer(middleware::from_fn(response_padding::response_padding_middleware))
        .layer(middleware::from_fn(error_unifier::error_unifier_middleware))
        .with_state(app_state)
}
