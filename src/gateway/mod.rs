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
pub mod socks_pool;

use axum::{
    middleware,
    routing::get,
    Router,
};
use std::sync::Arc;
use sqlx::sqlite::SqlitePool;

use crate::config::Config;
use crate::crypto::zk::KeyEncryptionKey;
use crate::gateway::ratelimit::RateLimiter;
use crate::gateway::socks_pool::Socks5Pool;
use state::AppState;
use tokio::sync::broadcast;

async fn fallback_500() -> impl axum::response::IntoResponse {
    (axum::http::StatusCode::INTERNAL_SERVER_ERROR, axum::Json(serde_json::json!({"error":"error"})))
}

pub fn build_router(
    pool: SqlitePool,
    config: Arc<Config>,
    kek: KeyEncryptionKey,
    rate_limiter: RateLimiter,
    socks_pool: Arc<Socks5Pool>,
    payment_tx: broadcast::Sender<String>,
) -> Router {
    let admin_keypair: Option<Arc<crate::crypto::blind_sig::AdminKeypair>> = {
        if let Some(hex_str) = config.security.admin_privkey_hex.as_ref() {
            match crate::crypto::blind_sig::AdminKeypair::from_hex(hex_str) {
                Ok(kp) => {
                    tracing::info!("Loaded admin RSA keypair from config (admin_privkey_hex)");
                    Some(Arc::new(kp))
                }
                Err(e) => {
                    tracing::error!(error = %e, "Failed to load admin_privkey_hex from config — admin endpoints will be DISABLED");
                    None
                }
            }
        } else {
            tracing::warn!("No admin_privkey_hex in config — generating ephemeral admin keypair (dev mode). Admin actions will be UNSTABLE across restarts.");
            Some(Arc::new(crate::crypto::blind_sig::generate_admin_keypair(2048)))
        }
    };

    let app_state = AppState {
        pool,
        config: Arc::new(config.as_ref().clone()),
        rate_limiter,
        kek: kek.clone(),
        worker_key: None,
        admin_keypair,
        socks_pool: socks_pool.clone(),
        xmr_client: Default::default(),
        btc_client: Default::default(),
        payment_tx,
        last_notif_block: Default::default(),
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
        .merge(crate::services::public::routes())
        .merge(crate::services::auth::routes())
        .merge(crate::services::listings::routes())
        .merge(crate::services::orders::routes())
        .merge(crate::services::chat::routes())
        .merge(crate::services::admin::routes())
        .merge(crate::services::disputes::routes())
        .route("/ws/payments/:order_id", get(crate::services::payments::subscribe::ws_handler))
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
