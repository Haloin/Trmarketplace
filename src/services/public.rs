//! Public unauthenticated metadata for the WASM client.

use axum::{extract::State, Json, Router, routing::get};
use serde::Serialize;

use crate::error::AppError;
use crate::gateway::state::AppState;

#[derive(Serialize)]
pub struct WorkerPubkeyResponse {
    /// X25519 public key (32 bytes, hex) for worker payment blob encryption.
    /// Set `security.worker_payment_pubkey_hex` in config or `WORKER_PAYMENT_PUBKEY_HEX` env.
    pub worker_payment_pubkey_hex: Option<String>,
}

pub fn routes() -> Router<AppState> {
    Router::new().route("/public/worker-pubkey", get(worker_pubkey))
}

async fn worker_pubkey(
    State(state): State<AppState>,
) -> Result<Json<WorkerPubkeyResponse>, AppError> {
    let hex_str = crate::crypto::worker_pubkey::resolve_worker_payment_pubkey(
        &state.config.server.data_dir,
        state.config.security.worker_payment_pubkey_hex.as_deref(),
    );
    Ok(Json(WorkerPubkeyResponse {
        worker_payment_pubkey_hex: hex_str,
    }))
}
