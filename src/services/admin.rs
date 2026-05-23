//! Admin Service
//! 
//! Administrative functions including KEK rotation.
//! SECURITY: Never expose KEK over network

use axum::{
    extract::{State, Extension},
    Json, Router,
    routing::post,
};
use serde::Serialize;

use crate::gateway::state::AppState;
use crate::gateway::auth_common::AuthPubkey;
use crate::error::AppError;
use crate::crypto::zk::KeyEncryptionKey;

#[derive(Serialize)]
pub struct RotateKekResponse {
    pub success: bool,
    pub message: String,
    pub kek_rotated: bool,
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/admin/rotate-kek", post(rotate_kek))
}

async fn rotate_kek(
    State(state): State<AppState>,
    Extension(AuthPubkey(user_pk_hash)): Extension<AuthPubkey>,
) -> Result<Json<RotateKekResponse>, AppError> {
    // SECURITY: Only admin can rotate the KEK
    if !crate::gateway::auth_common::is_admin(&state.config, &user_pk_hash) {
        return Err(AppError::Forbidden("Only admin can rotate KEK".into()));
    }

    // SECURITY: Generate new KEK but NEVER return it over the network
    let new_kek = KeyEncryptionKey::new();
    let new_kek_hex = hex::encode(new_kek.as_bytes());
    
    // Update config with new KEK
    let mut config_clone = (*state.config).clone();
    config_clone.security.kek_hex = Some(new_kek_hex);
    
    // Save config (persists KEK to disk, not to client)
    if let Err(e) = config_clone.save() {
        tracing::error!("Failed to persist KEK: {}", e);
        return Err(AppError::Internal("Failed to persist KEK rotation".into()));
    }
    
    
    // SECURITY: Return confirmation WITHOUT the key
    Ok(Json(RotateKekResponse {
        success: true,
        message: "KEK rotated successfully. Key persisted to config file.".to_string(),
        kek_rotated: true,
    }))
}