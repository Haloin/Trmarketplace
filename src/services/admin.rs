//! Admin service — KEK rotation and blind-signed authorization.

use axum::{
    extract::{State, Json},
    Json as JsonResponse, Router,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};

use crate::gateway::state::AppState;
use crate::error::AppError;
use crate::crypto::{blind_sig, zk::KeyEncryptionKey};

#[derive(Deserialize)]
pub struct RotateKekRequest {
    /// Legacy field — kept for compat but ignored.
    pub session_nonce: String,
    /// Blinded RSA admin token signature (hex).
    pub token_signature: Option<String>,
    /// The 32-byte token message hash that was blindly signed.
    /// Must match: SHA256("admin:rotate_kek:rotate:" || token_nonce || ":" || token_expiry_hour)
    pub token_message: Option<String>,
    /// Nonce used in the token message (prevents token replay).
    pub token_nonce: Option<String>,
    /// Hour bucket when the token was issued. Server allows ±1 hour tolerance.
    pub token_expiry_hour: Option<i64>,
}

#[derive(Serialize)]
pub struct RotateKekResponse {
    pub success: bool,
    pub message: String,
    pub kek_rotated: bool,
}

#[derive(Deserialize)]
pub struct BlindSignRequest {
    /// Hex-encoded blinded message (the output of `blind_message`).
    pub blinded_blob: String,
}

#[derive(Serialize)]
pub struct BlindSignResponse {
    /// Hex-encoded blinded signature (to be unblinded by the client).
    pub blinded_signature: String,
}

#[derive(Serialize)]
pub struct AdminPubkeyResponse {
    /// Hex-encoded admin RSA public key (PKCS#1 DER).
    pub admin_pubkey_hex: String,
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/admin/blind-sign", post(blind_sign))
        .route("/admin/pubkey", get(get_admin_pubkey))
        .route("/admin/rotate-kek", post(rotate_kek))
}

async fn blind_sign(
    State(state): State<AppState>,
    Json(req): Json<BlindSignRequest>,
) -> Result<JsonResponse<BlindSignResponse>, AppError> {
    let kp = state.admin_keypair.as_ref()
        .ok_or_else(|| AppError::Internal("Admin keypair not configured".into()))?;
    let blinded = hex::decode(&req.blinded_blob)
        .map_err(|e| AppError::BadRequest(format!("Invalid hex: {e}")))?;
    if blinded.is_empty() || blinded.len() > 512 {
        return Err(AppError::BadRequest("Blinded message must be 1-512 bytes".into()));
    }
    let signature = blind_sig::sign_blinded(&blinded, &kp.private);
    Ok(JsonResponse(BlindSignResponse {
        blinded_signature: hex::encode(signature),
    }))
}

async fn get_admin_pubkey(
    State(state): State<AppState>,
) -> Result<JsonResponse<AdminPubkeyResponse>, AppError> {
    let kp = state.admin_keypair.as_ref()
        .ok_or_else(|| AppError::Internal("Admin keypair not configured".into()))?;
    let hex_str = kp.pubkey_hex()
        .map_err(|e| AppError::Internal(format!("Failed to serialize pubkey: {e}")))?;
    Ok(JsonResponse(AdminPubkeyResponse { admin_pubkey_hex: hex_str }))
}

async fn rotate_kek(
    State(state): State<AppState>,
    Json(req): Json<RotateKekRequest>,
) -> Result<JsonResponse<RotateKekResponse>, AppError> {
    let kp = state.admin_keypair.as_ref()
        .ok_or_else(|| AppError::Internal("Admin keypair not configured".into()))?;

    // Verify the blind-signed admin token (same pattern as resolve_dispute).
    let sig_bytes = req.token_signature.as_ref()
        .and_then(|s| hex::decode(s).ok())
        .ok_or_else(|| AppError::BadRequest("Missing or invalid token_signature".into()))?;
    let msg_bytes = req.token_message.as_ref()
        .and_then(|s| hex::decode(s).ok())
        .ok_or_else(|| AppError::BadRequest("Missing or invalid token_message".into()))?;
    let token_nonce_hex = req.token_nonce.as_ref()
        .ok_or_else(|| AppError::BadRequest("Missing token_nonce".into()))?;
    let token_nonce_bytes = hex::decode(token_nonce_hex)
        .map_err(|_| AppError::BadRequest("Invalid token_nonce hex".into()))?;
    let token_expiry = req.token_expiry_hour
        .ok_or_else(|| AppError::BadRequest("Missing token_expiry_hour".into()))?;

    if msg_bytes.len() != 32 {
        return Err(AppError::BadRequest("token_message must be 32 bytes".into()));
    }
    let mut msg_hash = [0u8; 32];
    msg_hash.copy_from_slice(&msg_bytes);

    let expected = blind_sig::compose_token_message(
        "admin:rotate_kek",
        "rotate",
        &token_nonce_bytes,
        token_expiry as u64,
    );
    if msg_hash != expected {
        return Err(AppError::Forbidden("Token message does not match request context".into()));
    }
    if !blind_sig::verify_token(&msg_hash, &sig_bytes, &kp.public) {
        return Err(AppError::Forbidden("Invalid admin token signature".into()));
    }

    let now_hour = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() / 3600;
    let expiry_i64 = token_expiry;
    if (expiry_i64 - now_hour as i64).abs() > 1 {
        return Err(AppError::Forbidden("Admin token expired or not yet valid".into()));
    }

    // SECURITY: Generate new KEK but NEVER return it over the network
    let new_kek = KeyEncryptionKey::new();
    let new_kek_hex = hex::encode(new_kek.as_bytes());

    // Write KEK to a dedicated file with restricted permissions,
    // NOT to the main config file (avoid mixing credentials with app config).
    let kek_path = state.config.server.data_dir.join("kek.hex");
    if let Err(e) = std::fs::write(&kek_path, &new_kek_hex) {
        tracing::error!("Failed to write KEK file: {}", e);
        return Err(AppError::Internal("Failed to persist KEK rotation".into()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&kek_path, std::fs::Permissions::from_mode(0o600));
    }

    tracing::info!("KEK rotated");
    Ok(JsonResponse(RotateKekResponse {
        success: true,
        message: "KEK rotated successfully. Key written to dedicated file.".to_string(),
        kek_rotated: true,
    }))
}