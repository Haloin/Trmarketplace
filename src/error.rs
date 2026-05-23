use axum::{
    response::{IntoResponse, Response},
    http::StatusCode,
    Json,
};
use serde_json::json;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Authentication failed")]
    AuthFailed(String),

    #[error("Not found")]
    NotFound(String),

    #[error("Bad request")]
    BadRequest(String),

    #[error("Forbidden")]
    Forbidden(String),

    #[error("Conflict")]
    Conflict(String),

    #[error("Internal error")]
    Internal(String),

    #[error("Tor connection rejected")]
    TorRequired,

    #[error("Rate limited")]
    RateLimited,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        // Uniform error response — no distinguishing information.
        // All errors return 500 {"error":"error"} regardless of actual cause.
        // This prevents oracle attacks that exploit different error messages.
        (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error":"error"}))).into_response()
    }
}
