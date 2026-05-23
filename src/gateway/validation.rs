use axum::{
    extract::Request,
    middleware::Next,
    response::{IntoResponse, Response},
    http::{header, StatusCode},
    Json,
};
use serde::Deserialize;
use serde_json::json;

const MAX_REQUEST_SIZE: usize = 1_048_576;
const MAX_PATH_LENGTH: usize = 256;
const MAX_HEADER_COUNT: usize = 50;
const MAX_HEADER_VALUE_LENGTH: usize = 8192;

fn uniform_rejection() -> Response {
    (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error":"error"}))).into_response()
}

pub async fn validation_middleware(
    request: Request,
    next: Next,
) -> Response {
    let content_length = request
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<usize>().ok());

    if let Some(len) = content_length {
        if len > MAX_REQUEST_SIZE {
            return uniform_rejection();
        }
    }

    let path = request.uri().path();
    if path.len() > MAX_PATH_LENGTH {
        return uniform_rejection();
    }

    let header_count = request.headers().iter().count();
    if header_count > MAX_HEADER_COUNT {
        return uniform_rejection();
    }

    for (_name, value) in request.headers() {
        if let Ok(value_str) = value.to_str() {
            if value_str.len() > MAX_HEADER_VALUE_LENGTH {
                return uniform_rejection();
            }
        }
    }

    let method = request.method();
    if method == "POST" || method == "PUT" || method == "PATCH" {
        let content_type = request.headers().get(header::CONTENT_TYPE);
        if content_type.is_none() {
            return uniform_rejection();
        }

        if let Some(ct) = content_type {
            if let Ok(ct_str) = ct.to_str() {
                if !ct_str.starts_with("application/json") && !ct_str.starts_with("multipart/form-data") {
                    return uniform_rejection();
                }
            }
        }
    }

    next.run(request).await
}

// Validation traits for request bodies
pub trait Validatable {
    fn validate(&self) -> Result<(), String>;
}

// Generic validation for JSON bodies
pub fn validate_json<T: for<'de> Deserialize<'de> + Validatable>(
    body: &str,
) -> Result<T, String> {
    let value: T = serde_json::from_str(body)
        .map_err(|e| format!("Invalid JSON: {}", e))?;
    
    value.validate()?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validation_constants() {
        assert!(MAX_REQUEST_SIZE == 1_048_576);
        assert!(MAX_PATH_LENGTH == 256);
        assert!(MAX_HEADER_COUNT == 50);
        assert!(MAX_HEADER_VALUE_LENGTH == 8192);
    }
}
