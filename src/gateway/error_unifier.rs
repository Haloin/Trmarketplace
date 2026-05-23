use axum::{
    extract::Request,
    middleware::Next,
    response::{IntoResponse, Response},
    http::StatusCode,
    Json,
};
use serde_json::json;

pub async fn error_unifier_middleware(
    request: Request,
    next: Next,
) -> Response {
    let response = next.run(request).await;

    if response.status().is_client_error() {
        let (parts, _body) = response.into_parts();
        let orig_headers = parts.headers;

        let mut new_resp = (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error":"error"}))).into_response();
        *new_resp.headers_mut() = orig_headers;
        new_resp.headers_mut().remove("content-length");

        return new_resp;
    }

    response
}
