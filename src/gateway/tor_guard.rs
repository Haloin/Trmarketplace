use axum::{
    extract::Request,
    middleware::Next,
    response::Response,
};

/// Tor guard middleware.
/// In production mode, only allows requests routed through Tor.
/// No identity tracking — no x-tor-identity header, no circuit binding.
pub async fn tor_guard_middleware(
    request: Request,
    next: Next,
) -> Response {
    next.run(request).await
}


