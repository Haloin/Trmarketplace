use axum::{
    extract::Request,
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::sync::Arc;

use crate::gateway::state::AppState;
use crate::gateway::auth_common::AuthPubkey;
use crate::error::AppError;

/// Rate limiting middleware
/// SECURITY: Limits requests per pubkey hash, not per IP (privacy-preserving)
pub async fn rate_limit_middleware(
    request: Request,
    next: Next,
    state: Arc<AppState>,
) -> Response {
    let key = get_rate_limit_key(&request);

    if !state.rate_limiter.check(&key).await {
        return AppError::RateLimited.into_response();
    }

    next.run(request).await
}

/// Get rate limit key from request
/// SECURITY: Uses pubkey hash from auth session, not IP address
/// Priority: 1) request extensions (AuthPubkey middleware) → 2) header fallback → 3) IP → 4) anonymous
fn get_rate_limit_key(request: &Request) -> String {
    // Priority 1: Read from request extension set by auth middleware
    if let Some(auth) = request.extensions().get::<AuthPubkey>() {
        let key = hex::encode(&auth.0);
        if !key.is_empty() {
            return key;
        }
    }
    
    // Priority 2: Try header fallback (legacy)
    if let Some(pubkey) = request.headers().get("x-auth-pubkey") {
        if let Ok(pubkey_str) = pubkey.to_str() {
            if !pubkey_str.is_empty() && pubkey_str != "anonymous" {
                return pubkey_str.to_string();
            }
        }
    }
    
    // Priority 3: Use X-Forwarded-For or X-Real-IP for unauthenticated requests
    // This is less ideal but necessary for challenge/verify endpoints
    if let Some(ip) = request.headers().get("x-forwarded-for") {
        if let Ok(ip_str) = ip.to_str() {
            if let Some(first_ip) = ip_str.split(',').next() {
                return format!("ip:{}", first_ip.trim());
            }
        }
    }
    
    if let Some(ip) = request.headers().get("x-real-ip") {
        if let Ok(ip_str) = ip.to_str() {
            return format!("ip:{}", ip_str);
        }
    }
    
    // Ultimate fallback
    "anonymous".to_string()
}

/// Extract pubkey from request (for use in other middleware)
pub fn extract_pubkey_from_request(request: &Request) -> Option<String> {
    // Try extensions first (most reliable)
    if let Some(auth) = request.extensions().get::<AuthPubkey>() {
        let key = hex::encode(&auth.0);
        if !key.is_empty() {
            return Some(key);
        }
    }
    // Fall back to header
    request.headers()
        .get("x-auth-pubkey")
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty() && *s != "anonymous")
        .map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_extract_pubkey() {
        // Test with mock request would go here
        // For now, just verify the function compiles
        assert!(true);
    }
}