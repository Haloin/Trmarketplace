use axum::{
    extract::Request,
    middleware::Next,
    response::Response,
    http::HeaderValue,
};

pub async fn security_headers_middleware(
    request: Request,
    next: Next,
) -> Response {
    let host = request
        .headers()
        .get("Host")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let mut response = next.run(request).await;

    let headers = response.headers_mut();
    headers.insert("X-Content-Type-Options", HeaderValue::from_static("nosniff"));
    headers.insert("X-Frame-Options", HeaderValue::from_static("DENY"));
    headers.insert("Referrer-Policy", HeaderValue::from_static("no-referrer"));
    headers.insert("X-Robots-Tag", HeaderValue::from_static("noindex, nofollow"));
    headers.insert("Permissions-Policy", HeaderValue::from_static(
        "camera=(), microphone=(), geolocation=(), interest-cohort=()"
    ));
    headers.insert("Content-Security-Policy", HeaderValue::from_static(
        "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    ));
    headers.insert("Cache-Control", HeaderValue::from_static("no-store, max-age=0"));
    headers.insert("Pragma", HeaderValue::from_static("no-cache"));

    if let Some(host_str) = host {
        if host_str.contains(".onion") {
            if let Ok(val) = HeaderValue::from_str(&host_str) {
                headers.insert("Onion-Location", val);
            }
        }
    }

    response
}
