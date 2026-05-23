use axum::{
    extract::Request,
    middleware::Next,
    response::Response,
    body::{Body, Bytes},
    http::HeaderValue,
};

const PADDED_SIZE: usize = 4096;

fn padded_size(actual: usize) -> usize {
    if actual == 0 {
        PADDED_SIZE
    } else {
        ((actual + PADDED_SIZE - 1) / PADDED_SIZE) * PADDED_SIZE
    }
}

pub async fn response_padding_middleware(
    request: Request,
    next: Next,
) -> Response {
    let response = next.run(request).await;

    let (mut parts, body) = response.into_parts();

    let body_bytes = match axum::body::to_bytes(body, usize::MAX).await {
        Ok(bytes) => bytes,
        Err(_) => {
            let padded = vec![b' '; PADDED_SIZE];
            let _ = parts.headers.insert(
                "Content-Length",
                HeaderValue::from_static("4096"),
            );
            return Response::from_parts(parts, Body::from(Bytes::from(padded)));
        }
    };

    let target_len = padded_size(body_bytes.len());
    let mut padded: Vec<u8> = body_bytes.to_vec();
    padded.resize(target_len, b' ');

    let len_str = target_len.to_string();
    let _ = parts.headers.insert(
        "Content-Length",
        HeaderValue::from_str(&len_str).unwrap_or_else(|_| HeaderValue::from_static("4096")),
    );

    Response::from_parts(parts, Body::from(Bytes::from(padded)))
}
