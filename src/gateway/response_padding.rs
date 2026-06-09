use axum::{
    extract::Request,
    middleware::Next,
    response::Response,
    body::{Body, Bytes},
    http::HeaderValue,
};

const PADDED_SIZE: usize = 4096;

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

    if body_bytes.len() > PADDED_SIZE {
        let _ = parts.headers.insert(
            "Content-Length",
            HeaderValue::from_str(&body_bytes.len().to_string())
                .unwrap_or_else(|_| HeaderValue::from_static("4096")),
        );
        return Response::from_parts(parts, Body::from(body_bytes));
    }

    let mut padded: Vec<u8> = body_bytes.to_vec();
    padded.resize(PADDED_SIZE, b' ');

    let _ = parts.headers.insert(
        "Content-Length",
        HeaderValue::from_static("4096"),
    );

    Response::from_parts(parts, Body::from(Bytes::from(padded)))
}
