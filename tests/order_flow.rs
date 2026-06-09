mod common;

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    use super::common;

    #[tokio::test]
    async fn test_create_order_requires_auth() {
        let app = common::setup_test_app().await;

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/orders")
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        r#"{"listing_id":"test-listing","currency":"XMR","buyer_pubkey":"00ff"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(!resp.status().is_success(), "Order creation without auth must fail");
    }

    #[tokio::test]
    async fn test_get_order_requires_auth() {
        let app = common::setup_test_app().await;

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/orders/nonexistent-id")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(!resp.status().is_success(), "Order retrieval without auth must fail");
    }

    #[tokio::test]
    async fn test_create_order_missing_listing_id_fails() {
        let app = common::setup_test_app().await;

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/orders")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"currency":"XMR"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(!resp.status().is_success(), "Missing listing_id must fail auth check");
    }

    #[tokio::test]
    async fn test_create_order_empty_body_fails() {
        let app = common::setup_test_app().await;

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/orders")
                    .header("Content-Type", "application/json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(!resp.status().is_success());
    }

    #[tokio::test]
    async fn test_get_nonexistent_order_fails_no_auth() {
        let app = common::setup_test_app().await;

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/orders/fake-id-12345")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert!(!resp.status().is_success(), "Request without auth must fail");
    }
}
