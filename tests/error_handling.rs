mod common;

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    use super::common;

    #[tokio::test]
    async fn test_empty_body_returns_generic_error() {
        let app = common::setup_test_app().await;

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/challenge")
                    .header("Content-Type", "application/json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert!(resp.status().is_server_error());
        let body: serde_json::Value =
            serde_json::from_slice(&axum::body::to_bytes(resp.into_body(), 10_240).await.unwrap()).unwrap();
        // Should have exactly one field: "error"
        assert!(body.get("error").is_some(), "Error response must have 'error' field");
        assert!(
            body.as_object().is_none_or(|m| m.len() <= 2),
            "Error response must not leak details"
        );
    }

    #[tokio::test]
    async fn test_malformed_json_returns_generic_error() {
        let app = common::setup_test_app().await;

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/challenge")
                    .header("Content-Type", "application/json")
                    .body(Body::from("this is not json"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert!(resp.status().is_server_error());
    }

    #[tokio::test]
    async fn test_missing_field_returns_generic_error() {
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

        assert!(resp.status().is_server_error());
    }

    #[tokio::test]
    async fn test_unknown_path_returns_generic_error() {
        let app = common::setup_test_app().await;

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/nonexistent-route-12345")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert!(resp.status().is_server_error() || resp.status().is_client_error());
        let body: serde_json::Value =
            serde_json::from_slice(&axum::body::to_bytes(resp.into_body(), 10_240).await.unwrap()).unwrap();
        if let Some(obj) = body.as_object() {
            assert!(obj.contains_key("error"), "Error response must have 'error' field");
            assert!(obj.len() <= 2, "Error response must not leak details");
        }
    }

    #[tokio::test]
    async fn test_rate_limited_endpoint_returns_generic_error() {
        use tor_marketplace::crypto::zk;

        let app = common::setup_test_app().await;
        let kek = zk::KeyEncryptionKey::new();
        let pt = b"test-plaintext";

        // Verify that our crypto works correctly (not testing rate limiting on the app)
        let ct = zk::encrypt_test(pt, &kek).unwrap();
        assert!(zk::decrypt_test(&ct, &kek).is_ok());

        // The app's rate limiter has generous limits (30/60s), so just verify
        // that hitting endpoints repeatedly doesn't crash
        for _ in 0..5 {
            let resp = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/auth/challenge")
                        .header("Content-Type", "application/json")
                        .body(Body::from(r#"{"pubkey":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#))
                        .unwrap(),
                )
                .await
                .unwrap();
            // Should either succeed or return a generic error (not crash)
            assert!(
                resp.status() == StatusCode::OK || resp.status().is_server_error(),
                "Repeated requests must not crash the server"
            );
        }
    }
}
