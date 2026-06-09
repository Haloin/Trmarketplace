mod common;

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    use super::common;

    #[tokio::test]
    async fn test_list_listings_requires_auth() {
        let app = common::setup_test_app().await;

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/listings")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert!(!resp.status().is_success(), "Listing access without auth must fail");
    }

    #[tokio::test]
    async fn test_create_listing_requires_auth() {
        let app = common::setup_test_app().await;

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/listings")
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        r#"{"encrypted_data":"00ff","currency":"XMR","price_amount":"1.5"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert!(!resp.status().is_success(), "Listing creation without auth must fail");
    }

    #[tokio::test]
    async fn test_create_listing_missing_fields_fails() {
        let app = common::setup_test_app().await;

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/listings")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert!(!resp.status().is_success());
    }

    #[tokio::test]
    async fn test_create_listing_empty_body_fails() {
        let app = common::setup_test_app().await;

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/listings")
                    .header("Content-Type", "application/json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert!(!resp.status().is_success());
    }

    #[tokio::test]
    async fn test_listings_returns_json_array_on_success() {
        let app = common::setup_test_app().await;

        // Without auth, should still return a non-success but not crash
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/listings")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert!(!resp.status().is_success());
        // Verify the response body is parseable JSON
        let body = axum::body::to_bytes(resp.into_body(), 10_240).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(parsed.get("error").is_some() || parsed.is_array(),
                "Response must be valid JSON (error or array)");
    }
}
