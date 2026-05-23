#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        Router,
    };
    use std::sync::Arc;
    use tower::ServiceExt;

    use tor_marketplace::config::{
        BitcoinConfig, Config, DatabaseConfig, EscrowConfig, MoneroConfig, SecurityConfig,
        ServerConfig, TorConfig,
    };
    use tor_marketplace::crypto::zk::KeyEncryptionKey;
    use tor_marketplace::db;
    use tor_marketplace::gateway;
    use tor_marketplace::gateway::ratelimit::RateLimiter;

    fn test_config() -> Config {
        Config {
            database: DatabaseConfig::Sqlite {
                path: std::path::PathBuf::from(":memory:"),
            },
            server: ServerConfig {
                server_secret: "test_secret_32_bytes_long_for_testing!!".to_string(),
                ..ServerConfig::default()
            },
            tor: TorConfig::default(),
            monero: MoneroConfig::default(),
            bitcoin: BitcoinConfig::default(),
            security: SecurityConfig::default(),
            escrow: EscrowConfig::default(),
        }
    }

    async fn setup_test_app() -> Router {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(2)
            .connect(":memory:")
            .await
            .expect("Test DB failed");
        db::run_sqlite_migrations(&pool).await.unwrap();

        let config = Arc::new(test_config());
        let kek = KeyEncryptionKey::new();
        let rate_limiter = RateLimiter::new(30, 60);
        let master_seed = [0u8; 32];

        gateway::build_router(pool, config, kek, master_seed, rate_limiter)
    }

    #[tokio::test]
    async fn test_challenge_valid_pubkey() {
        let app = setup_test_app().await;
        let pubkey_hex =
            "0101010101010101010101010101010101010101010101010101010101010101";

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/challenge")
                    .header("Content-Type", "application/json")
                    .body(Body::from(format!(r#"{{"pubkey":"{}"}}"#, pubkey_hex)))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert!(response.status().is_success());
    }

    #[tokio::test]
    async fn test_challenge_invalid_pubkey() {
        let app = setup_test_app().await;

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/challenge")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"pubkey":"invalid"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        // All errors return 500 {"error":"error"} (Phase 1 anonymity — prevents oracle attacks)
        assert!(response.status().is_server_error());
    }

    #[tokio::test]
    async fn test_verify_no_body() {
        let app = setup_test_app().await;

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/verify")
                    .header("Content-Type", "application/json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // error_unifier converts Json rejection (422) to uniform 500 {"error":"error"}
        assert!(response.status().is_server_error());
    }

    #[tokio::test]
    async fn test_empty_body_rejected_as_500() {
        let app = setup_test_app().await;

        // POST to any Json endpoint with empty body → error_unifier converts 422 → 500
        let response = app
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

        assert!(response.status().is_server_error());
    }

    #[tokio::test]
    async fn test_full_auth_flow() {
        use ed25519_dalek::Signer;
        use ed25519_dalek::SigningKey;

        let app = setup_test_app().await;

        // Generate a fresh ed25519 keypair for this test
        let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let pubkey_hex = hex::encode(signing_key.verifying_key().to_bytes());

        // Step 1: Request a challenge
        let challenge_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/challenge")
                    .header("Content-Type", "application/json")
                    .body(Body::from(format!(r#"{{"pubkey":"{}"}}"#, pubkey_hex)))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(challenge_resp.status(), StatusCode::OK);

        // Parse challenge response
        let body_bytes =
            axum::body::to_bytes(challenge_resp.into_body(), 10_240).await.unwrap();
        let body: serde_json::Value =
            serde_json::from_slice(&body_bytes).unwrap();
        let challenge_id = body["challenge_id"].as_str().unwrap().to_string();
        let challenge_hex = body["challenge"].as_str().unwrap().to_string();
        let challenge_bytes = hex::decode(&challenge_hex).unwrap();

        // Sign the challenge with the private key
        let signature = signing_key.sign(&challenge_bytes);
        let sig_hex = hex::encode(signature.to_bytes());

        // Step 2: Verify signature and obtain auth_key
        let verify_resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/verify")
                    .header("Content-Type", "application/json")
                    .body(Body::from(format!(
                        r#"{{"pubkey":"{}","challenge_id":"{}","signature":"{}"}}"#,
                        pubkey_hex, challenge_id, sig_hex
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(verify_resp.status(), StatusCode::OK);

        let body_bytes =
            axum::body::to_bytes(verify_resp.into_body(), 10_240).await.unwrap();
        let body: serde_json::Value =
            serde_json::from_slice(&body_bytes).unwrap();
        let auth_key = body["auth_key"].as_str().unwrap().to_string();
        assert!(!auth_key.is_empty());
    }

    #[tokio::test]
    async fn test_listings_no_auth() {
        let app = setup_test_app().await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/listings")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Auth failure returns 500 {"error":"error"} — uniform error response (Phase 1)
        assert!(!response.status().is_success());
    }

    #[tokio::test]
    async fn test_create_listing_no_auth() {
        let app = setup_test_app().await;

        let response = app
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

        assert!(!response.status().is_success());
    }
}