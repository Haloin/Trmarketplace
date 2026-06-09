mod common;

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::Router;
    use ed25519_dalek::Signer;
    use tower::ServiceExt;

    use super::common;

    async fn full_auth(app: &Router) -> (String, String) {
        let sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let pk_hex = hex::encode(sk.verifying_key().to_bytes());

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/challenge")
                    .header("Content-Type", "application/json")
                    .body(Body::from(format!(r#"{{"pubkey":"{}"}}"#, pk_hex)))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body: serde_json::Value =
            serde_json::from_slice(&axum::body::to_bytes(resp.into_body(), 10_240).await.unwrap()).unwrap();
        let challenge = hex::decode(body["challenge"].as_str().unwrap()).unwrap();
        let challenge_id = body["challenge_id"].as_str().unwrap().to_string();
        let sig = hex::encode(sk.sign(&challenge).to_bytes());

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/verify")
                    .header("Content-Type", "application/json")
                    .body(Body::from(format!(
                        r#"{{"pubkey":"{}","challenge_id":"{}","signature":"{}"}}"#,
                        pk_hex, challenge_id, sig
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body: serde_json::Value =
            serde_json::from_slice(&axum::body::to_bytes(resp.into_body(), 10_240).await.unwrap()).unwrap();
        let auth_key = body["auth_key"].as_str().unwrap().to_string();
        (pk_hex, auth_key)
    }

    #[tokio::test]
    async fn test_full_auth_flow_succeeds() {
        let app = common::setup_test_app().await;
        let (pk, _) = full_auth(&app).await;
        assert!(!pk.is_empty());
    }

    #[tokio::test]
    async fn test_auth_with_wrong_signature_fails() {
        let app = common::setup_test_app().await;
        let sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let pk_hex = hex::encode(sk.verifying_key().to_bytes());

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/challenge")
                    .header("Content-Type", "application/json")
                    .body(Body::from(format!(r#"{{"pubkey":"{}"}}"#, pk_hex)))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body: serde_json::Value =
            serde_json::from_slice(&axum::body::to_bytes(resp.into_body(), 10_240).await.unwrap()).unwrap();
        let challenge_id = body["challenge_id"].as_str().unwrap().to_string();

        // Wrong signature (signed with different key)
        let wrong_sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let wrong_sig = hex::encode(wrong_sk.sign(b"garbage").to_bytes());

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/verify")
                    .header("Content-Type", "application/json")
                    .body(Body::from(format!(
                        r#"{{"pubkey":"{}","challenge_id":"{}","signature":"{}"}}"#,
                        pk_hex, challenge_id, wrong_sig
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(!resp.status().is_success());
    }

    #[tokio::test]
    async fn test_auth_challenge_response_format_uniform() {
        let app = common::setup_test_app().await;
        let pk_hex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/challenge")
                    .header("Content-Type", "application/json")
                    .body(Body::from(format!(r#"{{"pubkey":"{}"}}"#, pk_hex)))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body: serde_json::Value =
            serde_json::from_slice(&axum::body::to_bytes(resp.into_body(), 10_240).await.unwrap()).unwrap();
        assert!(body["challenge"].is_string());
        assert!(body["challenge_id"].is_string());
        assert_eq!(body.as_object().unwrap().len(), 2, "Response must contain exactly 2 fields");
    }
}
