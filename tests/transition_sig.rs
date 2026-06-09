//! Transition signature integration tests.

mod common;

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::Router;
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};
    use time::OffsetDateTime;
    use tower::ServiceExt;

    use super::common;
    use tor_marketplace::crypto::transition_sig::{sign_transition, TransitionPayload, TRANSITION_SIG_VERSION};

    /// Duplicate server HMAC helper (middleware keeps the real fn private).
    fn compute_hmac(auth_key: &[u8], pubkey: &[u8], hour_bucket: u64, path: &str, nonce: &[u8]) -> Vec<u8> {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(auth_key).unwrap();
        mac.update(pubkey);
        mac.update(&hour_bucket.to_le_bytes());
        mac.update(path.as_bytes());
        mac.update(nonce);
        mac.finalize().into_bytes().to_vec()
    }

    fn build_challenge(hmac: &[u8], pubkey: &[u8], hour_bucket: u64, nonce: &[u8]) -> Vec<u8> {
        let mut challenge = Vec::with_capacity(hmac.len() + pubkey.len() + 8 + nonce.len());
        challenge.extend_from_slice(hmac);
        challenge.extend_from_slice(pubkey);
        challenge.extend_from_slice(&hour_bucket.to_le_bytes());
        challenge.extend_from_slice(nonce);
        challenge
    }

    /// Do the full auth flow and return (signing_key, pubkey_bytes, auth_key_bytes).
    async fn full_auth(app: &Router) -> (SigningKey, Vec<u8>, Vec<u8>) {
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
        // auth_key is hex-encoded by the server (/auth/verify response).
        // The server uses the raw bytes for HMAC, so decode here.
        let auth_key = hex::decode(body["auth_key"].as_str().unwrap()).unwrap();
        (sk.clone(), sk.verifying_key().to_bytes().to_vec(), auth_key)
    }

    /// Build all 5 auth headers for a request.
    fn build_auth_headers(
        auth_key: &[u8],
        pubkey: &[u8],
        sk: &SigningKey,
        path: &str,
        hour_bucket: u64,
        nonce: &[u8],
    ) -> Vec<(&'static str, String)> {
        let hmac = compute_hmac(auth_key, pubkey, hour_bucket, path, nonce);
        let challenge = build_challenge(&hmac, pubkey, hour_bucket, nonce);
        let sig = sk.sign(&challenge);
        vec![
            ("x-auth-pubkey", hex::encode(pubkey)),
            ("x-auth-hmac", hex::encode(&hmac)),
            ("x-auth-hour", hour_bucket.to_string()),
            ("x-auth-nonce", hex::encode(nonce)),
            ("x-auth-signature", hex::encode(sig.to_bytes())),
        ]
    }

    /// SHA-256 of a blob, returned as 32-byte array.
    fn sha256(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    /// Current hour bucket (matches server's `(unix_ts / 3600)`).
    fn current_hour() -> u64 {
        (OffsetDateTime::now_utc().unix_timestamp() / 3600) as u64
    }

    /// Random 32 bytes for nonces/order IDs. Uses OsRng so each call
    /// produces a unique value (essential since the server's nonce
    /// replay cache is process-global and parallel tests would otherwise
    /// collide on a fixed seed).
    fn random_bytes(seed: u8) -> Vec<u8> {
        use rand::RngCore;
        let mut buf = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut buf);
        buf[0] = seed; // mix in a seed byte for test-debug traceability
        buf.to_vec()
    }

    /// Build a full update-order request URL + body.
    fn build_update_request(
        order_id: &[u8],
        new_blob: &[u8],
        prev_version: i64,
        nonce: &[u8],
        auth_key: &[u8],
        pubkey: &[u8],
        sk: &SigningKey,
    ) -> Request<Body> {
        let hour = current_hour();
        let new_blob_hash = sha256(new_blob);
        let payload = TransitionPayload::new(
            order_id.to_vec(),
            prev_version,
            new_blob_hash,
            nonce.to_vec(),
            hour,
        );
        let sig_bytes = sign_transition(sk, &payload).unwrap();

        let path = format!("/orders/{}/update", hex::encode(order_id));
        let headers = build_auth_headers(auth_key, pubkey, sk, &path, hour, nonce);

        let body = serde_json::json!({
            "client_encrypted_blob": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, new_blob),
            "transition_signature": hex::encode(sig_bytes),
            "nonce": hex::encode(nonce),
            "hour_bucket": hour,
        });
        let body_str = serde_json::to_string(&body).unwrap();

        let mut builder = Request::builder()
            .method("POST")
            .uri(&path)
            .header("Content-Type", "application/json");
        for (k, v) in &headers {
            builder = builder.header(*k, v.as_str());
        }
        builder.body(Body::from(body_str)).unwrap()
    }

    /// Helper: create a fresh order (authed) and return its id + version.
    async fn create_order(
        app: &Router,
        sk: &SigningKey,
        pubkey: &[u8],
        auth_key: &[u8],
    ) -> (Vec<u8>, i64) {
        let hour = current_hour();
        let create_nonce = random_bytes(7);
        let path = "/orders";
        let headers = build_auth_headers(auth_key, pubkey, sk, path, hour, &create_nonce);

        let blob = b"initial client-encrypted blob for test";
        let body = serde_json::json!({
            "client_encrypted_blob": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, blob),
            "nonce": hex::encode(&create_nonce),
        });
        let body_str = serde_json::to_string(&body).unwrap();

        let mut builder = Request::builder()
            .method("POST")
            .uri(path)
            .header("Content-Type", "application/json");
        for (k, v) in &headers {
            builder = builder.header(*k, v.as_str());
        }
        let req = builder.body(Body::from(body_str)).unwrap();

        let resp = app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        if status != StatusCode::OK {
            let body_bytes = axum::body::to_bytes(resp.into_body(), 102_400).await.unwrap();
            panic!("Order create failed: status={} body={}", status, String::from_utf8_lossy(&body_bytes));
        }

        let body: serde_json::Value =
            serde_json::from_slice(&axum::body::to_bytes(resp.into_body(), 102_400).await.unwrap()).unwrap();
        let id_hex = body["id"].as_str().unwrap();
        let version = body["version"].as_i64().unwrap();
        (hex::decode(id_hex).unwrap(), version)
    }

    #[tokio::test]
    async fn test_valid_transition_signature_is_accepted() {
        let app = common::setup_test_app().await;
        let (sk, pubkey, auth_key) = full_auth(&app).await;
        let (order_id, version) = create_order(&app, &sk, &pubkey, &auth_key).await;

        let new_blob = b"updated client-encrypted blob";
        let update_nonce = random_bytes(11);
        let req = build_update_request(&order_id, new_blob, version, &update_nonce, &auth_key, &pubkey, &sk);

        let resp = app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        if status != StatusCode::OK {
            let body_bytes = axum::body::to_bytes(resp.into_body(), 102_400).await.unwrap();
            panic!("Valid transition sig: status={} body={}", status, String::from_utf8_lossy(&body_bytes));
        }
    }

    #[tokio::test]
    async fn test_tampered_prev_version_fails() {
        let app = common::setup_test_app().await;
        let (sk, pubkey, auth_key) = full_auth(&app).await;
        let (order_id, _version) = create_order(&app, &sk, &pubkey, &auth_key).await;

        // Sign with prev_version=2 while DB is still at 1; update must fail.
        let new_blob = b"updated blob";
        let update_nonce = random_bytes(13);
        let req = build_update_request(&order_id, new_blob, 2, &update_nonce, &auth_key, &pubkey, &sk);

        let resp = app.clone().oneshot(req).await.unwrap();
        // Server returns 409 Conflict (TOCTOU) or 400 (sig mismatch).
        assert!(!resp.status().is_success(),
            "Submitting with wrong prev_version must fail (got {})", resp.status());
    }

    #[tokio::test]
    async fn test_tampered_blob_hash_in_request_fails() {
        let app = common::setup_test_app().await;
        let (sk, pubkey, auth_key) = full_auth(&app).await;
        let (order_id, version) = create_order(&app, &sk, &pubkey, &auth_key).await;

        // Build a request where the signature covers one blob but the
        // body sends a different one. We do this manually so we can
        // decouple sig from blob.
        let signed_blob = b"blob the client signed";
        let sent_blob = b"DIFFERENT blob the client tries to send";
        let update_nonce = random_bytes(17);
        let hour = current_hour();
        let payload = TransitionPayload::new(
            order_id.clone(),
            version,
            sha256(signed_blob),
            update_nonce.clone(),
            hour,
        );
        let sig_bytes = sign_transition(&sk, &payload).unwrap();

        let path = format!("/orders/{}/update", hex::encode(&order_id));
        let headers = build_auth_headers(&auth_key, &pubkey, &sk, &path, hour, &update_nonce);

        let body = serde_json::json!({
            "client_encrypted_blob": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, sent_blob),
            "transition_signature": hex::encode(sig_bytes),
            "nonce": hex::encode(&update_nonce),
            "hour_bucket": hour,
        });

        let mut builder = Request::builder()
            .method("POST")
            .uri(&path)
            .header("Content-Type", "application/json");
        for (k, v) in &headers {
            builder = builder.header(*k, v.as_str());
        }
        let req = builder.body(Body::from(serde_json::to_string(&body).unwrap())).unwrap();

        let resp = app.clone().oneshot(req).await.unwrap();
        assert!(!resp.status().is_success(),
            "Mismatched blob must fail (got {})", resp.status());
    }

    #[tokio::test]
    async fn test_wrong_signing_key_fails() {
        let app = common::setup_test_app().await;
        let (real_sk, pubkey, auth_key) = full_auth(&app).await;
        let (order_id, version) = create_order(&app, &real_sk, &pubkey, &auth_key).await;

        // Sign with a *different* ed25519 key, but submit the request
        // under the real pubkey. The server has the real pubkey (from
        // auth) and will reject the signature.
        let wrong_sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);

        let new_blob = b"updated blob";
        let update_nonce = random_bytes(19);
        let hour = current_hour();
        let payload = TransitionPayload::new(
            order_id.clone(),
            version,
            sha256(new_blob),
            update_nonce.clone(),
            hour,
        );
        let sig_bytes = sign_transition(&wrong_sk, &payload).unwrap();

        let path = format!("/orders/{}/update", hex::encode(&order_id));
        let headers = build_auth_headers(&auth_key, &pubkey, &real_sk, &path, hour, &update_nonce);

        let body = serde_json::json!({
            "client_encrypted_blob": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, new_blob),
            "transition_signature": hex::encode(sig_bytes),
            "nonce": hex::encode(&update_nonce),
            "hour_bucket": hour,
        });

        let mut builder = Request::builder()
            .method("POST")
            .uri(&path)
            .header("Content-Type", "application/json");
        for (k, v) in &headers {
            builder = builder.header(*k, v.as_str());
        }
        let req = builder.body(Body::from(serde_json::to_string(&body).unwrap())).unwrap();

        let resp = app.clone().oneshot(req).await.unwrap();
        assert!(!resp.status().is_success(),
            "Signature with wrong key must fail (got {})", resp.status());
    }

    #[tokio::test]
    async fn test_replay_nonce_fails() {
        let app = common::setup_test_app().await;
        let (sk, pubkey, auth_key) = full_auth(&app).await;
        let (order_id, version) = create_order(&app, &sk, &pubkey, &auth_key).await;

        let new_blob = b"updated blob";
        let update_nonce = random_bytes(23);
        let req = build_update_request(&order_id, new_blob, version, &update_nonce, &auth_key, &pubkey, &sk);
        let resp1 = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp1.status(), StatusCode::OK);

        // Replay: same nonce, new request. Server must reject.
        let req2 = build_update_request(&order_id, new_blob, version + 1, &update_nonce, &auth_key, &pubkey, &sk);
        let resp2 = app.clone().oneshot(req2).await.unwrap();
        assert!(!resp2.status().is_success(),
            "Replay with same nonce must fail (got {})", resp2.status());
    }

    /// Sanity check: the CBOR schema version is exactly what the
    /// server expects. This catches accidental wire-format changes
    /// during refactors.
    #[tokio::test]
    async fn test_transition_sig_version_is_stable() {
        assert_eq!(TRANSITION_SIG_VERSION, 1,
            "If you bump TRANSITION_SIG_VERSION, you are changing the wire format. \
             This is a breaking change for all deployed clients.");
    }

    /// Diagnostic: check that the orders table has the expected schema.
    /// If this fails, the migrations are out of sync with the orders
    /// service and the create_order handler will fail with 500.
    #[tokio::test]
    async fn test_orders_table_schema_check() {
        use sqlx::Row;
        let pool = common::create_test_db().await;
        let rows = sqlx::query("PRAGMA table_info(orders)")
            .fetch_all(&pool).await.unwrap();
        let column_names: Vec<String> = rows.iter()
            .map(|r| r.get::<String, _>("name"))
            .collect();
        eprintln!("orders table columns: {:?}", column_names);
        // We expect at minimum: id, encrypted_order_blob, day_bucket, expiry_bucket
        assert!(column_names.contains(&"id".to_string()), "orders table missing id");
        assert!(column_names.contains(&"encrypted_order_blob".to_string()),
            "orders table missing encrypted_order_blob (V10 migration not applied?)");
    }
}
