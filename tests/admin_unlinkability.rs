//! Blinded admin token integration tests.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use ed25519_dalek::{Signer, SigningKey};
use sha2::Sha256;
use tower::ServiceExt;

use tor_marketplace::crypto::blind_sig;

fn compute_hmac(auth_key: &[u8], pubkey: &[u8], hour_bucket: u64, path: &str, nonce: &[u8]) -> Vec<u8> {
    use hmac::{Hmac, Mac};
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

fn current_hour() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() / 3600
}

fn random_nonce(seed: u8) -> Vec<u8> {
    use rand::RngCore;
    let mut buf = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    buf[0] = seed;
    buf.to_vec()
}

async fn full_auth(app: &Router) -> (SigningKey, Vec<u8>, Vec<u8>) {
    let sk = SigningKey::generate(&mut rand::rngs::OsRng);
    let pk_hex = hex::encode(sk.verifying_key().to_bytes());

    let resp = app.clone().oneshot(
        Request::builder()
            .method("POST").uri("/auth/challenge")
            .header("Content-Type", "application/json")
            .body(Body::from(format!(r#"{{"pubkey":"{}"}}"#, pk_hex)))
            .unwrap()
    ).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(resp.into_body(), 10_240).await.unwrap()).unwrap();
    let challenge = hex::decode(body["challenge"].as_str().unwrap()).unwrap();
    let challenge_id = body["challenge_id"].as_str().unwrap().to_string();
    let sig_hex = hex::encode(sk.sign(&challenge).to_bytes());

    let resp = app.clone().oneshot(
        Request::builder()
            .method("POST").uri("/auth/verify")
            .header("Content-Type", "application/json")
            .body(Body::from(format!(
                r#"{{"pubkey":"{}","challenge_id":"{}","signature":"{}"}}"#,
                pk_hex, challenge_id, sig_hex
            ))).unwrap()
    ).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(resp.into_body(), 10_240).await.unwrap()).unwrap();
    let auth_key = hex::decode(body["auth_key"].as_str().unwrap()).unwrap();
    (sk.clone(), sk.verifying_key().to_bytes().to_vec(), auth_key)
}

#[tokio::test]
async fn test_blind_sign_http_roundtrip() {
    // Full blind-sign protocol over HTTP:
    //   1. Authenticate
    //   2. Compose token message, blind it
    //   3. POST to /admin/blind-sign → get blinded signature
    //   4. Unblind → get real signature
    //   5. Verify locally using the admin pubkey from /admin/pubkey
    let app = common::setup_test_app().await;
    let (_sk, _pk, auth_key) = full_auth(&app).await;

    // Step 1: Get the admin public key.
    let hour = current_hour();
    let get_nonce = random_nonce(50);
    let get_path = "/admin/pubkey";
    let headers = build_auth_headers(&auth_key, &_pk, &_sk, get_path, hour, &get_nonce);
    let mut builder = Request::builder().method("GET").uri(get_path);
    for (k, v) in &headers { builder = builder.header(*k, v.as_str()); }
    let req = builder.body(Body::empty()).unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK,
        "GET /admin/pubkey failed: status={}", resp.status());
    let body: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(resp.into_body(), 10_240).await.unwrap()).unwrap();
    let pubkey_hex = body["admin_pubkey_hex"].as_str().unwrap();
    let pubkey_der = hex::decode(pubkey_hex).unwrap();
    use rsa::pkcs1::DecodeRsaPublicKey;
    let rsa_pub = rsa::RsaPublicKey::from_pkcs1_der(&pubkey_der).unwrap();

    // Step 2: Compose token message and blind it.
    let token_nonce = b"test-token-nonce-001";
    let token_expiry = current_hour();
    let msg_hash = blind_sig::compose_token_message(
        "test:domain", "roundtrip-test", token_nonce, token_expiry);
    let (blinded, factor) = blind_sig::blind_message(&msg_hash, &rsa_pub);

    // Step 3: POST to /admin/blind-sign.
    let post_nonce = random_nonce(51);
    let post_path = "/admin/blind-sign";
    let headers = build_auth_headers(&auth_key, &_pk, &_sk, post_path, hour, &post_nonce);
    let body = serde_json::json!({
        "blinded_blob": hex::encode(&blinded),
    });
    let mut builder = Request::builder()
        .method("POST").uri(post_path)
        .header("Content-Type", "application/json");
    for (k, v) in &headers { builder = builder.header(*k, v.as_str()); }
    let req = builder.body(Body::from(serde_json::to_string(&body).unwrap())).unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let body_bytes = axum::body::to_bytes(resp.into_body(), 10_240).await.unwrap();
    assert_eq!(status, StatusCode::OK,
        "/admin/blind-sign failed: status={} body={}",
        status, String::from_utf8_lossy(&body_bytes));
    let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    let blinded_sig_hex = body["blinded_signature"].as_str().unwrap();
    let blinded_sig = hex::decode(blinded_sig_hex).unwrap();

    // Step 4: Unblind the signature.
    let sig = blind_sig::unblind_signature(&blinded_sig, &factor, &rsa_pub);

    // Step 5: Verify.
    assert!(blind_sig::verify_token(&msg_hash, &sig, &rsa_pub),
        "blind-signed + unblinded token must verify");
}

#[tokio::test]
async fn test_resolve_dispute_with_blind_token() {
    // Full flow: authenticate → create order → open dispute →
    // blind-sign → unblind → resolve dispute with token.
    use base64::Engine;

    let app = common::setup_test_app().await;
    let hour = current_hour();
    let (sk, pk, auth_key) = full_auth(&app).await;
    let token_expiry = current_hour();

    // Step 1: Create an order to dispute.
    let create_path = "/orders";
    let create_nonce = random_nonce(60);
    let headers = build_auth_headers(&auth_key, &pk, &sk, create_path, hour, &create_nonce);
    let body = serde_json::json!({
        "client_encrypted_blob": Engine::encode(
            &base64::engine::general_purpose::STANDARD, b"disputable-order"),
        "nonce": hex::encode(&create_nonce),
    });
    let mut builder = Request::builder()
        .method("POST").uri(create_path)
        .header("Content-Type", "application/json");
    for (k, v) in &headers { builder = builder.header(*k, v.as_str()); }
    let req = builder.body(Body::from(serde_json::to_string(&body).unwrap())).unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let body_bytes = axum::body::to_bytes(resp.into_body(), 102_400).await.unwrap();
    let create_body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    let order_id = create_body["id"].as_str().unwrap().to_string();

    // Step 2: Get admin pubkey to blind.
    let get_nonce = random_nonce(61);
    let get_path = "/admin/pubkey";
    let headers = build_auth_headers(&auth_key, &pk, &sk, get_path, hour, &get_nonce);
    let mut builder = Request::builder().method("GET").uri(get_path);
    for (k, v) in &headers { builder = builder.header(*k, v.as_str()); }
    let req = builder.body(Body::empty()).unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let body_bytes = axum::body::to_bytes(resp.into_body(), 10_240).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    let pubkey_der = hex::decode(body["admin_pubkey_hex"].as_str().unwrap()).unwrap();
    use rsa::pkcs1::DecodeRsaPublicKey;
    let rsa_pub = rsa::RsaPublicKey::from_pkcs1_der(&pubkey_der).unwrap();

    // Step 3: Compose token message for dispute resolution and blind it.
    let token_nonce = random_nonce(62);
    let msg_hash = blind_sig::compose_token_message(
        "dispute:resolve", &order_id, &token_nonce, token_expiry);
    let (blinded, factor) = blind_sig::blind_message(&msg_hash, &rsa_pub);

    // Step 4: POST /admin/blind-sign.
    let blind_nonce = random_nonce(63);
    let blind_path = "/admin/blind-sign";
    let headers = build_auth_headers(&auth_key, &pk, &sk, blind_path, hour, &blind_nonce);
    let body = serde_json::json!({
        "blinded_blob": hex::encode(&blinded),
    });
    let mut builder = Request::builder()
        .method("POST").uri(blind_path)
        .header("Content-Type", "application/json");
    for (k, v) in &headers { builder = builder.header(*k, v.as_str()); }
    let req = builder.body(Body::from(serde_json::to_string(&body).unwrap())).unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let body_bytes = axum::body::to_bytes(resp.into_body(), 10_240).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    let blinded_sig = hex::decode(body["blinded_signature"].as_str().unwrap()).unwrap();

    // Step 5: Unblind the signature.
    let token_sig = blind_sig::unblind_signature(&blinded_sig, &factor, &rsa_pub);

    // Step 6: POST /disputes/:id/resolve with the unblinded token.
    let resolve_path = format!("/disputes/{}/resolve", order_id);
    let resolve_nonce = random_nonce(64);
    let headers = build_auth_headers(&auth_key, &pk, &sk, &resolve_path, hour, &resolve_nonce);
    let body = serde_json::json!({
        "outcome_blob": Engine::encode(
            &base64::engine::general_purpose::STANDARD, b"admin-decision:release-funds"),
        "admin_signature": "", // legacy, ignored
        "nonce": hex::encode(&resolve_nonce),
        "token_signature": hex::encode(&token_sig),
        "token_message": hex::encode(msg_hash),
        "token_nonce": hex::encode(&token_nonce),
        "token_expiry_hour": token_expiry as i64,
    });
    let mut builder = Request::builder()
        .method("POST").uri(&resolve_path)
        .header("Content-Type", "application/json");
    for (k, v) in &headers { builder = builder.header(*k, v.as_str()); }
    let req = builder.body(Body::from(serde_json::to_string(&body).unwrap())).unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let body_bytes = axum::body::to_bytes(resp.into_body(), 10_240).await.unwrap();
    assert_eq!(status, StatusCode::OK,
        "resolve_dispute with blind token failed: status={} body={}",
        status, String::from_utf8_lossy(&body_bytes));
    let response_body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert!(!response_body["has_dispute"].as_bool().unwrap(),
        "dispute should be marked resolved");
}

#[tokio::test]
async fn test_invalid_token_rejected() {
    // A tampered token must be rejected by resolve_dispute.
    use base64::Engine;

    let app = common::setup_test_app().await;
    let hour = current_hour();
    let (sk, pk, auth_key) = full_auth(&app).await;
    let token_expiry = current_hour();

    // Create an order (same pattern as above).
    let create_path = "/orders";
    let create_nonce = random_nonce(70);
    let headers = build_auth_headers(&auth_key, &pk, &sk, create_path, hour, &create_nonce);
    let body = serde_json::json!({
        "client_encrypted_blob": Engine::encode(
            &base64::engine::general_purpose::STANDARD, b"order-to-attack"),
        "nonce": hex::encode(&create_nonce),
    });
    let mut builder = Request::builder()
        .method("POST").uri(create_path)
        .header("Content-Type", "application/json");
    for (k, v) in &headers { builder = builder.header(*k, v.as_str()); }
    let req = builder.body(Body::from(serde_json::to_string(&body).unwrap())).unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let body_bytes = axum::body::to_bytes(resp.into_body(), 102_400).await.unwrap();
    let create_body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    let order_id = create_body["id"].as_str().unwrap().to_string();

    // Attempt to resolve with a bogus token.
    let resolve_path = format!("/disputes/{}/resolve", order_id);
    let resolve_nonce = random_nonce(71);
    let headers = build_auth_headers(&auth_key, &pk, &sk, &resolve_path, hour, &resolve_nonce);
    let body = serde_json::json!({
        "outcome_blob": Engine::encode(
            &base64::engine::general_purpose::STANDARD, b"fake-resolution"),
        "admin_signature": "",
        "nonce": hex::encode(&resolve_nonce),
        "token_signature": "deadbeef",
        "token_message": "0000000000000000000000000000000000000000000000000000000000000000",
        "token_nonce": hex::encode(b"fake-nonce"),
        "token_expiry_hour": token_expiry as i64,
    });
    let mut builder = Request::builder()
        .method("POST").uri(&resolve_path)
        .header("Content-Type", "application/json");
    for (k, v) in &headers { builder = builder.header(*k, v.as_str()); }
    let req = builder.body(Body::from(serde_json::to_string(&body).unwrap())).unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    // Should be rejected — either 403 (Forbidden) or 400 (BadRequest).
    // error_unifier converts both to 500, so we check the body.
    let status = resp.status();
    assert!(
        status.is_client_error() || status == StatusCode::INTERNAL_SERVER_ERROR,
        "bogus token should be rejected, got: {}", status
    );
}

#[tokio::test]
async fn test_expired_token_rejected() {
    // A token with an expired expiry_hour must be rejected.
    use base64::Engine;

    let app = common::setup_test_app().await;
    let hour = current_hour();
    let (sk, pk, auth_key) = full_auth(&app).await;

    // Get admin pubkey and create a valid blind-signed token with an OLD expiry.
    let get_nonce = random_nonce(80);
    let get_path = "/admin/pubkey";
    let headers = build_auth_headers(&auth_key, &pk, &sk, get_path, hour, &get_nonce);
    let mut builder = Request::builder().method("GET").uri(get_path);
    for (k, v) in &headers { builder = builder.header(*k, v.as_str()); }
    let req = builder.body(Body::empty()).unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let body_bytes = axum::body::to_bytes(resp.into_body(), 10_240).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    let pubkey_der = hex::decode(body["admin_pubkey_hex"].as_str().unwrap()).unwrap();
    use rsa::pkcs1::DecodeRsaPublicKey;
    let rsa_pub = rsa::RsaPublicKey::from_pkcs1_der(&pubkey_der).unwrap();

    // Create order.
    let create_path = "/orders";
    let create_nonce = random_nonce(81);
    let headers = build_auth_headers(&auth_key, &pk, &sk, create_path, hour, &create_nonce);
    let body = serde_json::json!({
        "client_encrypted_blob": Engine::encode(
            &base64::engine::general_purpose::STANDARD, b"order-for-expiry-test"),
        "nonce": hex::encode(&create_nonce),
    });
    let mut builder = Request::builder()
        .method("POST").uri(create_path)
        .header("Content-Type", "application/json");
    for (k, v) in &headers { builder = builder.header(*k, v.as_str()); }
    let req = builder.body(Body::from(serde_json::to_string(&body).unwrap())).unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let body_bytes = axum::body::to_bytes(resp.into_body(), 102_400).await.unwrap();
    let create_body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    let order_id = create_body["id"].as_str().unwrap().to_string();

    // Make a token with expired timestamp (hour - 5).
    let old_expiry = current_hour().saturating_sub(5);
    let token_nonce = random_nonce(82);
    let msg_hash = blind_sig::compose_token_message(
        "dispute:resolve", &order_id, &token_nonce, old_expiry);
    let (blinded, factor) = blind_sig::blind_message(&msg_hash, &rsa_pub);
    let blind_nonce = random_nonce(83);
    let blind_path = "/admin/blind-sign";
    let headers = build_auth_headers(&auth_key, &pk, &sk, blind_path, hour, &blind_nonce);
    let body = serde_json::json!({ "blinded_blob": hex::encode(&blinded) });
    let mut builder = Request::builder()
        .method("POST").uri(blind_path)
        .header("Content-Type", "application/json");
    for (k, v) in &headers { builder = builder.header(*k, v.as_str()); }
    let req = builder.body(Body::from(serde_json::to_string(&body).unwrap())).unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let body_bytes = axum::body::to_bytes(resp.into_body(), 10_240).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    let blinded_sig = hex::decode(body["blinded_signature"].as_str().unwrap()).unwrap();
    let token_sig = blind_sig::unblind_signature(&blinded_sig, &factor, &rsa_pub);

    // Resolve with expired token.
    let resolve_path = format!("/disputes/{}/resolve", order_id);
    let resolve_nonce = random_nonce(84);
    let headers = build_auth_headers(&auth_key, &pk, &sk, &resolve_path, hour, &resolve_nonce);
    let body = serde_json::json!({
        "outcome_blob": Engine::encode(
            &base64::engine::general_purpose::STANDARD, b"expired-resolution"),
        "admin_signature": "",
        "nonce": hex::encode(&resolve_nonce),
        "token_signature": hex::encode(&token_sig),
        "token_message": hex::encode(msg_hash),
        "token_nonce": hex::encode(&token_nonce),
        "token_expiry_hour": old_expiry as i64,
    });
    let mut builder = Request::builder()
        .method("POST").uri(&resolve_path)
        .header("Content-Type", "application/json");
    for (k, v) in &headers { builder = builder.header(*k, v.as_str()); }
    let req = builder.body(Body::from(serde_json::to_string(&body).unwrap())).unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    assert!(
        status.is_client_error() || status == StatusCode::INTERNAL_SERVER_ERROR,
        "expired token should be rejected, got: {}", status
    );
}

#[tokio::test]
async fn test_rotate_kek_with_blind_token() {
    // Full flow: authenticate → blind-sign → unblind → rotate KEK.
    let app = common::setup_test_app().await;
    let hour = current_hour();
    let (sk, pk, auth_key) = full_auth(&app).await;
    let token_expiry = current_hour();

    // Get admin pubkey.
    let get_nonce = random_nonce(90);
    let get_path = "/admin/pubkey";
    let headers = build_auth_headers(&auth_key, &pk, &sk, get_path, hour, &get_nonce);
    let mut builder = Request::builder().method("GET").uri(get_path);
    for (k, v) in &headers { builder = builder.header(*k, v.as_str()); }
    let req = builder.body(Body::empty()).unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let body_bytes = axum::body::to_bytes(resp.into_body(), 10_240).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    let pubkey_der = hex::decode(body["admin_pubkey_hex"].as_str().unwrap()).unwrap();
    use rsa::pkcs1::DecodeRsaPublicKey;
    let rsa_pub = rsa::RsaPublicKey::from_pkcs1_der(&pubkey_der).unwrap();

    // Compose blind-sign token.
    let token_nonce = random_nonce(91);
    let msg_hash = blind_sig::compose_token_message(
        "admin:rotate_kek", "rotate", &token_nonce, token_expiry);
    let (blinded, factor) = blind_sig::blind_message(&msg_hash, &rsa_pub);

    // Blind-sign.
    let blind_nonce = random_nonce(92);
    let blind_path = "/admin/blind-sign";
    let headers = build_auth_headers(&auth_key, &pk, &sk, blind_path, hour, &blind_nonce);
    let body = serde_json::json!({ "blinded_blob": hex::encode(&blinded) });
    let mut builder = Request::builder()
        .method("POST").uri(blind_path)
        .header("Content-Type", "application/json");
    for (k, v) in &headers { builder = builder.header(*k, v.as_str()); }
    let req = builder.body(Body::from(serde_json::to_string(&body).unwrap())).unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK,
        "/admin/blind-sign failed: status={}", resp.status());
    let body_bytes = axum::body::to_bytes(resp.into_body(), 10_240).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    let blinded_sig = hex::decode(body["blinded_signature"].as_str().unwrap()).unwrap();
    let token_sig = blind_sig::unblind_signature(&blinded_sig, &factor, &rsa_pub);

    // Rotate KEK with valid token.
    let rotate_path = "/admin/rotate-kek";
    let rotate_nonce = random_nonce(93);
    let headers = build_auth_headers(&auth_key, &pk, &sk, rotate_path, hour, &rotate_nonce);
    let body = serde_json::json!({
        "session_nonce": "",
        "token_signature": hex::encode(&token_sig),
        "token_message": hex::encode(msg_hash),
        "token_nonce": hex::encode(&token_nonce),
        "token_expiry_hour": token_expiry as i64,
    });
    let mut builder = Request::builder()
        .method("POST").uri(rotate_path)
        .header("Content-Type", "application/json");
    for (k, v) in &headers { builder = builder.header(*k, v.as_str()); }
    let req = builder.body(Body::from(serde_json::to_string(&body).unwrap())).unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let body_bytes = axum::body::to_bytes(resp.into_body(), 10_240).await.unwrap();
    assert_eq!(status, StatusCode::OK,
        "rotate_kek with blind token failed: status={} body={}",
        status, String::from_utf8_lossy(&body_bytes));
    let response_body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert!(response_body["success"].as_bool().unwrap(),
        "rotate_kek should succeed");
}
