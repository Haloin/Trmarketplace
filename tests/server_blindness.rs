//! Server blindness: API must not decrypt stored blobs.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use ed25519_dalek::{Signer, SigningKey};
use sha2::Digest;
use tower::ServiceExt;

const STATE_RS: &str = include_str!("../src/gateway/state.rs");
const ORDERS_RS: &str = include_str!("../src/services/orders.rs");
const LISTINGS_RS: &str = include_str!("../src/services/listings.rs");
const CHAT_RS: &str = include_str!("../src/services/chat.rs");
const DISPUTES_RS: &str = include_str!("../src/services/disputes.rs");
const AUTH_RS: &str = include_str!("../src/services/auth.rs");
const DUMMY_WORKER_RS: &str = include_str!("../src/background/dummy_worker.rs");

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

fn random_bytes(seed: u8) -> Vec<u8> {
    use rand::RngCore;
    let mut buf = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    buf[0] = seed;
    buf.to_vec()
}

async fn full_auth(app: &Router) -> (SigningKey, Vec<u8>, Vec<u8>) {
    let sk = SigningKey::generate(&mut rand::rngs::OsRng);
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
    let sig_hex = hex::encode(sk.sign(&challenge).to_bytes());

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/verify")
                .header("Content-Type", "application/json")
                .body(Body::from(format!(
                    r#"{{"pubkey":"{}","challenge_id":"{}","signature":"{}"}}"#,
                    pk_hex, challenge_id, sig_hex
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(resp.into_body(), 10_240).await.unwrap()).unwrap();
    let auth_key = hex::decode(body["auth_key"].as_str().unwrap()).unwrap();
    (sk.clone(), sk.verifying_key().to_bytes().to_vec(), auth_key)
}

#[tokio::test]
async fn test_appstate_does_not_have_master_seed_field() {
    // AppState must not hold master_seed; worker_key is optional on API.
    assert!(
        !STATE_RS.contains("master_seed"),
        "AppState still references 'master_seed'. This field must be removed \
         so the API process cannot decrypt blobs. See src/gateway/state.rs."
    );
    assert!(
        STATE_RS.contains("worker_key"),
        "AppState must contain 'worker_key' field. See src/gateway/state.rs."
    );
    assert!(
        STATE_RS.contains("Option<[u8; 32]>"),
        "AppState.worker_key must be Option<[u8; 32]>. See src/gateway/state.rs."
    );
}

#[tokio::test]
async fn test_public_api_modules_do_not_decrypt_blobs() {
    // The 5 public-service modules must not call any decryption primitive on
    // client-encrypted blobs. They may import key types (HMAC, ed25519 for
    // auth) but must not open any blob.
    //
    // Forbidden substrings (case-insensitive substring match):
    let forbidden_substrings = [
        "chacha20poly1305",
        "ChaCha20Poly1305",
        "Aes256Gcm",
        "aes_gcm",
        "aes-256-gcm",
        "decrypt_in_place",
        "openssl::symm",
    ];
    // Also forbid the bare "decrypt" function/method call pattern, but allow
    // comments and struct fields named decrypt_*. Use a simple heuristic: any
    // line containing "decrypt(" or ".decrypt(" is forbidden.
    for (name, src) in [
        ("auth.rs", AUTH_RS),
        ("listings.rs", LISTINGS_RS),
        ("orders.rs", ORDERS_RS),
        ("chat.rs", CHAT_RS),
        ("disputes.rs", DISPUTES_RS),
    ] {
        for forbidden in forbidden_substrings {
            assert!(
                !src.contains(forbidden),
                "Public API module {} contains forbidden decryption pattern '{}'. \
                 API modules must NOT decrypt client blobs.",
                name, forbidden
            );
        }
        // Line-by-line scan for decrypt( / .decrypt( call patterns.
        for (i, line) in src.lines().enumerate() {
            let trimmed = line.trim();
            // Skip pure comment lines.
            if trimmed.starts_with("//") {
                continue;
            }
            // Skip lines that are part of multi-line doc comments.
            if trimmed.starts_with("*") || trimmed.starts_with("/*") {
                continue;
            }
            // The bare "decrypt" in any form — function call, method call.
            if line.contains("decrypt(") || line.contains(".decrypt(") {
                panic!(
                    "Public API module {} line {} contains a decrypt() call: {}\n\
                     API modules must NOT decrypt client blobs (server blindness).",
                    name, i + 1, line
                );
            }
        }
    }
}

#[tokio::test]
async fn test_orders_table_schema_is_minimal() {
    // Orders table: opaque blob columns only, no plaintext PII.
    use sqlx::Row;
    let pool = common::create_test_db().await;
    let rows = sqlx::query("PRAGMA table_info(orders)")
        .fetch_all(&pool).await.unwrap();
    let column_names: Vec<String> = rows.iter()
        .map(|r| r.get::<String, _>("name"))
        .collect();

    for col in ["id", "encrypted_order_blob", "day_bucket", "expiry_bucket"] {
        assert!(
            column_names.iter().any(|c| c == col),
            "orders table missing required column '{}'. Columns present: {:?}",
            col, column_names
        );
    }
    for col in [
        "version", "has_dispute", "client_encrypted_blob",
        "dispute_client_blob", "chat_encrypted_blob",
    ] {
        assert!(
            column_names.iter().any(|c| c == col),
            "orders table missing helper column '{}'. Columns present: {:?}",
            col, column_names
        );
    }
    let forbidden = [
        "address", "phone", "email", "tracking_number", "shipping_carrier",
        "customer_name", "recipient", "notes", "real_name", "city", "zip",
    ];
    for f in forbidden {
        assert!(
            !column_names.iter().any(|c| c.eq_ignore_ascii_case(f)),
            "orders table contains forbidden plaintext column '{}'. Server \
             blindness requires NO plaintext PII columns. Columns: {:?}",
            f, column_names
        );
    }
}

#[tokio::test]
async fn test_order_response_json_has_no_plaintext_leaks() {
    // Create an order via the auth flow, fetch it, and assert the response
    // JSON contains ONLY the documented OrderResponse fields — no plaintext
    // sensitive fields.
    use base64::Engine;

    let app = common::setup_test_app().await;
    let (sk, pubkey, auth_key) = full_auth(&app).await;

    // POST /orders
    let hour = current_hour();
    let create_nonce = random_bytes(7);
    let path = "/orders";
    let headers = build_auth_headers(&auth_key, &pubkey, &sk, path, hour, &create_nonce);
    let blob = b"plaintext-pretend-encrypted-blob-content";
    let body = serde_json::json!({
        "client_encrypted_blob": Engine::encode(
            &base64::engine::general_purpose::STANDARD, blob),
        "nonce": hex::encode(&create_nonce),
    });
    let mut builder = Request::builder()
        .method("POST").uri(path)
        .header("Content-Type", "application/json");
    for (k, v) in &headers {
        builder = builder.header(*k, v.as_str());
    }
    let req = builder.body(Body::from(serde_json::to_string(&body).unwrap())).unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let body_bytes = axum::body::to_bytes(resp.into_body(), 102_400).await.unwrap();
    assert_eq!(status, StatusCode::OK,
        "create_order failed: status={} body={}",
        status, String::from_utf8_lossy(&body_bytes));
    let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    let order_id = body["id"].as_str().unwrap().to_string();

    // GET /orders/:id
    let get_path = format!("/orders/{}", order_id);
    let get_nonce = random_bytes(9);
    let get_headers = build_auth_headers(&auth_key, &pubkey, &sk, &get_path, hour, &get_nonce);
    let mut builder = Request::builder()
        .method("GET").uri(&get_path);
    for (k, v) in &get_headers {
        builder = builder.header(*k, v.as_str());
    }
    let req = builder.body(Body::empty()).unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let body_bytes = axum::body::to_bytes(resp.into_body(), 102_400).await.unwrap();
    assert_eq!(status, StatusCode::OK,
        "get_order failed: status={} body={}",
        status, String::from_utf8_lossy(&body_bytes));
    let order: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

    // Whitelist of allowed fields (matches src/services/orders.rs:63-70).
    let allowed = [
        "id", "client_encrypted_blob", "day_bucket", "expiry_bucket",
        "version", "has_dispute",
    ];
    for key in order.as_object().unwrap().keys() {
        assert!(
            allowed.contains(&key.as_str()),
            "OrderResponse contains unexpected key '{}'. Allowed: {:?}. \
             This may be a plaintext leak (server blindness violation).",
            key, allowed
        );
    }
    for forbidden in [
        "address", "phone", "email", "tracking_number", "shipping_carrier",
        "customer_name", "recipient", "notes", "real_name", "city", "zip",
        "shipping_address", "billing_address",
    ] {
        assert!(
            !order.as_object().unwrap().contains_key(forbidden),
            "OrderResponse contains forbidden plaintext key '{}'.",
            forbidden
        );
    }
    let returned_blob = order["client_encrypted_blob"].as_str().unwrap();
    assert!(
        !returned_blob.contains("plaintext-pretend-encrypted"),
        "Server returned plaintext blob (not base64-encoded ciphertext)!"
    );
}

#[tokio::test]
async fn test_dummy_worker_uses_worker_key_not_master_seed() {
    // Dummy worker uses worker_key like real workers, not master_seed.
    assert!(
        !DUMMY_WORKER_RS.contains("master_seed"),
        "src/background/dummy_worker.rs still references 'master_seed'. \
         Update to use 'state.worker_key' so the dummy worker is \
         indistinguishable from real workers."
    );
    assert!(
        DUMMY_WORKER_RS.contains("worker_key"),
        "src/background/dummy_worker.rs must reference 'worker_key' field. \
         This is the API process's blindness guarantee."
    );
}
