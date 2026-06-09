use axum::Router;
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::SqlitePool;
use std::sync::Arc;

use tor_marketplace::config::{
    BitcoinConfig, Config, DatabaseConfig, EscrowConfig, MoneroConfig, SecurityConfig,
    ServerConfig, TorConfig,
};
use tor_marketplace::crypto::zk::KeyEncryptionKey;
use tor_marketplace::db;
use tor_marketplace::gateway;
use tor_marketplace::gateway::ratelimit::RateLimiter;
use tor_marketplace::gateway::socks_pool::Socks5Pool;

static INIT: std::sync::Once = std::sync::Once::new();

fn init_tracing() {
    INIT.call_once(|| {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("debug,sqlx=warn")),
            )
            .with_test_writer()
            .try_init();
    });
}

pub async fn create_test_db() -> SqlitePool {
    init_tracing();
    let pool = SqlitePoolOptions::new()
        .max_connections(2)
        .connect(":memory:")
        .await
        .expect("Failed to create test DB");

    db::run_sqlite_migrations(&pool)
        .await
        .expect("Failed to run migrations V1-V15");

    pool
}

pub fn test_config() -> Config {
    Config {
        database: DatabaseConfig::Sqlite { path: std::path::PathBuf::from(":memory:") },
        server: ServerConfig {
            server_secret: "test_secret_32_bytes_long_for_testing!!".to_string(),
            ..ServerConfig::default()
        },
        tor: TorConfig::default(),
        monero: MoneroConfig::default(),
        bitcoin: BitcoinConfig::default(),
        security: SecurityConfig {
            worker_payment_pubkey_hex: Some(
                "0000000000000000000000000000000000000000000000000000000000000001".to_string(),
            ),
            ..SecurityConfig::default()
        },
        escrow: EscrowConfig::default(),
    }
}

pub async fn setup_test_app() -> Router {
    init_tracing();
    let pool = SqlitePoolOptions::new()
        .max_connections(2)
        .connect(":memory:")
        .await
        .expect("Test DB failed");
    db::run_sqlite_migrations(&pool).await.unwrap();

    let config = Arc::new(test_config());
    let kek = KeyEncryptionKey::new();
    let rate_limiter = RateLimiter::new(30, 60);
    let socks_pool = Socks5Pool::new("127.0.0.1:9050", 4, false).unwrap();
    let (payment_tx, _) = tokio::sync::broadcast::channel(256);
    // last_notif_block can't be Default since the router builder creates it internally.
    // But the build_router function now adds it, so the test helper is fine.
    gateway::build_router(pool, config, kek, rate_limiter, socks_pool, payment_tx)
}
