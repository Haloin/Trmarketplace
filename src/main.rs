use anyhow::Result;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::watch;
use axum::Router;
use tower_http::services::ServeDir;

use tor_marketplace::config::{Config, DatabaseConfig};
use tor_marketplace::db;
use tor_marketplace::gateway;
use tor_marketplace::crypto::zk::KeyEncryptionKey;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"))
        )
        .with_target(false)
        .init();

    let config = Config::load()?;

    // Startup config validation
    if config.server.server_secret.is_empty() {
        return Err(anyhow::anyhow!("SERVER_SECRET must be set via env or config file"));
    }
    if config.server.server_secret.len() < 32 {
        return Err(anyhow::anyhow!("SERVER_SECRET must be at least 32 characters"));
    }
    if config.server.listen_addr.is_empty() {
        return Err(anyhow::anyhow!("listen_addr must not be empty"));
    }
    if config.server.rate_limit_per_minute == 0 {
        return Err(anyhow::anyhow!("rate_limit_per_minute must be > 0"));
    }
    if config.monero.wallet_rpc_url.is_empty() {
        return Err(anyhow::anyhow!("monero.wallet_rpc_url must not be empty"));
    }
    if config.bitcoin.rpc_url.is_empty() {
        return Err(anyhow::anyhow!("bitcoin.rpc_url must not be empty"));
    }
    if config.security.kek_rotation_days == 0 {
        return Err(anyhow::anyhow!("kek_rotation_days must be > 0"));
    }
    // Tor required in production.
    if !config.tor.enabled && std::env::var("RUST_ENV").as_deref() == Ok("production") {
        return Err(anyhow::anyhow!(
            "tor.enabled = false with RUST_ENV=production. Tor hidden service is required in production."
        ));
    }
    if config.tor.enabled {
        let tor_service = tor_marketplace::tor::TorService::new(config.tor.clone());
        tor_service.bootstrap()?;
        tor_service.cleanup_old_keys()?;
        let _tor_child = tor_service.start_tor_process()?;
        for i in 0..30 {
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            match tor_service.get_onion_address() {
                Ok(_) => {
                    break;
                }
                Err(_) => {
                    if i == 29 {
                        tracing::warn!("Tor hostname not ready after 30s");
                    }
                }
            }
        }
    }

    // Build SOCKS5 connection pool for Tor circuit isolation
    let socks_pool = tor_marketplace::gateway::socks_pool::Socks5Pool::new(
        &config.tor.socks5_addr,
        config.tor.socks5_pool_size,
        config.tor.enabled,
    )?;
    {
        let pool = socks_pool.clone();
        tokio::spawn(async move { pool.health_check_loop(60).await });
    }

    // Initialize database (SQLite for now)
    let pool = match &config.database {
        DatabaseConfig::Sqlite { path } => {
            let db_path = path.to_string_lossy().to_string();
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            db::init_sqlite_pool(&format!("sqlite:{}", db_path)).await?
        }
        DatabaseConfig::Postgres { url: _ } => {
            return Err(anyhow::anyhow!("PostgreSQL support coming soon - use SQLite for now"));
        }
    };
    
    db::run_sqlite_migrations(&pool).await?;

    let kek = load_kek()?;

    let config = Arc::new(config);

    // Create rate limiter
    let rate_limiter = tor_marketplace::gateway::ratelimit::RateLimiter::new(
        config.server.rate_limit_per_minute, 60,
    );

    let (payment_tx, _) = tokio::sync::broadcast::channel(256);

    let api_router = gateway::build_router(
        pool.clone(),
        config.clone(),
        kek.clone(),
        rate_limiter.clone(),
        socks_pool.clone(),
        payment_tx,
    );

    // Serve frontend static files as fallback
    let app = Router::new()
        .merge(api_router)
        .fallback_service(
            ServeDir::new("frontend")
                .append_index_html_on_directories(true)
        );

    let (_shutdown_tx, _shutdown_rx) = watch::channel(false);

    let addr = config.server.listen_addr.clone();
    tracing::info!("Starting API server on {}", addr);
    let listener = TcpListener::bind(&addr).await?;

    tokio::select! {
        result = axum::serve(listener, app) => { result?; }
        _ = tokio::signal::ctrl_c() => {
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            tracing::info!("API server shutdown complete");
        }
    }

    Ok(())
}


fn load_kek() -> Result<KeyEncryptionKey, anyhow::Error> {
    if let Ok(kek_hex) = std::env::var("KEK_HEX") {
        let key_bytes = hex::decode(&kek_hex)
            .map_err(|e| anyhow::anyhow!("Invalid KEK_HEX env: {e}"))?;
        if key_bytes.len() != 32 {
            return Err(anyhow::anyhow!("KEK_HEX must be exactly 32 bytes (64 hex chars)"));
        }
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&key_bytes);
        return Ok(KeyEncryptionKey::from_bytes(&key_array));
    }

    if std::env::var("EPHEMERAL_KEK").as_deref() == Ok("1") {
        tracing::warn!("Using ephemeral KEK — DO NOT USE IN PRODUCTION");
        return Ok(KeyEncryptionKey::new());
    }

    Err(anyhow::anyhow!(
        "KEK not configured. Set KEK_HEX env var (production) or EPHEMERAL_KEK=1 (dev)."
    ))
}
