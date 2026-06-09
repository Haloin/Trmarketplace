
use anyhow::Result;
use tokio::sync::watch;

use tor_marketplace::config::{Config, DatabaseConfig};
use tor_marketplace::crypto::escrow;
use tor_marketplace::crypto::zk::KeyEncryptionKey;
use tor_marketplace::db;
use tor_marketplace::gateway::ratelimit::RateLimiter;
use tor_marketplace::gateway::socks_pool::Socks5Pool;
use tor_marketplace::gateway::state::AppState;
use tor_marketplace::worker;

fn load_kek() -> Result<KeyEncryptionKey> {
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

    Err(anyhow::anyhow!(
        "No KEK configured. Set KEK_HEX env var to decrypt worker_key_hex from config."
    ))
}

fn init_worker_key(kek: &KeyEncryptionKey, config: &Config) -> Result<[u8; 32]> {
    if let Some(ref hex_str) = config.security.worker_key_hex {
        let key = escrow::decrypt_master_seed(hex_str, kek)
            .map_err(|e| anyhow::anyhow!("Failed to decrypt worker_key_hex: {e}"))?;
        tracing::info!("Worker key loaded from config (key separation enabled).");
        return Ok(key);
    }

    if std::env::var("EPHEMERAL_WORKER_KEY").as_deref() == Ok("1") {
        tracing::warn!("EPHEMERAL_WORKER_KEY=1: generating fresh random key for this session. Data will NOT survive restart.");
        return Ok(escrow::generate_master_seed());
    }

    Err(anyhow::anyhow!(
        "worker_key_hex not set in config. Either set it (recommended) or run with EPHEMERAL_WORKER_KEY=1 for development."
    ))
}

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

    // Basic validation
    if config.monero.wallet_rpc_url.is_empty() {
        return Err(anyhow::anyhow!("monero.wallet_rpc_url must not be empty"));
    }
    if config.bitcoin.rpc_url.is_empty() {
        return Err(anyhow::anyhow!("bitcoin.rpc_url must not be empty"));
    }
    // Tor required in production.
    if !config.tor.enabled && std::env::var("RUST_ENV").as_deref() == Ok("production") {
        return Err(anyhow::anyhow!(
            "tor.enabled = false with RUST_ENV=production. Tor hidden service is required in production."
        ));
    }

    // Tor bootstrap (optional)
    if config.tor.enabled {
        let tor_service = tor_marketplace::tor::TorService::new(config.tor.clone());
        tor_service.bootstrap()?;
        tor_service.cleanup_old_keys()?;
        let _tor_child = tor_service.start_tor_process()?;
        for i in 0..30 {
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            if tor_service.get_onion_address().is_ok() {
                break;
            }
            if i == 29 {
                tracing::warn!("Tor hostname not ready after 30s");
            }
        }
    }

    // SOCKS5 pool for outbound RPCs
    let socks_pool = Socks5Pool::new(
        &config.tor.socks5_addr,
        config.tor.socks5_pool_size,
        config.tor.enabled,
    )?;
    {
        let pool = socks_pool.clone();
        tokio::spawn(async move { pool.health_check_loop(60).await });
    }

    // Database
    let pool = match &config.database {
        DatabaseConfig::Sqlite { path } => {
            let db_path = path.to_string_lossy().to_string();
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            db::init_sqlite_pool(&format!("sqlite:{}", db_path)).await?
        }
        DatabaseConfig::Postgres { url: _ } => {
            return Err(anyhow::anyhow!("PostgreSQL support coming soon — use SQLite for now"));
        }
    };
    db::run_sqlite_migrations(&pool).await?;

    // Load KEK + worker key
    let kek = load_kek()?;
    let worker_key = init_worker_key(&kek, &config)?;

    {
        let pubkey_hex = tor_marketplace::crypto::worker_pubkey::payment_pubkey_hex_from_worker_key(&worker_key);
        tracing::info!(
            worker_payment_pubkey_hex = %pubkey_hex,
            "Set WORKER_PAYMENT_PUBKEY_HEX or security.worker_payment_pubkey_hex for the API process"
        );
        if std::env::var("EPHEMERAL_WORKER_KEY").as_deref() == Ok("1") {
            if let Err(e) = tor_marketplace::crypto::worker_pubkey::write_dev_pubkey_file(
                &config.server.data_dir,
                &pubkey_hex,
            ) {
                tracing::warn!("Could not write dev worker pubkey file: {e}");
            } else {
                tracing::info!(
                    path = %tor_marketplace::crypto::worker_pubkey::dev_pubkey_path(&config.server.data_dir).display(),
                    "Dev worker pubkey written for API auto-sync"
                );
            }
        }
    }

    let config = Arc::new(config);

    // Rate limiter (we don't accept external traffic, but AppState wants one)
    let rate_limiter = RateLimiter::new(1000, 60);

    // Broadcast channel (no subscribers in worker; needed for AppState shape)
    let (payment_tx, _) = tokio::sync::broadcast::channel(256);

    let app_state = AppState {
        pool: pool.clone(),
        config: config.clone(),
        rate_limiter,
        kek,
        // CRITICAL: the worker process IS the only one with this key.
        // The API binary constructs AppState with worker_key: None.
        worker_key: Some(worker_key),
        // Worker process does NOT hold the admin signing key.
        // Admin blind-sign endpoint runs in the API process.
        admin_keypair: None,
        socks_pool,
        xmr_client: Default::default(),
        btc_client: Default::default(),
        payment_tx,
        last_notif_block: Default::default(),
    };

    let (_shutdown_tx, shutdown_rx) = watch::channel(false);

    tracing::info!("Worker process started. Press Ctrl-C to stop.");
    worker::run_workers(app_state, shutdown_rx).await;

    tokio::signal::ctrl_c().await?;
    tracing::info!("Worker shutdown complete");

    Ok(())
}
