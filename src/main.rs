use anyhow::Result;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::watch;
use axum::Router;
use tower_http::services::ServeDir;

use tor_marketplace::config::{Config, DatabaseConfig};
use tor_marketplace::crypto::escrow;
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

    let mut config = Config::load()?;

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
    if let Some(ref pk) = config.security.admin_pubkey {
        if hex::decode(pk).is_err() {
            return Err(anyhow::anyhow!("admin_pubkey must be valid hex"));
        }
    }

    if config.security.admin_pubkey.is_none() {
        tracing::warn!(
            "SECURITY WARNING: admin_pubkey not configured. Dispute resolution and admin \
            features will be inaccessible until admin_pubkey is set in config."
        );
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

    // Initialize KEK - NEVER save to disk
    // Option 1: Load from environment variable (primary)
    // Option 2: Manual entry at startup
    // Option 3: HSM integration (for production)
    let kek = load_kek(&config)?;

    // Initialize master seed for per-order BTC owner key derivation.
    // Generated once at first startup, encrypted with KEK, persisted in config.
    let master_seed = init_master_seed(&kek, &mut config)?;

    fixup_old_orders(&pool, &master_seed).await?;

    let config = Arc::new(config);

    // Create rate limiter
    let rate_limiter = tor_marketplace::gateway::ratelimit::RateLimiter::new(
        config.server.rate_limit_per_minute, 60,
    );
    
    // Build router with KEK and master seed
    let api_router = gateway::build_router(
        pool.clone(),
        config.clone(),
        kek.clone(),
        master_seed,
        rate_limiter.clone(),
    );

    // Serve frontend static files as fallback
    let app = Router::new()
        .merge(api_router)
        .fallback_service(
            ServeDir::new("frontend")
                .append_index_html_on_directories(true)
        );

    // Create AppState with same KEK instance and persistent payment clients
    let app_state = tor_marketplace::gateway::state::AppState {
        pool: pool.clone(),
        config: config.clone(),
        rate_limiter: rate_limiter.clone(),
        kek: kek.clone(),
        master_seed,
        xmr_client: Default::default(),
        btc_client: Default::default(),
    };

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    tokio::spawn(tor_marketplace::background::run_workers(app_state, shutdown_rx));

    let addr = config.server.listen_addr.clone();
    tracing::info!("Starting server on {}", addr);
    let listener = TcpListener::bind(&addr).await?;

    tokio::select! {
        result = axum::serve(listener, app) => { result?; }
        _ = tokio::signal::ctrl_c() => {
            let _ = shutdown_tx.send(true);
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            tracing::info!("Shutdown complete");
        }
    }

    Ok(())
}


fn load_kek(config: &Config) -> Result<KeyEncryptionKey, anyhow::Error> {
    // Option 1: Load from environment variable (highest security - never saved to disk)
    if let Ok(kek_hex) = std::env::var("KEK_HEX") {
        let key_bytes = hex::decode(&kek_hex)
            .map_err(|e| anyhow::anyhow!("Invalid KEK_HEX env: {}", e))?;
        if key_bytes.len() != 32 {
            return Err(anyhow::anyhow!("KEK_HEX must be exactly 32 bytes (64 hex chars)"));
        }
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&key_bytes);
        return Ok(KeyEncryptionKey::from_bytes(&key_array));
    }
    
    // Option 2: Ephemeral KEK (must be explicitly opted in)
    if !config.security.kek_hex.is_some() {
        if std::env::var("EPHEMERAL_KEK").as_deref() != Ok("1") {
            return Err(anyhow::anyhow!(
                "KEK not configured. Set KEK_HEX env var or EPHEMERAL_KEK=1 for development"
            ));
        }
        tracing::warn!("KEK not configured! Starting in ephemeral mode.");
        tracing::warn!("To secure: Set KEK_HEX env var or implement HSM integration.");
        
        // Generate temporary KEK for this session only
        tracing::warn!("Using ephemeral KEK - DO NOT USE IN PRODUCTION");
        return Ok(KeyEncryptionKey::new());
    }
    
    // Load from config (legacy support, will be deprecated)
    if let Some(ref kek_hex) = config.security.kek_hex {
        let key_bytes = hex::decode(kek_hex)
            .map_err(|e| anyhow::anyhow!("Invalid KEK hex in config: {}", e))?;
        if key_bytes.len() != 32 {
            return Err(anyhow::anyhow!("KEK must be exactly 32 bytes"));
        }
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&key_bytes);
        tracing::warn!("KEK loaded from config file - NOT RECOMMENDED. Use KEK_HEX env var.");
        return Ok(KeyEncryptionKey::from_bytes(&key_array));
    }
    
    Err(anyhow::anyhow!("No KEK configured"))
}


fn init_master_seed(kek: &KeyEncryptionKey, config: &mut Config) -> Result<[u8; 32]> {
    if let Some(ref hex_str) = config.security.master_seed_hex {
        match escrow::decrypt_master_seed(hex_str, kek) {
            Ok(seed) => return Ok(seed),
            Err(e) => {
                tracing::warn!("Failed to decrypt master seed: {e}. Generating new one.");
            }
        }
    }

    let seed = escrow::generate_master_seed();
    let encrypted = escrow::encrypt_master_seed(&seed, kek)?;
    config.security.master_seed_hex = Some(encrypted);

    if let Err(e) = config.save() {
        tracing::warn!("Failed to save config with master seed: {e}");
        // Non-fatal: master seed is still held in memory for this session;
        // next startup will generate a new one (dev mode, gaps orders).
    }

    Ok(seed)
}


async fn fixup_old_orders(pool: &sqlx::SqlitePool, master_seed: &[u8; 32]) -> Result<()> {
    use sqlx::Row;
    use tor_marketplace::crypto::oblivious;
    use tor_marketplace::crypto::zk::floor_timestamp_6h;
    use tor_marketplace::db::models::OrderData;

    let count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM orders WHERE day_bucket IS NULL"
    )
    .fetch_one(pool)
    .await?;

    if count.0 == 0 {
        return Ok(());
    }

    tracing::info!("Migrating {} old-format orders to oblivious encryption", count.0);

    let rows = sqlx::query(
        "SELECT id, listing_id, buyer_pubkey_hash, seller_pubkey_hash, \
         buyer_pubkey, seller_pubkey, state, currency, escrow_address, \
         escrow_amount, time_lock_seconds, created_at, funded_at, shipped_at, \
         confirmed_at, released_at, refunded_at, expires_at, disputed_at, \
         dispute_id, owner_pubkey, fee_percent, fee_address \
         FROM orders WHERE day_bucket IS NULL"
    )
    .fetch_all(pool)
    .await?;

    for row in &rows {
        let id: Vec<u8> = row.get(0);
        let data = OrderData {
            listing_id: row.get(1),
            buyer_pubkey_hash: row.get(2),
            seller_pubkey_hash: row.get(3),
            buyer_pubkey: row.get(4),
            seller_pubkey: row.get(5),
            state: row.get(6),
            currency: row.get(7),
            escrow_address: row.get(8),
            escrow_amount: row.get(9),
            time_lock_seconds: row.get(10),
            created_at: row.get(11),
            funded_at: row.get(12),
            shipped_at: row.get(13),
            confirmed_at: row.get(14),
            released_at: row.get(15),
            refunded_at: row.get(16),
            expires_at: row.get(17),
            disputed_at: row.get(18),
            dispute_id: row.get(19),
            owner_pubkey: row.get(20),
            fee_percent: row.get(21),
            fee_address: row.get(22),
            dispute: None,
            chat_messages: vec![],
        };

        let json = serde_json::to_vec(&data)?;
        let blob = oblivious::encrypt_order_blob(&json, &master_seed[..], &id)
            .ok_or_else(|| anyhow::anyhow!("Encryption failed"))?;
        let day_bucket = floor_timestamp_6h(data.created_at);
        let expiry_bucket = data.expires_at.map(floor_timestamp_6h);

        sqlx::query(
            "UPDATE orders SET encrypted_order_blob = ?1, day_bucket = ?2, expiry_bucket = ?3 WHERE id = ?4"
        )
        .bind(&blob)
        .bind(day_bucket)
        .bind(expiry_bucket)
        .bind(&id)
        .execute(pool)
        .await?;
    }

    tracing::info!("Migration complete: {} orders encrypted", count.0);
    Ok(())
}