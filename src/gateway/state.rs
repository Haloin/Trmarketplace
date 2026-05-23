use std::sync::Arc;
use sqlx::sqlite::SqlitePool;
use crate::config::Config;
use crate::gateway::ratelimit::RateLimiter;
use crate::crypto::zk::KeyEncryptionKey;
use crate::services::payments::xmr::MoneroViewOnlyClient;
use crate::services::payments::btc_client::BtcPaymentClient;
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct AppState {
    pub pool: SqlitePool,
    pub config: Arc<Config>,
    pub rate_limiter: RateLimiter,
    pub kek: KeyEncryptionKey,
    /// Master seed for per-order BTC owner key derivation.
    /// Generated once at first startup, encrypted with KEK, stored in config.
    /// Held decrypted in memory for the lifetime of the process.
    pub master_seed: [u8; 32],
    /// Persistent XMR monitoring client (created once, holds fork detection state)
    pub xmr_client: Arc<Mutex<Option<MoneroViewOnlyClient>>>,
    /// Persistent BTC monitoring client (created once, holds fork detection state)
    pub btc_client: Arc<Mutex<Option<BtcPaymentClient>>>,
}
