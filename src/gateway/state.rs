use std::sync::Arc;
use sqlx::sqlite::SqlitePool;
use crate::config::Config;
use crate::gateway::ratelimit::RateLimiter;
use crate::gateway::socks_pool::Socks5Pool;
use crate::crypto::zk::KeyEncryptionKey;
use crate::crypto::blind_sig;
use crate::services::payments::xmr::MoneroViewOnlyClient;
use crate::services::payments::btc_client::BtcPaymentClient;
use tokio::sync::{broadcast, Mutex};

#[derive(Clone)]
pub struct AppState {
    pub pool: SqlitePool,
    pub config: Arc<Config>,
    pub rate_limiter: RateLimiter,
    pub kek: KeyEncryptionKey,
    /// Set only in the worker process; API handlers stay blind.
    pub worker_key: Option<[u8; 32]>,
    /// Admin RSA keypair for blind-signature protocol.
    pub admin_keypair: Option<Arc<blind_sig::AdminKeypair>>,
    /// SOCKS5 connection pool for circuit-isolated Tor outbound traffic.
    pub socks_pool: Arc<Socks5Pool>,
    /// Persistent XMR monitoring client (created once, holds fork detection state)
    pub xmr_client: Arc<Mutex<Option<MoneroViewOnlyClient>>>,
    /// Persistent BTC monitoring client (created once, holds fork detection state)
    pub btc_client: Arc<Mutex<Option<BtcPaymentClient>>>,
    /// Broadcast channel for payment notifications.
    /// Subscribers (WebSocket clients) receive order_id hex strings when funds arrive.
    pub payment_tx: broadcast::Sender<String>,
    /// Last scanned block hash for notification scanning.
    pub last_notif_block: Arc<Mutex<Option<String>>>,
}
