use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct Config {
    pub database: DatabaseConfig,
    pub server: ServerConfig,
    pub tor: TorConfig,
    pub monero: MoneroConfig,
    pub bitcoin: BitcoinConfig,
    pub security: SecurityConfig,
    pub escrow: EscrowConfig,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum DatabaseConfig {
    Sqlite { path: PathBuf },
    Postgres { url: String },
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self::Sqlite { path: PathBuf::from("data/marketplace.db") }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub listen_addr: String,
    pub data_dir: PathBuf,
    pub server_secret: String,
    pub rate_limit_per_minute: u32,
    pub default_lock_days: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:9080".to_string(),
            data_dir: PathBuf::from("data"),
            server_secret: String::new(),
            rate_limit_per_minute: 30,
            default_lock_days: 7,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TorConfig {
    pub enabled: bool,
    pub service_dir: PathBuf,
    pub port: u16,
    pub onion_address: Option<String>,
    /// SOCKS5 proxy address for outbound Tor connections.
    /// All RPC traffic (BTC, XMR) is routed through this proxy.
    /// Default: 127.0.0.1:9050 (standard Tor SOCKS port).
    #[serde(default = "default_socks5_addr")]
    pub socks5_addr: String,
    /// Number of isolated Tor circuits in the connection pool.
    /// Each circuit uses a different SOCKS auth username to force
    /// Tor `IsolateSOCKSAuth` — a new circuit per pool slot.
    #[serde(default = "default_socks5_pool_size")]
    pub socks5_pool_size: usize,
}

fn default_socks5_addr() -> String {
    "127.0.0.1:9050".to_string()
}

fn default_socks5_pool_size() -> usize {
    8
}

impl Default for TorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            service_dir: PathBuf::from("data/tor"),
            port: 80,
            onion_address: None,
            socks5_addr: default_socks5_addr(),
            socks5_pool_size: default_socks5_pool_size(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct MoneroConfig {
    pub wallet_rpc_url: String,
    pub wallet_rpc_user: Option<String>,
    pub wallet_rpc_password: Option<String>,
    pub confirmations_required: u32,
}

impl Default for MoneroConfig {
    fn default() -> Self {
        Self {
            wallet_rpc_url: "http://127.0.0.1:18089/json_rpc".to_string(),
            wallet_rpc_user: None,
            wallet_rpc_password: None,
            confirmations_required: 10,
        }
    }
}

fn default_btc_network() -> String {
    "mainnet".to_string()
}

#[derive(Clone, Serialize, Deserialize)]
pub struct BitcoinConfig {
    pub rpc_url: String,
    pub rpc_user: Option<String>,
    pub rpc_password: Option<String>,
    pub confirmations_required: u32,
    pub wallet_name: String,
    #[serde(default)]
    pub address_type: String,
    #[serde(default = "default_btc_network")]
    pub network: String,
}

impl BitcoinConfig {
    /// Parse the configured network string into a `bitcoin::Network`.
    pub fn btc_network(&self) -> Result<bitcoin::Network> {
        match self.network.to_lowercase().as_str() {
            "mainnet" => Ok(bitcoin::Network::Bitcoin),
            "testnet" => Ok(bitcoin::Network::Testnet),
            "signet" => Ok(bitcoin::Network::Signet),
            "regtest" => Ok(bitcoin::Network::Regtest),
            _ => Err(anyhow::anyhow!(
                "Invalid bitcoin.network '{}' — expected mainnet/testnet/signet/regtest",
                self.network
            )),
        }
    }
}

impl Default for BitcoinConfig {
    fn default() -> Self {
        Self {
            rpc_url: "http://127.0.0.1:8332".to_string(),
            rpc_user: None,
            rpc_password: None,
            confirmations_required: 6,
            wallet_name: "tor-marketplace".to_string(),
            address_type: "p2sh-segwit".to_string(),
            network: default_btc_network(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub max_order_value_xmr: f64,
    pub max_order_value_btc: f64,
    pub kek_rotation_days: u32,
    pub kek_hex: Option<String>,
    #[serde(default)]
    pub kek_version: u8,
    #[serde(default)]
    pub last_kek_rotation: Option<i64>,
    #[serde(default)]
    pub btc_min_payment_sats: u64,
    #[serde(default)]
    pub master_seed_hex: Option<String>,
    /// Worker key for background job decryption (separate from API server key).
    /// When set, background workers use this key to decrypt order blobs.
    /// API handlers remain blind and cannot decrypt.
    #[serde(default)]
    pub worker_key_hex: Option<String>,
    /// Admin RSA private key for blind signature protocol (PKCS#8 DER, hex).
    #[serde(default)]
    pub admin_privkey_hex: Option<String>,
    /// Admin RSA public key (PKCS#1 DER, hex-encoded). Distribute to admin
    /// clients. Embedded in production builds via env var `ADMIN_PUBKEY_HEX`.
    #[serde(default)]
    pub admin_pubkey_hex: Option<String>,
    /// Worker X25519 public key for client-side order blob encryption.
    /// Derived from `worker_key` via `derive_domain_key(key, "payment-decrypt")`.
    /// The worker logs this pubkey at startup; copy it here for the API process.
    #[serde(default)]
    pub worker_payment_pubkey_hex: Option<String>,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            max_order_value_xmr: 100.0,
            max_order_value_btc: 1.0,
            kek_rotation_days: 30,
            kek_hex: None,
            kek_version: 1,
            last_kek_rotation: None,
            btc_min_payment_sats: 546,
            master_seed_hex: None,
            worker_key_hex: None,
            admin_privkey_hex: None,
            admin_pubkey_hex: None,
            worker_payment_pubkey_hex: None,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct EscrowConfig {
    pub fee_percent: u64,
    #[serde(default)]
    pub fee_address_btc: Option<String>,
    #[serde(default)]
    pub fee_address_xmr: Option<String>,
}

impl Default for EscrowConfig {
    fn default() -> Self {
        Self {
            fee_percent: 4,
            fee_address_btc: None,
            fee_address_xmr: None,
        }
    }
}

impl Config {
    pub fn load() -> Result<Self> {
        let config_path = std::env::var("CONFIG_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("config.toml"));

        if config_path.exists() {
            let data = std::fs::read_to_string(&config_path)?;
            let mut config: Config = toml::from_str(&data)?;
            config.apply_env_overrides();
            return Ok(config);
        }

        Ok(Self::default())
    }

    fn apply_env_overrides(&mut self) {
        if let Ok(v) = std::env::var("LISTEN_ADDR") {
            self.server.listen_addr = v;
        }
        if let Ok(v) = std::env::var("DB_PATH") {
            self.database = DatabaseConfig::Sqlite { path: PathBuf::from(v) };
        }
        if let Ok(v) = std::env::var("DATABASE_URL") {
            self.database = DatabaseConfig::Postgres { url: v };
        }
        if let Ok(v) = std::env::var("MONERO_RPC_URL") {
            self.monero.wallet_rpc_url = v;
        }
        if let Ok(v) = std::env::var("BITCOIN_RPC_URL") {
            self.bitcoin.rpc_url = v;
        }
        if let Ok(v) = std::env::var("SERVER_SECRET") {
            self.server.server_secret = v;
        }
    }

    pub fn db_path(&self) -> Option<&PathBuf> {
        match &self.database {
            DatabaseConfig::Sqlite { path } => Some(path),
            DatabaseConfig::Postgres { .. } => None,
        }
    }

    pub fn db_url(&self) -> Option<&str> {
        match &self.database {
            DatabaseConfig::Sqlite { .. } => None,
            DatabaseConfig::Postgres { url } => Some(url),
        }
    }

    /// Save configuration to file
    /// SECURITY: Be careful not to expose sensitive data in logs
    pub fn save(&self) -> Result<()> {
        let config_path = std::env::var("CONFIG_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("config.toml"));

        let toml_string = toml::to_string_pretty(self)
            .map_err(|e| anyhow::anyhow!("Failed to serialize config: {}", e))?;

        std::fs::write(&config_path, toml_string)
            .map_err(|e| anyhow::anyhow!("Failed to write config file: {}", e))?;

        Ok(())
    }
}
