//! Bitcoin Core RPC client (amounts in u64 satoshis).

use anyhow::{anyhow, Result};
use base64::Engine;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

use crate::config::BitcoinConfig;
use crate::crypto::zk::constant_time_compare;

const SATOSHIS_PER_BTC: u64 = 100_000_000;
const DUST_THRESHOLD_SATS: u64 = 546;

/// All RPC request bodies are padded to this size on the wire
/// to prevent traffic analysis from distinguishing operation types.
const PADDED_BODY_SIZE: usize = 4096;

/// Baseline for timing jitter (ms). Pre-request and post-response delays
/// are each ~BASELINE_MS ± 30%, making total observable time per RPC call
/// approximately 2× baseline regardless of server-side operation speed.
const JITTER_BASELINE_MS: u64 = 1000;

/// Pad a JSON-RPC body to exactly PADDED_BODY_SIZE bytes by inserting
/// whitespace before the closing `}`. The result is still valid JSON.
fn pad_json_body(body: &serde_json::Value) -> Vec<u8> {
    let body_str = serde_json::to_string(body).expect("JSON serialization must not fail");
    debug_assert!(body_str.ends_with('}'), "JSON body must end with '}}'");
    let without_close = &body_str[..body_str.len() - 1];
    let mut padded = String::with_capacity(PADDED_BODY_SIZE);
    padded.push_str(without_close);
    let remaining = PADDED_BODY_SIZE.saturating_sub(padded.len() + 1);
    for _ in 0..remaining {
        padded.push(' ');
    }
    padded.push('}');
    debug_assert_eq!(padded.len(), PADDED_BODY_SIZE);
    padded.into_bytes()
}

/// Sleep for JITTER_BASELINE_MS ± 30% to prevent timing-based
/// traffic analysis from distinguishing fast vs slow operations.
async fn jitter_delay() {
    let jitter = rand::thread_rng().gen_range(
        (JITTER_BASELINE_MS * 7 / 10)..=(JITTER_BASELINE_MS * 13 / 10)
    );
    tokio::time::sleep(Duration::from_millis(jitter)).await;
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, PartialOrd)]
pub enum PaymentStatus {
    Pending,
    PartiallyFunded,
    Funded,
    Expired,
}

impl PaymentStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::PartiallyFunded => "partially_funded",
            Self::Funded => "funded",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone)]
pub struct BitcoinClient {
    pub config: BitcoinConfig,
    pub http: reqwest::Client,
    nonce: Arc<Mutex<u64>>,
    last_block_hash: Arc<Mutex<Option<(u64, String)>>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TransactionOutput {
    pub address: String,
    pub amount: f64,
    pub confirmations: i32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TransactionDetail {
    pub txid: String,
    pub address: Option<String>,
    pub amount: f64,
    pub fee: Option<f64>,
    pub confirmations: i32,
    pub time: i64,
    pub label: Option<String>,
}

impl BitcoinClient {
    /// Create a new Bitcoin RPC client using a pre-built reqwest::Client.
    /// The http client should come from Socks5Pool for circuit-isolated Tor routing.
    pub fn new(config: BitcoinConfig, http: reqwest::Client) -> Self {
        Self {
            config,
            http,
            nonce: Arc::new(Mutex::new(0)),
            last_block_hash: Arc::new(Mutex::new(None)),
        }
    }

    fn auth_header(&self) -> Option<String> {
        match (&self.config.rpc_user, &self.config.rpc_password) {
            (Some(user), Some(pass)) => {
                let creds = base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", user, pass));
                Some(format!("Basic {}", creds))
            }
            _ => None,
        }
    }

    pub(crate) async fn rpc_call<R: for<'de> Deserialize<'de>>(&self, method: &str, params: serde_json::Value) -> Result<R> {
        let mut nonce = self.nonce.lock().await;
        *nonce += 1;
        let id = *nonce;

        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        });

        let padded_body = pad_json_body(&body);

        jitter_delay().await;
        let mut req = self.http.post(&self.config.rpc_url).body(padded_body);
        if let Some(auth) = self.auth_header() {
            req = req.header("Authorization", auth);
        }
        req = req.header("Content-Type", "application/json");

        let resp = req.send().await.map_err(|e| anyhow!("BTC RPC request failed: {}", e))?;
        let json: serde_json::Value = resp.json().await.map_err(|e| anyhow!("BTC RPC parse failed: {}", e))?;
        jitter_delay().await;

        if let Some(error) = json.get("error") {
            if !error.is_null() {
                return Err(anyhow!("BTC RPC error: {}", error));
            }
        }

        Ok(serde_json::from_value(json["result"].clone())?)
    }

    pub async fn wallet_is_ready(&self) -> Result<bool> {
#[derive(Deserialize)]
    struct Result {
        #[allow(dead_code)]
        wallet_name: Option<String>,
    }
        let _: Result = self.rpc_call("getwalletinfo", serde_json::json!([])).await?;
        Ok(true)
    }

    pub async fn get_block_height(&self) -> Result<u64> {
        #[derive(Deserialize)]
        struct R { result: u64 }
        let r: R = self.rpc_call("getblockcount", serde_json::Value::Null).await?;
        Ok(r.result)
    }

    pub async fn get_block_hash(&self, height: u64) -> Result<String> {
        #[derive(Deserialize)]
        struct R { result: String }
        let r: R = self.rpc_call("getblockhash", serde_json::json!([height])).await?;
        Ok(r.result)
    }

    pub async fn check_for_fork(&self) -> Result<bool> {
        let current_height = self.get_block_height().await?;
        let current_hash = self.get_block_hash(current_height).await?;

        let mut cached = self.last_block_hash.lock().await;
        if let Some((cached_height, cached_hash)) = cached.as_ref() {
            if *cached_height == current_height {
                if !constant_time_compare(cached_hash.as_bytes(), current_hash.as_bytes()) {
                    tracing::warn!("BTC fork detected at height {}", current_height);
                    *cached = Some((current_height, current_hash));
                    return Ok(true);
                }
                return Ok(false);
            }
        }
        *cached = Some((current_height, current_hash));
        Ok(false)
    }

    pub async fn create_address(&self, order_id: &str) -> Result<String> {
        #[derive(Deserialize)]
        struct R { result: String }
        let addr_type = self.config.address_type.as_str();
        let r: R = self.rpc_call(
            "getnewaddress",
            serde_json::json!([format!("order:{}", order_id), addr_type]),
        ).await?;
        Ok(r.result)
    }

    pub async fn list_transactions_for_address(&self, address: &str) -> Result<Vec<TransactionDetail>> {
        #[derive(Deserialize)]
        struct R { result: Vec<TransactionDetail> }
        let r: R = self.rpc_call(
            "listtransactions",
            serde_json::json!([format!("order:*"), 10000, 0, true]),
        ).await?;

        let matching: Vec<TransactionDetail> = r.result
            .into_iter()
            .filter(|tx| tx.address.as_ref().is_some_and(|a| constant_time_compare(a.as_bytes(), address.as_bytes())))
            .collect();

        Ok(matching)
    }

    pub async fn get_transaction(&self, tx_hash: &str) -> Result<TransactionDetail> {
        #[derive(Deserialize)]
        struct R {
            result: TransactionDetail,
        }
        let r: R = self.rpc_call("gettransaction", serde_json::json!([tx_hash, true])).await?;
        Ok(r.result)
    }

    pub async fn get_address_balance(&self, address: &str) -> Result<(u64, u32)> {
        let txs = self.list_transactions_for_address(address).await?;

        let mut total_sats: u64 = 0;
        let mut max_confirmations: u32 = 0;

        for tx in txs {
            if tx.confirmations > 0 {
                let sats = btc_f64_to_sats(tx.amount);
                total_sats = total_sats.saturating_add(sats);
                max_confirmations = max_confirmations.max(tx.confirmations as u32);
            }
        }

        // NOTE: listtransactions with count=10000 covers the typical escrow address use case
        // (1-2 transactions max). For high-volume addresses, consider fallback to
        // listreceivedbyaddress for comprehensive balance queries.
        Ok((total_sats, max_confirmations))
    }

    pub async fn get_transaction_confirmations(&self, tx_hash: &str) -> Result<u32> {
        let tx = self.get_transaction(tx_hash).await?;
        Ok(tx.confirmations.max(0) as u32)
    }

    pub async fn list_unspent(&self, addresses: &[String]) -> Result<Vec<ListUnspentEntry>> {
        #[derive(Deserialize)]
        struct R { result: Vec<ListUnspentEntry> }
        let r: R = self.rpc_call(
            "listunspent",
            serde_json::json!([0, 9999999, addresses]),
        ).await?;
        Ok(r.result)
    }

    /// Fetch a raw wallet transaction and decode its hex, including OP_RETURN data.
    pub async fn get_raw_transaction(&self, tx_hash: &str) -> Result<RawTransaction> {
        #[derive(Deserialize)]
        struct R { result: RawTransaction }
        let r: R = self.rpc_call(
            "gettransaction",
            serde_json::json!([tx_hash, true]),
        ).await?;
        Ok(r.result)
    }

    /// Fetch all wallet transactions since a given block height (uses `listsinceblock`).
    /// Returns (transactions, last_block_hash).
    pub async fn list_since_block(&self, block_hash: &str) -> Result<(Vec<ListSinceBlockEntry>, String)> {
        #[derive(Deserialize)]
        struct R {
            result: ListSinceBlockResult,
        }
        #[derive(Deserialize)]
        struct ListSinceBlockResult {
            transactions: Vec<ListSinceBlockEntry>,
            lastblock: String,
        }
        let r: R = self.rpc_call(
            "listsinceblock",
            serde_json::json!([block_hash]),
        ).await?;
        Ok((r.result.transactions, r.result.lastblock))
    }

    /// Decode a raw transaction hex into structured data, revealing all outputs.
    pub async fn decode_raw_transaction(&self, hex: &str) -> Result<DecodedTx> {
        #[derive(Deserialize)]
        struct R { result: DecodedTx }
        let r: R = self.rpc_call("decoderawtransaction", serde_json::json!([hex])).await?;
        Ok(r.result)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ListUnspentEntry {
    pub txid: String,
    pub vout: u32,
    pub address: String,
    pub amount: f64,
    pub confirmations: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RawTransaction {
    pub hex: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ListSinceBlockEntry {
    pub txid: String,
    pub address: Option<String>,
    pub amount: f64,
    pub confirmations: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DecodedTx {
    pub txid: String,
    pub hash: String,
    pub version: i64,
    pub size: i64,
    pub vout: Vec<DecodedVout>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DecodedVout {
    pub value: f64,
    pub n: u32,
    pub script_pub_key: DecodedScriptPubKey,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DecodedScriptPubKey {
    pub asm: Option<String>,
    pub hex: String,
    pub r#type: Option<String>,
}

pub fn btc_f64_to_sats(amount: f64) -> u64 {
    (amount * SATOSHIS_PER_BTC as f64).round() as u64
}

pub fn sats_to_btc_f64(sats: u64) -> f64 {
    sats as f64 / SATOSHIS_PER_BTC as f64
}

pub fn parse_btc_amount(amount_str: &str) -> Result<u64> {
    if amount_str.is_empty() {
        return Err(anyhow!("Empty amount"));
    }
    let amount = amount_str.parse::<f64>().map_err(|_| anyhow!("Invalid BTC amount"))?;
    if amount <= 0.0 {
        return Err(anyhow!("Amount must be positive"));
    }
    let sats = btc_f64_to_sats(amount);
    if sats < DUST_THRESHOLD_SATS {
        return Err(anyhow!("Amount below dust threshold"));
    }
    Ok(sats)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_btc_sats_conversion() {
        assert_eq!(btc_f64_to_sats(1.0), 100_000_000);
        assert_eq!(btc_f64_to_sats(0.00000546), 546);
        assert_eq!(sats_to_btc_f64(100_000_000), 1.0);
    }

    #[test]
    fn test_parse_btc_amount() {
        assert_eq!(parse_btc_amount("1.0").unwrap(), 100_000_000);
        assert_eq!(parse_btc_amount("0.001").unwrap(), 100_000);
        assert!(parse_btc_amount("").is_err());
        assert!(parse_btc_amount("-1.0").is_err());
        assert!(parse_btc_amount("0.000005").is_err());
    }

    #[test]
    fn test_payment_status_order() {
        assert!(PaymentStatus::Pending < PaymentStatus::Funded);
        assert!(PaymentStatus::Funded < PaymentStatus::Expired);
    }

    #[test]
    fn test_btc_body_pads_to_4096() {
        let bodies = vec![
            serde_json::json!({"jsonrpc":"2.0","id":1,"method":"getblockcount","params":null}),
            serde_json::json!({"jsonrpc":"2.0","id":2,"method":"listtransactions","params":["*", 10000, 0, true]}),
            serde_json::json!({"jsonrpc":"2.0","id":3,"method":"gettransaction","params":["abc123", true]}),
        ];
        for body in &bodies {
            let padded = pad_json_body(body);
            assert_eq!(padded.len(), PADDED_BODY_SIZE);
            assert!(padded.ends_with(b"}"));
            let parsed: serde_json::Value = serde_json::from_slice(&padded)
                .expect("Padded body must be valid JSON");
            assert_eq!(parsed["jsonrpc"], "2.0");
            assert_eq!(parsed["method"], body["method"]);
        }
    }

    #[test]
    fn test_btc_body_shorter_than_4096() {
        let min_body = serde_json::json!({"jsonrpc":"2.0","id":1,"method":"x","params":null});
        assert!(serde_json::to_string(&min_body).unwrap().len() < PADDED_BODY_SIZE,
            "Precondition: minimal body is shorter than 4096");
        let padded = pad_json_body(&min_body);
        assert_eq!(padded.len(), PADDED_BODY_SIZE);
    }

    #[test]
    fn test_btc_padding_roundtrip_preserves_semantics() {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 42,
            "method": "getbalance",
            "params": {"account": 0, "minconf": 1},
        });
        let padded = pad_json_body(&body);
        let parsed: serde_json::Value = serde_json::from_slice(&padded).unwrap();
        assert_eq!(parsed["method"], "getbalance");
        assert_eq!(parsed["id"], 42);
        assert_eq!(parsed["params"]["minconf"], 1);
    }
}