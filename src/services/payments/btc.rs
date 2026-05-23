//! Bitcoin Payment Service (Low-level RPC client)
//!
//! Direct Bitcoin Core RPC interface.
//! SECURITY: Uses u64 satoshis for all amounts (no float precision loss)

use anyhow::{anyhow, Result};
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::config::BitcoinConfig;
use crate::crypto::zk::constant_time_compare;

const SATOSHIS_PER_BTC: u64 = 100_000_000;
const DUST_THRESHOLD_SATS: u64 = 546;

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
    pub fn new(config: BitcoinConfig) -> Result<Self, anyhow::Error> {
        Ok(Self {
            config,
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()?,
            nonce: Arc::new(Mutex::new(0)),
            last_block_hash: Arc::new(Mutex::new(None)),
        })
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

        let mut req = self.http.post(&self.config.rpc_url).json(&body);
        if let Some(auth) = self.auth_header() {
            req = req.header("Authorization", auth);
        }

        let resp = req.send().await.map_err(|e| anyhow!("BTC RPC request failed: {}", e))?;
        let json: serde_json::Value = resp.json().await.map_err(|e| anyhow!("BTC RPC parse failed: {}", e))?;

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
            .filter(|tx| tx.address.as_ref().map_or(false, |a| constant_time_compare(a.as_bytes(), address.as_bytes())))
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
}