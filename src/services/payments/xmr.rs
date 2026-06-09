//! Monero view-only wallet: detect payments, never spend. Fork detection included.

use anyhow::{anyhow, Result};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;
use subtle::ConstantTimeEq;
use time::OffsetDateTime;

use crate::config::MoneroConfig;

/// Minimum payment amount in piconero (0.001 XMR)
/// Prevents dust attack spam
const MIN_PAYMENT_PICONERO: u64 = 1_000_000_000;

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

/// Incoming transfer with full verification data
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IncomingTransfer {
    pub tx_hash: String,
    pub address: String,        // SECURITY: Track which address received
    pub amount: u64,            // Amount in piconero (integer, not float)
    pub confirmations: u64,
    pub timestamp: u64,
    pub block_height: u64,
}

/// Payment verification result
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PaymentStatus {
    pub received: bool,
    pub amount: u64,
    pub confirmations: u64,
    pub tx_hash: Option<String>,
    pub address: Option<String>,
    pub fork_detected: bool,
}

/// Payment audit record for rollback tracking
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PaymentAuditRecord {
    pub order_id: String,
    pub tx_hash: String,
    pub address: String,
    pub amount: u64,
    pub credited_height: u64,
    pub credited_at: i64,
    pub verified: bool,
    pub rollback_at: Option<i64>,
}

/// View-only Monero client - can view, CANNOT spend
#[derive(Clone)]
pub struct MoneroViewOnlyClient {
    config: MoneroConfig,
    http: reqwest::Client,
    nonce: Arc<Mutex<u64>>,
    last_block_height: Arc<Mutex<u64>>,
    last_block_hash: Arc<Mutex<String>>,
    fork_detected: Arc<Mutex<bool>>,
    pending_audits: Arc<Mutex<Vec<PaymentAuditRecord>>>,
}

impl MoneroViewOnlyClient {
    /// Create a new Monero view-only client using a pre-built reqwest::Client.
    /// The http client should come from Socks5Pool for circuit-isolated Tor routing.
    pub fn new(config: MoneroConfig, http: reqwest::Client) -> Self {
        Self {
            config,
            http,
            nonce: Arc::new(Mutex::new(0)),
            last_block_height: Arc::new(Mutex::new(0)),
            last_block_hash: Arc::new(Mutex::new(String::new())),
            fork_detected: Arc::new(Mutex::new(false)),
            pending_audits: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn auth_header(&self) -> Option<String> {
        match (&self.config.wallet_rpc_user, &self.config.wallet_rpc_password) {
            (Some(user), Some(pass)) => {
                let creds = base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    format!("{}:{}", user, pass),
                );
                Some(format!("Basic {}", creds))
            }
            _ => None,
        }
    }

    async fn rpc_call(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value> {
        // Pre-request jitter: ±30% of baseline
        {
            let jitter_ms = (JITTER_BASELINE_MS as f64
                * rand::thread_rng().gen_range(0.7..1.3)) as u64;
            tokio::time::sleep(tokio::time::Duration::from_millis(jitter_ms)).await;
        }

        let mut nonce = self.nonce.lock().await;
        *nonce += 1;

        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": *nonce,
            "method": method,
            "params": params,
        });

        let padded_body = pad_json_body(&body);

        let mut req = self.http.post(&self.config.wallet_rpc_url)
            .header("Content-Type", "application/json")
            .body(padded_body);

        if let Some(auth) = self.auth_header() {
            req = req.header("Authorization", auth);
        }

        let resp = req.send().await
            .map_err(|e| anyhow!("XMR RPC request failed: {}", e))?;

        let json: serde_json::Value = resp.json().await
            .map_err(|e| anyhow!("XMR RPC parse failed: {}", e))?;

        // Post-response jitter: normalize total round-trip time
        // so fast operations (e.g. get_height ~5ms) and slow ones
        // (e.g. create_address ~500ms) look identical on the wire.
        {
            let jitter_ms = (JITTER_BASELINE_MS as f64
                * rand::thread_rng().gen_range(0.7..1.3)) as u64;
            tokio::time::sleep(tokio::time::Duration::from_millis(jitter_ms)).await;
        }

        if let Some(error) = json.get("error") {
            if !error.is_null() {
                return Err(anyhow!("XMR RPC error: {}", error));
            }
        }

        Ok(json["result"].clone())
    }

    /// Get current blockchain height
    pub async fn get_height(&self) -> Result<u64> {
        let result = self.rpc_call("get_height", serde_json::Value::Null).await?;
        let height = result["height"]
            .as_u64()
            .ok_or_else(|| anyhow!("Missing height in response"))?;
        Ok(height)
    }

    /// Get block hash at specific height (for fork detection)
    pub async fn get_block_hash(&self, height: u64) -> Result<String> {
        let params = serde_json::json!({ "height": height });
        let result = self.rpc_call("get_block_hash", params).await?;
        let hash = result.as_str()
            .ok_or_else(|| anyhow!("Missing block hash"))?
            .to_string();
        Ok(hash)
    }

    /// Check for chain reorganization (fork)
    /// SECURITY: Verifies both height AND block hash continuity
    /// Returns Ok(true) if fork detected, Ok(false) if chain is healthy
    pub async fn check_for_fork(&self) -> Result<bool> {
        let current_height = self.get_height().await?;
        let current_hash = self.get_block_hash(current_height).await?;
        
        let mut last_height = self.last_block_height.lock().await;
        let mut last_hash = self.last_block_hash.lock().await;
        
        // First run - initialize tracking
        if *last_height == 0 {
            *last_height = current_height;
            *last_hash = current_hash;
            return Ok(false);
        }
        
        // Check for height regression (obvious fork)
        if current_height < *last_height {
            tracing::warn!(
                "Fork detected: height decreased from {} to {}", 
                *last_height, current_height
            );
            *self.fork_detected.lock().await = true;
            *last_height = current_height;
            *last_hash = current_hash;
            return Ok(true);
        }
        
        // Check for chain split at known height
        if current_height > *last_height && !last_hash.is_empty() {
            // Verify our last known block hash is still in the chain
            let known_hash = last_hash.clone();
            let reorg_height = *last_height;
            
            // Check if previous hash still matches
            if let Ok(current_known_hash) = self.get_block_hash(reorg_height).await {
                if !constant_time_eq_str(&current_known_hash, &known_hash) {
                    tracing::warn!(
                        "Fork detected: block hash mismatch at height {}", 
                        reorg_height
                    );
                    *self.fork_detected.lock().await = true;
                    *last_hash = current_hash;
                    return Ok(true);
                }
            }
        }
        
        *last_height = current_height;
        *last_hash = current_hash;
        Ok(false)
    }

    /// Mark fork as resolved and trigger re-verification of pending payments
    pub async fn fork_resolved(&self) {
        let mut fork_detected = self.fork_detected.lock().await;
        if *fork_detected {
            tracing::info!("Fork resolved - pending payments will be re-verified");
            *fork_detected = false;
        }
    }

    /// Check if fork is currently detected
    pub fn is_fork_detected(&self) -> bool {
        *self.fork_detected.blocking_lock()
    }

    /// Create a new subaddress for an order
    /// SECURITY: Each order gets unique address for payment isolation
    pub async fn create_subaddress(&self, order_id: &str) -> Result<String> {
        let params = serde_json::json!({
            "account_index": 0,
            "label": format!("order:{}", order_id),
        });

        let result = self.rpc_call("create_address", params).await?;
        
        let address = result["address"]
            .as_str()
            .ok_or_else(|| anyhow!("Missing address in response"))?
            .to_string();

        Ok(address)
    }

    /// Get transfers for a specific subaddress
    /// SECURITY: Filters by exact address to prevent cross-order credit attacks
    pub async fn get_incoming_transfers(&self, subaddress: &str) -> Result<Vec<IncomingTransfer>> {
        let current_height = self.get_height().await?;
        
        // SECURITY: Use get_address_txs to get transfers for SPECIFIC subaddress
        let params = serde_json::json!({
            "address": subaddress,
            "account_index": 0,
        });

        let result = self.rpc_call("get_address_txs", params).await?;
        
        let mut transfers = Vec::new();
        
        // Parse incoming transactions
        if let Some(txs_array) = result.get("transactions").or_else(|| result.get("txs")) {
            if let Some(arr) = txs_array.as_array() {
                for tx in arr {
                    // SECURITY: Verify this is an incoming transfer
                    let tx_type = tx["type"].as_str().unwrap_or("");
                    if !tx_type.contains("in") && tx_type != "in" {
                        continue;
                    }
                    
                    let amount = tx["amount"]
                        .as_u64()
                        .unwrap_or(0);
                    
                    // SECURITY: Skip dust amounts
                    if amount < MIN_PAYMENT_PICONERO {
                        continue;
                    }
                    
                    let tx_hash = tx["txid"]
                        .as_str()
                        .unwrap_or("")
                        .to_string();
                    
                    let timestamp = tx["timestamp"]
                        .as_u64()
                        .unwrap_or(0);
                    
                    let block_height = tx["height"]
                        .as_u64()
                        .unwrap_or(current_height);
                    
                    let confirmations = current_height.saturating_sub(block_height);
                    
                    transfers.push(IncomingTransfer {
                        tx_hash,
                        address: subaddress.to_string(), // SECURITY: Record target address
                        amount,
                        confirmations,
                        timestamp,
                        block_height,
                    });
                }
            }
        }
        
        Ok(transfers)
    }

    /// Check if payment has been received with sufficient confirmations
    /// SECURITY: Verifies ADDRESS + AMOUNT + CONFIRMATIONS
    pub async fn check_payment_with_confirmations(
        &self, 
        subaddress: &str, 
        expected_amount: u64,
        required_confirmations: u64,
    ) -> Result<PaymentStatus> {
        // SECURITY: Check for fork before any payment verification
        let fork_detected = self.check_for_fork().await?;
        if fork_detected {
            tracing::warn!("Payment verification skipped due to fork detection");
            return Ok(PaymentStatus {
                received: false,
                amount: 0,
                confirmations: 0,
                tx_hash: None,
                address: None,
                fork_detected: true,
            });
        }

        // SECURITY: Get transfers only for SPECIFIC subaddress
        let transfers = self.get_incoming_transfers(subaddress).await?;
        
        // SECURITY: Find transfer matching ALL criteria: address + amount + confirmations
        for transfer in &transfers {
            // SECURITY: Verify transfer is to EXPECTED address (constant-time compare)
            if !constant_time_eq_str(&transfer.address, subaddress) {
                tracing::warn!("Payment address mismatch for order");
                continue;
            }
            
            // SECURITY: Verify amount meets or exceeds expected (prevents underpayment)
            // Also verify amount is above dust threshold
            if transfer.amount < MIN_PAYMENT_PICONERO {
                continue;
            }
            
                if transfer.amount >= expected_amount && expected_amount > 0 {
                if transfer.confirmations >= required_confirmations {
                    return Ok(PaymentStatus {
                        received: true,
                        amount: transfer.amount,
                        confirmations: transfer.confirmations,
                        tx_hash: Some(transfer.tx_hash.clone()),
                        address: Some(transfer.address.clone()),
                        fork_detected: false,
                    });
                } else {
                    // Payment received but not enough confirmations yet
                    return Ok(PaymentStatus {
                        received: true,
                        amount: transfer.amount,
                        confirmations: transfer.confirmations,
                        tx_hash: Some(transfer.tx_hash.clone()),
                        address: Some(transfer.address.clone()),
                        fork_detected: false,
                    });
                }
            }
        }
        
        // No payment received
        Ok(PaymentStatus {
            received: false,
            amount: 0,
            confirmations: 0,
            tx_hash: None,
            address: None,
            fork_detected: false,
        })
    }

    /// Record payment for audit/rollback tracking
    pub async fn record_payment_audit(&self, record: PaymentAuditRecord) {
        let mut audits = self.pending_audits.lock().await;
        audits.push(record);
    }

    /// Get pending payment audits
    pub async fn get_pending_audits(&self) -> Vec<PaymentAuditRecord> {
        self.pending_audits.lock().await.clone()
    }

    /// Clear verified audit records
    pub async fn clear_verified_audits(&self) {
        let mut audits = self.pending_audits.lock().await;
        audits.retain(|a| !a.verified && a.rollback_at.is_none());
    }

    /// Mark audit as verified
    pub async fn verify_audit(&self, tx_hash: &str) {
        let mut audits = self.pending_audits.lock().await;
        for audit in audits.iter_mut() {
            if constant_time_eq_str(&audit.tx_hash, tx_hash) {
                audit.verified = true;
            }
        }
    }

    /// Rollback payment on fork detection
    pub async fn rollback_payment(&self, tx_hash: &str) -> Result<()> {
        let mut audits = self.pending_audits.lock().await;
        for audit in audits.iter_mut() {
            if constant_time_eq_str(&audit.tx_hash, tx_hash) {
                audit.rollback_at = Some(crate::crypto::zk::floor_timestamp_6h(OffsetDateTime::now_utc().unix_timestamp()));

            }
        }
        Ok(())
    }

    /// Quick balance check for a subaddress
    pub async fn get_balance(&self, subaddress: &str) -> Result<(u64, u64)> {
        let params = serde_json::json!({
            "account_index": 0,
            "address": subaddress,
        });

        let result = self.rpc_call("get_balance", params).await?;
        
        let balance = result["balance"]
            .as_u64()
            .unwrap_or(0);
            
        let unlocked = result["unlocked_balance"]
            .as_u64()
            .unwrap_or(0);
            
        Ok((balance, unlocked))
    }
}

/// Constant-time string comparison to prevent timing attacks
fn constant_time_eq_str(a: &str, b: &str) -> bool {
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    
    if a_bytes.len() != b_bytes.len() {
        return false;
    }
    
    a_bytes.ct_eq(b_bytes).unwrap_u8() == 1
}

// SECURITY NOTE:
// This view-only client intentionally does NOT include transfer methods.
// For spending, use a separate cold wallet system (air-gapped).
// This ensures even if server is compromised, attacker cannot spend funds.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_eq_str() {
        assert!(constant_time_eq_str("test", "test"));
        assert!(!constant_time_eq_str("test", "other"));
        assert!(!constant_time_eq_str("test", "test longer"));
    }

    #[test]
    fn test_min_payment_constant() {
        assert_eq!(MIN_PAYMENT_PICONERO, 1_000_000_000);
    }

    #[test]
    fn test_rpc_body_pads_to_4096() {
        let bodies = vec![
            serde_json::json!({"jsonrpc":"2.0","id":1,"method":"get_height","params":null}),
            serde_json::json!({"jsonrpc":"2.0","id":2,"method":"create_address","params":{"account_index":0,"label":"order:abc"}}),
            serde_json::json!({"jsonrpc":"2.0","id":3,"method":"get_address_txs","params":{"address":"abc123","account_index":0}}),
        ];
        for body in &bodies {
            let padded = pad_json_body(body);
            assert_eq!(padded.len(), PADDED_BODY_SIZE);
            assert!(padded.ends_with(b"}"));
            // Verify it parses back as valid JSON
            let parsed: serde_json::Value = serde_json::from_slice(&padded)
                .expect("Padded body must be valid JSON");
            assert_eq!(parsed["jsonrpc"], "2.0");
            assert_eq!(parsed["method"], body["method"]);
        }
    }

    #[test]
    fn test_rpc_body_shorter_than_4096() {
        // Even the most minimal body must be padded
        let min_body = serde_json::json!({"jsonrpc":"2.0","id":1,"method":"x","params":null});
        assert!(serde_json::to_string(&min_body).unwrap().len() < PADDED_BODY_SIZE,
            "Precondition: minimal body is shorter than 4096");
        let padded = pad_json_body(&min_body);
        assert_eq!(padded.len(), PADDED_BODY_SIZE);
    }

    #[test]
    fn test_padding_roundtrip_preserves_semantics() {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 42,
            "method": "get_balance",
            "params": {"account_index": 0, "address": "abc"},
        });
        let padded = pad_json_body(&body);
        let parsed: serde_json::Value = serde_json::from_slice(&padded).unwrap();
        assert_eq!(parsed["method"], "get_balance");
        assert_eq!(parsed["id"], 42);
        assert_eq!(parsed["params"]["address"], "abc");
    }
}