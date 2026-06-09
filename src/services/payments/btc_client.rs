//! High-level Bitcoin payment verification.

use anyhow::Result;
use std::sync::Arc;
use subtle::ConstantTimeEq;

use super::btc::BitcoinClient;
use crate::config::BitcoinConfig;

const DUST_THRESHOLD_SATS: u64 = 546;

#[derive(Debug, Clone)]
pub struct IncomingTransfer {
    pub address: String,
    pub amount: u64,
    pub confirmations: u32,
    pub tx_hash: String,
}

#[derive(Debug, Clone)]
pub struct BtcPaymentStatus {
    pub received: bool,
    pub amount: u64,
    pub confirmations: u32,
    pub tx_hash: Option<String>,
    pub address: Option<String>,
    pub fork_detected: bool,
}

impl BtcPaymentStatus {
    pub fn not_received() -> Self {
        Self {
            received: false,
            amount: 0,
            confirmations: 0,
            tx_hash: None,
            address: None,
            fork_detected: false,
        }
    }

    pub fn funded(amount: u64, confirmations: u32, tx_hash: String, address: String) -> Self {
        Self {
            received: true,
            amount,
            confirmations,
            tx_hash: Some(tx_hash),
            address: Some(address),
            fork_detected: false,
        }
    }
}

#[derive(Clone)]
pub struct BtcPaymentClient {
    inner: Arc<BitcoinClient>,
}

impl BtcPaymentClient {
    /// Create a new BTC payment client using a pre-built reqwest::Client.
    /// The http client should come from Socks5Pool for circuit-isolated Tor routing.
    pub fn new(config: BitcoinConfig, http: reqwest::Client) -> Self {
        let inner = BitcoinClient::new(config, http);
        Self {
            inner: Arc::new(inner),
        }
    }

    pub async fn wallet_is_ready(&self) -> Result<bool> {
        self.inner.wallet_is_ready().await
    }

    pub async fn check_for_fork(&self) -> Result<bool> {
        self.inner.check_for_fork().await
    }

    pub async fn create_address(&self, order_id: &str) -> Result<String> {
        self.inner.create_address(order_id).await
    }

    pub async fn get_incoming_transfers(&self, address: &str) -> Result<Vec<IncomingTransfer>> {
        let txs = self.inner.list_transactions_for_address(address).await?;

        let mut transfers: Vec<IncomingTransfer> = Vec::new();

        for tx in txs {
            if tx.confirmations <= 0 {
                continue;
            }
            if tx.amount <= 0.0 {
                continue;
            }
            let sats = (tx.amount * 100_000_000.0).round() as u64;

            if sats < DUST_THRESHOLD_SATS {
                continue;
            }

            if let Some(addr) = &tx.address {
                transfers.push(IncomingTransfer {
                    address: addr.clone(),
                    amount: sats,
                    confirmations: tx.confirmations.max(0) as u32,
                    tx_hash: tx.txid,
                });
            }
        }

        Ok(transfers)
    }

    pub async fn check_payment_with_confirmations(
        &self,
        address: &str,
        expected_satoshis: u64,
        required_confirmations: u64,
    ) -> Result<BtcPaymentStatus> {
        if self.inner.check_for_fork().await? {
            tracing::warn!("BTC fork detected - payment verification skipped");
            return Ok(BtcPaymentStatus {
                received: false,
                amount: 0,
                confirmations: 0,
                tx_hash: None,
                address: None,
                fork_detected: true,
            });
        }

        let transfers = self.get_incoming_transfers(address).await?;

        for transfer in &transfers {
            if !constant_time_eq_str(&transfer.address, address) {
                continue;
            }

            if transfer.amount < DUST_THRESHOLD_SATS {
                continue;
            }

                if transfer.amount >= expected_satoshis && expected_satoshis > 0
                && transfer.confirmations as u64 >= required_confirmations {
                    return Ok(BtcPaymentStatus::funded(
                        transfer.amount,
                        transfer.confirmations,
                        transfer.tx_hash.clone(),
                        address.to_string(),
                    ));
                }
        }

        Ok(BtcPaymentStatus::not_received())
    }

    pub async fn get_address_balance(&self, address: &str) -> Result<(u64, u32)> {
        self.inner.get_address_balance(address).await
    }

}

pub fn constant_time_eq_str(a: &str, b: &str) -> bool {
    a.as_bytes().ct_eq(b.as_bytes()).unwrap_u8() == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq_str("abc", "abc"));
        assert!(!constant_time_eq_str("abc", "abd"));
        assert!(!constant_time_eq_str("abc", "ab"));
    }

    #[test]
    fn test_dust_threshold() {
        assert!(546 >= DUST_THRESHOLD_SATS);
    }
}