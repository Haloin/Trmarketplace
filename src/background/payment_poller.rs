use std::sync::Arc;
use crate::db::models::{Order, OrderData};
use crate::crypto::oblivious;
use crate::crypto::zk::{constant_time_compare, floor_timestamp_6h};
use crate::gateway::state::AppState;
use crate::services::payments::xmr::{MoneroViewOnlyClient, PaymentAuditRecord};
use crate::services::payments::btc_client::BtcPaymentClient;
use rand::Rng;

const REQUIRED_CONFIRMATIONS_XMR: u64 = 10;
const REQUIRED_CONFIRMATIONS_BTC: u64 = 6;
const MIN_PAYMENT_SATS: u64 = 546;

/// Get worker key for decryption. Workers must have worker_key set.
fn get_worker_key(state: &AppState) -> anyhow::Result<&[u8; 32]> {
    state.worker_key.as_ref()
        .ok_or_else(|| anyhow::anyhow!("Worker key not configured - workers cannot decrypt"))
}

/// Dummy payment check to obfuscate timing: adds ~10-50ms of fake work
/// with 30% probability to prevent timing side channels.
async fn dummy_payment_check() {
    if !rand::thread_rng().gen_bool(0.3) {
        return;
    }
    // Simulate a brief RPC call
    let delay_ms = rand::thread_rng().gen_range(10..50);
    tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
}

pub async fn check_pending_payments(state: &Arc<AppState>) -> anyhow::Result<()> {
    let now = floor_timestamp_6h(time::OffsetDateTime::now_utc().unix_timestamp());
    let worker_key = get_worker_key(state)?;

    let orders = sqlx::query_as::<_, Order>(
        "SELECT * FROM orders"
    )
    .fetch_all(&state.pool)
    .await?;

    let xmr_client = get_or_init_xmr_client(state).await;
    let btc_client = get_or_init_btc_client(state).await;

    let mut xmr_orders = Vec::new();
    let mut btc_orders = Vec::new();
    let mut order_map: std::collections::HashMap<Vec<u8>, (usize, OrderData)> = std::collections::HashMap::new();

    let payment_decrypt_sk = crate::crypto::escrow::derive_domain_key(worker_key, "payment-decrypt");

    for order in &orders {
        let raw = oblivious::decrypt_ecdh_blob(&order.encrypted_order_blob, &payment_decrypt_sk)
            .or_else(|| oblivious::decrypt_order_blob(&order.encrypted_order_blob, worker_key, &order.id));
        let Some(raw) = raw else {
            dummy_payment_check().await;
            continue;
        };
        let Ok(data) = serde_json::from_slice::<OrderData>(&raw) else {
            dummy_payment_check().await;
            continue;
        };
        if data.escrow_address.is_none() {
            dummy_payment_check().await;
            continue;
        }
        match data.state.as_str() {
            "pending" => {
                match data.currency.as_str() {
                    "XMR" => xmr_orders.push((order.id.clone(), data)),
                    "BTC" => btc_orders.push((order.id.clone(), data)),
                    _ => dummy_payment_check().await,
                }
            }
            "released" => {
                if data.currency == "BTC" && data.settlement_txid.is_none() {
                    order_map.insert(order.id.clone(), (order.version as usize, data));
                } else {
                    dummy_payment_check().await;
                }
            }
            _ => dummy_payment_check().await,
        }
    }

    if !xmr_orders.is_empty() || !btc_orders.is_empty() {
        if let Ok(false) = xmr_client.check_for_fork().await {
            check_xmr_payments(&xmr_client, state, &xmr_orders, now).await?;
        }

        if let Ok(false) = btc_client.check_for_fork().await {
            check_btc_payments(&btc_client, state, &btc_orders, now).await?;
        }
    }

    // Retry settlement for released BTC orders without a settlement txid.
    for order_id in order_map.into_keys() {
        let _ = retry_btc_settlement(state, &order_id).await;
    }

    Ok(())
}

async fn check_xmr_payments(
    xmr_client: &MoneroViewOnlyClient,
    state: &Arc<AppState>,
    orders: &[(Vec<u8>, OrderData)],
    now: i64,
) -> anyhow::Result<()> {
    for (row_id, data) in orders {
        let Some(ref escrow_addr) = data.escrow_address else { dummy_payment_check().await; continue; };
        let amount_str = data.escrow_amount.as_deref().unwrap_or("0");
        let expected_piconero = parse_xmr_amount_safe(amount_str);

        if expected_piconero == 0 {
            dummy_payment_check().await;
            continue;
        }

        match xmr_client.check_payment_with_confirmations(
            escrow_addr,
            expected_piconero,
            REQUIRED_CONFIRMATIONS_XMR,
        ).await {
            Ok(status) => {
                if status.fork_detected {
                    dummy_payment_check().await;
                    continue;
                }

                if status.received && status.confirmations >= REQUIRED_CONFIRMATIONS_XMR {
                    if let Some(ref returned_addr) = status.address {
                        if !constant_time_compare(returned_addr.as_bytes(), escrow_addr.as_bytes()) {
                            dummy_payment_check().await;
                            continue;
                        }
                    }

                    let order_id_hex = hex::encode(row_id);
                    let audit = PaymentAuditRecord {
                        order_id: order_id_hex,
                        tx_hash: status.tx_hash.clone().unwrap_or_default(),
                        address: escrow_addr.clone(),
                        amount: status.amount,
                        credited_height: 0,
                        credited_at: now,
                        verified: true,
                        rollback_at: None,
                    };
                    xmr_client.record_payment_audit(audit).await;

                    let _ = mark_order_funded(state, row_id, now).await;
                } else if status.received {
                    dummy_payment_check().await;
                } else {
                    let expiry = data.expires_at.unwrap_or(now + 86400);
                    if now > expiry {
                        let _ = mark_order_cancelled(state, row_id).await;
                    } else {
                        dummy_payment_check().await;
                    }
                }
            }
            Err(_) => dummy_payment_check().await,
        }
    }

    Ok(())
}

async fn check_btc_payments(
    btc_client: &BtcPaymentClient,
    state: &Arc<AppState>,
    orders: &[(Vec<u8>, OrderData)],
    now: i64,
) -> anyhow::Result<()> {
    for (row_id, data) in orders {
        let Some(ref escrow_addr) = data.escrow_address else { dummy_payment_check().await; continue; };
        let amount_str = data.escrow_amount.as_deref().unwrap_or("0");
        let expected_sats = parse_btc_amount_safe(amount_str);

        if expected_sats == 0 {
            dummy_payment_check().await;
            continue;
        }

        match btc_client.check_payment_with_confirmations(
            escrow_addr,
            expected_sats,
            REQUIRED_CONFIRMATIONS_BTC,
        ).await {
            Ok(status) => {
                if status.fork_detected {
                    dummy_payment_check().await;
                    continue;
                }

                if status.received && u64::from(status.confirmations) >= REQUIRED_CONFIRMATIONS_BTC {
                    if let Some(ref returned_addr) = status.address {
                        if !constant_time_compare(returned_addr.as_bytes(), escrow_addr.as_bytes()) {
                            dummy_payment_check().await;
                            continue;
                        }
                    }

                    let _ = mark_order_funded(state, row_id, now).await;
                } else if status.received {
                    dummy_payment_check().await;
                } else {
                    let expiry = data.expires_at.unwrap_or(now + 86400);
                    if now > expiry {
                        let _ = mark_order_cancelled(state, row_id).await;
                    } else {
                        dummy_payment_check().await;
                    }
                }
            }
            Err(_) => dummy_payment_check().await,
        }
    }

    Ok(())
}

async fn mark_order_funded(state: &Arc<AppState>, order_id: &[u8], now: i64) -> anyhow::Result<()> {
    let worker_key = state.worker_key.as_ref()
        .ok_or_else(|| anyhow::anyhow!("worker_key not set"))?;
    let order = sqlx::query_as::<_, Order>(
        "SELECT * FROM orders WHERE id = ?1"
    )
    .bind(order_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| anyhow::anyhow!("order not found"))?;

    let raw = oblivious::decrypt_order_blob(&order.encrypted_order_blob, worker_key, &order.id)
        .ok_or_else(|| anyhow::anyhow!("decrypt failed"))?;
    let mut data: OrderData = serde_json::from_slice(&raw)
        .map_err(|e| anyhow::anyhow!("parse failed: {e}"))?;

    if data.state != "pending" {
        return Err(anyhow::anyhow!("order not in pending state"));
    }

    data.state = "funded".to_string();
    data.funded_at = Some(now);

    // Notify WebSocket subscribers
    let _ = state.payment_tx.send(hex::encode(order_id));

    let json = serde_json::to_vec(&data)?;
    let new_blob = oblivious::encrypt_order_blob(&json, worker_key, order_id)
        .ok_or_else(|| anyhow::anyhow!("Encryption failed"))?;
    let expiry_bucket = data.expires_at.map(floor_timestamp_6h);

    let result = sqlx::query(
        "UPDATE orders SET encrypted_order_blob = ?1, expiry_bucket = ?2, version = version + 1 WHERE id = ?3 AND version = ?4"
    )
    .bind(&new_blob)
    .bind(expiry_bucket)
    .bind(order_id)
    .bind(order.version)
    .execute(&state.pool)
    .await?;

    if result.rows_affected() == 0 {
        return Err(anyhow::anyhow!("order modified by concurrent writer"));
    }

    Ok(())
}

async fn mark_order_cancelled(state: &Arc<AppState>, order_id: &[u8]) -> anyhow::Result<()> {
    let worker_key = state.worker_key.as_ref()
        .ok_or_else(|| anyhow::anyhow!("worker_key not set"))?;
    let order = sqlx::query_as::<_, Order>(
        "SELECT * FROM orders WHERE id = ?1"
    )
    .bind(order_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| anyhow::anyhow!("order not found"))?;

    let raw = oblivious::decrypt_order_blob(&order.encrypted_order_blob, worker_key, &order.id)
        .ok_or_else(|| anyhow::anyhow!("decrypt failed"))?;
    let mut data: OrderData = serde_json::from_slice(&raw)
        .map_err(|e| anyhow::anyhow!("parse failed: {e}"))?;

    if data.state != "pending" {
        return Err(anyhow::anyhow!("order not in pending state"));
    }

    data.state = "cancelled".to_string();

    let json = serde_json::to_vec(&data)?;
    let new_blob = oblivious::encrypt_order_blob(&json, worker_key, order_id)
        .ok_or_else(|| anyhow::anyhow!("Encryption failed"))?;

    let result = sqlx::query(
        "UPDATE orders SET encrypted_order_blob = ?1, version = version + 1 WHERE id = ?2 AND version = ?3"
    )
    .bind(&new_blob)
    .bind(order_id)
    .bind(order.version)
    .execute(&state.pool)
    .await?;

    if result.rows_affected() == 0 {
        return Err(anyhow::anyhow!("order modified by concurrent writer"));
    }

    Ok(())
}

async fn retry_btc_settlement(state: &Arc<AppState>, order_id: &[u8]) -> anyhow::Result<()> {
    let worker_key = state.worker_key.as_ref()
        .ok_or_else(|| anyhow::anyhow!("worker_key not set"))?;
    let order = sqlx::query_as::<_, Order>(
        "SELECT * FROM orders WHERE id = ?1"
    )
    .bind(order_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| anyhow::anyhow!("order not found"))?;

    let raw = oblivious::decrypt_order_blob(&order.encrypted_order_blob, worker_key, &order.id)
        .ok_or_else(|| anyhow::anyhow!("decrypt failed"))?;
    let mut data: OrderData = serde_json::from_slice(&raw)
        .map_err(|e| anyhow::anyhow!("parse failed: {e}"))?;

    if data.state != "released" || data.settlement_txid.is_some() {
        return Ok(());
    }

    let btc_http = state.socks_pool.get_client(b"btc-settlement-worker").await;
    if crate::services::payments::stealth_escrow::settle_stealth_order(state, btc_http, order_id, &mut data).await.is_err() {
        return Ok(()); // retry next cycle
    }

    if data.settlement_txid.is_some() {
        let json = serde_json::to_vec(&data)?;
        let new_blob = oblivious::encrypt_order_blob(&json, worker_key, order_id)
            .ok_or_else(|| anyhow::anyhow!("Encryption failed"))?;
        let expiry_bucket = data.expires_at.map(floor_timestamp_6h);

        sqlx::query(
            "UPDATE orders SET encrypted_order_blob = ?1, expiry_bucket = ?2, version = version + 1 WHERE id = ?3 AND version = ?4"
        )
        .bind(&new_blob)
        .bind(expiry_bucket)
        .bind(order_id)
        .bind(order.version)
        .execute(&state.pool)
        .await?;
    }

    Ok(())
}

fn parse_btc_amount_safe(amount_str: &str) -> u64 {
    if amount_str.is_empty() {
        return 0;
    }
    let amount_str = amount_str.trim();
    if amount_str.contains('.') {
        let parts: Vec<&str> = amount_str.split('.').collect();
        if parts.len() != 2 {
            return 0;
        }
        let whole = parts[0].parse::<u64>().unwrap_or(0);
        let frac_str = parts[1];
        let padded = if frac_str.len() < 8 {
            format!("{}{}", frac_str, "0".repeat(8 - frac_str.len()))
        } else if frac_str.len() > 8 {
            let first_8 = &frac_str[..8];
            let ninth_char = frac_str.chars().nth(8).unwrap_or('0');
            if ninth_char >= '5' {
                let base = first_8.parse::<u64>().unwrap_or(0);
                format!("{:08}", base.saturating_add(1))
            } else {
                first_8.to_string()
            }
        } else {
            frac_str.to_string()
        };
        let frac = padded.parse::<u64>().unwrap_or(0);
        let sats = whole.saturating_mul(100_000_000).saturating_add(frac);
        if sats < MIN_PAYMENT_SATS { 0 } else { sats }
    } else {
        match amount_str.parse::<u64>() {
            Ok(v) => {
                let sats = v.saturating_mul(100_000_000);
                if sats < MIN_PAYMENT_SATS { 0 } else { sats }
            }
            Err(_) => 0,
        }
    }
}

fn parse_xmr_amount_safe(amount_str: &str) -> u64 {
    if amount_str.is_empty() {
        return 0;
    }

    let amount_str = amount_str.trim();

    if amount_str.contains('e') || amount_str.contains('E') {
        let mut parts = amount_str.split(['e', 'E']);
        let mantissa_str = parts.next().unwrap_or("");
        let exponent_str = parts.next().unwrap_or("0");
        let mantissa_piconero = parse_decimal_string_to_int(mantissa_str, 12);
        let exponent: i32 = exponent_str.parse().unwrap_or(0);
        if exponent >= 0 {
            mantissa_piconero.saturating_mul(10u64.pow(exponent as u32))
        } else {
            let divisor = 10u64.pow((-exponent) as u32);
            mantissa_piconero / divisor
        }
    } else {
        parse_decimal_string_to_int(amount_str, 12)
    }
}

fn parse_decimal_string_to_int(s: &str, decimal_places: u32) -> u64 {
    let parts: Vec<&str> = s.split('.').collect();
    match parts.len() {
        1 => {
            parts[0].parse::<u64>().unwrap_or(0)
                .saturating_mul(10u64.pow(decimal_places))
        }
        2 => {
            let whole = parts[0].parse::<u64>().unwrap_or(0);
            let frac_str = parts[1];
            let frac_u64 = if frac_str.len() < decimal_places as usize {
                format!("{}{}", frac_str, "0".repeat(decimal_places as usize - frac_str.len()))
                    .parse::<u64>()
                    .unwrap_or(0)
            } else if frac_str.len() > decimal_places as usize {
                frac_str[..decimal_places as usize].parse::<u64>().unwrap_or(0)
            } else {
                frac_str.parse::<u64>().unwrap_or(0)
            };
            whole.saturating_mul(10u64.pow(decimal_places)).saturating_add(frac_u64)
        }
        _ => 0,
    }
}

pub async fn create_escrow_address(state: &Arc<AppState>, order_id: &str) -> anyhow::Result<String> {
    let client = get_or_init_xmr_client(state).await;
    let address = client.create_subaddress(order_id).await?;
    Ok(address)
}

async fn get_or_init_xmr_client(state: &Arc<AppState>) -> MoneroViewOnlyClient {
    let mut guard = state.xmr_client.lock().await;
    if guard.is_none() {
        let http = state.socks_pool.get_client(b"xmr-payment-worker").await;
        *guard = Some(MoneroViewOnlyClient::new(state.config.monero.clone(), http));
    }
    guard.clone().expect("just initialized")
}

async fn get_or_init_btc_client(state: &Arc<AppState>) -> BtcPaymentClient {
    let mut guard = state.btc_client.lock().await;
    if guard.is_none() {
        let http = state.socks_pool.get_client(b"btc-payment-worker").await;
        *guard = Some(BtcPaymentClient::new(state.config.bitcoin.clone(), http));
    }
    guard.clone()
        .expect("just initialized")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_xmr_amount_safe() {
        assert_eq!(parse_xmr_amount_safe("1.0"), 1_000_000_000_000);
        assert_eq!(parse_xmr_amount_safe("0.001"), 1_000_000_000);
        assert_eq!(parse_xmr_amount_safe("0.000001"), 1_000_000);
        assert_eq!(parse_xmr_amount_safe("100"), 100_000_000_000_000);
        assert_eq!(parse_xmr_amount_safe("1e-3"), 1_000_000_000);
        assert_eq!(parse_xmr_amount_safe("1E-3"), 1_000_000_000);
        assert_eq!(parse_xmr_amount_safe("0.001e0"), 1_000_000_000);
        assert_eq!(parse_xmr_amount_safe("1e-6"), 1_000_000);
        assert_eq!(parse_xmr_amount_safe(""), 0);
        assert_eq!(parse_xmr_amount_safe("invalid"), 0);
        assert_eq!(parse_xmr_amount_safe("0"), 0);
        assert_eq!(parse_xmr_amount_safe("0.001234567890"), 1_234_567_890);
        assert_eq!(parse_decimal_string_to_int("0.001234567890123", 12), 1_234_567_890);
        assert_eq!(parse_decimal_string_to_int("1.0", 12), 1_000_000_000_000);
    }

    #[test]
    fn test_parse_btc_amount_safe() {
        assert_eq!(parse_btc_amount_safe("1.0"), 100_000_000);
        assert_eq!(parse_btc_amount_safe("0.00000546"), 546);
        assert_eq!(parse_btc_amount_safe("0.000005"), 0);
        assert_eq!(parse_btc_amount_safe(""), 0);
        assert_eq!(parse_btc_amount_safe("invalid"), 0);
        assert_eq!(parse_btc_amount_safe("100"), 10_000_000_000);
        assert_eq!(parse_btc_amount_safe("0.12345678"), 12_345_678);
        assert_eq!(parse_btc_amount_safe("0.000005459"), 546);
        assert_eq!(parse_btc_amount_safe("1.23456789"), 123_456_789);
    }

    #[test]
    fn test_min_payment_constants() {
        assert_eq!(MIN_PAYMENT_SATS, 546);
    }
}
