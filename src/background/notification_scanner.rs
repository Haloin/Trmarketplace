use std::sync::Arc;
use crate::db::models::{NotificationTracker, Order, OrderData};
use crate::crypto::oblivious;
use crate::crypto::zk::floor_timestamp_6h;
use crate::gateway::state::AppState;
use crate::services::escrow::btc::parse_secp_pubkey;
use crate::services::payments::btc::{BitcoinClient, DecodedVout};
use crate::services::payments::stealth_escrow;
use time::OffsetDateTime;

const NOTIFICATION_MAGIC: &[u8] = b"bobN";

pub async fn scan_notifications(state: &Arc<AppState>) -> anyhow::Result<()> {
    let btc_config = &state.config.bitcoin;
    let network = btc_config.btc_network()
        .map_err(|e| anyhow::anyhow!("Config error: {e}"))?;
    let http = state.socks_pool.get_client(b"btc-notif-scanner").await;
    let rpc = BitcoinClient::new(btc_config.clone(), http);

    // Track last scanned block in-memory (default to current height on first run)
    let last_block = state.last_notif_block.lock().await.clone();
    let block_hash = match last_block {
        Some(h) => h,
        None => {
            let height = rpc.get_block_height().await?;
            let hash = rpc.get_block_hash(height).await?;
            *state.last_notif_block.lock().await = Some(hash.clone());
            return Ok(()); // nothing to scan on first run
        }
    };

    let (txs, new_last_block) = match rpc.list_since_block(&block_hash).await {
        Ok(v) => v,
        Err(e) => {
            tracing::debug!("listsinceblock failed (first run?): {e}");
            return Ok(());
        }
    };

    for tx_entry in &txs {
        if tx_entry.confirmations < 1 {
            continue; // skip unconfirmed
        }

        let tx_hash_bytes = hex::decode(&tx_entry.txid)?;
        // Check if already processed
        let already = sqlx::query_as::<_, NotificationTracker>(
            "SELECT * FROM notification_tracker WHERE tx_hash = ?1"
        )
        .bind(&tx_hash_bytes)
        .fetch_optional(&state.pool)
        .await?;
        if already.is_some() {
            continue;
        }

        // Fetch and decode the transaction to find OP_RETURN outputs
        let raw_tx = match rpc.get_raw_transaction(&tx_entry.txid).await {
            Ok(t) => t,
            Err(_) => continue,
        };
        let decoded = match rpc.decode_raw_transaction(&raw_tx.hex).await {
            Ok(d) => d,
            Err(_) => continue,
        };

        // Look for OP_RETURN vout with our magic prefix
        let Some((order_id_bytes, buyer_pubkey_bytes)) = extract_notification(&decoded.vout) else {
            continue;
        };

        // Validate order_id length
        if order_id_bytes.len() != 32 {
            continue;
        }

        // Look up the order
        let order = match sqlx::query_as::<_, Order>(
            "SELECT * FROM orders WHERE id = ?1"
        )
        .bind(&order_id_bytes)
        .fetch_optional(&state.pool)
        .await?
        {
            Some(o) => o,
            None => continue, // order not found — skip
        };

        // Decrypt the order blob — skip if it already has an escrow address
        let Some(worker_key) = state.worker_key.as_ref() else {
            // Worker process must have worker_key set; skip if not.
            continue;
        };
        let raw = match oblivious::decrypt_order_blob(
            &order.encrypted_order_blob, worker_key, &order.id
        ) {
            Some(r) => r,
            None => continue,
        };
        let mut data: OrderData = match serde_json::from_slice(&raw) {
            Ok(d) => d,
            Err(_) => continue,
        };
        if data.escrow_address.is_some() {
            continue; // already funded
        }

        // Validate buyer pubkey is a valid secp256k1 public key
        if parse_secp_pubkey(&hex::encode(&buyer_pubkey_bytes)).is_err() {
            continue;
        }
        let buyer_pk_hex = hex::encode(&buyer_pubkey_bytes);

        // Derive stealth address
        let stealth_addr = match stealth_escrow::create_stealth_address_for_order(
            &buyer_pk_hex,
            worker_key,
            &order_id_bytes,
            network,
            &rpc,
        ).await {
            Ok(a) => a,
            Err(_) => continue,
        };

        // Update the order blob with the escrow address and buyer pubkey
        data.escrow_address = Some(stealth_addr);
        data.buyer_pubkey = Some(buyer_pk_hex);

        let json = serde_json::to_vec(&data)?;
        let new_blob = oblivious::encrypt_order_blob(&json, worker_key, &order_id_bytes)
            .ok_or_else(|| anyhow::anyhow!("Encryption failed"))?;
        let expiry_bucket = data.expires_at.map(floor_timestamp_6h);
        sqlx::query(
            "UPDATE orders SET encrypted_order_blob = ?1, expiry_bucket = ?2, version = version + 1 WHERE id = ?3 AND version = ?4"
        )
        .bind(&new_blob)
        .bind(expiry_bucket)
        .bind(&order_id_bytes)
        .bind(order.version)
        .execute(&state.pool)
        .await?;

        // Record in notification_tracker
        let now = floor_timestamp_6h(OffsetDateTime::now_utc().unix_timestamp());
        sqlx::query(
            "INSERT OR IGNORE INTO notification_tracker (tx_hash, order_id, buyer_pubkey, processed_at) VALUES (?1, ?2, ?3, ?4)"
        )
        .bind(&tx_hash_bytes)
        .bind(&order_id_bytes)
        .bind(&buyer_pubkey_bytes)
        .bind(now)
        .execute(&state.pool)
        .await?;

        tracing::info!(
            order_id = %hex::encode(&order_id_bytes),
            "BTC notification processed, stealth address imported"
        );
    }

    // Update last scanned block
    *state.last_notif_block.lock().await = Some(new_last_block);

    Ok(())
}

/// Extract order_id (32 bytes) and buyer_pubkey (33 bytes) from an OP_RETURN output
/// with the magic prefix `bobN` (4 bytes).
///
/// OP_RETURN data format: `[bobN:4][order_id:32][pubkey:33]` = 69 bytes total
fn extract_notification(vouts: &[DecodedVout]) -> Option<(Vec<u8>, Vec<u8>)> {
    for vout in vouts {
        let script_type = vout.script_pub_key.r#type.as_deref()?;
        if script_type != "nulldata" {
            continue;
        }
        let asm = vout.script_pub_key.asm.as_ref()?;
        // ASM format: "OP_RETURN <hexdata>"
        let hex_data = asm.strip_prefix("OP_RETURN ")?.trim();
        let bytes = hex::decode(hex_data).ok()?;

        // Check magic prefix
        if !bytes.starts_with(NOTIFICATION_MAGIC) {
            continue;
        }

        let payload = &bytes[NOTIFICATION_MAGIC.len()..];
        if payload.len() < 65 {
            continue; // need at least 32 + 33 bytes
        }

        let order_id = payload[..32].to_vec();
        let pubkey = payload[32..65].to_vec();
        return Some((order_id, pubkey));
    }
    None
}
