use std::sync::Arc;
use crate::db::models::{Order, OrderData, DisputeData};
use crate::crypto::oblivious;
use crate::crypto::zk::floor_timestamp_6h;
use crate::gateway::state::AppState;

pub async fn check_time_locks(state: &Arc<AppState>) -> anyhow::Result<()> {
    let now = floor_timestamp_6h(time::OffsetDateTime::now_utc().unix_timestamp());

    let orders = sqlx::query_as::<_, Order>(
        "SELECT * FROM orders"
    )
    .fetch_all(&state.pool)
    .await?;

    for order in &orders {
        let Some(raw) = oblivious::decrypt_order_blob(&order.encrypted_order_blob, &state.master_seed[..], &order.id) else { continue };
        let Ok(mut data) = serde_json::from_slice::<OrderData>(&raw) else { continue };

        let version = order.version;
        match data.state.as_str() {
            "shipped" => handle_shipped(&state, &order.id, &mut data, now, version).await?,
            "funded" => handle_funded(&state, &order.id, &mut data, now, version).await?,
            "disputed" => handle_disputed(&state, &order.id, &mut data, now, version).await?,
            _ => {}
        }
    }

    Ok(())
}

fn has_active_dispute(data: &OrderData) -> bool {
    data.dispute.as_ref().map_or(false, |d| d.resolved_at.is_none())
}

async fn write_order(state: &Arc<AppState>, id: &[u8], data: &OrderData, version: i64) -> anyhow::Result<()> {
    let json = serde_json::to_vec(data)?;
    let blob = oblivious::encrypt_order_blob(&json, &state.master_seed[..], id)
        .ok_or_else(|| anyhow::anyhow!("Encryption failed"))?;
    let expiry_bucket = data.expires_at.map(floor_timestamp_6h);
    let result = sqlx::query(
        "UPDATE orders SET encrypted_order_blob = ?1, expiry_bucket = ?2, version = version + 1 WHERE id = ?3 AND version = ?4"
    )
    .bind(&blob)
    .bind(expiry_bucket)
    .bind(id)
    .bind(version)
    .execute(&state.pool)
    .await?;

    if result.rows_affected() == 0 {
        return Err(anyhow::anyhow!("order modified by concurrent writer"));
    }

    Ok(())
}

async fn handle_shipped(state: &Arc<AppState>, id: &[u8], data: &mut OrderData, now: i64, version: i64) -> anyhow::Result<()> {
    if has_active_dispute(data) {
        return Ok(());
    }

    if !data.can_transition_to("released") {
        return Ok(());
    }

    let shipped_at = data.shipped_at.unwrap_or(data.created_at);
    let release_time = shipped_at.saturating_add(data.time_lock_seconds);

    if now >= release_time {
        data.state = "released".to_string();
        data.released_at = Some(now);
        write_order(state, id, data, version).await?;
    }

    Ok(())
}

async fn handle_funded(state: &Arc<AppState>, id: &[u8], data: &mut OrderData, now: i64, version: i64) -> anyhow::Result<()> {
    if has_active_dispute(data) {
        return Ok(());
    }

    if !data.can_transition_to("disputed") {
        return Ok(());
    }

    let funded_at = data.funded_at.unwrap_or(data.created_at);
    let ship_window = data.time_lock_seconds.saturating_mul(2);
    let abandon_time = funded_at.saturating_add(ship_window);

    if now >= abandon_time {
        data.state = "disputed".to_string();
        data.disputed_at = Some(now);
        data.expires_at = Some(now.saturating_add(data.time_lock_seconds));

        let dispute = DisputeData {
            id: uuid::Uuid::new_v4().to_string(),
            opened_by: hex::encode(&data.buyer_pubkey_hash),
            reason: "Auto-dispute: seller timeout after 2x time lock".to_string(),
            resolution: None,
            resolved_by: None,
            resolved_at: None,
            created_at: now,
            evidence: vec![],
        };

        data.dispute_id = Some(dispute.id.clone());
        data.dispute = Some(dispute);

        write_order(state, id, data, version).await?;
    }

    Ok(())
}

async fn handle_disputed(state: &Arc<AppState>, id: &[u8], data: &mut OrderData, now: i64, version: i64) -> anyhow::Result<()> {
    if !data.can_transition_to("refunded") {
        return Ok(());
    }

    let expires_at = data.expires_at.unwrap_or(data.created_at.saturating_add(data.time_lock_seconds));
    if now >= expires_at {
        if let Some(ref mut dispute) = data.dispute {
            if dispute.resolved_at.is_none() {
                dispute.resolution = Some("refund".to_string());
                dispute.resolved_by = Some("auto_system".to_string());
                dispute.resolved_at = Some(now);
            }
        }

        data.state = "refunded".to_string();
        data.refunded_at = Some(now);

        write_order(state, id, data, version).await?;
    }

    Ok(())
}
