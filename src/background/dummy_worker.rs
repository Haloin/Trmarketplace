use std::sync::Arc;
use rand::Rng;
use rand::rngs::OsRng;
use uuid::Uuid;

use crate::crypto::oblivious;
use crate::crypto::zk::floor_timestamp_6h;
use crate::db::models::{ChatMessageData, DisputeData, DisputeEvidenceEntry, OrderData};
use crate::gateway::state::AppState;

fn random_hex(rng: &mut impl Rng, bytes: usize) -> String {
    let buf: Vec<u8> = (0..bytes).map(|_| rng.gen()).collect();
    hex::encode(&buf)
}

fn random_hash(rng: &mut impl Rng) -> Vec<u8> {
    (0..32).map(|_| rng.gen()).collect()
}

fn random_ed25519_pubkey(rng: &mut impl Rng) -> String {
    random_hex(rng, 32)
}

fn random_amount(rng: &mut impl Rng, currency: &str) -> String {
    match currency {
        "BTC" => {
            format!("{}.{:08}", rng.gen_range(1u64..=50), rng.gen_range(0u64..100_000_000))
        }
        _ => {
            format!("{}.{:012}", rng.gen_range(1u64..=100), rng.gen_range(0u64..1_000_000_000_000))
        }
    }
}

fn random_escrow_address(rng: &mut impl Rng, currency: &str) -> String {
    match currency {
        "BTC" => {
            let chars: String = (0..31).map(|_| {
                let idx = rng.gen_range(0..32);
                "qrstuvwxyz234567acdefghjkmnpq".as_bytes()[idx] as char
            }).collect();
            format!("bc1q{}", chars)
        }
        _ => {
            // XMR standard: 4 + 94 hex chars = 95 chars total
            format!("4{}", random_hex(rng, 47))
        }
    }
}

/// Choose an order state with realistic lifecycle distribution,
/// then derive all timestamps from a single random seed per invocation.
fn generate_state_with_timestamps(
    rng: &mut impl Rng, created_at: i64, _now: i64,
) -> (String, Option<i64>, Option<i64>, Option<i64>, Option<i64>,
      Option<i64>, Option<i64>, Option<i64>) {
    let roll: f64 = rng.gen();
    let mut cur = created_at;

    fn step(rng: &mut impl Rng, t: i64) -> i64 {
        t + rng.gen_range(7200..172_800)  // 2h – 48h per transition
    }

    // fund happens for every non-pending state
    let do_fund = roll >= 0.15;
    let funded = if do_fund { let t = step(rng, cur); cur = t; Some(t) } else { None };

    let do_ship = roll >= 0.35;
    let shipped = if do_ship { let t = step(rng, cur); cur = t; Some(t) } else { None };

    let do_confirm = (0.50..0.60).contains(&roll) || roll >= 0.85;  // confirmed or released
    let confirmed = if do_confirm { let t = step(rng, cur); cur = t; Some(t) } else { None };

    let do_dispute = (0.60..0.70).contains(&roll) || (0.70..0.95).contains(&roll);
    let disputed = if do_dispute { let t = step(rng, cur); cur = t; Some(t) } else { None };

    let do_release = (0.70..0.85).contains(&roll);
    let released = if do_release { let t = step(rng, cur); cur = t; Some(t) } else { None };

    let do_refund = (0.85..0.95).contains(&roll);
    let refunded = if do_refund { let t = step(rng, cur); cur = t; Some(t) } else { None };

    let state = if roll < 0.15 { "pending" }
        else if roll < 0.35 { "funded" }
        else if roll < 0.50 { "shipped" }
        else if roll < 0.60 { "confirmed" }
        else if roll < 0.70 { "disputed" }
        else if roll < 0.85 { "released" }
        else if roll < 0.95 { "refunded" }
        else { "cancelled" };

    let cancelled = if roll >= 0.95 { Some(cur) } else { None };

    (state.to_string(), funded, shipped, confirmed, disputed, released, refunded, cancelled)
}

fn generate_chat_messages(
    rng: &mut impl Rng, buyer_hash: &[u8], seller_hash: &[u8],
    created_at: i64, last_at: i64,
) -> Vec<ChatMessageData> {
    let count = rng.gen_range(1..=8);
    let mut msgs = Vec::with_capacity(count);
    let span = last_at - created_at;
    for i in 0..count {
        let offset = if count == 1 { span / 2 } else { span * i as i64 / (count as i64 - 1) };
        let t = created_at + offset;
        msgs.push(ChatMessageData {
            id: Uuid::new_v4().as_bytes().to_vec(),
            sender_pubkey_hash: if i % 2 == 0 { buyer_hash.to_vec() } else { seller_hash.to_vec() },
            encrypted_body: (0..rng.gen_range(48..512)).map(|_| rng.gen()).collect(),
            created_at: t,
            expires_at: t + 7_776_000, // 90 days
        });
    }
    msgs
}

fn generate_dispute(
    rng: &mut impl Rng, buyer_hash: &[u8], _seller_hash: &[u8],
    disputed_at: Option<i64>, resolved: bool, resolved_at: Option<i64>,
) -> Option<(DisputeData, String)> {
    let did = Uuid::new_v4().to_string();
    let count = rng.gen_range(1..=3);
    let evidence: Vec<DisputeEvidenceEntry> = (0..count).map(|_| {
        DisputeEvidenceEntry {
            id: Uuid::new_v4().to_string(),
            submitted_by: if rng.gen_bool(0.5) { hex::encode(buyer_hash) } else { hex::encode(random_hash(rng)) },
            encrypted_content: (0..rng.gen_range(64..1024)).map(|_| rng.gen()).collect(),
            content_type: if rng.gen_bool(0.7) { "text".into() } else { "image".into() },
            created_at: disputed_at.unwrap_or(0) + rng.gen_range(-3600..3600),
        }
    }).collect();

    let reason = ["item not received", "wrong item", "quality issue", "counterfeit", "other"]
        [rng.gen_range(0..5)].to_string();

    let (resolution, resolved_by, res_at) = if resolved {
        (Some("seller".into()), Some("admin".into()), resolved_at)
    } else {
        (None, None, None)
    };

    Some((DisputeData {
        id: did.clone(),
        opened_by: "buyer".into(),
        reason,
        resolution,
        resolved_by,
        resolved_at: res_at,
        created_at: disputed_at.unwrap_or(0),
        evidence,
    }, did))
}

pub async fn run_dummy_worker(state: &Arc<AppState>) -> anyhow::Result<()> {
    let mut rng = OsRng;

    let prob: f64 = rng.gen();
    if prob > 0.30 {
        let ms = rng.gen_range(50..200);
        tokio::time::sleep(tokio::time::Duration::from_millis(ms)).await;
        return Ok(());
    }

    let now = floor_timestamp_6h(time::OffsetDateTime::now_utc().unix_timestamp());
    let order_id = Uuid::new_v4().as_bytes().to_vec();
    let listing_id = Uuid::new_v4().as_bytes().to_vec();
    let currency = if rng.gen_bool(0.7) { "XMR".to_string() } else { "BTC".to_string() };

    let age_hours: i64 = rng.gen_range(12..(48 * 6));
    let created_at = floor_timestamp_6h(now - (age_hours * 3600));

    let (order_state, funded_at, shipped_at, confirmed_at, disputed_at, released_at, refunded_at, _cancelled_at) =
        generate_state_with_timestamps(&mut rng, created_at, now);

    let buyer_hash = random_hash(&mut rng);
    let seller_hash = random_hash(&mut rng);
    let last_ts = released_at.or(refunded_at).or(disputed_at).or(confirmed_at)
        .or(shipped_at).or(funded_at).unwrap_or(created_at);
    let chat_messages = generate_chat_messages(&mut rng, &buyer_hash, &seller_hash, created_at, last_ts);

    let is_resolved = order_state == "released" || order_state == "refunded";
    let res_at = released_at.or(refunded_at);
    let (dispute, dispute_id) = if disputed_at.is_some() || (is_resolved && rng.gen_bool(0.3)) {
        generate_dispute(&mut rng, &buyer_hash, &seller_hash,
            disputed_at.or(Some(last_ts)), is_resolved, res_at)
            .map(|(d, id)| (Some(d), Some(id)))
            .unwrap_or((None, None))
    } else {
        (None, None)
    };

    let has_btc = currency == "BTC";
    let fee_percent = has_btc.then(|| rng.gen_range(1..=5));
    let owner_pubkey = fee_percent.map(|_| random_hex(&mut rng, 33));
    let fee_address = fee_percent.map(|_| random_escrow_address(&mut rng, "BTC"));

    let addr = random_escrow_address(&mut rng, &currency);
    let amount = random_amount(&mut rng, &currency);

    let data = OrderData {
        listing_id,
        buyer_pubkey_hash: buyer_hash,
        seller_pubkey_hash: seller_hash,
        buyer_pubkey: Some(random_ed25519_pubkey(&mut rng)),
        seller_pubkey: Some(random_ed25519_pubkey(&mut rng)),
        state: order_state,
        currency,
        escrow_address: Some(addr),
        escrow_amount: Some(amount),
        time_lock_seconds: rng.gen_range(86400..(14 * 86400)),
        created_at,
        funded_at,
        shipped_at,
        confirmed_at,
        released_at,
        refunded_at,
        expires_at: Some(created_at + rng.gen_range(86400..(21 * 86400))),
        disputed_at,
        dispute_id,
        owner_pubkey,
        fee_percent,
        fee_address,
        dispute,
        chat_messages,
        settlement_txid: released_at.map(|_| random_hex(&mut rng, 32)),
    };

    let json = serde_json::to_vec(&data)?;
    // Encrypt with worker_key so dummy blobs match real worker output.
    let Some(worker_key) = state.worker_key.as_ref() else {
        return Ok(());
    };
    let encrypted = oblivious::encrypt_order_blob(&json, worker_key, &order_id);

    let Some(encrypted) = encrypted else {
        return Ok(());
    };

    sqlx::query(
        "INSERT INTO orders (id, encrypted_order_blob, day_bucket, expiry_bucket) VALUES (?1, ?2, ?3, ?4)",
    )
    .bind(&order_id)
    .bind(&encrypted)
    .bind(now)
    .bind(data.expires_at)
    .execute(&state.pool)
    .await?;

    let ms = rng.gen_range(50..200);
    tokio::time::sleep(tokio::time::Duration::from_millis(ms)).await;

    Ok(())
}
