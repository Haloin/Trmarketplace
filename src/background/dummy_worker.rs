use std::sync::Arc;
use rand::Rng;
use rand::rngs::OsRng;
use uuid::Uuid;

use crate::db::models::OrderData;
use crate::crypto::oblivious;
use crate::crypto::zk::floor_timestamp_6h;
use crate::gateway::state::AppState;

fn random_hex(rng: &mut impl Rng, len: usize) -> String {
    let bytes: Vec<u8> = (0..len).map(|_| rng.gen::<u8>()).collect();
    hex::encode(&bytes)
}

fn random_amount(rng: &mut impl Rng, currency: &str) -> String {
    match currency {
        "BTC" => {
            let whole = rng.gen_range(1u64..=50);
            let frac = rng.gen_range(0u64..100_000_000);
            format!("{}.{:08}", whole, frac)
        }
        _ => {
            let whole = rng.gen_range(1u64..=100);
            let frac = rng.gen_range(0u64..1_000_000_000_000);
            format!("{}.{:012}", whole, frac)
        }
    }
}

fn random_escrow_address(rng: &mut impl Rng, currency: &str) -> String {
    match currency {
        "BTC" => format!("bc1{}", random_hex(rng, 32)),
        _ => format!("4{}", random_hex(rng, 60)),
    }
}

fn terminal_state(rng: &mut impl Rng) -> String {
    let n: f64 = rng.gen();
    if n < 0.40 {
        "cancelled"
    } else if n < 0.70 {
        "released"
    } else {
        "refunded"
    }.to_string()
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
    let currency = if rng.gen_bool(0.7) { "XMR" } else { "BTC" };
    let order_state = terminal_state(&mut rng);

    // Generate timestamps in the past so the order looks like it has aged naturally
    let age_hours: i64 = rng.gen_range(12..(48 * 6));
    let created_at = now - (age_hours * 3600);
    let created_at_floored = floor_timestamp_6h(created_at);

    let data = OrderData {
        listing_id,
        buyer_pubkey_hash: hex::decode(&random_hex(&mut rng, 32)).unwrap_or_default(),
        seller_pubkey_hash: hex::decode(&random_hex(&mut rng, 32)).unwrap_or_default(),
        buyer_pubkey: Some(random_hex(&mut rng, 64)),
        seller_pubkey: Some(random_hex(&mut rng, 64)),
        state: order_state,
        currency: currency.to_string(),
        escrow_address: Some(random_escrow_address(&mut rng, currency)),
        escrow_amount: Some(random_amount(&mut rng, currency)),
        time_lock_seconds: rng.gen_range(86400..(14 * 86400)),
        created_at: created_at_floored,
        funded_at: None,
        shipped_at: None,
        confirmed_at: None,
        released_at: None,
        refunded_at: None,
        expires_at: Some(created_at_floored + rng.gen_range(86400..(21 * 86400))),
        disputed_at: None,
        dispute_id: None,
        owner_pubkey: if currency == "BTC" { Some(random_hex(&mut rng, 66)) } else { None },
        fee_percent: if currency == "BTC" { Some(rng.gen_range(1..=5)) } else { None },
        fee_address: if currency == "BTC" { Some(random_hex(&mut rng, 34)) } else { None },
        dispute: None,
        chat_messages: vec![],
    };

    let json = serde_json::to_vec(&data)?;
    let encrypted = oblivious::encrypt_order_blob(&json, &state.master_seed[..], &order_id);

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
