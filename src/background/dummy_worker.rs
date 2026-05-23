use std::sync::Arc;
use rand::{Rng, RngCore};
use uuid::Uuid;

use crate::crypto::oblivious;
use crate::crypto::zk::floor_timestamp_6h;
use crate::gateway::state::AppState;

pub async fn run_dummy_worker(state: &Arc<AppState>) -> anyhow::Result<()> {
    let prob: f64 = {
        let mut rng = rand::thread_rng();
        rng.gen()
    };

    if prob > 0.30 {
        let ms = {
            let mut rng = rand::thread_rng();
            rng.gen_range(50..200)
        };
        tokio::time::sleep(tokio::time::Duration::from_millis(ms)).await;
        return Ok(());
    }

    let (order_id, encrypted, day_bucket) = {
        let mut rng = rand::thread_rng();

        let order_id = Uuid::new_v4().as_bytes().to_vec();

        let plaintext_size = rng.gen_range(100..400);
        let mut plaintext = vec![0u8; plaintext_size];
        rng.fill_bytes(&mut plaintext);

        let encrypted = oblivious::encrypt_order_blob(
            &plaintext,
            &state.master_seed,
            &order_id,
        );

        let day_bucket = floor_timestamp_6h(
            time::OffsetDateTime::now_utc().unix_timestamp(),
        );

        (order_id, encrypted, day_bucket)
    };

    let Some(encrypted) = encrypted else {
        return Ok(());
    };

    sqlx::query(
        "INSERT INTO orders (id, encrypted_order_blob, day_bucket, expiry_bucket) VALUES (?1, ?2, ?3, NULL)",
    )
    .bind(&order_id)
    .bind(&encrypted)
    .bind(day_bucket)
    .execute(&state.pool)
    .await?;

    let ms = {
        let mut rng = rand::thread_rng();
        rng.gen_range(50..200)
    };
    tokio::time::sleep(tokio::time::Duration::from_millis(ms)).await;

    Ok(())
}
