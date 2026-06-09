use std::sync::Arc;
use crate::db::models::{Listing, ListingData};
use crate::crypto::oblivious;
use crate::crypto::zk::floor_timestamp_6h;
use crate::gateway::state::AppState;

pub async fn check_listing_expiry(state: &Arc<AppState>) -> anyhow::Result<()> {
    // The listing-expiry worker needs the worker key to decrypt listing
    // blobs. The API process does not have the worker key (by design);
    // this worker only runs in the worker process.
    let Some(worker_key) = state.worker_key.as_ref() else {
        return Ok(());
    };

    let now = floor_timestamp_6h(time::OffsetDateTime::now_utc().unix_timestamp());

    let listings = sqlx::query_as::<_, Listing>(
        "SELECT * FROM listings WHERE status = 'active'"
    )
    .fetch_all(&state.pool)
    .await?;

    for listing in &listings {
        let Some(raw) = oblivious::decrypt_listing_blob(
            &listing.encrypted_listing_blob,
            worker_key,
            &listing.id,
        ) else { continue };
        let Ok(mut data) = serde_json::from_slice::<ListingData>(&raw) else { continue };

        let expired = data.expires_at.is_some_and(|exp| now >= exp);
        if !expired {
            continue;
        }

        data.status = "expired".to_string();
        data.updated_at = now;

        let Some(blob) = (|| {
            let json = serde_json::to_vec(&data).ok()?;
            oblivious::encrypt_listing_blob(&json, worker_key, &listing.id)
        })() else { continue };

        let version = listing.version;
        let result = sqlx::query(
            "UPDATE listings SET encrypted_listing_blob = ?1, status = ?2, version = version + 1 WHERE id = ?3 AND version = ?4"
        )
        .bind(&blob)
        .bind("expired")
        .bind(&listing.id)
        .bind(version)
        .execute(&state.pool)
        .await?;

        if result.rows_affected() == 0 {
            continue;
        }

        tracing::info!(listing_id = %hex::encode(&listing.id), "Listing expired");
    }

    Ok(())
}
