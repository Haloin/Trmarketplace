//! Worker process — background jobs in a separate binary from the API.

use std::sync::Arc;
use rand::Rng;
use tokio::sync::watch;
use crate::background::{payment_poller, time_lock, listing_expiry, notification_scanner, dummy_worker};
use crate::gateway::state::AppState;

fn jittered_interval(base_secs: u64) -> tokio::time::Duration {
    let jitter = rand::thread_rng().gen_range(0.5f64..1.5);
    let actual = (base_secs as f64 * jitter) as u64;
    tokio::time::Duration::from_secs(actual)
}

/// Verify that the AppState is configured for a worker process.
/// The worker MUST have `worker_key` set; the API process must not.
/// In dev/test, the worker can be run with `EPHEMERAL_WORKER_KEY=1` to
/// generate a fresh random key (data won't survive restart, but tests pass).
pub fn assert_worker_state(state: &AppState) -> anyhow::Result<()> {
    if state.worker_key.is_none() {
        if std::env::var("EPHEMERAL_WORKER_KEY").as_deref() == Ok("1") {
            tracing::warn!("EPHEMERAL_WORKER_KEY=1: generating fresh worker key (data will not survive restart)");
            return Err(anyhow::anyhow!("EPHEMERAL_WORKER_KEY=1 requires mutable state; this code path is unreachable"));
        }
        return Err(anyhow::anyhow!("Worker key not configured. Set worker_key_hex in config, or KEK_HEX env var to decrypt an existing config."));
    }
    Ok(())
}

pub async fn run_workers(state: AppState, shutdown_rx: watch::Receiver<bool>) {
    if let Err(e) = assert_worker_state(&state) {
        tracing::error!("Worker startup aborted: {e}");
        return;
    }
    let state = Arc::new(state);

    // Payment poller - randomized interval [30s, 90s]
    let s = state.clone();
    let mut rx = shutdown_rx.clone();
    tokio::spawn(async move {
        loop {
            let should_stop = tokio::select! {
                biased;
                _ = rx.changed() => *rx.borrow_and_update(),
                _ = tokio::time::sleep(jittered_interval(60)) => false,
            };
            if should_stop { break; }

            let _ = payment_poller::check_pending_payments(&s).await;
        }
    });

    // Time-lock checker - randomized interval [60s, 180s]
    let s = state.clone();
    let mut rx = shutdown_rx.clone();
    tokio::spawn(async move {
        loop {
            let should_stop = tokio::select! {
                biased;
                _ = rx.changed() => *rx.borrow_and_update(),
                _ = tokio::time::sleep(jittered_interval(120)) => false,
            };
            if should_stop { break; }

            let _ = time_lock::check_time_locks(&s).await;
        }
    });

    // Listing expiry checker - randomized interval [120s, 360s]
    let s = state.clone();
    let mut rx = shutdown_rx.clone();
    tokio::spawn(async move {
        loop {
            let should_stop = tokio::select! {
                biased;
                _ = rx.changed() => *rx.borrow_and_update(),
                _ = tokio::time::sleep(jittered_interval(240)) => false,
            };
            if should_stop { break; }

            let _ = listing_expiry::check_listing_expiry(&s).await;
        }
    });

    // BTC notification scanner - randomized interval [30s, 90s]
    let s = state.clone();
    let mut rx = shutdown_rx.clone();
    tokio::spawn(async move {
        loop {
            let should_stop = tokio::select! {
                biased;
                _ = rx.changed() => *rx.borrow_and_update(),
                _ = tokio::time::sleep(jittered_interval(60)) => false,
            };
            if should_stop { break; }
            let _ = notification_scanner::scan_notifications(&s).await;
        }
    });

    // Dummy traffic generator
    let mut rx = shutdown_rx;
    tokio::spawn(async move {
        loop {
            let should_stop = tokio::select! {
                biased;
                _ = rx.changed() => *rx.borrow_and_update(),
                _ = tokio::time::sleep(jittered_interval(300)) => false,
            };
            if should_stop { break; }
            let _ = dummy_worker::run_dummy_worker(&state).await;
        }
    });
}
