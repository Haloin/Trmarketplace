pub mod payment_poller;
pub mod time_lock;
pub mod dummy_worker;

use std::sync::Arc;
use rand::Rng;
use tokio::sync::watch;
use crate::gateway::state::AppState;

fn jittered_interval(base_secs: u64) -> tokio::time::Duration {
    let jitter = rand::thread_rng().gen_range(0.5f64..1.5);
    let actual = (base_secs as f64 * jitter) as u64;
    tokio::time::Duration::from_secs(actual)
}

pub async fn run_workers(state: AppState, shutdown_rx: watch::Receiver<bool>) {
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

    // Dummy traffic generator - placeholder (30% dummy operations TBD)
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
