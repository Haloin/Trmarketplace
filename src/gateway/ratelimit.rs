use std::sync::Arc;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct RateLimiter {
    buckets: Arc<Mutex<HashMap<String, RateEntry>>>,
    max_requests: u32,
    window_duration: Duration,
}

#[derive(Clone)]
struct RateEntry {
    count: u32,
    window_start: Instant,
}

impl RateLimiter {
    pub fn new(max_requests: u32, window_seconds: u64) -> Self {
        Self {
            buckets: Arc::new(Mutex::new(HashMap::new())),
            max_requests,
            window_duration: Duration::from_secs(window_seconds),
        }
    }

    pub async fn check(&self, key: &str) -> bool {
        let mut buckets = self.buckets.lock().await;
        let now = Instant::now();

        if let Some(entry) = buckets.get_mut(key) {
            if now - entry.window_start > self.window_duration {
                *entry = RateEntry {
                    count: 1,
                    window_start: now,
                };
                return true;
            }

            if entry.count >= self.max_requests {
                return false;
            }

            entry.count += 1;
            true
        } else {
            buckets.insert(key.to_string(), RateEntry {
                count: 1,
                window_start: now,
            });
            true
        }
    }

    pub async fn is_allowed(&self, key: &str) -> bool {
        self.check(key).await
    }
}
