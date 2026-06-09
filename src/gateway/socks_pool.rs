use anyhow::Result;
use reqwest::{Client, Proxy};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;


/// A pool of SOCKS5-proxied HTTP clients, each bound to a distinct Tor circuit.
///
/// Circuit isolation is achieved via `IsolateSOCKSAuth`:
/// each pool slot uses a unique SOCKS5 username (`tor-marketplace-{N}`),
/// which tells Tor to route that slot's traffic through a separate circuit.
///
/// When Tor is disabled (`config.tor.enabled == false`), all slots
/// return a direct (non-proxied) client — useful for development.
struct PoolSlot {
    client: Client,
    healthy: bool,
}

pub struct Socks5Pool {
    slots: Vec<RwLock<PoolSlot>>,
    socks5_addr: String,
    enabled: bool,
}

impl Socks5Pool {
    /// Build the pool. When `enabled` is false, all clients connect directly.
    pub fn new(socks5_addr: &str, pool_size: usize, enabled: bool) -> Result<Arc<Self>> {
        let mut slots = Vec::with_capacity(pool_size);
        for i in 0..pool_size {
            let mut builder = Client::builder()
                .timeout(Duration::from_secs(30))
                .pool_max_idle_per_host(2);

            if enabled {
                let proxy_url = if i == 0 {
                    // Slot 0: no auth, default circuit
                    format!("socks5://{}", socks5_addr)
                } else {
                    // Slots 1+: unique auth username per slot → isolated circuit
                    format!("socks5://tor-marketplace-{}:isolated@{}", i, socks5_addr)
                };
                let proxy = Proxy::all(&proxy_url)
                    .map_err(|e| anyhow::anyhow!("Invalid SOCKS5 proxy '{}': {}", proxy_url, e))?;
                builder = builder.proxy(proxy);
            }

            let client = builder.build()?;
            slots.push(RwLock::new(PoolSlot { client, healthy: true }));
        }

        Ok(Arc::new(Self {
            slots,
            socks5_addr: socks5_addr.to_string(),
            enabled,
        }))
    }

    /// Return the pool size.
    pub fn size(&self) -> usize {
        self.slots.len()
    }

    /// Get a client for the given key (pubkey hash, order id, etc.).
    /// The key is hashed to select a deterministic slot.
    pub async fn get_client(&self, key: &[u8]) -> Client {
        let idx = self.slot_index(key);
        let slot = self.slots[idx].read().await;
        slot.client.clone()
    }

    /// Get client by slot index directly.
    pub async fn get_client_by_index(&self, idx: usize) -> Option<Client> {
        let slot = self.slots.get(idx)?.read().await;
        Some(slot.client.clone())
    }

    /// Number of currently healthy circuits.
    pub async fn healthy_count(&self) -> usize {
        let mut count = 0;
        for slot in &self.slots {
            if slot.read().await.healthy {
                count += 1;
            }
        }
        count
    }

    /// Mark a slot as unhealthy and rebuild its client (forces new Tor circuit).
    pub async fn rotate_slot(&self, idx: usize) -> Result<()> {
        if idx >= self.slots.len() {
            return Err(anyhow::anyhow!("Slot index {} out of range", idx));
        }

        let mut builder = Client::builder()
            .timeout(Duration::from_secs(30))
            .pool_max_idle_per_host(2);

        if self.enabled {
            let proxy_url = if idx == 0 {
                format!("socks5://{}", self.socks5_addr)
            } else {
                format!("socks5://tor-marketplace-{}:isolated@{}", idx, self.socks5_addr)
            };
            let proxy = Proxy::all(&proxy_url)
                .map_err(|e| anyhow::anyhow!("Invalid SOCKS5 proxy: {}", e))?;
            builder = builder.proxy(proxy);
        }

        let client = builder.build()?;
        let mut slot = self.slots[idx].write().await;
        slot.client = client;
        slot.healthy = true;
        Ok(())
    }

    /// Background health check — pings each circuit through its slot client.
    /// Unhealthy circuits are auto-rotated.
    pub async fn health_check_loop(self: Arc<Self>, interval_secs: u64) {
        let mut tick = tokio::time::interval(Duration::from_secs(interval_secs));
        loop {
            tick.tick().await;
            for i in 0..self.slots.len() {
                let client = self.slots[i].read().await.client.clone();
                let ok = tokio::time::timeout(
                    Duration::from_secs(10),
                    client.head("http://check.torproject.org/").send(),
                )
                .await
                .is_ok_and(|r| r.is_ok());

                let mut slot = self.slots[i].write().await;
                if ok {
                    slot.healthy = true;
                } else {
                    slot.healthy = false;
                    tracing::warn!("Tor circuit slot {} unhealthy — will rotate", i);
                }
            }

            // Rotate unhealthy slots
            for i in 0..self.slots.len() {
                if !self.slots[i].read().await.healthy {
                    if let Err(e) = self.rotate_slot(i).await {
                        tracing::error!("Failed to rotate slot {}: {}", i, e);
                    } else {
                        tracing::info!("Rotated Tor circuit slot {}", i);
                    }
                }
            }
        }
    }

    /// Map a key to a pool slot index using blake3 hash.
    fn slot_index(&self, key: &[u8]) -> usize {
        if self.slots.is_empty() {
            return 0;
        }
        let hash = blake3::hash(key);
        let low = u64::from_le_bytes(hash.as_bytes()[..8].try_into().unwrap());
        (low % self.slots.len() as u64) as usize
    }
}
