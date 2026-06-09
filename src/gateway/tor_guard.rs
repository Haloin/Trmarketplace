use axum::{
    extract::Request,
    middleware::Next,
    response::Response,
};
use rand::Rng;

/// Circuit slot assigned to this request (for pool-based Tor circuit isolation).
/// Each request gets a random slot to enforce per-request circuit rotation.
#[derive(Clone, Copy, Debug)]
pub struct CircuitSlot(pub usize);

/// Tor guard middleware.
///
/// In production mode with Tor enabled, all outbound RPC traffic from this
/// server to Bitcoin / Monero daemons is routed through the SOCKS5 pool.
///
/// The middleware assigns a RANDOM circuit slot per request to enforce
/// per-request circuit rotation. This prevents circuit correlation and
/// provides stronger anonymity than per-user circuit isolation.
///
/// Default pool size is 8 circuits (configurable in config.toml).
pub async fn tor_guard_middleware(
    mut request: Request,
    next: Next,
) -> Response {
    // Assign random circuit slot per request (per-request circuit rotation)
    // Pool size is typically 8 (default from config.tor.socks5_pool_size)
    let slot = rand::thread_rng().gen_range(0..8);

    request.extensions_mut().insert(CircuitSlot(slot));
    next.run(request).await
}
