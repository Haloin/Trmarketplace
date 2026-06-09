# torMarketplace — Architecture

Privacy-first marketplace: Tor hidden service, blind API, separate worker process,
WASM client crypto, BTC stealth and XMR payments.

## Status

| Item | State |
|------|--------|
| Build | `cargo build` |
| Tests | 237 integration and unit tests |
| API binary | `tor-marketplace` — no `worker_key`, no blob decryption |
| Worker binary | `tor-marketplace-worker` — payment polling, time locks, dummy traffic |
| Client | WASM (`wasm/`) + static frontend (`frontend/`) |
| Local dev | `scripts/dev.ps1` / `scripts/dev.sh` |

## Process model

```
Browser (WASM + SPA)
    |  opaque blobs, HMAC auth, padded responses
    v
API (tor-marketplace)  --SQLite-->  orders / listings tables
    ^
    |  worker_key = None

Worker (tor-marketplace-worker)
    |  decrypts blobs for payment polling
    v
Bitcoin Core / monero-wallet-rpc
```

## Directory layout

```
src/
  main.rs, bin/worker.rs     API and worker entrypoints
  crypto/                    Primitives (oblivious, hmac_auth, blind_sig, stealth, ...)
  gateway/                   Middleware (stateless_auth, padding, tor_guard, ...)
  services/                  HTTP handlers
  background/                Worker job implementations
  worker/                    Worker orchestration (feature-gated)
  db/                        Migrations + models
wasm/                        Client-side crypto (wasm-pack -> frontend/wasm/)
frontend/                    Static SPA
tests/                       Integration and security tests
docs/                        THREAT_MODEL, CRYPTO_SPEC, OPERATIONS
scripts/                     dev, ci, backup, harden
```

## Security layers

| Layer | Mechanism |
|-------|-----------|
| Identity | Domain-scoped HMAC identities; client-side ephemeral keys |
| Auth | Stateless HMAC + Ed25519 per request; no sessions/cookies/Redis |
| Network | Tor hidden service; per-request SOCKS5 circuit slot |
| Transport | 4096-byte response padding; unified error shape |
| Storage | Blind API — opaque blobs only; minimal schema columns |
| Workers | Separate binary; scan-all orders; jittered intervals + dummy traffic |
| Payments | BTC stealth/CoinSwap; XMR view-only, padded RPC, fork detection |
| Temporal | 6-hour timestamp buckets; randomized worker intervals |
| Client crypto | WASM: X25519 ECDH + ChaCha20-Poly1305; transition signatures (CBOR + Ed25519) |
| Admin | Chaum RSA blind signatures; unlinkable per-action tokens |

## Database (orders)

Core columns:

- `id`, `encrypted_order_blob`, `day_bucket`, `expiry_bucket`
- Helper: `version`, `has_dispute`, `client_encrypted_blob`, `dispute_client_blob`, `chat_encrypted_blob`

No plaintext PII columns. Listings use `encrypted_listing_blob` + opaque `search_token`.

## Build

```sh
cargo build --release --locked
cargo build --release --features worker --bin tor-marketplace-worker
wasm-pack build wasm --target web --out-dir wasm/pkg
cp wasm/pkg/* frontend/wasm/
```

Production requires `KEK_HEX`, `SERVER_SECRET`, `tor.enabled = true`, and
`worker_payment_pubkey_hex` (or the dev sync file from the worker).

## Pre-launch checklist

Anonymity: no sessions/cookies/Redis; padded responses; floored timestamps; worker jitter and dummy ops; no IP logging in app.

Crypto: KEK from env only; ChaCha20-Poly1305; constant-time compares; key zeroization; transition sigs on order updates.

Workers: scan-all pattern; TOCTOU on version updates; API cannot decrypt.

Payments: XMR subaddress + view-only; BTC stealth off-chain PSBT; min 546 sats.

Ops gaps: PostgreSQL not implemented; docker-compose needs worker + WASM; external audit before real funds.

## Related docs

- [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)
- [docs/CRYPTO_SPEC.md](docs/CRYPTO_SPEC.md)
- [docs/OPERATIONS.md](docs/OPERATIONS.md)
