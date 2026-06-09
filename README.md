# tor-marketplace

Privacy-oriented marketplace over a Tor hidden service. The API stores opaque
encrypted blobs and never decrypts order content. Payment polling, time locks,
and related background work run in a separate worker binary. The browser client
encrypts locally via WASM and authenticates with per-request Ed25519 signatures.

## Components

| Part | Path | Role |
|------|------|------|
| API server | `tor-marketplace` | Listings, orders, chat, disputes; blind storage |
| Worker | `tor-marketplace-worker` | Decrypts blobs for payment checks; jittered scan loop |
| Frontend | `frontend/` | Static SPA served by the API |
| Client crypto | `wasm/` | Order/listing encryption, auth helpers (wasm-pack) |

Payments: Monero (subaddress per order) and Bitcoin (stealth-style off-chain PSBT).

## Requirements

- Rust stable (see `rust-toolchain.toml`)
- [wasm-pack](https://rustwasm.github.io/wasm-pack/) for the client build
- Tor, for production (`tor.enabled = true`)
- `monero-wallet-rpc` and Bitcoin Core RPC when exercising payments

## Development

Copy the example config and start both processes:

```sh
cp config.toml.example config.toml

# Unix
./scripts/dev.sh

# Windows
.\scripts\dev.ps1
```

The dev scripts build WASM if missing, start the worker, wait for
`data/dev_worker_payment_pubkey.hex`, then start the API on `127.0.0.1:9080`.
They set ephemeral keys (`EPHEMERAL_KEK`, `EPHEMERAL_WORKER_KEY`) suitable
for local use only.

Open the frontend through the API (static files under `/`). Use Tor Browser
when testing against a hidden service.

## Build

```sh
cargo build --release --locked
cargo build --release --features worker --bin tor-marketplace-worker

wasm-pack build wasm --target web --out-dir wasm/pkg
mkdir -p frontend/wasm && cp wasm/pkg/* frontend/wasm/
```

Production startup needs at least `SERVER_SECRET` and `KEK_HEX` in the
environment, `tor.enabled = true`, and `worker_payment_pubkey_hex` in config
(or the dev pubkey sync file written by the worker).

## Configuration

See `config.toml.example`. Secrets belong in the environment, not on disk:

- `SERVER_SECRET` — HMAC identity derivation (32+ bytes)
- `KEK_HEX` — 32-byte hex key-encryption key for persisted seeds

Database defaults to SQLite at `data/marketplace.db`. PostgreSQL hooks exist
in code but are not wired for production yet.

## Tests

```sh
cargo test
./scripts/ci.sh    # fmt, clippy, build, wasm, test, audit
```

Integration tests cover auth, order/listing flows, crypto primitives, and
several anonymity properties (timing padding, replay rejection, server blindness).

## Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md) — process split, directory layout, security layers
- [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) — adversary assumptions
- [docs/CRYPTO_SPEC.md](docs/CRYPTO_SPEC.md) — keys and algorithms
- [docs/OPERATIONS.md](docs/OPERATIONS.md) — deployment and operations

## License

MIT. See [LICENSE](LICENSE).
