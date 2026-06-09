# torMarketplace — Operations Guide

Build, deploy, and run a production instance. See [ARCHITECTURE.md](../ARCHITECTURE.md).

## Build

### Toolchain
- Rust edition 2021
- Pinned in `rust-toolchain.toml` (read this file to see the exact toolchain)
- All dependencies pinned in `Cargo.lock` — always use `cargo build --locked`

### Standard build
```sh
cargo build --release --locked
```
Produces a release binary at `target/release/tor-marketplace`.

### Worker-role build
```sh
cargo build --release --locked --features worker --bin tor-marketplace-worker
```

### WASM client build
```sh
wasm-pack build wasm --target web --out-dir wasm/pkg
cp wasm/pkg/* frontend/wasm/
```
Or run `scripts/ci.sh`, which builds WASM and copies it to `frontend/wasm/`.

### Local development (API + worker)
```sh
./scripts/dev.sh          # Linux/macOS
./scripts/dev.ps1         # Windows PowerShell
```

### Reproducible builds
Not currently configured.

---

## 2. Configuration

### Config file
`config.toml` is loaded by `Config::load()` in `src/config.rs:212`. The default
location is `./config.toml`; override with `CONFIG_PATH=/path/to/config.toml`.

A reference config is at `config.toml.example`. **Do not commit your real
`config.toml`** — it contains your `server_secret` and your encrypted
`master_seed_hex`/`worker_key_hex`.

### Environment variables (override config file)
See `docs/CRYPTO_SPEC.md` §5 for the full list. Critical ones:

| Variable | Required in production |
|---|---|
| `KEK_HEX` | **Yes**. 64 hex chars = 32 bytes. |
| `SERVER_SECRET` | **Yes**. ≥ 32 chars. |
| `MONERO_RPC_URL` | Yes (for XMR) |
| `BITCOIN_RPC_URL` | Yes (for BTC) |
| `LISTEN_ADDR` | Recommended: `127.0.0.1:9080` when Tor handles external access |
| `RUST_LOG` | No (default: `info`) |

### Generation of secrets

**KEK** (32 random bytes, hex-encoded):
```sh
openssl rand -hex 32
```

**server_secret** (≥ 32 random chars):
```sh
openssl rand -base64 48
```

**master_seed** and **worker_key** are generated automatically by the server on
first startup. They are encrypted with the KEK and stored in `config.toml`. **Do
not delete the config file after first startup** unless you have a backup of
the encrypted seeds — losing them means losing all order data forever.

---

## 3. Run

### Development (no Tor, ephemeral KEK)
```sh
EPHEMERAL_KEK=1 \
SERVER_SECRET="$(openssl rand -base64 48)" \
cargo run
```
The server will print "Using ephemeral KEK - DO NOT USE IN PRODUCTION" at
startup. The onion address will not be generated; the server binds
`127.0.0.1:9080` directly. Do not expose this port to the internet.

### Development (with Tor)
```sh
KEK_HEX="$(openssl rand -hex 32)" \
SERVER_SECRET="$(openssl rand -base64 48)" \
cargo run
```
The server starts an embedded Tor process and prints the onion address when
ready. Tor only — the clear-net listener is not started.

### Production
```sh
export KEK_HEX="<from secret manager>"
export SERVER_SECRET="<from secret manager>"
/app/tor-marketplace
```

The server runs as user `marketplace` (created by `scripts/harden.sh`).
Logs go to stdout. Use systemd or a container orchestrator to capture them.

**Expected log lines at startup:**
- "Starting server on 127.0.0.1:9080" (or similar)
- "Worker key loaded from config" (if `worker_key_hex` is set)
- "Tor ready" or onion address

**Failure modes:**
- "SERVER_SECRET must be set" → set the env var
- "KEK not configured" → set `KEK_HEX` or `EPHEMERAL_KEK=1`
- "Kek must be exactly 32 bytes" → check hex length (64 chars)
- "Tor hostname not ready after 30s" → check that Tor can bootstrap (outbound
  network access to the Tor network is required)

---

## 4. Deploy

### Recommended: Docker Compose
The repo includes `docker-compose.yml`. Note that the current compose file
defines a `redis` service, but the application does not actually use Redis
(no `redis` crate in `Cargo.toml`). The service can be safely removed.

The compose file binds the API to `127.0.0.1:9080` on the host. Tor runs in a
sidecar container and exposes the hidden service. Clear-net access is
blocked at the firewall level.

**Before running in production:**
1. Set `SERVER_SECRET` in `.env` (loaded by compose)
2. Generate `config.toml` from `config.toml.example` and write it to the host
3. Run `scripts/harden.sh` once on the host as root
4. Run `docker-compose up -d`
5. After startup, check logs for the onion address
6. From a separate machine, access the onion address via Tor browser

### Bare-metal (no Docker)
- Install Rust toolchain
- Install `sqlite3` (for backup script)
- Install `tor` (for outbound hidden service generation; the server can
  also embed its own)
- Create a `marketplace` user (see `scripts/harden.sh`)
- Install the systemd unit (template not yet provided)
- Run `scripts/harden.sh` once
- Start the service under systemd

### Infrastructure hardening checklist
- [ ] Run as non-root user (`marketplace`)
- [ ] Read-only filesystem (except `/app/data` and `/tmp`)
- [ ] No new privileges (`security_opt: no-new-privileges:true` in compose)
- [ ] Drop all Linux capabilities except `NET_BIND_SERVICE`
- [ ] Disable swap (`swapoff -a`)
- [ ] Apply `sysctl` settings from `scripts/harden.sh`
- [ ] Apply `iptables` rules from `scripts/harden.sh`
- [ ] Filesystem encryption (LUKS / ZFS) for the data partition
- [ ] Outbound network: only Tor (port 9001, 9030) and DNS
- [ ] Rate limiting at the firewall in addition to application level

---

## 5. Backup

### Encrypted backup
```sh
BACKUP_PUBKEY="<recipient GPG key ID>" ./scripts/backup.sh
```
- Requires `sqlite3` and `gpg` installed
- Produces a `.db.gpg` file in `./backups/`
- Verifies encryption after writing
- Refuses to run without `BACKUP_PUBKEY` (refuses to create unencrypted backups)

### Recovery
```sh
gpg --decrypt backups/marketplace_YYYYMMDD_HHMMSS.db.gpg > marketplace.db
```
Restore the database to `data/marketplace.db` and restart the service.

### Backup schedule
Recommended: daily, retained for 90 days, with off-site replication via
`rsync` or `rclone` to an air-gapped backup host.

### What is and is not in the backup
- **In the backup:** the SQLite database file. This contains:
  - Encrypted order blobs (opaque ciphertext)
  - Encrypted listing blobs
  - `notification_tracker` (BTC OP_RETURN scan state)
  - `kek_version`, `last_kek_rotation`, encrypted `master_seed_hex`,
    encrypted `worker_key_hex` (if you did not override via env)
  - Schema migrations table
- **NOT in the backup:** the KEK (env var only), the `server_secret` (env var
  only), the running process memory, in-flight WebSocket connections.

If the backup host is compromised, the attacker has the encrypted seeds but
not the KEK. Without the KEK, the seeds are useless. **This is the design
property — keep your KEK separate from your backups.**

---

## 6. Key rotation

### KEK rotation
KEK rotation is currently **not automated** in the application code. The
config has `kek_rotation_days = 30` as a hint, but there is no scheduler.

Manual rotation procedure:
1. Generate a new KEK: `openssl rand -hex 32`
2. Decrypt `master_seed_hex` and `worker_key_hex` with the old KEK
3. Re-encrypt them with the new KEK
4. Update `kek_hex` (or `KEK_HEX` env var) in production
5. Restart the service
6. Bump `kek_version` in config
7. **Future improvement:** add a re-encryption pass for existing
   order blobs (the blobs are encrypted with worker_key, not KEK, so KEK
   rotation does not require re-encrypting every blob; only the seed/key
   at-rest encryption needs to be re-done)

### server_secret rotation
**Currently requires a re-derivation of all admin identities and a re-key of
all domain-scoped user identities.** This is effectively a hard cutover:
all existing user orders will appear "owned by unknown" to the new server.
For a production marketplace, this should be done in a planned maintenance
window with a coordinated client-side update.

A future `server_secret_version` field would allow
so that rotation can happen with a soft cutover (old identities work for N
days, new identities for the next N days, then old are dropped).

### master_seed rotation
**Dangerous.** All existing BTC escrow addresses were derived from the
current `master_seed`. Rotating the seed invalidates the ability to sign
release/refund PSBTs for orders created under the old seed.

For BTC, the master seed is effectively a key that lives forever. Rotation
requires either a full re-keying of all in-flight orders (impossible without
the cooperation of every buyer and seller) or a planned transition where all
old orders are settled before rotation.

**Recommendation:** do not rotate `master_seed` in production. Treat it as
effectively permanent.

### worker_key rotation
**Less dangerous** than `master_seed` rotation. The worker key encrypts the
order blob at rest. Rotating it requires re-encrypting all order blobs in
the database.

A future `worker_key_version` field on each blob would allow
gradual rotation: workers re-encrypt blobs opportunistically as they
process them, and after one full scan cycle all blobs are under the new
key.

---

## 7. Monitoring

### What to monitor

**Process health:**
- Process is running (`systemctl is-active tor-marketplace` or container
  healthcheck)
- Onion address is responding (Tor browser smoke test)
- WebSocket subscribers connecting (count)

**Application logs:**
- No "decryption failed" spikes (indicates wrong-key or corruption)
- No "order modified by concurrent writer" spikes (TOCTOU conflicts are
  rare in normal operation)
- No repeated warnings from workers
- No "rate limit exceeded" floods (DDoS or runaway client)

**Database:**
- File size growth rate (abnormal = leak)
- Query latency (p99)
- Disk space (data dir)

**Tor:**
- Tor process running
- Onion address still resolves
- Outbound SOCKS5 connections succeeding

**Cryptocurrency daemons:**
- Bitcoin Core: block height advancing
- monero-wallet-rpc: responding to JSON-RPC
- Both: no fork detected

### What NOT to monitor
- Per-request user identity (would defeat anonymity)
- Per-request order content (we shouldn't be able to see this)
- Failed auth attempts by user (would log identifying data)

### Log forwarding
Logs go to stdout in JSON-friendly format via `tracing-subscriber`. Forward to
your log aggregator (Loki, Elasticsearch, etc.) but **strip or redact any
field that could contain order IDs, pubkeys, or session nonces**.

The application does not redact logs automatically; configure redaction in your log aggregator.

---

## 8. Incident response

### Server compromise (live process memory)
1. Kill the process immediately.
2. Treat `server_secret`, KEK, `master_seed`, and `worker_key` as compromised.
3. **The onion address is now linked to the operator.** Generate a new one
   (`scripts/generate-onion.sh` regenerates).
4. Issue a security advisory to all users that the server was compromised.
5. Force all users to re-register on a new instance.
6. If any settlement transactions were in flight, the attacker may have
   broadcast them. Check Bitcoin Core and monero-wallet-rpc logs.
7. Do not reuse the old onion address.

### KEK leak
1. Generate a new KEK.
2. Re-encrypt `master_seed_hex` and `worker_key_hex` with the new KEK.
3. Update the config and restart.
4. Existing order blobs are still encrypted with `worker_key`; the attacker
   who has the KEK has the worker_key and can decrypt them.
5. Re-encrypt all order blobs with a new `worker_key` (this requires the
   application to support `worker_key_version`).
6. As an interim measure, expire all old orders (force cancellation) to
   limit the damage window.

### server_secret leak
1. Treat admin identity as compromised.
2. Rotate `server_secret` (see §6).
3. All clients must re-authenticate with the new server.
4. All existing domain-scoped identities (used to authorize order access)
   are invalid. Users will need to re-establish ownership of in-flight
   orders.

### Database exfiltration
1. Seized database = K EK-encrypted seeds + encrypted order blobs.
2. Without the KEK, the seeds and blobs are useless. **Keep the KEK off the
   database host.**
3. If KEK was also on the same host (misconfiguration), assume full
   compromise of order data. Notify users, force password/identity
   rotation on the client side.

### Tor network compromised
Out of scope for the application. Follow Tor Project guidance.

### Supply chain (compromised dep)
1. `cargo audit` will surface known CVVs.
2. Pin the previous good version in `Cargo.toml` and `cargo update -p
   <crate>@<old> --precise <version>`.
3. Rebuild and redeploy.
4. Re-audit the affected code paths.

---

## 9. Performance expectations

Not benchmarked in this audit. Rough expectations based on architecture:

- **API throughput:** 100-500 req/s on a single core, depending on DB
  contention. SQLite is the bottleneck for concurrent writes.
- **Worker CPU:** negligible. Most time is spent sleeping.
- **Database size:** ~1 KB per order (4 col row + 1 KB blob). 100,000 orders
  = ~100 MB. Manageable.
- **Tor latency:** 200-500ms per request due to Tor's 3-hop path. UX must
  account for this (the client uses optimistic UI).
- **Memory:** ~50-100 MB resident for the API process. The worker process
  is smaller.

---

## Security review

- [ARCHITECTURE.md](../ARCHITECTURE.md) — pre-launch checklist
- This document — operational procedures
- `docs/THREAT_MODEL.md` — adversary classes
- `docs/CRYPTO_SPEC.md` — keys and algorithms

Run an external security audit before handling real funds.

## Known gaps

1. **PostgreSQL not supported.** `db/mod.rs` returns Err for postgres. Ship with SQLite only for now.
2. **No systemd unit template.** Write your own or use Docker.
3. **Log redaction not implemented.** Configure the log aggregator to strip sensitive fields.
4. **No Prometheus metrics endpoint.**
5. **Docker compose** runs the API and Tor sidecar only; worker and WASM frontend are separate.
6. **KEK rotation is manual.**
7. **Single-server deployment model.** HA with a shared DB is untested.
8. **Onion rotation** via `scripts/generate-onion.sh` only when the operator runs it.

## Reference

- [ARCHITECTURE.md](../ARCHITECTURE.md)
- `scripts/backup.sh` — encrypted backup
- `scripts/harden.sh` — system hardening
- `scripts/generate-onion.sh` — onion address generation
- `scripts/ci.sh` — CI test runner
- `docker-compose.yml` — container orchestration
- `Dockerfile` — container image
- `config.toml.example` — config file reference
