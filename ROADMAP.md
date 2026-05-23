# torMarketplace — Roadmap

**Single source of truth alongside `ARCHITECTURE.md`.**
All old planning docs (TODO.md, AGENTS.md, CONTINUITY.md, IMPLEMENTATION_STATUS.md, REAL_STATUS.md) were false/misleading and have been deleted.

**Target**: 9.4/10 anonymity, 200+ tests, ARCHITECTURE.md 10-layer compliance
**Current**: ~2%
**Dev**: 1 full-time
**Est. total**: ~17 weeks

---

## Phase 1: Identity & Leak Plugging (Weeks 1-2)

Independent quick wins. Highest anonymity-per-hour ratio.

### 1.1 — Layer 0: Ephemeral Domain-Separated Identities (~5 days)

Replace `buyer_pubkey_hash = blake3(pubkey)` with `identity = HMAC(root_key, "domain:orders" || nonce)`. Two orders from same user become unlinkable.

**Files**:
- `src/crypto/hmac_auth.rs` — add `derive_ephemeral_id()`
- `src/gateway/stateless_auth.rs` — emit domain-scoped ID
- `src/services/orders.rs` — use ephemeral ID in blob
- `src/services/chat.rs` — use chat-domain ID
- `src/gateway/auth_common.rs` — optional domain param

**Verify**: `cargo build` 0 warnings. Two orders from same user produce different `buyer_pubkey_hash`.

### 1.2 — Layer 6b: XMR Blind RPC (~3 days)

Pad all RPC request bodies to fixed size. Add ±30% timing jitter per call.

**Files**:
- `src/services/payments/xmr.rs` — `rpc_call()`: pad JSON to 4096, add `tokio::time::sleep(jitter)`

**Verify**: All XMR RPC calls are identical wire size. Timing varies per call.

### 1.3 — Layer 2: Per-Request Tor Circuit Isolation (~5 days)

Replace NO-OP `tor_guard.rs` with SOCKS5 circuit pool. Each request uses a different Tor circuit.

**Files**:
- `src/tor/circuit_pool.rs` (NEW) — pool of SOCKS5 connections on different circuits
- `src/gateway/tor_guard.rs` — rewrite: assign circuit from pool per request
- `Cargo.toml` — add `tokio-socks`

**Verify**: Two requests from same client hit different circuits.

---

## Phase 2: WASM Crypto Foundation (Weeks 3-5)

Client-side crypto library. Prerequisite for server-blind architecture.

### 2.1 — WASM project scaffold

**Files**:
- `wasm/Cargo.toml` (NEW)
- `Cargo.toml` — add wasm deps

### 2.2 — WASM encrypt/decrypt

**Files**:
- `src/wasm/lib.rs` (NEW) — #[wasm_bindgen] entrypoint
- `src/wasm/encrypt.rs` (NEW) — X25519 ECDH + ChaCha20-Poly1305
- `src/wasm/decrypt.rs` (NEW)

### 2.3 — WASM keygen + auth

**Files**:
- `src/wasm/keygen.rs` (NEW)
- `src/wasm/auth.rs` (NEW) — HMAC token generation

### 2.4 — Server key hierarchy

**Files**:
- `src/crypto/escrow.rs` — add `derive_domain_key()`
- `src/crypto/oblivious.rs` — add ECDH key exchange support

**Verify**: `wasm-pack build` succeeds. All 4 functions callable from JS.

---

## Phase 3: Oblivious Server Transformation (Weeks 6-9)

API server becomes blind. Workers process with separate keys.

### 3.1 — Order service: encrypted blob pass-through

**Files**:
- `src/services/orders.rs` — `create_order` stores client blob. `get_order` returns it. Remove `read_order()`, `decrypt_order_data()`.

### 3.2 — Dispute service: same pattern

**Files**:
- `src/services/disputes.rs` — no server-side decrypt

### 3.3 — Chat service: same pattern

**Files**:
- `src/services/chat.rs` — encrypted message pass-through

### 3.4 — Blind workers rewrite

**Files**:
- `src/background/payment_poller.rs` — workers use separate `worker_key`
- `src/background/time_lock.rs` — same

### 3.5 — V10 migration: drop old columns

**Files**:
- `src/db/mod.rs` — recreate orders table, keep only 4 columns

### 3.6 — Dead code removal

**Files**:
- Delete `src/crypto/encryption.rs`
- Strip AES-GCM from `src/crypto/zk.rs`

### 3.7 — Dummy worker

**Files**:
- `src/background/dummy_worker.rs` (NEW) — 30% dummy operations

**Verify**: API handlers cannot decrypt blobs. Workers can. 30% of operations are dummy.

---

## Phase 4: BTC Stealth Payments (Weeks 10-13)

BTC transactions look like normal P2WPKH on-chain.

### 4.1 — BIP47 stealth module

**Files**:
- `src/crypto/stealth.rs` (NEW)

### 4.2 — Stealth escrow service

**Files**:
- `src/services/payments/stealth_escrow.rs` (NEW)

### 4.3 — CoinSwap module

**Files**:
- `src/services/payments/coinswap.rs` (NEW)

### 4.4 — Update BTC payment flow

**Files**:
- `src/services/orders.rs` — replace p2wsh with stealth
- `src/services/payments/btc.rs` — minimal RPC only
- `src/services/escrow/btc.rs` — add stealth PSBT

### 4.5 — Update BTC payment polling

**Files**:
- `src/background/payment_poller.rs` — BIP47 notification scanning

---

## Phase 5: Admin Anonymity + Hardening (Weeks 14-15)

### 5.1 — Remove admin_pubkey

**Files**:
- `src/config.rs` — delete field
- `src/main.rs` — remove validation

### 5.2 — Blinded token admin auth

**Files**:
- `src/services/admin.rs` — rewrite
- `src/gateway/auth_common.rs` — replace `is_admin()`

### 5.3 — PSBT-only dispute resolution

**Files**:
- `src/services/disputes.rs` — admin cannot set state directly

### 5.4 — Infrastructure hardening

**Files**:
- `src/main.rs` — drop privileges, FD limits
- `scripts/harden.sh` — fix
- `Cargo.toml` — remove `aes-gcm`

---

## Phase 6: 200+ Tests (Weeks 16-17)

| Test file | Count |
|-----------|-------|
| `tests/anonymity/identity_unlinkability.rs` | 10 |
| `tests/anonymity/timing_obfuscation.rs` | 10 |
| `tests/anonymity/traffic_analysis.rs` | 10 |
| `tests/security/oracle_attacks.rs` | 10 |
| `tests/security/replay_attacks.rs` | 10 |
| `tests/security/crypto_attacks.rs` | 20 |
| `tests/unit/crypto/*` | 33 |
| `tests/integration/api/*` + `payments/*` | 30 |
| Security checklist (ARCHITECTURE.md §10) | 47 items |
| **Total** | **200+** |

---

## Honest Progress Tracking

Only two numbers matter:
- **% of ARCHITECTURE.md 10-layer compliance** (target: 100%)
- **Tests passing** (target: 200+)

Everything else is noise. Tracked in this file only.

---

*Created: 2026-05-22. Replaces all previous planning documents.*
