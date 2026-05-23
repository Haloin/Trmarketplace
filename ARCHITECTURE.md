# torMarketplace — Ultimate Project Blueprint

## 1. Current State (Starting Point)

```
Build:        cargo build   → 0 warnings, 0 errors
Tests:        cargo test    → 55/55 pass (19 escrow + 36 baseline)
P0 crashes:   4 (Order.updated_at, Dispute types ×3)
Anonymity:    ~3/10
Files:        40+ Rust source files across 13 modules
```

## 2. Final State (Destination)

```
Build:        cargo build   → 0 warnings, 0 errors
Tests:        cargo test    → 200+/200+ pass
P0 crashes:   0
Anonymity:    ~9.4/10
Files:        ~60 Rust source files across 18 modules
```

## 3. Ultimate Directory Structure

```
torMarketplace/
│
├── Cargo.toml                          ← 38 dependencies → 52
├── config.toml.example                 ← 3 sections → 7 sections
├── rust-toolchain.toml
├── Dockerfile
├── docker-compose.yml
│
├── src/
│   ├── main.rs                         ← 257 lines (unchanged shape, added features)
│   ├── lib.rs                          ← 9 modules → 16 modules
│   │
│   ├── config.rs                       ← Config struct (293 lines → ~400)
│   ├── error.rs                        ← AppError enum (57 lines → unified)
│   │
│   ├── crypto/                         ← Cryptographic primitives
│   │   ├── mod.rs                      ← 7 modules → 12 modules
│   │   ├── wallet.rs                   ← WalletVerifier (unchanged)
│   │   ├── encryption.rs               ← Client-side E2E (new)
│   │   ├── hash.rs                     ← Hashing utilities (unchanged)
│   │   ├── zk.rs                       ← KEK + EncryptedBlob (253 lines)
│   │   ├── session.rs                  ← Session crypto (362 lines → REMOVED)
│   │   ├── escrow.rs                   ← Master seed + key derivation (173 lines)
│   │   ├── client.rs                   ← WASM crypto client (new)
│   │   ├── hmac_auth.rs                ← Stateless HMAC auth (NEW)
│   │   ├── stealth.rs                  ← BIP47 stealth addresses (NEW)
│   │   ├── oblivious.rs               ← Oblivious order encryption (NEW)
│   │   └── dummy.rs                    ← Dummy operation generation (NEW)
│   │
│   ├── db/
│   │   ├── mod.rs                      ← Migrations V1-V10 (397 lines → ~600)
│   │   └── models.rs                   ← Order, Dispute structs (126 lines → ~40)
│   │
│   ├── gateway/                        ← HTTP middleware stack
│   │   ├── mod.rs                      ← Router builder (87 lines)
│   │   ├── state.rs                    ← AppState (27 lines → expanded)
│   │   ├── auth.rs                     ← Auth middleware (146 lines → REMOVED)
│   │   ├── stateless_auth.rs           ← HMAC stateless auth (NEW)
│   │   ├── tor_guard.rs               ← Tor enforcement (101 lines → expanded)
│   │   ├── ratelimit.rs                ← Rate limiter (unchanged)
│   │   ├── rate_limit_middleware.rs    ← Rate limit middleware (unchanged)
│   │   ├── security.rs                 ← Security headers (unchanged)
│   │   ├── validation.rs               ← Input validation (unchanged)
│   │   ├── response_padding.rs         ← Uniform response sizes (NEW)
│   │   └── error_unifier.rs            ← All errors → single response (NEW)
│   │
│   ├── services/
│   │   ├── mod.rs                      ← 9 modules → 11 modules
│   │   ├── auth.rs                     ← Challenge/verify (261 lines → REPLACED)
│   │   ├── orders.rs                   ← Order CRUD (600 lines → REWRITTEN)
│   │   ├── listings.rs                 ← Listing CRUD (unchanged)
│   │   ├── chat.rs                     ← Chat (unchanged)
│   │   ├── search.rs                   ← Search (unchanged)
│   │   ├── disputes.rs                 ← Dispute mgmt (422 lines → REWRITTEN)
│   │   ├── admin.rs                    ← Admin panel (unchanged)
│   │   ├── payments/
│   │   │   ├── mod.rs                  ← Payment routing (NEW)
│   │   │   ├── btc.rs                  ← Bitcoin RPC calls (unchanged)
│   │   │   ├── btc_client.rs           ← Bitcoin client (unchanged)
│   │   │   ├── xmr.rs                  ← Monero view-only (unchanged)
│   │   │   ├── stealth_escrow.rs       ← BIP47 off-chain escrow (NEW)
│   │   │   └── coinswap.rs             ← CoinSwap integration (NEW)
│   │   └── escrow/
│   │       ├── mod.rs                  ← Escrow routing (NEW)
│   │       └── btc.rs                  ← Multi-sig engine (523 lines)
│   │
│   ├── background/
│   │   ├── mod.rs                      ← Worker runner (76 lines → REWRITTEN)
│   │   ├── payment_poller.rs           ← Payment scanner (430 lines → REWRITTEN)
│   │   ├── time_lock.rs                ← Time-lock processor (183 lines → REWRITTEN)
│   │   └── dummy_worker.rs             ← Dummy traffic generator (NEW)
│   │
│   ├── tor.rs                          ← Tor service (unchanged)
│   ├── audit.rs                        ← Security audit (NEW → REMOVED)
│   │
│   └── wasm/                           ← WASM target (NEW)
│       ├── lib.rs                      ← Entrypoint for wasm-pack
│       ├── encrypt.rs                  ← Client-side order encryption
│       ├── decrypt.rs                  ← Client-side order decryption
│       ├── keygen.rs                   ← Ephemeral keypair generation
│       └── auth.rs                     ← HMAC auth token generation
│
├── wasm/                               ← WASM build output (NEW)
│   ├── pkg/                            ← wasm-pack build target
│   └── Cargo.toml                      ← WASM-dependency Cargo
│
├── frontend/                           ← Static frontend (unchanged)
│
├── tests/
│   ├── common/                         ← Test utilities (NEW)
│   │   └── mod.rs
│   ├── unit/                           ← Existing unit tests (EXPANDED)
│   ├── integration/                    ← API integration tests (EXPANDED)
│   ├── anonymity/                      ← Anonymity verification tests (NEW)
│   │   ├── identity_unlinkability.rs
│   │   ├── timing_obfuscation.rs
│   │   └── traffic_analysis.rs
│   └── security/                       ← Security/penetration tests (NEW)
│       ├── oracle_attacks.rs
│       ├── replay_attacks.rs
│       └── crypto_attacks.rs
│
├── scripts/
│   ├── backup.sh                       ← Encrypted backup (unchanged)
│   └── harden.sh                       ← System hardening (unchanged)
│
└── docs/
    ├── ARCHITECTURE.md                 ← Updated architecture doc
    ├── THREAT_MODEL.md                 ← Full threat model (NEW)
    ├── CRYPTO_SPEC.md                  ← Cryptographic spec (NEW)
    └── OPERATIONS.md                   ← Deployment guide (NEW)
```

## 4. Layer-by-Layer Detailed Architecture

### Layer 0: Identity — Ephemeral Per-Interaction

```
CURRENT (leaky):
  wallet_key (ed25519/secp256k1)
    └── pubkey_hash = blake3(pubkey)  ← SAME for ALL orders
        ├── Order 1: buyer_pubkey_hash = pubkey_hash
        ├── Order 2: buyer_pubkey_hash = pubkey_hash  ← LINKABLE!
        └── Session: links to pubkey_hash

FINAL (anonymous):
  root_key (offline, air-gapped)
    ├── identity_1 = HMAC(root_key, "domain:orders" || nonce_1)
    │   └── Order 1: ephemeral_buyer_hash = identity_1
    ├── identity_2 = HMAC(root_key, "domain:orders" || nonce_2)
    │   └── Order 2: ephemeral_buyer_hash = identity_2  ← DIFFERENT!
    ├── identity_3 = HMAC(root_key, "domain:chat" || nonce)
    │   └── Chat: ephemeral_sender_hash = identity_3
    └── auth_key = HMAC(root_key, "domain:auth")
        ├── Request 1: HMAC(auth_key, pk1 || nonce1 || path)
        ├── Request 2: HMAC(auth_key, pk2 || nonce2 || path)
        └── Server sees different ephemeral pubkey each time
```

**Files to create/modify:**
- `src/crypto/hmac_auth.rs` ← NEW: HMAC-based stateless token
- `src/gateway/stateless_auth.rs` ← NEW: replaces cookie-based auth

### Layer 1: Authentication — Stateless HMAC

```
CURRENT:
  Challenge → cookie → Redis session → linkable

FINAL:
  EACH REQUEST independently authenticated:
  ┌──────────────────────────────────────────┐
  │ Client:                                   │
  │   1. Generate ephemeral (sk, pk)          │
  │   2. Compute: token = HMAC(auth_key,      │
  │      pk || unix_hour_bucket || endpoint)  │
  │   3. Send: pk + token + signature         │
  │                                           │
  │ Server:                                   │
  │   1. Lookup auth_key by pk (anonymous)    │
  │   2. Verify HMAC matches                  │
  │   3. Verify ephemeral key signature       │
  │   4. Check replay cache (hour bucket)     │
  │   5. If all pass → authenticated          │
  │   NO session stored → NO linkability      │
  └──────────────────────────────────────────┘

Eliminated:
  src/crypto/session.rs     ← REMOVE (362 lines)
  src/gateway/auth.rs       ← REMOVE (146 lines)
  src/services/auth.rs      ← REWRITE (261 lines → 100 lines)
  Redis session storage     ← REMOVE
  Cookie auth               ← REMOVE
  users table               ← DROP in V8 migration
```

**Files to create/modify:**
- `src/crypto/hmac_auth.rs`   ← NEW
- `src/gateway/stateless_auth.rs`  ← NEW
- `src/services/auth.rs`      ← REWRITE

### Layer 2: Network — Per-Request Tor Circuits

```
CURRENT:
  ┌──────────┐     ┌──────────┐     ┌──────────┐
  │ Request 1 │────▶│ Circuit  │────▶│ Request 2 │  ← SAME circuit!
  └──────────┘     │  (same)  │     └──────────┘
                   └──────────┘

FINAL:
  ┌──────────┐     ┌──────────┐     
  │ Request 1 │────▶│ Circuit A│────▶ .onion
  └──────────┘     └──────────┘     
                                   
  ┌──────────┐     ┌──────────┐     
  │ Request 2 │────▶│ Circuit B│────▶ .onion  ← DIFFERENT circuit!
  └──────────┘     └──────────┘     

  Key changes:
  - client.isolated_client() per request
  - NO x-tor-identity header (REMOVED)
  - NO x-tor-circuit-id header (REMOVED)
  - onion-only enforcement configurable
```

**Files to modify:**
- `src/gateway/tor_guard.rs`  ← Remove x-tor-identity checks

### Layer 3: Transport Obfuscation

```
CURRENT:
  Response:   { "id": "abc123", "state": "pending" }       ← 42 bytes
  Error:      { "error": "Order not found" }               ← 26 bytes  ← DIFFERENT SIZE!

FINAL:
  ALL responses look identical:
    { "data": "<padded to 4096 bytes>" }
  ALL errors look identical:
    { "error": "error" }                        ← padded to 4096 bytes
  ALL HTTP statuses: 200 for success, 500 for everything else
  NO distinguishing headers
  NO Set-Cookie headers (stateless)
```

**Files to create/modify:**
- `src/gateway/response_padding.rs`   ← NEW
- `src/gateway/error_unifier.rs`     ← NEW
- `src/error.rs`                     ← MODIFY: single error response

### Layer 4: Oblivious Database

```
CURRENT SCHEMA (35 columns, 8 indexes):
  orders (
    id BLOB PRIMARY KEY,
    listing_id BLOB,
    buyer_pubkey_hash BLOB,          ← LINKABLE
    seller_pubkey_hash BLOB,         ← LINKABLE
    buyer_pubkey TEXT,                ← PUBLIC KEY
    seller_pubkey TEXT,               ← PUBLIC KEY
    state TEXT,                       ← PLAINTEXT
    currency TEXT,                    ← PLAINTEXT
    escrow_address TEXT,              ← PLAINTEXT
    escrow_amount TEXT,               ← PLAINTEXT
    time_lock_seconds INTEGER,
    created_at, funded_at, shipped_at,
    confirmed_at, released_at, refunded_at,
    expires_at, disputed_at,
    dispute_id TEXT,
    encrypted_blob BLOB,
    owner_pubkey TEXT, fee_percent INTEGER,
    fee_address TEXT,
    multi_sig_key BLOB, multi_sig_redeem_script TEXT,
    buyer_sig BLOB, seller_sig BLOB,
    updated_at INTEGER
  )

FINAL SCHEMA (4 columns, 1 index):
  orders (
    id BLOB PRIMARY KEY,                    ← random UUID
    encrypted_order_blob BLOB NOT NULL,     ← client-side encrypted
    day_bucket INTEGER NOT NULL,            ← floored to 6h
    expiry_bucket INTEGER                   ← floored to 6h
  )
  CREATE INDEX idx_orders_day ON orders(day_bucket);

  NO users table
  NO disputes table
  NO audit_logs table
  NO payment_audits table
  NO chat_messages table → replaced by E2E in order blob

encrypted_order_blob (client-side, server-blind):
  {
    "version": 1,
    "nonce": "<12 bytes>",
    "ciphertext": "<ChaCha20-Poly1305>",
    "ephemeral_pubkey": "<X25519 pubkey for reply>"
  }

Decrypted content (client-only):
  {
    "state": "pending",
    "currency": "BTC",
    "amount": "1.5",
    "listing_ref": "hash",
    "parties": ["ephemeral_id_1", "ephemeral_id_2"],
    "timestamps": { "created": 123456 },          ← floored
    "payment": { "type": "btc", "address": "..." },
    "dispute": { "status": "none" },
    "chat": { "messages": [{"encrypted": "..."}] }
  }
```

**Files to modify:**
- `src/db/models.rs`           ← SIMPLIFY: 35 fields → 4 fields
- `src/db/mod.rs`              ← ADD: V6-V10 migrations
- `src/services/orders.rs`     ← REWRITE: all queries use scan-all
- `src/background/*.rs`        ← REWRITE: blind worker pattern

### Layer 5: Blind Workers

```
CURRENT:
  payment_poller: SELECT * FROM orders WHERE state = 'pending'
  time_lock:      SELECT * FROM orders WHERE state IN ('shipped', 'funded', 'disputed')
  → Server knows exactly how many orders in each state
  → Server knows how many payments are pending
  → Timing of state transitions is visible

FINAL:
  blind_worker_loop:  ▷ Every 45-75s (randomized):
    1. SELECT id, encrypted_order_blob, day_bucket FROM orders
       ← SCANS ALL ORDERS (no WHERE clause)
    2. For each order:
       a. Attempt decrypt encrypted_order_blob
       b. If decrypt fails → skip
       c. If state == "pending" and has payment_address:
          - Check blockchain
          - If confirmed → re-encrypt with new state + UPDATE
       d. If state == "shipped" and time_lock expired:
          - Broadcast PSBT
          - Re-encrypt with new state + UPDATE
       e. If state == "funded" and seller timeout:
          - Auto-dispute
       f. If state == "disputed" and expiry:
          - Auto-refund
    3. 30% chance: process a DUMMY order
       - Generate random blob
       - Access blockchain with fake address
       - Same timing as real processing
    4. Sleep for randomized interval
```

**Files to modify:**
- `src/background/mod.rs`              ← REWRITE: jittered intervals
- `src/background/payment_poller.rs`   ← REWRITE: scan-all pattern
- `src/background/time_lock.rs`        ← REWRITE: scan-all pattern
- `src/background/dummy_worker.rs`     ← NEW: dummy operations

### Layer 6a: Bitcoin — Stealth Multi-Sig with BIP47

```
CURRENT:
  1. create_multisig_p2wsh(buyer, seller, owner) → 2-of-3 P2WSH
  2. import_multisig_watchonly(address) into Bitcoin Core
  3. Buyer pays to P2WSH address on-chain
  4. ✓ transaction visible: amount + distinctive script
  5. Funds released via PSBT with 2-of-3 signatures

FINAL:
  1. Seller publishes BIP47 payment code (base58, static)
  2. Buyer derives stealth address from seller's payment code + own key
     └── Looks like normal P2WPKH (no CHECKMULTISIG visible)
  3. Buyer sends payment to stealth address
  4. Multi-sig CONSTRUCTED OFF-CHAIN via PSBT negotiation
     └── 3-party PSBT: buyer + seller + owner all sign
     └── Settlement tx: single input → seller_output + fee_output
     └── On-chain: looks like normal payment to 2 recipients
  5. Optional: CoinSwap routing through 3 makers
     └── Bitcoin Core RPC not involved in address creation
     └── Only used for: balance check, fee estimation, broadcast
```

**Files to create/modify:**
- `src/crypto/stealth.rs`             ← NEW: BIP47 derivation
- `src/services/payments/stealth_escrow.rs`  ← NEW: stealth PSBT flow
- `src/services/payments/coinswap.rs`       ← NEW: CoinSwap routing
- `src/services/payments/btc.rs`            ← MODIFY: minimal RPC
- `src/services/escrow/btc.rs`              ← MODIFY: PSBT overhaul

### Layer 6b: Monero — Already Strong

Current state is mostly acceptable:
- ✓ Per-order subaddress
- ✓ View-only wallet
- ✓ 10 confirmations
- ✓ Fork detection with rollback
- ✓ Integer-only arithmetic (no f64)

Changes needed:
  1. Blind RPC: all RPC calls padded to fixed size
  2. No logging of RPC request patterns
  3. Randomized RPC timing (±30% jitter)

**Files to modify:**
- `src/services/payments/xmr.rs`     ← MODIFY: blind RPC calls

### Layer 7: Temporal Obfuscation

```
CURRENT:
  created_at = 1747826593           ← precise second
  funded_at  = 1747826653           ← 60 seconds later
  → Pattern: user creates + funds in same minute

FINAL:
  day_bucket = floor(1747826593 / 21600) * 21600  = 1747814400
  → All events in identical 6-hour bucket
  → Cannot distinguish order A from order B within same 6h window

  Worker intervals:
  base = 60s → actual = 60 ± random(30) = [30, 90]
  base = 120s → actual = 120 ± random(60) = [60, 180]
  base = 300s → actual = 300 ± random(150) = [150, 450]

  Each interval independently randomized:
  use rand::Rng;
  let jitter = rng.gen_range(0.5..1.5);
  let actual_interval = (base_seconds as f64 * jitter) as u64;

  No exponential backoff on error (eliminates timing signature):
  → Fixed randomized interval, regardless of success/failure
```

**Files to modify:**
- `src/background/mod.rs`                ← REWRITE: jittered loops
- `src/services/orders.rs`              ← MODIFY: floored timestamps
- `src/services/disputes.rs`            ← MODIFY: floored timestamps

### Layer 8: End-to-End Cryptography

```
CURRENT:
  - Server-side AES-GCM for storage encryption (KEK)
  - No client-side WASM

FINAL:
  ┌─────────────────────────────────────────────────────┐
  │ Client WASM (compiled from Rust → wasm-pack):       │
  │                                                      │
  │  src/wasm/                                           │
  │  ├── lib.rs   : WASM entrypoint                     │
  │  ├── encrypt.rs: encrypt_order_blob(plaintext: &str, │
  │  │               recipient_pubkey: &[u8]) → Vec<u8> │
  │  ├── decrypt.rs: decrypt_order_blob(blob: &[u8],    │
  │  │               private_key: &[u8]) → Option<String>│
  │  ├── keygen.rs:  generate_ephemeral_keypair()        │
  │  │               → (secret_key, public_key)          │
  │  └── auth.rs:    compute_auth_token(                 │
  │                   secret: &[u8], pubkey: &[u8],      │
  │                   path: &str, hour: u64) → String    │
  │                                                      │
  │  Algorithm: X25519 + ECDH + ChaCha20-Poly1305        │
  │  - Ephemeral keypair per message                     │
  │  - ECDH shared secret → ChaCha20 key                │
  │  - 96-bit random nonce                               │
  │  - Authenticated encryption                           │
  └─────────────────────────────────────────────────────┘

Key hierarchy:
  root_key
    ├── auth_key    → HMAC-based API authentication
    ├── order_key   → Order blob encryption (ECDH per order)
    ├── chat_key    → Chat message ratchet
    └── dispute_key → Evidence encryption
```

**Files to create/modify:**
- `src/wasm/*`                         ← ALL NEW
- `wasm/Cargo.toml`                    ← NEW
- `src/crypto/client.rs`               ← MODIFY: WASM-ready

### Layer 9: Admin Anonymity

```
CURRENT:
  config.security.admin_pubkey = "hex"  ← static, persistent

FINAL:
  No admin identity in config.
  Admin authentication via blinded tokens:
  1. Admin registers ephemeral identity per session
  2. Token is blinded, server signs without seeing content
  3. Admin unblinds → proves authorization without revealing identity
  4. No admin_pubkey in config → no linkable admin key
  
  Dispute resolution:
  - Admin resolves via PSBT only (never handles funds)
  - Resolution logged to encrypted_blob (not separate table)
  - All admin actions indistinguishable from user actions
```

**Files to modify:**
- `src/config.rs`                     ← REMOVE admin_pubkey
- `src/services/admin.rs`             ← REWRITE: blinded tokens
- `src/services/disputes.rs`          ← REWRITE: PSBT resolution

### Layer 10: Anti-Surveillance — Zero Forensic Value

```
If server is seized:
  CURRENT:
    - 35-column orders table → full marketplace data
    - users table → all user pubkey hashes
    - audit_logs table → all operations with timestamps
    - payment_audits → all transaction hashes
    - Redis sessions → all active users
    - Logs → request patterns, IPs, timing

  FINAL:
    - orders table → 4 columns, opaque blobs only
    - No users, audit_logs, payment_audits tables
    - No Redis (stateless auth)
    - No persistent logs
    - Each blob individually encrypted with different keys
    - Cannot determine:
      • Who owns which order
      • How many orders per user
      • Which currency was used
      • Order amounts
      • Order states
      • Transaction hashes on-chain
      • Admin actions
      • Chat content
```

## 5. Database Migration Plan

| Migration | Columns Added | Columns Removed |
|-----------|--------------|-----------------|
| V1 (done) | Initial schema | — |
| V2 (done) | audit_logs, payment_audits | — |
| V3 (done) | disputes, dispute_evidence | — |
| V4 (done) | 7 escrow columns on orders | — |
| V5 (done) | orders.updated_at | — |
| V6 | — | audit_logs, payment_audits |
| V7 | orders.encrypted_order_blob | — |
| V8 | — | users table |
| V9 | — | chat_messages table |
| V10 | — | disputes, dispute_evidence |
| V11 | orders.day_bucket | — |
| V12 | — | ALL old columns except id, day_bucket, encrypted_blob |

## 6. Cargo.toml Dependency Evolution

**Current (38 deps) → Final (52 deps)**

**ADD:**
- `bip47` ← BIP47 reusable payment codes
- `arti-client` ← Tor circuit isolation
- `subtle` ← Constant-time operations (already transitively used)
- `laplace-rs` ← Differential privacy for timestamps
- `blind-rsa-signatures` ← Admin blinded tokens
- `wasm-pack` ← WASM compilation
- `wasm-bindgen` ← WASM bindings
- `getrandom` ← WASM-compatible randomness
- `js-sys` ← WASM JS interop
- `web-sys` ← WASM JS interop

**REMOVE:**
- `redis` ← No more session storage (optional, keeps rate-limit cache)
- `aes-gcm` ← Replaced by ChaCha20-Poly1305 for new code
- `pbkdf2` ← Only needed for KEK derivation (keep)
- `session.rs` encryption → replaced by HMAC-auth

**KEEP (unchanged):**
- `axum`, `tokio`, `tower`, `tower-http`, `serde`, `serde_json`
- `sqlx`, `uuid`, `rand`, `hex`, `base64`, `zeroize`
- `ed25519-dalek`, `k256`
- `bitcoin`, `secp256k1`
- `chacha20poly1305`, `x25519-dalek`, `blake3`
- `sha2`, `hmac`, `hkdf`
- `time`, `reqwest`, `toml`
- `tracing`, `tracing-subscriber`
- `thiserror`, `anyhow`
- `once_cell`, `parking_lot`

## 7. Test Strategy — 200+ Tests

```
tests/
├── unit/                          ← 55 existing + 45 new = 100
│   ├── crypto/
│   │   ├── hmac_auth_tests.rs     ← 10 new
│   │   ├── oblivious_tests.rs     ← 8 new
│   │   ├── stealth_tests.rs       ← 10 new
│   │   └── escrow_tests.rs        ← 5 new
│   └── services/
│       ├── orders_tests.rs        ← 5 new (oblivious)
│       └── disputes_tests.rs      ← 7 new (oblivious)
│
├── integration/                   ← 5 existing + 25 new = 30
│   ├── api/
│   │   ├── order_flow.rs          ← 5 scenarios
│   │   ├── auth_flow.rs           ← 5 scenarios
│   │   └── dispute_flow.rs        ← 5 scenarios
│   └── payments/
│       ├── btc_flow.rs            ← 5 scenarios
│       └── xmr_flow.rs            ← 5 scenarios
│
├── anonymity/                     ← 30 new (UNIQUE TO THIS PROJECT)
│   ├── identity_unlinkability.rs  ← 10 tests
│   │   ├── same_user_different_orders → no common identity
│   │   ├── user_creates_and_views_order → no pubkey_hash reused
│   │   └── user_chats_on_order → no identity leakage
│   ├── timing_obfuscation.rs      ← 10 tests
│   │   ├── timestamps_floored_to_6h
│   │   ├── worker_intervals_jittered
│   │   └── no_correlation_between_consecutive_events
│   └── traffic_analysis.rs        ← 10 tests
│       ├── response_sizes_are_identical
│       ├── error_messages_are_identical
│       └── background_dummy_ops_indistinguishable
│
└── security/                      ← 40 new
    ├── oracle_attacks.rs          ← 10 tests
    │   ├── no_error_distinction_on_invalid_order
    │   ├── no_error_distinction_on_auth_failure
    │   └── response_timing_is_constant
    ├── replay_attacks.rs          ← 10 tests
    │   ├── hmac_token_replay_detected
    │   ├── challenge_replay_detected
    │   └── stale_hour_bucket_rejected
    └── crypto_attacks.rs          ← 20 tests
        ├── wrong_kek_fails_decryption
        ├── wrong_ephemeral_key_fails_decrypt
        ├── nonce_reuse_detected
        ├── key_zeroization_verified
        └── constant_time_compare_no_leakage
```

## 8. Implementation Phases — Detailed

### Phase 0: Stabilize (1-2 days)

| Step | File | Change |
|------|------|--------|
| 0.1 | `src/db/models.rs:29` | Add `pub updated_at: Option<i64>` to Order |
| 0.2 | `src/db/models.rs:75` | Change `opened_by: Vec<u8>` → `String` |
| 0.3 | `src/db/models.rs:78` | Change `resolved_by: Option<Vec<u8>>` → `Option<String>` |
| 0.4 | `src/db/models.rs:87` | Change `submitted_by: Vec<u8>` → `String` |
| 0.5 | `src/services/disputes.rs:111` | Insert with `hex::encode(pubkey_hash)` |
| 0.6 | `src/services/disputes.rs:274` | Remove `hex::encode` (already String) |
| 0.7 | `src/services/disputes.rs:329` | Insert with `hex::encode(pubkey_hash)` |
| 0.8 | `src/services/disputes.rs:415,418` | Remove `hex::encode` (struct fields now String) |

### Phase 1: Quick Anonymity Wins (2-3 days)

| Step | Change |
|------|--------|
| 1.1 | Uniform error: ALL fail → `{"error":"error"}` HTTP 500 |
| 1.2 | Response padding middleware (pad to 4096) |
| 1.3 | Worker intervals: 60s → rand[45,75], 120s → rand[90,150] |
| 1.4 | Floor timestamps: `floor(unix / 21600) * 21600` |
| 1.5 | Remove x-tor-identity checks |
| 1.6 | Remove x-tor-circuit-id from session |
| 1.7 | V6 migration: DROP audit_logs, payment_audits |

### Phase 2: Stateless Auth (1 week)

| Step | File | Action |
|------|------|--------|
| 2.1 | `src/crypto/hmac_auth.rs` | NEW: HMAC token generation + verification |
| 2.2 | `src/gateway/stateless_auth.rs` | NEW: middleware (replaces session auth) |
| 2.3 | `src/services/auth.rs` | REWRITE: challenge → ephemeral key registration |
| 2.4 | `src/crypto/session.rs` | DELETE |
| 2.5 | `src/gateway/auth.rs` | DELETE |
| 2.6 | `src/gateway/mod.rs` | MODIFY: swap session auth for stateless |
| 2.7 | `src/config.rs` | MODIFY: remove `session_ttl_seconds` |
| 2.8 | V8 migration: DROP users table | +20 lines |

### Phase 3: Oblivious Database (2 weeks)

| Step | File |
|------|------|
| 3.1 | `src/crypto/oblivious.rs` |
| 3.2 | `src/wasm/` |
| 3.3 | `src/db/models.rs` |
| 3.4 | `src/db/mod.rs` |
| 3.5 | `src/services/orders.rs` |
| 3.6 | `src/services/disputes.rs` |
| 3.7 | `src/background/payment_poller.rs` |
| 3.8 | `src/background/time_lock.rs` |

### Phase 4: BTC Stealth Payments (2-3 weeks)

| Step | File |
|------|------|
| 4.1 | `Cargo.toml` |
| 4.2 | `src/crypto/stealth.rs` |
| 4.3 | `src/services/payments/stealth_escrow.rs` |
| 4.4 | `src/services/payments/coinswap.rs` |
| 4.5 | `src/services/escrow/btc.rs` |
| 4.6 | `src/services/payments/btc.rs` |

### Phase 5: Dummy Traffic + Admin Anonymity (1 week)

| Step | File |
|------|------|
| 5.1 | `src/background/dummy_worker.rs` |
| 5.2 | `src/background/mod.rs` |
| 5.3 | `Cargo.toml` |
| 5.4 | `src/services/admin.rs` |
| 5.5 | `src/config.rs` |

### Phase 6: Anonymity Tests + Verification (1 week)

| Step | Tests |
|------|-------|
| 6.1 | `tests/anonymity/identity_unlinkability.rs` — 10 tests |
| 6.2 | `tests/anonymity/timing_obfuscation.rs` — 10 tests |
| 6.3 | `tests/anonymity/traffic_analysis.rs` — 10 tests |
| 6.4 | `tests/security/oracle_attacks.rs` — 10 tests |
| 6.5 | `tests/security/replay_attacks.rs` — 10 tests |
| 6.6 | `tests/security/crypto_attacks.rs` — 20 tests |
| 6.7 | Final sweep: `cargo build` 0 warnings + `cargo test` all pass |

### Phase 7: WASM Client-side Crypto (1 week, parallel)

| Step | File | Action |
|------|------|--------|
| 7.1 | `wasm/Cargo.toml` | NEW: WASM project |
| 7.2 | `src/wasm/lib.rs` | WASM entrypoint |
| 7.3 | `src/wasm/encrypt.rs` | ChaCha20-Poly1305 encrypt |
| 7.4 | `src/wasm/decrypt.rs` | ChaCha20-Poly1305 decrypt |
| 7.5 | `src/wasm/keygen.rs` | Ephemeral keypair |
| 7.6 | `src/wasm/auth.rs` | HMAC token |
| 7.7 | — | `wasm-pack build` verify |

## 9. Complete Cryptographic Key Hierarchy

```
┌──────────────────────────────────────────────────────────────────┐
│               KEY HIERARCHY (air-gapped → server → client)       │
├──────────────────────────────────────────────────────────────────┤
│                                                                   │
│  LEVEL 0: COLD STORAGE (air-gapped, paper wallet)                │
│  ┌──────────────────────────────────────────────────────────────┐ │
│  │ master_seed [32 bytes]                                       │ │
│  │   ├── HMAC → order_key_i for each BTC order                 │ │
│  │   └── BIP32 → root wallet (future)                          │ │
│  └──────────────────────────────────────────────────────────────┘ │
│           │                                                       │
│           ▼ encrypted with KEK, stored in config                  │
│                                                                   │
│  LEVEL 1: SERVER MEMORY                                          │
│  ┌──────────────────────────────────────────────────────────────┐ │
│  │ AppState.master_seed [32 bytes] (decrypted at startup)       │ │
│  │ AppState.kek: KeyEncryptionKey [32 bytes] (from env/manual) │ │
│  └──────────────────────────────────────────────────────────────┘ │
│           │                                                       │
│           ▼                                                       │
│                                                                   │
│  LEVEL 2: CLIENT (WASM / browser session)                        │
│  ┌──────────────────────────────────────────────────────────────┐ │
│  │ ephemeral_auth_keys: (sk, pk) — generated per request        │ │
│  │ ephemeral_chat_keys: (sk, pk) — generated per chat           │ │
│  │ ephemeral_order_keys: (sk, pk) — generated per order         │ │
│  └──────────────────────────────────────────────────────────────┘ │
│           │                                                       │
│           ▼                                                       │
│                                                                   │
│  LEVEL 3: TRANSPORT (per-message)                                │
│  ┌──────────────────────────────────────────────────────────────┐ │
│  │ HMAC tokens: HMAC(auth_key, pk || nonce || path)            │ │
│  │ Order blob: ChaCha20-Poly1305(plaintext, shared_secret)     │ │
│  │ Chat msg:   ChaCha20-Poly1305(text, chat_shared_secret)     │ │
│  └──────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  LEAKAGE ON COMPROMISE:                                          │
│  Level 0 leak → all orders, all payments, all keys (PGP)        │
│  Level 1 leak → current orders being processed                  │
│  Level 2 leak → ephemeral, compartmentalized                    │
│  Level 3 leak → individual messages only                        │
│                                                                   │
└──────────────────────────────────────────────────────────────────┘
```

## 10. Security Audit Checklist — Pre-Launch Verification

```
□ BUILD: cargo build produces 0 warnings
□ TESTS: cargo test passes 200+ tests
□ CLIPPY: cargo clippy -- -D warnings passes (if configured)
□ ANONYMITY CHECKS:
  □ No pubkey_hash stored anywhere in DB
  □ No users table
  □ No session cookies
  □ No Redis session storage
  □ No x-tor-identity header
  □ No x-tor-circuit-id header
  □ All error responses are identical
  □ All response bodies padded to 4096 bytes
  □ Timestamps floored to 6-hour buckets
  □ Background workers use randomized intervals
  □ Worker intervals have 30% jitter minimum
  □ 30% of worker operations are dummy
  □ No continuous logging of sensitive data
□ CRYPTO CHECKS:
  □ KEK loaded from env var or HSM only
  □ KEK never written to disk
  □ All comparisons use subtle::ConstantTimeEq
  □ Key zeroization on all secret keys
  □ PBKDF2 with 600,000 iterations minimum
  □ No CBC-mode encryption (ChaCha20-Poly1305 only)
  □ No custom crypto (audited crates only)
  □ BIP47 implementation correct (ECDH derivation)
  □ Nonce never reused (fresh OsRng per operation)
□ PAYMENT CHECKS:
  □ BTC: no multi-sig on-chain (stealth addresses)
  □ BTC: PSBT negotiation is off-chain
  □ BTC: CoinSwap routing optional but functional
  □ XMR: subaddress per order
  □ XMR: view-only wallet only
  □ XMR: integer arithmetic only (no f64)
  □ XMR: fork detection enabled
  □ XMR: 10 confirmation minimum
  □ Both: minimum payment threshold (546 sats)
□ WORKER CHECKS:
  □ Payment poller scans ALL orders (not filtered by state)
  □ Time-lock checker scans ALL orders
  □ Failed decryption gracefully skipped
  □ Dummy operations indistinguishable from real
  □ All UPDATEs have TOCTOU guard (WHERE + rows_affected)
  □ All transitions checked against state machine
□ INFRASTRUCTURE:
  □ Tor hidden service is the only public endpoint
  □ No IP logging in application
  □ No user-identifying data in logs
  □ Backups are encrypted
  □ Database encrypted at rest
  □ Application runs as non-root user
  □ Rate limiting enforced
  □ Maximum file descriptor limits set
```

---

*Blueprint Version: 2026-05-22*
*Target: 9.4/10 anonymity, 200+ tests, 52 dependencies*
