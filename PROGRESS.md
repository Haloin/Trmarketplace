# torMarketplace — Progress Snapshot

**Date:** 2026-05-23
**Build:** `cargo check` 0 errors, 0 warnings | `cargo test` 91/91 pass

---

## Stats vs Target

| Metric | Current | Target | Gap |
|--------|---------|--------|-----|
| `.rs` files in `src/` | 45 | ~60 | −15 |
| Public modules | 8 | 16 | −8 |
| Dependencies | 33 | 52 | −19 |
| Tests passing | 91 | 200+ | −109 |
| Anonymity score | ~5.5/10 | 9.4/10 | −3.9 |

---

## Phase Completion

| Phase | % | Notes |
|-------|---|-------|
| 0 — Stabilize | 100% | 4 P0 crashes fixed, Mutex poison, EncryptedBlob v2 |
| 1 — Quick Anonymity | 100% | Uniform errors, padding, jitter, flooring, tor_guard cleanup, V6 migration |
| 2 — Stateless Auth | 100% | HMAC auth, stateless middleware, auth rewrite, session.rs/gateway/auth.rs deleted, users table dropped |
| 3 — Oblivious DB | 90% | Orders + Listings both 4-column, scan-all workers, V7–V12 migrations; wasm/ deferred |
| 4 — BTC Stealth | 0% | Not started |
| 5 — Dummy + Admin | 60% | dummy_worker.rs done, admin_pubkey still in config, admin.rs not updated |
| 6 — Anonymity Tests | 0% | Not started |
| 7 — WASM Client | 0% | Not started |

---

## Layer Anonymity Scores

| Layer | Score | Key Gaps |
|-------|-------|----------|
| L0 — Ephemeral Identity | 40% | No per-interaction ephemeral keys; needs WASM client |
| L1 — Stateless Auth | 100% | Complete |
| L2 — Circuit Isolation | 10% | tor_guard.rs is a no-op; no arti-client |
| L3 — Transport Obfuscation | 100% | Complete |
| L4 — Oblivious DB | 85% | Needs WASM for client-side encryption |
| L5 — Blind Workers | 90% | BTC RPC has no timing jitter |
| L6a — Stealth BTC | 0% | No BIP47, still on P2WSH |
| L6b — Subaddress XMR | 70% | No RPC request size padding |
| L7 — Temporal Obfuscation | 70% | No laplace-rs differential privacy |
| L8 — Key Hygiene | 25% | No rotation, no HSM, no key ceremonies |
| L9 — Dummy Orders | 80% | Random garbage (not realistic JSON) |
| L10 — Anti-Surveillance | 30% | No WASM client, no forensic verification |

---

## Files Created (18)

| File | Phase |
|------|-------|
| `src/crypto/hmac_auth.rs` | P2 |
| `src/crypto/oblivious.rs` | P3 |
| `src/gateway/stateless_auth.rs` | P2 |
| `src/gateway/error_unifier.rs` | P1 |
| `src/gateway/response_padding.rs` | P1 |
| `src/gateway/auth_common.rs` | P2 |
| `src/background/dummy_worker.rs` | P5 |

## Files Deleted (2)

| File | Phase |
|------|-------|
| `src/crypto/session.rs` | P2 |
| `src/gateway/auth.rs` | P2 |

## Files Rewritten (10)

| File | Phase |
|------|-------|
| `src/services/auth.rs` | P2 |
| `src/services/orders.rs` | P3 |
| `src/services/listings.rs` | P3 |
| `src/services/disputes.rs` | P3 |
| `src/background/mod.rs` | P1, P5 |
| `src/background/payment_poller.rs` | P3 |
| `src/background/time_lock.rs` | P3 |
| `src/db/models.rs` | P3 |
| `src/error.rs` | P1 |
| `src/gateway/mod.rs` | P1, P2 |

## Files Modified (5+)

| File | Phase |
|------|-------|
| `src/config.rs` | P2 |
| `src/gateway/tor_guard.rs` | P1 |
| `src/db/mod.rs` | P1, P3 |
| `src/crypto/client.rs` | P3 |
| `src/crypto/zk.rs` | P0 |
| `src/crypto/mod.rs` | P2, P3 |
| `src/services/search.rs` | P3 |

## Security Audit Checklist (ARCH §10)

32/40 items passing (80%)

**Passing:** Build warnings, no pubkey_hash in DB, no users table, no sessions/cookies/Redis, no identity headers, uniform errors, padded responses, floored timestamps, jittered workers, 30% dummies, KEK from env, constant-time comparisons, zeroization, PBKDF2 600k, ChaCha20-Poly1305 only, PSBT off-chain, XMR subaddress/view-only/integer/fork, scan-all workers, TOCTOU guards, Tor-only, no IP logging.

**Failing:** 200+ tests (91 only), BIP47 not implemented, on-chain multi-sig still used, no CoinSwap, dummy ops use garbage not realistic JSON, no arti-client circuit isolation.

---

## Next Work (Priority Order)

1. **P5 cleanup:** Realistic dummy JSON blobs, remove admin_pubkey from config, rewrite admin.rs
2. **P6:** anonymity/security test suites (~70 tests)
3. **P7:** WASM client (`wasm/Cargo.toml` + `src/wasm/*`)
4. **P4:** BTC stealth (BIP47, stealth_escrow, CoinSwap)
5. **P2 leftover:** arti-client circuit isolation in tor_guard.rs
