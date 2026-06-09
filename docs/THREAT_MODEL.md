# torMarketplace — Threat Model

Backend and wire-protocol assumptions. Overview in [ARCHITECTURE.md](../ARCHITECTURE.md).

Not covered here: browser UI bugs, Tor Browser internals, or host-level compromise
unless noted below.

## Adversary classes

We assume five classes of adversary, ordered by capability.

### A1 — Passive network observer
Sits on the network path between the client and the Tor hidden service. Can observe
all bytes that transit the network. Cannot break Tor's onion encryption. Can perform
traffic analysis (timing, volume, packet sizes).

**Mitigations in place:**
- Tor hidden service is the only public endpoint (when `tor.enabled = true`)
- All response bodies padded to 4096 bytes (`gateway/response_padding.rs`)
- All error responses return identical shape (`gateway/error_unifier.rs`)
- 50% jitter on background worker intervals (`background/mod.rs:12-16`)
- 30% dummy traffic (`background/dummy_worker.rs`)
- No IP or user-agent stored (`tor_guard.rs` does not extract these)

**Gaps:**
- Frontend → server timing is not artificially padded; page-load timing leaks
  resource size. This is browser-side and partially mitigable with constant-time
  fetch patterns.
- On-chain BTC transactions (stealth addresses) are still publicly visible on the
  Bitcoin blockchain. Mitigated by stealth addresses that look like normal
  P2WPKH outputs, but a sophisticated adversary with access to merchant and buyer
  wallet activity could correlate.
- XMR subaddresses are per-order, so on-chain unlinkability is strong (XMR is
  already privacy-by-default).

### A2 — Active network adversary
Same as A1 but can also inject, drop, delay, or replay packets. Cannot break Tor
onion encryption. Can attempt man-in-the-middle within Tor (compromised guard or
exit within the path the server sees).

**Mitigations in place:**
- HMAC-based auth token is bound to `(pubkey, hour_bucket, path)`
  (`hmac_auth::generate_auth_token`). Replay within the same hour bucket is
  rejected by `stateless_auth.rs:71` replay cache.
- Ephemeral per-request signature proves key ownership
  (`hmac_auth::sign_challenge/verify_challenge`).
- ChaCha20-Poly1305 AEAD on all order blobs. Tamper detection is built into the
  cipher (`oblivious.rs:196-203` test verifies tampered blobs fail).

**Gaps:**
- If a client reuses the same `(pubkey, hour_bucket, path)` triple, the auth
  token is identical and the second use is rejected as replay. The frontend
  should use a fresh ephemeral keypair per request when signing.
- HMAC key derivation is per-pubkey (`hmac_auth::derive_auth_key`). The
  `auth_key` is `HMAC(server_secret, "auth_key_derivation_v1" || pubkey)`. If
  `server_secret` leaks, all client auth keys leak. This is the standard
  KDF-then-MAC pattern; no improvement available without HSM.

### A3 — Server seizure (cold disk)
Law enforcement, hosting provider, or physical attacker who seizes the server
machine while it is powered off. Has access to the full filesystem: SQLite
database, config files, application binary, logs.

**What the adversary gets:**
- The full `orders`, `listings`, `notification_tracker` tables
- Any persisted `master_seed_hex` and `worker_key_hex` (encrypted with KEK)
- The application binary, which is open-source so it does not help them
- The config file with non-secret settings
- The log directory if logs are persisted (currently not configured to write to
  file; only stdout)

**What the adversary does NOT get (with proper config):**
- The KEK (`KEK_HEX` env var is not on disk; it must be re-entered at startup
  in production)
- Cleartext order metadata *if* the worker process never decrypts to disk and the
  blobs are truly opaque
- The on-disk database is encrypted at the filesystem level (LUKS / ZFS) by the
  operator; this is deployment-dependent and not enforced by the application

**Mitigations in place:**
- API binary has no `master_seed` or `worker_key`; public handlers do not decrypt blobs
- Worker runs as a separate binary with `worker_key` only
- WASM client encrypts order blobs to worker X25519 pubkey (ECDH + ChaCha20-Poly1305)

**Remaining gaps:**
- Worker decrypts full `OrderData` JSON for payment polling (live memory risk)
- Worker re-encrypts with legacy oblivious format after payment detection
- Filesystem encryption at rest is operator-dependent

### A4 — Malicious or coerced admin
The marketplace operator (or someone who compromises the operator's credentials)
runs the admin tools. The adversary can call admin endpoints and resolve
disputes.

**What the adversary can do:**
- Resolve disputes with a valid blind-signed admin token
- Rotate KEK with a valid blind-signed admin token
- Blind-sign endpoint accepts blinded requests (rate-limited)

**Mitigations in place:**
- Chaum RSA blind signatures for admin authorization (unlinkable per action)
- Admin tokens are single-use with expiry (replay cache)
- API process cannot decrypt order blobs (server blindness preserved)

**Remaining gaps:**
- Admin RSA private key lives in API process memory
- BTC settlement still involves server-side PSBT broadcast

### A5 — Compromised supply chain
Adversary who has compromised one of: a Rust crate dependency, the rustc
compiler, the build environment, the Docker base image, the developer's
machine.

**Mitigations in place:**
- All deps are pinned in `Cargo.lock` (use `cargo build --locked`)
- No `git` deps in `Cargo.toml` (all crates.io)
- `cargo audit` runs in CI (`.github/workflows/ci.yml`, `scripts/ci.sh`)

**Not done:**
- Reproducible builds: not configured
- SBOM generation: not configured
- Dependency scanning in CI: not configured
- `cargo audit --deny warnings` as a gate: not configured

---

## Properties we aim to maintain

1. **Anonymity:** No party (operator, network observer, payment processor) can
   determine who is buying or selling what, in what quantity, with whom, without
   the cooperation of both parties.

2. **Unlinkability:** Two orders from the same buyer, or two chat messages from
   the same sender, or two dispute resolutions by the same admin, cannot be
   linked by anyone other than the parties themselves.

3. **Plausible deniability:** A user can deny any action they did not take.
   Auth tokens are scoped to a single hour-bucket and path; replay is impossible.

4. **Forward secrecy:** Compromise of long-term keys does not retroactively
   reveal past order content. (X25519 ephemeral per-message key exchange, then
   ChaCha20-Poly1305.)

5. **Seizure resistance:** A seized server has zero forensic value to anyone
   not already holding the KEK in memory.

6. **No forensic value:** Even with full server access, an adversary learns
   nothing about user identity, order content, payment flows, or chat content
   without the user-cooperative decryption keys.

---

## Properties we explicitly do NOT defend against

1. **Endpoint compromise.** If the client device is compromised, all bets are
   off. The WASM client runs in the browser; the browser is the trust root.
   We do not attempt to defend against browser-side malware.

2. **User operational security failures.** Reusing an ed25519 key across orders,
   leaking the onion address to a non-Tor connection, etc.

3. **Quantum computers.** X25519, Ed25519, secp256k1 are all broken by
   sufficiently large quantum computers. Post-quantum primitives are not used.

4. **Side channels on the server host.** Cache-timing, Spectre, power analysis,
   etc. on the server's CPU. The application uses constant-time primitives
   where it matters, but physical access to the host is out of scope.

5. **Compromise of the Tor network itself.** If Tor is broken at the protocol
   level (e.g. by a nation-state-level adversary), the hidden service is
   deanonymized. This is a Tor-network problem, not a torMarketplace problem.

6. **Compromise of the upstream wallet/daemon software.** Bitcoin Core or
   monero-wallet-rpc being compromised is not in scope.

## Open issues

- Docker compose does not yet run the worker or ship built WASM to the frontend
- PostgreSQL path in `db/mod.rs` is stubbed; production uses SQLite
- Order blob format differs before and after worker payment updates
- No automated browser E2E tests
- External security audit before handling real funds
