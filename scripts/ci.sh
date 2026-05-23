#!/bin/sh
set -euo pipefail

echo "[*] Running CI checks..."

echo "[*] Format check..."
cargo fmt --check

echo "[*] Clippy..."
cargo clippy -- -D warnings

echo "[*] Building..."
cargo build --release

echo "[*] Testing..."
cargo test

echo "[*] Auditing dependencies..."
if command -v cargo-audit &>/dev/null; then
    cargo audit
else
    cargo install cargo-audit && cargo audit
fi

echo "[*] All checks passed."
