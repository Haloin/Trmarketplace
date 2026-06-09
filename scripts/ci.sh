#!/bin/sh
set -euo pipefail

echo "[*] Running CI checks..."

echo "[*] Format check..."
cargo fmt --check

echo "[*] Clippy..."
cargo clippy -- -D warnings

echo "[*] Building server..."
cargo build --release

echo "[*] Building WASM client..."
if ! command -v wasm-pack &>/dev/null; then
    echo "[!] Installing wasm-pack..."
    cargo install wasm-pack
fi
rustup target add wasm32-unknown-unknown
wasm-pack build wasm --target no-modules --out-dir pkg --no-opt
mkdir -p frontend/wasm
cp wasm/pkg/* frontend/wasm/

echo "[*] Testing..."
cargo test

echo "[*] Auditing dependencies..."
if command -v cargo-audit &>/dev/null; then
    cargo audit
else
    cargo install cargo-audit && cargo audit
fi

echo "[*] All checks passed."
