#!/bin/sh
# Start API + worker together for local development.
# Worker writes data/dev_worker_payment_pubkey.hex; API picks it up automatically.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [ ! -f frontend/wasm/tor_marketplace_wasm.js ]; then
  echo "[*] Building WASM client..."
  command -v wasm-pack >/dev/null 2>&1 || { echo "[!] Install wasm-pack: cargo install wasm-pack"; exit 1; }
  wasm-pack build wasm --target web --out-dir pkg
  mkdir -p frontend/wasm
  cp wasm/pkg/* frontend/wasm/
  echo "[+] WASM built"
fi

mkdir -p data
export EPHEMERAL_KEK=1
export EPHEMERAL_WORKER_KEY=1
export SERVER_SECRET="${SERVER_SECRET:-dev_secret_32_bytes_minimum_length!!}"

PUBKEY_FILE="$ROOT/data/dev_worker_payment_pubkey.hex"
rm -f "$PUBKEY_FILE"

echo "[*] Starting worker (background)..."
cargo run --features worker --bin tor-marketplace-worker >>"$ROOT/data/worker.log" 2>&1 &
WORKER_PID=$!

cleanup() {
  echo "[*] Stopping worker (pid $WORKER_PID)..."
  kill "$WORKER_PID" 2>/dev/null || true
  wait "$WORKER_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

i=0
while [ ! -f "$PUBKEY_FILE" ]; do
  i=$((i + 1))
  if [ "$i" -gt 240 ]; then
    echo "[!] Timeout waiting for worker pubkey"
    tail -30 "$ROOT/data/worker.log" 2>/dev/null || true
    exit 1
  fi
  if ! kill -0 "$WORKER_PID" 2>/dev/null; then
    echo "[!] Worker exited early"
    tail -40 "$ROOT/data/worker.log" 2>/dev/null || true
    exit 1
  fi
  sleep 0.5
done

export WORKER_PAYMENT_PUBKEY_HEX="$(tr -d '\n\r' < "$PUBKEY_FILE")"
echo "[+] Worker pubkey synced"
echo "[*] Open http://127.0.0.1:9080 after API starts"
echo "[*] Worker log: data/worker.log"
echo "[*] Starting API (Ctrl+C stops both)..."

cargo run
