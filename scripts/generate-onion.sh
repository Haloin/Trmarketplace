#!/bin/sh
set -euo pipefail

# Generate .onion keys for the hidden service
SERVICE_DIR="${1:-./data/tor}"

mkdir -p "$SERVICE_DIR"

if [ -f "$SERVICE_DIR/hs_ed25519_secret_key" ]; then
    echo "[!] Tor keys already exist in $SERVICE_DIR"
    cat "$SERVICE_DIR/hostname" 2>/dev/null || echo "[!] No hostname file found"
    exit 0
fi

# Tor generates keys automatically on first run
# This script creates the torrc and Tor handles key generation
cat > "$SERVICE_DIR/torrc" << EOF
HiddenServiceDir $SERVICE_DIR
HiddenServicePort 80 127.0.0.1:9080
HiddenServicePort 443 127.0.0.1:9080
EOF

echo "[*] Config written to $SERVICE_DIR/torrc"
echo "[*] Start Tor to generate keys: tor -f $SERVICE_DIR/torrc"
echo "[*] The .onion address will be in $SERVICE_DIR/hostname after Tor starts"
