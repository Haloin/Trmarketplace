#!/bin/sh
# SECURITY: Encrypted backup script for Tor Marketplace
# All backups MUST be encrypted - never create unencrypted backups
set -euo pipefail

BACKUP_DIR="${1:-./backups}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
DATA_DIR="./data"

mkdir -p "$BACKUP_DIR"

echo "[*] Starting encrypted backup..."

if [ -f "$DATA_DIR/marketplace.db" ]; then
    # SECURITY: Require encryption - fail if not configured
    if [ -z "${BACKUP_PUBKEY:-}" ]; then
        echo "[!] ERROR: BACKUP_PUBKEY not set. Cannot create unencrypted backup."
        echo "[!] Set BACKUP_PUBKEY environment variable with recipient key ID."
        echo "[!] Example: export BACKUP_PUBKEY='0x12345678'"
        exit 1
    fi
    
    # Create encrypted backup via temp file (then shred)
    TEMP_BACKUP=$(mktemp)
    sqlite3 "$DATA_DIR/marketplace.db" ".backup $TEMP_BACKUP"
    gpg --encrypt --recipient "$BACKUP_PUBKEY" \
        --output "$BACKUP_DIR/marketplace_$TIMESTAMP.db.gpg" "$TEMP_BACKUP"
    shred -u "$TEMP_BACKUP"
    
    echo "[*] Encrypted backup: $BACKUP_DIR/marketplace_$TIMESTAMP.db.gpg"
    
    # Verify encryption
    if gpg --list-packets "$BACKUP_DIR/marketplace_$TIMESTAMP.db.gpg" 2>/dev/null; then
        echo "[*] Encryption verified"
    else
        echo "[!] WARNING: Backup may not be encrypted properly!"
        exit 1
    fi
    
else
    echo "[!] No database found at $DATA_DIR/marketplace.db"
    exit 1
fi

echo "[*] Backup complete to $BACKUP_DIR/"