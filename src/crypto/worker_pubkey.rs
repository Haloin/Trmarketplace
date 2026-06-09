//! Worker payment X25519 pubkey derivation and dev pubkey file sync.

use std::path::{Path, PathBuf};

pub const DEV_PUBKEY_FILENAME: &str = "dev_worker_payment_pubkey.hex";

/// Derive the X25519 public key clients use to encrypt order blobs for the worker.
pub fn payment_pubkey_hex_from_worker_key(worker_key: &[u8; 32]) -> String {
    use x25519_dalek::{PublicKey, StaticSecret};
    let payment_sk = crate::crypto::escrow::derive_domain_key(worker_key, "payment-decrypt");
    let payment_pk = PublicKey::from(&StaticSecret::from(payment_sk));
    hex::encode(payment_pk.as_bytes())
}

pub fn dev_pubkey_path(data_dir: &Path) -> PathBuf {
    data_dir.join(DEV_PUBKEY_FILENAME)
}

/// Write pubkey hex to the dev sync file (development only).
pub fn write_dev_pubkey_file(data_dir: &Path, pubkey_hex: &str) -> std::io::Result<()> {
    std::fs::create_dir_all(data_dir)?;
    std::fs::write(dev_pubkey_path(data_dir), pubkey_hex.trim())
}

/// Read pubkey from dev sync file if present and well-formed (64 hex chars).
pub fn read_dev_pubkey_file(data_dir: &Path) -> Option<String> {
    let contents = std::fs::read_to_string(dev_pubkey_path(data_dir)).ok()?;
    let trimmed = contents.trim();
    if trimmed.len() == 64 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        Some(trimmed.to_ascii_lowercase())
    } else {
        None
    }
}

/// Resolve worker payment pubkey: env → config → dev file.
pub fn resolve_worker_payment_pubkey(
    data_dir: &Path,
    config_hex: Option<&str>,
) -> Option<String> {
    if let Ok(v) = std::env::var("WORKER_PAYMENT_PUBKEY_HEX") {
        let t = v.trim();
        if !t.is_empty() {
            return Some(t.to_string());
        }
    }
    if let Some(h) = config_hex {
        let t = h.trim();
        if !t.is_empty() {
            return Some(t.to_string());
        }
    }
    read_dev_pubkey_file(data_dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payment_pubkey_deterministic() {
        let key = [42u8; 32];
        let a = payment_pubkey_hex_from_worker_key(&key);
        let b = payment_pubkey_hex_from_worker_key(&key);
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn test_dev_pubkey_file_roundtrip() {
        let dir = std::env::temp_dir().join(format!("tor_mkt_dev_pk_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let hex = "a".repeat(64);
        write_dev_pubkey_file(&dir, &hex).unwrap();
        assert_eq!(read_dev_pubkey_file(&dir).as_deref(), Some(hex.as_str()));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
