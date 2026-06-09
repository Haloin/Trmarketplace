//! Per-order P2WPKH stealth addresses via ECDH (minimal BIP47-style derivation).

use anyhow::{anyhow, Result};
use bitcoin::key::CompressedPublicKey;
use bitcoin::{Address, Network};
use secp256k1::ecdh::SharedSecret;
use secp256k1::{PublicKey, SecretKey};
use sha2::{Digest, Sha256};

use crate::services::escrow::btc::parse_secp_pubkey;

/// Derive a stealth private key using ECDH between two parties.
///
/// ECDH(our_sk, their_pk) = ECDH(their_sk, our_pk) = our_sk * their_sk * G
/// Both parties derive the same shared secret. The stealth private key is
/// SHA256(shared_secret || domain_separator || order_id).
///
/// This means:
///   - Buyer can derive: knows buyer_sk, seller_pk (from listing), order_id
///   - Seller can derive: knows seller_sk, buyer_pk (from order data), order_id
///   - No on-chain link between buyer, seller, and the funding address
pub fn derive_stealth_private_key(
    their_pk: &PublicKey,
    our_sk: &SecretKey,
    order_id: &[u8],
) -> Result<SecretKey> {
    let shared = SharedSecret::new(their_pk, our_sk);
    let tweak = Sha256::new()
        .chain_update(shared.secret_bytes())
        .chain_update(b"stealth-key-v1")
        .chain_update(order_id)
        .finalize();
    SecretKey::from_slice(&tweak)
        .map_err(|e| anyhow!("invalid stealth key derivation: {e}"))
}

/// Derive a stealth private key from seller's perspective (same result).
/// Alias for clarity: seller calls this with (seller_pk, buyer_sk, order_id).
pub fn derive_stealth_private_key_seller(
    their_pk: &PublicKey,
    our_sk: &SecretKey,
    order_id: &[u8],
) -> Result<SecretKey> {
    derive_stealth_private_key(their_pk, our_sk, order_id)
}

/// Compute the stealth public key from a stealth private key.
pub fn stealth_public_key(stealth_sk: &SecretKey) -> PublicKey {
    use secp256k1::Secp256k1;
    let secp = Secp256k1::new();
    PublicKey::from_secret_key(&secp, stealth_sk)
}

/// Create a P2WPKH address from a stealth public key.
/// This is a normal-looking Bitcoin address — indistinguishable from any other
/// P2WPKH address on-chain.
pub fn stealth_p2wpkh_address(stealth_pk: &PublicKey, network: Network) -> Address {
    let compressed = CompressedPublicKey(*stealth_pk);
    Address::p2wpkh(&compressed, network)
}

/// Parse a hex-encoded secp256k1 public key and convert to bitcoin Address.
/// Convenience function for creating stealth addresses from hex strings.
pub fn stealth_address_from_hex(
    buyer_pk_hex: &str,
    seller_sk_hex: &str,
    order_id: &[u8],
    network: Network,
) -> Result<Address> {
    let buyer_pk = parse_secp_pubkey(buyer_pk_hex)?;
    let seller_sk_bytes = hex::decode(seller_sk_hex)
        .map_err(|e| anyhow!("invalid seller sk hex: {e}"))?;
    let seller_sk = SecretKey::from_slice(&seller_sk_bytes)
        .map_err(|e| anyhow!("invalid seller secret key: {e}"))?;
    let stealth_sk = derive_stealth_private_key(&buyer_pk, &seller_sk, order_id)?;
    let stealth_pk = stealth_public_key(&stealth_sk);
    Ok(stealth_p2wpkh_address(&stealth_pk, network))
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::Secp256k1;

    #[test]
    fn test_derivation_symmetry() {
        let secp = Secp256k1::new();
        let (buyer_sk, buyer_pk) = secp.generate_keypair(&mut rand::rngs::OsRng);
        let (seller_sk, seller_pk) = secp.generate_keypair(&mut rand::rngs::OsRng);

        let stealth_sk_buyer = derive_stealth_private_key(&seller_pk, &buyer_sk, b"order-1").unwrap();
        let stealth_sk_seller = derive_stealth_private_key(&buyer_pk, &seller_sk, b"order-1").unwrap();

        assert_eq!(
            stealth_sk_buyer.secret_bytes(),
            stealth_sk_seller.secret_bytes(),
        );
    }

    #[test]
    fn test_different_orders_different_keys() {
        let secp = Secp256k1::new();
        let (_buyer_sk, buyer_pk) = secp.generate_keypair(&mut rand::rngs::OsRng);
        let (seller_sk, _) = secp.generate_keypair(&mut rand::rngs::OsRng);

        let sk1 = derive_stealth_private_key(&buyer_pk, &seller_sk, b"order-1").unwrap();
        let sk2 = derive_stealth_private_key(&buyer_pk, &seller_sk, b"order-2").unwrap();

        assert_ne!(sk1.secret_bytes(), sk2.secret_bytes());
    }

    #[test]
    fn test_different_parties_different() {
        let secp = Secp256k1::new();
        let (_sk_a, pk_a) = secp.generate_keypair(&mut rand::rngs::OsRng);
        let (_, pk_b) = secp.generate_keypair(&mut rand::rngs::OsRng);
        let (seller_sk, _) = secp.generate_keypair(&mut rand::rngs::OsRng);

        let sk1 = derive_stealth_private_key(&pk_a, &seller_sk, b"order-1").unwrap();
        let sk2 = derive_stealth_private_key(&pk_b, &seller_sk, b"order-1").unwrap();

        assert_ne!(sk1.secret_bytes(), sk2.secret_bytes());
    }

    #[test]
    fn test_p2wpkh_address_looks_normal() {
        let secp = Secp256k1::new();
        let (_buyer_sk, buyer_pk) = secp.generate_keypair(&mut rand::rngs::OsRng);
        let (seller_sk, _) = secp.generate_keypair(&mut rand::rngs::OsRng);

        let stealth_sk = derive_stealth_private_key(&buyer_pk, &seller_sk, b"test").unwrap();
        let stealth_pk = stealth_public_key(&stealth_sk);
        let addr = stealth_p2wpkh_address(&stealth_pk, Network::Bitcoin);

        assert!(addr.to_string().starts_with("bc1q"), "got: {}", addr);
    }

    #[test]
    fn test_stealth_address_from_hex() {
        let secp = Secp256k1::new();
        let (_buyer_sk, buyer_pk) = secp.generate_keypair(&mut rand::rngs::OsRng);
        let (seller_sk, _) = secp.generate_keypair(&mut rand::rngs::OsRng);

        let hex_pk = hex::encode(buyer_pk.serialize());
        let hex_sk = hex::encode(seller_sk.secret_bytes());

        let addr = stealth_address_from_hex(&hex_pk, &hex_sk, b"test", Network::Bitcoin).unwrap();
        assert!(addr.to_string().starts_with("bc1q"));
    }
}
