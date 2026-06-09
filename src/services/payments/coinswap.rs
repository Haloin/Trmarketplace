use anyhow::{anyhow, Result};
use bitcoin::absolute::LockTime;
use bitcoin::blockdata::witness::Witness;
use bitcoin::psbt::Psbt;
use bitcoin::transaction::{OutPoint, Sequence, TxIn, TxOut, Transaction, Version};
use bitcoin::{Address, Amount, Network, ScriptBuf, Txid};
use secp256k1::Secp256k1;
use std::str::FromStr;

use crate::crypto::{escrow, stealth};
use crate::services::escrow::btc::{broadcast_psbt, finalize_stealth_psbt, sign_stealth_input};
use crate::services::payments::btc::BitcoinClient;

const DUST_SATS: u64 = 546;
const DEFAULT_FEE_SATS: u64 = 2000;

#[derive(Clone, Debug)]
pub struct CoinSwapConfig {
    /// Number of intermediate self-transfer hops before the final output.
    /// Each hop generates a fresh derived key and address.
    pub hop_count: usize,
    pub network: Network,
    /// Fixed fee (in satoshis) deducted per hop as miner fee.
    pub fee_sats_per_hop: u64,
}

impl Default for CoinSwapConfig {
    fn default() -> Self {
        Self {
            hop_count: 3,
            network: Network::Regtest,
            fee_sats_per_hop: DEFAULT_FEE_SATS,
        }
    }
}

/// Build a self-transfer PSBT that moves funds from `prev_address` to
/// `next_address`, deducting `fee_sats` as miner fee.
fn build_self_transfer_psbt(
    prev_txid: &str,
    prev_vout: u32,
    amount_sats: u64,
    prev_address: &str,
    next_address: &str,
    fee_sats: u64,
    network: Network,
) -> Result<Psbt> {
    let txid = Txid::from_str(prev_txid)
        .map_err(|e| anyhow!("Invalid prev_txid: {}", e))?;

    let next_addr = Address::from_str(next_address)?
        .require_network(network)
        .map_err(|e| anyhow!("Next address wrong network: {}", e))?;

    let prev_addr = Address::from_str(prev_address)?
        .require_network(network)
        .map_err(|e| anyhow!("Prev address wrong network: {}", e))?;

    let output_value = amount_sats.saturating_sub(fee_sats);
    if output_value < DUST_SATS {
        return Err(anyhow!(
            "Output {} sats below dust threshold after {} sats fee",
            output_value, fee_sats
        ));
    }

    let unsigned_tx = Transaction {
        version: Version::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(txid, prev_vout),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(output_value),
            script_pubkey: next_addr.script_pubkey(),
        }],
    };

    let mut psbt = Psbt::from_unsigned_tx(unsigned_tx)
        .map_err(|e| anyhow!("PSBT create: {}", e))?;
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: Amount::from_sat(amount_sats),
        script_pubkey: prev_addr.script_pubkey(),
    });
    Ok(psbt)
}

/// Derive the i-th hop key for a coinswap chain identified by `chain_seed`.
fn hop_key(master_seed: &[u8; 32], chain_seed: &[u8], i: usize) -> Result<secp256k1::SecretKey> {
    let seed = [b"coinswap:", chain_seed, &(i as u64).to_le_bytes()].concat();
    escrow::derive_order_key(master_seed, &seed)
}

/// Run a CoinSwap chain: N self-transfers that break the on-chain link
/// between the original UTXO and the final destination address.
///
/// Each intermediate hop uses a fresh key derived from `master_seed` +
/// `chain_seed`, creating a new P2WPKH address on each hop. Only the
/// last hop reveals where funds ultimately go.
///
/// Returns all transaction IDs in order (last one is the final settlement).
pub async fn run_coinswap_chain(
    rpc: &BitcoinClient,
    master_seed: &[u8; 32],
    chain_seed: &[u8],
    utxo_txid: &str,
    utxo_vout: u32,
    utxo_amount_sats: u64,
    utxo_address: &str,
    sk: &secp256k1::SecretKey,
    pk: &secp256k1::PublicKey,
    final_address: &str,
    config: &CoinSwapConfig,
) -> Result<Vec<String>> {
    let secp = Secp256k1::signing_only();
    let mut txids = Vec::with_capacity(config.hop_count + 1);

    let mut prev_txid = utxo_txid.to_string();
    let mut prev_vout = utxo_vout;
    let mut prev_amount = utxo_amount_sats;
    let mut prev_address = utxo_address.to_string();
    let mut current_sk = *sk;
    let mut current_pk = *pk;

    for hop in 0..config.hop_count {
        let fee = config.fee_sats_per_hop;
        let is_last = hop == config.hop_count - 1;

        let next_sk = if is_last {
            // generate but don't use — the signed output goes to final_address
            hop_key(master_seed, chain_seed, hop)?;
            None
        } else {
            Some(hop_key(master_seed, chain_seed, hop)?)
        };

        let next_address = match &next_sk {
            Some(sk) => {
                let pk = stealth::stealth_public_key(sk);
                stealth::stealth_p2wpkh_address(&pk, config.network).to_string()
            }
            None => {
                // ensure final_address is valid for the network
                Address::from_str(final_address)?
                    .require_network(config.network)
                    .map_err(|e| anyhow!("Final address wrong network: {}", e))?;
                final_address.to_string()
            }
        };

        let mut psbt = build_self_transfer_psbt(
            &prev_txid,
            prev_vout,
            prev_amount,
            &prev_address,
            &next_address,
            fee,
            config.network,
        )?;

        sign_stealth_input(&mut psbt, 0, &current_sk, &current_pk, prev_amount)?;

        let tx_hex = finalize_stealth_psbt(psbt)?;
        let new_txid = broadcast_psbt(&tx_hex, rpc).await?;
        txids.push(new_txid.clone());

        prev_txid = new_txid;
        prev_vout = 0;
        prev_amount = prev_amount.saturating_sub(fee);

        // Advance to next hop's key
        if let Some(sk) = next_sk {
            prev_address = next_address;
            current_sk = sk;
            current_pk = secp256k1::PublicKey::from_secret_key(&secp, &current_sk);
        }
    }

    Ok(txids)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::escrow::generate_master_seed;
    use crate::crypto::stealth::stealth_public_key;

    #[test]
    fn test_build_self_transfer_psbt_success() {
        let master_seed = generate_master_seed();
        let sk = escrow::derive_order_key(&master_seed, b"test-key").unwrap();
        let pk = stealth_public_key(&sk);
        let addr = stealth::stealth_p2wpkh_address(&pk, Network::Regtest);

        let next_seed = escrow::derive_order_key(&master_seed, b"next-key").unwrap();
        let next_pk = stealth_public_key(&next_seed);
        let next_addr = stealth::stealth_p2wpkh_address(&next_pk, Network::Regtest);

        let psbt = build_self_transfer_psbt(
            "0000000000000000000000000000000000000000000000000000000000000001",
            0,
            100_000,
            &addr.to_string(),
            &next_addr.to_string(),
            1000,
            Network::Regtest,
        )
        .unwrap();

        let tx = &psbt.unsigned_tx;
        assert_eq!(tx.input.len(), 1);
        assert_eq!(tx.output.len(), 1);
        assert_eq!(tx.output[0].value.to_sat(), 99_000);
    }

    #[test]
    fn test_build_self_transfer_below_dust() {
        let result = build_self_transfer_psbt(
            "0000000000000000000000000000000000000000000000000000000000000001",
            0,
            1000,
            "bcrt1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
            "bcrt1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
            2000,
            Network::Regtest,
        );
        assert!(result.is_err(), "below dust should be rejected");
    }

    #[test]
    fn test_hop_key_deterministic() {
        let master_seed = generate_master_seed();
        let k1 = hop_key(&master_seed, b"chain-1", 0).unwrap();
        let k2 = hop_key(&master_seed, b"chain-1", 0).unwrap();
        assert_eq!(k1[..], k2[..]);

        let k3 = hop_key(&master_seed, b"chain-1", 1).unwrap();
        assert_ne!(k1[..], k3[..], "different hop indices must differ");

        let k4 = hop_key(&master_seed, b"chain-2", 0).unwrap();
        assert_ne!(k1[..], k4[..], "different chain seeds must differ");
    }

    #[test]
    fn test_coinswap_config_default() {
        let cfg = CoinSwapConfig::default();
        assert_eq!(cfg.hop_count, 3);
        assert_eq!(cfg.network, Network::Regtest);
        assert_eq!(cfg.fee_sats_per_hop, DEFAULT_FEE_SATS);
    }
}
