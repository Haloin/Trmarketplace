use anyhow::{anyhow, Result};
use bitcoin::absolute::LockTime;
use bitcoin::blockdata::witness::Witness;
use bitcoin::key::PublicKey as BtcPublicKey;
use bitcoin::psbt::Psbt;
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::transaction::{OutPoint, Sequence, TxIn, TxOut, Transaction, Version};
use bitcoin::{Address, Amount, Network, ScriptBuf, Txid};
use secp256k1::Secp256k1;
use std::str::FromStr;

use crate::services::payments::btc::BitcoinClient;

// ---------------------------------------------------------------------------
// Stealth (P2WPKH) settlement — single-key, no multi-sig
// ---------------------------------------------------------------------------

/// Build an unsigned PSBT for settling a stealth-funded order.
///
/// The input is the stealth P2WPKH UTXO; outputs go to seller + fee address.
/// Unlike the multi-sig path, only the stealth key holder needs to sign.
pub fn build_stealth_settlement_psbt(
    prev_txid: &str,
    prev_vout: u32,
    amount_sats: u64,
    stealth_address: &str,
    seller_address: &str,
    fee_address: &str,
    fee_percent: u64,
    network: Network,
) -> Result<Psbt> {
    let entires = [(prev_txid, prev_vout, amount_sats)];
    build_multi_utxo_settlement_psbt(&entires, stealth_address, seller_address, fee_address, fee_percent, network)
}

/// Build an unsigned PSBT from multiple UTXOs at the same stealth address.
///
/// Each entry is `(txid, vout, amount_sats)`. Total output = sum(inputs) * (1 - fee_percent/100).
/// All UTXOs must share the same `stealth_address` (same P2WPKH script).
pub fn build_multi_utxo_settlement_psbt(
    utxos: &[(&str, u32, u64)],
    stealth_address: &str,
    seller_address: &str,
    fee_address: &str,
    fee_percent: u64,
    network: Network,
) -> Result<Psbt> {
    if utxos.is_empty() {
        return Err(anyhow!("At least one UTXO required"));
    }

    let stealth_addr = Address::from_str(stealth_address)
        .map_err(|e| anyhow!("Invalid stealth address: {}", e))?
        .require_network(network)
        .map_err(|e| anyhow!("Stealth address wrong network: {}", e))?;
    let seller_addr = Address::from_str(seller_address)
        .map_err(|e| anyhow!("Invalid seller address: {}", e))?
        .require_network(network)
        .map_err(|e| anyhow!("Seller address wrong network: {}", e))?;
    let fee_addr = Address::from_str(fee_address)
        .map_err(|e| anyhow!("Invalid fee address: {}", e))?
        .require_network(network)
        .map_err(|e| anyhow!("Fee address wrong network: {}", e))?;

    let total_sats: u64 = utxos.iter().map(|(_, _, amt)| amt).sum();
    let seller_sats = total_sats * (100 - fee_percent) / 100;
    let fee_sats = total_sats - seller_sats;

    let mut inputs = Vec::with_capacity(utxos.len());
    for (txid_str, vout, _) in utxos {
        let txid = Txid::from_str(txid_str)
            .map_err(|e| anyhow!("Invalid txid {}: {}", txid_str, e))?;
        inputs.push(TxIn {
            previous_output: OutPoint::new(txid, *vout),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        });
    }

    let unsigned_tx = Transaction {
        version: Version::ONE,
        lock_time: LockTime::ZERO,
        input: inputs,
        output: vec![
            TxOut {
                value: Amount::from_sat(seller_sats),
                script_pubkey: seller_addr.script_pubkey(),
            },
            TxOut {
                value: Amount::from_sat(fee_sats),
                script_pubkey: fee_addr.script_pubkey(),
            },
        ],
    };

    let mut psbt = Psbt::from_unsigned_tx(unsigned_tx)
        .map_err(|e| anyhow!("Failed to create PSBT: {}", e))?;

    let script = stealth_addr.script_pubkey();
    for (i, (_, _, amt)) in utxos.iter().enumerate() {
        psbt.inputs[i].witness_utxo = Some(TxOut {
            value: Amount::from_sat(*amt),
            script_pubkey: script.clone(),
        });
    }
    Ok(psbt)
}

/// Sign a P2WPKH PSBT input with the stealth private key.
///
/// Computes the BIP143 sighash for the P2WPKH input and adds the ECDSA
/// signature to the PSBT's partial_sigs map.
pub fn sign_stealth_input(
    psbt: &mut Psbt,
    input_index: usize,
    stealth_sk: &secp256k1::SecretKey,
    stealth_pk: &secp256k1::PublicKey,
    amount_sats: u64,
) -> Result<()> {
    if input_index >= psbt.inputs.len() {
        return Err(anyhow!("Input index {} out of bounds", input_index));
    }

    // Verify the secret key matches the public key
    let secp = Secp256k1::signing_only();
    let expected_pk = secp256k1::PublicKey::from_secret_key(&secp, stealth_sk);
    if expected_pk != *stealth_pk {
        return Err(anyhow!("Stealth secret key does not match the provided public key"));
    }

    let witness_utxo = psbt.inputs[input_index]
        .witness_utxo
        .as_ref()
        .ok_or_else(|| anyhow!("PSBT input {} has no witness_utxo", input_index))?;

    // Verify the UTXO script is P2WPKH (native segwit v0)
    if !witness_utxo.script_pubkey.is_p2wpkh() {
        return Err(anyhow!("UTXO script is not P2WPKH"));
    }

    let sighash_type = EcdsaSighashType::All;

    let mut cache = SighashCache::new(&psbt.unsigned_tx);
    let sighash = cache
        .p2wpkh_signature_hash(
            input_index,
            &witness_utxo.script_pubkey,
            Amount::from_sat(amount_sats),
            sighash_type,
        )
        .map_err(|e| anyhow!("Failed to compute P2WPKH sighash: {}", e))?;

    let msg: secp256k1::Message = sighash.into();
    let sig = secp.sign_ecdsa(&msg, stealth_sk);

    let btc_pk = BtcPublicKey::new(*stealth_pk);
    let btc_sig = bitcoin::ecdsa::Signature {
        signature: sig,
        sighash_type,
    };
    psbt.inputs[input_index]
        .partial_sigs
        .insert(btc_pk, btc_sig);

    Ok(())
}

/// Finalize a P2WPKH PSBT by constructing the witness stack for each input and extracting the tx.
///
/// Each input must have exactly one signature in `partial_sigs`. The witness stack for
/// P2WPKH is: `[signature, pubkey]`.
pub fn finalize_stealth_psbt(psbt: Psbt) -> Result<String> {
    if psbt.inputs.is_empty() {
        return Err(anyhow!("PSBT has no inputs"));
    }

    let mut psbt = psbt;
    for i in 0..psbt.inputs.len() {
        let input = &psbt.inputs[i];

        if input.witness_script.is_some() {
            return Err(anyhow!("Input {}: P2WPKH must not have witness_script set", i));
        }

        if input.partial_sigs.is_empty() {
            return Err(anyhow!("Input {} has no signatures", i));
        }

        let (pk, sig) = input.partial_sigs.iter().next()
            .ok_or_else(|| anyhow!("Input {}: no signatures found", i))?;

        let mut witness = Witness::new();
        witness.push(sig.to_vec());
        witness.push(pk.inner.serialize());
        psbt.inputs[i].final_script_witness = Some(witness);
    }

    let tx = psbt
        .extract_tx()
        .map_err(|e| anyhow!("PSBT extract failed: {}", e))?;
    let tx_hex = bitcoin::consensus::encode::serialize_hex(&tx);
    Ok(tx_hex)
}

/// Broadcast a raw transaction via Bitcoin Core RPC.
pub async fn broadcast_psbt(tx_hex: &str, rpc_client: &BitcoinClient) -> Result<String> {
    let result: serde_json::Value = rpc_client
        .rpc_call("sendrawtransaction", serde_json::json!([tx_hex]))
        .await?;
    let txid = result
        .as_str()
        .ok_or_else(|| anyhow!("sendrawtransaction returned non-string"))?
        .to_string();
    Ok(txid)
}

/// Import a P2WSH multi-sig address as watch-only in Bitcoin Core.
///
/// Uses `importmulti` RPC with the witness script and a label so
/// Bitcoin Core can detect incoming payments. The `label` should
/// follow the `"order:<order_id>"` pattern (matches payment poller).
pub async fn import_multisig_watchonly(
    address: &str,
    witness_script_hex: &str,
    label: &str,
    rpc_client: &BitcoinClient,
) -> Result<()> {
    let params = serde_json::json!([{
        "scriptPubKey": {
            "address": address,
        },
        "witnessscript": witness_script_hex,
        "label": label,
        "watchonly": true,
        "internal": false,
        "timestamp": "now",
    }, {
        "rescan": false,
    }]);

    let _: serde_json::Value = rpc_client
        .rpc_call("importmulti", params)
        .await?;
    Ok(())
}

/// Import a plain address as watch-only in Bitcoin Core (P2PKH, P2WPKH, etc.).
///
/// No witness_script needed — simple address-based import.
/// Uses `importmulti` RPC. The `label` should follow `"order:<order_id>"`.
pub async fn import_address_watchonly(
    address: &str,
    label: &str,
    rpc_client: &BitcoinClient,
) -> Result<()> {
    let params = serde_json::json!([{
        "scriptPubKey": {
            "address": address,
        },
        "label": label,
        "watchonly": true,
        "internal": false,
        "timestamp": "now",
    }, {
        "rescan": false,
    }]);

    let _: serde_json::Value = rpc_client
        .rpc_call("importmulti", params)
        .await?;
    Ok(())
}

/// Parse a hex-encoded compressed secp256k1 public key (33 bytes).
pub fn parse_secp_pubkey(hex_str: &str) -> Result<secp256k1::PublicKey> {
    let bytes = hex::decode(hex_str)
        .map_err(|e| anyhow!("Invalid hex pubkey: {}", e))?;
    secp256k1::PublicKey::from_slice(&bytes)
        .map_err(|e| anyhow!("Invalid secp256k1 pubkey: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::key::CompressedPublicKey;
    use secp256k1::{SecretKey, Secp256k1};

    fn generate_test_keypair(secp: &Secp256k1<secp256k1::All>) -> (SecretKey, secp256k1::PublicKey) {
        let sk = SecretKey::new(&mut rand::rngs::OsRng);
        let pk = secp256k1::PublicKey::from_secret_key(secp, &sk);
        (sk, pk)
    }



    #[test]
    fn test_parse_secp_pubkey_roundtrip() {
        let secp = Secp256k1::new();
        let (_sk, pk) = generate_test_keypair(&secp);
        let hex_str = hex::encode(pk.serialize());
        let parsed = parse_secp_pubkey(&hex_str).unwrap();
        assert_eq!(pk, parsed);
    }

    #[test]
    fn test_parse_secp_pubkey_invalid() {
        assert!(parse_secp_pubkey("not-hex").is_err());
        assert!(parse_secp_pubkey("aabb").is_err()); // too short
        assert!(parse_secp_pubkey("").is_err());
    }

    // ------------------------------------------------------------------
    // Stealth / P2WPKH settlement tests
    // ------------------------------------------------------------------

    #[test]
    fn test_build_stealth_settlement_psbt() {
        let stealth_addr = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";
        let seller_addr = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";
        let fee_addr = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";

        let psbt = build_stealth_settlement_psbt(
            "0000000000000000000000000000000000000000000000000000000000000001",
            0,
            100_000_000,
            stealth_addr,
            seller_addr,
            fee_addr,
            4,
            Network::Bitcoin,
        )
        .unwrap();

        assert_eq!(psbt.inputs.len(), 1);
        assert_eq!(psbt.outputs.len(), 2);
        assert!(psbt.inputs[0].witness_utxo.is_some());
        assert!(psbt.inputs[0].witness_script.is_none());
    }

    #[test]
    fn test_full_stealth_settlement_lifecycle() {
        let secp = Secp256k1::new();
        let (stealth_sk, stealth_pk) = generate_test_keypair(&secp);
        let compressed = CompressedPublicKey(stealth_pk);
        let stealth_addr = Address::p2wpkh(&compressed, Network::Regtest);

        let seller_addr = Address::p2pkh(BtcPublicKey::new(stealth_pk), Network::Regtest);

        let mut psbt = build_stealth_settlement_psbt(
            "0000000000000000000000000000000000000000000000000000000000000001",
            0,
            100_000_000,
            &stealth_addr.to_string(),
            &seller_addr.to_string(),
            &seller_addr.to_string(),
            4,
            Network::Regtest,
        )
        .unwrap();

        // Sign with the stealth key
        sign_stealth_input(&mut psbt, 0, &stealth_sk, &stealth_pk, 100_000_000).unwrap();
        assert_eq!(psbt.inputs[0].partial_sigs.len(), 1);

        let tx_hex = finalize_stealth_psbt(psbt).unwrap();
        assert!(!tx_hex.is_empty());
        assert!(tx_hex.len() > 100);

        let decoded_tx: Transaction =
            bitcoin::consensus::encode::deserialize(&hex::decode(&tx_hex).unwrap()).unwrap();
        assert_eq!(decoded_tx.input.len(), 1);
        assert_eq!(decoded_tx.output.len(), 2);
        assert!(!decoded_tx.input[0].witness.is_empty());
    }

    #[test]
    fn test_stealth_settlement_fee_split() {
        let stealth_addr = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";
        let seller_addr = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";

        // 1 BTC, 4% fee -> 0.96 BTC seller, 0.04 BTC fee
        let psbt = build_stealth_settlement_psbt(
            "0000000000000000000000000000000000000000000000000000000000000001",
            0,
            100_000_000,
            stealth_addr,
            seller_addr,
            seller_addr,
            4,
            Network::Bitcoin,
        )
        .unwrap();

        let tx = &psbt.unsigned_tx;
        assert_eq!(tx.output[0].value.to_sat(), 96_000_000);
        assert_eq!(tx.output[1].value.to_sat(), 4_000_000);
    }

    #[test]
    fn test_sign_with_wrong_key_produces_invalid_sig() {
        let secp = Secp256k1::new();
        let (_stealth_sk, stealth_pk) = generate_test_keypair(&secp);
        let (wrong_sk, _wrong_pk) = generate_test_keypair(&secp);
        let compressed = CompressedPublicKey(stealth_pk);
        let stealth_addr = Address::p2wpkh(&compressed, Network::Regtest);
        let dest = Address::p2pkh(BtcPublicKey::new(stealth_pk), Network::Regtest);

        let mut psbt = build_stealth_settlement_psbt(
            "0000000000000000000000000000000000000000000000000000000000000001",
            0,
            100_000_000,
            &stealth_addr.to_string(),
            &dest.to_string(),
            &dest.to_string(),
            4,
            Network::Regtest,
        )
        .unwrap();

        // Sign with wrong key (sk doesn't match pk) must be rejected
        let result = sign_stealth_input(&mut psbt, 0, &wrong_sk, &stealth_pk, 100_000_000);
        assert!(result.is_err(), "Mismatched keypair must be rejected");
    }

    #[test]
    fn test_stealth_settlement_wrong_input_index() {
        let secp = Secp256k1::new();
        let (sk, pk) = generate_test_keypair(&secp);
        let stealth_addr = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";

        let mut psbt = build_stealth_settlement_psbt(
            "0000000000000000000000000000000000000000000000000000000000000001",
            0, 100_000_000,
            stealth_addr, stealth_addr, stealth_addr, 4, Network::Bitcoin,
        )
        .unwrap();

        let result = sign_stealth_input(&mut psbt, 99, &sk, &pk, 100_000_000);
        assert!(result.is_err());
    }
}
