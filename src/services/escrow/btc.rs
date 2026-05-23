use anyhow::{anyhow, Result};
use bitcoin::absolute::LockTime;
use bitcoin::blockdata::witness::Witness;
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::key::PublicKey as BtcPublicKey;
use bitcoin::opcodes::all::{OP_CHECKMULTISIG, OP_PUSHNUM_2, OP_PUSHNUM_3};
use bitcoin::psbt::Psbt;
use bitcoin::script::{Builder, ScriptBuf};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::transaction::{OutPoint, Sequence, TxIn, TxOut, Transaction, Version};
use bitcoin::{Address, Amount, Network, Txid};
use secp256k1::Secp256k1;
use std::str::FromStr;

use crate::services::payments::btc::BitcoinClient;

/// Parameters returned after creating a 2-of-3 P2WSH multi-sig address.
pub struct MultiSigParams {
    pub address: String,
    pub redeem_script_hex: String,
}

/// Create a 2-of-3 P2WSH multi-sig address from three secp256k1 public keys.
///
/// Builds a CHECKMULTISIG redeem script and wraps it in a P2WSH address.
/// Pure Rust — no RPC calls, fully testable.
pub fn create_multisig_p2wsh(
    buyer_pk: &secp256k1::PublicKey,
    seller_pk: &secp256k1::PublicKey,
    owner_pk: &secp256k1::PublicKey,
    network: Network,
) -> Result<MultiSigParams> {
    let btc_pk1 = BtcPublicKey::new(*buyer_pk);
    let btc_pk2 = BtcPublicKey::new(*seller_pk);
    let btc_pk3 = BtcPublicKey::new(*owner_pk);

    // Sort public keys lexicographically (BIP67)
    let mut keys = [btc_pk1, btc_pk2, btc_pk3];
    keys.sort();

    let redeem = Builder::new()
        .push_opcode(OP_PUSHNUM_2)
        .push_key(&keys[0])
        .push_key(&keys[1])
        .push_key(&keys[2])
        .push_opcode(OP_PUSHNUM_3)
        .push_opcode(OP_CHECKMULTISIG)
        .into_script();

    let address = Address::p2wsh(&redeem, network);

    Ok(MultiSigParams {
        address: address.to_string(),
        redeem_script_hex: serialize_hex(&redeem),
    })
}

/// Build an unsigned PSBT for releasing funds to seller + fee address.
///
/// Calculates fee split: seller gets `floor(amount * (100 - fee_percent) / 100)`,
/// fee address gets the remainder.
pub fn build_release_psbt(
    prev_txid: &str,
    prev_vout: u32,
    amount_sats: u64,
    redeem_script: &ScriptBuf,
    multisig_address: &str,
    seller_address: &str,
    fee_address: &str,
    fee_percent: u64,
    network: Network,
) -> Result<Psbt> {
    let txid = Txid::from_str(prev_txid)
        .map_err(|e| anyhow!("Invalid prev_txid: {}", e))?;
    let ms_addr = Address::from_str(multisig_address)
        .map_err(|e| anyhow!("Invalid multisig address: {}", e))?
        .require_network(network)
        .map_err(|e| anyhow!("Multisig address wrong network: {}", e))?;
    let seller_addr = Address::from_str(seller_address)
        .map_err(|e| anyhow!("Invalid seller address: {}", e))?
        .require_network(network)
        .map_err(|e| anyhow!("Seller address wrong network: {}", e))?;
    let fee_addr = Address::from_str(fee_address)
        .map_err(|e| anyhow!("Invalid fee address: {}", e))?
        .require_network(network)
        .map_err(|e| anyhow!("Fee address wrong network: {}", e))?;

    let seller_sats = amount_sats * (100 - fee_percent) / 100;
    let fee_sats = amount_sats - seller_sats;

    let unsigned_tx = Transaction {
        version: Version::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(txid, prev_vout),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        }],
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

    psbt.inputs[0].witness_script = Some(redeem_script.clone());
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: Amount::from_sat(amount_sats),
        script_pubkey: ms_addr.script_pubkey(),
    });
    Ok(psbt)
}

/// Build an unsigned PSBT for refunding funds back to the buyer.
pub fn build_refund_psbt(
    prev_txid: &str,
    prev_vout: u32,
    amount_sats: u64,
    redeem_script: &ScriptBuf,
    multisig_address: &str,
    buyer_address: &str,
    network: Network,
) -> Result<Psbt> {
    let txid = Txid::from_str(prev_txid)
        .map_err(|e| anyhow!("Invalid prev_txid: {}", e))?;
    let ms_addr = Address::from_str(multisig_address)
        .map_err(|e| anyhow!("Invalid multisig address: {}", e))?
        .require_network(network)
        .map_err(|e| anyhow!("Multisig address wrong network: {}", e))?;
    let buyer_addr = Address::from_str(buyer_address)
        .map_err(|e| anyhow!("Invalid buyer address: {}", e))?
        .require_network(network)
        .map_err(|e| anyhow!("Buyer address wrong network: {}", e))?;

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
            value: Amount::from_sat(amount_sats),
            script_pubkey: buyer_addr.script_pubkey(),
        }],
    };

    let mut psbt = Psbt::from_unsigned_tx(unsigned_tx)
        .map_err(|e| anyhow!("Failed to create PSBT: {}", e))?;

    psbt.inputs[0].witness_script = Some(redeem_script.clone());
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: Amount::from_sat(amount_sats),
        script_pubkey: ms_addr.script_pubkey(),
    });
    Ok(psbt)
}

/// Sign a specific input of a PSBT with the owner's secp256k1 key.
///
/// Computes the P2WSH sighash and adds the ECDSA signature
/// to the PSBT input's partial_sigs map.
pub fn owner_sign_psbt_input(
    psbt: &mut Psbt,
    input_index: usize,
    owner_sk: &secp256k1::SecretKey,
    owner_pk: &secp256k1::PublicKey,
    amount_sats: u64,
) -> Result<()> {
    if input_index >= psbt.inputs.len() {
        return Err(anyhow!("Input index {} out of bounds", input_index));
    }
    if psbt.inputs[input_index].witness_script.is_none() {
        return Err(anyhow!("PSBT input {} has no witness_script set", input_index));
    }

    let witness_script = psbt.inputs[input_index].witness_script.as_ref().unwrap();
    let secp = Secp256k1::signing_only();
    let sighash_type = EcdsaSighashType::All;

    let mut cache = SighashCache::new(&psbt.unsigned_tx);
    let sighash = cache
        .p2wsh_signature_hash(input_index, witness_script, Amount::from_sat(amount_sats), sighash_type)
        .map_err(|e| anyhow!("Failed to compute sighash: {}", e))?;

    let msg: secp256k1::Message = sighash.into();
    let sig = secp.sign_ecdsa(&msg, owner_sk);

    let btc_pk = BtcPublicKey::new(*owner_pk);
    let btc_sig = bitcoin::ecdsa::Signature {
        signature: sig,
        sighash_type,
    };
    psbt.inputs[input_index]
        .partial_sigs
        .insert(btc_pk, btc_sig);

    Ok(())
}

/// Finalize a PSBT by constructing the P2WSH witness and extracting the transaction.
///
/// Call this after at least 2 signatures have been added to `partial_sigs`.
/// Builds the witness stack `[0, sig1, sig2, witness_script]` for P2WSH multi-sig.
pub fn finalize_psbt(psbt: Psbt) -> Result<String> {
    if psbt.inputs.is_empty() {
        return Err(anyhow!("PSBT has no inputs"));
    }
    let input = &psbt.inputs[0];
    let witness_script = input
        .witness_script
        .as_ref()
        .ok_or_else(|| anyhow!("No witness_script on PSBT input"))?;

    let sig_count = input.partial_sigs.len();
    if sig_count < 2 {
        return Err(anyhow!(
            "Need at least 2 signatures for 2-of-3 multi-sig, got {}",
            sig_count
        ));
    }

    // Collect sigs ordered by their pubkey (BIP67 = lexicographic sort)
    let mut sigs: Vec<_> = input.partial_sigs.iter().collect();
    sigs.sort_by(|(pk_a, _), (pk_b, _)| pk_a.cmp(pk_b));

    let mut witness = Witness::new();
    witness.push(&[0u8]);
    for (_, sig) in &sigs {
        witness.push(sig.to_vec());
    }
    witness.push(witness_script.as_bytes());

    let mut psbt = psbt;
    psbt.inputs[0].final_script_witness = Some(witness);

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
    use secp256k1::{SecretKey, Secp256k1};

    fn generate_test_keypair(secp: &Secp256k1<secp256k1::All>) -> (SecretKey, secp256k1::PublicKey) {
        let sk = SecretKey::new(&mut rand::rngs::OsRng);
        let pk = secp256k1::PublicKey::from_secret_key(secp, &sk);
        (sk, pk)
    }

    #[test]
    fn test_create_multisig_p2wsh() {
        let secp = Secp256k1::new();
        let (_, pk1) = generate_test_keypair(&secp);
        let (_, pk2) = generate_test_keypair(&secp);
        let (_, pk3) = generate_test_keypair(&secp);

        let params = create_multisig_p2wsh(&pk1, &pk2, &pk3, Network::Bitcoin).unwrap();
        assert!(params.address.starts_with("bc1q") || params.address.starts_with("bc1p"));
        assert!(!params.redeem_script_hex.is_empty());
    }

    #[test]
    fn test_multisig_address_deterministic() {
        let secp = Secp256k1::new();
        let (_, pk1) = generate_test_keypair(&secp);
        let (_, pk2) = generate_test_keypair(&secp);
        let (_, pk3) = generate_test_keypair(&secp);

        let a1 = create_multisig_p2wsh(&pk1, &pk2, &pk3, Network::Bitcoin).unwrap();
        let a2 = create_multisig_p2wsh(&pk1, &pk2, &pk3, Network::Bitcoin).unwrap();
        assert_eq!(a1.address, a2.address);
        assert_eq!(a1.redeem_script_hex, a2.redeem_script_hex);
    }

    #[test]
    fn test_build_release_psbt() {
        let secp = Secp256k1::new();
        let (_, pk1) = generate_test_keypair(&secp);
        let (_, pk2) = generate_test_keypair(&secp);
        let (_, pk3) = generate_test_keypair(&secp);

        let ms = create_multisig_p2wsh(&pk1, &pk2, &pk3, Network::Bitcoin).unwrap();
        let redeem = ScriptBuf::from_hex(&ms.redeem_script_hex).unwrap();

        let seller_addr = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";
        let fee_addr = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";

        let psbt = build_release_psbt(
            "0000000000000000000000000000000000000000000000000000000000000001",
            0,
            100_000_000,
            &redeem,
            &ms.address,
            seller_addr,
            fee_addr,
            4,
            Network::Bitcoin,
        )
        .unwrap();

        assert_eq!(psbt.inputs.len(), 1);
        assert_eq!(psbt.outputs.len(), 2);
        assert!(psbt.inputs[0].witness_script.is_some());
    }

    #[test]
    fn test_build_refund_psbt() {
        let secp = Secp256k1::new();
        let (_, pk1) = generate_test_keypair(&secp);
        let (_, pk2) = generate_test_keypair(&secp);
        let (_, pk3) = generate_test_keypair(&secp);

        let ms = create_multisig_p2wsh(&pk1, &pk2, &pk3, Network::Bitcoin).unwrap();
        let redeem = ScriptBuf::from_hex(&ms.redeem_script_hex).unwrap();

        let buyer_addr = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";

        let psbt = build_refund_psbt(
            "0000000000000000000000000000000000000000000000000000000000000001",
            0,
            50_000_000,
            &redeem,
            &ms.address,
            buyer_addr,
            Network::Bitcoin,
        )
        .unwrap();

        assert_eq!(psbt.outputs.len(), 1);
    }

    #[test]
    fn test_full_psbt_lifecycle() {
        let secp = Secp256k1::new();
        let (sk1, pk1) = generate_test_keypair(&secp);
        let (_sk2, pk2) = generate_test_keypair(&secp);
        let (sk3, pk3) = generate_test_keypair(&secp);

        let ms = create_multisig_p2wsh(&pk1, &pk2, &pk3, Network::Regtest).unwrap();

        let seller_addr = Address::p2pkh(&BtcPublicKey::new(pk2), Network::Regtest).to_string();
        let fee_addr = Address::p2pkh(&BtcPublicKey::new(pk3), Network::Regtest).to_string();

        let redeem = ScriptBuf::from_hex(&ms.redeem_script_hex).unwrap();
        let mut psbt = build_release_psbt(
            "0000000000000000000000000000000000000000000000000000000000000001",
            0,
            100_000_000,
            &redeem,
            &ms.address,
            &seller_addr,
            &fee_addr,
            4,
            Network::Regtest,
        )
        .unwrap();

        let amount_sats = 100_000_000u64;

        owner_sign_psbt_input(&mut psbt, 0, &sk1, &pk1, amount_sats).unwrap();
        assert_eq!(psbt.inputs[0].partial_sigs.len(), 1);

        owner_sign_psbt_input(&mut psbt, 0, &sk3, &pk3, amount_sats).unwrap();
        assert_eq!(psbt.inputs[0].partial_sigs.len(), 2);

        let tx_hex = finalize_psbt(psbt).unwrap();
        assert!(!tx_hex.is_empty());
        assert!(tx_hex.len() > 100);

        let decoded_tx: Transaction =
            bitcoin::consensus::encode::deserialize(&hex::decode(&tx_hex).unwrap()).unwrap();
        assert_eq!(decoded_tx.input.len(), 1);
        assert_eq!(decoded_tx.output.len(), 2);
        assert!(!decoded_tx.input[0].witness.is_empty());
    }

    #[test]
    fn test_wrong_key_does_not_block_psbt_extraction() {
        let secp = Secp256k1::new();
        let (sk1, pk1) = generate_test_keypair(&secp);
        let (_, pk2) = generate_test_keypair(&secp);
        let (_sk3, pk3) = generate_test_keypair(&secp);
 
        let ms = create_multisig_p2wsh(&pk1, &pk2, &pk3, Network::Regtest).unwrap();
        let redeem = ScriptBuf::from_hex(&ms.redeem_script_hex).unwrap();
 
        let (sk_wrong, pk_wrong) = generate_test_keypair(&secp);
        let seller_addr = Address::p2pkh(&BtcPublicKey::new(pk2), Network::Regtest).to_string();

        let mut psbt = build_release_psbt(
            "0000000000000000000000000000000000000000000000000000000000000001",
            0,
            100_000_000,
            &redeem,
            &ms.address,
            &seller_addr,
            &seller_addr,
            4,
            Network::Regtest,
        )
        .unwrap();

        owner_sign_psbt_input(&mut psbt, 0, &sk_wrong, &pk_wrong, 100_000_000).unwrap();
        assert_eq!(psbt.inputs[0].partial_sigs.len(), 1);

        owner_sign_psbt_input(&mut psbt, 0, &sk1, &pk1, 100_000_000).unwrap();
        assert_eq!(psbt.inputs[0].partial_sigs.len(), 2);

        let result = finalize_psbt(psbt);
        assert!(result.is_ok());
    }

    #[test]
    fn test_fee_split_calculation() {
        // With fee_percent=4 on 1 BTC = 0.04 BTC fee, 0.96 BTC to seller
        let seller_sats = 100_000_000u64 * (100 - 4) / 100;
        let fee_sats = 100_000_000u64 - seller_sats;
        assert_eq!(seller_sats, 96_000_000);
        assert_eq!(fee_sats, 4_000_000);

        // Edge case: 1 sat with 50% fee
        let seller_sats = 1u64 * (100 - 50) / 100;
        assert_eq!(seller_sats, 0);
    }

    #[test]
    fn test_bip67_key_sorting() {
        // BIP67 requires keys sorted lexicographically by compressed pubkey
        let secp = Secp256k1::new();
        let (_, pk1) = generate_test_keypair(&secp);
        let (_, pk2) = generate_test_keypair(&secp);
        let (_, pk3) = generate_test_keypair(&secp);

        let a = create_multisig_p2wsh(&pk1, &pk2, &pk3, Network::Bitcoin).unwrap();
        let b = create_multisig_p2wsh(&pk3, &pk2, &pk1, Network::Bitcoin).unwrap();
        let c = create_multisig_p2wsh(&pk2, &pk1, &pk3, Network::Bitcoin).unwrap();

        assert_eq!(a.address, b.address);
        assert_eq!(b.address, c.address);
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
}
