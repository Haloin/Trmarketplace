use crate::crypto::{escrow, stealth};
use crate::db::models::OrderData;
use crate::error::AppError;
use crate::gateway::state::AppState;
use crate::services::escrow::btc::{
    broadcast_psbt, build_multi_utxo_settlement_psbt, finalize_stealth_psbt,
    import_address_watchonly, parse_secp_pubkey, sign_stealth_input,
};
use crate::services::payments::btc::{btc_f64_to_sats, BitcoinClient};
use bitcoin::Network;

/// Create a stealth P2WPKH address for a BTC order and import it
/// into Bitcoin Core as a watch-only address.
pub(crate) async fn create_stealth_address_for_order(
    buyer_pk_hex: &str,
    master_seed: &[u8; 32],
    order_id: &[u8],
    network: Network,
    btc_rpc: &BitcoinClient,
) -> Result<String, AppError> {
    let buyer_pk = parse_secp_pubkey(buyer_pk_hex)
        .map_err(|_| AppError::BadRequest("Invalid buyer pubkey".into()))?;

    let owner_sk = escrow::derive_order_key(master_seed, order_id)
        .map_err(|e| AppError::Internal(format!("Owner key derivation: {e}")))?;
    let stealth_sk = stealth::derive_stealth_private_key(&buyer_pk, &owner_sk, order_id)
        .map_err(|e| AppError::Internal(format!("Stealth key derivation: {e}")))?;
    let stealth_pk = stealth::stealth_public_key(&stealth_sk);
    let stealth_addr = stealth::stealth_p2wpkh_address(&stealth_pk, network);

    let label = format!("order:{}", hex::encode(order_id));
    import_address_watchonly(&stealth_addr.to_string(), &label, btc_rpc)
        .await
        .map_err(|e| AppError::Internal(format!("BTC import: {e}")))?;

    Ok(stealth_addr.to_string())
}

/// Attempt to settle a stealth-funded BTC order.
///
/// Finds all UTXOs at the order's stealth address, builds a PSBT that
/// aggregates them into a single output to seller (+ fee), derives the
/// stealth private key, signs each input, and broadcasts.
/// On success sets `data.settlement_txid`.
pub(crate) async fn settle_stealth_order(
    state: &AppState,
    btc_http: reqwest::Client,
    order_id: &[u8],
    data: &mut OrderData,
) -> Result<(), AppError> {
    if data.currency != "BTC" || data.settlement_txid.is_some() {
        return Ok(());
    }

    let network = state.config.bitcoin.btc_network()
        .map_err(|e| AppError::Internal(format!("Config error: {e}")))?;

    let stealth_address = data.escrow_address.as_ref()
        .ok_or_else(|| AppError::Internal("No escrow address for BTC order".into()))?;

    let rpc = BitcoinClient::new(state.config.bitcoin.clone(), btc_http);

    let utxos = rpc.list_unspent(&[stealth_address.clone()]).await
        .map_err(|e| AppError::Internal(format!("list_unspent: {e}")))?;
    if utxos.is_empty() {
        return Err(AppError::Internal("No UTXOs at stealth address".into()));
    }

    let seller_pk_hex = data.seller_pubkey.as_ref()
        .ok_or_else(|| AppError::Internal("Missing seller pubkey".into()))?;
    let seller_pk = parse_secp_pubkey(seller_pk_hex)
        .map_err(|_| AppError::Internal("Invalid seller pubkey".into()))?;
    let btc_pk = bitcoin::key::PublicKey::new(seller_pk);
    let seller_address = bitcoin::Address::p2pkh(btc_pk, network);

    let fee_address = state.config.escrow.fee_address_btc.as_ref()
        .ok_or_else(|| AppError::Internal("No fee address configured".into()))?;

    // Collect all UTXOs as (txid_str, vout, amount_sats)
    let entries: Vec<(&str, u32, u64)> = utxos.iter()
        .filter(|u| u.confirmations > 0)
        .map(|u| (u.txid.as_str(), u.vout, btc_f64_to_sats(u.amount)))
        .collect();

    if entries.is_empty() {
        return Err(AppError::Internal("No confirmed UTXOs at stealth address".into()));
    }

    let mut psbt = build_multi_utxo_settlement_psbt(
        &entries,
        stealth_address,
        &seller_address.to_string(),
        fee_address,
        state.config.escrow.fee_percent,
        network,
    ).map_err(|e| AppError::Internal(format!("PSBT build: {e}")))?;

    let owner_sk = escrow::derive_order_key(
        state.worker_key.as_ref()
            .ok_or_else(|| AppError::Internal("Worker key not set".into()))?,
        order_id,
    )
        .map_err(|e| AppError::Internal(format!("Owner key derivation: {e}")))?;
    let buyer_pk_hex = data.buyer_pubkey.as_ref()
        .ok_or_else(|| AppError::Internal("Missing buyer pubkey".into()))?;
    let buyer_pk = parse_secp_pubkey(buyer_pk_hex)
        .map_err(|_| AppError::Internal("Invalid buyer pubkey".into()))?;
    let stealth_sk = stealth::derive_stealth_private_key(&buyer_pk, &owner_sk, order_id)
        .map_err(|e| AppError::Internal(format!("Stealth key derivation: {e}")))?;
    let stealth_pk = stealth::stealth_public_key(&stealth_sk);

    // All UTXOs share the same stealth address/key, so sign each input
    for i in 0..entries.len() {
        let amt = entries[i].2;
        sign_stealth_input(&mut psbt, i, &stealth_sk, &stealth_pk, amt)
            .map_err(|e| AppError::Internal(format!("PSBT signing input {i}: {e}")))?;
    }

    let tx_hex = finalize_stealth_psbt(psbt)
        .map_err(|e| AppError::Internal(format!("PSBT finalize: {e}")))?;

    let txid = broadcast_psbt(&tx_hex, &rpc).await
        .map_err(|e| AppError::Internal(format!("Broadcast: {e}")))?;

    tracing::info!(order_id = %hex::encode(order_id), %txid, "BTC stealth settlement broadcast");
    data.settlement_txid = Some(txid);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::escrow::generate_master_seed;

    #[test]
    fn test_derive_stealth_keypair_roundtrip() {
        let master_seed = generate_master_seed();
        let order_id = b"test-order-stealth";
        let owner_sk = escrow::derive_order_key(&master_seed, order_id).unwrap();
        let _owner_pk = escrow::order_public_key(&owner_sk);

        let buyer_sk = escrow::derive_order_key(&master_seed, b"buyer-key").unwrap();
        let buyer_pk = escrow::order_public_key(&buyer_sk);

        let stealth_sk = stealth::derive_stealth_private_key(&buyer_pk, &owner_sk, order_id).unwrap();
        let stealth_pk = stealth::stealth_public_key(&stealth_sk);
        let addr = stealth::stealth_p2wpkh_address(&stealth_pk, bitcoin::Network::Regtest);

        assert!(addr.to_string().starts_with("bcrt1"), "regtest P2WPKH expected");
    }

    #[test]
    fn test_different_order_id_different_address() {
        let master_seed = generate_master_seed();
        let owner_sk = escrow::derive_order_key(&master_seed, b"order-1").unwrap();
        let buyer_sk = escrow::derive_order_key(&master_seed, b"buyer-1").unwrap();
        let buyer_pk = escrow::order_public_key(&buyer_sk);

        let sk1 = stealth::derive_stealth_private_key(&buyer_pk, &owner_sk, b"order-a").unwrap();
        let sk2 = stealth::derive_stealth_private_key(&buyer_pk, &owner_sk, b"order-b").unwrap();
        let pk1 = stealth::stealth_public_key(&sk1);
        let pk2 = stealth::stealth_public_key(&sk2);

        assert_ne!(pk1, pk2, "different order IDs must yield different stealth keys");
    }
}
