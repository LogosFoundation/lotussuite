use std::{ffi::OsString, str::FromStr, time::Duration};

use anyhow::Result;
use bitcoinsuite_bchd_grpc::{
    bchd_grpc::GetBlockchainInfoRequest,
    test_instance::{BchdTestConf, BchdTestInstance},
};
use bitcoinsuite_bitcoind::test_instance::{BitcoindChain, BitcoindTestConf, BitcoindTestInstance};
use bitcoinsuite_core::{Hashed, Network, OutPoint, Script, Sha256d};

pub async fn setup_xec_chain(
    num_generated_utxos: i32,
    redeem_script: &Script,
) -> Result<(BitcoindTestInstance, BchdTestInstance, Vec<(OutPoint, i64)>)> {
    let xec_args = vec![
        OsString::from_str("-uaclientname=Bitcoin NOT ABC").unwrap(),
        OsString::from_str("-ecash").unwrap(),
    ];
    let xec_conf = BitcoindTestConf::from_env(BitcoindChain::XEC, xec_args)?;
    setup_chain(Network::XEC, xec_conf, num_generated_utxos, redeem_script).await
}

pub async fn setup_bch_chain(
    num_generated_utxos: i32,
    redeem_script: &Script,
) -> Result<(BitcoindTestInstance, BchdTestInstance, Vec<(OutPoint, i64)>)> {
    let bch_conf = BitcoindTestConf::from_env(BitcoindChain::BCH, vec![])?;
    setup_chain(Network::BCH, bch_conf, num_generated_utxos, redeem_script).await
}

pub async fn setup_chain(
    network: Network,
    bitcoind_conf: BitcoindTestConf,
    num_generated_utxos: i32,
    redeem_script: &Script,
) -> Result<(BitcoindTestInstance, BchdTestInstance, Vec<(OutPoint, i64)>)> {
    let mut bitcoind = BitcoindTestInstance::setup(bitcoind_conf)?;
    bitcoind.wait_for_ready()?;
    let bchd_conf = BchdTestConf::from_env(bitcoind.p2p_port(), vec![])?;
    let mut bchd = BchdTestInstance::setup(bchd_conf).await?;
    let script_hash = redeem_script.to_p2sh();
    let address = bitcoind.cmd_json("decodescript", &[&redeem_script.hex()])?;
    let address = address["p2sh"].as_str().unwrap();
    let blocks = bitcoind.cmd_json(
        "generatetoaddress",
        &[&num_generated_utxos.to_string(), address],
    )?;
    bitcoind.cmd_json("generatetoaddress", &["100", address])?;
    let mut utxos = Vec::new();
    for block in blocks.members() {
        let block = bitcoind.cmd_json("getblock", &[block.as_str().unwrap(), "2"])?;
        let tx = &block["tx"][0];
        for (out_idx, output) in tx["vout"].members().enumerate() {
            if output["scriptPubKey"]["hex"].as_str().unwrap() == script_hash.hex() {
                let amount = output["value"]
                    .as_fixed_point_i64(network.coin_decimals() as u16)
                    .unwrap();
                utxos.push((
                    OutPoint {
                        txid: Sha256d::from_hex_be(tx["txid"].as_str().unwrap())?,
                        out_idx: out_idx as u32,
                    },
                    amount,
                ));
            }
        }
    }
    for attempt in 0..100 {
        if attempt == 100 {
            panic!("Timeout waiting for blocks");
        }
        let blockchain_info = bchd
            .client()
            .get_blockchain_info(GetBlockchainInfoRequest::default())
            .await?
            .into_inner();
        if blockchain_info.best_height == 100 + num_generated_utxos {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Ok((bitcoind, bchd, utxos))
}
