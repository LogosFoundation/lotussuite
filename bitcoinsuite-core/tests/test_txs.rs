
use bitcoinsuite_core::{
    ecc::Ecc, BitcoinCode, Hashed, OutPoint, P2PKHSignatory, Script, SequenceNo, Sha256d,
    ShaRmd160, SigHashType, SignData, SignField, TxBuilder, TxBuilderInput, TxBuilderOutput,
    TxInput, TxOutput,
};
use bitcoinsuite_ecc_secp256k1::EccSecp256k1;
use bitcoinsuite_test_utils_blockchain::{build_tx, setup_xec_chain};

async fn test_txs() -> Result<(), Box<dyn std::error::Error>> {
    let redeem_script = Script::from_static_slice(&[0x51]);
    let (bitcoind, mut utxos) = setup_xec_chain(13, &redeem_script).await?;

    let ecc = EccSecp256k1::default();
    let seckey = ecc.seckey_from_array([1; 32])?;
    let pubkey = ecc.derive_pubkey(&seckey);
    let p2pkh_script = Script::p2pkh(&ShaRmd160::digest(&pubkey.array()));

    let (outpoint, value) = utxos.pop().unwrap();
    let output_value = value / 12 - 10_000;
    let p2pkh_send_tx = build_tx(
        outpoint,
        &redeem_script,
        vec![
            TxOutput {
                value: output_value,
                script: p2pkh_script.clone(),
            };
            12
        ],
    );
    let txid_hex = bitcoind.cmd_string("sendrawtransaction", &[&p2pkh_send_tx.ser().hex()])?;
    let txid = Sha256d::from_hex_be(&txid_hex)?;

    let sig_hash_types = vec![
        SigHashType::ALL_BIP143,
        SigHashType::NONE_BIP143,
        SigHashType::SINGLE_BIP143,
        SigHashType::ALL_BIP143_ANYONECANPAY,
        SigHashType::NONE_BIP143_ANYONECANPAY,
        SigHashType::SINGLE_BIP143_ANYONECANPAY,
    ];
    for (idx, &sig_hash_type) in sig_hash_types.iter().enumerate() {
        let (miner_outpoint, miner_value) = utxos.pop().unwrap();
        let outputs = vec![
            TxOutput {
                value: 0,
                script: Script::opreturn(&[b"Hello", b"World"]),
            },
            TxOutput {
                value: output_value + miner_value - 10_000,
                script: Script::p2pkh(&ShaRmd160::new([0; 20])),
            },
        ];
        let mut tx_builder = TxBuilder::from_tx(build_tx(miner_outpoint, &redeem_script, outputs));
        tx_builder.inputs.push(TxBuilderInput::new(
            TxInput {
                prev_out: OutPoint {
                    txid: txid.clone(),
                    out_idx: idx as u32,
                },
                script: Script::default(),
                sequence: SequenceNo::finalized(),
                sign_data: Some(SignData::new(vec![
                    SignField::Value(output_value),
                    SignField::OutputScript(p2pkh_script.clone()),
                ])),
            },
            Box::new(P2PKHSignatory {
                seckey: seckey.clone(),
                pubkey,
                sig_hash_type,
            }),
        ));
        let signed_tx = tx_builder.sign(&ecc, 1000, 546)?;
        bitcoind.cmd_string("sendrawtransaction", &[&signed_tx.ser().hex()])?;
    }

    for (idx, &sig_hash_type) in sig_hash_types.iter().enumerate() {
        let (miner_outpoint, miner_value) = utxos.pop().unwrap();
        let outputs = vec![
            TxOutput {
                value: 0,
                script: Script::opreturn(&[b"Hello", b"World"]),
            },
            TxOutput {
                value: 12_345_678,
                script: Script::p2pkh(&ShaRmd160::new([0; 20])),
            },
        ];
        let mut tx = build_tx(miner_outpoint, &redeem_script, outputs);
        tx.inputs[0].sign_data = Some(SignData::new(vec![SignField::Value(miner_value)]));
        let mut tx_builder = TxBuilder::from_tx(tx);
        tx_builder.inputs.push(TxBuilderInput::new(
            TxInput {
                prev_out: OutPoint {
                    txid: txid.clone(),
                    out_idx: idx as u32 + 6,
                },
                script: Script::default(),
                sequence: SequenceNo::finalized(),
                sign_data: Some(SignData::new(vec![
                    SignField::Value(output_value),
                    SignField::OutputScript(p2pkh_script.clone()),
                ])),
            },
            Box::new(P2PKHSignatory {
                seckey: seckey.clone(),
                pubkey,
                sig_hash_type,
            }),
        ));
        let leftover_script = Script::from_slice(&[52]).to_p2sh();
        tx_builder
            .outputs
            .push(TxBuilderOutput::Leftover(leftover_script.clone()));
        let signed_tx = tx_builder.sign(&ecc, 1000, 546)?;
        let tx_size = signed_tx.ser().len();
        assert_eq!(
            signed_tx.outputs,
            vec![
                TxOutput {
                    value: 0,
                    script: Script::opreturn(&[b"Hello", b"World"]),
                },
                TxOutput {
                    value: 12_345_678,
                    script: Script::p2pkh(&ShaRmd160::new([0; 20])),
                },
                TxOutput {
                    value: output_value + miner_value - 12_345_678 - tx_size as i64,
                    script: leftover_script,
                },
            ]
        );
        bitcoind.cmd_string("sendrawtransaction", &[&signed_tx.ser().hex()])?;
    }

    Ok(())
}

#[test]
fn run_tx_tests() -> Result<(), Box<dyn std::error::Error>> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(test_txs())?;
    Ok(())
}
