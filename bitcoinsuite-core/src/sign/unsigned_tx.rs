use crate::{
    BitcoinCode, BitcoinSuiteError, Bytes, BytesMut, Hashed, Script, Sha256d, SigHashType,
    SigHashTypeInputs, SigHashTypeOutputs, SigHashTypeVariant, SignData, SignError, UnhashedTx,
};

use crate::sign::error::Result;

pub struct UnsignedTx {
    prevouts_hash: Sha256d,
    sequences_hash: Sha256d,
    outputs_hash: Sha256d,
    tx: UnhashedTx,
}

pub struct UnsignedTxInput<'tx> {
    idx: usize,
    unsigned_tx: &'tx mut UnsignedTx,
}

#[derive(Debug, Clone)]
pub struct SighashPreimage {
    pub bytes: Bytes,
    pub script_code: Script,
    pub redeem_script: Script,
}

impl UnsignedTx {
    pub fn new(tx: UnhashedTx) -> Self {
        UnsignedTx {
            prevouts_hash: calc_prevouts_hash(&tx),
            sequences_hash: calc_sequences_hash(&tx),
            outputs_hash: calc_outputs_hash(&tx),
            tx,
        }
    }

    pub fn new_dummy(tx: UnhashedTx) -> Self {
        UnsignedTx {
            prevouts_hash: Sha256d::default(),
            sequences_hash: Sha256d::default(),
            outputs_hash: Sha256d::default(),
            tx,
        }
    }

    pub fn tx(&self) -> &UnhashedTx {
        &self.tx
    }

    pub fn into_tx(self) -> UnhashedTx {
        self.tx
    }

    pub fn input_at(&mut self, input_idx: usize) -> UnsignedTxInput {
        UnsignedTxInput {
            idx: input_idx,
            unsigned_tx: self,
        }
    }
}

impl<'tx> UnsignedTxInput<'tx> {
    pub fn input_script_mut(&mut self) -> &mut Script {
        &mut self.unsigned_tx.tx.inputs[self.idx].script
    }

    pub fn input_sign_data_mut(&mut self) -> &mut Option<SignData> {
        &mut self.unsigned_tx.tx.inputs[self.idx].sign_data
    }

    pub fn unsigned_tx(&self) -> &UnsignedTx {
        self.unsigned_tx
    }

    pub fn input_idx(&self) -> usize {
        self.idx
    }

    pub fn sighash_preimage(
        &self,
        sig_hash_type: SigHashType,
        codesep_idx: Option<usize>,
    ) -> Result<SighashPreimage> {
        if sig_hash_type.variant != SigHashTypeVariant::Bip143 {
            return Err(SignError::InvalidSigHashType(sig_hash_type));
        }
        let tx = &self.unsigned_tx.tx;
        let input = &tx.inputs[self.idx];
        let sign_data = match &input.sign_data {
            Some(sign_data) => sign_data,
            None => return Err(SignError::NoSignData),
        };
        let redeem_script = sign_data.find_script_code()?;
        let script_code = redeem_script
            .cut_out_codesep(codesep_idx)
            .map_err(|err| match err {
                BitcoinSuiteError::Bytes(_) => SignError::InvalidScriptEncoding,
                BitcoinSuiteError::CodesepNotFound(idx) => SignError::CodesepNotFound(idx),
                _ => unreachable!(),
            })?;
        let mut preimage = BytesMut::new();
        preimage.put_bytes(tx.version.ser());
        preimage.put_byte_array(if sig_hash_type.input_type == SigHashTypeInputs::Fixed {
            self.unsigned_tx.prevouts_hash.byte_array().clone()
        } else {
            [0; 32].into()
        });
        preimage.put_byte_array(
            if sig_hash_type.input_type == SigHashTypeInputs::Fixed
                && sig_hash_type.output_type == SigHashTypeOutputs::All
            {
                self.unsigned_tx.sequences_hash.byte_array().clone()
            } else {
                [0; 32].into()
            },
        );
        preimage.put_bytes(input.prev_out.ser());
        preimage.put_bytes(script_code.ser());
        preimage.put_bytes(sign_data.find_value()?.ser());
        preimage.put_bytes(input.sequence.ser());
        preimage.put_byte_array(match sig_hash_type.output_type {
            SigHashTypeOutputs::All => self.unsigned_tx.outputs_hash.byte_array().clone(),
            SigHashTypeOutputs::Single if self.idx < tx.outputs.len() => {
                Sha256d::digest(&tx.outputs[self.idx].ser())
                    .byte_array()
                    .clone()
            }
            _ => [0; 32].into(),
        });
        preimage.put_bytes(tx.lock_time.ser());
        preimage.put_bytes(sig_hash_type.to_u32().ser());
        Ok(SighashPreimage {
            bytes: preimage.freeze(),
            script_code,
            redeem_script,
        })
    }
}

fn calc_prevouts_hash(tx: &UnhashedTx) -> Sha256d {
    let mut hashes = BytesMut::new();
    for input in &tx.inputs {
        hashes.put_bytes(input.prev_out.ser());
    }
    Sha256d::digest(&hashes.freeze())
}

fn calc_sequences_hash(tx: &UnhashedTx) -> Sha256d {
    let mut hashes = BytesMut::new();
    for input in &tx.inputs {
        hashes.put_bytes(input.sequence.ser());
    }
    Sha256d::digest(&hashes.freeze())
}

fn calc_outputs_hash(tx: &UnhashedTx) -> Sha256d {
    let mut hashes = BytesMut::new();
    for output in &tx.outputs {
        hashes.put_bytes(output.ser());
    }
    Sha256d::digest(&hashes.freeze())
}

#[cfg(test)]
mod tests {
    use crate::{
        Hashed, OutPoint, Script, SequenceNo, Sha256d, SigHashType, SignData, SignError, SignField,
        TxInput, TxOutput, UnhashedTx, UnsignedTx,
    };

    #[test]
    fn test_unsigned_tx_ctor() -> Result<(), Box<dyn std::error::Error>> {
        let tx = UnhashedTx {
            version: 1,
            inputs: vec![TxInput {
                prev_out: OutPoint::default(),
                script: Script::default(),
                sequence: SequenceNo::finalized(),
                sign_data: Some(SignData::new(vec![
                    SignField::Value(12345),
                    SignField::RedeemScript(Script::from_slice(&[0x51])),
                ])),
            }],
            outputs: vec![TxOutput::default()],
            lock_time: 0,
        };
        let unsigned_tx = UnsignedTx::new(tx);
        assert_eq!(
            unsigned_tx.prevouts_hash,
            Sha256d::from_hex_be(
                "e15426c0d1fbb5b78943c8425a9232fdfc1670d77f987707292a77ec6dce5aca"
            )?
        );
        assert_eq!(
            unsigned_tx.sequences_hash,
            Sha256d::from_hex_be(
                "445066705e799022b7095f7ceca255149f43acfc47e7f59e551f7bce2930b13b"
            )?
        );
        assert_eq!(
            unsigned_tx.outputs_hash,
            Sha256d::from_hex_be(
                "f9adfde059810f37b3d0686d67f6b29034e0c669537df7e59b40c14a0508b9ed"
            )?
        );
        Ok(())
    }

    #[test]
    fn test_sighash_preimage() -> Result<(), Box<dyn std::error::Error>> {
        let tx = UnhashedTx {
            version: 1,
            inputs: vec![TxInput {
                prev_out: OutPoint {
                    txid: Sha256d::new([0xae; 32]),
                    out_idx: 0x12345678,
                },
                script: Script::default(),
                sequence: SequenceNo::finalized(),
                sign_data: Some(SignData::new(vec![
                    SignField::Value(12345),
                    SignField::RedeemScript(Script::from_slice(&[0x51])),
                ])),
            }],
            outputs: vec![TxOutput::default()],
            lock_time: 0,
        };
        let mut unsigned_tx = UnsignedTx::new(tx);
        let input = unsigned_tx.input_at(0);
        {
            let preimage = input.sighash_preimage(SigHashType::ALL_BIP143, None)?.bytes;
            assert_eq!(
                preimage.hex(),
                "01000000\
                2c084ff03a1103581b512a25262f9a7d7e17565de0d4a4bb5d45cabb9b1f2ffb\
                3bb13029ce7b1f559ef5e747fcac439f1455a2ec7c5f09b72290795e70665044\
                aeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeae78563412\
                0151\
                3930000000000000\
                ffffffff\
                edb908054ac1409be5f77d5369c6e03490b2f6676d68d0b3370f8159e0fdadf9\
                00000000\
                41000000"
            );
        }
        {
            let preimage = input
                .sighash_preimage(SigHashType::NONE_BIP143, None)?
                .bytes;
            println!("{}", preimage.hex());
            assert_eq!(
                preimage.hex(),
                "01000000\
                2c084ff03a1103581b512a25262f9a7d7e17565de0d4a4bb5d45cabb9b1f2ffb\
                0000000000000000000000000000000000000000000000000000000000000000\
                aeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeae78563412\
                0151\
                3930000000000000\
                ffffffff\
                0000000000000000000000000000000000000000000000000000000000000000\
                00000000\
                42000000"
            );
        }
        {
            let preimage = input
                .sighash_preimage(SigHashType::SINGLE_BIP143, None)?
                .bytes;
            println!("{}", preimage.hex());
            assert_eq!(
                preimage.hex(),
                "01000000\
                2c084ff03a1103581b512a25262f9a7d7e17565de0d4a4bb5d45cabb9b1f2ffb\
                0000000000000000000000000000000000000000000000000000000000000000\
                aeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeae78563412\
                0151\
                3930000000000000\
                ffffffff\
                edb908054ac1409be5f77d5369c6e03490b2f6676d68d0b3370f8159e0fdadf9\
                00000000\
                43000000"
            );
        }
        {
            let preimage = input
                .sighash_preimage(SigHashType::ALL_BIP143_ANYONECANPAY, None)?
                .bytes;
            assert_eq!(
                preimage.hex(),
                "01000000\
                0000000000000000000000000000000000000000000000000000000000000000\
                0000000000000000000000000000000000000000000000000000000000000000\
                aeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeae78563412\
                0151\
                3930000000000000\
                ffffffff\
                edb908054ac1409be5f77d5369c6e03490b2f6676d68d0b3370f8159e0fdadf9\
                00000000\
                c1000000"
            );
        }
        {
            let preimage = input
                .sighash_preimage(SigHashType::NONE_BIP143_ANYONECANPAY, None)?
                .bytes;
            println!("{}", preimage.hex());
            assert_eq!(
                preimage.hex(),
                "01000000\
                0000000000000000000000000000000000000000000000000000000000000000\
                0000000000000000000000000000000000000000000000000000000000000000\
                aeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeae78563412\
                0151\
                3930000000000000\
                ffffffff\
                0000000000000000000000000000000000000000000000000000000000000000\
                00000000\
                c2000000"
            );
        }
        {
            let preimage = input
                .sighash_preimage(SigHashType::SINGLE_BIP143_ANYONECANPAY, None)?
                .bytes;
            println!("{}", preimage.hex());
            assert_eq!(
                preimage.hex(),
                "01000000\
                0000000000000000000000000000000000000000000000000000000000000000\
                0000000000000000000000000000000000000000000000000000000000000000\
                aeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeae78563412\
                0151\
                3930000000000000\
                ffffffff\
                edb908054ac1409be5f77d5369c6e03490b2f6676d68d0b3370f8159e0fdadf9\
                00000000\
                c3000000"
            );
        }

        Ok(())
    }

    #[test]
    fn test_sighash_preimage_codesep() -> Result<(), Box<dyn std::error::Error>> {
        let tx = UnhashedTx {
            version: 1,
            inputs: vec![TxInput {
                prev_out: OutPoint {
                    txid: Sha256d::new([0xae; 32]),
                    out_idx: 0x12345678,
                },
                script: Script::default(),
                sequence: SequenceNo::finalized(),
                sign_data: Some(SignData::new(vec![
                    SignField::Value(12345),
                    SignField::RedeemScript(Script::from_slice(&[0x51, 0xab, 0xac, 0xab, 0x87])),
                ])),
            }],
            outputs: vec![TxOutput::default()],
            lock_time: 0,
        };
        let mut unsigned_tx = UnsignedTx::new(tx);
        let input = unsigned_tx.input_at(0);
        {
            let preimage = input.sighash_preimage(SigHashType::ALL_BIP143, None)?.bytes;
            assert_eq!(
                preimage.hex(),
                "01000000\
                2c084ff03a1103581b512a25262f9a7d7e17565de0d4a4bb5d45cabb9b1f2ffb\
                3bb13029ce7b1f559ef5e747fcac439f1455a2ec7c5f09b72290795e70665044\
                aeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeae78563412\
                0551abacab87\
                3930000000000000\
                ffffffff\
                edb908054ac1409be5f77d5369c6e03490b2f6676d68d0b3370f8159e0fdadf9\
                00000000\
                41000000"
            );
        }
        {
            let preimage = input
                .sighash_preimage(SigHashType::ALL_BIP143, Some(0))?
                .bytes;
            assert_eq!(
                preimage.hex(),
                "01000000\
                2c084ff03a1103581b512a25262f9a7d7e17565de0d4a4bb5d45cabb9b1f2ffb\
                3bb13029ce7b1f559ef5e747fcac439f1455a2ec7c5f09b72290795e70665044\
                aeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeae78563412\
                03acab87\
                3930000000000000\
                ffffffff\
                edb908054ac1409be5f77d5369c6e03490b2f6676d68d0b3370f8159e0fdadf9\
                00000000\
                41000000"
            );
        }
        {
            let preimage = input
                .sighash_preimage(SigHashType::ALL_BIP143, Some(1))?
                .bytes;
            assert_eq!(
                preimage.hex(),
                "01000000\
                2c084ff03a1103581b512a25262f9a7d7e17565de0d4a4bb5d45cabb9b1f2ffb\
                3bb13029ce7b1f559ef5e747fcac439f1455a2ec7c5f09b72290795e70665044\
                aeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeae78563412\
                0187\
                3930000000000000\
                ffffffff\
                edb908054ac1409be5f77d5369c6e03490b2f6676d68d0b3370f8159e0fdadf9\
                00000000\
                41000000"
            );
        }
        {
            match input.sighash_preimage(SigHashType::ALL_BIP143, Some(2)) {
                Err(SignError::CodesepNotFound(2)) => {}
                result => panic!("Unexpected: {:?}", result),
            }
        }
        Ok(())
    }
}
