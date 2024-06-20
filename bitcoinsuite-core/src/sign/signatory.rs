use crate::{
    ecc::{Ecc, PubKey, SecKey},
    BytesMut, Hashed, Result, Script, Sha256d, SigHashType, UnsignedTxInput,
};

pub trait Signatory {
    fn sign_input<'tx>(&self, ecc: &dyn Ecc, input: UnsignedTxInput<'tx>) -> Result<()>;
}

fn _assert_obj_safe(_: &dyn Signatory) {}

pub struct P2PKHSignatory {
    pub seckey: SecKey,
    pub pubkey: PubKey,
    pub sig_hash_type: SigHashType,
}

impl Signatory for P2PKHSignatory {
    fn sign_input<'tx>(&self, ecc: &dyn Ecc, mut input: UnsignedTxInput<'tx>) -> Result<()> {
        let preimage = input.sighash_preimage(self.sig_hash_type, None)?;
        let sighash = Sha256d::digest(&preimage.bytes).byte_array().clone();
        let sig = ecc.schnorr_sign(&self.seckey, sighash);
        let mut sig_flagged = BytesMut::new();
        sig_flagged.put_bytes(sig);
        sig_flagged.put_slice(&[self.sig_hash_type.to_u32() as u8]);
        *input.input_script_mut() = Script::p2pkh_spend(&self.pubkey, sig_flagged.freeze());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        ecc::{DummyEcc, PubKey, SecKey},
        Hashed, OutPoint, P2PKHSignatory, Script, SequenceNo, ShaRmd160, SigHashType, SignData,
        SignField, Signatory, TxInput, TxOutput, UnhashedTx, UnsignedTx,
    };

    #[test]
    fn test_p2pkh_signatory() -> Result<(), Box<dyn std::error::Error>> {
        let outpoint = OutPoint::default();

        let ecc = DummyEcc;
        let seckey = SecKey::new_unchecked([1; 32]);
        let pubkey = PubKey::new_unchecked([2; 33]);
        let p2pkh_script = Script::p2pkh(&ShaRmd160::digest(&pubkey.array()));

        let tx = UnhashedTx {
            version: 1,
            inputs: vec![TxInput {
                prev_out: outpoint,
                script: Script::default(),
                sequence: SequenceNo::finalized(),
                sign_data: Some(SignData::new(vec![
                    SignField::Value(12345),
                    SignField::OutputScript(p2pkh_script),
                ])),
            }],
            outputs: vec![TxOutput::default()],
            lock_time: 0,
        };
        let sig_hash_types = vec![
            SigHashType::ALL_BIP143,
            SigHashType::NONE_BIP143,
            SigHashType::SINGLE_BIP143,
            SigHashType::ALL_BIP143_ANYONECANPAY,
            SigHashType::NONE_BIP143_ANYONECANPAY,
            SigHashType::SINGLE_BIP143_ANYONECANPAY,
        ];
        for sig_hash_type in sig_hash_types {
            let signatory = P2PKHSignatory {
                seckey: seckey.clone(),
                pubkey,
                sig_hash_type,
            };
            let mut unsigned_tx = UnsignedTx::new_dummy(tx.clone());
            signatory.sign_input(&ecc, unsigned_tx.input_at(0)).unwrap();
            let input = &unsigned_tx.tx().inputs[0];
            let expected_script = Script::from_slice(
                &[
                    [65].as_ref(),
                    &[0; 64],
                    &[sig_hash_type.to_u32() as u8],
                    &[33],
                    &[2; 33],
                ]
                .concat(),
            );
            assert_eq!(input.script, expected_script)
        }
        Ok(())
    }
}
