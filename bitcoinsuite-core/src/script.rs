use crate::{
    bytes::Bytes,
    ecc::{PubKey, PUBKEY_LENGTH},
    opcode::*,
    BitcoinCode, BitcoinSuiteError, BytesError, BytesMut, Hashed, Op, Result, ShaRmd160,
};

#[derive(Debug, Clone, PartialEq, Eq, Default, Hash)]
pub struct Script {
    bytecode: Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ScriptVariant {
    P2PK(PubKey),
    P2PKLegacy([u8; 65]),
    P2PKH(ShaRmd160),
    P2SH(ShaRmd160),
    P2TR(PubKey, Option<[u8; 32]>),
    Other(Script),
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Hash)]
pub struct ScriptOpIter {
    remaining_bytecode: Bytes,
}

impl BitcoinCode for Script {
    fn ser_to(&self, bytes: &mut crate::BytesMut) {
        self.bytecode.ser_to(bytes)
    }

    fn deser(data: &mut Bytes) -> crate::Result<Self> {
        Ok(Script {
            bytecode: Bytes::deser(data)?,
        })
    }
}

impl Script {
    pub fn new(bytecode: Bytes) -> Self {
        Script { bytecode }
    }

    pub fn from_slice(slice: &[u8]) -> Self {
        Script {
            bytecode: Bytes::from_slice(slice),
        }
    }

    pub fn from_static_slice(slice: &'static [u8]) -> Self {
        Script {
            bytecode: Bytes::from_bytes(slice),
        }
    }

    pub fn from_hex(hex: &str) -> crate::Result<Self> {
        Ok(Script::new(Bytes::from_bytes(hex::decode(hex)?)))
    }

    pub fn opreturn(data: &[&[u8]]) -> Self {
        let mut bytes = BytesMut::new();
        bytes.put_slice(&[OP_RETURN as u8]);
        for &item in data {
            if item.is_empty() {
                bytes.put_slice(&[OP_PUSHDATA1, 0]);
            } else if item.len() < OP_PUSHDATA1 as usize {
                bytes.put_slice(&[item.len() as u8]);
                bytes.put_slice(item);
            } else {
                bytes.put_slice(&[OP_PUSHDATA1]);
                bytes.put_slice(&[item.len() as u8]);
                bytes.put_slice(item);
            }
        }
        Script {
            bytecode: bytes.freeze(),
        }
    }

    pub fn p2pk(pubkey: &PubKey) -> Self {
        let mut bytes = BytesMut::new();
        bytes.put_slice(&[0x21]);
        bytes.put_slice(pubkey.as_slice());
        bytes.put_slice(&[OP_CHECKSIG]);
        Script {
            bytecode: bytes.freeze(),
        }
    }

    pub fn p2pk_legacy(pubkey: [u8; 65]) -> Self {
        let mut bytes = BytesMut::new();
        bytes.put_slice(&[0x41]);
        bytes.put_slice(&pubkey);
        bytes.put_slice(&[OP_CHECKSIG]);
        Script {
            bytecode: bytes.freeze(),
        }
    }

    pub fn p2pkh(hash: &ShaRmd160) -> Self {
        let mut bytes = BytesMut::new();
        bytes.put_slice(&[OP_DUP, OP_HASH160, 0x14]);
        bytes.put_byte_array(hash.byte_array().clone());
        bytes.put_slice(&[OP_EQUALVERIFY, OP_CHECKSIG]);
        Script {
            bytecode: bytes.freeze(),
        }
    }

    pub fn p2pkh_spend(pubkey: &PubKey, sig: Bytes) -> Self {
        let mut bytes = BytesMut::new();
        bytes.put_slice(&[sig.len() as u8]);
        bytes.put_bytes(sig);
        bytes.put_slice(&[PUBKEY_LENGTH as u8]);
        bytes.put_slice(pubkey.as_slice());
        Script {
            bytecode: bytes.freeze(),
        }
    }

    pub fn p2sh(hash: &ShaRmd160) -> Self {
        let mut bytes = BytesMut::new();
        bytes.put_slice(&[OP_HASH160, 0x14]);
        bytes.put_byte_array(hash.byte_array().clone());
        bytes.put_slice(&[OP_EQUAL]);
        Script {
            bytecode: bytes.freeze(),
        }
    }

    pub fn multisig<'a>(num_signers: u8, public_keys: impl IntoIterator<Item = &'a [u8]>) -> Self {
        assert!(num_signers != 0);
        assert!(num_signers <= 16);
        let mut bytes = BytesMut::new();
        bytes.put_slice(&[0x50 + num_signers]);
        let mut num_keys = 0;
        for public_key in public_keys {
            bytes.put_slice(&[public_key.len() as u8]);
            bytes.put_slice(public_key);
            num_keys += 1;
        }
        assert!(num_keys != 0);
        assert!(num_keys <= 16);
        bytes.put_slice(&[0x50 + num_keys as u8, OP_CHECKMULTISIG]);
        Script {
            bytecode: bytes.freeze(),
        }
    }

    pub fn p2tr(commitment: &PubKey, state: Option<[u8; 32]>) -> Self {
        let mut bytes = BytesMut::new();
        bytes.put_slice(&[OP_SCRIPTTYPE, OP_1, 0x21]);
        bytes.put_slice(commitment.as_slice());
        if let Some(state) = state {
            bytes.put_slice(&[0x20]);
            bytes.put_slice(&state);
        }
        Script {
            bytecode: bytes.freeze(),
        }
    }

    pub fn bytecode(&self) -> &Bytes {
        &self.bytecode
    }

    pub fn from_ops(ops_iter: impl Iterator<Item = Op>) -> Result<Self> {
        let mut bytecode = BytesMut::new();
        for op in ops_iter {
            op.ser_op(&mut bytecode)?;
        }
        Ok(Script {
            bytecode: bytecode.freeze(),
        })
    }

    pub fn ops(&self) -> ScriptOpIter {
        ScriptOpIter {
            remaining_bytecode: self.bytecode.clone(),
        }
    }

    pub fn hex(&self) -> String {
        self.bytecode.hex()
    }

    pub fn to_p2sh(&self) -> Self {
        Script::p2sh(&ShaRmd160::digest(&self.bytecode.clone()))
    }

    pub fn is_p2sh(&self) -> bool {
        matches!(self.bytecode.as_ref(), [OP_HASH160, 0x14, hash @ .., OP_EQUAL] if hash.len() == 20)
    }

    pub fn is_opreturn(&self) -> bool {
        self.bytecode
            .first()
            .map(|&opcode| opcode == OP_RETURN)
            .unwrap_or_default()
    }

    pub fn cut_out_codesep(&self, n_codesep: Option<usize>) -> Result<Script> {
        if let Some(n_codesep) = n_codesep {
            let mut n_codeseps_found = 0;
            let mut ops = self.ops();
            while let Some(op) = ops.next() {
                if let Op::Code(OP_CODESEPARATOR) = op? {
                    if n_codesep == n_codeseps_found {
                        return Ok(Script::new(ops.remaining_bytecode));
                    }
                    n_codeseps_found += 1;
                }
            }
            return Err(BitcoinSuiteError::CodesepNotFound(n_codesep));
        }
        Ok(self.clone())
    }

    pub fn parse_variant(&self) -> ScriptVariant {
        match self.bytecode.as_ref() {
            [0x21, pubkey @ .., OP_CHECKSIG] if pubkey.len() == PUBKEY_LENGTH => {
                ScriptVariant::P2PK(PubKey::new_unchecked(pubkey.try_into().unwrap()))
            }
            [0x41, pubkey @ .., OP_CHECKSIG] if pubkey.len() == 65 => {
                ScriptVariant::P2PKLegacy(pubkey.try_into().unwrap())
            }
            [OP_DUP, OP_HASH160, 0x14, hash @ .., OP_EQUALVERIFY, OP_CHECKSIG]
                if hash.len() == 20 =>
            {
                ScriptVariant::P2PKH(ShaRmd160::from_slice(hash).unwrap())
            }
            [OP_HASH160, 0x14, hash @ .., OP_EQUAL] if hash.len() == 20 => {
                ScriptVariant::P2SH(ShaRmd160::from_slice(hash).unwrap())
            }
            [OP_SCRIPTTYPE, OP_1, 0x21, rest @ ..] if rest.len() >= PUBKEY_LENGTH => {
                let commitment = &rest[..PUBKEY_LENGTH];
                let state = match &rest[PUBKEY_LENGTH..] {
                    [] => None,
                    [0x20, state @ ..] if state.len() == 32 => Some(state.try_into().unwrap()),
                    _ => return ScriptVariant::Other(self.clone()),
                };
                ScriptVariant::P2TR(PubKey::new_unchecked(commitment.try_into().unwrap()), state)
            }
            _ => ScriptVariant::Other(self.clone()),
        }
    }

    pub fn parse_p2pkh_spend(&self) -> Option<(Bytes, Bytes)> {
        let mut ops = self.ops();
        let sig_op = ops.next()?.ok()?;
        let sig = match sig_op {
            Op::Push(push_op, data) if push_op < OP_PUSHDATA1 => data,
            _ => return None,
        };
        let pubkey_op = ops.next()?.ok()?;
        let pubkey = match pubkey_op {
            Op::Push(push_op, data)
                if data.len() == PUBKEY_LENGTH && push_op as usize == PUBKEY_LENGTH =>
            {
                data
            }
            _ => return None,
        };
        Some((pubkey, sig))
    }
}

impl Iterator for ScriptOpIter {
    type Item = std::result::Result<Op, BytesError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining_bytecode.is_empty() {
            None
        } else {
            Some(Op::deser_op(&mut self.remaining_bytecode))
        }
    }
}

impl std::fmt::Display for Script {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Capacity adjusted to avoid reallocations in common scenarios: P2PKH and any scriptSig.
        let mut asm = String::with_capacity(self.bytecode.len() * 2 + 50);
        for op in self.ops() {
            match op {
                Ok(op) => asm.push_str(&op.to_string()),
                Err(_) => {
                    asm.push_str("[corrupt PUSHDATA] ");
                    break;
                }
            }
            asm.push(' ');
        }
        asm.pop();
        f.write_str(&asm)
    }
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use crate::{
        ecc::PubKey, opcode::*, BitcoinSuiteError, Hashed, Script, ScriptVariant, ShaRmd160,
    };

    #[test]
    fn test_cut_out_codesep_without() -> Result<(), Box<dyn std::error::Error>> {
        let script = Script::from_slice(&[OP_1, OP_2, OP_ADD, OP_3, OP_EQUAL]);
        assert_eq!(script.cut_out_codesep(None)?, script);
        for i in 0..100 {
            match script.cut_out_codesep(Some(i)) {
                Err(BitcoinSuiteError::CodesepNotFound(pos)) => assert_eq!(pos, i),
                other => panic!("Unexpected result: {:?}", other),
            }
        }
        Ok(())
    }

    #[test]
    fn test_cut_out_codesep() -> Result<(), Box<dyn std::error::Error>> {
        let script = Script::from_slice(&[
            OP_1,
            OP_CODESEPARATOR,
            OP_2,
            OP_CODESEPARATOR,
            OP_CODESEPARATOR,
            OP_ADD,
            OP_3,
            OP_CODESEPARATOR,
            OP_EQUAL,
            OP_CODESEPARATOR,
        ]);
        assert_eq!(script.cut_out_codesep(None)?, script);
        assert_eq!(
            script.cut_out_codesep(Some(0))?,
            Script::from_slice(&[
                OP_2,
                OP_CODESEPARATOR,
                OP_CODESEPARATOR,
                OP_ADD,
                OP_3,
                OP_CODESEPARATOR,
                OP_EQUAL,
                OP_CODESEPARATOR
            ])
        );
        assert_eq!(
            script.cut_out_codesep(Some(1))?,
            Script::from_slice(&[
                OP_CODESEPARATOR,
                OP_ADD,
                OP_3,
                OP_CODESEPARATOR,
                OP_EQUAL,
                OP_CODESEPARATOR
            ])
        );
        assert_eq!(
            script.cut_out_codesep(Some(2))?,
            Script::from_slice(&[OP_ADD, OP_3, OP_CODESEPARATOR, OP_EQUAL, OP_CODESEPARATOR])
        );
        assert_eq!(
            script.cut_out_codesep(Some(3))?,
            Script::from_slice(&[OP_EQUAL, OP_CODESEPARATOR])
        );
        assert_eq!(script.cut_out_codesep(Some(4))?, Script::from_slice(&[]));
        match script.cut_out_codesep(Some(5)) {
            Err(BitcoinSuiteError::CodesepNotFound(5)) => {}
            other => panic!("Unexpected result: {:?}", other),
        }
        Ok(())
    }

    #[test]
    fn test_p2pk() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            Script::p2pk(&PubKey::new_unchecked([0; 33])),
            Script::from_slice(&[
                0x21, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0xac
            ]),
        );
        Ok(())
    }

    #[test]
    fn test_p2pkh() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            Script::p2pkh(&ShaRmd160::new([0; 20])),
            Script::from_slice(&[
                0x76, 0xa9, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x88,
                0xac
            ]),
        );
        assert_eq!(
            Script::p2pkh(&ShaRmd160::new([0xff; 20])),
            Script::from_slice(&[
                0x76, 0xa9, 0x14, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x88, 0xac
            ]),
        );
        Ok(())
    }

    #[test]
    fn test_p2pkh_spend() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            Script::p2pkh_spend(&PubKey::new_unchecked([2; 33]), [7; 64].into()),
            Script::from_slice(&[
                0x40, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
                0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
                0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
                0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
                0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x21, 0x02, 0x02, 0x02, 0x02,
                0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                0x02
            ]),
        );
        Ok(())
    }

    #[test]
    fn test_p2sh() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            Script::p2sh(&ShaRmd160::new([0; 20])),
            Script::from_slice(&[
                0xa9, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x87,
            ]),
        );
        assert_eq!(
            Script::p2sh(&ShaRmd160::new([0xff; 20])),
            Script::from_slice(&[
                0xa9, 0x14, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x87,
            ]),
        );
        Ok(())
    }

    #[test]
    fn test_is_p2sh() -> Result<(), Box<dyn std::error::Error>> {
        assert!(Script::from_slice(&[
            0xa9, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x87,
        ])
        .is_p2sh());
        assert!(Script::from_slice(&[
            0xa9, 0x14, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x87,
        ])
        .is_p2sh());
        assert!(!Script::from_slice(&[
            0xa9, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x87,
        ])
        .is_p2sh());
        assert!(!Script::from_slice(&[
            0xa9, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x88,
        ])
        .is_p2sh());
        assert!(!Script::from_slice(&[
            0xa9, 0x15, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x87,
        ])
        .is_p2sh());
        Ok(())
    }

    #[test]
    fn test_p2tr() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            Script::p2tr(&PubKey::new_unchecked([0; 33]), None),
            Script::from_slice(&[
                0x62, 0x51, 0x21, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ]),
        );
        assert_eq!(
            Script::p2tr(&PubKey::new_unchecked([1; 33]), Some([2; 32])),
            Script::from_slice(&[
                0x62, 0x51, 0x21, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0x20, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
                2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
            ]),
        );
        Ok(())
    }

    #[test]
    fn test_parse_script_variant_p2pk() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            Script::from_hex(
                "21010203040506070809101112131415161718192021222324252627282930313233ac"
            )?
            .parse_variant(),
            ScriptVariant::P2PK(PubKey::new_unchecked(hex!(
                "010203040506070809101112131415161718192021222324252627282930313233"
            ))),
        );
        assert_eq!(
            Script::from_hex(
                "21000000000000000000000000000000000000000000000000000000000000000000ac"
            )?
            .parse_variant(),
            ScriptVariant::P2PK(PubKey::new_unchecked([0; 33])),
        );
        for script_hex in [
            // missing opcodes
            "000000000000000000000000000000000000000000000000000000000000000000ac",
            "21000000000000000000000000000000000000000000000000000000000000000000",
            // wrong opcodes
            "20000000000000000000000000000000000000000000000000000000000000000000ac",
            "21000000000000000000000000000000000000000000000000000000000000000000ab",
            // wrong push size
            "200000000000000000000000000000000000000000000000000000000000000000ac",
        ] {
            assert_eq!(
                Script::from_hex(script_hex)?.parse_variant(),
                ScriptVariant::Other(Script::from_hex(script_hex)?),
            );
        }
        Ok(())
    }

    #[test]
    fn test_parse_script_variant_p2pk_legacy() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            Script::from_hex(
                "410102030405060708091011121314151617181920212223242526272829303132\
                 333435363738394041424344454647484950515253545556575859606162636465ac"
            )?
            .parse_variant(),
            ScriptVariant::P2PKLegacy(
                hex::decode(
                    "0102030405060708091011121314151617181920212223242526272829303132\
                     333435363738394041424344454647484950515253545556575859606162636465"
                )?
                .try_into()
                .unwrap()
            ),
        );
        assert_eq!(
            Script::from_hex(
                "410000000000000000000000000000000000000000000000000000000000000000\
                 000000000000000000000000000000000000000000000000000000000000000000ac"
            )?
            .parse_variant(),
            ScriptVariant::P2PKLegacy([0; 65]),
        );
        for script_hex in [
            // missing opcodes
            "0000000000000000000000000000000000000000000000000000000000000000\
             000000000000000000000000000000000000000000000000000000000000000000ac",
            "410000000000000000000000000000000000000000000000000000000000000000\
             000000000000000000000000000000000000000000000000000000000000000000",
            // wrong opcodes
            "400000000000000000000000000000000000000000000000000000000000000000\
             000000000000000000000000000000000000000000000000000000000000000000ac",
            "410000000000000000000000000000000000000000000000000000000000000000\
             000000000000000000000000000000000000000000000000000000000000000000ab",
            // wrong push size
            "400000000000000000000000000000000000000000000000000000000000000000\
             0000000000000000000000000000000000000000000000000000000000000000ac",
        ] {
            assert_eq!(
                Script::from_hex(script_hex)?.parse_variant(),
                ScriptVariant::Other(Script::from_hex(script_hex)?),
            );
        }
        Ok(())
    }

    #[test]
    fn test_parse_script_variant_p2pkh() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            Script::from_hex("76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac")?.parse_variant(),
            ScriptVariant::P2PKH(ShaRmd160::from_hex(
                "89abcdefabbaabbaabbaabbaabbaabbaabbaabba"
            )?),
        );
        assert_eq!(
            Script::from_hex("76a914000000000000000000000000000000000000000088ac")?.parse_variant(),
            ScriptVariant::P2PKH(ShaRmd160::new([0; 20])),
        );
        for script_hex in [
            // missing opcodes
            "a914000000000000000000000000000000000000000088ac",
            "7614000000000000000000000000000000000000000088ac",
            "76a9000000000000000000000000000000000000000088ac",
            "76a9140000000000000000000000000000000000000088ac",
            "76a9140000000000000000000000000000000000000000ac",
            "76a914000000000000000000000000000000000000000088",
            // wrong opcodes
            "75a914000000000000000000000000000000000000000088ac",
            "76a814000000000000000000000000000000000000000088ac",
            "76a915000000000000000000000000000000000000000088ac",
            "76a914000000000000000000000000000000000000000087ac",
            "76a914000000000000000000000000000000000000000088ab",
            // wrong push size
            "76a9130000000000000000000000000000000000000088ac",
        ] {
            assert_eq!(
                Script::from_hex(script_hex)?.parse_variant(),
                ScriptVariant::Other(Script::from_hex(script_hex)?),
            );
        }
        Ok(())
    }

    #[test]
    fn test_parse_script_variant_p2sh() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            Script::from_hex("a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba87")?.parse_variant(),
            ScriptVariant::P2SH(ShaRmd160::from_hex(
                "89abcdefabbaabbaabbaabbaabbaabbaabbaabba"
            )?),
        );
        assert_eq!(
            Script::from_hex("a914000000000000000000000000000000000000000087")?.parse_variant(),
            ScriptVariant::P2SH(ShaRmd160::new([0; 20])),
        );
        for script_hex in [
            // missing opcodes
            "14000000000000000000000000000000000000000087",
            "a9000000000000000000000000000000000000000087",
            "a9140000000000000000000000000000000000000087",
            "a9140000000000000000000000000000000000000000",
            // wrong opcodes
            "a814000000000000000000000000000000000000000087",
            "a915000000000000000000000000000000000000000087",
            "a914000000000000000000000000000000000000000088",
            "a9130000000000000000000000000000000000000087",
        ] {
            assert_eq!(
                Script::from_hex(script_hex)?.parse_variant(),
                ScriptVariant::Other(Script::from_hex(script_hex)?),
            );
        }
        Ok(())
    }

    #[test]
    fn test_parse_script_variant_p2tr() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            Script::from_hex(
                "625121010203040506070809101112131415161718192021222324252627282930313233"
            )?
            .parse_variant(),
            ScriptVariant::P2TR(
                PubKey::new_unchecked(hex!(
                    "010203040506070809101112131415161718192021222324252627282930313233"
                )),
                None
            ),
        );
        assert_eq!(
            Script::from_hex(
                "625121000000000000000000000000000000000000000000000000000000000000000000"
            )?
            .parse_variant(),
            ScriptVariant::P2TR(PubKey::new_unchecked([0; 33]), None),
        );
        assert_eq!(
            Script::from_hex(
                "625121010203040506070809101112131415161718192021222324252627282930313233\
                 203231302928272625242322212019181716151413121110090807060504030201"
            )?
            .parse_variant(),
            ScriptVariant::P2TR(
                PubKey::new_unchecked(hex!(
                    "010203040506070809101112131415161718192021222324252627282930313233"
                )),
                Some(hex!(
                    "3231302928272625242322212019181716151413121110090807060504030201"
                ))
            ),
        );
        assert_eq!(
            Script::from_hex(
                "625121000000000000000000000000000000000000000000000000000000000000000000"
            )?
            .parse_variant(),
            ScriptVariant::P2TR(PubKey::new_unchecked([0; 33]), None),
        );
        assert_eq!(
            Script::from_hex(
                "625121000000000000000000000000000000000000000000000000000000000000000000\
                 200000000000000000000000000000000000000000000000000000000000000000"
            )?
            .parse_variant(),
            ScriptVariant::P2TR(PubKey::new_unchecked([0; 33]), Some([0; 32])),
        );
        for script_hex in [
            // missing opcodes
            "5121000000000000000000000000000000000000000000000000000000000000000000",
            "6221000000000000000000000000000000000000000000000000000000000000000000",
            "6251000000000000000000000000000000000000000000000000000000000000000000",
            "6251210000000000000000000000000000000000000000000000000000000000000000",
            "5121000000000000000000000000000000000000000000000000000000000000000000\
             200000000000000000000000000000000000000000000000000000000000000000",
            "6221000000000000000000000000000000000000000000000000000000000000000000\
             200000000000000000000000000000000000000000000000000000000000000000",
            "6251000000000000000000000000000000000000000000000000000000000000000000\
             200000000000000000000000000000000000000000000000000000000000000000",
            "6251210000000000000000000000000000000000000000000000000000000000000000\
             200000000000000000000000000000000000000000000000000000000000000000",
            "625121000000000000000000000000000000000000000000000000000000000000000000\
             0000000000000000000000000000000000000000000000000000000000000000",
            "625121000000000000000000000000000000000000000000000000000000000000000000\
             2000000000000000000000000000000000000000000000000000000000000000",
            // wrong opcodes
            "615121000000000000000000000000000000000000000000000000000000000000000000",
            "625221000000000000000000000000000000000000000000000000000000000000000000",
            "625120000000000000000000000000000000000000000000000000000000000000000000",
            "645121000000000000000000000000000000000000000000000000000000000000000000\
             200000000000000000000000000000000000000000000000000000000000000000",
            "625221000000000000000000000000000000000000000000000000000000000000000000\
             200000000000000000000000000000000000000000000000000000000000000000",
            "625120000000000000000000000000000000000000000000000000000000000000000000\
             200000000000000000000000000000000000000000000000000000000000000000",
            "625121000000000000000000000000000000000000000000000000000000000000000000\
             1f0000000000000000000000000000000000000000000000000000000000000000",
            // wrong push sizes
            "6251200000000000000000000000000000000000000000000000000000000000000000",
            "6251200000000000000000000000000000000000000000000000000000000000000000\
             200000000000000000000000000000000000000000000000000000000000000000",
            "625121000000000000000000000000000000000000000000000000000000000000000000\
             1f00000000000000000000000000000000000000000000000000000000000000",
        ] {
            assert_eq!(
                Script::from_hex(script_hex)?.parse_variant(),
                ScriptVariant::Other(Script::from_hex(script_hex)?),
            );
        }
        Ok(())
    }

    #[test]
    fn test_parse_p2pkh_spend() -> crate::Result<()> {
        // Bad script
        assert_eq!(Script::from_hex("04")?.parse_p2pkh_spend(), None);
        // Bad pubkey
        assert_eq!(
            Script::from_hex(
                "4100000000000000000000000000000000000000000000000000000000000000000000000000000000\
                 00000000000000000000000000000000000000000000000000\
                 200300000000000000000000000000000000000000000000000000000000000000")?
            .parse_p2pkh_spend(),
            None,
        );
        // Bad pubkey opcode (0x4c)
        assert_eq!(
            Script::from_hex(
                "4100000000000000000000000000000000000000000000000000000000000000000000000000000000\
                 00000000000000000000000000000000000000000000000000\
                 4c21030000000000000000000000000000000000000000000000000000000000000000")?
            .parse_p2pkh_spend(),
            None,
        );
        // Bad pubkey opcode (0x4d)
        assert_eq!(
            Script::from_hex(
                "4100000000000000000000000000000000000000000000000000000000000000000000000000000000\
                 00000000000000000000000000000000000000000000000000\
                 4d2100030000000000000000000000000000000000000000000000000000000000000000")?
            .parse_p2pkh_spend(),
            None,
        );
        // Bad pubkey opcode (0x4e)
        assert_eq!(
            Script::from_hex(
                "4100000000000000000000000000000000000000000000000000000000000000000000000000000000\
                 00000000000000000000000000000000000000000000000000\
                 4e21000000030000000000000000000000000000000000000000000000000000000000000000")?
            .parse_p2pkh_spend(),
            None,
        );
        // Bad sig opcode (0x4c)
        assert_eq!(
            Script::from_hex(
                "4c41000000000000000000000000000000000000000000000000000000000000000000000000000000\
                 0000000000000000000000000000000000000000000000000000\
                 21000000000000000000000000000000000000000000000000000000000000000000")?
            .parse_p2pkh_spend(),
            None,
        );
        // Bad sig opcode (0x4d)
        assert_eq!(
            Script::from_hex(
                "4d41003500000000000000000000000000000000000000000000000000000000000000000000000000\
                 000000000000000000000000000000000000000000000000000000\
                 21000000000000000000000000000000000000000000000000000000000000000000")?
            .parse_p2pkh_spend(),
            None,
        );
        // Bad sig opcode (0x4e)
        assert_eq!(
            Script::from_hex(
                "4e41000000350000000000000000000000000000000000000000000000000000000000000000000000\
                 0000000000000000000000000000000000000000000000000000000000\
                 21000000000000000000000000000000000000000000000000000000000000000000")?
            .parse_p2pkh_spend(),
            None,
        );
        // Good
        assert_eq!(
            Script::from_hex(
                "41000000000000000000000000000000000000000000000000000000000000000000000000\
                 0000000000000000000000000000000000000000000000000000000000\
                 21000000000000000000000000000000000000000000000000000000000000000000"
            )?
            .parse_p2pkh_spend(),
            Some(([0; 33].into(), [0; 65].into())),
        );
        Ok(())
    }

    #[test]
    fn test_script_display() -> crate::Result<()> {
        // P2PKH
        assert_eq!(
            Script::p2pkh(&ShaRmd160::new([0xff; 20])).to_string(),
            "OP_DUP OP_HASH160 0xffffffffffffffffffffffffffffffffffffffff OP_EQUALVERIFY OP_CHECKSIG"
        );
        // Incorrect opcode
        assert_eq!(Script::from_hex("ee")?.to_string(), "[unrecognized opcode]");
        // Incomplete pushdata
        assert_eq!(Script::from_hex("0200")?.to_string(), "[corrupt PUSHDATA]");
        // Empty pushdata
        assert_eq!(Script::from_hex("6a4c00")?.to_string(), "OP_RETURN \"\"");
        // ASCII string
        assert_eq!(
            Script::from_hex(
                "6a334368616e63656c6c6f72206f6e20746865204272696e6b206\
                 f66205365636f6e64204261696c6f757420666f722042616e6b73"
            )?
            .to_string(),
            "OP_RETURN \"Chancellor on the Brink of Second Bailout for Banks\""
        );
        // UTF8 string
        assert_eq!(
            Script::from_hex("6a16d791d6b0d6bcd7a8d6b5d790d7a9d6b4d781d799d7aa")?.to_string(),
            "OP_RETURN \"בְּרֵאשִׁית\""
        );
        // SLP token
        assert_eq!(
            Script::from_hex(
                "6a04534c500001010453454e44207e7dacd72dcdb14e00a03dd3a\
                ff47f019ed51a6f1f4e4f532ae50692f62bc4e5080000000000038\
                bd708000000000000091408000000000000092b080000000000000\
                67c08000000000000067c080000000000000cf7080000000000000\
                19f08000000000000033e08000000000000019f080000000000000\
                e6108000000000000002a"
            )?
            .to_string(),
            "OP_RETURN \"SLP\\0\" 0x01 \"SEND\" \
            0x7e7dacd72dcdb14e00a03dd3aff47f019ed51a6f1f4e4f532ae50692f62bc4e5 \
            0x0000000000038bd7 0x0000000000000914 0x000000000000092b \
            0x000000000000067c 0x000000000000067c 0x0000000000000cf7 \
            0x000000000000019f 0x000000000000033e 0x000000000000019f \
            0x0000000000000e61 0x000000000000002a"
        );
        // Symbols
        assert_eq!(
            Script::from_hex(
                "6a2a313233343536373839302d3d21402324255e262a28295f2b6\
                07e5b5d5c7b7d7c3b273a222c2e2f3c3e3f"
            )?
            .to_string(),
            "OP_RETURN \"1234567890-=!@#$%^&*()_+`~[]\\{}|;':\",./<>?\"",
        );
        // Emoji
        assert_eq!(
            Script::from_hex("6a094769766520f09faab7")?.to_string(),
            "OP_RETURN \"Give 🪷\"",
        );
        Ok(())
    }
}
