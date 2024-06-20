use crate::{
    get_merkle_root, lotus_txid, BitcoinCode, ByteArray, Bytes, BytesMut, Hashed, MerkleMode,
    Result, Sha256, Sha256d, Tx,
};

#[derive(Debug, Clone, PartialEq, Eq, Default, Hash)]
pub struct BitcoinHeader {
    pub version: i32,
    pub prev_block: Sha256d,
    pub merkle_root: Sha256d,
    pub timestamp: u32,
    pub bits: u32,
    pub nonce: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BitcoinBlock {
    pub header: BitcoinHeader,
    pub txs: Vec<Tx>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Hash)]
pub struct LotusHeader {
    pub prev_block: Sha256d,
    pub bits: u32,
    pub timestamp: i64,
    pub reserved: u16,
    pub nonce: u64,
    pub version: u8,
    pub size: u64,
    pub height: i32,
    pub epoch_hash: Sha256d,
    pub merkle_root: Sha256d,
    pub extended_metadata_hash: Sha256d,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LotusBlock {
    pub header: LotusHeader,
    pub metadata: Vec<LotusMetadataField>,
    pub txs: Vec<Tx>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LotusMetadataField {
    pub field_id: u32,
    pub field_value: Vec<u8>,
}

impl BitcoinCode for BitcoinHeader {
    fn ser_to(&self, bytes: &mut BytesMut) {
        self.version.ser_to(bytes);
        self.prev_block.ser_to(bytes);
        self.merkle_root.ser_to(bytes);
        self.timestamp.ser_to(bytes);
        self.bits.ser_to(bytes);
        self.nonce.ser_to(bytes);
    }

    fn deser(data: &mut Bytes) -> Result<Self> {
        Ok(BitcoinHeader {
            version: BitcoinCode::deser(data)?,
            prev_block: BitcoinCode::deser(data)?,
            merkle_root: BitcoinCode::deser(data)?,
            timestamp: BitcoinCode::deser(data)?,
            bits: BitcoinCode::deser(data)?,
            nonce: BitcoinCode::deser(data)?,
        })
    }
}

impl BitcoinCode for BitcoinBlock {
    fn ser_to(&self, bytes: &mut BytesMut) {
        self.header.ser_to(bytes);
        self.txs.ser_to(bytes);
    }

    fn deser(data: &mut Bytes) -> Result<Self> {
        Ok(BitcoinBlock {
            header: BitcoinCode::deser(data)?,
            txs: BitcoinCode::deser(data)?,
        })
    }
}

impl BitcoinCode for LotusHeader {
    fn ser_to(&self, bytes: &mut BytesMut) {
        self.prev_block.ser_to(bytes);
        self.bits.ser_to(bytes);
        ByteArray::<6>::from_slice(&self.timestamp.to_le_bytes()[..6])
            .unwrap()
            .ser_to(bytes);
        self.reserved.ser_to(bytes);
        self.nonce.ser_to(bytes);
        self.version.ser_to(bytes);
        ByteArray::<7>::from_slice(&self.size.to_le_bytes()[..7])
            .unwrap()
            .ser_to(bytes);
        self.height.ser_to(bytes);
        self.epoch_hash.ser_to(bytes);
        self.merkle_root.ser_to(bytes);
        self.extended_metadata_hash.ser_to(bytes);
    }

    fn deser(data: &mut Bytes) -> Result<Self> {
        Ok(LotusHeader {
            prev_block: BitcoinCode::deser(data)?,
            bits: BitcoinCode::deser(data)?,
            timestamp: {
                let timestamp = ByteArray::<6>::deser(data)?;
                let mut timestamp_array = [0; 8];
                timestamp_array[..6].copy_from_slice(timestamp.as_ref());
                i64::from_le_bytes(timestamp_array)
            },
            reserved: BitcoinCode::deser(data)?,
            nonce: BitcoinCode::deser(data)?,
            version: BitcoinCode::deser(data)?,
            size: {
                let size = ByteArray::<7>::deser(data)?;
                let mut size_array = [0; 8];
                size_array[..7].copy_from_slice(size.as_ref());
                u64::from_le_bytes(size_array)
            },
            height: BitcoinCode::deser(data)?,
            epoch_hash: BitcoinCode::deser(data)?,
            merkle_root: BitcoinCode::deser(data)?,
            extended_metadata_hash: BitcoinCode::deser(data)?,
        })
    }
}

impl BitcoinCode for LotusBlock {
    fn ser_to(&self, bytes: &mut BytesMut) {
        self.header.ser_to(bytes);
        self.metadata.ser_to(bytes);
        self.txs.ser_to(bytes);
    }

    fn deser(data: &mut Bytes) -> Result<Self> {
        Ok(LotusBlock {
            header: BitcoinCode::deser(data)?,
            metadata: BitcoinCode::deser(data)?,
            txs: BitcoinCode::deser(data)?,
        })
    }
}

impl BitcoinCode for LotusMetadataField {
    fn ser_to(&self, bytes: &mut BytesMut) {
        self.field_id.ser_to(bytes);
        self.field_value.ser_to(bytes);
    }

    fn deser(data: &mut Bytes) -> Result<Self> {
        Ok(LotusMetadataField {
            field_id: BitcoinCode::deser(data)?,
            field_value: BitcoinCode::deser(data)?,
        })
    }
}

impl BitcoinHeader {
    pub fn calc_hash(&self) -> Sha256d {
        let mut bytes = BytesMut::new();
        self.ser_to(&mut bytes);
        Sha256d::digest(&bytes.freeze())
    }

    pub fn solve(&mut self) {
        loop {
            let hash = self.calc_hash();
            if hash.as_slice()[31] & 0x80 == 0 {
                return;
            }
            self.nonce = self.nonce.wrapping_add(1);
        }
    }
}

impl LotusHeader {
    pub fn calc_hash(&self) -> Sha256d {
        let mut header = BytesMut::new();
        self.ser_to(&mut header);
        let header = header.freeze();
        let layer3 = &header[52..];
        let mut layer2 = BytesMut::new();
        layer2.put_slice(&header[32..52]);
        layer2.put_byte_array(Sha256::digest(layer3.into()).byte_array().clone());
        let mut layer1 = BytesMut::new();
        layer1.put_slice(&header[..32]);
        layer1.put_byte_array(Sha256::digest(&layer2.freeze()).byte_array().clone());
        let hash = Sha256::digest(&layer1.freeze());
        Sha256d::new(hash.byte_array().array())
    }

    pub fn solve(&mut self) {
        loop {
            let hash = self.calc_hash();
            if hash.as_slice()[31] & 0x80 == 0 {
                return;
            }
            self.nonce = self.nonce.wrapping_add(1);
        }
    }
}

impl BitcoinBlock {
    pub fn update_merkle_root(&mut self) {
        let leaves = self.txs.iter().map(|tx| tx.hash().clone()).collect();
        self.header.merkle_root = get_merkle_root(leaves, MerkleMode::Bitcoin);
    }
}

impl LotusBlock {
    pub fn update_merkle_root(&mut self) {
        let leaves = self
            .txs
            .iter()
            .map(|tx| {
                let mut leaf_bytes = BytesMut::new();
                leaf_bytes.put_byte_array(tx.hash().byte_array().clone());
                leaf_bytes.put_byte_array(lotus_txid(tx.unhashed_tx()).byte_array().clone());
                Sha256d::digest(&leaf_bytes.freeze())
            })
            .collect();
        self.header.merkle_root = get_merkle_root(leaves, MerkleMode::Lotus);
    }

    pub fn update_extended_metadata_hash(&mut self) {
        let mut bytes = BytesMut::new();
        self.metadata.ser_to(&mut bytes);
        self.header.extended_metadata_hash = Sha256d::digest(&bytes.freeze());
    }

    pub fn update_size(&mut self) {
        let mut bytes = BytesMut::new();
        self.ser_to(&mut bytes);
        self.header.size = bytes.freeze().len() as u64;
    }

    pub fn prepare(&mut self) {
        self.update_merkle_root();
        self.update_extended_metadata_hash();
        self.update_size();
        self.header.solve();
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        lotus_txid, BitcoinBlock, BitcoinHeader, Hashed, LotusBlock, LotusHeader, OutPoint, Script,
        SequenceNo, Sha256d, TxInput, TxOutput, UnhashedTx,
    };

    #[allow(clippy::inconsistent_digit_grouping)]
    #[test]
    fn test_bitcoin_genesis_block() {
        let genesis_header = BitcoinHeader {
            version: 1,
            prev_block: Sha256d::default(),
            timestamp: 1231006505,
            bits: 0x1d00ffff,
            nonce: 2083236893,
            ..Default::default()
        };
        let genesis_script_sig = *b"\
            \x04\xff\xff\x00\x1d\x01\x04\x45\
            The Times 03/Jan/2009 Chancellor on brink of second bailout for banks";
        let genesis_coinbase = UnhashedTx {
            version: 1,
            inputs: vec![TxInput {
                prev_out: OutPoint {
                    txid: Sha256d::default(),
                    out_idx: 0xffff_ffff,
                },
                script: Script::new(genesis_script_sig.into()),
                sequence: SequenceNo::finalized(),
                ..Default::default()
            }],
            outputs: vec![TxOutput {
                value: 50_000_000_00i64,
                script: Script::from_hex(
                    "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4c\
                    ef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac",
                )
                .unwrap(),
            }],
            lock_time: 0,
        };
        let genesis_coinbase = genesis_coinbase.hashed();
        let merkle_root_hex = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b";
        assert_eq!(
            genesis_coinbase.hash(),
            &Sha256d::from_hex_be(merkle_root_hex).unwrap()
        );
        let mut genesis_block = BitcoinBlock {
            header: genesis_header,
            txs: vec![genesis_coinbase],
        };
        genesis_block.update_merkle_root();
        assert_eq!(
            genesis_block.header.merkle_root,
            Sha256d::from_hex_be(merkle_root_hex).unwrap()
        );
        let genesis_hash_hex = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
        assert_eq!(
            genesis_block.header.calc_hash(),
            Sha256d::from_hex_be(genesis_hash_hex).unwrap()
        );
    }

    #[test]
    fn test_lotus_genesis_block() {
        let genesis_header = LotusHeader {
            prev_block: Sha256d::default(),
            bits: 0x1c100000,
            timestamp: 1624246260,
            nonce: 7146261898250975403,
            version: 1,
            height: 0,
            epoch_hash: Sha256d::default(),
            ..Default::default()
        };
        let genesis_script_sig = *b"\x27John 1:1 In the beginning was the Logos";
        let genesis_coinbase = UnhashedTx {
            version: 1,
            inputs: vec![TxInput {
                prev_out: OutPoint {
                    txid: Sha256d::default(),
                    out_idx: 0xffff_ffff,
                },
                script: Script::new(genesis_script_sig.into()),
                sequence: SequenceNo::finalized(),
                ..Default::default()
            }],
            outputs: vec![TxOutput {
                value: 130_000_000,
                script: Script::from_hex(
                    "6a056c6f676f730020ffe330c4b7643e554c62adcbe0b80537435d888b5c33d5e29a70cdd743e3\
                    a093",
                )
                .unwrap(),
            }, TxOutput {
                value: 130_000_000,
                script: Script::from_hex(
                    "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4c\
                    ef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac",
                )
                .unwrap(),
            }],
            lock_time: 0,
        };
        let genesis_txid = "7455e298a18829d294441acaabcb854e04b2dd609e29c6cc805392271f9c53ea";
        assert_eq!(
            lotus_txid(&genesis_coinbase),
            Sha256d::from_hex_be(genesis_txid).unwrap()
        );
        let genesis_coinbase = genesis_coinbase.hashed();
        let mut genesis_block = LotusBlock {
            header: genesis_header,
            txs: vec![genesis_coinbase],
            metadata: vec![],
        };
        genesis_block.update_merkle_root();
        genesis_block.update_extended_metadata_hash();
        genesis_block.update_size();
        let merkle_root_hex = "37f392d88f70cdada6d366a25a7ef90b6711bf2d6b5ffea4f39727dcb90af34c";
        assert_eq!(
            genesis_block.header.merkle_root,
            Sha256d::from_hex_be(merkle_root_hex).unwrap()
        );
        let genesis_hash_hex = "000000000abc0cde58ee7e919d3d4de183e6844add1fd5d14b4eac89d958f470";
        assert_eq!(
            genesis_block.header.calc_hash(),
            Sha256d::from_hex_be(genesis_hash_hex).unwrap()
        );
    }
}
