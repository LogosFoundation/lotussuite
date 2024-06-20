use std::{borrow::Cow, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

use crate::{AddressType, Hashed, Script, ShaRmd160};

pub const BITCOINCASH: &str = "bitcoincash";
pub const BCHREG: &str = "bchreg";
pub const SIMPLELEDGER: &str = "simpleledger";
pub const ECASH: &str = "ecash";
pub const ETOKEN: &str = "etoken";
pub const ECREGTEST: &str = "ecregtest";

const CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct CashAddress<'a> {
    addr_type: AddressType,
    hash: ShaRmd160,
    cash_addr: Cow<'a, str>,
    prefix: Cow<'a, str>,
}

#[derive(Error, Clone, Copy, Debug, Eq, PartialEq)]
pub enum CashAddressError {
    #[error("Invalid checksum")]
    InvalidChecksum,
    #[error("Invalid Base32 letter {1} at index {0}")]
    InvalidBase32Letter(usize, u8),
    #[error("Invalid address type {0}")]
    InvalidAddressType(u8),
    #[error("Missing prefix")]
    MissingPrefix,
    #[error("Invalid payload length: {0}")]
    InvalidPayloadLength(usize),
}

impl<'a> CashAddress<'a> {
    pub fn from_hash(
        prefix: impl Into<Cow<'a, str>>,
        addr_type: AddressType,
        hash: ShaRmd160,
    ) -> Self {
        let prefix = prefix.into();
        CashAddress {
            cash_addr: _to_cash_addr(&prefix, addr_type as u8, hash.as_slice()).into(),
            addr_type,
            hash,
            prefix,
        }
    }

    pub fn parse_cow(cash_addr: Cow<'a, str>) -> Result<Self, CashAddressError> {
        let (hash, addr_type, prefix) = _from_cash_addr(&cash_addr)?;
        Ok(CashAddress {
            cash_addr,
            addr_type,
            hash: ShaRmd160::from_array(hash.into()),
            prefix: prefix.into(),
        })
    }

    pub fn from_redeem_script(prefix: impl Into<Cow<'a, str>>, redeem_script: Script) -> Self {
        CashAddress::from_hash(
            prefix,
            AddressType::P2SH,
            ShaRmd160::digest(&redeem_script.bytecode().clone()),
        )
    }

    pub fn hash(&self) -> &ShaRmd160 {
        &self.hash
    }

    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    pub fn as_str(&self) -> &str {
        &self.cash_addr
    }

    pub fn into_string(self) -> String {
        self.cash_addr.into_owned()
    }

    pub fn addr_type(&self) -> AddressType {
        self.addr_type
    }

    pub fn with_prefix(&'a self, prefix: impl Into<Cow<'a, str>>) -> Self {
        Self::from_hash(prefix, self.addr_type, self.hash.clone())
    }

    pub fn to_owned_address(&self) -> CashAddress<'static> {
        CashAddress {
            addr_type: self.addr_type,
            hash: self.hash.clone(),
            cash_addr: self.cash_addr.to_string().into(),
            prefix: self.prefix.to_string().into(),
        }
    }

    pub fn into_owned_address(self) -> CashAddress<'static> {
        CashAddress {
            addr_type: self.addr_type,
            hash: self.hash,
            cash_addr: self.cash_addr.into_owned().into(),
            prefix: self.prefix.into_owned().into(),
        }
    }

    pub fn to_script(&self) -> Script {
        match self.addr_type {
            AddressType::P2PKH => Script::p2pkh(self.hash()),
            AddressType::P2SH => Script::p2sh(self.hash()),
        }
    }
}

impl FromStr for CashAddress<'static> {
    type Err = CashAddressError;

    fn from_str(s: &str) -> Result<Self, CashAddressError> {
        Ok(CashAddress::parse_cow(s.into())?.into_owned_address())
    }
}

#[derive(Serialize, Deserialize)]
struct SerAddress<'a> {
    addr_type: AddressType,
    hash: [u8; 20],
    prefix: &'a str,
}

impl Serialize for CashAddress<'_> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            self.as_str().serialize(serializer)
        } else {
            SerAddress {
                addr_type: self.addr_type,
                hash: self.hash.byte_array().array(),
                prefix: self.prefix(),
            }
            .serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for CashAddress<'static> {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            String::deserialize(deserializer)?
                .parse()
                .map_err(serde::de::Error::custom)
        } else {
            let ser_address = SerAddress::deserialize(deserializer)?;
            Ok(CashAddress::from_hash(
                ser_address.prefix,
                ser_address.addr_type,
                ShaRmd160::new(ser_address.hash),
            )
            .into_owned_address())
        }
    }
}

fn _map_to_b32(data: impl Iterator<Item = u8>) -> String {
    String::from_utf8(data.map(|x| CHARSET[x as usize]).collect()).unwrap()
}

fn _map_from_b32(string: &str) -> std::result::Result<Vec<u8>, CashAddressError> {
    string
        .as_bytes()
        .iter()
        .enumerate()
        .map(|(i, x)| {
            CHARSET
                .iter()
                .position(|c| x == c)
                .map(|x| x as u8)
                .ok_or(CashAddressError::InvalidBase32Letter(i, *x))
        })
        .collect()
}

fn _convert_bits(
    data: impl Iterator<Item = u8>,
    from_bits: u32,
    to_bits: u32,
    pad: bool,
) -> Option<Vec<u8>> {
    let mut acc = 0;
    let mut bits = 0;
    let mut ret = Vec::new();
    let maxv = (1 << to_bits) - 1;
    let max_acc = (1 << (from_bits + to_bits - 1)) - 1;
    for value in data {
        let value = value as u32;
        if (value >> from_bits) != 0 {
            return None;
        }
        acc = ((acc << from_bits) | value) & max_acc;
        bits += from_bits;
        while bits >= to_bits {
            bits -= to_bits;
            ret.push(((acc >> bits) & maxv) as u8);
        }
    }
    if pad {
        if bits != 0 {
            ret.push(((acc << (to_bits - bits)) & maxv) as u8);
        }
    } else if bits >= from_bits || ((acc << (to_bits - bits)) & maxv != 0) {
        return None;
    }
    Some(ret)
}

fn _poly_mod(values: impl Iterator<Item = u8>) -> u64 {
    let mut c = 1;
    for value in values {
        let c0 = (c >> 35) as u8;
        c = ((c & 0x07_ffff_ffffu64) << 5u64) ^ (value as u64);
        if c0 & 0x01 != 0 {
            c ^= 0x98_f2bc_8e61
        }
        if c0 & 0x02 != 0 {
            c ^= 0x79_b76d_99e2
        }
        if c0 & 0x04 != 0 {
            c ^= 0xf3_3e5f_b3c4
        }
        if c0 & 0x08 != 0 {
            c ^= 0xae_2eab_e2a8
        }
        if c0 & 0x10 != 0 {
            c ^= 0x1e_4f43_e470
        }
    }
    c ^ 1
}

fn _calculate_checksum(prefix: &str, payload: impl Iterator<Item = u8>) -> Vec<u8> {
    let poly = _poly_mod(
        prefix
            .as_bytes()
            .iter()
            .map(|x| *x & 0x1f)
            .chain([0])
            .chain(payload)
            .chain([0, 0, 0, 0, 0, 0, 0, 0]),
    );
    (0..8)
        .map(|i| ((poly >> (5 * (7 - i))) & 0x1f) as u8)
        .collect()
}

fn _verify_checksum(prefix: &str, payload: impl Iterator<Item = u8>) -> bool {
    let poly = _poly_mod(
        prefix
            .as_bytes()
            .iter()
            .map(|x| *x & 0x1f)
            .chain([0])
            .chain(payload),
    );
    poly == 0
}

fn _to_cash_addr(prefix: &str, version: u8, addr_bytes: &[u8]) -> String {
    let payload = _convert_bits([version].iter().chain(addr_bytes).cloned(), 8, 5, true).unwrap();
    let checksum = _calculate_checksum(prefix, payload.iter().cloned());
    String::from(prefix) + ":" + &_map_to_b32(payload.into_iter().chain(checksum))
}

fn _from_cash_addr(
    addr_string: &str,
) -> std::result::Result<([u8; 20], AddressType, String), CashAddressError> {
    let addr_string = addr_string.to_ascii_lowercase();
    let (prefix, payload_base32) = match addr_string.find(':') {
        Some(pos) => {
            let (prefix, payload_base32) = addr_string.split_at(pos + 1);
            (prefix[..prefix.len() - 1].to_string(), payload_base32)
        }
        None => return Err(CashAddressError::MissingPrefix),
    };
    let decoded = _map_from_b32(payload_base32)?;
    if !_verify_checksum(&prefix, decoded.iter().cloned()) {
        return Err(CashAddressError::InvalidChecksum);
    }
    let converted = _convert_bits(decoded.into_iter(), 5, 8, true).unwrap();
    let hash = &converted[1..converted.len() - 6];
    let hash: [u8; 20] = match hash.try_into() {
        Ok(hash) => hash,
        Err(_) => return Err(CashAddressError::InvalidPayloadLength(hash.len())),
    };
    Ok((
        hash,
        match converted[0] {
            0 => AddressType::P2PKH,
            8 => AddressType::P2SH,
            x => return Err(CashAddressError::InvalidAddressType(x)),
        },
        prefix,
    ))
}

#[cfg(test)]
mod tests {
    use crate::{
        AddressType, BitcoinSuiteError, CashAddress, CashAddressError, Hashed, Script, ShaRmd160,
        BITCOINCASH, SIMPLELEDGER,
    };

    #[test]
    fn test_from_hash1() {
        let addr = CashAddress::from_hash(BITCOINCASH, AddressType::P2PKH, ShaRmd160::new([0; 20]));
        assert_eq!(
            addr.as_str(),
            "bitcoincash:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqfnhks603"
        );
    }

    #[test]
    fn test_from_hash2() {
        let addr =
            CashAddress::from_hash(SIMPLELEDGER, AddressType::P2PKH, ShaRmd160::new([0; 20]));
        assert_eq!(
            addr.as_str(),
            "simpleledger:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq9gud9630"
        );
    }

    #[test]
    fn test_from_hash3() {
        let addr = CashAddress::from_hash(BITCOINCASH, AddressType::P2SH, ShaRmd160::new([0; 20]));
        assert_eq!(
            addr.as_str(),
            "bitcoincash:pqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq7k2ehe5v"
        );
    }

    #[test]
    fn test_from_hash4() {
        let addr =
            CashAddress::from_hash("redridinghood", AddressType::P2SH, ShaRmd160::new([0; 20]));
        assert_eq!(
            addr.as_str(),
            "redridinghood:pqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqxmg9w0gt"
        );
    }

    #[test]
    fn test_parse1() -> Result<(), CashAddressError> {
        let addr: CashAddress = "bitcoincash:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqfnhks603".parse()?;
        assert_eq!(addr.addr_type(), AddressType::P2PKH);
        assert_eq!(
            addr.as_str(),
            "bitcoincash:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqfnhks603"
        );
        assert_eq!(addr.hash(), &ShaRmd160::new([0; 20]));
        assert_eq!(addr.prefix(), "bitcoincash");
        Ok(())
    }

    #[test]
    fn test_parse2() -> Result<(), CashAddressError> {
        let addr: CashAddress =
            "simpleledger:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq9gud9630".parse()?;
        assert_eq!(addr.addr_type(), AddressType::P2PKH);
        assert_eq!(
            addr.as_str(),
            "simpleledger:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq9gud9630"
        );
        assert_eq!(addr.hash(), &ShaRmd160::new([0; 20]));
        assert_eq!(addr.prefix(), "simpleledger");
        Ok(())
    }

    #[test]
    fn test_parse3() -> Result<(), CashAddressError> {
        let addr: CashAddress = "bitcoincash:pqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq7k2ehe5v".parse()?;
        assert_eq!(addr.addr_type(), AddressType::P2SH);
        assert_eq!(
            addr.as_str(),
            "bitcoincash:pqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq7k2ehe5v"
        );
        assert_eq!(addr.hash(), &ShaRmd160::new([0; 20]));
        assert_eq!(addr.prefix(), "bitcoincash");
        Ok(())
    }

    #[test]
    fn test_parse4() -> Result<(), CashAddressError> {
        let addr: CashAddress =
            "redridinghood:pqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqxmg9w0gt".parse()?;
        assert_eq!(addr.addr_type(), AddressType::P2SH);
        assert_eq!(
            addr.as_str(),
            "redridinghood:pqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqxmg9w0gt"
        );
        assert_eq!(addr.hash(), &ShaRmd160::new([0; 20]));
        assert_eq!(addr.prefix(), "redridinghood");
        Ok(())
    }

    #[test]
    fn test_parse_fail_wrong_prefix() {
        let err = "wrongprefix:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqfnhks603"
            .parse::<CashAddress>()
            .unwrap_err();
        match err {
            CashAddressError::InvalidChecksum => {}
            _ => panic!("Unexpected error: {}", err),
        }
    }

    #[test]
    fn test_parse_fail_no_prefix() {
        let err = "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqfnhks603"
            .parse::<CashAddress>()
            .unwrap_err();
        match err {
            CashAddressError::MissingPrefix => {}
            _ => panic!("Unexpected error: {}", err),
        }
    }

    #[test]
    fn test_parse_fail_invalid_type() {
        let err = "bitcoincash:qyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqx2jnhvj3"
            .parse::<CashAddress>()
            .unwrap_err();
        match err {
            CashAddressError::InvalidAddressType(1) => {}
            _ => panic!("Unexpected error: {}", err),
        }
    }

    #[test]
    fn test_parse_fail_invalid_payload_length() {
        let err = "bitcoincash:qqqqqqqr0p35l2w"
            .parse::<CashAddress>()
            .unwrap_err();
        match err {
            CashAddressError::InvalidPayloadLength(3) => {}
            _ => panic!("Unexpected error: {}", err),
        }
    }

    #[test]
    fn test_from_redeem_script() -> Result<(), BitcoinSuiteError> {
        let addr =
            CashAddress::from_redeem_script("bitcoincash", Script::from_static_slice(&[0x51]));
        assert_eq!(addr.addr_type(), AddressType::P2SH);
        assert_eq!(
            addr.as_str(),
            "bitcoincash:prdpw30fk4ym6zl6rftfjuw806arpn26fv8cp7wyl3"
        );
        assert_eq!(
            addr.hash(),
            &ShaRmd160::from_hex_be("4b5acd30ba7ec77199561afa0bbd49b5e94517da")?
        );
        assert_eq!(addr.prefix(), "bitcoincash");
        Ok(())
    }

    #[test]
    fn test_serialize_json() -> Result<(), CashAddressError> {
        let addr: CashAddress = "bitcoincash:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqfnhks603".parse()?;
        let addr_json = serde_json::to_string(&addr).unwrap();
        assert_eq!(
            addr_json,
            "\"bitcoincash:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqfnhks603\""
        );
        Ok(())
    }

    #[test]
    fn test_deserialize_json() {
        let addr_json = "\"bitcoincash:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqfnhks603\"";
        let addr: CashAddress = serde_json::from_str(addr_json).unwrap();
        assert_eq!(
            addr.as_str(),
            "bitcoincash:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqfnhks603"
        );
    }

    #[test]
    fn test_serialize_bincode() -> Result<(), CashAddressError> {
        let addr: CashAddress = "bitcoincash:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqfnhks603".parse()?;
        let addr_bincode = bincode::serialize(&addr).unwrap();
        assert_eq!(
            hex::encode(&addr_bincode),
            // 4 bytes addr_type, 20 bytes hash, 8 bytes prefix length, 11 bytes "bitcoincash"
            "00000000\
            0000000000000000000000000000000000000000\
            0b00000000000000\
            626974636f696e63617368"
        );
        Ok(())
    }

    #[test]
    fn test_deserialize_bincode() {
        let addr_bincode = hex::decode(
            // 4 bytes addr_type, 20 bytes hash, 8 bytes prefix length, 11 bytes "bitcoincash"
            "00000000\
            0000000000000000000000000000000000000000\
            0b00000000000000\
            626974636f696e63617368",
        )
        .unwrap();
        let addr: CashAddress = bincode::deserialize(&addr_bincode).unwrap();
        assert_eq!(
            addr.as_str(),
            "bitcoincash:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqfnhks603"
        );
    }

    #[test]
    fn test_with_prefix() -> Result<(), CashAddressError> {
        let addr: CashAddress =
            "redridinghood:pqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqxmg9w0gt".parse()?;
        let new_addr = addr.with_prefix("prelude");
        assert_eq!(new_addr.addr_type(), AddressType::P2SH);
        assert_eq!(
            new_addr.as_str(),
            "prelude:pqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqrs52h40n"
        );
        assert_eq!(new_addr.hash(), &ShaRmd160::new([0; 20]));
        assert_eq!(new_addr.prefix(), "prelude");
        Ok(())
    }

    #[test]
    fn test_to_script_p2sh() -> Result<(), CashAddressError> {
        let addr: CashAddress = "bitcoincash:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqfnhks603".parse()?;
        assert_eq!(
            addr.to_script().bytecode().as_ref(),
            &[
                0x76, 0xa9, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x88,
                0xac
            ]
        );
        Ok(())
    }

    #[test]
    fn test_to_script_p2pkh() -> Result<(), CashAddressError> {
        let addr: CashAddress = "bitcoincash:pqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq7k2ehe5v".parse()?;
        assert_eq!(
            addr.to_script().bytecode().as_ref(),
            &[0xa9, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x87]
        );
        Ok(())
    }
}
