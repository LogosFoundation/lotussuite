use std::{fmt::Display, str::FromStr};
use thiserror::Error;

use crate::{BytesMut, Hashed, Net, Script, Sha256};

pub const LOTUS_ADDRESS_CHECKSUM_LEN: usize = 4;
pub const LOTUS_PREFIX: &str = "lotus";

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct LotusAddress {
    prefix: String,
    net: Net,
    lotus_addr: String,
    script: Script,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum LotusAddressType {
    OutputScript = 0,
}

#[derive(Error, Clone, Debug, Eq, PartialEq)]
pub enum LotusAddressError {
    #[error("Missing prefix")]
    MissingPrefix,

    #[error("Missing checksum")]
    MissingChecksum,

    #[error("Missing net character")]
    MissingNetChar,

    #[error("Unsupported net {0}")]
    UnsupportedNet(char),

    #[error("Invalid base58")]
    InvalidBase58(bs58::decode::Error),

    #[error("Missing base58")]
    MissingBase58,

    #[error("Missing payload")]
    MissingPayload,

    #[error("Invalid payload type: {0}")]
    InvalidPayloadType(u8),

    #[error("Invalid checksum, expected {expected} but got {actual}")]
    InvalidChecksum { expected: String, actual: String },
}

use self::LotusAddressError::*;

impl LotusAddress {
    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    pub fn net(&self) -> Net {
        self.net
    }

    pub fn script(&self) -> &Script {
        &self.script
    }

    pub fn as_str(&self) -> &str {
        &self.lotus_addr
    }
}

impl LotusAddress {
    pub fn new(prefix: &str, net: Net, script: Script) -> Self {
        let mut lotus_addr = prefix.to_string();
        let net_char = match net {
            Net::Mainnet => '_',
            Net::Regtest => 'R',
        };
        lotus_addr.push(net_char);

        let checksum = calc_checksum(
            prefix,
            net_char,
            LotusAddressType::OutputScript as u8,
            script.bytecode(),
        );

        let mut data = BytesMut::new();
        data.put_slice(&[LotusAddressType::OutputScript as u8]);
        data.put_slice(script.bytecode());
        data.put_slice(&checksum);
        lotus_addr.push_str(&bs58::encode(data.as_slice()).into_string());

        LotusAddress {
            prefix: prefix.to_string(),
            net,
            lotus_addr,
            script,
        }
    }
}

impl FromStr for LotusAddress {
    type Err = LotusAddressError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // "lotus" part of an address
        let prefix = s
            .chars()
            .take_while(|&c| (c.is_ascii_alphabetic() && c.is_lowercase()) || c.is_ascii_digit())
            .collect::<String>();
        if prefix.is_empty() {
            return Err(MissingPrefix);
        }
        // net: "_" for mainnet, "R" for regtest, "T" for testnet (unsupported)
        let net_char = s.chars().nth(prefix.len()).ok_or(MissingNetChar)?;
        let net = match net_char {
            '_' => Net::Mainnet,
            'R' => Net::Regtest,
            _ => return Err(UnsupportedNet(net_char)),
        };
        // Base58 encoded data
        let data_b58 = &s[prefix.len() + 1..];
        let data = bs58::decode(&data_b58).into_vec().map_err(InvalidBase58)?;
        // First byte indicates payload type. Currently only "0" is supported
        let payload_type = *data.first().ok_or(MissingBase58)?;
        if payload_type != 0 {
            return Err(InvalidPayloadType(payload_type));
        }
        // Remainder is the payload, here the scriptPubKey
        let checksum_end_idx = data
            .len()
            .checked_sub(LOTUS_ADDRESS_CHECKSUM_LEN)
            .ok_or(MissingChecksum)?;
        let payload = data.get(1..checksum_end_idx).ok_or(MissingChecksum)?;
        if payload.is_empty() {
            return Err(MissingPayload);
        }
        let expected_checksum = &data[data.len() - LOTUS_ADDRESS_CHECKSUM_LEN..];
        let actual_checksum = calc_checksum(&prefix, net_char, payload_type, payload);

        // Verify checksum
        if expected_checksum != actual_checksum {
            return Err(InvalidChecksum {
                expected: hex::encode(expected_checksum),
                actual: hex::encode(actual_checksum),
            });
        }
        let script = Script::from_slice(payload);
        Ok(LotusAddress {
            prefix,
            net,
            lotus_addr: s.to_string(),
            script,
        })
    }
}

impl Display for LotusAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.lotus_addr.fmt(f)
    }
}

fn calc_checksum(prefix: &str, net_char: char, payload_type: u8, payload: &[u8]) -> [u8; 4] {
    // The data that will be hashed for the checksum
    let mut checksum_preimage = BytesMut::new();
    checksum_preimage.put_slice(prefix.as_bytes());
    checksum_preimage.put_slice(&[net_char as u8, payload_type]);
    checksum_preimage.put_slice(payload);
    let checksum_hash = Sha256::digest(&checksum_preimage.freeze());
    checksum_hash.as_slice()[..LOTUS_ADDRESS_CHECKSUM_LEN]
        .try_into()
        .unwrap()
}

#[cfg(test)]
mod tests {
    use crate::{Hashed, LotusAddress, LotusAddressError, Net, Script, ShaRmd160, LOTUS_PREFIX};

    #[test]
    fn decode_lotus_address() -> Result<(), Box<dyn std::error::Error>> {
        let p2pkh = Script::p2pkh(&ShaRmd160::from_hex(
            "b50b86a893d80c9e2ee72b199612374b7b4c1cd8",
        )?);
        let p2sh = Script::p2sh(&ShaRmd160::from_hex(
            "260617ebf668c9102f71ce24aba97fcaaf9c666a",
        )?);
        {
            let address =
                "lotus_16PSJNf1EDEfGvaYzaXJCJZrXH4pgiTo7kyW61iGi".parse::<LotusAddress>()?;
            assert_eq!(address.prefix(), "lotus");
            assert_eq!(address.net(), Net::Mainnet);
            assert_eq!(address.script(), &p2pkh);
            assert_eq!(
                address.as_str(),
                "lotus_16PSJNf1EDEfGvaYzaXJCJZrXH4pgiTo7kyW61iGi",
            );
        }
        {
            let address =
                "lotusR16PSJNf1EDEfGvaYzaXJCJZrXH4pgiTo7kyVqAied".parse::<LotusAddress>()?;
            assert_eq!(address.prefix(), "lotus");
            assert_eq!(address.net(), Net::Regtest);
            assert_eq!(address.script(), &p2pkh);
            assert_eq!(
                address.as_str(),
                "lotusR16PSJNf1EDEfGvaYzaXJCJZrXH4pgiTo7kyVqAied",
            );
        }
        {
            let address = "lotus_1PrQReKdmXH6hyCk4NFR398HeWxvJWW4E3jjM3".parse::<LotusAddress>()?;
            assert_eq!(address.prefix(), "lotus");
            assert_eq!(address.net(), Net::Mainnet);
            assert_eq!(address.script(), &p2sh);
            assert_eq!(
                address.as_str(),
                "lotus_1PrQReKdmXH6hyCk4NFR398HeWxvJWW4E3jjM3",
            );
        }
        {
            let address = "lotusR1PrQReKdmXH6hyCk4NFR398HeWxvJWW4Hie3rA".parse::<LotusAddress>()?;
            assert_eq!(address.prefix(), "lotus");
            assert_eq!(address.net(), Net::Regtest);
            assert_eq!(address.script(), &p2sh);
            assert_eq!(
                address.as_str(),
                "lotusR1PrQReKdmXH6hyCk4NFR398HeWxvJWW4Hie3rA",
            );
        }

        assert_eq!(
            "A".parse::<LotusAddress>().unwrap_err(),
            LotusAddressError::MissingPrefix,
        );
        assert_eq!(
            "lotus".parse::<LotusAddress>().unwrap_err(),
            LotusAddressError::MissingNetChar,
        );
        assert_eq!(
            "lotusP".parse::<LotusAddress>().unwrap_err(),
            LotusAddressError::UnsupportedNet('P'),
        );
        assert_eq!(
            "lotus_".parse::<LotusAddress>().unwrap_err(),
            LotusAddressError::MissingBase58,
        );
        assert_eq!(
            "lotusR".parse::<LotusAddress>().unwrap_err(),
            LotusAddressError::MissingBase58,
        );
        assert_eq!(
            "lotus_0".parse::<LotusAddress>().unwrap_err(),
            LotusAddressError::InvalidBase58(bs58::decode::Error::InvalidCharacter {
                character: '0',
                index: 0
            }),
        );
        assert_eq!(
            "lotus_1".parse::<LotusAddress>().unwrap_err(),
            LotusAddressError::MissingChecksum,
        );
        assert_eq!(
            "lotus_1111".parse::<LotusAddress>().unwrap_err(),
            LotusAddressError::MissingChecksum,
        );
        assert_eq!(
            "lotus_11111".parse::<LotusAddress>().unwrap_err(),
            LotusAddressError::MissingPayload,
        );
        assert_eq!(
            "lotus_111111".parse::<LotusAddress>().unwrap_err(),
            LotusAddressError::InvalidChecksum {
                expected: "00000000".to_string(),
                actual: "66276ef9".to_string(),
            },
        );

        Ok(())
    }

    #[test]
    fn encode_lotus_address() -> Result<(), Box<dyn std::error::Error>> {
        let p2pkh = Script::p2pkh(&ShaRmd160::from_hex(
            "b50b86a893d80c9e2ee72b199612374b7b4c1cd8",
        )?);
        let p2sh = Script::p2sh(&ShaRmd160::from_hex(
            "260617ebf668c9102f71ce24aba97fcaaf9c666a",
        )?);
        {
            let address = LotusAddress::new(LOTUS_PREFIX, Net::Mainnet, p2pkh.clone());
            assert_eq!(address.prefix(), "lotus");
            assert_eq!(address.net(), Net::Mainnet);
            assert_eq!(address.script(), &p2pkh);
            assert_eq!(
                address.as_str(),
                "lotus_16PSJNf1EDEfGvaYzaXJCJZrXH4pgiTo7kyW61iGi",
            );
        }
        {
            let address = LotusAddress::new(LOTUS_PREFIX, Net::Regtest, p2pkh.clone());
            assert_eq!(address.prefix(), "lotus");
            assert_eq!(address.net(), Net::Regtest);
            assert_eq!(address.script(), &p2pkh);
            assert_eq!(
                address.as_str(),
                "lotusR16PSJNf1EDEfGvaYzaXJCJZrXH4pgiTo7kyVqAied",
            );
        }
        {
            let address = LotusAddress::new(LOTUS_PREFIX, Net::Mainnet, p2sh.clone());
            assert_eq!(address.prefix(), "lotus");
            assert_eq!(address.net(), Net::Mainnet);
            assert_eq!(address.script(), &p2sh);
            assert_eq!(
                address.as_str(),
                "lotus_1PrQReKdmXH6hyCk4NFR398HeWxvJWW4E3jjM3",
            );
        }
        {
            let address = LotusAddress::new(LOTUS_PREFIX, Net::Regtest, p2sh.clone());
            assert_eq!(address.prefix(), "lotus");
            assert_eq!(address.net(), Net::Regtest);
            assert_eq!(address.script(), &p2sh);
            assert_eq!(
                address.as_str(),
                "lotusR1PrQReKdmXH6hyCk4NFR398HeWxvJWW4Hie3rA",
            );
        }

        Ok(())
    }
}
