use std::{
    cmp::Ordering,
    fmt::{Debug, Display},
    hash::Hash,
};

use digest::Digest;

use crate::{
    byte_array::ByteArray,
    bytes::Bytes,
    error::{BitcoinSuiteError, Result},
    BitcoinCode, BytesMut,
};

pub trait Hashed: Display + Debug + Eq + PartialEq + AsRef<[u8]> + Hash + Sized {
    type Array: Default;
    fn size() -> usize;
    fn from_array(array: Self::Array) -> Self;
    fn digest(data: &[u8]) -> Self;
    fn from_slice_optional(hash: &[u8]) -> Option<Self>;
    fn byte_array(&self) -> &Self::Array;

    fn from_slice(hash: &[u8]) -> Result<Self> {
        Self::from_slice_optional(hash).ok_or_else(|| BitcoinSuiteError::InvalidSize {
            expected: Self::size(),
            actual: hash.len(),
        })
    }

    fn from_slice_be(hash: &[u8]) -> Result<Self> {
        let mut hash = hash.to_vec();
        hash.reverse();
        Self::from_slice(&hash)
    }

    fn from_slice_or_null(hash: &[u8]) -> Self {
        Self::from_slice_optional(hash).unwrap_or_else(|| Self::from_array(Default::default()))
    }

    fn from_slice_be_or_null(hash: &[u8]) -> Self {
        let mut hash = hash.to_vec();
        hash.reverse();
        Self::from_slice_optional(&hash).unwrap_or_else(|| Self::from_array(Default::default()))
    }

    fn from_hex(hex: &str) -> Result<Self> {
        Self::from_slice(&hex::decode(hex)?)
    }

    fn from_hex_be(hex: &str) -> Result<Self> {
        Self::from_slice_be(&hex::decode(hex)?)
    }

    fn as_slice(&self) -> &[u8] {
        self.as_ref()
    }

    fn to_vec_be(&self) -> Vec<u8> {
        self.as_slice().iter().cloned().rev().collect()
    }

    fn to_hex_be(&self) -> String {
        hex::encode(&self.to_vec_be())
    }
}

macro_rules! hash_algo {
    ($NAME: ident, $SIZE: literal, $DIGEST_FN: path) => {
        #[derive(Clone, Eq, PartialEq, Default, Hash)]
        pub struct $NAME(ByteArray<$SIZE>);

        impl Hashed for $NAME {
            type Array = ByteArray<$SIZE>;

            fn size() -> usize {
                $SIZE
            }

            fn from_array(array: Self::Array) -> Self {
                $NAME(array)
            }

            fn digest(data: &[u8]) -> Self {
                let hash = $DIGEST_FN(data.as_ref());
                Self::new(hash.into())
            }

            fn from_slice_optional(hash: &[u8]) -> Option<Self> {
                let hash: [u8; $SIZE] = hash.try_into().ok()?;
                Some(Self::new(hash))
            }

            fn byte_array(&self) -> &Self::Array {
                &self.0
            }
        }

        impl $NAME {
            pub fn new(hash: [u8; $SIZE]) -> Self {
                $NAME(ByteArray::new(hash))
            }
        }

        impl Debug for $NAME {
            fn fmt(
                &self,
                fmt: &mut std::fmt::Formatter<'_>,
            ) -> std::result::Result<(), std::fmt::Error> {
                write!(fmt, "{}({})", stringify!($NAME), self.to_hex_be())
            }
        }

        impl Display for $NAME {
            fn fmt(
                &self,
                fmt: &mut std::fmt::Formatter<'_>,
            ) -> std::result::Result<(), std::fmt::Error> {
                write!(fmt, "{}", self.to_hex_be())
            }
        }

        impl AsRef<[u8]> for $NAME {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl From<ByteArray<$SIZE>> for $NAME {
            fn from(array: ByteArray<$SIZE>) -> Self {
                $NAME(array)
            }
        }

        impl From<$NAME> for ByteArray<$SIZE> {
            fn from(hash: $NAME) -> Self {
                hash.0
            }
        }

        impl BitcoinCode for $NAME {
            fn ser_to(&self, bytes: &mut BytesMut) {
                self.0.ser_to(bytes)
            }

            fn deser(data: &mut Bytes) -> Result<Self>
            where
                Self: Sized,
            {
                Ok($NAME(ByteArray::<$SIZE>::deser(data)?))
            }
        }

        impl PartialOrd for $NAME {
            fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
                Some(self.cmp(other))
            }
        }

        impl Ord for $NAME {
            fn cmp(&self, other: &Self) -> Ordering {
                let a = self.as_slice().iter().rev();
                let b = other.as_slice().iter().rev();
                for (&byte1, &byte2) in a.zip(b) {
                    match byte1.cmp(&byte2) {
                        Ordering::Equal => continue,
                        ordering => return ordering,
                    }
                }
                Ordering::Equal
            }
        }
    };
}

hash_algo!(Sha1, 20, sha1::Sha1::digest);
hash_algo!(Ripemd160, 20, ripemd::Ripemd160::digest);
hash_algo!(Sha256, 32, sha2::Sha256::digest);
fn sha256d(data: &[u8]) -> [u8; 32] {
    sha2::Sha256::digest(&sha2::Sha256::digest(data)).into()
}
hash_algo!(Sha256d, 32, sha256d);
fn sha_rmd160(data: &[u8]) -> [u8; 20] {
    ripemd::Ripemd160::digest(&sha2::Sha256::digest(data)).into()
}
hash_algo!(ShaRmd160, 20, sha_rmd160);
