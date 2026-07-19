//! A transaction's `recent_blockhash`/durable-nonce value: 32 opaque bytes,
//! base58-addressable exactly like [`crate::pubkey::Pubkey`] but with no PDA
//! machinery of its own. Mirrors `solana_hash::Hash`.

use std::fmt;
use std::str::FromStr;

pub const HASH_BYTES: usize = 32;

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Hash([u8; HASH_BYTES]);

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum HashError {
    #[error("base58 decode error: {0}")]
    Base58(String),
    #[error("invalid hash length: expected {HASH_BYTES} bytes, got {0}")]
    InvalidLength(usize),
}

impl Hash {
    pub const fn new_from_array(bytes: [u8; HASH_BYTES]) -> Self {
        Hash(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn to_bytes(self) -> [u8; HASH_BYTES] {
        self.0
    }
}

impl FromStr for Hash {
    type Err = HashError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = bs58::decode(s)
            .into_vec()
            .map_err(|e| HashError::Base58(e.to_string()))?;
        if bytes.len() != HASH_BYTES {
            return Err(HashError::InvalidLength(bytes.len()));
        }
        let mut arr = [0u8; HASH_BYTES];
        arr.copy_from_slice(&bytes);
        Ok(Hash(arr))
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", bs58::encode(self.0).into_string())
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base58_round_trip() {
        let s = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
        assert_eq!(Hash::from_str(s).unwrap().to_string(), s);
    }

    #[test]
    fn rejects_wrong_length() {
        let err = Hash::from_str("11111111111111111111111111111").unwrap_err();
        assert!(matches!(err, HashError::InvalidLength(_)));
    }
}
