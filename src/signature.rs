//! A transaction signature: 64 opaque bytes, base58-addressable exactly
//! like [`crate::pubkey::Pubkey`] but with no PDA machinery of its own.
//! Mirrors `solana_signature::Signature`.

use std::fmt;
use std::str::FromStr;

pub const SIGNATURE_BYTES: usize = 64;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Signature([u8; SIGNATURE_BYTES]);

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SignatureError {
    #[error("base58 decode error: {0}")]
    Base58(String),
    #[error("invalid signature length: expected {SIGNATURE_BYTES} bytes, got {0}")]
    InvalidLength(usize),
}

impl Signature {
    /// The all-zero placeholder every unsigned transaction slot starts as.
    pub const ZERO: Signature = Signature([0u8; SIGNATURE_BYTES]);

    pub const fn new_from_array(bytes: [u8; SIGNATURE_BYTES]) -> Self {
        Signature(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn to_bytes(self) -> [u8; SIGNATURE_BYTES] {
        self.0
    }
}

impl Default for Signature {
    fn default() -> Self {
        Self::ZERO
    }
}

impl FromStr for Signature {
    type Err = SignatureError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = bs58::decode(s)
            .into_vec()
            .map_err(|e| SignatureError::Base58(e.to_string()))?;
        if bytes.len() != SIGNATURE_BYTES {
            return Err(SignatureError::InvalidLength(bytes.len()));
        }
        let mut arr = [0u8; SIGNATURE_BYTES];
        arr.copy_from_slice(&bytes);
        Ok(Signature(arr))
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", bs58::encode(self.0).into_string())
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_signature_round_trips_through_display() {
        let s = Signature::ZERO;
        assert_eq!(s.as_bytes(), &[0u8; 64]);
        assert_eq!(Signature::from_str(&s.to_string()).unwrap(), s);
    }

    #[test]
    fn rejects_wrong_length() {
        let err = Signature::from_str("11111111111111111111111111111").unwrap_err();
        assert!(matches!(err, SignatureError::InvalidLength(_)));
    }

    #[test]
    fn default_is_zero() {
        assert_eq!(Signature::default(), Signature::ZERO);
    }
}
