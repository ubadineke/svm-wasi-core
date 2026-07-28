//! Re-exports `solana-signature`'s `Signature`. Same rationale as
//! [`crate::pubkey`] and [`crate::hash`]. No `ZERO` const upstream — use
//! `Signature::default()` for the all-zero unsigned-slot placeholder.

pub use solana_signature::{ParseSignatureError, Signature, SIGNATURE_BYTES};

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn default_is_all_zero_and_round_trips_through_display() {
        let s = Signature::default();
        assert_eq!(<[u8; 64]>::from(s), [0u8; 64]);
        assert_eq!(Signature::from_str(&s.to_string()).unwrap(), s);
    }

    #[test]
    fn rejects_wrong_length() {
        assert!(Signature::from_str("11111111111111111111111111111").is_err());
    }
}
