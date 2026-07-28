//! Re-exports `solana-hash`'s `Hash` — a transaction's `recent_blockhash`/
//! durable-nonce value — rather than hand-rolling a base58-addressable
//! newtype. Same rationale as [`crate::pubkey`].

pub use solana_hash::{Hash, ParseHashError, HASH_BYTES};

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn base58_round_trip() {
        let s = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
        assert_eq!(Hash::from_str(s).unwrap().to_string(), s);
    }

    #[test]
    fn rejects_wrong_length() {
        assert!(Hash::from_str("11111111111111111111111111111").is_err());
    }
}
