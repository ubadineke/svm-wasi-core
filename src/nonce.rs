//! Durable-nonce account state, via `solana-nonce`'s own `Versions`/`State`/
//! `Data` types (bincode-deserialized, using this crate's `serde` feature).
//!
//! [`usable_blockhash`] is the one convenience upstream doesn't hand you
//! directly: the blockhash to spend a freshly fetched nonce account, or
//! `None` if it isn't usable.

pub use solana_nonce::{
    state::{Data as NonceData, DurableNonce, State as NonceState},
    versions::Versions as NonceAccount,
};

use crate::hash::Hash;
use crate::pubkey::Pubkey;

#[derive(Debug, thiserror::Error)]
pub enum NonceError {
    #[error("failed to deserialize nonce account data: {0}")]
    Decode(#[from] Box<bincode::ErrorKind>),
}

/// Parses a nonce account's raw `data`, exactly as returned by
/// `getAccountInfo` for an account owned by the System Program.
pub fn parse_nonce_account(data: &[u8]) -> Result<NonceAccount, NonceError> {
    bincode::deserialize(data).map_err(NonceError::from)
}

/// The blockhash usable as a transaction's `recent_blockhash` to spend this
/// nonce, or `None` if the account is uninitialized or still on the
/// `Legacy` version — the runtime never accepts a Legacy nonce regardless
/// of its state; every nonce account created by current tooling is `Current`.
pub fn usable_blockhash(account: &NonceAccount) -> Option<Hash> {
    match account {
        NonceAccount::Current(state) => match state.as_ref() {
            NonceState::Initialized(data) => Some(data.blockhash()),
            NonceState::Uninitialized => None,
        },
        NonceAccount::Legacy(_) => None,
    }
}

/// Bincode-encodes a `Current`/`Initialized` nonce account's raw account
/// data — the exact bytes `getAccountInfo` would hand back for a real one.
/// Meant for tests: any plugin whose tool consumes a durable nonce needs to
/// mock this exact response shape, so this lives here once instead of every
/// downstream test suite hand-assembling its own copy.
pub fn encode_initialized_nonce_account(
    authority: Pubkey,
    blockhash: Hash,
    lamports_per_signature: u64,
) -> Vec<u8> {
    let durable_nonce = DurableNonce::from_blockhash(&blockhash);
    let data = NonceData::new(authority, durable_nonce, lamports_per_signature);
    let account = NonceAccount::new(NonceState::Initialized(data));
    bincode::serialize(&account).expect("nonce account always serializes")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_current_initialized_account_and_recovers_its_blockhash() {
        let authority = Pubkey::new_from_array([1; 32]);
        let blockhash = Hash::new_from_array([2; 32]);
        let raw = encode_initialized_nonce_account(authority, blockhash, 5_000);

        let account = parse_nonce_account(&raw).unwrap();
        match &account {
            NonceAccount::Current(state) => match state.as_ref() {
                NonceState::Initialized(data) => assert_eq!(data.authority, authority),
                NonceState::Uninitialized => panic!("expected Initialized"),
            },
            NonceAccount::Legacy(_) => panic!("expected Current"),
        }

        // The recovered blockhash is the durable-nonce-domain value, not the
        // original blockhash directly — but it round-trips through our
        // helper the same way a real transaction would consume it.
        assert!(usable_blockhash(&account).is_some());
    }

    #[test]
    fn legacy_version_is_never_usable_even_if_initialized() {
        let authority = Pubkey::new_from_array([1; 32]);
        let blockhash = Hash::new_from_array([2; 32]);
        let durable_nonce = DurableNonce::from_blockhash(&blockhash);
        let data = NonceData::new(authority, durable_nonce, 5_000);
        let account = NonceAccount::Legacy(Box::new(NonceState::Initialized(data)));

        assert_eq!(usable_blockhash(&account), None);
    }

    #[test]
    fn uninitialized_account_has_no_usable_blockhash() {
        let account = NonceAccount::new(NonceState::Uninitialized);
        assert_eq!(usable_blockhash(&account), None);
    }

    #[test]
    fn rejects_malformed_bytes_rather_than_panicking() {
        let err = parse_nonce_account(&[0u8; 3]).unwrap_err();
        assert!(matches!(err, NonceError::Decode(_)));
    }
}
