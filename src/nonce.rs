//! Durable-nonce account state: parses the 80 raw bytes the System Program
//! writes into a nonce account's `data` (as returned by `getAccountInfo`),
//! and exposes the one thing a durable-nonce transaction actually needs —
//! the blockhash-equivalent value to place in the message's
//! `recent_blockhash` field so it never expires waiting on a human
//! approval (the bounty's own "trap #1").
//!
//! Wire format verified against the real implementation, not reconstructed
//! from a description: `anza-xyz/solana-sdk`, `nonce/src/{state,versions}.rs`.
//! It's bincode: a `Versions` enum tag (Legacy = 0, Current = 1), then a
//! `State` enum tag (Uninitialized = 0, Initialized = 1) — both 4-byte LE
//! `u32`s, matching `SystemInstruction`'s own tagging — then, if
//! initialized, `Data { authority: Pubkey, durable_nonce: Hash,
//! fee_calculator: { lamports_per_signature: u64 } }`. Total size is
//! asserted upstream (`nonce/src/state.rs`, `test_nonce_state_size`) to be
//! exactly 80 bytes.

use crate::hash::Hash;
use crate::pubkey::Pubkey;

pub const NONCE_ACCOUNT_LENGTH: usize = 80;

const VERSION_LEGACY: u32 = 0;
const VERSION_CURRENT: u32 = 1;
const STATE_UNINITIALIZED: u32 = 0;
const STATE_INITIALIZED: u32 = 1;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum NonceError {
    #[error("nonce account data is {0} bytes, expected {NONCE_ACCOUNT_LENGTH}")]
    InvalidLength(usize),
    #[error("unknown nonce version discriminant: {0}")]
    UnknownVersion(u32),
    #[error("unknown nonce state discriminant: {0}")]
    UnknownState(u32),
}

/// An initialized nonce account's data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NonceData {
    /// Must sign `advance_nonce_account`/`withdraw_nonce_account`.
    pub authority: Pubkey,
    /// The value to place in a transaction's `recent_blockhash` field to
    /// spend this nonce — read directly from account state, no further
    /// hashing needed (despite the name, this is a value in the durable-
    /// nonce domain, not a real recent blockhash; the runtime accepts it in
    /// that field specifically because a durable-nonce transaction advances
    /// the nonce as its first instruction).
    pub blockhash: Hash,
    pub lamports_per_signature: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NonceVersion {
    /// Pre-dates the durable-nonce/blockhash domain separation. The runtime
    /// never accepts a Legacy nonce for a durable transaction regardless of
    /// its state (`Versions::verify_recent_blockhash` always returns `None`
    /// for it) — every nonce account created by current tooling is
    /// `Current`; treat a `Legacy` one as unusable rather than attempting to
    /// build a transaction against it.
    Legacy,
    Current,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NonceState {
    Uninitialized,
    Initialized(NonceData),
}

/// A parsed nonce account: version plus state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NonceAccount {
    pub version: NonceVersion,
    pub state: NonceState,
}

impl NonceAccount {
    /// Parses a nonce account's raw `data`, exactly as returned by
    /// `getAccountInfo` for an account owned by the System Program with
    /// `data.len() == 80`.
    pub fn parse(data: &[u8]) -> Result<Self, NonceError> {
        if data.len() != NONCE_ACCOUNT_LENGTH {
            return Err(NonceError::InvalidLength(data.len()));
        }

        let version = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let version = match version {
            VERSION_LEGACY => NonceVersion::Legacy,
            VERSION_CURRENT => NonceVersion::Current,
            other => return Err(NonceError::UnknownVersion(other)),
        };

        let state_tag = u32::from_le_bytes(data[4..8].try_into().unwrap());
        let state = match state_tag {
            STATE_UNINITIALIZED => NonceState::Uninitialized,
            STATE_INITIALIZED => {
                let mut authority = [0u8; 32];
                authority.copy_from_slice(&data[8..40]);
                let mut blockhash = [0u8; 32];
                blockhash.copy_from_slice(&data[40..72]);
                let lamports_per_signature = u64::from_le_bytes(data[72..80].try_into().unwrap());
                NonceState::Initialized(NonceData {
                    authority: Pubkey::new_from_array(authority),
                    blockhash: Hash::new_from_array(blockhash),
                    lamports_per_signature,
                })
            }
            other => return Err(NonceError::UnknownState(other)),
        };

        Ok(Self { version, state })
    }

    /// The blockhash usable as a transaction's `recent_blockhash` to spend
    /// this nonce, or `None` if the account is uninitialized or still on
    /// the `Legacy` version — mirrors `Versions::verify_recent_blockhash`'s
    /// own rejection of both cases.
    pub fn usable_blockhash(&self) -> Option<Hash> {
        match (self.version, self.state) {
            (NonceVersion::Current, NonceState::Initialized(data)) => Some(data.blockhash),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hand_assembled_initialized_account(
        version: u32,
        authority: Pubkey,
        blockhash: Hash,
        lamports_per_signature: u64,
    ) -> Vec<u8> {
        let mut data = Vec::with_capacity(NONCE_ACCOUNT_LENGTH);
        data.extend_from_slice(&version.to_le_bytes());
        data.extend_from_slice(&STATE_INITIALIZED.to_le_bytes());
        data.extend_from_slice(authority.as_bytes());
        data.extend_from_slice(blockhash.as_bytes());
        data.extend_from_slice(&lamports_per_signature.to_le_bytes());
        data
    }

    #[test]
    fn parses_current_initialized_account() {
        let authority = Pubkey::new_from_array([1; 32]);
        let blockhash = Hash::new_from_array([2; 32]);
        let data = hand_assembled_initialized_account(VERSION_CURRENT, authority, blockhash, 5_000);

        assert_eq!(data.len(), NONCE_ACCOUNT_LENGTH);
        let account = NonceAccount::parse(&data).unwrap();

        assert_eq!(account.version, NonceVersion::Current);
        assert_eq!(
            account.state,
            NonceState::Initialized(NonceData {
                authority,
                blockhash,
                lamports_per_signature: 5_000
            })
        );
        assert_eq!(account.usable_blockhash(), Some(blockhash));
    }

    #[test]
    fn legacy_version_is_never_usable_even_if_initialized() {
        let authority = Pubkey::new_from_array([1; 32]);
        let blockhash = Hash::new_from_array([2; 32]);
        let data = hand_assembled_initialized_account(VERSION_LEGACY, authority, blockhash, 5_000);

        let account = NonceAccount::parse(&data).unwrap();
        assert_eq!(account.version, NonceVersion::Legacy);
        assert_eq!(account.usable_blockhash(), None);
    }

    #[test]
    fn uninitialized_account_has_no_usable_blockhash() {
        let mut data = vec![0u8; NONCE_ACCOUNT_LENGTH];
        data[0..4].copy_from_slice(&VERSION_CURRENT.to_le_bytes());
        data[4..8].copy_from_slice(&STATE_UNINITIALIZED.to_le_bytes());

        let account = NonceAccount::parse(&data).unwrap();
        assert_eq!(account.state, NonceState::Uninitialized);
        assert_eq!(account.usable_blockhash(), None);
    }

    #[test]
    fn rejects_wrong_length() {
        let err = NonceAccount::parse(&[0u8; 79]).unwrap_err();
        assert_eq!(err, NonceError::InvalidLength(79));
    }

    #[test]
    fn rejects_unknown_version_discriminant() {
        let mut data = vec![0u8; NONCE_ACCOUNT_LENGTH];
        data[0..4].copy_from_slice(&99u32.to_le_bytes());
        let err = NonceAccount::parse(&data).unwrap_err();
        assert_eq!(err, NonceError::UnknownVersion(99));
    }

    #[test]
    fn rejects_unknown_state_discriminant() {
        let mut data = vec![0u8; NONCE_ACCOUNT_LENGTH];
        data[0..4].copy_from_slice(&VERSION_CURRENT.to_le_bytes());
        data[4..8].copy_from_slice(&7u32.to_le_bytes());
        let err = NonceAccount::parse(&data).unwrap_err();
        assert_eq!(err, NonceError::UnknownState(7));
    }
}
