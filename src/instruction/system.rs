//! Thin re-export over `solana-system-interface`'s instruction builders.
//! Requires this crate's `solana-system-interface` feature `bincode`.
//!
//! No standalone `initialize_nonce_account` upstream — only bundled inside
//! [`create_nonce_account`], which covers the common "fresh nonce account"
//! case.

pub use solana_system_interface::instruction::{
    advance_nonce_account, authorize_nonce_account, create_account, create_nonce_account, transfer,
    withdraw_nonce_account,
};

use crate::pubkey::Pubkey;
use std::str::FromStr;

pub fn id() -> Pubkey {
    Pubkey::from_str("11111111111111111111111111111111").expect("hardcoded program id")
}

/// The sysvar `advance_nonce_account`/`withdraw_nonce_account` read the
/// current blockhash from.
pub fn recent_blockhashes_sysvar_id() -> Pubkey {
    Pubkey::from_str("SysvarRecentB1ockHashes11111111111111111111").expect("hardcoded sysvar id")
}

/// The sysvar nonce-account creation/withdrawal check rent-exemption against.
pub fn rent_sysvar_id() -> Pubkey {
    Pubkey::from_str("SysvarRent111111111111111111111111111111111").expect("hardcoded sysvar id")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn program_id_is_the_all_zero_pubkey() {
        assert_eq!(id().to_bytes(), [0u8; 32]);
    }

    #[test]
    fn transfer_encodes_discriminant_and_lamports() {
        let from = Pubkey::from_str("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").unwrap();
        let to = Pubkey::from_str("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL").unwrap();

        let ix = transfer(&from, &to, 1_000_000_000);

        assert_eq!(ix.program_id, id());
        assert_eq!(ix.data, [2, 0, 0, 0, 0, 202, 154, 59, 0, 0, 0, 0]);
    }

    #[test]
    fn advance_nonce_account_encodes_fixed_accounts_and_empty_args() {
        let nonce = Pubkey::from_str("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").unwrap();
        let authority = Pubkey::from_str("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL").unwrap();

        let ix = advance_nonce_account(&nonce, &authority);

        assert_eq!(ix.data, [4, 0, 0, 0]);
        assert_eq!(ix.accounts.len(), 3);
    }

    #[test]
    fn create_nonce_account_bundles_create_and_initialize() {
        let payer = Pubkey::from_str("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").unwrap();
        let nonce = Pubkey::from_str("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL").unwrap();

        let ixs = create_nonce_account(&payer, &nonce, &payer, 1_500_000);
        assert_eq!(ixs.len(), 2);

        let mut expected_initialize_data = vec![6, 0, 0, 0];
        expected_initialize_data.extend_from_slice(payer.as_ref());
        assert_eq!(ixs[1].data, expected_initialize_data);
    }
}
