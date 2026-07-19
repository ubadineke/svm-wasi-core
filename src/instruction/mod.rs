//! Hand-rolled instruction encoding for the handful of native/SPL programs a
//! transfer-building tool plugin needs: System, SPL Token / Token-2022, and
//! the Associated Token Account and Memo programs. Every byte layout here is
//! cited against the program's own source (see each submodule), not
//! reconstructed from memory.
//!
//! Module boundaries mirror `solana-program`'s own (`system_instruction`,
//! `spl_token_interface::instruction`, ...) so a reviewer already familiar
//! with the real SDK recognizes the shape immediately.

pub mod associated_token_account;
pub mod memo;
pub mod system;
pub mod token;

use crate::pubkey::Pubkey;
use std::str::FromStr;

/// Mirrors `solana_instruction::AccountMeta`: which accounts an instruction
/// touches, and whether each must sign / be writable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccountMeta {
    pub pubkey: Pubkey,
    pub is_signer: bool,
    pub is_writable: bool,
}

impl AccountMeta {
    pub const fn new(pubkey: Pubkey, is_signer: bool) -> Self {
        AccountMeta {
            pubkey,
            is_signer,
            is_writable: true,
        }
    }

    pub const fn new_readonly(pubkey: Pubkey, is_signer: bool) -> Self {
        AccountMeta {
            pubkey,
            is_signer,
            is_writable: false,
        }
    }
}

/// Mirrors `solana_instruction::Instruction`: one instruction's program,
/// account list, and opaque data payload, ready to be placed in a
/// [`crate::message`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Instruction {
    pub program_id: Pubkey,
    pub accounts: Vec<AccountMeta>,
    pub data: Vec<u8>,
}

/// Decodes a hardcoded, known-valid base58 program id. Only ever called with
/// literal constants covered by this module's own tests — a decode failure
/// here would mean the crate itself is broken, not that untrusted input was
/// rejected, so `expect` is the right tool rather than propagating a
/// `Result` a caller could never meaningfully react to.
pub(crate) fn known_id(base58: &str) -> Pubkey {
    Pubkey::from_str(base58).expect("hardcoded program id must be valid base58")
}
