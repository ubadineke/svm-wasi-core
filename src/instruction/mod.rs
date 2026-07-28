//! Thin wrappers over the modular `solana-system-interface` /
//! `spl-token-interface` / `spl-memo` crates, plus `subscriptions` (Solana
//! Foundation's Subscriptions & Allowances program), which has no published
//! interface crate and is hand-encoded, verified against its own source.

pub mod associated_token_account;
pub mod memo;
pub mod subscriptions;
pub mod system;
pub mod token;

pub use solana_instruction::{AccountMeta, Instruction};

use crate::pubkey::Pubkey;
use std::str::FromStr;

/// Decodes a hardcoded, known-valid base58 program id. Only ever called
/// with literal constants, so `expect` is right — a failure here means the
/// crate itself is broken, not that untrusted input was rejected.
pub(crate) fn known_id(base58: &str) -> Pubkey {
    Pubkey::from_str(base58).expect("hardcoded program id must be valid base58")
}
