//! SPL Token / Token-2022 instruction encoding.
//!
//! Unlike System's bincode tagging, `TokenInstruction` is manually packed:
//! a single `u8` discriminant (the enum's declaration order) followed by
//! fields in raw little-endian form, no framing. Token-2022 accepts the
//! exact same `Transfer`/`TransferChecked` byte layout as classic Token (a
//! deliberate ABI-compatibility choice upstream), so one encoder serves
//! both — callers pick the program by passing [`token_program_id`] or
//! [`token_2022_program_id`].
//!
//! Verified against the real on-chain program's own `pack()` method and
//! account-list doc comments: `solana-program/token`,
//! `interface/src/instruction.rs`.

use super::{known_id, AccountMeta, Instruction};
use crate::pubkey::Pubkey;

const TRANSFER_DISCRIMINANT: u8 = 3;
const TRANSFER_CHECKED_DISCRIMINANT: u8 = 12;

pub fn token_program_id() -> Pubkey {
    known_id("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
}

pub fn token_2022_program_id() -> Pubkey {
    known_id("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb")
}

/// `TokenInstruction::Transfer { amount }`, single-owner form (no
/// multisig). Prefer [`transfer_checked`] for anything user-facing: it
/// pins the mint and decimals, so a token-substitution or decimals-mismatch
/// attack fails closed instead of silently moving the wrong asset.
pub fn transfer(
    source: &Pubkey,
    destination: &Pubkey,
    owner: &Pubkey,
    amount: u64,
    token_program_id: &Pubkey,
) -> Instruction {
    let mut data = Vec::with_capacity(1 + 8);
    data.push(TRANSFER_DISCRIMINANT);
    data.extend_from_slice(&amount.to_le_bytes());

    Instruction {
        program_id: *token_program_id,
        accounts: vec![
            AccountMeta::new(*source, false),
            AccountMeta::new(*destination, false),
            AccountMeta::new_readonly(*owner, true),
        ],
        data,
    }
}

/// `TokenInstruction::TransferChecked { amount, decimals }`, single-owner
/// form (no multisig).
pub fn transfer_checked(
    source: &Pubkey,
    mint: &Pubkey,
    destination: &Pubkey,
    owner: &Pubkey,
    amount: u64,
    decimals: u8,
    token_program_id: &Pubkey,
) -> Instruction {
    let mut data = Vec::with_capacity(1 + 8 + 1);
    data.push(TRANSFER_CHECKED_DISCRIMINANT);
    data.extend_from_slice(&amount.to_le_bytes());
    data.push(decimals);

    Instruction {
        program_id: *token_program_id,
        accounts: vec![
            AccountMeta::new(*source, false),
            AccountMeta::new_readonly(*mint, false),
            AccountMeta::new(*destination, false),
            AccountMeta::new_readonly(*owner, true),
        ],
        data,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn pk(s: &str) -> Pubkey {
        Pubkey::from_str(s).unwrap()
    }

    #[test]
    fn transfer_encodes_tag_and_amount() {
        let source = pk("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
        let dest = pk("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr");
        let owner = pk("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
        let program = token_program_id();

        let ix = transfer(&source, &dest, &owner, 42, &program);

        assert_eq!(ix.program_id, program);
        assert_eq!(ix.data, [3, 42, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(
            ix.accounts,
            vec![
                AccountMeta::new(source, false),
                AccountMeta::new(dest, false),
                AccountMeta::new_readonly(owner, true),
            ]
        );
    }

    #[test]
    fn transfer_checked_encodes_tag_amount_and_decimals() {
        let source = pk("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
        let mint = pk("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");
        let dest = pk("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr");
        let owner = pk("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
        let program = token_2022_program_id();

        let ix = transfer_checked(&source, &mint, &dest, &owner, 6_131_218, 6, &program);

        assert_eq!(ix.program_id, program);
        let mut expected = vec![12u8];
        expected.extend_from_slice(&6_131_218u64.to_le_bytes());
        expected.push(6);
        assert_eq!(ix.data, expected);
        assert_eq!(
            ix.accounts,
            vec![
                AccountMeta::new(source, false),
                AccountMeta::new_readonly(mint, false),
                AccountMeta::new(dest, false),
                AccountMeta::new_readonly(owner, true),
            ]
        );
    }

    #[test]
    fn token_and_token_2022_ids_are_distinct_and_stable() {
        assert_eq!(
            token_program_id().to_string(),
            "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
        );
        assert_eq!(
            token_2022_program_id().to_string(),
            "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
        );
    }
}
