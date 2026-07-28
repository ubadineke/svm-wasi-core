//! Thin wrappers dispatching to `spl-token-interface` or
//! `spl-token-2022-interface`'s instruction builders, by which program id
//! the caller passes. The two programs share the same wire layout, but each
//! crate's own `check_program_account` only accepts its own program id, so
//! Token-2022 must go through the Token-2022 crate's builder.

use super::Instruction;
use crate::pubkey::Pubkey;

pub fn token_program_id() -> Pubkey {
    spl_token_interface::id()
}

pub fn token_2022_program_id() -> Pubkey {
    spl_token_2022_interface::id()
}

/// Single-owner (no multisig) `Transfer`. Prefer [`transfer_checked`] for
/// anything user-facing — it pins the mint and decimals, so a
/// token-substitution or decimals-mismatch attack fails closed.
///
/// `token_program_id` must be [`token_program_id`] or [`token_2022_program_id`],
/// else this panics.
#[allow(deprecated)]
pub fn transfer(
    source: &Pubkey,
    destination: &Pubkey,
    owner: &Pubkey,
    amount: u64,
    token_program_id: &Pubkey,
) -> Instruction {
    if *token_program_id == spl_token_2022_interface::id() {
        spl_token_2022_interface::instruction::transfer(
            token_program_id,
            source,
            destination,
            owner,
            &[],
            amount,
        )
        .expect("token_2022_program_id always passes Token-2022's own check_program_account")
    } else {
        spl_token_interface::instruction::transfer(
            token_program_id,
            source,
            destination,
            owner,
            &[],
            amount,
        )
        .expect(
            "token_program_id must be spl_token_interface::id() or spl_token_2022_interface::id()",
        )
    }
}

/// Single-owner (no multisig) `TransferChecked`. Same dispatch-by-program-id
/// rule as [`transfer`].
#[allow(clippy::too_many_arguments)]
pub fn transfer_checked(
    source: &Pubkey,
    mint: &Pubkey,
    destination: &Pubkey,
    owner: &Pubkey,
    amount: u64,
    decimals: u8,
    token_program_id: &Pubkey,
) -> Instruction {
    if *token_program_id == spl_token_2022_interface::id() {
        spl_token_2022_interface::instruction::transfer_checked(
            token_program_id,
            source,
            mint,
            destination,
            owner,
            &[],
            amount,
            decimals,
        )
        .expect("token_2022_program_id always passes Token-2022's own check_program_account")
    } else {
        spl_token_interface::instruction::transfer_checked(
            token_program_id,
            source,
            mint,
            destination,
            owner,
            &[],
            amount,
            decimals,
        )
        .expect(
            "token_program_id must be spl_token_interface::id() or spl_token_2022_interface::id()",
        )
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
        assert_eq!(ix.accounts.len(), 3);
        assert_eq!(ix.accounts[2].pubkey, owner);
        assert!(ix.accounts[2].is_signer);
    }

    #[test]
    fn transfer_checked_encodes_tag_amount_and_decimals_for_token_2022() {
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
        assert_eq!(ix.accounts.len(), 4);
    }

    #[test]
    fn transfer_checked_encodes_tag_amount_and_decimals_for_classic_token() {
        let source = pk("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
        let mint = pk("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");
        let dest = pk("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr");
        let owner = pk("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
        let program = token_program_id();

        let ix = transfer_checked(&source, &mint, &dest, &owner, 500, 9, &program);

        assert_eq!(ix.program_id, program);
        let mut expected = vec![12u8];
        expected.extend_from_slice(&500u64.to_le_bytes());
        expected.push(9);
        assert_eq!(ix.data, expected);
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
