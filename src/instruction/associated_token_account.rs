//! Associated Token Account (ATA) program: deterministic per-(wallet, mint)
//! token accounts, and the instructions that create them.
//!
//! Verified against the real program's own instruction builder —
//! `solana-program/associated-token-account`, `interface/src/
//! instruction.rs`, `build_associated_token_account_instruction` — down to
//! the account order and the single-byte (no framing) instruction data.

use super::{known_id, system, AccountMeta, Instruction};
use crate::pubkey::{Pubkey, PubkeyError};

const CREATE: u8 = 0;
const CREATE_IDEMPOTENT: u8 = 1;

pub fn id() -> Pubkey {
    known_id("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")
}

/// The deterministic ATA for `(wallet, mint)` under `token_program_id`.
/// Seed order — `[wallet, token_program_id, mint]` — per
/// `spl_associated_token_account_interface::address::
/// get_associated_token_address_and_bump_seed_internal`.
pub fn get_associated_token_address(
    wallet: &Pubkey,
    mint: &Pubkey,
    token_program_id: &Pubkey,
) -> Result<Pubkey, PubkeyError> {
    let (address, _bump) = Pubkey::find_program_address(
        &[
            wallet.as_bytes(),
            token_program_id.as_bytes(),
            mint.as_bytes(),
        ],
        &id(),
    )?;
    Ok(address)
}

/// `AssociatedTokenAccountInstruction::Create`. Fails on-chain if the
/// account already exists — prefer [`create_associated_token_account_idempotent`]
/// unless a pre-existing account at that address is itself an error case
/// worth surfacing.
pub fn create_associated_token_account(
    funding_account: &Pubkey,
    wallet: &Pubkey,
    mint: &Pubkey,
    token_program_id: &Pubkey,
) -> Result<Instruction, PubkeyError> {
    build(funding_account, wallet, mint, token_program_id, CREATE)
}

/// `AssociatedTokenAccountInstruction::CreateIdempotent`: a no-op (not an
/// error) if the ATA already exists with the expected owner. This is the
/// right default for a transfer-building plugin — "create the destination
/// ATA if it's missing" should never fail just because a concurrent
/// transaction already created it.
pub fn create_associated_token_account_idempotent(
    funding_account: &Pubkey,
    wallet: &Pubkey,
    mint: &Pubkey,
    token_program_id: &Pubkey,
) -> Result<Instruction, PubkeyError> {
    build(
        funding_account,
        wallet,
        mint,
        token_program_id,
        CREATE_IDEMPOTENT,
    )
}

fn build(
    funding_account: &Pubkey,
    wallet: &Pubkey,
    mint: &Pubkey,
    token_program_id: &Pubkey,
    tag: u8,
) -> Result<Instruction, PubkeyError> {
    let associated_account = get_associated_token_address(wallet, mint, token_program_id)?;
    Ok(Instruction {
        program_id: id(),
        accounts: vec![
            AccountMeta::new(*funding_account, true),
            AccountMeta::new(associated_account, false),
            AccountMeta::new_readonly(*wallet, false),
            AccountMeta::new_readonly(*mint, false),
            AccountMeta::new_readonly(system::id(), false),
            AccountMeta::new_readonly(*token_program_id, false),
        ],
        data: vec![tag],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::instruction::token;
    use std::str::FromStr;

    fn pk(s: &str) -> Pubkey {
        Pubkey::from_str(s).unwrap()
    }

    /// Same real mainnet (wallet, mint) pair used in `pubkey`'s known-answer
    /// test: reuse it here so this module is checked against a live,
    /// on-chain ATA too, not just its own account-list plumbing.
    #[test]
    fn get_associated_token_address_matches_known_mainnet_ata() {
        let wallet = pk("5Q544fKrFoe6tsEbD7S8EmxGTJYAKtTVhAW5Q5pge4j1");
        let usdc_mint = pk("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");

        let ata =
            get_associated_token_address(&wallet, &usdc_mint, &token::token_program_id()).unwrap();

        assert_eq!(
            ata.to_string(),
            "BmeV7UWExZeSboQXYW4biUVEx2SyYDVTdWhHoQEQcUFu"
        );
    }

    #[test]
    fn create_idempotent_uses_tag_one_and_six_accounts() {
        let funding = pk("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
        let wallet = pk("5Q544fKrFoe6tsEbD7S8EmxGTJYAKtTVhAW5Q5pge4j1");
        let mint = pk("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");
        let token_program = token::token_program_id();

        let ix =
            create_associated_token_account_idempotent(&funding, &wallet, &mint, &token_program)
                .unwrap();

        assert_eq!(ix.data, vec![CREATE_IDEMPOTENT]);
        assert_eq!(ix.program_id, id());
        assert_eq!(ix.accounts.len(), 6);
        assert_eq!(ix.accounts[0], AccountMeta::new(funding, true));
        assert_eq!(
            ix.accounts[1],
            AccountMeta::new(
                get_associated_token_address(&wallet, &mint, &token_program).unwrap(),
                false
            )
        );
        assert_eq!(ix.accounts[2], AccountMeta::new_readonly(wallet, false));
        assert_eq!(ix.accounts[3], AccountMeta::new_readonly(mint, false));
        assert_eq!(
            ix.accounts[4],
            AccountMeta::new_readonly(system::id(), false)
        );
        assert_eq!(
            ix.accounts[5],
            AccountMeta::new_readonly(token_program, false)
        );
    }

    #[test]
    fn create_uses_tag_zero() {
        let funding = pk("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
        let wallet = pk("5Q544fKrFoe6tsEbD7S8EmxGTJYAKtTVhAW5Q5pge4j1");
        let mint = pk("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");

        let ix =
            create_associated_token_account(&funding, &wallet, &mint, &token::token_program_id())
                .unwrap();

        assert_eq!(ix.data, vec![CREATE]);
    }
}
