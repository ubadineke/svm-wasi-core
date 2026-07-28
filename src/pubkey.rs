//! Re-exports `solana-pubkey`'s `Pubkey` rather than hand-rolling PDA
//! derivation. Requires this crate's `solana-pubkey` features `curve25519`
//! + `sha2` (needed for `try_find_program_address`/`create_program_address`).
//!
//! Prefer `Pubkey::try_find_program_address` over the panicking
//! `find_program_address`: a panic inside a wasm32-wasip2 component traps
//! the whole guest instance, which is the wrong failure mode here.

pub use solana_pubkey::{ParsePubkeyError, Pubkey, PubkeyError, PUBKEY_BYTES};

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";

    #[test]
    fn try_find_program_address_is_off_curve_and_reproducible() {
        let program = Pubkey::from_str(TOKEN_PROGRAM).unwrap();
        let (address, bump) =
            Pubkey::try_find_program_address(&[b"metadata", b"seed-two"], &program).unwrap();

        let bump_seed = [bump];
        let reproduced =
            Pubkey::create_program_address(&[b"metadata", b"seed-two", &bump_seed], &program)
                .unwrap();
        assert_eq!(address, reproduced);
    }

    /// Known-answer vector: a real mainnet Associated Token Account.
    #[test]
    fn known_answer_mainnet_ata_matches_the_official_crate() {
        let wallet = Pubkey::from_str("5Q544fKrFoe6tsEbD7S8EmxGTJYAKtTVhAW5Q5pge4j1").unwrap();
        let usdc_mint = Pubkey::from_str("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v").unwrap();
        let token_program = Pubkey::from_str(TOKEN_PROGRAM).unwrap();
        let ata_program = Pubkey::from_str("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL").unwrap();

        let (address, bump) = Pubkey::try_find_program_address(
            &[wallet.as_ref(), token_program.as_ref(), usdc_mint.as_ref()],
            &ata_program,
        )
        .unwrap();

        assert_eq!(
            address.to_string(),
            "BmeV7UWExZeSboQXYW4biUVEx2SyYDVTdWhHoQEQcUFu"
        );
        assert_eq!(bump, 255);
    }
}
