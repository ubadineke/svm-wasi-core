//! Solana `Pubkey`: base58 addressing and program-derived-address (PDA)
//! derivation, with no dependency on `solana-sdk`.
//!
//! `find_program_address`/`create_program_address` deliberately return
//! `Result` rather than panicking (as `solana-program`'s do): a panic inside
//! a wasm32-wasip2 component traps the whole guest instance, which for a
//! ZeroClaw tool plugin means the host sees an opaque fault instead of the
//! `Result<ToolResult, String>` the WIT contract expects. A library meant to
//! run inside a plugin must never unwind past its own boundary.

use curve25519_dalek::edwards::CompressedEdwardsY;
use sha2::{Digest, Sha256};
use std::fmt;
use std::str::FromStr;

pub const PUBKEY_BYTES: usize = 32;

const PDA_MARKER: &[u8] = b"ProgramDerivedAddress";
const MAX_SEED_LEN: usize = 32;
const MAX_SEEDS: usize = 16;

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Pubkey([u8; PUBKEY_BYTES]);

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PubkeyError {
    #[error("base58 decode error: {0}")]
    Base58(String),
    #[error("invalid pubkey length: expected {PUBKEY_BYTES} bytes, got {0}")]
    InvalidLength(usize),
    #[error("seed too long: max {MAX_SEED_LEN} bytes per seed")]
    SeedTooLong,
    #[error("too many seeds: max {MAX_SEEDS}")]
    TooManySeeds,
    #[error("no viable PDA bump seed found for the given seeds and program id")]
    NoViableBump,
    #[error("the provided seeds and bump do not derive an off-curve address")]
    InvalidSeeds,
}

impl Pubkey {
    pub const fn new_from_array(bytes: [u8; PUBKEY_BYTES]) -> Self {
        Pubkey(bytes)
    }

    pub fn to_bytes(self) -> [u8; PUBKEY_BYTES] {
        self.0
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// True if this 32-byte value decompresses to a valid point on the
    /// ed25519 curve. A valid PDA must be *off* curve (nobody holds the
    /// private key for it), so this is the rejection test PDA derivation
    /// runs against every SHA-256 candidate.
    pub fn is_on_curve(&self) -> bool {
        CompressedEdwardsY(self.0).decompress().is_some()
    }

    /// `sha256(seeds... || program_id || "ProgramDerivedAddress")`, rejected
    /// if the result lands on-curve. Mirrors `solana_program::pubkey::Pubkey
    /// ::create_program_address`, minus the panicking API surface.
    pub fn create_program_address(
        seeds: &[&[u8]],
        program_id: &Pubkey,
    ) -> Result<Pubkey, PubkeyError> {
        if seeds.len() > MAX_SEEDS {
            return Err(PubkeyError::TooManySeeds);
        }
        for seed in seeds {
            if seed.len() > MAX_SEED_LEN {
                return Err(PubkeyError::SeedTooLong);
            }
        }

        let mut hasher = Sha256::new();
        for seed in seeds {
            hasher.update(seed);
        }
        hasher.update(program_id.as_bytes());
        hasher.update(PDA_MARKER);

        let mut arr = [0u8; PUBKEY_BYTES];
        arr.copy_from_slice(&hasher.finalize());
        let candidate = Pubkey(arr);

        if candidate.is_on_curve() {
            return Err(PubkeyError::InvalidSeeds);
        }
        Ok(candidate)
    }

    /// Searches bump seeds from 255 down to 0 for the first off-curve
    /// address, returning it together with the bump that produced it.
    pub fn find_program_address(
        seeds: &[&[u8]],
        program_id: &Pubkey,
    ) -> Result<(Pubkey, u8), PubkeyError> {
        if seeds.len() >= MAX_SEEDS {
            return Err(PubkeyError::TooManySeeds);
        }
        for bump in (0..=u8::MAX).rev() {
            let bump_seed = [bump];
            let mut seeds_with_bump: Vec<&[u8]> = Vec::with_capacity(seeds.len() + 1);
            seeds_with_bump.extend_from_slice(seeds);
            seeds_with_bump.push(&bump_seed);
            match Self::create_program_address(&seeds_with_bump, program_id) {
                Ok(address) => return Ok((address, bump)),
                Err(PubkeyError::InvalidSeeds) => continue,
                Err(other) => return Err(other),
            }
        }
        Err(PubkeyError::NoViableBump)
    }
}

impl FromStr for Pubkey {
    type Err = PubkeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = bs58::decode(s)
            .into_vec()
            .map_err(|e| PubkeyError::Base58(e.to_string()))?;
        if bytes.len() != PUBKEY_BYTES {
            return Err(PubkeyError::InvalidLength(bytes.len()));
        }
        let mut arr = [0u8; PUBKEY_BYTES];
        arr.copy_from_slice(&bytes);
        Ok(Pubkey(arr))
    }
}

impl fmt::Display for Pubkey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", bs58::encode(self.0).into_string())
    }
}

impl fmt::Debug for Pubkey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Well-known, stable program ids (Solana core programs).
    const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
    const ATA_PROGRAM: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";

    #[test]
    fn base58_round_trip() {
        let pk = Pubkey::from_str(TOKEN_PROGRAM).unwrap();
        assert_eq!(pk.to_string(), TOKEN_PROGRAM);
    }

    #[test]
    fn from_str_rejects_wrong_length() {
        // 31-byte payload once decoded.
        let err = Pubkey::from_str("11111111111111111111111111111").unwrap_err();
        assert!(matches!(err, PubkeyError::InvalidLength(_)));
    }

    #[test]
    fn from_str_rejects_invalid_base58() {
        let err = Pubkey::from_str("not-valid-base58-0OIl").unwrap_err();
        assert!(matches!(err, PubkeyError::Base58(_)));
    }

    #[test]
    fn create_program_address_rejects_too_many_seeds() {
        let program = Pubkey::from_str(TOKEN_PROGRAM).unwrap();
        let seed: &[u8] = b"s";
        let seeds = vec![seed; MAX_SEEDS + 1];
        let err = Pubkey::create_program_address(&seeds, &program).unwrap_err();
        assert_eq!(err, PubkeyError::TooManySeeds);
    }

    #[test]
    fn create_program_address_rejects_oversized_seed() {
        let program = Pubkey::from_str(TOKEN_PROGRAM).unwrap();
        let big_seed = vec![0u8; MAX_SEED_LEN + 1];
        let err = Pubkey::create_program_address(&[&big_seed], &program).unwrap_err();
        assert_eq!(err, PubkeyError::SeedTooLong);
    }

    #[test]
    fn find_program_address_is_off_curve_and_reproducible() {
        let program = Pubkey::from_str(TOKEN_PROGRAM).unwrap();
        let (address, bump) =
            Pubkey::find_program_address(&[b"metadata", b"seed-two"], &program).unwrap();
        assert!(!address.is_on_curve());

        // Re-deriving with the returned bump via create_program_address must
        // reproduce the exact same address.
        let bump_seed = [bump];
        let reproduced =
            Pubkey::create_program_address(&[b"metadata", b"seed-two", &bump_seed], &program)
                .unwrap();
        assert_eq!(address, reproduced);
    }

    /// Known-answer test: derives a real mainnet wallet's USDC ATA
    /// (`[wallet, token_program_id, mint]` seeds). Cross-checked against an
    /// independent from-scratch Python re-implementation and confirmed
    /// on-chain via `getTokenAccountsByOwner` (slot 433648265).
    #[test]
    fn find_program_address_known_answer_mainnet_ata() {
        let wallet = Pubkey::from_str("5Q544fKrFoe6tsEbD7S8EmxGTJYAKtTVhAW5Q5pge4j1").unwrap();
        let usdc_mint = Pubkey::from_str("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v").unwrap();
        let token_program = Pubkey::from_str(TOKEN_PROGRAM).unwrap();
        let ata_program = Pubkey::from_str(ATA_PROGRAM).unwrap();

        let (address, bump) = Pubkey::find_program_address(
            &[
                wallet.as_bytes(),
                token_program.as_bytes(),
                usdc_mint.as_bytes(),
            ],
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
