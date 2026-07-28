//! SPL Token / Token-2022 mint and account state parsing, via
//! `spl-token-2022-interface`'s `Mint`/`Account`/`Pack` and its
//! `StateWithExtensions`/TLV extension readers.
//!
//! Uses `spl-token-2022-interface`'s own `Mint`/`Account`, not
//! `spl-token-interface`'s: only the former implement the `BaseState` trait
//! `StateWithExtensions` requires, despite identical byte layout.
//!
//! Three extension finders, all mint extensions (pass a **mint** account's
//! raw `data`, not a token account's): [`find_transfer_fee_config`] (fees
//! silently deducted before the recipient sees them), [`find_permanent_delegate`]
//! (an address able to transfer/burn any holder's tokens, forever), and
//! [`find_transfer_hook`] (every transfer must CPI into an arbitrary program).

pub use spl_token_2022_interface::state::{Account as TokenAccount, AccountState, Mint};

use solana_program_pack::Pack;
use solana_pubkey::Pubkey;
use spl_token_2022_interface::extension::permanent_delegate::PermanentDelegate;
use spl_token_2022_interface::extension::transfer_fee::TransferFeeConfig as RawTransferFeeConfig;
use spl_token_2022_interface::extension::transfer_hook::TransferHook as RawTransferHook;
use spl_token_2022_interface::extension::{BaseStateWithExtensions, StateWithExtensions};

#[derive(Debug, thiserror::Error)]
pub enum TokenStateError {
    #[error("{0}")]
    Program(#[from] solana_program_error::ProgramError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransferFee {
    pub epoch: u64,
    pub maximum_fee: u64,
    pub transfer_fee_basis_points: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransferFeeConfig {
    pub transfer_fee_config_authority: Option<Pubkey>,
    pub withdraw_withheld_authority: Option<Pubkey>,
    pub withheld_amount: u64,
    /// In effect while `current_epoch < newer_transfer_fee.epoch`.
    pub older_transfer_fee: TransferFee,
    /// In effect while `current_epoch >= newer_transfer_fee.epoch`.
    pub newer_transfer_fee: TransferFee,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransferHookConfig {
    pub authority: Option<Pubkey>,
    pub program_id: Option<Pubkey>,
}

/// Unpacks a mint's base fields (same 82-byte layout for SPL Token and
/// Token-2022). `Pack::unpack` requires an exact-length slice, so input is
/// trimmed to the base length first.
pub fn unpack_mint(data: &[u8]) -> Result<Mint, TokenStateError> {
    let base_len = Mint::LEN.min(data.len());
    Mint::unpack(&data[..base_len]).map_err(TokenStateError::from)
}

/// Unpacks a token account's base fields (see [`unpack_mint`] for why the
/// input is trimmed first).
pub fn unpack_token_account(data: &[u8]) -> Result<TokenAccount, TokenStateError> {
    let base_len = TokenAccount::LEN.min(data.len());
    TokenAccount::unpack(&data[..base_len]).map_err(TokenStateError::from)
}

/// Finds the `TransferFeeConfig` extension on a **mint**, if present.
pub fn find_transfer_fee_config(
    mint_data: &[u8],
) -> Result<Option<TransferFeeConfig>, TokenStateError> {
    let state = StateWithExtensions::<Mint>::unpack(mint_data)?;
    let Ok(raw) = state.get_extension::<RawTransferFeeConfig>() else {
        return Ok(None);
    };
    Ok(Some(TransferFeeConfig {
        transfer_fee_config_authority: raw.transfer_fee_config_authority.into(),
        withdraw_withheld_authority: raw.withdraw_withheld_authority.into(),
        withheld_amount: raw.withheld_amount.into(),
        older_transfer_fee: TransferFee {
            epoch: raw.older_transfer_fee.epoch.into(),
            maximum_fee: raw.older_transfer_fee.maximum_fee.into(),
            transfer_fee_basis_points: raw.older_transfer_fee.transfer_fee_basis_points.into(),
        },
        newer_transfer_fee: TransferFee {
            epoch: raw.newer_transfer_fee.epoch.into(),
            maximum_fee: raw.newer_transfer_fee.maximum_fee.into(),
            transfer_fee_basis_points: raw.newer_transfer_fee.transfer_fee_basis_points.into(),
        },
    }))
}

/// Finds the `PermanentDelegate` extension's delegate on a **mint**, if
/// present. Not a red flag in every legitimate use case (some
/// regulated-asset mints need it), but a mint-risk check must never omit it.
pub fn find_permanent_delegate(mint_data: &[u8]) -> Result<Option<Pubkey>, TokenStateError> {
    let state = StateWithExtensions::<Mint>::unpack(mint_data)?;
    let Ok(raw) = state.get_extension::<PermanentDelegate>() else {
        return Ok(None);
    };
    Ok(raw.delegate.into())
}

/// Finds the `TransferHook` extension on a **mint**, if present.
pub fn find_transfer_hook(mint_data: &[u8]) -> Result<Option<TransferHookConfig>, TokenStateError> {
    let state = StateWithExtensions::<Mint>::unpack(mint_data)?;
    let Ok(raw) = state.get_extension::<RawTransferHook>() else {
        return Ok(None);
    };
    Ok(Some(TransferHookConfig {
        authority: raw.authority.into(),
        program_id: raw.program_id.into(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINT_LEN: usize = 82;
    const ACCOUNT_TYPE_OFFSET: usize = 165; // same absolute offset for mints and accounts
    const TLV_START_OFFSET: usize = ACCOUNT_TYPE_OFFSET + 1;
    const EXT_TYPE_TRANSFER_FEE_CONFIG: u16 = 1;
    const EXT_TYPE_PERMANENT_DELEGATE: u16 = 12;

    fn pk(byte: u8) -> Pubkey {
        Pubkey::new_from_array([byte; 32])
    }

    fn encode_coption_pubkey(buf: &mut Vec<u8>, value: Option<Pubkey>) {
        match value {
            Some(pubkey) => {
                buf.extend_from_slice(&1u32.to_le_bytes());
                buf.extend_from_slice(pubkey.as_ref());
            }
            None => buf.extend_from_slice(&[0u8; 36]),
        }
    }

    /// Hand-assembled per the base layout verified against
    /// `spl-token-interface`'s own `Mint::unpack_from_slice` (mint_authority
    /// COption<Pubkey>, supply u64 LE, decimals u8, is_initialized bool,
    /// freeze_authority COption<Pubkey>) — the same bytes the official
    /// parser under test consumes, assembled independently of it.
    fn hand_assembled_plain_mint(
        mint_authority: Option<Pubkey>,
        supply: u64,
        decimals: u8,
    ) -> Vec<u8> {
        let mut data = Vec::with_capacity(MINT_LEN);
        encode_coption_pubkey(&mut data, mint_authority);
        data.extend_from_slice(&supply.to_le_bytes());
        data.push(decimals);
        data.push(1); // is_initialized
        encode_coption_pubkey(&mut data, None); // freeze_authority
        assert_eq!(data.len(), MINT_LEN);
        data
    }

    #[test]
    fn unpacks_a_plain_mint() {
        let data = hand_assembled_plain_mint(Some(pk(7)), 1_000_000_000, 6);
        let mint = unpack_mint(&data).unwrap();
        assert_eq!(mint.supply, 1_000_000_000);
        assert_eq!(mint.decimals, 6);
        assert!(mint.is_initialized);
    }

    #[test]
    fn plain_mint_has_no_extensions() {
        let data = hand_assembled_plain_mint(None, 1, 0);
        assert_eq!(find_transfer_fee_config(&data).unwrap(), None);
        assert_eq!(find_permanent_delegate(&data).unwrap(), None);
        assert_eq!(find_transfer_hook(&data).unwrap(), None);
    }

    #[test]
    fn parses_permanent_delegate_on_an_extended_mint() {
        let mut data = hand_assembled_plain_mint(Some(pk(1)), 1_000_000, 6);
        data.resize(ACCOUNT_TYPE_OFFSET, 0); // zero-pad 82..165
        data.push(1); // AccountType::Mint

        let delegate = pk(9);
        data.extend_from_slice(&EXT_TYPE_PERMANENT_DELEGATE.to_le_bytes());
        data.extend_from_slice(&32u16.to_le_bytes());
        data.extend_from_slice(delegate.as_ref());
        assert_eq!(data.len(), TLV_START_OFFSET + 4 + 32); // +4 for the TLV type+length header

        assert_eq!(find_permanent_delegate(&data).unwrap(), Some(delegate));
        assert_eq!(find_transfer_fee_config(&data).unwrap(), None);

        // Base Mint fields still unpack correctly — extensions never
        // disturb bytes 0..82.
        assert_eq!(unpack_mint(&data).unwrap().supply, 1_000_000);
    }

    #[test]
    fn parses_transfer_fee_config_on_an_extended_mint() {
        let mut data = hand_assembled_plain_mint(Some(pk(1)), 1_000_000, 6);
        data.resize(ACCOUNT_TYPE_OFFSET, 0);
        data.push(1);

        let config_authority = pk(10);
        let withdraw_authority = pk(11);
        let mut value = Vec::with_capacity(108);
        value.extend_from_slice(config_authority.as_ref());
        value.extend_from_slice(withdraw_authority.as_ref());
        value.extend_from_slice(&500u64.to_le_bytes()); // withheld_amount
        value.extend_from_slice(&0u64.to_le_bytes()); // older epoch
        value.extend_from_slice(&1_000_000u64.to_le_bytes()); // older maximum_fee
        value.extend_from_slice(&50u16.to_le_bytes()); // older basis points
        value.extend_from_slice(&100u64.to_le_bytes()); // newer epoch
        value.extend_from_slice(&2_000_000u64.to_le_bytes()); // newer maximum_fee
        value.extend_from_slice(&75u16.to_le_bytes()); // newer basis points
        assert_eq!(value.len(), 108);

        data.extend_from_slice(&EXT_TYPE_TRANSFER_FEE_CONFIG.to_le_bytes());
        data.extend_from_slice(&(value.len() as u16).to_le_bytes());
        data.extend_from_slice(&value);

        let config = find_transfer_fee_config(&data).unwrap().unwrap();
        assert_eq!(config.transfer_fee_config_authority, Some(config_authority));
        assert_eq!(config.withdraw_withheld_authority, Some(withdraw_authority));
        assert_eq!(config.withheld_amount, 500);
        assert_eq!(
            config.older_transfer_fee,
            TransferFee {
                epoch: 0,
                maximum_fee: 1_000_000,
                transfer_fee_basis_points: 50
            }
        );
        assert_eq!(
            config.newer_transfer_fee,
            TransferFee {
                epoch: 100,
                maximum_fee: 2_000_000,
                transfer_fee_basis_points: 75
            }
        );
    }
}
