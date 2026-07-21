//! SPL Token / Token-2022 mint and account state parsing: decoding on-chain
//! account data fetched via [`crate::rpc::RpcClient::get_account_info`], the
//! read side complementing [`crate::instruction::token`]'s encode side.
//!
//! Base layouts and the Token-2022 extension TLV format are verified
//! against `solana-program/token-2022`'s own source (`interface/src/
//! {state,extension/mod,extension/transfer_fee,extension/permanent_delegate,
//! extension/transfer_hook}.rs`), not reconstructed from a description. One
//! non-obvious detail: a *mint* with extensions is zero-padded out to 165
//! bytes (the token *account* size) before its extension data starts, so
//! both mints and accounts locate their `AccountType` marker at the same
//! offset (165) — deliberate upstream, so an extended mint can never be
//! misread as an extended account purely from size.

use crate::pubkey::Pubkey;

pub const MINT_LEN: usize = 82;
pub const ACCOUNT_LEN: usize = 165;
const ACCOUNT_TYPE_OFFSET: usize = ACCOUNT_LEN; // 165, identical for mint and account
const TLV_START_OFFSET: usize = ACCOUNT_TYPE_OFFSET + 1; // 166

const EXT_TYPE_UNINITIALIZED: u16 = 0;
const EXT_TYPE_TRANSFER_FEE_CONFIG: u16 = 1;
const EXT_TYPE_PERMANENT_DELEGATE: u16 = 12;
const EXT_TYPE_TRANSFER_HOOK: u16 = 14;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TokenStateError {
    #[error("account data is {actual} bytes, too short for a {expected}-byte {kind}")]
    TooShort {
        actual: usize,
        expected: usize,
        kind: &'static str,
    },
    #[error("invalid account state byte: {0}")]
    InvalidAccountState(u8),
    #[error("malformed TLV extension data: {0}")]
    MalformedTlv(String),
}

/// The original SPL Token program's `COption<T>`: a 4-byte little-endian
/// `u32` presence tag (`0` = `None`, `1` = `Some`) followed by `T`'s bytes.
/// Distinct from Token-2022's newer `MaybeNull<Pubkey>` (see
/// [`decode_maybe_null_pubkey`]) used only within extension data.
fn decode_coption_pubkey(bytes: &[u8]) -> Option<Pubkey> {
    let tag = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    if tag == 0 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes[4..36]);
    Some(Pubkey::new_from_array(arr))
}

fn decode_coption_u64(bytes: &[u8]) -> Option<u64> {
    let tag = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    if tag == 0 {
        return None;
    }
    Some(u64::from_le_bytes(bytes[4..12].try_into().unwrap()))
}

/// Token-2022's `MaybeNull<Pubkey>` (a.k.a. `OptionalNonZeroPubkey`)
/// convention used throughout its extensions: 32 raw bytes, all-zero means
/// `None`, anything else is the pubkey itself. No separate presence tag —
/// unlike [`decode_coption_pubkey`], which is a different, older encoding
/// used only in the base Mint/Account layout.
fn decode_maybe_null_pubkey(bytes: &[u8]) -> Option<Pubkey> {
    if bytes.iter().all(|&b| b == 0) {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    Some(Pubkey::new_from_array(arr))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccountState {
    Uninitialized,
    Initialized,
    Frozen,
}

/// The base 82-byte Mint layout, common to SPL Token and Token-2022 (a
/// Token-2022 mint's extensions, if any, live past this — see
/// [`find_transfer_fee_config`] and friends).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mint {
    pub mint_authority: Option<Pubkey>,
    pub supply: u64,
    pub decimals: u8,
    pub is_initialized: bool,
    pub freeze_authority: Option<Pubkey>,
}

impl Mint {
    pub fn unpack(data: &[u8]) -> Result<Self, TokenStateError> {
        if data.len() < MINT_LEN {
            return Err(TokenStateError::TooShort {
                actual: data.len(),
                expected: MINT_LEN,
                kind: "Mint",
            });
        }
        Ok(Self {
            mint_authority: decode_coption_pubkey(&data[0..36]),
            supply: u64::from_le_bytes(data[36..44].try_into().unwrap()),
            decimals: data[44],
            is_initialized: data[45] != 0,
            freeze_authority: decode_coption_pubkey(&data[46..82]),
        })
    }
}

/// The base 165-byte token Account layout, common to SPL Token and
/// Token-2022.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TokenAccount {
    pub mint: Pubkey,
    pub owner: Pubkey,
    pub amount: u64,
    pub delegate: Option<Pubkey>,
    pub state: AccountState,
    pub is_native: Option<u64>,
    pub delegated_amount: u64,
    pub close_authority: Option<Pubkey>,
}

impl TokenAccount {
    pub fn unpack(data: &[u8]) -> Result<Self, TokenStateError> {
        if data.len() < ACCOUNT_LEN {
            return Err(TokenStateError::TooShort {
                actual: data.len(),
                expected: ACCOUNT_LEN,
                kind: "Account",
            });
        }

        let mut mint = [0u8; 32];
        mint.copy_from_slice(&data[0..32]);
        let mut owner = [0u8; 32];
        owner.copy_from_slice(&data[32..64]);
        let state = match data[108] {
            0 => AccountState::Uninitialized,
            1 => AccountState::Initialized,
            2 => AccountState::Frozen,
            other => return Err(TokenStateError::InvalidAccountState(other)),
        };

        Ok(Self {
            mint: Pubkey::new_from_array(mint),
            owner: Pubkey::new_from_array(owner),
            amount: u64::from_le_bytes(data[64..72].try_into().unwrap()),
            delegate: decode_coption_pubkey(&data[72..108]),
            state,
            is_native: decode_coption_u64(&data[109..121]),
            delegated_amount: u64::from_le_bytes(data[121..129].try_into().unwrap()),
            close_authority: decode_coption_pubkey(&data[129..165]),
        })
    }
}

/// Walks the TLV extension entries in `data` (a full mint or token
/// account's raw bytes), returning `(extension_type, value_bytes)` pairs.
/// Empty if `data` is no longer than [`ACCOUNT_TYPE_OFFSET`] — too short to
/// hold even the `AccountType` marker, so it's a bare Mint/Account with no
/// extensions at all.
fn tlv_entries(data: &[u8]) -> Result<Vec<(u16, &[u8])>, TokenStateError> {
    if data.len() <= ACCOUNT_TYPE_OFFSET {
        return Ok(Vec::new());
    }

    let mut entries = Vec::new();
    let mut offset = TLV_START_OFFSET;
    while offset + 4 <= data.len() {
        let ext_type = u16::from_le_bytes(data[offset..offset + 2].try_into().unwrap());
        if ext_type == EXT_TYPE_UNINITIALIZED {
            break; // padding / end of TLV data
        }
        let len = u16::from_le_bytes(data[offset + 2..offset + 4].try_into().unwrap()) as usize;
        let value_start = offset + 4;
        let value_end = value_start + len;
        if value_end > data.len() {
            return Err(TokenStateError::MalformedTlv(format!(
                "extension type {ext_type} claims {len} bytes but only {} remain",
                data.len().saturating_sub(value_start)
            )));
        }
        entries.push((ext_type, &data[value_start..value_end]));
        offset = value_end;
    }
    Ok(entries)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransferFee {
    pub epoch: u64,
    pub maximum_fee: u64,
    pub transfer_fee_basis_points: u16,
}

fn decode_transfer_fee(bytes: &[u8]) -> TransferFee {
    TransferFee {
        epoch: u64::from_le_bytes(bytes[0..8].try_into().unwrap()),
        maximum_fee: u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
        transfer_fee_basis_points: u16::from_le_bytes(bytes[16..18].try_into().unwrap()),
    }
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

/// Finds and decodes the `TransferFeeConfig` extension, if present — a
/// mint whose transfers silently deduct a fee (up to
/// `transfer_fee_basis_points` / 10,000, capped at `maximum_fee`) before
/// the recipient sees it. A tool that quotes a transfer amount without
/// checking this will misreport what actually lands.
pub fn find_transfer_fee_config(data: &[u8]) -> Result<Option<TransferFeeConfig>, TokenStateError> {
    for (ext_type, value) in tlv_entries(data)? {
        if ext_type != EXT_TYPE_TRANSFER_FEE_CONFIG {
            continue;
        }
        if value.len() != 108 {
            return Err(TokenStateError::MalformedTlv(format!(
                "TransferFeeConfig expected 108 bytes, got {}",
                value.len()
            )));
        }
        return Ok(Some(TransferFeeConfig {
            transfer_fee_config_authority: decode_maybe_null_pubkey(&value[0..32]),
            withdraw_withheld_authority: decode_maybe_null_pubkey(&value[32..64]),
            withheld_amount: u64::from_le_bytes(value[64..72].try_into().unwrap()),
            older_transfer_fee: decode_transfer_fee(&value[72..90]),
            newer_transfer_fee: decode_transfer_fee(&value[90..108]),
        }));
    }
    Ok(None)
}

/// Finds the `PermanentDelegate` extension's delegate, if present — an
/// address able to transfer or burn *any* holder's tokens for this mint,
/// unconditionally, forever. Not a red flag in every legitimate use case
/// (some regulated-asset mints need it), but a tool surfacing mint risk
/// must never omit it.
pub fn find_permanent_delegate(data: &[u8]) -> Result<Option<Pubkey>, TokenStateError> {
    for (ext_type, value) in tlv_entries(data)? {
        if ext_type != EXT_TYPE_PERMANENT_DELEGATE {
            continue;
        }
        if value.len() != 32 {
            return Err(TokenStateError::MalformedTlv(format!(
                "PermanentDelegate expected 32 bytes, got {}",
                value.len()
            )));
        }
        return Ok(decode_maybe_null_pubkey(value));
    }
    Ok(None)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransferHookConfig {
    pub authority: Option<Pubkey>,
    pub program_id: Option<Pubkey>,
}

/// Finds the `TransferHook` extension, if present — every transfer of this
/// mint's tokens must successfully CPI into `program_id`, which can impose
/// arbitrary additional logic (or fail the transfer outright). A build-only
/// tool plugin can't execute that CPI itself, but it must surface the
/// hook's existence so a human approving the transaction isn't surprised.
pub fn find_transfer_hook(data: &[u8]) -> Result<Option<TransferHookConfig>, TokenStateError> {
    for (ext_type, value) in tlv_entries(data)? {
        if ext_type != EXT_TYPE_TRANSFER_HOOK {
            continue;
        }
        if value.len() != 64 {
            return Err(TokenStateError::MalformedTlv(format!(
                "TransferHook expected 64 bytes, got {}",
                value.len()
            )));
        }
        return Ok(Some(TransferHookConfig {
            authority: decode_maybe_null_pubkey(&value[0..32]),
            program_id: decode_maybe_null_pubkey(&value[32..64]),
        }));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pk(byte: u8) -> Pubkey {
        Pubkey::new_from_array([byte; 32])
    }

    fn encode_coption_pubkey(buf: &mut Vec<u8>, value: Option<Pubkey>) {
        match value {
            Some(pubkey) => {
                buf.extend_from_slice(&1u32.to_le_bytes());
                buf.extend_from_slice(pubkey.as_bytes());
            }
            None => buf.extend_from_slice(&[0u8; 36]),
        }
    }

    fn encode_coption_u64(buf: &mut Vec<u8>, value: Option<u64>) {
        match value {
            Some(v) => {
                buf.extend_from_slice(&1u32.to_le_bytes());
                buf.extend_from_slice(&v.to_le_bytes());
            }
            None => buf.extend_from_slice(&[0u8; 12]),
        }
    }

    fn hand_assembled_mint(mint_authority: Option<Pubkey>, supply: u64, decimals: u8) -> Vec<u8> {
        let mut data = Vec::with_capacity(MINT_LEN);
        encode_coption_pubkey(&mut data, mint_authority);
        data.extend_from_slice(&supply.to_le_bytes());
        data.push(decimals);
        data.push(1); // is_initialized
        encode_coption_pubkey(&mut data, None); // freeze_authority
        assert_eq!(data.len(), MINT_LEN);
        data
    }

    fn hand_assembled_account(
        mint: Pubkey,
        owner: Pubkey,
        amount: u64,
        delegate: Option<Pubkey>,
    ) -> Vec<u8> {
        let mut data = Vec::with_capacity(ACCOUNT_LEN);
        data.extend_from_slice(mint.as_bytes());
        data.extend_from_slice(owner.as_bytes());
        data.extend_from_slice(&amount.to_le_bytes());
        encode_coption_pubkey(&mut data, delegate);
        data.push(1); // state = Initialized
        encode_coption_u64(&mut data, None); // is_native
        data.extend_from_slice(&0u64.to_le_bytes()); // delegated_amount
        encode_coption_pubkey(&mut data, None); // close_authority
        assert_eq!(data.len(), ACCOUNT_LEN);
        data
    }

    #[test]
    fn unpacks_a_plain_mint_with_no_authorities() {
        let data = hand_assembled_mint(None, 1_000_000_000, 6);
        let mint = Mint::unpack(&data).unwrap();
        assert_eq!(mint.mint_authority, None);
        assert_eq!(mint.supply, 1_000_000_000);
        assert_eq!(mint.decimals, 6);
        assert!(mint.is_initialized);
        assert_eq!(mint.freeze_authority, None);
    }

    #[test]
    fn unpacks_a_mint_with_a_mint_authority() {
        let authority = pk(7);
        let data = hand_assembled_mint(Some(authority), 42, 9);
        let mint = Mint::unpack(&data).unwrap();
        assert_eq!(mint.mint_authority, Some(authority));
    }

    #[test]
    fn mint_unpack_rejects_short_data() {
        let err = Mint::unpack(&[0u8; MINT_LEN - 1]).unwrap_err();
        assert_eq!(
            err,
            TokenStateError::TooShort {
                actual: MINT_LEN - 1,
                expected: MINT_LEN,
                kind: "Mint"
            }
        );
    }

    #[test]
    fn unpacks_a_token_account_with_a_delegate() {
        let mint = pk(1);
        let owner = pk(2);
        let delegate = pk(3);
        let data = hand_assembled_account(mint, owner, 123_456, Some(delegate));

        let account = TokenAccount::unpack(&data).unwrap();
        assert_eq!(account.mint, mint);
        assert_eq!(account.owner, owner);
        assert_eq!(account.amount, 123_456);
        assert_eq!(account.delegate, Some(delegate));
        assert_eq!(account.state, AccountState::Initialized);
        assert_eq!(account.is_native, None);
    }

    #[test]
    fn account_with_no_extensions_has_no_transfer_fee_config() {
        let data = hand_assembled_account(pk(1), pk(2), 0, None);
        assert_eq!(find_transfer_fee_config(&data).unwrap(), None);
        assert_eq!(find_permanent_delegate(&data).unwrap(), None);
        assert_eq!(find_transfer_hook(&data).unwrap(), None);
    }

    /// Hand-assembles a Token-2022 *mint* with a `TransferFeeConfig`
    /// extension, exercising the padding trick verified against source:
    /// bytes 82..165 are zero padding (not extension data), the
    /// `AccountType` marker sits at absolute offset 165, and TLV data
    /// starts at 166 — for a mint exactly the same as for an account.
    #[test]
    fn parses_transfer_fee_config_on_an_extended_mint() {
        let mut data = hand_assembled_mint(Some(pk(1)), 1_000_000, 6);
        data.resize(ACCOUNT_TYPE_OFFSET, 0); // zero-pad 82..165
        data.push(1); // AccountType::Mint

        let config_authority = pk(10);
        let withdraw_authority = pk(11);
        let mut extension_value = Vec::with_capacity(108);
        extension_value.extend_from_slice(config_authority.as_bytes());
        extension_value.extend_from_slice(withdraw_authority.as_bytes());
        extension_value.extend_from_slice(&500u64.to_le_bytes()); // withheld_amount
        extension_value.extend_from_slice(&0u64.to_le_bytes()); // older_transfer_fee.epoch
        extension_value.extend_from_slice(&1_000_000u64.to_le_bytes()); // older maximum_fee
        extension_value.extend_from_slice(&50u16.to_le_bytes()); // older basis points
        extension_value.extend_from_slice(&100u64.to_le_bytes()); // newer_transfer_fee.epoch
        extension_value.extend_from_slice(&2_000_000u64.to_le_bytes()); // newer maximum_fee
        extension_value.extend_from_slice(&75u16.to_le_bytes()); // newer basis points
        assert_eq!(extension_value.len(), 108);

        data.extend_from_slice(&EXT_TYPE_TRANSFER_FEE_CONFIG.to_le_bytes());
        data.extend_from_slice(&(extension_value.len() as u16).to_le_bytes());
        data.extend_from_slice(&extension_value);

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

        // The base Mint fields must still unpack correctly — extensions
        // never disturb bytes 0..82.
        let mint = Mint::unpack(&data).unwrap();
        assert_eq!(mint.supply, 1_000_000);
    }

    #[test]
    fn parses_permanent_delegate_on_an_extended_account() {
        let mut data = hand_assembled_account(pk(1), pk(2), 0, None);
        data.push(2); // AccountType::Account

        let delegate = pk(9);
        data.extend_from_slice(&EXT_TYPE_PERMANENT_DELEGATE.to_le_bytes());
        data.extend_from_slice(&32u16.to_le_bytes());
        data.extend_from_slice(delegate.as_bytes());

        assert_eq!(find_permanent_delegate(&data).unwrap(), Some(delegate));
        // Unrelated extension queries against the same account correctly
        // find nothing.
        assert_eq!(find_transfer_fee_config(&data).unwrap(), None);
    }

    #[test]
    fn permanent_delegate_all_zero_bytes_means_none_not_the_zero_pubkey() {
        let mut data = hand_assembled_account(pk(1), pk(2), 0, None);
        data.push(2);
        data.extend_from_slice(&EXT_TYPE_PERMANENT_DELEGATE.to_le_bytes());
        data.extend_from_slice(&32u16.to_le_bytes());
        data.extend_from_slice(&[0u8; 32]);

        assert_eq!(find_permanent_delegate(&data).unwrap(), None);
    }

    #[test]
    fn parses_transfer_hook_with_both_fields_present() {
        let mut data = hand_assembled_mint(None, 1, 0);
        data.resize(ACCOUNT_TYPE_OFFSET, 0);
        data.push(1);

        let authority = pk(20);
        let program_id = pk(21);
        data.extend_from_slice(&EXT_TYPE_TRANSFER_HOOK.to_le_bytes());
        data.extend_from_slice(&64u16.to_le_bytes());
        data.extend_from_slice(authority.as_bytes());
        data.extend_from_slice(program_id.as_bytes());

        let hook = find_transfer_hook(&data).unwrap().unwrap();
        assert_eq!(hook.authority, Some(authority));
        assert_eq!(hook.program_id, Some(program_id));
    }

    #[test]
    fn multiple_extensions_are_each_found_independently() {
        let mut data = hand_assembled_mint(None, 1, 0);
        data.resize(ACCOUNT_TYPE_OFFSET, 0);
        data.push(1);

        let delegate = pk(30);
        data.extend_from_slice(&EXT_TYPE_PERMANENT_DELEGATE.to_le_bytes());
        data.extend_from_slice(&32u16.to_le_bytes());
        data.extend_from_slice(delegate.as_bytes());

        let hook_program = pk(31);
        data.extend_from_slice(&EXT_TYPE_TRANSFER_HOOK.to_le_bytes());
        data.extend_from_slice(&64u16.to_le_bytes());
        data.extend_from_slice(&[0u8; 32]); // authority: none
        data.extend_from_slice(hook_program.as_bytes());

        assert_eq!(find_permanent_delegate(&data).unwrap(), Some(delegate));
        let hook = find_transfer_hook(&data).unwrap().unwrap();
        assert_eq!(hook.authority, None);
        assert_eq!(hook.program_id, Some(hook_program));
        assert_eq!(find_transfer_fee_config(&data).unwrap(), None);
    }

    #[test]
    fn malformed_tlv_length_is_rejected_rather_than_panicking() {
        let mut data = hand_assembled_account(pk(1), pk(2), 0, None);
        data.push(2);
        data.extend_from_slice(&EXT_TYPE_PERMANENT_DELEGATE.to_le_bytes());
        // Claims 1000 bytes of value data but the buffer ends immediately.
        data.extend_from_slice(&1000u16.to_le_bytes());

        let err = find_permanent_delegate(&data).unwrap_err();
        assert!(matches!(err, TokenStateError::MalformedTlv(_)));
    }

    #[test]
    fn wrong_sized_extension_value_is_rejected() {
        let mut data = hand_assembled_account(pk(1), pk(2), 0, None);
        data.push(2);
        data.extend_from_slice(&EXT_TYPE_PERMANENT_DELEGATE.to_le_bytes());
        data.extend_from_slice(&16u16.to_le_bytes()); // should be 32
        data.extend_from_slice(&[0u8; 16]);

        let err = find_permanent_delegate(&data).unwrap_err();
        assert!(matches!(err, TokenStateError::MalformedTlv(_)));
    }
}
