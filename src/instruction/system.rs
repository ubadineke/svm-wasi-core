//! System program instruction encoding.
//!
//! `SystemInstruction` is bincode-tagged: a 4-byte little-endian `u32`
//! variant discriminant followed by the variant's fields in declaration
//! order, each raw little-endian. For the fixed-size fields used here
//! (`u64`, `Pubkey`) that's byte-for-byte identical to a hand-written
//! encoder, so no borsh/bincode dependency is pulled in just for this.
//!
//! Discriminants and account lists verified against `solana-program/system`'s
//! own codama-generated client (auto-derived from the on-chain IDL) for
//! `create_account`/`transfer`/`advance_nonce_account`; the remaining nonce
//! instructions are verified against `agave`'s on-chain processor itself.

use super::{known_id, AccountMeta, Instruction};
use crate::pubkey::Pubkey;

const CREATE_ACCOUNT_DISCRIMINANT: u32 = 0;
const TRANSFER_DISCRIMINANT: u32 = 2;
const ADVANCE_NONCE_ACCOUNT_DISCRIMINANT: u32 = 4;
const WITHDRAW_NONCE_ACCOUNT_DISCRIMINANT: u32 = 5;
const INITIALIZE_NONCE_ACCOUNT_DISCRIMINANT: u32 = 6;
const AUTHORIZE_NONCE_ACCOUNT_DISCRIMINANT: u32 = 7;

pub fn id() -> Pubkey {
    known_id("11111111111111111111111111111111")
}

/// The sysvar `advance_nonce_account` (and `initialize`/`withdraw`) read the
/// current blockhash from.
pub fn recent_blockhashes_sysvar_id() -> Pubkey {
    known_id("SysvarRecentB1ockHashes11111111111111111111")
}

/// The sysvar `initialize_nonce_account`/`withdraw_nonce_account` check
/// rent-exemption against.
pub fn rent_sysvar_id() -> Pubkey {
    known_id("SysvarRent111111111111111111111111111111111")
}

/// `SystemInstruction::CreateAccount { lamports, space, owner }`.
///
/// Both `payer` and `new_account` must sign: `payer` authorizes the lamport
/// transfer, `new_account` proves ownership of the private key for the
/// address being created (there is no PDA/CPI path here, so this is always
/// a plain keypair signature, not a `invoke_signed` seed proof).
pub fn create_account(
    payer: &Pubkey,
    new_account: &Pubkey,
    lamports: u64,
    space: u64,
    owner: &Pubkey,
) -> Instruction {
    let mut data = Vec::with_capacity(4 + 8 + 8 + 32);
    data.extend_from_slice(&CREATE_ACCOUNT_DISCRIMINANT.to_le_bytes());
    data.extend_from_slice(&lamports.to_le_bytes());
    data.extend_from_slice(&space.to_le_bytes());
    data.extend_from_slice(owner.as_bytes());

    Instruction {
        program_id: id(),
        accounts: vec![
            AccountMeta::new(*payer, true),
            AccountMeta::new(*new_account, true),
        ],
        data,
    }
}

/// `SystemInstruction::Transfer { lamports }`.
pub fn transfer(from: &Pubkey, to: &Pubkey, lamports: u64) -> Instruction {
    let mut data = Vec::with_capacity(4 + 8);
    data.extend_from_slice(&TRANSFER_DISCRIMINANT.to_le_bytes());
    data.extend_from_slice(&lamports.to_le_bytes());

    Instruction {
        program_id: id(),
        accounts: vec![AccountMeta::new(*from, true), AccountMeta::new(*to, false)],
        data,
    }
}

/// `SystemInstruction::AdvanceNonceAccount`, the primitive a durable-nonce
/// transaction places first so it never expires waiting on a human
/// approval. Message-layer placement (instruction 0) is enforced by
/// [`crate::message::legacy::Message::try_compile_with_durable_nonce`] /
/// [`crate::message::v0::Message::try_compile_with_durable_nonce`]; parsing
/// the nonce account's own state lives in [`crate::nonce`].
pub fn advance_nonce_account(nonce_account: &Pubkey, nonce_authority: &Pubkey) -> Instruction {
    Instruction {
        program_id: id(),
        accounts: vec![
            AccountMeta::new(*nonce_account, false),
            AccountMeta::new_readonly(recent_blockhashes_sysvar_id(), false),
            AccountMeta::new_readonly(*nonce_authority, true),
        ],
        data: ADVANCE_NONCE_ACCOUNT_DISCRIMINANT.to_le_bytes().to_vec(),
    }
}

/// `SystemInstruction::InitializeNonceAccount(authority)`. Turns a freshly
/// `create_account`-ed, System-owned, rent-exempt 80-byte account into a
/// durable-nonce account. The nonce account itself does not need to sign
/// this instruction (only `create_account` required its signature); no
/// separate authority signature is required here either — the account is
/// self-authorizing until this call sets its permanent authority.
pub fn initialize_nonce_account(nonce_account: &Pubkey, authority: &Pubkey) -> Instruction {
    let mut data = Vec::with_capacity(4 + 32);
    data.extend_from_slice(&INITIALIZE_NONCE_ACCOUNT_DISCRIMINANT.to_le_bytes());
    data.extend_from_slice(authority.as_bytes());

    Instruction {
        program_id: id(),
        accounts: vec![
            AccountMeta::new(*nonce_account, false),
            AccountMeta::new_readonly(recent_blockhashes_sysvar_id(), false),
            AccountMeta::new_readonly(rent_sysvar_id(), false),
        ],
        data,
    }
}

/// `SystemInstruction::AuthorizeNonceAccount(new_authority)`. Changes who
/// must sign future `advance`/`withdraw` calls; `current_authority` must
/// sign this instruction (checked by the runtime against the account's
/// stored authority, not by account position).
pub fn authorize_nonce_account(
    nonce_account: &Pubkey,
    current_authority: &Pubkey,
    new_authority: &Pubkey,
) -> Instruction {
    let mut data = Vec::with_capacity(4 + 32);
    data.extend_from_slice(&AUTHORIZE_NONCE_ACCOUNT_DISCRIMINANT.to_le_bytes());
    data.extend_from_slice(new_authority.as_bytes());

    Instruction {
        program_id: id(),
        accounts: vec![
            AccountMeta::new(*nonce_account, false),
            AccountMeta::new_readonly(*current_authority, true),
        ],
        data,
    }
}

/// `SystemInstruction::WithdrawNonceAccount(lamports)`. Withdrawing the
/// account's entire balance also resets it to `Uninitialized`, freeing it
/// for reuse; `authority` must sign (the runtime checks this against the
/// account's stored authority — or, for an already-uninitialized account,
/// against the nonce account's own key).
pub fn withdraw_nonce_account(
    nonce_account: &Pubkey,
    authority: &Pubkey,
    to: &Pubkey,
    lamports: u64,
) -> Instruction {
    let mut data = Vec::with_capacity(4 + 8);
    data.extend_from_slice(&WITHDRAW_NONCE_ACCOUNT_DISCRIMINANT.to_le_bytes());
    data.extend_from_slice(&lamports.to_le_bytes());

    Instruction {
        program_id: id(),
        accounts: vec![
            AccountMeta::new(*nonce_account, false),
            AccountMeta::new(*to, false),
            AccountMeta::new_readonly(recent_blockhashes_sysvar_id(), false),
            AccountMeta::new_readonly(rent_sysvar_id(), false),
            AccountMeta::new_readonly(*authority, true),
        ],
        data,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn program_id_is_the_all_zero_pubkey() {
        assert_eq!(id().to_bytes(), [0u8; 32]);
    }

    #[test]
    fn create_account_encodes_discriminant_and_fields_in_order() {
        let payer = Pubkey::from_str("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").unwrap();
        let new_account = Pubkey::from_str("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL").unwrap();
        let owner = Pubkey::from_str("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr").unwrap();

        let ix = create_account(&payer, &new_account, 890_880, 165, &owner);

        assert_eq!(ix.program_id, id());
        assert_eq!(
            ix.accounts,
            vec![
                AccountMeta::new(payer, true),
                AccountMeta::new(new_account, true)
            ]
        );

        let mut expected = vec![0, 0, 0, 0]; // discriminant 0, LE u32
        expected.extend_from_slice(&890_880u64.to_le_bytes());
        expected.extend_from_slice(&165u64.to_le_bytes());
        expected.extend_from_slice(owner.as_bytes());
        assert_eq!(ix.data, expected);
    }

    #[test]
    fn transfer_encodes_discriminant_and_lamports() {
        let from = Pubkey::from_str("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").unwrap();
        let to = Pubkey::from_str("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL").unwrap();

        let ix = transfer(&from, &to, 1_000_000_000);

        assert_eq!(ix.program_id, id());
        assert_eq!(
            ix.accounts,
            vec![AccountMeta::new(from, true), AccountMeta::new(to, false)]
        );
        assert_eq!(ix.data, [2, 0, 0, 0, 0, 202, 154, 59, 0, 0, 0, 0]);
    }

    #[test]
    fn advance_nonce_account_encodes_fixed_accounts_and_empty_args() {
        let nonce = Pubkey::from_str("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").unwrap();
        let authority = Pubkey::from_str("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL").unwrap();

        let ix = advance_nonce_account(&nonce, &authority);

        assert_eq!(ix.data, [4, 0, 0, 0]);
        assert_eq!(
            ix.accounts,
            vec![
                AccountMeta::new(nonce, false),
                AccountMeta::new_readonly(recent_blockhashes_sysvar_id(), false),
                AccountMeta::new_readonly(authority, true),
            ]
        );
    }

    #[test]
    fn initialize_nonce_account_encodes_discriminant_and_authority() {
        let nonce = Pubkey::from_str("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").unwrap();
        let authority = Pubkey::from_str("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL").unwrap();

        let ix = initialize_nonce_account(&nonce, &authority);

        let mut expected = vec![6, 0, 0, 0];
        expected.extend_from_slice(authority.as_bytes());
        assert_eq!(ix.data, expected);
        assert_eq!(
            ix.accounts,
            vec![
                AccountMeta::new(nonce, false),
                AccountMeta::new_readonly(recent_blockhashes_sysvar_id(), false),
                AccountMeta::new_readonly(rent_sysvar_id(), false),
            ]
        );
    }

    #[test]
    fn authorize_nonce_account_encodes_discriminant_and_new_authority() {
        let nonce = Pubkey::from_str("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").unwrap();
        let current = Pubkey::from_str("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL").unwrap();
        let new_authority =
            Pubkey::from_str("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr").unwrap();

        let ix = authorize_nonce_account(&nonce, &current, &new_authority);

        let mut expected = vec![7, 0, 0, 0];
        expected.extend_from_slice(new_authority.as_bytes());
        assert_eq!(ix.data, expected);
        assert_eq!(
            ix.accounts,
            vec![
                AccountMeta::new(nonce, false),
                AccountMeta::new_readonly(current, true)
            ]
        );
    }

    #[test]
    fn withdraw_nonce_account_encodes_discriminant_lamports_and_five_accounts() {
        let nonce = Pubkey::from_str("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").unwrap();
        let authority = Pubkey::from_str("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL").unwrap();
        let to = Pubkey::from_str("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr").unwrap();

        let ix = withdraw_nonce_account(&nonce, &authority, &to, 890_880);

        let mut expected = vec![5, 0, 0, 0];
        expected.extend_from_slice(&890_880u64.to_le_bytes());
        assert_eq!(ix.data, expected);
        assert_eq!(
            ix.accounts,
            vec![
                AccountMeta::new(nonce, false),
                AccountMeta::new(to, false),
                AccountMeta::new_readonly(recent_blockhashes_sysvar_id(), false),
                AccountMeta::new_readonly(rent_sysvar_id(), false),
                AccountMeta::new_readonly(authority, true),
            ]
        );
    }
}
