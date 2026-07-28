//! Re-exports `solana-message`'s legacy `Message` and versioned `v0::Message`.
//!
//! `legacy::Message::new_with_nonce` prepends `AdvanceNonceAccount` but
//! leaves `recent_blockhash` at its default — a caller who forgets to also
//! set it builds an invalid durable-nonce transaction. The two functions
//! below do both in one call.

pub use solana_message::{v0, AddressLookupTableAccount, CompileError, Message, MessageHeader};
pub use v0::Message as MessageV0;

use crate::hash::Hash;
use crate::pubkey::Pubkey;
use solana_instruction::Instruction;
use solana_system_interface::instruction::advance_nonce_account;

/// Builds a durable-nonce legacy message: `advance_nonce_account` is
/// prepended as instruction 0 (the runtime requires it consume the nonce
/// before anything else can fail), and `recent_blockhash` is set to the
/// nonce's own stored value.
///
/// `nonce_blockhash` should come from the nonce account's freshly fetched
/// state (see [`crate::nonce`]), not from `getLatestBlockhash`.
pub fn compile_legacy_with_durable_nonce(
    payer: &Pubkey,
    nonce_account: &Pubkey,
    nonce_authority: &Pubkey,
    nonce_blockhash: Hash,
    instructions: &[Instruction],
) -> Message {
    let mut all = Vec::with_capacity(instructions.len() + 1);
    all.push(advance_nonce_account(nonce_account, nonce_authority));
    all.extend_from_slice(instructions);

    let mut message = Message::new(&all, Some(payer));
    message.recent_blockhash = nonce_blockhash;
    message
}

/// Same as [`compile_legacy_with_durable_nonce`], for the versioned (v0)
/// format with address lookup tables.
pub fn compile_v0_with_durable_nonce(
    payer: &Pubkey,
    nonce_account: &Pubkey,
    nonce_authority: &Pubkey,
    nonce_blockhash: Hash,
    instructions: &[Instruction],
    address_lookup_table_accounts: &[AddressLookupTableAccount],
) -> Result<v0::Message, CompileError> {
    let mut all = Vec::with_capacity(instructions.len() + 1);
    all.push(advance_nonce_account(nonce_account, nonce_authority));
    all.extend_from_slice(instructions);

    v0::Message::try_compile(payer, &all, address_lookup_table_accounts, nonce_blockhash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_system_interface::instruction::transfer;
    use std::str::FromStr;

    #[test]
    fn durable_nonce_message_places_advance_nonce_first_and_uses_nonce_blockhash() {
        let payer = Pubkey::from_str("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").unwrap();
        let nonce_account =
            Pubkey::from_str("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL").unwrap();
        let to = Pubkey::from_str("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr").unwrap();
        let nonce_blockhash = Hash::new_from_array([9; 32]);

        let transfer_ix = transfer(&payer, &to, 1_000);
        let message = compile_legacy_with_durable_nonce(
            &payer,
            &nonce_account,
            &payer,
            nonce_blockhash,
            &[transfer_ix],
        );

        assert_eq!(message.instructions[0].data, [4, 0, 0, 0]);
        assert_eq!(message.instructions.len(), 2);
        assert_eq!(message.recent_blockhash, nonce_blockhash);
        assert!(message.account_keys.contains(&nonce_account));
    }

    #[test]
    fn durable_nonce_v0_message_places_advance_nonce_first_and_uses_nonce_blockhash() {
        let payer = Pubkey::from_str("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").unwrap();
        let nonce_account =
            Pubkey::from_str("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL").unwrap();
        let to = Pubkey::from_str("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr").unwrap();
        let nonce_blockhash = Hash::new_from_array([9; 32]);

        let transfer_ix = transfer(&payer, &to, 1_000);
        let message = compile_v0_with_durable_nonce(
            &payer,
            &nonce_account,
            &payer,
            nonce_blockhash,
            &[transfer_ix],
            &[],
        )
        .unwrap();

        assert_eq!(message.instructions[0].data, [4, 0, 0, 0]);
        assert_eq!(message.instructions.len(), 2);
        assert_eq!(message.recent_blockhash, nonce_blockhash);
        assert!(message.account_keys.contains(&nonce_account));
    }
}
