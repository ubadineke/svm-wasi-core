//! The original, unversioned transaction message format.

use super::compiled_keys::{CompileError, CompiledKeys};
use super::{
    compile_instructions, push_short_vec_len, resolve_key_index, CompiledInstruction, MessageHeader,
};
use crate::hash::Hash;
use crate::instruction::{system, Instruction};
use crate::pubkey::Pubkey;

/// A legacy (unversioned) Solana transaction message.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Message {
    pub header: MessageHeader,
    pub account_keys: Vec<Pubkey>,
    pub recent_blockhash: Hash,
    pub instructions: Vec<CompiledInstruction>,
}

impl Message {
    /// Compiles `instructions` into a message: collects every account
    /// referenced, orders them by the wire format's signer/writable
    /// categories (payer forced first), and resolves each instruction's
    /// accounts to indexes into that list.
    pub fn try_compile(
        payer: &Pubkey,
        instructions: &[Instruction],
        recent_blockhash: Hash,
    ) -> Result<Self, CompileError> {
        let compiled_keys = CompiledKeys::compile(instructions, Some(*payer));
        let (header, account_keys) = compiled_keys.try_into_message_components()?;
        let instructions = compile_instructions(instructions, |key| {
            resolve_key_index(key, &account_keys, &[], &[])
        })?;

        Ok(Self {
            header,
            account_keys,
            recent_blockhash,
            instructions,
        })
    }

    /// Builds a durable-nonce transaction: `advance_nonce_account` is
    /// prepended as instruction 0 (the placement the runtime requires — it
    /// consumes the nonce before anything else in the transaction can
    /// fail), and `recent_blockhash` is set to the nonce account's own
    /// stored blockhash-equivalent value rather than a freshly fetched one.
    /// This is the direct fix for the bounty's "trap #1": an
    /// approval-gated payment built with a normal blockhash goes stale the
    /// moment a human doesn't approve within ~60-90 seconds; one built
    /// against a durable nonce stays valid until it's actually advanced.
    ///
    /// `nonce_blockhash` should come from [`crate::nonce::NonceAccount::
    /// usable_blockhash`] on the nonce account's freshly fetched state —
    /// not from `getLatestBlockhash`.
    pub fn try_compile_with_durable_nonce(
        payer: &Pubkey,
        nonce_account: &Pubkey,
        nonce_authority: &Pubkey,
        nonce_blockhash: Hash,
        instructions: &[Instruction],
    ) -> Result<Self, CompileError> {
        let mut all = Vec::with_capacity(instructions.len() + 1);
        all.push(system::advance_nonce_account(
            nonce_account,
            nonce_authority,
        ));
        all.extend_from_slice(instructions);
        Self::try_compile(payer, &all, nonce_blockhash)
    }

    /// The wire-format bytes: header, then compact-u16-prefixed account
    /// keys, the raw 32-byte blockhash, and compact-u16-prefixed
    /// instructions. No version prefix — that's what distinguishes a legacy
    /// message from a [`super::MessageV0`] on the wire.
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = vec![
            self.header.num_required_signatures,
            self.header.num_readonly_signed_accounts,
            self.header.num_readonly_unsigned_accounts,
        ];

        push_short_vec_len(&mut buf, self.account_keys.len());
        for key in &self.account_keys {
            buf.extend_from_slice(key.as_bytes());
        }

        buf.extend_from_slice(self.recent_blockhash.as_bytes());

        push_short_vec_len(&mut buf, self.instructions.len());
        for ix in &self.instructions {
            ix.serialize_into(&mut buf);
        }

        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::instruction::{system, token};

    #[test]
    fn payer_is_index_zero_and_only_signer() {
        let payer = Pubkey::new_from_array([1; 32]);
        let to = Pubkey::new_from_array([2; 32]);
        let blockhash = Hash::new_from_array([9; 32]);

        let ix = system::transfer(&payer, &to, 1_000);
        let message = Message::try_compile(&payer, &[ix], blockhash).unwrap();

        assert_eq!(message.account_keys[0], payer);
        assert_eq!(message.header.num_required_signatures, 1);
        assert_eq!(message.header.num_readonly_signed_accounts, 0);
        // system program + `to` are both non-signer; `to` is writable, system
        // program is invoked-only (readonly, not written by System::transfer).
        assert_eq!(message.header.num_readonly_unsigned_accounts, 1);
    }

    #[test]
    fn instruction_accounts_resolve_to_correct_indexes() {
        let payer = Pubkey::new_from_array([1; 32]);
        let to = Pubkey::new_from_array([2; 32]);
        let blockhash = Hash::new_from_array([9; 32]);

        let ix = system::transfer(&payer, &to, 1_000);
        let message = Message::try_compile(&payer, &[ix], blockhash).unwrap();

        let compiled = &message.instructions[0];
        let program_index = compiled.program_id_index as usize;
        assert_eq!(message.account_keys[program_index], system::id());
        let account_pubkeys: Vec<Pubkey> = compiled
            .accounts
            .iter()
            .map(|&i| message.account_keys[i as usize])
            .collect();
        assert_eq!(account_pubkeys, vec![payer, to]);
    }

    #[test]
    fn unknown_account_key_is_rejected_rather_than_panicking() {
        // A hand-built instruction referencing a program that never went
        // through CompiledKeys::compile would be a bug in a caller — make
        // sure we surface it as an error, not a panic or silent bad index.
        let payer = Pubkey::new_from_array([1; 32]);
        let compiled_keys = CompiledKeys::compile(&[], Some(payer));
        let (_header, account_keys) = compiled_keys.try_into_message_components().unwrap();

        let stray = Pubkey::new_from_array([99; 32]);
        let result = compile_instructions(
            &[Instruction {
                program_id: stray,
                accounts: vec![],
                data: vec![],
            }],
            |key| resolve_key_index(key, &account_keys, &[], &[]),
        );
        assert_eq!(result, Err(CompileError::UnknownInstructionKey(stray)));
    }

    #[test]
    fn serialize_matches_hand_assembled_bytes_for_a_single_transfer() {
        let payer = Pubkey::new_from_array([1; 32]);
        let to = Pubkey::new_from_array([2; 32]);
        let blockhash = Hash::new_from_array([9; 32]);

        let ix = system::transfer(&payer, &to, 500);
        let message = Message::try_compile(&payer, &[ix], blockhash).unwrap();
        let bytes = message.serialize();

        let mut expected = vec![
            message.header.num_required_signatures,
            message.header.num_readonly_signed_accounts,
            message.header.num_readonly_unsigned_accounts,
        ];
        expected.push(message.account_keys.len() as u8); // fits in one shortvec byte
        for key in &message.account_keys {
            expected.extend_from_slice(key.as_bytes());
        }
        expected.extend_from_slice(blockhash.as_bytes());
        expected.push(message.instructions.len() as u8);
        for ix in &message.instructions {
            expected.push(ix.program_id_index);
            expected.push(ix.accounts.len() as u8);
            expected.extend_from_slice(&ix.accounts);
            expected.push(ix.data.len() as u8);
            expected.extend_from_slice(&ix.data);
        }

        assert_eq!(bytes, expected);
    }

    #[test]
    fn two_instructions_sharing_an_account_reuse_its_index() {
        let payer = Pubkey::new_from_array([1; 32]);
        let mint = Pubkey::new_from_array([2; 32]);
        let source = Pubkey::new_from_array([3; 32]);
        let dest = Pubkey::new_from_array([4; 32]);
        let blockhash = Hash::new_from_array([9; 32]);
        let token_program = token::token_program_id();

        let ix1 = token::transfer_checked(&source, &mint, &dest, &payer, 1, 0, &token_program);
        let ix2 = token::transfer_checked(&source, &mint, &dest, &payer, 2, 0, &token_program);
        let message = Message::try_compile(&payer, &[ix1, ix2], blockhash).unwrap();

        // `source`, `mint`, `dest`, `token_program` each appear once in
        // account_keys despite being referenced by both instructions.
        let unique_count = message.account_keys.len();
        assert_eq!(
            unique_count,
            message
                .account_keys
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len()
        );
        assert_eq!(
            message.instructions[0].accounts,
            message.instructions[1].accounts
        );
    }

    #[test]
    fn durable_nonce_message_places_advance_nonce_first_and_uses_nonce_blockhash() {
        let payer = Pubkey::new_from_array([1; 32]);
        let nonce_account = Pubkey::new_from_array([2; 32]);
        let to = Pubkey::new_from_array([3; 32]);
        let nonce_blockhash = Hash::new_from_array([9; 32]);

        let transfer_ix = system::transfer(&payer, &to, 1_000);
        let message = Message::try_compile_with_durable_nonce(
            &payer,
            &nonce_account,
            &payer, // payer is also the nonce authority in this scenario
            nonce_blockhash,
            &[transfer_ix],
        )
        .unwrap();

        // Instruction 0 must be AdvanceNonceAccount (discriminant [4,0,0,0]).
        assert_eq!(message.instructions[0].data, [4, 0, 0, 0]);
        assert_eq!(message.instructions.len(), 2);
        // The message's recent_blockhash must be the nonce's own value, not
        // a separately supplied one.
        assert_eq!(message.recent_blockhash, nonce_blockhash);
        // The nonce account itself must be present and writable.
        assert!(message.account_keys.contains(&nonce_account));
    }
}
