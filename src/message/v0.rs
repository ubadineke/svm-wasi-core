//! The versioned (v0) message format: adds on-chain address lookup tables
//! so a transaction can reference far more accounts than fit as raw 32-byte
//! keys within the ~1232-byte transaction size limit.

use super::compiled_keys::{CompileError, CompiledKeys};
use super::{
    compile_instructions, push_short_vec_len, resolve_key_index, CompiledInstruction, MessageHeader,
};
use crate::hash::Hash;
use crate::instruction::{system, Instruction};
use crate::pubkey::Pubkey;

/// The version-prefix bit: set on a versioned message's first byte, with
/// the low 7 bits carrying the version number (`0` for this module). A
/// legacy message's first byte is `header.num_required_signatures`, which
/// in practice is always far below 128, so the two formats never collide.
pub const MESSAGE_VERSION_PREFIX: u8 = 0x80;

/// An on-chain address lookup table, as a plugin would obtain it: fetch the
/// account via RPC, decode its stored address list. Decoding that account's
/// own on-chain data format is out of scope for this module — this struct
/// is the input `try_compile` needs, not a promise this crate parses ALT
/// account state (see the `rpc`/shaping layer for that, once implemented).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddressLookupTableAccount {
    pub key: Pubkey,
    pub addresses: Vec<Pubkey>,
}

/// One entry in a compiled message's `address_table_lookups`: which ALT to
/// read, and which of its stored addresses (by index) this transaction
/// loads as writable vs. readonly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageAddressTableLookup {
    pub account_key: Pubkey,
    pub writable_indexes: Vec<u8>,
    pub readonly_indexes: Vec<u8>,
}

/// Addresses resolved out of address lookup tables during compilation,
/// split by writable/readonly — the two segments that, appended after the
/// static account keys in that order, form the full account-index space
/// instruction account indexes are resolved against.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct LoadedAddresses {
    pub writable: Vec<Pubkey>,
    pub readonly: Vec<Pubkey>,
}

/// A v0 (versioned) Solana transaction message.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Message {
    pub header: MessageHeader,
    /// Static account keys only — accounts loaded via `address_table_lookups`
    /// are *not* included here, per the wire format.
    pub account_keys: Vec<Pubkey>,
    pub recent_blockhash: Hash,
    /// Account indexes reference the concatenation of `account_keys`, then
    /// every table's `writable_indexes`-resolved keys (in
    /// `address_table_lookups` order), then every table's
    /// `readonly_indexes`-resolved keys — not `account_keys` alone.
    pub instructions: Vec<CompiledInstruction>,
    pub address_table_lookups: Vec<MessageAddressTableLookup>,
}

impl Message {
    /// Compiles `instructions` into a v0 message. Any eligible account (not
    /// a signer, invoked program, or the nonce account) present in
    /// `address_lookup_table_accounts` moves from the static key list into
    /// that table's lookup entry, in table order.
    pub fn try_compile(
        payer: &Pubkey,
        instructions: &[Instruction],
        address_lookup_table_accounts: &[AddressLookupTableAccount],
        recent_blockhash: Hash,
    ) -> Result<Self, CompileError> {
        let mut compiled_keys = CompiledKeys::compile(instructions, Some(*payer));

        let mut address_table_lookups = Vec::with_capacity(address_lookup_table_accounts.len());
        let mut dynamic_writable = Vec::new();
        let mut dynamic_readonly = Vec::new();
        for lookup_table_account in address_lookup_table_accounts {
            if let Some((lookup, loaded)) =
                compiled_keys.try_extract_table_lookup(lookup_table_account)?
            {
                address_table_lookups.push(lookup);
                dynamic_writable.extend(loaded.writable);
                dynamic_readonly.extend(loaded.readonly);
            }
        }

        let (header, account_keys) = compiled_keys.try_into_message_components()?;
        let instructions = compile_instructions(instructions, |key| {
            resolve_key_index(key, &account_keys, &dynamic_writable, &dynamic_readonly)
        })?;

        Ok(Self {
            header,
            account_keys,
            recent_blockhash,
            instructions,
            address_table_lookups,
        })
    }

    /// Builds a durable-nonce v0 message: `advance_nonce_account` is
    /// prepended as instruction 0, and `recent_blockhash` is set to the
    /// nonce account's own stored value. See [`super::legacy::Message::
    /// try_compile_with_durable_nonce`] for the full rationale (the
    /// bounty's "trap #1") — this is the same fix for the versioned format.
    ///
    /// `nonce_blockhash` should come from [`crate::nonce::NonceAccount::
    /// usable_blockhash`], not from `getLatestBlockhash`.
    pub fn try_compile_with_durable_nonce(
        payer: &Pubkey,
        nonce_account: &Pubkey,
        nonce_authority: &Pubkey,
        nonce_blockhash: Hash,
        instructions: &[Instruction],
        address_lookup_table_accounts: &[AddressLookupTableAccount],
    ) -> Result<Self, CompileError> {
        let mut all = Vec::with_capacity(instructions.len() + 1);
        all.push(system::advance_nonce_account(
            nonce_account,
            nonce_authority,
        ));
        all.extend_from_slice(instructions);
        Self::try_compile(payer, &all, address_lookup_table_accounts, nonce_blockhash)
    }

    /// The wire-format bytes: `0x80` version-prefix byte, header, then the
    /// same account-keys/blockhash/instructions shape as a legacy message
    /// (static keys only), followed by compact-u16-prefixed address table
    /// lookups.
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = vec![
            MESSAGE_VERSION_PREFIX, // version 0
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

        push_short_vec_len(&mut buf, self.address_table_lookups.len());
        for lookup in &self.address_table_lookups {
            buf.extend_from_slice(lookup.account_key.as_bytes());
            push_short_vec_len(&mut buf, lookup.writable_indexes.len());
            buf.extend_from_slice(&lookup.writable_indexes);
            push_short_vec_len(&mut buf, lookup.readonly_indexes.len());
            buf.extend_from_slice(&lookup.readonly_indexes);
        }

        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::instruction::{system, token, AccountMeta};

    fn pk(byte: u8) -> Pubkey {
        Pubkey::new_from_array([byte; 32])
    }

    #[test]
    fn version_prefix_byte_is_set() {
        let payer = pk(1);
        let message = Message::try_compile(&payer, &[], &[], Hash::default()).unwrap();
        assert_eq!(message.serialize()[0], MESSAGE_VERSION_PREFIX);
    }

    #[test]
    fn with_no_lookup_tables_behaves_like_a_static_only_message() {
        let payer = pk(1);
        let to = pk(2);
        let ix = system::transfer(&payer, &to, 1_000);

        let message = Message::try_compile(&payer, &[ix], &[], Hash::default()).unwrap();

        assert!(message.address_table_lookups.is_empty());
        assert_eq!(message.account_keys[0], payer);
        assert!(message.account_keys.contains(&to));
        assert!(message.account_keys.contains(&system::id()));
    }

    #[test]
    fn eligible_account_moves_into_lookup_table_and_out_of_static_keys() {
        let payer = pk(1);
        let source = pk(2);
        let mint = pk(3);
        let dest = pk(4); // writable, non-signer, non-invoked: ALT-eligible
        let token_program = token::token_program_id();

        let ix = token::transfer_checked(&source, &mint, &dest, &payer, 10, 0, &token_program);
        let alt = AddressLookupTableAccount {
            key: pk(200),
            addresses: vec![dest],
        };

        let message =
            Message::try_compile(&payer, &[ix], std::slice::from_ref(&alt), Hash::default())
                .unwrap();

        assert!(!message.account_keys.contains(&dest));
        assert_eq!(message.address_table_lookups.len(), 1);
        assert_eq!(message.address_table_lookups[0].account_key, alt.key);
        assert_eq!(message.address_table_lookups[0].writable_indexes, vec![0]);
        assert!(message.address_table_lookups[0].readonly_indexes.is_empty());
    }

    #[test]
    fn instruction_account_index_resolves_into_dynamic_writable_segment() {
        let payer = pk(1);
        let source = pk(2);
        let mint = pk(3);
        let dest = pk(4);
        let token_program = token::token_program_id();

        let ix = token::transfer_checked(&source, &mint, &dest, &payer, 10, 0, &token_program);
        let alt = AddressLookupTableAccount {
            key: pk(200),
            addresses: vec![dest],
        };

        let message =
            Message::try_compile(&payer, &[ix], std::slice::from_ref(&alt), Hash::default())
                .unwrap();

        // `dest`'s index must be >= account_keys.len() (it's in the dynamic
        // writable segment, not the static one).
        let compiled = &message.instructions[0];
        let dest_index = compiled.accounts[2] as usize; // [source, mint, dest, owner]
        assert!(dest_index >= message.account_keys.len());
        assert_eq!(dest_index, message.account_keys.len()); // first (only) dynamic-writable key
    }

    #[test]
    fn signer_account_is_never_extracted_even_if_present_in_a_lookup_table() {
        let payer = pk(1);
        let to = pk(2);
        let ix = system::transfer(&payer, &to, 1_000);
        // `payer` is a signer; it must never be pulled out into a lookup
        // table even though it's present in this table's address list.
        let alt = AddressLookupTableAccount {
            key: pk(200),
            addresses: vec![payer],
        };

        let message =
            Message::try_compile(&payer, &[ix], std::slice::from_ref(&alt), Hash::default())
                .unwrap();

        assert!(message.account_keys.contains(&payer));
        assert!(message.address_table_lookups.is_empty());
    }

    #[test]
    fn multiple_lookup_tables_concatenate_writable_then_readonly_across_tables() {
        let payer = pk(1);
        let program = pk(2);
        let w0 = pk(10);
        let w1 = pk(11);
        let r0 = pk(20);
        let r1 = pk(21);

        let ix = Instruction {
            program_id: program,
            accounts: vec![
                AccountMeta::new(w0, false),
                AccountMeta::new(w1, false),
                AccountMeta::new_readonly(r0, false),
                AccountMeta::new_readonly(r1, false),
            ],
            data: vec![],
        };
        let table0 = AddressLookupTableAccount {
            key: pk(100),
            addresses: vec![w0, r0],
        };
        let table1 = AddressLookupTableAccount {
            key: pk(101),
            addresses: vec![w1, r1],
        };

        let message =
            Message::try_compile(&payer, &[ix], &[table0, table1], Hash::default()).unwrap();

        // Resolved order: static keys, then [w0, w1] (writable across both
        // tables in table order), then [r0, r1] (readonly across both
        // tables in table order) — per the doc comment on `instructions`.
        let base = message.account_keys.len();
        let compiled = &message.instructions[0];
        assert_eq!(compiled.accounts[0] as usize, base); // w0
        assert_eq!(compiled.accounts[1] as usize, base + 1); // w1
        assert_eq!(compiled.accounts[2] as usize, base + 2); // r0
        assert_eq!(compiled.accounts[3] as usize, base + 3); // r1
    }

    #[test]
    fn durable_nonce_v0_message_places_advance_nonce_first_and_uses_nonce_blockhash() {
        let payer = pk(1);
        let nonce_account = pk(2);
        let to = pk(3);
        let nonce_blockhash = Hash::new_from_array([9; 32]);

        let transfer_ix = system::transfer(&payer, &to, 1_000);
        let message = Message::try_compile_with_durable_nonce(
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
