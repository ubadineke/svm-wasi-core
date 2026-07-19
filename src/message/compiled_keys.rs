//! Account collection, deduplication, and ordering shared by legacy and v0
//! message compilation. Ported field-for-field from `CompiledKeys` in
//! `anza-xyz/solana-sdk`'s `message` crate (`src/compiled_keys.rs`) — this
//! is the part of the wire format most likely to silently diverge from the
//! real runtime if reimplemented from a description rather than the source.

use super::v0::{AddressLookupTableAccount, LoadedAddresses, MessageAddressTableLookup};
use super::MessageHeader;
use crate::instruction::{system, Instruction};
use crate::pubkey::Pubkey;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CompileError {
    #[error("account index overflowed 256 accounts during message compilation")]
    AccountIndexOverflow,
    #[error("address lookup table has more than 256 addresses")]
    AddressTableLookupIndexOverflow,
    #[error("instruction references an account key not present in this message: {0}")]
    UnknownInstructionKey(Pubkey),
}

#[derive(Default, Debug, Clone, PartialEq, Eq)]
struct KeyMeta {
    is_signer: bool,
    is_writable: bool,
    is_invoked: bool,
    is_nonce: bool,
}

/// Every account an instruction set touches, keyed by pubkey so duplicates
/// across instructions collapse into one entry whose signer/writable flags
/// are the union of every place that account appeared. `BTreeMap` isn't an
/// implementation detail here — the runtime orders same-category accounts
/// by pubkey byte value, not by first-appearance order, and a message built
/// with a different tie-break would still be *valid* but would not match
/// what a real client/validator produces for the same inputs.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub(super) struct CompiledKeys {
    payer: Option<Pubkey>,
    key_meta_map: BTreeMap<Pubkey, KeyMeta>,
}

impl CompiledKeys {
    pub(super) fn compile(instructions: &[Instruction], payer: Option<Pubkey>) -> Self {
        let mut key_meta_map = BTreeMap::<Pubkey, KeyMeta>::new();
        for ix in instructions {
            key_meta_map.entry(ix.program_id).or_default().is_invoked = true;
            for account_meta in &ix.accounts {
                let meta = key_meta_map.entry(account_meta.pubkey).or_default();
                meta.is_signer |= account_meta.is_signer;
                meta.is_writable |= account_meta.is_writable;
            }
        }
        if let Some(nonce_pubkey) = get_nonce_pubkey(instructions) {
            key_meta_map.entry(nonce_pubkey).or_default().is_nonce = true;
        }
        if let Some(payer) = payer {
            let meta = key_meta_map.entry(payer).or_default();
            meta.is_signer = true;
            meta.is_writable = true;
        }
        Self {
            payer,
            key_meta_map,
        }
    }

    /// Partitions the compiled keys into the four wire-format categories —
    /// writable signers (payer first), readonly signers, writable
    /// non-signers, readonly non-signers — and derives the message header
    /// from their sizes.
    pub(super) fn try_into_message_components(
        self,
    ) -> Result<(MessageHeader, Vec<Pubkey>), CompileError> {
        let try_into_u8 =
            |n: usize| u8::try_from(n).map_err(|_| CompileError::AccountIndexOverflow);

        let Self {
            payer,
            mut key_meta_map,
        } = self;
        if let Some(payer) = &payer {
            key_meta_map.remove(payer);
        }

        let writable_signer_keys: Vec<Pubkey> = payer
            .into_iter()
            .chain(
                key_meta_map
                    .iter()
                    .filter_map(|(k, m)| (m.is_signer && m.is_writable).then_some(*k)),
            )
            .collect();
        let readonly_signer_keys: Vec<Pubkey> = key_meta_map
            .iter()
            .filter_map(|(k, m)| (m.is_signer && !m.is_writable).then_some(*k))
            .collect();
        let writable_non_signer_keys: Vec<Pubkey> = key_meta_map
            .iter()
            .filter_map(|(k, m)| (!m.is_signer && m.is_writable).then_some(*k))
            .collect();
        let readonly_non_signer_keys: Vec<Pubkey> = key_meta_map
            .iter()
            .filter_map(|(k, m)| (!m.is_signer && !m.is_writable).then_some(*k))
            .collect();

        let signers_len = writable_signer_keys.len() + readonly_signer_keys.len();
        let header = MessageHeader {
            num_required_signatures: try_into_u8(signers_len)?,
            num_readonly_signed_accounts: try_into_u8(readonly_signer_keys.len())?,
            num_readonly_unsigned_accounts: try_into_u8(readonly_non_signer_keys.len())?,
        };

        let static_account_keys = writable_signer_keys
            .into_iter()
            .chain(readonly_signer_keys)
            .chain(writable_non_signer_keys)
            .chain(readonly_non_signer_keys)
            .collect();

        Ok((header, static_account_keys))
    }

    /// Moves every remaining eligible key (not a signer, not an invoked
    /// program, not the nonce account) that appears in `lookup_table_account`
    /// out of the pending static-key set and into an address-table-lookup
    /// entry instead. Returns `None` if nothing in this table matched.
    pub(super) fn try_extract_table_lookup(
        &mut self,
        lookup_table_account: &AddressLookupTableAccount,
    ) -> Result<Option<(MessageAddressTableLookup, LoadedAddresses)>, CompileError> {
        let (writable_indexes, drained_writable_keys) = self
            .try_drain_keys_found_in_lookup_table(&lookup_table_account.addresses, |m| {
                !m.is_signer && !m.is_invoked && !m.is_nonce && m.is_writable
            })?;
        let (readonly_indexes, drained_readonly_keys) = self
            .try_drain_keys_found_in_lookup_table(&lookup_table_account.addresses, |m| {
                !m.is_signer && !m.is_invoked && !m.is_nonce && !m.is_writable
            })?;

        if writable_indexes.is_empty() && readonly_indexes.is_empty() {
            return Ok(None);
        }

        Ok(Some((
            MessageAddressTableLookup {
                account_key: lookup_table_account.key,
                writable_indexes,
                readonly_indexes,
            },
            LoadedAddresses {
                writable: drained_writable_keys,
                readonly: drained_readonly_keys,
            },
        )))
    }

    fn try_drain_keys_found_in_lookup_table(
        &mut self,
        lookup_table_addresses: &[Pubkey],
        key_meta_filter: impl Fn(&KeyMeta) -> bool,
    ) -> Result<(Vec<u8>, Vec<Pubkey>), CompileError> {
        let mut lookup_table_indexes = Vec::new();
        let mut drained_keys = Vec::new();

        // Search first (borrowing key_meta_map immutably); only once the
        // search is complete can we remove the matches (mutably) — mirrors
        // the two-phase structure of the upstream implementation, which
        // exists for exactly this borrow-checker reason.
        for search_key in key_meta_map_matches(&self.key_meta_map, &key_meta_filter) {
            for (key_index, key) in lookup_table_addresses.iter().enumerate() {
                if *key == search_key {
                    let lookup_table_index = u8::try_from(key_index)
                        .map_err(|_| CompileError::AddressTableLookupIndexOverflow)?;
                    lookup_table_indexes.push(lookup_table_index);
                    drained_keys.push(search_key);
                    break;
                }
            }
        }

        for key in &drained_keys {
            self.key_meta_map.remove(key);
        }

        Ok((lookup_table_indexes, drained_keys))
    }
}

fn key_meta_map_matches(
    map: &BTreeMap<Pubkey, KeyMeta>,
    filter: impl Fn(&KeyMeta) -> bool,
) -> Vec<Pubkey> {
    map.iter()
        .filter_map(|(k, m)| filter(m).then_some(*k))
        .collect()
}

/// `SystemInstruction::AdvanceNonceAccount`'s packed discriminant — inlined
/// rather than imported to avoid a dependency cycle with
/// [`crate::instruction::system`] beyond the program id itself.
const ADVANCE_NONCE_ACCOUNT_DATA: [u8; 4] = [4, 0, 0, 0];

/// A durable-nonce transaction places `AdvanceNonceAccount` first so the
/// runtime consumes the nonce before anything else can fail; detecting that
/// shape here means the nonce account is never accidentally offered up for
/// address-table-lookup extraction (an ALT-loaded account can't be the
/// nonce account the runtime checks before any lookups are resolved).
fn get_nonce_pubkey(instructions: &[Instruction]) -> Option<Pubkey> {
    let ix = instructions.first()?;
    if ix.program_id != system::id() {
        return None;
    }
    if ix.data.get(0..4) != Some(&ADVANCE_NONCE_ACCOUNT_DATA[..]) {
        return None;
    }
    ix.accounts.first().map(|meta| meta.pubkey)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::instruction::{system, AccountMeta};

    fn pk(byte: u8) -> Pubkey {
        Pubkey::new_from_array([byte; 32])
    }

    #[test]
    fn compile_dedupes_and_unions_flags_across_instructions() {
        let program = pk(1);
        let acc = pk(2);
        let instructions = vec![
            Instruction {
                program_id: program,
                accounts: vec![AccountMeta::new_readonly(acc, false)],
                data: vec![],
            },
            Instruction {
                program_id: program,
                accounts: vec![AccountMeta::new(acc, true)],
                data: vec![],
            },
        ];

        let compiled = CompiledKeys::compile(&instructions, None);
        assert_eq!(
            compiled.key_meta_map[&acc],
            KeyMeta {
                is_signer: true,
                is_writable: true,
                ..Default::default()
            }
        );
        assert_eq!(
            compiled.key_meta_map[&program],
            KeyMeta {
                is_invoked: true,
                ..Default::default()
            }
        );
    }

    #[test]
    fn payer_is_always_writable_signer_and_first() {
        let program = pk(1);
        let other_signer = pk(2);
        let payer = pk(3);
        let instructions = vec![Instruction {
            program_id: program,
            accounts: vec![AccountMeta::new_readonly(other_signer, true)],
            data: vec![],
        }];

        let compiled = CompiledKeys::compile(&instructions, Some(payer));
        let (header, keys) = compiled.try_into_message_components().unwrap();

        assert_eq!(keys[0], payer);
        assert_eq!(header.num_required_signatures, 2); // payer + other_signer
        assert_eq!(header.num_readonly_signed_accounts, 1); // other_signer
    }

    #[test]
    fn same_category_keys_are_ordered_by_pubkey_not_first_appearance() {
        let program = pk(1);
        // Intentionally instruction-ordered high-byte-first, low-byte-second.
        let high = pk(200);
        let low = pk(10);
        let instructions = vec![Instruction {
            program_id: program,
            accounts: vec![AccountMeta::new(high, false), AccountMeta::new(low, false)],
            data: vec![],
        }];

        let compiled = CompiledKeys::compile(&instructions, None);
        let (_header, keys) = compiled.try_into_message_components().unwrap();

        // Both are writable non-signers; BTreeMap ordering means `low` (pk(10))
        // must sort before `high` (pk(200)) regardless of instruction order.
        let low_pos = keys.iter().position(|k| *k == low).unwrap();
        let high_pos = keys.iter().position(|k| *k == high).unwrap();
        assert!(low_pos < high_pos);
    }

    #[test]
    fn nonce_instruction_marks_first_account_as_nonce() {
        let nonce_account = pk(5);
        let authority = pk(6);
        let advance_nonce = system::advance_nonce_account(&nonce_account, &authority);

        let compiled = CompiledKeys::compile(&[advance_nonce], Some(authority));
        assert!(compiled.key_meta_map[&nonce_account].is_nonce);
    }

    #[test]
    fn nonce_account_is_excluded_from_lookup_table_extraction() {
        let nonce_account = pk(5);
        let authority = pk(6);
        let advance_nonce = system::advance_nonce_account(&nonce_account, &authority);

        let mut compiled = CompiledKeys::compile(&[advance_nonce], Some(authority));
        let lookup_table = AddressLookupTableAccount {
            key: pk(9),
            addresses: vec![nonce_account],
        };

        // Even though the nonce account is writable and non-signer (the shape
        // try_extract_table_lookup normally targets), is_nonce must suppress it.
        let extracted = compiled.try_extract_table_lookup(&lookup_table).unwrap();
        assert_eq!(extracted, None);
    }

    #[test]
    fn table_lookup_extracts_writable_and_readonly_and_picks_lowest_index() {
        let program = pk(1);
        let writable_key = pk(2);
        let readonly_key = pk(3);
        let instructions = vec![Instruction {
            program_id: program,
            accounts: vec![
                AccountMeta::new(writable_key, false),
                AccountMeta::new_readonly(readonly_key, false),
            ],
            data: vec![],
        }];
        let mut compiled = CompiledKeys::compile(&instructions, None);

        // Duplicate entries in the table; lowest index must win.
        let lookup_table = AddressLookupTableAccount {
            key: pk(9),
            addresses: vec![writable_key, readonly_key, writable_key],
        };

        let (lookup, loaded) = compiled
            .try_extract_table_lookup(&lookup_table)
            .unwrap()
            .unwrap();
        assert_eq!(lookup.writable_indexes, vec![0]);
        assert_eq!(lookup.readonly_indexes, vec![1]);
        assert_eq!(loaded.writable, vec![writable_key]);
        assert_eq!(loaded.readonly, vec![readonly_key]);

        // Extracted keys must be gone from the pending static-key set.
        let (_header, static_keys) = compiled.try_into_message_components().unwrap();
        assert!(!static_keys.contains(&writable_key));
        assert!(!static_keys.contains(&readonly_key));
    }

    #[test]
    fn invoked_program_is_never_extracted_into_a_lookup_table() {
        let program = pk(1);
        let instructions = vec![Instruction {
            program_id: program,
            accounts: vec![],
            data: vec![],
        }];
        let mut compiled = CompiledKeys::compile(&instructions, None);

        let lookup_table = AddressLookupTableAccount {
            key: pk(9),
            addresses: vec![program],
        };
        let extracted = compiled.try_extract_table_lookup(&lookup_table).unwrap();
        assert_eq!(extracted, None);
    }

    #[test]
    fn too_many_signer_accounts_overflows_u8_header_field() {
        let payer = pk(0);
        let mut accounts = Vec::new();
        for i in 1..=255u8 {
            accounts.push(AccountMeta::new_readonly(
                Pubkey::new_from_array([i; 32]),
                true,
            ));
        }
        let instructions = vec![Instruction {
            program_id: pk(254),
            accounts,
            data: vec![],
        }];

        let compiled = CompiledKeys::compile(&instructions, Some(payer));
        let err = compiled.try_into_message_components().unwrap_err();
        assert_eq!(err, CompileError::AccountIndexOverflow);
    }
}
