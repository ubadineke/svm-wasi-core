//! Transaction message construction: legacy [`legacy::Message`] and
//! versioned [`v0::Message`] (with address lookup tables), both built on
//! [`crate::shortvec`] for the wire format and [`compiled_keys`] for account
//! ordering/deduplication.
//!
//! Account compilation (who signs, who's writable, in what order) is
//! verified against the real implementation's own source — not
//! reconstructed from the wire-format description in the docs — since it's
//! the single easiest place to get subtly wrong: `anza-xyz/solana-sdk`,
//! `message/src/{compiled_keys,legacy,versions/v0/mod}.rs`.

mod compiled_keys;
pub mod legacy;
pub mod v0;

use crate::instruction::Instruction;
use crate::pubkey::Pubkey;
use crate::shortvec;

pub use compiled_keys::CompileError;
pub use legacy::Message;
pub use v0::{AddressLookupTableAccount, Message as MessageV0, MessageAddressTableLookup};

/// Mirrors `solana_message::MessageHeader`: how many of `account_keys` (from
/// the front) must sign, and how many of the signer/non-signer partitions
/// are read-only. Three raw bytes on the wire, in this field order.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MessageHeader {
    pub num_required_signatures: u8,
    pub num_readonly_signed_accounts: u8,
    pub num_readonly_unsigned_accounts: u8,
}

/// One instruction with its accounts and program resolved to indexes into a
/// message's account-key list, rather than raw pubkeys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompiledInstruction {
    pub program_id_index: u8,
    pub accounts: Vec<u8>,
    pub data: Vec<u8>,
}

impl CompiledInstruction {
    fn serialize_into(&self, buf: &mut Vec<u8>) {
        buf.push(self.program_id_index);
        push_short_vec_len(buf, self.accounts.len());
        buf.extend_from_slice(&self.accounts);
        push_short_vec_len(buf, self.data.len());
        buf.extend_from_slice(&self.data);
    }
}

/// Appends a compact-u16 length prefix. `len` is always a message-internal
/// list length, structurally bounded by the ~1232-byte transaction wire
/// limit — far below `u16::MAX` — so the truncating cast is safe; the
/// assert exists so a future violation fails loudly instead of silently
/// corrupting the wire format.
pub(crate) fn push_short_vec_len(buf: &mut Vec<u8>, len: usize) {
    debug_assert!(
        len <= u16::MAX as usize,
        "message list length exceeds u16::MAX"
    );
    shortvec::encode_len_into(buf, len as u16);
}

/// Resolves `target` to its index in the concatenation of `static_keys`,
/// `dynamic_writable`, and `dynamic_readonly` — the exact key-segment order
/// versioned-message account indexes are defined against. For a legacy
/// message (no dynamic keys), pass empty slices for the latter two.
fn resolve_key_index(
    target: &Pubkey,
    static_keys: &[Pubkey],
    dynamic_writable: &[Pubkey],
    dynamic_readonly: &[Pubkey],
) -> Option<u8> {
    if let Some(i) = static_keys.iter().position(|k| k == target) {
        return u8::try_from(i).ok();
    }
    let offset = static_keys.len();
    if let Some(i) = dynamic_writable.iter().position(|k| k == target) {
        return u8::try_from(offset + i).ok();
    }
    let offset = offset + dynamic_writable.len();
    if let Some(i) = dynamic_readonly.iter().position(|k| k == target) {
        return u8::try_from(offset + i).ok();
    }
    None
}

fn compile_instructions(
    instructions: &[Instruction],
    key_index: impl Fn(&Pubkey) -> Option<u8>,
) -> Result<Vec<CompiledInstruction>, CompileError> {
    instructions
        .iter()
        .map(|ix| {
            let program_id_index = key_index(&ix.program_id)
                .ok_or(CompileError::UnknownInstructionKey(ix.program_id))?;
            let accounts = ix
                .accounts
                .iter()
                .map(|meta| {
                    key_index(&meta.pubkey).ok_or(CompileError::UnknownInstructionKey(meta.pubkey))
                })
                .collect::<Result<Vec<u8>, CompileError>>()?;
            Ok(CompiledInstruction {
                program_id_index,
                accounts,
                data: ix.data.clone(),
            })
        })
        .collect()
}
