//! Memo program: attach a UTF-8 note to a transaction. Instruction data is
//! the raw memo bytes with no discriminant/tag at all — the program's own
//! job is just to validate UTF-8 and log any signer accounts passed to it.
//!
//! Program id verified against `solana-program/memo`,
//! `interface/src/lib.rs` (the widely-deployed id used across the
//! ecosystem's tooling and explorers).

use super::{known_id, AccountMeta, Instruction};
use crate::pubkey::Pubkey;

pub fn id() -> Pubkey {
    known_id("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr")
}

/// Builds a memo instruction. `signers` is typically empty for a simple
/// "attach this note" use — pass accounts only when the memo should also
/// assert (and have the runtime log) that they signed this transaction.
pub fn build_memo(memo: &str, signers: &[Pubkey]) -> Instruction {
    Instruction {
        program_id: id(),
        accounts: signers
            .iter()
            .map(|s| AccountMeta::new_readonly(*s, true))
            .collect(),
        data: memo.as_bytes().to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn data_is_raw_utf8_with_no_discriminant() {
        let ix = build_memo("order #4471", &[]);
        assert_eq!(ix.data, b"order #4471");
        assert!(ix.accounts.is_empty());
    }

    #[test]
    fn signers_become_readonly_signer_metas() {
        let signer = Pubkey::from_str("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").unwrap();
        let ix = build_memo("hi", &[signer]);
        assert_eq!(ix.accounts, vec![AccountMeta::new_readonly(signer, true)]);
    }
}
