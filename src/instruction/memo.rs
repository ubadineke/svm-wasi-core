//! Thin wrapper over `spl-memo-interface`'s `build_memo` (plain `spl-memo`'s
//! own `build_memo` is deprecated in favor of it). Targets the v3 program
//! id (`MemoSq4g...`).

use super::Instruction;
use crate::pubkey::Pubkey;

pub fn id() -> Pubkey {
    spl_memo_interface::v3::id()
}

/// Builds a memo instruction. `signers` is typically empty; pass accounts
/// only when the memo should also assert that they signed this transaction.
pub fn build_memo(memo: &str, signers: &[Pubkey]) -> Instruction {
    let signer_refs: Vec<&Pubkey> = signers.iter().collect();
    spl_memo_interface::instruction::build_memo(&id(), memo.as_bytes(), &signer_refs)
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
        assert_eq!(ix.accounts.len(), 1);
        assert_eq!(ix.accounts[0].pubkey, signer);
        assert!(ix.accounts[0].is_signer);
        assert!(!ix.accounts[0].is_writable);
    }

    #[test]
    fn program_id_matches_current_memo_program() {
        assert_eq!(
            id().to_string(),
            "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"
        );
    }
}
