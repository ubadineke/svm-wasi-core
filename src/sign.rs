//! Ed25519 signing, feature-gated (`sign`) so T0/T1 plugins never pull this
//! in — only off-chain tooling (test harnesses, scripts signing on a
//! human's behalf) or a T2 plugin holding a scoped session key needs it.

use crate::pubkey::Pubkey;
use crate::signature::Signature;
use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};

pub const KEYPAIR_BYTES: usize = 64;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SignError {
    #[error("expected {KEYPAIR_BYTES} bytes, got {0}")]
    InvalidLength(usize),
    #[error("stored public key does not match the key derived from the secret seed")]
    PublicKeyMismatch,
}

/// A loaded signing key. Deliberately opaque — no `Debug`/`Clone` that
/// would make it easy to accidentally log or duplicate key material.
pub struct Keypair {
    signing_key: SigningKey,
    pubkey: Pubkey,
}

impl Keypair {
    /// Loads a keypair from the Solana CLI's on-disk format: 64 bytes,
    /// `seed(32) || public_key(32)`, as `solana-keygen` writes to `id.json`.
    /// Cross-checks the stored public key against the one derived from the
    /// seed — a corrupted/hand-edited file fails loudly instead of silently
    /// producing a keypair that can't sign for the address it claims.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SignError> {
        if bytes.len() != KEYPAIR_BYTES {
            return Err(SignError::InvalidLength(bytes.len()));
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes[0..32]);
        let signing_key = SigningKey::from_bytes(&seed);
        let derived: VerifyingKey = signing_key.verifying_key();
        if derived.to_bytes() != bytes[32..64] {
            return Err(SignError::PublicKeyMismatch);
        }
        Ok(Self {
            signing_key,
            pubkey: Pubkey::new_from_array(derived.to_bytes()),
        })
    }

    pub fn pubkey(&self) -> Pubkey {
        self.pubkey
    }

    pub fn sign_message(&self, message: &[u8]) -> Signature {
        Signature::from(self.signing_key.sign(message).to_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keypair_bytes(seed: [u8; 32], pubkey: [u8; 32]) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        bytes[0..32].copy_from_slice(&seed);
        bytes[32..64].copy_from_slice(&pubkey);
        bytes
    }

    /// RFC 8032 §7.1 test vector 1 (empty message) — independent of this
    /// crate's own implementation, since it's a published, widely-cited
    /// known-answer vector, not derived from our own code.
    #[test]
    fn signs_the_rfc8032_empty_message_test_vector() {
        let seed: [u8; 32] =
            hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap()
                .try_into()
                .unwrap();
        let pubkey: [u8; 32] =
            hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
                .unwrap()
                .try_into()
                .unwrap();
        let expected_sig: [u8; 64] = hex::decode(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        )
        .unwrap()
        .try_into()
        .unwrap();

        let keypair = Keypair::from_bytes(&keypair_bytes(seed, pubkey)).unwrap();
        assert_eq!(keypair.pubkey().to_bytes(), pubkey);

        let sig = keypair.sign_message(&[]);
        assert_eq!(<[u8; 64]>::from(sig), expected_sig);
    }

    #[test]
    fn rejects_wrong_length() {
        // `Keypair` deliberately has no `Debug`/`Clone` (avoid accidentally
        // logging or duplicating key material), so match the `Result`
        // directly rather than `.unwrap_err()` (which needs `T: Debug`).
        let result = Keypair::from_bytes(&[0u8; 63]);
        assert!(matches!(result, Err(SignError::InvalidLength(63))));
    }

    #[test]
    fn rejects_mismatched_public_key() {
        let seed = [7u8; 32];
        let wrong_pubkey = [9u8; 32]; // not actually derived from `seed`
        let result = Keypair::from_bytes(&keypair_bytes(seed, wrong_pubkey));
        assert!(matches!(result, Err(SignError::PublicKeyMismatch)));
    }
}
