//! The outer transaction envelope: a signature array plus a message. This is
//! what actually gets base64-encoded and returned to a human/host/multisig
//! for signing — a T1 "unsigned transaction" is not a bare [`Message`], it's
//! this: a compact-u16-prefixed array of (initially all-zero) signature
//! slots followed by the message bytes, exactly as the wire format defines.
//!
//! Mirrors `solana_sdk`'s own split between `Transaction` (legacy message)
//! and `VersionedTransaction` (any versioned message) rather than one
//! generic type, since the two message formats already don't share a common
//! base in this crate either.

use crate::hash::Hash;
use crate::message::{push_short_vec_len, Message, MessageV0};
#[cfg(feature = "sign")]
use crate::sign::Keypair;
use crate::signature::Signature;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;

#[cfg(feature = "sign")]
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SignTransactionError {
    #[error("pubkey is not one of this transaction's required signers")]
    NotARequiredSigner,
}

/// Finds `pubkey`'s index among the first `num_required_signatures` account
/// keys (the only ones eligible to sign), and fills that signature slot —
/// shared by both [`Transaction::try_sign`] and
/// [`VersionedTransaction::try_sign`].
#[cfg(feature = "sign")]
fn sign_into(
    signatures: &mut [Signature],
    account_keys: &[crate::pubkey::Pubkey],
    num_required_signatures: u8,
    message_bytes: &[u8],
    keypair: &Keypair,
) -> Result<(), SignTransactionError> {
    let index = account_keys[..num_required_signatures as usize]
        .iter()
        .position(|k| *k == keypair.pubkey())
        .ok_or(SignTransactionError::NotARequiredSigner)?;
    signatures[index] = keypair.sign_message(message_bytes);
    Ok(())
}

/// A legacy-message transaction with unsigned (all-zero) signature slots.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transaction {
    pub signatures: Vec<Signature>,
    pub message: Message,
}

impl Transaction {
    /// Wraps `message` with `header.num_required_signatures` all-zero
    /// signature placeholders — exactly the shape a human, host, or
    /// multisig expects to receive for approval; nothing here requires a
    /// key.
    pub fn new_unsigned(message: Message) -> Self {
        let signatures = vec![Signature::ZERO; message.header.num_required_signatures as usize];
        Self {
            signatures,
            message,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        push_short_vec_len(&mut buf, self.signatures.len());
        for sig in &self.signatures {
            buf.extend_from_slice(sig.as_bytes());
        }
        buf.extend_from_slice(&self.message.serialize());
        buf
    }

    pub fn to_base64(&self) -> String {
        BASE64.encode(self.serialize())
    }

    /// Signs the message bytes with `keypair` and fills in that signer's
    /// slot. Errors rather than panicking if `keypair`'s pubkey isn't one
    /// of this message's required signers.
    #[cfg(feature = "sign")]
    pub fn try_sign(&mut self, keypair: &Keypair) -> Result<(), SignTransactionError> {
        let message_bytes = self.message.serialize();
        sign_into(
            &mut self.signatures,
            &self.message.account_keys,
            self.message.header.num_required_signatures,
            &message_bytes,
            keypair,
        )
    }
}

/// A versioned (v0) transaction with unsigned (all-zero) signature slots.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VersionedTransaction {
    pub signatures: Vec<Signature>,
    pub message: MessageV0,
}

impl VersionedTransaction {
    pub fn new_unsigned(message: MessageV0) -> Self {
        let signatures = vec![Signature::ZERO; message.header.num_required_signatures as usize];
        Self {
            signatures,
            message,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        push_short_vec_len(&mut buf, self.signatures.len());
        for sig in &self.signatures {
            buf.extend_from_slice(sig.as_bytes());
        }
        buf.extend_from_slice(&self.message.serialize());
        buf
    }

    pub fn to_base64(&self) -> String {
        BASE64.encode(self.serialize())
    }

    /// The blockhash (or durable-nonce value) this transaction was built
    /// against — convenience accessor, since a caller checking tx freshness
    /// shouldn't need to know the message's internal field layout.
    pub fn recent_blockhash(&self) -> Hash {
        self.message.recent_blockhash
    }

    /// Signs the message bytes with `keypair` and fills in that signer's
    /// slot. Errors rather than panicking if `keypair`'s pubkey isn't one
    /// of this message's required signers.
    #[cfg(feature = "sign")]
    pub fn try_sign(&mut self, keypair: &Keypair) -> Result<(), SignTransactionError> {
        let message_bytes = self.message.serialize();
        sign_into(
            &mut self.signatures,
            &self.message.account_keys,
            self.message.header.num_required_signatures,
            &message_bytes,
            keypair,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::instruction::system;
    use crate::pubkey::Pubkey;

    #[test]
    fn unsigned_transaction_has_one_placeholder_per_required_signature() {
        let payer = Pubkey::new_from_array([1; 32]);
        let to = Pubkey::new_from_array([2; 32]);
        let ix = system::transfer(&payer, &to, 1_000);
        let message = Message::try_compile(&payer, &[ix], Hash::default()).unwrap();

        let tx = Transaction::new_unsigned(message.clone());

        assert_eq!(
            tx.signatures.len(),
            message.header.num_required_signatures as usize
        );
        assert!(tx.signatures.iter().all(|s| *s == Signature::ZERO));
    }

    #[test]
    fn serialize_prefixes_signatures_then_message_bytes() {
        let payer = Pubkey::new_from_array([1; 32]);
        let to = Pubkey::new_from_array([2; 32]);
        let ix = system::transfer(&payer, &to, 1_000);
        let message = Message::try_compile(&payer, &[ix], Hash::default()).unwrap();
        let tx = Transaction::new_unsigned(message.clone());

        let bytes = tx.serialize();
        let mut expected = vec![tx.signatures.len() as u8]; // fits in one shortvec byte
        for sig in &tx.signatures {
            expected.extend_from_slice(sig.as_bytes());
        }
        expected.extend_from_slice(&message.serialize());
        assert_eq!(bytes, expected);
    }

    #[test]
    fn to_base64_round_trips_through_standard_base64() {
        let payer = Pubkey::new_from_array([1; 32]);
        let to = Pubkey::new_from_array([2; 32]);
        let ix = system::transfer(&payer, &to, 1_000);
        let message = Message::try_compile(&payer, &[ix], Hash::default()).unwrap();
        let tx = Transaction::new_unsigned(message);

        let encoded = tx.to_base64();
        let decoded = BASE64.decode(&encoded).unwrap();
        assert_eq!(decoded, tx.serialize());
    }

    #[test]
    fn versioned_transaction_unsigned_matches_v0_header() {
        let payer = Pubkey::new_from_array([1; 32]);
        let to = Pubkey::new_from_array([2; 32]);
        let ix = system::transfer(&payer, &to, 1_000);
        let message = MessageV0::try_compile(&payer, &[ix], &[], Hash::default()).unwrap();

        let tx = VersionedTransaction::new_unsigned(message.clone());
        assert_eq!(
            tx.signatures.len(),
            message.header.num_required_signatures as usize
        );
        assert_eq!(tx.recent_blockhash(), message.recent_blockhash);
        assert_eq!(tx.serialize()[0..1], [tx.signatures.len() as u8]);
    }

    #[cfg(feature = "sign")]
    #[test]
    fn try_sign_fills_the_payers_slot_with_a_verifiable_signature() {
        use crate::sign::Keypair;
        use ed25519_dalek::Verifier;

        // Same RFC 8032 §7.1 vector used in `sign::tests` — independent of
        // this crate's own signing code, just reused here for a real key.
        let mut keypair_bytes = [0u8; 64];
        keypair_bytes[0..32].copy_from_slice(
            &hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap(),
        );
        keypair_bytes[32..64].copy_from_slice(
            &hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
                .unwrap(),
        );
        let keypair = Keypair::from_bytes(&keypair_bytes).unwrap();

        let payer = keypair.pubkey();
        let to = Pubkey::new_from_array([2; 32]);
        let ix = system::transfer(&payer, &to, 1_000);
        let message = Message::try_compile(&payer, &[ix], Hash::default()).unwrap();
        let mut tx = Transaction::new_unsigned(message);

        tx.try_sign(&keypair).unwrap();

        assert_ne!(tx.signatures[0], Signature::ZERO);
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&payer.to_bytes()).unwrap();
        let sig = ed25519_dalek::Signature::from_bytes(&tx.signatures[0].to_bytes());
        assert!(verifying_key.verify(&tx.message.serialize(), &sig).is_ok());
    }

    #[cfg(feature = "sign")]
    #[test]
    fn try_sign_rejects_a_keypair_that_is_not_a_required_signer() {
        use crate::sign::Keypair;

        let mut keypair_bytes = [0u8; 64];
        keypair_bytes[0..32].copy_from_slice(
            &hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap(),
        );
        keypair_bytes[32..64].copy_from_slice(
            &hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
                .unwrap(),
        );
        let unrelated_keypair = Keypair::from_bytes(&keypair_bytes).unwrap();

        let payer = Pubkey::new_from_array([1; 32]);
        let to = Pubkey::new_from_array([2; 32]);
        let ix = system::transfer(&payer, &to, 1_000);
        let message = Message::try_compile(&payer, &[ix], Hash::default()).unwrap();
        let mut tx = Transaction::new_unsigned(message);

        let err = tx.try_sign(&unrelated_keypair).unwrap_err();
        assert_eq!(err, SignTransactionError::NotARequiredSigner);
    }
}
