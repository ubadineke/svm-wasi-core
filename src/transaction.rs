//! The outer transaction envelope: a signature array plus a message —
//! a compact-u16-prefixed array of (initially all-zero) signature slots
//! followed by the message bytes.
//!
//! Hand-rolled: the official `VersionedTransaction::try_new` requires
//! signing keypairs up front, which doesn't fit a T1 plugin's "hand an
//! unsigned tx to a human/multisig" flow.
//!
//! Wire bytes: signature count via `solana-short-vec`'s `ShortVec`,
//! bincode-serialized, followed by the message's own bincode bytes (correct
//! since the message's `Vec` fields are themselves `serde(with =
//! "solana_short_vec")`).

use crate::hash::Hash;
use crate::message::{Message, MessageV0};
#[cfg(feature = "sign")]
use crate::sign::Keypair;
use crate::signature::Signature;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use solana_short_vec::ShortVec;

#[cfg(feature = "sign")]
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SignTransactionError {
    #[error("pubkey is not one of this transaction's required signers")]
    NotARequiredSigner,
}

/// Finds `pubkey`'s index among the first `num_required_signatures` account
/// keys and fills that signature slot.
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

fn serialize_with_signatures(signatures: &[Signature], message_bytes: Vec<u8>) -> Vec<u8> {
    let mut buf = bincode::serialize(&ShortVec(signatures.to_vec()))
        .expect("signature array always serializes");
    buf.extend_from_slice(&message_bytes);
    buf
}

/// A legacy-message transaction with unsigned (all-zero) signature slots.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transaction {
    pub signatures: Vec<Signature>,
    pub message: Message,
}

impl Transaction {
    /// Wraps `message` with `header.num_required_signatures` all-zero
    /// signature placeholders.
    pub fn new_unsigned(message: Message) -> Self {
        let signatures =
            vec![Signature::default(); message.header.num_required_signatures as usize];
        Self {
            signatures,
            message,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let message_bytes = bincode::serialize(&self.message).expect("message always serializes");
        serialize_with_signatures(&self.signatures, message_bytes)
    }

    pub fn to_base64(&self) -> String {
        BASE64.encode(self.serialize())
    }

    /// Signs the message bytes with `keypair` and fills in that signer's
    /// slot.
    #[cfg(feature = "sign")]
    pub fn try_sign(&mut self, keypair: &Keypair) -> Result<(), SignTransactionError> {
        let message_bytes = bincode::serialize(&self.message).expect("message always serializes");
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
        let signatures =
            vec![Signature::default(); message.header.num_required_signatures as usize];
        Self {
            signatures,
            message,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        // bincode-serializing the struct alone omits the 0x80 version prefix.
        let mut message_bytes = vec![solana_message::MESSAGE_VERSION_PREFIX];
        message_bytes.extend_from_slice(
            &bincode::serialize(&self.message).expect("message always serializes"),
        );
        serialize_with_signatures(&self.signatures, message_bytes)
    }

    pub fn to_base64(&self) -> String {
        BASE64.encode(self.serialize())
    }

    /// The blockhash (or durable-nonce value) this transaction was built
    /// against.
    pub fn recent_blockhash(&self) -> Hash {
        self.message.recent_blockhash
    }

    /// Signs the message bytes with `keypair` and fills in that signer's
    /// slot.
    #[cfg(feature = "sign")]
    pub fn try_sign(&mut self, keypair: &Keypair) -> Result<(), SignTransactionError> {
        let message_bytes = bincode::serialize(&self.message).expect("message always serializes");
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
        let message = Message::new(&[ix], Some(&payer));

        let tx = Transaction::new_unsigned(message.clone());

        assert_eq!(
            tx.signatures.len(),
            message.header.num_required_signatures as usize
        );
        assert!(tx.signatures.iter().all(|s| *s == Signature::default()));
    }

    #[test]
    fn to_base64_round_trips_through_standard_base64() {
        let payer = Pubkey::new_from_array([1; 32]);
        let to = Pubkey::new_from_array([2; 32]);
        let ix = system::transfer(&payer, &to, 1_000);
        let message = Message::new(&[ix], Some(&payer));
        let tx = Transaction::new_unsigned(message);

        let encoded = tx.to_base64();
        let decoded = BASE64.decode(&encoded).unwrap();
        assert_eq!(decoded, tx.serialize());
    }

    #[test]
    fn versioned_transaction_unsigned_matches_v0_header_and_version_prefix() {
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

        let bytes = tx.serialize();
        // First byte(s): compact-u16 signature count (1 signer here fits in
        // one byte), followed by that many 64-byte signatures, then the
        // 0x80 version-prefix byte.
        assert_eq!(bytes[0], tx.signatures.len() as u8);
        let version_byte_index = 1 + tx.signatures.len() * 64;
        assert_eq!(
            bytes[version_byte_index],
            solana_message::MESSAGE_VERSION_PREFIX
        );
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
        let message = Message::new(&[ix], Some(&payer));
        let mut tx = Transaction::new_unsigned(message);

        tx.try_sign(&keypair).unwrap();

        assert_ne!(tx.signatures[0], Signature::default());
        let message_bytes = bincode::serialize(&tx.message).unwrap();
        let verifying_key =
            ed25519_dalek::VerifyingKey::from_bytes(&<[u8; 32]>::try_from(payer.as_ref()).unwrap())
                .unwrap();
        let sig_bytes: [u8; 64] = tx.signatures[0].into();
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        assert!(verifying_key.verify(&message_bytes, &sig).is_ok());
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
        let message = Message::new(&[ix], Some(&payer));
        let mut tx = Transaction::new_unsigned(message);

        let err = tx.try_sign(&unrelated_keypair).unwrap_err();
        assert_eq!(err, SignTransactionError::NotARequiredSigner);
    }
}
