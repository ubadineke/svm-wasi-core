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

#[derive(Debug, thiserror::Error)]
pub enum ParseVersionedTransactionError {
    #[error("invalid base64: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("truncated transaction: nothing follows the signature array")]
    Truncated,
    #[error("invalid signature array encoding: {0}")]
    Signatures(String),
    #[error("not a versioned (v0) message: missing the 0x80 prefix byte")]
    NotVersioned,
    #[error("invalid message encoding: {0}")]
    Message(String),
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

    /// The exact bytes a signature must cover for this transaction: the
    /// `0x80` version-prefix byte followed by the bincode-serialized
    /// message. This is not just the wire-format encoding — Solana's
    /// runtime verifies a v0 transaction's signatures against precisely
    /// these prefixed bytes (confirmed against `solana-message`'s own
    /// wincode `SchemaWrite` impl, the encoding real `VersionedTransaction`
    /// signing actually uses), so `try_sign`/`insert_signature` and
    /// `serialize` must agree on this, not each compute their own version.
    fn message_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![solana_message::MESSAGE_VERSION_PREFIX];
        bytes.extend_from_slice(
            &bincode::serialize(&self.message).expect("message always serializes"),
        );
        bytes
    }

    pub fn serialize(&self) -> Vec<u8> {
        serialize_with_signatures(&self.signatures, self.message_bytes())
    }

    pub fn to_base64(&self) -> String {
        BASE64.encode(self.serialize())
    }

    /// The blockhash (or durable-nonce value) this transaction was built
    /// against.
    pub fn recent_blockhash(&self) -> Hash {
        self.message.recent_blockhash
    }

    /// Parses the wire format `serialize()`/`to_base64()` produce: a
    /// compact-u16-prefixed signature array followed by the `0x80`-prefixed
    /// message bytes. The inverse of `serialize()` — needed by a signer
    /// that receives a `transaction_base64` from a plugin and has to hand
    /// back a signed one.
    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self, ParseVersionedTransactionError> {
        let mut cursor = std::io::Cursor::new(bytes);
        let ShortVec(signatures): ShortVec<Signature> = bincode::deserialize_from(&mut cursor)
            .map_err(|e| ParseVersionedTransactionError::Signatures(e.to_string()))?;
        let consumed = cursor.position() as usize;
        let rest = bytes
            .get(consumed..)
            .ok_or(ParseVersionedTransactionError::Truncated)?;
        let (&version_byte, message_bytes) = rest
            .split_first()
            .ok_or(ParseVersionedTransactionError::Truncated)?;
        if version_byte != solana_message::MESSAGE_VERSION_PREFIX {
            return Err(ParseVersionedTransactionError::NotVersioned);
        }
        let message: MessageV0 = bincode::deserialize(message_bytes)
            .map_err(|e| ParseVersionedTransactionError::Message(e.to_string()))?;
        Ok(Self {
            signatures,
            message,
        })
    }

    pub fn try_from_base64(encoded: &str) -> Result<Self, ParseVersionedTransactionError> {
        let bytes = BASE64.decode(encoded)?;
        Self::try_from_bytes(&bytes)
    }

    /// Signs the message bytes with `keypair` and fills in that signer's
    /// slot.
    #[cfg(feature = "sign")]
    pub fn try_sign(&mut self, keypair: &Keypair) -> Result<(), SignTransactionError> {
        let message_bytes = self.message_bytes();
        sign_into(
            &mut self.signatures,
            &self.message.account_keys,
            self.message.header.num_required_signatures,
            &message_bytes,
            keypair,
        )
    }

    /// Fills `pubkey`'s signature slot with an already-computed signature —
    /// for a signer that isn't a seed-derived [`Keypair`], e.g. a recovered
    /// stealth one-time key signed via `stealth_sign::sign_with_recovered_key`
    /// over [`Self::message_bytes`].
    #[cfg(feature = "sign")]
    pub fn insert_signature(
        &mut self,
        pubkey: &crate::pubkey::Pubkey,
        signature: Signature,
    ) -> Result<(), SignTransactionError> {
        let index = self.message.account_keys
            [..self.message.header.num_required_signatures as usize]
            .iter()
            .position(|k| k == pubkey)
            .ok_or(SignTransactionError::NotARequiredSigner)?;
        self.signatures[index] = signature;
        Ok(())
    }

    /// The exact bytes an external signer must sign — see
    /// [`Self::message_bytes`]. Exposed publicly (unlike the internal
    /// helper) so a signer outside this module, e.g. `stealth_sign`, can
    /// produce a valid signature without re-deriving this crate's wire
    /// format itself.
    pub fn message_bytes_to_sign(&self) -> Vec<u8> {
        self.message_bytes()
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

    #[test]
    fn versioned_transaction_round_trips_through_base64() {
        let payer = Pubkey::new_from_array([1; 32]);
        let to = Pubkey::new_from_array([2; 32]);
        let ix = system::transfer(&payer, &to, 1_000);
        let message =
            MessageV0::try_compile(&payer, &[ix], &[], Hash::new_from_array([9; 32])).unwrap();
        let tx = VersionedTransaction::new_unsigned(message);

        let encoded = tx.to_base64();
        let decoded = VersionedTransaction::try_from_base64(&encoded).unwrap();

        assert_eq!(decoded, tx);
    }

    #[test]
    fn try_from_bytes_rejects_a_legacy_message_missing_the_version_prefix() {
        let payer = Pubkey::new_from_array([1; 32]);
        let to = Pubkey::new_from_array([2; 32]);
        let ix = system::transfer(&payer, &to, 1_000);
        let message = Message::new(&[ix], Some(&payer));
        let legacy_tx = Transaction::new_unsigned(message);

        let err = VersionedTransaction::try_from_bytes(&legacy_tx.serialize()).unwrap_err();
        assert!(matches!(err, ParseVersionedTransactionError::NotVersioned));
    }

    #[cfg(feature = "sign")]
    #[test]
    fn versioned_try_sign_produces_a_signature_verifiable_against_the_prefixed_message() {
        use crate::sign::Keypair;
        use ed25519_dalek::Verifier;

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
        let message = MessageV0::try_compile(&payer, &[ix], &[], Hash::default()).unwrap();
        let mut tx = VersionedTransaction::new_unsigned(message);

        tx.try_sign(&keypair).unwrap();

        assert_ne!(tx.signatures[0], Signature::default());
        // The signature must verify against the *prefixed* message bytes —
        // the same bytes Solana's runtime actually checks for a v0
        // transaction (confirmed against `solana-message`'s wincode
        // `SchemaWrite` impl) — not the bare bincode-serialized message.
        let verifying_key =
            ed25519_dalek::VerifyingKey::from_bytes(&<[u8; 32]>::try_from(payer.as_ref()).unwrap())
                .unwrap();
        let sig_bytes: [u8; 64] = tx.signatures[0].into();
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        assert!(verifying_key
            .verify(&tx.message_bytes_to_sign(), &sig)
            .is_ok());
    }

    #[cfg(feature = "stealth-sign")]
    #[test]
    fn insert_signature_from_a_recovered_stealth_key_verifies_and_round_trips() {
        use crate::stealth::{ephemeral_keypair, generate_keypair, recover_one_time_privkey};
        use crate::stealth_sign::sign_with_recovered_key;
        use ed25519_dalek::Verifier;

        let (scan_priv, scan_pub) = generate_keypair();
        let (spend_priv, spend_pub) = generate_keypair();
        let (ephemeral_scalar, ephemeral_pub) = ephemeral_keypair();

        let one_time_address =
            crate::stealth::derive_one_time_address(&scan_pub, &spend_pub, &ephemeral_scalar)
                .unwrap();
        let t = recover_one_time_privkey(&scan_priv, &ephemeral_pub, &spend_priv).unwrap();

        let to = Pubkey::new_from_array([2; 32]);
        let ix = system::transfer(&one_time_address, &to, 1_000);
        let message =
            MessageV0::try_compile(&one_time_address, &[ix], &[], Hash::default()).unwrap();
        let mut tx = VersionedTransaction::new_unsigned(message);

        let signature = sign_with_recovered_key(&t, &tx.message_bytes_to_sign()).unwrap();
        tx.insert_signature(&one_time_address, signature).unwrap();

        assert_ne!(tx.signatures[0], Signature::default());

        // Round-trip through the same base64 wire format a plugin/RPC call
        // would use, then verify the signature still checks out against a
        // standard, independent verifier.
        let encoded = tx.to_base64();
        let decoded = VersionedTransaction::try_from_base64(&encoded).unwrap();
        assert_eq!(decoded, tx);

        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(
            &<[u8; 32]>::try_from(one_time_address.as_ref()).unwrap(),
        )
        .unwrap();
        let sig_bytes: [u8; 64] = decoded.signatures[0].into();
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        assert!(verifying_key
            .verify(&decoded.message_bytes_to_sign(), &sig)
            .is_ok());
    }

    #[cfg(feature = "sign")]
    #[test]
    fn insert_signature_rejects_a_pubkey_that_is_not_a_required_signer() {
        let payer = Pubkey::new_from_array([1; 32]);
        let to = Pubkey::new_from_array([2; 32]);
        let ix = system::transfer(&payer, &to, 1_000);
        let message = MessageV0::try_compile(&payer, &[ix], &[], Hash::default()).unwrap();
        let mut tx = VersionedTransaction::new_unsigned(message);

        let unrelated = Pubkey::new_from_array([9; 32]);
        let err = tx
            .insert_signature(&unrelated, Signature::default())
            .unwrap_err();
        assert_eq!(err, SignTransactionError::NotARequiredSigner);
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
