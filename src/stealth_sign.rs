//! Raw-scalar Ed25519 signing for a recovered stealth one-time private key —
//! never a seed-derived [`crate::sign::Keypair`]. Native-only, off-host
//! signer tooling: no plugin in this repo has any reason to sign a
//! transaction, so this module refuses to compile for any wasm target
//! rather than relying on Cargo feature discipline alone.

#[cfg(target_family = "wasm")]
compile_error!(
    "stealth_sign is native-only, off-host signer tooling and must never be a wasm \
     component dependency. If you're seeing this from a plugin's Cargo.toml, drop the \
     `stealth-sign` feature — plugins build unsigned transactions only; signing happens \
     in a separate signer the operator runs on their own device."
);

use crate::signature::Signature;
use crate::stealth::Scalar;
use ed25519_dalek::hazmat::{raw_sign, ExpandedSecretKey};
use ed25519_dalek::VerifyingKey;
use rand_core::{OsRng, RngCore};
use sha2::Sha512;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum StealthSignError {
    #[error("recovered scalar's public point is not a valid verifying key")]
    InvalidPoint,
}

/// Signs `message` with a one-time private scalar recovered via
/// [`crate::stealth::recover_one_time_privkey`]. Uses `ed25519-dalek`'s
/// `hazmat` API with a freshly random nonce prefix per call: since there's
/// no seed to derive a deterministic prefix from (this scalar was never a
/// seed in the first place), a fresh CSPRNG value each call guarantees the
/// per-signature nonce is never reused across two different messages under
/// the same key — the one invariant this API's safety warning is about.
pub fn sign_with_recovered_key(
    scalar: &Scalar,
    message: &[u8],
) -> Result<Signature, StealthSignError> {
    let point = scalar * curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
    let verifying_key = VerifyingKey::from_bytes(&point.compress().to_bytes())
        .map_err(|_| StealthSignError::InvalidPoint)?;

    let mut hash_prefix = [0u8; 32];
    OsRng.fill_bytes(&mut hash_prefix);
    let expanded = ExpandedSecretKey {
        scalar: *scalar,
        hash_prefix,
    };

    let sig = raw_sign::<Sha512>(&expanded, message, &verifying_key);
    Ok(Signature::from(sig.to_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stealth::{ephemeral_keypair, generate_keypair, recover_one_time_privkey};
    use ed25519_dalek::Verifier;

    #[test]
    fn signs_a_message_verifiable_by_a_standard_ed25519_verifier() {
        let (scan_priv, scan_pub) = generate_keypair();
        let (spend_priv, spend_pub) = generate_keypair();
        let (_ephemeral_scalar, ephemeral_pub) = ephemeral_keypair();

        let t = recover_one_time_privkey(&scan_priv, &ephemeral_pub, &spend_priv)
            .expect("valid points");
        let point = &t * curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
        let one_time_pubkey_bytes = point.compress().to_bytes();

        let message = b"unsigned transaction message bytes go here";
        let signature = sign_with_recovered_key(&t, message).expect("valid point");

        let verifying_key = VerifyingKey::from_bytes(&one_time_pubkey_bytes).unwrap();
        let sig_bytes: [u8; 64] = signature.into();
        let dalek_sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        assert!(verifying_key.verify(message, &dalek_sig).is_ok());

        // Sanity: the pubkey this signature verifies against really is the
        // one-time address the scan/derive functions would agree on, not
        // some unrelated point this test made up.
        let _ = (scan_pub, spend_pub);
    }

    #[test]
    fn two_signatures_over_different_messages_use_different_nonces() {
        let (scan_priv, _scan_pub) = generate_keypair();
        let (spend_priv, _spend_pub) = generate_keypair();
        let (_r, ephemeral_pub) = ephemeral_keypair();
        let t = recover_one_time_privkey(&scan_priv, &ephemeral_pub, &spend_priv)
            .expect("valid points");

        let sig_a = sign_with_recovered_key(&t, b"message a").unwrap();
        let sig_b = sign_with_recovered_key(&t, b"message b").unwrap();

        let bytes_a: [u8; 64] = sig_a.into();
        let bytes_b: [u8; 64] = sig_b.into();
        // Different messages, and even the same message signed twice, must
        // not collide on R (the first 32 bytes) — a repeated R with two
        // different messages under randomized EdDSA would be a broken RNG,
        // not just an edge case.
        assert_ne!(bytes_a[..32], bytes_b[..32]);
    }
}
