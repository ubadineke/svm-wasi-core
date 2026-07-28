//! DKSAP (Dual-Key Stealth Address Protocol) primitives: ephemeral keypair
//! generation, ECDH-style shared secret, and one-time address derivation.
//! Not ed25519 signing — plain Edwards-curve point/scalar math via
//! `curve25519-dalek`, feature-gated (`stealth`) so plugins that don't need
//! it never pull in curve arithmetic.
//!
//! A one-time address is `T = H(shared)·G + S`, where `shared` is `r·V`
//! (sender side, from the recipient's published scan pubkey `V`) or `v·R`
//! (recipient side, from the sender's published ephemeral pubkey `R`) — both
//! sides land on the same point since `r·V = r·(v·G) = v·(r·G) = v·R`.
//! Recovering the one-time *private* key (`t = s + H(shared) mod L`) needs
//! the spend scalar `s`, which this module never touches — that happens in
//! a separate signer holding the spend key.

use crate::pubkey::Pubkey;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::traits::IsIdentity;
use rand_core::OsRng;
use sha2::Sha512;

// Re-exported so callers can name the scalar type without adding
// `curve25519-dalek` as their own direct dependency.
pub use curve25519_dalek::scalar::Scalar;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum StealthError {
    #[error("{kind} is not a valid point on the curve")]
    InvalidPoint { kind: &'static str },
    #[error(
        "shared secret is the identity point — refuse to derive from a degenerate ECDH result"
    )]
    DegenerateSharedSecret,
    #[error("scan private key must be 64 hex characters (32 bytes): {0}")]
    InvalidScalarHex(String),
}

fn decompress(pubkey: &Pubkey, kind: &'static str) -> Result<EdwardsPoint, StealthError> {
    let bytes: [u8; 32] = pubkey
        .as_ref()
        .try_into()
        .map_err(|_| StealthError::InvalidPoint { kind })?;
    CompressedEdwardsY(bytes)
        .decompress()
        .ok_or(StealthError::InvalidPoint { kind })
}

fn to_pubkey(point: &EdwardsPoint) -> Pubkey {
    Pubkey::new_from_array(point.compress().to_bytes())
}

/// Hashes a shared-secret point to a scalar mod the group order `L` — the
/// `c` in `T = c·G + S`. Refuses the identity point: an ECDH result of the
/// identity would mean `c` collapses to a hash of an all-zero-equivalent
/// input, degrading the "fresh, unlinkable" property this whole scheme
/// exists for.
fn hash_shared_secret(shared: &EdwardsPoint) -> Result<Scalar, StealthError> {
    if shared.is_identity() {
        return Err(StealthError::DegenerateSharedSecret);
    }
    Ok(Scalar::hash_from_bytes::<Sha512>(
        shared.compress().as_bytes(),
    ))
}

/// Generates a fresh random `(scalar, point)` pair — the same operation
/// whether it's producing a per-payment ephemeral keypair or a long-lived
/// scan/spend keypair at setup time.
pub fn generate_keypair() -> (Scalar, Pubkey) {
    let scalar = Scalar::random(&mut OsRng);
    let point = &scalar * curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
    (scalar, to_pubkey(&point))
}

/// Alias for [`generate_keypair`], named for the call site that generates a
/// fresh `(r, R)` for one payment.
pub fn ephemeral_keypair() -> (Scalar, Pubkey) {
    generate_keypair()
}

/// Hex-encodes a private scalar (scan or spend key) for storage in an
/// operator's encrypted config section — the wire format `__config` values
/// arrive in (a flat string map), so a scalar has to round-trip through a
/// string somehow.
pub fn scalar_to_hex(scalar: &Scalar) -> String {
    hex::encode(scalar.to_bytes())
}

/// Inverse of [`scalar_to_hex`]. Does not reduce mod `L` silently — a
/// non-canonical scalar encoding is rejected rather than accepted and
/// quietly reinterpreted, since this decodes operator-supplied secret
/// config, not a value this crate generated itself.
pub fn scalar_from_hex(hex_str: &str) -> Result<Scalar, StealthError> {
    let bytes = hex::decode(hex_str).map_err(|e| StealthError::InvalidScalarHex(e.to_string()))?;
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| StealthError::InvalidScalarHex("expected 32 bytes".to_string()))?;
    Option::<Scalar>::from(Scalar::from_canonical_bytes(array))
        .ok_or_else(|| StealthError::InvalidScalarHex("not a canonical scalar mod L".to_string()))
}

/// Sender side: derives the one-time address a payment should go to, given
/// the recipient's published `(scan_pub, spend_pub)` meta-address and this
/// payment's own ephemeral scalar `r`. `T = H(r·V)·G + S`.
pub fn derive_one_time_address(
    scan_pub: &Pubkey,
    spend_pub: &Pubkey,
    ephemeral_scalar: &Scalar,
) -> Result<Pubkey, StealthError> {
    let scan_point = decompress(scan_pub, "scan_pub")?;
    let spend_point = decompress(spend_pub, "spend_pub")?;
    let shared = ephemeral_scalar * scan_point;
    let c = hash_shared_secret(&shared)?;
    let one_time = &c * curve25519_dalek::constants::ED25519_BASEPOINT_TABLE + spend_point;
    Ok(to_pubkey(&one_time))
}

/// Recipient/scanner side: recomputes the same one-time address from the
/// scan *private* scalar `v` and the ephemeral *public* key `R` a sender
/// published alongside their payment. `T = H(v·R)·G + S` — identical result
/// to [`derive_one_time_address`] because `v·R = r·V`.
pub fn recompute_one_time_address(
    scan_priv: &Scalar,
    ephemeral_pub: &Pubkey,
    spend_pub: &Pubkey,
) -> Result<Pubkey, StealthError> {
    let ephemeral_point = decompress(ephemeral_pub, "ephemeral_pub")?;
    let spend_point = decompress(spend_pub, "spend_pub")?;
    let shared = scan_priv * ephemeral_point;
    let c = hash_shared_secret(&shared)?;
    let one_time = &c * curve25519_dalek::constants::ED25519_BASEPOINT_TABLE + spend_point;
    Ok(to_pubkey(&one_time))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sender_and_recipient_derive_the_same_one_time_address() {
        let (scan_priv, scan_pub) = generate_keypair();
        let (_spend_priv, spend_pub) = generate_keypair();
        let (ephemeral_scalar, ephemeral_pub) = ephemeral_keypair();

        let sender_side = derive_one_time_address(&scan_pub, &spend_pub, &ephemeral_scalar)
            .expect("valid points");
        let recipient_side = recompute_one_time_address(&scan_priv, &ephemeral_pub, &spend_pub)
            .expect("valid points");

        assert_eq!(sender_side, recipient_side);
    }

    #[test]
    fn different_ephemeral_scalars_produce_different_addresses() {
        let (_scan_priv, scan_pub) = generate_keypair();
        let (_spend_priv, spend_pub) = generate_keypair();
        let (r1, _) = ephemeral_keypair();
        let (r2, _) = ephemeral_keypair();

        let t1 = derive_one_time_address(&scan_pub, &spend_pub, &r1).unwrap();
        let t2 = derive_one_time_address(&scan_pub, &spend_pub, &r2).unwrap();

        assert_ne!(t1, t2);
    }

    #[test]
    fn wrong_scan_key_recomputes_a_different_address() {
        let (_scan_priv, scan_pub) = generate_keypair();
        let (wrong_scan_priv, _wrong_scan_pub) = generate_keypair();
        let (_spend_priv, spend_pub) = generate_keypair();
        let (ephemeral_scalar, ephemeral_pub) = ephemeral_keypair();

        let real = derive_one_time_address(&scan_pub, &spend_pub, &ephemeral_scalar).unwrap();
        let wrong =
            recompute_one_time_address(&wrong_scan_priv, &ephemeral_pub, &spend_pub).unwrap();

        assert_ne!(real, wrong);
    }

    #[test]
    fn rejects_a_non_canonical_point() {
        // Not every y-coordinate has a matching x on the curve — scan small
        // y values for one curve25519-dalek itself rejects, rather than
        // assuming which bit pattern fails ahead of time.
        let bogus_bytes = (2u64..1000)
            .map(|y| {
                let mut bytes = [0u8; 32];
                bytes[..8].copy_from_slice(&y.to_le_bytes());
                bytes
            })
            .find(|bytes| CompressedEdwardsY(*bytes).decompress().is_none())
            .expect("at least one small y value in range is off-curve");
        let bogus = Pubkey::new_from_array(bogus_bytes);
        let (_scan_priv, scan_pub) = generate_keypair();
        let (ephemeral_scalar, _) = ephemeral_keypair();

        let err = derive_one_time_address(&scan_pub, &bogus, &ephemeral_scalar).unwrap_err();
        assert_eq!(err, StealthError::InvalidPoint { kind: "spend_pub" });
    }

    #[test]
    fn scalar_hex_round_trips() {
        let (scalar, _pub) = generate_keypair();
        let hex_str = scalar_to_hex(&scalar);
        assert_eq!(hex_str.len(), 64);
        assert_eq!(scalar_from_hex(&hex_str).unwrap(), scalar);
    }

    #[test]
    fn scalar_from_hex_rejects_wrong_length() {
        let err = scalar_from_hex("deadbeef").unwrap_err();
        assert!(matches!(err, StealthError::InvalidScalarHex(_)));
    }

    #[test]
    fn scalar_from_hex_rejects_non_hex() {
        let err = scalar_from_hex(&"zz".repeat(32)).unwrap_err();
        assert!(matches!(err, StealthError::InvalidScalarHex(_)));
    }
}
