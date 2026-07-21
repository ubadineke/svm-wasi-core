//! Solana's "compact-u16" / short-vec length-prefix encoding — prefixes the
//! signatures, account-keys, and instruction accounts/data arrays in a
//! transaction message. Not borsh, not standard LEB128: Solana's own
//! 7-bits-per-byte, continuation-bit-in-the-high-bit scheme, capped at 3
//! bytes. Reference: <https://docs.rs/solana-short-vec>.

const CONTINUATION_BIT: u8 = 0x80;
const VALUE_MASK: u8 = 0x7f;
const MAX_ENCODED_LEN: usize = 3;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ShortVecError {
    #[error("truncated short-vec length prefix: ran out of bytes before a terminating byte")]
    Truncated,
    #[error("short-vec length prefix exceeds the 3-byte (u16) maximum")]
    TooLong,
    #[error("non-canonical short-vec encoding: a shorter encoding represents the same value")]
    NonCanonical,
}

/// Appends `len`'s compact-u16 encoding to `buf`.
///
/// `len` must fit in a `u16` (0..=65535) — every use of this encoding in a
/// Solana transaction bounds an array that small (account/instruction/
/// signature counts).
pub fn encode_len_into(buf: &mut Vec<u8>, len: u16) {
    let mut rem = len as u32;
    loop {
        let mut byte = (rem & VALUE_MASK as u32) as u8;
        rem >>= 7;
        if rem == 0 {
            buf.push(byte);
            break;
        }
        byte |= CONTINUATION_BIT;
        buf.push(byte);
    }
}

/// Same as [`encode_len_into`], returning a freshly allocated buffer.
pub fn encode_len(len: u16) -> Vec<u8> {
    let mut buf = Vec::with_capacity(MAX_ENCODED_LEN);
    encode_len_into(&mut buf, len);
    buf
}

/// Decodes a compact-u16 length prefix from the start of `bytes`, returning
/// the value and the remaining slice. Rejects non-canonical encodings (e.g.
/// `0` as `[0x80, 0x00]` instead of `[0x00]`) to match upstream's strictness.
pub fn decode_len(bytes: &[u8]) -> Result<(u16, &[u8]), ShortVecError> {
    let mut value: u32 = 0;
    let mut consumed = 0usize;

    for (i, byte) in bytes.iter().enumerate().take(MAX_ENCODED_LEN) {
        value |= ((byte & VALUE_MASK) as u32) << (i * 7);
        consumed += 1;
        if byte & CONTINUATION_BIT == 0 {
            if value > u16::MAX as u32 {
                return Err(ShortVecError::TooLong);
            }
            let value = value as u16;
            if encode_len(value).len() != consumed {
                return Err(ShortVecError::NonCanonical);
            }
            return Ok((value, &bytes[consumed..]));
        }
    }

    if consumed == MAX_ENCODED_LEN {
        Err(ShortVecError::TooLong)
    } else {
        Err(ShortVecError::Truncated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_byte_boundary() {
        assert_eq!(encode_len(0), vec![0x00]);
        assert_eq!(encode_len(127), vec![0x7f]);
    }

    #[test]
    fn two_byte_boundary() {
        assert_eq!(encode_len(128), vec![0x80, 0x01]);
        assert_eq!(encode_len(16383), vec![0xff, 0x7f]);
    }

    #[test]
    fn three_byte_boundary() {
        assert_eq!(encode_len(16384), vec![0x80, 0x80, 0x01]);
        assert_eq!(encode_len(u16::MAX), vec![0xff, 0xff, 0x03]);
    }

    #[test]
    fn round_trips_every_boundary_value() {
        for &len in &[0u16, 1, 127, 128, 16383, 16384, 65535] {
            let encoded = encode_len(len);
            let (decoded, rest) = decode_len(&encoded).unwrap();
            assert_eq!(decoded, len);
            assert!(rest.is_empty());
        }
    }

    #[test]
    fn decode_leaves_trailing_bytes_untouched() {
        let mut buf = encode_len(300);
        buf.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        let (decoded, rest) = decode_len(&buf).unwrap();
        assert_eq!(decoded, 300);
        assert_eq!(rest, &[0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn rejects_truncated_input() {
        // Continuation bit set with nothing following.
        let err = decode_len(&[0x80]).unwrap_err();
        assert_eq!(err, ShortVecError::Truncated);
    }

    #[test]
    fn rejects_more_than_three_bytes() {
        let err = decode_len(&[0x80, 0x80, 0x80, 0x01]).unwrap_err();
        assert_eq!(err, ShortVecError::TooLong);
    }

    #[test]
    fn rejects_non_canonical_encoding() {
        // 0 encoded with an unnecessary continuation byte.
        let err = decode_len(&[0x80, 0x00]).unwrap_err();
        assert_eq!(err, ShortVecError::NonCanonical);
    }
}
