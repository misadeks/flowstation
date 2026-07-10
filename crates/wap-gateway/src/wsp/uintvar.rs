//! Uintvar codec (WAP-230 §8.1.2).
//!
//! A uintvar is a big-endian, base-128 variable-length integer. Every byte
//! carries 7 payload bits (`byte & 0x7F`); the high bit (`0x80`) is a
//! *continuation* marker — set on every byte except the last.
//!
//! Examples:
//! * `0x1D`             → 29        (1 byte, no continuation)
//! * `0x83 0x1D`        → 413       ((0x03 << 7) | 0x1D)
//! * `0x94 0x80 0x00`   → 327680    ((0x14 << 14) | (0x00 << 7) | 0x00)
//!
//! We cap at u32 which comfortably covers every WSP length / session-id we
//! will ever see (WAP-230 §8.2.4 SDU sizes are 32-bit).

use crate::error::{WapError, WapResult};

/// Maximum number of bytes a uintvar may span before we treat it as
/// malformed. WAP-230 requires ≤5 bytes to fit a 32-bit value; anything
/// longer means the sender lost its mind (or is trying to overflow us).
const MAX_UINTVAR_BYTES: usize = 5;

/// Decode a uintvar from the start of `bytes`. Returns `(value, consumed)`.
pub fn decode(bytes: &[u8]) -> WapResult<(u32, usize)> {
    let mut value: u32 = 0;
    for (i, &b) in bytes.iter().enumerate() {
        if i >= MAX_UINTVAR_BYTES {
            return Err(WapError::WspDecode(format!("uintvar exceeds {MAX_UINTVAR_BYTES} bytes")));
        }
        value = value
            .checked_shl(7)
            .ok_or_else(|| WapError::WspDecode("uintvar overflow".to_owned()))?
            | u32::from(b & 0x7F);
        if b & 0x80 == 0 {
            return Ok((value, i + 1));
        }
    }
    Err(WapError::Truncated {
        expected: bytes.len() + 1,
        actual: bytes.len(),
    })
}

/// Encode `value` as a uintvar, appending the bytes to `out`.
///
/// Emits between 1 and 5 bytes.
pub fn encode(value: u32, out: &mut Vec<u8>) {
    // Compute how many 7-bit groups we need. `value == 0` still needs 1 byte.
    let mut n_bytes: u32 = 1;
    let mut probe = value >> 7;
    while probe != 0 {
        n_bytes += 1;
        probe >>= 7;
    }
    for i in (0..n_bytes).rev() {
        let shift = i * 7;
        let mut b = ((value >> shift) & 0x7F) as u8;
        if i != 0 {
            b |= 0x80;
        }
        out.push(b);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_single_byte() {
        assert_eq!(decode(&[0x1D]).unwrap(), (29, 1));
        assert_eq!(decode(&[0x00]).unwrap(), (0, 1));
        assert_eq!(decode(&[0x7F]).unwrap(), (127, 1));
    }

    #[test]
    fn decodes_two_bytes() {
        // 0x83 0x1D → (3<<7) | 0x1D = 413. Matches PD-10b hardware fixture.
        assert_eq!(decode(&[0x83, 0x1D]).unwrap(), (413, 2));
        assert_eq!(decode(&[0x81, 0x00]).unwrap(), (128, 2));
    }

    #[test]
    fn decodes_three_bytes() {
        // 0x94 0x80 0x00 → (0x14<<14) | 0 | 0 = 327680. From SDU-Size cap.
        assert_eq!(decode(&[0x94, 0x80, 0x00]).unwrap(), (327680, 3));
    }

    #[test]
    fn round_trip_common_values() {
        for v in [0, 1, 127, 128, 413, 1400, 327680, u32::MAX] {
            let mut buf = Vec::new();
            encode(v, &mut buf);
            let (got, n) = decode(&buf).unwrap();
            assert_eq!(got, v, "value mismatch for {v}");
            assert_eq!(n, buf.len(), "consumed mismatch for {v}");
        }
    }

    #[test]
    fn round_trip_hardware_bytes() {
        // Every uintvar seen in the MTP3550 fixture header prefix.
        for bytes in [&[0x1D][..], &[0x83, 0x1D][..], &[0x94, 0x80, 0x00][..]] {
            let (v, n) = decode(bytes).unwrap();
            assert_eq!(n, bytes.len());
            let mut re = Vec::new();
            encode(v, &mut re);
            assert_eq!(re, bytes, "encode did not reproduce {bytes:?}");
        }
    }

    #[test]
    fn rejects_unterminated() {
        assert!(matches!(decode(&[0x83]), Err(WapError::Truncated { .. })));
        assert!(matches!(decode(&[]), Err(WapError::Truncated { .. })));
    }

    #[test]
    fn rejects_too_long() {
        // 6 continuation bytes → past MAX_UINTVAR_BYTES.
        let junk = [0x80, 0x80, 0x80, 0x80, 0x80, 0x00];
        assert!(matches!(decode(&junk), Err(WapError::WspDecode(_))));
    }
}
