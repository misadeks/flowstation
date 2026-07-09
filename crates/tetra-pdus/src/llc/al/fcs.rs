/// 32-bit CRC for AL-FINAL / AL-UFINAL PDUs.
///
/// Algorithm: CRC-32/BZIP2 — polynomial 0x04C11DB7, MSB-first (no reflection),
/// initial value 0xFFFF_FFFF, final XOR 0xFFFF_FFFF.
///
/// NOTE: spec ambiguous — ETSI TS 100 392-2 v3.10.1 clause 21 does not name a
/// specific CRC-32 variant.  We use the ISO 3309 / ITU-T V.42 "unreflected"
/// (BZIP2) form. If a live bench trace disagrees, amend the polynomial, refin,
/// and refout parameters here.
///
/// Test vector: CRC-32/BZIP2 of ASCII `b"123456789"` = **0xFC891918**.
/// (The reflected / Ethernet / ZLIB variant would give 0xCBF43926.)
///
/// ETSI TS 100 392-2 v3.10.1 clause 21.2.3 (FCS field in AL-FINAL/AL-UFINAL).

const POLY: u32 = 0x04C11DB7;

/// Build the 256-entry CRC-32 lookup table at compile time.
const fn make_crc32_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0usize;
    while i < 256 {
        let mut crc = (i as u32) << 24;
        let mut j = 0;
        while j < 8 {
            if crc & 0x8000_0000 != 0 {
                crc = (crc << 1) ^ POLY;
            } else {
                crc <<= 1;
            }
            j += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}

static CRC32_TABLE: [u32; 256] = make_crc32_table();

/// Compute CRC-32/BZIP2 over `bytes`.
///
/// - Polynomial : 0x04C11DB7 (MSB-first, no input/output reflection)
/// - Initial CRC: 0xFFFF_FFFF
/// - Final XOR  : 0xFFFF_FFFF
/// - Check value: `crc32(b"123456789")` == **0xFC891918**
pub fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in bytes {
        let idx = ((crc >> 24) ^ byte as u32) as usize;
        crc = (crc << 8) ^ CRC32_TABLE[idx];
    }
    crc ^ 0xFFFF_FFFF
}

/// Compute CRC-32/BZIP2 over an arbitrary bit stream (one bit per entry,
/// value 0 or 1, MSB-first).
///
/// Bit-serial equivalent of [`crc32`]; produces the same value when the input
/// length is a multiple of 8 and the bits are the MSB-first expansion of the
/// same bytes.
///
/// TETRA's AL is bit-transparent: the TL-SDU can be any bit length and the
/// FCS is bit-serially computed over that exact bit length. See ETSI
/// TS 100 392-2 v3.10.1 clause 21.4.4 and nexus-bs `components/fcs.rs`
/// (`compute_fcs`).
pub fn crc32_bits(bits: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in bits {
        let feedback = ((b & 1) ^ ((crc >> 31) as u8)) & 1;
        crc <<= 1;
        if feedback != 0 {
            crc ^= POLY;
        }
    }
    !crc
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::{crc32, crc32_bits};

    /// Expand `bytes` into an MSB-first bit vector (one `u8` per bit).
    fn to_bits_msb_first(bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(bytes.len() * 8);
        for &byte in bytes {
            for i in (0..8).rev() {
                out.push((byte >> i) & 1);
            }
        }
        out
    }

    #[test]
    fn crc32_bits_matches_bytewise_on_aligned_input() {
        let data: Vec<u8> = (0u8..37).map(|i| i.wrapping_mul(13).wrapping_add(5)).collect();
        let bits = to_bits_msb_first(&data);
        assert_eq!(crc32(&data), crc32_bits(&bits));
    }

    #[test]
    fn crc32_bits_check_vector() {
        // CRC-32/BZIP2 of "123456789" bits (MSB-first) = 0xFC891918.
        let bits = to_bits_msb_first(b"123456789");
        assert_eq!(crc32_bits(&bits), 0xFC89_1918);
    }

    #[test]
    fn crc32_bits_empty() {
        assert_eq!(crc32_bits(&[]), 0x0000_0000);
    }

    #[test]
    fn crc32_bits_non_byte_aligned() {
        // 25-bit input: bytes 0xAB, 0xCD, then 1 extra bit (MSB of 0x80 = 1).
        let mut bits = to_bits_msb_first(&[0xAB, 0xCD]);
        bits.push(1);
        // Deterministic and stable; recompute by hand-appending the FCS and
        // checking the residual (see round-trip test below).
        let crc = crc32_bits(&bits);

        // Residual property: appending the 32-bit CRC MSB-first must yield the
        // CRC-32/BZIP2 residual constant 0x38FB2284.
        let mut with_fcs = bits.clone();
        for i in (0..32).rev() {
            with_fcs.push(((crc >> i) & 1) as u8);
        }
        assert_eq!(
            crc32_bits(&with_fcs),
            0x38FB_2284,
            "residual mismatch on non-byte-aligned input"
        );
    }

    #[test]
    fn crc32_empty_input() {
        // CRC-32/BZIP2 of zero bytes: init XOR finalxor = 0xFFFF_FFFF ^ 0xFFFF_FFFF = 0.
        assert_eq!(crc32(&[]), 0x0000_0000);
    }

    #[test]
    fn crc32_known_vector() {
        // CRC-32/BZIP2 (unreflected, poly 0x04C11DB7) of ASCII "123456789".
        // Reference: https://crccalc.com/ — CRC-32/BZIP2 row.
        assert_eq!(crc32(b"123456789"), 0xFC89_1918);
    }

    #[test]
    fn crc32_round_trip() {
        // Build a deterministic 100-byte pseudo-random buffer.
        let data: Vec<u8> =
            (0u8..100).map(|i| i.wrapping_mul(7).wrapping_add(13)).collect();

        let crc = crc32(&data);

        // CRC must be deterministic.
        assert_eq!(crc32(&data), crc, "CRC must be deterministic");

        // Appending the 4-byte big-endian CRC and recomputing must yield the
        // CRC-32/BZIP2 residual (0x38FB_2284).
        let mut buf_with_fcs = data.clone();
        buf_with_fcs.extend_from_slice(&crc.to_be_bytes());
        assert_eq!(
            crc32(&buf_with_fcs),
            0x38FB_2284,
            "residual mismatch — algorithm parameters may be wrong"
        );

        // Flipping any bit in the data must change the CRC.
        let mut tampered = data.clone();
        tampered[42] ^= 0x80;
        assert_ne!(crc32(&tampered), crc, "tampered data must yield a different CRC");
    }
}
