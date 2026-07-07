/// Advanced Link SDU segmentation.
///
/// Splits a TL-SDU (plus its 32-bit FCS) into a sequence of AL-DATA / AL-FINAL
/// (or AL-UDATA / AL-UFINAL) PDUs ready for delivery to the MAC layer.
///
/// The FCS is appended to the SDU byte stream before fragmentation, so the FCS
/// value may span segment boundaries exactly as the spec permits.
///
/// NOTE: spec ambiguous — the FCS is also placed in the FINAL PDU's `fcs` field
/// for semantic clarity at the codec level; the wire layout (FCS spanning segments)
/// is the authoritative form and AL-3 must handle that.
///
/// ETSI TS 100 392-2 v3.10.1 clauses 21.2.3.2, 21.2.3.3, 21.2.3.6, 21.2.3.7.

use tetra_core::BitBuffer;

use crate::llc::pdus::al_data::{AlDataAlFinal, AlDataVariant};
use crate::llc::pdus::al_udata::{AlAlUdataAlUfinal, AlUdataVariant};
use super::error::SegmentationError;
use super::fcs::crc32;

/// N271 upper bound: maximum TL-SDU + FCS length in bits.
/// N271_AL_MAX_TLSDU_LEN = 4 096 octets (ETSI TS 100 392-2 v3.10.1 Annex A.2).
const MAX_AL_SDU_BITS: usize = 4096 * 8;

/// Maximum number of segments (S(S) is an 8-bit field: values 0..=255).
const MAX_SEGMENTS: usize = 256;

// ─── Acknowledged segmenter ─────────────────────────────────────────────────

/// Configuration for the acknowledged AL segmenter.
pub struct SegmenterConfig {
    /// Number of bits available for the `tl_sdu_segment` payload in each PDU
    /// (the MAC block budget minus the LLC/AL header overhead).
    pub segment_payload_bits: usize,
    /// Initial N(S) value.  All PDUs for the same SDU share this value.
    /// Wraps modulo 8 in the AL state machine (AL-3).
    pub starting_n_s: u8,
    /// When `true`, the FINAL PDU uses variant `FinalAr`; otherwise `Final`.
    pub request_ack_on_final: bool,
    /// When `true`, all non-final (DATA) PDUs use variant `DataAr`.
    /// Normally `false`; only set when mid-SDU ACK requests are required.
    pub request_ack_on_data: bool,
}

/// Output produced by [`segment_sdu`].
pub struct SegmenterOutput {
    /// The generated AL-DATA / AL-FINAL PDUs in send order (S(S) = 0, 1, …).
    pub pdus: Vec<AlDataAlFinal>,
    /// N(S) value shared by every PDU in this SDU.
    pub n_s_used: u8,
    /// Number of PDUs (= S(S) values) produced: 1..=256.
    pub segment_count: u8,
}

/// Segment `sdu` into a sequence of AL-DATA / AL-FINAL PDUs.
///
/// The 32-bit FCS is computed over `sdu` and appended to the bit stream before
/// slicing, so FCS bits may appear in any segment including non-final ones.
///
/// # Errors
/// - [`SegmentationError::EmptySdu`] — `sdu` is empty.
/// - [`SegmentationError::SegmentTooSmall`] — `config.segment_payload_bits < 8`.
/// - [`SegmentationError::SduTooLarge`] — SDU + FCS exceeds N271 (4 096 octets)
///   or the required segment count would exceed 256 (S(S) space).
pub fn segment_sdu(
    sdu: &[u8],
    config: &SegmenterConfig,
) -> Result<SegmenterOutput, SegmentationError> {
    if sdu.is_empty() {
        return Err(SegmentationError::EmptySdu);
    }
    if config.segment_payload_bits < 8 {
        return Err(SegmentationError::SegmentTooSmall {
            requested: config.segment_payload_bits,
            minimum: 8,
        });
    }

    let total_bits = sdu.len() * 8 + 32; // SDU + FCS
    if total_bits > MAX_AL_SDU_BITS {
        return Err(SegmentationError::SduTooLarge {
            bits: total_bits,
            max_bits: MAX_AL_SDU_BITS,
        });
    }

    let num_segments = total_bits.div_ceil(config.segment_payload_bits);
    // NOTE: spec ambiguous — S(S) is 8-bit, so at most 256 unique values (0..=255).
    // If the chosen segment size is too small to fit the SDU in 256 segments we
    // reject rather than silently truncate.  Chosen behaviour: SduTooLarge.
    if num_segments > MAX_SEGMENTS {
        return Err(SegmentationError::SduTooLarge {
            bits: total_bits,
            max_bits: config.segment_payload_bits * MAX_SEGMENTS,
        });
    }

    let fcs_val = crc32(sdu);
    let bits = sdu_to_bitvec_with_fcs(sdu, fcs_val);
    debug_assert_eq!(bits.len(), total_bits);

    let seg_size = config.segment_payload_bits;
    let mut pdus = Vec::with_capacity(num_segments);

    for idx in 0..num_segments {
        let start = idx * seg_size;
        let end = usize::min(start + seg_size, total_bits);
        let seg_bits = &bits[start..end];

        let is_final = idx == num_segments - 1;
        let variant = if is_final {
            if config.request_ack_on_final {
                AlDataVariant::FinalAr
            } else {
                AlDataVariant::Final
            }
        } else if config.request_ack_on_data {
            AlDataVariant::DataAr
        } else {
            AlDataVariant::Data
        };

        pdus.push(AlDataAlFinal {
            variant,
            n_s: config.starting_n_s,
            s_s: idx as u8,
            tl_sdu_segment: bitvec_to_bitbuffer(seg_bits),
            fcs: if is_final { Some(fcs_val) } else { None },
        });
    }

    Ok(SegmenterOutput {
        n_s_used: config.starting_n_s,
        segment_count: num_segments as u8,
        pdus,
    })
}

// ─── Unacknowledged segmenter ────────────────────────────────────────────────

/// Configuration for the unacknowledged AL segmenter.
pub struct UnackSegmenterConfig {
    /// Number of bits available for the `tl_sdu_segment` payload.
    pub segment_payload_bits: usize,
    /// Initial N(S) value (8-bit space for unacknowledged SDUs).
    pub starting_n_s: u8,
}

/// Output produced by [`segment_unack_sdu`].
pub struct UnackSegmenterOutput {
    /// The generated AL-UDATA / AL-UFINAL PDUs in send order.
    pub pdus: Vec<AlAlUdataAlUfinal>,
    /// N(S) value shared by every PDU.
    pub n_s_used: u8,
    /// Number of PDUs produced.
    pub segment_count: u8,
}

/// Segment `sdu` into a sequence of AL-UDATA / AL-UFINAL PDUs.
///
/// Semantics are identical to [`segment_sdu`] except that the PDU type is
/// unacknowledged.
///
/// # Errors
/// Same conditions as [`segment_sdu`].
pub fn segment_unack_sdu(
    sdu: &[u8],
    config: &UnackSegmenterConfig,
) -> Result<UnackSegmenterOutput, SegmentationError> {
    if sdu.is_empty() {
        return Err(SegmentationError::EmptySdu);
    }
    if config.segment_payload_bits < 8 {
        return Err(SegmentationError::SegmentTooSmall {
            requested: config.segment_payload_bits,
            minimum: 8,
        });
    }

    let total_bits = sdu.len() * 8 + 32;
    if total_bits > MAX_AL_SDU_BITS {
        return Err(SegmentationError::SduTooLarge {
            bits: total_bits,
            max_bits: MAX_AL_SDU_BITS,
        });
    }

    let num_segments = total_bits.div_ceil(config.segment_payload_bits);
    if num_segments > MAX_SEGMENTS {
        return Err(SegmentationError::SduTooLarge {
            bits: total_bits,
            max_bits: config.segment_payload_bits * MAX_SEGMENTS,
        });
    }

    let fcs_val = crc32(sdu);
    let bits = sdu_to_bitvec_with_fcs(sdu, fcs_val);

    let seg_size = config.segment_payload_bits;
    let mut pdus = Vec::with_capacity(num_segments);

    for idx in 0..num_segments {
        let start = idx * seg_size;
        let end = usize::min(start + seg_size, total_bits);
        let seg_bits = &bits[start..end];

        let is_final = idx == num_segments - 1;
        let variant = if is_final { AlUdataVariant::Ufinal } else { AlUdataVariant::Udata };

        pdus.push(AlAlUdataAlUfinal {
            variant,
            n_s: config.starting_n_s,
            s_s: idx as u8,
            tl_sdu_segment: bitvec_to_bitbuffer(seg_bits),
            fcs: if is_final { Some(fcs_val) } else { None },
        });
    }

    Ok(UnackSegmenterOutput {
        n_s_used: config.starting_n_s,
        segment_count: num_segments as u8,
        pdus,
    })
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Convert SDU bytes and a pre-computed FCS value into a flat bitvec (0/1 per entry),
/// MSB-first.
fn sdu_to_bitvec_with_fcs(sdu: &[u8], fcs: u32) -> Vec<u8> {
    let mut bits = Vec::with_capacity(sdu.len() * 8 + 32);
    for &byte in sdu {
        for i in (0..8).rev() {
            bits.push((byte >> i) & 1);
        }
    }
    for i in (0..32).rev() {
        bits.push(((fcs >> i) & 1) as u8);
    }
    bits
}

/// Build a [`BitBuffer`] from a bitvec slice (one bit per byte, MSB-first).
fn bitvec_to_bitbuffer(bits: &[u8]) -> BitBuffer {
    let mut buf = BitBuffer::new_autoexpand(bits.len() + 8);
    for &b in bits {
        buf.write_bits(b as u64, 1);
    }
    buf.seek(0);
    buf
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::llc::pdus::al_data::AlDataVariant;
    use crate::llc::pdus::al_udata::AlUdataVariant;

    // ── Acknowledged segmenter ────────────────────────────────────────────

    #[test]
    fn ack_single_segment_sdu() {
        // A 3-byte SDU + 4-byte FCS = 56 bits; with a 512-bit segment budget,
        // everything fits in a single AL-FINAL.
        let sdu = b"abc";
        let config = SegmenterConfig {
            segment_payload_bits: 512,
            starting_n_s: 0,
            request_ack_on_final: false,
            request_ack_on_data: false,
        };
        let out = segment_sdu(sdu, &config).unwrap();
        assert_eq!(out.segment_count, 1);
        assert_eq!(out.pdus.len(), 1);
        assert_eq!(out.n_s_used, 0);

        let pdu = &out.pdus[0];
        assert_eq!(pdu.variant, AlDataVariant::Final);
        assert_eq!(pdu.s_s, 0);
        assert_eq!(pdu.n_s, 0);
        assert!(pdu.fcs.is_some(), "FINAL must carry FCS");
        // 24 SDU bits + 32 FCS bits = 56 bits in tl_sdu_segment
        assert_eq!(pdu.tl_sdu_segment.get_len(), 56);
    }

    #[test]
    fn ack_multi_segment_sdu() {
        // 500-byte SDU + 4-byte FCS = 504 bytes = 4 032 bits.
        // 200-bit segment budget → ceil(4032 / 200) = 21 segments.
        let sdu: Vec<u8> = (0u8..=255).cycle().take(500).collect();
        let config = SegmenterConfig {
            segment_payload_bits: 200,
            starting_n_s: 5,
            request_ack_on_final: false,
            request_ack_on_data: false,
        };
        let out = segment_sdu(&sdu, &config).unwrap();

        let expected = (500usize * 8 + 32).div_ceil(200); // 21
        assert_eq!(out.segment_count as usize, expected);
        assert_eq!(out.pdus.len(), expected);
        assert_eq!(out.n_s_used, 5);

        // All PDUs share the same N(S).
        for pdu in &out.pdus {
            assert_eq!(pdu.n_s, 5);
        }
        // S(S) is sequential.
        for (i, pdu) in out.pdus.iter().enumerate() {
            assert_eq!(pdu.s_s as usize, i, "S(S) must be sequential");
        }
        // Non-final variants are Data.
        for pdu in &out.pdus[..expected - 1] {
            assert_eq!(pdu.variant, AlDataVariant::Data);
            assert!(pdu.fcs.is_none());
        }
        // Last is Final with FCS.
        let last = &out.pdus[expected - 1];
        assert_eq!(last.variant, AlDataVariant::Final);
        assert!(last.fcs.is_some());
    }

    #[test]
    fn ack_ar_variant() {
        let sdu = b"hello world";
        let config = SegmenterConfig {
            segment_payload_bits: 40,
            starting_n_s: 3,
            request_ack_on_final: true,
            request_ack_on_data: true,
        };
        let out = segment_sdu(sdu, &config).unwrap();
        // Last PDU must be FinalAr.
        let last = out.pdus.last().unwrap();
        assert_eq!(last.variant, AlDataVariant::FinalAr);
        // Non-final PDUs must be DataAr.
        for pdu in &out.pdus[..out.pdus.len().saturating_sub(1)] {
            assert_eq!(pdu.variant, AlDataVariant::DataAr);
        }
    }

    #[test]
    fn ack_rejects_empty_sdu() {
        let config =
            SegmenterConfig { segment_payload_bits: 200, starting_n_s: 0, request_ack_on_final: false, request_ack_on_data: false };
        assert!(matches!(segment_sdu(&[], &config), Err(SegmentationError::EmptySdu)));
    }

    #[test]
    fn ack_rejects_too_small_segment() {
        let config =
            SegmenterConfig { segment_payload_bits: 4, starting_n_s: 0, request_ack_on_final: false, request_ack_on_data: false };
        assert!(matches!(
            segment_sdu(b"x", &config),
            Err(SegmentationError::SegmentTooSmall { requested: 4, minimum: 8 })
        ));
    }

    // ── Unacknowledged segmenter ──────────────────────────────────────────

    #[test]
    fn unack_multi_segment_sdu() {
        let sdu: Vec<u8> = (0u8..100).collect();
        let config = UnackSegmenterConfig {
            segment_payload_bits: 96,
            starting_n_s: 200,
        };
        let out = segment_unack_sdu(&sdu, &config).unwrap();

        let expected = (100usize * 8 + 32).div_ceil(96); // ceil(832/96) = 9
        assert_eq!(out.segment_count as usize, expected);
        assert_eq!(out.n_s_used, 200);

        for (i, pdu) in out.pdus.iter().enumerate() {
            assert_eq!(pdu.n_s, 200);
            assert_eq!(pdu.s_s as usize, i);
        }
        for pdu in &out.pdus[..expected - 1] {
            assert_eq!(pdu.variant, AlUdataVariant::Udata);
            assert!(pdu.fcs.is_none());
        }
        let last = out.pdus.last().unwrap();
        assert_eq!(last.variant, AlUdataVariant::Ufinal);
        assert!(last.fcs.is_some());
    }
}
