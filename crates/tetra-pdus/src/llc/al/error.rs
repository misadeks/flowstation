/// Errors returned by the Advanced Link segmentation and reassembly functions.
///
/// ETSI TS 100 392-2 v3.10.1 clause 21.2.
use std::fmt;

// ─── Segmentation errors ────────────────────────────────────────────────────

/// Error returned by [`crate::llc::al::segmenter::segment_sdu`] and
/// [`crate::llc::al::segmenter::segment_unack_sdu`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SegmentationError {
    /// The caller supplied a zero-length SDU.
    EmptySdu,
    /// The SDU + FCS bit count exceeds the N271 upper bound.
    SduTooLarge { bits: usize, max_bits: usize },
    /// The requested segment payload budget is below the 1-octet minimum.
    SegmentTooSmall { requested: usize, minimum: usize },
}

impl fmt::Display for SegmentationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SegmentationError::EmptySdu => write!(f, "SDU is empty"),
            SegmentationError::SduTooLarge { bits, max_bits } => {
                write!(f, "SDU too large: {} bits, maximum is {} bits", bits, max_bits)
            }
            SegmentationError::SegmentTooSmall { requested, minimum } => {
                write!(
                    f,
                    "Segment payload too small: {} bits requested, minimum is {} bits",
                    requested, minimum
                )
            }
        }
    }
}

impl std::error::Error for SegmentationError {}

// ─── Reassembly errors ──────────────────────────────────────────────────────

/// Error returned by [`crate::llc::al::reassembler::Reassembler::feed`] and
/// [`crate::llc::al::reassembler::UnackReassembler::feed`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReassemblyError {
    /// PDU N(S) does not match the reassembler's expected N(S).
    MismatchedNs { got: u8, expected: u8 },
    /// A second PDU with the same S(S) carries a different payload.
    ConflictingRetransmission { s_s: u8 },
    /// A segment arrived whose S(S) is beyond the already-received FINAL index.
    SegmentAfterFinal { got: u8, final_index: u8 },
    /// [`Reassembler::feed`] was called after `Complete` or `FcsFailure` was
    /// already returned.
    AlreadyDone,
}

impl fmt::Display for ReassemblyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReassemblyError::MismatchedNs { got, expected } => {
                write!(f, "Mismatched N(S): got {}, expected {}", got, expected)
            }
            ReassemblyError::ConflictingRetransmission { s_s } => {
                write!(f, "Conflicting retransmission for S(S)={}", s_s)
            }
            ReassemblyError::SegmentAfterFinal { got, final_index } => {
                write!(
                    f,
                    "Segment S(S)={} arrived after FINAL S(S)={}",
                    got, final_index
                )
            }
            ReassemblyError::AlreadyDone => {
                write!(f, "Reassembler already completed or failed; cannot accept more PDUs")
            }
        }
    }
}

impl std::error::Error for ReassemblyError {}
