/// Advanced Link SDU reassembly.
///
/// Buffers inbound AL-DATA / AL-FINAL (or AL-UDATA / AL-UFINAL) segments,
/// handles out-of-order delivery, detects conflicting retransmissions, and
/// validates the 32-bit FCS on completion.
///
/// One [`Reassembler`] (or [`UnackReassembler`]) instance is created per
/// (link-id, N(S)) tuple.  The AL state machine (AL-3) owns a
/// `HashMap<(LinkId, u8), Reassembler>`.
///
/// The FCS is recovered from the **tail of the concatenated bit stream**
/// (last 32 bits of all assembled `tl_sdu_segment`s), *not* from the codec's
/// semantic `fcs: Option<u32>` field. This matches the ETSI wire layout, where
/// the FCS is appended to the SDU before segmentation and can therefore span
/// segment boundaries or sit entirely inside the FINAL fragment
/// (ETSI TS 100 392-2 v3.10.1 table 21.17, note 2).
///
/// ETSI TS 100 392-2 v3.10.1 clauses 21.2.3.2, 21.2.3.3, 21.2.3.6, 21.2.3.7.

use tetra_core::BitBuffer;

use crate::llc::pdus::al_data::{AlDataAlFinal, AlDataVariant};
use crate::llc::pdus::al_udata::AlAlUdataAlUfinal;
use super::error::ReassemblyError;
use super::fcs::crc32_bits;

// ─── Shared helpers ──────────────────────────────────────────────────────────

/// Extract all bits from a `BitBuffer` (reading from position 0) into a
/// bitvec (one `u8` per bit, value 0 or 1, MSB first).
fn bitbuffer_to_bitvec(bb: &BitBuffer) -> Vec<u8> {
    let len = bb.get_len();
    if len == 0 {
        return Vec::new();
    }
    let mut copy = BitBuffer::from_bitbuffer(bb);
    let mut bits = Vec::with_capacity(len);
    for _ in 0..len {
        bits.push(copy.read_bit().unwrap_or(0));
    }
    bits
}

/// Details returned when the concatenated bit stream fails FCS verification.
///
/// All three values are surfaced to the caller (the LLC entity) so hardware
/// bring-up logs can pinpoint whether the mismatch is a CRC variant issue,
/// a bit-range issue, or a genuine wire error.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct FcsFailureInfo {
    /// Total length of the concatenated `tl_sdu_segment` bit stream.
    pub assembled_len: usize,
    /// The 32-bit value read from the tail of the assembled stream.
    pub extracted_fcs: u32,
    /// The 32-bit value computed by `crc32_bits` over `assembled[..len - 32]`.
    pub computed_fcs: u32,
}

/// Attempt to reconstruct the SDU + validate FCS from a complete, contiguous
/// bitvec (`0..=fi` segments concatenated).
///
/// TETRA's AL is bit-transparent (see `fcs::crc32_bits` and ETSI
/// TS 100 392-2 v3.10.1 clause 21.4.4): the TL-SDU may be any bit-length,
/// the 32-bit FCS is bit-serially computed over the exact TL-SDU bit-length,
/// and the concatenated on-wire stream is `TL-SDU-bits ++ FCS-bits`.
///
/// Returns `Ok(BitBuffer)` on FCS match (holding the recovered TL-SDU bits),
/// or `Err(FcsFailureInfo)` on FCS failure / malformed input.
fn reconstruct_sdu(all_bits: &[u8]) -> Result<BitBuffer, FcsFailureInfo> {
    let assembled_len = all_bits.len();
    if assembled_len < 32 {
        return Err(FcsFailureInfo {
            assembled_len,
            extracted_fcs: 0,
            computed_fcs: 0,
        });
    }
    let split = assembled_len - 32;

    let extracted_fcs =
        all_bits[split..].iter().fold(0u32, |acc, &b| (acc << 1) | (b as u32));

    let sdu_bits = &all_bits[..split];
    let computed_fcs = crc32_bits(sdu_bits);

    if extracted_fcs != computed_fcs {
        tracing::debug!(
            assembled_len,
            extracted_fcs = format!("0x{:08X}", extracted_fcs),
            computed_fcs = format!("0x{:08X}", computed_fcs),
            "AL FCS mismatch"
        );
        return Err(FcsFailureInfo { assembled_len, extracted_fcs, computed_fcs });
    }

    // Rebuild the SDU as a BitBuffer, preserving its exact bit-length
    // (may be non-byte-aligned; TETRA AL is bit-transparent). Size the
    // backing storage to exactly the SDU bit length so `into_bytes()` on
    // a byte-aligned SDU returns the original byte count with no trailing
    // padding byte.
    let mut sdu = BitBuffer::new_autoexpand(sdu_bits.len());
    for &b in sdu_bits {
        sdu.write_bits(b as u64, 1);
    }
    sdu.seek(0);
    Ok(sdu)
}

// ─── Acknowledged reassembler ────────────────────────────────────────────────

/// Result returned from [`Reassembler::feed`].
#[derive(Debug)]
pub enum ReassemblerFeed {
    /// PDU accepted; more segments are still needed before the SDU is complete.
    NeedMore { received_count: u8, missing_indices: Vec<u8> },
    /// SDU reassembled and FCS validated.  The recovered TL-SDU bits (may be
    /// non-byte-aligned; TETRA's AL is bit-transparent) are returned as a
    /// [`BitBuffer`] with the read cursor at 0.
    Complete { sdu: BitBuffer },
    /// SDU reassembly completed but FCS validation failed; the SDU is discarded.
    /// The failure details are surfaced for diagnostic logging.
    FcsFailure { received_count: u8, info: FcsFailureInfo },
}

impl PartialEq for ReassemblerFeed {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Self::NeedMore { received_count: a, missing_indices: b },
                Self::NeedMore { received_count: c, missing_indices: d },
            ) => a == c && b == d,
            (Self::Complete { sdu: a }, Self::Complete { sdu: b }) => {
                a.to_bitstr() == b.to_bitstr()
            }
            (
                Self::FcsFailure { received_count: a, info: b },
                Self::FcsFailure { received_count: c, info: d },
            ) => a == c && b == d,
            _ => false,
        }
    }
}

/// Per-(link, N(S)) reassembly context for the acknowledged AL service.
///
/// The AL state machine (AL-3) owns one instance per in-flight SDU.
pub struct Reassembler {
    /// Expected N(S) for all PDUs belonging to this SDU.
    n_s: u8,
    /// Received segment bit vectors, indexed by S(S).  `None` = hole.
    segments: Vec<Option<Vec<u8>>>,
    /// Set when an AL-FINAL or AL-FINAL-AR PDU is received.
    final_segment_index: Option<u8>,
    /// FCS value extracted from the FINAL PDU's semantic `fcs` field.
    /// Stored for potential debugging; validation uses the bit-stream tail.
    fcs: Option<u32>,
    /// True once `Complete` or `FcsFailure` has been returned.
    done: bool,
}

impl Reassembler {
    /// Create a new reassembler for the SDU identified by `n_s`.
    pub fn new(n_s: u8) -> Self {
        Reassembler {
            n_s,
            segments: Vec::new(),
            final_segment_index: None,
            fcs: None,
            done: false,
        }
    }

    /// Feed an inbound AL-DATA / AL-FINAL PDU into the reassembler.
    ///
    /// # Errors
    /// - [`ReassemblyError::AlreadyDone`] — called after `Complete`/`FcsFailure`.
    /// - [`ReassemblyError::MismatchedNs`] — PDU belongs to a different SDU.
    /// - [`ReassemblyError::SegmentAfterFinal`] — S(S) beyond the known FINAL.
    /// - [`ReassemblyError::ConflictingRetransmission`] — same S(S), different payload.
    pub fn feed(&mut self, pdu: &AlDataAlFinal) -> Result<ReassemblerFeed, ReassemblyError> {
        if self.done {
            return Err(ReassemblyError::AlreadyDone);
        }
        if pdu.n_s != self.n_s {
            return Err(ReassemblyError::MismatchedNs { got: pdu.n_s, expected: self.n_s });
        }

        let s_s = pdu.s_s;

        // Reject segments past the known FINAL boundary.
        if let Some(fi) = self.final_segment_index {
            if s_s > fi {
                return Err(ReassemblyError::SegmentAfterFinal { got: s_s, final_index: fi });
            }
        }

        // Grow the segment store if needed.
        if s_s as usize >= self.segments.len() {
            self.segments.resize(s_s as usize + 1, None);
        }

        let new_bits = bitbuffer_to_bitvec(&pdu.tl_sdu_segment);

        match &self.segments[s_s as usize] {
            Some(existing) if *existing == new_bits => {
                // Idempotent duplicate — accepted silently (acknowledged retransmission).
            }
            Some(_) => {
                return Err(ReassemblyError::ConflictingRetransmission { s_s });
            }
            None => {
                self.segments[s_s as usize] = Some(new_bits);
            }
        }

        // Record FINAL boundary and FCS semantic field.
        let is_final =
            matches!(pdu.variant, AlDataVariant::Final | AlDataVariant::FinalAr);
        if is_final {
            self.final_segment_index = Some(s_s);
            self.fcs = pdu.fcs;
            // Trim any segments stored beyond the FINAL index (shouldn't happen
            // under normal operation but keeps state consistent).
            self.segments.truncate(s_s as usize + 1);
        }

        self.try_reassemble()
    }

    /// True once [`feed`](Self::feed) has returned `Complete` or `FcsFailure`.
    pub fn is_done(&self) -> bool {
        self.done
    }

    /// S(S) values for which no segment has been received yet, useful for
    /// building the bitmap in an AL-ACK PDU.
    pub fn missing_segments(&self) -> Vec<u8> {
        self.missing_indices_internal()
    }

    /// The smallest missing S(S) value, corresponding to the S(R) "oldest
    /// not-yet-received" field in an [`AlAckAlRnr`](crate::llc::pdus::al_ack::AlAckAlRnr).
    pub fn oldest_missing(&self) -> Option<u8> {
        self.missing_indices_internal().into_iter().next()
    }

    /// Next S(S) we expect to receive: the smallest missing index in the
    /// current window, or `segments.len()` when the received prefix is
    /// contiguous (no gaps).
    ///
    /// This is the correct value for the S(R) field of a cumulative AL-ACK
    /// while the SDU is still being reassembled (`ReassemblerFeed::NeedMore`).
    /// It says "I have received every S(S) below this value; please send this
    /// one next."  It is **never** the sentinel `SR::RestOfSduReceived`
    /// (0b1111_1010 = 250) — that value is reserved for full-SDU confirmation
    /// and would falsely tell the peer the SDU is complete.
    ///
    /// ETSI TS 100 392-2 v3.10.1 clause 21.2.3.1.
    pub fn next_expected_ss(&self) -> u8 {
        self.missing_indices_internal()
            .into_iter()
            .next()
            .unwrap_or(self.segments.len() as u8)
    }

    fn missing_indices_internal(&self) -> Vec<u8> {
        let end = match self.final_segment_index {
            Some(fi) => fi as usize + 1,
            None => self.segments.len(),
        };
        (0..end)
            .filter(|&i| !matches!(self.segments.get(i), Some(Some(_))))
            .map(|i| i as u8)
            .collect()
    }

    fn received_count(&self) -> u8 {
        self.segments.iter().filter(|s| s.is_some()).count() as u8
    }

    /// Attempt to complete reassembly; called after every segment insertion.
    fn try_reassemble(&mut self) -> Result<ReassemblerFeed, ReassemblyError> {
        let received = self.received_count();

        let Some(fi) = self.final_segment_index else {
            let missing = self.missing_indices_internal();
            return Ok(ReassemblerFeed::NeedMore {
                received_count: received,
                missing_indices: missing,
            });
        };

        // Check every slot 0..=fi is filled.
        let all_present = (0..=(fi as usize))
            .all(|i| matches!(self.segments.get(i), Some(Some(_))));

        if !all_present {
            let missing = self.missing_indices_internal();
            return Ok(ReassemblerFeed::NeedMore {
                received_count: received,
                missing_indices: missing,
            });
        }

        // Concatenate all bit vectors.
        let mut all_bits: Vec<u8> = Vec::new();
        for i in 0..=(fi as usize) {
            all_bits.extend_from_slice(self.segments[i].as_ref().unwrap());
        }

        self.done = true;
        match reconstruct_sdu(&all_bits) {
            Ok(sdu) => Ok(ReassemblerFeed::Complete { sdu }),
            Err(info) => Ok(ReassemblerFeed::FcsFailure { received_count: received, info }),
        }
    }
}

// ─── Unacknowledged reassembler ──────────────────────────────────────────────

/// Result returned from [`UnackReassembler::feed`].
#[derive(Debug)]
pub enum UnackReassemblerFeed {
    /// PDU accepted; more segments are still needed.
    NeedMore { received_count: u8 },
    /// SDU reassembled and FCS validated.
    Complete { sdu: BitBuffer },
    /// SDU reassembly completed but FCS validation failed.
    FcsFailure { received_count: u8, info: FcsFailureInfo },
    /// SDU discarded by a state-machine timeout before all segments arrived.
    Discarded { received_count: u8, missing_count: u8 },
}

impl PartialEq for UnackReassemblerFeed {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Self::NeedMore { received_count: a },
                Self::NeedMore { received_count: b },
            ) => a == b,
            (Self::Complete { sdu: a }, Self::Complete { sdu: b }) => {
                a.to_bitstr() == b.to_bitstr()
            }
            (
                Self::FcsFailure { received_count: a, info: b },
                Self::FcsFailure { received_count: c, info: d },
            ) => a == c && b == d,
            (
                Self::Discarded { received_count: a, missing_count: b },
                Self::Discarded { received_count: c, missing_count: d },
            ) => a == c && b == d,
            _ => false,
        }
    }
}

/// Per-(link, N(S)) reassembly context for the unacknowledged AL service.
///
/// There is no retransmission on the unack path; any duplicate segment is
/// treated as a protocol error rather than an idempotent retransmission.
pub struct UnackReassembler {
    n_s: u8,
    segments: Vec<Option<Vec<u8>>>,
    final_segment_index: Option<u8>,
    fcs: Option<u32>,
    done: bool,
}

impl UnackReassembler {
    /// Create a new unacknowledged reassembler for the SDU identified by `n_s`.
    pub fn new(n_s: u8) -> Self {
        UnackReassembler {
            n_s,
            segments: Vec::new(),
            final_segment_index: None,
            fcs: None,
            done: false,
        }
    }

    /// Feed an inbound AL-UDATA / AL-UFINAL PDU.
    ///
    /// Unlike the acknowledged path, duplicate segments are **not** tolerated
    /// (no retransmission on the unack service).
    ///
    /// # Errors
    /// - [`ReassemblyError::AlreadyDone`]
    /// - [`ReassemblyError::MismatchedNs`]
    /// - [`ReassemblyError::SegmentAfterFinal`]
    /// - [`ReassemblyError::ConflictingRetransmission`] — any duplicate S(S).
    pub fn feed(
        &mut self,
        pdu: &AlAlUdataAlUfinal,
    ) -> Result<UnackReassemblerFeed, ReassemblyError> {
        if self.done {
            return Err(ReassemblyError::AlreadyDone);
        }
        if pdu.n_s != self.n_s {
            return Err(ReassemblyError::MismatchedNs { got: pdu.n_s, expected: self.n_s });
        }

        let s_s = pdu.s_s;

        if let Some(fi) = self.final_segment_index {
            if s_s > fi {
                return Err(ReassemblyError::SegmentAfterFinal { got: s_s, final_index: fi });
            }
        }

        if s_s as usize >= self.segments.len() {
            self.segments.resize(s_s as usize + 1, None);
        }

        let new_bits = bitbuffer_to_bitvec(&pdu.tl_sdu_segment);

        // No idempotent tolerance on the unack path.
        if self.segments[s_s as usize].is_some() {
            return Err(ReassemblyError::ConflictingRetransmission { s_s });
        }
        self.segments[s_s as usize] = Some(new_bits);

        use crate::llc::pdus::al_udata::AlUdataVariant;
        if pdu.variant == AlUdataVariant::Ufinal {
            self.final_segment_index = Some(s_s);
            self.fcs = pdu.fcs;
            self.segments.truncate(s_s as usize + 1);
        }

        self.try_reassemble()
    }

    /// Discard this reassembly context (called by the state machine's SDU timeout).
    ///
    /// Transitions the reassembler to the done state and returns a count of
    /// received vs missing segments for logging.
    pub fn discard(&mut self) -> UnackReassemblerFeed {
        let received_count = self.segments.iter().filter(|s| s.is_some()).count() as u8;
        let end = match self.final_segment_index {
            Some(fi) => fi as usize + 1,
            None => self.segments.len(),
        };
        let missing_count = (0..end)
            .filter(|&i| !matches!(self.segments.get(i), Some(Some(_))))
            .count() as u8;
        self.done = true;
        UnackReassemblerFeed::Discarded { received_count, missing_count }
    }

    fn received_count(&self) -> u8 {
        self.segments.iter().filter(|s| s.is_some()).count() as u8
    }

    fn try_reassemble(&mut self) -> Result<UnackReassemblerFeed, ReassemblyError> {
        let received = self.received_count();

        let Some(fi) = self.final_segment_index else {
            return Ok(UnackReassemblerFeed::NeedMore { received_count: received });
        };

        let all_present = (0..=(fi as usize))
            .all(|i| matches!(self.segments.get(i), Some(Some(_))));

        if !all_present {
            return Ok(UnackReassemblerFeed::NeedMore { received_count: received });
        }

        let mut all_bits: Vec<u8> = Vec::new();
        for i in 0..=(fi as usize) {
            all_bits.extend_from_slice(self.segments[i].as_ref().unwrap());
        }

        self.done = true;
        match reconstruct_sdu(&all_bits) {
            Ok(sdu) => Ok(UnackReassemblerFeed::Complete { sdu }),
            Err(info) => Ok(UnackReassemblerFeed::FcsFailure { received_count: received, info }),
        }
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::llc::al::segmenter::{
        SegmenterConfig, UnackSegmenterConfig, segment_sdu, segment_unack_sdu,
    };

    // ── Acknowledged reassembler ──────────────────────────────────────────

    /// Expand `bytes` into an MSB-first bit string (each byte → 8 chars).
    fn bytes_to_bitstr(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 8);
        for &b in bytes {
            for i in (0..8).rev() {
                s.push(if (b >> i) & 1 == 1 { '1' } else { '0' });
            }
        }
        s
    }

    #[test]
    fn ack_reassemble_in_order() {
        let sdu: Vec<u8> = (0u8..200).collect();
        let config = SegmenterConfig {
            segment_payload_bits: 400,
            starting_n_s: 2,
            request_ack_on_final: false,
            request_ack_on_data: false,
        };
        let out = segment_sdu(&sdu, &config).unwrap();

        let mut r = Reassembler::new(2);
        let last = out.pdus.len() - 1;
        for (i, pdu) in out.pdus.iter().enumerate() {
            let result = r.feed(pdu).unwrap();
            if i == last {
                match result {
                    ReassemblerFeed::Complete { sdu: recovered } => {
                        assert_eq!(recovered.to_bitstr(), bytes_to_bitstr(&sdu));
                    }
                    other => panic!("expected Complete, got {:?}", other),
                }
            } else {
                assert!(
                    matches!(result, ReassemblerFeed::NeedMore { .. }),
                    "expected NeedMore for segment {}", i
                );
            }
        }
        assert!(r.is_done());
    }

    #[test]
    fn ack_reassemble_out_of_order() {
        let sdu: Vec<u8> = (0u8..200).collect();
        let config = SegmenterConfig {
            segment_payload_bits: 400,
            starting_n_s: 0,
            request_ack_on_final: false,
            request_ack_on_data: false,
        };
        let out = segment_sdu(&sdu, &config).unwrap();

        // Feed in reverse order.
        let mut r = Reassembler::new(0);
        let n = out.pdus.len();
        for pdu in out.pdus.iter().rev() {
            let result = r.feed(pdu).unwrap();
            // Complete only when the very last missing piece (s_s=0) is delivered.
            if pdu.s_s == 0 {
                match result {
                    ReassemblerFeed::Complete { sdu: recovered } => {
                        assert_eq!(recovered.to_bitstr(), bytes_to_bitstr(&sdu));
                    }
                    other => panic!("expected Complete after last segment, got {:?}", other),
                }
            } else {
                // Either NeedMore (FINAL not yet seen) or NeedMore (holes remain).
                assert!(
                    matches!(result, ReassemblerFeed::NeedMore { .. }),
                    "segment {} of {}: expected NeedMore", pdu.s_s, n
                );
            }
        }
    }

    #[test]
    fn ack_reassemble_with_duplicate() {
        let sdu = b"duplicate test payload";
        let config = SegmenterConfig {
            segment_payload_bits: 80,
            starting_n_s: 1,
            request_ack_on_final: false,
            request_ack_on_data: false,
        };
        let out = segment_sdu(sdu, &config).unwrap();

        let mut r = Reassembler::new(1);
        // Feed first segment twice — must be idempotent.
        r.feed(&out.pdus[0]).unwrap();
        r.feed(&out.pdus[0]).unwrap(); // duplicate — must not error

        // Feed remaining segments.
        let last = out.pdus.len() - 1;
        for (i, pdu) in out.pdus.iter().enumerate().skip(1) {
            let result = r.feed(pdu).unwrap();
            if i == last {
                assert!(matches!(result, ReassemblerFeed::Complete { .. }));
            }
        }
    }

    #[test]
    fn ack_conflicting_retransmission_rejected() {
        let sdu = b"original payload";
        let config = SegmenterConfig {
            segment_payload_bits: 80,
            starting_n_s: 0,
            request_ack_on_final: false,
            request_ack_on_data: false,
        };
        let out = segment_sdu(sdu, &config).unwrap();

        // Build a second PDU for s_s=0 with a modified payload.
        let mut corrupted = out.pdus[0].clone();
        let original_bits = corrupted.tl_sdu_segment.to_bitstr();
        // Flip the first bit.
        let flipped: String = original_bits
            .chars()
            .enumerate()
            .map(|(i, c)| if i == 0 { if c == '0' { '1' } else { '0' } } else { c })
            .collect();
        corrupted.tl_sdu_segment = BitBuffer::from_bitstr(&flipped);

        let mut r = Reassembler::new(0);
        r.feed(&out.pdus[0]).unwrap();

        // Second feed with a different payload for the same S(S).
        assert_eq!(
            r.feed(&corrupted),
            Err(ReassemblyError::ConflictingRetransmission { s_s: 0 })
        );
    }

    #[test]
    fn ack_fcs_corruption_detected() {
        let sdu: Vec<u8> = (0u8..50).collect();
        let config = SegmenterConfig {
            segment_payload_bits: 128,
            starting_n_s: 4,
            request_ack_on_final: false,
            request_ack_on_data: false,
        };
        let mut out = segment_sdu(&sdu, &config).unwrap();
        assert!(out.pdus.len() >= 2, "need at least 2 segments for this test");

        // Corrupt a bit in the first segment's payload.
        let bits = out.pdus[0].tl_sdu_segment.to_bitstr();
        let flipped: String = bits
            .chars()
            .enumerate()
            .map(|(i, c)| if i == 0 { if c == '0' { '1' } else { '0' } } else { c })
            .collect();
        out.pdus[0].tl_sdu_segment = BitBuffer::from_bitstr(&flipped);

        let mut r = Reassembler::new(4);
        let last = out.pdus.len() - 1;
        for (i, pdu) in out.pdus.iter().enumerate() {
            let result = r.feed(pdu).unwrap();
            if i == last {
                assert!(
                    matches!(result, ReassemblerFeed::FcsFailure { .. }),
                    "expected FcsFailure for corrupted SDU, got {:?}", result
                );
            }
        }
    }

    #[test]
    fn ack_mismatched_ns_rejected() {
        let sdu = b"ns mismatch test";
        let config = SegmenterConfig {
            segment_payload_bits: 128,
            starting_n_s: 3,
            request_ack_on_final: false,
            request_ack_on_data: false,
        };
        let out = segment_sdu(sdu, &config).unwrap();

        let mut r = Reassembler::new(5); // expects N(S)=5 but PDU has N(S)=3
        assert_eq!(
            r.feed(&out.pdus[0]),
            Err(ReassemblyError::MismatchedNs { got: 3, expected: 5 })
        );
    }

    // ── Bit-aligned reassembly (mirrors hardware bring-up trace PD-5c-H11) ─

    /// Regression test for the hardware bring-up failure where a live MS sent
    /// 18 × 214-bit AL-DATA + 1 × 31-bit AL-FINAL-AR = 3883 bits total. The
    /// concatenated TL-SDU is 3851 bits — not byte-aligned. The reassembler
    /// must bit-serially CRC the 3851-bit body against the trailing 32-bit
    /// FCS and return the recovered bits without requiring byte alignment.
    #[test]
    fn ack_reassemble_non_byte_aligned_sdu() {
        use crate::llc::al::fcs::crc32_bits;

        // Build a deterministic 3851-bit body (arbitrary bit content).
        let body_bits: Vec<u8> = (0..3851u32).map(|i| ((i * 5 + 3) & 1) as u8).collect();
        let fcs = crc32_bits(&body_bits);

        // Concatenate body + 32-bit FCS MSB-first.
        let mut stream = body_bits.clone();
        for i in (0..32).rev() {
            stream.push(((fcs >> i) & 1) as u8);
        }
        assert_eq!(stream.len(), 3883);

        // Slice into 18 × 214 + 1 × 31 fragments, matching the trace shape.
        let mut pdus: Vec<AlDataAlFinal> = Vec::with_capacity(19);
        let mut cursor = 0usize;
        for s_s in 0..18u8 {
            let seg = &stream[cursor..cursor + 214];
            let mut buf = BitBuffer::new_autoexpand(214);
            for &b in seg {
                buf.write_bits(b as u64, 1);
            }
            buf.seek(0);
            pdus.push(AlDataAlFinal {
                variant: AlDataVariant::Data,
                n_s: 0,
                s_s,
                tl_sdu_segment: buf,
                fcs: None,
            });
            cursor += 214;
        }
        // FINAL-AR: 31 bits.
        let final_seg = &stream[cursor..];
        assert_eq!(final_seg.len(), 31);
        let mut fbuf = BitBuffer::new_autoexpand(31);
        for &b in final_seg {
            fbuf.write_bits(b as u64, 1);
        }
        fbuf.seek(0);
        pdus.push(AlDataAlFinal {
            variant: AlDataVariant::FinalAr,
            n_s: 0,
            s_s: 18,
            tl_sdu_segment: fbuf,
            fcs: Some(fcs),
        });

        // Feed every fragment in order.
        let mut r = Reassembler::new(0);
        let last = pdus.len() - 1;
        for (i, pdu) in pdus.iter().enumerate() {
            let result = r.feed(pdu).unwrap();
            if i == last {
                match result {
                    ReassemblerFeed::Complete { sdu: recovered } => {
                        assert_eq!(recovered.get_len(), 3851);
                        let recovered_bits: String = recovered.to_bitstr();
                        let expected_bits: String = body_bits
                            .iter()
                            .map(|&b| if b == 1 { '1' } else { '0' })
                            .collect();
                        assert_eq!(recovered_bits, expected_bits);
                    }
                    other => panic!(
                        "expected Complete on non-byte-aligned SDU, got {:?}",
                        other
                    ),
                }
            } else {
                assert!(matches!(result, ReassemblerFeed::NeedMore { .. }));
            }
        }
    }

    // ── Unacknowledged reassembler ────────────────────────────────────────

    #[test]
    fn unack_reassemble_in_order() {
        let sdu: Vec<u8> = (0u8..100).collect();
        let config = UnackSegmenterConfig {
            segment_payload_bits: 200,
            starting_n_s: 42,
        };
        let out = segment_unack_sdu(&sdu, &config).unwrap();

        let mut r = UnackReassembler::new(42);
        let last = out.pdus.len() - 1;
        for (i, pdu) in out.pdus.iter().enumerate() {
            let result = r.feed(pdu).unwrap();
            if i == last {
                match result {
                    UnackReassemblerFeed::Complete { sdu: recovered } => {
                        assert_eq!(recovered.to_bitstr(), bytes_to_bitstr(&sdu));
                    }
                    other => panic!("expected Complete, got {:?}", other),
                }
            } else {
                assert!(matches!(result, UnackReassemblerFeed::NeedMore { .. }));
            }
        }
    }

    #[test]
    fn unack_conflicting_retransmission_rejected() {
        let sdu = b"unack no dup";
        let config = UnackSegmenterConfig {
            segment_payload_bits: 80,
            starting_n_s: 10,
        };
        let out = segment_unack_sdu(sdu, &config).unwrap();

        let mut r = UnackReassembler::new(10);
        r.feed(&out.pdus[0]).unwrap();

        // Exact duplicate on unack path → error (no idempotent tolerance).
        assert_eq!(
            r.feed(&out.pdus[0]),
            Err(ReassemblyError::ConflictingRetransmission { s_s: 0 })
        );
    }

    #[test]
    fn unack_discard_returns_incomplete() {
        let sdu: Vec<u8> = (0u8..100).collect();
        let config = UnackSegmenterConfig {
            segment_payload_bits: 200,
            starting_n_s: 7,
        };
        let out = segment_unack_sdu(&sdu, &config).unwrap();
        let n = out.pdus.len();
        assert!(n >= 2);

        let mut r = UnackReassembler::new(7);
        // Feed only the FINAL PDU so `final_segment_index` is known, then
        // immediately discard; the missing_count should reflect all the
        // segments that precede it.
        r.feed(&out.pdus[n - 1]).unwrap();

        let result = r.discard();
        match result {
            UnackReassemblerFeed::Discarded { received_count, missing_count } => {
                assert_eq!(received_count, 1, "only the FINAL segment was received");
                assert!(missing_count > 0, "all preceding segments are missing");
            }
            other => panic!("expected Discarded, got {:?}", other),
        }
        assert!(r.done);
    }

    // ── next_expected_ss helper (for cumulative AL-ACK S(R)) ──────────────

    fn ns_pdu(n_s: u8, s_s: u8) -> AlDataAlFinal {
        AlDataAlFinal {
            variant: AlDataVariant::Data,
            n_s,
            s_s,
            tl_sdu_segment: BitBuffer::from_bitstr("10101010"),
            fcs: None,
        }
    }

    #[test]
    fn next_expected_ss_empty() {
        let r = Reassembler::new(0);
        assert_eq!(r.next_expected_ss(), 0);
    }

    #[test]
    fn next_expected_ss_no_gap() {
        let mut r = Reassembler::new(0);
        r.feed(&ns_pdu(0, 0)).unwrap();
        r.feed(&ns_pdu(0, 1)).unwrap();
        r.feed(&ns_pdu(0, 2)).unwrap();
        // Contiguous 0..3 received, no FINAL → next expected is 3.
        assert_eq!(r.next_expected_ss(), 3);
        // And crucially it is NOT the RestOfSduReceived sentinel value (250).
        assert_ne!(r.next_expected_ss(), 250);
    }

    #[test]
    fn next_expected_ss_with_gap() {
        let mut r = Reassembler::new(0);
        r.feed(&ns_pdu(0, 0)).unwrap();
        r.feed(&ns_pdu(0, 2)).unwrap();
        // Segments 0 and 2 received, gap at 1 → next expected is 1.
        assert_eq!(r.next_expected_ss(), 1);
    }
}
