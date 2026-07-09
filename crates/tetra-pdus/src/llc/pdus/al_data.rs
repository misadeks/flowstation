use core::fmt;

use tetra_core::BitBuffer;
use tetra_core::pdu_parse_error::*;
use tetra_core::let_field;

/// Discriminates between the four variants sharing LLC PDU type 9.
///
/// ETSI TS 100 392-2 v3.10.1 clauses 21.2.3.2 and 21.2.3.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlDataVariant {
    /// AL-DATA: non-final fragment, no ACK request.
    Data,
    /// AL-DATA-AR: non-final fragment, ACK requested.
    DataAr,
    /// AL-FINAL: last fragment of SDU, no ACK request.
    Final,
    /// AL-FINAL-AR: last fragment of SDU, ACK requested.
    FinalAr,
}

impl AlDataVariant {
    fn from_flags(final_flag: u64, ar_flag: u64) -> Self {
        match (final_flag != 0, ar_flag != 0) {
            (false, false) => AlDataVariant::Data,
            (false, true) => AlDataVariant::DataAr,
            (true, false) => AlDataVariant::Final,
            (true, true) => AlDataVariant::FinalAr,
        }
    }

    fn final_flag(self) -> u64 {
        match self {
            AlDataVariant::Data | AlDataVariant::DataAr => 0,
            AlDataVariant::Final | AlDataVariant::FinalAr => 1,
        }
    }

    fn ar_flag(self) -> u64 {
        match self {
            AlDataVariant::Data | AlDataVariant::Final => 0,
            AlDataVariant::DataAr | AlDataVariant::FinalAr => 1,
        }
    }

    /// Whether this variant marks the terminating fragment of an SDU.
    ///
    /// This does **not** imply a dedicated FCS wire field — the FCS is always
    /// carried inside `tl_sdu_segment` (possibly spanning segments). See the
    /// module-level docs for `AlDataAlFinal` and the reassembler.
    pub fn is_final(self) -> bool {
        matches!(self, AlDataVariant::Final | AlDataVariant::FinalAr)
    }
}

impl fmt::Display for AlDataVariant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AlDataVariant::Data => write!(f, "AL-DATA"),
            AlDataVariant::DataAr => write!(f, "AL-DATA-AR"),
            AlDataVariant::Final => write!(f, "AL-FINAL"),
            AlDataVariant::FinalAr => write!(f, "AL-FINAL-AR"),
        }
    }
}

/// AL-DATA / AL-FINAL / AL-DATA-AR / AL-FINAL-AR PDU — acknowledged information-carrying PDU.
///
/// AL-FINAL is the last fragment of an SDU; AL-DATA is a non-final fragment.
/// The -AR variants request an immediate AL-ACK.
///
/// **Wire layout has no dedicated FCS field.** Per ETSI TS 100 392-2 v3.10.1
/// (clauses 21.2.3.2 / 21.2.3.3 and tables 21.15 / 21.17), the 32-bit FCS is
/// appended to the SDU byte stream *before* segmentation and can therefore
/// spill into any fragment — including the FINAL. The codec treats everything
/// after the 17-bit header as `tl_sdu_segment`; extracting the FCS is the
/// reassembler's job (it recovers the last 32 bits of the concatenated
/// bit stream — see `al::reassembler::reconstruct_sdu`).
///
/// The `fcs: Option<u32>` field is a purely semantic hint: the segmenter fills
/// it on the FINAL PDU it emits for diagnostics/tests, and the reassembler
/// does not consult it. Encoders do not write it to the wire and decoders
/// always leave it `None`.
///
/// Wire layout after the 4-bit `LlcPduType` (= 9):
/// ```text
/// final_flag      1   0 = AL-DATA / AL-DATA-AR, 1 = AL-FINAL / AL-FINAL-AR
/// ar_flag         1   0 = no ACK request, 1 = ACK requested (-AR)
/// n_s             3   send sequence number, modulo (N272 + 1)
/// s_s             8   segment sequence number within the current SDU
/// tl_sdu_segment  *   remaining bits (may include FCS spillover)
/// ```
#[derive(Debug, Clone)]
pub struct AlDataAlFinal {
    /// Which of the four sub-variants this PDU represents.
    pub variant: AlDataVariant,
    /// Send sequence number, 3 bits (0..7), modulo (N272 + 1).
    pub n_s: u8,
    /// Segment sequence number within the current SDU, 8 bits (0..255).
    pub s_s: u8,
    /// The TL-SDU segment payload (bit-precise). For FINAL/FinalAr this may
    /// carry the trailing bits of the 32-bit FCS that was appended to the SDU
    /// before segmentation.
    pub tl_sdu_segment: BitBuffer,
    /// Semantic hint: the full 32-bit FCS the segmenter appended to this SDU.
    /// **Not** a wire field — the codec never reads or writes it. The
    /// reassembler recovers the FCS from the concatenated bit stream tail.
    pub fcs: Option<u32>,
}

impl PartialEq for AlDataAlFinal {
    fn eq(&self, other: &Self) -> bool {
        self.variant == other.variant
            && self.n_s == other.n_s
            && self.s_s == other.s_s
            && self.tl_sdu_segment.to_bitstr() == other.tl_sdu_segment.to_bitstr()
            && self.fcs == other.fcs
    }
}

impl Eq for AlDataAlFinal {}

impl AlDataAlFinal {
    /// Decode from a `BitBuffer` positioned immediately **after** the 4-bit `LlcPduType`.
    ///
    /// `pdu_len_bits`: total PDU length in bits **including** the 4-bit LLC type, as
    /// provided by the MAC layer. The buffer must contain exactly `pdu_len_bits - 4` bits;
    /// the decoder returns `PduParseErr::InconsistentLength` if the sizes do not match.
    ///
    /// All post-header bits are captured as `tl_sdu_segment`; FCS extraction is
    /// deferred to the reassembler (`al::reassembler`). See the type-level docs.
    pub fn from_bitbuf(buf: &mut BitBuffer, pdu_len_bits: usize) -> Result<Self, PduParseErr> {
        // Fixed bits: 4 (type) + 1 + 1 + 3 + 8 = 17.
        const HEADER_BITS: usize = 17;
        if pdu_len_bits < HEADER_BITS {
            return Err(PduParseErr::InconsistentLength {
                expected: HEADER_BITS,
                found: pdu_len_bits,
            });
        }

        // Validate buffer length against declared PDU size.
        let expected_body = pdu_len_bits - 4;
        if buf.get_len_remaining() != expected_body {
            return Err(PduParseErr::InconsistentLength {
                expected: expected_body,
                found: buf.get_len_remaining(),
            });
        }

        let_field!(buf, final_flag, 1);
        let_field!(buf, ar_flag, 1);
        let_field!(buf, n_s, 3);
        let_field!(buf, s_s, 8);

        let variant = AlDataVariant::from_flags(final_flag, ar_flag);

        // Everything after the 17-bit header is tl_sdu_segment. FCS spillover
        // (if any) rides inside these bits and is recovered downstream by the
        // reassembler from the tail of the concatenated stream.
        let sdu_len = pdu_len_bits - HEADER_BITS;
        let mut sdu = BitBuffer::new_autoexpand(sdu_len + 8);
        for _ in 0..sdu_len {
            let b = buf
                .read_bits(1)
                .ok_or(PduParseErr::BufferEnded { field: Some("tl_sdu_segment") })?;
            sdu.write_bits(b, 1);
        }
        sdu.seek(0);

        Ok(AlDataAlFinal { variant, n_s: n_s as u8, s_s: s_s as u8, tl_sdu_segment: sdu, fcs: None })
    }

    /// Encode into a `BitBuffer`, writing the 4-bit `LlcPduType` (9) first.
    ///
    /// The semantic `fcs` field is **not** written to the wire; any FCS bits
    /// live inside `tl_sdu_segment` (placed there by the segmenter).
    pub fn to_bitbuf(&self, buf: &mut BitBuffer) {
        // 4-bit LlcPduType = 9 (AlDataAlFinal)
        buf.write_bits(9, 4);
        buf.write_bits(self.variant.final_flag(), 1);
        buf.write_bits(self.variant.ar_flag(), 1);
        buf.write_bits(self.n_s as u64, 3);
        buf.write_bits(self.s_s as u64, 8);

        let sdu_len = self.tl_sdu_segment.get_len();
        let mut sdu_copy = BitBuffer::from_bitbuffer(&self.tl_sdu_segment);
        buf.copy_bits(&mut sdu_copy, sdu_len);
    }
}

impl fmt::Display for AlDataAlFinal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "al_data_al_final {{ variant: {}, n_s: {}, s_s: {}, sdu_len: {}, fcs: {:?} }}",
            self.variant,
            self.n_s,
            self.s_s,
            self.tl_sdu_segment.get_len(),
            self.fcs,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(pdu: &AlDataAlFinal) -> AlDataAlFinal {
        let mut enc = BitBuffer::new_autoexpand(256);
        pdu.to_bitbuf(&mut enc);
        let pdu_len_bits = enc.get_len_written();
        enc.seek(0);
        enc.read_bits(4).unwrap();
        AlDataAlFinal::from_bitbuf(&mut enc, pdu_len_bits).expect("decode failed")
    }

    fn make_sdu(bits: &str) -> BitBuffer {
        BitBuffer::from_bitstr(bits)
    }

    #[test]
    fn al_data_default_round_trip() {
        let pdu = AlDataAlFinal {
            variant: AlDataVariant::Data,
            n_s: 0,
            s_s: 0,
            tl_sdu_segment: make_sdu(""),
            fcs: None,
        };
        let d = round_trip(&pdu);
        assert_eq!(d.variant, pdu.variant);
        assert_eq!(d.n_s, 0);
        assert_eq!(d.s_s, 0);
        assert_eq!(d.tl_sdu_segment.get_len(), 0);
        assert_eq!(d.fcs, None);
    }

    #[test]
    fn al_final_ar_populated_round_trip() {
        // Semantic `fcs` is not a wire field — the segmenter fills it as a hint,
        // but decoders always leave it None. Round-trip preserves everything else.
        let pdu = AlDataAlFinal {
            variant: AlDataVariant::FinalAr,
            n_s: 7,
            s_s: 200,
            tl_sdu_segment: make_sdu("10110011"),
            fcs: Some(0xDEADBEEF),
        };
        let d = round_trip(&pdu);
        assert_eq!(d.variant, pdu.variant);
        assert_eq!(d.n_s, pdu.n_s);
        assert_eq!(d.s_s, pdu.s_s);
        assert_eq!(d.tl_sdu_segment.to_bitstr(), pdu.tl_sdu_segment.to_bitstr());
        assert_eq!(d.fcs, None, "decoder must not synthesise a wire FCS");
    }

    #[test]
    fn al_data_ar_round_trip() {
        let pdu = AlDataAlFinal {
            variant: AlDataVariant::DataAr,
            n_s: 3,
            s_s: 42,
            tl_sdu_segment: make_sdu("1100101011110000"),
            fcs: None,
        };
        let d = round_trip(&pdu);
        assert_eq!(d.variant, pdu.variant);
        assert_eq!(d.s_s, 42);
        assert_eq!(d.tl_sdu_segment.to_bitstr(), pdu.tl_sdu_segment.to_bitstr());
    }

    /// Regression for PD-5c-H9: the 48-bit AL-FINAL-AR captured on-air with a
    /// 31-bit tail (last few SDU bits + spilled FCS bits) previously failed
    /// with `InconsistentLength { expected: 32, found: 31 }`. It must parse.
    #[test]
    fn al_final_ar_short_tail_48bit_from_wire() {
        let wire = "100111000000100101110111010000011010001110101111";
        assert_eq!(wire.len(), 48);
        let mut buf = BitBuffer::from_bitstr(wire);
        let type_bits = buf.read_bits(4).unwrap();
        assert_eq!(type_bits, 9, "LlcPduType must be 9 (AlDataAlFinal)");

        let pdu = AlDataAlFinal::from_bitbuf(&mut buf, 48)
            .expect("short-tail AL-FINAL-AR must parse");

        assert_eq!(pdu.variant, AlDataVariant::FinalAr);
        assert_eq!(pdu.n_s, 0);
        assert_eq!(pdu.s_s, 18, "s_s == 18 (fragment 19, terminating 0..17)");
        assert_eq!(pdu.tl_sdu_segment.get_len(), 31);
        assert_eq!(
            pdu.tl_sdu_segment.to_bitstr(),
            "1110111010000011010001110101111"
        );
        assert_eq!(pdu.fcs, None);
    }

    /// A full-length non-final AL-DATA fragment (214-bit tl_sdu_segment) must
    /// still parse — the common hot path during SDU streaming.
    #[test]
    fn al_data_full_length_214bit_tail_still_parses() {
        let tail: String = (0..214).map(|i| if i % 3 == 0 { '1' } else { '0' }).collect();
        let pdu = AlDataAlFinal {
            variant: AlDataVariant::Data,
            n_s: 4,
            s_s: 7,
            tl_sdu_segment: make_sdu(&tail),
            fcs: None,
        };
        let d = round_trip(&pdu);
        assert_eq!(d.variant, AlDataVariant::Data);
        assert_eq!(d.n_s, 4);
        assert_eq!(d.s_s, 7);
        assert_eq!(d.tl_sdu_segment.get_len(), 214);
        assert_eq!(d.tl_sdu_segment.to_bitstr(), tail);
    }

    /// Round-trip AL-FINAL-AR at tail sizes 8, 100, 214. The encoded PDU length
    /// must be exactly `17 + tail_bits` — no phantom FCS on the wire.
    #[test]
    fn al_final_ar_round_trip_various_tail_sizes() {
        for &tail_bits in &[8usize, 100, 214] {
            let tail: String = (0..tail_bits)
                .map(|i| if (i * 7 + 3) % 5 < 3 { '1' } else { '0' })
                .collect();
            let pdu = AlDataAlFinal {
                variant: AlDataVariant::FinalAr,
                n_s: 2,
                s_s: (tail_bits % 256) as u8,
                tl_sdu_segment: make_sdu(&tail),
                fcs: Some(0xCAFEBABE),
            };

            let mut enc = BitBuffer::new_autoexpand(256);
            pdu.to_bitbuf(&mut enc);
            let encoded_len = enc.get_len_written();
            assert_eq!(
                encoded_len,
                17 + tail_bits,
                "encoded PDU must be 17-bit header + tail only (no phantom FCS) for tail={}",
                tail_bits
            );

            enc.seek(0);
            enc.read_bits(4).unwrap();
            let d = AlDataAlFinal::from_bitbuf(&mut enc, encoded_len)
                .expect("round-trip decode must succeed");
            assert_eq!(d.variant, AlDataVariant::FinalAr);
            assert_eq!(d.n_s, 2);
            assert_eq!(d.s_s, (tail_bits % 256) as u8);
            assert_eq!(d.tl_sdu_segment.get_len(), tail_bits);
            assert_eq!(d.tl_sdu_segment.to_bitstr(), tail);
            assert_eq!(d.fcs, None);
        }
    }
}
