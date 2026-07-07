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

    fn has_fcs(self) -> bool {
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
/// FCS (32 bits) is **implicitly** present iff the variant is `Final` or `FinalAr`.
/// There is **no length field** in the PDU; segment length is determined by the MAC
/// block size. The caller must supply `pdu_len_bits` (total PDU bits including the
/// 4-bit LLC type) so the decoder can locate the FCS boundary.
///
/// NOTE: per the decompile, FCS may spill from a preceding AL-DATA when the last
/// user segment does not align to a MAC block boundary. AL-1 codec does not model
/// that spillover; the FCS is treated as belonging entirely to the FINAL PDU.
///
/// ETSI TS 100 392-2 v3.10.1 clauses 21.2.3.2 and 21.2.3.3.
///
/// Wire layout after the 4-bit `LlcPduType` (= 9):
/// ```text
/// final_flag      1   0 = AL-DATA / AL-DATA-AR, 1 = AL-FINAL / AL-FINAL-AR
/// ar_flag         1   0 = no ACK request, 1 = ACK requested (-AR)
/// n_s             3   send sequence number, modulo (N272 + 1)
/// s_s             8   segment sequence number within the current SDU
/// tl_sdu_segment  *   remaining bits (minus 32 iff Final/FinalAr)
/// fcs            32   conditional: present iff Final or FinalAr
/// ```
#[derive(Debug, Clone)]
pub struct AlDataAlFinal {
    /// Which of the four sub-variants this PDU represents.
    pub variant: AlDataVariant,
    /// Send sequence number, 3 bits (0..7), modulo (N272 + 1).
    pub n_s: u8,
    /// Segment sequence number within the current SDU, 8 bits (0..255).
    pub s_s: u8,
    /// The TL-SDU segment payload (bit-precise).
    pub tl_sdu_segment: BitBuffer,
    /// Optional Frame Check Sequence (32 bits), present iff variant is Final or FinalAr.
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
    pub fn from_bitbuf(buf: &mut BitBuffer, pdu_len_bits: usize) -> Result<Self, PduParseErr> {
        // Validate buffer length against declared PDU size.
        let expected_body = pdu_len_bits.saturating_sub(4);
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

        // Fixed bits: 4 (type) + 1 + 1 + 3 + 8 = 17.
        const HEADER_BITS: usize = 17;
        if pdu_len_bits < HEADER_BITS {
            return Err(PduParseErr::InconsistentLength {
                expected: HEADER_BITS,
                found: pdu_len_bits,
            });
        }
        let payload_and_fcs = pdu_len_bits - HEADER_BITS;

        let (sdu, fcs) = if variant.has_fcs() {
            if payload_and_fcs < 32 {
                return Err(PduParseErr::InconsistentLength {
                    expected: 32,
                    found: payload_and_fcs,
                });
            }
            let sdu_len = payload_and_fcs - 32;
            let mut sdu = BitBuffer::new_autoexpand(sdu_len + 8);
            for _ in 0..sdu_len {
                let b = buf
                    .read_bits(1)
                    .ok_or(PduParseErr::BufferEnded { field: Some("tl_sdu_segment") })?;
                sdu.write_bits(b, 1);
            }
            sdu.seek(0);
            let fcs_raw = buf
                .read_bits(32)
                .ok_or(PduParseErr::BufferEnded { field: Some("fcs") })?;
            (sdu, Some(fcs_raw as u32))
        } else {
            let sdu_len = payload_and_fcs;
            let mut sdu = BitBuffer::new_autoexpand(sdu_len + 8);
            for _ in 0..sdu_len {
                let b = buf
                    .read_bits(1)
                    .ok_or(PduParseErr::BufferEnded { field: Some("tl_sdu_segment") })?;
                sdu.write_bits(b, 1);
            }
            sdu.seek(0);
            (sdu, None)
        };

        Ok(AlDataAlFinal { variant, n_s: n_s as u8, s_s: s_s as u8, tl_sdu_segment: sdu, fcs })
    }

    /// Encode into a `BitBuffer`, writing the 4-bit `LlcPduType` (9) first.
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

        if let Some(fcs) = self.fcs {
            buf.write_bits(fcs as u64, 32);
        }
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
        assert_eq!(d.fcs, pdu.fcs);
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
}
