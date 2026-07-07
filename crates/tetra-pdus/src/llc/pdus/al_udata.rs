use core::fmt;

use tetra_core::BitBuffer;
use tetra_core::pdu_parse_error::*;
use tetra_core::let_field;

/// Discriminates between the two unacknowledged variants sharing LLC PDU type 10.
///
/// ETSI TS 100 392-2 v3.10.1 clauses 21.2.3.6 and 21.2.3.7.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlUdataVariant {
    /// AL-UDATA: non-final unacknowledged fragment.
    Udata,
    /// AL-UFINAL: last unacknowledged fragment.
    Ufinal,
}

impl fmt::Display for AlUdataVariant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AlUdataVariant::Udata => write!(f, "AL-UDATA"),
            AlUdataVariant::Ufinal => write!(f, "AL-UFINAL"),
        }
    }
}

/// AL-UDATA / AL-UFINAL PDU — unacknowledged information-carrying PDU.
///
/// FCS (32 bits) is **implicitly** present iff the variant is `Ufinal`.
/// There is **no length field** in the PDU; segment length is determined by the MAC
/// block size. The caller must supply `pdu_len_bits` (total PDU bits including the
/// 4-bit LLC type) so the decoder can locate the FCS boundary.
///
/// NOTE: per the decompile, FCS spillover from the preceding AL-UDATA is not modelled
/// in AL-1; the FCS is treated as belonging entirely to the UFINAL PDU.
///
/// ETSI TS 100 392-2 v3.10.1 clauses 21.2.3.6 and 21.2.3.7.
///
/// Wire layout after the 4-bit `LlcPduType` (= 10):
/// ```text
/// final_flag      1   0 = AL-UDATA, 1 = AL-UFINAL
/// n_s             8   send sequence number (large space for unacked SDUs)
/// s_s             8   segment sequence number within current SDU
/// tl_sdu_segment  *   remaining bits (minus 32 iff Ufinal)
/// fcs            32   conditional: present iff Ufinal
/// ```
#[derive(Debug, Clone)]
pub struct AlAlUdataAlUfinal {
    /// Whether this is the final fragment.
    pub variant: AlUdataVariant,
    /// Send sequence number, 8 bits (0..255).
    pub n_s: u8,
    /// Segment sequence number within current SDU, 8 bits (0..255).
    pub s_s: u8,
    /// The TL-SDU segment payload (bit-precise).
    pub tl_sdu_segment: BitBuffer,
    /// Optional Frame Check Sequence (32 bits), present iff variant is Ufinal.
    pub fcs: Option<u32>,
}

impl PartialEq for AlAlUdataAlUfinal {
    fn eq(&self, other: &Self) -> bool {
        self.variant == other.variant
            && self.n_s == other.n_s
            && self.s_s == other.s_s
            && self.tl_sdu_segment.to_bitstr() == other.tl_sdu_segment.to_bitstr()
            && self.fcs == other.fcs
    }
}

impl Eq for AlAlUdataAlUfinal {}

impl AlAlUdataAlUfinal {
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
        let_field!(buf, n_s, 8);
        let_field!(buf, s_s, 8);

        let variant = if final_flag != 0 { AlUdataVariant::Ufinal } else { AlUdataVariant::Udata };

        // Fixed bits: 4 (type) + 1 + 8 + 8 = 21.
        const HEADER_BITS: usize = 21;
        if pdu_len_bits < HEADER_BITS {
            return Err(PduParseErr::InconsistentLength {
                expected: HEADER_BITS,
                found: pdu_len_bits,
            });
        }
        let payload_and_fcs = pdu_len_bits - HEADER_BITS;

        let (sdu, fcs) = if variant == AlUdataVariant::Ufinal {
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

        Ok(AlAlUdataAlUfinal { variant, n_s: n_s as u8, s_s: s_s as u8, tl_sdu_segment: sdu, fcs })
    }

    /// Encode into a `BitBuffer`, writing the 4-bit `LlcPduType` (10) first.
    pub fn to_bitbuf(&self, buf: &mut BitBuffer) {
        // 4-bit LlcPduType = 10 (AlAlUdataAlUfinal)
        buf.write_bits(10, 4);

        let final_flag: u64 =
            match self.variant { AlUdataVariant::Udata => 0, AlUdataVariant::Ufinal => 1 };
        buf.write_bits(final_flag, 1);
        buf.write_bits(self.n_s as u64, 8);
        buf.write_bits(self.s_s as u64, 8);

        let sdu_len = self.tl_sdu_segment.get_len();
        let mut sdu_copy = BitBuffer::from_bitbuffer(&self.tl_sdu_segment);
        buf.copy_bits(&mut sdu_copy, sdu_len);

        if let Some(fcs) = self.fcs {
            buf.write_bits(fcs as u64, 32);
        }
    }
}

impl fmt::Display for AlAlUdataAlUfinal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "al_udata {{ variant: {}, n_s: {}, s_s: {}, sdu_len: {}, fcs: {:?} }}",
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

    fn round_trip(pdu: &AlAlUdataAlUfinal) -> AlAlUdataAlUfinal {
        let mut enc = BitBuffer::new_autoexpand(256);
        pdu.to_bitbuf(&mut enc);
        let pdu_len_bits = enc.get_len_written();
        enc.seek(0);
        enc.read_bits(4).unwrap();
        AlAlUdataAlUfinal::from_bitbuf(&mut enc, pdu_len_bits).expect("decode failed")
    }

    fn make_sdu(bits: &str) -> BitBuffer {
        BitBuffer::from_bitstr(bits)
    }

    #[test]
    fn al_udata_default_round_trip() {
        let pdu = AlAlUdataAlUfinal {
            variant: AlUdataVariant::Udata,
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
    fn al_ufinal_populated_round_trip() {
        let pdu = AlAlUdataAlUfinal {
            variant: AlUdataVariant::Ufinal,
            n_s: 200,
            s_s: 42,
            tl_sdu_segment: make_sdu("11001010"),
            fcs: Some(0xCAFEBABE),
        };
        let d = round_trip(&pdu);
        assert_eq!(d.variant, pdu.variant);
        assert_eq!(d.n_s, pdu.n_s);
        assert_eq!(d.s_s, pdu.s_s);
        assert_eq!(d.tl_sdu_segment.to_bitstr(), pdu.tl_sdu_segment.to_bitstr());
        assert_eq!(d.fcs, pdu.fcs);
    }
}
