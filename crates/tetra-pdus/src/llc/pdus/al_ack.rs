use core::fmt;

use tetra_core::BitBuffer;
use tetra_core::pdu_parse_error::*;
use tetra_core::let_field;

// ─── S(R) segment-receive sequence number ──────────────────────────────────

/// S(R): oldest-not-received segment number field inside an `AcknowledgementBlock`.
///
/// The special wire value `0b11111010` (250) has a distinct meaning.
///
/// ETSI TS 100 392-2 v3.10.1 clause 21.2.3.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SR {
    /// Normal oldest-not-received segment number (0..=249).
    OldestNotReceived(u8),
    /// All remaining segments of the current SDU have been received (`0b11111010` = 250).
    RestOfSduReceived,
    /// Reserved (251..=255).
    Reserved(u8),
}

impl SR {
    fn into_raw(self) -> u8 {
        match self {
            SR::OldestNotReceived(v) => v,
            SR::RestOfSduReceived => 0b1111_1010,
            SR::Reserved(v) => v,
        }
    }
}

impl From<u8> for SR {
    fn from(v: u8) -> Self {
        match v {
            0..=249 => SR::OldestNotReceived(v),
            250 => SR::RestOfSduReceived,
            _ => SR::Reserved(v),
        }
    }
}

impl fmt::Display for SR {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SR::OldestNotReceived(v) => write!(f, "SR::OldestNotReceived({})", v),
            SR::RestOfSduReceived => write!(f, "SR::RestOfSduReceived"),
            SR::Reserved(v) => write!(f, "SR::Reserved({})", v),
        }
    }
}

// ─── AckLength ─────────────────────────────────────────────────────────────

/// Encoded acknowledgement-length field (6 bits) inside an `AcknowledgementBlock`.
///
/// ETSI TS 100 392-2 v3.10.1 clause 21.2.3.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AckLength {
    /// `000000` (0): entire SDU received; no S(R), no bitmap.
    EntireSduReceived,
    /// `000001..111110` (1..62): `N` acknowledged segments.
    ///
    /// S(R) is always present. Bitmap of `N-1` bits is present iff `N >= 2`
    /// (bit = 1 means received, bit = 0 means not received).
    Segments(u8),
    /// `111111` (63): SDU FCS failure — peer should retransmit entire SDU; no S(R), no bitmap.
    SduFcsFailure,
}

impl AckLength {
    fn into_raw(self) -> u64 {
        match self {
            AckLength::EntireSduReceived => 0,
            AckLength::Segments(n) => n as u64,
            AckLength::SduFcsFailure => 63,
        }
    }
}

impl From<u64> for AckLength {
    fn from(v: u64) -> Self {
        match v {
            0 => AckLength::EntireSduReceived,
            1..=62 => AckLength::Segments(v as u8),
            _ => AckLength::SduFcsFailure,
        }
    }
}

// ─── AcknowledgementBlock ──────────────────────────────────────────────────

/// One acknowledgement block within an AL-ACK / AL-RNR PDU.
///
/// ETSI TS 100 392-2 v3.10.1 clause 21.2.3.1.
///
/// Wire layout:
/// ```text
/// n_r           3   TL-SDU number being acknowledged
/// ack_length    6   encoded acknowledgement scope (AckLength)
/// [Segments(N)]
///   s_r         8   oldest-not-received segment number (SR)
///   [N >= 2]
///   ack_bitmap  N-1 bits: 1 = received, 0 = not received
/// ```
#[derive(Debug, Clone)]
pub struct AcknowledgementBlock {
    /// TL-SDU receive sequence number being acknowledged, 3 bits (0..7).
    pub n_r: u8,
    /// Acknowledgement scope / length code.
    pub ack_length: AckLength,
    /// Oldest-not-received segment number; present iff `ack_length == Segments(N)`.
    pub s_r: Option<SR>,
    /// Per-segment received bitmap; present iff `ack_length == Segments(N)` and `N >= 2`.
    /// Length = N-1 bits.
    pub ack_bitmap: Option<BitBuffer>,
}

impl PartialEq for AcknowledgementBlock {
    fn eq(&self, other: &Self) -> bool {
        self.n_r == other.n_r
            && self.ack_length == other.ack_length
            && self.s_r == other.s_r
            && match (&self.ack_bitmap, &other.ack_bitmap) {
                (Some(a), Some(b)) => a.to_bitstr() == b.to_bitstr(),
                (None, None) => true,
                _ => false,
            }
    }
}

impl Eq for AcknowledgementBlock {}

impl AcknowledgementBlock {
    fn from_bitbuf(buf: &mut BitBuffer) -> Result<Self, PduParseErr> {
        let_field!(buf, nr, 3);
        let_field!(buf, ack_len_raw, 6);
        let ack_length = AckLength::from(ack_len_raw);

        let (s_r, ack_bitmap) = match ack_length {
            AckLength::Segments(n) => {
                let_field!(buf, sr_raw, 8);
                let sr = SR::from(sr_raw as u8);
                let bitmap = if n >= 2 {
                    let bm_bits = (n - 1) as usize;
                    let mut bm = BitBuffer::new_autoexpand(bm_bits + 8);
                    for _ in 0..bm_bits {
                        let b = buf
                            .read_bits(1)
                            .ok_or(PduParseErr::BufferEnded { field: Some("ack_bitmap") })?;
                        bm.write_bits(b, 1);
                    }
                    bm.seek(0);
                    Some(bm)
                } else {
                    None
                };
                (Some(sr), bitmap)
            }
            _ => (None, None),
        };

        Ok(AcknowledgementBlock { n_r: nr as u8, ack_length, s_r, ack_bitmap })
    }

    fn to_bitbuf(&self, buf: &mut BitBuffer) {
        buf.write_bits(self.n_r as u64, 3);
        buf.write_bits(self.ack_length.into_raw(), 6);

        if let AckLength::Segments(n) = self.ack_length {
            let sr_raw = self.s_r.unwrap_or(SR::OldestNotReceived(0)).into_raw();
            buf.write_bits(sr_raw as u64, 8);

            if n >= 2 {
                if let Some(bm) = &self.ack_bitmap {
                    let bm_bits = bm.get_len();
                    let mut bm_copy = BitBuffer::from_bitbuffer(bm);
                    buf.copy_bits(&mut bm_copy, bm_bits);
                } else {
                    // bitmap expected but missing — write zeros
                    let bm_bits = (n - 1) as usize;
                    buf.write_zeroes(bm_bits);
                }
            }
        }
    }

    /// Minimum bit-width of one block (n_r=3 + ack_length=6 = 9).
    const MIN_BITS: usize = 9;
}

// ─── AlAckAlRnrKind ────────────────────────────────────────────────────────

/// Discriminant for AL-ACK vs AL-RNR.
///
/// Wire value: flow_control bit — **1 = ACK, 0 = RNR**.
///
/// ETSI TS 100 392-2 v3.10.1 clause 21.2.3.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlAckAlRnrKind {
    /// Receiver is ready; acknowledges received SDUs.
    Ack,
    /// Receiver is not ready; peer should suspend transmission.
    Rnr,
}

impl fmt::Display for AlAckAlRnrKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AlAckAlRnrKind::Ack => write!(f, "AL-ACK"),
            AlAckAlRnrKind::Rnr => write!(f, "AL-RNR"),
        }
    }
}

// ─── AlAckAlRnr ────────────────────────────────────────────────────────────

/// AL-ACK / AL-RNR PDU — acknowledgement and receiver-not-ready control.
///
/// Both variants carry one or more `AcknowledgementBlock`s. An RNR carries the same
/// block structure as an ACK; the flow-control bit is the only discriminant.
///
/// The number of additional blocks after the first is bounded by N272 (spec window
/// size). This decoder reads blocks until fewer than 9 bits remain, with a hard cap
/// of 15 additional blocks.
///
/// ETSI TS 100 392-2 v3.10.1 clause 21.2.3.1.
///
/// Wire layout after the 4-bit `LlcPduType` (= 11):
/// ```text
/// flow_control      1   1 = AL-ACK, 0 = AL-RNR
/// first_block       *   one AcknowledgementBlock (see struct)
/// [other_blocks]*   *   additional blocks until PDU bits exhausted (≤ 15)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlAckAlRnr {
    /// Whether this is an ACK or an RNR.
    pub kind: AlAckAlRnrKind,
    /// The mandatory first acknowledgement block.
    pub first_block: AcknowledgementBlock,
    /// Zero or more additional blocks (bounded by N272 − 1; capped at 15).
    pub other_blocks: Vec<AcknowledgementBlock>,
}

impl AlAckAlRnr {
    /// Decode from a `BitBuffer` positioned immediately **after** the 4-bit `LlcPduType`.
    ///
    /// `pdu_len_bits`: total PDU length in bits **including** the 4-bit LLC type, as
    /// provided by the MAC layer. The buffer must contain exactly `pdu_len_bits - 4` bits;
    /// the decoder returns `PduParseErr::InconsistentLength` if the sizes do not match.
    /// Blocks are decoded greedily until fewer than 9 bits remain, capped at 15 additional blocks.
    pub fn from_bitbuf(buf: &mut BitBuffer, pdu_len_bits: usize) -> Result<Self, PduParseErr> {
        // Validate buffer length against declared PDU size.
        let expected_body = pdu_len_bits.saturating_sub(4);
        if buf.get_len_remaining() != expected_body {
            return Err(PduParseErr::InconsistentLength {
                expected: expected_body,
                found: buf.get_len_remaining(),
            });
        }

        let_field!(buf, flow_ctrl, 1);
        let kind = if flow_ctrl != 0 { AlAckAlRnrKind::Ack } else { AlAckAlRnrKind::Rnr };

        let first_block = AcknowledgementBlock::from_bitbuf(buf)?;

        let mut other_blocks = Vec::new();
        while buf.get_len_remaining() >= AcknowledgementBlock::MIN_BITS
            && other_blocks.len() < 15
        {
            other_blocks.push(AcknowledgementBlock::from_bitbuf(buf)?);
        }

        Ok(AlAckAlRnr { kind, first_block, other_blocks })
    }

    /// Encode into a `BitBuffer`, writing the 4-bit `LlcPduType` (11) first.
    pub fn to_bitbuf(&self, buf: &mut BitBuffer) {
        // 4-bit LlcPduType = 11 (AlAckAlRnr)
        buf.write_bits(11, 4);

        let flow_ctrl: u64 = match self.kind { AlAckAlRnrKind::Ack => 1, AlAckAlRnrKind::Rnr => 0 };
        buf.write_bits(flow_ctrl, 1);

        self.first_block.to_bitbuf(buf);
        for blk in &self.other_blocks {
            blk.to_bitbuf(buf);
        }
    }
}

impl fmt::Display for AlAckAlRnr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "al_ack_al_rnr {{ kind: {}, blocks: {} }}",
            self.kind,
            1 + self.other_blocks.len(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(pdu: &AlAckAlRnr) -> AlAckAlRnr {
        let mut enc = BitBuffer::new_autoexpand(256);
        pdu.to_bitbuf(&mut enc);
        let pdu_len_bits = enc.get_len_written();
        enc.seek(0);
        enc.read_bits(4).unwrap();
        AlAckAlRnr::from_bitbuf(&mut enc, pdu_len_bits).expect("decode failed")
    }

    fn entire_block(n_r: u8) -> AcknowledgementBlock {
        AcknowledgementBlock { n_r, ack_length: AckLength::EntireSduReceived, s_r: None, ack_bitmap: None }
    }

    #[test]
    fn al_ack_default_round_trip() {
        let pdu = AlAckAlRnr { kind: AlAckAlRnrKind::Ack, first_block: entire_block(0), other_blocks: vec![] };
        assert_eq!(round_trip(&pdu), pdu);
    }

    #[test]
    fn al_rnr_single_block_round_trip() {
        let pdu = AlAckAlRnr {
            kind: AlAckAlRnrKind::Rnr,
            first_block: AcknowledgementBlock {
                n_r: 5,
                ack_length: AckLength::Segments(1),
                s_r: Some(SR::OldestNotReceived(3)),
                ack_bitmap: None,
            },
            other_blocks: vec![],
        };
        assert_eq!(round_trip(&pdu), pdu);
    }

    #[test]
    fn al_ack_multi_block_with_bitmap_round_trip() {
        let pdu = AlAckAlRnr {
            kind: AlAckAlRnrKind::Ack,
            first_block: AcknowledgementBlock {
                n_r: 3,
                ack_length: AckLength::Segments(3),
                s_r: Some(SR::OldestNotReceived(7)),
                // 3-1 = 2 bitmap bits
                ack_bitmap: Some(BitBuffer::from_bitstr("10")),
            },
            other_blocks: vec![
                entire_block(1),
                AcknowledgementBlock {
                    n_r: 2,
                    ack_length: AckLength::SduFcsFailure,
                    s_r: None,
                    ack_bitmap: None,
                },
            ],
        };
        assert_eq!(round_trip(&pdu), pdu);
    }

    #[test]
    fn al_ack_rest_of_sdu_received_round_trip() {
        let pdu = AlAckAlRnr {
            kind: AlAckAlRnrKind::Ack,
            first_block: AcknowledgementBlock {
                n_r: 7,
                ack_length: AckLength::Segments(2),
                s_r: Some(SR::RestOfSduReceived),
                // 2-1 = 1 bitmap bit
                ack_bitmap: Some(BitBuffer::from_bitstr("1")),
            },
            other_blocks: vec![],
        };
        assert_eq!(round_trip(&pdu), pdu);
    }
}
