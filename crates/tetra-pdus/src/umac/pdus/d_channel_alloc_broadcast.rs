use core::fmt;

use tetra_core::{BitBuffer, pdu_parse_error::PduParseErr};

/// NOTE: spec ambiguous — chosen behaviour: UL/DL mode codes per
/// ETSI EN 300 392-2 clause 21.4.3.4 (approx.).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum UlDlMode {
    UlOnly = 0,
    DlOnly = 1,
    /// NOTE: spec ambiguous — chosen behaviour: 2 = symmetric UL+DL.
    Symmetric = 2,
    // 3 = reserved
}

impl UlDlMode {
    fn from_raw(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::UlOnly),
            1 => Some(Self::DlOnly),
            2 => Some(Self::Symmetric),
            _ => None, // 3 = reserved
        }
    }

    fn to_raw(self) -> u8 {
        self as u8
    }
}

impl fmt::Display for UlDlMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UlDlMode::UlOnly => write!(f, "UlOnly"),
            UlDlMode::DlOnly => write!(f, "DlOnly"),
            UlDlMode::Symmetric => write!(f, "Symmetric"),
        }
    }
}

/// D-CHANNEL-ALLOCATION-BROADCAST PDU
///
/// NOTE: spec ambiguous — wire format taken from ETSI EN 300 392-2 clause
/// 21.4.3.4 (approximate; hardware bring-up in PD-9 will validate against a
/// reference terminal).
///
/// Total: 36 bits
/// ```text
///  PDU_type          4   fixed = 0x4 (broadcast family)
///  broadcast_type    4   fixed = 0x3 (D-CHANNEL-ALLOCATION-BROADCAST)
///  dl_frequency_band 4   DL frequency band per clause 21.4.4.1.1
///  carrier_number   12   LCN of the PDCH carrier
///  timeslot          2   0 = TS1, 1 = TS2, 2 = TS3, 3 = TS4
///  ul_dl_mode        2   0=UL only, 1=DL only, 2=UL+DL, 3=reserved
///  encoding          2   0 = π/4-DQPSK (V1 default)
///  channel_bandwidth 2   0 = 25 kHz (V1 default)
///  rand_access_group 3   0-7 random access group
///  reserved          1   write 0, ignore on read
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DChannelAllocationBroadcast {
    /// NOTE: spec ambiguous — chosen behaviour: dl_frequency_band uses the
    /// same 4-bit frequency-band encoding as SYSINFO (clause 21.4.4.1.1).
    pub dl_frequency_band: u8,
    /// Logical channel number (LCN) of the PDCH carrier. 12 bits.
    pub carrier_number: u16,
    /// Timeslot index: 0 = TS1, 1 = TS2, 2 = TS3, 3 = TS4.
    /// NOTE: spec ambiguous — chosen behaviour: 0-based index mapping.
    pub timeslot: u8,
    pub ul_dl_mode: UlDlMode,
    /// NOTE: spec ambiguous — chosen behaviour: 0 = π/4-DQPSK (V1 default).
    pub encoding: u8,
    /// NOTE: spec ambiguous — chosen behaviour: 0 = 25 kHz (V1 default).
    pub channel_bandwidth: u8,
    /// Random Access Group for this PDCH. 3 bits, range 0–7.
    pub rand_access_group: u8,
}

/// Fixed PDU type header: broadcast family = 4, broadcast_type = 3.
/// NOTE: spec ambiguous — PDU_type 4 is assumed for the broadcast family.
const PDU_TYPE: u8 = 0x4;
const BROADCAST_TYPE: u8 = 0x3;

impl DChannelAllocationBroadcast {
    /// Encode to `buf`. Writes exactly 36 bits.
    pub fn to_bitbuf(&self, buf: &mut BitBuffer) {
        // 4-bit PDU type (broadcast family)
        // NOTE: spec ambiguous — chosen behaviour: PDU_type = 4 for broadcast.
        buf.write_bits(PDU_TYPE as u64, 4);
        // 4-bit broadcast_type = 3
        // NOTE: spec ambiguous — chosen behaviour: broadcast_type = 3 for
        // D-CHANNEL-ALLOCATION-BROADCAST.
        buf.write_bits(BROADCAST_TYPE as u64, 4);
        // 4-bit DL frequency band
        buf.write_bits(self.dl_frequency_band as u64, 4);
        // 12-bit carrier number (LCN)
        buf.write_bits(self.carrier_number as u64, 12);
        // 2-bit timeslot index
        // NOTE: spec ambiguous — chosen behaviour: 0-based (0=TS1..3=TS4).
        buf.write_bits(self.timeslot as u64, 2);
        // 2-bit UL/DL mode
        buf.write_bits(self.ul_dl_mode.to_raw() as u64, 2);
        // 2-bit encoding
        buf.write_bits(self.encoding as u64, 2);
        // 2-bit channel bandwidth
        buf.write_bits(self.channel_bandwidth as u64, 2);
        // 3-bit random access group
        buf.write_bits(self.rand_access_group as u64, 3);
        // 1-bit reserved (write 0)
        buf.write_bits(0, 1);
    }

    /// Decode from `buf`. Consumes exactly 36 bits.
    pub fn from_bitbuf(buf: &mut BitBuffer) -> Result<Self, PduParseErr> {
        // 4-bit PDU type — validate
        let pdu_type = buf.read_field(4, "pdu_type")? as u8;
        if pdu_type != PDU_TYPE {
            return Err(PduParseErr::InvalidValue {
                field: "pdu_type",
                value: pdu_type as u64,
            });
        }
        // 4-bit broadcast_type — validate
        let broadcast_type = buf.read_field(4, "broadcast_type")? as u8;
        if broadcast_type != BROADCAST_TYPE {
            return Err(PduParseErr::InvalidValue {
                field: "broadcast_type",
                value: broadcast_type as u64,
            });
        }
        let dl_frequency_band = buf.read_field(4, "dl_frequency_band")? as u8;
        let carrier_number = buf.read_field(12, "carrier_number")? as u16;
        let timeslot = buf.read_field(2, "timeslot")? as u8;
        let ul_dl_mode_raw = buf.read_field(2, "ul_dl_mode")? as u8;
        let ul_dl_mode = UlDlMode::from_raw(ul_dl_mode_raw).ok_or(PduParseErr::InvalidValue {
            field: "ul_dl_mode",
            value: ul_dl_mode_raw as u64,
        })?;
        let encoding = buf.read_field(2, "encoding")? as u8;
        let channel_bandwidth = buf.read_field(2, "channel_bandwidth")? as u8;
        let rand_access_group = buf.read_field(3, "rand_access_group")? as u8;
        // reserved bit — read and discard
        let _ = buf.read_field(1, "reserved")?;

        Ok(Self {
            dl_frequency_band,
            carrier_number,
            timeslot,
            ul_dl_mode,
            encoding,
            channel_bandwidth,
            rand_access_group,
        })
    }
}

impl fmt::Display for DChannelAllocationBroadcast {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "D-CHANNEL-ALLOCATION-BROADCAST {{ band={} carrier={} ts={} mode={} enc={} bw={} rag={} }}",
            self.dl_frequency_band,
            self.carrier_number,
            self.timeslot,
            self.ul_dl_mode,
            self.encoding,
            self.channel_bandwidth,
            self.rand_access_group,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Canonical round-trip test with a known bit vector.
    /// NOTE: spec ambiguous — the canonical vector was derived from the chosen
    /// wire encoding in this file; hardware bring-up in PD-9 will validate it.
    #[test]
    fn test_round_trip_canonical() {
        let pdu = DChannelAllocationBroadcast {
            dl_frequency_band: 4,   // 0b0100
            carrier_number: 1521,   // 0b010111110001  (carrier 1521)
            timeslot: 3,            // TS4 (0b11)
            ul_dl_mode: UlDlMode::Symmetric,
            encoding: 0,
            channel_bandwidth: 0,
            rand_access_group: 5,   // 0b101
        };

        let mut buf = BitBuffer::new(36);
        pdu.to_bitbuf(&mut buf);
        assert_eq!(buf.get_len(), 36, "encoded PDU must be exactly 36 bits");

        buf.seek(0);
        let decoded = DChannelAllocationBroadcast::from_bitbuf(&mut buf)
            .expect("canonical PDU must decode without error");

        assert_eq!(decoded, pdu, "round-trip must be lossless");
    }

    #[test]
    fn test_round_trip_ul_only() {
        let pdu = DChannelAllocationBroadcast {
            dl_frequency_band: 7,
            carrier_number: 100,
            timeslot: 0,
            ul_dl_mode: UlDlMode::UlOnly,
            encoding: 0,
            channel_bandwidth: 0,
            rand_access_group: 0,
        };

        let mut buf = BitBuffer::new(36);
        pdu.to_bitbuf(&mut buf);
        buf.seek(0);
        let decoded = DChannelAllocationBroadcast::from_bitbuf(&mut buf).unwrap();
        assert_eq!(decoded, pdu);
    }

    #[test]
    fn test_invalid_pdu_type_rejected() {
        // Build a valid PDU, then corrupt the pdu_type nibble
        let pdu = DChannelAllocationBroadcast {
            dl_frequency_band: 4,
            carrier_number: 1521,
            timeslot: 3,
            ul_dl_mode: UlDlMode::Symmetric,
            encoding: 0,
            channel_bandwidth: 0,
            rand_access_group: 5,
        };
        let mut buf = BitBuffer::new(36);
        pdu.to_bitbuf(&mut buf);

        // Overwrite the first 4 bits (pdu_type) with 0b0000 (invalid)
        let mut corrupt = BitBuffer::new(36);
        corrupt.write_bits(0x0, 4); // wrong pdu_type
        corrupt.write_bits(BROADCAST_TYPE as u64, 4);
        corrupt.write_bits(4, 4);
        corrupt.write_bits(1521, 12);
        corrupt.write_bits(3, 2);
        corrupt.write_bits(2, 2);
        corrupt.write_bits(0, 2);
        corrupt.write_bits(0, 2);
        corrupt.write_bits(5, 3);
        corrupt.write_bits(0, 1);
        corrupt.seek(0);
        assert!(DChannelAllocationBroadcast::from_bitbuf(&mut corrupt).is_err());
    }
}
