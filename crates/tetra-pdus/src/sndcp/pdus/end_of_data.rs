//! SN-END OF DATA (MS → SwMI), SN-PDU type 8.
//!
//! ETSI TS 100 392-2 v3.10.1 clause 28.4.4.7. NOTE: this PDU has NO NSAPI —
//! END-OF-DATA is per-MS, not per-NSAPI, so all currently-Ready contexts for
//! the sending MS transition to Standby. Verified against Motorola MTM800E
//! live captures 2026-07-08 (6-bit uplink PDU) and the Nexus-BS reference
//! implementation.

use tetra_core::{BitBuffer, expect_pdu_type, pdu_parse_error::PduParseErr};

use crate::sndcp::enums::sn_pdu_type::SnPduType;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndOfData {
    /// 1 bit: when true, the SwMI is asked to switch service immediately
    /// (e.g. tear down the acknowledged AL right now instead of after the
    /// current SDU completes).
    pub immediate_service_change: bool,
}

impl EndOfData {
    pub fn from_bitbuf(buffer: &mut BitBuffer) -> Result<Self, PduParseErr> {
        let pdu_type = buffer.read_field(4, "pdu_type")?;
        expect_pdu_type!(pdu_type, SnPduType::EndOfData)?;
        let immediate_service_change = buffer.read_field(1, "immediate_service_change")? != 0;
        // o-bit: no optional elements handled in V1.
        let _obit = buffer.read_field(1, "obit")?;
        Ok(EndOfData { immediate_service_change })
    }

    pub fn to_bitbuf(&self, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
        buffer.write_bits(SnPduType::EndOfData.into_raw(), 4);
        buffer.write_bit(self.immediate_service_change as u8);
        buffer.write_bit(0); // o-bit = 0
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_default() {
        let pdu = EndOfData { immediate_service_change: false };
        let mut buf = BitBuffer::new_autoexpand(32);
        pdu.to_bitbuf(&mut buf).unwrap();
        let bits = buf.to_bitstr();
        buf.seek(0);
        let decoded = EndOfData::from_bitbuf(&mut buf).unwrap();
        assert_eq!(decoded, pdu);
        let mut buf2 = BitBuffer::new_autoexpand(32);
        decoded.to_bitbuf(&mut buf2).unwrap();
        assert_eq!(buf2.to_bitstr(), bits);
    }

    #[test]
    fn round_trip_with_optionals() {
        let pdu = EndOfData { immediate_service_change: true };
        let mut buf = BitBuffer::new_autoexpand(32);
        pdu.to_bitbuf(&mut buf).unwrap();
        let bits = buf.to_bitstr();
        buf.seek(0);
        let decoded = EndOfData::from_bitbuf(&mut buf).unwrap();
        assert_eq!(decoded, pdu);
        let mut buf2 = BitBuffer::new_autoexpand(32);
        decoded.to_bitbuf(&mut buf2).unwrap();
        assert_eq!(buf2.to_bitstr(), bits);
    }

    #[test]
    fn decodes_minimal_6bit_wire_from_motorola() {
        // Real MS PDU: type(4)=1000 immediate(1)=0 obit(1)=0 → 6 bits total.
        // Before this fix, decoder read a spurious 4-bit "nsapi" and hit BufferEnded.
        let mut buf = BitBuffer::from_bitstr("100000");
        let decoded = EndOfData::from_bitbuf(&mut buf).unwrap();
        assert!(!decoded.immediate_service_change);
    }
}
