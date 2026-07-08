//! SN-UNITDATA (either direction), SN-PDU type 4.
//!
//! Wire layout (ETSI TS 100 392-2 v3.10.1 clause 28.4.4.4, Table 28.16):
//! ```text
//!  bits  4 | 4 | 4 | 4 | N*8
//!        type=4 | nsapi | pcomp | dcomp | ip_payload
//! ```
//! Total header = 16 bits (byte-aligned; no pad, no PDU-priority, no o-bit).
//! Confirmed against DIMETRA tsc.elf UNPACK sequences at 0x0075606C.

use tetra_core::{BitBuffer, expect_pdu_type, pdu_parse_error::PduParseErr};

use crate::sndcp::enums::sn_pdu_type::SnPduType;
use crate::sndcp::fields::nsapi::Nsapi;

/// SN-UNITDATA carries a raw (unacknowledged) IP payload.
///
/// Ref: ETSI TS 100 392-2 v3.10.1 clause 28.4.4.4, Table 28.16.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unitdata {
    pub nsapi: Nsapi,
    /// Protocol Header Compression algorithm index (4 bits). 0 = no compression.
    pub pcomp: u8,
    /// Data Compression algorithm index (4 bits). 0 = no compression.
    pub dcomp: u8,
    pub payload: Vec<u8>,
}

impl Unitdata {
    pub fn from_bitbuf(buffer: &mut BitBuffer) -> Result<Self, PduParseErr> {
        let pdu_type = buffer.read_field(4, "pdu_type")?;
        expect_pdu_type!(pdu_type, SnPduType::Unitdata)?;
        let nsapi = Nsapi::from_bitbuf(buffer)?;
        let pcomp = buffer.read_field(4, "pcomp")? as u8;
        let dcomp = buffer.read_field(4, "dcomp")? as u8;

        let remaining = buffer.get_len_remaining();
        if remaining % 8 != 0 {
            return Err(PduParseErr::InconsistentLength { expected: 0, found: remaining % 8 });
        }
        let mut payload = Vec::with_capacity(remaining / 8);
        for _ in 0..(remaining / 8) {
            payload.push(buffer.read_field(8, "unitdata_payload_octet")? as u8);
        }
        Ok(Unitdata { nsapi, pcomp, dcomp, payload })
    }

    pub fn to_bitbuf(&self, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
        buffer.write_bits(SnPduType::Unitdata.into_raw(), 4);
        self.nsapi.to_bitbuf(buffer)?;
        buffer.write_bits(self.pcomp as u64, 4);
        buffer.write_bits(self.dcomp as u64, 4);
        for &b in &self.payload {
            buffer.write_bits(b as u64, 8);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_default() {
        let pdu = Unitdata { nsapi: Nsapi(1), pcomp: 0, dcomp: 0, payload: vec![] };
        let mut buf = BitBuffer::new_autoexpand(64);
        pdu.to_bitbuf(&mut buf).unwrap();
        let bits = buf.to_bitstr();
        buf.seek(0);
        let decoded = Unitdata::from_bitbuf(&mut buf).unwrap();
        assert_eq!(decoded, pdu);
        let mut buf2 = BitBuffer::new_autoexpand(64);
        decoded.to_bitbuf(&mut buf2).unwrap();
        assert_eq!(buf2.to_bitstr(), bits);
    }

    #[test]
    fn round_trip_with_payload_and_compression_fields() {
        let pdu = Unitdata {
            nsapi: Nsapi(5),
            pcomp: 2,
            dcomp: 1,
            payload: vec![0x45, 0x00, 0x00, 0x1C, 0xDE, 0xAD, 0xBE, 0xEF],
        };
        let mut buf = BitBuffer::new_autoexpand(128);
        pdu.to_bitbuf(&mut buf).unwrap();
        let bits = buf.to_bitstr();
        buf.seek(0);
        let decoded = Unitdata::from_bitbuf(&mut buf).unwrap();
        assert_eq!(decoded, pdu);
        let mut buf2 = BitBuffer::new_autoexpand(128);
        decoded.to_bitbuf(&mut buf2).unwrap();
        assert_eq!(buf2.to_bitstr(), bits);
    }

    #[test]
    fn header_is_exactly_16_bits() {
        // Empty payload: buffer should be exactly 16 bits after encoding.
        let pdu = Unitdata { nsapi: Nsapi(3), pcomp: 0, dcomp: 0, payload: vec![] };
        let mut buf = BitBuffer::new_autoexpand(32);
        pdu.to_bitbuf(&mut buf).unwrap();
        assert_eq!(buf.get_len(), 16, "SN-UNITDATA header must be exactly 16 bits");
    }

    #[test]
    fn rejects_non_octet_payload() {
        // 16-bit header + 3 stray bits => remaining % 8 != 0
        // type=4 (0100), nsapi=1 (0001), pcomp=0 (0000), dcomp=0 (0000), 3 stray bits (101)
        let mut buf = BitBuffer::from_bitstr("0100000100000000101");
        buf.seek(0);
        assert!(matches!(
            Unitdata::from_bitbuf(&mut buf),
            Err(PduParseErr::InconsistentLength { expected: 0, found: 3 })
        ));
    }
}
