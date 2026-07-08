//! SN-DATA (either direction), SN-PDU type 5.
//!
//! Wire layout is byte-identical to SN-UNITDATA (type 4), with only the
//! type nibble differing. Both use acknowledged LLC (AL) rather than
//! basic link (BL).
//!
//! ETSI TS 100 392-2 v3.10.1 clause 28.4.4.4, Table 28.16 (shared layout).

use tetra_core::{BitBuffer, expect_pdu_type, pdu_parse_error::PduParseErr};

use crate::sndcp::enums::sn_pdu_type::SnPduType;
use crate::sndcp::fields::nsapi::Nsapi;

/// SN-DATA carries an acknowledged IP payload (N-PDU).
///
/// Ref: ETSI TS 100 392-2 v3.10.1 clause 28.4.4.4 (same wire layout as
/// SN-UNITDATA but type nibble = 5 and transported over Advanced Link).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnData {
    pub nsapi: Nsapi,
    /// Protocol Header Compression algorithm index (4 bits). 0 = no compression.
    pub pcomp: u8,
    /// Data Compression algorithm index (4 bits). 0 = no compression.
    pub dcomp: u8,
    /// Raw N-PDU (IP payload) bytes.
    pub n_pdu: Vec<u8>,
}

impl SnData {
    pub fn from_bitbuf(buffer: &mut BitBuffer) -> Result<Self, PduParseErr> {
        let pdu_type = buffer.read_field(4, "pdu_type")?;
        expect_pdu_type!(pdu_type, SnPduType::Data)?;
        let nsapi = Nsapi::from_bitbuf(buffer)?;
        let pcomp = buffer.read_field(4, "pcomp")? as u8;
        let dcomp = buffer.read_field(4, "dcomp")? as u8;

        let remaining = buffer.get_len_remaining();
        if remaining % 8 != 0 {
            return Err(PduParseErr::InconsistentLength { expected: 0, found: remaining % 8 });
        }
        let mut n_pdu = Vec::with_capacity(remaining / 8);
        for _ in 0..(remaining / 8) {
            n_pdu.push(buffer.read_field(8, "sn_data_payload_octet")? as u8);
        }
        Ok(SnData { nsapi, pcomp, dcomp, n_pdu })
    }

    pub fn to_bitbuf(&self, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
        buffer.write_bits(SnPduType::Data.into_raw(), 4);
        self.nsapi.to_bitbuf(buffer)?;
        buffer.write_bits(self.pcomp as u64, 4);
        buffer.write_bits(self.dcomp as u64, 4);
        for &b in &self.n_pdu {
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
        let pdu = SnData { nsapi: Nsapi(2), pcomp: 0, dcomp: 0, n_pdu: vec![] };
        let mut buf = BitBuffer::new_autoexpand(64);
        pdu.to_bitbuf(&mut buf).unwrap();
        let bits = buf.to_bitstr();
        buf.seek(0);
        let decoded = SnData::from_bitbuf(&mut buf).unwrap();
        assert_eq!(decoded, pdu);
        let mut buf2 = BitBuffer::new_autoexpand(64);
        decoded.to_bitbuf(&mut buf2).unwrap();
        assert_eq!(buf2.to_bitstr(), bits);
    }

    #[test]
    fn round_trip_with_payload_and_compression_fields() {
        let pdu = SnData {
            nsapi: Nsapi(7),
            pcomp: 3,
            dcomp: 2,
            n_pdu: vec![0x45, 0x00, 0x00, 0x1C, 0x12, 0x34, 0x56, 0x78],
        };
        let mut buf = BitBuffer::new_autoexpand(128);
        pdu.to_bitbuf(&mut buf).unwrap();
        let bits = buf.to_bitstr();
        buf.seek(0);
        let decoded = SnData::from_bitbuf(&mut buf).unwrap();
        assert_eq!(decoded, pdu);
        let mut buf2 = BitBuffer::new_autoexpand(128);
        decoded.to_bitbuf(&mut buf2).unwrap();
        assert_eq!(buf2.to_bitstr(), bits);
    }
}
