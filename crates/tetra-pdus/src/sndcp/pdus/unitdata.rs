//! SN-UNITDATA (either direction), SN-PDU type 4.

use tetra_core::{BitBuffer, expect_pdu_type, pdu_parse_error::PduParseErr};

use crate::sndcp::enums::sn_pdu_type::SnPduType;
use crate::sndcp::fields::nsapi::Nsapi;

/// SN-UNITDATA carries a raw IP payload.
///
/// NOTE: spec ambiguous — chosen behaviour: after the 12-bit header
/// (type|NSAPI|prio|obit), skip 4 pad bits to reach the octet boundary, then read
/// all remaining full octets as IP payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unitdata {
    pub nsapi: Nsapi,
    /// 3 bits.
    pub pdu_priority: u8,
    pub payload: Vec<u8>,
}

impl Unitdata {
    pub fn from_bitbuf(buffer: &mut BitBuffer) -> Result<Self, PduParseErr> {
        let pdu_type = buffer.read_field(4, "pdu_type")?;
        expect_pdu_type!(pdu_type, SnPduType::Unitdata)?;
        let nsapi = Nsapi::from_bitbuf(buffer)?;
        let pdu_priority = buffer.read_field(3, "pdu_priority")? as u8;
        let _obit = buffer.read_field(1, "obit")?;
        // 4 pad bits to reach octet boundary.
        let _pad = buffer.read_field(4, "unitdata_pad")?;

        let remaining = buffer.get_len_remaining();
        if remaining % 8 != 0 {
            return Err(PduParseErr::InconsistentLength { expected: 0, found: remaining % 8 });
        }
        let mut payload = Vec::with_capacity(remaining / 8);
        for _ in 0..(remaining / 8) {
            payload.push(buffer.read_field(8, "unitdata_payload_octet")? as u8);
        }
        Ok(Unitdata { nsapi, pdu_priority, payload })
    }

    pub fn to_bitbuf(&self, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
        buffer.write_bits(SnPduType::Unitdata.into_raw(), 4);
        self.nsapi.to_bitbuf(buffer)?;
        buffer.write_bits(self.pdu_priority as u64, 3);
        buffer.write_bit(0); // o-bit = 0
        buffer.write_bits(0, 4); // 4 pad bits
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
        let pdu = Unitdata { nsapi: Nsapi(1), pdu_priority: 0, payload: vec![] };
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
    fn round_trip_with_optionals() {
        let pdu = Unitdata {
            nsapi: Nsapi(5),
            pdu_priority: 7,
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
    fn rejects_non_octet_payload() {
        // header(12) + pad(4) + 3 stray bits => remaining % 8 != 0
        let mut buf = BitBuffer::from_bitstr("0100 0001 000 0 0000 101".replace(' ', "").as_str());
        buf.seek(0);
        assert!(matches!(
            Unitdata::from_bitbuf(&mut buf),
            Err(PduParseErr::InconsistentLength { expected: 0, found: 3 })
        ));
    }
}
