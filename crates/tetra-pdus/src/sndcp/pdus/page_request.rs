//! SN-PAGE REQUEST (SwMI → MS), SN-PDU type 10, subtype 0.

use tetra_core::{BitBuffer, expect_pdu_type, pdu_parse_error::PduParseErr};

use crate::sndcp::enums::sn_pdu_type::SnPduType;
use crate::sndcp::fields::nsapi::Nsapi;

const PAGE_SUBTYPE_REQUEST: u64 = 0;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageRequest {
    pub nsapi: Nsapi,
}

impl PageRequest {
    pub fn from_bitbuf(buffer: &mut BitBuffer) -> Result<Self, PduParseErr> {
        let pdu_type = buffer.read_field(4, "pdu_type")?;
        expect_pdu_type!(pdu_type, SnPduType::Page)?;
        let subtype = buffer.read_field(1, "page_subtype")?;
        if subtype != PAGE_SUBTYPE_REQUEST {
            return Err(PduParseErr::InvalidValue { field: "page_subtype", value: subtype });
        }
        let nsapi = Nsapi::from_bitbuf(buffer)?;
        let _obit = buffer.read_field(1, "obit")?;
        Ok(PageRequest { nsapi })
    }

    pub fn to_bitbuf(&self, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
        buffer.write_bits(SnPduType::Page.into_raw(), 4);
        buffer.write_bits(PAGE_SUBTYPE_REQUEST, 1);
        self.nsapi.to_bitbuf(buffer)?;
        buffer.write_bit(0); // o-bit = 0
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_default() {
        let pdu = PageRequest { nsapi: Nsapi(0) };
        let mut buf = BitBuffer::new_autoexpand(32);
        pdu.to_bitbuf(&mut buf).unwrap();
        let bits = buf.to_bitstr();
        buf.seek(0);
        let decoded = PageRequest::from_bitbuf(&mut buf).unwrap();
        assert_eq!(decoded, pdu);
        let mut buf2 = BitBuffer::new_autoexpand(32);
        decoded.to_bitbuf(&mut buf2).unwrap();
        assert_eq!(buf2.to_bitstr(), bits);
    }

    #[test]
    fn round_trip_with_optionals() {
        let pdu = PageRequest { nsapi: Nsapi(3) };
        let mut buf = BitBuffer::new_autoexpand(32);
        pdu.to_bitbuf(&mut buf).unwrap();
        let bits = buf.to_bitstr();
        buf.seek(0);
        let decoded = PageRequest::from_bitbuf(&mut buf).unwrap();
        assert_eq!(decoded, pdu);
        let mut buf2 = BitBuffer::new_autoexpand(32);
        decoded.to_bitbuf(&mut buf2).unwrap();
        assert_eq!(buf2.to_bitstr(), bits);
    }
}
