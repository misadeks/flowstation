//! SN-DEACTIVATE PDP CONTEXT ACCEPT (either direction), SN-PDU type 1.

use tetra_core::{BitBuffer, expect_pdu_type, pdu_parse_error::PduParseErr};

use crate::sndcp::enums::sn_pdu_type::SnPduType;
use crate::sndcp::fields::nsapi::Nsapi;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeactivatePdpContextAccept {
    pub nsapi: Nsapi,
}

impl DeactivatePdpContextAccept {
    pub fn from_bitbuf(buffer: &mut BitBuffer) -> Result<Self, PduParseErr> {
        let pdu_type = buffer.read_field(4, "pdu_type")?;
        expect_pdu_type!(pdu_type, SnPduType::DeactivatePdpContextAccept)?;
        let nsapi = Nsapi::from_bitbuf(buffer)?;
        let _obit = buffer.read_field(1, "obit")?;
        Ok(DeactivatePdpContextAccept { nsapi })
    }

    pub fn to_bitbuf(&self, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
        buffer.write_bits(SnPduType::DeactivatePdpContextAccept.into_raw(), 4);
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
        let pdu = DeactivatePdpContextAccept { nsapi: Nsapi(0) };
        let mut buf = BitBuffer::new_autoexpand(32);
        pdu.to_bitbuf(&mut buf).unwrap();
        let bits = buf.to_bitstr();
        buf.seek(0);
        let decoded = DeactivatePdpContextAccept::from_bitbuf(&mut buf).unwrap();
        assert_eq!(decoded, pdu);
        let mut buf2 = BitBuffer::new_autoexpand(32);
        decoded.to_bitbuf(&mut buf2).unwrap();
        assert_eq!(buf2.to_bitstr(), bits);
    }

    #[test]
    fn round_trip_with_optionals() {
        let pdu = DeactivatePdpContextAccept { nsapi: Nsapi(7) };
        let mut buf = BitBuffer::new_autoexpand(32);
        pdu.to_bitbuf(&mut buf).unwrap();
        let bits = buf.to_bitstr();
        buf.seek(0);
        let decoded = DeactivatePdpContextAccept::from_bitbuf(&mut buf).unwrap();
        assert_eq!(decoded, pdu);
        let mut buf2 = BitBuffer::new_autoexpand(32);
        decoded.to_bitbuf(&mut buf2).unwrap();
        assert_eq!(buf2.to_bitstr(), bits);
    }
}
