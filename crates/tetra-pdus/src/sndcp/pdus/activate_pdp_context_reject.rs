//! SN-ACTIVATE PDP CONTEXT REJECT (SwMI → MS), SN-PDU type 3.

use tetra_core::{BitBuffer, expect_pdu_type, pdu_parse_error::PduParseErr};

use crate::sndcp::enums::reject_cause::RejectCause;
use crate::sndcp::enums::sn_pdu_type::SnPduType;
use crate::sndcp::fields::nsapi::Nsapi;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivatePdpContextReject {
    pub nsapi: Nsapi,
    pub reject_cause: RejectCause,
}

impl ActivatePdpContextReject {
    pub fn from_bitbuf(buffer: &mut BitBuffer) -> Result<Self, PduParseErr> {
        let pdu_type = buffer.read_field(4, "pdu_type")?;
        expect_pdu_type!(pdu_type, SnPduType::ActivatePdpContextReject)?;
        let nsapi = Nsapi::from_bitbuf(buffer)?;
        let cause_raw = buffer.read_field(8, "reject_cause")? as u8;
        let reject_cause = RejectCause::from_raw(cause_raw);
        let obit = buffer.read_field(1, "obit")?;
        if obit == 1 {
            return Err(PduParseErr::NotImplemented { field: Some("reject_optional") });
        }
        Ok(ActivatePdpContextReject { nsapi, reject_cause })
    }

    pub fn to_bitbuf(&self, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
        buffer.write_bits(SnPduType::ActivatePdpContextReject.into_raw(), 4);
        self.nsapi.to_bitbuf(buffer)?;
        buffer.write_bits(self.reject_cause.into_raw() as u64, 8);
        buffer.write_bit(0); // o-bit = 0
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_default() {
        let pdu = ActivatePdpContextReject { nsapi: Nsapi(0), reject_cause: RejectCause::SubscriberUnknown };
        let mut buf = BitBuffer::new_autoexpand(32);
        pdu.to_bitbuf(&mut buf).unwrap();
        let bits = buf.to_bitstr();
        buf.seek(0);
        let decoded = ActivatePdpContextReject::from_bitbuf(&mut buf).unwrap();
        assert_eq!(decoded, pdu);
        let mut buf2 = BitBuffer::new_autoexpand(32);
        decoded.to_bitbuf(&mut buf2).unwrap();
        assert_eq!(buf2.to_bitstr(), bits);
    }

    #[test]
    fn round_trip_with_optionals() {
        let pdu = ActivatePdpContextReject { nsapi: Nsapi(6), reject_cause: RejectCause::AuthenticationFailure };
        let mut buf = BitBuffer::new_autoexpand(32);
        pdu.to_bitbuf(&mut buf).unwrap();
        let bits = buf.to_bitstr();
        buf.seek(0);
        let decoded = ActivatePdpContextReject::from_bitbuf(&mut buf).unwrap();
        assert_eq!(decoded, pdu);
        let mut buf2 = BitBuffer::new_autoexpand(32);
        decoded.to_bitbuf(&mut buf2).unwrap();
        assert_eq!(buf2.to_bitstr(), bits);
    }

    #[test]
    fn optional_section_not_implemented() {
        // type(4)=3, nsapi(4)=0, cause(8)=1, obit(1)=1
        let mut buf = BitBuffer::from_bitstr("0011000000000001 1".replace(' ', "").as_str());
        buf.seek(0);
        assert!(matches!(
            ActivatePdpContextReject::from_bitbuf(&mut buf),
            Err(PduParseErr::NotImplemented { field: Some("reject_optional") })
        ));
    }
}
