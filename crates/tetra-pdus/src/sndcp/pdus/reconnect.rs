//! SN-RECONNECT (MS → SwMI), SN-PDU type 9.
//!
//! ETSI TS 100 392-2 v3.10.1 clause 28.4.4.8. NSAPI is CONDITIONAL, present
//! only when `data_to_send = true`. Real hardware sends NSAPI-less RECONNECTs
//! (verified against Motorola MTM800E live captures 2026-07-08 and Nexus-BS
//! reference implementation).

use tetra_core::{BitBuffer, expect_pdu_type, pdu_parse_error::PduParseErr};

use crate::sndcp::enums::sn_pdu_type::SnPduType;
use crate::sndcp::fields::nsapi::Nsapi;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reconnect {
    /// 1 bit `data_to_send`: when true, an NSAPI follows and MS has data ready.
    /// When false, MS is signalling readiness to receive but has no uplink data.
    pub data_to_send: bool,
    /// NSAPI (4 bits) — present iff `data_to_send == true`.
    pub nsapi: Option<Nsapi>,
}

impl Reconnect {
    pub fn from_bitbuf(buffer: &mut BitBuffer) -> Result<Self, PduParseErr> {
        let pdu_type = buffer.read_field(4, "pdu_type")?;
        expect_pdu_type!(pdu_type, SnPduType::Reconnect)?;
        let data_to_send = buffer.read_field(1, "data_to_send")? != 0;
        let nsapi = if data_to_send {
            Some(Nsapi::from_bitbuf(buffer)?)
        } else {
            None
        };
        // o-bit: no optional elements handled in V1.
        let _obit = buffer.read_field(1, "obit")?;
        Ok(Reconnect { data_to_send, nsapi })
    }

    pub fn to_bitbuf(&self, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
        buffer.write_bits(SnPduType::Reconnect.into_raw(), 4);
        buffer.write_bit(self.data_to_send as u8);
        if let Some(nsapi) = self.nsapi {
            nsapi.to_bitbuf(buffer)?;
        }
        buffer.write_bit(0); // o-bit = 0
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_default() {
        let pdu = Reconnect { data_to_send: false, nsapi: None };
        let mut buf = BitBuffer::new_autoexpand(32);
        pdu.to_bitbuf(&mut buf).unwrap();
        let bits = buf.to_bitstr();
        buf.seek(0);
        let decoded = Reconnect::from_bitbuf(&mut buf).unwrap();
        assert_eq!(decoded, pdu);
        let mut buf2 = BitBuffer::new_autoexpand(32);
        decoded.to_bitbuf(&mut buf2).unwrap();
        assert_eq!(buf2.to_bitstr(), bits);
    }

    #[test]
    fn round_trip_with_optionals() {
        let pdu = Reconnect { data_to_send: true, nsapi: Some(Nsapi(15)) };
        let mut buf = BitBuffer::new_autoexpand(32);
        pdu.to_bitbuf(&mut buf).unwrap();
        let bits = buf.to_bitstr();
        buf.seek(0);
        let decoded = Reconnect::from_bitbuf(&mut buf).unwrap();
        assert_eq!(decoded, pdu);
        let mut buf2 = BitBuffer::new_autoexpand(32);
        decoded.to_bitbuf(&mut buf2).unwrap();
        assert_eq!(buf2.to_bitstr(), bits);
    }

    #[test]
    fn decodes_minimal_6bit_wire_no_nsapi() {
        // type(4)=1001 data_to_send(1)=0 obit(1)=0 → 6 bits total, no NSAPI.
        let mut buf = BitBuffer::from_bitstr("100100");
        let decoded = Reconnect::from_bitbuf(&mut buf).unwrap();
        assert!(!decoded.data_to_send);
        assert!(decoded.nsapi.is_none());
    }
}
