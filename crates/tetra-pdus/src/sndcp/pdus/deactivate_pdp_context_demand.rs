//! SN-DEACTIVATE PDP CONTEXT DEMAND (either direction), SN-PDU type 2.

use tetra_core::typed_pdu_fields::*;
use tetra_core::{BitBuffer, expect_pdu_type, pdu_parse_error::PduParseErr};

use crate::sndcp::enums::deactivation_type::DeactivationType;
use crate::sndcp::enums::sn_pdu_type::SnPduType;
use crate::sndcp::fields::nsapi::Nsapi;
use crate::sndcp::fields::snei::Snei;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeactivatePdpContextDemand {
    pub deactivation_type: DeactivationType,
    pub nsapi: Nsapi,
    pub snei: Option<Snei>,
}

impl DeactivatePdpContextDemand {
    pub fn from_bitbuf(buffer: &mut BitBuffer) -> Result<Self, PduParseErr> {
        let pdu_type = buffer.read_field(4, "pdu_type")?;
        expect_pdu_type!(pdu_type, SnPduType::DeactivatePdpContextDemand)?;
        let dt_raw = buffer.read_field(8, "deactivation_type")?;
        let deactivation_type = DeactivationType::try_from(dt_raw)
            .map_err(|_| PduParseErr::InvalidValue { field: "deactivation_type", value: dt_raw })?;
        let nsapi = Nsapi::from_bitbuf(buffer)?;

        let mut snei = None;
        let obit = delimiters::read_obit(buffer)?;
        if obit {
            let snei_present = buffer.read_field(1, "snei_present")? == 1;
            if snei_present {
                snei = Some(Snei::from_bitbuf(buffer)?);
            }
            let mbit = delimiters::read_mbit(buffer)?;
            if mbit {
                return Err(PduParseErr::NotImplemented { field: Some("deactivate_demand_type3") });
            }
        }
        Ok(DeactivatePdpContextDemand { deactivation_type, nsapi, snei })
    }

    pub fn to_bitbuf(&self, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
        buffer.write_bits(SnPduType::DeactivatePdpContextDemand.into_raw(), 4);
        buffer.write_bits(self.deactivation_type.into_raw(), 8);
        self.nsapi.to_bitbuf(buffer)?;

        let obit = self.snei.is_some();
        delimiters::write_obit(buffer, obit as u8);
        if obit {
            buffer.write_bit(self.snei.is_some() as u8); // SNEI_present
            if let Some(snei) = &self.snei {
                snei.to_bitbuf(buffer)?;
            }
            delimiters::write_mbit(buffer, 0);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_default() {
        let pdu = DeactivatePdpContextDemand {
            deactivation_type: DeactivationType::Normal,
            nsapi: Nsapi(1),
            snei: None,
        };
        let mut buf = BitBuffer::new_autoexpand(64);
        pdu.to_bitbuf(&mut buf).unwrap();
        let bits = buf.to_bitstr();
        buf.seek(0);
        let decoded = DeactivatePdpContextDemand::from_bitbuf(&mut buf).unwrap();
        assert_eq!(decoded, pdu);
        let mut buf2 = BitBuffer::new_autoexpand(64);
        decoded.to_bitbuf(&mut buf2).unwrap();
        assert_eq!(buf2.to_bitstr(), bits);
    }

    #[test]
    fn round_trip_with_optionals() {
        let pdu = DeactivatePdpContextDemand {
            deactivation_type: DeactivationType::NetworkInitiated,
            nsapi: Nsapi(9),
            snei: Some(Snei(0xBEEF)),
        };
        let mut buf = BitBuffer::new_autoexpand(64);
        pdu.to_bitbuf(&mut buf).unwrap();
        let bits = buf.to_bitstr();
        buf.seek(0);
        let decoded = DeactivatePdpContextDemand::from_bitbuf(&mut buf).unwrap();
        assert_eq!(decoded, pdu);
        let mut buf2 = BitBuffer::new_autoexpand(64);
        decoded.to_bitbuf(&mut buf2).unwrap();
        assert_eq!(buf2.to_bitstr(), bits);
    }
}
