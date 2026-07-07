//! SN-ACTIVATE PDP CONTEXT DEMAND (MS → SwMI), SN-PDU type 0, table 28.24.

use std::net::Ipv4Addr;

use tetra_core::typed_pdu_fields::*;
use tetra_core::{BitBuffer, expect_pdu_type, pdu_parse_error::PduParseErr};

use crate::sndcp::enums::pdms_type::PdmsType;
use crate::sndcp::enums::sn_pdu_type::SnPduType;
use crate::sndcp::fields::ip_address;
use crate::sndcp::fields::nsapi::Nsapi;
use crate::sndcp::fields::pco::Pco;
use crate::sndcp::fields::snei::Snei;
use crate::sndcp::pdus::{read_type3_chain_pco, write_type3_chain_pco};

/// PCOMPNegotiation MSB (bit 7): V.J. TCP/IP header compression requested.
const PCOMP_VJ_MASK: u8 = 0x80;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivatePdpContextDemand {
    /// 4 bits, = 0 for this spec version.
    pub sndcp_version: u8,
    pub nsapi: Nsapi,
    /// 3 bits. 0 = static (MS supplies IPv4), 1..7 = dynamic.
    pub atid: u8,
    /// Present iff `atid == 0`.
    pub ip_address: Option<Ipv4Addr>,
    pub pdms_type: PdmsType,
    /// 8 bits.
    pub pcomp_negotiation: u8,
    /// Present iff PCOMPNegotiation bit 7 == 1.
    pub vj_slots: Option<u8>,
    pub snei: Option<Snei>,
    pub apn: Option<Vec<u8>>,
    pub pco: Option<Pco>,
}

impl ActivatePdpContextDemand {
    pub fn from_bitbuf(buffer: &mut BitBuffer) -> Result<Self, PduParseErr> {
        let pdu_type = buffer.read_field(4, "pdu_type")?;
        expect_pdu_type!(pdu_type, SnPduType::ActivatePdpContext)?;

        let sndcp_version = buffer.read_field(4, "sndcp_version")? as u8;
        let nsapi = Nsapi::from_bitbuf(buffer)?;
        let atid = buffer.read_field(3, "atid")? as u8;
        let ip_address = if atid == 0 { Some(ip_address::read_ipv4(buffer)?) } else { None };

        let pdms_raw = buffer.read_field(4, "pdms_type")?;
        let pdms_type =
            PdmsType::try_from(pdms_raw).map_err(|_| PduParseErr::InvalidValue { field: "pdms_type", value: pdms_raw })?;

        let pcomp_negotiation = buffer.read_field(8, "pcomp_negotiation")? as u8;
        let vj_slots = if pcomp_negotiation & PCOMP_VJ_MASK != 0 {
            Some(buffer.read_field(8, "vj_slots")? as u8)
        } else {
            None
        };

        let mut snei = None;
        let mut apn = None;
        let mut pco = None;
        let obit = delimiters::read_obit(buffer)?;
        if obit {
            // NOTE: spec ambiguous — chosen behaviour: presence flags (SNEI, SwMI IPv6,
            // SwMI MobIPv4) appear first, then APN_Present, matching table 28.23's three
            // type-2 presence bits preceding the APN element.
            let snei_present = buffer.read_field(1, "snei_present")? == 1;
            let swmi_ipv6_present = buffer.read_field(1, "swmi_ipv6_present")? == 1;
            let swmi_mobipv4_present = buffer.read_field(1, "swmi_mobipv4_present")? == 1;
            let apn_present = buffer.read_field(1, "apn_present")? == 1;

            if snei_present {
                snei = Some(Snei::from_bitbuf(buffer)?);
            }
            if swmi_ipv6_present {
                return Err(PduParseErr::NotImplemented { field: Some("demand_swmi_ipv6") });
            }
            if swmi_mobipv4_present {
                return Err(PduParseErr::NotImplemented { field: Some("demand_swmi_mobipv4") });
            }
            if apn_present {
                let len = buffer.read_field(8, "apn_length")? as usize;
                let mut bytes = Vec::with_capacity(len);
                for _ in 0..len {
                    bytes.push(buffer.read_field(8, "apn_octet")? as u8);
                }
                apn = Some(bytes);
            }

            pco = read_type3_chain_pco(buffer)?;
        }

        Ok(ActivatePdpContextDemand {
            sndcp_version,
            nsapi,
            atid,
            ip_address,
            pdms_type,
            pcomp_negotiation,
            vj_slots,
            snei,
            apn,
            pco,
        })
    }

    pub fn to_bitbuf(&self, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
        buffer.write_bits(SnPduType::ActivatePdpContext.into_raw(), 4);
        buffer.write_bits(self.sndcp_version as u64, 4);
        self.nsapi.to_bitbuf(buffer)?;
        buffer.write_bits(self.atid as u64, 3);
        if let Some(addr) = &self.ip_address {
            ip_address::write_ipv4(buffer, addr);
        }
        buffer.write_bits(self.pdms_type.into_raw(), 4);
        buffer.write_bits(self.pcomp_negotiation as u64, 8);
        if let Some(vj) = self.vj_slots {
            buffer.write_bits(vj as u64, 8);
        }

        let obit = self.snei.is_some() || self.apn.is_some() || self.pco.is_some();
        delimiters::write_obit(buffer, obit as u8);
        if obit {
            buffer.write_bit(self.snei.is_some() as u8); // SNEI_present
            buffer.write_bit(0); // SwMI_IPv6_present
            buffer.write_bit(0); // SwMI_MobIPv4_present
            buffer.write_bit(self.apn.is_some() as u8); // APN_Present
            if let Some(snei) = &self.snei {
                snei.to_bitbuf(buffer)?;
            }
            if let Some(apn) = &self.apn {
                buffer.write_bits(apn.len() as u64, 8);
                for &b in apn {
                    buffer.write_bits(b as u64, 8);
                }
            }
            write_type3_chain_pco(buffer, &self.pco)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sndcp::enums::configuration_protocol::ConfigurationProtocol;
    use crate::sndcp::enums::protocol_identity::ProtocolIdentity;
    use crate::sndcp::fields::pco::PcoEntry;

    fn base() -> ActivatePdpContextDemand {
        ActivatePdpContextDemand {
            sndcp_version: 0,
            nsapi: Nsapi(1),
            atid: 1, // dynamic → no IP
            ip_address: None,
            pdms_type: PdmsType::Standard,
            pcomp_negotiation: 0,
            vj_slots: None,
            snei: None,
            apn: None,
            pco: None,
        }
    }

    fn assert_round_trip(pdu: &ActivatePdpContextDemand) {
        let mut buf = BitBuffer::new_autoexpand(256);
        pdu.to_bitbuf(&mut buf).unwrap();
        let bits = buf.to_bitstr();
        buf.seek(0);
        let decoded = ActivatePdpContextDemand::from_bitbuf(&mut buf).unwrap();
        assert_eq!(&decoded, pdu);
        let mut buf2 = BitBuffer::new_autoexpand(256);
        decoded.to_bitbuf(&mut buf2).unwrap();
        assert_eq!(buf2.to_bitstr(), bits);
    }

    #[test]
    fn round_trip_default() {
        assert_round_trip(&base());
    }

    #[test]
    fn round_trip_static_ip() {
        let mut pdu = base();
        pdu.atid = 0;
        pdu.ip_address = Some(Ipv4Addr::new(10, 0, 0, 5));
        assert_round_trip(&pdu);
    }

    #[test]
    fn round_trip_with_optionals() {
        let mut pdu = base();
        pdu.pcomp_negotiation = 0x80;
        pdu.vj_slots = Some(2);
        pdu.snei = Some(Snei(0xABCD));
        pdu.apn = Some(b"internet".to_vec());
        pdu.pco = Some(Pco {
            configuration_protocol: ConfigurationProtocol::Ppp,
            entries: vec![PcoEntry {
                protocol_identity: ProtocolIdentity::Chap,
                contents: vec![2, 5, 0, 4],
            }],
        });
        assert_round_trip(&pdu);
    }
}
