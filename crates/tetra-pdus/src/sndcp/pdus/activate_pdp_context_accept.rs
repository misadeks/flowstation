//! SN-ACTIVATE PDP CONTEXT ACCEPT (SwMI → MS), SN-PDU type 0, table 28.23.

use std::net::Ipv4Addr;

use tetra_core::typed_pdu_fields::*;
use tetra_core::{BitBuffer, expect_pdu_type, pdu_parse_error::PduParseErr};

use crate::sndcp::enums::sn_pdu_type::SnPduType;
use crate::sndcp::enums::tia::Tia;
use crate::sndcp::fields::ip_address;
use crate::sndcp::fields::mtu::Mtu;
use crate::sndcp::fields::nsapi::Nsapi;
use crate::sndcp::fields::pco::Pco;
use crate::sndcp::fields::snei::Snei;
use crate::sndcp::fields::timer_value::{ReadyTimer, ResponseWaitTimer, StandbyTimer};
use crate::sndcp::pdus::{read_type3_chain_pco, write_type3_chain_pco};

/// PCOMP MSB (bit 7): V.J. TCP/IP header compression granted.
const PCOMP_VJ_MASK: u8 = 0x80;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivatePdpContextAccept {
    pub nsapi: Nsapi,
    /// 3 bits.
    pub pdu_priority_max: u8,
    pub ready_timer: ReadyTimer,
    pub standby_timer: StandbyTimer,
    pub response_wait_timer: ResponseWaitTimer,
    pub tia: Tia,
    /// Present iff `tia` is Ipv4Static or Ipv4Dynamic.
    pub ip4_address: Option<Ipv4Addr>,
    /// 8 bits.
    pub pcomp: u8,
    /// Present iff PCOMP bit 7 == 1.
    pub vj_slots: Option<u8>,
    pub mtu: Mtu,
    pub snei: Option<Snei>,
    pub pco: Option<Pco>,
}

impl ActivatePdpContextAccept {
    pub fn from_bitbuf(buffer: &mut BitBuffer) -> Result<Self, PduParseErr> {
        let pdu_type = buffer.read_field(4, "pdu_type")?;
        expect_pdu_type!(pdu_type, SnPduType::ActivatePdpContext)?;

        let nsapi = Nsapi::from_bitbuf(buffer)?;
        let pdu_priority_max = buffer.read_field(3, "pdu_priority_max")? as u8;
        let ready_timer = ReadyTimer(buffer.read_field(4, "ready_timer")? as u8);
        let standby_timer = StandbyTimer(buffer.read_field(4, "standby_timer")? as u8);
        let response_wait_timer = ResponseWaitTimer(buffer.read_field(4, "response_wait_timer")? as u8);

        let tia_raw = buffer.read_field(3, "tia")?;
        let tia = Tia::try_from(tia_raw).map_err(|_| PduParseErr::InvalidValue { field: "tia", value: tia_raw })?;

        let ip4_address = match tia {
            Tia::Ipv4Static | Tia::Ipv4Dynamic => Some(ip_address::read_ipv4(buffer)?),
            Tia::Ipv6Static | Tia::Ipv6Dynamic => {
                return Err(PduParseErr::NotImplemented { field: Some("accept_ipv6_address") });
            }
            _ => None,
        };

        let pcomp = buffer.read_field(8, "pcomp")? as u8;
        let vj_slots = if pcomp & PCOMP_VJ_MASK != 0 {
            Some(buffer.read_field(8, "vj_slots")? as u8)
        } else {
            None
        };

        let mtu_raw = buffer.read_field(3, "mtu")? as u8;
        let mtu = Mtu::try_from(mtu_raw).map_err(|_| PduParseErr::InvalidValue { field: "mtu", value: mtu_raw as u64 })?;

        let mut snei = None;
        let mut pco = None;
        let obit = delimiters::read_obit(buffer)?;
        if obit {
            let snei_present = buffer.read_field(1, "snei_present")? == 1;
            let swmi_ipv6_present = buffer.read_field(1, "swmi_ipv6_present")? == 1;
            let swmi_mobipv4_present = buffer.read_field(1, "swmi_mobipv4_present")? == 1;
            if snei_present {
                snei = Some(Snei::from_bitbuf(buffer)?);
            }
            if swmi_ipv6_present {
                return Err(PduParseErr::NotImplemented { field: Some("accept_swmi_ipv6") });
            }
            if swmi_mobipv4_present {
                return Err(PduParseErr::NotImplemented { field: Some("accept_swmi_mobipv4") });
            }
            pco = read_type3_chain_pco(buffer)?;
        }

        Ok(ActivatePdpContextAccept {
            nsapi,
            pdu_priority_max,
            ready_timer,
            standby_timer,
            response_wait_timer,
            tia,
            ip4_address,
            pcomp,
            vj_slots,
            mtu,
            snei,
            pco,
        })
    }

    pub fn to_bitbuf(&self, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
        buffer.write_bits(SnPduType::ActivatePdpContext.into_raw(), 4);
        self.nsapi.to_bitbuf(buffer)?;
        buffer.write_bits(self.pdu_priority_max as u64, 3);
        buffer.write_bits(self.ready_timer.into_raw(), 4);
        buffer.write_bits(self.standby_timer.into_raw(), 4);
        buffer.write_bits(self.response_wait_timer.into_raw(), 4);
        buffer.write_bits(self.tia.into_raw(), 3);
        if let Some(addr) = &self.ip4_address {
            ip_address::write_ipv4(buffer, addr);
        }
        buffer.write_bits(self.pcomp as u64, 8);
        if let Some(vj) = self.vj_slots {
            buffer.write_bits(vj as u64, 8);
        }
        buffer.write_bits(self.mtu.into_raw(), 3);

        let obit = self.snei.is_some() || self.pco.is_some();
        delimiters::write_obit(buffer, obit as u8);
        if obit {
            buffer.write_bit(self.snei.is_some() as u8); // SNEI_present
            buffer.write_bit(0); // SwMI_IPv6_present
            buffer.write_bit(0); // SwMI_MobIPv4_present
            if let Some(snei) = &self.snei {
                snei.to_bitbuf(buffer)?;
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

    fn base() -> ActivatePdpContextAccept {
        ActivatePdpContextAccept {
            nsapi: Nsapi(1),
            pdu_priority_max: 4,
            ready_timer: ReadyTimer(8),
            standby_timer: StandbyTimer(5),
            response_wait_timer: ResponseWaitTimer(8),
            tia: Tia::Ipv4Static,
            ip4_address: Some(Ipv4Addr::new(192, 168, 1, 180)),
            pcomp: 0,
            vj_slots: None,
            mtu: Mtu(4),
            snei: None,
            pco: None,
        }
    }

    fn assert_round_trip(pdu: &ActivatePdpContextAccept) {
        let mut buf = BitBuffer::new_autoexpand(256);
        pdu.to_bitbuf(&mut buf).unwrap();
        let bits = buf.to_bitstr();
        buf.seek(0);
        let decoded = ActivatePdpContextAccept::from_bitbuf(&mut buf).unwrap();
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
    fn round_trip_with_optionals() {
        let mut pdu = base();
        pdu.tia = Tia::Ipv4Dynamic;
        pdu.pcomp = 0x80;
        pdu.vj_slots = Some(3);
        pdu.snei = Some(Snei(0x1234));
        pdu.pco = Some(Pco {
            configuration_protocol: ConfigurationProtocol::Ppp,
            entries: vec![PcoEntry {
                protocol_identity: ProtocolIdentity::Chap,
                contents: vec![3, 5, 0, 4],
            }],
        });
        assert_round_trip(&pdu);
    }

    #[test]
    fn round_trip_no_ip() {
        let mut pdu = base();
        pdu.tia = Tia::NoIpAddress;
        pdu.ip4_address = None;
        assert_round_trip(&pdu);
    }
}
