//! SN-DATA-TRANSMIT-REQUEST, SN-PDU type 6 (MS → BS only).
//!
//! ETSI TS 100 392-2 v3.10.1 clause 28.4.4.5, Table 28.30.
//! Resource request sub-structure: Table 28.115.

use tetra_core::{BitBuffer, expect_pdu_type, pdu_parse_error::PduParseErr};

use crate::llc::enums::data_transfer_throughput::DataTransferThroughput;
use crate::sndcp::enums::connection_symmetry::ConnectionSymmetry;
use crate::sndcp::enums::logical_link_status::LogicalLinkStatus;
use crate::sndcp::enums::sn_pdu_type::SnPduType;
use crate::sndcp::fields::nsapi::Nsapi;

/// Resource request embedded in SN-DATA-TRANSMIT-REQUEST when
/// `enhanced_pi4_dqpsk_service = true`.
///
/// Ref: ETSI TS 100 392-2 v3.10.1 Table 28.115.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceRequest {
    /// Connection symmetry (1 bit): 0=symmetric, 1=asymmetric.
    pub connection_symmetry: ConnectionSymmetry,
    /// Data transfer throughput class (3 bits). Reuses the LLC AL-1 enum.
    pub data_transfer_throughput: DataTransferThroughput,
    /// Number of UL slots (symmetric) or UL+DL count (asymmetric UL side) (2 bits).
    pub n_ul_or_ul_dl_slots: u8,
    /// Number of DL slots (2 bits); present only when `connection_symmetry = Asymmetric`.
    pub n_dl_slots: Option<u8>,
    /// Full PM capability (2 bits). Values 0..3.
    pub full_pm_capability: u8,
    // Reserved 2 bits: must be 0b11 on emit; any value accepted on parse.
}

/// SN-DATA-TRANSMIT-REQUEST (type 6). Sent by an MS to request acknowledged
/// packet-data transfer after PDP context activation.
///
/// Ref: ETSI TS 100 392-2 v3.10.1 clause 28.4.4.5, Table 28.30.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnDataTransmitRequest {
    pub nsapi: Nsapi,
    /// Logical Link Status (1 bit).
    pub logical_link_status: LogicalLinkStatus,
    /// `enhanced_pi4_dqpsk_service` (1 bit): 1 iff `resource_request` is present.
    pub enhanced_pi4_dqpsk_service: bool,
    /// Present iff `enhanced_pi4_dqpsk_service == true`.
    pub resource_request: Option<ResourceRequest>,
    /// o-bit (1 bit): 1 iff a type-2 optional block follows.
    pub o_bit: bool,
    /// SNDCP Network Endpoint Identifier (16 bits). Present iff o_bit && P-bit in
    /// the type-2 header.
    ///
    /// NOTE: spec ambiguous — chosen behaviour: V1 codec reads/writes the full
    /// 16-bit SNEI whenever o_bit is set, without separately parsing the P-bit
    /// wrapper; the SNEI is always treated as present when o_bit = 1.
    pub sndcp_network_endpoint_identifier: Option<u16>,
    /// m-bit (1 bit): 1 iff additional NSAPI block follows.
    pub m_bit: bool,
    /// Additional NSAPIs (4 bits each) present when m_bit = 1.
    pub nsapi_additional: Vec<u8>,
}

impl ResourceRequest {
    fn from_bitbuf(buffer: &mut BitBuffer, asymmetric: bool) -> Result<Self, PduParseErr> {
        let data_transfer_throughput = DataTransferThroughput::try_from(
            buffer.read_field(3, "data_transfer_throughput")?,
        )
        .map_err(|_| PduParseErr::InvalidValue { field: "data_transfer_throughput", value: 0 })?;
        let n_ul_or_ul_dl_slots = buffer.read_field(2, "n_ul_or_ul_dl_slots")? as u8;
        let n_dl_slots = if asymmetric {
            Some(buffer.read_field(2, "n_dl_slots")? as u8)
        } else {
            None
        };
        let full_pm_capability = buffer.read_field(2, "full_pm_capability")? as u8;
        // Reserved 2 bits — accept anything on parse.
        let _reserved = buffer.read_field(2, "res_rr");
        Ok(ResourceRequest {
            connection_symmetry: if asymmetric {
                ConnectionSymmetry::Asymmetric
            } else {
                ConnectionSymmetry::Symmetric
            },
            data_transfer_throughput,
            n_ul_or_ul_dl_slots,
            n_dl_slots,
            full_pm_capability,
        })
    }

    fn to_bitbuf(&self, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
        buffer.write_bits(self.data_transfer_throughput.into_raw(), 3);
        buffer.write_bits(self.n_ul_or_ul_dl_slots as u64, 2);
        if let Some(dl) = self.n_dl_slots {
            buffer.write_bits(dl as u64, 2);
        }
        buffer.write_bits(self.full_pm_capability as u64, 2);
        buffer.write_bits(0b11, 2); // reserved, MUST be 11₂ on emit
        Ok(())
    }
}

impl SnDataTransmitRequest {
    pub fn from_bitbuf(buffer: &mut BitBuffer) -> Result<Self, PduParseErr> {
        let pdu_type = buffer.read_field(4, "pdu_type")?;
        expect_pdu_type!(pdu_type, SnPduType::DataTransmitRequest)?;
        let nsapi = Nsapi::from_bitbuf(buffer)?;
        let lls_raw = buffer.read_field(1, "logical_link_status")?;
        let logical_link_status = LogicalLinkStatus::try_from(lls_raw)
            .map_err(|_| PduParseErr::InvalidValue { field: "logical_link_status", value: lls_raw })?;
        let enhanced = buffer.read_field(1, "enhanced_pi4_dqpsk_service")? != 0;

        let resource_request = if enhanced {
            // Read connection_symmetry first to know if n_dl_slots follows.
            let sym_raw = buffer.read_field(1, "connection_symmetry")?;
            let asymmetric = sym_raw != 0;
            Some(ResourceRequest::from_bitbuf(buffer, asymmetric)?)
        } else {
            None
        };

        let o_bit = buffer.read_field(1, "o_bit")? != 0;
        let sndcp_network_endpoint_identifier = if o_bit {
            // NOTE: spec ambiguous — chosen behaviour: read SNEI (16 bits) whenever
            // o_bit is set; P-bit wrapper not separately parsed in V1.
            Some(buffer.read_field(16, "snei")? as u16)
        } else {
            None
        };

        let m_bit = buffer.read_field(1, "m_bit")? != 0;
        let mut nsapi_additional = Vec::new();
        if m_bit {
            // Read additional NSAPIs until m_bit = 0 in each subsequent block.
            loop {
                let extra_nsapi = buffer.read_field(4, "nsapi_additional")? as u8;
                nsapi_additional.push(extra_nsapi);
                let more = buffer.read_field(1, "m_bit_continued")?;
                if more == 0 {
                    break;
                }
            }
        }

        Ok(SnDataTransmitRequest {
            nsapi,
            logical_link_status,
            enhanced_pi4_dqpsk_service: enhanced,
            resource_request,
            o_bit,
            sndcp_network_endpoint_identifier,
            m_bit,
            nsapi_additional,
        })
    }

    pub fn to_bitbuf(&self, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
        buffer.write_bits(SnPduType::DataTransmitRequest.into_raw(), 4);
        self.nsapi.to_bitbuf(buffer)?;
        buffer.write_bits(self.logical_link_status.into_raw(), 1);
        buffer.write_bits(self.enhanced_pi4_dqpsk_service as u64, 1);
        if let Some(rr) = &self.resource_request {
            // Write connection_symmetry first, then the rest of ResourceRequest.
            buffer.write_bits(rr.connection_symmetry.into_raw(), 1);
            rr.to_bitbuf(buffer)?;
        }
        buffer.write_bits(self.o_bit as u64, 1);
        if let Some(snei) = self.sndcp_network_endpoint_identifier {
            buffer.write_bits(snei as u64, 16);
        }
        buffer.write_bits(self.m_bit as u64, 1);
        if self.m_bit {
            let last = self.nsapi_additional.len().saturating_sub(1);
            for (i, &extra) in self.nsapi_additional.iter().enumerate() {
                buffer.write_bits(extra as u64, 4);
                // m_bit continuation: 1 if more follow, 0 on last.
                buffer.write_bits(if i < last { 1 } else { 0 }, 1);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_default() {
        let pdu = SnDataTransmitRequest {
            nsapi: Nsapi(3),
            logical_link_status: LogicalLinkStatus::NotConnected,
            enhanced_pi4_dqpsk_service: false,
            resource_request: None,
            o_bit: false,
            sndcp_network_endpoint_identifier: None,
            m_bit: false,
            nsapi_additional: vec![],
        };
        let mut buf = BitBuffer::new_autoexpand(64);
        pdu.to_bitbuf(&mut buf).unwrap();
        let bits = buf.to_bitstr();
        buf.seek(0);
        let decoded = SnDataTransmitRequest::from_bitbuf(&mut buf).unwrap();
        assert_eq!(decoded, pdu);
        let mut buf2 = BitBuffer::new_autoexpand(64);
        decoded.to_bitbuf(&mut buf2).unwrap();
        assert_eq!(buf2.to_bitstr(), bits);
    }

    #[test]
    fn round_trip_with_optionals() {
        let pdu = SnDataTransmitRequest {
            nsapi: Nsapi(5),
            logical_link_status: LogicalLinkStatus::Connected,
            enhanced_pi4_dqpsk_service: true,
            resource_request: Some(ResourceRequest {
                connection_symmetry: ConnectionSymmetry::Asymmetric,
                data_transfer_throughput: DataTransferThroughput::OneOver4,
                n_ul_or_ul_dl_slots: 2,
                n_dl_slots: Some(3),
                full_pm_capability: 1,
            }),
            o_bit: true,
            sndcp_network_endpoint_identifier: Some(0xABCD),
            m_bit: true,
            nsapi_additional: vec![6, 7],
        };
        let mut buf = BitBuffer::new_autoexpand(128);
        pdu.to_bitbuf(&mut buf).unwrap();
        let bits = buf.to_bitstr();
        buf.seek(0);
        let decoded = SnDataTransmitRequest::from_bitbuf(&mut buf).unwrap();
        assert_eq!(decoded, pdu);
        let mut buf2 = BitBuffer::new_autoexpand(128);
        decoded.to_bitbuf(&mut buf2).unwrap();
        assert_eq!(buf2.to_bitstr(), bits);
    }
}
