//! SN-DATA-TRANSMIT-RESPONSE, SN-PDU type 7 (BS → MS only).
//!
//! ETSI TS 100 392-2 v3.10.1 clause 28.4.4.6, Table 28.31.
//! Reject-cause table: Table 28.125.

use tetra_core::{BitBuffer, expect_pdu_type, pdu_parse_error::PduParseErr};

use crate::sndcp::enums::sn_pdu_type::SnPduType;
use crate::sndcp::enums::transmit_response_reject_cause::TransmitResponseRejectCause;
use crate::sndcp::fields::nsapi::Nsapi;

/// SN-DATA-TRANSMIT-RESPONSE (type 7). Sent by the BS to accept or reject
/// an MS SN-DATA-TRANSMIT-REQUEST.
///
/// Ref: ETSI TS 100 392-2 v3.10.1 clause 28.4.4.6, Table 28.31.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnDataTransmitResponse {
    /// NSAPI echoed from the corresponding request (4 bits).
    pub nsapi: Nsapi,
    /// 1 bit: `true` = grant, `false` = deny.
    pub accept: bool,
    /// Reject cause (8 bits). Present iff `accept = false`.
    ///
    /// Ref: ETSI TS 100 392-2 v3.10.1 Table 28.125.
    pub transmit_response_reject_cause: Option<TransmitResponseRejectCause>,
    /// o-bit (1 bit): 1 iff a type-2 optional block follows.
    pub o_bit: bool,
    /// SNDCP Network Endpoint Identifier (16 bits). Present iff o_bit.
    ///
    /// NOTE: spec ambiguous — chosen behaviour: SNEI always read/written when
    /// o_bit = 1; P-bit wrapper not separately parsed in V1.
    pub sndcp_network_endpoint_identifier: Option<u16>,
    /// m-bit (1 bit): 1 iff additional NSAPI block follows.
    pub m_bit: bool,
    /// Additional NSAPIs (4 bits each) present when m_bit = 1.
    pub nsapi_additional: Vec<u8>,
}

impl SnDataTransmitResponse {
    pub fn from_bitbuf(buffer: &mut BitBuffer) -> Result<Self, PduParseErr> {
        let pdu_type = buffer.read_field(4, "pdu_type")?;
        expect_pdu_type!(pdu_type, SnPduType::DataTransmitResponse)?;
        let nsapi = Nsapi::from_bitbuf(buffer)?;
        let accept = buffer.read_field(1, "accept")? != 0;
        let transmit_response_reject_cause = if !accept {
            let raw = buffer.read_field(8, "reject_cause")? as u8;
            Some(TransmitResponseRejectCause::from(raw))
        } else {
            None
        };
        let o_bit = buffer.read_field(1, "o_bit")? != 0;
        let sndcp_network_endpoint_identifier = if o_bit {
            // NOTE: spec ambiguous — chosen behaviour: V1 reads SNEI (16 bits)
            // whenever o_bit is set without separately parsing the P-bit wrapper.
            Some(buffer.read_field(16, "snei")? as u16)
        } else {
            None
        };
        let m_bit = buffer.read_field(1, "m_bit")? != 0;
        let mut nsapi_additional = Vec::new();
        if m_bit {
            loop {
                let extra_nsapi = buffer.read_field(4, "nsapi_additional")? as u8;
                nsapi_additional.push(extra_nsapi);
                let more = buffer.read_field(1, "m_bit_continued")?;
                if more == 0 {
                    break;
                }
            }
        }
        Ok(SnDataTransmitResponse {
            nsapi,
            accept,
            transmit_response_reject_cause,
            o_bit,
            sndcp_network_endpoint_identifier,
            m_bit,
            nsapi_additional,
        })
    }

    pub fn to_bitbuf(&self, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
        buffer.write_bits(SnPduType::DataTransmitResponse.into_raw(), 4);
        self.nsapi.to_bitbuf(buffer)?;
        buffer.write_bits(self.accept as u64, 1);
        if let Some(cause) = &self.transmit_response_reject_cause {
            buffer.write_bits(cause.into_raw() as u64, 8);
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
    fn round_trip_accept() {
        let pdu = SnDataTransmitResponse {
            nsapi: Nsapi(4),
            accept: true,
            transmit_response_reject_cause: None,
            o_bit: false,
            sndcp_network_endpoint_identifier: None,
            m_bit: false,
            nsapi_additional: vec![],
        };
        let mut buf = BitBuffer::new_autoexpand(64);
        pdu.to_bitbuf(&mut buf).unwrap();
        let bits = buf.to_bitstr();
        buf.seek(0);
        let decoded = SnDataTransmitResponse::from_bitbuf(&mut buf).unwrap();
        assert_eq!(decoded, pdu);
        let mut buf2 = BitBuffer::new_autoexpand(64);
        decoded.to_bitbuf(&mut buf2).unwrap();
        assert_eq!(buf2.to_bitstr(), bits);
    }

    #[test]
    fn round_trip_with_optionals() {
        let pdu = SnDataTransmitResponse {
            nsapi: Nsapi(9),
            accept: false,
            transmit_response_reject_cause: Some(TransmitResponseRejectCause::UnknownNsapi),
            o_bit: true,
            sndcp_network_endpoint_identifier: Some(0x1234),
            m_bit: true,
            nsapi_additional: vec![10, 11],
        };
        let mut buf = BitBuffer::new_autoexpand(128);
        pdu.to_bitbuf(&mut buf).unwrap();
        let bits = buf.to_bitstr();
        buf.seek(0);
        let decoded = SnDataTransmitResponse::from_bitbuf(&mut buf).unwrap();
        assert_eq!(decoded, pdu);
        let mut buf2 = BitBuffer::new_autoexpand(128);
        decoded.to_bitbuf(&mut buf2).unwrap();
        assert_eq!(buf2.to_bitstr(), bits);
    }
}
