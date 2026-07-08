//! SN-PDU dispatcher and shared type-3 (PCO) chain helpers.

pub mod activate_pdp_context_accept;
pub mod activate_pdp_context_demand;
pub mod activate_pdp_context_reject;
pub mod data;
pub mod data_transmit_request;
pub mod data_transmit_response;
pub mod deactivate_pdp_context_accept;
pub mod deactivate_pdp_context_demand;
pub mod end_of_data;
pub mod page_request;
pub mod page_response;
pub mod reconnect;
pub mod unitdata;

pub use activate_pdp_context_accept::ActivatePdpContextAccept;
pub use activate_pdp_context_demand::ActivatePdpContextDemand;
pub use activate_pdp_context_reject::ActivatePdpContextReject;
pub use data::SnData;
pub use data_transmit_request::{ResourceRequest, SnDataTransmitRequest};
pub use data_transmit_response::SnDataTransmitResponse;
pub use deactivate_pdp_context_accept::DeactivatePdpContextAccept;
pub use deactivate_pdp_context_demand::DeactivatePdpContextDemand;
pub use end_of_data::EndOfData;
pub use page_request::PageRequest;
pub use page_response::PageResponse;
pub use reconnect::Reconnect;
pub use unitdata::Unitdata;

use tetra_core::typed_pdu_fields::*;
use tetra_core::{BitBuffer, pdu_parse_error::PduParseErr};

use crate::sndcp::enums::sn_pdu_type::SnPduType;
use crate::sndcp::fields::pco::Pco;

/// PCO type-3/4 element identifier (table 28.127).
const PCO_ELEM_ID: u64 = 1;

/// Read an m-bit-delimited chain of type-3 elements, capturing the PCO if present.
/// Unknown element bodies are skipped. Returns the decoded PCO (if any).
pub(crate) fn read_type3_chain_pco(buffer: &mut BitBuffer) -> Result<Option<Pco>, PduParseErr> {
    let mut mbit = delimiters::read_mbit(buffer)?;
    let mut pco = None;
    while mbit {
        let elem_id = buffer.read_field(4, "t3elem_id")?;
        let elem_len = buffer.read_field(11, "t3elem_len")? as usize;
        if elem_id == PCO_ELEM_ID {
            pco = Some(Pco::from_bitbuf(buffer, elem_len)?);
        } else {
            for _ in 0..elem_len {
                buffer.read_bit().ok_or(PduParseErr::BufferEnded { field: Some("t3elem_body") })?;
            }
        }
        mbit = delimiters::read_mbit(buffer)?;
    }
    Ok(pco)
}

/// Write an m-bit-delimited chain of type-3 elements carrying an optional PCO,
/// followed by the terminating m-bit = 0.
pub(crate) fn write_type3_chain_pco(buffer: &mut BitBuffer, pco: &Option<Pco>) -> Result<(), PduParseErr> {
    if let Some(pco) = pco {
        delimiters::write_mbit(buffer, 1);
        let mut tmp = BitBuffer::new_autoexpand(256);
        let body_bits = pco.to_bitbuf(&mut tmp)?;
        buffer.write_bits(PCO_ELEM_ID, 4);
        buffer.write_bits(body_bits as u64, 11);
        tmp.seek(0);
        buffer.copy_bits(&mut tmp, body_bits);
    }
    delimiters::write_mbit(buffer, 0);
    Ok(())
}

/// A decoded SN-PDU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnPdu {
    ActivatePdpContextDemand(ActivatePdpContextDemand),
    ActivatePdpContextAccept(ActivatePdpContextAccept),
    ActivatePdpContextReject(ActivatePdpContextReject),
    DeactivatePdpContextDemand(DeactivatePdpContextDemand),
    DeactivatePdpContextAccept(DeactivatePdpContextAccept),
    Unitdata(Unitdata),
    Data(SnData),
    DataTransmitRequest(SnDataTransmitRequest),
    DataTransmitResponse(SnDataTransmitResponse),
    PageRequest(PageRequest),
    PageResponse(PageResponse),
    EndOfData(EndOfData),
    Reconnect(Reconnect),
    Unhandled { sn_pdu_type: SnPduType, remaining_bits: usize },
}

impl SnPdu {
    /// Decode an uplink (MS → SwMI) SN-PDU.
    pub fn from_bitbuf_ul(buffer: &mut BitBuffer) -> Result<Self, PduParseErr> {
        Self::from_bitbuf_dir(buffer, false)
    }

    /// Decode a downlink (SwMI → MS) SN-PDU.
    pub fn from_bitbuf_dl(buffer: &mut BitBuffer) -> Result<Self, PduParseErr> {
        Self::from_bitbuf_dir(buffer, true)
    }

    fn from_bitbuf_dir(buffer: &mut BitBuffer, downlink: bool) -> Result<Self, PduParseErr> {
        let raw = buffer.read_field(4, "sn_pdu_type")?;
        buffer.seek_rel(-4); // rewind so per-PDU decoders re-read the type
        let sn_pdu_type =
            SnPduType::try_from(raw).map_err(|_| PduParseErr::InvalidValue { field: "sn_pdu_type", value: raw })?;

        match sn_pdu_type {
            SnPduType::ActivatePdpContext => {
                if downlink {
                    Ok(SnPdu::ActivatePdpContextAccept(ActivatePdpContextAccept::from_bitbuf(buffer)?))
                } else {
                    Ok(SnPdu::ActivatePdpContextDemand(ActivatePdpContextDemand::from_bitbuf(buffer)?))
                }
            }
            SnPduType::DeactivatePdpContextAccept => {
                Ok(SnPdu::DeactivatePdpContextAccept(DeactivatePdpContextAccept::from_bitbuf(buffer)?))
            }
            SnPduType::DeactivatePdpContextDemand => {
                Ok(SnPdu::DeactivatePdpContextDemand(DeactivatePdpContextDemand::from_bitbuf(buffer)?))
            }
            SnPduType::ActivatePdpContextReject => {
                Ok(SnPdu::ActivatePdpContextReject(ActivatePdpContextReject::from_bitbuf(buffer)?))
            }
            SnPduType::Unitdata => Ok(SnPdu::Unitdata(Unitdata::from_bitbuf(buffer)?)),
            // SN-DATA (type 5): direction-symmetric wire layout, direction-specific semantics.
            SnPduType::Data => Ok(SnPdu::Data(SnData::from_bitbuf(buffer)?)),
            // SN-DATA-TRANSMIT-REQUEST (type 6): UL only (MS → BS).
            SnPduType::DataTransmitRequest if !downlink => {
                Ok(SnPdu::DataTransmitRequest(SnDataTransmitRequest::from_bitbuf(buffer)?))
            }
            // SN-DATA-TRANSMIT-RESPONSE (type 7): DL only (BS → MS).
            SnPduType::DataTransmitResponse if downlink => {
                Ok(SnPdu::DataTransmitResponse(SnDataTransmitResponse::from_bitbuf(buffer)?))
            }
            SnPduType::EndOfData => Ok(SnPdu::EndOfData(EndOfData::from_bitbuf(buffer)?)),
            SnPduType::Reconnect => Ok(SnPdu::Reconnect(Reconnect::from_bitbuf(buffer)?)),
            SnPduType::Page => {
                // Peek the subtype bit (after the 4-bit type) to route request vs response.
                buffer.seek_rel(4);
                let subtype = buffer.read_field(1, "page_subtype")?;
                buffer.seek_rel(-5);
                if subtype == 0 {
                    Ok(SnPdu::PageRequest(PageRequest::from_bitbuf(buffer)?))
                } else {
                    Ok(SnPdu::PageResponse(PageResponse::from_bitbuf(buffer)?))
                }
            }
            SnPduType::NotSupported
            | SnPduType::DataPriority
            | SnPduType::Modify
            | SnPduType::Reserved(_) => Ok(SnPdu::Unhandled {
                sn_pdu_type,
                remaining_bits: buffer.get_len_remaining(),
            }),
            // Direction-wrong: TRANSMIT-REQUEST in DL or TRANSMIT-RESPONSE in UL.
            SnPduType::DataTransmitRequest | SnPduType::DataTransmitResponse => {
                Ok(SnPdu::Unhandled {
                    sn_pdu_type,
                    remaining_bits: buffer.get_len_remaining(),
                })
            }
        }
    }

    /// Encode this SN-PDU.
    pub fn to_bitbuf(&self, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
        match self {
            SnPdu::ActivatePdpContextDemand(p) => p.to_bitbuf(buffer),
            SnPdu::ActivatePdpContextAccept(p) => p.to_bitbuf(buffer),
            SnPdu::ActivatePdpContextReject(p) => p.to_bitbuf(buffer),
            SnPdu::DeactivatePdpContextDemand(p) => p.to_bitbuf(buffer),
            SnPdu::DeactivatePdpContextAccept(p) => p.to_bitbuf(buffer),
            SnPdu::Unitdata(p) => p.to_bitbuf(buffer),
            SnPdu::Data(p) => p.to_bitbuf(buffer),
            SnPdu::DataTransmitRequest(p) => p.to_bitbuf(buffer),
            SnPdu::DataTransmitResponse(p) => p.to_bitbuf(buffer),
            SnPdu::PageRequest(p) => p.to_bitbuf(buffer),
            SnPdu::PageResponse(p) => p.to_bitbuf(buffer),
            SnPdu::EndOfData(p) => p.to_bitbuf(buffer),
            SnPdu::Reconnect(p) => p.to_bitbuf(buffer),
            SnPdu::Unhandled { sn_pdu_type, .. } => {
                Err(PduParseErr::NotImplemented { field: Some(sn_pdu_type_static_name(*sn_pdu_type)) })
            }
        }
    }
}

fn sn_pdu_type_static_name(t: SnPduType) -> &'static str {
    match t {
        SnPduType::NotSupported => "sn_not_supported",
        SnPduType::DataPriority => "sn_data_priority",
        SnPduType::Modify => "sn_modify",
        SnPduType::Reserved(_) => "sn_reserved",
        _ => "sn_unhandled",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sndcp::fields::nsapi::Nsapi;

    #[test]
    fn dispatch_end_of_data_ul() {
        let pdu = EndOfData { immediate_service_change: false };
        let mut buf = BitBuffer::new_autoexpand(32);
        pdu.to_bitbuf(&mut buf).unwrap();
        buf.seek(0);
        let decoded = SnPdu::from_bitbuf_ul(&mut buf).unwrap();
        assert_eq!(decoded, SnPdu::EndOfData(pdu));
    }

    #[test]
    fn dispatch_page_request_dl() {
        let pdu = PageRequest { nsapi: Nsapi(2) };
        let mut buf = BitBuffer::new_autoexpand(32);
        pdu.to_bitbuf(&mut buf).unwrap();
        buf.seek(0);
        let decoded = SnPdu::from_bitbuf_dl(&mut buf).unwrap();
        assert_eq!(decoded, SnPdu::PageRequest(pdu));
    }

    #[test]
    fn dispatch_page_response_ul() {
        let pdu = PageResponse { nsapi: Nsapi(5) };
        let mut buf = BitBuffer::new_autoexpand(32);
        pdu.to_bitbuf(&mut buf).unwrap();
        buf.seek(0);
        let decoded = SnPdu::from_bitbuf_ul(&mut buf).unwrap();
        assert_eq!(decoded, SnPdu::PageResponse(pdu));
    }

    #[test]
    fn dispatch_sn_data_ul() {
        use crate::sndcp::pdus::data::SnData;
        let pdu = SnData { nsapi: Nsapi(4), pcomp: 0, dcomp: 0, n_pdu: vec![0x45] };
        let mut buf = BitBuffer::new_autoexpand(32);
        pdu.to_bitbuf(&mut buf).unwrap();
        buf.seek(0);
        let decoded = SnPdu::from_bitbuf_ul(&mut buf).unwrap();
        assert!(matches!(decoded, SnPdu::Data(_)));
    }

    #[test]
    fn dispatch_data_transmit_request_ul() {
        use crate::sndcp::enums::logical_link_status::LogicalLinkStatus;
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
        let mut buf = BitBuffer::new_autoexpand(32);
        pdu.to_bitbuf(&mut buf).unwrap();
        buf.seek(0);
        let decoded = SnPdu::from_bitbuf_ul(&mut buf).unwrap();
        assert!(matches!(decoded, SnPdu::DataTransmitRequest(_)));
    }

    #[test]
    fn dispatch_data_transmit_response_dl() {
        use crate::sndcp::enums::transmit_response_reject_cause::TransmitResponseRejectCause;
        let pdu = SnDataTransmitResponse {
            nsapi: Nsapi(5),
            accept: false,
            transmit_response_reject_cause: Some(TransmitResponseRejectCause::UnknownNsapi),
            o_bit: false,
            sndcp_network_endpoint_identifier: None,
            m_bit: false,
            nsapi_additional: vec![],
        };
        let mut buf = BitBuffer::new_autoexpand(32);
        pdu.to_bitbuf(&mut buf).unwrap();
        buf.seek(0);
        let decoded = SnPdu::from_bitbuf_dl(&mut buf).unwrap();
        assert!(matches!(decoded, SnPdu::DataTransmitResponse(_)));
    }

    #[test]
    fn transmit_request_in_dl_is_unhandled() {
        // DataTransmitRequest (type 6) in a downlink context is direction-wrong → Unhandled.
        use crate::sndcp::enums::logical_link_status::LogicalLinkStatus;
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
        let mut buf = BitBuffer::new_autoexpand(32);
        pdu.to_bitbuf(&mut buf).unwrap();
        buf.seek(0);
        let decoded = SnPdu::from_bitbuf_dl(&mut buf).unwrap();
        assert!(matches!(decoded, SnPdu::Unhandled { sn_pdu_type: SnPduType::DataTransmitRequest, .. }));
    }
}
