// Clause 17.3.5 Service state diagram for the LTPD-SAP (MLE-SNDCP)

#![allow(unused)]
use tetra_core::{BitBuffer, EndpointId, Layer2Service, LinkId, TetraAddress, Todo, TxReporter};

use crate::lcmc::fields::chan_alloc_req::CmceChanAllocReq;

#[derive(Debug, Clone)]
pub struct LtpdMleActivityReq {
    pub sleep_mode: bool,
}

#[derive(Debug, Clone)]
pub struct LtpdMleBreakInd {}

#[derive(Debug, Clone)]
pub struct LtpdMleBusyInd {}

#[derive(Debug, Clone)]
pub struct LtpdMleCancelReq {
    pub handle: Todo,
}

#[derive(Debug, Clone)]
pub struct LtpdMleCloseInd {}

#[derive(Debug, Clone)]
pub struct LtpdMleConfigureReq {
    pub chan_change_accepted: bool,
    pub chan_change_handle: Todo,
    pub call_release: Todo,
    pub endpoint_id: EndpointId,
    pub encryption_flag: bool,
    pub ms_default_data_prio: Todo,
    pub layer2_data_prio_lifetime: Todo,
    pub layer2_data_prio_signalling_delay: Todo,
    pub data_prio_random_access_delay_factor: Todo,
    pub data_class_info: Todo,
    pub schedule_repetition_info: Todo,
    pub sndcp_status: Todo,
}

#[derive(Debug, Clone)]
pub struct LtpdMleConfigureInd {
    pub endpoint_id: EndpointId,
    pub chan_change_responce_required: bool,
    pub chan_change_handle: Todo,
    pub reason_for_config_indication: Todo,
    pub conflicting_endpoint_id: EndpointId,
}

#[derive(Debug, Clone)]
pub struct LtpdMleConnectReq {
    pub address: Todo,
    pub endpoint_id: EndpointId,
    pub link_id: LinkId,
    pub reservation_info: Todo,
    pub pdu_prio: Todo,
    pub layer2_qos: Todo,
    pub encryption_flag: bool,
    pub setup_report: Todo,
}

#[derive(Debug, Clone)]
pub struct LtpdMleConnectInd {
    pub address: Todo,
    pub endpoint_id: EndpointId,
    pub new_endpoint_id: EndpointId,
    pub link_id: LinkId,
    pub layer2_qos: Todo,
    pub encryption_flag: bool,
    pub chan_change_resp_req: bool,
    pub chan_change_handle: Option<Todo>,
    pub setup_report: Todo,
}

#[derive(Debug, Clone)]
pub struct LtpdMleConnectResp {
    pub address: Todo,
    pub endpoint_id: EndpointId,
    pub link_id: LinkId,
    pub pdu_prio: Todo,
    pub stealing_permission: bool,
    pub layer2_qos: Todo,
    pub encryption_flag: bool,
    pub setup_report: Todo,
}

#[derive(Debug, Clone)]
pub struct LtpdMleConnectConfirm {
    pub address: Todo,
    pub endpoint_id: EndpointId,
    pub link_id: LinkId,
    pub layer2_qos: Todo,
    pub encryption_flag: bool,
    pub channel_change_resp_req: bool,
    pub channel_change_handle: Todo,
    pub setup_report: Todo,
}

#[derive(Debug, Clone)]
pub struct LtpdMleDisableInd {
    pub permitted_services_in_temp_disabled_mode: Todo,
}

#[derive(Debug, Clone)]
pub struct LtpdMleDisconnectReq {
    pub endpoint_id: EndpointId,
    pub link_id: LinkId,
    pub pdu_prio: Todo,
    pub encryption_flag: bool,
    pub report: Todo,
}

#[derive(Debug, Clone)]
pub struct LtpdMleDisconnectInd {
    pub endpoint_id: EndpointId,
    pub new_endpoint_id: EndpointId,
    pub link_id: LinkId,
    pub encryption_flag: bool,
    pub chan_change_resp_req: bool,
    pub chan_change_handle: Option<Todo>,
    pub report: Todo,
}

#[derive(Debug, Clone)]
pub struct LtpdMleEnableInd {}

#[derive(Debug, Clone)]
pub struct LtpdMleInfoInd {
    pub broadcast_params: Todo,
    pub subscriber_class_match: Todo,
    pub schedule_timing_prompt: Todo,
    pub permitted_cell_info: Todo,
}

#[derive(Debug, Clone)]
pub struct LtpdMleIdleInd {}

#[derive(Debug, Clone)]
pub struct LtpdMleOpenInd {
    pub mcc: Todo, // Current network
    pub mnc: Todo, // Current network
}

#[derive(Debug, Clone)]
pub struct LtpdMleReceiveInd {
    pub endpoint_id: EndpointId,
    pub received_tetra_address: Todo, // ITSI/GSSI
    pub received_address_type: Todo,
}

#[derive(Debug, Clone)]
pub struct LtpdMleReconnectReq {
    pub endpoint_id: EndpointId,
    pub link_id: LinkId,
    pub reservation_info: Todo,
    pub pdu_prio: Todo,
    pub encryption_flag: bool,
    pub stealing_permission: bool,
}

#[derive(Debug, Clone)]
pub struct LtpdMleReconnectConfirm {
    pub endpoint_id: EndpointId,
    pub new_endpoint_id: EndpointId,
    pub link_id: LinkId,
    pub encryption_flag: bool,
    pub report: Todo,
    pub reconnection_result: Todo,
}

#[derive(Debug, Clone)]
pub struct LtpdMleReconnectInd {
    pub endpoint_id: EndpointId,
    pub new_endpoint_id: EndpointId,
    pub link_id: LinkId,
    pub encryption_flag: bool,
    pub report: Todo,
    pub reconnection_result: Todo,
}

#[derive(Debug, Clone)]
pub struct LtpdMleReleaseReq {
    pub link_id: LinkId,
}

#[derive(Debug, Clone)]
pub struct LtpdMleReportInd {
    pub handle: Todo,
    pub transfer_result: Todo,
}

#[derive(Debug, Clone)]
pub struct LtpdMleResumeInd {
    pub mcc: Todo, // Current network
    pub mnc: Todo, // Current network
}

/// SNDCP → MLE downlink primitive over TL-PD SAP.
/// Symmetric to `LtpdMleUnitdataInd`.
///
/// The SDU already has the SN-PDU body bits; MLE prepends the 3-bit SNDCP
/// protocol discriminator (0b100) and forwards the resulting TL-SDU to LLC
/// via the TLA SAP.
///
/// The `layer2service` field selects Basic Link (unacknowledged, for SN-UNITDATA
/// carrying user IP) vs Advanced Link (acknowledged, for SNDCP control PDUs and
/// SN-DATA). MLE dispatches to `TlaTl(Data|Unitdata)ReqBl` or the AL equivalent
/// depending on this field. Landing SNDCP-side selection lives in PD-4.
///
/// The `packet_data_flag` is threaded through so LLC/UMAC can (later) route the
/// PDU onto the PDCH scheduler when it is set.
#[derive(Debug, Clone)]
pub struct LtpdMleUnitdataReq {
    pub main_address: TetraAddress,
    pub link_id: LinkId,
    pub endpoint_id: EndpointId,
    /// SN-PDU body bits, WITHOUT the 3-bit MLE SNDCP discriminator (MLE prepends it).
    pub sdu: BitBuffer,
    /// Basic Link (unacknowledged) for SN-UNITDATA; Advanced Link (acknowledged) for SN-DATA and control PDUs.
    pub layer2service: Layer2Service,
    /// True when the SDU carries user IP (SN-UNITDATA); false for SNDCP control PDUs.
    /// Threads through to LLC and eventually to the UMAC PDCH scheduler in PD-5.
    pub packet_data_flag: bool,
    /// Optional AIE session; wire through the existing plumbing (None until AIE lands).
    pub air_interface_encryption: Option<Todo>,
    pub tx_reporter: Option<TxReporter>,
    /// PD-5c-H2 piggyback: optional channel-allocation request that SNDCP
    /// attaches to the SN-DATA-TRANSMIT-RESPONSE so the outgoing MacResource
    /// carries both the response SDU and the PDCH grant in a single PDU.
    /// MLE forwards this unchanged through the LTPD→TLA path; LLC and UMAC
    /// already thread it end-to-end on the TLA and TMA SAPs.
    pub chan_alloc: Option<CmceChanAllocReq>,
    /// PD-5c-H14: N.261 Advanced Link number (0..=3) captured by SNDCP from
    /// the most recent uplink AL frame (via `LtpdMleUnitdataInd.al_link_number`,
    /// H13). When `Some`, MLE routes the downlink onto `TlaTlDataReqAl` so LLC
    /// segments it as AL-DATA on the MS's open AL link. `None` keeps the
    /// legacy BL path (`TlaTlDataReqBl`) — required for SNDCP control PDUs
    /// (SN-ACTIVATE/PAGE) that must ride BL before the AL exists, and for any
    /// non-packet-data ack-BL traffic (CMCE/MM).
    pub al_link_number: Option<u8>,
}

#[derive(Debug, Clone)]
pub struct LtpdMleUnitdataInd {
    pub sdu: BitBuffer,
    pub endpoint_id: EndpointId,
    pub link_id: LinkId,
    pub received_tetra_address: TetraAddress, // ITSI/GSSI
    pub chan_change_resp_req: bool,
    pub chan_change_handle: Option<Todo>,
    /// PD-5c-H13: AL provenance flag. `Some(n)` iff the SDU was assembled by
    /// LLC on Advanced Link number `n` (from `TlaTlDataIndAl.al_link_number`);
    /// `None` when it arrived over a Basic Link. SNDCP uses this to learn the
    /// AL (link_id, endpoint_id) tuple to prefer for downlink SN-DATA — the
    /// tuple captured at ACTIVATE PDP DEMAND is BL-only and stops routing to
    /// the MS once it opens an AL.
    pub al_link_number: Option<u8>,
}
