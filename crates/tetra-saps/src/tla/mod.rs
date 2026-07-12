#![allow(unused)]
use tetra_core::{BitBuffer, EndpointId, LinkId, TetraAddress, Todo, TxReporter};

use crate::lcmc::fields::chan_alloc_req::CmceChanAllocReq;

#[derive(Debug, Clone)]
pub struct TlCancelReq {
    pub handle: Todo,
}

/// advanced link
#[derive(Debug, Clone)]
pub struct TlConnectReq {
    // address_type: Todo,
    main_address: Todo,
    scrambling_code: Todo,
    link_id: LinkId,
    endpoint_id: EndpointId,
    pdu_prio: Todo,
    stealing_permission: bool,
    subscriber_class: Todo,
    qos: Todo,
    al_service: Todo,
    air_interface_encryption: Todo,
    req_handle: Todo,
    setup_report: Todo,
}
/// advanced link
#[derive(Debug, Clone)]
pub struct TlConnectInd {
    // address_type: Todo,
    main_address: Todo,
    scrambling_code: Todo,
    link_id: LinkId,
    endpoint_id: EndpointId,
    new_endpoint_id: Option<Todo>,
    css_endpoint_id: Option<Todo>,
    qos: Todo,
    al_service: Todo,
    air_interface_encryption: Todo,
    chan_change_resp_req: bool,
    chan_change_handle: Option<Todo>,
    chan_info: Option<Todo>,
    req_handle: Todo,
    setup_report: Todo,
}
/// advanced link
#[derive(Debug, Clone)]
pub struct TlConnectResp {
    // address_type: Todo,
    main_address: Todo,
    scrambling_code: Todo,
    link_id: LinkId,
    endpoint_id: EndpointId,
    pdu_prio: Todo,
    stealing_permission: bool,
    subscriber_class: Todo,
    qos: Todo,
    al_service: Todo,
    air_interface_encryption: Todo,
    req_handle: Todo,
    setup_report: Todo,
}
/// advanced link
#[derive(Debug, Clone)]
pub struct TlConnectConf {
    // address_type: Todo,
    main_address: Todo,
    scrambling_code: Todo,
    link_id: LinkId,
    endpoint_id: EndpointId,
    new_endpoint_id: Option<Todo>,
    css_endpoint_id: Option<Todo>,
    qos: Todo,
    al_service: Todo,
    air_interface_encryption: Todo,
    chan_change_resp_req: bool,
    chan_change_handle: Option<Todo>,
    chan_info: Option<Todo>,
    req_handle: Todo,
    setup_report: Todo,
}

/// advanced link only
#[derive(Debug, Clone)]
pub struct TlDataReqAl;
#[derive(Debug, Clone)]
pub struct TlDataIndAl;
#[derive(Debug, Clone)]
pub struct TlDataConfAl;

/// Clause 20.3.5.1.4
/// TL-DATA request: this primitive shall be used by the layer 2 service user to request transmission of a TL-SDU. The
// TL-SDU will be acknowledged by the peer entity.
#[derive(Debug, Clone)]
pub struct TlaTlDataReqBl {
    // pub address_type: Todo,
    pub main_address: TetraAddress,
    pub link_id: LinkId,
    pub endpoint_id: EndpointId,
    pub tl_sdu: BitBuffer,
    // pub scrambling_code: u32, // TODO FIXME: according to the spec, should be there, but why do we need to provide this?
    // pub pdu_prio: Todo, // Optional feature
    pub stealing_permission: bool,
    pub subscriber_class: Todo,
    pub fcs_flag: bool,
    pub air_interface_encryption: Option<Todo>,
    pub stealing_repeats_flag: Option<bool>,
    pub data_class_info: Option<Todo>,
    pub req_handle: Todo,
    pub graceful_degradation: Option<Todo>,

    // Custom fields for BS stack:
    /// Optional Channel Allocation Request that may be included by CMCE
    pub chan_alloc: Option<CmceChanAllocReq>,

    /// Optional TxReporter that may be included to track transmission and optionally, acknowledgement
    pub tx_reporter: Option<TxReporter>,
}

/// Clause 20.3.5.1.4
/// TL-DATA indication: this primitive shall be used by the layer 2 to deliver the received TL-SDU to the layer 2 service
// user.
#[derive(Debug, Clone)]
pub struct TlaTlDataIndBl {
    // pub address_type: Todo,
    pub main_address: TetraAddress,
    pub link_id: LinkId,
    pub endpoint_id: EndpointId,
    pub new_endpoint_id: Option<EndpointId>,
    pub css_endpoint_id: Option<EndpointId>,
    pub tl_sdu: Option<BitBuffer>,
    pub scrambling_code: u32,
    pub fcs_flag: bool,
    pub air_interface_encryption: Todo,
    pub chan_change_resp_req: bool,
    pub chan_change_handle: Option<Todo>,
    pub chan_info: Option<Todo>,
    pub req_handle: Todo,
}

/// Clause 20.3.5.1.4
/// TL-DATA response: this primitive shall be used by the layer 2 service user to respond to the previous TL-DATA
// indication primitive. The TL-DATA response primitive may contain a TL-SDU. That TL-SDU will be sent without an
// explicit acknowledgement from the peer entity.
#[derive(Debug, Clone)]
pub struct TlDataRespBl {
    // pub address_type: Todo,
    pub main_address: TetraAddress,
    pub link_id: LinkId,
    pub endpoint_id: EndpointId,
    pub tl_sdu: BitBuffer,
    pub scrambling_code: Todo,
    pub pdu_prio: Todo,
    pub stealing_permission: bool,
    pub subscriber_class: Todo,
    pub fcs_flag: bool,
    pub air_interface_encryption: Todo,
    pub stealing_repeats_flag: Option<bool>,
    pub data_class_info: Option<Todo>,
    pub req_handle: Todo,
}

/// Clause 20.3.5.1.4
// TL-DATA confirm: this primitive shall be used by the layer 2 to inform the layer 2 service user that it has completed
// successfully the transmission of the requested TL-SDU. Depending on the availability of the response primitive at the
// peer entity before transmission of the acknowledgement, the confirm primitive may or may not carry a TL-SDU.
#[derive(Debug, Clone)]
pub struct TlDataConfBl {
    // pub address_type: Todo,
    pub main_address: TetraAddress,
    pub link_id: LinkId,
    pub endpoint_id: EndpointId,
    pub new_endpoint_id: Option<Todo>,
    pub css_endpoint_id: Option<Todo>,
    pub tl_sdu: Option<BitBuffer>,
    pub scrambling_code: Todo,
    pub fcs_flag: bool,
    pub air_interface_encryption: Todo,
    pub chan_change_resp_req: bool,
    pub chan_change_handle: Option<Todo>,
    pub chan_info: Option<Todo>,
    pub req_handle: Todo,
    pub report: Todo,
}

/// Advanced link only
#[derive(Debug, Clone)]
pub struct TlDisconnectReq;
/// Advanced link only
#[derive(Debug, Clone)]
pub struct TlDisconnectInd;
/// Advanced link only
#[derive(Debug, Clone)]
pub struct TlDisconnectConf;

/// advanced link, BS only
#[derive(Debug, Clone)]
pub struct TlReceiveInd;

// advanced link
#[derive(Debug, Clone)]
pub struct TlReleaseReq {
    // pub address_type: Todo,
    pub main_address: TetraAddress,
    pub link_id: LinkId,
}
#[derive(Debug, Clone)]
pub struct TlReleaseInd {
    // pub address_type: Todo,
    pub main_address: TetraAddress,
    pub link_id: Option<Todo>,
    pub endpoint_id: EndpointId,
}

/// advanced link
#[derive(Debug, Clone)]
pub struct TlReconnectReq;
/// advanced link
#[derive(Debug, Clone)]
pub struct TlReconnectResp;

// pub enum TlaReport {
//     /// Confirm handle to the request
//     ConfirmHandle,

// }

#[derive(Debug, Clone)]
pub struct TlaTlReportInd {
    pub req_handle: Option<Todo>,
    pub report: Todo,
    pub chan_change_resp_req: Option<bool>,
    pub chan_change_handle: Option<Todo>,
    pub chan_info: Option<Todo>,
    pub endpoint_id: Option<Todo>,
}

// ─── PD-REWRITE C3: formal TL-* primitives on TLA SAP ──────────────────────
//
// LLC emits these at spec-defined AL state transitions.  SNDCP consumes them
// in Commits 4b/4c to own the reset/disconnect/reconnect/release decision
// (see phase3-design.md §Commit 4a-d).  During the migration window
// (Commit 3 → Commit 5) both these primitives AND the legacy
// `al_events.rs` `AlDeliveryHook` fire in parallel at the same LLC call
// sites; `al_events.rs` retires in Commit 5.

/// Emitted by LLC when an AL-SETUP round-trip completes and the link
/// transitions to `Established`.  Fired at every LLC AL-SETUP success site;
/// parallel primitive for what previously was not surfaced upward at all.
#[derive(Debug, Clone)]
pub struct TlaTlEstablishInd {
    pub main_address: TetraAddress,
    pub link_id: LinkId,
    pub endpoint_id: EndpointId,
    pub n261: u8,
    /// 0 = unacknowledged AL service, 1 = acknowledged AL service.
    pub service: u8,
}

/// Emitted by LLC when an AL-RECONNECT round-trip completes.  Placeholder
/// primitive: LLC-side reconnect wiring is minimal today, so this type is
/// defined for SAP shape completeness; the emission site is filled in
/// during Commits 4c (SNDCP-side wiring) or a follow-up C3b if the
/// LLC-side reconnect handling requires more scaffolding.
#[derive(Debug, Clone)]
pub struct TlaTlReconnectInd {
    pub main_address: TetraAddress,
    pub link_id: LinkId,
    pub endpoint_id: EndpointId,
    pub n261: u8,
}

/// Emitted by LLC when an AL link is released (peer AL-DISC, local
/// TL-RELEASE, or MAC-driven purge).  Distinct from `TlDisconnectInd`
/// (which is spec-defined for peer-initiated disconnect only) — this
/// primitive covers ALL release paths so SNDCP has a single funnel.
#[derive(Debug, Clone)]
pub struct TlaTlReleaseInd {
    pub main_address: TetraAddress,
    pub link_id: LinkId,
    pub endpoint_id: EndpointId,
    pub n261: u8,
    pub cause: TlaReleaseCause,
}

/// Cause classifier for [`TlaTlReleaseInd`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlaReleaseCause {
    /// Peer sent an AL-DISC PDU.
    PeerDisconnect,
    /// Local user requested release (TL-RELEASE.req).
    LocalRelease,
    /// Peer sent an AL-SETUP with reason "Reset".
    PeerReset,
}

/// Emitted by LLC alongside every `AlDeliveryHook` fire so SNDCP can
/// consume delivery outcomes via the formal SAP path instead of the
/// out-of-band `al_events.rs` hook.  Both channels fire in parallel from
/// Commit 3 through Commit 5; Commit 5 retires `al_events.rs`.
#[derive(Debug, Clone)]
pub struct TlaTlReportOutcomeInd {
    pub main_address: TetraAddress,
    pub link_id: LinkId,
    pub endpoint_id: EndpointId,
    pub n261: u8,
    pub n_s: u8,
    pub outcome: TlaReportOutcome,
}

/// Reason-typed outcome for [`TlaTlReportOutcomeInd`].  Mirrors
/// `AlDeliveryOutcome` in `tetra-entities` but lives in the SAP crate so
/// callers (SNDCP, wap-gateway) don't need to import entity types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlaReportOutcome {
    /// Peer explicitly AL-ACKed the entire SDU.
    Delivered,
    /// SDU released without a peer AL-ACK on a fire-and-forget link.
    FireAndForget,
    /// SDU exhausted its per-link N.274 × (N.273 + 1) retx budget.
    RetxExhausted,
}
// ─── end PD-REWRITE C3 primitives ──────────────────────────────────────────

/// Clause 20.3.5.1.9
/// TL-UNITDATA request: this primitive shall be used in the unacknowledged data transfer service by the layer 2
/// service user to request layer 2 to transmit a TL-SDU.
#[derive(Debug, Clone)]
pub struct TlaTlUnitdataReqBl {
    // pub address_type: Todo,
    pub main_address: TetraAddress,
    pub link_id: LinkId,
    pub endpoint_id: EndpointId,
    pub tl_sdu: BitBuffer,
    // pub scrambling_code: Todo, // TODO FIXME reintroduce in MLE for sysinfo/sync
    // pub pdu_prio: Todo,
    pub stealing_permission: bool,
    pub subscriber_class: Todo,
    pub fcs_flag: bool,
    pub air_interface_encryption: Option<Todo>,
    // pub data_prio: Todo,
    pub packet_data_flag: bool,
    pub n_tlsdu_repeats: u8, // TODO check data type and purpose
    // pub scheduled_data_status: Todo,
    // pub max_schedule_interval: Option<Todo>,
    pub data_class_info: Option<Todo>,
    pub req_handle: Todo,

    // Custom fields for BS stack:
    /// Optional Channel Allocation Request that may be included by CMCE
    pub chan_alloc: Option<CmceChanAllocReq>,

    /// Optional TxReporter that may be included to track transmission and optionally, acknowledgement
    pub tx_reporter: Option<TxReporter>,
}

/// Clause 20.3.5.1.9
/// TL-UNITDATA indication: this primitive shall be used in the unacknowledged data transfer service to deliver
/// the received TL-SDU to the layer 2 service user.
#[derive(Debug, Clone)]
pub struct TlaTlUnitdataIndBl {
    // pub address_type: Todo,
    pub main_address: TetraAddress,
    pub link_id: LinkId,
    pub endpoint_id: EndpointId,
    pub new_endpoint_id: Option<EndpointId>,
    pub css_endpoint_id: Option<EndpointId>,
    pub tl_sdu: Option<BitBuffer>,
    pub scrambling_code: u32,
    pub fcs_flag: bool,
    pub air_interface_encryption: Todo,
    pub chan_change_resp_req: bool,
    pub chan_change_handle: Option<Todo>,
    pub chan_info: Option<Todo>,
    pub report: Option<Todo>,
}

/// Clause 20.3.5.1.9, optional
/// TL-UNITDATA confirm: this primitive may be used in the unacknowledged data transfer service to indicate
/// completion of sending of the requested TL-SDU.
#[derive(Debug, Clone)]
pub struct TlUnitdataConfBl {
    // pub address_type: Todo,
    pub main_address: TetraAddress,
    pub link_id: LinkId,
    pub endpoint_id: EndpointId,
    pub req_handle: Todo,
    pub report: Option<Todo>,
}

/// TLA-DATA request for the acknowledged Advanced Link service.
/// Symmetric to `TlaTlDataReqBl`. The LLC entity segments the `tl_sdu`
/// according to the negotiated N.271/N.272/N.274 parameters and transmits
/// AL-DATA/AL-FINAL-AR PDUs on the previously-established AL link.
#[derive(Debug, Clone)]
pub struct TlaTlDataReqAl {
    pub main_address: TetraAddress,
    pub link_id: u32,
    pub endpoint_id: u32,
    /// N.261: 0..=3; must match an Established AL link.
    pub al_link_number: u8,
    pub tl_sdu: BitBuffer,
    pub subscriber_class: u8,
    /// NOTE: spec ambiguous — chosen behaviour: fcs_flag is reserved for future
    /// extended-AL wiring and ignored by the segmenter (which always emits FCS
    /// in the FINAL PDU).
    pub fcs_flag: bool,
    pub air_interface_encryption: Option<Todo>,
    pub req_handle: Todo,
    pub tx_reporter: Option<TxReporter>,
}

/// TLA-DATA indication for the acknowledged Advanced Link service.
/// LLC delivers the fully reassembled TL-SDU to the upper layer once all
/// segments arrive and FCS validates.
#[derive(Debug, Clone)]
pub struct TlaTlDataIndAl {
    pub main_address: TetraAddress,
    pub link_id: u32,
    pub endpoint_id: u32,
    pub al_link_number: u8,
    pub tl_sdu: BitBuffer,
    pub subscriber_class: u8,
    /// Always `true` when this Ind is emitted (LLC drops FCS failures);
    /// kept for parity with BL indications and future extended-AL wiring.
    pub fcs_ok: bool,
    pub air_interface_encryption: Option<Todo>,
}

/// TLA-UNITDATA request for the unacknowledged Advanced Link service.
#[derive(Debug, Clone)]
pub struct TlaTlUnitdataReqAl {
    pub main_address: TetraAddress,
    pub link_id: u32,
    pub endpoint_id: u32,
    pub al_link_number: u8,
    pub tl_sdu: BitBuffer,
    pub subscriber_class: u8,
    /// NOTE: spec ambiguous — reserved for future extended-AL wiring.
    pub fcs_flag: bool,
    pub air_interface_encryption: Option<Todo>,
    pub req_handle: Todo,
    pub tx_reporter: Option<TxReporter>,
}

/// TLA-UNITDATA indication for the unacknowledged Advanced Link service.
#[derive(Debug, Clone)]
pub struct TlaTlUnitdataIndAl {
    pub main_address: TetraAddress,
    pub link_id: u32,
    pub endpoint_id: u32,
    pub al_link_number: u8,
    pub tl_sdu: BitBuffer,
    pub subscriber_class: u8,
    pub fcs_ok: bool,
    pub air_interface_encryption: Option<Todo>,
}

/// Advanced link
#[derive(Debug, Clone)]
pub struct TlUnitdataReqAl;
/// Advanced link
#[derive(Debug, Clone)]
pub struct TlUnitdataIndAl;
/// Advanced link, optional?
#[derive(Debug, Clone)]
pub struct TlUnitdataConfAl;
