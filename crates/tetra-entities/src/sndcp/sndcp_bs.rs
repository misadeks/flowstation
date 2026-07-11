//! SNDCP BS entity — per-PDP-context state machine.
//!
//! Implements ETSI EN 300 392-2 clause 28.4 (SNDCP PDU exchange), clause 28.23
//! (SN-ACTIVATE PDP CONTEXT ACCEPT), clause 28.24 (SN-ACTIVATE PDP CONTEXT DEMAND),
//! and clause 28.108 (reject cause codes).
//!
//! All downward SN-PDUs go via `LtpdMleUnitdataReq` on `TlpdSap` (PD-2), which PD-3 MLE
//! routes to LLC over BL (Basic Link). V1 does not distinguish AL/BL routing; that is a
//! follow-up item.
//!
//! The IPv4 pool, timer encoded values and MTU code are now read from
//! `config.packet_data` (PD-7).  When no `[packet_data]` section is present the
//! defaults reproduce the pre-PD-7 hardcodes exactly.
//!
//! CHAP helpers (`find_chap_response_id`, `chap_success_optional_section`) were moved to
//! `crates/tetra-pdus/src/sndcp/fields/pco.rs` (PD-1). This module uses the structured
//! PCO types from that crate directly.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::Ipv4Addr;

use tetra_config::bluestation::{CfgPacketData, SharedConfig};
use tetra_core::tetra_entities::TetraEntity;
use tetra_core::{BitBuffer, Layer2Service, Sap, TdmaTime, TetraAddress};
use tetra_saps::lcmc::enums::alloc_type::ChanAllocType;
use tetra_saps::lcmc::enums::ul_dl_assignment::UlDlAssignment;
use tetra_saps::lcmc::fields::chan_alloc_req::CmceChanAllocReq;
use tetra_saps::ltpd::{LtpdMleUnitdataInd, LtpdMleUnitdataReq};
use tetra_saps::{SapMsg, SapMsgInner};

use tetra_pdus::sndcp::enums::configuration_protocol::ConfigurationProtocol;
use tetra_pdus::sndcp::enums::protocol_identity::ProtocolIdentity;
use tetra_pdus::sndcp::enums::reject_cause::RejectCause;
use tetra_pdus::sndcp::enums::tia::Tia;
use tetra_pdus::sndcp::enums::transmit_response_reject_cause::TransmitResponseRejectCause;
use tetra_pdus::sndcp::fields::mtu::Mtu;
use tetra_pdus::sndcp::fields::nsapi::Nsapi;
use tetra_pdus::sndcp::fields::pco::{Pco, PcoEntry};
use tetra_pdus::sndcp::fields::timer_value::{ReadyTimer, ResponseWaitTimer, StandbyTimer};
use tetra_pdus::sndcp::enums::deactivation_type::DeactivationType;
use tetra_pdus::sndcp::pdus::{
    ActivatePdpContextAccept, ActivatePdpContextReject, DeactivatePdpContextAccept,
    DeactivatePdpContextDemand, PageRequest, SnData, SnDataTransmitRequest, SnDataTransmitResponse,
    SnPdu, Unitdata,
};

use crate::{MessageQueue, TetraEntityTrait};

// --- Constants ----------------------------------------------------------------

/// Timer values in TETRA timeslots (not read from config — these govern the
/// internal countdown state machine, not the on-wire PDU fields).
/// 1 timeslot ≈ 14.167 ms (1 hyperframe = 4320 timeslots = 61.2 s).
const READY_TIMER_SLOTS: i32 = 4237;       // approx 60 s (was 706 = ~10 s;
                                             // widened to avoid racing the MS's END-OF-DATA,
                                             // which arrives ~10 s after handshake completes)
const STANDBY_TIMER_SLOTS: i32 = 42_353;   // approx 10 min
const RESP_WAIT_TIMER_SLOTS: i32 = 706;    // approx 10 s

// --- Ipv4Pool -----------------------------------------------------------------

/// Tiny IPv4 address allocator.
///
/// Holds the set of addresses available for dynamic allocation.  Built from
/// `CfgPacketData` at `Sndcp` construction time: the full subnet
/// (base+1 .. broadcast-1) minus tun_addr minus pre-reserved static leases.
struct Ipv4Pool {
    available: HashSet<Ipv4Addr>,
    /// Network address of the configured subnet (= `ipv4_pool_base`).
    base_u32: u32,
    /// Total number of addresses in the subnet (2^(32-prefix)).
    total: u32,
}

impl Ipv4Pool {
    /// Build the pool from a [`CfgPacketData`] snapshot.
    ///
    /// Excludes:
    /// - the network address (`base`)
    /// - the broadcast address (`base + 2^(32-prefix) - 1`)
    /// - `tun_addr` (the gateway address, not handed to MSes)
    /// - each `static_lease.ipv4` (pre-reserved; dynamic allocation skips them)
    fn from_config(pd: &CfgPacketData) -> Self {
        let base_u32 = u32::from(pd.ipv4_pool_base);
        let total: u32 = 1u32 << (32 - pd.ipv4_pool_prefix);
        let broadcast: u32 = base_u32 + total - 1;
        let tun_u32 = u32::from(pd.tun_addr);
        let static_u32: HashSet<u32> =
            pd.static_lease.iter().map(|l| u32::from(l.ipv4)).collect();

        let available: HashSet<Ipv4Addr> = ((base_u32 + 1)..broadcast)
            .filter(|&a| a != tun_u32 && !static_u32.contains(&a))
            .map(Ipv4Addr::from)
            .collect();

        Self { available, base_u32, total }
    }

    /// Allocate any available address.
    ///
    /// NOTE: spec ambiguous — chosen behaviour: allocate the lowest available
    /// address for deterministic test output rather than a random one.
    fn allocate(&mut self) -> Option<Ipv4Addr> {
        let ip = self.available.iter().copied().min()?;
        self.available.remove(&ip);
        Some(ip)
    }

    /// Allocate a specific address.  Returns `Some(ip)` iff `ip` is currently
    /// in the `available` set.
    fn allocate_specific(&mut self, ip: Ipv4Addr) -> Option<Ipv4Addr> {
        if self.available.remove(&ip) { Some(ip) } else { None }
    }

    /// Return an address to the pool.
    fn free(&mut self, ip: Ipv4Addr) {
        self.available.insert(ip);
    }

    /// True iff `ip` falls anywhere inside the configured subnet
    /// (regardless of allocation state or exclusions).
    #[allow(dead_code)]
    fn is_in_range(&self, ip: Ipv4Addr) -> bool {
        let v = u32::from(ip);
        v >= self.base_u32 && v < self.base_u32.saturating_add(self.total)
    }
}

// --- Public types -------------------------------------------------------------

/// Key into the per-MS PDP context table.
///
/// Two MSes with different addresses may share an NSAPI value, so both fields are
/// needed. `TetraAddress` does not implement `Eq`/`Hash`, so we store only the SSI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PdpKey {
    pub ssi: u32,
    pub nsapi: u8,
}

impl PdpKey {
    fn new(addr: TetraAddress, nsapi: u8) -> Self {
        Self { ssi: addr.ssi, nsapi }
    }
}

/// State of a PDP context (ETSI EN 300 392-2 clause 28.4 state machine).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PdpState {
    /// ACCEPT sent; awaiting Ready (V1: immediate transition to Ready).
    /// Activation timestamp is stored in `PdpContext::last_activity`.
    WaitForAccept,
    /// Fully active; can send/receive SN-UNITDATA or SN-DATA.
    Ready,
    /// SN-DATA-TRANSMIT-REQUEST accepted; waiting for the MS to establish
    /// an Advanced Link before sending SN-DATA.
    ///
    /// NOTE: spec ambiguous — chosen behaviour: V1 transitions from
    /// WaitingForAlSetup directly to Ready on the first SN-DATA uplink,
    /// without verifying the AL link state (PD-3 currently BL-routes
    /// everything; full AL inspection deferred to a later PR).
    WaitingForAlSetup,
    /// Ready timer expired; MS must be paged before more downlink data.
    Standby,
    /// SN-PAGE REQUEST sent; awaiting SN-PAGE RESPONSE.
    WaitForPageResponse,
    /// DEACTIVATE ACCEPT sent; context being torn down.
    Deactivating,
}

/// A single active PDP context.
#[derive(Clone)]
pub struct PdpContext {
    pub key: PdpKey,
    pub state: PdpState,
    pub ipv4: Ipv4Addr,
    pub tia: Tia,
    /// Cached SDU of the ACCEPT we sent (pos=0, without MLE discriminator).
    /// Resent verbatim on retransmitted DEMAND (idempotency).
    pub last_accept_sdu: BitBuffer,
    pub last_activity: TdmaTime,
    pub ready_deadline: Option<TdmaTime>,
    pub standby_deadline: Option<TdmaTime>,
    pub resp_wait_deadline: Option<TdmaTime>,
    /// IP payloads queued while the MS is in Standby / WaitForPageResponse.
    pub pending_downlink: VecDeque<Vec<u8>>,
    /// Link-layer addressing captured from the uplink ACTIVATE DEMAND.
    pub link_id: u32,
    pub endpoint_id: u32,
    /// PD-5c-H13/H14: Advanced Link tuple learned from the most recent uplink
    /// SN-DATA/UNITDATA whose `LtpdMleUnitdataInd.al_link_number` was `Some`.
    /// When set, downlink user-data SN-PDUs prefer this tuple over the BL
    /// tuple above, so the reply reaches the MS on the AL it opened for the
    /// data phase rather than the BL that carried the ACTIVATE DEMAND.
    /// `None` until we see the first uplink AL frame; falls back to BL then.
    ///
    /// H14: the tuple now also carries the N.261 `al_link_number` (0..=3) so
    /// MLE can address the correct AL segmenter via `TlaTlDataReqAl`.
    pub al_link: Option<AlLinkTuple>,
}

/// PD-5c-H14: SNDCP-cached Advanced Link addressing for a PDP context.
///
/// `link_id` / `endpoint_id` mirror the LLC-side addressing (u32 aliases from
/// `tetra_core::sap_fields`); `al_link_number` is the N.261 index (0..=3) that
/// LLC's AL entities key on when segmenting/reassembling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AlLinkTuple {
    pub link_id: u32,
    pub endpoint_id: u32,
    pub al_link_number: u8,
}

/// Uplink IP payload surfaced to the higher layer (pd-gateway / tests).
#[derive(Debug, Clone)]
pub struct GatewayUplink {
    pub main_address: TetraAddress,
    pub nsapi: u8,
    pub payload: Vec<u8>,
}

/// Downlink IP payload injected from the higher layer (pd-gateway / tests).
#[derive(Debug, Clone)]
pub struct GatewayDownlink {
    pub dest_ipv4: Ipv4Addr,
    pub payload: Vec<u8>,
}

// --- Sndcp entity -------------------------------------------------------------

pub struct Sndcp {
    config: SharedConfig,
    ipv4_pool: Ipv4Pool,
    contexts: HashMap<PdpKey, PdpContext>,
    /// Reverse index: allocated IPv4 to context key (for downlink routing).
    ipv4_to_key: HashMap<Ipv4Addr, PdpKey>,
    /// Uplink IP payloads for the pd-gateway (PD-6) or tests to drain.
    pub uplink_ip_queue: VecDeque<GatewayUplink>,
    /// PD-9: sender end of the pd-gateway bridge for uplink IP payloads.  When
    /// `Some`, `tick_end` drains `uplink_ip_queue` into it.  `None` in tests
    /// that inspect `uplink_ip_queue` directly and in configs where
    /// `packet_data.enabled = false`.
    gateway_uplink_tx: Option<crossbeam_channel::Sender<GatewayUplink>>,
    /// PD-9: receiver end of the pd-gateway bridge for downlink IP payloads.
    /// When `Some`, `tick_start` drains it and injects each item via
    /// `feed_downlink_ip_acknowledged` (Ready contexts) or `feed_downlink_ip`
    /// (Standby / WaitForPageResponse).
    gateway_downlink_rx: Option<crossbeam_channel::Receiver<GatewayDownlink>>,
    /// Current TDMA time, recorded in `tick_start`.
    dltime: TdmaTime,
    /// Live count of `contexts`, updated on every insert / remove. Cloned
    /// out via [`Self::pdp_count_observer`] so external observers (the
    /// built-in WAP portal in `bluestation-bs`) can display the count
    /// without owning a reference to the entity.
    pdp_count_observer: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl Sndcp {
    pub fn new(config: SharedConfig) -> Self {
        let pd = config.config().packet_data.clone();
        Self {
            ipv4_pool: Ipv4Pool::from_config(&pd),
            config,
            contexts: HashMap::new(),
            ipv4_to_key: HashMap::new(),
            uplink_ip_queue: VecDeque::new(),
            gateway_uplink_tx: None,
            gateway_downlink_rx: None,
            dltime: TdmaTime::default(),
            pdp_count_observer: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }

    /// Clone the shared `AtomicUsize` handle that tracks the live PDP-context
    /// count. The value is updated on every `contexts.insert / remove` call
    /// inside SNDCP; external observers (e.g. the built-in WAP portal) just
    /// `.load(Relaxed)` it.
    pub fn pdp_count_observer(&self) -> std::sync::Arc<std::sync::atomic::AtomicUsize> {
        std::sync::Arc::clone(&self.pdp_count_observer)
    }

    /// Refresh the shared PDP counter to match the current context table.
    /// Call from every mutation site.
    #[inline]
    fn refresh_pdp_count(&self) {
        self.pdp_count_observer
            .store(self.contexts.len(), std::sync::atomic::Ordering::Relaxed);
    }

    /// PD-9: install the pd-gateway bridge channels.  `bluestation-bs` calls
    /// this after `Sndcp::new` and before handing the entity to the router
    /// when `packet_data.enabled` is true.  Tests that want to inspect
    /// `uplink_ip_queue` directly leave the channels unset.
    pub fn set_gateway_channels(
        &mut self,
        uplink_tx: crossbeam_channel::Sender<GatewayUplink>,
        downlink_rx: crossbeam_channel::Receiver<GatewayDownlink>,
    ) {
        self.gateway_uplink_tx = Some(uplink_tx);
        self.gateway_downlink_rx = Some(downlink_rx);
    }

    // -- Uplink dispatch -------------------------------------------------------

    fn on_uplink_pdu(&mut self, queue: &mut MessageQueue, ind: &LtpdMleUnitdataInd) {
        let mut buf = ind.sdu.clone();
        buf.seek(0);
        // Skip the 3-bit MLE SNDCP protocol discriminator (0b100).
        if buf.read_bits(3).is_none() {
            tracing::warn!("SNDCP: uplink SDU too short for discriminator");
            return;
        }
        let sn_pdu = match SnPdu::from_bitbuf_ul(&mut buf) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(
                    "SNDCP: failed to decode uplink SN-PDU from {:?}: {e:?}",
                    ind.received_tetra_address
                );
                return;
            }
        };
        match sn_pdu {
            SnPdu::ActivatePdpContextDemand(d) => self.on_activate_demand(queue, ind, d),
            SnPdu::DeactivatePdpContextDemand(d) => self.on_deactivate_demand(queue, ind, d),
            SnPdu::DeactivatePdpContextAccept(a) => self.on_deactivate_accept(ind, a),
            SnPdu::Unitdata(u) => self.on_uplink_unitdata(ind, u),
            SnPdu::Data(d) => self.on_uplink_data(queue, ind, d),
            SnPdu::DataTransmitRequest(r) => self.on_data_transmit_request(queue, ind, r),
            SnPdu::PageResponse(pr) => self.on_page_response(queue, ind, pr),
            SnPdu::EndOfData(eod) => self.on_end_of_data(ind, eod),
            SnPdu::Reconnect(rc) => self.on_reconnect(ind, rc),
            other => {
                tracing::warn!(
                    "SNDCP: unhandled uplink SN-PDU from {:?}: {other:?}",
                    ind.received_tetra_address
                );
            }
        }
    }

    // -- SN-ACTIVATE PDP CONTEXT DEMAND (table 28.24) -------------------------

    /// Handle an SN-ACTIVATE PDP CONTEXT DEMAND and reply with ACCEPT or REJECT.
    ///
    /// Ref: ETSI EN 300 392-2 clause 28.4 (state machine), table 28.24 (DEMAND),
    /// table 28.23 (ACCEPT), table 28.108 (reject causes).
    fn on_activate_demand(
        &mut self,
        queue: &mut MessageQueue,
        ind: &LtpdMleUnitdataInd,
        demand: tetra_pdus::sndcp::pdus::ActivatePdpContextDemand,
    ) {
        let main_address = ind.received_tetra_address;
        let nsapi = demand.nsapi.0;
        let key = PdpKey::new(main_address, nsapi);

        // Check whether a context already exists for this (SSI, NSAPI) pair.
        if let Some(ctx) = self.contexts.get_mut(&key) {
            match ctx.state {
                // Active context: resend the cached ACCEPT verbatim (idempotent retransmission).
                // NOTE: spec ambiguous — chosen behaviour: always resend for WaitForAccept, Ready,
                // or Standby regardless of DEMAND params. A DEMAND for a different IP after
                // activation is a protocol error; we give the MS its existing ACCEPT.
                PdpState::WaitForAccept | PdpState::Ready | PdpState::Standby => {
                    tracing::info!(
                        "SNDCP: retransmitted ACTIVATE DEMAND from {:?} NSAPI={nsapi} — resending cached ACCEPT",
                        main_address
                    );
                    let sdu = ctx.last_accept_sdu.clone();
                    ctx.resp_wait_deadline =
                        Some(self.dltime.add_timeslots(RESP_WAIT_TIMER_SLOTS));
                    send_downlink(
                        queue, main_address, ind.link_id, ind.endpoint_id,
                        sdu, Layer2Service::Acknowledged, false,
                    );
                    return;
                }
                // Context exists but in a terminal state — reject as conflict.
                _ => {
                    tracing::warn!(
                        "SNDCP: ACTIVATE DEMAND from {:?} NSAPI={nsapi} conflicts with context in {:?}",
                        main_address, ctx.state
                    );
                    self.send_reject(queue, ind, demand.nsapi, RejectCause::PdpContextAlreadyActive);
                    return;
                }
            }
        }

        // -- Allocate IPv4 -----------------------------------------------------
        // ATID == 0  => static request (MS supplies the specific IPv4 it wants).
        // ATID != 0  => dynamic request (SwMI assigns any free address).
        let (ipv4, tia) = if demand.atid == 0 {
            let requested = demand.ip_address.unwrap_or_else(|| self.config.config().packet_data.ipv4_pool_base);
            match self.ipv4_pool.allocate_specific(requested) {
                Some(ip) => (ip, Tia::Ipv4Static),
                None => {
                    tracing::info!(
                        "SNDCP: static IPv4 {requested} not available for {:?} NSAPI={nsapi}",
                        main_address
                    );
                    self.send_reject(
                        queue, ind, demand.nsapi,
                        RejectCause::RequestedStaticIpv4NotAvailable,
                    );
                    return;
                }
            }
        } else {
            match self.ipv4_pool.allocate() {
                Some(ip) => (ip, Tia::Ipv4Dynamic),
                None => {
                    tracing::info!(
                        "SNDCP: IPv4 pool exhausted for {:?} NSAPI={nsapi}", main_address
                    );
                    self.send_reject(queue, ind, demand.nsapi, RejectCause::NoResource);
                    return;
                }
            }
        };

        // -- Build ACCEPT ------------------------------------------------------
        // Detect CHAP in the DEMAND PCO. If a CHAP Response (or Challenge) is present,
        // echo its identifier in a CHAP Success in the ACCEPT PCO.
        let chap_id = chap_id_from_pco(&demand.pco);
        let pco = chap_id.map(|id| Pco {
            configuration_protocol: ConfigurationProtocol::Ppp,
            entries: vec![PcoEntry {
                protocol_identity: ProtocolIdentity::Chap,
                // CHAP Success (RFC 1994): [code=3, id echoed, length_hi=0, length_lo=4].
                contents: vec![3u8, id, 0, 4],
            }],
        });

        let pd = self.config.config().packet_data.clone();
        // mtu_to_code is guaranteed Some after config validation.
        let mtu_code = tetra_config::bluestation::mtu_to_code(pd.mtu)
            .unwrap_or(4); // fallback: 4 = 1500 octets (table 28.79)
        let accept = ActivatePdpContextAccept {
            nsapi: demand.nsapi,
            pdu_priority_max: pd.timers.pdu_priority_max,
            ready_timer: ReadyTimer(pd.timers.ready_timer),
            standby_timer: StandbyTimer(pd.timers.standby_timer),
            response_wait_timer: ResponseWaitTimer(pd.timers.resp_wait_timer),
            tia,
            ip4_address: Some(ipv4),
            pcomp: 0,
            vj_slots: None,
            mtu: Mtu(mtu_code),
            snei: None,
            pco,
        };

        let mut sdu = BitBuffer::new_autoexpand(256);
        if let Err(e) = accept.to_bitbuf(&mut sdu) {
            tracing::warn!(
                "SNDCP: failed to encode ACCEPT for {:?}: {e:?}; freeing {ipv4}", main_address
            );
            self.ipv4_pool.free(ipv4);
            return;
        }
        sdu.seek(0);
        let cached_sdu = sdu.clone();

        tracing::info!(
            "SNDCP: -> SN-ACTIVATE PDP CONTEXT ACCEPT to {:?}: NSAPI={nsapi} TIA={tia} IPv4={ipv4} CHAP={}",
            main_address,
            chap_id.map(|id| format!("Success(id={id})")).unwrap_or_else(|| "none".to_string())
        );

        // -- Insert context (state = Ready immediately, V1 best-effort) -------
        // NOTE: spec ambiguous — chosen behaviour: V1 transitions directly to Ready without
        // waiting for an LLC ACK. Real ACK-driven transitions can be layered in a later step.
        let ctx = PdpContext {
            key,
            state: PdpState::Ready,
            ipv4,
            tia,
            last_accept_sdu: cached_sdu,
            last_activity: self.dltime,
            ready_deadline: Some(self.dltime.add_timeslots(READY_TIMER_SLOTS)),
            standby_deadline: None,
            resp_wait_deadline: None,
            pending_downlink: VecDeque::new(),
            link_id: ind.link_id,
            endpoint_id: ind.endpoint_id,
            al_link: None,
        };
        self.ipv4_to_key.insert(ipv4, key);
        self.contexts.insert(key, ctx);
        self.refresh_pdp_count();

        send_downlink(
            queue, main_address, ind.link_id, ind.endpoint_id,
            sdu, Layer2Service::Acknowledged, false,
        );
    }

    // -- SN-DEACTIVATE PDP CONTEXT DEMAND -------------------------------------

    fn on_deactivate_demand(
        &mut self,
        queue: &mut MessageQueue,
        ind: &LtpdMleUnitdataInd,
        demand: tetra_pdus::sndcp::pdus::DeactivatePdpContextDemand,
    ) {
        let main_address = ind.received_tetra_address;
        let nsapi = demand.nsapi.0;
        let key = PdpKey::new(main_address, nsapi);

        let ipv4 = match self.contexts.get(&key) {
            Some(ctx) => ctx.ipv4,
            None => {
                tracing::warn!(
                    "SNDCP: DEACTIVATE DEMAND from {:?} NSAPI={nsapi}: context not found",
                    main_address
                );
                return;
            }
        };

        let deact_accept = DeactivatePdpContextAccept { nsapi: demand.nsapi };
        let mut sdu = BitBuffer::new_autoexpand(32);
        if let Err(e) = deact_accept.to_bitbuf(&mut sdu) {
            tracing::warn!("SNDCP: failed to encode DEACTIVATE ACCEPT: {e:?}");
        } else {
            sdu.seek(0);
            send_downlink(
                queue, main_address, ind.link_id, ind.endpoint_id,
                sdu, Layer2Service::Acknowledged, false,
            );
        }

        self.ipv4_pool.free(ipv4);
        self.ipv4_to_key.remove(&ipv4);
        self.contexts.remove(&key);
        self.refresh_pdp_count();
        tracing::info!("SNDCP: context {:?} NSAPI={nsapi} IPv4={ipv4} deactivated", main_address);
    }

    // -- SN-DEACTIVATE PDP CONTEXT ACCEPT -------------------------------------

    fn on_deactivate_accept(
        &mut self,
        ind: &LtpdMleUnitdataInd,
        accept: tetra_pdus::sndcp::pdus::DeactivatePdpContextAccept,
    ) {
        let main_address = ind.received_tetra_address;
        let nsapi = accept.nsapi.0;
        let key = PdpKey::new(main_address, nsapi);

        match self.contexts.get(&key) {
            Some(ctx) if ctx.state == PdpState::Deactivating => {
                let ipv4 = ctx.ipv4;
                self.ipv4_pool.free(ipv4);
                self.ipv4_to_key.remove(&ipv4);
                self.contexts.remove(&key);
                self.refresh_pdp_count();
                tracing::info!(
                    "SNDCP: SwMI-initiated deactivation confirmed for {:?} NSAPI={nsapi}",
                    main_address
                );
            }
            Some(ctx) => {
                tracing::warn!(
                    "SNDCP: unexpected DEACTIVATE ACCEPT from {:?} NSAPI={nsapi} in state {:?}",
                    main_address, ctx.state
                );
            }
            None => {
                tracing::warn!(
                    "SNDCP: DEACTIVATE ACCEPT from {:?} NSAPI={nsapi}: context not found",
                    main_address
                );
            }
        }
    }

    // -- SN-UNITDATA uplink ----------------------------------------------------

    fn on_uplink_unitdata(&mut self, ind: &LtpdMleUnitdataInd, u: Unitdata) {
        let main_address = ind.received_tetra_address;
        let nsapi = u.nsapi.0;
        let key = PdpKey::new(main_address, nsapi);

        let ctx = match self.contexts.get_mut(&key) {
            Some(c) if matches!(c.state, PdpState::Ready | PdpState::Standby) => c,
            Some(c) => {
                tracing::warn!(
                    "SNDCP: uplink UNITDATA from {:?} NSAPI={nsapi} in unexpected state {:?}",
                    main_address, c.state
                );
                return;
            }
            None => {
                tracing::warn!(
                    "SNDCP: uplink UNITDATA from {:?} NSAPI={nsapi}: context not found",
                    main_address
                );
                return;
            }
        };

        // Any uplink packet restores the context to Ready and resets the timer.
        // NOTE: spec ambiguous — chosen behaviour: reset ready_deadline on every uplink SN-UNITDATA.
        ctx.state = PdpState::Ready;
        ctx.ready_deadline = Some(self.dltime.add_timeslots(READY_TIMER_SLOTS));
        ctx.standby_deadline = None;
        ctx.last_activity = self.dltime;

        // PD-5c-H13: if this SN-UNITDATA rode in on an Advanced Link, remember
        // the (link_id, endpoint_id) so subsequent downlinks route back on the
        // same AL instead of the BL captured at ACTIVATE DEMAND time.
        // PD-5c-H14: also remember the N.261 `al_link_number` so MLE can address
        // the AL segmenter via `TlaTlDataReqAl.al_link_number`.
        if let Some(n) = ind.al_link_number {
            ctx.al_link = Some(AlLinkTuple {
                link_id: ind.link_id,
                endpoint_id: ind.endpoint_id,
                al_link_number: n,
            });
        }

        self.uplink_ip_queue.push_back(GatewayUplink {
            main_address,
            nsapi,
            payload: u.payload,
        });
    }

    // -- SN-DATA-TRANSMIT-REQUEST (type 6, MS → BS) ----------------------------

    /// Handle an MS-initiated SN-DATA-TRANSMIT-REQUEST.
    ///
    /// Semantics:
    /// - Context in Ready / Standby / WaitingForAlSetup: accept (idempotent for retries).
    /// - Context in WaitForAccept / Deactivating / WaitForPageResponse: reject with
    ///   SndcpServiceTemporarilyNotAvailable (34) so the MS backs off and retries.
    /// - No context at all: reject with UnknownNsapi (1).
    ///
    /// Ref: ETSI TS 100 392-2 v3.10.1 clause 28.4.4.5.
    fn on_data_transmit_request(
        &mut self,
        queue: &mut MessageQueue,
        ind: &LtpdMleUnitdataInd,
        req: SnDataTransmitRequest,
    ) {
        let main_address = ind.received_tetra_address;
        let nsapi = req.nsapi.0;
        let key = PdpKey::new(main_address, nsapi);

        // Accept in Ready or Standby (fresh request) or WaitingForAlSetup (idempotent retry:
        // the MS has not yet observed AL come up and is asking again). Reject in Idle /
        // WaitForAccept / Deactivating / WaitForPageResponse with a semantically correct cause.
        // NOTE: spec ambiguous — chosen behaviour: WaitingForAlSetup retries return accept
        // again rather than a "service temporarily not available" (34) reject, so the MS keeps
        // whatever backoff behaviour it already had after the first accept.
        let reject_cause: Option<TransmitResponseRejectCause> = match self.contexts.get(&key) {
            Some(ctx) => match ctx.state {
                PdpState::Ready | PdpState::Standby | PdpState::WaitingForAlSetup => None,
                PdpState::WaitForAccept
                | PdpState::Deactivating
                | PdpState::WaitForPageResponse => {
                    Some(TransmitResponseRejectCause::SndcpServiceTemporarilyNotAvailable)
                }
            },
            None => Some(TransmitResponseRejectCause::UnknownNsapi),
        };

        if let Some(cause) = reject_cause {
            tracing::info!(
                "SNDCP: -> SN-DATA-TRANSMIT-RESPONSE reject ({:?}) to {:?} NSAPI={nsapi}",
                cause,
                main_address
            );
            let resp = SnDataTransmitResponse {
                nsapi: req.nsapi,
                accept: false,
                transmit_response_reject_cause: Some(cause),
                o_bit: false,
                sndcp_network_endpoint_identifier: None,
                m_bit: false,
                nsapi_additional: vec![],
            };
            let mut sdu = BitBuffer::new_autoexpand(32);
            if let Err(e) = resp.to_bitbuf(&mut sdu) {
                tracing::warn!("SNDCP: failed to encode DATA-TRANSMIT-RESPONSE reject: {e:?}");
                return;
            }
            sdu.seek(0);
            send_downlink(
                queue, main_address, ind.link_id, ind.endpoint_id,
                sdu, Layer2Service::Acknowledged, false,
            );

            // PD-5c-H31 (2026-07-11): when we reject with UnknownNsapi (context
            // is genuinely gone — usually because the BS was restarted while
            // MS kept its cached PDP context), ALSO emit an SN-DEACTIVATE PDP
            // CONTEXT DEMAND (network-initiated) so the MS drops its stale
            // context and goes back through the full ACTIVATE handshake. Per
            // ETSI EN 300 392-5 §5.6, this is the correct network-side way to
            // recover from a lost context. Without it, MTP3550 firmware just
            // keeps re-sending the same SN-DATA-TRANSMIT-REQUEST forever, and
            // the user sees "browser opens but nothing happens".
            if matches!(cause, TransmitResponseRejectCause::UnknownNsapi) {
                let deact = DeactivatePdpContextDemand {
                    deactivation_type: DeactivationType::NetworkInitiated,
                    nsapi: req.nsapi,
                    snei: None,
                };
                let mut sdu = BitBuffer::new_autoexpand(32);
                if let Err(e) = deact.to_bitbuf(&mut sdu) {
                    tracing::warn!("SNDCP: H31 failed to encode DEACTIVATE-DEMAND: {e:?}");
                    return;
                }
                sdu.seek(0);
                send_downlink(
                    queue, main_address, ind.link_id, ind.endpoint_id,
                    sdu, Layer2Service::Acknowledged, false,
                );
                tracing::info!(
                    "SNDCP: H31 -> SN-DEACTIVATE PDP CONTEXT DEMAND (NetworkInitiated) to {:?} NSAPI={nsapi}",
                    main_address
                );
            }
            return;
        }

        // Accept: transition context directly to Ready. In earlier PD-4b work we
        // parked in WaitingForAlSetup to signal "waiting for the MS to bring AL up",
        // but hardware verification 2026-07-08 confirmed real Motorola MTM800E MSes
        // run the whole handshake over Basic Link (BL-DATA / BL-ADATA) and never
        // send AL-SETUP. Sitting in WaitingForAlSetup caused:
        //   * END-OF-DATA to log "no Ready contexts to transition" (per-MS scan
        //     looks for Ready only)
        //   * Standby/Ready transitions to never fire
        //   * downlink IP path to be gated on a state the MS never reaches
        // NOTE: spec ambiguous — chosen behaviour: promote directly to Ready on
        // TRANSMIT-RESPONSE(accept). If we ever wire real SNDCP↔AL bridging, restore
        // the WaitingForAlSetup transition here and gate the promotion on receipt
        // of AL-SETUP from the peer.
        if let Some(ctx) = self.contexts.get_mut(&key) {
            ctx.state = PdpState::Ready;
            ctx.ready_deadline = Some(self.dltime.add_timeslots(READY_TIMER_SLOTS));
            ctx.resp_wait_deadline = None;
        }

        tracing::info!(
            "SNDCP: -> SN-DATA-TRANSMIT-RESPONSE accept to {:?} NSAPI={nsapi}",
            main_address
        );
        let resp = SnDataTransmitResponse {
            nsapi: req.nsapi,
            accept: true,
            transmit_response_reject_cause: None,
            o_bit: false,
            sndcp_network_endpoint_identifier: None,
            m_bit: false,
            nsapi_additional: vec![],
        };
        let mut sdu = BitBuffer::new_autoexpand(32);
        if let Err(e) = resp.to_bitbuf(&mut sdu) {
            tracing::warn!("SNDCP: failed to encode DATA-TRANSMIT-RESPONSE accept: {e:?}");
            return;
        }
        sdu.seek(0);

        // PD-5c-H2: piggyback the PDCH grant on the SN-DATA-TRANSMIT-RESPONSE.
        // MTP3550 firmware requires the ChanAllocElement to ride on the same
        // MacResource PDU as the response SDU; a standalone empty-SDU grant is
        // silently ignored. See parent-session bring-up log 2026-07-09 21:51.
        //
        // MVP profile: hardcode TS4 (matches the "no active voice" bring-up
        // scenario handle_pdch_reserve_req previously picked dynamically).
        // UMAC's validate_chan_alloc rejects the grant if TS4 conflicts.
        //
        // usage: None — nexus-bs sets usage_marker=None on the piggybacked
        //                grant. Marker was previously injected by
        //                emit_pdch_mac_resource; not needed on the piggyback.
        // alloc_type Additional — MS retains MCCH presence.
        // ul_dl_assigned Both   — symmetric UL+DL PDCH.
        // clch_permission is derived by UMAC (Add||Rep && Ul||Both == true).
        let main_carrier = self.config.config().cell.main_carrier;
        let chan_alloc = CmceChanAllocReq {
            usage: None,
            carrier: Some(main_carrier),
            timeslots: [false, false, false, true],
            alloc_type: ChanAllocType::Additional,
            ul_dl_assigned: UlDlAssignment::Both,
        };
        send_downlink_with_chan_alloc(
            queue, main_address, ind.link_id, ind.endpoint_id,
            sdu, Layer2Service::Acknowledged, false, Some(chan_alloc), None,
        );
    }

    // -- SN-DATA uplink (type 5, acknowledged data) ----------------------------

    /// Handle an uplink SN-DATA PDU (acknowledged N-PDU).
    ///
    /// Accepts data from contexts in Ready, WaitingForAlSetup, or Standby.
    /// If in WaitingForAlSetup, promotes directly to Ready — V1 shortcut since
    /// PD-3 routes everything over BL and AL setup cannot be directly observed.
    ///
    /// NOTE: spec ambiguous — chosen behaviour: treat first SN-DATA in
    /// WaitingForAlSetup as implicit AL setup confirmation and promote to Ready.
    fn on_uplink_data(&mut self, queue: &mut MessageQueue, ind: &LtpdMleUnitdataInd, data: SnData) {
        let _ = queue; // no downlink response for uplink data
        let main_address = ind.received_tetra_address;
        let nsapi = data.nsapi.0;
        let key = PdpKey::new(main_address, nsapi);

        let ctx = match self.contexts.get_mut(&key) {
            Some(c) if matches!(
                c.state,
                PdpState::Ready | PdpState::WaitingForAlSetup | PdpState::Standby
            ) => c,
            Some(c) => {
                tracing::warn!(
                    "SNDCP: uplink SN-DATA from {:?} NSAPI={nsapi} in unexpected state {:?}",
                    main_address, c.state
                );
                return;
            }
            None => {
                tracing::warn!(
                    "SNDCP: uplink SN-DATA from {:?} NSAPI={nsapi}: context not found",
                    main_address
                );
                return;
            }
        };

        // NOTE: spec ambiguous — chosen behaviour: WaitingForAlSetup → Ready on first
        // SN-DATA uplink. Full AL link inspection deferred (PD-3 currently BL-routes).
        ctx.state = PdpState::Ready;
        ctx.ready_deadline = Some(self.dltime.add_timeslots(READY_TIMER_SLOTS));
        ctx.standby_deadline = None;
        ctx.resp_wait_deadline = None;
        ctx.last_activity = self.dltime;

        // PD-5c-H13: if this SN-DATA rode in on an Advanced Link, remember the
        // (link_id, endpoint_id) so subsequent downlink SN-DATA routes back on
        // the same AL instead of the BL captured at ACTIVATE DEMAND time.
        // PD-5c-H14: also cache the N.261 `al_link_number` for the AL segmenter.
        if let Some(n) = ind.al_link_number {
            ctx.al_link = Some(AlLinkTuple {
                link_id: ind.link_id,
                endpoint_id: ind.endpoint_id,
                al_link_number: n,
            });
        }

        self.uplink_ip_queue.push_back(GatewayUplink {
            main_address,
            nsapi,
            payload: data.n_pdu,
        });
    }

    // -- SN-PAGE RESPONSE ------------------------------------------------------

    fn on_page_response(
        &mut self,
        queue: &mut MessageQueue,
        ind: &LtpdMleUnitdataInd,
        pr: tetra_pdus::sndcp::pdus::PageResponse,
    ) {
        let main_address = ind.received_tetra_address;
        let nsapi = pr.nsapi.0;
        let key = PdpKey::new(main_address, nsapi);

        let ctx = match self.contexts.get_mut(&key) {
            Some(c) => c,
            None => {
                tracing::warn!(
                    "SNDCP: PAGE RESPONSE from {:?} NSAPI={nsapi}: context not found",
                    main_address
                );
                return;
            }
        };

        if ctx.state != PdpState::WaitForPageResponse {
            tracing::warn!(
                "SNDCP: PAGE RESPONSE from {:?} NSAPI={nsapi} in unexpected state {:?}",
                main_address, ctx.state
            );
            return;
        }

        ctx.state = PdpState::Ready;
        ctx.ready_deadline = Some(self.dltime.add_timeslots(READY_TIMER_SLOTS));
        ctx.standby_deadline = None;
        ctx.last_activity = self.dltime;

        let link_id = ctx.link_id;
        let endpoint_id = ctx.endpoint_id;
        let nsapi_field = Nsapi(nsapi);
        let pending: Vec<Vec<u8>> = ctx.pending_downlink.drain(..).collect();

        for payload in pending {
            let ud = Unitdata { nsapi: nsapi_field, pcomp: 0, dcomp: 0, payload };
            let mut sdu = BitBuffer::new_autoexpand(256);
            if let Err(e) = ud.to_bitbuf(&mut sdu) {
                tracing::warn!("SNDCP: failed to encode UNITDATA for pending downlink: {e:?}");
                continue;
            }
            sdu.seek(0);
            send_downlink(
                queue, main_address, link_id, endpoint_id,
                sdu, Layer2Service::Unacknowledged, true,
            );
        }
        tracing::info!(
            "SNDCP: PAGE RESPONSE from {:?} NSAPI={nsapi}: Ready, pending downlink drained",
            main_address
        );
    }

    // -- SN-END OF DATA --------------------------------------------------------

    fn on_end_of_data(
        &mut self,
        ind: &LtpdMleUnitdataInd,
        eod: tetra_pdus::sndcp::pdus::EndOfData,
    ) {
        // END-OF-DATA is per-MS, not per-NSAPI (clause 28.4.4.7).
        // Semantics:
        //   * Ready         -> Standby         (normal case, MS finished a burst)
        //   * Standby       -> Standby         (no-op, refresh standby_deadline)
        //   * WaitForAccept -> Standby         (edge case: activation ACK still in flight
        //                                       when MS decides it's done; treat as Standby
        //                                       so we don't leave the context stuck)
        // Contexts in Deactivating / WaitForPageResponse are left alone: DEACTIVATE is
        // in progress or a page is outstanding, both should complete on their own timer.
        // NOTE: spec ambiguous — chosen behaviour: accept END-OF-DATA in Ready OR Standby
        // OR WaitForAccept to avoid racing the ~10 s Ready-timer with the MS's own
        // end-of-session signal. Live-hardware traces 2026-07-09 20:59 confirmed the MS
        // routinely sends END-OF-DATA ~10 s after handshake, right at the timer boundary.
        let main_address = ind.received_tetra_address;
        let mut moved = 0usize;
        for (key, ctx) in self.contexts.iter_mut() {
            if key.ssi != main_address.ssi {
                continue;
            }
            match ctx.state {
                PdpState::Ready | PdpState::Standby | PdpState::WaitForAccept => {
                    ctx.state = PdpState::Standby;
                    ctx.standby_deadline =
                        Some(self.dltime.add_timeslots(STANDBY_TIMER_SLOTS));
                    ctx.ready_deadline = None;
                    ctx.resp_wait_deadline = None;
                    moved += 1;
                }
                PdpState::WaitingForAlSetup
                | PdpState::Deactivating
                | PdpState::WaitForPageResponse => {
                    // leave alone
                }
            }
        }
        if moved > 0 {
            tracing::info!(
                "SNDCP: {:?} END OF DATA (immediate={}): moved {} contexts to Standby",
                main_address,
                eod.immediate_service_change,
                moved
            );
        } else {
            tracing::debug!(
                "SNDCP: END OF DATA from {:?} (immediate={}): no eligible contexts",
                main_address,
                eod.immediate_service_change
            );
        }
    }

    // -- SN-RECONNECT ----------------------------------------------------------

    fn on_reconnect(
        &mut self,
        ind: &LtpdMleUnitdataInd,
        rc: tetra_pdus::sndcp::pdus::Reconnect,
    ) {
        // RECONNECT NSAPI is conditional (clause 28.4.4.8). If present, target that
        // context; if absent, move any Standby context for this MS back to Ready
        // (V1: apply to the first Standby one found; multi-context RECONNECT is rare).
        //
        // PD-5c-H23 (2026-07-11): MTP3550 hardware observation. MTP3550's local
        // SNDCP READY timer is shorter than our READY_TIMER_SLOTS (60 s). Even
        // after a successful WSP CONNECT + ConnectReply delivery, the MS goes
        // Standby locally within ~1 s and then sends a RECONNECT to promote
        // itself back to Ready so it can transmit its outstanding WTP Ack. Our
        // context is still Ready from BS's perspective, so previously we logged
        // a WARN and did nothing — the MS then hung "connecting" (red blink)
        // because it interpreted our silence as no PDCH grant, waited for T252,
        // and eventually SNDCP-reconnected again on BL.
        //
        // Treat any RECONNECT as a liveness ping: refresh the READY timer so
        // the context stays in Ready long enough for the MS to complete its
        // outstanding uplink. This is spec-consistent (RECONNECT semantically
        // asserts "I need Ready" regardless of BS view of state) and turns the
        // logs from WARN into INFO for the common MTP3550 case.
        let main_address = ind.received_tetra_address;
        match rc.nsapi.map(|n| n.0) {
            Some(nsapi) => {
                let key = PdpKey::new(main_address, nsapi);
                if let Some(ctx) = self.contexts.get_mut(&key) {
                    match ctx.state {
                        PdpState::Standby => {
                            ctx.state = PdpState::Ready;
                            ctx.ready_deadline =
                                Some(self.dltime.add_timeslots(READY_TIMER_SLOTS));
                            ctx.standby_deadline = None;
                            tracing::info!(
                                "SNDCP: {:?} NSAPI={nsapi} Standby->Ready (RECONNECT data_to_send)",
                                main_address
                            );
                        }
                        PdpState::Ready => {
                            // H23: refresh READY timer instead of warning. MTP3550 sends
                            // this after WSP CONNECT when its own READY timer expires
                            // before ours; treat as liveness ping.
                            ctx.ready_deadline =
                                Some(self.dltime.add_timeslots(READY_TIMER_SLOTS));
                            tracing::info!(
                                "SNDCP: {:?} NSAPI={nsapi} RECONNECT in Ready — refreshed READY timer",
                                main_address
                            );
                        }
                        other => {
                            tracing::warn!(
                                "SNDCP: RECONNECT from {:?} NSAPI={nsapi} in unexpected state {:?}",
                                main_address, other
                            );
                        }
                    }
                } else {
                    tracing::warn!(
                        "SNDCP: RECONNECT from {:?} NSAPI={nsapi}: context not found",
                        main_address
                    );
                }
            }
            None => {
                // No NSAPI carried: apply to any Standby context for the MS, and also
                // refresh any Ready context's READY timer (H23 liveness ping semantics).
                let mut moved = 0usize;
                let mut refreshed = 0usize;
                for (key, ctx) in self.contexts.iter_mut() {
                    if key.ssi != main_address.ssi {
                        continue;
                    }
                    match ctx.state {
                        PdpState::Standby => {
                            ctx.state = PdpState::Ready;
                            ctx.ready_deadline =
                                Some(self.dltime.add_timeslots(READY_TIMER_SLOTS));
                            ctx.standby_deadline = None;
                            moved += 1;
                        }
                        PdpState::Ready => {
                            ctx.ready_deadline =
                                Some(self.dltime.add_timeslots(READY_TIMER_SLOTS));
                            refreshed += 1;
                        }
                        _ => {}
                    }
                }
                if moved > 0 {
                    tracing::info!(
                        "SNDCP: {:?} RECONNECT (no data_to_send): moved {} contexts Standby->Ready",
                        main_address, moved
                    );
                } else if refreshed > 0 {
                    tracing::info!(
                        "SNDCP: {:?} RECONNECT (no data_to_send): refreshed {} Ready contexts (H23 liveness)",
                        main_address, refreshed
                    );
                } else {
                    tracing::debug!(
                        "SNDCP: RECONNECT from {:?} (no data_to_send): no eligible contexts",
                        main_address
                    );
                }
            }
        }
        // PD-5c-H37 REVERTED (2026-07-11): the empty-SDU+chan_alloc trick
        // stopped MS from AL-acking subsequent downlinks. Hardware log 12:29
        // showed zero AL-ACKs after H37 fired. The empty AL-DATA frame likely
        // pollutes MS's AL RX N(S) tracking, or MS's MAC doesn't accept a
        // chan_alloc piggybacked on a zero-length payload. Reverting.
        //
        // Real fix will need H36 (LLC delivery feedback to WSP gateway) or a
        // dedicated non-SDU PDCH arm SAP primitive.
    }

    // -- Downlink injection (gateway / tests) ----------------------------------

    /// Inject a downlink IP datagram. Routes based on context state:
    /// - `Ready`: send SN-UNITDATA immediately (unacknowledged, packet_data_flag=true).
    /// - `Standby`: queue payload and send SN-PAGE REQUEST (acknowledged).
    /// - `WaitForPageResponse`: queue payload only.
    /// - Other states: drop with a warning.
    pub fn feed_downlink_ip(&mut self, queue: &mut MessageQueue, downlink: GatewayDownlink) {
        let key = match self.ipv4_to_key.get(&downlink.dest_ipv4).copied() {
            Some(k) => k,
            None => {
                tracing::info!("SNDCP: downlink drop — no context for IPv4 {}", downlink.dest_ipv4);
                return;
            }
        };

        let ctx = match self.contexts.get_mut(&key) {
            Some(c) => c,
            None => {
                tracing::warn!("SNDCP: downlink drop — context for {} disappeared", downlink.dest_ipv4);
                return;
            }
        };

        let main_address = TetraAddress::issi(key.ssi);
        let nsapi = Nsapi(key.nsapi);
        let link_id = ctx.link_id;
        let endpoint_id = ctx.endpoint_id;
        // PD-5c-H13: for Ready-state user data, prefer the AL tuple learned
        // from uplink AL-DATA. Keep the BL tuple for Standby/PAGE REQUEST —
        // paging must reach the MS on a control channel it is monitoring.
        let (data_link_id, data_endpoint_id) = ctx
            .al_link
            .map(|t| (t.link_id, t.endpoint_id))
            .unwrap_or((link_id, endpoint_id));

        match ctx.state {
            PdpState::Ready => {
                ctx.ready_deadline = Some(self.dltime.add_timeslots(READY_TIMER_SLOTS));
                ctx.last_activity = self.dltime;
                let ud = Unitdata { nsapi, pcomp: 0, dcomp: 0, payload: downlink.payload };
                let mut sdu = BitBuffer::new_autoexpand(256);
                if let Err(e) = ud.to_bitbuf(&mut sdu) {
                    tracing::warn!("SNDCP: failed to encode downlink UNITDATA: {e:?}");
                    return;
                }
                sdu.seek(0);
                send_downlink(queue, main_address, data_link_id, data_endpoint_id, sdu,
                    Layer2Service::Unacknowledged, true);
            }
            PdpState::Standby => {
                ctx.pending_downlink.push_back(downlink.payload);
                ctx.state = PdpState::WaitForPageResponse;
                let pr = PageRequest { nsapi };
                let mut sdu = BitBuffer::new_autoexpand(32);
                if let Err(e) = pr.to_bitbuf(&mut sdu) {
                    tracing::warn!("SNDCP: failed to encode PAGE REQUEST: {e:?}");
                    return;
                }
                sdu.seek(0);
                send_downlink(queue, main_address, link_id, endpoint_id, sdu,
                    Layer2Service::Acknowledged, false);
                tracing::info!("SNDCP: paging {:?} NSAPI={} — downlink queued", main_address, key.nsapi);
            }
            PdpState::WaitForPageResponse => {
                ctx.pending_downlink.push_back(downlink.payload);
            }
            other => {
                tracing::warn!(
                    "SNDCP: downlink drop for {:?} NSAPI={} in state {other:?}",
                    main_address, key.nsapi
                );
            }
        }
    }

    /// Inject a downlink IP datagram using acknowledged transfer (SN-DATA).
    ///
    /// Sends SN-DATA via `LtpdMleUnitdataReq { layer2service: Acknowledged,
    /// packet_data_flag: true }`.  Only sends when the context is in `Ready`
    /// state; drops with a warning in all other states.
    ///
    /// The existing `feed_downlink_ip` (unacknowledged, SN-UNITDATA) signature
    /// is intentionally unchanged — this is a companion method.
    pub fn feed_downlink_ip_acknowledged(
        &mut self,
        queue: &mut MessageQueue,
        downlink: GatewayDownlink,
    ) {
        let key = match self.ipv4_to_key.get(&downlink.dest_ipv4).copied() {
            Some(k) => k,
            None => {
                tracing::info!(
                    "SNDCP: ack downlink drop — no context for IPv4 {}",
                    downlink.dest_ipv4
                );
                return;
            }
        };

        let ctx = match self.contexts.get_mut(&key) {
            Some(c) => c,
            None => {
                tracing::warn!(
                    "SNDCP: ack downlink drop — context for {} disappeared",
                    downlink.dest_ipv4
                );
                return;
            }
        };

        if ctx.state != PdpState::Ready {
            tracing::warn!(
                "SNDCP: ack downlink drop for NSAPI={} — context not Ready (state={:?})",
                key.nsapi, ctx.state
            );
            return;
        }

        let main_address = TetraAddress::issi(key.ssi);
        let nsapi = Nsapi(key.nsapi);
        // PD-5c-H13: prefer the AL tuple learned from uplink AL-DATA over the
        // BL tuple captured at ACTIVATE DEMAND time. Once the MS has opened an
        // Advanced Link for the data phase, downlink SN-DATA must ride that AL
        // or LLC will wrap it as BL-DATA on MCCH and the MS will ignore it.
        // PD-5c-H14: also thread the cached N.261 `al_link_number` so MLE can
        // emit `TlaTlDataReqAl` (BL fallback keeps `al_link_number = None`).
        let (link_id, endpoint_id, al_link_number) = match ctx.al_link {
            Some(t) => (t.link_id, t.endpoint_id, Some(t.al_link_number)),
            None => (ctx.link_id, ctx.endpoint_id, None),
        };

        ctx.ready_deadline = Some(self.dltime.add_timeslots(READY_TIMER_SLOTS));
        ctx.last_activity = self.dltime;

        let sn_data = SnData { nsapi, pcomp: 0, dcomp: 0, n_pdu: downlink.payload };
        let mut sdu = BitBuffer::new_autoexpand(256);
        if let Err(e) = sn_data.to_bitbuf(&mut sdu) {
            tracing::warn!("SNDCP: failed to encode downlink SN-DATA: {e:?}");
            return;
        }
        sdu.seek(0);
        send_downlink_with_al(queue, main_address, link_id, endpoint_id, sdu,
            Layer2Service::Acknowledged, true, al_link_number);
    }

    // -- Timer housekeeping ----------------------------------------------------

    fn run_timers(&mut self) {
        let now = self.dltime;
        let mut to_remove: Vec<(PdpKey, Ipv4Addr)> = Vec::new();

        for ctx in self.contexts.values_mut() {
            match ctx.state {
                PdpState::Ready => {
                    if let Some(dl) = ctx.ready_deadline {
                        if timer_expired(dl, now) {
                            ctx.state = PdpState::Standby;
                            ctx.standby_deadline = Some(now.add_timeslots(STANDBY_TIMER_SLOTS));
                            ctx.ready_deadline = None;
                        }
                    }
                }
                PdpState::Standby => {
                    if let Some(dl) = ctx.standby_deadline {
                        if timer_expired(dl, now) {
                            to_remove.push((ctx.key, ctx.ipv4));
                        }
                    }
                }
                PdpState::WaitForAccept => {
                    if let Some(dl) = ctx.resp_wait_deadline {
                        if timer_expired(dl, now) {
                            to_remove.push((ctx.key, ctx.ipv4));
                        }
                    }
                }
                _ => {}
            }
        }

        for (key, ipv4) in to_remove {
            self.ipv4_pool.free(ipv4);
            self.ipv4_to_key.remove(&ipv4);
            self.contexts.remove(&key);
        }
        self.refresh_pdp_count();
    }

    // -- Helpers ---------------------------------------------------------------

    fn send_reject(
        &self,
        queue: &mut MessageQueue,
        ind: &LtpdMleUnitdataInd,
        nsapi: Nsapi,
        cause: RejectCause,
    ) {
        let pdu = ActivatePdpContextReject { nsapi, reject_cause: cause };
        let mut sdu = BitBuffer::new_autoexpand(32);
        if let Err(e) = pdu.to_bitbuf(&mut sdu) {
            tracing::warn!("SNDCP: failed to encode REJECT ({cause:?}): {e:?}");
            return;
        }
        sdu.seek(0);
        send_downlink(
            queue, ind.received_tetra_address, ind.link_id, ind.endpoint_id,
            sdu, Layer2Service::Acknowledged, false,
        );
    }
}

// --- TetraEntityTrait ---------------------------------------------------------

impl TetraEntityTrait for Sndcp {
    fn entity(&self) -> TetraEntity {
        TetraEntity::Sndcp
    }

    fn rx_prim(&mut self, queue: &mut MessageQueue, message: SapMsg) {
        let SapMsgInner::LtpdMleUnitdataInd(ref ind) = message.msg else {
            tracing::debug!(
                "SNDCP: unhandled prim (sap={:?}): {:?}", message.sap, message.msg
            );
            return;
        };
        // Clone to avoid holding a reference across mutable `on_uplink_pdu` dispatch.
        let ind = ind.clone();
        self.on_uplink_pdu(queue, &ind);
    }

    fn tick_start(&mut self, queue: &mut MessageQueue, ts: TdmaTime) {
        self.dltime = ts;
        // PD-9: pump any downlink IP payloads from the pd-gateway bridge into
        // the SNDCP downlink path.  Prefer acknowledged SN-DATA (matches the
        // AL path the MS uses uplink); fall back to SN-UNITDATA / SN-PAGE for
        // contexts that are not currently in Ready state.
        if self.gateway_downlink_rx.is_some() {
            // Drain into a local Vec first — the injection methods take
            // `&mut self` and would clash with a borrow of the receiver.
            let mut pending: Vec<GatewayDownlink> = Vec::new();
            if let Some(rx) = self.gateway_downlink_rx.as_ref() {
                while let Ok(dl) = rx.try_recv() {
                    pending.push(dl);
                }
            }
            for dl in pending {
                let ready = self
                    .ipv4_to_key
                    .get(&dl.dest_ipv4)
                    .and_then(|k| self.contexts.get(k))
                    .map(|c| c.state == PdpState::Ready)
                    .unwrap_or(false);
                if ready {
                    self.feed_downlink_ip_acknowledged(queue, dl);
                } else {
                    self.feed_downlink_ip(queue, dl);
                }
            }
        }
    }

    fn tick_end(&mut self, _queue: &mut MessageQueue, _ts: TdmaTime) -> bool {
        self.run_timers();
        // PD-9: drain accumulated uplink IP payloads to the pd-gateway bridge.
        // If the bridge is gone (send error) we null out the sender so we stop
        // trying and log once — SNDCP itself keeps working.
        if self.gateway_uplink_tx.is_some() {
            let mut disconnect = false;
            while let Some(u) = self.uplink_ip_queue.pop_front() {
                if let Some(tx) = self.gateway_uplink_tx.as_ref() {
                    if tx.send(u).is_err() {
                        disconnect = true;
                        break;
                    }
                }
            }
            if disconnect {
                tracing::warn!("SNDCP: pd-gateway uplink channel disconnected; dropping bridge");
                self.gateway_uplink_tx = None;
            }
        }
        false
    }
}

// --- Free helpers -------------------------------------------------------------

/// Send a SN-PDU body downward via `LtpdMleUnitdataReq` on `TlpdSap` -> MLE -> LLC.
/// MLE (PD-3) prepends the 3-bit SNDCP discriminator before forwarding to LLC.
fn send_downlink(
    queue: &mut MessageQueue,
    main_address: TetraAddress,
    link_id: u32,
    endpoint_id: u32,
    sdu: BitBuffer,
    layer2service: Layer2Service,
    packet_data_flag: bool,
) {
    send_downlink_with_chan_alloc(
        queue, main_address, link_id, endpoint_id,
        sdu, layer2service, packet_data_flag, None, None,
    );
}

/// PD-5c-H14: send a downlink request that carries an N.261 `al_link_number`
/// so MLE routes it onto `TlaTlDataReqAl` (Advanced Link) rather than the
/// default `TlaTlDataReqBl`. Used for downlink SN-DATA once SNDCP has learned
/// the MS's AL from an uplink AL frame.
fn send_downlink_with_al(
    queue: &mut MessageQueue,
    main_address: TetraAddress,
    link_id: u32,
    endpoint_id: u32,
    sdu: BitBuffer,
    layer2service: Layer2Service,
    packet_data_flag: bool,
    al_link_number: Option<u8>,
) {
    send_downlink_with_chan_alloc(
        queue, main_address, link_id, endpoint_id,
        sdu, layer2service, packet_data_flag, None, al_link_number,
    );
}

/// Same as `send_downlink` but attaches an optional `CmceChanAllocReq` to the
/// outgoing `LtpdMleUnitdataReq` (PD-5c-H2 piggyback). MLE forwards it through
/// LLC → UMAC unchanged; UMAC then builds the resulting `MacResource` with the
/// `ChanAllocElement` on the SAME PDU that carries this SDU.
fn send_downlink_with_chan_alloc(
    queue: &mut MessageQueue,
    main_address: TetraAddress,
    link_id: u32,
    endpoint_id: u32,
    sdu: BitBuffer,
    layer2service: Layer2Service,
    packet_data_flag: bool,
    chan_alloc: Option<CmceChanAllocReq>,
    al_link_number: Option<u8>,
) {
    queue.push_back(SapMsg {
        sap: Sap::TlpdSap,
        src: TetraEntity::Sndcp,
        dest: TetraEntity::Mle,
        msg: SapMsgInner::LtpdMleUnitdataReq(LtpdMleUnitdataReq {
            main_address,
            link_id,
            endpoint_id,
            sdu,
            layer2service,
            packet_data_flag,
            air_interface_encryption: None,
            tx_reporter: None,
            chan_alloc,
            al_link_number,
        }),
    });
}

/// Scan a decoded PCO for a PPP CHAP packet and return the CHAP identifier to echo.
/// Prefers a CHAP Response (code 2) over a Challenge (code 1). Returns `None` if no
/// CHAP entries are found.
fn chap_id_from_pco(pco: &Option<Pco>) -> Option<u8> {
    let pco = pco.as_ref()?;
    let mut challenge_id: Option<u8> = None;
    for entry in &pco.entries {
        if entry.protocol_identity == ProtocolIdentity::Chap && entry.contents.len() >= 2 {
            match entry.contents[0] {
                2 => return Some(entry.contents[1]), // Response — echo this id
                1 if challenge_id.is_none() => challenge_id = Some(entry.contents[1]),
                _ => {}
            }
        }
    }
    challenge_id
}

/// True iff `now` is strictly after `deadline` (timer has fired).
fn timer_expired(deadline: TdmaTime, now: TdmaTime) -> bool {
    // now.diff(deadline) = now - deadline; positive => now is later than deadline.
    now.diff(deadline) > 0
}
