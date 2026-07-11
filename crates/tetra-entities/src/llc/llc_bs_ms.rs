use std::collections::{HashMap, HashSet, VecDeque};

use crate::{MessageQueue, TetraEntityTrait};
use tetra_config::bluestation::SharedConfig;
use tetra_core::tetra_entities::TetraEntity;
use tetra_core::{BitBuffer, Layer2Service, Sap, SsiType, TdmaTime, TetraAddress, TxReporter, TxState};
use tetra_saps::lcmc::enums::alloc_type::ChanAllocType;
use tetra_saps::lcmc::enums::ul_dl_assignment::UlDlAssignment;
use tetra_saps::lcmc::fields::chan_alloc_req::CmceChanAllocReq;
use tetra_saps::tla::{
    TlaTlDataIndAl, TlaTlDataIndBl, TlaTlDataReqAl, TlaTlUnitdataIndAl, TlaTlUnitdataIndBl,
    TlaTlUnitdataReqAl,
};
use tetra_saps::tma::TmaUnitdataReq;
use tetra_saps::{SapMsg, SapMsgInner};

use crate::llc::al_events::{AlDeliveryEvent, AlDeliveryHook, AlDeliveryOutcome};
use crate::llc::components::fcs;
use tetra_pdus::llc::consts::consts::N251_BL_MAX_TLSDU_LEN_BITS;
use tetra_pdus::llc::consts::consts::N252_BL_MAX_TLSDU_RETRANSMITS_ACKED;
use tetra_pdus::llc::consts::timers::T251_SENDER_RETRY_TIMER;
use tetra_pdus::llc::enums::llc_pdu_type::LlcPduType;
use tetra_pdus::llc::pdus::bl_ack::BlAck;
use tetra_pdus::llc::pdus::bl_adata::BlAdata;
use tetra_pdus::llc::pdus::bl_data::BlData;
use tetra_pdus::llc::pdus::bl_udata::BlUdata;

// ── Advanced Link imports ────────────────────────────────────────────────────
use tetra_pdus::llc::al::error::SegmentationError;
use tetra_pdus::llc::al::reassembler::{Reassembler, ReassemblerFeed, UnackReassembler, UnackReassemblerFeed};
use tetra_pdus::llc::al::segmenter::{SegmenterConfig, UnackSegmenterConfig, segment_sdu, segment_unack_sdu};
use tetra_pdus::llc::consts::timers::{
    T252_ACK_WAITING_TIMER, T261_SETUP_WAITING_TIMER, T263_DISCONNECT_WAITING_TIMER,
    T265_RECONNECT_WAITING_TIMER, T271_RECEIVER_NOT_READY_FOR_TX_TIMER,
    T272_RECEIVER_NOT_READY_FOR_RX_TIMER,
};
use tetra_pdus::llc::enums::advanced_link_service::AdvancedLinkService;
use tetra_pdus::llc::enums::advanced_link_type::AdvancedLinkType;
use tetra_pdus::llc::enums::al_disc_cause::AlDiscCause;
use tetra_pdus::llc::enums::reconnect_report::ReconnectReport;
use tetra_pdus::llc::enums::setup_report::SetupReport;
use tetra_pdus::llc::pdus::al_ack::{AcknowledgementBlock, AckLength, AlAckAlRnr, AlAckAlRnrKind, SR};
use tetra_pdus::llc::pdus::al_data::{AlDataAlFinal, AlDataVariant};
use tetra_pdus::llc::pdus::al_disc::AlDisc;
use tetra_pdus::llc::pdus::al_reconnect::AlReconnect;
use tetra_pdus::llc::pdus::al_setup::AlSetup;
use tetra_pdus::llc::pdus::al_udata::AlAlUdataAlUfinal;

/// Struct that maintains state expected acknowledgement data for a transmitted message.
/// Aka, we still expect an ack for this.
pub struct ExpectedInAck {
    /// Carrier on which the original message was sent
    pub carrier_num: u16,
    /// Timeslot on which the original message was sent
    pub ts: u8,
    /// Address to which the message was sent
    pub addr: TetraAddress,

    /// Expected ack sequence number for the original message
    pub ns: u8,

    pub bl_type: Layer2Service,

    /// Time this message was received from the MLE
    pub t_first: TdmaTime,
    /// Time this message was actually passed down to the Umac. If a previous message on the basic link is already
    /// submitted, the message has to wait until that previous message was sent and acknowledged, or lost.
    pub t_submitted_to_umac: Option<TdmaTime>,
    /// Time the RxReporter signalled the message was fully transmitted. Also set if the Umac discarded the message
    /// This helps attempting to retransmit the message after a brief delay.
    pub t_umac_done: Option<TdmaTime>,
    /// TxReporter struct. Used by Umac to signal Tx time to Llc, so llc can do retransmissions if needed.
    /// Also used by Llc to signal Ack to upper layer (if appliccable)
    pub tx_reporter: TxReporter,

    // Optional retransmission buffer, to allow for automatic retransmission of the PDU if no acknowledgement is received
    pub retransmission_buf: SapMsg,
    /// Number of retransmissions performed so far
    pub retransmit_count: u8,
}

/// Struct that maintains state for an ACK we still need to send back.
pub struct ScheduledOutAck {
    pub addr: TetraAddress,
    pub t_start: TdmaTime,
    /// Received sequence number
    pub nr: u8,
    /// Carrier on which the original message was received
    pub carrier_num: u16,
    /// Timeslot on which the original message was received
    pub ts: u8,
}

// ─── Advanced Link types ─────────────────────────────────────────────────────

/// Compact key that uniquely identifies one AL link.
///
/// NOTE: spec ambiguous — `ssi_type` is excluded from the hash key because in
/// flowstation V1 AL links are always ISSI.  If GSSI AL links are ever needed,
/// add `ssi_type` here and derive `Hash` for `TetraAddress`.
///
/// ETSI TS 100 392-2 v3.10.1 clause 21.4, N.261 = 2-bit link number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AlLinkKey {
    /// SSI extracted from the peer's main address.
    pub ssi: u32,
    /// LLC link_id as carried by the TMA-UNITDATA primitive.
    pub link_id: u32,
    /// LLC endpoint_id.
    pub endpoint_id: u32,
    /// Two-bit link number (N.261), 0..=3.
    pub n261: u8,
}

impl AlLinkKey {
    /// Build a key from a raw TMA-UNITDATA address tuple plus the N.261 from the PDU.
    pub fn from_prim(main_address: TetraAddress, link_id: u32, endpoint_id: u32, n261: u8) -> Self {
        Self { ssi: main_address.ssi, link_id, endpoint_id, n261 }
    }
}

/// Per-link AL state machine phase.
///
/// ETSI TS 100 392-2 v3.10.1 clause 21.4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlPhase {
    Idle,
    /// Sent/received AL-SETUP proposal, awaiting the confirming AL-SETUP.
    SetupPending,
    Established,
    /// Sent/received AL-RECONNECT proposal, awaiting confirmation.
    ReconnectPending,
    /// Sent AL-DISC, awaiting confirming AL-DISC from the peer.
    DisconnectPending,
    /// Peer sent AL-RNR; TX is frozen until T.272 expires or AL-ACK/non-RNR arrives.
    FlowControlled,
}

/// One TL-SDU buffered in the acknowledged TX window.
pub struct OutstandingSdu {
    /// N(S) shared by every segment of this SDU.
    pub n_s: u8,
    /// Encoded AL-DATA / AL-FINAL PDUs in S(S) order.
    pub pdus: Vec<AlDataAlFinal>,
    /// Time this SDU was last (re-)submitted to UMAC; `None` = not yet sent.
    ///
    /// NOTE (PD-5c-H17): this stamps the *submission* moment, not the moment
    /// UMAC actually finished putting the tail of the SDU on the air. It is
    /// kept for diagnostics / first-send tracking, but the T.252 ACK-wait
    /// clock is driven by `last_segment_tx_at`, not this field.
    pub sent_at: Option<TdmaTime>,
    /// Per-segment ACK flag indexed by S(S).  `true` = peer confirmed receipt.
    pub acked_segments: Vec<bool>,
    /// Per-segment `TxReporter` (indexed by S(S)). LLC hands each reporter to
    /// UMAC when the segment is pushed for transmission; UMAC calls
    /// `mark_transmitted()` when the PDU actually leaves the air. On
    /// retransmission the entry is replaced with a fresh `Pending` reporter.
    /// `None` means the slot has no outstanding TX (already acked or never
    /// pushed) — such slots are ignored by the T.252 gate.
    pub segment_reporters: Vec<Option<TxReporter>>,
    /// dltime at which the T.252 ACK-wait clock started — i.e. the tick on
    /// which the *last* still-unacked segment of the current transmission
    /// round transitioned to `Transmitted`. `None` while at least one
    /// unacked segment is still `Pending` (UMAC has not aired it yet), and
    /// cleared on retransmission so the clock restarts once the retx tail
    /// leaves the air.
    ///
    /// PD-5c-H17: the previous implementation compared against `sent_at`
    /// (submission time). For multi-fragment SDUs UMAC paces segments
    /// across many frames, so `sent_at` fires T.252 too early and the SDU
    /// is dropped before the peer's AL-ACK for the last fragment can
    /// physically arrive. Compare against `last_segment_tx_at` instead.
    pub last_segment_tx_at: Option<TdmaTime>,
    /// Number of SDU-level retransmissions performed so far (vs N.273).
    pub retx_count: u8,
    /// When `true` the SDU is (re)sent on the very next `submit_al_activity_to_umac`
    /// call regardless of the T.251 timer (set on peer-reported FCS failure).
    pub force_retx: bool,
}

/// All state for one AL link.
pub struct AlLink {
    pub key: AlLinkKey,
    /// Full peer `TetraAddress` (preserves `ssi_type`; used in outbound primitives).
    pub main_address: TetraAddress,
    pub phase: AlPhase,
    // ── Negotiated parameters ─────────────────────────────────────────────────
    pub service: AdvancedLinkService,
    pub max_tl_sdu_octets: u16,
    /// N.272 — window size; 1..=3 for original AL.  Drives the N(S) modulus
    /// so peer ACK-window arithmetic stays spec-compliant.
    pub tx_window: u8,
    /// Effective concurrency cap on outstanding TX SDUs.  Distinct from
    /// `tx_window`: for a peer negotiating `connection_width == 0` (Original
    /// AL, single-slot, non-DQPSK) we force this to 1 because such peers
    /// cannot pipeline SDUs even if `tl_sdu_window_size_n272_n281` advertises
    /// a larger window.  For `connection_width == 1` (Extended AL) we honor
    /// the negotiated window.  See PD-5c-H15.
    pub effective_tx_sdu_window: u8,
    /// N.273 — max SDU retransmissions.
    pub max_sdu_retx: u8,
    /// N.274 — max per-segment retransmissions.
    pub max_segment_retx: u8,
    // ── TX window ─────────────────────────────────────────────────────────────
    /// Next N(S) value to assign when segmenting a new SDU; wraps mod (tx_window+1).
    pub next_n_s: u8,
    pub outstanding_sdus: VecDeque<OutstandingSdu>,
    // ── RX reassembly ─────────────────────────────────────────────────────────
    /// In-flight acknowledged reassemblers, keyed by peer N(S).
    pub reassemblers: HashMap<u8, Reassembler>,
    /// In-flight unacknowledged reassemblers, keyed by peer N(S).
    pub unack_reassemblers: HashMap<u8, UnackReassembler>,
    /// Unack SDU timeout start times (T.271), keyed by N(S).
    pub unack_started_at: HashMap<u8, TdmaTime>,
    // ── Timer start times ─────────────────────────────────────────────────────
    /// T.261 start — set when an AL-SETUP is transmitted.
    pub t_setup_start: Option<TdmaTime>,
    /// T.263 start — set when an AL-DISC is transmitted.
    pub t_disc_start: Option<TdmaTime>,
    /// T.265 start — set when an AL-RECONNECT Propose is transmitted.
    pub t_reconnect_start: Option<TdmaTime>,
    /// T.272 start — set when an AL-RNR is received.
    pub t_rnr_start: Option<TdmaTime>,
    // ── Retry counters ────────────────────────────────────────────────────────
    pub setup_retries: u8,
    pub disc_retries: u8,
    pub reconnect_retries: u8,
    // ── Pending retransmission PDUs ───────────────────────────────────────────
    /// Copy of the outgoing AL-SETUP for T.261 retransmission.
    pub pending_setup_pdu: Option<AlSetup>,
    /// Copy of the outgoing AL-RECONNECT for T.265 retransmission.
    pub pending_reconnect_pdu: Option<AlReconnect>,
    // ── Carrier ───────────────────────────────────────────────────────────────
    /// Carrier on which all PDUs for this link are sent.
    pub carrier_num: u16,
    // ── Deferred ACK ──────────────────────────────────────────────────────────
    /// When `true`, at least one non-AR segment has been received and a batched
    /// AL-ACK will be flushed in `tick_end`.
    pub needs_deferred_ack: bool,
    // ── Pending SDU buffer (window-full backpressure) ─────────────────────────
    /// NOTE: spec ambiguous — chosen behaviour: unbounded queue for V1;
    /// cap and shed with warn in a later PR if we see memory pressure.
    pub pending_sdus: VecDeque<Vec<u8>>,

    // ── PD-5c-H47: AL-SETUP-CON echo cache ────────────────────────────────────
    /// Cached copy of the last accepted `AL-SETUP` echo, keyed to the
    /// current negotiated parameters. When the peer sends a byte-identical
    /// duplicate `AL-SETUP` (its `AL-SETUP-CON` was lost in DL air), we
    /// re-emit this cached echo verbatim without re-running the accept
    /// flow. Invalidated on every transition out of `Established`.
    pub last_setup_echo: Option<AlSetup>,

    // ── PD-5c-H49: recently-delivered N(S) ring ───────────────────────────────
    /// Bounded ring of N(S) values whose SDUs have been reassembled and
    /// handed to the upper layer via `TlaTlDataIndAl` but whose peer AL-ACK
    /// may have been lost in DL air. When a subsequent AL-DATA / AL-FINAL
    /// arrives with an N(S) already in the ring, we re-emit the AL-ACK
    /// (spec-mandated on AR — see ETSI TS 100 392-2 v3.10.1 clause 21.4.3)
    /// but skip reassembly + skip re-delivery upward, breaking the
    /// H33 WSP-Result-replay cascade that would otherwise saturate the
    /// peer's PDCH and starve future AL-ACKs.
    ///
    /// Bounded by the peer's `tx_window` (N.272; ≤ 3 for original AL,
    /// ≤ 7 for extended): entries older than one window rollover cannot
    /// be duplicates by definition.
    pub recently_delivered_ns: VecDeque<u8>,
}

impl AlLink {
    /// Discard all in-flight RX/TX AL transfer state on this link while
    /// keeping the link registration and negotiated parameters intact.
    ///
    /// Called when the peer re-establishes the link via AL-SETUP
    /// (any non-Success accepted report — Reset, ServiceDefinition,
    /// ServiceChange) or AL-RECONNECT `Propose`. In both cases the peer
    /// assumes a clean slate and will start sending fresh AL-DATA
    /// fragments from `s_s = 0`; if stale reassembler slots survive,
    /// every fresh fragment collides and is rejected as a conflicting
    /// retransmission.
    fn reset_transfer_state(&mut self) {
        // RX reassembly buffers.
        self.reassemblers.clear();
        self.unack_reassemblers.clear();
        self.unack_started_at.clear();
        // TX bookkeeping.
        self.outstanding_sdus.clear();
        self.pending_sdus.clear();
        self.next_n_s = 0;
        self.needs_deferred_ack = false;
        // Procedure timers + retry counters + pending retransmissions.
        // Callers overwrite phase/t_setup_start/t_reconnect_start
        // immediately after, but clear defensively so stray state from
        // an aborted procedure cannot leak into the fresh session.
        self.t_setup_start = None;
        self.t_reconnect_start = None;
        self.t_disc_start = None;
        self.t_rnr_start = None;
        self.setup_retries = 0;
        self.reconnect_retries = 0;
        self.disc_retries = 0;
        self.pending_setup_pdu = None;
        self.pending_reconnect_pdu = None;
        // PD-5c-H47: cached SETUP echo is tied to a live Established link.
        // Any transfer-state reset means the negotiation is being replayed,
        // so drop the cache.
        self.last_setup_echo = None;
        // PD-5c-H49: duplicate-N(S) ring is transfer-scoped; a re-SETUP
        // means the peer will start a new SDU stream from N(S) = 0 and
        // stale entries could either false-positive or false-negative
        // against the fresh stream.
        self.recently_delivered_ns.clear();
    }
}

/// Error type for AL-layer operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AlError {
    UnknownLink(AlLinkKey),
    WindowFull,
    NotEstablished,
    SduTooLarge { got: usize, max: u16 },
    SegmentationFailed(SegmentationError),
    InvalidState { expected: AlPhase, got: AlPhase },
}

pub struct Llc {
    config: SharedConfig,
    dltime: TdmaTime,

    /// When we receive a message, and it needs to be acknowledged, we store it here for later
    /// integration into a response message, or we will make a separate BL-ACK for it.
    scheduled_out_acks: VecDeque<ScheduledOutAck>,

    /// Outbound messages, that are either already submitted to the Umac, and wait for ack,
    /// or, messages that can't be sent until previous messages for the same SSI have been
    /// acknowledged, first.
    outbound_messages: VecDeque<ExpectedInAck>,
    outbound_udata_messages: VecDeque<SapMsg>,

    /// Per-link send sequence variable per SSI. Alternates between 0 and 1.
    link_send_seq: HashMap<u32, u8>,

    // ── Advanced Link ─────────────────────────────────────────────────────────
    /// All currently known AL links (Idle, SetupPending, Established, …).
    pub al_links: HashMap<AlLinkKey, AlLink>,
    /// Number of bits available for the `tl_sdu_segment` payload inside each
    /// AL-DATA / AL-FINAL PDU.  Default = 400 bits (suitable for a single MAC
    /// block minus header overhead).  AL-5 may make this configurable.
    pub al_segment_payload_bits: usize,

    /// PD-10c-H36: optional sync callback fired on every AL SDU-level
    /// delivery outcome (peer AL-ACK, fire-and-forget release, retx
    /// exhaustion). Consumed by `wap-gateway` via a bridge in
    /// `bluestation-bs` to suppress redundant WSP/WTP retransmissions.
    /// `None` in isolated unit tests and when the wap-gateway is disabled.
    delivery_hook: Option<AlDeliveryHook>,
}

impl Llc {
    pub fn new(config: SharedConfig) -> Self {
        let seg_payload_bits = config.config().llc.advanced_link.segment_payload_octets as usize * 8;
        Self {
            dltime: TdmaTime::default(),
            config,
            scheduled_out_acks: VecDeque::new(),
            outbound_messages: VecDeque::new(),
            outbound_udata_messages: VecDeque::new(),
            link_send_seq: HashMap::new(),
            al_links: HashMap::new(),
            al_segment_payload_bits: seg_payload_bits,
            delivery_hook: None,
        }
    }

    /// PD-10c-H36: install the [`AlDeliveryHook`]. Called once at wiring time
    /// by `bluestation-bs`. Any previously installed hook is replaced.
    pub fn set_delivery_hook(&mut self, hook: AlDeliveryHook) {
        self.delivery_hook = Some(hook);
    }

    /// Fire the delivery hook if installed. Never panics; a hook that panics
    /// would take down the entity thread, but that's on the hook implementer.
    fn emit_delivery(&self, key: AlLinkKey, n_s: u8, outcome: AlDeliveryOutcome) {
        if let Some(hook) = &self.delivery_hook {
            hook(AlDeliveryEvent {
                ssi: key.ssi,
                link_id: key.link_id,
                endpoint_id: key.endpoint_id,
                n261: key.n261,
                n_s,
                outcome,
            });
        }
    }

    fn main_carrier(&self) -> u16 {
        self.config.config().cell.main_carrier
    }

    /// Schedule an ACK to be sent at a later time
    pub fn schedule_outgoing_ack(&mut self, dltime: TdmaTime, addr: TetraAddress, carrier_num: u16, ts: u8, ns: u8) {
        self.scheduled_out_acks.push_back(ScheduledOutAck {
            t_start: dltime,
            nr: ns,
            addr,
            carrier_num,
            ts,
        });
    }

    /// Returns details for outstanding to-be-sent ACK, if any. Returned u8 is the sequence number.
    /// ETSI 22.3.2.3 case d: when a waiting ACK and outgoing TL-DATA exist for the same link, the
    /// LLC shall emit a combined BL-ADATA PDU. We match by SSI plus carrier because the ACK must
    /// stay on the same traffic/signalling carrier as the original uplink.
    fn get_out_ack_seq_if_any(&mut self, addr: TetraAddress, carrier_num: u16) -> Option<u8> {
        for i in 0..self.scheduled_out_acks.len() {
            if self.scheduled_out_acks[i].addr.ssi == addr.ssi && self.scheduled_out_acks[i].carrier_num == carrier_num {
                let n = self.scheduled_out_acks[i].nr;
                self.scheduled_out_acks.remove(i);
                return Some(n);
            }
        }
        None
    }

    /// Returns the next send sequence number V(S) for this link, then toggles it.
    /// Each link independently starts at 0 and alternates 0,1,0,1,...
    fn get_next_send_seq(&mut self, addr: &TetraAddress) -> u8 {
        let vs = self.link_send_seq.entry(addr.ssi).or_insert(0);
        let ns = *vs;
        *vs ^= 1;
        ns
    }

    /// Returns and removes the expected ACK entry for the given SSI, if any
    fn take_expected_ack_for_ssi(&mut self, ssi: u32, carrier_num: u16) -> Option<ExpectedInAck> {
        for i in 0..self.outbound_messages.len() {
            let msg = &self.outbound_messages[i];
            if msg.addr.ssi == ssi && msg.carrier_num == carrier_num && msg.t_submitted_to_umac.is_some() {
                return self.outbound_messages.remove(i);
            }
        }
        None
    }

    /// Process incoming ACK per ETSI 22.3.2.3(k).
    /// Matches by SSI and N(R) so that retransmitted BL-DATA entries are matched correctly.
    fn process_incoming_ack(&mut self, addr: TetraAddress, carrier_num: u16, nr: u8) {
        // Get the expected ACK entry
        let Some(expected_ack) = self.take_expected_ack_for_ssi(addr.ssi, carrier_num) else {
            tracing::warn!("received unexpected ACK for SSI {} carrier {} N(R) {}", addr.ssi, carrier_num, nr);
            return;
        };

        // Check it was indeed already transmitted by the Umac
        if expected_ack.t_umac_done.is_none() {
            // This may be an old retransmission of an ack for the before-last basic link message
            // Let's push the ack back into the head of the queue (not tail)..
            tracing::warn!(
                "received ACK for SSI {} carrier {} N(R) {} that was not yet transmitted by Umac. Ignoring",
                addr.ssi,
                carrier_num,
                nr
            );
            self.outbound_messages.push_front(expected_ack);
            return;
        }

        // Check N(R)
        if expected_ack.ns == nr {
            // Successful ACK: N(R) matches N(S)
            tracing::debug!("received ACK for SSI {} carrier {} N(R) {}", addr.ssi, carrier_num, expected_ack.ns);
            expected_ack.tx_reporter.mark_acknowledged();
            return;
        } else {
            // N(R) mismatch — per ETSI 22.3.2.3(k), not a successful ACK. Maybe a retransmission?
            // Let's push it back into the queue head (not the tail) and see if an ack arrives later
            tracing::warn!(
                "received unexpected ACK for SSI {} carrier {}: N(R)={}, expected N(S)={}. Ignoring",
                addr.ssi,
                carrier_num,
                nr,
                expected_ack.ns
            );
            self.outbound_messages.push_front(expected_ack);
            return;
        }

        // The expected_ack is confirmed as matched and goes out of scope here
    }

    fn rx_tma_prim(&mut self, queue: &mut MessageQueue, message: SapMsg) {
        tracing::trace!("rx_tma_prim");
        match message.msg {
            SapMsgInner::TmaUnitdataInd(_) => {
                self.rx_tma_unitdata_ind(queue, message);
            }
            SapMsgInner::TmaReportInd(_) => {
                self.rx_tma_report_ind(queue, message);
            }
            _ => {
                tracing::error!("BUG: unexpected message or state -- routing error");
                return;
            }
        }
    }

    fn rx_tla_tlunitdata_req_bl(&mut self, _queue: &mut MessageQueue, message: SapMsg) {
        tracing::trace!("rx_tla_tlunitdata_req_bl");
        let SapMsgInner::TlaTlUnitdataReqBl(mut prim) = message.msg else {
            tracing::error!("BUG: unexpected message or state -- routing error");
            return;
        };

        let mut pdu_buf = BitBuffer::new_autoexpand(32);
        // PD-5c-H43 (audit LLC-02): propagate the caller's fcs_flag instead
        // of hard-coding `false`. BL-DATA/BL-ADATA already honour prim.fcs_flag
        // (see rx_tla_tldata_req_bl); BL-UDATA silently stripped it.
        let pdu = BlUdata { has_fcs: prim.fcs_flag };
        pdu.to_bitbuf(&mut pdu_buf);
        let sdu_len = prim.tl_sdu.get_len_remaining();
        // PD-5c-H42 (audit LLC-04): enforce ETSI N.251 BL TL-SDU max length
        // on TX. Motorola TSC gates the same limit at 0x02a25548
        // (size_to_bl_limit <= bl_size); over-sized SDUs would be silently
        // dropped by the peer's MAC/LLC. Reject rather than truncate so the
        // upper layer sees a hard error instead of a corrupt SDU on the wire.
        if sdu_len > N251_BL_MAX_TLSDU_LEN_BITS as usize {
            tracing::warn!(
                "LLC BL-UDATA TX (unitdata_req): TL-SDU len {} bits exceeds N.251 max {} bits — dropping",
                sdu_len, N251_BL_MAX_TLSDU_LEN_BITS
            );
            return;
        }
        pdu_buf.copy_bits(&mut prim.tl_sdu, sdu_len);
        pdu_buf.seek(0);
        tracing::debug!("-> {:?} sdu {}", pdu, pdu_buf.dump_bin());

        let preferred_carrier = prim
            .chan_alloc
            .as_ref()
            .and_then(|ca| ca.carrier)
            .unwrap_or_else(|| self.main_carrier());
        let sapmsg = SapMsg {
            sap: Sap::TmaSap,
            src: self.entity(),
            dest: TetraEntity::Umac,
            msg: SapMsgInner::TmaUnitdataReq(TmaUnitdataReq {
                carrier_num: Some(preferred_carrier),
                req_handle: prim.req_handle,
                pdu: pdu_buf,
                main_address: prim.main_address,
                link_id: prim.link_id,
                endpoint_id: prim.endpoint_id,
                stealing_permission: prim.stealing_permission,
                subscriber_class: prim.subscriber_class,
                air_interface_encryption: prim.air_interface_encryption,
                stealing_repeats_flag: None, // fixme
                data_category: prim.data_class_info,
                chan_alloc: prim.chan_alloc,
                tx_reporter: prim.tx_reporter.take(),
                packet_data_flag: prim.packet_data_flag,
            }),
        };

        // Put into transmit queue
        self.outbound_udata_messages.push_back(sapmsg);
    }

    /// Schedules a message that was not acked in time for a retransmission
    fn submit_for_acknowledged_transmission(queue: &mut MessageQueue, ack: &mut ExpectedInAck, dltime: TdmaTime) {
        // Clone the sapmsg. Make sure we set (or for retransmission: reset) timers properly
        let sapmsg = ack.retransmission_buf.clone();
        ack.t_submitted_to_umac = Some(dltime);
        ack.t_umac_done = None;
        ack.tx_reporter.reset();

        // Send the message
        queue.push_back(sapmsg);
    }

    /// See Clause 22.3.2.3 for Acknowledged data transmission in basic link
    fn rx_tla_tldata_req_bl(&mut self, _queue: &mut MessageQueue, message: SapMsg) {
        tracing::trace!("rx_tla_tldata_req_bl");
        let SapMsgInner::TlaTlDataReqBl(mut prim) = message.msg else {
            tracing::error!("BUG: unexpected message or state -- routing error");
            return;
        };

        // PD-5c-H42 (audit LLC-04): enforce ETSI N.251 BL TL-SDU max length
        // (2595 bits) on every BL TX path. Motorola TSC gates the same limit
        // at 0x02a25548 (size_to_bl_limit <= bl_size). Reject at the entry
        // point so all four downstream builds (BL-ACK-piggyback, BL-UDATA
        // fallback, BL-ADATA, BL-DATA) are covered uniformly.
        let sdu_len_bits = prim.tl_sdu.get_len_remaining();
        if sdu_len_bits > N251_BL_MAX_TLSDU_LEN_BITS as usize {
            tracing::warn!(
                "LLC BL TX (tldata_req): TL-SDU len {} bits exceeds N.251 max {} bits — dropping",
                sdu_len_bits, N251_BL_MAX_TLSDU_LEN_BITS
            );
            return;
        }

        let preferred_carrier = prim
            .chan_alloc
            .as_ref()
            .and_then(|ca| ca.carrier)
            .unwrap_or_else(|| self.main_carrier());

        // Traffic-channel responses may carry the TL-SDU on the BL-ACK itself.
        // This is required for U-Alert and other BL response payloads.
        if prim.stealing_permission {
            if let Some(out_ack_n) = self.get_out_ack_seq_if_any(prim.main_address, preferred_carrier) {
                let mut pdu_buf = BitBuffer::new_autoexpand(32);
                let pdu = BlAck {
                    has_fcs: prim.fcs_flag,
                    nr: out_ack_n,
                };
                pdu.to_bitbuf(&mut pdu_buf);
                let sdu_len = prim.tl_sdu.get_len_remaining();
                pdu_buf.copy_bits(&mut prim.tl_sdu, sdu_len);
                pdu_buf.seek(0);
                tracing::debug!(ts=%self.dltime, "-> {:?} piggyback sdu {}", pdu, pdu_buf.dump_bin());

                let sapmsg = SapMsg {
                    sap: Sap::TmaSap,
                    src: self.entity(),
                    dest: TetraEntity::Umac,
                    msg: SapMsgInner::TmaUnitdataReq(TmaUnitdataReq {
                        carrier_num: Some(preferred_carrier),
                        req_handle: prim.req_handle,
                        pdu: pdu_buf,
                        main_address: prim.main_address,
                        link_id: prim.link_id,
                        endpoint_id: prim.endpoint_id,
                        stealing_permission: prim.stealing_permission,
                        subscriber_class: prim.subscriber_class,
                        air_interface_encryption: prim.air_interface_encryption,
                        stealing_repeats_flag: prim.stealing_repeats_flag,
                        data_category: prim.data_class_info,
                        chan_alloc: prim.chan_alloc,
                        tx_reporter: prim.tx_reporter.take(),
                        packet_data_flag: false,
                    }),
                };
                self.outbound_udata_messages.push_back(sapmsg);
                return;
            }
        }

        // Group signalling and STCH requests without an ACK to piggyback should
        // go out as BL-UDATA instead of being dropped.
        if prim.stealing_permission || prim.main_address.ssi_type == SsiType::Gssi {
            let mut pdu_buf = BitBuffer::new_autoexpand(32);
            // PD-5c-H43 (audit LLC-02): propagate the caller's fcs_flag
            // instead of hard-coding `false`. Consistent with the BL-DATA /
            // BL-ADATA branches above which already use prim.fcs_flag.
            let pdu = BlUdata { has_fcs: prim.fcs_flag };
            pdu.to_bitbuf(&mut pdu_buf);
            let sdu_len = prim.tl_sdu.get_len_remaining();
            pdu_buf.copy_bits(&mut prim.tl_sdu, sdu_len);
            pdu_buf.seek(0);
            tracing::debug!(ts=%self.dltime, "-> {:?} sdu {}", pdu, pdu_buf.dump_bin());

            let sapmsg = SapMsg {
                sap: Sap::TmaSap,
                src: self.entity(),
                dest: TetraEntity::Umac,
                msg: SapMsgInner::TmaUnitdataReq(TmaUnitdataReq {
                    carrier_num: Some(preferred_carrier),
                    req_handle: prim.req_handle,
                    pdu: pdu_buf,
                    main_address: prim.main_address,
                    link_id: 0,
                    endpoint_id: prim.endpoint_id,
                    stealing_permission: prim.stealing_permission,
                    subscriber_class: prim.subscriber_class,
                    air_interface_encryption: prim.air_interface_encryption,
                    stealing_repeats_flag: prim.stealing_repeats_flag,
                    data_category: prim.data_class_info,
                    chan_alloc: prim.chan_alloc,
                    tx_reporter: prim.tx_reporter.take(),
                    packet_data_flag: false,
                }),
            };
            self.outbound_udata_messages.push_back(sapmsg);
            return;
        }

        // If an ack still needs to be sent, get the relevant expected sequence number
        let out_ack_n = self.get_out_ack_seq_if_any(prim.main_address, preferred_carrier);

        // Get per-link send sequence number N(S) = V(S), then toggle V(S)
        let ns = self.get_next_send_seq(&prim.main_address);

        // Construct PDU, write header
        let mut pdu_buf = BitBuffer::new_autoexpand(32);

        // Determine message type and build
        if let Some(out_ack_n) = out_ack_n {
            // BL-ADATA (acknowledged, with or without FCS)
            let pdu = BlAdata {
                has_fcs: prim.fcs_flag,
                nr: out_ack_n,
                ns,
            };
            pdu.to_bitbuf(&mut pdu_buf);
            // Append SDU
            let sdu_len = prim.tl_sdu.get_len_remaining();
            pdu_buf.copy_bits(&mut prim.tl_sdu, sdu_len);
            pdu_buf.seek(0);
            tracing::debug!(ts=%self.dltime, "-> {:?} sdu {}", pdu, pdu_buf.dump_bin());
        } else {
            // BL-DATA (acknowledged, with or without FCS) — ETSI Clause 22.3.2.3
            let pdu = BlData {
                has_fcs: prim.fcs_flag,
                ns,
            };
            pdu.to_bitbuf(&mut pdu_buf);
            // Append SDU
            let sdu_len = prim.tl_sdu.get_len_remaining();
            pdu_buf.copy_bits(&mut prim.tl_sdu, sdu_len);
            pdu_buf.seek(0);
            tracing::debug!(ts=%self.dltime, "-> {:?} sdu {}", pdu, pdu_buf.dump_bin());
        }

        // Derive the timeslot from chan_alloc (first set timeslot in [bool;4]), defaulting to 1.
        // Must be done before chan_alloc is moved into TmaUnitdataReq below.
        let derived_ts: u8 = prim
            .chan_alloc
            .as_ref()
            .and_then(|ca| ca.timeslots.iter().enumerate().find(|&(_, &set)| set).map(|(i, _)| (i + 1) as u8))
            .unwrap_or(1);

        // Either take tx_reporter passed down or create a new one
        let tx_reporter = prim.tx_reporter.take().unwrap_or_else(|| TxReporter::new());

        let sapmsg = SapMsg {
            sap: Sap::TmaSap,
            src: self.entity(),
            dest: TetraEntity::Umac,
            msg: SapMsgInner::TmaUnitdataReq(TmaUnitdataReq {
                carrier_num: Some(preferred_carrier),
                req_handle: prim.req_handle,
                pdu: pdu_buf,
                main_address: prim.main_address,
                link_id: 0,
                endpoint_id: prim.endpoint_id,
                stealing_permission: prim.stealing_permission,
                subscriber_class: prim.subscriber_class,
                air_interface_encryption: prim.air_interface_encryption,
                stealing_repeats_flag: prim.stealing_repeats_flag,
                data_category: prim.data_class_info,
                chan_alloc: prim.chan_alloc,
                tx_reporter: Some(tx_reporter.clone()),
                packet_data_flag: false, // TlaTlDataReqBl carries signalling, not packet data
            }),
        };

        // Register that we expect an ACK for this message on the derived timeslot
        tracing::trace!("setting expected ack for carrier {} ts{}", preferred_carrier, derived_ts);
        self.outbound_messages.push_back(ExpectedInAck {
            carrier_num: preferred_carrier,
            ns,
            addr: prim.main_address,
            ts: derived_ts,
            bl_type: Layer2Service::Acknowledged,
            tx_reporter,
            t_first: self.dltime,
            t_submitted_to_umac: None,
            t_umac_done: None,
            retransmission_buf: sapmsg, // Clone the message to keep a copy for potential retransmission
            retransmit_count: 0,
        });

        // The message will now be picked up for transmission at end-of-tick, if the ssi does not yet have
        // a pending message waiting for an ack.
    }

    fn rx_tla_tldata_req_al(&mut self, queue: &mut MessageQueue, message: SapMsg) {
        let prim: TlaTlDataReqAl = match message.msg {
            SapMsgInner::TlaTlDataReqAl(prim) => prim,
            _ => {
                tracing::error!("BUG: rx_tla_tldata_req_al: not TlaTlDataReqAl");
                return;
            }
        };
        let key = AlLinkKey {
            ssi: prim.main_address.ssi,
            link_id: prim.link_id,
            endpoint_id: prim.endpoint_id,
            n261: prim.al_link_number,
        };
        let phase = self.al_links.get(&key).map(|l| l.phase);
        match phase {
            None => {
                tracing::warn!("TLA-DATA-Req-Al: no such AL link {:?}, dropping SDU", key);
                return;
            }
            Some(p) if p != AlPhase::Established && p != AlPhase::FlowControlled => {
                tracing::warn!(
                    "TLA-DATA-Req-Al: link {:?} not Established (phase {:?}), dropping",
                    key,
                    p
                );
                return;
            }
            _ => {}
        }
        let sdu: Vec<u8> = prim.tl_sdu.into_bytes();
        if let Err(e) = self.enqueue_al_sdu(queue, key, sdu) {
            tracing::warn!("TLA-DATA-Req-Al: enqueue_al_sdu failed for link {:?}: {:?}", key, e);
        }
    }

    fn rx_tla_tlunitdata_req_al(&mut self, queue: &mut MessageQueue, message: SapMsg) {
        let prim: TlaTlUnitdataReqAl = match message.msg {
            SapMsgInner::TlaTlUnitdataReqAl(prim) => prim,
            _ => {
                tracing::error!("BUG: rx_tla_tlunitdata_req_al: not TlaTlUnitdataReqAl");
                return;
            }
        };
        let key = AlLinkKey {
            ssi: prim.main_address.ssi,
            link_id: prim.link_id,
            endpoint_id: prim.endpoint_id,
            n261: prim.al_link_number,
        };
        let (carrier, addr, l_id, e_id, next_n_s) = {
            let Some(link) = self.al_links.get_mut(&key) else {
                tracing::warn!("TLA-UNITDATA-Req-Al: no such AL link {:?}, dropping SDU", key);
                return;
            };
            if link.phase != AlPhase::Established {
                tracing::warn!(
                    "TLA-UNITDATA-Req-Al: link {:?} not Established (phase {:?}), dropping",
                    key,
                    link.phase
                );
                return;
            }
            let n_s = link.next_n_s;
            link.next_n_s = link.next_n_s.wrapping_add(1);
            (
                link.carrier_num,
                link.main_address,
                link.key.link_id,
                link.key.endpoint_id,
                n_s,
            )
        };

        let sdu: Vec<u8> = prim.tl_sdu.into_bytes();
        let config = UnackSegmenterConfig {
            segment_payload_bits: self.al_segment_payload_bits,
            starting_n_s: next_n_s,
        };
        let output = match segment_unack_sdu(&sdu, &config) {
            Ok(o) => o,
            Err(e) => {
                tracing::warn!("TLA-UNITDATA-Req-Al: segmentation failed for link {:?}: {:?}", key, e);
                return;
            }
        };
        for pdu in &output.pdus {
            let mut buf = BitBuffer::new_autoexpand(256);
            pdu.to_bitbuf(&mut buf);
            buf.seek(0);
            queue.push_back(SapMsg {
                sap: Sap::TmaSap,
                src: TetraEntity::Llc,
                dest: TetraEntity::Umac,
                msg: SapMsgInner::TmaUnitdataReq(TmaUnitdataReq {
                    carrier_num: Some(carrier),
                    req_handle: 0,
                    pdu: buf,
                    main_address: addr,
                    link_id: l_id,
                    endpoint_id: e_id,
                    stealing_permission: false,
                    subscriber_class: 0,
                    air_interface_encryption: None,
                    stealing_repeats_flag: None,
                    data_category: None,
                    chan_alloc: None,
                    tx_reporter: None,
                    packet_data_flag: false, // AL unack segments are signalling
                }),
            });
        }
        tracing::debug!("TLA-UNITDATA-Req-Al: sent {} segments for link {:?}", output.segment_count, key);
    }

    fn rx_tla_prim(&mut self, queue: &mut MessageQueue, message: SapMsg) {
        tracing::trace!("rx_tla_prim");
        match &message.msg {
            SapMsgInner::TlaTlDataReqBl(_) => {
                self.rx_tla_tldata_req_bl(queue, message);
            }
            SapMsgInner::TlaTlUnitdataReqBl(_) => {
                self.rx_tla_tlunitdata_req_bl(queue, message);
            }
            SapMsgInner::TlaTlDataReqAl(_) => {
                self.rx_tla_tldata_req_al(queue, message);
            }
            SapMsgInner::TlaTlUnitdataReqAl(_) => {
                self.rx_tla_tlunitdata_req_al(queue, message);
            }
            _ => {
                tracing::warn!("unhandled match variant, ignoring");
            }
        }
    }

    fn rx_tma_report_ind(&mut self, _queue: &mut MessageQueue, mut _message: SapMsg) {
        tracing::trace!("rx_tma_report_ind, ignoring");
    }

    /// Clause 20.4.1.1.4 TMA-UNITDATA primitive
    /// TMA-UNITDATA indication: this primitive shall be used by the MAC to deliver a received TM-SDU. This primitive
    /// may also be used with no TM-SDU if the MAC needs to inform the higher layers of a channel allocation received
    /// without an associated TM-SDU.
    fn rx_tma_unitdata_ind(&mut self, queue: &mut MessageQueue, mut message: SapMsg) {
        tracing::trace!("rx_tma_unitdata_ind");

        // Determine which type of TL-SDU we have
        let pdu_type = if let SapMsgInner::TmaUnitdataInd(prim) = &mut message.msg {
            let Some(pdu) = prim.pdu.as_ref() else {
                tracing::warn!("LLC: rx_tma_unitdata_ind received message with no pdu, ignoring");
                return;
            };
            let Some(bits) = pdu.peek_bits(4) else {
                tracing::warn!("insufficient bits: {}", pdu.dump_bin());
                return;
            };
            let Ok(pdu_type) = LlcPduType::try_from(bits) else {
                tracing::warn!("invalid pdu type: {} in {}", bits, pdu.dump_bin());
                return;
            };

            pdu_type
        } else {
            tracing::error!("BUG: unexpected message or state -- routing error");
            return;
        };

        // Call handler function
        match pdu_type {
            // All Basic Link types can be handled by the same function
            LlcPduType::BlAdata
            | LlcPduType::BlAdataFcs
            | LlcPduType::BlData
            | LlcPduType::BlDataFcs
            | LlcPduType::BlUdata
            | LlcPduType::BlUdataFcs
            | LlcPduType::BlAck
            | LlcPduType::BlAckFcs => {
                self.rx_tma_unitdata_ind_bl(queue, message);
            }

            LlcPduType::AlSetup
            | LlcPduType::AlDataAlFinal
            | LlcPduType::AlAlUdataAlUfinal
            | LlcPduType::AlAckAlRnr
            | LlcPduType::AlReconnect
            | LlcPduType::AlDisc => {
                self.rx_tma_unitdata_ind_al(queue, message);
            }

            _ => {
                // PD-5c-H43 (audit LLC-01): PDU types 13 (SuppLlcPdu) and 14
                // (L2SigPdu) are valid ETSI PDU types that flowstation does
                // not implement. Log as `warn!` (non-fatal, unsupported)
                // rather than `error!("BUG:...")` to avoid false alarm-level
                // entries when a conforming peer emits them. TSC's
                // `ula_get_common_llc_pdu_type` returns a NOT_HANDLED status
                // code for these — no crash log there either.
                tracing::warn!(
                    "LLC: unsupported PDU type {:?} (SuppLlcPdu/L2SigPdu not implemented), dropping",
                    pdu_type
                );
                return;
            }
        }
    }

    fn rx_tma_unitdata_ind_bl(&mut self, queue: &mut MessageQueue, mut message: SapMsg) {
        tracing::trace!("rx_tma_unitdata_ind_bl");

        // Get header bits (again) and prepare MLE message
        let SapMsgInner::TmaUnitdataInd(prim) = &mut message.msg else {
            tracing::error!("BUG: unexpected message or state -- routing error");
            return;
        };
        let Some(mut pdu) = prim.pdu.take() else {
            tracing::warn!("LLC: rx_tma_unitdata_ind_bl received message with no pdu, ignoring");
            return;
        };
        let Some(bits) = pdu.peek_bits(4) else {
            tracing::warn!("insufficient bits: {}", pdu.dump_bin());
            return;
        };
        let Ok(pdu_type) = LlcPduType::try_from(bits) else {
            tracing::warn!("invalid pdu type: {} in {}", bits, pdu.dump_bin());
            return;
        };

        let (has_fcs, ns, nr) = match pdu_type {
            LlcPduType::BlAdata | LlcPduType::BlAdataFcs => match BlAdata::from_bitbuf(&mut pdu) {
                Ok(pdu) => {
                    tracing::debug!(ts=%self.dltime, "<- {:?}", pdu);
                    (pdu.has_fcs, Some(pdu.ns), Some(pdu.nr))
                }
                Err(e) => {
                    tracing::warn!("Failed parsing BlAdata: {:?} {}", e, pdu.dump_bin());
                    return;
                }
            },

            LlcPduType::BlData | LlcPduType::BlDataFcs => match BlData::from_bitbuf(&mut pdu) {
                Ok(pdu) => {
                    tracing::debug!(ts=%self.dltime, "<- {:?}", pdu);
                    (pdu.has_fcs, Some(pdu.ns), None)
                }
                Err(e) => {
                    tracing::warn!("Failed parsing BlData: {:?} {}", e, pdu.dump_bin());
                    return;
                }
            },
            LlcPduType::BlAck | LlcPduType::BlAckFcs => match BlAck::from_bitbuf(&mut pdu) {
                Ok(pdu) => {
                    tracing::debug!(ts=%self.dltime, "<- {:?}", pdu);
                    (pdu.has_fcs, None, Some(pdu.nr))
                }
                Err(e) => {
                    tracing::warn!("Failed parsing BlAck: {:?} {}", e, pdu.dump_bin());
                    return;
                }
            },
            LlcPduType::BlUdata | LlcPduType::BlUdataFcs => match BlUdata::from_bitbuf(&mut pdu) {
                Ok(pdu) => {
                    tracing::debug!(ts=%self.dltime, "<- {:?}", pdu);
                    (pdu.has_fcs, None, None)
                }
                Err(e) => {
                    tracing::warn!("Failed parsing BlUdata: {:?} {}", e, pdu.dump_bin());
                    return;
                }
            },
            _ => {
                tracing::error!("BUG: unexpected message or state -- routing error");
                return;
            }
        };

        // If FCS is present, check it. If wrong, we bail here
        if has_fcs && !fcs::check_fcs(&pdu) {
            tracing::warn!("FCS check failed");
            return;
        }

        // If ns is present, we need to send an ACK
        let msg_dltime = self.dltime.add_timeslots(-2); // Msg on uplink was sent two timeslots ago. 
        if let Some(ns) = ns {
            // Send ACK
            self.schedule_outgoing_ack(msg_dltime, prim.main_address, prim.carrier_num, msg_dltime.t, ns);
        }

        // if nr is present, we have received an ACK on a previous message
        if let Some(nr) = nr {
            self.process_incoming_ack(prim.main_address, prim.carrier_num, nr);
        }

        if pdu_type == LlcPduType::BlAck || pdu_type == LlcPduType::BlAckFcs {
            if pdu.get_len_remaining() == 0 {
                return;
            }
            tracing::debug!("BL-ACK PDU carrying a payload: {}", pdu.dump_bin());
            pdu.set_raw_start(pdu.get_raw_pos());
            let m = TlaTlDataIndBl {
                main_address: prim.main_address,
                link_id: 0,
                endpoint_id: prim.endpoint_id,
                new_endpoint_id: prim.new_endpoint_id,
                css_endpoint_id: prim.css_endpoint_id,
                tl_sdu: Some(pdu),
                scrambling_code: prim.scrambling_code,
                fcs_flag: has_fcs,
                air_interface_encryption: prim.air_interface_encryption,
                chan_change_resp_req: prim.chan_change_response_req,
                chan_change_handle: prim.chan_change_handle,
                chan_info: prim.chan_info,
                req_handle: 0, // TODO FIXME
            };
            queue.push_back(SapMsg {
                sap: Sap::TlaSap,
                src: TetraEntity::Llc,
                dest: TetraEntity::Mle,
                msg: SapMsgInner::TlaTlDataIndBl(m),
            });
            return;
        }

        // If unacknowledged data transfer service, we send a TL-UNITDATA indication
        // to MLE. If acknowledged data transfer service, we send a TL-DATA indication
        pdu.set_raw_start(pdu.get_raw_pos());
        let s = if pdu_type == LlcPduType::BlUdata || pdu_type == LlcPduType::BlUdataFcs {
            // Unacknowledged data transfer service
            let m = TlaTlUnitdataIndBl {
                // address_type: 0, // TODO FIXME
                main_address: prim.main_address,
                link_id: 0,
                endpoint_id: prim.endpoint_id,
                new_endpoint_id: prim.new_endpoint_id,
                css_endpoint_id: prim.css_endpoint_id,
                tl_sdu: if pdu.get_len_remaining() > 0 { Some(pdu) } else { None },
                scrambling_code: prim.scrambling_code,
                fcs_flag: has_fcs,
                air_interface_encryption: prim.air_interface_encryption,
                chan_change_resp_req: prim.chan_change_response_req,
                chan_change_handle: prim.chan_change_handle,
                chan_info: prim.chan_info,
                report: None, // TODO FIXME
            };
            SapMsg {
                sap: Sap::TlaSap,
                src: TetraEntity::Llc,
                dest: TetraEntity::Mle,
                msg: SapMsgInner::TlaTlUnitdataIndBl(m),
            }
        } else {
            // Acknowledged data transfer service
            let m = TlaTlDataIndBl {
                // address_type: 0, // TODO FIXME
                main_address: prim.main_address,
                link_id: prim.link_id,
                endpoint_id: prim.endpoint_id,
                new_endpoint_id: prim.new_endpoint_id,
                css_endpoint_id: prim.css_endpoint_id,
                tl_sdu: if pdu.get_len_remaining() > 0 { Some(pdu) } else { None },
                scrambling_code: prim.scrambling_code,
                fcs_flag: has_fcs,
                air_interface_encryption: prim.air_interface_encryption,
                chan_change_resp_req: prim.chan_change_response_req,
                chan_change_handle: prim.chan_change_handle,
                chan_info: prim.chan_info,
                req_handle: 0, // TODO FIXME
            };
            SapMsg {
                sap: Sap::TlaSap,
                src: TetraEntity::Llc,
                dest: TetraEntity::Mle,
                msg: SapMsgInner::TlaTlDataIndBl(m),
            }
        };

        queue.push_back(s);
    }

    fn submit_retransmissions_to_umac(&mut self, queue: &mut MessageQueue) -> bool {
        let mut had_activity = false;
        let dltime = self.dltime;
        let mut removals: Option<Vec<(u32, u16)>> = None;

        // if !self.outbound_messages.is_empty() {
        //     tracing::error!("{}", Self::format_expected_ack_list(&self.outbound_messages));
        // }

        for ack in self.outbound_messages.iter_mut() {
            // First, check which have newly been txed, or discarded by Umac. If so, start t_umac_done.
            if ack.t_umac_done.is_none() && (ack.tx_reporter.is_transmitted() || ack.tx_reporter.is_discarded()) {
                // TxReporter has now marked it as txed or dropped, so we can set t_umac_done
                ack.t_umac_done = Some(self.dltime);
                tracing::trace!("schedule_retransmissions: {} umac_done at {}", ack.addr.ssi, dltime);
            }

            // If we don't have a t_umac_done, there is no need for a retransmission in any case
            let Some(t_umac_done) = ack.t_umac_done else {
                continue;
            };

            // Retransmit scenario 1: it was transmitted but no ack received within the expected window (ETSI T.251 / N.252)
            // Retransmission scenario 2: it has been dropped by Umac due to congestion. Retransmit after same window
            let age = dltime.diff(t_umac_done); // Never fails
            if age as u32 >= T251_SENDER_RETRY_TIMER {
                // Time for either retransmitting or giving up
                if ack.retransmit_count < N252_BL_MAX_TLSDU_RETRANSMITS_ACKED {
                    // Retransmit
                    ack.retransmit_count += 1;
                    tracing::info!(
                        "retransmitting SSI {} N(S) {} attempt {}",
                        ack.addr.ssi,
                        ack.ns,
                        ack.retransmit_count
                    );

                    Self::submit_for_acknowledged_transmission(queue, ack, self.dltime.forward_to_timeslot(ack.t_first.t));
                    had_activity = true;
                } else {
                    // Exhausted retransmissions, flag for discard
                    removals.get_or_insert(Vec::new()).push((ack.addr.ssi, ack.carrier_num));
                }
            }
        }

        // Remove any expired entries
        if let Some(removals) = removals {
            for (ssi, carrier_num) in removals {
                // ssi was just collected from expected_acks above, so the entry exists.
                // Use if-let rather than unwrap so a future refactor of the collection
                // logic can't panic the LLC worker here.
                let Some(ack) = self.take_expected_ack_for_ssi(ssi, carrier_num) else {
                    tracing::debug!(
                        "schedule_retransmissions: expected ACK for SSI {} carrier {} already gone, skipping",
                        ssi,
                        carrier_num
                    );
                    continue;
                };
                tracing::warn!(
                    "schedule_retransmissions: SSI {} carrier {} N(S) {} exhausted retransmissions",
                    ack.addr.ssi,
                    ack.carrier_num,
                    ack.ns
                );
                match ack.tx_reporter.get_state() {
                    TxState::Transmitted => ack.tx_reporter.mark_lost(),
                    TxState::Discarded => {
                        tracing::warn!(
                            "schedule_retransmissions: SSI {} carrier {} N(S) {} expired after repeated UMAC discards; leaving reporter discarded",
                            ack.addr.ssi,
                            ack.carrier_num,
                            ack.ns
                        );
                    }
                    state => {
                        tracing::warn!(
                            "schedule_retransmissions: SSI {} carrier {} N(S) {} expired in unexpected reporter state {:?}",
                            ack.addr.ssi,
                            ack.carrier_num,
                            ack.ns,
                            state
                        );
                    }
                }
            }
            // The ack expires here
        }

        had_activity
    }

    fn submit_free_messages_to_umac(&mut self, queue: &mut MessageQueue) -> bool {
        let mut had_activity = false;
        let mut ssi_blocked: HashSet<u32> = HashSet::new();
        for ack in self.outbound_messages.iter_mut() {
            // Check if already submitted to umac
            if ack.t_submitted_to_umac.is_some() {
                // This ssi currently waits for an ack, and is thus blocked
                ssi_blocked.insert(ack.addr.ssi);
                continue;
            }

            // Not submitted; check if blocked
            if ssi_blocked.contains(&ack.addr.ssi) {
                // This SSI already has an unacked message in flight, so this one must wait —
                // strict per-link ordering is normal acknowledged-mode flow control
                // (ETSI EN 300 392-2 §22.3.2.3). Logged at trace, NOT debug: when a radio goes
                // away with several queued acknowledged SDS, this branch fires on every tick for
                // every queued message until the backlog drains, which floods the log
                // (FH-BUG-042 — one departed radio produced 3403 of 4149 lines). The queue still
                // drains correctly; only the per-tick noise was the defect.
                tracing::trace!(
                    "SSI {} N(S) {} still blocked by previous message, cannot submit next message",
                    ack.addr.ssi,
                    ack.ns
                );
                continue;
            }

            // Not submitted and not blocked. We can submit it now.
            // tracing::debug!("submitting message for SSI {} N(S) {} to umac", ack.addr.ssi, ack.ns);
            tracing::debug!(
                "submitting message for SSI {} N(S) {} to umac: {:?}",
                ack.addr.ssi,
                ack.ns,
                ack.retransmission_buf.msg
            );
            Self::submit_for_acknowledged_transmission(queue, ack, self.dltime.forward_to_timeslot(ack.t_first.t));
            ssi_blocked.insert(ack.addr.ssi);
            had_activity = true;
        }

        had_activity
    }

    /// Pops all elements from the scheduled_out_acks queue, prepares BL-ACK messages, and send them down
    fn submit_ack_replies_to_umac(&mut self, queue: &mut MessageQueue) -> bool {
        let had_activity = !self.scheduled_out_acks.is_empty();
        while let Some(ack) = self.scheduled_out_acks.pop_front() {
            tracing::debug!(
                "auto-ack for ssi: {}, carrier: {}, n: {}, ts: {}",
                ack.addr.ssi,
                ack.carrier_num,
                ack.nr,
                ack.ts
            );

            // Send BL-ACK via FACCH (stealing) on the traffic timeslot if the original
            // message arrived on a traffic channel (TS2-4), otherwise via MCCH (TS1).
            let steal = matches!(ack.ts, 2..=4);
            let mut pdu_buf = BitBuffer::new_autoexpand(5);
            let pdu = BlAck {
                has_fcs: false,
                nr: ack.nr,
            };
            pdu.to_bitbuf(&mut pdu_buf);
            pdu_buf.seek(0);
            tracing::debug!(ts=%self.dltime, "-> {:?} {}", pdu, pdu_buf.dump_bin());

            // We're sending an ACK for a received uplink message, however, we don't have that message here
            // Since DL is two slots ahead of UL, we will correct that. We now have the dltime for reception
            // of the original message.
            let chan_alloc = match steal {
                true => {
                    let mut timeslots = [false; 4];
                    timeslots[(ack.ts - 1) as usize] = true;
                    Some(CmceChanAllocReq {
                        usage: None,
                        timeslots,
                        alloc_type: ChanAllocType::Replace,
                        ul_dl_assigned: UlDlAssignment::Both,
                        carrier: Some(ack.carrier_num),
                    })
                }
                false => None,
            };
            let sapmsg = SapMsg {
                sap: Sap::TmaSap,
                src: TetraEntity::Llc,
                dest: TetraEntity::Umac,
                msg: SapMsgInner::TmaUnitdataReq(TmaUnitdataReq {
                    carrier_num: Some(ack.carrier_num),
                    req_handle: 0, // TODO FIXME
                    pdu: pdu_buf,
                    main_address: ack.addr,
                    link_id: if steal { ack.ts as u32 } else { 0 },
                    endpoint_id: 0, // todo fixme
                    stealing_permission: steal,
                    subscriber_class: 0,            // TODO FIXME
                    air_interface_encryption: None, // TODO FIXME
                    stealing_repeats_flag: None,    // TODO FIXME
                    data_category: None,            // TODO FIXME
                    chan_alloc,
                    tx_reporter: None, // By definition, no higher layer entity is interested
                    packet_data_flag: false, // ACK replies are never packet data
                }),
            };
            queue.push_back(sapmsg);
        }
        had_activity
    }

    /// Pops all elements from the scheduled_out_acks queue, prepares BL-ACK messages, and send them down
    fn submit_udata_msgs_to_umac(&mut self, queue: &mut MessageQueue) -> bool {
        let had_activity = !self.outbound_udata_messages.is_empty();
        while let Some(msg) = self.outbound_udata_messages.pop_front() {
            tracing::debug!("submitting udata msg to umac: {:?}", msg.msg);
            queue.push_back(msg);
        }
        had_activity
    }

    fn format_expected_ack_list(ack_list: &VecDeque<ExpectedInAck>) -> String {
        let mut ret = String::new();
        ret.push_str("Expected in acks:\n");
        for ack in ack_list {
            ret.push_str(&format!(
                "  ssi: {}, carrier: {}, n: {}, retransmissions: {}, t_first: {:?}, t_umac_done: {:?}, state: {:?}\n",
                ack.addr.ssi,
                ack.carrier_num,
                ack.ns,
                ack.retransmit_count,
                ack.t_first,
                ack.t_umac_done,
                ack.tx_reporter.get_state()
            ));
        }
        ret
    }

    fn format_scheduled_ack_list(ack_list: &Vec<ScheduledOutAck>) -> String {
        let mut ret = String::new();
        ret.push_str("Scheduled out acks:\n");
        for ack in ack_list {
            ret.push_str(&format!(
                "  t_start: {}, ssi: {}, carrier: {}, n: {}\n",
                ack.t_start.t, ack.addr.ssi, ack.carrier_num, ack.nr
            ));
        }
        ret
    }

    // ─── Advanced Link dispatcher ─────────────────────────────────────────────

    /// Top-level dispatcher for inbound AL PDUs.
    ///
    /// Called by `rx_tma_unitdata_ind` after the PDU type is identified as an
    /// AL variant.  Reads the 4-bit LLC type to advance the cursor, decodes the
    /// PDU-specific payload, and routes to the appropriate handler.
    ///
    /// ETSI TS 100 392-2 v3.10.1 clause 21.4.
    fn rx_tma_unitdata_ind_al(&mut self, queue: &mut MessageQueue, mut message: SapMsg) {
        let SapMsgInner::TmaUnitdataInd(prim) = &mut message.msg else {
            tracing::error!("BUG: rx_tma_unitdata_ind_al: not TmaUnitdataInd");
            return;
        };
        let Some(mut pdu) = prim.pdu.take() else {
            tracing::warn!("rx_tma_unitdata_ind_al: no PDU");
            return;
        };

        let pdu_len_bits = pdu.get_len();
        let Some(type_raw) = pdu.read_bits(4) else {
            tracing::warn!("rx_tma_unitdata_ind_al: truncated PDU");
            return;
        };
        let Ok(pdu_type) = LlcPduType::try_from(type_raw) else {
            tracing::warn!("rx_tma_unitdata_ind_al: invalid PDU type {}", type_raw);
            return;
        };

        let carrier_num = prim.carrier_num;
        let main_address = prim.main_address;
        let link_id = prim.link_id;
        let endpoint_id = prim.endpoint_id;

        match pdu_type {
            LlcPduType::AlSetup => {
                let Ok(setup) = AlSetup::from_bitbuf(&mut pdu) else {
                    tracing::warn!("rx_tma_unitdata_ind_al: failed to parse AL-SETUP");
                    return;
                };
                tracing::debug!(ts=%self.dltime, "<- {}", setup);
                let key = AlLinkKey::from_prim(main_address, link_id, endpoint_id, setup.advanced_link_number_n261);
                self.on_al_setup(queue, key, carrier_num, main_address, setup);
            }
            LlcPduType::AlDataAlFinal => {
                let Ok(data) = AlDataAlFinal::from_bitbuf(&mut pdu, pdu_len_bits) else {
                    tracing::warn!("rx_tma_unitdata_ind_al: failed to parse AL-DATA/FINAL");
                    return;
                };
                tracing::debug!(ts=%self.dltime, "<- {}", data);
                // AL-DATA does not carry N.261; resolve the link by (ssi, link_id, endpoint_id).
                let Some(key) = self.find_al_link_for_data(main_address.ssi, link_id, endpoint_id) else {
                    tracing::warn!("rx_tma_unitdata_ind_al: AL-DATA for unknown link ssi={}", main_address.ssi);
                    return;
                };
                self.on_al_data(queue, key, data);
            }
            LlcPduType::AlAlUdataAlUfinal => {
                let Ok(udata) = AlAlUdataAlUfinal::from_bitbuf(&mut pdu, pdu_len_bits) else {
                    tracing::warn!("rx_tma_unitdata_ind_al: failed to parse AL-UDATA/UFINAL");
                    return;
                };
                tracing::debug!(ts=%self.dltime, "<- {}", udata);
                let Some(key) = self.find_al_link_for_data(main_address.ssi, link_id, endpoint_id) else {
                    tracing::warn!("rx_tma_unitdata_ind_al: AL-UDATA for unknown link ssi={}", main_address.ssi);
                    return;
                };
                self.on_al_udata(queue, key, udata);
            }
            LlcPduType::AlAckAlRnr => {
                let Ok(ack) = AlAckAlRnr::from_bitbuf(&mut pdu, pdu_len_bits) else {
                    tracing::warn!("rx_tma_unitdata_ind_al: failed to parse AL-ACK/RNR");
                    return;
                };
                tracing::debug!(ts=%self.dltime, "<- {}", ack);
                let Some(key) = self.find_al_link_for_data(main_address.ssi, link_id, endpoint_id) else {
                    tracing::warn!("rx_tma_unitdata_ind_al: AL-ACK/RNR for unknown link ssi={}", main_address.ssi);
                    return;
                };
                self.on_al_ack_rnr(queue, key, ack);
            }
            LlcPduType::AlReconnect => {
                let Ok(reconnect) = AlReconnect::from_bitbuf(&mut pdu) else {
                    tracing::warn!("rx_tma_unitdata_ind_al: failed to parse AL-RECONNECT");
                    return;
                };
                tracing::debug!(ts=%self.dltime, "<- {}", reconnect);
                let key = AlLinkKey::from_prim(main_address, link_id, endpoint_id, reconnect.advanced_link_number_n261);
                self.on_al_reconnect(queue, key, carrier_num, main_address, reconnect);
            }
            LlcPduType::AlDisc => {
                let Ok(disc) = AlDisc::from_bitbuf(&mut pdu) else {
                    tracing::warn!("rx_tma_unitdata_ind_al: failed to parse AL-DISC");
                    return;
                };
                tracing::debug!(ts=%self.dltime, "<- {}", disc);
                let key = AlLinkKey::from_prim(main_address, link_id, endpoint_id, disc.advanced_link_number_n261);
                self.on_al_disc(queue, key, carrier_num, main_address, disc);
            }
            _ => {
                tracing::error!("BUG: rx_tma_unitdata_ind_al: unexpected pdu_type {:?}", pdu_type);
            }
        }
    }

    // ─── AL-SETUP ──────────────────────────────────────────────────────────────

    /// Handle an inbound AL-SETUP PDU.
    ///
    /// Two-way handshake per ETSI TS 100 392-2 v3.10.1 clause 21.4.2.
    ///
    /// NOTE: spec ambiguous — V1 only accepts Ack service with original AL
    /// (non-augmented or Original-type augmented window).  Extended-AL windows
    /// are rejected with `SetupReport::Reset`.  Any `setup_report` other than
    /// `Success` on an inbound PDU is treated as a new proposal from the peer;
    /// `Reset` is the explicit teardown request. The H47 duplicate-SETUP
    /// fast-path (below) accepts any non-`Reset` incoming report as a
    /// candidate duplicate (see PD-5c-H48).
    fn on_al_setup(
        &mut self,
        queue: &mut MessageQueue,
        key: AlLinkKey,
        carrier_num: u16,
        main_address: TetraAddress,
        pdu: AlSetup,
    ) {
        // Check if this is a confirming reply for our own pending SETUP.
        let is_confirm = matches!(self.al_links.get(&key), Some(link) if link.phase == AlPhase::SetupPending)
            && pdu.setup_report == SetupReport::Success;

        if is_confirm {
            // Peer accepted our SETUP proposal.
            if let Some(link) = self.al_links.get_mut(&key) {
                link.phase = AlPhase::Established;
                link.t_setup_start = None;
                tracing::info!(
                    "AL link {:?} established (our proposal confirmed by peer)",
                    key
                );
            }
            return;
        }

        // PD-5c-H47: duplicate-SETUP fast path. When we've already accepted
        // an AL-SETUP on this link and the peer's fresh proposal is
        // byte-identical to what we accepted, its AL-SETUP-CON was almost
        // certainly lost in DL air. Re-emit the cached echo verbatim so the
        // peer sees the CON on the second try, without re-running the full
        // accept flow (which would purge UMAC, reset RX/TX state, and reset
        // phase — none of which is appropriate here because the link is
        // still live). AlSetup derives PartialEq, so we compare what our
        // echo *would* be for this incoming proposal to the cached echo:
        // if the proposals match, the echoes match too.
        //
        // PD-5c-H48: the guard here MUST be `!= Reset`, not `== Success`.
        // MTP3550 / MTP6550 hardware sends `setup_report: ServiceDefinition`
        // on both the initial proposal and the duplicate retransmit; the
        // original H47 guard `== Success` never fired for real peer
        // proposals (Success is the code we emit on our own CON echo).
        // Any inbound value that is not `Reset` is a proposal from the
        // peer; `Reset` is the explicit teardown request (H38/H39 territory)
        // and must continue to fall through to the full re-setup + purge
        // path below. The `build_setup_echo(..., Success) == cached`
        // payload-identity check still gates whether we actually re-emit.
        let cache_setup_echo_enabled = {
            let cfg = self.config.config();
            cfg.llc.advanced_link.cache_setup_echo
        };
        if cache_setup_echo_enabled {
            if let Some(link) = self.al_links.get(&key) {
                if link.phase == AlPhase::Established
                    && pdu.setup_report != SetupReport::Reset
                {
                    if let Some(cached) = &link.last_setup_echo {
                        let would_be_echo = Self::build_setup_echo(&pdu, SetupReport::Success);
                        if &would_be_echo == cached {
                            let msg = Self::make_al_sap_msg_setup(
                                cached.clone(),
                                carrier_num,
                                main_address,
                                key.link_id,
                                key.endpoint_id,
                            );
                            queue.push_back(msg);
                            tracing::info!(
                                "AL link {:?} duplicate SETUP — re-echoed cached AL-SETUP-CON (H47)",
                                key
                            );
                            return;
                        }
                    }
                }
            }
        }

        // Validate the proposal.
        let supported = Self::is_setup_supported(&pdu);
        if !supported {
            // Reject.  NOTE: spec ambiguous — use Reset for extended-AL rejection,
            // ServiceChange for service-type mismatch.
            let reject_report = if pdu.advanced_link_service != AdvancedLinkService::Ack {
                SetupReport::ServiceChange
            } else {
                SetupReport::Reset
            };
            let reject = Self::build_setup_echo(&pdu, reject_report);
            let msg = Self::make_al_sap_msg_setup(reject, carrier_num, main_address, key.link_id, key.endpoint_id);
            queue.push_back(msg);
            tracing::info!("AL-SETUP from ssi={} rejected ({:?})", key.ssi, reject_report);
            return;
        }

        // Derive negotiated parameters.
        let tx_window = if pdu.tl_sdu_window_size_n272_n281 == 0 {
            pdu.n272_n281_augmented.unwrap_or(1).min(3)
        } else {
            pdu.tl_sdu_window_size_n272_n281
        };
        // PD-5c-H15: peers negotiating Original AL (`connection_width == 0`)
        // are single-slot and cannot pipeline SDUs at line rate even if the
        // window field advertises otherwise; serialize to 1 outstanding SDU.
        // Extended AL peers keep the negotiated window.
        let effective_tx_sdu_window = if pdu.connection_width == 0 {
            1
        } else {
            tx_window
        };
        let max_tl_sdu_octets = pdu.max_tl_sdu_length_n271.octets();

        // PD-5c-H38: detect whether this AL-SETUP re-establishes an existing
        // AL link (any live phase — Established, FlowControlled, RnrReceived,
        // or a lingering SetupPending / DisconnectPending). If so, purge any
        // DL PDUs still queued in UMAC for this peer BEFORE we send the
        // AL-SETUP echo. The peer's fresh AL RX window would drop stale
        // pre-setup N(S) segments AND wedge on them, so it never ACKs the
        // subsequent fresh N(S)=0 SDU — the exact 20-25 s
        // AL-SETUP/menu-result loop observed on the MTP6550 hardware log
        // 2026-07-11 12:51:57–12:52:46.
        //
        // Mirrors DIMETRA BRC firmware
        // `dlai_cancel_pd_transmission_on_setup_req` (in rlj_app @ 0x0021ae18):
        //   dlai_remove_tma_requests_by_address(issi)
        //   _clean_pd_user_dl_tx_state_if_needed(issi)
        //   rm_cancel_transmission_conditional(...)
        //
        // Safe on the first-time-setup path (link entry absent) — the guard
        // below skips the message so first-time behaviour is unchanged.
        let is_re_setup = self.al_links.contains_key(&key);
        if is_re_setup {
            queue.push_back(SapMsg {
                sap: Sap::Control,
                src: TetraEntity::Llc,
                dest: TetraEntity::Umac,
                msg: SapMsgInner::TmaPurgeByAddressReq { issi: key.ssi },
            });
            tracing::debug!(
                "AL link {:?} re-setup: queued TmaPurgeByAddressReq(issi={}) to UMAC",
                key, key.ssi
            );
        }

        // Accept: create or update the link.
        let link = self.al_links.entry(key).or_insert_with(|| AlLink {
            key,
            main_address,
            phase: AlPhase::Idle,
            service: pdu.advanced_link_service,
            max_tl_sdu_octets,
            tx_window,
            effective_tx_sdu_window,
            max_sdu_retx: pdu.max_retx_n273_or_repetition_n282,
            max_segment_retx: pdu.max_segment_retx_n274,
            next_n_s: 0,
            outstanding_sdus: VecDeque::new(),
            reassemblers: HashMap::new(),
            unack_reassemblers: HashMap::new(),
            unack_started_at: HashMap::new(),
            t_setup_start: None,
            t_disc_start: None,
            t_reconnect_start: None,
            t_rnr_start: None,
            setup_retries: 0,
            disc_retries: 0,
            reconnect_retries: 0,
            pending_setup_pdu: None,
            pending_reconnect_pdu: None,
            carrier_num,
            needs_deferred_ack: false,
            pending_sdus: VecDeque::new(),
            last_setup_echo: None,
            recently_delivered_ns: VecDeque::new(),
        });
        // Reset any transfer state carried over from a prior session on
        // this same link key.  On a freshly-inserted link this is a
        // no-op; on re-setup it discards stale RX reassemblers and TX
        // bookkeeping so the peer's fresh N(S)/S(S) window starts clean.
        link.reset_transfer_state();
        link.phase = AlPhase::Established;
        link.t_setup_start = None;
        link.carrier_num = carrier_num;
        link.service = pdu.advanced_link_service;
        link.max_tl_sdu_octets = max_tl_sdu_octets;
        link.tx_window = tx_window;
        link.effective_tx_sdu_window = effective_tx_sdu_window;
        link.max_sdu_retx = pdu.max_retx_n273_or_repetition_n282;
        link.max_segment_retx = pdu.max_segment_retx_n274;

        tracing::info!(
            "AL link {:?} established (peer proposal accepted, RX/TX state reset)",
            key
        );

        // Echo back with Success.
        let echo = Self::build_setup_echo(&pdu, SetupReport::Success);
        // PD-5c-H47: cache the echo so a duplicate AL-SETUP (peer's CON was
        // lost in DL air) can be answered without re-running the accept
        // flow. See the duplicate-detection block at the top of this fn.
        if let Some(link) = self.al_links.get_mut(&key) {
            link.last_setup_echo = Some(echo.clone());
        }
        let msg = Self::make_al_sap_msg_setup(echo, carrier_num, main_address, key.link_id, key.endpoint_id);
        queue.push_back(msg);
    }

    /// True if V1 supports the parameters carried in an AL-SETUP proposal.
    ///
    /// NOTE: spec ambiguous — V1 supports only Ack service and original AL
    /// (window 1..3).  Extended-AL (tl_sdu_window_size == 0 with Extended type)
    /// is rejected.
    fn is_setup_supported(pdu: &AlSetup) -> bool {
        if pdu.advanced_link_service != AdvancedLinkService::Ack {
            return false;
        }
        if pdu.tl_sdu_window_size_n272_n281 == 0 {
            if let Some(AdvancedLinkType::Extended) = pdu.advanced_link_type {
                return false;
            }
        }
        true
    }

    fn build_setup_echo(pdu: &AlSetup, report: SetupReport) -> AlSetup {
        AlSetup {
            advanced_link_service: pdu.advanced_link_service,
            advanced_link_number_n261: pdu.advanced_link_number_n261,
            max_tl_sdu_length_n271: pdu.max_tl_sdu_length_n271,
            connection_width: pdu.connection_width,
            advanced_link_symmetry: pdu.advanced_link_symmetry,
            n264_dqpsk_ts_uplink: pdu.n264_dqpsk_ts_uplink,
            n264_dqpsk_ts_downlink: pdu.n264_dqpsk_ts_downlink,
            data_transfer_throughput: pdu.data_transfer_throughput,
            tl_sdu_window_size_n272_n281: pdu.tl_sdu_window_size_n272_n281,
            max_retx_n273_or_repetition_n282: pdu.max_retx_n273_or_repetition_n282,
            max_segment_retx_n274: pdu.max_segment_retx_n274,
            setup_report: report,
            n_s: pdu.n_s,
            advanced_link_type: pdu.advanced_link_type,
            n272_n281_augmented: pdu.n272_n281_augmented,
            reserved: pdu.reserved,
        }
    }

    // ─── AL-DISC ──────────────────────────────────────────────────────────────

    /// Handle an inbound AL-DISC PDU.
    ///
    /// ETSI TS 100 392-2 v3.10.1 clause 21.4.7.
    fn on_al_disc(
        &mut self,
        queue: &mut MessageQueue,
        key: AlLinkKey,
        carrier_num: u16,
        main_address: TetraAddress,
        pdu: AlDisc,
    ) {
        // PD-5c-H39: mirror the H38 purge on the DISC teardown path.
        //
        // Motorola BRC fires `dlai_cancel_pd_transmission_on_user_removal`
        // (@ 0x0021ad6c) when the user record for an AL peer is torn down.
        // Even though the SETUP-side purge (H38) covers the "DISC → new
        // SETUP" reconnect race, the DISC handler still needs to purge any
        // DL PDUs already queued in UMAC for this peer: an MS that DISCs
        // without ever re-SETUPping (e.g. it powered off, roamed, or
        // switched to voice) would otherwise leak stale MAC-RESOURCE /
        // grant PDUs onto the air until UMAC drains them. Emitting the
        // purge from DISC as well matches the "SETUP + DISC both purge"
        // pattern in the DIMETRA firmware and closes the audit P0-1 gap.
        //
        // Guardrail: emit the purge BEFORE removing the link entry so the
        // ISSI is still resolvable from `key.ssi`, and only when a link
        // entry actually exists — stray DISCs for unknown peers do not
        // deserve a purge (nothing to purge).
        let link_exists = self.al_links.contains_key(&key);
        if link_exists {
            queue.push_back(SapMsg {
                sap: Sap::Control,
                src: TetraEntity::Llc,
                dest: TetraEntity::Umac,
                msg: SapMsgInner::TmaPurgeByAddressReq { issi: key.ssi },
            });
            tracing::debug!(
                "AL link {:?} torn down: queued TmaPurgeByAddressReq(issi={}) to UMAC",
                key, key.ssi
            );
        }

        // Check if this is a confirming reply to our own AL-DISC.
        let we_initiated = matches!(
            self.al_links.get(&key),
            Some(link) if link.phase == AlPhase::DisconnectPending
        );

        if we_initiated {
            // Peer confirmed our DISC.
            if let Some(link) = self.al_links.get_mut(&key) {
                link.t_disc_start = None;
            }
            self.al_links.remove(&key);
            tracing::info!("AL link {:?} disconnected (our DISC confirmed by peer)", key);
            return;
        }

        // Peer is requesting disconnect; reply and remove link.
        let reply = AlDisc {
            advanced_link_service: pdu.advanced_link_service,
            advanced_link_number_n261: pdu.advanced_link_number_n261,
            report: AlDiscCause::Success,
        };
        let msg = Self::make_al_sap_msg_disc(reply, carrier_num, main_address, key.link_id, key.endpoint_id);
        self.al_links.remove(&key);
        queue.push_back(msg);
        tracing::info!("AL link {:?} disconnected (peer-initiated)", key);
    }

    // ─── AL-DATA / AL-FINAL ──────────────────────────────────────────────────

    /// Handle an inbound AL-DATA / AL-FINAL PDU.
    ///
    /// Feeds the segment into the per-(link, N(S)) reassembler and enqueues
    /// an AL-ACK if the PDU carries the AR flag or reassembly completes/fails.
    ///
    /// ETSI TS 100 392-2 v3.10.1 clause 21.4.3.
    fn on_al_data(&mut self, queue: &mut MessageQueue, key: AlLinkKey, pdu: AlDataAlFinal) {
        let ar_flag = matches!(pdu.variant, AlDataVariant::DataAr | AlDataVariant::FinalAr);
        let n_s = pdu.n_s;

        // PD-5c-H49: duplicate-N(S) fast path. If we've already reassembled
        // and delivered the SDU for this N(S) and the peer is retransmitting
        // (because our AL-ACK was lost in DL air), re-emit AL-ACK on AR
        // *without* re-reassembling and *without* re-delivering the SDU
        // upward. Prevents the re-delivered SDU from triggering the H33
        // WSP-Result-replay path, which would enqueue large DL fragments
        // ahead of our tiny AL-ACK and starve the peer of the ACK it needs,
        // cascading into an AL-SETUP-Reset.  See ETSI TS 100 392-2 v3.10.1
        // clause 21.4.3 + DIMETRA rlj_app `dlai_rx_duplicate_sdu_ack`.
        let dedupe_enabled = self.config.config().llc.advanced_link.dedupe_completed_ns;
        if dedupe_enabled {
            let hit = self
                .al_links
                .get(&key)
                .map(|l| l.recently_delivered_ns.contains(&n_s))
                .unwrap_or(false);
            if hit {
                let (carrier, addr) = match self.al_links.get(&key) {
                    Some(l) => (l.carrier_num, l.main_address),
                    None => return,
                };
                tracing::debug!(
                    "AL link {:?} N(S)={} duplicate AL-DATA/FINAL (already delivered) — {}",
                    key, n_s,
                    if ar_flag { "re-ACKing without redelivery" } else { "silently ignoring (non-AR)" }
                );
                if ar_flag {
                    let ack_pdu = AlAckAlRnr {
                        kind: AlAckAlRnrKind::Ack,
                        first_block: AcknowledgementBlock {
                            n_r: n_s,
                            ack_length: AckLength::EntireSduReceived,
                            s_r: None,
                            ack_bitmap: None,
                        },
                        other_blocks: vec![],
                    };
                    let msg = Self::make_al_sap_msg_ack(
                        ack_pdu, carrier, addr, key.link_id, key.endpoint_id,
                    );
                    queue.push_back(msg);
                }
                return;
            }
        }

        let (ack_block_opt, completed_sdu, carrier, addr, link_id, endpoint_id) = {
            let Some(link) = self.al_links.get_mut(&key) else {
                tracing::warn!("on_al_data: link {:?} not found", key);
                return;
            };
            if link.phase != AlPhase::Established && link.phase != AlPhase::FlowControlled {
                tracing::warn!(
                    "on_al_data: PDU in phase {:?} (expected Established), dropping",
                    link.phase
                );
                return;
            }

            // Get or create reassembler for this N(S).
            let reassembler = link.reassemblers.entry(n_s).or_insert_with(|| Reassembler::new(n_s));

            let feed_result = reassembler.feed(&pdu);
            let mut completed_sdu = None;

            let ack_block_opt: Option<AcknowledgementBlock> = match feed_result {
                Ok(ReassemblerFeed::Complete { sdu }) => {
                    tracing::info!(
                        "AL link {:?} N(S)={} reassembly complete ({} bits)",
                        key, n_s, sdu.get_len()
                    );
                    completed_sdu = Some(sdu);
                    link.reassemblers.remove(&n_s);
                    // PD-5c-H49: record this N(S) in the recently-delivered
                    // ring so a peer retransmit (its retry timer fired
                    // before our AL-ACK reached it) re-ACKs without
                    // re-delivering. Bound by `tx_window` because the peer
                    // cannot have more outstanding SDUs than its own N.272
                    // window, so an entry older than one window-worth of
                    // deliveries is guaranteed stale.
                    if dedupe_enabled {
                        link.recently_delivered_ns.retain(|&x| x != n_s);
                        link.recently_delivered_ns.push_back(n_s);
                        let cap = link.tx_window.max(1) as usize;
                        while link.recently_delivered_ns.len() > cap {
                            link.recently_delivered_ns.pop_front();
                        }
                    }
                    Some(AcknowledgementBlock {
                        n_r: n_s,
                        ack_length: AckLength::EntireSduReceived,
                        s_r: None,
                        ack_bitmap: None,
                    })
                }
                Ok(ReassemblerFeed::FcsFailure { info, .. }) => {
                    tracing::warn!(
                        assembled_len = info.assembled_len,
                        extracted_fcs = format!("0x{:08X}", info.extracted_fcs),
                        computed_fcs = format!("0x{:08X}", info.computed_fcs),
                        "AL link {:?} N(S)={} FCS failure",
                        key, n_s
                    );
                    link.reassemblers.remove(&n_s);
                    Some(AcknowledgementBlock {
                        n_r: n_s,
                        ack_length: AckLength::SduFcsFailure,
                        s_r: None,
                        ack_bitmap: None,
                    })
                }
                Ok(ReassemblerFeed::NeedMore { received_count: _, missing_indices: _ }) => {
                    if ar_flag {
                        // Immediate cumulative ACK: S(R) = oldest missing S(S),
                        // or the next expected S(S) when the received prefix is
                        // contiguous. Never `SR::RestOfSduReceived` here — that
                        // sentinel means the whole SDU is received, which is
                        // handled by the `Complete` arm above.
                        //
                        // `AckLength::Segments(1)` with S(R) only (no bitmap)
                        // is a valid cumulative ACK shape per ETSI TS 100 392-2
                        // clause 21.2.3.1: "I confirm every S(S) below S(R);
                        // please send S(R) next."
                        let sr = SR::OldestNotReceived(reassembler.next_expected_ss());
                        Some(AcknowledgementBlock {
                            n_r: n_s,
                            ack_length: AckLength::Segments(1),
                            s_r: Some(sr),
                            ack_bitmap: None,
                        })
                    } else {
                        // Defer ACK to tick_end.
                        link.needs_deferred_ack = true;
                        None
                    }
                }
                Err(e) => {
                    tracing::warn!("on_al_data: reassembler error {:?}, dropping", e);
                    // NOTE: spec ambiguous — ConflictingRetransmission: do not ACK.
                    None
                }
            };

            (
                ack_block_opt,
                completed_sdu,
                link.carrier_num,
                link.main_address,
                key.link_id,
                key.endpoint_id,
            )
        };

        if let Some(sdu) = completed_sdu {
            queue.push_back(SapMsg {
                sap: Sap::TlaSap,
                src: TetraEntity::Llc,
                dest: TetraEntity::Mle,
                msg: SapMsgInner::TlaTlDataIndAl(TlaTlDataIndAl {
                    main_address: addr,
                    link_id,
                    endpoint_id,
                    al_link_number: key.n261,
                    tl_sdu: sdu,
                    subscriber_class: 0,
                    fcs_ok: true,
                    air_interface_encryption: None,
                }),
            });
            tracing::info!("TLA-DATA-Ind-Al on link {:?}", key);
        }

        if let Some(block) = ack_block_opt {
            let ack_pdu = AlAckAlRnr {
                kind: AlAckAlRnrKind::Ack,
                first_block: block,
                other_blocks: vec![],
            };
            let msg = Self::make_al_sap_msg_ack(ack_pdu, carrier, addr, link_id, endpoint_id);
            queue.push_back(msg);
        }
    }

    // ─── AL-UDATA / AL-UFINAL ────────────────────────────────────────────────

    /// Handle an inbound AL-UDATA / AL-UFINAL PDU (unacknowledged service).
    ///
    /// No AL-ACK is generated.  An SDU-level T.271 timeout discards partially
    /// received SDUs whose segments have not all arrived within the timer window.
    ///
    /// ETSI TS 100 392-2 v3.10.1 clause 21.4.4.
    fn on_al_udata(&mut self, queue: &mut MessageQueue, key: AlLinkKey, pdu: AlAlUdataAlUfinal) {
        let n_s = pdu.n_s;
        let dltime = self.dltime;

        let (main_address, completed_sdu) = {
            let Some(link) = self.al_links.get_mut(&key) else {
                tracing::warn!("on_al_udata: link {:?} not found", key);
                return;
            };
            if link.phase != AlPhase::Established {
                tracing::warn!("on_al_udata: PDU in phase {:?}, dropping", link.phase);
                return;
            }

            link.unack_started_at.entry(n_s).or_insert(dltime);

            let reassembler =
                link.unack_reassemblers.entry(n_s).or_insert_with(|| UnackReassembler::new(n_s));

            let result = reassembler.feed(&pdu);

            let completed = match result {
                Ok(UnackReassemblerFeed::Complete { sdu }) => {
                    tracing::info!(
                        "AL link {:?} N(S)={} unack reassembly complete ({} bits)",
                        key, n_s, sdu.get_len()
                    );
                    link.unack_reassemblers.remove(&n_s);
                    link.unack_started_at.remove(&n_s);
                    Some(sdu)
                }
                Ok(UnackReassemblerFeed::FcsFailure { info, .. }) => {
                    tracing::warn!(
                        assembled_len = info.assembled_len,
                        extracted_fcs = format!("0x{:08X}", info.extracted_fcs),
                        computed_fcs = format!("0x{:08X}", info.computed_fcs),
                        "AL link {:?} N(S)={} unack FCS failure, discarding",
                        key, n_s
                    );
                    link.unack_reassemblers.remove(&n_s);
                    link.unack_started_at.remove(&n_s);
                    None
                }
                Ok(UnackReassemblerFeed::NeedMore { .. }) => None,
                Ok(UnackReassemblerFeed::Discarded { .. }) => {
                    link.unack_reassemblers.remove(&n_s);
                    link.unack_started_at.remove(&n_s);
                    None
                }
                Err(e) => {
                    tracing::warn!("on_al_udata: reassembler error {:?}, dropping", e);
                    link.unack_reassemblers.remove(&n_s);
                    link.unack_started_at.remove(&n_s);
                    None
                }
            };

            (link.main_address, completed)
        };

        if let Some(sdu) = completed_sdu {
            queue.push_back(SapMsg {
                sap: Sap::TlaSap,
                src: TetraEntity::Llc,
                dest: TetraEntity::Mle,
                msg: SapMsgInner::TlaTlUnitdataIndAl(TlaTlUnitdataIndAl {
                    main_address,
                    link_id: key.link_id,
                    endpoint_id: key.endpoint_id,
                    al_link_number: key.n261,
                    tl_sdu: sdu,
                    subscriber_class: 0,
                    fcs_ok: true,
                    air_interface_encryption: None,
                }),
            });
            tracing::info!("TLA-UNITDATA-Ind-Al on link {:?}", key);
        }
    }

    // ─── AL-ACK / AL-RNR ─────────────────────────────────────────────────────

    /// Handle an inbound AL-ACK or AL-RNR PDU.
    ///
    /// For AL-RNR: transitions the link to `FlowControlled` and starts T.272.
    /// For both: processes acknowledgement blocks to advance the TX window.
    ///
    /// ETSI TS 100 392-2 v3.10.1 clause 21.4.5.
    fn on_al_ack_rnr(&mut self, _queue: &mut MessageQueue, key: AlLinkKey, pdu: AlAckAlRnr) {
        // PD-10c-H36: two-scope split — the first block owns the mutable
        // borrow on `self.al_links`; once it drops, the second block calls
        // `self.emit_delivery` (which needs `&self` for the hook) without a
        // borrow-checker conflict.
        let delivered: Vec<u8> = {
            let Some(link) = self.al_links.get_mut(&key) else {
                tracing::warn!("on_al_ack_rnr: link {:?} not found", key);
                return;
            };
            if link.phase != AlPhase::Established && link.phase != AlPhase::FlowControlled {
                tracing::warn!(
                    "on_al_ack_rnr: PDU in phase {:?} (expected Established/FlowControlled), dropping",
                    link.phase
                );
                return;
            }

            if pdu.kind == AlAckAlRnrKind::Rnr {
                link.phase = AlPhase::FlowControlled;
                link.t_rnr_start = Some(self.dltime);
                tracing::debug!("AL link {:?} entering FlowControlled (peer RNR)", key);
            } else if link.phase == AlPhase::FlowControlled {
                link.phase = AlPhase::Established;
                link.t_rnr_start = None;
                tracing::debug!("AL link {:?} leaving FlowControlled (ACK received)", key);
            }

            // Process all acknowledgement blocks.
            let all_blocks =
                std::iter::once(&pdu.first_block).chain(pdu.other_blocks.iter());

            let mut delivered: Vec<u8> = Vec::new();
            for block in all_blocks {
                if let Some(n_s) = Self::process_ack_block(link, block) {
                    delivered.push(n_s);
                }
            }
            delivered
        };
        for n_s in delivered {
            self.emit_delivery(key, n_s, AlDeliveryOutcome::Delivered);
        }
    }

    /// Apply one `AcknowledgementBlock` to the link's outstanding SDU window.
    ///
    /// Returns `Some(n_s)` when this block fully acknowledged an outstanding
    /// SDU (used by the caller to fire the H36 delivery hook).
    fn process_ack_block(link: &mut AlLink, block: &AcknowledgementBlock) -> Option<u8> {
        let n_r = block.n_r;

        match block.ack_length {
            AckLength::EntireSduReceived => {
                // Remove the matching SDU from the window.
                let was_outstanding = link.outstanding_sdus.iter().any(|sdu| sdu.n_s == n_r);
                link.outstanding_sdus.retain(|sdu| sdu.n_s != n_r);
                tracing::debug!("AL N(S)={} fully acknowledged", n_r);
                if was_outstanding { Some(n_r) } else { None }
            }
            AckLength::SduFcsFailure => {
                // Peer reports FCS failure; schedule immediate retransmission.
                if let Some(sdu) = link.outstanding_sdus.iter_mut().find(|s| s.n_s == n_r) {
                    sdu.force_retx = true;
                    sdu.acked_segments.iter_mut().for_each(|a| *a = false);
                    tracing::debug!("AL N(S)={} FCS failure, scheduling retx", n_r);
                }
                None
            }
            AckLength::Segments(n) => {
                let Some(sdu) = link.outstanding_sdus.iter_mut().find(|s| s.n_s == n_r) else {
                    return None;
                };
                // All segments before S(R) are received.
                let total = sdu.acked_segments.len();
                match block.s_r {
                    Some(SR::OldestNotReceived(sr)) => {
                        for idx in 0..sr as usize {
                            if idx < total {
                                sdu.acked_segments[idx] = true;
                            }
                        }
                        // sr itself is NOT received (leave false).
                        // Process bitmap for segments after sr.
                        if let Some(bm) = &block.ack_bitmap {
                            let bm_len = bm.get_len();
                            let mut bm_copy = BitBuffer::from_bitbuffer(bm);
                            for k in 0..bm_len {
                                let bit = bm_copy.read_bit().unwrap_or(0);
                                let ss = sr as usize + 1 + k;
                                if ss < total && bit == 1 {
                                    sdu.acked_segments[ss] = true;
                                }
                            }
                        }
                        let _ = n; // `n` is the number of segments reported in the block
                    }
                    Some(SR::RestOfSduReceived) => {
                        // All segments received.
                        sdu.acked_segments.iter_mut().for_each(|a| *a = true);
                    }
                    _ => {}
                }
                // If all segments are now acked, remove from window.
                if sdu.acked_segments.iter().all(|&a| a) {
                    let ns = sdu.n_s;
                    link.outstanding_sdus.retain(|s| s.n_s != ns);
                    tracing::debug!("AL N(S)={} fully acknowledged (via segment bitmap)", ns);
                    Some(ns)
                } else {
                    None
                }
            }
        }
    }

    // ─── AL-RECONNECT ────────────────────────────────────────────────────────

    /// Handle an inbound AL-RECONNECT PDU.
    ///
    /// ETSI TS 100 392-2 v3.10.1 clause 21.4.6.
    fn on_al_reconnect(
        &mut self,
        queue: &mut MessageQueue,
        key: AlLinkKey,
        carrier_num: u16,
        main_address: TetraAddress,
        pdu: AlReconnect,
    ) {
        match pdu.reconnect_report {
            ReconnectReport::Propose => {
                // Peer proposes reconnect; accept.
                let reply = AlReconnect {
                    advanced_link_service: pdu.advanced_link_service,
                    advanced_link_number_n261: pdu.advanced_link_number_n261,
                    reconnect_report: ReconnectReport::Accept,
                };
                if let Some(link) = self.al_links.get_mut(&key) {
                    link.phase = AlPhase::Established;
                    link.carrier_num = carrier_num;
                    // MS proposes a fresh N(S) window; discard stale
                    // reassembler slots so the incoming s_s=0 does not
                    // collide with a previous session's segment 0.
                    link.reset_transfer_state();
                } else {
                    // Create a minimal link on reconnect if none exists (e.g. BS restarted).
                    // Use config defaults for negotiated parameters since no SETUP PDU was seen.
                    let al_cfg = {
                        let cfg = self.config.config();
                        cfg.llc.advanced_link.clone()
                    };
                    self.al_links.insert(key, AlLink {
                        key,
                        main_address,
                        phase: AlPhase::Established,
                        service: pdu.advanced_link_service,
                        max_tl_sdu_octets: al_cfg.max_tl_sdu_octets,
                        tx_window: al_cfg.tx_window,
                        // No SETUP PDU on the reconnect self-heal path, so we
                        // fall back to the config default without the
                        // conservative `connection_width == 0` override.
                        effective_tx_sdu_window: al_cfg.tx_window,
                        max_sdu_retx: al_cfg.max_sdu_retx,
                        max_segment_retx: al_cfg.max_segment_retx,
                        next_n_s: 0,
                        outstanding_sdus: VecDeque::new(),
                        reassemblers: HashMap::new(),
                        unack_reassemblers: HashMap::new(),
                        unack_started_at: HashMap::new(),
                        t_setup_start: None,
                        t_disc_start: None,
                        t_reconnect_start: None,
                        t_rnr_start: None,
                        setup_retries: 0,
                        disc_retries: 0,
                        reconnect_retries: 0,
                        pending_setup_pdu: None,
                        pending_reconnect_pdu: None,
                        carrier_num,
                        needs_deferred_ack: false,
                        pending_sdus: VecDeque::new(),
                        last_setup_echo: None,
                        recently_delivered_ns: VecDeque::new(),
                    });
                }
                let msg = Self::make_al_sap_msg_reconnect(
                    reply, carrier_num, main_address, key.link_id, key.endpoint_id,
                );
                queue.push_back(msg);
                tracing::info!(
                    "AL link {:?} reconnected (peer-proposed, accepted, RX/TX state reset)",
                    key
                );
            }
            ReconnectReport::Accept => {
                // Our Propose was accepted.
                if let Some(link) = self.al_links.get_mut(&key) {
                    link.phase = AlPhase::Established;
                    link.t_reconnect_start = None;
                }
                tracing::info!("AL link {:?} reconnected (our proposal confirmed)", key);
            }
            ReconnectReport::Reject => {
                if let Some(link) = self.al_links.get_mut(&key) {
                    link.phase = AlPhase::Idle;
                    link.t_reconnect_start = None;
                }
                tracing::info!("AL link {:?} reconnect rejected by peer", key);
            }
            ReconnectReport::Reserved => {
                tracing::warn!("AL link {:?} received reserved ReconnectReport, ignoring", key);
            }
        }
    }

    // ─── tick_end AL activity ─────────────────────────────────────────────────

    /// Called from `tick_end` to handle AL retransmissions, deferred ACKs, and
    /// timer expiry for every known link.
    ///
    /// ETSI TS 100 392-2 v3.10.1 clauses 21.4.2 – 21.4.7, timers T.252/T.261/
    /// T.263/T.265/T.271/T.272. Note: T.251 is a *Basic Link* timer and is
    /// deliberately not used on the AL retx path — AL uses T.252 (Annex A.1,
    /// "AL acknowledgement waiting timer", 9 signalling frames ≈ 510 ms).
    fn submit_al_activity_to_umac(&mut self, queue: &mut MessageQueue) -> bool {
        let dltime = self.dltime;
        // Extract config-driven retry limits before the loop to avoid borrow conflicts
        // with the mutable borrow of self.al_links inside the loop.
        let (cfg_max_setup, cfg_max_disc, cfg_max_reconnect, cfg_proactive_disc) = {
            let cfg = self.config.config();
            let al = &cfg.llc.advanced_link;
            (al.max_setup_retries, al.max_disc_retries, al.max_reconnect_retries,
             al.proactive_disc_on_retx_exhaust)
        };
        let mut msgs: Vec<SapMsg> = Vec::new();
        let mut links_to_set_idle: Vec<AlLinkKey> = Vec::new();
        let mut links_to_remove: Vec<AlLinkKey> = Vec::new();
        // PD-10c-H36: collect drop events for post-loop emission (can't call
        // &self.emit_delivery while self.al_links is mutably borrowed).
        let mut drops: Vec<(AlLinkKey, u8, AlDeliveryOutcome)> = Vec::new();
        // PD-5c-H47: collect links that hit retx-exhaustion so we can emit
        // AL-DISC + TmaPurgeByAddressReq after the al_links borrow ends.
        let mut retx_exhausted_links: Vec<AlLinkKey> = Vec::new();

        for (key, link) in self.al_links.iter_mut() {
            // 0. T.272 — RNR receiver-not-ready expiry (must run before step 1 so that
            //    buffered SDUs can be dispatched in the same tick they unfreeze).
            if link.phase == AlPhase::FlowControlled {
                if let Some(t_start) = link.t_rnr_start {
                    if dltime.diff(t_start) as u64 >= T272_RECEIVER_NOT_READY_FOR_RX_TIMER as u64 {
                        link.phase = AlPhase::Established;
                        link.t_rnr_start = None;
                        tracing::info!(
                            "AL link {:?} T.272 expired, resuming transmission",
                            key
                        );
                    }
                }
            }

            // 1. TX retransmission (Established only; FlowControlled blocks sending).
            if link.phase == AlPhase::Established {
                let mut sdus_to_remove: Vec<u8> = Vec::new();
                for sdu in link.outstanding_sdus.iter_mut() {
                    // PD-5c-H17: gate the T.252 clock on UMAC actually having
                    // aired the tail of this SDU. `last_segment_tx_at` stays
                    // `None` until every still-unacked segment reports
                    // `Transmitted`; at that point we stamp `dltime` and the
                    // T.252 ACK-wait window opens. Discarded segments (UMAC
                    // congestion) trigger an immediate `force_retx` so we
                    // don't stall waiting for a tail that will never fly.
                    if sdu.last_segment_tx_at.is_none() {
                        let mut all_transmitted = true;
                        let mut any_discarded = false;
                        for (idx, rep_opt) in sdu.segment_reporters.iter().enumerate() {
                            if sdu.acked_segments.get(idx).copied().unwrap_or(false) {
                                continue; // ignore already-acked slots
                            }
                            match rep_opt {
                                Some(rep) => {
                                    if rep.is_discarded() {
                                        any_discarded = true;
                                    } else if !rep.is_transmitted() {
                                        all_transmitted = false;
                                    }
                                }
                                None => {
                                    // Unacked slot without a reporter — treat
                                    // as not-yet-transmitted so we don't open
                                    // the ACK window prematurely.
                                    all_transmitted = false;
                                }
                            }
                        }
                        if any_discarded {
                            sdu.force_retx = true;
                        } else if all_transmitted && !sdu.segment_reporters.is_empty() {
                            sdu.last_segment_tx_at = Some(dltime);
                        }
                    }

                    // ETSI TS 100 392-2 v3.10.1 clause 21.4.5, Annex A.1 T.252
                    // (AL acknowledgement waiting timer, 9 signalling frames
                    // ≈ 510 ms). T.251 is the Basic Link retry timer and must
                    // not be used here — AL RTT on granted PDCH can exceed
                    // T.251 (≈ 226 ms) so a peer-negotiated `max_retx = 0`
                    // would otherwise drop the SDU before its AL-ACK arrives.
                    //
                    // PD-5c-H17: measure against `last_segment_tx_at` — the
                    // moment UMAC finished airing the tail — not the initial
                    // submission time. Multi-fragment SDUs whose last frag
                    // leaves the air hundreds of ms after enqueue would
                    // otherwise be dropped before the peer's AL-ACK could
                    // physically arrive. SDUs that have `sent_at == None`
                    // were buffered while the link was FlowControlled (or
                    // similarly deferred) and have never been submitted to
                    // UMAC yet — those still need to be pushed through this
                    // loop for their *initial* send, so treat them as
                    // needing tx immediately.
                    let needs_retx = sdu.force_retx || match (sdu.sent_at, sdu.last_segment_tx_at) {
                        (None, _) => true, // never sent — initial send from buffered state
                        (Some(_), None) => false, // tail not yet aired — T.252 has not started
                        (Some(_), Some(t)) => dltime.diff(t) as u64 >= T252_ACK_WAITING_TIMER as u64,
                    };
                    let has_unacked = sdu.acked_segments.iter().any(|&a| !a);
                    if needs_retx && has_unacked {
                        // PD-5c-H26 (2026-07-11 MTP3550 fix): peer-requested
                        // retransmission (SduFcsFailure ACK sets `force_retx`)
                        // is a different animal from time-based retx. When the
                        // MS explicitly tells us "I got the SDU but the FCS
                        // failed, please resend", honoring that is essential
                        // for TETRA AL correctness — MS is still holding the
                        // AL link open for our retry. Dropping in that case
                        // caused MS to send AL-RECONNECT (link reset), forcing
                        // a WSP-CONNECT loop and a red-blinking radio.
                        // Time-based retx (T.252 expired, no ACK at all)
                        // still honors max_sdu_retx.
                        let peer_requested_retx = sdu.force_retx;
                        // PD-5c-H44 (audit 01-al §P12): distinguish "initial
                        // send from buffered state" (sent_at == None) from a
                        // real retransmission. Only real retx should be
                        // budget-gated by max_sdu_retx and should increment
                        // retx_count — otherwise a deferred initial send
                        // burns a retry attempt, giving one fewer retx than
                        // N.273 permits.
                        let is_initial_send = sdu.sent_at.is_none();
                        // PD-5c-H44 (audit 01-al §P7): N.274 (max_segment_retx)
                        // must be honoured alongside N.273 (max_sdu_retx).
                        // Because our TX path retransmits all still-unacked
                        // segments together on each pass, retx_count at the
                        // SDU level equals the per-segment retransmit count
                        // for every unacked segment — so a combined min-cap
                        // enforces the tighter of the two negotiated bounds.
                        // Treat max_segment_retx = 0 as "unlimited" only when
                        // the SDU-level cap is already binding; otherwise
                        // honour it as a hard "no per-segment retx" limit.
                        //
                        // PD-5c-H46 (MTP6550 field regression, hardware trace
                        // 53:51.898–54:17.058): Motorola MTP6550 negotiates
                        // AL-SETUP with `N.273 = 0, N.274 = 3, service = Ack`.
                        // Taken literally (min(0, 3) = 0) that yields
                        // fire-and-forget DL SDUs on a *reliable* service —
                        // any air loss then wedges WSP because H45 defers
                        // WTP Result retx while AL delivery is in flight,
                        // and AL delivery never confirms. The MS's own
                        // `N.274 = 3` shows it *expects* 3 attempts.
                        // ETSI clause 23.5 is ambiguous on `N.273 = 0`:
                        // one reading is "no retx", the other is
                        // "no explicit SDU-level cap; use N.274 as the
                        // effective bound". For `service = Ack` (reliable),
                        // the second reading is the only one that keeps the
                        // service its name. Adopt it as a targeted quirk:
                        // when `service = Ack`, `N.273 = 0`, `N.274 > 0`,
                        // use `N.274` as the effective cap.
                        //
                        // - Genuine "no retx" negotiations (both zero, or
                        //   non-Ack service) still route to fire-and-forget
                        //   via `effective_max_retx == 0` below.
                        // - Honestly low N.274 (e.g. N.273=3, N.274=1) is
                        //   still capped by the H44 `min()` — this quirk
                        //   only fires when N.273 itself is zero.
                        // - H26 peer-requested (SduFcsFailure) retx path
                        //   remains independent with its own cap of 3.
                        let effective_max_retx = if link.max_segment_retx == 0 {
                            // Per audit §P7: N.274 = 0 means the peer opted
                            // out of per-segment retx entirely. Any retx of
                            // any segment violates the contract, so treat as
                            // no retx budget at all.
                            0
                        } else if link.max_sdu_retx == 0
                            && link.service == AdvancedLinkService::Ack
                        {
                            // PD-5c-H46: MTP6550 quirk (see above).
                            link.max_segment_retx
                        } else {
                            std::cmp::min(link.max_sdu_retx, link.max_segment_retx)
                        };
                        // Use the link's per-negotiated max_sdu_retx (from SETUP PDU or config
                        // default for reconnect-fallback links) rather than the global constant.
                        if !is_initial_send
                            && sdu.retx_count >= effective_max_retx
                            && !peer_requested_retx
                        {
                            // PD-5c-H19: with max_sdu_retx=0 (MS-negotiated for Original AL /
                            // Motorola MTP3550), we've already transmitted the SDU once and by
                            // spec have no retry budget. Prior behaviour dropped with a WARN
                            // which is misleading — the bits are on the air, the peer simply
                            // hasn't sent an AL-ACK (either it did receive them but its stack
                            // suppresses AL-ACK to app-layer failures, or the ACK crossed
                            // with a schedule change). Dropping does NOT undo the transmission;
                            // it only frees our outstanding-SDU slot so we can enqueue the next
                            // one. Log at DEBUG (fire-and-forget completion) instead of WARN
                            // (protocol failure) — this stops the alarm-log storm on every
                            // downlink SDU when the peer doesn't AL-ACK.
                            if effective_max_retx == 0 {
                                tracing::debug!(
                                    "AL link {:?} N(S)={} fire-and-forget SDU released (effective_max_retx=0)",
                                    key, sdu.n_s
                                );
                                drops.push((*key, sdu.n_s, AlDeliveryOutcome::DroppedFireAndForget));
                            } else {
                                tracing::warn!(
                                    "AL link {:?} N(S)={} exhausted retransmissions (retx_count={}, effective_max={}), dropping SDU",
                                    key, sdu.n_s, sdu.retx_count, effective_max_retx
                                );
                                drops.push((*key, sdu.n_s, AlDeliveryOutcome::DroppedRetxExhausted));
                                // PD-5c-H47: mark this link for proactive
                                // AL-DISC + UMAC purge so the peer can tear
                                // down its side immediately instead of
                                // waiting for its own SDU-lifetime timer.
                                if cfg_proactive_disc && !retx_exhausted_links.contains(key) {
                                    retx_exhausted_links.push(*key);
                                }
                            }
                            sdus_to_remove.push(sdu.n_s);
                            continue;
                        }
                        if peer_requested_retx && sdu.retx_count >= 3 {
                            // Even peer-requested retx has an upper bound to avoid
                            // infinite loops if the RF environment is genuinely broken.
                            tracing::warn!(
                                "AL link {:?} N(S)={} exceeded peer-requested retx cap (3), dropping",
                                key, sdu.n_s
                            );
                            drops.push((*key, sdu.n_s, AlDeliveryOutcome::DroppedRetxExhausted));
                            if cfg_proactive_disc && !retx_exhausted_links.contains(key) {
                                retx_exhausted_links.push(*key);
                            }
                            sdus_to_remove.push(sdu.n_s);
                            continue;
                        }
                        if peer_requested_retx {
                            tracing::debug!(
                                "AL link {:?} N(S)={} peer-requested retx #{} (SduFcsFailure)",
                                key, sdu.n_s, sdu.retx_count + 1
                            );
                        }
                        sdu.force_retx = false;
                        sdu.sent_at = Some(dltime);
                        // PD-5c-H17: retx opens a new T.252 window. Clear the
                        // previous stamp; it will be re-set once every fresh
                        // reporter reports `Transmitted`.
                        sdu.last_segment_tx_at = None;
                        // PD-5c-H44 (audit 01-al §P12): only real retransmissions
                        // burn budget. A deferred initial send (is_initial_send)
                        // must not increment retx_count.
                        if !is_initial_send {
                            sdu.retx_count += 1;
                        }
                        // (Re)send only the unacknowledged segments. Hand a
                        // fresh `TxReporter` to UMAC per segment so we can
                        // observe when the tail actually leaves the air.
                        for (idx, pdu) in sdu.pdus.iter().enumerate() {
                            if !sdu.acked_segments.get(idx).copied().unwrap_or(false) {
                                let mut buf = BitBuffer::new_autoexpand(256);
                                pdu.to_bitbuf(&mut buf);
                                buf.seek(0);
                                let reporter = TxReporter::new();
                                // Overwrite any stale reporter for this slot.
                                if idx < sdu.segment_reporters.len() {
                                    sdu.segment_reporters[idx] = Some(reporter.clone());
                                }
                                msgs.push(SapMsg {
                                    sap: Sap::TmaSap,
                                    src: TetraEntity::Llc,
                                    dest: TetraEntity::Umac,
                                    msg: SapMsgInner::TmaUnitdataReq(TmaUnitdataReq {
                                        carrier_num: Some(link.carrier_num),
                                        req_handle: 0,
                                        pdu: buf,
                                        main_address: link.main_address,
                                        link_id: link.key.link_id,
                                        endpoint_id: link.key.endpoint_id,
                                        stealing_permission: false,
                                        subscriber_class: 0,
                                        air_interface_encryption: None,
                                        stealing_repeats_flag: None,
                                        data_category: None,
                                        chan_alloc: None,
                                        tx_reporter: Some(reporter),
                                        packet_data_flag: false, // AL retransmissions are signalling
                                    }),
                                });
                            }
                        }
                        if !is_initial_send {
                            tracing::info!(
                                "AL link {:?} N(S)={} retransmitting (attempt {}/{})",
                                key, sdu.n_s, sdu.retx_count, effective_max_retx
                            );
                        }
                    }
                }
                for ns in sdus_to_remove {
                    link.outstanding_sdus.retain(|s| s.n_s != ns);
                }
            }

            // 2. Deferred ACK flush.
            if link.needs_deferred_ack {
                link.needs_deferred_ack = false;
                // Build one AL-ACK covering all in-progress reassemblers.
                // For each in-flight N(S), emit a cumulative ACK block whose
                // S(R) is the next expected S(S) (smallest missing index, or
                // `segments.len()` when the received prefix is contiguous).
                // Never `SR::RestOfSduReceived` here — that sentinel is reserved
                // for full-SDU confirmation, which is handled by the immediate
                // ACK in `on_al_data`'s `Complete` arm.
                let blocks: Vec<AcknowledgementBlock> = link
                    .reassemblers
                    .iter()
                    .map(|(&n_s, reassembler)| AcknowledgementBlock {
                        n_r: n_s,
                        ack_length: AckLength::Segments(1),
                        s_r: Some(SR::OldestNotReceived(reassembler.next_expected_ss())),
                        ack_bitmap: None,
                    })
                    .collect();

                if !blocks.is_empty() {
                    let (first, rest) = blocks.split_first().unwrap();
                    let ack_pdu = AlAckAlRnr {
                        kind: AlAckAlRnrKind::Ack,
                        first_block: first.clone(),
                        other_blocks: rest.to_vec(),
                    };
                    msgs.push(Self::make_al_sap_msg_ack(
                        ack_pdu,
                        link.carrier_num,
                        link.main_address,
                        link.key.link_id,
                        link.key.endpoint_id,
                    ));
                }
            }

            // 3. Unack SDU timeout (T.271).
            let timed_out_ns: Vec<u8> = link
                .unack_started_at
                .iter()
                .filter(|&(_, t)| dltime.diff(*t) as u64 >= T271_RECEIVER_NOT_READY_FOR_TX_TIMER as u64)
                .map(|(&ns, _)| ns)
                .collect();
            for ns in timed_out_ns {
                if let Some(ra) = link.unack_reassemblers.get_mut(&ns) {
                    let result = ra.discard();
                    tracing::warn!(
                        "AL link {:?} N(S)={} unack SDU T.271 timeout: {:?}",
                        key, ns, result
                    );
                }
                link.unack_reassemblers.remove(&ns);
                link.unack_started_at.remove(&ns);
            }

            // 4. T.261 — AL-SETUP retry / give-up.
            if link.phase == AlPhase::SetupPending {
                if let Some(t_start) = link.t_setup_start {
                    if dltime.diff(t_start) as u64 >= T261_SETUP_WAITING_TIMER as u64 {
                        if (link.setup_retries as u32) < cfg_max_setup as u32 {
                            link.setup_retries += 1;
                            link.t_setup_start = Some(dltime);
                            if let Some(setup_pdu) = link.pending_setup_pdu.clone() {
                                msgs.push(Self::make_al_sap_msg_setup(
                                    setup_pdu,
                                    link.carrier_num,
                                    link.main_address,
                                    link.key.link_id,
                                    link.key.endpoint_id,
                                ));
                                tracing::info!(
                                    "AL link {:?} SETUP retry {}",
                                    key, link.setup_retries
                                );
                            }
                        } else {
                            tracing::warn!(
                                "AL link {:?} SETUP N.262 exhausted, returning to Idle",
                                key
                            );
                            links_to_set_idle.push(*key);
                        }
                    }
                }
            }

            // 5. T.263 — AL-DISC retry / give-up.
            if link.phase == AlPhase::DisconnectPending {
                if let Some(t_start) = link.t_disc_start {
                    if dltime.diff(t_start) as u64 >= T263_DISCONNECT_WAITING_TIMER as u64 {
                        if (link.disc_retries as u32) < cfg_max_disc as u32 {
                            link.disc_retries += 1;
                            link.t_disc_start = Some(dltime);
                            let disc_pdu = AlDisc {
                                advanced_link_service: link.service,
                                advanced_link_number_n261: link.key.n261,
                                report: AlDiscCause::Success,
                            };
                            msgs.push(Self::make_al_sap_msg_disc(
                                disc_pdu,
                                link.carrier_num,
                                link.main_address,
                                link.key.link_id,
                                link.key.endpoint_id,
                            ));
                        } else {
                            tracing::warn!(
                                "AL link {:?} DISC N.263 exhausted, removing link",
                                key
                            );
                            links_to_remove.push(*key);
                        }
                    }
                }
            }

            // 6. T.265 — AL-RECONNECT retry / give-up.
            if link.phase == AlPhase::ReconnectPending {
                if let Some(t_start) = link.t_reconnect_start {
                    if dltime.diff(t_start) as u64 >= T265_RECONNECT_WAITING_TIMER as u64 {
                        if (link.reconnect_retries as u32) < cfg_max_reconnect as u32 {
                            link.reconnect_retries += 1;
                            link.t_reconnect_start = Some(dltime);
                            if let Some(pdu) = link.pending_reconnect_pdu.clone() {
                                msgs.push(Self::make_al_sap_msg_reconnect(
                                    pdu,
                                    link.carrier_num,
                                    link.main_address,
                                    link.key.link_id,
                                    link.key.endpoint_id,
                                ));
                            }
                        } else {
                            tracing::warn!(
                                "AL link {:?} RECONNECT N.265 exhausted, returning to Idle",
                                key
                            );
                            links_to_set_idle.push(*key);
                        }
                    }
                }
            }

        }

        for key in links_to_set_idle {
            if let Some(link) = self.al_links.get_mut(&key) {
                link.phase = AlPhase::Idle;
                link.t_setup_start = None;
                link.t_reconnect_start = None;
            }
        }
        for key in links_to_remove {
            self.al_links.remove(&key);
        }

        // PD-5c-H47: proactive AL-DISC + UMAC purge for links that hit
        // retx-exhaustion. Emitted after `drops` are queued but before
        // `emit_delivery` fires, so H36 subscribers still see the
        // `DroppedRetxExhausted` event first when the drops loop runs
        // below. Mirrors DIMETRA `dlai_cancel_pd_transmission_on_user_removal`
        // (BRC @ 0x0021ad6c) — the same purge helper the H39 DISC path
        // already targets — and matches the standard normal-teardown
        // AlDiscCause used on every clean session end.
        for key in retx_exhausted_links {
            let (service, carrier_num, main_address) =
                match self.al_links.get(&key) {
                    Some(link) => (link.service, link.carrier_num, link.main_address),
                    None => continue, // already gone (e.g. duplicate hit above)
                };
            let disc_pdu = AlDisc {
                advanced_link_service: service,
                advanced_link_number_n261: key.n261,
                report: AlDiscCause::Success,
            };
            msgs.push(Self::make_al_sap_msg_disc(
                disc_pdu,
                carrier_num,
                main_address,
                key.link_id,
                key.endpoint_id,
            ));
            msgs.push(SapMsg {
                sap: Sap::Control,
                src: TetraEntity::Llc,
                dest: TetraEntity::Umac,
                msg: SapMsgInner::TmaPurgeByAddressReq { issi: key.ssi },
            });
            self.al_links.remove(&key);
            tracing::warn!(
                "AL link {:?} retx-exhausted — emitted proactive AL-DISC(Success) + TmaPurgeByAddressReq (H47)",
                key
            );
        }

        let pending_to_send: Vec<(AlLinkKey, Vec<u8>)> = {
            let mut to_send = Vec::new();
            for (key, link) in self.al_links.iter_mut() {
                if link.phase == AlPhase::Established {
                    while link.outstanding_sdus.len() < link.effective_tx_sdu_window as usize {
                        if let Some(sdu) = link.pending_sdus.pop_front() {
                            to_send.push((*key, sdu));
                        } else {
                            break;
                        }
                    }
                }
            }
            to_send
        };
        for (key, sdu) in pending_to_send {
            if let Err(e) = self.enqueue_al_sdu(queue, key, sdu) {
                tracing::warn!(
                    "submit_al_activity_to_umac: failed to flush pending SDU on link {:?}: {:?}",
                    key,
                    e
                );
            }
        }

        let had = !msgs.is_empty();
        for msg in msgs {
            queue.push_back(msg);
        }
        // PD-10c-H36: emit any drops now that the mutable borrow on
        // self.al_links has ended.
        for (key, n_s, outcome) in drops {
            self.emit_delivery(key, n_s, outcome);
        }
        had
    }

    // ─── AL helpers ───────────────────────────────────────────────────────────

    /// Find an AL link by (ssi, link_id, endpoint_id), ignoring n261.
    ///
    /// Used for PDU types that do not carry a link number (AL-DATA, AL-ACK).
    ///
    /// NOTE: spec ambiguous — if multiple N.261 links exist for the same address,
    /// this picks the first one in hash-map iteration order.  V1 supports only
    /// link 0 so there is at most one.
    fn find_al_link_for_data(
        &self,
        ssi: u32,
        link_id: u32,
        endpoint_id: u32,
    ) -> Option<AlLinkKey> {
        self.al_links
            .keys()
            .find(|k| k.ssi == ssi && k.link_id == link_id && k.endpoint_id == endpoint_id)
            .copied()
    }

    fn make_al_sap_msg_setup(
        pdu: AlSetup,
        carrier_num: u16,
        main_address: TetraAddress,
        link_id: u32,
        endpoint_id: u32,
    ) -> SapMsg {
        let mut buf = BitBuffer::new_autoexpand(64);
        pdu.to_bitbuf(&mut buf);
        buf.seek(0);
        Self::make_al_raw_sap_msg(buf, carrier_num, main_address, link_id, endpoint_id)
    }

    fn make_al_sap_msg_disc(
        pdu: AlDisc,
        carrier_num: u16,
        main_address: TetraAddress,
        link_id: u32,
        endpoint_id: u32,
    ) -> SapMsg {
        let mut buf = BitBuffer::new_autoexpand(16);
        pdu.to_bitbuf(&mut buf);
        buf.seek(0);
        Self::make_al_raw_sap_msg(buf, carrier_num, main_address, link_id, endpoint_id)
    }

    fn make_al_sap_msg_reconnect(
        pdu: AlReconnect,
        carrier_num: u16,
        main_address: TetraAddress,
        link_id: u32,
        endpoint_id: u32,
    ) -> SapMsg {
        let mut buf = BitBuffer::new_autoexpand(16);
        pdu.to_bitbuf(&mut buf);
        buf.seek(0);
        Self::make_al_raw_sap_msg(buf, carrier_num, main_address, link_id, endpoint_id)
    }

    fn make_al_sap_msg_ack(
        pdu: AlAckAlRnr,
        carrier_num: u16,
        main_address: TetraAddress,
        link_id: u32,
        endpoint_id: u32,
    ) -> SapMsg {
        let mut buf = BitBuffer::new_autoexpand(64);
        pdu.to_bitbuf(&mut buf);
        buf.seek(0);
        Self::make_al_raw_sap_msg(buf, carrier_num, main_address, link_id, endpoint_id)
    }

    fn make_al_raw_sap_msg(
        pdu: BitBuffer,
        carrier_num: u16,
        main_address: TetraAddress,
        link_id: u32,
        endpoint_id: u32,
    ) -> SapMsg {
        SapMsg {
            sap: Sap::TmaSap,
            src: TetraEntity::Llc,
            dest: TetraEntity::Umac,
            msg: SapMsgInner::TmaUnitdataReq(TmaUnitdataReq {
                carrier_num: Some(carrier_num),
                req_handle: 0,
                pdu,
                main_address,
                link_id,
                endpoint_id,
                stealing_permission: false,
                subscriber_class: 0,
                air_interface_encryption: None,
                stealing_repeats_flag: None,
                data_category: None,
                chan_alloc: None,
                tx_reporter: None,
                packet_data_flag: false, // AL raw messages are signalling (ACKs, setup, etc.)
            }),
        }
    }

    /// Segment `sdu` and enqueue all resulting PDUs onto `queue` for the
    /// specified `link`. When the TX window is full, the SDU is buffered in
    /// `AlLink::pending_sdus` for later dispatch.
    ///
    /// Returns `Err` (without side-effects) only for hard failures (unknown link,
    /// wrong phase, SDU too large, segmentation error).
    pub(super) fn enqueue_al_sdu(
        &mut self,
        queue: &mut MessageQueue,
        key: AlLinkKey,
        sdu: Vec<u8>,
    ) -> Result<(), AlError> {
        let link = self.al_links.get_mut(&key).ok_or(AlError::UnknownLink(key))?;

        if link.phase != AlPhase::Established && link.phase != AlPhase::FlowControlled {
            return Err(AlError::NotEstablished);
        }
        if sdu.len() > link.max_tl_sdu_octets as usize {
            return Err(AlError::SduTooLarge { got: sdu.len(), max: link.max_tl_sdu_octets });
        }

        if link.outstanding_sdus.len() >= link.effective_tx_sdu_window as usize {
            link.pending_sdus.push_back(sdu);
            return Ok(());
        }

        let n_s = link.next_n_s;
        let tx_window = link.tx_window;
        let carrier = link.carrier_num;
        let addr = link.main_address;
        let l_id = link.key.link_id;
        let e_id = link.key.endpoint_id;
        let seg_bits = self.al_segment_payload_bits;

        let config = SegmenterConfig {
            segment_payload_bits: seg_bits,
            starting_n_s: n_s,
            request_ack_on_final: true,
            request_ack_on_data: false,
        };

        let output = segment_sdu(&sdu, &config).map_err(AlError::SegmentationFailed)?;

        let seg_count = output.pdus.len();
        let acked_segments = vec![false; seg_count];
        // PD-5c-H17: create one TxReporter per segment so LLC can observe
        // (via UMAC's `mark_transmitted`) when the tail actually leaves the
        // air. UMAC paces segments across many frames; the T.252 ACK-wait
        // clock must not start until the last one is gone.
        let reporters: Vec<TxReporter> = (0..seg_count).map(|_| TxReporter::new()).collect();

        let link = self.al_links.get_mut(&key).ok_or(AlError::UnknownLink(key))?;
        link.next_n_s = (n_s + 1) % (tx_window + 1);
        link.outstanding_sdus.push_back(OutstandingSdu {
            n_s,
            pdus: output.pdus.clone(),
            sent_at: None,
            acked_segments,
            segment_reporters: reporters.iter().cloned().map(Some).collect(),
            last_segment_tx_at: None,
            retx_count: 0,
            force_retx: false,
        });

        let link = self.al_links.get(&key).ok_or(AlError::UnknownLink(key))?;
        let is_established = link.phase == AlPhase::Established;
        if is_established {
            for (pdu, reporter) in output.pdus.iter().zip(reporters.iter()) {
                let mut buf = BitBuffer::new_autoexpand(256);
                pdu.to_bitbuf(&mut buf);
                buf.seek(0);
                queue.push_back(SapMsg {
                    sap: Sap::TmaSap,
                    src: TetraEntity::Llc,
                    dest: TetraEntity::Umac,
                    msg: SapMsgInner::TmaUnitdataReq(TmaUnitdataReq {
                        carrier_num: Some(carrier),
                        req_handle: 0,
                        pdu: buf,
                        main_address: addr,
                        link_id: l_id,
                        endpoint_id: e_id,
                        stealing_permission: false,
                        subscriber_class: 0,
                        air_interface_encryption: None,
                        stealing_repeats_flag: None,
                        data_category: None,
                        chan_alloc: None,
                        tx_reporter: Some(reporter.clone()),
                        packet_data_flag: false, // AL SDU segments are signalling
                    }),
                });
            }

            let dltime = self.dltime;
            if let Some(sdu_entry) = self.al_links.get_mut(&key).and_then(|l| l.outstanding_sdus.back_mut()) {
                sdu_entry.sent_at = Some(dltime);
            }
        }

        Ok(())
    }
}

impl TetraEntityTrait for Llc {
    fn entity(&self) -> TetraEntity {
        TetraEntity::Llc
    }

    fn set_config(&mut self, config: SharedConfig) {
        self.config = config;
    }

    fn rx_prim(&mut self, queue: &mut MessageQueue, message: SapMsg) {
        tracing::debug!("rx_prim: {:?}", message);
        // tracing::debug!(ts=%message.dltime, "rx_prim: {:?}", message);

        match message.sap {
            Sap::TmaSap => {
                self.rx_tma_prim(queue, message);
            }

            // TMB-SAP and TMC-SAP are skipped and passed straight between MAC and MLE
            Sap::TlaSap => {
                self.rx_tla_prim(queue, message);
            }
            _ => {
                tracing::warn!("unhandled match variant, ignoring");
            }
        }
    }

    fn tick_start(&mut self, _queue: &mut MessageQueue, ts: TdmaTime) {
        self.dltime = ts;
    }

    fn tick_end(&mut self, queue: &mut MessageQueue, _ts: TdmaTime) -> bool {
        let mut had_activity = false;

        // Step 1 / 4: Check if we have any transmitted messages that were not acked within the expected window
        // Schedule a retransmission if appropriate.
        had_activity |= self.submit_retransmissions_to_umac(queue);

        // Step 2 / 4: Check if there are any messages that were not yet sent down, that we can now send down the stack
        // Messages may be kept since the target SSI has not yet acked them . If the link is now free, we can send the message down and register that we expect an ACK for it.
        had_activity |= self.submit_free_messages_to_umac(queue);

        // Step 3 / 4: Check if any unsent ACKs are still here
        // Take oldest element from scheduled_out_acks, and remove it from the list
        had_activity |= self.submit_ack_replies_to_umac(queue);

        // Step 4 / 5: Send any U-DATA messages
        had_activity |= self.submit_udata_msgs_to_umac(queue);

        // Step 5 / 5: AL retransmissions, deferred ACKs, and timer expiry
        had_activity |= self.submit_al_activity_to_umac(queue);

        had_activity
    }
}
