/// Advanced Link (AL) LLC state machine tests.
///
/// Tests the AL-3 state machine implemented in `llc_bs_ms.rs`.
/// All tests instantiate `Llc` directly (without ComponentTest) so they can
/// inspect internal state (`al_links`, outstanding windows, …) alongside
/// the outbound message queue.
///
/// Pattern:
///   1. Build `Llc` directly via `Llc::new(shared_config)`.
///   2. Advance `tick_start`.
///   3. Call `rx_prim` with an encoded `TmaUnitdataInd`.
///   4. Call `tick_end` to flush deferred ACKs / retransmissions.
///   5. Inspect `queue` and `llc.al_links`.
mod common;

use common::ComponentTest;
use tetra_config::bluestation::StackMode;
use tetra_core::{BitBuffer, Sap, SsiType, TdmaTime, TetraAddress, debug};
use tetra_core::tetra_entities::TetraEntity;
use tetra_entities::llc::llc_bs_ms::{AlLinkKey, AlPhase, Llc};
use tetra_entities::{MessageQueue, TetraEntityTrait};
use tetra_pdus::llc::al::segmenter::{SegmenterConfig, segment_sdu};
use tetra_pdus::llc::consts::timers::{
    T251_SENDER_RETRY_TIMER, T252_ACK_WAITING_TIMER, T261_SETUP_WAITING_TIMER,
    T272_RECEIVER_NOT_READY_FOR_RX_TIMER,
};
use tetra_pdus::llc::enums::advanced_link_service::AdvancedLinkService;
use tetra_pdus::llc::enums::advanced_link_symmetry::AdvancedLinkSymmetry;
use tetra_pdus::llc::enums::al_disc_cause::AlDiscCause;
use tetra_pdus::llc::enums::data_transfer_throughput::DataTransferThroughput;
use tetra_pdus::llc::enums::max_tl_sdu_length_n271::MaxTlSduLengthN271;
use tetra_pdus::llc::enums::setup_report::SetupReport;
use tetra_pdus::llc::pdus::al_ack::{AckLength, AcknowledgementBlock, AlAckAlRnr, AlAckAlRnrKind, SR};
use tetra_pdus::llc::pdus::al_data::{AlDataAlFinal, AlDataVariant};
use tetra_pdus::llc::pdus::al_disc::AlDisc;
use tetra_pdus::llc::pdus::al_reconnect::AlReconnect;
use tetra_pdus::llc::enums::reconnect_report::ReconnectReport;
use tetra_pdus::llc::pdus::al_setup::AlSetup;
use tetra_saps::sapmsg::{SapMsg, SapMsgInner};
use tetra_saps::tla::{TlaTlDataIndAl, TlaTlDataReqAl};
use tetra_saps::tma::TmaUnitdataInd;

const CARRIER: u16 = 1521;
const SSI: u32 = 1234567;
const LINK_ID: u32 = 0;
const ENDPOINT_ID: u32 = 0;
const N261: u8 = 0;

/// Default test address.
fn test_addr() -> TetraAddress {
    TetraAddress::new(SSI, SsiType::Issi)
}

/// Default `AlLinkKey` matching `test_addr()`, `LINK_ID`, `ENDPOINT_ID`, `N261`.
fn test_key() -> AlLinkKey {
    AlLinkKey::from_prim(test_addr(), LINK_ID, ENDPOINT_ID, N261)
}

/// Build a standard AL-SETUP PDU (Ack service, window=3, SDU=256B).
fn make_setup_pdu(report: SetupReport) -> AlSetup {
    AlSetup {
        advanced_link_service: AdvancedLinkService::Ack,
        advanced_link_number_n261: N261,
        max_tl_sdu_length_n271: MaxTlSduLengthN271::Bytes256,
        connection_width: 0,
        advanced_link_symmetry: AdvancedLinkSymmetry::Symmetric,
        n264_dqpsk_ts_uplink: None,
        n264_dqpsk_ts_downlink: None,
        data_transfer_throughput: DataTransferThroughput::NetworkDependentMin,
        tl_sdu_window_size_n272_n281: 3,
        max_retx_n273_or_repetition_n282: 3,
        max_segment_retx_n274: 3,
        setup_report: report,
        n_s: None,
        advanced_link_type: None,
        n272_n281_augmented: None,
        reserved: None,
    }
}

/// Build an Extended-AL AL-SETUP PDU (connection_width=1, window=3).
///
/// Used in tests that need the negotiated window to be honored (i.e. multiple
/// outstanding SDUs allowed).  In the default `make_setup_pdu`, `connection_width=0`
/// (Original AL) triggers the PD-5c-H15 serialization override that caps
/// `effective_tx_sdu_window` at 1 regardless of the negotiated window.
fn make_setup_pdu_extended(report: SetupReport) -> AlSetup {
    AlSetup {
        connection_width: 1,
        n264_dqpsk_ts_uplink: Some(1),
        n264_dqpsk_ts_downlink: None,
        ..make_setup_pdu(report)
    }
}

/// Wrap a serialised PDU `BitBuffer` in a `TmaUnitdataInd` and then a `SapMsg`
/// addressed LLC ← Umac on `TmaSap`.
fn make_tma_ind(pdu: BitBuffer) -> SapMsg {
    SapMsg {
        sap: Sap::TmaSap,
        src: TetraEntity::Umac,
        dest: TetraEntity::Llc,
        msg: SapMsgInner::TmaUnitdataInd(TmaUnitdataInd {
            carrier_num: CARRIER,
            pdu: Some(pdu),
            main_address: test_addr(),
            scrambling_code: 0,
            link_id: LINK_ID,
            endpoint_id: ENDPOINT_ID,
            new_endpoint_id: None,
            css_endpoint_id: None,
            air_interface_encryption: 0,
            chan_change_response_req: false,
            chan_change_handle: None,
            chan_info: None,
        }),
    }
}

/// Build a fresh `Llc` backed by the default BS test config.
fn make_llc() -> (Llc, MessageQueue) {
    let cfg = ComponentTest::get_default_test_config(StackMode::Bs);
    let shared_cfg = tetra_config::bluestation::SharedConfig::from_parts(cfg, None);
    let llc = Llc::new(shared_cfg);
    let queue = MessageQueue::new();
    (llc, queue)
}

/// Run one tick: tick_start(ts) → rx_prim(msg) → tick_end(ts).
fn one_tick(llc: &mut Llc, queue: &mut MessageQueue, ts: TdmaTime, msg: SapMsg) {
    llc.tick_start(queue, ts);
    llc.rx_prim(queue, msg);
    llc.tick_end(queue, ts);
}

/// Drain the queue into a Vec.
fn drain_queue(queue: &mut MessageQueue) -> Vec<SapMsg> {
    let mut msgs = Vec::new();
    while let Some(m) = queue.pop_front() {
        msgs.push(m);
    }
    msgs
}

/// Drain the queue and return the first `TlaTlDataIndAl` message found, if any.
fn take_data_ind_al(queue: &mut MessageQueue) -> Option<TlaTlDataIndAl> {
    while let Some(msg) = queue.pop_front() {
        if let SapMsgInner::TlaTlDataIndAl(ind) = msg.msg {
            return Some(ind);
        }
    }
    None
}

/// Build a TLA-DATA-Req-Al SapMsg for the test address.
fn make_tla_data_req_al_sap(sdu: Vec<u8>) -> SapMsg {
    SapMsg {
        sap: Sap::TlaSap,
        src: TetraEntity::Mle,
        dest: TetraEntity::Llc,
        msg: SapMsgInner::TlaTlDataReqAl(TlaTlDataReqAl {
            main_address: test_addr(),
            link_id: LINK_ID,
            endpoint_id: ENDPOINT_ID,
            al_link_number: N261,
            tl_sdu: BitBuffer::from_vec(sdu),
            subscriber_class: 0,
            fcs_flag: false,
            air_interface_encryption: None,
            req_handle: 0,
            tx_reporter: None,
        }),
    }
}

// ─── Test helpers ─────────────────────────────────────────────────────────────

/// Feed an AL-SETUP to `llc` and return the output messages.
fn send_setup_to_llc(llc: &mut Llc, queue: &mut MessageQueue, setup: AlSetup) -> Vec<SapMsg> {
    let mut buf = BitBuffer::new_autoexpand(64);
    setup.to_bitbuf(&mut buf);
    buf.seek(0);
    one_tick(llc, queue, TdmaTime::default(), make_tma_ind(buf));
    drain_queue(queue)
}

/// Establish a link by feeding a valid AL-SETUP.  Returns the outgoing reply messages.
fn establish_link(llc: &mut Llc, queue: &mut MessageQueue) -> Vec<SapMsg> {
    send_setup_to_llc(llc, queue, make_setup_pdu(SetupReport::ServiceDefinition))
}

// ─── Tests ────────────────────────────────────────────────────────────────────

/// AL-SETUP from peer: link must be created in `Established` and
/// an outgoing AL-SETUP (Success) must appear on the queue.
#[test]
fn al_setup_from_peer_transitions_to_established() {
    debug::setup_logging_verbose();
    let (mut llc, mut queue) = make_llc();

    let msgs = establish_link(&mut llc, &mut queue);

    // Link must now be Established.
    let link = llc.al_links.get(&test_key()).expect("link should exist");
    assert_eq!(link.phase, AlPhase::Established);

    // One outgoing AL-SETUP (Success reply) must be on the queue.
    assert_eq!(msgs.len(), 1);
    let SapMsgInner::TmaUnitdataReq(ref req) = msgs[0].msg else {
        panic!("expected TmaUnitdataReq");
    };
    assert_eq!(req.main_address.ssi, SSI);
}

/// AL-DISC from peer: link must be removed and a reply AL-DISC enqueued.
#[test]
fn al_disc_from_peer_removes_link() {
    debug::setup_logging_verbose();
    let (mut llc, mut queue) = make_llc();

    // Establish link first.
    establish_link(&mut llc, &mut queue);
    assert!(llc.al_links.contains_key(&test_key()));

    // Send AL-DISC.
    let disc = AlDisc {
        advanced_link_service: AdvancedLinkService::Ack,
        advanced_link_number_n261: N261,
        report: AlDiscCause::Success,
    };
    let mut buf = BitBuffer::new_autoexpand(16);
    disc.to_bitbuf(&mut buf);
    buf.seek(0);
    one_tick(&mut llc, &mut queue, TdmaTime::default(), make_tma_ind(buf));
    let msgs = drain_queue(&mut queue);

    // Link must be removed.
    assert!(!llc.al_links.contains_key(&test_key()), "link should be removed after DISC");

    // One outgoing AL-DISC reply.
    assert_eq!(msgs.len(), 1);
    assert!(matches!(msgs[0].msg, SapMsgInner::TmaUnitdataReq(_)));
}

/// Single-PDU SDU (AL-FINAL-AR): reassembly must complete, a
/// `TlaTlDataIndAl` must be emitted, and an AL-ACK with
/// `EntireSduReceived` must be enqueued.
#[test]
fn al_data_single_pdu_sdu_acked() {
    debug::setup_logging_verbose();
    let (mut llc, mut queue) = make_llc();
    establish_link(&mut llc, &mut queue);

    // Segment a short SDU into one PDU.
    let sdu = b"hello".to_vec();
    let cfg = SegmenterConfig {
        segment_payload_bits: 400,
        starting_n_s: 0,
        request_ack_on_final: true,
        request_ack_on_data: false,
    };
    let out = segment_sdu(&sdu, &cfg).expect("segmentation should succeed");
    assert_eq!(out.pdus.len(), 1, "short SDU should produce exactly one segment");

    let mut buf = BitBuffer::new_autoexpand(128);
    out.pdus[0].to_bitbuf(&mut buf);
    buf.seek(0);
    let pdu_len = buf.get_len();
    // Re-seek and wrap in TmaUnitdataInd.
    buf.seek(0);
    one_tick(&mut llc, &mut queue, TdmaTime::default(), make_tma_ind(buf));
    let _ = pdu_len; // used to confirm non-zero length
    let ind = take_data_ind_al(&mut queue).expect("TlaTlDataIndAl must be in queue");
    assert_eq!(ind.tl_sdu.into_bytes(), sdu, "reassembled SDU must match original");
    assert!(ind.fcs_ok, "fcs_ok must be true");
    let msgs = drain_queue(&mut queue);

    // One AL-ACK must be emitted.
    assert_eq!(msgs.len(), 1, "expected exactly one AL-ACK");
    let SapMsgInner::TmaUnitdataReq(ref req) = msgs[0].msg else {
        panic!("expected TmaUnitdataReq");
    };

    // Decode and verify the ACK.
    let mut ack_buf = req.pdu.clone();
    let type_bits = ack_buf.read_bits(4).expect("must read LLC type");
    // AlAckAlRnr PDU type = 11.
    assert_eq!(type_bits, 11, "outgoing PDU must be AL-ACK (type 11)");
    let pdu_len_bits = req.pdu.get_len();
    let mut pdu_copy = req.pdu.clone();
    pdu_copy.read_bits(4); // skip LLC type
    let ack = AlAckAlRnr::from_bitbuf(&mut pdu_copy, pdu_len_bits)
        .expect("AL-ACK must parse");
    assert_eq!(ack.kind, AlAckAlRnrKind::Ack);
    assert_eq!(ack.first_block.ack_length, AckLength::EntireSduReceived);
    assert_eq!(ack.first_block.n_r, 0, "N(R) must be 0 (the N(S) we sent)");
}

/// Multi-PDU reassembly: 3 AL-DATA/FINAL segments fed in order.
/// After the last (AL-FINAL-AR) the complete SDU must be delivered to TLA and
/// an AL-ACK must be emitted.
#[test]
fn al_data_multi_pdu_sdu_reassembles_and_acks() {
    debug::setup_logging_verbose();
    let (mut llc, mut queue) = make_llc();
    establish_link(&mut llc, &mut queue);

    // 200-byte SDU, 50-bit segments → 3+ segments.
    let sdu: Vec<u8> = (0u8..200).collect();
    let cfg = SegmenterConfig {
        segment_payload_bits: 50,
        starting_n_s: 0,
        request_ack_on_final: true,
        request_ack_on_data: false,
    };
    let out = segment_sdu(&sdu, &cfg).expect("segmentation ok");
    assert!(out.pdus.len() >= 3, "should produce multiple segments");

    let ts = TdmaTime::default();
    // Feed segments in order; collect all output messages.
    let mut all_msgs: Vec<SapMsg> = Vec::new();
    for pdu in &out.pdus {
        let mut buf = BitBuffer::new_autoexpand(128);
        pdu.to_bitbuf(&mut buf);
        buf.seek(0);
        llc.tick_start(&mut queue, ts);
        llc.rx_prim(&mut queue, make_tma_ind(buf));
        llc.tick_end(&mut queue, ts);
        all_msgs.extend(drain_queue(&mut queue));
    }

    let ind_al = all_msgs
        .iter()
        .find_map(|m| {
            if let SapMsgInner::TlaTlDataIndAl(ref ind) = m.msg {
                Some(ind.clone())
            } else {
                None
            }
        })
        .expect("TlaTlDataIndAl must be delivered after reassembly");
    assert_eq!(ind_al.tl_sdu.into_bytes(), sdu, "reassembled SDU must match original");

    // At least one AL-ACK emitted (the final segment triggers it).
    let acks: Vec<_> = all_msgs
        .iter()
        .filter(|m| matches!(&m.msg, SapMsgInner::TmaUnitdataReq(_)))
        .collect();
    assert!(!acks.is_empty(), "at least one AL-ACK must be emitted");
}

/// FCS corruption: encode the PDU to wire, flip a bit in the SDU data area
/// so the embedded FCS (last 32 bits of tl_sdu_segment) won't match CRC32.
/// LLC must emit an AL-ACK with `SduFcsFailure`.
#[test]
fn al_data_fcs_corruption_generates_repeat_ack() {
    debug::setup_logging_verbose();
    let (mut llc, mut queue) = make_llc();
    establish_link(&mut llc, &mut queue);

    let sdu = b"corrupt me".to_vec();
    let cfg = SegmenterConfig {
        segment_payload_bits: 400,
        starting_n_s: 0,
        request_ack_on_final: true,
        request_ack_on_data: false,
    };
    let out = segment_sdu(&sdu, &cfg).expect("segmentation ok");
    assert_eq!(out.pdus.len(), 1, "one segment");

    // Encode the PDU to a wire buffer.
    let mut wire = BitBuffer::new_autoexpand(256);
    out.pdus[0].to_bitbuf(&mut wire);

    // The wire format is:
    //   4b LLC type | 1b final | 1b AR | 3b N(S) | 8b S(S) | tl_sdu_segment | separate fcs
    //
    // For a single-segment 10-byte SDU:
    //   header = 17 bits
    //   tl_sdu_segment = 80 (SDU) + 32 (embedded FCS) = 112 bits  (bits 17..129)
    //   separate fcs field = 32 bits                               (bits 129..161)
    //
    // The reassembler validates against the embedded FCS (bits 97..129).
    // To trigger FcsFailure, corrupt one bit in the SDU data area (bits 17..97),
    // leaving the embedded FCS intact so CRC32(corrupted_sdu) ≠ embedded_fcs.
    wire.seek(20); // bit 20 is well inside the 10-byte SDU payload
    let original_bit = wire.read_bits(1).unwrap();
    wire.seek(20);
    wire.write_bits(1 - original_bit, 1); // flip the bit
    wire.seek(0);

    one_tick(&mut llc, &mut queue, TdmaTime::default(), make_tma_ind(wire));
    let msgs = drain_queue(&mut queue);

    // An AL-ACK with SduFcsFailure must appear.
    let ack_msg = msgs.iter().find(|m| matches!(&m.msg, SapMsgInner::TmaUnitdataReq(_)));
    assert!(ack_msg.is_some(), "an AL-ACK must be emitted on FCS failure");
    let SapMsgInner::TmaUnitdataReq(ref req) = ack_msg.unwrap().msg else { unreachable!() };
    let pdu_len = req.pdu.get_len();
    let mut pdu = req.pdu.clone();
    pdu.read_bits(4); // skip LLC type
    let ack = AlAckAlRnr::from_bitbuf(&mut pdu, pdu_len).expect("AL-ACK must parse");
    assert_eq!(ack.first_block.ack_length, AckLength::SduFcsFailure,
        "ACK length must be SduFcsFailure on FCS error");
}

/// TX window: a TLA-DATA-Req-Al puts an SDU in flight.
/// Feeding an incoming AL-ACK with `EntireSduReceived` must shrink the window.
#[test]
fn al_ack_from_peer_advances_window() {
    debug::setup_logging_verbose();
    let (mut llc, mut queue) = make_llc();
    establish_link(&mut llc, &mut queue);

    // Send one SDU via the real SAP.
    let sdu = b"window test".to_vec();
    llc.rx_prim(&mut queue, make_tla_data_req_al_sap(sdu));

    // Window has one outstanding SDU.
    {
        let link = llc.al_links.get(&test_key()).unwrap();
        assert_eq!(link.outstanding_sdus.len(), 1);
    }
    drain_queue(&mut queue); // discard encoded PDUs

    // Build an incoming AL-ACK with EntireSduReceived for N(S)=0.
    let ack_pdu = AlAckAlRnr {
        kind: AlAckAlRnrKind::Ack,
        first_block: AcknowledgementBlock {
            n_r: 0,
            ack_length: AckLength::EntireSduReceived,
            s_r: None,
            ack_bitmap: None,
        },
        other_blocks: vec![],
    };
    let mut buf = BitBuffer::new_autoexpand(64);
    ack_pdu.to_bitbuf(&mut buf);
    buf.seek(0);
    one_tick(&mut llc, &mut queue, TdmaTime::default(), make_tma_ind(buf));

    // Window must now be empty.
    let link = llc.al_links.get(&test_key()).unwrap();
    assert_eq!(link.outstanding_sdus.len(), 0, "ACK must remove the SDU from the window");
}

/// AL-RNR freezes TX: after receiving AL-RNR, any new TLA-DATA-Req-Al
/// succeeds but no NEW PDUs are submitted to UMAC
/// in `tick_end` until T.272 expires.
#[test]
fn al_rnr_from_peer_freezes_tx() {
    debug::setup_logging_verbose();
    let (mut llc, mut queue) = make_llc();
    establish_link(&mut llc, &mut queue);

    // Send first SDU; drain the initial PDUs.
    llc.rx_prim(&mut queue, make_tla_data_req_al_sap(b"first sdu".to_vec()));
    drain_queue(&mut queue);

    // Feed an AL-RNR (ACK + RNR flag).
    let rnr_pdu = AlAckAlRnr {
        kind: AlAckAlRnrKind::Rnr,
        first_block: AcknowledgementBlock {
            n_r: 0,
            ack_length: AckLength::EntireSduReceived,
            s_r: None,
            ack_bitmap: None,
        },
        other_blocks: vec![],
    };
    let mut buf = BitBuffer::new_autoexpand(64);
    rnr_pdu.to_bitbuf(&mut buf);
    buf.seek(0);
    one_tick(&mut llc, &mut queue, TdmaTime::default(), make_tma_ind(buf));
    drain_queue(&mut queue);

    // Verify link is now FlowControlled.
    assert_eq!(
        llc.al_links.get(&test_key()).unwrap().phase,
        AlPhase::FlowControlled,
        "link must be FlowControlled after RNR"
    );

    // Send a second SDU (buffered, not yet sent).
    llc.rx_prim(&mut queue, make_tla_data_req_al_sap(b"second sdu".to_vec()));
    {
        let link = llc.al_links.get(&test_key()).unwrap();
        assert_eq!(link.outstanding_sdus.len(), 1, "one SDU should be outstanding");
    }

    // Tick once without advancing T.272; no new PDUs for the second SDU should be emitted
    // because we are FlowControlled.
    llc.tick_start(&mut queue, TdmaTime::default());
    llc.tick_end(&mut queue, TdmaTime::default());
    let msgs = drain_queue(&mut queue);
    let umac_pdus: Vec<_> = msgs.iter()
        .filter(|m| matches!(&m.msg, SapMsgInner::TmaUnitdataReq(_)))
        .collect();
    assert!(umac_pdus.is_empty(), "no PDUs should be sent to UMAC while FlowControlled");

    // Advance time past T.272 — the link should unfreeze.
    let ticks_past_rnr = T272_RECEIVER_NOT_READY_FOR_RX_TIMER + 1;
    let ts_past = TdmaTime::default().add_timeslots(ticks_past_rnr as i32);
    llc.tick_start(&mut queue, ts_past);
    llc.tick_end(&mut queue, ts_past);
    let msgs = drain_queue(&mut queue);

    let phase = llc.al_links.get(&test_key()).unwrap().phase;
    assert_eq!(phase, AlPhase::Established, "link must be Established after T.272 expiry");

    // Now PDUs for the second SDU should be emitted.
    let umac_pdus: Vec<_> = msgs.iter()
        .filter(|m| matches!(&m.msg, SapMsgInner::TmaUnitdataReq(_)))
        .collect();
    assert!(!umac_pdus.is_empty(), "PDUs must be sent after T.272 expiry");
}

/// AL-SETUP timeout / retry / give-up:
/// After injecting a link into `SetupPending`, ticking past
/// T.261 × (N.262 + 1) times must return the link to `Idle`.
#[test]
fn al_setup_timeout_retries_then_gives_up() {
    debug::setup_logging_verbose();
    let (mut llc, mut queue) = make_llc();

    // Establish a link normally (peer sends SETUP → we send SETUP back).
    establish_link(&mut llc, &mut queue);
    drain_queue(&mut queue);

    // Simulate that we then sent a SETUP to the peer and are waiting for their reply.
    // We do this by manually putting the link into SetupPending with a setup timer.
    {
        let link = llc.al_links.get_mut(&test_key()).unwrap();
        link.phase = AlPhase::SetupPending;
        link.t_setup_start = Some(TdmaTime::default());
        link.setup_retries = 0;
        link.pending_setup_pdu = Some(make_setup_pdu(SetupReport::ServiceDefinition));
    }

    // N262 = 3 retries.  Each retry fires after T.261 ticks.
    // After 4 T.261 windows (3 retries + 1 give-up) the link must be Idle.
    // Use N262+2 intervals to be safe.
    let interval = T261_SETUP_WAITING_TIMER + 1;
    let mut t = TdmaTime::default();
    for _ in 0..(4 * interval) {
        t = t.add_timeslots(1);
        llc.tick_start(&mut queue, t);
        llc.tick_end(&mut queue, t);
        drain_queue(&mut queue);
    }

    let phase = llc.al_links.get(&test_key()).map(|l| l.phase);
    assert_eq!(
        phase,
        Some(AlPhase::Idle),
        "link must return to Idle after N.262 retries exhausted; got {:?}", phase
    );
}

/// AL-RECONNECT propose from peer: link stays Established and a reply
/// `Accept` AL-RECONNECT is enqueued.
#[test]
fn al_reconnect_propose_from_peer_accepted() {
    debug::setup_logging_verbose();
    let (mut llc, mut queue) = make_llc();
    establish_link(&mut llc, &mut queue);
    drain_queue(&mut queue);

    let reconnect = AlReconnect {
        advanced_link_service: AdvancedLinkService::Ack,
        advanced_link_number_n261: N261,
        reconnect_report: ReconnectReport::Propose,
    };
    let mut buf = BitBuffer::new_autoexpand(16);
    reconnect.to_bitbuf(&mut buf);
    buf.seek(0);
    one_tick(&mut llc, &mut queue, TdmaTime::default(), make_tma_ind(buf));
    let msgs = drain_queue(&mut queue);

    // Link must remain Established.
    assert_eq!(llc.al_links.get(&test_key()).unwrap().phase, AlPhase::Established);

    // One outgoing AL-RECONNECT Accept.
    assert_eq!(msgs.len(), 1);
    assert!(matches!(msgs[0].msg, SapMsgInner::TmaUnitdataReq(_)));
}

/// Sending an SDU when the window is full must buffer it in `pending_sdus`.
#[test]
fn al_sdu_window_full_buffers_in_pending() {
    debug::setup_logging_verbose();
    let (mut llc, mut queue) = make_llc();
    // Extended-AL peer so `effective_tx_sdu_window == tx_window == 3` (see PD-5c-H15).
    send_setup_to_llc(&mut llc, &mut queue, make_setup_pdu_extended(SetupReport::ServiceDefinition));
    drain_queue(&mut queue);

    // Flood the window (tx_window = 3).
    for i in 0..3u8 {
        llc.rx_prim(&mut queue, make_tla_data_req_al_sap(vec![i; 10]));
        drain_queue(&mut queue);
    }

    let link = llc.al_links.get(&test_key()).unwrap();
    assert_eq!(link.outstanding_sdus.len(), 3, "window must be full with 3 SDUs");

    llc.rx_prim(&mut queue, make_tla_data_req_al_sap(b"overflow".to_vec()));
    let link = llc.al_links.get(&test_key()).unwrap();
    assert_eq!(link.pending_sdus.len(), 1, "fourth SDU must be buffered in pending_sdus");
    assert_eq!(link.outstanding_sdus.len(), 3, "window must still have 3 SDUs");
}

// ─── PD-5c-H15: Original-AL peer forces max-1 outstanding SDU ────────────────
//
// The default `make_setup_pdu` uses `connection_width == 0` (Original AL,
// single-slot, non-DQPSK) which matches the observed Motorola MTP3550 peer
// that cannot handle pipelined SDUs.  The LLC must gate outstanding TX SDUs
// at 1 regardless of the negotiated window field.

/// With `connection_width == 0`, two rapid `TLA-DATA-Req-Al` primitives result
/// in exactly one outstanding SDU and one pending SDU.
#[test]
fn al_conn_w_zero_serializes_tx() {
    debug::setup_logging_verbose();
    let (mut llc, mut queue) = make_llc();
    establish_link(&mut llc, &mut queue); // connection_width=0, win=3
    drain_queue(&mut queue);

    // Sanity: the negotiated window is still 3 for spec-modulus arithmetic,
    // but the effective gate is 1.
    {
        let link = llc.al_links.get(&test_key()).expect("link must exist");
        assert_eq!(link.tx_window, 3);
        assert_eq!(link.effective_tx_sdu_window, 1,
            "connection_width == 0 must clamp effective window to 1");
    }

    llc.tick_start(&mut queue, TdmaTime::default());
    llc.rx_prim(&mut queue, make_tla_data_req_al_sap(b"first".to_vec()));
    llc.rx_prim(&mut queue, make_tla_data_req_al_sap(b"second".to_vec()));

    let link = llc.al_links.get(&test_key()).unwrap();
    assert_eq!(link.outstanding_sdus.len(), 1,
        "only one SDU may be outstanding under conn_w=0 serialization");
    assert_eq!(link.pending_sdus.len(), 1,
        "second SDU must be buffered in pending_sdus");
    assert_eq!(link.outstanding_sdus[0].n_s, 0);
}

/// After AL-ACK for N(S)=0, the pending second SDU is automatically promoted
/// to outstanding and segmentation begins.
#[test]
fn al_pending_sdu_drains_on_ack() {
    debug::setup_logging_verbose();
    let (mut llc, mut queue) = make_llc();
    establish_link(&mut llc, &mut queue);
    drain_queue(&mut queue);

    llc.rx_prim(&mut queue, make_tla_data_req_al_sap(b"first".to_vec()));
    llc.rx_prim(&mut queue, make_tla_data_req_al_sap(b"second".to_vec()));
    drain_queue(&mut queue);
    {
        let link = llc.al_links.get(&test_key()).unwrap();
        assert_eq!(link.outstanding_sdus.len(), 1);
        assert_eq!(link.pending_sdus.len(), 1);
    }

    // Peer ACKs N(S)=0 → outstanding retires; the drain loop in
    // submit_al_activity_to_umac (invoked from tick_end) must promote the
    // pending SDU to outstanding and emit its AL-DATA PDUs.
    let ack_pdu = AlAckAlRnr {
        kind: AlAckAlRnrKind::Ack,
        first_block: AcknowledgementBlock {
            n_r: 0,
            ack_length: AckLength::EntireSduReceived,
            s_r: None,
            ack_bitmap: None,
        },
        other_blocks: vec![],
    };
    let mut buf = BitBuffer::new_autoexpand(64);
    ack_pdu.to_bitbuf(&mut buf);
    buf.seek(0);
    one_tick(&mut llc, &mut queue, TdmaTime::default(), make_tma_ind(buf));
    let msgs = drain_queue(&mut queue);

    let link = llc.al_links.get(&test_key()).unwrap();
    assert_eq!(link.pending_sdus.len(), 0, "pending SDU must drain after ACK");
    assert_eq!(link.outstanding_sdus.len(), 1,
        "the promoted SDU now occupies the window (N(S)=1)");
    assert_eq!(link.outstanding_sdus[0].n_s, 1,
        "the second SDU inherits N(S)=1");

    let umac_pdus: Vec<_> = msgs.iter()
        .filter(|m| matches!(&m.msg, SapMsgInner::TmaUnitdataReq(_)))
        .collect();
    assert!(!umac_pdus.is_empty(),
        "AL-DATA PDUs for the promoted SDU must be emitted");
}

/// Regression: a single low-rate SDU still segments and completes as before —
/// the serialization gate must not change single-SDU behavior.
#[test]
fn al_single_sdu_unaffected_by_serialization_gate() {
    debug::setup_logging_verbose();
    let (mut llc, mut queue) = make_llc();
    establish_link(&mut llc, &mut queue);
    drain_queue(&mut queue);

    llc.rx_prim(&mut queue, make_tla_data_req_al_sap(b"just one".to_vec()));

    let link = llc.al_links.get(&test_key()).unwrap();
    assert_eq!(link.outstanding_sdus.len(), 1, "single SDU must be outstanding");
    assert_eq!(link.pending_sdus.len(), 0, "no pending");
    assert_eq!(link.outstanding_sdus[0].n_s, 0);

    let msgs = drain_queue(&mut queue);
    let umac_pdus: Vec<_> = msgs.iter()
        .filter(|m| matches!(&m.msg, SapMsgInner::TmaUnitdataReq(_)))
        .collect();
    assert!(!umac_pdus.is_empty(), "AL-DATA PDUs must be emitted immediately");
}

/// With `connection_width == 1` (Extended AL), the negotiated window is honored
/// and multiple SDUs may be outstanding concurrently.
#[test]
fn al_conn_w_one_honors_negotiated_window() {
    debug::setup_logging_verbose();
    let (mut llc, mut queue) = make_llc();
    send_setup_to_llc(&mut llc, &mut queue, make_setup_pdu_extended(SetupReport::ServiceDefinition));
    drain_queue(&mut queue);

    {
        let link = llc.al_links.get(&test_key()).unwrap();
        assert_eq!(link.tx_window, 3);
        assert_eq!(link.effective_tx_sdu_window, 3,
            "connection_width == 1 must preserve the negotiated window");
    }

    for i in 0..3u8 {
        llc.rx_prim(&mut queue, make_tla_data_req_al_sap(vec![i; 10]));
    }

    let link = llc.al_links.get(&test_key()).unwrap();
    assert_eq!(link.outstanding_sdus.len(), 3,
        "extended-AL peer must allow all three SDUs concurrent");
    assert_eq!(link.pending_sdus.len(), 0, "nothing buffered");
}

/// Sending an SDU to an unknown AL link through the SAP must be a silent drop.
#[test]
fn al_sdu_for_unknown_link_is_silently_dropped() {
    debug::setup_logging_verbose();
    let (mut llc, mut queue) = make_llc();
    llc.rx_prim(&mut queue, make_tla_data_req_al_sap(b"no link".to_vec()));
    let msgs = drain_queue(&mut queue);
    assert!(msgs.is_empty(), "SAP request for unknown link must produce no output");
    assert!(llc.al_links.is_empty(), "no link should have been created");
}

/// Smoke test: SDU enters via TLA-DATA-Req-Al, AL-DATA/FINAL-AR PDUs appear on
/// TmaSap outbound, a synthetic peer AL-ACK is fed back, and the window advances.
#[test]
fn al_data_req_via_sap_completes_full_tx_cycle() {
    debug::setup_logging_verbose();
    let (mut llc, mut queue) = make_llc();
    establish_link(&mut llc, &mut queue);
    drain_queue(&mut queue);

    llc.rx_prim(&mut queue, make_tla_data_req_al_sap(b"full cycle sdu".to_vec()));

    llc.tick_start(&mut queue, TdmaTime::default());
    llc.tick_end(&mut queue, TdmaTime::default());
    let msgs = drain_queue(&mut queue);

    let umac_pdus: Vec<_> = msgs
        .iter()
        .filter(|m| matches!(&m.msg, SapMsgInner::TmaUnitdataReq(_)))
        .collect();
    assert!(!umac_pdus.is_empty(), "AL-DATA PDUs must reach UMAC after SAP request");

    {
        let link = llc.al_links.get(&test_key()).unwrap();
        assert_eq!(link.outstanding_sdus.len(), 1, "one SDU must be in the TX window");
        assert_eq!(link.outstanding_sdus[0].n_s, 0, "first SDU must have N(S)=0");
    }

    let ack_pdu = AlAckAlRnr {
        kind: AlAckAlRnrKind::Ack,
        first_block: AcknowledgementBlock {
            n_r: 0,
            ack_length: AckLength::EntireSduReceived,
            s_r: None,
            ack_bitmap: None,
        },
        other_blocks: vec![],
    };
    let mut ack_buf = BitBuffer::new_autoexpand(64);
    ack_pdu.to_bitbuf(&mut ack_buf);
    ack_buf.seek(0);
    one_tick(&mut llc, &mut queue, TdmaTime::default(), make_tma_ind(ack_buf));

    let link = llc.al_links.get(&test_key()).unwrap();
    assert_eq!(link.outstanding_sdus.len(), 0, "ACK must advance the TX window");
}

/// AL-5: The LLC state machine must honour a non-default `tx_window` from
/// `AdvancedLinkConfig`.
///
/// Strategy: create a link via the reconnect-fallback path (no prior SETUP PDU),
/// which uses config defaults for all negotiated parameters including `tx_window`.
/// With `tx_window = 2`, the window fills after exactly 2 outstanding SDUs, and a
/// third TLA-DATA-Req-Al goes to `pending_sdus`.  With `tx_window = 3` the same
/// two sends leave room for one more.
#[test]
fn al_tx_window_config_respected() {
    debug::setup_logging_verbose();

    // -- Build Llc with tx_window = 2 -----------------------------------------
    let mut cfg_w2 = ComponentTest::get_default_test_config(StackMode::Bs);
    cfg_w2.llc.advanced_link.tx_window = 2;
    let sc_w2 = tetra_config::bluestation::SharedConfig::from_parts(cfg_w2, None);
    let mut llc_w2 = Llc::new(sc_w2);
    let mut q_w2 = MessageQueue::new();

    // -- Build Llc with default tx_window = 3 ---------------------------------
    let (mut llc_w3, mut q_w3) = make_llc();

    // -- Trigger reconnect-fallback to create a link using config defaults -----
    //
    // When AL-RECONNECT Propose arrives for an unknown link, the LLC creates a
    // minimal AlLink using the config defaults (reconnect-fallback path).
    let reconnect = AlReconnect {
        advanced_link_service: AdvancedLinkService::Ack,
        advanced_link_number_n261: N261,
        reconnect_report: ReconnectReport::Propose,
    };
    let mut buf = BitBuffer::new_autoexpand(16);
    reconnect.to_bitbuf(&mut buf);
    buf.seek(0);

    // Feed reconnect to both LLCs (one_tick = tick_start + rx_prim + tick_end).
    let reconnect_msg_w2 = make_tma_ind(buf.clone());
    one_tick(&mut llc_w2, &mut q_w2, TdmaTime::default(), reconnect_msg_w2);
    drain_queue(&mut q_w2);

    buf.seek(0);
    let reconnect_msg_w3 = make_tma_ind(buf);
    one_tick(&mut llc_w3, &mut q_w3, TdmaTime::default(), reconnect_msg_w3);
    drain_queue(&mut q_w3);

    // Verify link tx_window was set from config.
    let key = test_key();
    assert_eq!(llc_w2.al_links.get(&key).expect("w2 link").tx_window, 2);
    assert_eq!(llc_w3.al_links.get(&key).expect("w3 link").tx_window, 3);

    // -- Enqueue SDUs via TLA-DATA-Req-Al (public SAP interface) --------------
    //
    // Perform tick_start once, then rx_prim multiple times without tick_end so
    // that submit_al_activity_to_umac does not flush pending SDUs between sends.
    let ts = TdmaTime::default();
    let sdu = b"AL-5 test payload".to_vec();

    llc_w2.tick_start(&mut q_w2, ts);
    llc_w2.rx_prim(&mut q_w2, make_tla_data_req_al_sap(sdu.clone()));  // SDU 1
    llc_w2.rx_prim(&mut q_w2, make_tla_data_req_al_sap(sdu.clone()));  // SDU 2
    // After 2 enqueues the window (size=2) is full; a 3rd goes to pending.
    llc_w2.rx_prim(&mut q_w2, make_tla_data_req_al_sap(sdu.clone()));  // SDU 3

    {
        let link = llc_w2.al_links.get(&key).unwrap();
        assert_eq!(link.outstanding_sdus.len(), 2, "w2: exactly 2 outstanding (= tx_window)");
        assert_eq!(link.pending_sdus.len(), 1,     "w2: 3rd SDU buffered in pending");
    }

    llc_w3.tick_start(&mut q_w3, ts);
    llc_w3.rx_prim(&mut q_w3, make_tla_data_req_al_sap(sdu.clone()));  // SDU 1
    llc_w3.rx_prim(&mut q_w3, make_tla_data_req_al_sap(sdu.clone()));  // SDU 2
    // With tx_window=3 there is still room; 3rd SDU goes directly to outstanding.
    llc_w3.rx_prim(&mut q_w3, make_tla_data_req_al_sap(sdu.clone()));  // SDU 3

    {
        let link = llc_w3.al_links.get(&key).unwrap();
        assert_eq!(link.outstanding_sdus.len(), 3, "w3: 3 outstanding (window not full)");
        assert_eq!(link.pending_sdus.len(), 0,     "w3: nothing buffered");
    }
}

// ─── AL-ACK S(R) correctness (PD-5c-H8) ──────────────────────────────────────
//
// Regression tests for the bug where the BS was sending
// `SR::RestOfSduReceived` (wire value 250) in cumulative AL-ACKs while an SDU
// was only partially reassembled.  That sentinel means "peer has the whole
// SDU" and desynchronised the MS's AL peer.  The correct value in the
// `NeedMore` state is `SR::OldestNotReceived(next_expected_ss)` — the next
// segment S(S) the receiver needs.

/// Build a single AL-DATA / AL-DATA-AR fragment (non-FINAL) with a fixed
/// 8-bit payload — enough to satisfy the wire encoder without being part
/// of a real SDU.
fn make_al_data_fragment(variant: AlDataVariant, n_s: u8, s_s: u8) -> BitBuffer {
    let pdu = AlDataAlFinal {
        variant,
        n_s,
        s_s,
        tl_sdu_segment: BitBuffer::from_bitstr("10101010"),
        fcs: None,
    };
    let mut buf = BitBuffer::new_autoexpand(64);
    pdu.to_bitbuf(&mut buf);
    buf.seek(0);
    buf
}

/// Decode the AL-ACK PDU carried by the first `TmaUnitdataReq` in `msgs`.
fn extract_al_ack(msgs: &[SapMsg]) -> AlAckAlRnr {
    let req = msgs
        .iter()
        .find_map(|m| match &m.msg {
            SapMsgInner::TmaUnitdataReq(r) => Some(r),
            _ => None,
        })
        .expect("at least one TmaUnitdataReq must be present");
    let pdu_len = req.pdu.get_len();
    let mut pdu = req.pdu.clone();
    let ty = pdu.read_bits(4).expect("LLC type bits");
    assert_eq!(ty, 11, "expected AlAckAlRnr (type 11), got {}", ty);
    AlAckAlRnr::from_bitbuf(&mut pdu, pdu_len).expect("AL-ACK must parse")
}

/// Three non-AR AL-DATA fragments (no FINAL) arriving contiguously must
/// produce a deferred AL-ACK at `tick_end` whose S(R) is
/// `OldestNotReceived(3)` — **not** `RestOfSduReceived`.
///
/// Regression test for PD-5c-H8.  Prior to the fix, the BS emitted
/// `SR::RestOfSduReceived` (wire value 250), telling the MS's AL peer that
/// the whole SDU had been received while it was still being reassembled;
/// the MS then re-SETUPed the link.
#[test]
fn al_data_non_ar_contiguous_window_acks_next_expected() {
    debug::setup_logging_verbose();
    let (mut llc, mut queue) = make_llc();
    establish_link(&mut llc, &mut queue);
    drain_queue(&mut queue);

    let ts = TdmaTime::default();
    // Feed three non-AR AL-DATA fragments (variant = Data → no FINAL, no AR).
    for s_s in 0..3u8 {
        let buf = make_al_data_fragment(AlDataVariant::Data, /* n_s */ 0, s_s);
        llc.tick_start(&mut queue, ts);
        llc.rx_prim(&mut queue, make_tma_ind(buf));
        // Do NOT tick_end between segments — we want the deferred flush to
        // observe all three at once.
    }
    // Between-rx no ACK yet: this is the deferred-ACK path.
    let ts_flush = TdmaTime::default();
    llc.tick_end(&mut queue, ts_flush);
    let msgs = drain_queue(&mut queue);

    let ack = extract_al_ack(&msgs);
    assert_eq!(ack.kind, AlAckAlRnrKind::Ack);
    assert_eq!(ack.first_block.n_r, 0, "ACK must reference N(S)=0");
    assert_eq!(
        ack.first_block.ack_length,
        AckLength::Segments(1),
        "cumulative ACK uses Segments(1) shape"
    );
    assert_eq!(
        ack.first_block.s_r,
        Some(SR::OldestNotReceived(3)),
        "S(R) must be the next expected S(S) (=3), not RestOfSduReceived"
    );
    assert_ne!(
        ack.first_block.s_r,
        Some(SR::RestOfSduReceived),
        "S(R) must never be RestOfSduReceived while reassembly is incomplete"
    );
}

/// An AL-DATA-**AR** fragment (ACK requested) must produce an *immediate*
/// AL-ACK in the same tick with the correct cumulative S(R) — the next
/// expected S(S), not `RestOfSduReceived`.
#[test]
fn al_data_ar_immediate_ack_uses_next_expected_sr() {
    debug::setup_logging_verbose();
    let (mut llc, mut queue) = make_llc();
    establish_link(&mut llc, &mut queue);
    drain_queue(&mut queue);

    let ts = TdmaTime::default();
    // Single AL-DATA-AR fragment, s_s=0, no FINAL.
    let buf = make_al_data_fragment(AlDataVariant::DataAr, /* n_s */ 0, 0);
    llc.tick_start(&mut queue, ts);
    llc.rx_prim(&mut queue, make_tma_ind(buf));
    // rx_prim's on_al_data must have already enqueued the immediate ACK; no
    // tick_end needed to observe it.
    let msgs = drain_queue(&mut queue);

    let ack = extract_al_ack(&msgs);
    assert_eq!(ack.kind, AlAckAlRnrKind::Ack);
    assert_eq!(ack.first_block.n_r, 0);
    assert_eq!(ack.first_block.ack_length, AckLength::Segments(1));
    assert_eq!(
        ack.first_block.s_r,
        Some(SR::OldestNotReceived(1)),
        "after receiving s_s=0 only, next expected is 1"
    );
}

/// A gap in the received segment sequence must be reflected in the ACK's
/// S(R) field.  Feeding s_s=0 and s_s=2 (skipping 1) must yield an ACK
/// whose S(R) is `OldestNotReceived(1)`.
#[test]
fn al_data_gap_acks_oldest_missing() {
    debug::setup_logging_verbose();
    let (mut llc, mut queue) = make_llc();
    establish_link(&mut llc, &mut queue);
    drain_queue(&mut queue);

    let ts = TdmaTime::default();
    llc.tick_start(&mut queue, ts);
    llc.rx_prim(
        &mut queue,
        make_tma_ind(make_al_data_fragment(AlDataVariant::Data, 0, 0)),
    );
    llc.rx_prim(
        &mut queue,
        make_tma_ind(make_al_data_fragment(AlDataVariant::Data, 0, 2)),
    );
    llc.tick_end(&mut queue, ts);
    let msgs = drain_queue(&mut queue);

    let ack = extract_al_ack(&msgs);
    assert_eq!(ack.first_block.n_r, 0);
    assert_eq!(ack.first_block.ack_length, AckLength::Segments(1));
    assert_eq!(
        ack.first_block.s_r,
        Some(SR::OldestNotReceived(1)),
        "with gap at s_s=1, ACK must ask for s_s=1"
    );
}

// ─── PD-5c-H10: reassembler reset on AL-SETUP / AL-RECONNECT ─────────────────
//
// After the peer re-establishes the AL link (via AL-SETUP with any non-Success
// report, or via AL-RECONNECT Propose), it starts sending fresh AL-DATA
// fragments from s_s=0. Any stale reassembler slot from the prior session
// would otherwise reject the fresh fragment as `ConflictingRetransmission`.
// These tests exercise both code paths in `llc_bs_ms.rs::{on_al_setup,
// on_al_reconnect}` and lock in the regression path where natural
// reassembler advancement (without a reset event) still works.

/// Feed one AL-DATA fragment at (n_s=0, s_s=0) to prime the reassembler with
/// a stale slot that would collide with any fresh session's first segment.
fn prime_stale_reassembler(llc: &mut Llc, queue: &mut MessageQueue, ts: TdmaTime) {
    llc.tick_start(queue, ts);
    llc.rx_prim(
        queue,
        make_tma_ind(make_al_data_fragment(AlDataVariant::Data, 0, 0)),
    );
    llc.tick_end(queue, ts);
    drain_queue(queue);
    assert!(
        llc.al_links
            .get(&test_key())
            .expect("link must exist")
            .reassemblers
            .contains_key(&0),
        "prime step should have created a reassembler at N(S)=0",
    );
}

/// Feed a complete single-PDU SDU segmented from `starting_n_s=0` and return
/// the resulting TLA-DATA-Ind and drained messages. Panics if reassembly
/// dropped the fragment (i.e. `ConflictingRetransmission` fired).
fn feed_fresh_single_pdu_sdu(
    llc: &mut Llc,
    queue: &mut MessageQueue,
    ts: TdmaTime,
    sdu: &[u8],
) -> (TlaTlDataIndAl, Vec<SapMsg>) {
    let cfg = SegmenterConfig {
        segment_payload_bits: 400,
        starting_n_s: 0,
        request_ack_on_final: true,
        request_ack_on_data: false,
    };
    let out = segment_sdu(sdu, &cfg).expect("segmentation should succeed");
    assert_eq!(out.pdus.len(), 1, "test SDU should fit in one segment");

    let mut buf = BitBuffer::new_autoexpand(128);
    out.pdus[0].to_bitbuf(&mut buf);
    buf.seek(0);
    llc.tick_start(queue, ts);
    llc.rx_prim(queue, make_tma_ind(buf));
    llc.tick_end(queue, ts);

    let ind = take_data_ind_al(queue).unwrap_or_else(|| {
        panic!(
            "TlaTlDataIndAl must be delivered after fresh s_s=0; \
             stale reassembler was not cleared"
        )
    });
    let msgs = drain_queue(queue);
    (ind, msgs)
}

/// After the peer re-sends AL-SETUP with a non-Success report (Reset,
/// ServiceDefinition, ServiceChange), our reassembler slots from the previous
/// session must be discarded so the peer's fresh s_s=0 does not collide.
#[test]
fn al_setup_reset_clears_stale_reassembler() {
    debug::setup_logging_verbose();
    let (mut llc, mut queue) = make_llc();
    establish_link(&mut llc, &mut queue);
    drain_queue(&mut queue);

    let ts = TdmaTime::default();
    prime_stale_reassembler(&mut llc, &mut queue, ts);

    // Peer re-establishes with AL-SETUP report=Reset.
    let reset_msgs = send_setup_to_llc(&mut llc, &mut queue, make_setup_pdu(SetupReport::Reset));
    assert_eq!(
        llc.al_links.get(&test_key()).unwrap().phase,
        AlPhase::Established,
        "link must remain Established after peer re-setup",
    );
    assert!(
        llc.al_links
            .get(&test_key())
            .unwrap()
            .reassemblers
            .is_empty(),
        "reassemblers must be cleared on AL-SETUP re-establishment",
    );
    // The AL-SETUP echo (Success) is expected on the wire.
    assert!(
        reset_msgs
            .iter()
            .any(|m| matches!(m.msg, SapMsgInner::TmaUnitdataReq(_))),
        "AL-SETUP echo must be emitted",
    );

    // Fresh single-PDU SDU from s_s=0 must now reassemble cleanly.
    let sdu = b"post-reset".to_vec();
    let (ind, _) = feed_fresh_single_pdu_sdu(&mut llc, &mut queue, ts, &sdu);
    assert_eq!(ind.tl_sdu.into_bytes(), sdu);
    assert!(ind.fcs_ok);
}

/// After the peer sends AL-RECONNECT with report=Propose, our reassembler
/// slots must be cleared so the peer's proposed fresh N(S) window starts
/// from a clean slate.
#[test]
fn al_reconnect_propose_clears_stale_reassembler() {
    debug::setup_logging_verbose();
    let (mut llc, mut queue) = make_llc();
    establish_link(&mut llc, &mut queue);
    drain_queue(&mut queue);

    let ts = TdmaTime::default();
    prime_stale_reassembler(&mut llc, &mut queue, ts);

    // Peer proposes reconnect.
    let reconnect = AlReconnect {
        advanced_link_service: AdvancedLinkService::Ack,
        advanced_link_number_n261: N261,
        reconnect_report: ReconnectReport::Propose,
    };
    let mut buf = BitBuffer::new_autoexpand(16);
    reconnect.to_bitbuf(&mut buf);
    buf.seek(0);
    one_tick(&mut llc, &mut queue, ts, make_tma_ind(buf));
    let msgs = drain_queue(&mut queue);

    assert_eq!(
        llc.al_links.get(&test_key()).unwrap().phase,
        AlPhase::Established,
        "link must remain Established after AL-RECONNECT accept",
    );
    assert!(
        llc.al_links
            .get(&test_key())
            .unwrap()
            .reassemblers
            .is_empty(),
        "reassemblers must be cleared on AL-RECONNECT(Propose) accept",
    );
    // Accept reply on the wire.
    assert!(
        msgs.iter()
            .any(|m| matches!(m.msg, SapMsgInner::TmaUnitdataReq(_))),
        "AL-RECONNECT Accept must be emitted",
    );

    // Fresh single-PDU SDU from s_s=0 must now reassemble cleanly.
    let sdu = b"post-reconnect".to_vec();
    let (ind, _) = feed_fresh_single_pdu_sdu(&mut llc, &mut queue, ts, &sdu);
    assert_eq!(ind.tl_sdu.into_bytes(), sdu);
    assert!(ind.fcs_ok);
}

/// Regression: after a normal SDU completes on N(S)=0, a subsequent AL-DATA
/// at N(S)=0, s_s=0 must reassemble via natural reassembler advancement
/// (map entry removed on completion), without needing a reset event. This
/// guards against an over-eager reset from breaking the happy path.
#[test]
fn al_data_after_completed_sdu_still_works_via_natural_advancement() {
    debug::setup_logging_verbose();
    let (mut llc, mut queue) = make_llc();
    establish_link(&mut llc, &mut queue);
    drain_queue(&mut queue);

    let ts = TdmaTime::default();
    let sdu1 = b"first".to_vec();
    let (ind1, _) = feed_fresh_single_pdu_sdu(&mut llc, &mut queue, ts, &sdu1);
    assert_eq!(ind1.tl_sdu.into_bytes(), sdu1);
    assert!(
        llc.al_links
            .get(&test_key())
            .unwrap()
            .reassemblers
            .is_empty(),
        "completed SDU must remove its reassembler slot",
    );

    // Second SDU, again from s_s=0 (peer's next N(S) after ack, which in
    // practice would advance mod tx_window+1 but the test focuses on the
    // simplest same-slot repeat; a real MS would send different N(S)).
    let sdu2 = b"second".to_vec();
    let (ind2, _) = feed_fresh_single_pdu_sdu(&mut llc, &mut queue, ts, &sdu2);
    assert_eq!(ind2.tl_sdu.into_bytes(), sdu2);
}





// ─── PD-5c-H16: AL TX retx timer must use T.252, not the BL T.251 ────────────
//
// The AL retransmission path in `submit_al_activity_to_umac` must wait
// T252_ACK_WAITING_TIMER (Annex A.1, 9 signalling frames ≈ 510 ms) before
// declaring an outstanding SDU due for retransmission or drop. Using
// T251_SENDER_RETRY_TIMER (4 frames ≈ 226 ms — the Basic Link retry timer)
// drops downlink SDUs before the MS's AL-ACK physically reaches us on a
// granted PDCH.

/// Build an AL-SETUP with a specific `max_retx_n273_or_repetition_n282`
/// (mapped into `link.max_sdu_retx`). Uses the default (Ack, window=3, 256B).
fn make_setup_pdu_with_retx(report: SetupReport, max_retx: u8) -> AlSetup {
    AlSetup {
        max_retx_n273_or_repetition_n282: max_retx,
        ..make_setup_pdu(report)
    }
}

/// Establish a link with a peer-negotiated `max_retx`, drain the setup reply,
/// then push one TLA-DATA-Req-Al through and drain the resulting AL-DATA
/// segments. Returns the `TdmaTime` at which the SDU's initial send was
/// stamped (== `TdmaTime::default()`).
fn establish_and_tx_one_sdu(
    llc: &mut Llc,
    queue: &mut MessageQueue,
    max_retx: u8,
    sdu: Vec<u8>,
) -> TdmaTime {
    send_setup_to_llc(llc, queue, make_setup_pdu_with_retx(SetupReport::ServiceDefinition, max_retx));
    drain_queue(queue);
    // Initial send: enqueue_al_sdu stamps sent_at = self.dltime, which is
    // TdmaTime::default() until tick_start is called with a later value.
    llc.rx_prim(queue, make_tla_data_req_al_sap(sdu));
    drain_queue(queue);
    let link = llc.al_links.get(&test_key()).expect("link exists");
    assert_eq!(link.outstanding_sdus.len(), 1, "one SDU must be outstanding after tx");
    assert_eq!(link.max_sdu_retx, max_retx, "negotiated max_sdu_retx must be honored");
    TdmaTime::default()
}

/// Advance dltime to `t` and run one empty tick (no rx). Returns any messages
/// pushed by `submit_al_activity_to_umac`.
fn tick_at(llc: &mut Llc, queue: &mut MessageQueue, t: TdmaTime) -> Vec<SapMsg> {
    llc.tick_start(queue, t);
    llc.tick_end(queue, t);
    drain_queue(queue)
}

/// After T.251 elapses (≈ 226 ms) but before T.252 (≈ 510 ms), the AL TX path
/// must NOT retransmit or drop the SDU. This is the core regression: the old
/// code would fire at T.251 and (with `max_retx=0`) drop the SDU before the
/// ACK could physically arrive.
#[test]
fn al_tx_no_retx_before_t252() {
    debug::setup_logging_verbose();
    let (mut llc, mut queue) = make_llc();
    let t0 = establish_and_tx_one_sdu(&mut llc, &mut queue, /* max_retx */ 3, b"h16 keepalive".to_vec());

    // Advance just past T.251 but well before T.252.
    let t1 = t0.add_timeslots(T251_SENDER_RETRY_TIMER as i32 + 1);
    assert!((T251_SENDER_RETRY_TIMER + 1) < T252_ACK_WAITING_TIMER,
        "test invariant: T.251+1 must be strictly less than T.252");
    let msgs = tick_at(&mut llc, &mut queue, t1);

    // SDU must still be outstanding and no AL-DATA retransmission emitted.
    let link = llc.al_links.get(&test_key()).expect("link exists");
    assert_eq!(link.outstanding_sdus.len(), 1, "SDU must still be outstanding before T.252");
    assert_eq!(link.outstanding_sdus[0].retx_count, 0, "no retransmission before T.252");
    let umac_pdus: Vec<_> = msgs.iter()
        .filter(|m| matches!(&m.msg, SapMsgInner::TmaUnitdataReq(_)))
        .collect();
    assert!(umac_pdus.is_empty(),
        "no TmaUnitdataReq must be emitted before T.252 elapses (got {})", umac_pdus.len());
}

/// After T.252 elapses with `max_sdu_retx >= 1`, the SDU must be retransmitted
/// (not dropped). This confirms the timer path itself still functions.
#[test]
fn al_tx_retransmits_after_t252() {
    debug::setup_logging_verbose();
    let (mut llc, mut queue) = make_llc();
    let t0 = establish_and_tx_one_sdu(&mut llc, &mut queue, /* max_retx */ 3, b"h16 retx".to_vec());

    // Advance past T.252 by one timeslot.
    let t1 = t0.add_timeslots(T252_ACK_WAITING_TIMER as i32 + 1);
    let msgs = tick_at(&mut llc, &mut queue, t1);

    let link = llc.al_links.get(&test_key()).expect("link exists");
    assert_eq!(link.outstanding_sdus.len(), 1, "SDU must still be outstanding (retxed, not dropped)");
    assert!(link.outstanding_sdus[0].retx_count >= 1,
        "retx_count must advance after T.252 elapses; got {}", link.outstanding_sdus[0].retx_count);
    let umac_pdus: Vec<_> = msgs.iter()
        .filter(|m| matches!(&m.msg, SapMsgInner::TmaUnitdataReq(_)))
        .collect();
    assert!(!umac_pdus.is_empty(),
        "a TmaUnitdataReq retransmission must be emitted after T.252 elapses");
}

/// With `max_sdu_retx = 0` (peer negotiated "no retransmissions"), the SDU is
/// given one full T.252 ACK window and only then dropped. This is the
/// hardware-observed configuration on Motorola MTP3550.
#[test]
fn al_tx_sdu_dropped_after_t252_when_max_retx_zero() {
    debug::setup_logging_verbose();
    let (mut llc, mut queue) = make_llc();
    let t0 = establish_and_tx_one_sdu(&mut llc, &mut queue, /* max_retx */ 0, b"h16 drop".to_vec());

    // Ticking before T.252 must not drop.
    let t_pre = t0.add_timeslots(T251_SENDER_RETRY_TIMER as i32 + 1);
    tick_at(&mut llc, &mut queue, t_pre);
    let link = llc.al_links.get(&test_key()).expect("link exists");
    assert_eq!(link.outstanding_sdus.len(), 1, "SDU must survive until T.252 has elapsed");

    // Ticking past T.252 fires the drop (retx_count=0 >= max_sdu_retx=0).
    let t_post = t0.add_timeslots(T252_ACK_WAITING_TIMER as i32 + 1);
    tick_at(&mut llc, &mut queue, t_post);
    let link = llc.al_links.get(&test_key()).expect("link exists");
    assert_eq!(link.outstanding_sdus.len(), 0,
        "SDU must be dropped once T.252 elapsed and max_sdu_retx is exhausted");
}

/// An AL-ACK that arrives within the T.252 window (e.g. ~ 300 ms after emit,
/// which is well after the old T.251 threshold but still comfortably inside
/// T.252) must clear the outstanding SDU without any drop.
#[test]
fn al_ack_within_t252_prevents_drop() {
    debug::setup_logging_verbose();
    let (mut llc, mut queue) = make_llc();
    let t0 = establish_and_tx_one_sdu(&mut llc, &mut queue, /* max_retx */ 0, b"h16 late ack".to_vec());

    // Advance dltime past T.251 (would have been the drop point pre-H16) but
    // strictly less than T.252 — this is where hardware traces show the ACK
    // physically arriving.
    let t_ack = t0.add_timeslots(T251_SENDER_RETRY_TIMER as i32 + 2);
    assert!((T251_SENDER_RETRY_TIMER + 2) < T252_ACK_WAITING_TIMER,
        "test invariant: T.251+2 must still be inside the T.252 window");

    // Feed an AL-ACK EntireSduReceived for N(S)=0 at t_ack.
    let ack_pdu = AlAckAlRnr {
        kind: AlAckAlRnrKind::Ack,
        first_block: AcknowledgementBlock {
            n_r: 0,
            ack_length: AckLength::EntireSduReceived,
            s_r: None,
            ack_bitmap: None,
        },
        other_blocks: vec![],
    };
    let mut buf = BitBuffer::new_autoexpand(64);
    ack_pdu.to_bitbuf(&mut buf);
    buf.seek(0);
    one_tick(&mut llc, &mut queue, t_ack, make_tma_ind(buf));

    let link = llc.al_links.get(&test_key()).expect("link exists");
    assert_eq!(link.outstanding_sdus.len(), 0,
        "AL-ACK arriving inside the T.252 window must clear the SDU without a drop");
}
