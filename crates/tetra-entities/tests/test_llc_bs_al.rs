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
use tetra_pdus::llc::consts::timers::{T261_SETUP_WAITING_TIMER, T272_RECEIVER_NOT_READY_FOR_RX_TIMER};
use tetra_pdus::llc::enums::advanced_link_service::AdvancedLinkService;
use tetra_pdus::llc::enums::advanced_link_symmetry::AdvancedLinkSymmetry;
use tetra_pdus::llc::enums::al_disc_cause::AlDiscCause;
use tetra_pdus::llc::enums::data_transfer_throughput::DataTransferThroughput;
use tetra_pdus::llc::enums::max_tl_sdu_length_n271::MaxTlSduLengthN271;
use tetra_pdus::llc::enums::setup_report::SetupReport;
use tetra_pdus::llc::pdus::al_ack::{AckLength, AcknowledgementBlock, AlAckAlRnr, AlAckAlRnrKind};
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
    establish_link(&mut llc, &mut queue);
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
