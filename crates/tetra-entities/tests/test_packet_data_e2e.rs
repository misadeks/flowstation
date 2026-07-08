/// PD-8: Full packet-data lifecycle integration test.
///
/// Wires SNDCP + MLE + LLC + UMAC together and drives a complete PDP-context
/// lifecycle: ACTIVATE, uplink SN-UNITDATA, downlink SN-UNITDATA (PDCH grant),
/// Ready-timer expiry → Standby, SN-PAGE-REQUEST / RESPONSE round-trip, and
/// DEACTIVATE – all verified through the full SapMsg chain.
mod common;

use std::net::Ipv4Addr;

use tetra_config::bluestation::{CfgPacketData, SharedConfig, StackMode};
use tetra_core::tetra_entities::TetraEntity;
use tetra_core::{BitBuffer, Layer2Service, Sap, SsiType, TdmaTime, TetraAddress, debug};
use tetra_entities::llc::llc_bs_ms::Llc;
use tetra_entities::mle::mle_bs::MleBs;
use tetra_entities::sndcp::sndcp_bs::{GatewayDownlink, Sndcp};
use tetra_entities::umac::umac_bs::UmacBs;
use tetra_entities::{MessageQueue, TetraEntityTrait};
use tetra_pdus::sndcp::enums::deactivation_type::DeactivationType;
use tetra_pdus::sndcp::enums::pdms_type::PdmsType;
use tetra_pdus::sndcp::enums::tia::Tia;
use tetra_pdus::sndcp::fields::nsapi::Nsapi;
use tetra_pdus::sndcp::pdus::{
    ActivatePdpContextDemand, DeactivatePdpContextDemand, PageResponse, SnPdu, Unitdata,
};
use tetra_pdus::umac::pdus::mac_resource::MacResource;
use tetra_saps::ltpd::{LtpdMleUnitdataInd, LtpdMleUnitdataReq};
use tetra_saps::sapmsg::{SapMsg, SapMsgInner};
use tetra_saps::tla::{TlaTlDataReqBl, TlaTlUnitdataReqBl};
use tetra_saps::tma::TmaUnitdataReq;
use tetra_saps::tmv::TmvUnitdataReqSlots;

// ── Constants ──────────────────────────────────────────────────────────────────

const TEST_ISSI: u32 = 1234;
const TEST_NSAPI: u8 = 3;
/// Slightly more than READY_TIMER_SLOTS (706 slots ≈ 10 s); enough to expire it.
const PAST_READY_TIMER: i32 = 750;

// ── TestStack ─────────────────────────────────────────────────────────────────

/// Manually-wired entity stack with a shared MessageQueue.
///
/// All entities share `queue`. `lmac_sink` captures messages whose destination
/// is not one of the four wired entities (i.e. messages destined for LMAC from
/// UMAC's scheduler, carrying TMV slot descriptors and MAC PDUs).
struct TestStack {
    sndcp: Sndcp,
    mle: MleBs,
    llc: Llc,
    umac: UmacBs,
    queue: MessageQueue,
    lmac_sink: Vec<SapMsg>,
    now: TdmaTime,
}

impl TestStack {
    fn new() -> Self {
        let mut config = common::ComponentTest::get_default_test_config(StackMode::Bs);
        // Enable packet data so UMAC initialises the PDCH allocator.
        config.packet_data = CfgPacketData { enabled: true, ..CfgPacketData::default() };
        let shared = SharedConfig::from_parts(config, None);

        let sndcp = Sndcp::new(shared.clone());
        let mle = MleBs::new(shared.clone());
        let llc = Llc::new(shared.clone());
        let umac = UmacBs::new(shared, None);
        // packet_data.enabled=true already sets this, but the helper is idempotent.
        // Keep for clarity in case someone runs with a different config path.

        TestStack {
            sndcp,
            mle,
            llc,
            umac,
            queue: MessageQueue::new(),
            lmac_sink: Vec::new(),
            now: TdmaTime { h: 0, m: 1, f: 1, t: 1 },
        }
    }
}

/// Route one message to the correct entity; unknown destinations go to lmac_sink.
fn route_msg(stack: &mut TestStack, msg: SapMsg) {
    match msg.dest {
        TetraEntity::Sndcp => stack.sndcp.rx_prim(&mut stack.queue, msg),
        TetraEntity::Mle => stack.mle.rx_prim(&mut stack.queue, msg),
        TetraEntity::Llc => stack.llc.rx_prim(&mut stack.queue, msg),
        TetraEntity::Umac => stack.umac.rx_prim(&mut stack.queue, msg),
        _ => stack.lmac_sink.push(msg),
    }
}

/// Drain the queue until empty, collecting and returning clones of every message seen.
fn drain_collecting(stack: &mut TestStack) -> Vec<SapMsg> {
    let mut all = Vec::new();
    loop {
        let msg = match stack.queue.pop_front() {
            Some(m) => m,
            None => break,
        };
        all.push(msg.clone());
        route_msg(stack, msg);
    }
    all
}

/// Execute one full tick cycle (tick_start → drain → tick_end{LLC,UMAC,others} → drain each),
/// advance `stack.now` by one timeslot, and return all messages that flew through the queue.
///
/// Mirrors the exact ordering in `MessageRouter::tick_start` / `tick_end`.
fn tick_stack(stack: &mut TestStack) -> Vec<SapMsg> {
    let now = stack.now;
    let mut all = Vec::new();

    // 1. tick_start on all entities (sets dltime, initialises UMAC scheduler).
    stack.sndcp.tick_start(&mut stack.queue, now);
    stack.mle.tick_start(&mut stack.queue, now);
    stack.llc.tick_start(&mut stack.queue, now);
    stack.umac.tick_start(&mut stack.queue, now);

    // 2. Deliver all messages queued during tick_start (or injected before this call).
    all.extend(drain_collecting(stack));

    // 3. LLC tick_end (flushes deferred BL-ACKs) → deliver.
    stack.llc.tick_end(&mut stack.queue, now);
    all.extend(drain_collecting(stack));

    // 4. UMAC tick_end (finalises scheduling, may emit MAC-RESOURCE to LMAC) → deliver.
    stack.umac.tick_end(&mut stack.queue, now);
    all.extend(drain_collecting(stack));

    // 5. Remaining entities' tick_end (SNDCP runs ready/standby timers here) → deliver.
    stack.sndcp.tick_end(&mut stack.queue, now);
    stack.mle.tick_end(&mut stack.queue, now);
    all.extend(drain_collecting(stack));

    // 6. Advance TDMA time by one timeslot (mirrors MessageRouter).
    stack.now = stack.now.add_timeslots(1);

    all
}

// ── PDU-builder helpers ───────────────────────────────────────────────────────

/// Prepend the 3-bit SNDCP protocol discriminator (0b100) to `sn_pdu_bits`.
/// The resulting buffer is positioned at 0 and is suitable for `LtpdMleUnitdataInd.sdu`.
fn with_discriminator(sn_pdu_bits: &BitBuffer) -> BitBuffer {
    let mut sdu = BitBuffer::new_autoexpand(sn_pdu_bits.get_len() + 3);
    sdu.write_bits(0b100, 3);
    let mut src = sn_pdu_bits.clone();
    src.seek(0);
    let len = src.get_len();
    sdu.copy_bits(&mut src, len);
    sdu.seek(0);
    sdu
}

/// Build an SN-ACTIVATE PDP CONTEXT DEMAND (dynamic ATID, no CHAP, no APN) with
/// the SNDCP protocol discriminator prepended.
fn build_activate_demand_pdu(nsapi: u8) -> BitBuffer {
    let demand = ActivatePdpContextDemand {
        sndcp_version: 0,
        nsapi: Nsapi(nsapi),
        atid: 1, // dynamic ATID
        ip_address: None,
        pdms_type: PdmsType::Standard,
        pcomp_negotiation: 0,
        vj_slots: None,
        snei: None,
        apn: None,
        pco: None,
    };
    let mut buf = BitBuffer::new_autoexpand(256);
    demand.to_bitbuf(&mut buf).expect("encode demand");
    buf.seek(0);
    with_discriminator(&buf)
}

/// Build an SN-UNITDATA PDU with the SNDCP protocol discriminator prepended.
fn build_unitdata_pdu(nsapi: u8, payload: &[u8]) -> BitBuffer {
    let ud = Unitdata { nsapi: Nsapi(nsapi), pdu_priority: 0, payload: payload.to_vec() };
    let mut buf = BitBuffer::new_autoexpand(256);
    ud.to_bitbuf(&mut buf).expect("encode unitdata");
    buf.seek(0);
    with_discriminator(&buf)
}

/// Build an SN-DEACTIVATE PDP CONTEXT DEMAND with the SNDCP protocol discriminator prepended.
fn build_deactivate_demand_pdu(nsapi: u8) -> BitBuffer {
    let deact = DeactivatePdpContextDemand {
        deactivation_type: DeactivationType::Normal,
        nsapi: Nsapi(nsapi),
        snei: None,
    };
    let mut buf = BitBuffer::new_autoexpand(64);
    deact.to_bitbuf(&mut buf).expect("encode deactivate demand");
    buf.seek(0);
    with_discriminator(&buf)
}

/// Build an SN-PAGE RESPONSE with the SNDCP protocol discriminator prepended.
fn build_page_response_pdu(nsapi: u8) -> BitBuffer {
    let pr = PageResponse { nsapi: Nsapi(nsapi) };
    let mut buf = BitBuffer::new_autoexpand(32);
    pr.to_bitbuf(&mut buf).expect("encode page response");
    buf.seek(0);
    with_discriminator(&buf)
}

// ── Uplink injection helper ───────────────────────────────────────────────────

/// Wrap a pre-built SDU (with discriminator) in a `LtpdMleUnitdataInd` as if
/// MLE forwarded it upward from the air interface to SNDCP.
fn make_uplink_ind(sdu: BitBuffer, issi: u32) -> SapMsg {
    SapMsg {
        sap: Sap::TlpdSap,
        src: TetraEntity::Mle,
        dest: TetraEntity::Sndcp,
        msg: SapMsgInner::LtpdMleUnitdataInd(LtpdMleUnitdataInd {
            sdu,
            endpoint_id: 0,
            link_id: 0,
            received_tetra_address: TetraAddress::new(issi, SsiType::Issi),
            chan_change_resp_req: false,
            chan_change_handle: None,
        }),
    }
}

// ── Message-chain finder helpers ──────────────────────────────────────────────

/// Find the first `LtpdMleUnitdataReq` (SNDCP → MLE) in a message list.
fn find_ltpd_unitdata_req(msgs: &[SapMsg]) -> Option<LtpdMleUnitdataReq> {
    msgs.iter().find_map(|m| {
        if m.src == TetraEntity::Sndcp {
            if let SapMsgInner::LtpdMleUnitdataReq(req) = &m.msg {
                return Some(req.clone());
            }
        }
        None
    })
}

/// Find the first `TlaTlDataReqBl` (MLE → LLC, Acknowledged path) in a message list.
fn find_tla_data_req_bl(msgs: &[SapMsg]) -> Option<TlaTlDataReqBl> {
    msgs.iter().find_map(|m| {
        if let SapMsgInner::TlaTlDataReqBl(req) = &m.msg {
            Some(req.clone())
        } else {
            None
        }
    })
}

/// Find the first `TlaTlUnitdataReqBl` (MLE → LLC, Unacknowledged path) in a message list.
fn find_tla_unitdata_req_bl(msgs: &[SapMsg]) -> Option<TlaTlUnitdataReqBl> {
    msgs.iter().find_map(|m| {
        if let SapMsgInner::TlaTlUnitdataReqBl(req) = &m.msg {
            Some(req.clone())
        } else {
            None
        }
    })
}

/// Find the first `TmaUnitdataReq` (LLC → UMAC) in a message list.
fn find_tma_unitdata_req(msgs: &[SapMsg]) -> Option<TmaUnitdataReq> {
    msgs.iter().find_map(|m| {
        if m.src == TetraEntity::Llc {
            if let SapMsgInner::TmaUnitdataReq(req) = &m.msg {
                return Some(req.clone());
            }
        }
        None
    })
}

/// Decode a downlink SN-PDU from `LtpdMleUnitdataReq.sdu` (no discriminator prefix).
fn decode_dl_from_sdu(sdu: &BitBuffer) -> SnPdu {
    let mut buf = sdu.clone();
    buf.seek(0);
    SnPdu::from_bitbuf_dl(&mut buf).expect("decode_dl from sdu")
}

/// Decode a downlink SN-PDU from a TLA `tl_sdu` (skip the 3-bit SNDCP discriminator).
fn decode_dl_from_tl_sdu(tl_sdu: &BitBuffer) -> SnPdu {
    let mut buf = tl_sdu.clone();
    buf.seek(0);
    buf.read_bits(3).expect("skip discriminator");
    SnPdu::from_bitbuf_dl(&mut buf).expect("decode_dl from tl_sdu")
}

/// Scan LMAC sink messages for the first MAC-RESOURCE addressed to `issi` that
/// carries a `chan_alloc_element` (PDCH channel grant).
fn find_pdch_mac_resource(sink_msgs: &[SapMsg], issi: u32) -> Option<MacResource> {
    for msg in sink_msgs {
        let slots: Vec<_> = match &msg.msg {
            SapMsgInner::TmvUnitdataReq(slot) => vec![slot.clone()],
            SapMsgInner::TmvUnitdataReqSlots(TmvUnitdataReqSlots { slots }) => slots.clone(),
            _ => continue,
        };
        for slot in slots {
            for block in [&slot.blk1, &slot.blk2].into_iter().flatten() {
                let mut buf = block.mac_block.clone();
                buf.seek(0);
                // A SCH/F block may carry multiple concatenated MAC-PDUs.
                // Iterate through them using length_ind (total PDU bytes) to advance.
                loop {
                    if buf.get_len_remaining() < 2 {
                        break;
                    }
                    let start_pos = buf.get_pos();
                    let mut peek = buf.clone();
                    // MAC-RESOURCE has mac_pdu_type = 0 (2-bit field at the start).
                    if peek.read_field(2, "t").map(|t| t != 0).unwrap_or(true) {
                        break; // Non-zero mac_pdu_type; no more MAC-RESOURCEs here.
                    }
                    let Ok(pdu) = MacResource::from_bitbuf(&mut buf) else {
                        break;
                    };
                    if pdu.addr.map(|a| a.ssi) == Some(issi) && pdu.chan_alloc_element.is_some() {
                        return Some(pdu);
                    }
                    // Advance past this PDU (length_ind gives total bytes).
                    let pdu_end = start_pos + pdu.length_ind as usize * 8;
                    if pdu_end == 0 || pdu_end > buf.get_len() {
                        break;
                    }
                    buf.seek(pdu_end);
                }
            }
        }
    }
    None
}

// ── Phase 1–3 + 7 test ────────────────────────────────────────────────────────

/// ACTIVATE → UPLINK → DOWNLINK → DEACTIVATE: the core packet-data lifecycle.
///
/// Proves that PD-1..PD-7 compose correctly end-to-end:
/// • SNDCP allocates an IPv4, emits ACCEPT via LtpdMleUnitdataReq
/// • MLE wraps it in TlaTlDataReqBl (Acknowledged)
/// • LLC wraps it in TmaUnitdataReq for UMAC
/// • Uplink UNITDATA surfaces to the gateway queue
/// • Downlink IP triggers PDCH reservation + MAC-RESOURCE grant
/// • DEACTIVATE frees the IP back to the pool
#[test]
fn activate_uplink_downlink_deactivate() {
    debug::setup_logging_verbose();

    let mut stack = TestStack::new();

    // ── Phase 1: MS sends SN-ACTIVATE PDP CONTEXT DEMAND ─────────────────────
    //
    // Inject DEMAND as if MLE forwarded it upward to SNDCP.
    stack.queue.push_back(make_uplink_ind(
        build_activate_demand_pdu(TEST_NSAPI),
        TEST_ISSI,
    ));
    let phase1_msgs = tick_stack(&mut stack);

    // [P1-A] SNDCP emitted LtpdMleUnitdataReq (Acknowledged, !packet_data_flag).
    let ltpd_req = find_ltpd_unitdata_req(&phase1_msgs)
        .expect("P1: SNDCP must emit LtpdMleUnitdataReq for ACCEPT");
    assert_eq!(ltpd_req.layer2service, Layer2Service::Acknowledged,
        "P1: ACTIVATE ACCEPT must use Acknowledged service");
    assert!(!ltpd_req.packet_data_flag, "P1: ACCEPT is not IP data");
    assert_eq!(ltpd_req.main_address.ssi, TEST_ISSI, "P1: ACCEPT addressed to MS ISSI");

    // [P1-B] Decode the ACCEPT PDU from the LtpdMleUnitdataReq SDU.
    let accept = match decode_dl_from_sdu(&ltpd_req.sdu) {
        SnPdu::ActivatePdpContextAccept(a) => a,
        other => panic!("P1: expected ACCEPT PDU, got {other:?}"),
    };
    assert_eq!(accept.nsapi.0, TEST_NSAPI, "P1: ACCEPT NSAPI must match demand");
    assert_eq!(accept.tia, Tia::Ipv4Dynamic, "P1: dynamic ATID must produce Ipv4Dynamic TIA");
    let allocated_ip = accept.ip4_address.expect("P1: ACCEPT must carry an IPv4 address");
    assert!(
        allocated_ip >= Ipv4Addr::new(192, 168, 100, 2)
            && allocated_ip <= Ipv4Addr::new(192, 168, 100, 254),
        "P1: allocated IP {allocated_ip} must be within default pool 192.168.100.2–.254"
    );

    // [P1-C] MLE forwarded the ACCEPT as TlaTlDataReqBl to LLC.
    let tla_data = find_tla_data_req_bl(&phase1_msgs)
        .expect("P1: MLE must produce TlaTlDataReqBl for Acknowledged ACCEPT");
    assert_eq!(tla_data.main_address.ssi, TEST_ISSI, "P1: TlaTlDataReqBl SSI");
    // Verify the tl_sdu starts with the SNDCP discriminator (0b100) then decodes the ACCEPT.
    let accept_from_tl = match decode_dl_from_tl_sdu(&tla_data.tl_sdu) {
        SnPdu::ActivatePdpContextAccept(a) => a,
        other => panic!("P1: tl_sdu must decode to ACCEPT, got {other:?}"),
    };
    assert_eq!(accept_from_tl.nsapi.0, TEST_NSAPI, "P1: tl_sdu ACCEPT NSAPI");
    assert_eq!(accept_from_tl.ip4_address, Some(allocated_ip),
        "P1: tl_sdu ACCEPT IP must match what SNDCP allocated");

    // [P1-D] LLC forwarded a TmaUnitdataReq to UMAC.
    let tma_accept = find_tma_unitdata_req(&phase1_msgs)
        .expect("P1: LLC must produce TmaUnitdataReq for UMAC");
    assert_eq!(tma_accept.main_address.ssi, TEST_ISSI, "P1: TmaUnitdataReq SSI");
    assert!(!tma_accept.packet_data_flag, "P1: ACCEPT is signalling, not packet data");

    // ── Phase 2: MS sends uplink SN-UNITDATA ─────────────────────────────────
    //
    // A plausible ICMP echo request payload (28 bytes of mock IP/ICMP).
    let icmp_echo_request = {
        let mut p = vec![
            // Minimal IPv4 header (20 bytes)
            0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00,
            0x40, 0x01, 0x00, 0x00,
            0xc0, 0xa8, 0x64, 0x02, // src: 192.168.100.2
            0xc0, 0xa8, 0x64, 0x01, // dst: 192.168.100.1
            // ICMP echo request (8 bytes)
            0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01,
        ];
        p.truncate(28);
        p
    };

    stack.queue.push_back(make_uplink_ind(
        build_unitdata_pdu(TEST_NSAPI, &icmp_echo_request),
        TEST_ISSI,
    ));
    let phase2_msgs = tick_stack(&mut stack);

    // [P2-A] Uplink UNITDATA must NOT cause SNDCP to emit any downlink SapMsgs.
    //        SNDCP queues it for the gateway; the downlink chain is NOT involved.
    assert!(
        find_ltpd_unitdata_req(&phase2_msgs).is_none(),
        "P2: uplink UNITDATA must NOT produce any LtpdMleUnitdataReq (downlink), got: {phase2_msgs:?}"
    );

    // [P2-B] The payload surfaced in SNDCP's gateway-facing uplink queue.
    let ul = stack.sndcp.uplink_ip_queue.pop_front()
        .expect("P2: SNDCP must push uplink UNITDATA to gateway queue");
    assert_eq!(ul.main_address.ssi, TEST_ISSI, "P2: gateway uplink SSI");
    assert_eq!(ul.nsapi, TEST_NSAPI, "P2: gateway uplink NSAPI");
    assert_eq!(ul.payload, icmp_echo_request, "P2: gateway uplink payload");
    assert!(stack.sndcp.uplink_ip_queue.is_empty(), "P2: no leftover uplink items");

    // ── Phase 3: Gateway sends ICMP echo reply downlink ───────────────────────
    //
    // Simulate pd-gateway echoing the reply back via feed_downlink_ip.
    let icmp_echo_reply = {
        let mut p = vec![
            0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00,
            0x40, 0x01, 0x00, 0x00,
            0xc0, 0xa8, 0x64, 0x01, // src: 192.168.100.1
            0xc0, 0xa8, 0x64, 0x02, // dst: 192.168.100.2
            // ICMP echo reply
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01,
        ];
        p.truncate(28);
        p
    };

    // feed_downlink_ip pushes LtpdMleUnitdataReq directly to the queue.
    stack.sndcp.feed_downlink_ip(
        &mut stack.queue,
        GatewayDownlink { dest_ipv4: allocated_ip, payload: icmp_echo_reply.clone() },
    );
    let phase3_msgs = tick_stack(&mut stack);

    // [P3-A] SNDCP emitted LtpdMleUnitdataReq (Unacknowledged, packet_data_flag=true).
    let ltpd_ud_req = find_ltpd_unitdata_req(&phase3_msgs)
        .expect("P3: SNDCP must emit LtpdMleUnitdataReq for downlink UNITDATA");
    assert_eq!(ltpd_ud_req.layer2service, Layer2Service::Unacknowledged,
        "P3: SN-UNITDATA uses Unacknowledged service");
    assert!(ltpd_ud_req.packet_data_flag, "P3: packet_data_flag must be set for IP data");

    // [P3-B] MLE forwarded it as TlaTlUnitdataReqBl with packet_data_flag preserved.
    let tla_ud = find_tla_unitdata_req_bl(&phase3_msgs)
        .expect("P3: MLE must produce TlaTlUnitdataReqBl for Unacknowledged UNITDATA");
    assert!(tla_ud.packet_data_flag, "P3: packet_data_flag must pass through MLE");
    // Verify the tl_sdu carries the echo reply.
    let ud_from_tl = match decode_dl_from_tl_sdu(&tla_ud.tl_sdu) {
        SnPdu::Unitdata(u) => u,
        other => panic!("P3: tl_sdu must decode to SN-UNITDATA, got {other:?}"),
    };
    assert_eq!(ud_from_tl.nsapi.0, TEST_NSAPI, "P3: UNITDATA NSAPI");
    assert_eq!(ud_from_tl.payload, icmp_echo_reply, "P3: UNITDATA payload = echo reply");

    // [P3-C] LLC forwarded a TmaUnitdataReq with packet_data_flag=true to UMAC.
    let tma_ud = find_tma_unitdata_req(&phase3_msgs)
        .expect("P3: LLC must produce TmaUnitdataReq for UMAC");
    assert!(tma_ud.packet_data_flag, "P3: packet_data_flag must pass through LLC");
    assert_eq!(tma_ud.main_address.ssi, TEST_ISSI, "P3: TmaUnitdataReq PDCH SSI");

    // [P3-D] UMAC created a PDCH reservation for ISSI 1234.
    assert!(
        stack.umac.pdch_allocator().reservations.contains_key(&TEST_ISSI),
        "P3: UMAC must have a PDCH reservation for ISSI {TEST_ISSI}"
    );
    assert!(
        stack.umac.pdch_allocator().current_timeslot.is_some(),
        "P3: UMAC must have a current PDCH timeslot assigned"
    );

    // [P3-E] UMAC eventually emits a MAC-RESOURCE with channel-allocation for ISSI 1234.
    //        Run additional ticks until the scheduler has had a chance to do so.
    for _ in 0..10 {
        if find_pdch_mac_resource(&stack.lmac_sink, TEST_ISSI).is_some() {
            break;
        }
        tick_stack(&mut stack);
    }
    let mac_res = find_pdch_mac_resource(&stack.lmac_sink, TEST_ISSI)
        .expect("P3: UMAC must emit MAC-RESOURCE with ChanAllocElement for ISSI {TEST_ISSI}");
    assert!(
        mac_res.chan_alloc_element.is_some(),
        "P3: MAC-RESOURCE must carry chan_alloc_element (channel_allocation_flag=1)"
    );

    // ── Phase 7: MS sends SN-DEACTIVATE PDP CONTEXT DEMAND ───────────────────
    //
    // Run deactivate here (before standby phases) to confirm the basic lifecycle.
    // The standby / paging lifecycle is tested in `standby_paging_lifecycle`.
    stack.queue.push_back(make_uplink_ind(
        build_deactivate_demand_pdu(TEST_NSAPI),
        TEST_ISSI,
    ));
    let phase7_msgs = tick_stack(&mut stack);

    // [P7-A] SNDCP emitted SN-DEACTIVATE PDP CONTEXT ACCEPT.
    let ltpd_deact = find_ltpd_unitdata_req(&phase7_msgs)
        .expect("P7: SNDCP must emit LtpdMleUnitdataReq for DEACTIVATE ACCEPT");
    assert_eq!(ltpd_deact.layer2service, Layer2Service::Acknowledged,
        "P7: DEACTIVATE ACCEPT uses Acknowledged service");
    match decode_dl_from_sdu(&ltpd_deact.sdu) {
        SnPdu::DeactivatePdpContextAccept(a) => {
            assert_eq!(a.nsapi.0, TEST_NSAPI, "P7: DEACTIVATE ACCEPT NSAPI");
        }
        other => panic!("P7: expected DEACTIVATE ACCEPT, got {other:?}"),
    }

    // [P7-B] MLE forwarded the DEACTIVATE ACCEPT to LLC.
    // NOTE: LLC uses strict per-SSI ordered acknowledged-mode (ETSI §22.3.2.3). Since
    // the ACTIVATE ACCEPT BL-DATA has not yet been ACKed by ISSI 1234 (no BL-ACK
    // injected in this test), LLC correctly holds the DEACTIVATE ACCEPT in its
    // outbound queue until the first frame is ACKed. This is correct protocol behavior,
    // NOT a bug. We assert only up to the MLE level here; LLC→UMAC is covered by
    // phase 1's P1-D assertion (which does receive its TmaUnitdataReq immediately,
    // as no prior ISSI-1234 frame was in-flight then).
    assert!(
        find_tla_data_req_bl(&phase7_msgs).is_some(),
        "P7: MLE must produce TlaTlDataReqBl for the DEACTIVATE ACCEPT"
    );
    // LLC DEACTIVATE ACCEPT delivery to UMAC is deferred (blocked by pending ACTIVATE
    // ACCEPT ACK); not asserted here.

    // [P7-C] IPv4 returned to pool: request the same IP statically → must succeed.
    let static_demand = ActivatePdpContextDemand {
        sndcp_version: 0,
        nsapi: Nsapi(TEST_NSAPI),
        atid: 0, // static ATID
        ip_address: Some(allocated_ip),
        pdms_type: PdmsType::Standard,
        pcomp_negotiation: 0,
        vj_slots: None,
        snei: None,
        apn: None,
        pco: None,
    };
    let mut encode_buf = BitBuffer::new_autoexpand(256);
    static_demand.to_bitbuf(&mut encode_buf).unwrap();
    encode_buf.seek(0);
    let sdu2 = with_discriminator(&encode_buf);

    // NOTE: spec ambiguous — chosen behaviour: use a different SSI (9999) so no
    // "context already active" collision with the freshly-deactivated SSI 1234.
    stack.queue.push_back(make_uplink_ind(sdu2, 9999));
    let phase7b_msgs = tick_stack(&mut stack);
    let ltpd_realloc = find_ltpd_unitdata_req(&phase7b_msgs)
        .expect("P7-C: static re-alloc of freed IP must succeed");
    match decode_dl_from_sdu(&ltpd_realloc.sdu) {
        SnPdu::ActivatePdpContextAccept(a) => {
            assert_eq!(a.ip4_address, Some(allocated_ip),
                "P7-C: static re-alloc must yield the same IP (proves it was freed)");
        }
        other => panic!("P7-C: expected ACCEPT for freed IP, got {other:?}"),
    }
}

// ── Phase 4–6 test ─────────────────────────────────────────────────────────────

/// Standby / paging lifecycle (phases 4, 5, 6 from the PD-8 spec).
///
/// Proves Ready-timer expiry, SN-PAGE-REQUEST emission, and that the queued
/// downlink payload is drained as SN-UNITDATA after SN-PAGE-RESPONSE.
#[test]
fn standby_paging_lifecycle() {
    debug::setup_logging_verbose();

    let mut stack = TestStack::new();

    // Bring up a PDP context first (mirrors phase 1 of the lifecycle test).
    stack.queue.push_back(make_uplink_ind(
        build_activate_demand_pdu(TEST_NSAPI),
        TEST_ISSI,
    ));
    let setup_msgs = tick_stack(&mut stack);
    let ltpd_accept = find_ltpd_unitdata_req(&setup_msgs)
        .expect("setup: ACTIVATE must produce ACCEPT");
    let allocated_ip = match decode_dl_from_sdu(&ltpd_accept.sdu) {
        SnPdu::ActivatePdpContextAccept(a) => a.ip4_address.expect("IP in ACCEPT"),
        other => panic!("setup: expected ACCEPT, got {other:?}"),
    };

    // ── Phase 4: Advance past the ready timer → context → Standby ────────────
    //
    // READY_TIMER_SLOTS ≈ 706 timeslots (10 s). Run PAST_READY_TIMER (750) real
    // ticks so the UMAC scheduler's sequential-timeslot invariant is satisfied.
    // SNDCP's tick_end calls run_timers() on every tick; the transition fires
    // once the elapsed time since last activity exceeds READY_TIMER_SLOTS.
    for _ in 0..PAST_READY_TIMER {
        tick_stack(&mut stack);
    }

    // [P4] Black-box proof of Standby: feeding downlink IP must produce a
    //      SN-PAGE REQUEST (not SN-UNITDATA).
    let page_payload = vec![0xCA, 0xFE, 0xBA, 0xBE];
    stack.sndcp.feed_downlink_ip(
        &mut stack.queue,
        GatewayDownlink { dest_ipv4: allocated_ip, payload: page_payload.clone() },
    );
    let phase4_msgs = tick_stack(&mut stack);

    let page_req_ltpd = find_ltpd_unitdata_req(&phase4_msgs)
        .expect("P4: Standby must trigger SN-PAGE REQUEST via LtpdMleUnitdataReq");
    assert_eq!(page_req_ltpd.layer2service, Layer2Service::Acknowledged,
        "P4: PAGE REQUEST uses Acknowledged service");
    assert!(!page_req_ltpd.packet_data_flag, "P4: PAGE REQUEST is not IP data");
    match decode_dl_from_sdu(&page_req_ltpd.sdu) {
        SnPdu::PageRequest(pr) => {
            assert_eq!(pr.nsapi.0, TEST_NSAPI, "P4: PAGE REQUEST NSAPI");
        }
        other => panic!("P4: expected PAGE REQUEST, got {other:?}"),
    }

    // [P4-chain] PAGE REQUEST also travelled through MLE → LLC → UMAC.
    assert!(
        find_tla_data_req_bl(&phase4_msgs).is_some(),
        "P4: MLE must produce TlaTlDataReqBl for PAGE REQUEST"
    );
    assert!(
        find_tma_unitdata_req(&phase4_msgs).is_some(),
        "P4: LLC must produce TmaUnitdataReq for PAGE REQUEST"
    );

    // ── Phase 5: No UNITDATA while waiting for page response ─────────────────
    //
    // The page_payload is queued internally. A second downlink while in
    // WaitForPageResponse must be queued too and produce no new PAGE REQUEST.
    let second_payload = vec![0xDE, 0xAD, 0xBE, 0xEF];
    stack.sndcp.feed_downlink_ip(
        &mut stack.queue,
        GatewayDownlink { dest_ipv4: allocated_ip, payload: second_payload.clone() },
    );
    let phase5_msgs = tick_stack(&mut stack);

    // [P5] No SNDCP downlink messages: second payload is queued only.
    let p5_sndcp_out: Vec<&SapMsg> = phase5_msgs.iter()
        .filter(|m| m.src == TetraEntity::Sndcp)
        .collect();
    assert!(
        p5_sndcp_out.is_empty(),
        "P5: second downlink while WaitForPageResponse must be queued, not sent (got {p5_sndcp_out:?})"
    );

    // ── Phase 6: MS PAGE RESPONSE → context back to Ready; queued payload drained
    stack.queue.push_back(make_uplink_ind(
        build_page_response_pdu(TEST_NSAPI),
        TEST_ISSI,
    ));
    let phase6_msgs = tick_stack(&mut stack);

    // [P6-A] Two SN-UNITDATA PDUs must be emitted (one per queued payload).
    let unitdata_reqs: Vec<LtpdMleUnitdataReq> = phase6_msgs.iter()
        .filter_map(|m| {
            if m.src == TetraEntity::Sndcp {
                if let SapMsgInner::LtpdMleUnitdataReq(req) = &m.msg {
                    return Some(req.clone());
                }
            }
            None
        })
        .collect();
    assert_eq!(unitdata_reqs.len(), 2,
        "P6: PAGE RESPONSE must drain 2 queued UNITDATA PDUs, got {}", unitdata_reqs.len());

    for (i, req) in unitdata_reqs.iter().enumerate() {
        assert_eq!(req.layer2service, Layer2Service::Unacknowledged,
            "P6: drained UNITDATA[{i}] must be Unacknowledged");
        assert!(req.packet_data_flag,
            "P6: drained UNITDATA[{i}] must carry packet_data_flag=true");
    }

    // Decode and verify payload order.
    let payloads: Vec<Vec<u8>> = unitdata_reqs.iter()
        .map(|req| match decode_dl_from_sdu(&req.sdu) {
            SnPdu::Unitdata(u) => u.payload,
            other => panic!("P6: drained msg is not UNITDATA: {other:?}"),
        })
        .collect();
    assert_eq!(payloads[0], page_payload, "P6: first drained payload = page_payload");
    assert_eq!(payloads[1], second_payload, "P6: second drained payload = second_payload");

    // [P6-B] Both UNITDATA passed through MLE (TlaTlUnitdataReqBl) and LLC (TmaUnitdataReq).
    let tla_unitdata_count = phase6_msgs.iter()
        .filter(|m| matches!(&m.msg, SapMsgInner::TlaTlUnitdataReqBl(_)))
        .count();
    assert_eq!(tla_unitdata_count, 2,
        "P6: MLE must produce 2 TlaTlUnitdataReqBl for the drained UNITDATA");

    let tma_unitdata_count = phase6_msgs.iter()
        .filter(|m| m.src == TetraEntity::Llc
            && matches!(&m.msg, SapMsgInner::TmaUnitdataReq(r) if r.packet_data_flag))
        .count();
    assert_eq!(tma_unitdata_count, 2,
        "P6: LLC must produce 2 TmaUnitdataReq(packet_data_flag=true) for the drained UNITDATA");
}
