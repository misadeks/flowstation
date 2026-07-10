/// PD-8: Full packet-data lifecycle integration test.
///
/// Wires SNDCP + MLE + LLC + UMAC together and drives a complete PDP-context
/// lifecycle: ACTIVATE, uplink SN-UNITDATA and SN-DATA (acknowledged flow),
/// downlink SN-UNITDATA and SN-DATA, Ready-timer expiry â†’ Standby,
/// SN-PAGE-REQUEST / RESPONSE round-trip, and DEACTIVATE â€“ all verified through
/// the full SapMsg chain.
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
use tetra_pdus::sndcp::enums::logical_link_status::LogicalLinkStatus;
use tetra_pdus::sndcp::enums::pdms_type::PdmsType;
use tetra_pdus::sndcp::enums::tia::Tia;
use tetra_pdus::sndcp::fields::nsapi::Nsapi;
use tetra_pdus::sndcp::pdus::{
    ActivatePdpContextDemand, DeactivatePdpContextDemand, PageResponse, SnData,
    SnDataTransmitRequest, SnPdu, Unitdata,
};
use tetra_pdus::umac::pdus::mac_resource::MacResource;
use tetra_saps::ltpd::{LtpdMleUnitdataInd, LtpdMleUnitdataReq};
use tetra_saps::sapmsg::{SapMsg, SapMsgInner};
use tetra_saps::tla::{TlaTlDataIndAl, TlaTlDataReqBl, TlaTlUnitdataReqBl};
use tetra_saps::tma::TmaUnitdataReq;
use tetra_saps::tmv::TmvUnitdataReqSlots;

// â”€â”€ Constants â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

const TEST_ISSI: u32 = 1234;
const TEST_NSAPI: u8 = 3;
/// Slightly more than READY_TIMER_SLOTS (4237 slots â‰ˆ 60 s); enough to expire it.
/// PD-4i widened the Ready timer from ~10 s to ~60 s so END-OF-DATA doesn't race it.
const PAST_READY_TIMER: i32 = 4300;

// â”€â”€ TestStack â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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

/// Execute one full tick cycle (tick_start â†’ drain â†’ tick_end{LLC,UMAC,others} â†’ drain each),
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

    // 3. LLC tick_end (flushes deferred BL-ACKs) â†’ deliver.
    stack.llc.tick_end(&mut stack.queue, now);
    all.extend(drain_collecting(stack));

    // 4. UMAC tick_end (finalises scheduling, may emit MAC-RESOURCE to LMAC) â†’ deliver.
    stack.umac.tick_end(&mut stack.queue, now);
    all.extend(drain_collecting(stack));

    // 5. Remaining entities' tick_end (SNDCP runs ready/standby timers here) â†’ deliver.
    stack.sndcp.tick_end(&mut stack.queue, now);
    stack.mle.tick_end(&mut stack.queue, now);
    all.extend(drain_collecting(stack));

    // 6. Advance TDMA time by one timeslot (mirrors MessageRouter).
    stack.now = stack.now.add_timeslots(1);

    all
}

// â”€â”€ PDU-builder helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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
    let ud = Unitdata { nsapi: Nsapi(nsapi), pcomp: 0, dcomp: 0, payload: payload.to_vec() };
    let mut buf = BitBuffer::new_autoexpand(256);
    ud.to_bitbuf(&mut buf).expect("encode unitdata");
    buf.seek(0);
    with_discriminator(&buf)
}

/// Build a minimal SN-DATA-TRANSMIT-REQUEST (type 6) with the SNDCP discriminator prepended.
/// No enhanced_pi4_dqpsk, no o_bit, no additional NSAPIs â€” matches Motorola MTM800E minimum form.
fn build_data_transmit_request_pdu(nsapi: u8) -> BitBuffer {
    let req = SnDataTransmitRequest {
        nsapi: Nsapi(nsapi),
        logical_link_status: LogicalLinkStatus::NotConnected,
        enhanced_pi4_dqpsk_service: false,
        resource_request: None,
        o_bit: false,
        sndcp_network_endpoint_identifier: None,
        m_bit: false,
        nsapi_additional: vec![],
    };
    let mut buf = BitBuffer::new_autoexpand(64);
    req.to_bitbuf(&mut buf).expect("encode data transmit request");
    buf.seek(0);
    with_discriminator(&buf)
}

/// Build an SN-DATA (type 5) PDU with the SNDCP protocol discriminator prepended.
fn build_sn_data_pdu(nsapi: u8, payload: &[u8]) -> BitBuffer {
    let d = SnData { nsapi: Nsapi(nsapi), pcomp: 0, dcomp: 0, n_pdu: payload.to_vec() };
    let mut buf = BitBuffer::new_autoexpand(256);
    d.to_bitbuf(&mut buf).expect("encode sn data");
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

// â”€â”€ Uplink injection helper â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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
            al_link_number: None,
        }),
    }
}

/// PD-5c-H12: Wrap a pre-built SDU (with SNDCP discriminator) in a
/// `TlaTlDataIndAl` as if LLC just finished reassembling an Advanced-Link
/// uplink SDU and delivered it up to MLE on the TLA SAP. Exercises the AL
/// routing arm in `MleBs::rx_tla_prim`.
fn make_uplink_ind_al(sdu: BitBuffer, issi: u32) -> SapMsg {
    SapMsg {
        sap: Sap::TlaSap,
        src: TetraEntity::Llc,
        dest: TetraEntity::Mle,
        msg: SapMsgInner::TlaTlDataIndAl(TlaTlDataIndAl {
            main_address: TetraAddress::new(issi, SsiType::Issi),
            link_id: 0,
            endpoint_id: 0,
            al_link_number: 1,
            tl_sdu: sdu,
            subscriber_class: 0,
            fcs_ok: true,
            air_interface_encryption: None,
        }),
    }
}

// â”€â”€ Message-chain finder helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Find the first `LtpdMleUnitdataReq` (SNDCP â†’ MLE) in a message list.
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

/// Find the first `TlaTlDataReqBl` (MLE â†’ LLC, Acknowledged path) in a message list.
fn find_tla_data_req_bl(msgs: &[SapMsg]) -> Option<TlaTlDataReqBl> {
    msgs.iter().find_map(|m| {
        if let SapMsgInner::TlaTlDataReqBl(req) = &m.msg {
            Some(req.clone())
        } else {
            None
        }
    })
}

/// Find the first `TlaTlUnitdataReqBl` (MLE â†’ LLC, Unacknowledged path) in a message list.
fn find_tla_unitdata_req_bl(msgs: &[SapMsg]) -> Option<TlaTlUnitdataReqBl> {
    msgs.iter().find_map(|m| {
        if let SapMsgInner::TlaTlUnitdataReqBl(req) = &m.msg {
            Some(req.clone())
        } else {
            None
        }
    })
}

/// Find the first `TmaUnitdataReq` (LLC â†’ UMAC) in a message list.
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

// â”€â”€ Phase 1â€“3 + 7 test â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// ACTIVATE â†’ UPLINK â†’ DOWNLINK â†’ DEACTIVATE: the core packet-data lifecycle.
///
/// Proves that PD-1..PD-7 compose correctly end-to-end:
/// â€¢ SNDCP allocates an IPv4, emits ACCEPT via LtpdMleUnitdataReq
/// â€¢ MLE wraps it in TlaTlDataReqBl (Acknowledged)
/// â€¢ LLC wraps it in TmaUnitdataReq for UMAC
/// â€¢ Uplink UNITDATA surfaces to the gateway queue
/// â€¢ Downlink IP triggers PDCH reservation + MAC-RESOURCE grant
/// â€¢ DEACTIVATE frees the IP back to the pool
#[test]
fn activate_uplink_downlink_deactivate() {
    debug::setup_logging_verbose();

    let mut stack = TestStack::new();

    // â”€â”€ Phase 1: MS sends SN-ACTIVATE PDP CONTEXT DEMAND â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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
        "P1: allocated IP {allocated_ip} must be within default pool 192.168.100.2â€“.254"
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

    // â”€â”€ Phase 2: MS sends uplink SN-UNITDATA â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

    // â”€â”€ Phase 3: Gateway sends ICMP echo reply downlink â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

    // [P3-E] PD-5c-H2: with the piggyback pattern, no standalone empty-SDU
    //        MAC-RESOURCE-with-ChanAllocElement is emitted on the DL IP data
    //        path. The bookkeeping asserted in [P3-D] (allocator reservation +
    //        current_timeslot) is the observable signal here. The actual PDCH
    //        grant to the MS rides on the SN-DATA-TRANSMIT-RESPONSE in Phase
    //        3.5 below.
    // Give the scheduler a few ticks so any DL PDU can drain to LMAC.
    for _ in 0..10 {
        tick_stack(&mut stack);
    }

    // â”€â”€ Phase 3.5: SN-DATA-TRANSMIT-REQUEST / SN-DATA (acknowledged flow) â”€â”€â”€â”€
    //
    // A Motorola MTM800E, after receiving ACTIVATE ACCEPT, sends
    // SN-DATA-TRANSMIT-REQUEST (type 6) to negotiate acknowledged packet-data
    // transfer. SNDCP must respond with SN-DATA-TRANSMIT-RESPONSE (type 7,
    // accept=true) and transition to WaitingForAlSetup.
    //
    // The first uplink SN-DATA (type 5) that follows acts as the implicit AL
    // setup confirmation (PD-4b NOTE). SNDCP delivers it to the gateway queue
    // exactly like an SN-UNITDATA.
    //
    // For the downlink direction, `feed_downlink_ip_acknowledged` must emit an
    // SN-DATA PDU (type 5) via `LtpdMleUnitdataReq { layer2service: Acknowledged }`.

    // Inject minimal SN-DATA-TRANSMIT-REQUEST (no enhanced mode, no o_bit).
    stack.queue.push_back(make_uplink_ind(
        build_data_transmit_request_pdu(TEST_NSAPI),
        TEST_ISSI,
    ));
    let phase35a_msgs = tick_stack(&mut stack);

    // [P3.5-A] SNDCP emitted SN-DATA-TRANSMIT-RESPONSE with accept=true.
    let ltpd_txr = find_ltpd_unitdata_req(&phase35a_msgs)
        .expect("P3.5: SNDCP must emit LtpdMleUnitdataReq for DATA-TRANSMIT-RESPONSE");
    assert_eq!(ltpd_txr.layer2service, Layer2Service::Acknowledged,
        "P3.5: TRANSMIT-RESPONSE uses Acknowledged service");
    assert!(!ltpd_txr.packet_data_flag, "P3.5: TRANSMIT-RESPONSE is signalling, not IP data");
    match decode_dl_from_sdu(&ltpd_txr.sdu) {
        SnPdu::DataTransmitResponse(r) => {
            assert_eq!(r.nsapi.0, TEST_NSAPI, "P3.5: TRANSMIT-RESPONSE NSAPI");
            assert!(r.accept, "P3.5: TRANSMIT-RESPONSE must be accept=true");
        }
        other => panic!("P3.5: expected DataTransmitResponse, got {other:?}"),
    }

    // [P3.5-B] MLE forwarded TRANSMIT-RESPONSE as TlaTlDataReqBl (Acknowledged service).
    // NOTE: LLC defers it (blocked by ACTIVATE ACCEPT BL-ACK, same as Phase 7).
    assert!(
        find_tla_data_req_bl(&phase35a_msgs).is_some(),
        "P3.5: MLE must produce TlaTlDataReqBl for DATA-TRANSMIT-RESPONSE"
    );

    // [P3.5-B2] PD-5c-H2: the SN-DATA-TRANSMIT-RESPONSE LtpdMleUnitdataReq must
    // carry the piggybacked CmceChanAllocReq so UMAC emits a SINGLE MacResource
    // with both the response SDU and the ChanAllocElement â€” the pattern
    // MTP3550 firmware requires. The TlaTlDataReqBl and downstream
    // TmaUnitdataReq must thread the same chan_alloc through unchanged.
    assert!(
        ltpd_txr.chan_alloc.is_some(),
        "P3.5: TRANSMIT-RESPONSE must piggyback CmceChanAllocReq (PD-5c-H2)"
    );
    let tla_dl = find_tla_data_req_bl(&phase35a_msgs)
        .expect("P3.5: TlaTlDataReqBl must exist for TRANSMIT-RESPONSE");
    assert!(
        tla_dl.chan_alloc.is_some(),
        "P3.5: MLE must thread chan_alloc through onto TlaTlDataReqBl"
    );

    // Inject uplink SN-DATA (type 5, acknowledged IP data).
    let icmp_req2: Vec<u8> = vec![
        0x45, 0x00, 0x00, 0x1c, 0x00, 0x02, 0x00, 0x00,
        0x40, 0x01, 0x00, 0x00,
        0xc0, 0xa8, 0x64, 0x02, // src: 192.168.100.2
        0xc0, 0xa8, 0x64, 0x01, // dst: 192.168.100.1
        0x08, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01,
    ];
    stack.queue.push_back(make_uplink_ind(
        build_sn_data_pdu(TEST_NSAPI, &icmp_req2),
        TEST_ISSI,
    ));
    let phase35b_msgs = tick_stack(&mut stack);

    // [P3.5-C] SN-DATA uplink â†’ gateway queue; no downlink produced.
    assert!(
        find_ltpd_unitdata_req(&phase35b_msgs).is_none(),
        "P3.5: uplink SN-DATA must NOT produce any LtpdMleUnitdataReq"
    );
    let ul_data = stack.sndcp.uplink_ip_queue.pop_front()
        .expect("P3.5: SNDCP must push uplink SN-DATA to gateway queue");
    assert_eq!(ul_data.main_address.ssi, TEST_ISSI, "P3.5: SN-DATA uplink SSI");
    assert_eq!(ul_data.nsapi, TEST_NSAPI, "P3.5: SN-DATA uplink NSAPI");
    assert_eq!(ul_data.payload, icmp_req2, "P3.5: SN-DATA uplink payload");
    assert!(stack.sndcp.uplink_ip_queue.is_empty(), "P3.5: no leftover uplink items");

    // Gateway sends acknowledged IP reply via feed_downlink_ip_acknowledged.
    let icmp_reply2: Vec<u8> = vec![
        0x45, 0x00, 0x00, 0x1c, 0x00, 0x02, 0x00, 0x00,
        0x40, 0x01, 0x00, 0x00,
        0xc0, 0xa8, 0x64, 0x01, // src: 192.168.100.1
        0xc0, 0xa8, 0x64, 0x02, // dst: 192.168.100.2
        0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01,
    ];
    stack.sndcp.feed_downlink_ip_acknowledged(
        &mut stack.queue,
        GatewayDownlink { dest_ipv4: allocated_ip, payload: icmp_reply2.clone() },
    );
    let phase35c_msgs = tick_stack(&mut stack);

    // [P3.5-D] SNDCP emitted LtpdMleUnitdataReq(Acknowledged, packet_data_flag=true) with SN-DATA.
    let ltpd_data_dl = find_ltpd_unitdata_req(&phase35c_msgs)
        .expect("P3.5: SNDCP must emit LtpdMleUnitdataReq for acknowledged downlink SN-DATA");
    assert_eq!(ltpd_data_dl.layer2service, Layer2Service::Acknowledged,
        "P3.5: acknowledged downlink must use Acknowledged service");
    assert!(ltpd_data_dl.packet_data_flag,
        "P3.5: SN-DATA downlink must carry packet_data_flag=true");
    match decode_dl_from_sdu(&ltpd_data_dl.sdu) {
        SnPdu::Data(d) => {
            assert_eq!(d.nsapi.0, TEST_NSAPI, "P3.5: SN-DATA downlink NSAPI");
            assert_eq!(d.n_pdu, icmp_reply2, "P3.5: SN-DATA downlink payload");
        }
        other => panic!("P3.5: expected SnData (type 5), got {other:?}"),
    }
    // [P3.5-E] MLE forwarded SN-DATA downlink as TlaTlDataReqBl (Acknowledged service).
    // NOTE: LLC defers it (blocked by pending ACTIVATE ACCEPT BL-ACK, same as Phase 7).
    assert!(
        find_tla_data_req_bl(&phase35c_msgs).is_some(),
        "P3.5: MLE must produce TlaTlDataReqBl for acknowledged SN-DATA downlink"
    );

    // â”€â”€ Phase 7: MS sends SN-DEACTIVATE PDP CONTEXT DEMAND â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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
    // NOTE: LLC uses strict per-SSI ordered acknowledged-mode (ETSI Â§22.3.2.3). Since
    // the ACTIVATE ACCEPT BL-DATA has not yet been ACKed by ISSI 1234 (no BL-ACK
    // injected in this test), LLC correctly holds the DEACTIVATE ACCEPT in its
    // outbound queue until the first frame is ACKed. This is correct protocol behavior,
    // NOT a bug. We assert only up to the MLE level here; LLCâ†’UMAC is covered by
    // phase 1's P1-D assertion (which does receive its TmaUnitdataReq immediately,
    // as no prior ISSI-1234 frame was in-flight then).
    assert!(
        find_tla_data_req_bl(&phase7_msgs).is_some(),
        "P7: MLE must produce TlaTlDataReqBl for the DEACTIVATE ACCEPT"
    );
    // LLC DEACTIVATE ACCEPT delivery to UMAC is deferred (blocked by pending ACTIVATE
    // ACCEPT ACK); not asserted here.

    // [P7-C] IPv4 returned to pool: request the same IP statically â†’ must succeed.
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

    // NOTE: spec ambiguous â€” chosen behaviour: use a different SSI (9999) so no
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

// â”€â”€ Phase 4â€“6 test â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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

    // â”€â”€ Phase 4: Advance past the ready timer â†’ context â†’ Standby â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    //
    // READY_TIMER_SLOTS â‰ˆ 4237 timeslots (60 s). Run PAST_READY_TIMER (4300) real
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

    // [P4-chain] PAGE REQUEST also travelled through MLE â†’ LLC â†’ UMAC.
    assert!(
        find_tla_data_req_bl(&phase4_msgs).is_some(),
        "P4: MLE must produce TlaTlDataReqBl for PAGE REQUEST"
    );
    assert!(
        find_tma_unitdata_req(&phase4_msgs).is_some(),
        "P4: LLC must produce TmaUnitdataReq for PAGE REQUEST"
    );

    // â”€â”€ Phase 5: No UNITDATA while waiting for page response â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

    // â”€â”€ Phase 6: MS PAGE RESPONSE â†’ context back to Ready; queued payload drained
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

/// PD-5c-H12: Uplink AL-assembled SN-DATA must route through MLE â†’ SNDCP.
///
/// Before the fix, `TlaTlDataIndAl` (emitted by LLC after AL reassembly)
/// hit the catch-all in `MleBs::rx_tla_prim` and produced
/// `BUG: unexpected message or state -- routing error`, so SNDCP never saw
/// the SN-DATA and the MS retransmitted indefinitely. This test walks the
/// full BS-side chain: LLC-emitted `TlaTlDataIndAl` â†’ MLE dispatch â†’
/// SNDCP consumption â†’ gateway uplink queue.
#[test]
fn al_uplink_sn_data_reaches_sndcp() {
    debug::setup_logging_verbose();

    let mut stack = TestStack::new();

    // Bring up the PDP context via the existing BL/TLPD injection path.
    stack.queue.push_back(make_uplink_ind(
        build_activate_demand_pdu(TEST_NSAPI),
        TEST_ISSI,
    ));
    let setup_msgs = tick_stack(&mut stack);
    let ltpd_accept = find_ltpd_unitdata_req(&setup_msgs)
        .expect("setup: ACTIVATE must produce ACCEPT");
    match decode_dl_from_sdu(&ltpd_accept.sdu) {
        SnPdu::ActivatePdpContextAccept(_) => {}
        other => panic!("setup: expected ACCEPT, got {other:?}"),
    };

    // Now inject SN-DATA over the AL path â€” simulating LLC delivering an
    // assembled Advanced-Link SDU up to MLE.
    let icmp_req: Vec<u8> = vec![
        0x45, 0x00, 0x00, 0x1c, 0x00, 0x02, 0x00, 0x00,
        0x40, 0x01, 0x00, 0x00,
        0xc0, 0xa8, 0x64, 0x02,
        0xc0, 0xa8, 0x64, 0x01,
        0x08, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01,
    ];
    stack.queue.push_back(make_uplink_ind_al(
        build_sn_data_pdu(TEST_NSAPI, &icmp_req),
        TEST_ISSI,
    ));
    let al_msgs = tick_stack(&mut stack);

    // MLE must have translated the AL Ind into an LtpdMleUnitdataInd on TlpdSap.
    let mle_ltpd_ind = al_msgs.iter().find(|m|
        m.src == TetraEntity::Mle
            && m.dest == TetraEntity::Sndcp
            && matches!(m.msg, SapMsgInner::LtpdMleUnitdataInd(_))
    );
    assert!(mle_ltpd_ind.is_some(),
        "H12: MLE must forward AL Ind as LtpdMleUnitdataInd on TlpdSap");

    // SNDCP must have consumed it and pushed the IP payload upstream.
    let ul = stack.sndcp.uplink_ip_queue.pop_front()
        .expect("H12: SNDCP must push AL-delivered SN-DATA payload to gateway queue");
    assert_eq!(ul.main_address.ssi, TEST_ISSI, "H12: uplink SSI");
    assert_eq!(ul.nsapi, TEST_NSAPI, "H12: uplink NSAPI");
    assert_eq!(ul.payload, icmp_req, "H12: uplink payload bytes");
}

// -- PD-9: pd-gateway bridge integration ---------------------------------------

/// PD-9: When set_gateway_channels is installed, SNDCP must drain
/// uplink_ip_queue into the sender end during 	ick_end, so the
/// pd-gateway bridge (running on a separate std thread) can read from it.
#[test]
fn pd9_sndcp_drains_uplink_ip_queue_to_gateway_channel() {
    debug::setup_logging_verbose();

    let mut stack = TestStack::new();
    // Install the bridge channels BEFORE any ticks so tick_end sees the sender.
    let (u_tx, u_rx) = crossbeam_channel::unbounded::<
        tetra_entities::sndcp::sndcp_bs::GatewayUplink,
    >();
    let (_d_tx, d_rx) = crossbeam_channel::unbounded::<GatewayDownlink>();
    stack.sndcp.set_gateway_channels(u_tx, d_rx);

    // Phase 1: activate a PDP context so on_uplink_data has state to route through.
    stack.queue.push_back(make_uplink_ind(
        build_activate_demand_pdu(TEST_NSAPI),
        TEST_ISSI,
    ));
    let phase1 = tick_stack(&mut stack);
    let accept = match decode_dl_from_sdu(
        &find_ltpd_unitdata_req(&phase1).expect("PD-9: ACCEPT missing").sdu,
    ) {
        SnPdu::ActivatePdpContextAccept(a) => a,
        other => panic!("PD-9: expected ACCEPT, got {other:?}"),
    };
    let _allocated_ip = accept.ip4_address.expect("PD-9: ACCEPT must carry IPv4");

    // With the channel installed, tick_end should have already drained the
    // (empty) uplink queue with no items surfacing yet.
    assert!(u_rx.try_recv().is_err(), "PD-9: no uplink items expected pre-injection");

    // Phase 2: inject an uplink SN-DATA (AL-DATA path — matches PD-5c-H12).
    let ip_payload = vec![0x45u8, 0x00, 0x00, 0x1c,  0, 1, 0, 0,  0x40, 0x01, 0, 0,
                          0xc0, 0xa8, 0x64, 0x02,  0xc0, 0xa8, 0x64, 0x01,
                          0x08, 0x00, 0, 0,  0, 1, 0, 1];
    stack.queue.push_back(make_uplink_ind_al(
        build_sn_data_pdu(TEST_NSAPI, &ip_payload),
        TEST_ISSI,
    ));
    let _phase2 = tick_stack(&mut stack);

    // The queue must have been drained into the sender; assert the receiver
    // sees exactly one matching uplink item and the internal queue is empty.
    let ul = u_rx.try_recv()
        .expect("PD-9: SNDCP must forward uplink IP payload via the gateway channel");
    assert_eq!(ul.main_address.ssi, TEST_ISSI, "PD-9: gateway uplink SSI");
    assert_eq!(ul.nsapi, TEST_NSAPI, "PD-9: gateway uplink NSAPI");
    assert_eq!(ul.payload, ip_payload, "PD-9: gateway uplink payload bytes");
    assert!(u_rx.try_recv().is_err(), "PD-9: no additional uplink items expected");
    assert!(
        stack.sndcp.uplink_ip_queue.is_empty(),
        "PD-9: uplink_ip_queue must be drained by tick_end"
    );
}

/// PD-9: When the bridge sends a GatewayDownlink into the receiver end,
/// SNDCP's 	ick_start must pick it up and emit an acknowledged SN-DATA
/// LtpdMleUnitdataReq on TlpdSap (Ready contexts) — matching the AL path
/// used by the uplink direction on live hardware.
#[test]
fn pd9_sndcp_feeds_downlink_ip_from_gateway_channel_as_sn_data() {
    debug::setup_logging_verbose();

    let mut stack = TestStack::new();
    let (u_tx, _u_rx) = crossbeam_channel::unbounded::<
        tetra_entities::sndcp::sndcp_bs::GatewayUplink,
    >();
    let (d_tx, d_rx) = crossbeam_channel::unbounded::<GatewayDownlink>();
    stack.sndcp.set_gateway_channels(u_tx, d_rx);

    // Activate to Ready so feed_downlink_ip_acknowledged is chosen.
    stack.queue.push_back(make_uplink_ind(
        build_activate_demand_pdu(TEST_NSAPI),
        TEST_ISSI,
    ));
    let phase1 = tick_stack(&mut stack);
    let accept = match decode_dl_from_sdu(
        &find_ltpd_unitdata_req(&phase1).expect("PD-9: ACCEPT missing").sdu,
    ) {
        SnPdu::ActivatePdpContextAccept(a) => a,
        other => panic!("PD-9: expected ACCEPT, got {other:?}"),
    };
    let allocated_ip = accept.ip4_address.expect("PD-9: ACCEPT must carry IPv4");

    // Bridge injects a downlink IP payload for this leased address.
    let dl_payload = vec![0x45u8, 0x00, 0x00, 0x1c,  0, 2, 0, 0,  0x40, 0x01, 0, 0,
                          0xc0, 0xa8, 0x64, 0x01,  0xc0, 0xa8, 0x64, 0x02,
                          0x00, 0x00, 0, 0,  0, 1, 0, 1];
    d_tx.send(GatewayDownlink { dest_ipv4: allocated_ip, payload: dl_payload.clone() })
        .expect("PD-9: downlink channel send must succeed");

    // Tick — tick_start must drain the receiver and enqueue an SN-DATA
    // LtpdMleUnitdataReq (Acknowledged, packet_data_flag=true).
    let msgs = tick_stack(&mut stack);

    let sn_data_reqs: Vec<LtpdMleUnitdataReq> = msgs.iter()
        .filter_map(|m| {
            if m.src == TetraEntity::Sndcp {
                if let SapMsgInner::LtpdMleUnitdataReq(req) = &m.msg {
                    if req.packet_data_flag
                        && req.layer2service == Layer2Service::Acknowledged
                        && matches!(decode_dl_from_sdu(&req.sdu), SnPdu::Data(_))
                    {
                        return Some(req.clone());
                    }
                }
            }
            None
        })
        .collect();
    assert_eq!(sn_data_reqs.len(), 1,
        "PD-9: expected exactly one acknowledged SN-DATA LtpdMleUnitdataReq, got {}: {msgs:?}",
        sn_data_reqs.len());

    let req = &sn_data_reqs[0];
    assert_eq!(req.main_address.ssi, TEST_ISSI, "PD-9: downlink addressed to MS");
    match decode_dl_from_sdu(&req.sdu) {
        SnPdu::Data(d) => {
            assert_eq!(d.nsapi.0, TEST_NSAPI, "PD-9: SN-DATA NSAPI matches context");
            assert_eq!(d.n_pdu, dl_payload, "PD-9: SN-DATA N-PDU payload round-trip");
        }
        other => panic!("PD-9: expected SnPdu::Data, got {other:?}"),
    }
}


// -- PD-5c-H13: SNDCP tracks AL link and prefers it for downlink ---------------

/// Like `make_uplink_ind_al` but lets the caller pick the link_id / endpoint_id
/// / al_link_number so a test can simulate an MS that opened AL link 4 for its
/// packet-data session after activating on BL link 1.
fn make_uplink_ind_al_at(
    sdu: BitBuffer,
    issi: u32,
    link_id: u32,
    endpoint_id: u32,
    al_link_number: u8,
) -> SapMsg {
    SapMsg {
        sap: Sap::TlaSap,
        src: TetraEntity::Llc,
        dest: TetraEntity::Mle,
        msg: SapMsgInner::TlaTlDataIndAl(TlaTlDataIndAl {
            main_address: TetraAddress::new(issi, SsiType::Issi),
            link_id,
            endpoint_id,
            al_link_number,
            tl_sdu: sdu,
            subscriber_class: 0,
            fcs_ok: true,
            air_interface_encryption: None,
        }),
    }
}

/// PD-5c-H13: After the MS opens an Advanced Link, downlink SN-DATA must ride
/// that AL (link_id learned from the uplink AL frame), not the BL link_id
/// captured at ACTIVATE DEMAND time. Prior to H13, `ctx.link_id` was frozen at
/// activation and every downlink went out on the ACTIVATE BL — the MS's WAP
/// session was on AL and it ignored replies arriving on the wrong LLC channel.
#[test]
fn pd_al_uplink_learns_al_link_and_downlink_uses_it() {
    debug::setup_logging_verbose();

    let mut stack = TestStack::new();

    // Activate PDP context over BL (as the real MS does): the ACTIVATE DEMAND
    // arrives with link_id=0/endpoint_id=0 via `make_uplink_ind`, which is the
    // BL tuple SNDCP caches into `ctx.link_id/endpoint_id`.
    stack.queue.push_back(make_uplink_ind(
        build_activate_demand_pdu(TEST_NSAPI),
        TEST_ISSI,
    ));
    let setup = tick_stack(&mut stack);
    let accept = match decode_dl_from_sdu(
        &find_ltpd_unitdata_req(&setup).expect("H13: ACCEPT missing").sdu,
    ) {
        SnPdu::ActivatePdpContextAccept(a) => a,
        other => panic!("H13: expected ACCEPT, got {other:?}"),
    };
    let allocated_ip = accept.ip4_address.expect("H13: ACCEPT must carry IPv4");

    // Now inject uplink SN-DATA on an AL link (link_id=4, al_link_number=4) —
    // simulating LLC delivering an AL-assembled SDU up to MLE after the MS
    // opened an Advanced Link for its data phase.
    let icmp_req: Vec<u8> = vec![
        0x45, 0x00, 0x00, 0x1c, 0x00, 0x02, 0x00, 0x00,
        0x40, 0x01, 0x00, 0x00,
        0xc0, 0xa8, 0x64, 0x02,
        0xc0, 0xa8, 0x64, 0x01,
        0x08, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01,
    ];
    stack.queue.push_back(make_uplink_ind_al_at(
        build_sn_data_pdu(TEST_NSAPI, &icmp_req),
        TEST_ISSI,
        /* link_id */ 4,
        /* endpoint_id */ 0,
        /* al_link_number */ 4,
    ));
    let _al_msgs = tick_stack(&mut stack);
    // Drain the uplink so it doesn't shadow the downlink assertion below.
    let _ = stack.sndcp.uplink_ip_queue.pop_front()
        .expect("H13: SNDCP must consume the AL SN-DATA");

    // Feed a downlink IP reply. The resulting LtpdMleUnitdataReq MUST use the
    // AL link_id (4) — not the BL link_id (0) captured at activation.
    let icmp_reply: Vec<u8> = vec![
        0x45, 0x00, 0x00, 0x1c, 0x00, 0x03, 0x00, 0x00,
        0x40, 0x01, 0x00, 0x00,
        0xc0, 0xa8, 0x64, 0x01,
        0xc0, 0xa8, 0x64, 0x02,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x01,
    ];
    stack.sndcp.feed_downlink_ip_acknowledged(
        &mut stack.queue,
        GatewayDownlink { dest_ipv4: allocated_ip, payload: icmp_reply.clone() },
    );
    let dl_msgs = tick_stack(&mut stack);

    let ltpd_dl = find_ltpd_unitdata_req(&dl_msgs)
        .expect("H13: SNDCP must emit LtpdMleUnitdataReq for downlink SN-DATA");
    assert_eq!(
        ltpd_dl.link_id, 4,
        "H13: downlink SN-DATA must ride the AL link_id (4) learned from uplink AL-DATA, not the BL link_id (0) from ACTIVATE"
    );
    assert_eq!(ltpd_dl.endpoint_id, 0, "H13: downlink endpoint_id matches AL");
    assert!(ltpd_dl.packet_data_flag, "H13: SN-DATA carries packet_data_flag");
    match decode_dl_from_sdu(&ltpd_dl.sdu) {
        SnPdu::Data(d) => {
            assert_eq!(d.nsapi.0, TEST_NSAPI);
            assert_eq!(d.n_pdu, icmp_reply);
        }
        other => panic!("H13: expected SN-DATA, got {other:?}"),
    }

    // PD-5c-H14: SNDCP must also thread the N.261 al_link_number (4) on the
    // outbound LtpdMleUnitdataReq so MLE can route the downlink onto AL. Prior
    // to H14 this field did not exist and MLE fell back to TlaTlDataReqBl.
    assert_eq!(
        ltpd_dl.al_link_number, Some(4),
        "H14: SNDCP must forward the cached AL number (4) on downlink SN-DATA"
    );

    // PD-5c-H14: and MLE must in turn emit TlaTlDataReqAl (not TlaTlDataReqBl)
    // for LLC's AL segmenter. This is the primary fix — before H14, LLC saw
    // BL-DATA and the MS's AL peer ignored it because BL-DATA does not advance
    // the AL RX window.
    let tla_al = dl_msgs.iter().find_map(|m| match &m.msg {
        SapMsgInner::TlaTlDataReqAl(req) if req.main_address.ssi == TEST_ISSI => Some(req),
        _ => None,
    }).expect("H14: MLE must emit TlaTlDataReqAl for SNDCP AL-routed downlink");
    assert_eq!(tla_al.link_id, 4, "H14: AL request link_id");
    assert_eq!(tla_al.endpoint_id, 0, "H14: AL request endpoint_id");
    assert_eq!(tla_al.al_link_number, 4, "H14: AL request N.261 index");

    // And no TlaTlDataReqBl should have been emitted for this downlink SDU
    // (the legacy BL path is the exact bug H14 fixes).
    assert!(
        find_tla_data_req_bl(&dl_msgs).is_none(),
        "H14: downlink SN-DATA must NOT fall back to TlaTlDataReqBl once AL is known"
    );
}

/// PD-5c-H13: If no AL uplink has been seen yet, downlink must fall back to
/// the BL (link_id, endpoint_id) captured at ACTIVATE DEMAND. Otherwise we'd
/// break the pre-H13 flow where every downlink correctly went out on BL.
#[test]
fn pd_downlink_falls_back_to_bl_when_no_al_link_yet() {
    debug::setup_logging_verbose();

    let mut stack = TestStack::new();

    stack.queue.push_back(make_uplink_ind(
        build_activate_demand_pdu(TEST_NSAPI),
        TEST_ISSI,
    ));
    let setup = tick_stack(&mut stack);
    let accept = match decode_dl_from_sdu(
        &find_ltpd_unitdata_req(&setup).expect("H13-fallback: ACCEPT missing").sdu,
    ) {
        SnPdu::ActivatePdpContextAccept(a) => a,
        other => panic!("H13-fallback: expected ACCEPT, got {other:?}"),
    };
    let allocated_ip = accept.ip4_address.expect("H13-fallback: IPv4");

    // No AL uplink — feed the downlink directly.
    let icmp_reply: Vec<u8> = vec![
        0x45, 0x00, 0x00, 0x1c, 0x00, 0x04, 0x00, 0x00,
        0x40, 0x01, 0x00, 0x00,
        0xc0, 0xa8, 0x64, 0x01,
        0xc0, 0xa8, 0x64, 0x02,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x01,
    ];
    stack.sndcp.feed_downlink_ip_acknowledged(
        &mut stack.queue,
        GatewayDownlink { dest_ipv4: allocated_ip, payload: icmp_reply },
    );
    let dl_msgs = tick_stack(&mut stack);

    let ltpd_dl = find_ltpd_unitdata_req(&dl_msgs)
        .expect("H13-fallback: SNDCP must emit LtpdMleUnitdataReq");
    // The ACTIVATE DEMAND was injected via `make_uplink_ind` which sets
    // link_id=0/endpoint_id=0; downlink must use those same values because no
    // AL has been learned yet.
    assert_eq!(
        ltpd_dl.link_id, 0,
        "H13-fallback: no AL learned — must fall back to BL link_id from ACTIVATE"
    );
    assert_eq!(ltpd_dl.endpoint_id, 0, "H13-fallback: BL endpoint_id from ACTIVATE");
}
