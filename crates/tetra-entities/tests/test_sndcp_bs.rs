mod common;

// Integration tests for the SNDCP BS state machine (PD-4).
// Pattern: build `LtpdMleUnitdataInd` with SDU = 3-bit SNDCP discriminator (0b100)
// followed by the encoded SN-PDU body, feed to `Sndcp::rx_prim`, then drain the
// outbound queue and decode each `LtpdMleUnitdataReq` payload using the PD-1 codecs.

use std::net::Ipv4Addr;

use tetra_config::bluestation::{SharedConfig, StackMode};
use tetra_core::tetra_entities::TetraEntity;
use tetra_core::{BitBuffer, Layer2Service, Sap, SsiType, TetraAddress};
use tetra_entities::sndcp::sndcp_bs::{GatewayDownlink, Sndcp};
use tetra_entities::{MessageQueue, TetraEntityTrait};
use tetra_pdus::sndcp::enums::configuration_protocol::ConfigurationProtocol;
use tetra_pdus::sndcp::enums::deactivation_type::DeactivationType;
use tetra_pdus::sndcp::enums::pdms_type::PdmsType;
use tetra_pdus::sndcp::enums::protocol_identity::ProtocolIdentity;
use tetra_pdus::sndcp::enums::reject_cause::RejectCause;
use tetra_pdus::sndcp::fields::nsapi::Nsapi;
use tetra_pdus::sndcp::fields::pco::{Pco, PcoEntry};
use tetra_pdus::sndcp::pdus::{
    ActivatePdpContextAccept, ActivatePdpContextDemand, DeactivatePdpContextDemand,
    EndOfData, PageResponse, SnPdu, Unitdata,
};
use tetra_saps::ltpd::{LtpdMleUnitdataInd, LtpdMleUnitdataReq};
use tetra_saps::sapmsg::{SapMsg, SapMsgInner};

// --- Test fixture helpers -----------------------------------------------------

fn test_addr(ssi: u32) -> TetraAddress {
    TetraAddress::new(ssi, SsiType::Issi)
}

fn make_sndcp() -> (Sndcp, MessageQueue) {
    let config = common::ComponentTest::get_default_test_config(StackMode::Bs);
    let shared_config = SharedConfig::from_parts(config, None);
    let sndcp = Sndcp::new(shared_config);
    let queue = MessageQueue::new();
    (sndcp, queue)
}

/// Prepend the 3-bit SNDCP discriminator (0b100) to `sn_pdu_bits`.
fn with_discriminator(sn_pdu_bits: &BitBuffer) -> BitBuffer {
    let mut sdu = BitBuffer::new_autoexpand(sn_pdu_bits.get_len() + 3);
    sdu.write_bits(0b100, 3); // SNDCP protocol discriminator
    let mut src = sn_pdu_bits.clone();
    src.seek(0);
    let src_len = src.get_len();
    sdu.copy_bits(&mut src, src_len);
    sdu.seek(0);
    sdu
}

fn encode_demand(d: &ActivatePdpContextDemand) -> BitBuffer {
    let mut buf = BitBuffer::new_autoexpand(256);
    d.to_bitbuf(&mut buf).expect("encode demand");
    buf.seek(0);
    buf
}

fn encode_unitdata(u: &Unitdata) -> BitBuffer {
    let mut buf = BitBuffer::new_autoexpand(256);
    u.to_bitbuf(&mut buf).expect("encode unitdata");
    buf.seek(0);
    buf
}

fn encode_end_of_data(e: &EndOfData) -> BitBuffer {
    let mut buf = BitBuffer::new_autoexpand(32);
    e.to_bitbuf(&mut buf).expect("encode end_of_data");
    buf.seek(0);
    buf
}

fn encode_page_response(p: &PageResponse) -> BitBuffer {
    let mut buf = BitBuffer::new_autoexpand(32);
    p.to_bitbuf(&mut buf).expect("encode page_response");
    buf.seek(0);
    buf
}

fn encode_deactivate_demand(d: &DeactivatePdpContextDemand) -> BitBuffer {
    let mut buf = BitBuffer::new_autoexpand(64);
    d.to_bitbuf(&mut buf).expect("encode deactivate_demand");
    buf.seek(0);
    buf
}

fn make_ind(sdu: BitBuffer, ssi: u32) -> SapMsg {
    SapMsg {
        sap: Sap::TlpdSap,
        src: TetraEntity::Mle,
        dest: TetraEntity::Sndcp,
        msg: SapMsgInner::LtpdMleUnitdataInd(LtpdMleUnitdataInd {
            sdu,
            endpoint_id: 0,
            link_id: 0,
            received_tetra_address: test_addr(ssi),
            chan_change_resp_req: false,
            chan_change_handle: None,
        }),
    }
}

/// Build a simple dynamic-ATID ACTIVATE DEMAND (no CHAP, no APN).
fn demand_dynamic(nsapi: u8) -> ActivatePdpContextDemand {
    ActivatePdpContextDemand {
        sndcp_version: 0,
        nsapi: Nsapi(nsapi),
        atid: 1, // dynamic
        ip_address: None,
        pdms_type: PdmsType::Standard,
        pcomp_negotiation: 0,
        vj_slots: None,
        snei: None,
        apn: None,
        pco: None,
    }
}

/// Drain all remaining messages from the queue into a Vec.
fn drain_queue(queue: &mut MessageQueue) -> Vec<SapMsg> {
    let mut out = Vec::new();
    while let Some(m) = queue.pop_front() {
        out.push(m);
    }
    out
}

/// Send a DEMAND and return the first outbound SapMsg.
fn activate(
    sndcp: &mut Sndcp,
    queue: &mut MessageQueue,
    ssi: u32,
    demand: ActivatePdpContextDemand,
) -> Option<SapMsg> {
    let pdu_bits = encode_demand(&demand);
    let sdu = with_discriminator(&pdu_bits);
    sndcp.rx_prim(queue, make_ind(sdu, ssi));
    queue.pop_front()
}

/// Extract the `LtpdMleUnitdataReq` from a SapMsg (panics on mismatch).
fn unwrap_req(msg: SapMsg) -> LtpdMleUnitdataReq {
    match msg.msg {
        SapMsgInner::LtpdMleUnitdataReq(req) => req,
        other => panic!("expected LtpdMleUnitdataReq, got {other:?}"),
    }
}

/// Decode the SDU of a `LtpdMleUnitdataReq` as a downlink SN-PDU.
fn decode_dl(req: &LtpdMleUnitdataReq) -> SnPdu {
    let mut buf = req.sdu.clone();
    buf.seek(0);
    SnPdu::from_bitbuf_dl(&mut buf).expect("decode_dl")
}

// --- Tests --------------------------------------------------------------------

/// 1. Dynamic ATID, no CHAP → ACCEPT with an IP from the pool.
#[test]
fn activate_demand_dynamic_ip_produces_accept_with_ipv4() {
    let (mut sndcp, mut queue) = make_sndcp();
    let msg = activate(&mut sndcp, &mut queue, 1001, demand_dynamic(3)).expect("no response");
    let req = unwrap_req(msg);
    assert_eq!(req.layer2service, Layer2Service::Acknowledged);
    assert!(!req.packet_data_flag);
    let pdu = decode_dl(&req);
    let ActivatePdpContextAccept { ip4_address, pco, .. } = match pdu {
        SnPdu::ActivatePdpContextAccept(a) => a,
        other => panic!("expected ACCEPT, got {other:?}"),
    };
    let ip = ip4_address.expect("no ip in ACCEPT");
    // Pool range: 192.168.1.180..=192.168.1.190
    assert!(
        ip >= Ipv4Addr::new(192, 168, 1, 180) && ip <= Ipv4Addr::new(192, 168, 1, 190),
        "IP {ip} outside pool range"
    );
    assert!(pco.is_none(), "expected no PCO for no-CHAP demand");
}

/// 2. DEMAND carries CHAP Response id=7 → ACCEPT PCO has CHAP Success id=7.
#[test]
fn activate_demand_with_chap_response_produces_accept_with_chap_success() {
    let (mut sndcp, mut queue) = make_sndcp();
    let mut demand = demand_dynamic(5);
    demand.pco = Some(Pco {
        configuration_protocol: ConfigurationProtocol::Ppp,
        entries: vec![PcoEntry {
            protocol_identity: ProtocolIdentity::Chap,
            // CHAP Response: code=2, id=7
            contents: vec![2u8, 7, 0, 4],
        }],
    });
    let msg = activate(&mut sndcp, &mut queue, 2001, demand).expect("no response");
    let req = unwrap_req(msg);
    let pdu = decode_dl(&req);
    let ActivatePdpContextAccept { pco, .. } = match pdu {
        SnPdu::ActivatePdpContextAccept(a) => a,
        other => panic!("expected ACCEPT, got {other:?}"),
    };
    let pco = pco.expect("expected PCO with CHAP Success");
    assert_eq!(pco.entries.len(), 1);
    let entry = &pco.entries[0];
    assert_eq!(entry.protocol_identity, ProtocolIdentity::Chap);
    // CHAP Success: code=3, id echoed=7
    assert_eq!(entry.contents[0], 3, "CHAP code should be Success (3)");
    assert_eq!(entry.contents[1], 7, "CHAP id should echo 7");
}

/// 3. Static ATID=0 with IPv4 outside 192.168.1.180..190 → REJECT cause 5.
#[test]
fn activate_demand_static_ip_not_in_pool_rejected() {
    let (mut sndcp, mut queue) = make_sndcp();
    let demand = ActivatePdpContextDemand {
        sndcp_version: 0,
        nsapi: Nsapi(3),
        atid: 0, // static
        ip_address: Some(Ipv4Addr::new(10, 0, 0, 1)), // outside pool
        pdms_type: PdmsType::Standard,
        pcomp_negotiation: 0,
        vj_slots: None,
        snei: None,
        apn: None,
        pco: None,
    };
    let msg = activate(&mut sndcp, &mut queue, 3001, demand).expect("no response");
    let req = unwrap_req(msg);
    let pdu = decode_dl(&req);
    let reject = match pdu {
        SnPdu::ActivatePdpContextReject(r) => r,
        other => panic!("expected REJECT, got {other:?}"),
    };
    assert_eq!(reject.reject_cause, RejectCause::RequestedStaticIpv4NotAvailable);
}

/// 4. Exhaust the 11-address pool, then a 12th dynamic DEMAND → REJECT cause 6.
#[test]
fn activate_demand_ip_pool_exhausted_rejected() {
    let (mut sndcp, mut queue) = make_sndcp();
    // Exhaust 11 IPs (distinct SSIs share same pool)
    for i in 0u32..11 {
        let msg = activate(&mut sndcp, &mut queue, 10_000 + i, demand_dynamic(3))
            .expect("activate failed");
        let req = unwrap_req(msg);
        let pdu = decode_dl(&req);
        assert!(
            matches!(pdu, SnPdu::ActivatePdpContextAccept(_)),
            "activation {i} should succeed, got {pdu:?}"
        );
    }
    // 12th attempt (different SSI)
    let msg = activate(&mut sndcp, &mut queue, 99_999, demand_dynamic(3))
        .expect("no response on exhausted");
    let req = unwrap_req(msg);
    let pdu = decode_dl(&req);
    let reject = match pdu {
        SnPdu::ActivatePdpContextReject(r) => r,
        other => panic!("expected REJECT for exhausted pool, got {other:?}"),
    };
    assert_eq!(reject.reject_cause, RejectCause::NoResource);
}

/// 5. Deactivate demand frees IP and removes context.
#[test]
fn deactivate_demand_frees_ip_and_removes_context() {
    let (mut sndcp, mut queue) = make_sndcp();
    // Activate
    let msg = activate(&mut sndcp, &mut queue, 5001, demand_dynamic(3)).expect("no ACCEPT");
    let ip = match decode_dl(&unwrap_req(msg)) {
        SnPdu::ActivatePdpContextAccept(a) => a.ip4_address.expect("no ip"),
        other => panic!("expected ACCEPT, got {other:?}"),
    };

    // Send DEACTIVATE DEMAND
    let deact = DeactivatePdpContextDemand {
        deactivation_type: DeactivationType::Normal,
        nsapi: Nsapi(3),
        snei: None,
    };
    let sdu = with_discriminator(&encode_deactivate_demand(&deact));
    sndcp.rx_prim(&mut queue, make_ind(sdu, 5001));
    let msg = queue.pop_front().expect("no DEACTIVATE ACCEPT");
    let pdu = decode_dl(&unwrap_req(msg));
    assert!(matches!(pdu, SnPdu::DeactivatePdpContextAccept(_)), "expected DEACT ACCEPT, got {pdu:?}");

    // The IP should now be free: try static re-allocation
    let demand2 = ActivatePdpContextDemand {
        sndcp_version: 0,
        nsapi: Nsapi(3),
        atid: 0, // static
        ip_address: Some(ip),
        pdms_type: PdmsType::Standard,
        pcomp_negotiation: 0,
        vj_slots: None,
        snei: None,
        apn: None,
        pco: None,
    };
    let msg2 = activate(&mut sndcp, &mut queue, 5002, demand2).expect("no response after re-alloc");
    let pdu2 = decode_dl(&unwrap_req(msg2));
    assert!(
        matches!(pdu2, SnPdu::ActivatePdpContextAccept(_)),
        "static re-alloc of freed IP should succeed, got {pdu2:?}"
    );
}

/// 6. Uplink SN-UNITDATA pushes payload to `uplink_ip_queue`.
#[test]
fn uplink_unitdata_pushes_to_gateway_queue() {
    let (mut sndcp, mut queue) = make_sndcp();
    activate(&mut sndcp, &mut queue, 6001, demand_dynamic(3)).expect("no ACCEPT");
    drain_queue(&mut queue); // discard ACCEPT

    let payload = vec![0x45u8, 0x00, 0x00, 0x14, 0x00, 0x01, 0x00, 0x00];
    let ud = Unitdata { nsapi: Nsapi(3), pdu_priority: 0, payload: payload.clone() };
    let sdu = with_discriminator(&encode_unitdata(&ud));
    sndcp.rx_prim(&mut queue, make_ind(sdu, 6001));

    // Uplink UNITDATA should NOT produce any downlink messages
    let msgs = drain_queue(&mut queue);
    assert!(msgs.is_empty(), "uplink UNITDATA should not produce downlink messages");

    let ul = sndcp.uplink_ip_queue.pop_front().expect("no uplink in gateway queue");
    assert_eq!(ul.payload, payload);
    assert_eq!(ul.nsapi, 3);
}

/// 7. `feed_downlink_ip` in Ready state → SN-UNITDATA sent downward.
#[test]
fn downlink_ip_when_ready_sends_unitdata() {
    let (mut sndcp, mut queue) = make_sndcp();
    let msg = activate(&mut sndcp, &mut queue, 7001, demand_dynamic(4)).expect("no ACCEPT");
    let ip = match decode_dl(&unwrap_req(msg)) {
        SnPdu::ActivatePdpContextAccept(a) => a.ip4_address.unwrap(),
        other => panic!("expected ACCEPT, got {other:?}"),
    };

    let payload = vec![0xDE, 0xAD, 0xBE, 0xEF];
    sndcp.feed_downlink_ip(&mut queue, GatewayDownlink { dest_ipv4: ip, payload: payload.clone() });

    let msg = queue.pop_front().expect("no downlink UNITDATA");
    let req = unwrap_req(msg);
    assert_eq!(req.layer2service, Layer2Service::Unacknowledged);
    assert!(req.packet_data_flag);
    let pdu = decode_dl(&req);
    match pdu {
        SnPdu::Unitdata(u) => {
            assert_eq!(u.payload, payload);
            assert_eq!(u.nsapi.0, 4);
        }
        other => panic!("expected UNITDATA, got {other:?}"),
    }
}

/// 8. `feed_downlink_ip` when Standby → SN-PAGE REQUEST sent + payload queued.
#[test]
fn downlink_ip_when_standby_sends_page_request() {
    let (mut sndcp, mut queue) = make_sndcp();
    let msg = activate(&mut sndcp, &mut queue, 8001, demand_dynamic(5)).expect("no ACCEPT");
    let ip = match decode_dl(&unwrap_req(msg)) {
        SnPdu::ActivatePdpContextAccept(a) => a.ip4_address.unwrap(),
        other => panic!("expected ACCEPT, got {other:?}"),
    };

    // Transition to Standby via SN-END OF DATA
    let eod = EndOfData { nsapi: Nsapi(5) };
    sndcp.rx_prim(&mut queue, make_ind(with_discriminator(&encode_end_of_data(&eod)), 8001));
    drain_queue(&mut queue); // END OF DATA produces no output

    // Feed downlink IP while Standby
    let payload = vec![0xCA, 0xFE];
    sndcp.feed_downlink_ip(&mut queue, GatewayDownlink { dest_ipv4: ip, payload: payload.clone() });

    let msg = queue.pop_front().expect("no PAGE REQUEST");
    let req = unwrap_req(msg);
    assert_eq!(req.layer2service, Layer2Service::Acknowledged, "PAGE REQUEST should be Ack");
    assert!(!req.packet_data_flag);
    let pdu = decode_dl(&req);
    match pdu {
        SnPdu::PageRequest(pr) => assert_eq!(pr.nsapi.0, 5),
        other => panic!("expected PAGE REQUEST, got {other:?}"),
    }
    // Payload should be queued, no UNITDATA yet
    assert!(queue.pop_front().is_none(), "UNITDATA should not be sent before PAGE RESPONSE");
}

/// 9. SN-PAGE RESPONSE drains the queued downlink payload as SN-UNITDATA.
#[test]
fn page_response_drains_queued_downlink() {
    let (mut sndcp, mut queue) = make_sndcp();
    let msg = activate(&mut sndcp, &mut queue, 9001, demand_dynamic(6)).expect("no ACCEPT");
    let ip = match decode_dl(&unwrap_req(msg)) {
        SnPdu::ActivatePdpContextAccept(a) => a.ip4_address.unwrap(),
        other => panic!("expected ACCEPT, got {other:?}"),
    };

    // Transition to Standby
    let eod = EndOfData { nsapi: Nsapi(6) };
    sndcp.rx_prim(&mut queue, make_ind(with_discriminator(&encode_end_of_data(&eod)), 9001));
    drain_queue(&mut queue);

    // Queue two downlink payloads
    let payload1 = vec![0x01u8, 0x02];
    let payload2 = vec![0x03u8, 0x04];
    sndcp.feed_downlink_ip(&mut queue, GatewayDownlink { dest_ipv4: ip, payload: payload1.clone() });
    drain_queue(&mut queue); // discard PAGE REQUEST
    // Second downlink arrives in WaitForPageResponse state
    sndcp.feed_downlink_ip(&mut queue, GatewayDownlink { dest_ipv4: ip, payload: payload2.clone() });
    assert!(queue.pop_front().is_none(), "second downlink should be queued only, no output");

    // Feed PAGE RESPONSE → both payloads should be flushed as UNITDATA
    let pr = PageResponse { nsapi: Nsapi(6) };
    sndcp.rx_prim(&mut queue, make_ind(with_discriminator(&encode_page_response(&pr)), 9001));

    let msgs = drain_queue(&mut queue);
    assert_eq!(msgs.len(), 2, "expected 2 UNITDATA PDUs, got {}", msgs.len());
    let payloads: Vec<Vec<u8>> = msgs
        .into_iter()
        .map(|m| match decode_dl(&unwrap_req(m)) {
            SnPdu::Unitdata(u) => u.payload,
            other => panic!("expected UNITDATA, got {other:?}"),
        })
        .collect();
    assert_eq!(payloads[0], payload1);
    assert_eq!(payloads[1], payload2);
}

/// 10. Retransmitted identical DEMAND returns cached ACCEPT bits verbatim.
#[test]
fn retransmitted_demand_returns_cached_accept_verbatim() {
    let (mut sndcp, mut queue) = make_sndcp();
    let demand = demand_dynamic(7);

    let msg1 = activate(&mut sndcp, &mut queue, 10001, demand.clone()).expect("no first ACCEPT");
    let req1 = unwrap_req(msg1);
    let mut bits1 = req1.sdu.clone();
    bits1.seek(0);
    let bitstr1 = bits1.to_bitstr();

    // Re-send the same DEMAND
    let sdu = with_discriminator(&encode_demand(&demand));
    sndcp.rx_prim(&mut queue, make_ind(sdu, 10001));
    let msg2 = queue.pop_front().expect("no second ACCEPT");
    let req2 = unwrap_req(msg2);
    let mut bits2 = req2.sdu.clone();
    bits2.seek(0);
    let bitstr2 = bits2.to_bitstr();

    assert_eq!(bitstr1, bitstr2, "retransmitted ACCEPT should be bit-for-bit identical");
}

/// 11. An unrecognised SN-PDU type (SN-DATA, type 5) is dropped without panic.
#[test]
fn unknown_pdu_type_dropped_without_panic() {
    let (mut sndcp, mut queue) = make_sndcp();
    // type=5 (SN-DATA=0b0101), rest zeroed — results in SnPdu::Unhandled
    let mut sn_bits = BitBuffer::new_autoexpand(16);
    sn_bits.write_bits(0b0101, 4); // SN-DATA type (type=5)
    sn_bits.write_bits(0, 12);     // padding
    sn_bits.seek(0);
    let sdu = with_discriminator(&sn_bits);

    sndcp.rx_prim(&mut queue, make_ind(sdu, 11001));
    assert!(queue.pop_front().is_none(), "unhandled PDU type should not produce output");
}