/// MLE BS TL-PD SAP downlink handler tests (PD-3).
///
/// Tests the `rx_tlpd_prim` handler implemented in `mle_bs.rs`.
/// Each test instantiates `MleBs` directly (without ComponentTest) so the
/// outbound message queue can be inspected without routing overhead.
///
/// Pattern:
///   1. Build `MleBs` directly via `MleBs::new(shared_config)`.
///   2. Construct a `LtpdMleUnitdataReq` wrapped in a `SapMsg` on `TlpdSap`.
///   3. Call `mle.rx_prim(&mut queue, sapmsg)`.
///   4. Inspect `queue` for the expected downstream TLA primitive.
mod common;

use tetra_config::bluestation::{SharedConfig, StackMode};
use tetra_core::tetra_entities::TetraEntity;
use tetra_core::{BitBuffer, Layer2Service, Sap, SsiType, TetraAddress};
use tetra_entities::mle::mle_bs::MleBs;
use tetra_entities::{MessageQueue, TetraEntityTrait};
use tetra_saps::ltpd::LtpdMleUnitdataReq;
use tetra_saps::sapmsg::{SapMsg, SapMsgInner};

const SSI: u32 = 1234567;
const LINK_ID: u32 = 0;
const ENDPOINT_ID: u32 = 0;

fn test_addr() -> TetraAddress {
    TetraAddress::new(SSI, SsiType::Issi)
}

fn make_mle() -> (MleBs, MessageQueue) {
    let config = common::ComponentTest::get_default_test_config(StackMode::Bs);
    let shared_config = SharedConfig::from_parts(config, None);
    let mle = MleBs::new(shared_config);
    let queue = MessageQueue::new();
    (mle, queue)
}

/// Test 1: Unacknowledged layer2service produces TlaTlUnitdataReqBl with SNDCP
/// discriminator prepended (0b100 = bits "100") followed by the SDU bits.
#[test]
fn tlpd_unacknowledged_produces_bl_unitdata_req_with_discriminator() {
    let (mut mle, mut queue) = make_mle();

    let sdu = BitBuffer::from_bitstr("01010101");
    let prim = LtpdMleUnitdataReq {
        main_address: test_addr(),
        link_id: LINK_ID,
        endpoint_id: ENDPOINT_ID,
        sdu,
        layer2service: Layer2Service::Unacknowledged,
        packet_data_flag: true,
        air_interface_encryption: None,
        tx_reporter: None,
        chan_alloc: None,
        al_link_number: None,
    };
    let sapmsg = SapMsg {
        sap: Sap::TlpdSap,
        src: TetraEntity::Sndcp,
        dest: TetraEntity::Mle,
        msg: SapMsgInner::LtpdMleUnitdataReq(prim),
    };

    mle.rx_prim(&mut queue, sapmsg);

    // Expect exactly one message forwarded to LLC
    let msg = queue.pop_front().expect("expected one message in queue");
    assert!(queue.pop_front().is_none(), "expected exactly one message");

    let SapMsgInner::TlaTlUnitdataReqBl(out) = msg.msg else {
        panic!("expected TlaTlUnitdataReqBl, got something else");
    };

    // Verify routing
    assert_eq!(msg.sap, Sap::TlaSap);
    assert_eq!(msg.dest, TetraEntity::Llc);
    assert_eq!(msg.src, TetraEntity::Mle);

    // Verify packet_data_flag is threaded through
    assert!(out.packet_data_flag);

    // Verify the tl_sdu starts with the 3-bit SNDCP discriminator (0b100) then the SDU
    let mut tl_sdu = out.tl_sdu;
    tl_sdu.seek(0);
    let discriminator = tl_sdu.read_bits(3).expect("should have 3 discriminator bits");
    assert_eq!(discriminator, 0b100, "SNDCP discriminator must be 0b100");
    // Read the remaining 8 SDU bits
    let sdu_bits = tl_sdu.read_bits(8).expect("should have 8 SDU bits");
    assert_eq!(sdu_bits, 0b01010101, "SDU bits should follow discriminator unchanged");
}

/// Test 2: Acknowledged layer2service produces TlaTlDataReqBl with SNDCP
/// discriminator prepended.
#[test]
fn tlpd_acknowledged_produces_bl_data_req_with_discriminator() {
    let (mut mle, mut queue) = make_mle();

    let sdu = BitBuffer::from_bitstr("01010101");
    let prim = LtpdMleUnitdataReq {
        main_address: test_addr(),
        link_id: LINK_ID,
        endpoint_id: ENDPOINT_ID,
        sdu,
        layer2service: Layer2Service::Acknowledged,
        packet_data_flag: false,
        air_interface_encryption: None,
        tx_reporter: None,
        chan_alloc: None,
        al_link_number: None,
    };
    let sapmsg = SapMsg {
        sap: Sap::TlpdSap,
        src: TetraEntity::Sndcp,
        dest: TetraEntity::Mle,
        msg: SapMsgInner::LtpdMleUnitdataReq(prim),
    };

    mle.rx_prim(&mut queue, sapmsg);

    let msg = queue.pop_front().expect("expected one message in queue");
    assert!(queue.pop_front().is_none(), "expected exactly one message");

    let SapMsgInner::TlaTlDataReqBl(out) = msg.msg else {
        panic!("expected TlaTlDataReqBl, got something else");
    };

    // Verify routing
    assert_eq!(msg.sap, Sap::TlaSap);
    assert_eq!(msg.dest, TetraEntity::Llc);
    assert_eq!(msg.src, TetraEntity::Mle);

    // Verify the tl_sdu starts with the 3-bit SNDCP discriminator (0b100) then the SDU
    let mut tl_sdu = out.tl_sdu;
    tl_sdu.seek(0);
    let discriminator = tl_sdu.read_bits(3).expect("should have 3 discriminator bits");
    assert_eq!(discriminator, 0b100, "SNDCP discriminator must be 0b100");
    let sdu_bits = tl_sdu.read_bits(8).expect("should have 8 SDU bits");
    assert_eq!(sdu_bits, 0b01010101, "SDU bits should follow discriminator unchanged");
}

/// Test 3: A SapMsg on TlpdSap carrying an unexpected SapMsgInner variant is
/// dropped silently (queue stays empty; no panic).
#[test]
fn tlpd_wrong_variant_drops_with_error_log() {
    let (mut mle, mut queue) = make_mle();

    // Feed a TlpdSap message with a non-LtpdMleUnitdataReq inner variant.
    // Use LtpdMleUnitdataInd as a stand-in for "wrong direction" / wrong variant.
    use tetra_saps::ltpd::LtpdMleUnitdataInd;
    let wrong_prim = LtpdMleUnitdataInd {
        sdu: BitBuffer::from_bitstr("0000"),
        endpoint_id: ENDPOINT_ID,
        link_id: LINK_ID,
        received_tetra_address: test_addr(),
        chan_change_resp_req: false,
        chan_change_handle: None,
        al_link_number: None,
    };
    let sapmsg = SapMsg {
        sap: Sap::TlpdSap,
        src: TetraEntity::Llc,
        dest: TetraEntity::Mle,
        msg: SapMsgInner::LtpdMleUnitdataInd(wrong_prim),
    };

    mle.rx_prim(&mut queue, sapmsg);

    assert!(queue.pop_front().is_none(), "queue must be empty after wrong variant");
}

/// PD-5c-H14: Acknowledged + packet_data_flag + `al_link_number: Some(n)`
/// (populated by SNDCP after learning the MS's AL from an uplink AL frame,
/// H13) must route the downlink onto `TlaTlDataReqAl` so LLC segments as
/// AL-DATA on the correct N.261 link. Prior to H14 this dropped to BL-DATA
/// and the MS's AL peer ignored it.
#[test]
fn tlpd_acknowledged_pd_with_al_link_produces_tla_data_req_al() {
    let (mut mle, mut queue) = make_mle();

    let sdu = BitBuffer::from_bitstr("11110000");
    let prim = LtpdMleUnitdataReq {
        main_address: test_addr(),
        link_id: 4,
        endpoint_id: 0,
        sdu,
        layer2service: Layer2Service::Acknowledged,
        packet_data_flag: true,
        air_interface_encryption: None,
        tx_reporter: None,
        chan_alloc: None,
        al_link_number: Some(2),
    };
    let sapmsg = SapMsg {
        sap: Sap::TlpdSap,
        src: TetraEntity::Sndcp,
        dest: TetraEntity::Mle,
        msg: SapMsgInner::LtpdMleUnitdataReq(prim),
    };

    mle.rx_prim(&mut queue, sapmsg);

    let msg = queue.pop_front().expect("expected one message in queue");
    assert!(queue.pop_front().is_none(), "expected exactly one message");

    let SapMsgInner::TlaTlDataReqAl(out) = msg.msg else {
        panic!("H14: expected TlaTlDataReqAl, got {:?}", msg.msg);
    };

    assert_eq!(msg.sap, Sap::TlaSap);
    assert_eq!(msg.dest, TetraEntity::Llc);
    assert_eq!(msg.src, TetraEntity::Mle);
    assert_eq!(out.link_id, 4);
    assert_eq!(out.endpoint_id, 0);
    assert_eq!(out.al_link_number, 2, "N.261 index must be forwarded to LLC");

    // Discriminator + SDU bits are preserved on the AL path.
    let mut tl_sdu = out.tl_sdu;
    tl_sdu.seek(0);
    let discriminator = tl_sdu.read_bits(3).expect("3 discriminator bits");
    assert_eq!(discriminator, 0b100, "SNDCP discriminator must be 0b100");
    let sdu_bits = tl_sdu.read_bits(8).expect("8 SDU bits");
    assert_eq!(sdu_bits, 0b11110000);
}

/// PD-5c-H14: Acknowledged + packet_data_flag but `al_link_number: None`
/// (SNDCP has not yet learned an AL for this MS) must fall back to
/// `TlaTlDataReqBl`. This keeps the pre-AL-learn flow (SN-ACTIVATE / PAGE
/// REQUEST replies) intact on BL where the MS is monitoring.
#[test]
fn tlpd_acknowledged_pd_without_al_link_stays_bl() {
    let (mut mle, mut queue) = make_mle();

    let prim = LtpdMleUnitdataReq {
        main_address: test_addr(),
        link_id: 4,
        endpoint_id: 0,
        sdu: BitBuffer::from_bitstr("10101010"),
        layer2service: Layer2Service::Acknowledged,
        packet_data_flag: true,
        air_interface_encryption: None,
        tx_reporter: None,
        chan_alloc: None,
        al_link_number: None,
    };
    let sapmsg = SapMsg {
        sap: Sap::TlpdSap,
        src: TetraEntity::Sndcp,
        dest: TetraEntity::Mle,
        msg: SapMsgInner::LtpdMleUnitdataReq(prim),
    };

    mle.rx_prim(&mut queue, sapmsg);
    let msg = queue.pop_front().expect("expected one message in queue");
    assert!(matches!(msg.msg, SapMsgInner::TlaTlDataReqBl(_)),
        "H14: without al_link_number, must stay on BL-DATA");
}

/// PD-5c-H14: Acknowledged + `al_link_number: Some(_)` but `packet_data_flag:
/// false` (e.g. hypothetical CMCE/MM ack traffic) must NOT route onto AL —
/// only packet-data SN-DATA rides the Advanced Link in the H14 design.
#[test]
fn tlpd_acknowledged_non_pd_stays_bl() {
    let (mut mle, mut queue) = make_mle();

    let prim = LtpdMleUnitdataReq {
        main_address: test_addr(),
        link_id: 4,
        endpoint_id: 0,
        sdu: BitBuffer::from_bitstr("00001111"),
        layer2service: Layer2Service::Acknowledged,
        packet_data_flag: false,
        air_interface_encryption: None,
        tx_reporter: None,
        chan_alloc: None,
        al_link_number: Some(2),
    };
    let sapmsg = SapMsg {
        sap: Sap::TlpdSap,
        src: TetraEntity::Sndcp,
        dest: TetraEntity::Mle,
        msg: SapMsgInner::LtpdMleUnitdataReq(prim),
    };

    mle.rx_prim(&mut queue, sapmsg);
    let msg = queue.pop_front().expect("expected one message in queue");
    assert!(matches!(msg.msg, SapMsgInner::TlaTlDataReqBl(_)),
        "H14: without packet_data_flag, must stay on BL-DATA even if al_link_number is set");
}
