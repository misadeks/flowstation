/// PD-5c-H12: MLE BS uplink routing for `TlaTlDataIndAl`.
///
/// Verifies that when LLC delivers an assembled Advanced-Link SDU to MLE,
/// MLE reads the 3-bit MLE protocol discriminator and forwards the
/// remaining bits to the correct downstream entity — mirroring the BL
/// path. Prior to this fix, `TlaTlDataIndAl` hit the catch-all in
/// `rx_tla_prim` and produced `BUG: unexpected message or state -- routing
/// error`, silently dropping every AL-assembled uplink SDU.
mod common;

use tetra_config::bluestation::{SharedConfig, StackMode};
use tetra_core::tetra_entities::TetraEntity;
use tetra_core::{BitBuffer, Sap, SsiType, TetraAddress};
use tetra_entities::mle::mle_bs::MleBs;
use tetra_entities::{MessageQueue, TetraEntityTrait};
use tetra_saps::sapmsg::{SapMsg, SapMsgInner};
use tetra_saps::tla::TlaTlDataIndAl;

const SSI: u32 = 1234567;
const LINK_ID: u32 = 0;
const ENDPOINT_ID: u32 = 0;
const AL_LINK_NUMBER: u8 = 1;

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

/// Builds a TL-SDU beginning with the 3-bit SNDCP MLE discriminator (0b100)
/// followed by an arbitrary payload.
fn build_sndcp_al_sdu(payload: &str) -> BitBuffer {
    let mut s = String::from("100"); // MleProtocolDiscriminator::Sndcp
    s.push_str(payload);
    BitBuffer::from_bitstr(&s)
}

/// H12 core assertion: TlaTlDataIndAl with SNDCP discriminator produces
/// exactly one LtpdMleUnitdataInd, routed on TlpdSap to the SNDCP entity,
/// with the discriminator stripped and all identity fields preserved.
#[test]
fn al_data_ind_sndcp_routes_to_ltpd() {
    let (mut mle, mut queue) = make_mle();

    let payload = "0110001110101"; // arbitrary SN-PDU body bits
    let sdu = build_sndcp_al_sdu(payload);

    let prim = TlaTlDataIndAl {
        main_address: test_addr(),
        link_id: LINK_ID,
        endpoint_id: ENDPOINT_ID,
        al_link_number: AL_LINK_NUMBER,
        tl_sdu: sdu,
        subscriber_class: 0,
        fcs_ok: true,
        air_interface_encryption: None,
    };
    let sapmsg = SapMsg {
        sap: Sap::TlaSap,
        src: TetraEntity::Llc,
        dest: TetraEntity::Mle,
        msg: SapMsgInner::TlaTlDataIndAl(prim),
    };

    mle.rx_prim(&mut queue, sapmsg);

    let msg = queue.pop_front().expect("expected one message in queue");
    assert!(queue.pop_front().is_none(), "expected exactly one message");

    assert_eq!(msg.sap, Sap::TlpdSap);
    assert_eq!(msg.src, TetraEntity::Mle);
    assert_eq!(msg.dest, TetraEntity::Sndcp);

    let SapMsgInner::LtpdMleUnitdataInd(ind) = msg.msg else {
        panic!("expected LtpdMleUnitdataInd, got a different variant");
    };
    assert_eq!(ind.received_tetra_address, test_addr());
    assert_eq!(ind.link_id, LINK_ID);
    assert_eq!(ind.endpoint_id, ENDPOINT_ID);

    // Discriminator has been consumed (position advanced past it); the rest
    // of the buffer should be the untouched SN-PDU body.
    let mut sdu_out = ind.sdu;
    assert_eq!(sdu_out.get_pos(), 3, "position should be past the 3-bit discriminator");
    let payload_bits = sdu_out.read_bits(payload.len()).expect("payload bits");
    let expected = u64::from_str_radix(payload, 2).unwrap();
    assert_eq!(payload_bits, expected);
}

/// Defensive check: an AL Ind with `fcs_ok = false` is dropped, not
/// forwarded. LLC currently drops FCS failures before emitting the Ind, so
/// this branch primarily guards against future regressions.
#[test]
fn al_data_ind_with_fcs_failure_is_dropped() {
    let (mut mle, mut queue) = make_mle();

    let prim = TlaTlDataIndAl {
        main_address: test_addr(),
        link_id: LINK_ID,
        endpoint_id: ENDPOINT_ID,
        al_link_number: AL_LINK_NUMBER,
        tl_sdu: build_sndcp_al_sdu("0110001110101"),
        subscriber_class: 0,
        fcs_ok: false,
        air_interface_encryption: None,
    };
    let sapmsg = SapMsg {
        sap: Sap::TlaSap,
        src: TetraEntity::Llc,
        dest: TetraEntity::Mle,
        msg: SapMsgInner::TlaTlDataIndAl(prim),
    };

    mle.rx_prim(&mut queue, sapmsg);
    assert!(queue.pop_front().is_none(), "no messages should be emitted for FCS failure");
}

/// PD-5c-H13: MLE must populate `LtpdMleUnitdataInd.al_link_number` from the
/// AL primitive so SNDCP can learn which Advanced Link to route downlink
/// SN-DATA back on. Prior to H13 this flag did not exist; downlink stayed on
/// the BL captured at ACTIVATE DEMAND and the MS ignored the reply.
#[test]
fn al_ind_populates_al_link_number_in_ltpd() {
    let (mut mle, mut queue) = make_mle();

    let prim = TlaTlDataIndAl {
        main_address: test_addr(),
        link_id: 4,
        endpoint_id: 0,
        al_link_number: 4,
        tl_sdu: build_sndcp_al_sdu("0110001110101"),
        subscriber_class: 0,
        fcs_ok: true,
        air_interface_encryption: None,
    };
    let sapmsg = SapMsg {
        sap: Sap::TlaSap,
        src: TetraEntity::Llc,
        dest: TetraEntity::Mle,
        msg: SapMsgInner::TlaTlDataIndAl(prim),
    };

    mle.rx_prim(&mut queue, sapmsg);

    let msg = queue.pop_front().expect("expected LtpdMleUnitdataInd");
    let SapMsgInner::LtpdMleUnitdataInd(ind) = msg.msg else {
        panic!("expected LtpdMleUnitdataInd variant");
    };
    assert_eq!(ind.al_link_number, Some(4));
    assert_eq!(ind.link_id, 4);
    assert_eq!(ind.endpoint_id, 0);
}

/// PD-5c-H13: the BL path must leave `al_link_number` as `None` so SNDCP
/// keeps using the BL tuple captured at ACTIVATE DEMAND.
#[test]
fn bl_ind_leaves_al_link_number_none() {
    use tetra_saps::tla::TlaTlDataIndBl;

    let (mut mle, mut queue) = make_mle();

    let prim = TlaTlDataIndBl {
        main_address: test_addr(),
        link_id: 1,
        endpoint_id: 0,
        new_endpoint_id: None,
        css_endpoint_id: None,
        tl_sdu: Some(build_sndcp_al_sdu("0110001110101")),
        scrambling_code: 0,
        fcs_flag: true,
        air_interface_encryption: 0,
        chan_change_resp_req: false,
        chan_change_handle: None,
        chan_info: None,
        req_handle: 0,
    };
    let sapmsg = SapMsg {
        sap: Sap::TlaSap,
        src: TetraEntity::Llc,
        dest: TetraEntity::Mle,
        msg: SapMsgInner::TlaTlDataIndBl(prim),
    };

    mle.rx_prim(&mut queue, sapmsg);

    let msg = queue.pop_front().expect("expected LtpdMleUnitdataInd");
    let SapMsgInner::LtpdMleUnitdataInd(ind) = msg.msg else {
        panic!("expected LtpdMleUnitdataInd variant");
    };
    assert_eq!(ind.al_link_number, None);
    assert_eq!(ind.link_id, 1);
}
