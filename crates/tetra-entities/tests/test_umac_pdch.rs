/// PD-5: Packet Data Channel (PDCH) allocator tests.
///
/// All PDCH code paths in UmacBs are gated behind `packet_data_enabled`.
/// These tests flip that flag via `set_packet_data_enabled_for_test` so
/// the production default (false) is not disturbed.
mod common;

use tetra_config::bluestation::StackMode;
use tetra_core::{BitBuffer, Sap, SsiType, TdmaTime, TetraAddress, debug};
use tetra_core::tetra_entities::TetraEntity;
use tetra_entities::umac::umac_bs::UmacBs;
use tetra_pdus::umac::pdus::d_channel_alloc_broadcast::DChannelAllocationBroadcast;
use tetra_saps::sapmsg::{SapMsg, SapMsgInner};
use tetra_saps::tla::{TlaTlUnitdataReqBl};
use tetra_saps::tma::TmaUnitdataReq;

use crate::common::ComponentTest;

const MAIN_CARRIER: u16 = 1521;

fn issi_addr(ssi: u32) -> TetraAddress {
    TetraAddress { ssi, ssi_type: SsiType::Issi }
}

/// Helper: create a `TmaUnitdataReq` with `packet_data_flag = true` pointing at `issi`.
fn make_pdch_unitdata_req(issi: u32) -> TmaUnitdataReq {
    TmaUnitdataReq {
        req_handle: 0,
        pdu: BitBuffer::from_bitstr("1010101010101010"),
        main_address: issi_addr(issi),
        link_id: 0,
        endpoint_id: 0,
        stealing_permission: false,
        subscriber_class: 0,
        air_interface_encryption: None,
        stealing_repeats_flag: None,
        data_category: None,
        carrier_num: Some(MAIN_CARRIER),
        chan_alloc: None,
        tx_reporter: None,
        packet_data_flag: true,
    }
}

// ── test 1 ────────────────────────────────────────────────────────────────────
/// With packet_data_enabled = false (the default), ticking a hyperframe
/// must never produce a D-CHANNEL-ALLOCATION-BROADCAST.
#[test]
fn default_off_scheduler_behaviour_matches_today() {
    debug::setup_logging_verbose();

    let mut test = ComponentTest::new(StackMode::Bs, Some(TdmaTime { h: 0, m: 1, f: 1, t: 1 }));
    test.populate_entities(vec![TetraEntity::Umac], vec![TetraEntity::Lmac]);

    // Do NOT enable PDCH — leave at default (false).

    // Run one full hyperframe (60 multiframes × 18 frames × 4 timeslots).
    test.run_stack(Some(60 * 18 * 4));

    // Inspect the UmacBs entity directly; broadcast_pending must remain None.
    let umac = test
        .router
        .get_entity(TetraEntity::Umac)
        .expect("UMAC not found")
        .as_any_mut()
        .downcast_mut::<UmacBs>()
        .expect("downcast to UmacBs");

    assert!(
        umac.pdch_aach_broadcast_pending.is_none(),
        "D-CHANNEL-ALLOCATION-BROADCAST must not be emitted when packet_data_enabled = false"
    );
}

// ── test 2 ────────────────────────────────────────────────────────────────────
/// With packet_data_enabled = true, ticking to frame 1 of the first multiframe
/// must cause a D-CHANNEL-ALLOCATION-BROADCAST to be staged in
/// `pdch_aach_broadcast_pending`, and that buffer must decode to valid fields.
#[test]
fn pdch_broadcast_emitted_when_enabled() {
    debug::setup_logging_verbose();

    // Start at timeslot 1 of frame 1 so the first tick hits the broadcast gate.
    let mut test = ComponentTest::new(StackMode::Bs, Some(TdmaTime { h: 0, m: 1, f: 1, t: 1 }));
    test.populate_entities(vec![TetraEntity::Umac], vec![TetraEntity::Lmac]);

    // Enable PDCH.
    {
        let umac = test
            .router
            .get_entity(TetraEntity::Umac)
            .expect("UMAC not found")
            .as_any_mut()
            .downcast_mut::<UmacBs>()
            .expect("downcast to UmacBs");
        umac.set_packet_data_enabled_for_test(true);
    }

    // Run enough ticks to hit t=1, f=1 (which should already be frame 1 of the
    // run, so 1 tick into the scheduler triggers the broadcast gate).
    // The broadcast gate fires at ts.t == 1 && ts.f == 1, but run_stack advances
    // the clock from the start_dl_time. Start at t=1, f=1, so 1 tick = that slot.
    test.run_stack(Some(1));

    let umac = test
        .router
        .get_entity(TetraEntity::Umac)
        .expect("UMAC not found")
        .as_any_mut()
        .downcast_mut::<UmacBs>()
        .expect("downcast to UmacBs");

    // The broadcast must have been staged.
    assert!(
        umac.pdch_aach_broadcast_pending.is_some(),
        "D-CHANNEL-ALLOCATION-BROADCAST must be staged when packet_data_enabled = true and t=1,f=1"
    );

    // Decode it and verify the fields.
    let mut buf = umac
        .pdch_aach_broadcast_pending
        .take()
        .expect("buffer exists");
    let pdu = DChannelAllocationBroadcast::from_bitbuf(&mut buf)
        .expect("D-CHANNEL-ALLOCATION-BROADCAST must parse without error");

    // TS4 = index 3 per spec scope decision.
    // NOTE: spec ambiguous — chosen behaviour: TS4 (index 3) reserved for PDCH.
    assert_eq!(pdu.timeslot, 3, "PDCH must be on TS4 (index 3)");
    // Encoding 0 = π/4-DQPSK.
    assert_eq!(pdu.encoding, 0, "encoding must be 0 (π/4-DQPSK)");
    // Bandwidth 0 = 25 kHz.
    assert_eq!(pdu.channel_bandwidth, 0, "bandwidth must be 0 (25 kHz)");
}

// ── test 3 ────────────────────────────────────────────────────────────────────
/// Feeding a `TmaUnitdataReq { packet_data_flag: true }` to UMAC must create
/// a PDCH reservation for the source ISSI.
#[test]
fn pdch_allocator_reserves_on_first_uplink() {
    debug::setup_logging_verbose();

    const TEST_ISSI: u32 = 1234;

    let mut test = ComponentTest::new(StackMode::Bs, Some(TdmaTime { h: 0, m: 1, f: 1, t: 1 }));
    test.populate_entities(vec![TetraEntity::Umac], vec![TetraEntity::Lmac]);

    // Enable PDCH.
    {
        let umac = test
            .router
            .get_entity(TetraEntity::Umac)
            .expect("UMAC")
            .as_any_mut()
            .downcast_mut::<UmacBs>()
            .expect("downcast");
        umac.set_packet_data_enabled_for_test(true);
    }

    // Submit a packet-data unitdata request.
    test.submit_message(SapMsg {
        sap: Sap::TmaSap,
        src: TetraEntity::Llc,
        dest: TetraEntity::Umac,
        msg: SapMsgInner::TmaUnitdataReq(make_pdch_unitdata_req(TEST_ISSI)),
    });
    test.run_stack(Some(1));

    let umac = test
        .router
        .get_entity(TetraEntity::Umac)
        .expect("UMAC")
        .as_any_mut()
        .downcast_mut::<UmacBs>()
        .expect("downcast");

    assert!(
        umac.pdch_allocator().reservations.contains_key(&TEST_ISSI),
        "PDCH allocator must have a reservation for ISSI={TEST_ISSI} after packet-data uplink"
    );
    assert_eq!(
        umac.pdch_allocator().reservations[&TEST_ISSI].nsapi,
        0,
        "NSAPI must be 0 (default for PD-5)"
    );
}

// ── test 4 ────────────────────────────────────────────────────────────────────
/// A reservation that has been idle for more than PDCH_IDLE_RELEASE_FRAMES
/// frames must be released on the next tick.
#[test]
fn pdch_allocator_releases_after_idle() {
    debug::setup_logging_verbose();

    use tetra_entities::umac::subcomp::pdch_allocator::PDCH_IDLE_RELEASE_FRAMES;

    const TEST_ISSI: u32 = 5678;

    // Start at a known time.
    let start = TdmaTime { h: 0, m: 1, f: 1, t: 1 };
    let mut test = ComponentTest::new(StackMode::Bs, Some(start));
    test.populate_entities(vec![TetraEntity::Umac], vec![TetraEntity::Lmac]);

    // Enable PDCH.
    {
        let umac = test
            .router
            .get_entity(TetraEntity::Umac)
            .expect("UMAC")
            .as_any_mut()
            .downcast_mut::<UmacBs>()
            .expect("downcast");
        umac.set_packet_data_enabled_for_test(true);
    }

    // Submit a packet-data uplink so a reservation is created.
    test.submit_message(SapMsg {
        sap: Sap::TmaSap,
        src: TetraEntity::Llc,
        dest: TetraEntity::Umac,
        msg: SapMsgInner::TmaUnitdataReq(make_pdch_unitdata_req(TEST_ISSI)),
    });
    // One tick to process the uplink message.
    test.run_stack(Some(1));

    // Confirm reservation created.
    {
        let umac = test
            .router
            .get_entity(TetraEntity::Umac)
            .expect("UMAC")
            .as_any_mut()
            .downcast_mut::<UmacBs>()
            .expect("downcast");
        assert!(
            umac.pdch_allocator().reservations.contains_key(&TEST_ISSI),
            "reservation must exist after uplink"
        );
    }

    // Advance past the idle threshold.
    // PDCH_IDLE_RELEASE_FRAMES frames = PDCH_IDLE_RELEASE_FRAMES * 4 timeslots.
    let idle_timeslots = (PDCH_IDLE_RELEASE_FRAMES * 4 + 4) as usize; // +4 for safety margin
    test.run_stack(Some(idle_timeslots));

    // After the ticks the allocator's expire_idle must have fired and removed the entry.
    let umac = test
        .router
        .get_entity(TetraEntity::Umac)
        .expect("UMAC")
        .as_any_mut()
        .downcast_mut::<UmacBs>()
        .expect("downcast");

    assert!(
        !umac.pdch_allocator().reservations.contains_key(&TEST_ISSI),
        "idle reservation must be released after {PDCH_IDLE_RELEASE_FRAMES} frames"
    );
}

// ── test 5 ────────────────────────────────────────────────────────────────────
/// Sending a `SapMsgInner::PdchReleaseReq { issi, nsapi }` to UMAC must
/// immediately remove the reservation for that ISSI.
#[test]
fn pdch_release_req_removes_reservation() {
    debug::setup_logging_verbose();

    const TEST_ISSI: u32 = 9999;

    let start = TdmaTime { h: 0, m: 1, f: 1, t: 1 };
    let mut test = ComponentTest::new(StackMode::Bs, Some(start));
    test.populate_entities(vec![TetraEntity::Umac], vec![TetraEntity::Lmac]);

    // Enable PDCH and create a reservation.
    {
        let umac = test
            .router
            .get_entity(TetraEntity::Umac)
            .expect("UMAC")
            .as_any_mut()
            .downcast_mut::<UmacBs>()
            .expect("downcast");
        umac.set_packet_data_enabled_for_test(true);
    }

    test.submit_message(SapMsg {
        sap: Sap::TmaSap,
        src: TetraEntity::Llc,
        dest: TetraEntity::Umac,
        msg: SapMsgInner::TmaUnitdataReq(make_pdch_unitdata_req(TEST_ISSI)),
    });
    test.run_stack(Some(1));

    // Confirm reservation was created.
    {
        let umac = test
            .router
            .get_entity(TetraEntity::Umac)
            .expect("UMAC")
            .as_any_mut()
            .downcast_mut::<UmacBs>()
            .expect("downcast");
        assert!(
            umac.pdch_allocator().reservations.contains_key(&TEST_ISSI),
            "pre-condition: reservation must exist"
        );
    }

    // Send PdchReleaseReq.
    test.submit_message(SapMsg {
        sap: Sap::Control,
        src: TetraEntity::Sndcp,
        dest: TetraEntity::Umac,
        msg: SapMsgInner::PdchReleaseReq { issi: TEST_ISSI, nsapi: 0 },
    });
    test.run_stack(Some(1));

    let umac = test
        .router
        .get_entity(TetraEntity::Umac)
        .expect("UMAC")
        .as_any_mut()
        .downcast_mut::<UmacBs>()
        .expect("downcast");

    assert!(
        !umac.pdch_allocator().reservations.contains_key(&TEST_ISSI),
        "PdchReleaseReq must remove the reservation for ISSI={TEST_ISSI}"
    );
}

// ── test 6 ────────────────────────────────────────────────────────────────────
/// `packet_data_flag` must propagate from `TlaTlUnitdataReqBl` through the
/// LLC layer and arrive in `TmaUnitdataReq` with `packet_data_flag = true`.
///
/// We wire LLC + UMAC together and feed the TLA primitive to LLC, then
/// check that UMAC received a `TmaUnitdataReq` with the flag set.
#[test]
fn packet_data_flag_threads_through_llc_to_umac() {
    debug::setup_logging_verbose();

    let mut test = ComponentTest::new(StackMode::Bs, Some(TdmaTime { h: 0, m: 1, f: 1, t: 1 }));
    // We need LLC (to thread the flag) and a UMAC sink to observe the output.
    // Use a Sink on UMAC so messages destined for UMAC are captured instead of
    // being processed (which would need the full UMAC entity).
    // Actually, we need UMAC to receive and process the message to check internal
    // state. Let's use LLC + UMAC, and a sink on Lmac to capture what comes out.
    test.populate_entities(vec![TetraEntity::Llc, TetraEntity::Umac], vec![TetraEntity::Lmac]);

    // Enable PDCH so the packet-data path is active.
    {
        let umac = test
            .router
            .get_entity(TetraEntity::Umac)
            .expect("UMAC")
            .as_any_mut()
            .downcast_mut::<UmacBs>()
            .expect("downcast");
        umac.set_packet_data_enabled_for_test(true);
    }

    const TEST_ISSI: u32 = 7777;

    // Build a TlaTlUnitdataReqBl with packet_data_flag = true.
    let sdu = BitBuffer::from_bitstr("10101010");
    let tla_req = TlaTlUnitdataReqBl {
        main_address: issi_addr(TEST_ISSI),
        link_id: 0,
        endpoint_id: 0,
        tl_sdu: sdu,
        stealing_permission: false,
        subscriber_class: 0,
        fcs_flag: false,
        air_interface_encryption: None,
        packet_data_flag: true,  // <-- the flag under test
        n_tlsdu_repeats: 0,
        data_class_info: None,
        req_handle: 0,
        chan_alloc: None,
        tx_reporter: None,
    };

    test.submit_message(SapMsg {
        sap: Sap::TlaSap,
        src: TetraEntity::Mle,
        dest: TetraEntity::Llc,
        msg: SapMsgInner::TlaTlUnitdataReqBl(tla_req),
    });
    test.run_stack(Some(2));

    // If packet_data_flag threading worked, UMAC must have called
    // `handle_pdch_unitdata_req` and created a reservation.
    // That's the observable side-effect we can check via the test accessor.
    let umac = test
        .router
        .get_entity(TetraEntity::Umac)
        .expect("UMAC")
        .as_any_mut()
        .downcast_mut::<UmacBs>()
        .expect("downcast");

    assert!(
        umac.pdch_allocator().reservations.contains_key(&TEST_ISSI),
        "packet_data_flag=true must propagate through LLC→UMAC and trigger a PDCH reservation \
         for ISSI={TEST_ISSI}"
    );
}
