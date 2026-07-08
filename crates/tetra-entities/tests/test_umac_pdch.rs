/// PD-5: Packet Data Channel (PDCH) allocator tests.
///
/// All PDCH code paths in UmacBs are gated behind `packet_data_enabled`.
/// These tests flip that flag via `set_packet_data_enabled_for_test` so
/// the production default (false) is not disturbed.
mod common;

use tetra_config::bluestation::StackMode;
use tetra_core::{BitBuffer, Direction, Sap, SsiType, TdmaTime, TetraAddress, debug};
use tetra_core::tetra_entities::TetraEntity;
use tetra_entities::umac::umac_bs::UmacBs;
use tetra_pdus::umac::pdus::access_define::AccessDefine;
use tetra_pdus::umac::pdus::mac_resource::MacResource;
use tetra_saps::control::call_control::{CallControl, Circuit, CircuitDlMediaSource};
use tetra_saps::control::enums::circuit_mode_type::CircuitModeType;
use tetra_saps::sapmsg::{SapMsg, SapMsgInner};
use tetra_saps::tla::TlaTlUnitdataReqBl;
use tetra_saps::tma::TmaUnitdataReq;
use tetra_saps::tmv::TmvUnitdataReqSlots;

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

/// Scan all LMAC sink messages for a MAC-RESOURCE PDU addressed to `issi` that
/// carries a `chan_alloc_element`.  Returns the first matching PDU.
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
                // Peek at mac_pdu_type; only MAC-RESOURCE (0) carries chan_alloc.
                let mut peek = buf.clone();
                if peek.read_field(2, "t").map(|t| t != 0).unwrap_or(true) {
                    continue;
                }
                let Ok(pdu) = MacResource::from_bitbuf(&mut buf) else {
                    continue;
                };
                if pdu.addr.map(|a| a.ssi) == Some(issi) && pdu.chan_alloc_element.is_some() {
                    return Some(pdu);
                }
            }
        }
    }
    None
}

// ── test 1 ────────────────────────────────────────────────────────────────────
/// With `packet_data_enabled = false` (the default), ticking a hyperframe must
/// never produce a MAC-RESOURCE with a `chan_alloc_element` for a PDCH grant,
/// and the ACCESS-DEFINE bring-up buffer must remain `None`.
#[test]
fn default_off_scheduler_behaviour_unchanged() {
    debug::setup_logging_verbose();

    let mut test = ComponentTest::new(StackMode::Bs, Some(TdmaTime { h: 0, m: 1, f: 1, t: 1 }));
    test.populate_entities(vec![TetraEntity::Umac], vec![TetraEntity::Lmac]);

    // Do NOT enable PDCH — leave at default (false).

    // Run one full hyperframe (60 multiframes × 18 frames × 4 timeslots).
    test.run_stack(Some(60 * 18 * 4));

    let sink_msgs = test.dump_sinks();

    // No PDCH-related MAC-RESOURCE should appear in the LMAC output.
    assert!(
        find_pdch_mac_resource(&sink_msgs, 0).is_none(),
        "no PDCH MAC-RESOURCE should be emitted when packet_data_enabled = false \
         (checked via generic SSI=0 search)"
    );

    let umac = test
        .router
        .get_entity(TetraEntity::Umac)
        .expect("UMAC not found")
        .as_any_mut()
        .downcast_mut::<UmacBs>()
        .expect("downcast to UmacBs");

    assert!(
        umac.pdch_access_define_buf.is_none(),
        "ACCESS-DEFINE must not be built when packet_data_enabled = false"
    );
}

// ── test 2 ────────────────────────────────────────────────────────────────────
/// `packet_data_flag` must propagate from `TlaTlUnitdataReqBl` through the
/// LLC layer and arrive in `TmaUnitdataReq` with `packet_data_flag = true`.
///
/// We wire LLC + UMAC together and feed the TLA primitive to LLC, then
/// check that UMAC received a `TmaUnitdataReq` with the flag set by
/// verifying that a PDCH reservation was created for the source ISSI.
#[test]
fn packet_data_flag_threads_through_llc_to_umac() {
    debug::setup_logging_verbose();

    let mut test = ComponentTest::new(StackMode::Bs, Some(TdmaTime { h: 0, m: 1, f: 1, t: 1 }));
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
        packet_data_flag: true, // <-- the flag under test
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

    // If packet_data_flag threading worked, UMAC must have created a reservation.
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

// ── test 3 ────────────────────────────────────────────────────────────────────
/// The first `TmaUnitdataReq { packet_data_flag: true }` for a new ISSI must
/// cause UMAC to emit a `MAC-RESOURCE` PDU with a `ChanAllocElement` granting
/// the PDCH timeslot.  Fields checked: SSI, carrier_number, ts_assigned bitmap.
#[test]
fn first_packet_data_pdu_triggers_mac_resource_with_channel_allocation() {
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

    // Submit the first packet-data PDU for the ISSI.
    test.submit_message(SapMsg {
        sap: Sap::TmaSap,
        src: TetraEntity::Llc,
        dest: TetraEntity::Umac,
        msg: SapMsgInner::TmaUnitdataReq(make_pdch_unitdata_req(TEST_ISSI)),
    });
    // Run enough ticks for the message to be processed and finalized into LMAC.
    test.run_stack(Some(4));

    let sink_msgs = test.dump_sinks();

    let pdu = find_pdch_mac_resource(&sink_msgs, TEST_ISSI)
        .expect("MAC-RESOURCE with ChanAllocElement must be emitted for the first PDCH PDU");

    let chan_alloc = pdu.chan_alloc_element.expect("chan_alloc_element must be present");

    // Exactly one timeslot must be assigned (the dynamically-chosen PDCH slot).
    let assigned_count = chan_alloc.ts_assigned.iter().filter(|&&b| b).count();
    assert_eq!(assigned_count, 1, "exactly one timeslot must be assigned in the PDCH grant");

    // TS1 must never be the PDCH slot (it's the control channel).
    assert!(
        !chan_alloc.ts_assigned[0],
        "TS1 must never be assigned as a PDCH timeslot"
    );

    // With no voice circuits active, TS4 is the preferred PDCH slot.
    assert!(
        chan_alloc.ts_assigned[3],
        "with no voice circuits, PDCH must prefer TS4 (highest eligible)"
    );

    // The carrier must be the main carrier.
    assert_eq!(chan_alloc.carrier_num, MAIN_CARRIER, "PDCH carrier must be the main carrier");
}

// ── test 4 ────────────────────────────────────────────────────────────────────
/// When `packet_data_enabled = true` and a PDCH timeslot is available, UMAC
/// must build an `ACCESS-DEFINE` PDU with `common_or_assigned_control = true`
/// and `access_code = 1` (B) for the PDCH random-access channel.
///
/// NOTE: the ACCESS-DEFINE is currently stored in-memory pending full BNCH
/// broadcast-slot injection (deferred to a later PR).  This test decodes the
/// in-memory buffer and checks the fields.
#[test]
fn access_define_emitted_at_enable() {
    debug::setup_logging_verbose();

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

    // Run one tick so the PDCH bring-up path fires.
    test.run_stack(Some(1));

    let umac = test
        .router
        .get_entity(TetraEntity::Umac)
        .expect("UMAC")
        .as_any_mut()
        .downcast_mut::<UmacBs>()
        .expect("downcast");

    let buf = umac
        .pdch_access_define_buf
        .as_ref()
        .expect("pdch_access_define_buf must be Some after first tick with packet_data_enabled=true");

    let mut decode_buf = buf.clone();
    let access_def = AccessDefine::from_bitbuf(&mut decode_buf)
        .expect("pdch_access_define_buf must be a valid ACCESS-DEFINE PDU");

    assert!(
        access_def.common_or_assigned_control,
        "ACCESS-DEFINE must use assigned-channel control for PDCH"
    );
    assert_eq!(
        access_def.access_code, 1,
        "ACCESS-DEFINE access_code must be 1 (B) for the PDCH RA channel"
    );
}

// ── test 5 ────────────────────────────────────────────────────────────────────
/// Feeding a `TmaUnitdataReq { packet_data_flag: true }` to UMAC must create
/// a PDCH reservation for the source ISSI in the `PdchAllocator`.
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

// ── test 6 ────────────────────────────────────────────────────────────────────
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

// ── test 7 ────────────────────────────────────────────────────────────────────
/// Sending a `SapMsgInner::PdchReleaseReq { issi, nsapi }` to UMAC must
/// immediately remove the reservation for that ISSI.
#[test]
fn pdch_release_req_removes_assignment() {
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

// ── test 8 ────────────────────────────────────────────────────────────────────
/// When TS2, TS3, and TS4 are all occupied by voice circuits, the PDCH
/// allocator must not pick any timeslot (`current_timeslot = None`) and
/// no `pdch_broadcast_hook_fired` must be set.
#[test]
fn pdch_yields_to_voice_when_all_slots_taken() {
    debug::setup_logging_verbose();

    // Start at t=1, f=1 so the first tick is the hyperframe broadcast gate.
    let start = TdmaTime { h: 0, m: 1, f: 1, t: 1 };
    let mut test = ComponentTest::new(StackMode::Bs, Some(start));
    test.populate_entities(vec![TetraEntity::Umac], vec![TetraEntity::Lmac]);

    // Helper: send a CallControl::Open for a voice circuit on the given timeslot.
    let open_voice = |ts: u8| -> SapMsg {
        SapMsg {
            sap: Sap::Control,
            src: TetraEntity::Cmce,
            dest: TetraEntity::Umac,
            msg: SapMsgInner::CmceCallControl(CallControl::Open(Circuit {
                direction: Direction::Both,
                carrier_num: MAIN_CARRIER,
                ts,
                peer_carrier_num: None,
                peer_ts: None,
                usage: 4, // TCH/S group call
                circuit_mode: CircuitModeType::TchS,
                speech_service: Some(0),
                etee_encrypted: false,
                dl_media_source: CircuitDlMediaSource::SwMI,
            })),
        }
    };

    // Occupy TS2, TS3, TS4 with voice circuits.
    test.submit_message(open_voice(2));
    test.submit_message(open_voice(3));
    test.submit_message(open_voice(4));
    // Process the circuit-open messages.
    test.deliver_all_messages();

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

    // Verify the circuits are actually registered (pre-condition).
    {
        let umac = test
            .router
            .get_entity(TetraEntity::Umac)
            .expect("UMAC")
            .as_any_mut()
            .downcast_mut::<UmacBs>()
            .expect("downcast");
        for ts in [2u8, 3, 4] {
            assert!(
                umac.channel_scheduler.circuit_is_active(Direction::Dl, ts),
                "pre-condition: TS{ts} must have an active voice circuit"
            );
        }
    }

    // Run one tick at t=1, f=1 — the PDCH broadcast gate.
    test.run_stack(Some(1));

    let sink_msgs = test.dump_sinks();

    let umac = test
        .router
        .get_entity(TetraEntity::Umac)
        .expect("UMAC")
        .as_any_mut()
        .downcast_mut::<UmacBs>()
        .expect("downcast");

    // No PDCH timeslot should have been chosen.
    assert_eq!(
        umac.pdch_allocator().current_timeslot,
        None,
        "PDCH must yield when all eligible timeslots (TS2/3/4) are occupied by voice"
    );

    // No MAC-RESOURCE-with-channel-allocation must have been emitted.
    assert!(
        find_pdch_mac_resource(&sink_msgs, 0).is_none(),
        "no PDCH MAC-RESOURCE should be emitted when PDCH yields to voice pressure"
    );
}
