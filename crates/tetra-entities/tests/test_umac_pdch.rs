/// PD-5: Packet Data Channel (PDCH) allocator tests.
///
/// All PDCH code paths in UmacBs are gated behind `packet_data_enabled`.
/// These tests flip that flag via `set_packet_data_enabled_for_test` so
/// the production default (false) is not disturbed.
mod common;

use tetra_config::bluestation::{CfgPacketDataPdch, StackMode};
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
/// PD-5c-H2: with the piggyback pattern, the SN-UNITDATA-first fallback path
/// (a packet-data `TmaUnitdataReq` arriving BEFORE any TRANSMIT-REQUEST /
/// TRANSMIT-RESPONSE handshake) no longer emits a standalone MAC-RESOURCE
/// with a `ChanAllocElement`. Instead it arms the PDCH allocator
/// (`current_timeslot`, `reservations`) and flips the AACH via
/// `pdch_timeslot` so the MS observes AssignedControl on the chosen slot.
///
/// The primary PDCH grant now rides on the TRANSMIT-RESPONSE MacResource —
/// see `piggyback_grant_rides_on_transmit_response_mac_resource`.
#[test]
fn first_packet_data_pdu_arms_pdch_bookkeeping() {
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
    test.run_stack(Some(4));

    let umac = test
        .router
        .get_entity(TetraEntity::Umac)
        .expect("UMAC")
        .as_any_mut()
        .downcast_mut::<UmacBs>()
        .expect("downcast");

    // Allocator must reserve the ISSI and mark the highest free TS as current.
    assert!(
        umac.pdch_allocator().reservations.contains_key(&TEST_ISSI),
        "first packet-data PDU must reserve PDCH for ISSI={TEST_ISSI}"
    );
    assert_eq!(
        umac.pdch_allocator().primary_timeslot(),
        Some(4),
        "with no voice circuits, PDCH must prefer TS4 (highest eligible)"
    );

    // AACH must flip to AssignedControl on the chosen TS.
    assert_eq!(
        umac.channel_scheduler.pdch_timeslot(),
        Some(4),
        "SN-UNITDATA-first fallback must arm pdch_timeslot=Some(4) so AACH signals AssignedControl"
    );
}

// ── test 4 ────────────────────────────────────────────────────────────────────
/// `build_pdch_access_define_for_override` must produce a valid ACCESS-DEFINE PDU
/// with `common_or_assigned_control = true` and the supplied `access_code`.
///
/// This tests the builder helper directly without asserting any emission cadence
/// from the tick loop (DIMETRA does not emit ACCESS-DEFINE on tick; see
/// `build_pdch_access_define_for_override` docs).
#[test]
fn access_define_builder_produces_valid_pdu() {
    debug::setup_logging_verbose();

    let mut test = ComponentTest::new(StackMode::Bs, Some(TdmaTime { h: 0, m: 1, f: 1, t: 1 }));
    test.populate_entities(vec![TetraEntity::Umac], vec![TetraEntity::Lmac]);

    // Enable PDCH so the UmacBs is fully constructed with PDCH support.
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

    // Run one tick (not needed for builder, but ensures the tick path doesn't panic).
    test.run_stack(Some(1));

    let umac = test
        .router
        .get_entity(TetraEntity::Umac)
        .expect("UMAC")
        .as_any_mut()
        .downcast_mut::<UmacBs>()
        .expect("downcast");

    // Builder invocation: access_code=1 (B), timeslot=4.
    let mut buf = umac.build_pdch_access_define_for_override(1, 4);
    let access_def = AccessDefine::from_bitbuf(&mut buf)
        .expect("build_pdch_access_define_for_override must produce a valid ACCESS-DEFINE PDU");

    assert!(
        access_def.common_or_assigned_control,
        "ACCESS-DEFINE must use assigned-channel control"
    );
    assert_eq!(
        access_def.access_code, 1,
        "ACCESS-DEFINE access_code must be 1 (B) when requested"
    );

    // The tick loop must NOT have set pdch_access_define_buf — no automatic emission.
    assert!(
        umac.pdch_access_define_buf.is_none(),
        "pdch_access_define_buf must remain None after tick (no automatic ACCESS-DEFINE emission)"
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
/// A reservation that has been idle for more than the configured idle-release
/// threshold must be released on the next tick. Uses a compact 12-frame threshold
/// via the packet_data config so the test itself finishes quickly, rather than
/// waiting the production 300-frame default (~17 s).
#[test]
fn pdch_allocator_releases_after_idle() {
    debug::setup_logging_verbose();

    const TEST_ISSI: u32 = 5678;
    const TEST_IDLE_FRAMES: u32 = 12;

    // Start at a known time.
    let start = TdmaTime { h: 0, m: 1, f: 1, t: 1 };
    let mut test = ComponentTest::new(StackMode::Bs, Some(start));
    test.populate_entities(vec![TetraEntity::Umac], vec![TetraEntity::Lmac]);

    // Enable PDCH and shorten the idle threshold for this test.
    {
        let umac = test
            .router
            .get_entity(TetraEntity::Umac)
            .expect("UMAC")
            .as_any_mut()
            .downcast_mut::<UmacBs>()
            .expect("downcast");
        umac.set_packet_data_enabled_for_test(true);
        umac.pdch_allocator_mut().idle_release_frames = TEST_IDLE_FRAMES;
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
    let idle_timeslots = (TEST_IDLE_FRAMES * 4 + 4) as usize; // +4 for safety margin
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
        "idle reservation must be released after {TEST_IDLE_FRAMES} frames"
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

// ── test PD-7 ─────────────────────────────────────────────────────────────────
/// PD-7: Setting `packet_data.enabled = true` in the config (not via
/// `set_packet_data_enabled_for_test`) must auto-enable PDCH.
/// Submitting a `TmaUnitdataReq { packet_data_flag: true }` then causes UMAC
/// to grant a PDCH timeslot.
#[test]
fn packet_data_enabled_via_config_auto_enables_pdch() {
    debug::setup_logging_verbose();

    use tetra_config::bluestation::CfgPacketData;

    const TEST_ISSI: u32 = 7777;

    let mut config = ComponentTest::get_default_test_config(StackMode::Bs);
    // Enable packet data via config — do NOT call set_packet_data_enabled_for_test.
    config.packet_data = CfgPacketData {
        enabled: true,
        ..CfgPacketData::default()
    };

    let mut test = ComponentTest::from_config(config, Some(TdmaTime { h: 0, m: 1, f: 1, t: 1 }));
    test.populate_entities(vec![TetraEntity::Umac], vec![TetraEntity::Lmac]);

    // Submit a packet-data unitdata request.
    test.submit_message(SapMsg {
        sap: Sap::TmaSap,
        src: TetraEntity::Llc,
        dest: TetraEntity::Umac,
        msg: SapMsgInner::TmaUnitdataReq(make_pdch_unitdata_req(TEST_ISSI)),
    });
    test.run_stack(Some(4));

    let umac = test
        .router
        .get_entity(TetraEntity::Umac)
        .expect("UMAC not found")
        .as_any_mut()
        .downcast_mut::<UmacBs>()
        .expect("downcast to UmacBs");

    assert!(
        umac.pdch_allocator().primary_timeslot().is_some(),
        "packet_data.enabled=true in config must auto-enable PDCH \
         (current_timeslot must be Some after packet-data uplink)"
    );
}

// ── test 8 ────────────────────────────────────────────────────────────────────
/// When TS2, TS3, and TS4 are all occupied by voice circuits, the PDCH
/// allocator must not pick any timeslot (`current_timeslot = None`) and
/// no MAC-RESOURCE-with-channel-allocation must be emitted.
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
        umac.pdch_allocator().primary_timeslot(),
        None,
        "PDCH must yield when all eligible timeslots (TS2/3/4) are occupied by voice"
    );

    // No MAC-RESOURCE-with-channel-allocation must have been emitted.
    assert!(
        find_pdch_mac_resource(&sink_msgs, 0).is_none(),
        "no PDCH MAC-RESOURCE should be emitted when PDCH yields to voice pressure"
    );
}

// ── test PD-5c-H2 (piggyback) ─────────────────────────────────────────────────
/// PD-5c-H2. Feeding UMAC a `TmaUnitdataReq` with a `chan_alloc` and a non-empty
/// PDU must produce a **single** MAC-RESOURCE that carries BOTH the SDU bits
/// AND the ChanAllocElement — the piggyback pattern that MTP3550 firmware
/// requires. It must also flip the AACH on the assigned TS to
/// `AssignedControl` (`pdch_timeslot = Some(ts)`) and mark the grant as a
/// random-access response (PD-5c-H5).
#[test]
fn piggyback_grant_rides_on_transmit_response_mac_resource() {
    use tetra_saps::lcmc::enums::alloc_type::ChanAllocType;
    use tetra_saps::lcmc::enums::ul_dl_assignment::UlDlAssignment;
    use tetra_saps::lcmc::fields::chan_alloc_req::CmceChanAllocReq;

    debug::setup_logging_verbose();

    const TEST_ISSI: u32 = 1234;

    let mut test = ComponentTest::new(StackMode::Bs, Some(TdmaTime { h: 0, m: 1, f: 1, t: 1 }));
    test.populate_entities(vec![TetraEntity::Umac], vec![TetraEntity::Lmac]);

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

    // Build a TmaUnitdataReq carrying a non-empty SDU (would be the SN-DATA
    // TRANSMIT-RESPONSE in production) and a piggybacked TS4 grant.
    let piggyback_req = TmaUnitdataReq {
        req_handle: 0,
        pdu: BitBuffer::from_bitstr("11110000101010101100"),
        main_address: issi_addr(TEST_ISSI),
        link_id: 0,
        endpoint_id: 0,
        stealing_permission: false,
        subscriber_class: 0,
        air_interface_encryption: None,
        stealing_repeats_flag: None,
        data_category: None,
        carrier_num: Some(MAIN_CARRIER),
        chan_alloc: Some(CmceChanAllocReq {
            usage: None,
            carrier: Some(MAIN_CARRIER),
            timeslots: [false, false, false, true],
            alloc_type: ChanAllocType::Additional,
            ul_dl_assigned: UlDlAssignment::Both,
        }),
        tx_reporter: None,
        packet_data_flag: false, // signalling PDU, not IP data
    };
    test.submit_message(SapMsg {
        sap: Sap::TmaSap,
        src: TetraEntity::Llc,
        dest: TetraEntity::Umac,
        msg: SapMsgInner::TmaUnitdataReq(piggyback_req),
    });
    test.run_stack(Some(4));

    let sink_msgs = test.dump_sinks();

    // Locate a MAC-RESOURCE with chan_alloc_element for our ISSI.
    let pdu = find_pdch_mac_resource(&sink_msgs, TEST_ISSI)
        .expect("piggyback path must emit a MAC-RESOURCE with ChanAllocElement");

    let chan_alloc = pdu
        .chan_alloc_element
        .expect("chan_alloc_element must be present on the piggybacked MAC-RESOURCE");

    // Grant fields.
    assert_eq!(chan_alloc.ts_assigned, [false, false, false, true],
        "grant must target TS4");
    assert_eq!(chan_alloc.ul_dl_assigned, UlDlAssignment::Both,
        "grant must be UL+DL");
    assert_eq!(chan_alloc.alloc_type, ChanAllocType::Additional,
        "grant must be Additional so the MS keeps MCCH presence");
    assert!(chan_alloc.clch_permission,
        "CLCH permission must be granted so MTP3550 linearises on the TS");
    assert_eq!(chan_alloc.carrier_num, MAIN_CARRIER,
        "grant must be on the main carrier");

    // Random-access flag must be forced on for piggybacked ISSI grants
    // (PD-5c-H5) even when LLC forwards TlaTlDataReqBl with link_id=0.
    assert!(pdu.random_access_flag,
        "piggybacked ISSI grant must have random_access_flag=true (PD-5c-H5)");

    // Length indicator must reflect a non-empty SDU (i.e. the grant is not
    // riding on an empty-payload MacResource).
    assert!(pdu.length_ind > 0,
        "piggyback path must carry a non-empty SDU on the same PDU as the grant");

    // AACH must be armed on TS4.
    let umac = test.router.get_entity(TetraEntity::Umac).expect("UMAC")
        .as_any_mut().downcast_mut::<UmacBs>().expect("downcast");
    assert_eq!(umac.channel_scheduler.pdch_timeslot(), Some(4),
        "piggyback path must arm the PDCH AACH on the assigned timeslot");
}

// ── PD-5b test 1 ──────────────────────────────────────────────────────────────
/// After `emit_pdch_mac_resource` fires (triggered by a packet-data uplink),
/// the scheduler's `pdch_timeslot` must be `Some(4)` so the AACH on TS4 carries
/// `AssignedControl / AssignedOnly` on subsequent frames.
///
/// This is the primary regression test for PD-5b: the root cause was that
/// `pdch_timeslot` was never set, so the MS saw `Unallocated` on TS4 and
/// abandoned the granted timeslot within 1-2 frames.
#[test]
fn pdch_mac_resource_activates_assigned_control_aach_on_pdch_slot() {
    debug::setup_logging_verbose();

    const TEST_ISSI: u32 = 8888;

    let mut test = ComponentTest::new(StackMode::Bs, Some(TdmaTime { h: 0, m: 1, f: 1, t: 1 }));
    test.populate_entities(vec![TetraEntity::Umac], vec![TetraEntity::Lmac]);

    {
        let umac = test.router.get_entity(TetraEntity::Umac).expect("UMAC")
            .as_any_mut().downcast_mut::<UmacBs>().expect("downcast");
        umac.set_packet_data_enabled_for_test(true);
    }

    // Submit a packet-data uplink — triggers reserve + AACH bookkeeping
    // (SN-UNITDATA-first fallback path in handle_pdch_unitdata_req).
    test.submit_message(SapMsg {
        sap: Sap::TmaSap,
        src: TetraEntity::Llc,
        dest: TetraEntity::Umac,
        msg: SapMsgInner::TmaUnitdataReq(make_pdch_unitdata_req(TEST_ISSI)),
    });
    test.run_stack(Some(4));

    let umac = test.router.get_entity(TetraEntity::Umac).expect("UMAC")
        .as_any_mut().downcast_mut::<UmacBs>().expect("downcast");

    // After the fallback bookkeeping, the scheduler must have pdch_timeslot = Some(4).
    assert_eq!(
        umac.channel_scheduler.pdch_timeslot(),
        Some(4),
        "PDCH fallback path must arm pdch_timeslot=Some(4) so AACH signals AssignedControl"
    );
}

// ── PD-5b test 2 ──────────────────────────────────────────────────────────────
/// After voice preempts the PDCH slot and subsequently releases it, the PDCH
/// must NOT ghost-reappear: `pdch_timeslot` must stay `None` until the MS
/// re-requests via a new TRANSMIT-REQUEST / packet-data uplink.
///
/// Regression guard for the tick-loop re-arm bug: if `set_pdch_timeslot` were
/// called in the per-hyperframe tick with the "would-choose" slot, the AACH
/// would flip back to AssignedControl after voice ends without an MS-initiated
/// request, causing the MS to try to access a ghost PDCH session.
#[test]
fn pdch_tick_reasserts_aach_after_intra_frame_change() {
    debug::setup_logging_verbose();

    const TEST_ISSI: u32 = 6543;

    let mut test = ComponentTest::new(StackMode::Bs, Some(TdmaTime { h: 0, m: 1, f: 1, t: 1 }));
    test.populate_entities(vec![TetraEntity::Umac], vec![TetraEntity::Lmac]);

    // Enable PDCH.
    {
        let umac = test.router.get_entity(TetraEntity::Umac).expect("UMAC")
            .as_any_mut().downcast_mut::<UmacBs>().expect("downcast");
        umac.set_packet_data_enabled_for_test(true);
    }

    // Step 1: submit a packet-data uplink → PDCH granted on TS4.
    test.submit_message(SapMsg {
        sap: Sap::TmaSap,
        src: TetraEntity::Llc,
        dest: TetraEntity::Umac,
        msg: SapMsgInner::TmaUnitdataReq(make_pdch_unitdata_req(TEST_ISSI)),
    });
    test.run_stack(Some(4));

    {
        let umac = test.router.get_entity(TetraEntity::Umac).expect("UMAC")
            .as_any_mut().downcast_mut::<UmacBs>().expect("downcast");
        assert_eq!(
            umac.channel_scheduler.pdch_timeslot(),
            Some(4),
            "pre-condition: PDCH must be active on TS4 before voice preemption"
        );
    }

    // Step 2: voice opens a circuit on TS4 → preempts PDCH.
    test.submit_message(SapMsg {
        sap: Sap::Control,
        src: TetraEntity::Cmce,
        dest: TetraEntity::Umac,
        msg: SapMsgInner::CmceCallControl(CallControl::Open(Circuit {
            direction: Direction::Both,
            carrier_num: MAIN_CARRIER,
            ts: 4,
            peer_carrier_num: None,
            peer_ts: None,
            usage: 4,
            circuit_mode: CircuitModeType::TchS,
            speech_service: Some(0),
            etee_encrypted: false,
            dl_media_source: CircuitDlMediaSource::SwMI,
        })),
    });
    test.run_stack(Some(2));

    {
        let umac = test.router.get_entity(TetraEntity::Umac).expect("UMAC")
            .as_any_mut().downcast_mut::<UmacBs>().expect("downcast");
        assert_eq!(
            umac.channel_scheduler.pdch_timeslot(),
            None,
            "voice preemption on TS4 must clear pdch_timeslot"
        );
    }

    // Step 3: voice releases TS4.
    test.submit_message(SapMsg {
        sap: Sap::Control,
        src: TetraEntity::Cmce,
        dest: TetraEntity::Umac,
        msg: SapMsgInner::CmceCallControl(CallControl::Close(Direction::Both, 4)),
    });
    // Run several hyperframes so the PDCH tick fires at least once.
    test.run_stack(Some(4 * 18 * 4));

    let umac = test.router.get_entity(TetraEntity::Umac).expect("UMAC")
        .as_any_mut().downcast_mut::<UmacBs>().expect("downcast");

    // PDCH must NOT ghost-reappear — still None until the MS re-requests.
    assert_eq!(
        umac.channel_scheduler.pdch_timeslot(),
        None,
        "PDCH must not ghost-reappear after voice releases the preempted slot; \
         re-activation requires an MS-initiated TRANSMIT-REQUEST"
    );
}

// ── PD-5c-H52b: multi-slot drain tests ────────────────────────────────────────

/// Build a `ComponentTest` with multi-slot PDCH enabled: `multi_slot = true`,
/// `dl_max_slots_per_frame = max_slots`, `require_ms_capability = require_cap`.
fn make_multislot_test(max_slots: u8, require_cap: bool) -> ComponentTest {
    let mut cfg = ComponentTest::get_default_test_config(StackMode::Bs);
    cfg.packet_data.pdch = CfgPacketDataPdch {
        multi_slot: true,
        dl_max_slots_per_frame: max_slots,
        require_ms_capability: require_cap,
        ..Default::default()
    };
    cfg.packet_data.enabled = true;
    ComponentTest::from_config(cfg, Some(TdmaTime { h: 0, m: 1, f: 1, t: 1 }))
}

/// H52b test 1: when `dl_max_slots_per_frame = 2` and both TS3 and TS4 are free,
/// two SDUs for two different multislot-capable ISSIs are each drained onto
/// separate timeslots in one tick.
#[test]
fn pdch_multislot_drain_uses_two_ts_when_both_free() {
    debug::setup_logging_verbose();

    const ISSI_A: u32 = 1001;
    const ISSI_B: u32 = 1002;

    let mut test = make_multislot_test(2, true);
    test.populate_entities(vec![TetraEntity::Umac], vec![TetraEntity::Lmac]);

    // Mark both ISSIs as multislot-capable in the shared state.
    test.config.state_write().ms_multislot_cap.insert(ISSI_A, true);
    test.config.state_write().ms_multislot_cap.insert(ISSI_B, true);

    // Submit two packet-data PDUs for two different ISSIs (arms PDCH).
    for issi in [ISSI_A, ISSI_B] {
        test.submit_message(SapMsg {
            sap: Sap::TmaSap,
            src: TetraEntity::Llc,
            dest: TetraEntity::Umac,
            msg: SapMsgInner::TmaUnitdataReq(make_pdch_unitdata_req(issi)),
        });
    }
    // tick 1: deliver messages (SDUs enqueued); tick 2: drain fires.
    test.run_stack(Some(2));

    let umac = test.router.get_entity(TetraEntity::Umac).expect("UMAC")
        .as_any_mut().downcast_mut::<UmacBs>().expect("downcast");

    // After two ticks both SDUs must have been drained (queue length drops from 2 to 0).
    assert_eq!(
        umac.pdch_dl_queue_len_for_test(),
        0,
        "multi-slot drain must consume both SDUs in one drain tick when TS3 and TS4 are free"
    );
    // Both TS3 and TS4 should be in the current_timeslots.
    assert!(
        umac.pdch_allocator().current_timeslots.len() >= 2,
        "current_timeslots must hold at least 2 entries when N=2 slots are chosen"
    );
}

/// H52b test 2: when `dl_max_slots_per_frame = 2` but TS3 and TS4 are both
/// occupied by voice, only TS2 is chosen and only one SDU is drained per tick.
#[test]
fn pdch_multislot_falls_back_to_one_ts_when_ts3_busy() {
    debug::setup_logging_verbose();

    const ISSI_A: u32 = 2001;

    let mut test = make_multislot_test(2, false);
    test.populate_entities(vec![TetraEntity::Umac], vec![TetraEntity::Lmac]);

    // Occupy TS3 and TS4 with voice circuits.
    for ts in [3u8, 4u8] {
        test.submit_message(SapMsg {
            sap: Sap::Control,
            src: TetraEntity::Cmce,
            dest: TetraEntity::Umac,
            msg: SapMsgInner::CmceCallControl(CallControl::Open(Circuit {
                direction: Direction::Dl,
                carrier_num: 1521,
                peer_carrier_num: None,
                ts,
                peer_ts: None,
                usage: 4,
                circuit_mode: CircuitModeType::TchS,
                speech_service: Some(0),
                etee_encrypted: false,
                dl_media_source: CircuitDlMediaSource::LocalLoopback,
            })),
        });
    }
    test.run_stack(Some(2));

    // Queue two SDUs for the same ISSI.
    for _ in 0..2 {
        test.submit_message(SapMsg {
            sap: Sap::TmaSap,
            src: TetraEntity::Llc,
            dest: TetraEntity::Umac,
            msg: SapMsgInner::TmaUnitdataReq(make_pdch_unitdata_req(ISSI_A)),
        });
    }
    test.run_stack(Some(2));

    let umac = test.router.get_entity(TetraEntity::Umac).expect("UMAC")
        .as_any_mut().downcast_mut::<UmacBs>().expect("downcast");

    // With TS3 and TS4 busy, only TS2 is available: at most 1 slot chosen.
    assert!(
        umac.pdch_allocator().current_timeslots.len() <= 1,
        "only one slot (TS2) should be chosen when TS3 and TS4 are both occupied by voice"
    );
}

/// H52b test 3: an ISSI whose `multislot_phase_mod` is `false` must be capped
/// to at most 1 slot per tick, even when N=2 is configured.
#[test]
fn pdch_multislot_gated_by_ms_capability() {
    debug::setup_logging_verbose();

    const ISSI_SINGLE: u32 = 3001;

    let mut test = make_multislot_test(2, true);
    test.populate_entities(vec![TetraEntity::Umac], vec![TetraEntity::Lmac]);

    // Mark ISSI as non-multislot-capable.
    test.config.state_write().ms_multislot_cap.insert(ISSI_SINGLE, false);

    // Queue two SDUs for the same ISSI.
    for _ in 0..2 {
        test.submit_message(SapMsg {
            sap: Sap::TmaSap,
            src: TetraEntity::Llc,
            dest: TetraEntity::Umac,
            msg: SapMsgInner::TmaUnitdataReq(make_pdch_unitdata_req(ISSI_SINGLE)),
        });
    }
    // tick 1: deliver messages (SDUs enqueued); tick 2: drain fires.
    test.run_stack(Some(2));

    let umac = test.router.get_entity(TetraEntity::Umac).expect("UMAC")
        .as_any_mut().downcast_mut::<UmacBs>().expect("downcast");

    // The non-multislot MS must have only 1 SDU drained: 1 remains.
    assert_eq!(
        umac.pdch_dl_queue_len_for_test(),
        1,
        "non-multislot MS must be capped at 1 slot per tick; second SDU must remain in queue"
    );
}
