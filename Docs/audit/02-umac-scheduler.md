# UMAC scheduler audit — flowstation vs DIMETRA BRC

**Base commit:** HEAD (run `git rev-parse --short HEAD` in repo root)
**Scope:** DL scheduler grant policy, UL grant response, capacity requests, subslot vs full-slot
decision, fragmentation drive from scheduler side. Excludes AL/LLC and PDCH allocator lifecycle
(covered in separate reports).

---

## Method

| Source | Detail |
|---|---|
| flowstation `bs_sched.rs` | 2580 lines — main scheduler loop, grant machinery, AACH generation |
| flowstation `umac_bs.rs` | 2580 lines — RX/TX dispatch, cap-req handling, FACCH steal path |
| flowstation `bs_frag.rs` | 423 lines — DL fragmentation state machine |
| flowstation `bs_defrag.rs` | 202 lines — UL defragmentation, timeout logic |
| flowstation `circuit_mgr.rs` | 149 lines — circuit state (DL/UL, voice blocks) |
| Motorola `umac.txt` | 196 UMAC-tagged `rlj_app` symbols; grant/capreq/MSPD coverage |
| Motorola `pdch_mac_strings.txt` | 27 KB MAC/PDCH runtime strings, CRM/PDRQ log evidence |
| ETSI EN 300 392-2 | Clauses 21.4, 21.5, 21.5.4, 23.5 |
| Disassembly | `sub_0.elf` not disassembled (symbol names are sufficient for all 12 properties; reserve for follow-up) |

Time cap: one session, ~3 h read + evidence cross-reference.

---

## Guardrails

- [x] No files under `crates/` modified.
- [x] Motorola evidence anchored to symbol names from `umac.txt` and strings from `pdch_mac_strings.txt`.
- [x] flowstation evidence cited at `crates/…/file.rs:LINE`.

---

## Properties

### Property 1: Grant opportunity search discipline

- **ETSI:** §21.5.2 — BS grants are advisory; the standard does not mandate a scheduling algorithm. The BS selects a UL grant window in the forward multiframe.
- **Motorola:** `dlai_scan_hi_pri_capreq` (addr `0x00202c4c`, 864 bytes), `_scan_lo_pri_capreq_with_follow_up` (addr `0x0020374c`), `_find_most_tokens_capreq` (addr `0x002032e4`, 240 bytes), `_get_most_tokens_capreq` (addr `0x0020348c`). Motorola separates capacity requests into high-priority and low-priority queues and within the low-priority queue selects the MS with the **most tokens** (credit-based fairness). There are also dedicated paths for SSI, event-label, random-access, and reserved-access capreqs (`_try_to_pack_lo_pri_capreq_ssi`, `_try_to_pack_lo_pri_capreq_el`, etc.).
- **flowstation:** `ul_process_cap_req` (`crates/tetra-entities/src/umac/subcomp/bs_sched.rs:582`) processes one capreq inline per received MAC PDU. No priority queue, no token accounting. Grants are issued on a **first-received, first-served** basis. `dl_take_prioritized_sched_item` (`bs_sched.rs:1444`) returns `Grant > FragBuf > Resource > Stealing` within the same per-timeslot `Vec`, which is FIFO within type.
- **Verdict:** DIVERGENT-LOW
- **Follow-up:** accept — scheduler algorithm is implementation-defined per ETSI; FIFO is compliant. Under multi-MS load, unfairness may appear. Noted for future token/priority work.

---

### Property 2: Subslot vs full-slot grant decision

- **ETSI:** §21.5.6 — `BasicSlotgrant.capacity_allocation` encodes `FirstSubslotGranted`, `SecondSubslotGranted`, or `GrantNSlots`. BS chooses based on whether the request is `Req1Subslot` or a full-slot count.
- **Motorola:** `_get_halfslot_most_tokens_capreq` (addr `0x00203874`, 216 bytes), `_find_capreq_for_one_subslot` (addr `0x0020213c`, 116 bytes). Motorola has a dedicated half-slot capreq path that can coexist with a simultaneously requested full-slot from a different MS.
- **flowstation:** `is_halfslot = res_req == ReservationRequirement::Req1Subslot` (`bs_sched.rs:588`). Half-slot reservations use `ul1`/`ul2` independently per `TimeslotSchedule`. `ul_reserve_grant` returns `1` or `2` to indicate which sub-slot was assigned (`bs_sched.rs:513–521`). A half-slot and a full-slot from different MSs correctly coexist in the same frame if only one is a half-slot. No automatic downgrade from full-slot to half-slot request.
- **Verdict:** MATCH
- **Follow-up:** none

---

### Property 3: Uplink capacity request handling — persistence and deduplication

- **ETSI:** §21.5.4, §21.5.2 — MS may piggyback `reservation_req` on every UL frame while a multi-slot reservation is in progress. BS may choose to ignore repeated requests.
- **Motorola:** `dlai_find_capreq_for_address` (addr `0x00201e5c`, 564 bytes), `_find_capreq_for_ms_in_queue` (addr `0x00201d40`, 284 bytes), `dlai_kill_capreq` (addr `0x001fac18`, 144 bytes), `dlai_purge_capreqs` (addr `0x001fad5c`, 476 bytes), `dlai_check_delay_was_exceeded_for_capreq_pdu` (addr `0x001fa718`, 128 bytes). Motorola maintains a persistent per-MS capreq queue with age/delay tracking and explicit kill/purge operations.
- **flowstation:** Capreqs are handled **inline and statelessly**. Each MAC-DATA, MAC-ACCESS, MAC-END-UL, and MAC-END-HU that carries a `reservation_req` calls `ul_process_cap_req` immediately (`umac_bs.rs:715`, `:917`, `:1116`, `:1244`). Deduplication is implemented: if the MS already owns ≥ `requested_cap` forward slots in the window, the grant is suppressed (`bs_sched.rs:613–626`, comment: "PD-5c-H7"). No persistent queue; if the grant response is lost on the DL, the MS must retry via random access.
- **Verdict:** DIVERGENT-LOW
- **Follow-up:** accept — stateless inline handling is simpler and fits the single-cell use case. Grant loss recovery relies on MS retry, which is standard TETRA behavior. No interop issue observed.

---

### Property 4: MAC-RESOURCE address type selection (SSI vs event-label)

- **ETSI:** §21.4.2, Table 21.4 — MAC-RESOURCE may carry either `address` (SSI/GSSI) or `event_label` (9-bit) for more compact headers on assigned channels.
- **Motorola:** `dlai_resrec_get_active_grant_for_event_label` (addr `0x001fcd60`, 104 bytes), `dlai_find_acceptable_event_label_capreq` (addr `0x00203a68`, 160 bytes), `dlai_remove_capreq_for_event_label` (addr `0x002020ec`, 80 bytes). Motorola actively uses event labels in PDCH grant responses, reducing MAC-RESOURCE header overhead on assigned channels.
- **flowstation:** `event_label: None` is hardcoded on **every** outgoing MAC-RESOURCE path:
  - `dl_make_minimal_resource` (`bs_sched.rs:1152`)
  - FACCH/stealing path (`umac_bs.rs:1433`)
  - Normal signalling path (`umac_bs.rs:1521`)
  - Carrier signalling path (`umac_bs.rs:1585`, `:1692`)
  - `EventLabelStore` struct exists (`subcomp/event_label_store.rs`) with `get_free_label()`, `create_label_for_addr()`, but is **commented out** of `UmacBs::new()` (`umac_bs.rs:143`: `// event_label_store: EventLabelStore::new()`).
  - UL MAC-DATA with `event_label` returns `unimplemented_log!("event labels not implemented")` (`umac_bs.rs:622–624`).
- **Verdict:** MISSING
- **Follow-up:** implement — event label support is required for correct PDCH operation when the MS expects compact headers on the assigned channel. On voice/MCCH paths the absence is harmless. See Draft Issue 1.

---

### Property 5: Downlink queue draining discipline and head-of-line blocking

- **ETSI:** §21.4 — no mandated DL queue ordering beyond grant/response timeliness.
- **Motorola:** `dlai_scan_hi_pri_capreq`, `_try_to_fit_tma_req_with_grant_or_grant_only` (addr `0x0020c144`, 1996 bytes), `_prevent_packing_al_data_with_grant_before_al_ack` (addr `0x0020b8f8`, 184 bytes). Motorola separates high-priority and low-priority DL elements and prevents packing AL data before an AL ACK is received for a previous grant.
- **flowstation:** `dl_take_prioritized_sched_item` (`bs_sched.rs:1444–1486`) implements: **(1) Grant first**, **(2) FragBuf second** (in-flight fragmentation continuation), **(3) Resource third**, **(4) Stealing last**. Frame 18 suppresses all delivery (`bs_sched.rs:1445–1448`). Deferred items (`dltx_next_slot_queue`) are prepended to the next frame's queue (`bs_sched.rs:1372–1378`). No AL-window awareness: the UMAC will drain the queue regardless of whether LLC has acknowledged prior segments.
- **Verdict:** MATCH (ordering), DIVERGENT-LOW (no AL-window backpressure — see Property 6)
- **Follow-up:** accept

---

### Property 6: Backpressure when LLC transmit window is full

- **ETSI:** §21 — MAC layer is unacknowledged; AL (clause 22) provides the acknowledgment mechanism. The standard does not require UMAC to track AL windows, but practical implementations may.
- **Motorola:** `_prevent_packing_al_data_with_grant_before_al_ack` (addr `0x0020b8f8`, 184 bytes). This function, co-located with `_try_to_fit_tma_req_with_grant_or_grant_only`, prevents DL AL data from being packed into a slot when a pending grant has not yet been acknowledged. This implements a soft backpressure gate.
- **flowstation:** No equivalent mechanism. `rx_ul_tma_unitdata_req` and `rx_ul_tma_unitdata_req_carrier` enqueue MAC-RESOURCE PDUs into `dltx_queues` without consulting LLC window state (`umac_bs.rs:1532–1533`, `:1705–1706`). The scheduler drains the queue blindly. LLC window enforcement is entirely above UMAC (in the AL layer).
- **Verdict:** DIVERGENT-LOW
- **Follow-up:** accept — for small single-cell deployments this is not a practical issue. If AL overrun is observed under load, a `TmaBackpressureInd` signal from LLC could gate enqueueing.

---

### Property 7: Fill-frame and Null PDU emission on empty slot

- **ETSI:** §21.4.3.3, §23.5.1 — idle signalling slots should carry Null PDU (MAC-RESOURCE with `length_ind=0`). Hangtime slots carry Null PDU with `AssignedControl`/`AssignedOnly` AACH.
- **Motorola:** not directly evidenced in symbol strings (idle-channel behavior is likely in `_generate_default_blks` or similar, inferred from `dlai_remember_that_dummy_grant_is_sent_in_this_slot` addr `0x001ef918`).
- **flowstation:**
  - **Idle MCCH TS1 (odd frames):** `generate_default_blks` emits `SCH/F + Null PDU` (`bs_sched.rs:1911–1919`)
  - **Idle MCCH TS1 (even frames):** `SCH/HD + Null PDU` + `BNCH/SYSINFO` (`bs_sched.rs:1902–1910`)
  - **TS2–4 idle:** `BSCH + BNCH/SYSINFO` per timeslot (`bs_sched.rs:1921–1934`)
  - **Hangtime:** `generate_hangtime_idle_schf()` emits `SCH/F + Null PDU` (`bs_sched.rs:321–327`)
  - **Slot padding:** `try_add_null_pdus` appends a Null PDU if ≥16 bits remain in an `SCH/HD` or `SCH/F` block (`bs_sched.rs:1089–1122`). Does **not** append to `STCH` (MAC-U-SIGNAL header consumes whole half-slot).
  - No BS-originated DL **MAC-U-SIGNAL** (`MacUSignal`) is ever emitted; `MacUSignal` is decoded on UL only (`umac_bs.rs:1301`).
- **Verdict:** MATCH
- **Follow-up:** none

---

### Property 8: MSPD (Multi-Slot Packet Data) count vs grant slot count

- **ETSI:** §21.5.2, §23.5.2.2.7 — multi-slot grants are expressed as `GrantNSlots` in `BasicSlotgrantCapAlloc`. The standard does not define an "MSPD" structure; that is a Motorola implementation concept.
- **Motorola:** `ccai_mspd_resize_slot_assignment_change` (addr `0x001df654`, 224 bytes), `ccai_mspd_resize_update_dla` (addr `0x001df734`, 652 bytes), `ccai_mspd_resize_check_for_preemption` (addr `0x001e0764`, 616 bytes), `MSPD_NEXT_SLOT` (addr `0x001fc6c8`, 92 bytes), `dlai_is_fragmentation_ongoing_for_ms_on_mspd` (addr `0x00204ea0`, 92 bytes), `dlai_update_mspd_ul_grant_status` (addr `0x00205100`). Motorola maintains a dedicated per-MS multi-slot packet data channel (MSPD) structure with add-slot, remove-slot, resize, and preemption operations. Multiple MSs can share a PDCH with individually tracked slot counts.
- **flowstation:** No MSPD concept. Multi-slot grants awarded by `BasicSlotgrantCapAlloc::from_req_slotcount(requested_cap)` (`bs_sched.rs:687`). The scheduler caps requests at `MACSCHED_NUM_FRAMES - 1 = 17` (`bs_sched.rs:600`, comment: "PD-5c-H32"). UL schedule tracks owners as `Option<u32>` (ISSI) per sub-slot, no per-MS slot count structure. `ul_owned_slot_count_in_window` provides a read of how many slots an MS currently holds (`bs_sched.rs:557–574`). Single-user PDCH works; simultaneous multi-MS PDCH sharing is not managed.
- **Verdict:** OPEN-QUESTION
- **Follow-up:** investigate — for multi-user PDCH deployments, the absence of MSPD-equivalent per-MS slot tracking may cause over-granting or starvation. Single-subscriber PDCH is functionally complete.

---

### Property 9: Event label allocation and lifecycle

- **ETSI:** §21.4.2, Table 21.4 — event label (9-bit field) may replace the SSI address in MAC PDUs on assigned channels for header compression. BS allocates the label and informs the MS.
- **Motorola:** `dlai_find_acceptable_event_label_capreq` (addr `0x00203a68`), `dlai_remove_capreq_for_event_label` (addr `0x002020ec`), `dlai_is_el_capreq_allowed_to_process` (addr `0x002031c0`), `dlai_resrec_get_active_grant_for_event_label` (addr `0x001fcd60`). Full event label lifecycle: allocation on assignment, tracking by active grant, deallocation on capreq completion.
- **flowstation:**
  - `EventLabelStore` (`crates/tetra-entities/src/umac/subcomp/event_label_store.rs`) provides `get_free_label()` (linear allocation modulo 0x1FF, `event_label_store.rs:28–32`), `create_label_for_addr()`, `get_addr_by_label()`. The store is **completely disconnected** from UMAC operation: the field `event_label_store` is commented out of `UmacBs` (`umac_bs.rs:66, 143`).
  - Inbound UL MAC-DATA with `event_label` hits `unimplemented_log!("event labels not implemented")` and returns early (`umac_bs.rs:622–624`).
  - All outgoing MAC-RESOURCEs set `event_label: None` (`bs_sched.rs:1152`; `umac_bs.rs:1433, 1521, 1585, 1692`).
  - Inbound MAC-ACCESS with event label also early-returns (`umac_bs.rs:808–812`).
- **Verdict:** MISSING
- **Follow-up:** implement — event label infrastructure exists but is not wired. Required for PDCH sessions where the MS expects event-label addressing in grant responses. See Draft Issue 1.

---

### Property 10: UL grant piggybacked on DL resource

- **ETSI:** §21.4.3.2 — a `slot_granting_element` may be embedded in a `MAC-RESOURCE` PDU, piggybacking the grant on an existing downlink PDU to the same MS.
- **Motorola:** `dlai_try_to_pack_tma_req_with_grant_for_response` (addr `0x0020c910`, 192 bytes), `_try_to_fit_tma_req_with_grant_or_grant_only` (addr `0x0020c144`, 1996 bytes). Motorola packs grant elements into existing TMA PDUs if the MS already has a pending DL response.
- **flowstation:** `dl_integrate_sched_elems_for_timeslot` (`bs_sched.rs:1229–1305`) scans the per-timeslot queue for an existing `Resource` addressed to the same ISSI and merges `Grant` and `RandomAccessAck` into it. If none is found, a standalone minimal MAC-RESOURCE is created (`bs_sched.rs:1276–1300`). Usage marker is propagated from grant into the MAC-RESOURCE `usage_marker` field (`bs_sched.rs:1258–1261`). The integration is called during `finalize_ts_for_tick_inner` immediately before building the block (`bs_sched.rs:1594`).
- **Verdict:** MATCH
- **Follow-up:** none

---

### Property 11: DL fragmentation correctness (MAC-FRAG-DL / MAC-END-DL)

- **ETSI:** §21.5, §21.5.1 — DL fragmentation uses `MAC-RESOURCE` with `length_ind=0b111111` as start, followed by `MAC-FRAG-DL` (4-bit header), and `MAC-END-DL` carrying the final length.
- **Motorola:** `dlai_is_mac_frag_expected_in_grant_plan` (addr `0x001e733c`, 136 bytes), `dlai_is_grant_valid_for_fragmentation` (addr `0x001e7314`, 40 bytes), `_prevent_long_frag_due_to_frame_18_on_mspd` (addr `0x002080b0`, 160 bytes). Motorola integrates fragmentation with the grant plan and prevents fragmentation from spanning frame 18.
- **flowstation:**
  - `BsFragger::get_resource_chunk`: sets `length_ind = 0b111111` for frag start; thresholds `MIN_SLOT_CAP_FOR_RES_FRAG_START = 32` bits and `MIN_SLOT_CAP_FOR_FRAG = 16` bits (`bs_frag.rs:19–20`, `:90–121`).
  - `BsFragger::get_frag_or_end_chunk`: writes `MacFragDl` (4-bit header), or `MacEndDl` if remaining data fits (`bs_frag.rs:129–201`).
  - Frame 18: `dl_take_prioritized_sched_item` returns `None` for frame 18 (`bs_sched.rs:1445–1448`), so no fragment is emitted on frame 18. The `BsFragger` remains in `dltx_next_slot_queue` for the next multiframe.
  - `TxReporter::mark_transmitted()` called only when `is_fully_transmitted = true` (`bs_frag.rs:224–227`). `Drop` impl calls `mark_discarded()` for partially transmitted fraggers (`bs_frag.rs:234–243`).
- **Verdict:** MATCH
- **Follow-up:** none. Note: `chan_alloc_element` in MAC-END-DL is `None` always (`bs_frag.rs:148`); ETSI allows piggybacking a channel allocation in MAC-END. This is minor: `// TODO FIXME: support adding ChanAlloc element in MAC-END` (`bs_frag.rs:128`).

---

### Property 12: UL defragmentation timeout

- **ETSI:** §21.5 — no specific timeout value mandated; implementation decides how long to retain incomplete fragments.
- **Motorola:** timeout mechanism not directly named in `umac.txt`; inferred from timer symbols in `pdch_mac_strings.txt` (`PDRQ_TREQ_EXPIRY`, `PDRQ_TRSP_EXPIRY`, `PDRQ_TS_EXPIRY`). Likely on the order of T203/T204 timer classes (spec-defined timer values).
- **flowstation:** `DEFRAG_TS_BEFORE_TIMEOUT = 10 * 4 = 40 timeslots` (10 frames, ~560 ms at 18 frames/multiframe × 4 ts/frame × ~1 ms/ts) (`bs_defrag.rs:8`). `age_buffers` is called once per tick and resets incomplete buffers after the threshold (`bs_defrag.rs:30–39`). Comment: `// TODO check documentation. 10 frames.`
- **Verdict:** OPEN-QUESTION
- **Follow-up:** investigate — verify 10-frame timeout against ETSI and Motorola live trace. The value is empirically reasonable but unvalidated against spec.

---

## Findings summary

| # | Property | Verdict | Follow-up |
|---|---|---|---|
| 1 | Grant opportunity search discipline | DIVERGENT-LOW | accept |
| 2 | Subslot vs full-slot grant decision | MATCH | none |
| 3 | UL capreq handling — persistence & dedup | DIVERGENT-LOW | accept |
| 4 | MAC-RESOURCE address type (SSI vs event-label) | MISSING | implement |
| 5 | DL queue draining discipline | MATCH | none |
| 6 | Backpressure with full LLC transmit window | DIVERGENT-LOW | accept |
| 7 | Fill-frame / Null PDU on empty slot | MATCH | none |
| 8 | MSPD vs grant slot count | OPEN-QUESTION | investigate |
| 9 | Event label allocation and lifecycle | MISSING | implement |
| 10 | UL grant piggybacked on DL resource | MATCH | none |
| 11 | DL fragmentation correctness | MATCH | none |
| 12 | UL defragmentation timeout | OPEN-QUESTION | investigate |

Verdicts: MATCH ×5, DIVERGENT-LOW ×3, MISSING ×2, OPEN-QUESTION ×2.
Draft issues: 1 (Properties 4 and 9 share one root issue).

---

## Draft issues (HIGH-impact only)

### Issue draft 1: Event label support is scaffolded but not wired

**Symptoms:**
- MS initiates a PDCH session and sends MAC-DATA or MAC-ACCESS with `event_label` set in
  the capacity-request PDU. The BS silently drops it (`unimplemented_log!`).
- Outgoing MAC-RESOURCE PDUs always carry a full SSI address (`event_label: None`) even on
  assigned channels where the MS expects compact headers.
- PDCH grant responses may be ignored by Motorola terminals (MXP600, MTP3550) that map
  event-label-addressed responses only.

**Reproduction:**
1. Run flowstation with `packet_data.enabled = true` on a Motorola MXP600 or MTP3550.
2. Initiate a data call; observe the PDCH grant sequence.
3. In Wireshark / air capture, inspect the `MAC-RESOURCE` PDU following the UL capreq:
   `event_label` field should be non-null on the response. Currently it is always absent.

**Reference:**
- ETSI EN 300 392-2 §21.4.2, Table 21.4 — event-label addressing in MAC-RESOURCE.
- Motorola symbols: `dlai_resrec_get_active_grant_for_event_label` (`umac.txt:57`),
  `dlai_find_acceptable_event_label_capreq` (`umac.txt:127`).
- flowstation: `umac_bs.rs:66` (commented-out field), `umac_bs.rs:622–624` (early return),
  `bs_sched.rs:1152` (`event_label: None`), `subcomp/event_label_store.rs` (unused store).

**Suggested fix path:**
1. Uncomment `event_label_store: EventLabelStore::new()` in `UmacBs::new()`.
2. On first PDCH grant for an ISSI, call `event_label_store.create_label_for_addr(addr)` and
   embed the label in the outgoing `MAC-RESOURCE`.
3. On inbound MAC-DATA/MAC-ACCESS with `event_label`, resolve via `get_addr_by_label()`.
4. On PDCH session teardown, remove the label.
5. Test with MXP600 and compare PDCH session setup against live BRC capture.