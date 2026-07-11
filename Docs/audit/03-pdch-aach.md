<!--
  Audit Report 03 — PDCH Allocator and AACH State Machine
  Static analysis only.  No code changes, no commits, no GH issues opened.
  Produced: 2026-07-11
-->

# Audit 03: PDCH Allocator + AACH State Machine

**Scope:** Packet Data Channel reservation/release logic and the Access
Assignment Channel state machine that announces PDCH status to MSs.

---

## Meta

| Field | Value |
|---|---|
| **Base commit** | workspace `v0.3.9` — `misadeks/flowstation` worktree `misadeks-silver-carnival` |
| **Date** | 2026-07-11 |
| **Method** | Static read of four flowstation source files; cross-reference against 128 PDCH-tagged and 24 AACH-tagged Motorola BRC symbols (`rlj_app.symbols.txt`) plus 27 KB of PDCH/AACH debug strings from `sub_0.elf`; compared against ETSI EN 300 392-2 clauses 21.4.2, 21.4.3, 21.4.7.2, 23.2, 23.5 |
| **Disassembly** | Symbol table and string extraction only; no instruction-level disassembly was required for the checked properties |
| **Auditor** | AI research sub-agent (orchestrated static audit) |

### Guardrails

* **Read-only.** No source file was modified.
* **No commits.** No `git commit` or `git push`.
* **No GH issues.** Draft issues are listed in §6 for human triage.
* Every claim is pinned to an exact file+line citation or a Motorola symbol address.
* "Spec ambiguous" comments already present in the source are noted; the audit does **not** silently normalise them.
* MSPD / multi-slot PDCH comparison is noted where it diverges but not flagged as a defect since flowstation targets single-slot dynamic PDCH only.

---

## 1  Sources Consulted

### flowstation

| File | Lines | Role |
|---|---|---|
| `crates/tetra-entities/src/umac/subcomp/pdch_allocator.rs` | 185 | PDCH reserve / release / idle-expiry |
| `crates/tetra-entities/src/umac/umac_bs.rs` | 2 580 | PDCH tick driver; AACH arming; `handle_pdch_unitdata_req` |
| `crates/tetra-entities/src/umac/subcomp/bs_sched.rs` | 2 967 | AACH generation; slot-selection; voice-preemption guard |
| `crates/tetra-pdus/src/umac/pdus/access_assign.rs` | 239 | AACH PDU codec (frames 1–17) |
| `crates/tetra-pdus/src/umac/pdus/access_assign_fr18.rs` | 185 | AACH PDU codec (frame 18) |
| `crates/tetra-pdus/src/umac/enums/access_assign_dl_usage.rs` | 57 | DL usage-marker enum |
| `crates/tetra-pdus/src/umac/enums/access_assign_ul_usage.rs` | 59 | UL usage-marker enum |

### Motorola BRC reference

| Artifact | Key identifiers used |
|---|---|
| `pdch.txt` (128 symbols) | `process_pdch_setup_req`, `process_pdch_release_req`, `ccai_ruthless_release_pdch`, `postpone_pdch_release`, `rm_init_max_pdch_grant_pm`, `dlai_reconfigure_to_pdch`, `ccai_pdch_release_initialise` |
| `aach.txt` (24 symbols) | `dlai_pack_AACH_frame_eq_18`, `dlai_pack_AACH_frame_ne_18`, `dlai_pack_AACH_common`, `dlai_pack_AACH_uplink`, `dlai_pack_AACH_access`, `dlai_get_alternate_usage_marker`, `cca_update_channel_usage_marker`, `update_usage_marker`, `is_usage_marker_update_possible`, `schedule_usage_marker_update`, `dlai_update_usage_marker_before_transmission_if_needed` |
| `pdch_mac_strings.txt` (27 KB) | `Num_PDCH_SRPAccessNoFinalAckBRC`, `PDRQ_TREQ_EXPIRY`…`PDRQ_TRAA_EXPIRY`, `M_MAXUSERSPERDYNPDCHAN`, `pdch_hold_off_info`, `[CRM] set pdch setup hold off`, `PDCH config. race prevention`, `IN_USE_DYNAMIC_PDCH`, state strings |

### ETSI EN 300 392-2

Clauses 21.4.2 (AACH structure), 21.4.3 (PDCH announcement), 21.4.7.2
(ACCESS-ASSIGN PDU Tables 21.82–21.84), 23.2 (TDMA channel structure),
23.5 (traffic usage marker / UMt range §23.5.1, §23.5.2.2.7).

---

## 2  Properties

---

### P1 — Reserve/release atomicity

**Claim:** Concurrent `reserve()` / `expire_idle()` calls from two MSs cannot
race and corrupt the reservation table.

**ETSI reference:** No explicit atomicity requirement; implied by §21.4.3
that a slot must be reliably announced once reserved.

**Motorola reference:** `pdch_allocator.rs:29` comment "PDCH config. race
prevention" string at `0x00432240` confirms Motorola considers this a
real hazard (though for CRM channel-status state, not the allocator map
itself).

**flowstation implementation:**
`PdchAllocator` holds a plain `HashMap<u32, PdchReservation>` with no
`Mutex` or `RwLock`
(`pdch_allocator.rs:29–43`).
`UmacBs` is a single-threaded actor: all tick, message-receive, and
reserve/release calls originate from the same thread that owns
`UmacBs` (`umac_bs.rs:1544–1548`, `umac_bs.rs:2455–2526`). No
`Arc<Mutex<…>>` wrapper exists anywhere in the call graph.

**Verdict: ✅ CONFORM.**
Single-threaded actor model makes the HashMap safe without a lock.
No concurrent access is possible given current architecture.

**Follow-up:** If `UmacBs` is ever split across threads (e.g. async I/O
for PD gateway integration), `PdchAllocator` must be wrapped or
replaced with a thread-safe structure.

---

### P2 — Idle-release threshold

**Claim:** The number of idle frames before a reservation is auto-released
is correctly chosen and matches (or is justified against) Motorola's
practice.

**ETSI reference:** ETSI EN 300 392-2 does not mandate a specific idle
timeout for BS-side PDCH reservations.  §21.4.3 defines the MS-side
T_Treq / T_Trsp timers but not a BS idle-release window.

**Motorola reference:**
```
0x007704A8: PDRQ_TREQ_EXPIRY
0x007704B8: PDRQ_TRSP_EXPIRY
0x007704C8: PDRQ_TS_EXPIRY
0x007704D8: PDRQ_TCR_EXPIRY
0x007704DC: PDRQ_TZCD_EXPIRY
0x007704F0: PDRQ_TRAA_EXPIRY
0x007B2934: Num_PDCH_SRPAccessNoFinalAckBRC
```
Motorola maintains at least **six** distinct named per-PDCH timers plus a
`NoFinalAckBRC` counter.  None of these maps directly to a single
"N idle frames" threshold; DIMETRA uses a state-machine approach (PDRQ
states: INITIAL → ALLOC → IN_USE) with per-event timers rather than a
polling idle counter.

**flowstation implementation:**
```rust
// pdch_allocator.rs:8
pub const PDCH_IDLE_RELEASE_FRAMES: u32 = 300;
// Comment: "At 18 frames/second this is approximately 1 second.
//  NOTE: spec ambiguous — chosen behaviour."
```
The constant is 300 frames ÷ 18 frames/s ≈ **16.7 seconds**, *not* 1
second (the comment is wrong).  The `expire_idle` poll runs every
timeslot tick, computing:
```rust
// pdch_allocator.rs:109-111
let idle_timeslots = now.diff(r.last_used_at);
let idle_frames    = (idle_timeslots / 4).unsigned_abs();
if idle_frames >= threshold { … release … }
```
At 4 timeslots per frame this correctly yields 300 frames = 1200
timeslots.

**Verdict: ⚠️ PARTIAL.**
* The constant value (300 frames, ~16.7 s) is reasonable and interoperable
  but is not derived from any ETSI normative value; it is an unexplained
  design choice.
* Motorola uses event-driven timers (T_Treq etc.), not a polling frame
  counter; flowstation's polling approach will have up to one-timeslot
  jitter in release timing (negligible in practice).
* The inline comment ("approximately 1 second") is arithmetically wrong
  (`300 / 18 = 16.7 s`, not `1 s`).

**Follow-up:** Fix the `PDCH_IDLE_RELEASE_FRAMES` comment (trivial).
Consider adding a T_Treq-style explicit release on final-ACK timeout
(matches Motorola `Num_PDCH_SRPAccessNoFinalAckBRC`).

---

### P3 — Piggyback grant slot-selection algorithm

**Claim:** The algorithm used to select which timeslot becomes the PDCH
is correct and matches the preference implied by Motorola firmware.

**ETSI reference:** §21.4.3 leaves slot selection to BS discretion.

**Motorola reference:**
```
0x00771304: pdrq_find_single_slot_channel: found channel, lcn=%d.
0x0077133C: pdrq_find_single_slot_channel: skip lcn=%d, channel_status=%d,
            mspd_reservation=%d, ZC_deny=%d, brc_req=%d, zc_release=%d,
            reserved_req_id=%d.
```
Motorola's `pdrq_find_single_slot_channel` evaluates at least five
conditions per LCN: channel_status, MSPD reservation, ZC_deny flag,
BRC request flag, ZC release flag.

**flowstation implementation:**
```rust
// umac_bs.rs:2479-2486
let pdch_ts_chosen: Option<u8> = [4u8, 3, 2]
    .iter()
    .find(|&&ts_candidate| {
        !self.channel_scheduler.circuit_is_active(Direction::Dl, ts_candidate)
    })
    .copied();
```
Also in the SN-UNITDATA-first fallback
(`umac_bs.rs:1807-1810`) and the `handle_pdch_unitdata_req` path,
the same highest-numbered-free-TS heuristic is used.  Only a single
condition is checked: DL circuit occupancy.

**Verdict: ⚠️ PARTIAL.**
The algorithm is functionally correct for a single-carrier cell without
MSPD.  However:
* No ZC-deny or BRC-request gate is implemented (not needed since
  flowstation has no ZC federation layer in scope).
* The preference ordering (TS4 > TS3 > TS2) is a reasonable policy but is
  not validated against Motorola's actual ordering.
* The SN-UNITDATA-first fallback path (`umac_bs.rs:1807`) duplicates the
  same logic as the tick path (`umac_bs.rs:2479`) — if the policy changes,
  both must be updated consistently.

**Follow-up:** Extract the slot-selection heuristic into a named helper to
avoid duplication.

---

### P4 — PDCH allocation at AL setup: pre-reserved vs. on-demand

**Claim:** flowstation's on-demand reservation model (triggered by the
first inbound PDU) is appropriate, or a pre-reservation at AL-SETUP time
is needed to match ETSI §21.4.3 and Motorola behaviour.

**ETSI reference:** §21.4.3 states the BS "announces" the PDCH using
the AACH *before* the MS sends data on it.  The announcement is carried
in MAC-RESOURCE / MAC-SYSINFO to allow the MS to identify the channel.

**Motorola reference:**
```
0x001e39cc  96 STT_FUNC  process_pdch_setup_req
0x001e3560 616 STT_FUNC  process_mspd_setup
0x0042CA78: [CRM] set pdch setup hold off mcch_lcn:%d
0x0042CA68: [CRM] process pdch hold off expiry
```
Motorola has an explicit `process_pdch_setup_req` function (96 bytes)
and a hold-off mechanism that *delays* PDCH AACH emission until a
timer expires.  The PDRQ module drives this: it requests the CRM to set
up the PDCH in advance, then the CRM gates the AACH announcement via
the hold-off timer.  This is a **proactive** model: the BS reserves the
PDCH LCN *before* the first MS packet arrives, so the AACH can advertise
the channel continuously.

**flowstation implementation:**
The AACH `AssignedControl` marker is armed only inside
`handle_pdch_unitdata_req` (first inbound PDU) or the tick's
SN-UNITDATA-first fallback (`umac_bs.rs:1802–1827`).  There is no
`process_pdch_setup_req` analogue.  An MS that monitors the AACH *before*
sending its first PDU will never see an `AssignedControl` marker, and
therefore cannot determine whether the slot is available for PDCH
random access.

**Verdict: 🔴 DIVERGE (HIGH).**
Per ETSI §21.4.3, the PDCH announcement should precede MS data; the
current on-demand model does not satisfy this.  An MS that performs
AACH monitoring before its first SN-UNITDATA-REQ (which is valid
behaviour per the standard) will find the slot as `Unallocated` and
may not attempt PDCH access at all, falling back to MCCH-based SDS
delivery instead.

**Draft issue:** See §6 / Issue A.

---

### P5 — Max PDCH reservation count enforcement

**Claim:** flowstation enforces a maximum number of simultaneous PDCH
reservations, preventing resource exhaustion.

**ETSI reference:** No normative hard limit, but §21.4.3 implies the BS
controls access by granting / denying PDCH setup.

**Motorola reference:**
```
0x00137CB8: M_MAXUSERSPERDYNPDCHAN
0x0077F768: M_MAXUSERSPERDYNPDCHAN updated …
0x007703EC: PDRQ_MAX_USERS_PER_MSPDCH
0x00773330: Setting max users per mspdch to %d.
0x007703D0: PDRQ_MAX_USERS_PER_DYNPDCH
0x00234adc: rm_init_max_pdch_grant_pm
```
Motorola has a MIB parameter `M_MAXUSERSPERDYNPDCHAN`, a PDRQ event
`PDRQ_MAX_USERS_PER_MSPDCH`, and an `rm_init_max_pdch_grant_pm`
function.  The PDRQ module actively rejects new `PDCH_RESOURCE_REQUEST`
messages when the limit is reached:
```
0x00770F10: Received PDCH_RESOURCE_GRANT that should be rejected, lcn=%d
```

**flowstation implementation:**
```rust
// pdch_allocator.rs:29-33
pub struct PdchAllocator {
    pub reservations: HashMap<u32, PdchReservation>,
    …
}
// pdch_allocator.rs:66-84
pub fn reserve(&mut self, issi: u32, nsapi: u8, now: TdmaTime) -> bool {
    if self.reservations.contains_key(&issi) {
        …  // refresh
    } else {
        …  // insert unconditionally
    }
}
```
There is no capacity check before inserting.  Any number of ISSIs can
accumulate reservations.  A single PDCH timeslot sharing its air-time
across an unbounded number of MSs will degrade per-MS throughput to zero,
and with UMt space only [4,62] = 59 distinct values, wrapping will cause
UMt aliasing (see P8).

**Verdict: MATCH (via H40).**
Resolved 2026-07-11 by commit tag `PD-5c-H40`:
- New constant `PDCH_MAX_RESERVATIONS = 56` in `pdch_allocator.rs`
  (3 UMt values held as headroom for expire_idle / reserve races).
- `PdchAllocator::reserve()` signature changed from `bool` to
  `Option<bool>`: `Some(true)` = new, `Some(false)` = refresh (always
  accepted even at cap), `None` = admission refused with a warn log.
- `PdchAllocator::alloc_umt()` now `Option<u8>` and scans [4, 62] for a
  slot not currently held by any live reservation, so cursor wrap can
  never assign a duplicate UMt.
- Both callers in `umac_bs.rs` updated: piggyback grant path leaves the
  AACH un-armed on refusal; SN-UNITDATA-first fallback drops the PDU on
  refusal (MS retries via SN-DATA-TRANSMIT-REQUEST).
Tests: 5 new unit tests in `pdch_allocator::tests` cover the cap, the
refresh-at-cap allowance, release+re-reserve, and UMt-collision
avoidance across live reservations.

**Draft issue:** See §6 / Issue B — closed.

---

### P6 — PDCH announcement hold-off during AL setup transition

**Claim:** flowstation correctly handles the timing between AL-SETUP
completion and PDCH AACH emission, avoiding premature or late
announcement.

**ETSI reference:** §21.4.3 implies the PDCH AACH should be stable before
the MS uses the channel.

**Motorola reference:**
```
0x0042CA78: [CRM] set pdch setup hold off mcch_lcn:%d
0x0042CA68: [CRM] process pdch hold off expiry
0x0042CA8C: [CRM] start next pdch hold off timer:%d
0x0042CAB4: [CRM] crm_update_chan_after_pdch_hold_off_expiry lcn:%d
```
Motorola uses an explicit hold-off timer before activating the PDCH AACH,
giving LLC/LAPD time to finish the AL-SETUP exchange before the channel
is advertised.

**flowstation implementation:**
`set_pdch_timeslot(Some(ts))` is called immediately when the first
PDU arrives, with no hold-off:
```rust
// umac_bs.rs:1819-1820
self.channel_scheduler.set_pdch_timeslot(Some(ts));
self.pdch_allocator.current_timeslot = Some(ts);
```
The AACH change takes effect on the very next call to
`generate_bbk_block`, i.e., one timeslot later.

The `TmaPurgeByAddressReq` handler (AL re-setup case) correctly clears
the in-flight queue (`umac_bs.rs:1750–1770`) but does not gate the AACH
either.

**Verdict: ⚠️ PARTIAL.**
For the current single-carrier single-slot scope the absence of a
hold-off timer is unlikely to cause observable issues: the AACH change
happens within one timeslot after PDU arrival, which is a sub-frame
delay.  However, there is no protection against an AL-SETUP arriving
mid-announcement (cross-reference: AL/UMAC audit finding on re-setup
purge).

**Follow-up:** Consider whether a configurable hold-off (even 0 ms
default) should be provided to match Motorola's model.

---

### P7 — DL usage marker for reserved subslot (ETSI 21.4.2)

**Claim:** When a PDCH is reserved, the downlink AACH usage marker
correctly encodes the reserved status per ETSI Table 21.84.

**ETSI reference:** EN 300 392-2 Table 21.84 (ACCESS-ASSIGN, frames 1–17,
header `1x`):
- DL field1 usage marker = `000001` → "Assigned control channel"
- UL usage = `10` → "Assigned channel only"
- This selects header `10` in field b14–b13.

**Motorola reference:**
```
0x001e60fc  dlai_pack_AACH_common
0x001e6234  dlai_pack_AACH_uplink
0x001e6324  dlai_pack_AACH_access
```
The split into `common`, `uplink`, `access` variants confirms Motorola
packs header=01/10/11 in separate functions; the naming aligns with the
ETSI table.

**flowstation implementation:**
```rust
// bs_sched.rs:1813-1829
} else if self.pdch_timeslot == Some(ts.t) {
    aach.dl_usage = AccessAssignDlUsage::AssignedControl;  // → marker 1
    aach.ul_usage = AccessAssignUlUsage::AssignedOnly;      // → header 10
    aach.f2_af = Some(AccessField { access_code: 0, base_frame_len: 4 });
}
```
`to_bitbuf` serialises this as header `10` with DL marker 1:
```rust
// access_assign.rs:160-167
} else if self.ul_usage == AccessAssignUlUsage::AssignedOnly {
    let header = 2;  // 0b10
    buf.write_bits(header as u64, 2);
    let dl_usage = self.dl_usage.to_usage_marker();  // = 1 for AssignedControl
    buf.write_bits(dl_usage as u64, 6);
    …
}
```
`AccessAssignDlUsage::AssignedControl.to_usage_marker()` = 1
(`access_assign_dl_usage.rs:26`).  Bit pattern produced: `10|000001|…`.
This matches ETSI Table 21.84 header=10 / DL=000001 precisely.

**Verdict: ✅ CONFORM.**

---

### P8 — UL usage marker collision handling

**Claim:** The UMt rotation scheme prevents or detects collisions when
multiple MSs share the single PDCH timeslot.

**ETSI reference:** §23.5.1: UMt valid range [4, 62]; 0 = unallocated,
1–3 and 63 = reserved.  No BS-side collision-avoidance procedure is
specified; BSs are implicitly expected to assign unique UMts per active
reservation.

**Motorola reference:**
```
0x001e5d74  dlai_get_alternate_usage_marker
0x00214608  is_usage_marker_update_possible
0x00214664  schedule_usage_marker_update
0x002146a8  is_ready_to_update_usage_marker_after_one_transmission
0x002146d4  is_ready_to_update_usage_marker_after_all_transmissions
0x00214700  update_usage_marker
0x00214784  dlai_update_usage_marker_before_transmission_if_needed
0x002147d4  dlai_update_usage_marker_after_transmission_if_needed
```
Motorola has an **alternate** UMt getter plus a staged update pipeline
(before/after transmission) — indicating that UMt aliasing is handled
actively, with the ability to assign an alternate marker when a
conflict is detected.

**flowstation implementation:**
```rust
// pdch_allocator.rs:57-61
pub fn alloc_umt(&mut self) -> u8 {
    let umt = self.next_umt;
    self.next_umt = if umt >= 62 { 4 } else { umt + 1 };
    umt
}
// pdch_allocator.rs:38-43
/// Valid range [4, 62] per ETSI §23.5.1.  Wraps back to 4 after 62.
next_umt: u8,
```
The cursor allocates UMts in order [4…62], wrapping at 63→4.  This
gives **59 distinct values**.  If 60 or more ISSIs hold simultaneous
reservations, the cursor wraps and a new reservation receives a UMt
already held by an existing reservation:
```rust
// pdch_allocator.rs:71-83
let umt = self.alloc_umt();
self.reservations.insert(issi, PdchReservation { … umt, … });
```
There is no check that `umt` is not already in use.  There is also no
`dlai_get_alternate_usage_marker` equivalent.

UMt aliasing causes two MSs to interpret the AACH `AssignedControl`
announcement as referring to them simultaneously, leading to uplink
collision.

**Verdict: ⚠️ PARTIAL.**
* For a realistic cell with < 59 simultaneous packet-data MSs, the
  rolling cursor is safe and correct.
* No collision detection or alternate-UMt mechanism exists, unlike
  Motorola.
* Combined with P5 (no max PDCH count), a pathological or adversarial
  load could force UMt aliasing.

**Follow-up:** Add a uniqueness check in `alloc_umt` that skips any
UMt already present in `reservations`.  59 slots is sufficient for any
realistic single-TS PDCH load.

---

### P9 — Default marker for unreserved slots

**Claim:** Timeslots that are not in PDCH or Traffic mode emit the correct
AACH value for "unallocated" (not "common control").

**ETSI reference:** §21.4.2 / Table 21.84: DL marker 0 = Unallocated, UL
marker 0 = Unallocated.  A slot not carrying any channel should not
advertise itself as CommonControl (marker 2) since that would invite
unnecessary random access attempts.

**Motorola reference:** (Not directly observable from symbol names; common
control AACH is confirmed by `dlai_pack_AACH_common` at `0x001e60fc`
existing as a separate function, implying it is not the default path.)

**flowstation implementation:**
```rust
// bs_sched.rs:1830-1841
} else {
    aach.dl_usage = if let Some(usage) = dl_traffic_usage {
        AccessAssignDlUsage::Traffic(usage)
    } else {
        AccessAssignDlUsage::Unallocated
    };
    aach.ul_usage = if let Some(usage) = ul_traffic_usage {
        AccessAssignUlUsage::Traffic(usage)
    } else {
        AccessAssignUlUsage::Unallocated
    };
}
```
`AccessAssignDlUsage::Unallocated` serialises as `to_usage_marker()` = 0
(`access_assign_dl_usage.rs:26`).  This selects header `11` in
`to_bitbuf` and writes DL marker 0 and UL marker 0:
```rust
// access_assign.rs:169-178
let header = 3;
buf.write_bits(dl_usage as u64, 6);  // = 0
buf.write_bits(ul_usage as u64, 6);  // = 0
```
Bit pattern `11|000000|000000` = both subslots unallocated.
TS1 on a primary MCCH carrier emits `CommonControl` (marker 2),
not `Unallocated`, which is correct.

**Verdict: ✅ CONFORM.**

---

### P10 — AACH state machine transitions: announcement → reserved → freed

**Claim:** The AACH state machine correctly drives the slot through the
three phases visible to the MS: (a) no announcement, (b) `AssignedControl`
/ `AssignedOnly` when a PDCH is active, (c) reversion to `Unallocated`
or `Traffic` when the PDCH is freed.

**ETSI reference:** §21.4.3 / §23.5.

**Motorola reference:** `IN_USE_DYNAMIC_PDCH` / `IN_USE_STATIC_PDCH`
channel-status strings at `0x00431EEC` / `0x00431E9C` confirm Motorola
has explicit channel-status transitions for PDCH.

**flowstation implementation:**

**(a) Arming (announcement):**
```rust
// umac_bs.rs:1819-1820 (SN-UNITDATA-first path)
self.channel_scheduler.set_pdch_timeslot(Some(ts));
self.pdch_allocator.current_timeslot = Some(ts);
```

**(b) Sustained emission (reserved):**
```rust
// bs_sched.rs:1813-1829
} else if self.pdch_timeslot == Some(ts.t) {
    aach.dl_usage = AccessAssignDlUsage::AssignedControl;
    aach.ul_usage = AccessAssignUlUsage::AssignedOnly;
    aach.f2_af = Some(AccessField { access_code: 0, base_frame_len: 4 });
}
```
Emitted every non-frame-18 timeslot tick while `pdch_timeslot == Some(ts)`.

**(c) Release — idle expiry:**
```rust
// umac_bs.rs:2467-2470
if !released.is_empty() && self.pdch_allocator.reservations.is_empty() {
    self.channel_scheduler.set_pdch_timeslot(None);
    self.pdch_allocator.current_timeslot = None;
}
```

**(c) Release — explicit PdchReleaseReq:**
```rust
// umac_bs.rs:1731-1734
if self.pdch_allocator.reservations.is_empty() {
    self.channel_scheduler.set_pdch_timeslot(None);
    self.pdch_allocator.current_timeslot = None;
}
```

**(c) Voice preemption (atomic):**
```rust
// bs_sched.rs:1068-1075
if Some(circuit.ts) == self.pdch_timeslot {
    tracing::warn!("… clearing AssignedControl AACH");
    self.pdch_timeslot = None;
}
```
`create_circuit` is called *before* the next `generate_bbk_block`,
so the AACH transitions from `AssignedControl` to `Traffic` in the same
frame as the voice circuit creation — atomic from the MS perspective.

Unit-test coverage:
- `bs_sched.rs:2601` `pdch_slot_generates_assigned_control_aach` — ✓
- `bs_sched.rs:2626` `pdch_slot_cleared_returns_to_unallocated_aach` — ✓
- `bs_sched.rs:2653` `voice_circuit_preempts_pdch_clears_pdch_slot` — ✓

**Priority rule** (hangtime > PDCH > Traffic/Unallocated) is enforced by
`if in_hangtime … else if self.pdch_timeslot … else …` ordering
(`bs_sched.rs:1803–1841`).

**Verdict: ✅ CONFORM.**

---

### P11 — Frame 18 periodic AACH and `AccessAssignFr18` codec

**Claim:** The frame-18 AACH is encoded with the correct header and field
layout per ETSI Table 21.82, and the Motorola firmware confirms the same
frame-18 code path distinction.

**ETSI reference:** EN 300 392-2 Table 21.82 (ACCESS-ASSIGN frame 18):
- header `11` (= 3): field1 = traffic UMt; field2 = access field.
- headers `00/01/10`: field1 and field2 are both access fields.
The table structure is *different* from the frames 1–17 encoding
(Table 21.84 for which header `01`/`10` have field1 = DL UMt).

**Motorola reference:**
```
0x001e649c  dlai_pack_AACH_frame_eq_18   (212 bytes)
0x001e6570  dlai_pack_AACH_frame_ne_18   (236 bytes)
0x00205ef4  _pm_start_packing_mspd_frame_eq_17   (140 bytes)
0x00205f80  _pm_start_packing_pdch_frame_ne_18   (368 bytes)
0x002073c4  _qam_start_packing_pdch_frame_eq_18  (268 bytes)
```
Motorola has **separate functions** for frame-18 and non-frame-18 AACH
packing, confirming the codec bifurcation matches ETSI Table 21.82.

**flowstation implementation:**
```rust
// bs_sched.rs:1744
if ts.f != 18 {
    … AccessAssign codec …
} else {
    … AccessAssignFr18 codec …
}
```
`AccessAssignFr18` correctly implements Table 21.82:
```rust
// access_assign_fr18.rs:60-125
match s._header {
    0 | 1 | 2 => {
        // both fields are access fields — correct
        s.f1_af1 = Some(…); s.f2_af2 = Some(…);
    }
    3 => {
        // field1 = traffic UMt; must be_traffic()
        let ul_usage = AccessAssignUlUsage::from_usage_marker(field1)…?;
        if !ul_usage.is_traffic() { return Err(InvalidValue) }
        s.f2_af = Some(…);  // access field
    }
}
```
The `!ul_usage.is_traffic()` guard (`access_assign_fr18.rs:109-113`) was
added per PR #85 credit (doc-comment `access_assign_fr18.rs:97-106`);
previously a panic occurred on malformed bursts.

**Known caveat:**
```rust
// bs_sched.rs:1884
// TODO FIXME: Access field defaults are possibly not great
aach.to_bitbuf(&mut aach_bb);
```
The frame-18 `AssignedOnly` branch uses `base_frame_len: 0` for both
access fields (`bs_sched.rs:1871-1883`), while the `CommonOnly` branch
uses `base_frame_len: 1` (subslot 1) and `0` (subslot 2).  Per ETSI
§21.4.7.2, `base_frame_len` of 0 means "1 frame" — this is technically
valid but may not be the intended default and is not compared against
Motorola's emitted value (no string evidence available).

**Motorola cadence:**
Motorola `_pm_start_packing_mspd_frame_eq_17` suggests Motorola's
internal frame numbering is 0-indexed (frame 17 = ETSI frame 18).
This is consistent with flowstation's ETSI 1-indexed `ts.f == 18` check.

**Verdict: ⚠️ PARTIAL.**
* Codec split is correct.
* `!is_traffic()` crash guard is correct and important.
* `base_frame_len: 0` in the `AssignedOnly` frame-18 path is flagged
  by a TODO; the spec allows it but it is unverified against Motorola
  emitted values.

**Follow-up:** Resolve TODO on frame-18 `base_frame_len` defaults;
verify against an AACH capture from a live Motorola cell on frame 18.

---

## 3  Findings Summary Table

| # | Property | Verdict | Severity |
|---|---|---|---|
| P1 | Reserve/release atomicity | ✅ CONFORM | — |
| P2 | Idle-release threshold (300 frames, comment error) | ⚠️ PARTIAL | LOW |
| P3 | Slot-selection algorithm (highest-free-TS) | ⚠️ PARTIAL | LOW |
| P4 | PDCH allocation model (on-demand vs. pre-reserved) | 🔴 DIVERGE | HIGH |
| P5 | Max PDCH reservation count enforcement | ✅ MATCH (via H40) | — |
| P6 | PDCH announcement hold-off during AL setup | ⚠️ PARTIAL | MEDIUM |
| P7 | DL usage marker for reserved subslot | ✅ CONFORM | — |
| P8 | UL usage marker collision handling | ⚠️ PARTIAL | MEDIUM |
| P9 | Default marker for unreserved slots (Unallocated = 0) | ✅ CONFORM | — |
| P10 | AACH state machine transitions: arm → sustain → free | ✅ CONFORM | — |
| P11 | Frame-18 periodic AACH (AccessAssignFr18 codec) | ⚠️ PARTIAL | LOW |

**Verdict counts:** CONFORM 4 · MATCH-via-fix 1 · PARTIAL 5 · DIVERGE/GAP 1

---

## 4  Spec Ambiguity Notes

The following items are marked `NOTE: spec ambiguous — chosen behaviour`
in the source code.  They are not counted as defects but are catalogued
here for traceability.

| Location | Ambiguity | Chosen behaviour |
|---|---|---|
| `pdch_allocator.rs:7-8` | Idle-release frame count | 300 frames (~16.7 s) |
| `pdch_allocator.rs:22-25` | UMt assignment timing | Assigned at reservation creation; echoed in AACH Traffic(UMt) field |
| `pdch_allocator.rs:39-43` | UMt cursor scope | Per-allocator (not per-timeslot) |
| `pdch_allocator.rs:100-103` | Frame counting from `TdmaTime.diff()` | `(timeslots / 4).unsigned_abs()` |
| `umac_bs.rs:100-104` | ACCESS-DEFINE emission semantics | Not emitted at boot; access-code-A embedded in SYSINFO optional field |
| `umac_bs.rs:1842-1844` | ACCESS-DEFINE override defaults | `common_or_assigned_control = true`, conservative V1 timings |
| `bs_sched.rs:1884` | Frame-18 access field `base_frame_len` | 0 (= "1 frame"); flagged as TODO |

---

## 5  Minor Code Issues (Non-defect)

**M1 — `PDCH_IDLE_RELEASE_FRAMES` comment wrong**
`pdch_allocator.rs:8`: comment says "approximately 1 second" but
300 frames ÷ 18 frames/s = **16.7 seconds**.

**M2 — `to_bitbuf` panic on wrong `ul_usage` for header-3**
`access_assign.rs:174`: `self.ul_usage.to_usage_marker().unwrap()` will
panic if `ul_usage` is `CommonOnly`, `CommonAndAssigned`, or
`AssignedOnly` and the code falls through to the `else` branch (header=3
path).  `to_usage_marker()` returns `None` for those variants, causing
an unwrap panic.  The call site in `to_bitbuf` should return an error
or use `unwrap_or` with a logged fallback, since a misconfigured caller
can trigger this in production without a prior assertion.

**M3 — Slot-selection logic duplicated**
`umac_bs.rs:1807-1810` and `umac_bs.rs:2479-2486` contain identical
`[4u8, 3, 2].iter().find(…circuit_is_active…)` expressions.  A divergence
during maintenance would silently create inconsistent slot-selection
between the SN-UNITDATA-first fallback and the main tick path.

---

## 6  Draft Issues for HIGH-severity Findings

### Issue A — P4: PDCH not pre-announced before first MS packet

**Severity:** HIGH
**Component:** `crates/tetra-entities/src/umac/umac_bs.rs`,
`crates/tetra-entities/src/umac/subcomp/bs_sched.rs`

**Description:**
Per ETSI EN 300 392-2 §21.4.3, the BS is responsible for advertising the
PDCH via the AACH *before* the MS is expected to use it.  Currently
flowstation sets `pdch_timeslot = Some(ts)` only when the first inbound
TMA SDU with `packet_data_flag=true` arrives (`umac_bs.rs:1819`).

An MS performing AACH monitoring before sending its first SNDCP PDU will
observe `Unallocated` on all TS2–TS4 and may conclude that no PDCH is
available.  This is inconsistent with ETSI §21.4.3 and Motorola's
proactive `process_pdch_setup_req` model.

**Proposed remediation:**
Introduce a `pdch_enabled` AACH state that is active as long as
`packet_data_enabled = true` and at least one eligible timeslot is free,
regardless of whether any MS has sent a PDU.  The PDCH timeslot selection
should run at cell boot (or when `packet_data_enabled` transitions to
true) rather than on first PDU arrival.

---

### Issue B — P5: No maximum PDCH user count enforced

**Severity:** HIGH
**Component:** `crates/tetra-entities/src/umac/subcomp/pdch_allocator.rs`

**Description:**
`PdchAllocator::reserve()` inserts unconditionally into `reservations`
with no capacity check (`pdch_allocator.rs:66-84`).  Motorola gates new
PDCH grants on `M_MAXUSERSPERDYNPDCHAN` (MIB parameter) and
`rm_init_max_pdch_grant_pm`.

Unbounded reservations create two secondary hazards:
1. UMt namespace exhaustion: with > 59 simultaneous reservations the
   rotating cursor [4,62] wraps and aliases, causing two MSs to share the
   same UMt (P8).
2. Scheduling collapse: a single TS4 with many MSs time-sharing it will
   deliver near-zero throughput per MS.

**Proposed remediation:**
Add a `max_reservations: usize` field to `PdchAllocator` (configurable
via `config.packet_data.max_users`; default 16 to match a conservative
single-slot capacity).  `reserve()` returns a `Result<bool, PdchError>`
and returns `Err(PdchError::Capacity)` when the limit is reached.
The `UmacBs` caller should emit a `PDCH_RESOURCE_DENY` equivalent.

---

## 7  Cross-references

* **AL/UMAC audit (brief 01):** P4 and P6 of this report are the
  PDCH-side view of the AL-SETUP timing issue flagged in AL brief §3.
  The `TmaPurgeByAddressReq` path (`umac_bs.rs:1750`) was introduced
  to address the AL re-setup purge; PDCH pre-announcement is the
  remaining open item.
* **FACCH_CONNECT_FIX_REPORT.md:** No direct overlap; FACCH concerns
  circuit-mode only.

---

*End of Audit 03.*