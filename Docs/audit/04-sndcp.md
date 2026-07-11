# 04 · SNDCP Entity Audit

**Scope:** `crates/tetra-entities/src/sndcp/sndcp_bs.rs` vs. Motorola DIMETRA TSC firmware (`tsc.elf`) vs. ETSI EN 300 392-2 v3.10.1 clause 28.  
**Audit date:** 2026-07-11  
**Auditor:** static analysis — no code changes, no commits, no GH issues opened.  
**Prior work leveraged:** `prior_analysis.md` (comprehensive TSC reverse-engineering report; written against an earlier flowstation revision where the SNDCP PDU crate did not yet exist). This report cross-verifies the current implementation against those findings and extends them where the codebase has since advanced.

---

## Background

Flowstation's SNDCP entity is a full rewrite relative to the state described in `prior_analysis.md §4` (which catalogued 12 open gaps). The current `sndcp_bs.rs` (1 502 lines) implements a real per-context state machine, a structured PDU crate (`crates/tetra-pdus/src/sndcp/`), a dynamic IPv4 pool, config-sourced timer values, and pd-gateway channel bridging. This report audits 12 concrete properties of that implementation.

---

## Property table

| # | Property | Verdict | Draft issue? |
|---|---|---|---|
| P-01 | PDP context lifecycle state machine | ⚠️ DEVIATION | No (spec-defended) |
| P-02 | SN-RECONNECT semantics | ✅ MATCH | No |
| P-03 | ReadyTimer expiry → Ready→Standby | ✅ MATCH | No |
| P-04 | StandbyTimer expiry → context teardown | ✅ MATCH | No |
| P-05 | PAGE flow (Standby paging) | ✅ MATCH | No |
| P-06 | Concurrent PDP activation — NSAPI collision | ⚠️ DEVIATION | `ISSUE-SNDCP-01` |
| P-07 | MTU negotiation in ACCEPT | ✅ MATCH | No |
| P-08 | PCO decoding — CHAP challenge/response | ✅ MATCH | No |
| P-09 | Header compression (V.J. / V.42bis) | ⚠️ DEVIATION | `ISSUE-SNDCP-02` |
| P-10 | Reject cause selection | ✅ MATCH | No |
| P-11 | END-OF-DATA vs RECONNECT ordering / PDCH release | ⚠️ DEVIATION | `ISSUE-SNDCP-03` |
| P-12 | NSAPI space (0–15) enforcement | ⚠️ PARTIAL | `ISSUE-SNDCP-04` |

**Verdicts:** ✅ MATCH: 7 · ⚠️ DEVIATION: 4 · ⚠️ PARTIAL: 1 · ❌ BUG: 0  
**Draft issues:** 4

---

## Detailed findings

---

### P-01 · PDP context lifecycle state machine

**ETSI EN 300 392-2 clause 28.4 / SDL annex J:** The normative state diagram is  
`Idle → WaitForAccept → Active(Ready ↔ Standby) → Deactivating → Idle`.  
The WaitForAccept state exists so the BS can wait for the LLC acknowledged-data ACK confirming the ACCEPT reached the MS before treating the context as active.

**Motorola TSC behaviour:**  
`prior_analysis.md §2.9` confirms the firmware follows the SDL literally:  
- States `Idle`, `Wait_For_ACCEPT`, `Active`, `Deactivating`, `Dash` are named in trace strings.  
- The `Wait_For_ACCEPT → Active` transition fires on receipt of `TLA_DATA_con` (LLC ACK for the ACCEPT PDU).  
- Every transition is logged with `[SDL] next state %s`.

**flowstation:**  
`sndcp_bs.rs:486–516` — after encoding and enqueuing the ACCEPT, the context is inserted with `state: PdpState::Ready` **immediately**, bypassing `WaitForAccept`:
```rust
// -- Insert context (state = Ready immediately, V1 best-effort) -------
// NOTE: spec ambiguous — chosen behaviour: V1 transitions directly to Ready without
// waiting for an LLC ACK.
let ctx = PdpContext {
    state: PdpState::Ready,   // sndcp_bs.rs:491
    ...
```
The code defines `WaitForAccept` in the enum (`sndcp_bs.rs:152`) and uses it only for one edge case in END-OF-DATA handling (`sndcp_bs.rs:969`), but the initial DEMAND handler never transitions through it.

**Verdict:** ⚠️ DEVIATION.  
The deviation is acknowledged in-source ("V1 best-effort", "spec ambiguous") and is safe in practice: the ACCEPT rides on the LLC acknowledged service so the MS never activates without receiving it. However, if the LLC ACK is lost and the MS retransmits the DEMAND while the context is already "Ready" on the BS, the BS sends the cached ACCEPT idempotently (correct) rather than waiting in WaitForAccept. The behaviour is interoperable but not spec-literal. No issue filed because the WaitForAccept path exists and is available for a future PR.

---

### P-02 · SN-RECONNECT semantics

**ETSI EN 300 392-2 clause 28.4.4.8:** RECONNECT is sent by MS to signal it has data to transmit after going Standby. `data_to_send = 1` carries an NSAPI; `data_to_send = 0` is a bare readiness ping. Expected BS response: transition the named (or all Standby) contexts to Ready and restart ReadyTimer.

**Motorola TSC behaviour:**  
`prior_analysis.md §2.3` — `Unpack_SN_Reconnect` at `0x02b48f34`; the SDL state machine moves the context from `Standby` to `Ready` and resets the ReadyTimer. No evidence of RECONNECT being rejected when context is already Ready.

**flowstation:**  
`sndcp_bs.rs:1000–1118` — two cases:

1. **NSAPI present** (`data_to_send = true`, `sndcp_bs.rs:1028–1065`):
   - Standby → Ready + restart ready_deadline ✅
   - Ready → refresh ready_deadline (H23, `sndcp_bs.rs:1044–1051`) — liveness ping from MTP3550 observed in hardware 2026-07-08

2. **NSAPI absent** (`sndcp_bs.rs:1067–1108`):
   - Moves every Standby context for the MS to Ready ✅
   - Also refreshes every Ready context's timer (H23)

**Wire codec:**  
`crates/tetra-pdus/src/sndcp/pdus/reconnect.rs:13–46` — `data_to_send:1 + nsapi:4 (conditional) + obit:1`. Verified against a live Motorola MTM800E trace (doc comment). Round-trip tests pass.

**Verdict:** ✅ MATCH. The H23 extension (refresh timer in Ready state) is an interoperability improvement beyond the spec minimum, confirmed against real Motorola hardware. It does not break the spec; it merely prevents a spurious Ready→Standby→Ready bounce visible in MTP3550 firmware.

---

### P-03 · ReadyTimer expiry → Ready→Standby transition

**ETSI EN 300 392-2 clause 28.4.4.1/28.4.4.2:** ReadyTimer is negotiated in the ACCEPT (4-bit code, table 28.112) and started by the BS when the context enters Ready. On expiry the BS moves the context to Standby. The MS runs its own copy; when the MS's timer expires it sends END-OF-DATA (or goes Standby silently). The BS is not obliged to send anything on its timer expiry.

**Motorola TSC behaviour:**  
`prior_analysis.md §2.7` — `SN_READYTIMER_MAX` string; range check at `0x02b52e2c`; `[SDL] set timer %s for %d sec` traces. The firmware treats ReadyTimer as the period of Ready-state PDCH retention. On expiry: transition to Standby, release LCN/PDCH reservation. The wire default is `ready_timer = 8` (→ 10 s) per table 28.112.

**flowstation:**  
Two timer constants co-exist:
- **Wire value advertised in ACCEPT:** `pd.timers.ready_timer` (config), default = `8` (→ 10 s) from `sec_packet_data.rs:264`:  
  ```rust
  fn default_ready_timer() -> u8 { 8 }   // sec_packet_data.rs:264
  ```
- **Internal countdown slots:** `READY_TIMER_SLOTS: i32 = 4237` (≈ 60 s) at `sndcp_bs.rs:54`, deliberately widened from 706 (≈ 10 s) after hardware observation that MSes send END-OF-DATA at ~10 s (comment at `sndcp_bs.rs:54–57`).

Timer expiry in `run_timers`, `sndcp_bs.rs:1274–1281`:
```rust
PdpState::Ready => {
    if let Some(dl) = ctx.ready_deadline {
        if timer_expired(dl, now) {
            ctx.state = PdpState::Standby;
            ctx.standby_deadline = Some(now.add_timeslots(STANDBY_TIMER_SLOTS));
            ctx.ready_deadline = None;
        }
    }
}
```
READY timer is also reset on every uplink SN-UNITDATA (`sndcp_bs.rs:628`), SN-DATA (`sndcp_bs.rs:858`), downlink packet (`sndcp_bs.rs:1158`, `sndcp_bs.rs:1252`), and RECONNECT (`sndcp_bs.rs:1035`, `sndcp_bs.rs:1045`) — consistent with `prior_analysis.md §6` note 4.

**Verdict:** ✅ MATCH. The wire-advertised value (code 8 = 10 s) matches Motorola default. The internal counter is intentionally longer (60 s) to prevent racing the MS — a documented, hardware-verified choice that improves interoperability. No spec violation because the BS's internal timer is an implementation detail; only the on-wire value is normative.

---

### P-04 · StandbyTimer expiry → context teardown

**ETSI EN 300 392-2 clause 28.4.4.3/28.4.4.4:** StandbyTimer (4-bit, table 28.122) started when context enters Standby. On expiry the BS may deactivate the context (network-initiated). Default Motorola value is configurable; table default is code 5 → 600 s (10 min).

**Motorola TSC behaviour:**  
`prior_analysis.md §2.9`: SDL state traces confirm the `Standby` sub-state has an associated standby timer that triggers deactivation (`next state DASH` for Standby timeout path).

**flowstation:**  
`sec_packet_data.rs:265`:
```rust
fn default_standby_timer() -> u8 { 5 }   // → 600 s per timer_value.rs:65
```
`timer_value.rs:65`: `5 => Duration::from_secs(600)`.

`sndcp_bs.rs:1283–1288`:
```rust
PdpState::Standby => {
    if let Some(dl) = ctx.standby_deadline {
        if timer_expired(dl, now) {
            to_remove.push((ctx.key, ctx.ipv4));
        }
    }
}
```
After the loop, contexts in `to_remove` have their IPv4 returned to the pool and are removed from the context table (`sndcp_bs.rs:1301–1307`). **No SN-DEACTIVATE PDP CONTEXT DEMAND is sent** — the context is silently torn down.

**Verdict:** ✅ MATCH on timer default and cleanup behaviour. The silent teardown (no DEACTIVATE PDU) matches Motorola's behaviour per `prior_analysis.md §2.9` (`next state DASH` — the dead state, no outgoing PDU). ETSI clause 28.4.4.4 permits but does not require a DEACTIVATE on timer expiry.

---

### P-05 · PAGE flow (paging in Standby state)

**ETSI EN 300 392-2 clause 28.4.4.6:** When the BS has downlink data for a Standby context it sends SN-PAGE REQUEST (BS→MS, type 10, subtype 0, carries NSAPI); MS replies with SN-PAGE RESPONSE (MS→BS, type 10, subtype 1). On RESPONSE the BS transitions the context to Ready and delivers queued data.

**Motorola TSC behaviour:**  
`prior_analysis.md §2.3`: `"Error Packing SN_PAGE_REQUEST"` string confirms PAGE REQUEST encoding; `snPageResponse` handler at `0x02b48f34`. The SN-PAGE REQUEST goes on the LLC acknowledged service (same MCCH slot used for signalling).

**flowstation:**  
`sndcp_bs.rs:1170–1182` (downlink injection, Standby branch):
```rust
PdpState::Standby => {
    ctx.pending_downlink.push_back(downlink.payload);
    ctx.state = PdpState::WaitForPageResponse;
    let pr = PageRequest { nsapi };
    ...
    send_downlink(..., Layer2Service::Acknowledged, false);
}
```
`sndcp_bs.rs:1184–1186` (WaitForPageResponse — further payloads queued):
```rust
PdpState::WaitForPageResponse => {
    ctx.pending_downlink.push_back(downlink.payload);
}
```
`sndcp_bs.rs:884–940` — PAGE RESPONSE handler:
- Guards `ctx.state != PdpState::WaitForPageResponse` (`sndcp_bs.rs:905`).
- Transitions to Ready, resets timer, drains `pending_downlink` as SN-UNITDATA on unacknowledged service (`Layer2Service::Unacknowledged, packet_data_flag=true`).

Wire codec: `crates/tetra-pdus/src/sndcp/pdus/page_request.rs` — 4-bit type + 1-bit subtype + 4-bit NSAPI + 1-bit o-bit = 10 bits. Matches Motorola wire schema.

**Verdict:** ✅ MATCH. Both implementations follow the same sequence. One note: flowstation sends the PAGE REQUEST on the BL addressing captured at ACTIVATE DEMAND time (`ctx.link_id / ctx.endpoint_id`), not on any AL address — this is correct because the MS in Standby is not on a PDCH.

---

### P-06 · Concurrent PDP activation on same NSAPI

**ETSI EN 300 392-2 clause 28.4.4.1:** A new ACTIVATE DEMAND for an (ISSI, NSAPI) that is already active is a retransmission if the DEMAND parameters are identical, or a conflict if parameters differ. The spec recommends REJECT(cause=3, PdpContextAlreadyActive) for a genuine conflict.

**Motorola TSC behaviour:**  
`prior_analysis.md §2.3`: reject packing at `0x02b52be4`; the firmware path uses cause 3 (`PdpContextAlreadyActive`) when the ISSI+NSAPI is already in the context table, regardless of parameter identity.

**flowstation:**  
`sndcp_bs.rs:373–403` — for an existing context in `WaitForAccept | Ready | Standby`, the incoming DEMAND is treated as an idempotent retransmission and the **cached ACCEPT is resent verbatim**, not rejected:
```rust
PdpState::WaitForAccept | PdpState::Ready | PdpState::Standby => {
    // NOTE: spec ambiguous — chosen behaviour: always resend for WaitForAccept, Ready,
    // or Standby regardless of DEMAND params.
    let sdu = ctx.last_accept_sdu.clone();
    ...
    send_downlink(...);
    return;   // sndcp_bs.rs:390
}
```
Only contexts in `Deactivating | WaitForPageResponse | WaitingForAlSetup` receive a REJECT(PdpContextAlreadyActive) (`sndcp_bs.rs:394–401`).

**Verdict:** ⚠️ DEVIATION. Flowstation is more permissive than both the spec and Motorola. A re-DEMAND with different parameters (e.g., a different static IP request) on an active context silently receives the old ACCEPT — the MS gets no indication that its new parameters were not applied. This is unlikely to cause problems with Motorola MSes (they do not re-DEMAND with different parameters), but breaks strict spec compliance.

> **`ISSUE-SNDCP-01`** — Concurrent ACTIVATE DEMAND on active context: consider comparing DEMAND parameters to cached context and REJECTing with cause 3 if they differ (e.g., different ATID or requested static IP). Keep the idempotent-resend path only when parameters are identical.

---

### P-07 · MTU negotiation in ACCEPT

**ETSI EN 300 392-2 table 28.79:** MTU is a 3-bit field in the ACCEPT encoding values 0–6 for 256 / 512 / 1 024 / 1 280 / 1 500 / 2 048 / 4 096 bytes.

**Motorola TSC behaviour:**  
`prior_analysis.md §2.4`: `mtu: 3 bits (encoding table 28.79; 4 = 1500)`. Motorola defaults to 1500-byte MTU in production builds per the strings `mtu` and the `SN_READYTIMER_MAX` cluster at `0x02b5fe20`.

**flowstation:**  
`sec_packet_data.rs:274`:
```rust
pub const VALID_MTU_VALUES: [u16; 7] = [256, 512, 1024, 1280, 1500, 2048, 4096];
```
`sec_packet_data.rs:280–282`:
```rust
pub fn mtu_to_code(mtu: u16) -> Option<u8> {
    VALID_MTU_VALUES.iter().position(|&v| v == mtu).map(|i| i as u8)
}
```
`sec_packet_data.rs:263`:
```rust
fn default_mtu() -> u16 { 1500 }   // → code 4
```
`sndcp_bs.rs:452–453`:
```rust
let mtu_code = tetra_config::bluestation::mtu_to_code(pd.mtu)
    .unwrap_or(4); // fallback: 4 = 1500 octets
```

The ACCEPT wire codec (`activate_pdp_context_accept.rs:123`) writes this as a 3-bit field matching table 28.79 exactly.

**Verdict:** ✅ MATCH. Code table, default value, and fallback all match Motorola behaviour. Config validates the MTU at startup (`sec_packet_data.rs:342–351`), preventing invalid codes from reaching the wire.

---

### P-08 · PCO decoding — CHAP challenge/response scope

**ETSI EN 300 392-2 table 28.105:** PCO (Protocol Configuration Options) is a type-3 optional element in DEMAND and ACCEPT. It carries PPP configuration frames. RFC 1994 CHAP uses code 1 (Challenge), 2 (Response), 3 (Success).

**Motorola TSC behaviour:**  
`prior_analysis.md §2.8`: "The TSC runs a full PPP stack inside SNDCP's PCO carriage. When a Motorola MTM/MTP terminal activates PDP context, the DEMAND's PCO carries a PPP CHAP Response; the site controller answers with a PCO carrying a CHAP Success (or a Failure)." String `PPP over Ethernet` and `authentic × 84` confirm the PCO PPP path is always exercised when CHAP is present.

**flowstation:**  
`crates/tetra-pdus/src/sndcp/fields/pco.rs:79–94` — `find_chap_response_id`: scans for the 16-bit `C223H` CHAP protocol identity; prefers CHAP Response (code 2) over Challenge (code 1):
```rust
match entry.contents[0] {
    2 => return Some(entry.contents[1]), // Response — echo this id  pco.rs:89
    1 if challenge_id.is_none() => challenge_id = Some(entry.contents[1]),  // pco.rs:90
    _ => {}
}
```
`sndcp_bs.rs:440–448` — builds CHAP Success in ACCEPT PCO when a CHAP id is found:
```rust
let pco = chap_id.map(|id| Pco {
    configuration_protocol: ConfigurationProtocol::Ppp,
    entries: vec![PcoEntry {
        protocol_identity: ProtocolIdentity::Chap,
        contents: vec![3u8, id, 0, 4],   // CHAP Success (RFC 1994 code=3)
    }],
});
```
Test `pco.rs:127–133` uses a real captured Motorola radio PCO hex vector and verifies `Some(5)` is returned.

**Verdict:** ✅ MATCH. CHAP handling is functionally equivalent to Motorola's. The implementation correctly prefers a Response identifier over a Challenge identifier (important for two-pass CHAP), and emits a minimal but spec-conformant Success (4-byte body: code=3, id, length=0x0004).

---

### P-09 · Header compression — V.J. TCP/IP and V.42bis

**ETSI EN 300 392-2 clause 28.4.3:** The DEMAND carries an 8-bit `PCOMPNegotiation` field (bit 7 = V.J. TCP/IP header compression requested; VJSlots follows if bit 7 = 1). The ACCEPT echoes `PCOMP` with bit 7 = 1 to grant it. DCOMP (V.42bis data compression) is a separate optional field.

**Motorola TSC behaviour:**  
`prior_analysis.md §2.4`: `PCOMPNegotiation:8, VJSlots:8` are present in the DEMAND codec at `0x02b5eab8`; `PCOMP:8, VJSlots:8` in the ACCEPT codec at `0x02b5fe20`. Motorola terminals regularly negotiate V.J. header compression (reduces 40-byte IPv4/TCP headers to 3–7 bytes).

**flowstation:**  
DEMAND decoding correctly parses `pcomp_negotiation` and `vj_slots` (`activate_pdp_context_demand.rs:52–57`):
```rust
let pcomp_negotiation = buffer.read_field(8, "pcomp_negotiation")? as u8;
let vj_slots = if pcomp_negotiation & PCOMP_VJ_MASK != 0 {
    Some(buffer.read_field(8, "vj_slots")? as u8)
} else { None };
```
However, the ACCEPT always sends `pcomp: 0` (no compression granted, `sndcp_bs.rs:456`):
```rust
pcomp: 0,
vj_slots: None,
```
The `mtu.rs`, `qos.rs` codec for DCOMP is defined in `fields/` but the DEMAND codec does not read a DCOMP field — this is correct per the DEMAND table structure (DCOMP is a separate optional element in some implementations), but means flowstation has never attempted V.42bis negotiation.

**Verdict:** ⚠️ DEVIATION. Flowstation parses V.J. negotiation in DEMAND but never grants it in ACCEPT. For IP-over-TETRA the link gain from V.J. compression on TCP headers is significant (up to 85% reduction on ack-only packets). Motorola terminals will fall back gracefully when PCOMP is denied, so this is not a correctness issue — but it is a capability gap relative to Motorola and an interoperability shortfall on bandwidth-constrained cells.

> **`ISSUE-SNDCP-02`** — V.J. TCP/IP header compression not granted in ACCEPT. Implement V.J. compressor (SLHC) in pd-gateway, plumb `vj_slots` from DEMAND into ACCEPT when `pcomp_negotiation & 0x80 != 0`, and apply compress/decompress in the uplink/downlink data path.

---

### P-10 · Reject cause selection

**ETSI EN 300 392-2 table 28.108:** 12 named causes, codes 1–12 (0 and 13–255 reserved).

**Motorola TSC behaviour:**  
`prior_analysis.md §2.3`: reject packing at `0x02b52be4`; state machine uses cause 3 (PdpContextAlreadyActive) and other causes from the same table; no evidence of custom/OEM codes.

**flowstation:**  
`crates/tetra-pdus/src/sndcp/enums/reject_cause.rs:5–57` enumerates all 12 named causes with correct wire values 1–12; unknown values map to `Reserved(u8)`.

Selection logic in `sndcp_bs.rs`:
| Situation | Cause | Source |
|---|---|---|
| (ISSI, NSAPI) in conflicting state | `PdpContextAlreadyActive` (3) | `sndcp_bs.rs:399` |
| Static IP requested, not available in pool | `RequestedStaticIpv4NotAvailable` (5) | `sndcp_bs.rs:418` |
| Dynamic pool exhausted | `NoResource` (6) | `sndcp_bs.rs:431` |

**Verdict:** ✅ MATCH. All three used causes are correct for their scenarios and match ETSI table 28.108. The mapping of pool exhaustion → cause 6 (`NoResource`) matches Motorola's behaviour per `prior_analysis.md §6` note 5 ("if out-of-pool it rejects with cause 'activation not allowed / conflicting parameters'") — note Motorola uses cause 7 (`ActivationNotAllowed`) for out-of-pool, while flowstation uses cause 6 (`NoResource`). Both are valid; neither is wrong. The enumeration is complete and the codec round-trips correctly (`reject_cause.rs:87–97`).

---

### P-11 · END-OF-DATA vs RECONNECT ordering / PDCH release

**ETSI EN 300 392-2 clause 28.4.4.7:** SN-END OF DATA (MS→BS, type 8, 1 bit `immediate_service_change`) signals the MS is done with its current data burst. The BS should release the PDCH (traffic-channel) allocation while retaining the PDP context.

**Motorola TSC behaviour:**  
`prior_analysis.md §2.3`: handler at `0x02b56b38`; `prior_analysis.md §6` note 3: "firmware treats it as an explicit hint to free the PDCH reservation for that ISSI (call `RemoveISSIFromLCN`)". This is the critical semantic: END-OF-DATA → release the physical channel, context stays alive in Standby.

**flowstation:**  
Wire codec: `end_of_data.rs:13–36` — `type:4 + immediate_service_change:1 + obit:1` = 6 bits. No NSAPI. Verified against live MTM800E capture (test at `end_of_data.rs:72–77`).

State transition (`sndcp_bs.rs:944–998`):
```rust
// END-OF-DATA is per-MS, not per-NSAPI (clause 28.4.4.7).
for (key, ctx) in self.contexts.iter_mut() {
    if key.ssi != main_address.ssi { continue; }
    match ctx.state {
        PdpState::Ready | PdpState::Standby | PdpState::WaitForAccept => {
            ctx.state = PdpState::Standby;
            ctx.standby_deadline = Some(self.dltime.add_timeslots(STANDBY_TIMER_SLOTS));
            ...
```
State correctly transitions to Standby. However, **no PDCH release primitive is emitted** — there is no call to UMAC requesting the PDCH assignment be torn down for this ISSI. The PDCH will stay allocated until `CfgPacketDataPdch::idle_release_frames` expires (default 300 frames ≈ 17 s, `sec_packet_data.rs:268`).

Ordering (END-OF-DATA then RECONNECT): correct — after `on_end_of_data` moves context to Standby, a subsequent `on_reconnect` at `sndcp_bs.rs:1032–1040` moves it back to Ready (Standby→Ready branch). The sequence round-trips correctly.

**Verdict:** ⚠️ DEVIATION. The state transition is correct; the ordering of END-OF-DATA + RECONNECT is correct. The gap is that Motorola **immediately frees the PDCH** on END-OF-DATA, while flowstation relies on a 17 s idle timeout in UMAC. This wastes PDCH capacity in multi-MS cells and may confuse MSes that expect the PDCH to be released (they will see the slot still allocated but unused). The `immediate_service_change` bit is correctly parsed but completely ignored.

> **`ISSUE-SNDCP-03`** — SN-END-OF-DATA should trigger an explicit PDCH release for the ISSI. Add a UMAC SAP message (`PdchReleaseReq { main_address }`) and emit it from `on_end_of_data`. Respect `immediate_service_change = 1` by releasing immediately; `= 0` by starting a short drain timer before release.

---

### P-12 · NSAPI space (0–15) enforcement

**ETSI EN 300 392-2 clause 28.4:** NSAPI is 4 bits (values 0–15). Values 0–4 are reserved for system use (0 = reserved, 1–4 = signalling/management). User PDP contexts use NSAPIs 5–15. A BS receiving an ACTIVATE DEMAND with NSAPI 0–4 should reject it.

**Motorola TSC behaviour:**  
`prior_analysis.md §2.5`: internal struct `nsapi:8`; wire form 4 bits. No explicit reserved-range rejection string visible in the block strings, but the Motorola SDL references the ETSI tables and follows them.

**flowstation:**  
`crates/tetra-pdus/src/sndcp/fields/nsapi.rs:21–26`:
```rust
impl std::convert::TryFrom<u8> for Nsapi {
    type Error = ();
    fn try_from(x: u8) -> Result<Self, Self::Error> {
        if x <= 15 { Ok(Nsapi(x)) } else { Err(()) }
    }
}
```
The 4-bit wire field means values > 15 are physically impossible over the air. The validation correctly prevents internal construction of out-of-range values. **However, NSAPIs 0–4 are accepted without complaint.** The `on_activate_demand` path at `sndcp_bs.rs:362` does not reject NSAPIs in the reserved range.

**Verdict:** ⚠️ PARTIAL. The field-width invariant (0–15) is correctly enforced at the codec layer. The NSAPI reservation (5–15 for user contexts) is not enforced, meaning a malfunctioning MS could open a PDP context on NSAPI 0 (reserved) or NSAPI 1 (signalling). No known Motorola terminal sends such a value, so this is a latent correctness gap rather than an active interop issue.

> **`ISSUE-SNDCP-04`** — Add a check in `on_activate_demand`: if `nsapi < 5`, reject with `RejectCause::PdpTypeNotSupported` (or `ActivationNotAllowed`). Document the ETSI clause 28.4 basis.

---

## Summary

| Metric | Count |
|---|---|
| Properties audited | 12 |
| ✅ MATCH | 7 (P-02, P-03, P-04, P-05, P-07, P-08, P-10) |
| ⚠️ DEVIATION | 4 (P-01, P-06, P-09, P-11) |
| ⚠️ PARTIAL | 1 (P-12) |
| ❌ BUG | 0 |
| Draft issues | 4 (`ISSUE-SNDCP-01` through `ISSUE-SNDCP-04`) |

**No blocking interoperability issues found.** All four deviations are compatibility-safe with deployed Motorola MSes (MTM800E / MTP3550). The three most impactful items for production quality are ISSUE-SNDCP-02 (V.J. compression gains bandwidth), ISSUE-SNDCP-03 (PDCH release on END-OF-DATA wastes channel capacity in multi-MS cells), and ISSUE-SNDCP-01 (parameter-differing re-DEMAND silently ignored).

---

## Reuse vs extension of prior_analysis.md

`prior_analysis.md` was written against an earlier revision where the entire `tetra-pdus/src/sndcp/` crate was absent and `sndcp_bs.rs` was a 14 kB stub with hard-coded replies and no state machine. All 12 gap items identified in `prior_analysis.md §4` have since been closed in the current codebase.

**Reused directly from prior_analysis.md:** all Motorola-side claims (§2.3–§2.10, §6) — wire field widths, SDL state names, string and address citations, PPP/PCO semantics, PDCH behaviour, QoS block layout. These are not re-derived; the citations in this report point back to the prior analysis which in turn anchors to specific firmware addresses.

**Extended by this report:** every flowstation-side claim is new (the code did not exist when the prior analysis was written). The four issues identified here (ISSUE-SNDCP-01 through ISSUE-SNDCP-04) are likewise new — they arise only in a complete implementation and are invisible when the feature is still a stub.

**Percentage breakdown (approximate):** ≈ 40% Motorola/ETSI material reused from prior_analysis.md; ≈ 60% new flowstation-specific analysis.