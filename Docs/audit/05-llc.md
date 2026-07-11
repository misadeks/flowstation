# 05 — LLC BL Sublayer Audit  
**flowstation vs. Motorola DIMETRA TSC + ETSI EN 300 392-2**

| Field | Value |
|---|---|
| Report | 05-llc.md |
| Scope | BL PDU framing, LLC dispatcher, FCS, sequence numbers, ACK cadence, ordering |
| AL sublayer | → see `01-al.md` |
| Spec reference | ETSI EN 300 392-2 V3.10.1 (clause 21 LLC; clause 6.3 FCS) |
| Flowstation tag | HEAD (`misadeks/flowstation`) |
| Motorola firmware | DIMETRA TSC + rlj\_app (RLJ symbols extracted) |
| Date | 2026-07-11 |
| Verdict scale | ✅ Compliant · ⚠️ Deviation · ❌ Bug · ℹ️ N/A-or-AL |

---

## Source Map

| Artefact | Path |
|---|---|
| LLC entity | `crates/tetra-entities/src/llc/llc_bs_ms.rs` (2797 lines) |
| BL-ACK PDU | `crates/tetra-pdus/src/llc/pdus/bl_ack.rs` |
| BL-DATA PDU | `crates/tetra-pdus/src/llc/pdus/bl_data.rs` |
| BL-UDATA PDU | `crates/tetra-pdus/src/llc/pdus/bl_udata.rs` |
| BL-ADATA PDU | `crates/tetra-pdus/src/llc/pdus/bl_adata.rs` |
| LLC PDU type enum | `crates/tetra-pdus/src/llc/enums/llc_pdu_type.rs` |
| FCS component | `crates/tetra-entities/src/llc/components/fcs.rs` |
| LLC constants | `crates/tetra-pdus/src/llc/consts/consts.rs` |
| LLC timers | `crates/tetra-pdus/src/llc/consts/timers.rs` |
| TSC dispatcher | `tsc.LLCHeader_dispatcher.asm` (0x026fe710, 2608 bytes) |
| TSC BL/LLC symbols | `llc_rlj.txt` (RLJ app, rlj\_app ELF) |
| TSC function catalog | `tsc.functions.txt` (38 911 entries) |
| TSC strings | `tsc.strings.txt` + `tsc.strings_xref.txt` |

---

## Property 1 — BL vs. AL demux on 4-bit PDU-type field

**ETSI EN 300 392-2 clause 21.2.1** defines 16 PDU types (4-bit field).  
Bits 3–0 encode: `[llc_link_type][has_fcs][bl_pdu_type[1:0]]` for types 0–7 (BL),  
and `1xxxxxxx` (bit3 = 1) for types 8–15 (AL).

### flowstation

`rx_tma_unitdata_ind` (`llc_bs_ms.rs:867`) peeks 4 bits without advancing the cursor:

```rust
let Some(bits) = pdu.peek_bits(4) else { ... };           // :867
let Ok(pdu_type) = LlcPduType::try_from(bits) else { ... };  // :871
```

The `LlcPduType::try_from` covers all 16 values 0–15 (`llc_pdu_type.rs:24–46`).  
The dispatch `match` at `:883` routes:

- Types 0–7 (BL) → `rx_tma_unitdata_ind_bl`  `:893`
- Types 8–12, 15 (AL) → `rx_tma_unitdata_ind_al`  `:902`
- Types 13 (`SuppLlcPdu`), 14 (`L2SigPdu`) → `_` arm `:905–908`

### Motorola TSC

`ula_get_common_llc_pdu_type` (0x0022d3ec, 148 bytes) unpacks the LLC type.  
`ula_handle_al_common_llc_pdu_type` (0x0022d4d4, 312 bytes) handles AL variants.  
`LLCHeader_dispatcher` (0x026fe710, 2608 bytes) handles full header decode.  
The RLJ-app `ulai_unpack_llc_type` (0x00229d98, 60 bytes) is the upstream entry.

String ref `UNPACK(dataInd->LLCHeader, 8, source)` at 0x02b55e58 confirms the TSC reads 8 bits of LLC header (covering the 4-bit type + next 4 header bits in one operation).

### Analysis

The flowstation 4-bit dispatch is structurally correct.  
**⚠️ Deviation**: PDU types 13 (`SuppLlcPdu`) and 14 (`L2SigPdu`) are valid ETSI values that fall to `tracing::error!("BUG: unexpected message or state -- routing error")` and are silently dropped. The message text is misleading — these are legitimate unsupported PDU types, not internal routing errors. TSC has no equivalent `BUG` log for these.  
No crashable path (both branches `return`), but operator diagnostics are incorrect.

**Verdict: ⚠️ Deviation** — SuppLlcPdu/L2SigPdu labelled as routing BUG; should be `warn!("unsupported PDU type")`.  
**Draft issue**: `LLC-01`.

---

## Property 2 — N(S) / N(R) field widths: 1-bit BL vs. 3-bit AL

**ETSI EN 300 392-2 clause 21.2.2** (BL PDU formats):

| PDU | N(S) | N(R) | Spec ref |
|---|---|---|---|
| BL-ADATA | 1 bit | 1 bit | clause 21.2.2.2 |
| BL-DATA | 1 bit | — | clause 21.2.2.3 |
| BL-UDATA | — | — | clause 21.2.2.4 |
| BL-ACK | — | 1 bit | clause 21.2.2.1 |

AL N(S)/N(R) (3-bit for original AL, up to 4-bit for Extended AL) → **see 01-al.md**.

### flowstation

`bl_adata.rs`:
```rust
let_field!(buf, nr, 1);          // bl_adata.rs:28 — 1 bit
let_field!(buf, ns, 1);          // bl_adata.rs:29 — 1 bit
```

`bl_data.rs`:
```rust
let_field!(buf, ns, 1);          // bl_data.rs:24 — 1 bit
```

`bl_ack.rs`:
```rust
let_field!(buf, nr, 1);          // bl_ack.rs:29 — 1 bit
```

`bl_udata.rs`: no sequence field.

TX paths write identically:
```rust
buf.write_bits(self.ns as u64, 1);  // bl_data.rs:38
buf.write_bits(self.nr as u64, 1);  // bl_ack.rs:42
```

The `ns` and `nr` fields are typed as `u8` but the write truncates to 1 bit.

### Motorola TSC

`ulai_unpack_bl_data` (0x00229ffc, 84 bytes), `ulai_unpack_bl_ack` (0x0022a090, 84 bytes): symmetric sizes to flowstation parsers, consistent with a 1-bit field extraction.

### Analysis

All BL sequence-number fields are correctly encoded as 1-bit.  
**✅ Compliant**.

---

## Property 3 — FCS presence gate: when is FCS included?

**ETSI EN 300 392-2 clause 21.2.1**: the `has_fcs` flag is bit 2 (second-MSB) of the 4-bit LLC PDU type field. FCS is optional on all four BL PDU types.

### flowstation

The `has_fcs` bool is decoded from bit 1 (the second bit read) in every BL `from_bitbuf`:

```rust
let_field!(buf, has_fcs, 1);        // bl_data.rs:20 — bit 1 of 4-bit type
```

**RX path** (`llc_bs_ms.rs:982`):
```rust
if has_fcs && !fcs::check_fcs(&pdu) {
    tracing::warn!("FCS check failed");
    return;                          // :984 — PDU silently dropped
}
```

**TX paths**:

| PDU type | FCS source |
|---|---|
| BL-UDATA (outbound) | hardcoded `has_fcs: false` (`:483`) |
| BL-ACK (auto-reply) | hardcoded `has_fcs: false` (`:1239`) |
| BL-DATA / BL-ADATA | `prim.fcs_flag` from upper layer (`:637`, `:649`) |
| BL-ACK (piggybacked on TL-DATA-Req) | `prim.fcs_flag` (`:553`) |

### Motorola TSC

The TSC has **separate** unpack functions for FCS variants:

```
ulai_unpack_bl_data_fcs     0x0022a198  160 bytes
ulai_unpack_bl_udata_fcs    0x0022a238  112 bytes
ulai_unpack_bl_ack_fcs      0x0022a2a8  140 bytes
```

`al_is_fcs_flag_enabled_for_al_x_final` (0x00101ddc, 72 bytes) and `al_is_fcs_flag_enabled_for_al_x_ufinal` (0x00101e24, 72 bytes) govern AL-side FCS independently.

### Analysis

**⚠️ Deviation**: Outbound BL-UDATA always sends `has_fcs: false` (`llc_bs_ms.rs:483`) even if the upper layer set `fcs_flag = true` in the TLA primitive. The `fcs_flag` from `TlaTlUnitdataReqBl` is never consulted on the TX path. This is inconsistent with the BL-DATA/BL-ADATA path which propagates `prim.fcs_flag`. No FCS is appended even if the peer requested it.

**Verdict: ⚠️ Deviation** — BL-UDATA TX unconditionally clears `has_fcs`.  
**Draft issue**: `LLC-02`.

---

## Property 4 — FCS polynomial and initial value

**ETSI EN 300 392-2 clause 6.3**: CRC-32/MPEG-2 polynomial  
G(x) = x³²+x²⁶+x²³+x²²+x¹⁶+x¹²+x¹¹+x¹⁰+x⁸+x⁷+x⁵+x⁴+x²+x+1 = **0x04C11DB7**,  
initial remainder = **0xFFFFFFFF**, final result = ones-complement (`~crc`).

### flowstation

`fcs.rs`:

```rust
let mut crc: u32 = 0xFFFFFFFF;   // fcs.rs:9  — init ✓
// ... CRC-32 MPEG-2 shift-register loop ...
if feedback != 0 {
    crc ^= 0x04C11DB7;           // fcs.rs:26 — polynomial ✓
}
!crc                             // fcs.rs:30 — complement ✓
```

Unit test (`fcs.rs:55–62`) verifies a real-world BL-DATA capture:

```rust
let fcs = compute_fcs(&bitbuf, 5, 5 + 224);
let extracted_fcs = bitbuf.peek_bits_startoffset(5 + 224, 32).unwrap() as u32;
assert_eq!(fcs, extracted_fcs);   // fcs.rs:61
```

### Motorola TSC

`_append_fcs_to_l3_pdu` (0x001ebe88, 160 bytes), `_remove_fcs_from_l3_pdu` (0x001f6724, 84 bytes), `_restore_fcs_for_l3_pdu` (0x001f6778, 76 bytes) — FCS management in rlj\_app.  
String counters `Num_SiteLink_FR_BadFCS_PVC_A` / `_PVC_B` confirm the TSC tracks FCS failures per PVC link.

### FCS coverage window — potential bug

The `check_fcs` function (`fcs.rs:35`) computes FCS from `bitbuf.get_pos()` to `get_len()-32`. After `BlData::from_bitbuf` consumes 5 bits (4-bit type + 1-bit N(S)), `get_pos() = 5`. Therefore:

```
FCS covers: [bit 5 … bit len-33]  (TL-SDU only)
NOT covered: [bit 0 … bit 4]      (LLC type field + N(S))
```

If ETSI clause 21.4.3 requires FCS to protect the full LLC PDU including header bits, this leaves the header unprotected — a corrupt LLC type or N(S) bit would pass FCS validation.  
The test vector (`fcs.rs:57`) is consistent with this behaviour: `compute_fcs(&bitbuf, 5, 5 + 224)` explicitly starts after the header. The test passes but does not exercise header-bit corruption.

**Verdict: ✅ Compliant** on polynomial/initial value.  
**⚠️ Deviation** on FCS coverage: header bits not protected; verify against ETSI 21.4.3 (spec text ambiguous in available sources).  
**Draft issue**: `LLC-03`.

---

## Property 5 — BL-ACK generation cadence

**ETSI EN 300 392-2 clause 22.3.2.3 case d**: when a waiting ACK and an outgoing TL-DATA exist for the same link, the LLC shall issue a combined BL-ADATA instead of a separate BL-ACK.

### flowstation

**Per-PDU scheduling** (`llc_bs_ms.rs:989–992`):

```rust
if let Some(ns) = ns {
    self.schedule_outgoing_ack(msg_dltime, prim.main_address,
                               prim.carrier_num, msg_dltime.t, ns);  // :991
}
```

One entry pushed to `scheduled_out_acks` per received BL-DATA / BL-ADATA.

**ACK coalescing into BL-ADATA** (`llc_bs_ms.rs:550`):

```rust
if let Some(out_ack_n) = self.get_out_ack_seq_if_any(prim.main_address, preferred_carrier) {
    let pdu = BlAck { has_fcs: prim.fcs_flag, nr: out_ack_n };
    // … piggybacked BL-ACK on outgoing TLA-DATA-Req :552–585
```

And at `:634–641` for BL-ADATA upgrade:

```rust
if let Some(out_ack_n) = out_ack_n {
    let pdu = BlAdata { has_fcs: prim.fcs_flag, nr: out_ack_n, ns };
    // …
}
```

**Standalone ACK flush** (`submit_ack_replies_to_umac`, `:1222–1287`): drains the full `scheduled_out_acks` queue once per `tick_end`.

### Motorola TSC

`pdu_requires_bl_ack_for_u_auth_result` (0x0021e79c, 56 bytes) and `pdu_requires_bl_ack_for_u_disconnect` (0x0021e7d4, 56 bytes) are message-type-specific ACK predicates, confirming per-message ACK decisions (not a coalescing model).  
`dlai_not_ready_for_bl_data_end` (0x00208328, 800 bytes) and `dlai_not_ready_for_bl_data` (0x00208648, 212 bytes) handle end-of-BL-DATA flow on the DL.

### Analysis

ACK-per-PDU with piggyback coalescing matches ETSI 22.3.2.3 case d.  
**⚠️ Minor deviation**: `scheduled_out_acks` is an unbounded `VecDeque`. If multiple BL-DATA arrive from the same SSI in a single tick (protocol violation by peer, but possible on replay), multiple entries accumulate. `get_out_ack_seq_if_any` removes only the **first** matching entry, so surplus entries are sent as separate standalone BL-ACK PDUs in the same tick. This violates the "one ACK outstanding at a time" spirit of BL.  
Bounded by ETSI's 1-frame window (peer should not send two unanswered BL-DATA), but no defensive cap in code.

**Verdict: ✅ Compliant** on cadence design; **⚠️ Deviation** on multi-same-tick ACK accumulation.

---

## Property 6 — Fragmentation slot count (BL)

**ETSI EN 300 392-2 clause 21.2 / Annex A.2**: BL does **not** fragment. Each BL-DATA/BL-UDATA carries exactly one TL-SDU. Max TL-SDU = N.251 = **2 595 bits** (~324 octets) with FCS; 2 627 bits (~328 octets) without FCS.

### flowstation

`consts.rs:6`:
```rust
pub const N251_BL_MAX_TLSDU_LEN_BITS: u32 = 2595;
```

No fragmentation logic exists for BL PDUs. The TX path in `rx_tla_tldata_req_bl` (`llc_bs_ms.rs:534`) copies the TL-SDU verbatim into the PDU buffer:

```rust
let sdu_len = prim.tl_sdu.get_len_remaining();
pdu_buf.copy_bits(&mut prim.tl_sdu, sdu_len);   // :644, :656
```

No length guard against N.251. If `sdu_len > 2595`, the oversized SDU goes on the wire.

### Motorola TSC

`size_to_bl_limit <= bl_size` at function 0x02a25548 (2608 bytes) enforces a BL size ceiling before transmission; string context confirms this is an active gate.

### Analysis

**⚠️ Deviation**: flowstation has no TX-side enforcement of the N.251 = 2 595-bit BL TL-SDU limit. An SDU exceeding this length is transmitted unclipped. The TSC enforces the limit explicitly.

**Verdict: ⚠️ Deviation** — missing N.251 TX-side size gate.  
**Draft issue**: `LLC-04`.

---

## Property 7 — Reassembly buffer bound (BL)

**ETSI EN 300 392-2 clause 22.3.2.3**: BL has no reassembly; each PDU carries a complete TL-SDU. Per-SSI in-flight acknowledged window = 1 frame.

### flowstation

`outbound_messages` is `VecDeque<ExpectedInAck>` (`llc_bs_ms.rs:304`).  
The per-SSI flow-control in `submit_free_messages_to_umac` (`:1178`) ensures at most one submitted (UMAC-pending) frame per SSI. However the queue itself is unbounded — entries accumulate for any number of SSIs.

Retransmit constants (`consts.rs:9`, `timers.rs:16`):

```rust
pub const N252_BL_MAX_TLSDU_RETRANSMITS_ACKED: u8 = 3;
pub const T251_SENDER_RETRY_TIMER: u32 = frames!(4);   // 4 signalling frames ≈ 230 ms
```

A single unresponsive peer occupies a slot for up to `T251 × N252 = 4 × 3 = 12 frames ≈ 690 ms`.  
With many simultaneous unresponsive SSIs, `outbound_messages` grows without bound.

### Motorola TSC

No direct evidence of a hard per-SSI queue depth cap, but the TSC's `dlai_not_ready_for_bl_data_end` (800 bytes) function indicates it manages flow-control state per-DL-AI entry.

### Analysis

No BL-layer reassembly buffer is needed or present (correct).  
**ℹ️ Note**: `outbound_messages` has no maximum depth; under radio-loss storms this could become a memory pressure source. No evidence the TSC has a cap either, so flagging as an observation rather than a blocking bug.

**Verdict: ✅ Compliant** (no reassembly needed); ℹ️ observe unbounded TX queue under loss.

---

## Property 8 — LLC dispatcher unknown-PDU-type handling

**ETSI EN 300 392-2 clause 21.2.1**: PDU types 13 (`SuppLlcPdu`) and 14 (`L2SigPdu`) are specified values not in common use.

### flowstation

Top-level `rx_tma_unitdata_ind` (`llc_bs_ms.rs:905`):

```rust
_ => {
    tracing::error!("BUG: unexpected message or state -- routing error");
    return;    // :907 — silent drop after error log
}
```

Called for types 13 and 14.  
Inner BL dispatcher (`llc_bs_ms.rs:975`):

```rust
_ => {
    tracing::error!("BUG: unexpected message or state -- routing error");
    return;
}
```

Called if somehow a non-BL type reaches `rx_tma_unitdata_ind_bl` (defensive; should never fire).

No panic, no protocol REJECT, no MLE notification. PDU is silently discarded after the `tracing::error!` log.

### Motorola TSC

`ulai_unpack_llc_type` (0x00229d98, 60 bytes) and `ula_get_common_llc_pdu_type` (0x0022d3ec, 148 bytes) both return an integer status code; callers test the return value. Unknown PDU types return a `NOT_HANDLED` status and the frame is discarded without logging a crash.

### Analysis

**⚠️ Deviation**: flowstation logs a `tracing::error!("BUG: ...")` for a valid-but-unsupported ETSI PDU type, misleading operators into thinking software is defective. Should be `tracing::warn!("LLC: unsupported PDU type {:?}, dropping", pdu_type)`. TSC treats this as a clean non-fatal condition.

**Verdict: ⚠️ Deviation** — error classification; no crash risk.  
**Draft issue**: `LLC-01` (same as Property 1).

---

## Property 9 — Sequence-number wraparound (BL modulo-2)

**ETSI EN 300 392-2 clause 22.3.2**: BL operates a 1-bit send sequence V(S) ∈ {0, 1}, modulo 2.

### flowstation

`get_next_send_seq` (`llc_bs_ms.rs:395–400`):

```rust
fn get_next_send_seq(&mut self, addr: &TetraAddress) -> u8 {
    let vs = self.link_send_seq.entry(addr.ssi).or_insert(0);
    let ns = *vs;
    *vs ^= 1;   // :398 — XOR toggle 0↔1, correct modulo-2
    ns
}
```

Per-SSI state stored in `HashMap<u32, u8>` (`llc_bs_ms.rs:308`).  
V(S) starts at 0 on first message; no explicit reset on link teardown.

TX wire write (`bl_data.rs:38`):

```rust
buf.write_bits(self.ns as u64, 1);   // truncates to 1 bit
```

### Motorola TSC

`ulai_unpack_bl_data` (0x00229ffc, 84 bytes) extracts a 1-bit N(S); by symmetry, the DL packing would write 1 bit.

### Analysis

Modulo-2 wraparound via `^= 1` is correct.  
**ℹ️ Note**: V(S) is not reset when an SSI disappears from the network. On reconnect, the first outgoing BL-DATA may use V(S)=1 rather than 0, which is legal (peer will accept either), but could confuse a peer that stores expected N(S) across sessions. Not a protocol error; the peer's N(R) comparison handles this.

**Verdict: ✅ Compliant**.

---

## Property 10 — PDU length field (8-bit vs. 12-bit)

**ETSI EN 300 392-2 clause 21.2.2** (Tables 21–22, BL PDU formats): BL PDUs carry **no explicit length field**. The TL-SDU length is implicit from the MAC frame boundary. The 4-bit LLC type field is immediately followed by optional 1-bit sequence numbers, then the TL-SDU payload; the length is determined by MAC framing.

### flowstation

No length field in any BL PDU struct:

- `BlData` fields: `has_fcs: bool`, `ns: u8` — header = 5 bits total (`bl_data.rs:7–12`)
- `BlAdata` fields: `has_fcs`, `nr`, `ns` — header = 6 bits (`bl_adata.rs:9–16`)
- `BlUdata` fields: `has_fcs` — header = 4 bits (`bl_udata.rs:9–12`)
- `BlAck` fields: `has_fcs`, `nr` — header = 5 bits (`bl_ack.rs:9–16`)

The SDU is consumed via `pdu.get_len_remaining()` after header parsing — length known from buffer boundary.

### Motorola TSC

`UNPACK(dataInd->LLCHeader, 8, source)` at 0x02b55e58 reads 8 bits (the 4-bit type + 4 further header bits depending on PDU type), consistent with no separate length field.

### Analysis

**✅ Compliant** — no explicit PDU length field used or expected.  
The "8-bit vs. 12-bit" distinction from the audit scope does not apply to BL PDUs; it applies to the total MAC-layer TM-SDU length indicator, not the LLC layer.

---

## Property 11 — Ordering guarantees: BL → SNDCP

**ETSI EN 300 392-2 clause 22.3.2.3**: acknowledged BL operates a window of 1; the LLC shall not transmit the next TL-SDU until the previous one is acknowledged.

### flowstation

`submit_free_messages_to_umac` (`llc_bs_ms.rs:1178`):

```rust
let mut ssi_blocked: HashSet<u32> = HashSet::new();
for ack in self.outbound_messages.iter_mut() {
    if ack.t_submitted_to_umac.is_some() {
        ssi_blocked.insert(ack.addr.ssi);   // :1185 — mark SSI in-flight
        continue;
    }
    if ssi_blocked.contains(&ack.addr.ssi) {
        // per-link FIFO stall — ETSI §22.3.2.3  :1190–1203
        continue;
    }
    // submit :1214
    ssi_blocked.insert(ack.addr.ssi);
}
```

Arrival order preserved: `outbound_messages` is a `VecDeque` appended at the back, iterated front-to-back.  
SNDCP receives SDUs in the order they are delivered upward via `TlaTlDataIndBl` (`llc_bs_ms.rs:1058`), which is dispatch-order (single-threaded event loop).

### Motorola TSC

`dlai_not_ready_for_bl_data` (0x00208648, 212 bytes) manages the "not ready" state for downlink BL-DATA, confirming per-link serialization on the TSC side too.

### Analysis

**✅ Compliant** — strict per-SSI FIFO with single in-flight frame enforced by `ssi_blocked`.

---

## Findings Summary

| # | Property | Verdict | Draft Issue |
|---|---|---|---|
| P1 | BL vs. AL demux on PDU-type field | ⚠️ SuppLlcPdu/L2SigPdu miscategorised as BUG | LLC-01 |
| P2 | N(S)/N(R) 1-bit width for BL | ✅ Compliant | — |
| P3 | FCS presence gate | ⚠️ BL-UDATA TX always clears has_fcs | LLC-02 |
| P4 | FCS polynomial / init / coverage | ✅ Poly+init correct; ⚠️ header bits not protected by FCS | LLC-03 |
| P5 | BL-ACK generation cadence | ✅ / ⚠️ multi-same-tick ACK accumulation | — |
| P6 | Fragmentation slot count (BL) | ⚠️ N.251 TX-size limit not enforced | LLC-04 |
| P7 | Reassembly buffer bound | ✅ Compliant (no BL reassembly); ℹ️ TX queue unbounded | — |
| P8 | Unknown PDU type handling | ⚠️ Same as P1 — log severity + message misleading | LLC-01 |
| P9 | Sequence-number modulo-2 wraparound | ✅ Compliant | — |
| P10 | PDU length field (8/12-bit) | ✅ N/A — no BL length field per ETSI | — |
| P11 | Ordering guarantees BL → SNDCP | ✅ Compliant | — |

**Totals**: 11 properties · 6 ✅ Compliant · 5 ⚠️ Deviation · 0 ❌ Bug · 0 ℹ️ N/A-or-AL  
**Draft issues opened**: 4 (LLC-01, LLC-02, LLC-03, LLC-04)

---

## Draft Issues

### LLC-01: SuppLlcPdu / L2SigPdu mislabelled as routing BUG

**File**: `crates/tetra-entities/src/llc/llc_bs_ms.rs:905–908`  
**Problem**: PDU types 13 and 14 are valid ETSI values that fall to a `tracing::error!("BUG: unexpected message or state -- routing error")` branch. This fires on any peer that emits these PDU types (e.g., a future supplementary LLC service), producing false alarm-level log entries.  
**Fix**: Replace with `tracing::warn!("LLC: unsupported PDU type {:?} (types 13/14 not implemented), dropping", pdu_type)`.

### LLC-02: BL-UDATA TX unconditionally clears has_fcs

**File**: `crates/tetra-entities/src/llc/llc_bs_ms.rs:483`  
**Problem**: `let pdu = BlUdata { has_fcs: false };` ignores the `fcs_flag` from the TLA primitive. BL-DATA and BL-ADATA correctly propagate `prim.fcs_flag`; BL-UDATA silently strips it.  
**Fix**: Pass `has_fcs: prim.fcs_flag` and append FCS when set, consistent with the DATA/ADATA TX paths.

### LLC-03: FCS computed over TL-SDU only — LLC header bits unprotected

**File**: `crates/tetra-entities/src/llc/components/fcs.rs:43`  
**Problem**: `check_fcs` computes from `bitbuf.get_pos()` (= 5 for BL-DATA, 6 for BL-ADATA, 4 for BL-UDATA) rather than from bit 0. This leaves the 4-bit LLC type and 1-bit N(S) outside the protected window. A single bit-flip in the type field would pass FCS and be misrouted to the wrong handler.  
**Verify**: Confirm whether ETSI EN 300 392-2 clause 21.4.3 requires FCS to cover the full LLC PDU from bit 0 or only the TL-SDU body. If full-PDU, seek(0) before calling `compute_fcs` on the raw bitbuf.

### LLC-04: N.251 BL TL-SDU maximum length not enforced on TX

**File**: `crates/tetra-entities/src/llc/llc_bs_ms.rs:643–656`  
**Problem**: No guard enforces `N251_BL_MAX_TLSDU_LEN_BITS = 2595` on outgoing BL-DATA/BL-UDATA. An oversized SDU is transmitted, which may cause the peer MAC/LLC to silently discard it (Motorola TSC enforces this with the `size_to_bl_limit <= bl_size` check at 0x02a25548).  
**Fix**: Add `if sdu_len > N251_BL_MAX_TLSDU_LEN_BITS as usize { tracing::warn!(…); return; }` before the PDU build in `rx_tla_tldata_req_bl`.

---

## Cross-References

- **AL sublayer** (N(S) 3/4-bit, reassembly buffers, AL-ACK cadence): see `01-al.md`
- **SNDCP ordering** (how LLC delivers to SNDCP): see SNDCP audit
- `fcs.rs` is shared by BL and AL; the FCS coverage issue (LLC-03) affects both

---

*End of report 05-llc.md*