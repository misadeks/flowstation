# Stack audit — flowstation vs Motorola DIMETRA BRC + TSC

**Base commit:** `734924d` (branch `misadeks-stack-audit`, based on `feature/packet-data`)
**Date:** 2026-07-11
**Method:** Static analysis. Symbol harvesting from Motorola BRC (`rlj_app.symbols.txt`, 9 806 named PPC functions) + TSC (`tsc.functions.txt`, 38 911 identified functions) + ETSI EN 300 392-2 cross-reference. Full capstone disassembly (193 MB) and Ghidra 12.1.2 headless analysis produced as side-artifacts (see `../../` session state).

**Scope in / out:**

| In scope                                | Out of scope                              |
| --------------------------------------- | ----------------------------------------- |
| LLC AL + BL sublayers                   | WTP/WSP (covered by H24–H36)              |
| UMAC scheduler + fragmentation          | Voice / CMCE                              |
| PDCH allocator + AACH                   | MM, cipher/KM                             |
| SNDCP                                   | Dashboard, non-radio subsystems           |

**No `crates/` source changes were made.** All findings are documented for a
follow-up fix session to triage.

---

## Reports

| # | Layer                    | File                                        | Properties | HIGH / MISSING | Draft issues |
| - | ------------------------ | ------------------------------------------- | ---------- | -------------- | ------------ |
| 1 | AL (Advanced Link)       | [`01-al.md`](./01-al.md)                    | 12         | 1 HIGH + 1 MISS| 2            |
| 2 | UMAC scheduler           | [`02-umac-scheduler.md`](./02-umac-scheduler.md) | 12   | 2 MISS         | 1            |
| 3 | PDCH allocator + AACH    | [`03-pdch-aach.md`](./03-pdch-aach.md)      | 11         | 2 HIGH (P4/P5) | 2            |
| 4 | SNDCP                    | [`04-sndcp.md`](./04-sndcp.md)              | 12         | 0 (4 deviation)| 4            |
| 5 | LLC (BL sublayer)        | [`05-llc.md`](./05-llc.md)                  | 8          | 0              | 4            |

Total: **55 properties audited, 13 draft issues, 0 GitHub issues opened.**

---

## Priority matrix

Priority buckets defined in `session-state/…/plan.md`:

- **P0** — HIGH-impact spec violation with data-corruption or connection-loss risk
- **P1** — HIGH-impact deviation from Motorola *or* lower-impact bug
- **P2** — missing feature that isn't wire-visible under current test scenarios

### P0 — investigate first

| Report | Item | Root cause | Symptom |
| ------ | ---- | ---------- | ------- |
| `01-al` §P5 | **AL-DISC without UMAC TX purge** | On AL-DISC the LLC clears its own state but does not signal UMAC to purge queued MAC-DATA for that address. Motorola invokes `TmaPurgeByAddressReq` on DISC as well as re-SETUP. | Stale queued PDUs from the previous AL session leak into the next session, corrupting sequence-number continuity → retx storm or reassembly wedge. |
| `03-pdch-aach` §P5 | **PDCH reservations unbounded** | `PdchAllocator::reserve()` inserts unconditionally with no cap; UMt cursor wraps at 59 slots. | With ≥ 59 concurrent MSs on a cell, two MSs share the same UMt → downlink packets delivered to the wrong subscriber. |

### P1 — HIGH deviation or important bug (not data-corruption class)

| Report | Item | Verdict |
| ------ | ---- | ------- |
| `01-al` §P7 | **N.274 (`max_segment_retx`) negotiated but never enforced** | MISSING |
| `01-al` §P12 | `retx_count` off-by-one vs N.273 | DIVERGENT-LOW (retx budget off by 1) |
| `02-umac` §P4+P9 | **MAC-RESOURCE address type and event-label lifecycle** (combined) — flowstation always uses SSI addressing; never emits event-labels, so label reuse race is theoretical but the wire format diverges from Motorola BRC | MISSING |
| `03-pdch-aach` §P4 | **On-demand PDCH allocation vs Motorola's pre-reservation** — first user pays an extra 4-frame setup latency | DIVERGE-HIGH |
| `03-pdch-aach` §P6 | PDCH announcement hold-off during AL-SETUP | PARTIAL |
| `05-llc` §LLC-01..04 | 4 BL-sublayer bugs: FCS coverage window (LLC-03), N.251 max TL-SDU not enforced on TX (LLC-04), plus 2 minor | mixed |

### P2 — SPEC / MISSING but not currently wire-visible

| Report | Item | Note |
| ------ | ---- | ---- |
| `04-sndcp` all 4 | ISSUE-SNDCP-01…04: parameter-differing re-DEMAND, V.J. compression, PDCH release on END-OF-DATA, NSAPI reserved-range check | Compatibility-safe with all tested Motorola MSes (MTM800E / MTP3550); prioritise for feature completeness, not blocking. |
| `01-al` §P4 | T.252 value + clock-start semantics | DIVERGENT-LOW |
| `01-al` §P6 | AR flag on outbound DL AL-DATA segments | DIVERGENT-LOW |
| `02-umac` §P1 P3 P6 | Grant search discipline, capreq dedup, backpressure with full window | DIVERGENT-LOW |
| `03-pdch-aach` §P2 P3 P8 P11 | Idle-release threshold, slot-selection algorithm, UL usage-marker collision, frame-18 codec `base_frame_len` TODO | PARTIAL |

### Open questions (need more evidence before verdict)

- `01-al` §P10: `al_disable_ar_flag_for_al_data` / `_prevent_packing_al_data_with_grant_before_al_ack` semantics (rlj_app symbols exist but no matching flowstation code path).
- `01-al` §P11: `dlai_clear_slack_reserved_access_for_dl_slot` — Motorola has a slack-clear step per DL slot; flowstation appears to lack the equivalent but impact is unclear.
- `02-umac` §P8 P12: MSPD vs grant slot count relationship; UL defragmentation timeout (no timer wired).

---

## Guardrails satisfied

- [x] No files under `crates/` modified.
- [x] Every Motorola claim anchored to a symbol+addr, string ref, or ≤ 20-line PPC disasm excerpt.
- [x] Every flowstation claim anchored to `crates/…/file.rs:LINE`.
- [x] No GitHub issues opened. Draft issues live inside each per-layer report.
- [x] WTP/WSP explicitly excluded.
- [x] Each layer report committed separately for reviewability.

---

## Side artifacts (not committed to the repo — kept in session state)

- `session-state/…/files/audit/symbols/` — per-layer filtered symbol lists (AL 500, UMAC 196, PDCH 128, AACH 24, LLC 19 + all copied categorized files).
- `session-state/…/files/decomp/` — full capstone disassembly:
  - `sub_0.asm` 19.3 MB (9 636 rlj_app funcs, symbol-named)
  - `sub_1.asm` 8.7 MB (3 788 funcs)
  - `sub_2.asm` 62.9 MB (linear disasm of raw PPC blob)
  - `tsc.asm` 102.7 MB (38 911 funcs, boundaries from `tsc.functions.txt`)
- `session-state/…/files/ghidra/` — Ghidra 12.1.2 + Temurin JDK 21 installation (available for future deeper decompilation).

---

## Follow-up

None from this session. A separate fix session should triage each draft issue,
starting with the two P0 items in `01-al` §P5 and `03-pdch-aach` §P5.
