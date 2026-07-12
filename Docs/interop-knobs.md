# Interop knobs

flowstation supports several non-default behaviors intended for interoperability
with specific MS-firmware quirks. Each is documented below with its spec
noncompliance reasoning, the interop failure symptom, and how to enable.

## Configuration profiles

_Landed in Commit 6 (see `phase3-design.md`). Until then, manage individual
knobs directly._

- `interop_profile = "standard"` — spec-compliant defaults, all quirk gates off
- `interop_profile = "mtp3550"` — enables H33 + H35 + H36 + H45 + H49 + H50 for MTP3550 handset interop
- `interop_profile = "mtp6550"` — enables H46 for MTP6550 WSP-portal interop
- `interop_profile = "custom"` — manage individual gates directly

## Individual knobs

### `[llc.advanced_link] n273_zero_ack_uses_seg_cap` (H46)

**Default:** `false` (spec-compliant as of PD-REWRITE Commit 1)
**Enable with:** `true` (MTP6550 WSP portal interop only)
**Spec ref:** ETSI TS 100 392-2 §22.3.3.2 + Annex A. N.273 range 0..=7, value 0 is a legal negotiated setting meaning "no SDU retransmissions" (fire-and-forget on ACK link).
**Effect when `true`:** forces `max_retx = N.274` (rather than `min(N.273, N.274) = 0`) when N.273=0 on ACK service, non-SNDCP-bound.
**Interop failure symptom without:** MTP6550 WSP portal times out; the MS expects its N.274 retry budget honored even after negotiating N.273=0.
**Startup log:** BS emits `WARN gate="llc.advanced_link.n273_zero_ack_uses_seg_cap"` at boot when enabled.

### `[llc.advanced_link] dedupe_completed_ns` (H49)

**Default:** `true`
**Spec ref:** ETSI TS 100 392-2 §22.3.3.2.7 NOTE 6. The strategy of sending an ACK for a below-window TL-SDU while discarding the segment is explicitly permitted. This gate can be flipped off for debugging when the dedupe interferes with reproducing a bug.
**Effect when `false`:** every inbound AL-DATA is fed to the reassembler unconditionally; peer retransmissions produce duplicate upward deliveries.
**Not startup-warned:** spec-legal behavior.

### `[llc.advanced_link] h47_cached_echo_clears_rx` (H50)

**Default:** `true`
**Effect when `false`:** on a cached-echo re-emission (duplicate AL-SETUP path), RX reassembler state is preserved. May cause Frankenstein-SDU FCS failures if the peer's duplicate SETUP is actually a fresh re-establishment.
**Not startup-warned:** spec-legal behavior.

### `[wap_gateway.wtp] *` (H33 / H34 / H35)

_Documented in Commit 5 when WTP↔SNDCP wiring lands. Until then see
`crates/wap-gateway/src/wtp/responder.rs::ResponderConfig`._

## Deprecated fields (soft migration)

### `[llc.advanced_link] proactive_disc_on_retx_exhaust` (H47 — REMOVED)

**Status:** Removed in PD-REWRITE Commit 1 as a spec violation per ETSI
TS 100 392-2 §22.3.3.2.6 NOTE 1 ("The service user should immediately either
reset or disconnect the advanced link"). LLC now never spontaneously emits
AL-DISC; retx exhaustion surfaces via the `AlDeliveryOutcome::DroppedRetxExhausted`
delivery event and, once Commit 5 lands, via the formal `TlReportInd`
primitive on the TLA SAP. SNDCP (Commit 4b) then decides teardown.

**TOML migration:** Setting this field in operator TOML **logs an INFO line
and is ignored**. Config load succeeds. Remove from your TOML at your
convenience. See test `pd_rewrite_c1_deprecated_proactive_disc_field_is_ignored`
in `crates/tetra-config/src/bluestation/sec_llc.rs::tests`.

## Startup WARN messages

At BS startup, `bluestation-bs` emits a WARN log for every enabled gate + the
active `interop_profile` (once Commit 6 lands). Grep `interop gate` in the
boot log to inventory active quirks.
