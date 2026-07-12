# Interop knobs

flowstation supports several non-default behaviors intended for interoperability
with specific MS-firmware quirks. Each is documented below with its spec
noncompliance reasoning, the interop failure symptom, and how to enable.

## Configuration profiles

**Landed in Commit 6.** Set via `interop_profile` in the `[llc]` TOML section:

```toml
[llc]
interop_profile = "mtp3550_interop"  # or "standard" / "mtp6550_interop" / "custom"

[llc.advanced_link]
# individual knobs still overridable; explicit values win over profile defaults
```

### Available profiles

- **`standard`** *(default)* — spec-compliant behavior everywhere. Interop
  gates are at their spec-default values (H46 off, H49/H50 default-true per
  §22.3.3.2.7 NOTE 6). Recommended for greenfield deployments and mixed-fleet
  test benches.
- **`mtp3550_interop`** — names the H49 + H50 LLC gates as an interop group
  for MTP3550 handset fleets. Both are default-true today, so this profile
  is functionally a no-op relative to `standard` at Commit 6 landing. The
  profile exists to (a) give operators a stable named surface, (b) let future
  default-flip commits change semantics without silently breaking MTP3550
  interop, (c) accommodate the eventual Commit 6b (see below) which will
  add WTP-side gates (H33/H35/H36/H45) to this profile.
- **`mtp6550_interop`** — enables H46 (`n273_zero_ack_uses_seg_cap = true`)
  for MTP6550 WSP-portal interop. Spec-noncompliant per ETSI TS 100 392-2
  §22.3.3.2 + Annex A; startup emits a WARN log naming the gate.
- **`custom`** — no profile-driven overrides. Every knob comes from either
  an explicit TOML value or the spec-compliant default.

### Precedence rule

**explicit knob > profile default > spec default.**

Setting `n273_zero_ack_uses_seg_cap = false` in `[llc.advanced_link]` under
`interop_profile = "mtp6550_interop"` disables the H46 quirk even though
the profile enables it. This lets operators use a named profile as a
starting point and override specific gates when needed.

### Commit 6b future scope

The WTP-side interop mechanisms (H33/H34/H35/H36/H45) are currently
**always-on** because they're hardcoded in `wap-gateway`'s
`ResponderConfig::default()` and const `AL_SUPPRESS_WINDOW`. A future
commit (Commit 6b in `phase3-design.md`) will make them individually
configurable and the `mtp3550_interop` profile will then also gate them.
Operators using MTP3550 hardware currently get those behaviors regardless
of profile choice — this is intended for the current commit.

**H34 is orthogonal** (WAP-201 legal on its own); not part of any profile.

## Individual knobs

### `[llc.advanced_link] n273_zero_ack_uses_seg_cap` (H46)

**Default:** `false` (spec-compliant as of PD-REWRITE Commit 1)
**Enable with:** `true` (MTP6550 WSP portal interop only)
**Profile shortcut:** `interop_profile = "mtp6550_interop"`
**Spec ref:** ETSI TS 100 392-2 §22.3.3.2 + Annex A. N.273 range 0..=7, value 0 is a legal negotiated setting meaning "no SDU retransmissions" (fire-and-forget on ACK link).
**Effect when `true`:** forces `max_retx = N.274` (rather than `min(N.273, N.274) = 0`) when N.273=0 on ACK service, non-SNDCP-bound.
**Interop failure symptom without:** MTP6550 WSP portal times out; the MS expects its N.274 retry budget honored even after negotiating N.273=0.
**Startup log:** BS emits `WARN gate="llc.advanced_link.n273_zero_ack_uses_seg_cap"` at boot when enabled.

### `[llc.advanced_link] dedupe_completed_ns` (H49)

**Default:** `true` (spec-legal per §22.3.3.2.7 NOTE 6)
**Profile shortcut:** `interop_profile = "mtp3550_interop"` (names it explicitly)
**Spec ref:** ETSI TS 100 392-2 §22.3.3.2.7 NOTE 6. The strategy of sending an ACK for a below-window TL-SDU while discarding the segment is explicitly permitted. This gate can be flipped off for debugging when the dedupe interferes with reproducing a bug.
**Effect when `false`:** every inbound AL-DATA is fed to the reassembler unconditionally; peer retransmissions produce duplicate upward deliveries.
**Startup log:** WARN emitted when enabled (part of the mtp3550_interop inventory since Commit 6).

### `[llc.advanced_link] h47_cached_echo_clears_rx` (H50)

**Default:** `true`
**Profile shortcut:** `interop_profile = "mtp3550_interop"` (names it explicitly)
**Effect when `false`:** on a cached-echo re-emission (duplicate AL-SETUP path), RX reassembler state is preserved. May cause Frankenstein-SDU FCS failures if the peer's duplicate SETUP is actually a fresh re-establishment.
**Startup log:** WARN emitted when enabled (Commit 6).

### `[wap_gateway.wtp] *` (H33 / H34 / H35 / H36 / H45)

_Documented in Commit 6b when WTP↔config wiring lands. Until then see
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
convenience.

## Startup INFO / WARN messages

At BS startup, `bluestation-bs` emits:
- One INFO log naming the active `interop_profile`.
- One WARN log per enabled interop gate (naming the gate + spec section
  + interop target + active profile).

Grep `interop gate` in the boot log to inventory active quirks, or
`interop_profile` for the profile choice.

