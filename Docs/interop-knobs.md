# Interop knobs

flowstation supports several non-default behaviors intended for interoperability
with specific MS-firmware quirks. Each is documented below with its spec
noncompliance reasoning, the interop failure symptom, and how to enable.

## Behavioral note: retransmission budget change (PD-REWRITE Commit 2b)

Prior to Commit 2b, the LLC AL retx machine used a **cap-based** logic:
`effective_max_retx = min(N.273, N.274)` — total attempts per SDU capped at
`min(N.273, N.274)`.  Commit 2b implements the spec-mandated
**N.274→N.273 escalation** per ETSI TS 100 392-2 §22.3.3.2.6 clause b: on
per-segment N.274 exhaust, the LLC restarts the SDU from segment 0 using
the original segmentation, consuming one N.273 budget.  Drop with
`DroppedRetxExhausted` only when **both** N.274 and N.273 are exhausted.

**Airtime impact:** total attempts per SDU now scale as
`N.274 × (N.273 + 1)` in the general case — a substantial increase over
the old `min(N.273, N.274)` cap.  Example: with the common (N.273=3,
N.274=3) negotiation, the old logic drops after 3 attempts; the new logic
drops after up to 12 attempts (3 per-segment attempts × 4 segmentation
rounds).  This is spec-compliant and expected — it gives the SDU more
chances to land on air before SNDCP is notified of failure.

**Short-circuits (behavior unchanged):**
* `N.274 == 0`: fire-and-forget; escalation never fires; drop after 0 retx.
* `N.273 == 0` (without H46 gate): min-based logic yields per-segment cap
  of 0; drop after 0 retx.
* `N.273 == 0` (with H46 gate = `n273_zero_ack_uses_seg_cap = true`):
  per-segment cap becomes N.274, but no N.273 budget exists to escalate
  against — drop after N.274 attempts.  MTP6550 behavior preserved.

**Operator-visible log signal:** each escalation emits an INFO log:
`AL link {:?} N(S)={} N.274 exhausted — escalating to full-SDU retx {}/{}
(§22.3.3.2.6)`.  Grep `escalating to full-SDU retx` in the boot log to
inventory active escalations.

## WAP gateway WSP capability handling (PD-11-H1)

The WAP gateway's WSP ConnectReply builder can echo the MS-proposed
capability list in two modes. The choice is genuinely MS-firmware
dependent — some UP.Browser builds accept verbatim echo, others need
Kannel-style stripping. Neither is universally correct.

Set via `wsp_capability_mode` in the `[wap_gateway]` TOML section:

```toml
[wap_gateway]
wsp_capability_mode = "verbatim_echo"   # default
# wsp_capability_mode = "sanitize"      # legacy Kannel-parity behaviour
```

**`verbatim_echo` (default, PD-11-H1):** Every capability the MS proposed
comes back byte-for-byte in the ConnectReply, including Openwave's
`Protocol-Options: 0xF0` (Confirmed-Push + Push + Suspend/Resume +
Ack-Headers) and the `x-up-1` Extended-Method. Documented as
tested-working for UP.Browser 6.3 on Motorola MTP3550 in
`crates/wap-gateway/src/wsp/caps.rs` and `crates/wap-gateway/src/lib.rs`
module-level docs.

**`sanitize` (opt-in, legacy PD-10b-H5):** Kannel `sanitize_capabilities()`
parity. Clears top 4 bits of `Protocol-Options` (`0xF0 → 0x00`) and
refuses Extended-Methods / Header-Code-Pages with a zero-length
payload (wire bytes `01 86`). Some MS firmware revisions want this.

**Symptom to look for when the mode is wrong:** MS re-Invokes the same
tid every ~4–8 s despite the WTP layer confirming AL-ACK delivery. The
gateway log shows repeated `H33: re-Invoke on ResultSent txn — replaying
cached Result` entries and `H36: LLC AL-ACK observed` on the same tid —
meaning the Result reaches MS at LLC level but MS's WSP rejects the
ConnectReply content. Flip the mode and rerun.

Both modes always emit `Encoding-Version: 1.3` in the headers block
(wire bytes `C3 93`) because absence defaults MS to WSP 1.2 encoding
per WAP-230 §8.4.2.70 and every tested browser accepts 1.3.

**Startup log signal:** the gateway emits an INFO log naming the active
mode: `wap-gateway WSP ConnectReply capability mode selected
wsp_capability_mode=verbatim_echo`.

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

