# WAP portal — design & status

Built-in status portal served by `wap-gateway` so MS radios (Motorola MTP3550 /
MTP6550, UP.Browser 6.3) can browse live FlowStation state over WSP without
any external HTTP server. Landed on `feature/wap-portal`, branched off
`feature/packet-data`.

## Architecture

### Layering

`wap-gateway` stays free of any dependency on `tetra-entities` /
`tetra-config`. Portal handlers receive live state through a narrow trait
defined inside `wap-gateway` itself:

```rust
pub trait PortalDataSource: Send + Sync + std::fmt::Debug {
    fn radios(&self, max: usize) -> Vec<RadioSnapshot>;
    fn system(&self) -> SystemSnapshot;
}
```

The trait methods are **synchronous**: `DashboardState` is backed by
`std::sync::RwLock`, so wrapping the calls in async futures would only add a
`Box::pin` per request without changing the underlying blocking behaviour.

`bluestation-bs` supplies the concrete impl (`BluestationPortalData`) as a
thin adapter over startup state; see
[the MVP note below](#mvp-vs-full-live-data-wiring) for what's wired today
versus what's deferred.

### Dispatch

`WspHandler::handle_get` resolves the request URI as before, then — if a
portal is configured — matches the resolved path against the portal's
`path_prefix`. Portal hits are served locally; misses fall through to the
existing `upstream_base` reqwest relay. Non-portal URIs behave byte-identical
to the pre-portal build.

### Page tree

```
/portal              index → 1 Radios · 2 Weather · 3 System
/portal/radios       top-N live radios (ISSI · callsign · [RSSI] · N s)
/portal/weather      cached METAR line for the configured ICAO
/portal/system       version · uptime · pdp contexts · cell load
```

Every response body is ≤ 350 B WMLC (empirically safe on MTP3550).
`Content-Type` is emitted as the WSP short-form well-known
`application/vnd.wap.wmlc` (wire byte `0x94`). WBXML v1.1, WML 1.1 public-ID.

## Config

New sub-table `[wap_gateway.portal]` in the main FlowStation config, validated
in `tetra_config::bluestation::sec_wap_gateway`:

| key                     | type    | default    | notes                                    |
|-------------------------|---------|------------|------------------------------------------|
| `enabled`               | bool    | `false`    | when false the portal is not constructed |
| `path_prefix`           | string  | `"/portal"` | must start with `/`                     |
| `metar_icao`            | string  | `""`       | empty disables the weather page          |
| `metar_refresh_seconds` | u32     | `1800`     | background poll interval                 |
| `radios_max`            | u8      | `5`        | rows on the radios page                  |

Unknown keys in either `[wap_gateway]` or `[wap_gateway.portal]` are
rejected by the config validator (`parsing.rs` walks the `extra` bag on
both levels).

## Runtime

```
RunConfig {
    listen_addr, listen_port, upstream_url,
    portal: Option<PortalRunConfig { config, data }>,
}
```

`wap_gateway::run` spawns a background METAR poller when a portal is
attached, sharing the same `CancellationToken` as the responder so the two
shut down together. The poller keeps the WSP hot path allocation-free —
handlers only take a short read-lock on `MetarCache`.

## MVP vs full live-data wiring

**Landed in this branch (validated by unit tests):**

* Config section + validation + unknown-key rejection.
* `wap-gateway::portal` module — trait, config, WMLC encoder, METAR poller,
  4 pages, prefix router.
* `WspHandler` portal interception with test that portal hits stay local and
  non-portal hits still fall through to upstream.
* `RunConfig` extension + `bluestation-bs` wiring behind
  `[wap_gateway.portal].enabled`.

**Deferred to a follow-up (intentionally not blocking hardware validation):**

* Real `DashboardState`-backed `radios()` implementation. The current adapter
  returns an empty list, so `/portal/radios` renders `(none)`. Full wiring
  needs `DashboardServer` refactored to accept an externally-owned
  `DashboardState` so the same handle can be shared with the portal adapter
  — currently the server constructs it internally, and `wire_wap_gateway`
  runs before that construction.
* `Sndcp::pdp_count()` accessor + wiring. Today the system page shows
  `pdp 0` unconditionally.
* Cell-load metric on the system page (`load n/a` until a cheap accessor
  exists on the LMAC/PHY side).
* Send-SDS POST form (Phase 4) — WSP `handle_get` still returns 405 for POST.

## Tests

Unit tests inside `wap-gateway`:

* `portal::wmlc` — header bytes match the H35 known-good prefix
  (`01 04 6a 00`); `wrap_card` framing terminates correctly; anchor and empty
  element shapes.
* `portal::pages` — every page starts with the WBXML v1.1 header and stays
  inside the 350 B budget; radios page shows `(none)` when empty and caps at
  `radios_max`; weather page falls back to `no data yet`; system page renders
  version + uptime + pdp + load.
* `portal::metar` — cache round-trip.
* `portal` (mod) — router matches `/portal` and known subpages, rejects
  siblings like `/portalx`, returns 404 for unknown subpaths.
* `wsp::session` — portal-prefix GET returns WMLC (status 0x20, header byte
  `0x94`, WBXML v1.1 body header); non-portal GET still falls through to
  upstream and 502s on an unreachable base.

Config tests in `tetra-config`:

* Portal defaults; full TOML parse; ICAO uppercased on validation;
  `path_prefix` must start with `/`; zero `radios_max` / `metar_refresh_seconds`
  rejected; unknown-key rejection at `[wap_gateway.portal]`.

Full workspace test count: 19 config + 90 wap-gateway unit tests, all
passing.

## Hardware validation — TODO

Not run yet (no radio access from this dev box). To capture once on the pi:

* MTP3550: byte size of each page on the wire, whether all 4 render correctly,
  whether the anchor navigation works.
* MTP6550: same 4 pages (this is the radio that rejected WBXML v1.3 — v1.1
  should be safe but confirm).
* METAR fetch reachability from the pi (aviationweather.gov over IPv4).
* Cross-check that H22–H35 WTP/LLC behaviour is unchanged (no regressions in
  the WSP responder — the portal only touches the content path).

## Constraints honored from tonight's WAP work

* Result payload well under one WTP segment — hard-capped at 350 B via
  `debug_assert!` inside `wrap_card`.
* No sync HTTP in the request path — METAR is polled in a dedicated tokio
  task; handlers only read from a `RwLock` cache.
* MTP3550 firmware WTP-Ack quirks are untouched — this feature is
  content-layer only; the responder/LLC path is not modified.
* `WspGatewayState::with_upstream` preserved for compatibility; new
  `with_upstream_and_portal` is what `run` uses.
