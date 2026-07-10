# wap-gateway

An in-process Rust WAP 1.x gateway **library** that replaces Kannel for the
FlowStation TETRA packet-data stack (issue **PD-10**).

## Why not Kannel

Two blockers:

1. **Openwave dialect incompatibility.** Kannel's `sanitize_capabilities()`
   / `reply_known_capabilities()` in `wap/wsp_session.c` strips MS-supplied
   Protocol Options (`0xF0` → `0x00`) and Extended Methods (`x-up-1` →
   empty) in `ConnectReply`. Motorola MTP3550 handsets running UP.Browser
   6.3 reject the resulting session and trigger `SN-RECONNECT` every ~40 s.
   Hardware-verified via tcpdump.
2. **Kannel 1.4.5 no longer builds on modern Debian** (bison 3
   incompatibilities in `wmlscript/wsgram.y`).

## Hosting model

`wap-gateway` is a **library**. The top-level `bluestation-bs` binary spawns
`wap_gateway::run` on the same tokio runtime that already hosts the SNDCP /
TUN task. There is no separate binary, no separate systemd unit, and no
separate config file — operators configure it in the main FlowStation
config:

```toml
[wap_gateway]
enabled = true
# listen_addr defaults to `packet_data.tun_addr`, so most operators don't set it:
# listen_addr = "10.222.0.1"
listen_port = 9201                    # optional, default 9201
upstream_url = "http://127.0.0.1:8081"
log_level = "info"                    # optional, default "info"
```

Restart `bluestation-bs` and the gateway comes back with it. No kannel to
stop, no extra systemd unit.

## Scope (v0.1 = PD-10)

| Sub-phase | Status | Description                                              |
|-----------|--------|----------------------------------------------------------|
| PD-10a-1  | ✅     | Crate skeleton, `Wdp` UDP wrapper                        |
| PD-10a-2  | ✅     | WTP PDU codec (Invoke, Result, Ack, Abort, SAR, N-Ack)   |
| PD-10a-3  | ✅     | WTP responder state machine (class 2, retx, SAR)         |
| PD-10a-4  | ✅     | Config surface (`[wap_gateway]`) + bluestation-bs wiring |
| PD-10b    | ⏳     | WSP-CO Connect / ConnectReply with Openwave cap echo     |
| PD-10c    | ⏳     | WSP Get → HTTP backend → WSP Reply                       |

Explicitly **out of scope for v0.1**: WTP class 1 push, WSP-CL (port 9200),
WTLS, MOR > 1, session resume, mid-session capability re-negotiation,
on-the-fly WMLScript compilation, on-the-fly WBXML encoding of text WML.

## API

```rust
use wap_gateway::{RunConfig, run};

let cfg = RunConfig {
    listen_addr: "10.222.0.1".parse().unwrap(),
    listen_port: 9201,
    upstream_url: "http://127.0.0.1:8081".into(),
};
// Spawn on any multi-thread tokio runtime; runs until the socket dies.
tokio::spawn(async move { run(cfg).await });
```

`bluestation-bs::wire_wap_gateway` shows the production wiring.

## Testing

```bash
cargo test   -p wap-gateway
cargo clippy -p wap-gateway --all-targets -- -D warnings
cargo fmt    -p wap-gateway --check
```

## Openwave / TETRA-tuning notes (from hardware bring-up)

* **Protocol Options MUST be echoed as `0xF0`** (Confirmed Push + Push +
  Session Resume + Ack Headers) — capability id 2.
* **Extended Methods MUST include `x-up-1`** — capability id 5, payload
  `[0x10, "x-up-1\0"]`.
* **WTP retransmission**: TETRA RTT is ~300-500 ms typical, up to 1500 ms
  under retx pressure. Default `T_ACK = 3 s` per spec — we tune to 4 s
  with `max_retx = 3`.
* **Session idle timeout**: MS closes idle sessions after ~60 s; we drop
  session state after 90 s and reply with a WSP Abort to Gets on unknown
  session IDs.
