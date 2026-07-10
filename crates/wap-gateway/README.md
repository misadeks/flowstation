# wap-gateway

A minimal Rust WAP 1.x gateway that replaces Kannel for the FlowStation TETRA
packet-data stack (issue **PD-10**).

## Why not Kannel

Two blockers:

1. **Openwave dialect incompatibility.** Kannel's
   `sanitize_capabilities()` / `reply_known_capabilities()` in
   `wap/wsp_session.c` strips MS-supplied Protocol Options (`0xF0` → `0x00`)
   and Extended Methods (`x-up-1` → empty) in `ConnectReply`. Motorola
   MTP3550 handsets running UP.Browser 6.3 reject the resulting session and
   trigger `SN-RECONNECT` every ~40 s. Hardware-verified via tcpdump.
2. **Kannel 1.4.5 no longer builds on modern Debian** (bison 3 incompatibilities
   in `wmlscript/wsgram.y`).

Writing a tightly-scoped Rust responder is faster and gives us end-to-end
control over the Openwave quirks.

## Scope (v0.1 = PD-10)

| Sub-phase | Status | Description                                              |
|-----------|--------|----------------------------------------------------------|
| PD-10a-1  | ✅     | Crate skeleton, TOML config, UDP loop                    |
| PD-10a-2  | ✅     | WTP PDU codec (Invoke, Result, Ack, Abort, SAR, N-Ack)   |
| PD-10a-3  | ✅     | WTP responder state machine (class 2, retx, SAR)         |
| PD-10b    | ⏳     | WSP-CO Connect / ConnectReply with Openwave cap echo     |
| PD-10c    | ⏳     | WSP Get → HTTP backend → WSP Reply                       |

Explicitly **out of scope for v0.1**: WTP class 1 push, WSP-CL (port 9200),
WTLS, MOR > 1, session resume, mid-session capability re-negotiation,
on-the-fly WMLScript compilation, on-the-fly WBXML encoding of text WML.

## Configuration

`wap-gateway-config.toml` (see `wap-gateway-config.example.toml`):

```toml
flowstation_config = "/home/pi/flowstation-config.toml"
listen_port = 9201
upstream_url = "http://127.0.0.1:8081"
log_level = "info"
# Optional override — skips reading `flowstation_config`:
# listen_addr = "10.222.0.1"
```

The gateway resolves its bind address from `packet_data.tun_addr` in the
FlowStation config (also accepts the `[sndcp]` alias for
forward-compatibility).

## Building & deploying

```bash
# On the dev machine (cross-compile to Raspberry Pi):
cargo build --release --target aarch64-unknown-linux-gnu -p wap-gateway

# Copy binary to the pi:
scp target/aarch64-unknown-linux-gnu/release/flowstation-wap-gateway pi@sxcvr.local:~

# On the pi:
sudo systemctl stop kannel                                                   # if still installed
sudo cp flowstation-wap-gateway /usr/local/bin/
sudo mkdir -p /etc/flowstation
sudo cp wap-gateway-config.example.toml /etc/flowstation/wap-gateway-config.toml
sudo cp crates/wap-gateway/systemd/flowstation-wap-gateway.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now flowstation-wap-gateway
sudo journalctl -u flowstation-wap-gateway -f
```

The pre-existing iptables NAT rules for the HTTP backend on the pi stay
unchanged.

## Testing

```bash
cargo test  -p wap-gateway
cargo clippy -p wap-gateway -- -D warnings
cargo fmt   --check
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
