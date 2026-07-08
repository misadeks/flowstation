# pd-gateway — FlowStation Packet-Data TUN Gateway (PD-6)

`pd-gateway` is the standalone binary (and companion library) that bridges
IPv4 packets between a Linux TUN interface and the TETRA SNDCP entity's
`uplink_ip_queue` / `feed_downlink_ip` API.

Actual wiring into `bluestation-bs` happens in PD-9.  PD-6 delivers the
crate, the standalone binary, and a set of tests.

---

## Quick-start

### 1. Grant `CAP_NET_ADMIN` (or run as root)

```bash
# One-time capability grant for the release binary:
sudo setcap cap_net_admin=eip target/release/pd-gateway
```

### 2. Run

```bash
./target/release/pd-gateway \
    --tun-name flowstation-pd0 \
    --tun-addr 192.168.100.1 \
    --tun-prefix-len 24 \
    --mtu 1500
```

The interface is brought up automatically.  You should see it with:

```bash
ip tuntap list
ip addr show flowstation-pd0
```

### 3. (Optional) NAT — let TETRA MSs reach the internet

```bash
# Enable IP forwarding:
sudo sysctl -w net.ipv4.ip_forward=1

# Masquerade outbound traffic via your uplink interface (e.g. eth0):
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
```

### 4. Verify

From the gateway host, ping an allocated MS address to see packets appear
on the TUN:

```bash
ping -I flowstation-pd0 192.168.100.180
```

---

## Running the integration test

The integration test opens a real TUN interface and requires `CAP_NET_ADMIN`
(or root):

```bash
sudo cargo test -p pd-gateway -- --ignored --test-threads=1
```

---

## systemd unit sample

```ini
[Unit]
Description=FlowStation Packet-Data TUN Gateway
After=network.target

[Service]
ExecStart=/usr/bin/pd-gateway \
    --tun-name flowstation-pd0 \
    --tun-addr 192.168.100.1 \
    --tun-prefix-len 24
Restart=on-failure
# Grant just the capability needed — no need to run as root.
AmbientCapabilities=CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
```

---

## Architecture notes

```
                ┌──────────────────────────────────┐
                │          bluestation-bs           │
                │  ┌────────────┐  ┌─────────────┐ │
  TETRA air ────►  │  SNDCP Bs  │  │ GatewayHandle│ │
  interface     │  │ uplink_ip  ├──► push_uplink  │ │
                │  │  _queue    │  │             │ │
                │  │            │  │try_pop_      │ │
                │  │feed_down-  ◄──┤ downlink    │ │
                │  │  link_ip   │  └──────┬──────┘ │
                │  └────────────┘         │         │
                └─────────────────────────┼─────────┘
                                          │ async mpsc
                              ┌───────────┴──────────┐
                              │      TUN task         │
                              │  (tokio-tun 0.15)     │
                              └───────────┬───────────┘
                                          │
                              ┌───────────▼───────────┐
                              │   Linux TUN interface  │
                              │   (flowstation-pd0)    │
                              └───────────────────────┘
```
