//! Integration test: real TUN loopback (Linux + CAP_NET_ADMIN only).
//!
//! Run with:
//!   sudo cargo test -p pd-gateway -- --ignored --test-threads=1

#[cfg(target_os = "linux")]
use pd_gateway::{GatewayConfig, UplinkFromSndcp, spawn_gateway_task};
#[cfg(target_os = "linux")]
use std::net::Ipv4Addr;
#[cfg(target_os = "linux")]
use tokio::time::{Duration, timeout};

/// Build a minimal valid 20-byte IPv4 header.
#[cfg(target_os = "linux")]
fn make_ipv4_packet(dest: Ipv4Addr) -> Vec<u8> {
    let mut pkt = vec![0u8; 20];
    pkt[0] = 0x45; // version=4, IHL=5
    let d = dest.octets();
    pkt[16] = d[0];
    pkt[17] = d[1];
    pkt[18] = d[2];
    pkt[19] = d[3];
    pkt
}

/// End-to-end smoke test against a real TUN interface.
///
/// This test requires `CAP_NET_ADMIN` (or root).  It is marked `#[ignore]`
/// so that `cargo test -p pd-gateway` skips it by default.
///
/// Run explicitly with:
///   sudo cargo test -p pd-gateway -- --ignored --test-threads=1
#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "requires CAP_NET_ADMIN; run: sudo cargo test -p pd-gateway -- --ignored --test-threads=1"]
async fn tun_loopback_survives_end_to_end() {
    // Use a distinct interface name to avoid collisions with other tests.
    let config = GatewayConfig {
        tun_name: "flowstation-test0".to_string(),
        tun_addr: Ipv4Addr::new(192, 168, 200, 1),
        tun_prefix_len: 24,
        mtu: 1500,
    };

    let handle = spawn_gateway_task(config)
        .await
        .expect("failed to open TUN (need CAP_NET_ADMIN / root)");

    // Push a fake IPv4 packet from the "SNDCP" side (uplink → TUN).
    // The destination is an address in the gateway's own subnet.
    let dest = Ipv4Addr::new(192, 168, 200, 2);
    let payload = make_ipv4_packet(dest);
    handle
        .push_uplink(UplinkFromSndcp {
            issi: 42,
            nsapi: 0,
            payload,
        })
        .expect("push_uplink failed");

    // Wait briefly for a downlink response.  Whether the kernel sends back an
    // ICMP unreachable depends on routing; the test only asserts liveness.
    // NOTE: spec ambiguous — chosen behaviour: treat a timeout as non-fatal;
    // the important invariant is that the handle is still usable afterwards.
    let _ = timeout(Duration::from_millis(300), async {
        loop {
            if handle.try_pop_downlink().is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;

    // The handle must remain alive (no panics, no closed channels).
    // A second push must succeed.
    handle
        .push_uplink(UplinkFromSndcp {
            issi: 42,
            nsapi: 0,
            payload: make_ipv4_packet(Ipv4Addr::new(192, 168, 200, 3)),
        })
        .expect("handle no longer usable after loopback test");
}
