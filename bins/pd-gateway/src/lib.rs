//! pd-gateway: bridges IPv4 packets between the OS TUN interface and the
//! SNDCP entity's `uplink_ip_queue` / `feed_downlink_ip` API.
//!
//! # Usage
//! Call [`spawn_gateway_task`] to obtain a [`GatewayHandle`].  From the SNDCP
//! tick loop:
//! - drain `sndcp.uplink_ip_queue` → [`GatewayHandle::push_uplink`]
//! - [`GatewayHandle::try_pop_downlink`] → `sndcp.feed_downlink_ip`

pub mod ip;
pub(crate) mod tun;

use std::net::Ipv4Addr;
use tokio::sync::mpsc;

// ── Public types ──────────────────────────────────────────────────────────────

/// An IPv4 packet arriving from a TETRA MS (uplink direction: MS → internet).
#[derive(Debug, Clone)]
pub struct UplinkFromSndcp {
    /// ISSI of the originating subscriber.
    pub issi: u32,
    /// NSAPI context identifier.
    pub nsapi: u8,
    /// Raw IPv4 payload.
    pub payload: Vec<u8>,
}

/// An IPv4 packet destined for a TETRA MS (downlink direction: internet → MS).
#[derive(Debug, Clone)]
pub struct DownlinkToSndcp {
    /// Destination IPv4 of the MS.
    pub dest_ipv4: Ipv4Addr,
    /// Raw IPv4 payload.
    pub payload: Vec<u8>,
}

/// Configuration for the TUN interface and gateway subnet.
#[derive(Debug, Clone)]
pub struct GatewayConfig {
    /// TUN interface name, e.g. `"flowstation-pd0"`.
    pub tun_name: String,
    /// Gateway's own IPv4 address on the TUN interface, e.g. `192.168.100.1`.
    pub tun_addr: Ipv4Addr,
    /// Subnet prefix length, e.g. `24`.
    pub tun_prefix_len: u8,
    /// Interface MTU in bytes.
    pub mtu: u16,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            tun_name: "flowstation-pd0".to_string(),
            tun_addr: Ipv4Addr::new(192, 168, 100, 1),
            tun_prefix_len: 24,
            mtu: 1500,
        }
    }
}

/// Errors produced by the gateway subsystem.
#[derive(Debug, thiserror::Error)]
pub enum GatewayError {
    #[error("gateway channel closed")]
    ChannelClosed,
    #[error("tun open failed: {0}")]
    TunOpen(String),
    #[error("ip packet too small")]
    IpTooSmall,
    #[error("ip packet is not ipv4")]
    IpNotV4,
}

// ── GatewayHandle ─────────────────────────────────────────────────────────────

/// Bridge between the synchronous SNDCP tick loop and the async TUN task.
///
/// Obtained from [`spawn_gateway_task`].  All methods are safe to call from
/// non-async (sync) contexts.
pub struct GatewayHandle {
    uplink_tx: mpsc::UnboundedSender<UplinkFromSndcp>,
    /// Wrapped in a Mutex so sync code can call `try_recv` without an executor.
    downlink_rx: std::sync::Mutex<mpsc::UnboundedReceiver<DownlinkToSndcp>>,
    pub config: GatewayConfig,
}

impl GatewayHandle {
    /// Forward an uplink packet from SNDCP to the TUN interface.  Non-blocking.
    pub fn push_uplink(&self, pkt: UplinkFromSndcp) -> Result<(), GatewayError> {
        self.uplink_tx.send(pkt).map_err(|_| GatewayError::ChannelClosed)
    }

    /// Poll for the next downlink packet from the TUN interface without blocking.
    /// Returns `None` if the queue is empty.
    pub fn try_pop_downlink(&self) -> Option<DownlinkToSndcp> {
        self.downlink_rx.lock().ok()?.try_recv().ok()
    }

    /// Construct a handle directly from channel halves — test helper only.
    #[cfg(test)]
    pub(crate) fn from_channels(
        uplink_tx: mpsc::UnboundedSender<UplinkFromSndcp>,
        downlink_rx: mpsc::UnboundedReceiver<DownlinkToSndcp>,
        config: GatewayConfig,
    ) -> Self {
        Self {
            uplink_tx,
            downlink_rx: std::sync::Mutex::new(downlink_rx),
            config,
        }
    }
}

impl std::fmt::Debug for GatewayHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatewayHandle")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

// ── spawn_gateway_task ────────────────────────────────────────────────────────

/// Spawn the gateway task and return a [`GatewayHandle`].
///
/// On Linux this opens a real TUN interface and starts an async I/O loop.
/// On other platforms it returns `Err(GatewayError::TunOpen(…))` because
/// TUN/TAP is Linux-only.
///
/// # NOTE: spec ambiguous — chosen behaviour
/// The spec prose says "returns a no-op handle on non-Linux", but the required
/// test `handle_survives_tun_open_failure_on_non_linux` asserts an error.
/// We follow the test: non-Linux returns `Err(GatewayError::TunOpen)`.
/// Tests that exercise `GatewayHandle` directly use the `from_channels` helper.
pub async fn spawn_gateway_task(config: GatewayConfig) -> Result<GatewayHandle, GatewayError> {
    spawn_gateway_task_inner(config).await
}

#[cfg(target_os = "linux")]
async fn spawn_gateway_task_inner(config: GatewayConfig) -> Result<GatewayHandle, GatewayError> {
    let (uplink_tx, uplink_rx) = mpsc::unbounded_channel::<UplinkFromSndcp>();
    let (downlink_tx, downlink_rx) = mpsc::unbounded_channel::<DownlinkToSndcp>();

    let tun_device = tun::open_tun(&config).await?;
    tokio::spawn(async move {
        if let Err(e) = tun::tun_loop(tun_device, uplink_rx, downlink_tx).await {
            tracing::error!("TUN loop terminated: {e}");
        }
    });

    Ok(GatewayHandle {
        uplink_tx,
        downlink_rx: std::sync::Mutex::new(downlink_rx),
        config,
    })
}

#[cfg(not(target_os = "linux"))]
async fn spawn_gateway_task_inner(_config: GatewayConfig) -> Result<GatewayHandle, GatewayError> {
    Err(GatewayError::TunOpen("TUN not supported on this OS".into()))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that push_uplink succeeds and try_pop_downlink returns injected
    /// packets — exercising the channel mechanics without any real TUN.
    #[test]
    fn push_uplink_and_try_pop_roundtrip_via_channel() {
        let (uplink_tx, _uplink_rx) = mpsc::unbounded_channel::<UplinkFromSndcp>();
        let (downlink_tx, downlink_rx) = mpsc::unbounded_channel::<DownlinkToSndcp>();
        let config = GatewayConfig::default();
        let handle = GatewayHandle::from_channels(uplink_tx, downlink_rx, config);

        // Uplink push must succeed.
        let uplink = UplinkFromSndcp {
            issi: 1001,
            nsapi: 5,
            payload: vec![0x45, 0, 0, 20, 0, 1, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2],
        };
        handle.push_uplink(uplink).expect("push_uplink failed");

        // No downlink yet.
        assert!(handle.try_pop_downlink().is_none());

        // Inject a downlink packet directly through the channel.
        let pkt = DownlinkToSndcp {
            dest_ipv4: Ipv4Addr::new(10, 0, 0, 2),
            payload: vec![0x45, 0, 0, 20, 0, 2, 0, 0, 64, 17, 0, 0, 10, 0, 0, 2, 10, 0, 0, 1],
        };
        downlink_tx.send(pkt.clone()).expect("channel send failed");

        // Now pop must return the packet.
        let got = handle.try_pop_downlink().expect("expected a downlink packet");
        assert_eq!(got.dest_ipv4, pkt.dest_ipv4);
        assert_eq!(got.payload, pkt.payload);

        // Queue is now empty.
        assert!(handle.try_pop_downlink().is_none());
    }

    /// On non-Linux `spawn_gateway_task` must return a `TunOpen` error because
    /// there is no TUN/TAP subsystem available.
    #[cfg(not(target_os = "linux"))]
    #[tokio::test]
    async fn handle_survives_tun_open_failure_on_non_linux() {
        let result = spawn_gateway_task(GatewayConfig::default()).await;
        assert!(
            matches!(result, Err(GatewayError::TunOpen(_))),
            "expected GatewayError::TunOpen on non-Linux, got: {result:?}",
        );
    }
}
