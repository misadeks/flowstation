//! TUN interface I/O — real implementation on Linux, no-op stub elsewhere.
//!
//! Both cfg branches export:
//!   `open_tun(config) -> Result<…, GatewayError>`
//! Only the Linux branch exports `tun_loop`.

// ── Linux real implementation ─────────────────────────────────────────────────

#[cfg(target_os = "linux")]
mod real {
    use crate::{DownlinkToSndcp, GatewayConfig, GatewayError, UplinkFromSndcp};
    use std::net::Ipv4Addr;
    use std::sync::Arc;
    use tokio::sync::mpsc;
    use tokio_tun::Tun;

    /// Convert a CIDR prefix length (0–32) to an IPv4 netmask.
    fn prefix_to_netmask(prefix_len: u8) -> Ipv4Addr {
        if prefix_len == 0 {
            return Ipv4Addr::new(0, 0, 0, 0);
        }
        // Shift a full 32-bit mask right by (32 - prefix_len) bits.
        let bits = !((1u32 << (32 - prefix_len as u32)) - 1);
        Ipv4Addr::from(bits)
    }

    /// Open a TUN interface with the parameters from `config`.
    ///
    /// # NOTE: spec ambiguous — chosen behaviour
    /// The spec sketched `open_tun` returning a `TunBuilder`; the actual
    /// `tokio-tun` 0.15 API returns the built `Tun` directly.  We return
    /// `Arc<Tun>` so both the reader and writer halves of `tun_loop` can
    /// share it without unsafe.
    pub async fn open_tun(config: &GatewayConfig) -> Result<Arc<Tun>, GatewayError> {
        let netmask = prefix_to_netmask(config.tun_prefix_len);
        let tun = Tun::builder()
            .name(&config.tun_name)
            .address(config.tun_addr)
            .netmask(netmask)
            .mtu(config.mtu as i32)
            .up()
            .build()
            .map_err(|e| GatewayError::TunOpen(e.to_string()))?
            .pop()
            .ok_or_else(|| GatewayError::TunOpen("builder returned no device".into()))?;
        Ok(Arc::new(tun))
    }

    /// Drive the TUN interface:
    /// - uplink packets received from `uplink_rx` are written to the TUN.
    /// - packets read from the TUN are parsed and sent as downlink on `downlink_tx`.
    ///
    /// Returns when `uplink_rx` is closed or a fatal TUN read error occurs.
    pub async fn tun_loop(
        tun: Arc<Tun>,
        mut uplink_rx: mpsc::UnboundedReceiver<UplinkFromSndcp>,
        downlink_tx: mpsc::UnboundedSender<DownlinkToSndcp>,
    ) -> Result<(), GatewayError> {
        // Reuse buffer across iterations to avoid per-packet allocation.
        let mut buf = vec![0u8; 2048];
        loop {
            tokio::select! {
                maybe_pkt = uplink_rx.recv() => {
                    match maybe_pkt {
                        None => {
                            tracing::info!("uplink channel closed — shutting down TUN loop");
                            return Ok(());
                        }
                        Some(pkt) => {
                            if let Err(e) = tun.send_all(&pkt.payload).await {
                                tracing::warn!("TUN write error (issi={} nsapi={}): {e}",
                                    pkt.issi, pkt.nsapi);
                            }
                        }
                    }
                }

                result = tun.recv(&mut buf) => {
                    match result {
                        Err(e) => {
                            return Err(GatewayError::TunOpen(
                                format!("TUN read error: {e}")
                            ));
                        }
                        Ok(n) => {
                            let packet = &buf[..n];
                            match crate::ip::parse_ipv4_dest(packet) {
                                Ok(dest_ipv4) => {
                                    let dl = DownlinkToSndcp {
                                        dest_ipv4,
                                        payload: packet.to_vec(),
                                    };
                                    if downlink_tx.send(dl).is_err() {
                                        tracing::warn!(
                                            "downlink channel closed — dropping TUN packet"
                                        );
                                    }
                                }
                                Err(e) => {
                                    tracing::debug!("dropping non-IPv4 TUN frame: {e}");
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

// ── Non-Linux stub ────────────────────────────────────────────────────────────

#[cfg(not(target_os = "linux"))]
mod stub {
    use crate::{GatewayConfig, GatewayError};

    // NOTE: not called by spawn_gateway_task_inner on non-Linux (which returns
    // early with TunOpen error), but kept for API completeness and future tests.
    #[allow(dead_code)]
    pub async fn open_tun(_config: &GatewayConfig) -> Result<(), GatewayError> {
        Err(GatewayError::TunOpen("TUN not supported on this OS".into()))
    }
}

// ── Re-exports ────────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
pub(crate) use real::{open_tun, tun_loop};
