//! `wap-gateway` — an in-process WAP 1.x gateway library that replaces
//! Kannel for the FlowStation TETRA packet-data stack (PD-10).
//!
//! # Motivation
//!
//! Kannel 1.4.5's `sanitize_capabilities()` in `wap/wsp_session.c` strips
//! Openwave / UP.Browser-specific capabilities (Protocol Options `0xF0`,
//! Extended Method `x-up-1`) from the ConnectReply. Motorola MTP3550
//! handsets running UP.Browser 6.3 reject the resulting session and retry
//! via `SN-RECONNECT` every 40 s. Kannel also no longer builds on modern
//! Debian (bison 3 breaks `wmlscript/wsgram.y`).
//!
//! # Hosting model
//!
//! This crate is a **library** consumed by the top-level `bluestation-bs`
//! binary. It has no `main.rs`, no dedicated systemd unit, and reads no
//! config files of its own — the operator configures it via a
//! `[wap_gateway]` section in the main FlowStation config (see
//! `tetra_config::bluestation::sec_wap_gateway`).
//!
//! `bluestation-bs` calls [`run`] on the same tokio runtime that already
//! hosts the SNDCP / TUN task. If `wap_gateway.enabled = false` the caller
//! simply skips [`run`] and the gateway never binds a socket.
//!
//! # Scope (v0.1 = PD-10)
//!
//! * UDP listener on `<listen_addr>:<listen_port>` (default 9201, address
//!   defaults to `packet_data.tun_addr`).
//! * WTP responder for class 2 transactions (Invoke → Ack → Result → Ack)
//!   with SAR (Segmentation And Reassembly) — [`wtp::Responder`].
//! * WSP-CO Connect / ConnectReply with Openwave-correct capability *echo*
//!   (PD-10b, upcoming).
//! * HTTP GET to a configurable upstream URL, response passed through
//!   verbatim (PD-10c, upcoming).
//!
//! # Module map
//!
//! * [`wdp`]    — thin async UDP wrapper (Wireless Datagram Protocol layer).
//! * [`wtp`]    — Wireless Transaction Protocol: PDU codec + responder FSM.
//! * [`wsp`]    — Wireless Session Protocol: capability + header codec, session FSM.
//! * [`error`]  — `WapError` / `WapResult`.

pub mod error;
pub mod wdp;
pub mod wsp;
pub mod wtp;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

pub use error::{WapError, WapResult};
use tracing::info;

use crate::wdp::Wdp;
use crate::wtp::{Responder, ResponderConfig, handler_fn};

/// Runtime configuration for [`run`].
///
/// Mirrors `tetra_config::bluestation::CfgWapGateway` but is redefined here
/// so `wap-gateway` does not depend on `tetra-config` (keeps the layering
/// crisp and lets `wap-gateway` stay useful in isolation for tests).
#[derive(Debug, Clone)]
pub struct RunConfig {
    /// IPv4 the UDP socket binds to.
    pub listen_addr: Ipv4Addr,
    /// UDP port to bind (WSP-CO default is 9201).
    pub listen_port: u16,
    /// Upstream HTTP backend base URL (used by PD-10c).
    pub upstream_url: String,
}

/// Run the WAP gateway forever. Returns only on a fatal I/O error (e.g. the
/// UDP socket dies). Cancellation is via the tokio task handle — the caller
/// aborts the task at process shutdown.
///
/// # Placeholder handler
///
/// Until PD-10b lands, [`run`] responds to every completed Invoke with a
/// 3-byte WSP Disconnect stub. This is enough to exercise the full
/// Invoke → Ack → Result → Ack path against real MS hardware without
/// pretending to be a functional WSP-CO gateway yet.
#[tracing::instrument(skip_all, fields(listen = %format!("{}:{}", cfg.listen_addr, cfg.listen_port)))]
pub async fn run(cfg: RunConfig) -> WapResult<()> {
    let bind: SocketAddr = SocketAddr::new(IpAddr::V4(cfg.listen_addr), cfg.listen_port);
    let wdp = Wdp::bind(bind).await?;
    info!(
        local = %wdp.local_addr(),
        upstream = %cfg.upstream_url,
        "wap-gateway listening",
    );

    let handler = handler_fn(|_peer, _payload| async move {
        // WSP Disconnect stub: Type=5, followed by a 1-byte uintvar session
        // id 0 and a trailing padding zero. Just enough to be a well-formed
        // Result payload; PD-10b replaces this with the real WSP-CO
        // ConnectReply / Reply builder.
        vec![0x05, 0x00, 0x00]
    });
    let responder = Responder::new(wdp, handler, ResponderConfig::default());
    responder.run().await
}
