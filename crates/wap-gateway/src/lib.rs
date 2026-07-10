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
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::wdp::Wdp;
use crate::wsp::session::{WspGatewayState, WspHandler};
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

/// Run the WAP gateway until [`CancellationToken::cancel`] is called on
/// `shutdown` (graceful) or a fatal I/O error propagates from the socket.
///
/// Callers typically drive this from a shared `CancellationToken` on
/// `bluestation-bs`. Pass [`CancellationToken::new`] if you don't need
/// cooperative shutdown.
///
/// # WSP handler
///
/// [`run`] instantiates a [`WspHandler`] backed by a fresh
/// [`WspGatewayState`] and wires it into the WTP responder. On every
/// completed Class-2 Invoke the handler decodes the WSP PDU, dispatches
/// Connect / Disconnect through the session state machine, and answers
/// any other PDU with WSP status `501 Not Implemented` (PD-10c replaces
/// that stub with the real HTTP relay).
#[tracing::instrument(skip_all, fields(listen = %format!("{}:{}", cfg.listen_addr, cfg.listen_port)))]
pub async fn run(cfg: RunConfig, shutdown: CancellationToken) -> WapResult<()> {
    let bind: SocketAddr = SocketAddr::new(IpAddr::V4(cfg.listen_addr), cfg.listen_port);
    let wdp = Wdp::bind(bind).await?;
    info!(
        local = %wdp.local_addr(),
        upstream = %cfg.upstream_url,
        "wap-gateway listening",
    );

    let wsp_state = WspGatewayState::new();
    let handler = {
        let wsp = WspHandler::new(wsp_state);
        handler_fn(move |peer, payload| {
            let wsp = wsp.clone();
            async move { wsp.handle(peer, payload).await }
        })
    };
    let responder = Responder::new(wdp, handler, ResponderConfig::default());

    tokio::select! {
        res = responder.run() => res,
        () = shutdown.cancelled() => {
            info!("wap-gateway shutdown requested");
            Ok(())
        }
    }
}
