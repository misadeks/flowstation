//! `flowstation-wap-gateway` binary entrypoint.
//!
//! Loads a TOML config, opens a UDP socket on `<listen_addr>:<listen_port>`,
//! and runs the receive loop. In PD-10a-1 the loop just logs decoded WTP PDUs.
//! PD-10a-2 / PD-10a-3 will wire the responder state machine in.

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use wap_gateway::wtp::{Responder, ResponderConfig, handler_fn};
use wap_gateway::{GatewayConfig, wdp::Wdp};

#[derive(Parser, Debug)]
#[command(
    name = "flowstation-wap-gateway",
    about = "FlowStation standalone WAP 1.x gateway (replaces Kannel).",
    long_about = "Openwave / UP.Browser-compatible WAP responder. Listens on UDP \
                  <tun_addr>:9201 and bridges WSP-CO to an HTTP upstream."
)]
struct Args {
    /// Path to `wap-gateway-config.toml`.
    #[arg(long, short = 'c', default_value = "/etc/flowstation/wap-gateway-config.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // We initialise `tracing` twice: once at INFO so we can log the config
    // path even if the file itself is broken, and then a second time with the
    // user-configured filter once the file has been read. `EnvFilter::builder`
    // won't let us swap live so we just install a fresh subscriber; in
    // practice the pre-config subscriber emits at most 1–2 lines.
    init_tracing("info");

    info!(config = %args.config.display(), "loading gateway config");
    let cfg = GatewayConfig::from_path(&args.config).with_context(|| format!("loading {}", args.config.display()))?;

    reinit_tracing_if_needed(&cfg.log_level);

    let bind_addr: SocketAddr = (cfg.listen_addr, cfg.listen_port).into();
    info!(
        %bind_addr,
        upstream = %cfg.upstream_url,
        "starting flowstation-wap-gateway"
    );

    let wdp = Wdp::bind(bind_addr).await.with_context(|| format!("binding UDP {bind_addr}"))?;

    info!(local = %wdp.local_addr(), "UDP socket bound");

    // Placeholder handler for PD-10a: echo a 3-byte WSP Disconnect stub so we
    // exercise the full Invoke → Ack → Result → Ack path from real MS
    // hardware. PD-10b replaces this with a WSP-CO ConnectReply handler and
    // PD-10c with a WSP Get → HTTP → WSP Reply pipeline.
    let handler = handler_fn(|_peer, _payload| async move {
        // WSP Disconnect PDU: PDU type = 5 (Disconnect) followed by a
        // 1-octet session-id-uintvar of 0. This keeps the responder honest
        // on-wire without pretending to be a fully functional gateway yet.
        vec![0x05, 0x00, 0x00]
    });
    let responder = Responder::new(wdp, handler, ResponderConfig::default());
    let recv_task = tokio::spawn(async move { responder.run().await });

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("SIGINT received, shutting down");
        }
        res = recv_task => {
            match res {
                Ok(Ok(())) => warn!("responder exited without error"),
                Ok(Err(e)) => error!(err = %e, "responder failed"),
                Err(e)     => error!(err = %e, "responder panicked"),
            }
        }
    }

    Ok(())
}

fn init_tracing(level: &str) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));
    let _ = tracing_subscriber::fmt().with_env_filter(filter).with_target(false).try_init();
}

/// Best-effort second init after the config file is read. If the initial
/// `try_init` above already succeeded, this call is a no-op.
fn reinit_tracing_if_needed(level: &str) {
    init_tracing(level);
}

/// Read datagrams forever, decode the WTP header, and log summaries.
///
/// Retained for reference; the live loop now runs through
/// [`Responder`]. Kept here so a future v0.2+ "monitor mode" can be
/// re-attached without re-deriving the log formatting.
#[allow(dead_code)]
#[tracing::instrument(skip(wdp))]
async fn receive_loop(wdp: Wdp) -> anyhow::Result<()> {
    use tracing::debug;
    use wap_gateway::wtp::WtpPdu;
    loop {
        let (peer, bytes) = wdp.recv().await.context("wdp recv")?;
        let head = hex_head(&bytes, 32);
        match WtpPdu::decode(&bytes) {
            Ok(pdu) => {
                info!(%peer, ty = ?pdu.pdu_type(), tid = pdu.tid(), len = bytes.len(), "wtp pdu");
                debug!(%peer, head = %head, "wtp pdu bytes (first 32)");
            }
            Err(e) => {
                warn!(%peer, err = %e, head = %head, len = bytes.len(), "malformed WTP PDU");
            }
        }
    }
}

/// Render up to `max` bytes of `buf` as hex.
#[allow(dead_code)]
fn hex_head(buf: &[u8], max: usize) -> String {
    let mut s = String::with_capacity(max * 3);
    for (i, b) in buf.iter().take(max).enumerate() {
        if i > 0 {
            s.push(' ');
        }
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    if buf.len() > max {
        s.push_str(" …");
    }
    s
}
