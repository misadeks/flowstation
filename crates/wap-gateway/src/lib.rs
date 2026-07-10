//! `wap-gateway` — a minimal Rust WAP 1.x gateway that replaces Kannel for the
//! FlowStation TETRA packet-data stack.
//!
//! # Motivation
//!
//! Kannel 1.4.5's `sanitize_capabilities()` in `wap/wsp_session.c` strips
//! Openwave / UP.Browser-specific capabilities (Protocol Options `0xF0`,
//! Extended Method `x-up-1`) from the ConnectReply. Motorola MTP3550
//! handsets running UP.Browser 6.3 reject the resulting session and retry
//! via `SN-RECONNECT` every 40s. Kannel also no longer builds on modern
//! Debian (bison 3 breaks `wmlscript/wsgram.y`). This crate exists to
//! bypass both problems by writing a tightly-scoped, spec-correct, Openwave-
//! respecting responder.
//!
//! # Scope (v0.1 = PD-10)
//!
//! * UDP listener on `<tun_addr>:9201` (WSP connection-oriented port).
//! * WTP responder for class 2 transactions (Invoke → Ack → Result → Ack),
//!   with SAR (Segmentation And Reassembly).
//! * WSP-CO Connect / ConnectReply with capability *echo* (no
//!   Kannel-style sanitisation).
//! * HTTP GET to a configurable upstream URL, response passed through
//!   verbatim (we serve pre-compiled `.wmlc` WBXML — never re-encode).
//!
//! # Module map
//!
//! * [`config`] — TOML gateway config, `flowstation_config` tun_addr resolution.
//! * [`wdp`]    — thin UDP wrapper (Wireless Datagram Protocol layer).
//! * [`wtp`]    — Wireless Transaction Protocol: PDU codec + responder FSM.
//! * [`wsp`]    — Wireless Session Protocol: capability + header codec, session FSM.
//! * [`error`]  — `WapError` / `WapResult`.

pub mod config;
pub mod error;
pub mod wdp;
pub mod wsp;
pub mod wtp;

pub use config::GatewayConfig;
pub use error::{WapError, WapResult};
