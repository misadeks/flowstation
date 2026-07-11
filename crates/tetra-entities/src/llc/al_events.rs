//! PD-10c-H36: LLC → gateway AL delivery feedback (see plan.md).
//!
//! LLC emits [`AlDeliveryEvent`]s through an installed [`AlDeliveryHook`]
//! whenever an outstanding AL SDU is either AL-ACKed by the peer or dropped
//! (fire-and-forget release, retransmit budget exhausted). Consumers use this
//! as a *hint* to suppress redundant WSP/WTP retries — it is never a
//! substitute for the existing retx logic (fallback path stays live).
//!
//! The hook is a plain `Arc<dyn Fn(...) + Send + Sync>` so `tetra-entities`
//! stays free of any tokio dependency. The `bluestation-bs` binary bridges
//! the hook to a `tokio::sync::broadcast::Sender` so async consumers
//! (`wap-gateway`) can subscribe.
//!
//! See `crates/wap-gateway/src/wtp/responder.rs` for the consumer side.

use std::sync::Arc;

/// Outcome carried by an [`AlDeliveryEvent`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlDeliveryOutcome {
    /// Peer explicitly AL-ACKed the entire SDU (spec `EntireSduReceived`).
    Delivered,
    /// The SDU was released without a peer AL-ACK on a link negotiated with
    /// `max_sdu_retx = 0` (e.g. Motorola MTP3550 Original AL). The bits went
    /// on the air; the peer simply never confirmed. Downstream should treat
    /// this as "probably delivered but unverified".
    DroppedFireAndForget,
    /// The SDU exhausted its per-link retransmit budget without an AL-ACK.
    /// Almost certainly not delivered.
    DroppedRetxExhausted,
}

/// One AL SDU-level delivery event, keyed by the AL link tuple + `N(S)`.
///
/// The receiver correlates by `ssi` (via the SNDCP-owned IPv4 ↔ ISSI
/// mapping) — no `N(S)` bookkeeping is currently plumbed through SNDCP, so
/// consumers do time-window matching rather than exact-N(S) matching.
#[derive(Debug, Clone)]
pub struct AlDeliveryEvent {
    pub ssi: u32,
    pub link_id: u32,
    pub endpoint_id: u32,
    pub n261: u8,
    pub n_s: u8,
    pub outcome: AlDeliveryOutcome,
}

/// Sync callback installed on `Llc` via `set_delivery_hook`. Must not block
/// (LLC calls it from the main entity tick).
pub type AlDeliveryHook = Arc<dyn Fn(AlDeliveryEvent) + Send + Sync>;
