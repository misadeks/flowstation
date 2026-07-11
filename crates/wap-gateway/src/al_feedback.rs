//! PD-10c-H36: AL delivery feedback types + peer resolver trait.
//!
//! `wap-gateway` receives AL SDU delivery events from LLC through a
//! `tokio::sync::broadcast` channel that is *not* set up inside this crate
//! (`wap-gateway` has no dependency on `tetra-entities`). The bridge lives
//! in `bluestation-bs::build_bs_stack`: it installs a sync
//! `tetra_entities::llc::al_events::AlDeliveryHook` on `Llc`, translates
//! each event into the mirror struct defined here, and publishes it on a
//! broadcast channel handed into [`crate::RunConfig::al_events_rx`].
//!
//! The correlator inside the WTP responder subscribes to that channel and
//! uses the [`AlPeerResolver`] trait to convert a WTP peer `SocketAddr`
//! into the corresponding TETRA ISSI (SNDCP owns that mapping).

use std::net::SocketAddr;
use std::sync::Arc;

/// Mirror of `tetra_entities::llc::al_events::AlDeliveryOutcome`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlDeliveryOutcome {
    Delivered,
    DroppedFireAndForget,
    DroppedRetxExhausted,
}

/// Mirror of `tetra_entities::llc::al_events::AlDeliveryEvent`. Duplicated
/// here to keep `wap-gateway` free of `tetra-entities` deps.
#[derive(Debug, Clone)]
pub struct AlDeliveryEvent {
    pub ssi: u32,
    pub link_id: u32,
    pub endpoint_id: u32,
    pub n261: u8,
    pub n_s: u8,
    pub outcome: AlDeliveryOutcome,
}

/// Resolve a WTP peer's UDP `SocketAddr` to the TETRA ISSI SNDCP assigned
/// to it. Implemented in `bluestation-bs` over the SNDCP
/// `issi_observer` snapshot.
pub trait AlPeerResolver: Send + Sync {
    /// Returns `Some(ssi)` if the peer's IPv4 is currently mapped to an
    /// active PDP context; `None` otherwise.
    fn issi_for_peer(&self, peer: SocketAddr) -> Option<u32>;
}

/// Convenience alias for a shared, dynamically-dispatched resolver.
pub type SharedAlPeerResolver = Arc<dyn AlPeerResolver>;
