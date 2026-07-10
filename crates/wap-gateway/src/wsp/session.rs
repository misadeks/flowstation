//! WSP session state machine and WTP-handler adapter (WAP-230 §7).
//!
//! A WSP session is a stateful conversation between one MS and this
//! gateway, keyed on `(peer_addr, server_session_id)`. On the wire the MS
//! identifies its side by source UDP port; we identify our side by an
//! integer session id we hand out in the ConnectReply. Once a session is
//! Connected, subsequent method-invoke PDUs (Get / Post / …) share the
//! same TCP-like context (headers, MOR, caps).
//!
//! # State diagram
//!
//! ```text
//!     Null ──Connect──▶ Connecting ──ConnectReply sent──▶ Connected
//!                            │                                │
//!                            └── idle 90 s ───┐                │
//!                                            ▼                │
//!                                          Null ◀──Disconnect─┘
//!                                            ▲
//!                                            └── idle 90 s ───┘
//! ```
//!
//! # Session table
//!
//! Sessions live in a [`WspGatewayState::sessions`] DashMap under the
//! [`SessionKey`] `(peer, server_session_id)`. The peer address doubles as
//! the "MS identity" — WAP-201 conflates transport source and identity for
//! Class-2 transactions, which is fine on TETRA where each MS has a stable
//! UDP source port for the lifetime of the PPP session.
//!
//! # Handler wiring
//!
//! [`WspHandler::handle`] is the entry point invoked by the WTP responder
//! for every completed Class-2 Invoke. It:
//!
//! 1. Decodes the WSP PDU with [`WspPdu::decode`].
//! 2. Dispatches on PDU type — Connect creates / reuses a session and
//!    replies with a spec-echo ConnectReply; Disconnect tears the session
//!    down; anything else answers with WSP status `501 Not Implemented`
//!    (PD-10c replaces this).
//! 3. Returns the encoded response bytes for the WTP responder to wrap
//!    into a Result PDU.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use dashmap::DashMap;
use tokio::time::Instant;
use tracing::{debug, info, warn};

use crate::wsp::pdu::{HeaderBlock, STATUS_NOT_IMPLEMENTED, WspPdu, build_connect_reply, build_status_reply};

/// Idle timeout after which a session is dropped from the table.
/// WAP-230 §7.4 doesn't specify a wall value; 90 s matches the WTP
/// responder's idle sweep so both layers evict on the same cadence.
pub const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(90);

/// Session table key: `(MS peer address, gateway-chosen session id)`.
pub type SessionKey = (SocketAddr, u32);

/// WSP session lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Handshake in progress — we received Connect, haven't yet observed
    /// the WTP-Ack for the ConnectReply. We don't currently distinguish
    /// this from Connected because the WTP layer already handles that
    /// Ack-tracking; kept as a distinct variant for future PD-10c work.
    Connecting,
    /// Fully established — Get / Post / etc. may flow.
    Connected,
}

/// Per-session state stored in the session table.
#[derive(Debug, Clone)]
pub struct WspSession {
    pub state: SessionState,
    /// Capabilities the MS proposed on Connect. Echoed on ConnectReply
    /// and available to PD-10c when it decides how big a Reply body can be.
    pub client_capabilities: Vec<crate::wsp::caps::Capability>,
    /// Last time we saw traffic on this session — updated on every PDU.
    pub last_seen: Instant,
}

/// Shared, cloneable gateway-wide state used by the WSP handler.
#[derive(Debug, Clone, Default)]
pub struct WspGatewayState {
    sessions: Arc<DashMap<SessionKey, WspSession>>,
    /// Monotonic counter for server-chosen session IDs. Starts at 1 so
    /// `0` remains free to mean "no session" in the Disconnect path.
    next_session_id: Arc<AtomicU32>,
}

impl WspGatewayState {
    /// Create a fresh, empty session table.
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(DashMap::new()),
            next_session_id: Arc::new(AtomicU32::new(1)),
        }
    }

    /// Number of live sessions in the table. Useful for tests and metrics.
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Drop sessions whose `last_seen` is older than [`SESSION_IDLE_TIMEOUT`].
    ///
    /// Currently called opportunistically from [`WspHandler::handle`]; the
    /// gateway does not yet spawn a dedicated sweep task because the
    /// steady-state number of MS peers per BS is small (single digits) and
    /// keeping the sweep on the RX-hot-path avoids one more tokio task in
    /// the shared runtime.
    pub fn evict_idle(&self, now: Instant) {
        self.sessions.retain(|key, sess| {
            let alive = now.duration_since(sess.last_seen) < SESSION_IDLE_TIMEOUT;
            if !alive {
                info!(peer = %key.0, sid = key.1, "wsp: evicting idle session");
            }
            alive
        });
    }

    /// Allocate the next server session id. Never returns zero.
    fn allocate_session_id(&self) -> u32 {
        loop {
            let id = self.next_session_id.fetch_add(1, Ordering::Relaxed);
            if id != 0 {
                return id;
            }
        }
    }
}

/// Adapter that plugs a [`WspGatewayState`] into the WTP responder's
/// `Handler` trait. Cloneable so the [`crate::wtp::handler_fn`] closure
/// can move a fresh clone into every invocation.
#[derive(Debug, Clone)]
pub struct WspHandler {
    pub state: WspGatewayState,
}

impl WspHandler {
    pub fn new(state: WspGatewayState) -> Self {
        Self { state }
    }

    /// Process one WSP PDU from `peer` and return the bytes to send back
    /// as the WTP Result payload. Malformed input is answered with WSP
    /// status 400 (`Bad Request`), a well-defined WAP-230 §8.7.3 code the
    /// client is guaranteed to understand.
    #[tracing::instrument(level = "debug", skip(self, payload), fields(peer = %peer, len = payload.len()))]
    pub async fn handle(&self, peer: SocketAddr, payload: Vec<u8>) -> Vec<u8> {
        // Opportunistic idle-session sweep. Cheap when the table is small
        // and keeps us from needing a separate janitor task in PD-10b.
        self.state.evict_idle(Instant::now());

        let pdu = match WspPdu::decode(&payload) {
            Ok(p) => p,
            Err(e) => {
                warn!(error = %e, "wsp: failed to decode PDU, replying 400");
                return build_status_reply(STATUS_BAD_REQUEST).encode();
            }
        };
        debug!(kind = ?pdu.pdu_type_code(), "wsp: decoded PDU");

        match pdu {
            WspPdu::Connect { .. } => self.handle_connect(peer, pdu),
            WspPdu::Disconnect { server_session_id } => self.handle_disconnect(peer, server_session_id),
            other => {
                info!(
                    kind = other.pdu_type_code(),
                    "wsp: PDU type not implemented in PD-10b, replying 501"
                );
                build_status_reply(STATUS_NOT_IMPLEMENTED).encode()
            }
        }
    }

    fn handle_connect(&self, peer: SocketAddr, connect: WspPdu) -> Vec<u8> {
        let sid = self.state.allocate_session_id();
        let key: SessionKey = (peer, sid);

        // Snapshot caps for the session record BEFORE we move `connect`
        // into build_connect_reply().
        let caps_snapshot = match &connect {
            WspPdu::Connect { capabilities, .. } => capabilities.clone(),
            _ => Vec::new(),
        };

        let reply = match build_connect_reply(&connect, sid, HeaderBlock::empty()) {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, "wsp: build_connect_reply failed, replying 400");
                return build_status_reply(STATUS_BAD_REQUEST).encode();
            }
        };

        self.state.sessions.insert(
            key,
            WspSession {
                state: SessionState::Connected,
                client_capabilities: caps_snapshot,
                last_seen: Instant::now(),
            },
        );
        info!(peer = %peer, sid, "wsp: session established");
        reply.encode()
    }

    fn handle_disconnect(&self, peer: SocketAddr, sid: u32) -> Vec<u8> {
        let removed = self.state.sessions.remove(&(peer, sid)).is_some();
        info!(peer = %peer, sid, removed, "wsp: Disconnect received");
        // WAP-230 §8.2.2.5 - Disconnect is not confirmed at WSP layer, but
        // WTP class 2 still expects some Result body. Empty Reply with
        // status 200 is what Kannel emits.
        build_status_reply(STATUS_OK).encode()
    }
}

/// WAP-230 §8.7.3.1 — Status = "OK".
pub const STATUS_OK: u8 = 0x20;
/// WAP-230 §8.7.3.4 — Status = "Bad Request".
pub const STATUS_BAD_REQUEST: u8 = 0x40;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wsp::caps::Capability;

    fn loopback_peer() -> SocketAddr {
        "127.0.0.1:12345".parse().unwrap()
    }

    fn synthetic_connect_bytes() -> Vec<u8> {
        // Bare-minimum Connect: version 0x10, one cap (Protocol-Options 0xF0),
        // empty headers. Wire form:
        //   01 10 <caps-len uintvar> <hdrs-len uintvar> <caps>
        WspPdu::Connect {
            version: 0x10,
            capabilities: vec![Capability::ProtocolOptions(0xF0)],
            headers: HeaderBlock::empty(),
        }
        .encode()
    }

    #[tokio::test]
    async fn connect_establishes_session_and_sanitizes_caps() {
        let state = WspGatewayState::new();
        let h = WspHandler::new(state.clone());
        let reply_bytes = h.handle(loopback_peer(), synthetic_connect_bytes()).await;

        let reply = WspPdu::decode(&reply_bytes).unwrap();
        let WspPdu::ConnectReply {
            server_session_id,
            capabilities,
            ..
        } = reply
        else {
            panic!("expected ConnectReply, got {reply:?}");
        };
        assert!(server_session_id >= 1);
        // build_connect_reply clears the top nibble of Protocol-Options
        // (0xF0 → 0x00) to match Kannel's sanitize_capabilities().
        assert_eq!(capabilities, vec![Capability::ProtocolOptions(0x00)]);
        assert_eq!(state.session_count(), 1);
    }

    #[tokio::test]
    async fn disconnect_removes_session() {
        let state = WspGatewayState::new();
        let h = WspHandler::new(state.clone());
        let peer = loopback_peer();
        let reply_bytes = h.handle(peer, synthetic_connect_bytes()).await;
        let sid = match WspPdu::decode(&reply_bytes).unwrap() {
            WspPdu::ConnectReply { server_session_id, .. } => server_session_id,
            _ => unreachable!(),
        };
        assert_eq!(state.session_count(), 1);

        let disc = WspPdu::Disconnect { server_session_id: sid }.encode();
        let _ = h.handle(peer, disc).await;
        assert_eq!(state.session_count(), 0);
    }

    #[tokio::test]
    async fn unknown_pdu_replies_501() {
        let h = WspHandler::new(WspGatewayState::new());
        // 0x40 = Get, which PD-10b does not implement.
        let reply_bytes = h.handle(loopback_peer(), vec![0x40, 0x00, 0x00]).await;
        let WspPdu::Reply { status, .. } = WspPdu::decode(&reply_bytes).unwrap() else {
            panic!("expected Reply");
        };
        assert_eq!(status, STATUS_NOT_IMPLEMENTED);
    }

    #[tokio::test]
    async fn malformed_pdu_replies_400() {
        let h = WspHandler::new(WspGatewayState::new());
        let reply_bytes = h.handle(loopback_peer(), vec![]).await;
        let WspPdu::Reply { status, .. } = WspPdu::decode(&reply_bytes).unwrap() else {
            panic!("expected Reply");
        };
        assert_eq!(status, STATUS_BAD_REQUEST);
    }

    #[tokio::test]
    async fn evict_idle_drops_stale_sessions() {
        let state = WspGatewayState::new();
        let h = WspHandler::new(state.clone());
        let _ = h.handle(loopback_peer(), synthetic_connect_bytes()).await;
        assert_eq!(state.session_count(), 1);

        // Hand-roll a future timestamp past the idle window.
        let future = Instant::now() + SESSION_IDLE_TIMEOUT + Duration::from_secs(1);
        state.evict_idle(future);
        assert_eq!(state.session_count(), 0);
    }
}
