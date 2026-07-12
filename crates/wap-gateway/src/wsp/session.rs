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

use crate::error::{WapError, WapResult};
use crate::portal::WapPortal;
use crate::wsp::WspCapabilityMode;
use crate::wsp::pdu::{
    ContentType, HeaderBlock, STATUS_BAD_GATEWAY, STATUS_BAD_REQUEST, STATUS_INTERNAL_ERROR, STATUS_METHOD_NOT_ALLOWED, STATUS_NOT_FOUND,
    STATUS_NOT_IMPLEMENTED, STATUS_OK, WspPdu, build_connect_reply, build_get_reply, build_status_reply, pdu_type,
};

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
///
/// Owns the [`reqwest::Client`] used for the PD-10c HTTP upstream relay.
/// Cloning is cheap (`Arc` all the way down) and safe to do per RX frame.
#[derive(Debug, Clone)]
pub struct WspGatewayState {
    sessions: Arc<DashMap<SessionKey, WspSession>>,
    /// Monotonic counter for server-chosen session IDs. Starts at 1 so
    /// `0` remains free to mean "no session" in the Disconnect path.
    next_session_id: Arc<AtomicU32>,
    /// HTTP client used by [`WspHandler::handle_get`] to fetch upstream
    /// content. Built once (with reasonable timeouts and no redirect
    /// following — WSP MSs re-Get on 3xx via a fresh request anyway).
    http: reqwest::Client,
    /// Default upstream base URL. Used only when the MS sends a relative
    /// URI (rare — real MSs always send absolute). Kept as a plain string
    /// to avoid parsing until we actually need it.
    upstream_base: Arc<String>,
    /// Optional built-in portal. When set, [`WspHandler::handle_get`]
    /// intercepts URIs whose path starts with the portal's `path_prefix`
    /// and serves WMLC locally, bypassing `upstream_base` entirely.
    portal: Option<WapPortal>,
    /// PD-11-H1: how [`build_connect_reply`] handles the MS-proposed
    /// capability list. Default [`WspCapabilityMode::VerbatimEcho`] matches
    /// what `caps.rs` / `lib.rs` document as tested-working for UP.Browser
    /// 6.3 on Motorola MTP3550; operators can flip to
    /// [`WspCapabilityMode::Sanitize`] for firmware revisions that need
    /// Kannel-style stripping.
    capability_mode: WspCapabilityMode,
}

impl Default for WspGatewayState {
    fn default() -> Self {
        Self::new()
    }
}

impl WspGatewayState {
    /// Create a fresh session table with a default HTTP client and no
    /// configured upstream base URL (relative-URI requests will fail with
    /// 502). Prefer [`WspGatewayState::with_upstream`] in production.
    pub fn new() -> Self {
        Self::with_upstream(String::new())
    }

    /// Create a session table with a configured upstream base URL used to
    /// resolve relative Get URIs. Absolute URIs (`http://…`) bypass this
    /// base and go directly to the requested host — this mirrors Kannel's
    /// transparent-proxy behaviour and matches what UP.Browser 6.3 sends
    /// on the wire (an absolute URL every time).
    pub fn with_upstream(upstream_base: String) -> Self {
        Self::with_upstream_and_portal(upstream_base, None)
    }

    /// Same as [`Self::with_upstream`] but also attaches an optional
    /// [`WapPortal`] that intercepts GETs to its configured path prefix.
    pub fn with_upstream_and_portal(upstream_base: String, portal: Option<WapPortal>) -> Self {
        Self::with_upstream_portal_and_capability_mode(upstream_base, portal, WspCapabilityMode::default())
    }

    /// Full-fat constructor that also lets the caller pin the
    /// [`WspCapabilityMode`] used by [`build_connect_reply`]. All other
    /// constructors delegate here with the default mode.
    pub fn with_upstream_portal_and_capability_mode(
        upstream_base: String,
        portal: Option<WapPortal>,
        capability_mode: WspCapabilityMode,
    ) -> Self {
        // Build the client with conservative timeouts. Redirect following
        // is disabled so we return 3xx status codes straight to the MS —
        // WSP browsers re-issue a fresh Get on 3xx (WAP-230 §7.2), and
        // following server-side would strip cookies / auth from the redirect
        // target which we can't currently propagate.
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap_or_else(|e| {
                // Client::build only fails on TLS init glitches; reqwest
                // ships a `Client::new()` that panics on the same paths, so
                // falling back to it doesn't help. Panic here is acceptable
                // — this runs at gateway startup before any I/O.
                panic!("wap-gateway: failed to build reqwest client: {e}");
            });
        Self {
            sessions: Arc::new(DashMap::new()),
            next_session_id: Arc::new(AtomicU32::new(1)),
            http,
            upstream_base: Arc::new(upstream_base),
            portal,
            capability_mode,
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
            WspPdu::MethodInvoke {
                method_code: pdu_type::GET,
                uri,
                ..
            } => self.handle_get(peer, uri).await,
            WspPdu::MethodInvoke { method_code, uri, .. } => {
                info!(
                    method = format!("{method_code:#04x}"),
                    uri, "wsp: non-GET method not implemented, replying 405"
                );
                build_status_reply(STATUS_METHOD_NOT_ALLOWED).encode()
            }
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
        // PD-10c-H27 (2026-07-11 MTP3550 fix): evict any prior WSP sessions
        // for this peer BEFORE allocating a fresh one. WSP-CO doesn't require
        // explicit Disconnect, and flaky MTP3550 firmware can retry CONNECT
        // several times per real user attempt — each one allocating a fresh
        // session_id. Left alone the sessions map grew across the lifetime of
        // the process; the "only works after reboot" symptom is a strong
        // signal that per-peer state accumulated to the point where MS's
        // cached session view diverged from ours. Mirror H25 (WTP txn
        // eviction) one layer up.
        let stale: Vec<SessionKey> = self
            .state
            .sessions
            .iter()
            .filter(|entry| entry.key().0 == peer)
            .map(|entry| *entry.key())
            .collect();
        let stale_count = stale.len();
        for k in stale {
            self.state.sessions.remove(&k);
        }
        if stale_count > 0 {
            info!(peer = %peer, evicted = stale_count, "H27: evicted stale WSP sessions on CONNECT");
        }

        let sid = self.state.allocate_session_id();
        let key: SessionKey = (peer, sid);

        // Snapshot caps for the session record BEFORE we move `connect`
        // into build_connect_reply().
        let caps_snapshot = match &connect {
            WspPdu::Connect { capabilities, .. } => capabilities.clone(),
            _ => Vec::new(),
        };

        let reply = match build_connect_reply(&connect, sid, HeaderBlock::empty(), self.state.capability_mode) {
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
        info!(peer = %peer, sid, sessions_total = self.state.sessions.len(), "wsp: session established");
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

    /// PD-10c hot path: fetch `uri` from upstream, translate the HTTP
    /// response into a WSP Reply.
    ///
    /// * Absolute URIs (`http://…` / `https://…`) go straight to the host
    ///   named in the URL (Kannel's transparent-proxy behaviour — this is
    ///   what UP.Browser 6.3 sends every time on TETRA).
    /// * Relative URIs are resolved against
    ///   [`WspGatewayState::upstream_base`]; the browser fleet in this
    ///   deployment doesn't emit relative URIs but keeping the code path
    ///   here means a future WSP client we haven't seen won't get
    ///   surprised by a 502.
    ///
    /// Every failure mode (unparseable URI, upstream refused, timeout,
    /// upstream 5xx propagated through reqwest) folds to WSP status
    /// `502 Bad Gateway` with a short text/plain body. That body ends up
    /// in the WSP Reply and, on real hardware, is rendered by the browser
    /// error page — so keep it short and ASCII-safe.
    async fn handle_get(&self, peer: SocketAddr, uri: String) -> Vec<u8> {
        let resolved = match resolve_uri(&uri, self.state.upstream_base.as_str()) {
            Ok(u) => u,
            Err(e) => {
                warn!(peer = %peer, uri, error = %e, "wsp: could not resolve Get URI");
                return build_get_reply(
                    STATUS_BAD_REQUEST,
                    ContentType::WellKnown(ContentType::TEXT_PLAIN),
                    format!("wap-gateway: bad request URI: {e}").into_bytes(),
                )
                .encode();
            }
        };

        // Portal intercept: if configured and the resolved path matches the
        // portal's prefix, serve WMLC locally without touching upstream.
        if let Some(portal) = &self.state.portal
            && let Some(resp) = portal.route(resolved.path())
        {
            info!(
                peer = %peer,
                path = resolved.path(),
                bytes = resp.body.len(),
                "wsp: portal GET",
            );
            return build_get_reply(resp.status, resp.content_type, resp.body).encode();
        }

        info!(peer = %peer, uri = %resolved, "wsp: GET upstream");

        match self.state.http.get(resolved.clone()).send().await {
            Ok(resp) => {
                let http_status = resp.status();
                let content_type_header = resp
                    .headers()
                    .get(reqwest::header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_owned())
                    .unwrap_or_else(|| "application/octet-stream".to_owned());
                let content_type = ContentType::from_http(&content_type_header);

                let body = match resp.bytes().await {
                    Ok(b) => b.to_vec(),
                    Err(e) => {
                        warn!(peer = %peer, uri = %resolved, error = %e, "wsp: upstream body read failed");
                        return build_get_reply(
                            STATUS_BAD_GATEWAY,
                            ContentType::WellKnown(ContentType::TEXT_PLAIN),
                            b"wap-gateway: upstream body read failed".to_vec(),
                        )
                        .encode();
                    }
                };

                let wsp_status = http_to_wsp_status(http_status.as_u16());
                info!(
                    peer = %peer,
                    uri = %resolved,
                    http_status = http_status.as_u16(),
                    wsp_status = format!("{wsp_status:#04x}"),
                    bytes = body.len(),
                    content_type = %content_type_header,
                    "wsp: upstream response",
                );
                build_get_reply(wsp_status, content_type, body).encode()
            }
            Err(e) => {
                warn!(peer = %peer, uri = %resolved, error = %e, "wsp: upstream fetch failed");
                let (status, msg) = if e.is_timeout() {
                    (STATUS_BAD_GATEWAY, "wap-gateway: upstream timeout")
                } else if e.is_connect() {
                    (STATUS_BAD_GATEWAY, "wap-gateway: upstream connect refused")
                } else {
                    (STATUS_INTERNAL_ERROR, "wap-gateway: upstream fetch error")
                };
                build_get_reply(status, ContentType::WellKnown(ContentType::TEXT_PLAIN), msg.as_bytes().to_vec()).encode()
            }
        }
    }
}

/// Resolve `uri` — the exact URI bytes from the WSP Get PDU — against the
/// configured `upstream_base`. Absolute URIs are returned as-is (after
/// validation); relative URIs are joined onto `upstream_base`.
///
/// Returns a validated [`reqwest::Url`] ready to hand to `Client::get`.
fn resolve_uri(uri: &str, upstream_base: &str) -> WapResult<reqwest::Url> {
    if uri.starts_with("http://") || uri.starts_with("https://") {
        return reqwest::Url::parse(uri).map_err(|e| WapError::Config(format!("invalid absolute URI {uri:?}: {e}")));
    }
    if upstream_base.is_empty() {
        return Err(WapError::Config(format!("relative URI {uri:?} but no upstream_url configured")));
    }
    let base = reqwest::Url::parse(upstream_base).map_err(|e| WapError::Config(format!("bad upstream_url {upstream_base:?}: {e}")))?;
    base.join(uri)
        .map_err(|e| WapError::Config(format!("could not join {uri:?} onto upstream_url: {e}")))
}

/// Map an HTTP numeric status code onto the closest WSP §8.7.3 short-form
/// status. WSP compresses the space by grouping (top nibble is the HTTP
/// class × 0x10; bottom nibble is the sub-code with 0x00 = generic-in-class).
/// For anything we don't have a named constant for we fall back to the
/// class-generic code so the MS at least sees the right family.
fn http_to_wsp_status(code: u16) -> u8 {
    match code {
        200 => STATUS_OK,
        201 => 0x21, // Created
        204 => 0x24, // No Content
        301 => 0x31, // Moved Permanently
        302 => 0x32, // Moved Temporarily
        304 => 0x34, // Not Modified
        400 => STATUS_BAD_REQUEST,
        401 => 0x41, // Unauthorized
        403 => 0x43, // Forbidden
        404 => STATUS_NOT_FOUND,
        405 => STATUS_METHOD_NOT_ALLOWED,
        500 => STATUS_INTERNAL_ERROR,
        501 => STATUS_NOT_IMPLEMENTED,
        502 => STATUS_BAD_GATEWAY,
        503 => 0x53, // Service Unavailable
        504 => 0x54, // Gateway Timeout
        c => {
            // Class-generic fallback: (100s digit) << 4.
            let class = (c / 100) as u8;
            match class {
                1..=5 => class << 4,
                _ => STATUS_INTERNAL_ERROR,
            }
        }
    }
}

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
    async fn connect_verbatim_echo_default_preserves_protocol_options() {
        // PD-11-H1: default mode is VerbatimEcho — Protocol-Options 0xF0
        // comes back untouched.
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
        assert_eq!(capabilities, vec![Capability::ProtocolOptions(0xF0)]);
        assert_eq!(state.session_count(), 1);
    }

    #[tokio::test]
    async fn connect_sanitize_mode_clears_protocol_options_top_nibble() {
        // Opt-in Sanitize mode keeps the legacy Kannel-parity behaviour.
        let state = WspGatewayState::with_upstream_portal_and_capability_mode(String::new(), None, WspCapabilityMode::Sanitize);
        let h = WspHandler::new(state.clone());
        let reply_bytes = h.handle(loopback_peer(), synthetic_connect_bytes()).await;

        let reply = WspPdu::decode(&reply_bytes).unwrap();
        let WspPdu::ConnectReply { capabilities, .. } = reply else {
            panic!("expected ConnectReply");
        };
        assert_eq!(capabilities, vec![Capability::ProtocolOptions(0x00)]);
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
        // 0x30 is unassigned; decodes as WspPdu::Unknown. PD-10c re-routes
        // 0x40 (Get) into the HTTP relay path so it no longer answers 501.
        let reply_bytes = h.handle(loopback_peer(), vec![0x30, 0x00, 0x00]).await;
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

    // ── PD-10c: HTTP relay tests ─────────────────────────────────────────

    use crate::wsp::pdu::STATUS_NOT_FOUND;

    #[test]
    fn http_to_wsp_status_maps_well_known() {
        assert_eq!(http_to_wsp_status(200), STATUS_OK);
        assert_eq!(http_to_wsp_status(404), STATUS_NOT_FOUND);
        assert_eq!(http_to_wsp_status(405), STATUS_METHOD_NOT_ALLOWED);
        assert_eq!(http_to_wsp_status(502), STATUS_BAD_GATEWAY);
    }

    #[test]
    fn http_to_wsp_status_falls_back_to_class_generic() {
        // 418 → class 4 → 0x40 (Bad Request family, generic).
        assert_eq!(http_to_wsp_status(418), 0x40);
        // 599 → class 5 → 0x50.
        assert_eq!(http_to_wsp_status(599), 0x50);
        // Weird 999 → internal error.
        assert_eq!(http_to_wsp_status(999), STATUS_INTERNAL_ERROR);
    }

    #[test]
    fn resolve_uri_passes_absolute_unchanged() {
        let u = resolve_uri("http://10.222.0.1:8081/index.wml", "http://example.invalid/").unwrap();
        assert_eq!(u.as_str(), "http://10.222.0.1:8081/index.wml");
    }

    #[test]
    fn resolve_uri_joins_relative_against_base() {
        let u = resolve_uri("/index.wml", "http://127.0.0.1:8081/").unwrap();
        assert_eq!(u.as_str(), "http://127.0.0.1:8081/index.wml");
    }

    #[test]
    fn resolve_uri_rejects_relative_without_base() {
        assert!(resolve_uri("/index.wml", "").is_err());
    }

    #[test]
    fn non_get_method_replies_405() {
        // 0x42 = HEAD. Wire bytes: [42][uri-len=1][/]
        let bytes = vec![pdu_type::HEAD, 0x01, b'/'];
        let h = WspHandler::new(WspGatewayState::with_upstream("http://127.0.0.1:1/".to_owned()));
        let rt = tokio::runtime::Runtime::new().unwrap();
        let reply_bytes = rt.block_on(h.handle(loopback_peer(), bytes));
        let WspPdu::Reply { status, .. } = WspPdu::decode(&reply_bytes).unwrap() else {
            panic!("expected Reply");
        };
        assert_eq!(status, STATUS_METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn get_to_unreachable_upstream_replies_502() {
        // Port 1 on loopback is guaranteed-refused on every OS we care about.
        let h = WspHandler::new(WspGatewayState::with_upstream("http://127.0.0.1:1/".to_owned()));
        // Build a Get for a relative URI so it resolves against the base.
        let get = WspPdu::MethodInvoke {
            method_code: pdu_type::GET,
            uri: "/whatever".to_owned(),
            headers: HeaderBlock::empty(),
        }
        .encode();
        let reply_bytes = h.handle(loopback_peer(), get).await;
        let WspPdu::Reply { status, body, .. } = WspPdu::decode(&reply_bytes).unwrap() else {
            panic!("expected Reply");
        };
        assert_eq!(status, STATUS_BAD_GATEWAY);
        assert!(!body.is_empty(), "502 body must carry a diagnostic string");
    }

    #[tokio::test]
    async fn get_with_unparseable_uri_replies_400() {
        let h = WspHandler::new(WspGatewayState::with_upstream(String::new()));
        let get = WspPdu::MethodInvoke {
            method_code: pdu_type::GET,
            uri: "not-a-url".to_owned(),
            headers: HeaderBlock::empty(),
        }
        .encode();
        let reply_bytes = h.handle(loopback_peer(), get).await;
        let WspPdu::Reply { status, .. } = WspPdu::decode(&reply_bytes).unwrap() else {
            panic!("expected Reply");
        };
        // No upstream_url + relative → 400.
        assert_eq!(status, STATUS_BAD_REQUEST);
    }

    // ── Portal dispatch tests ────────────────────────────────────────────

    use crate::portal::{MetarCache, PortalConfig, PortalDataSource, RadioSnapshot, SystemSnapshot, WapPortal};

    #[derive(Debug, Default)]
    struct PortalStub;

    impl PortalDataSource for PortalStub {
        fn radios(&self, _max: usize) -> Vec<RadioSnapshot> {
            Vec::new()
        }
        fn system(&self) -> SystemSnapshot {
            SystemSnapshot {
                uptime: std::time::Duration::from_secs(1),
                version: "test".into(),
                pdp_contexts: 0,
                cell_load_pct: None,
            }
        }
    }

    fn portal_state() -> WspGatewayState {
        let portal = WapPortal::new(
            PortalConfig {
                path_prefix: "/portal".into(),
                metar_icao: String::new(),
                metar_refresh_seconds: 1800,
                radios_max: 3,
            },
            Arc::new(PortalStub),
            MetarCache::new(),
        );
        // upstream_base is deliberately unreachable so we can prove portal URIs
        // *don't* hit it.
        WspGatewayState::with_upstream_and_portal("http://127.0.0.1:1/".to_owned(), Some(portal))
    }

    #[tokio::test]
    async fn portal_get_returns_wmlc_locally() {
        let h = WspHandler::new(portal_state());
        let get = WspPdu::MethodInvoke {
            method_code: pdu_type::GET,
            uri: "http://10.0.0.1/portal/system".to_owned(),
            headers: HeaderBlock::empty(),
        }
        .encode();
        let reply_bytes = h.handle(loopback_peer(), get).await;
        let WspPdu::Reply { status, headers, body } = WspPdu::decode(&reply_bytes).unwrap() else {
            panic!("expected Reply");
        };
        assert_eq!(status, STATUS_OK);
        // Content-Type is encoded as the first header byte (WSP short-form
        // well-known): 0x80 | 0x14 = 0x94 for application/vnd.wap.wmlc.
        assert_eq!(headers.raw.first().copied(), Some(0x94));
        assert_eq!(&body[..4], &[0x01, 0x04, 0x6a, 0x00], "WBXML v1.1 header");
    }

    #[tokio::test]
    async fn non_portal_get_still_hits_upstream_and_502s() {
        // Same portal state as above, but hit a non-portal path → should try
        // upstream on 127.0.0.1:1 and 502.
        let h = WspHandler::new(portal_state());
        let get = WspPdu::MethodInvoke {
            method_code: pdu_type::GET,
            uri: "http://10.0.0.1/index.wml".to_owned(),
            headers: HeaderBlock::empty(),
        }
        .encode();
        let reply_bytes = h.handle(loopback_peer(), get).await;
        let WspPdu::Reply { status, .. } = WspPdu::decode(&reply_bytes).unwrap() else {
            panic!("expected Reply");
        };
        assert_eq!(status, STATUS_BAD_GATEWAY);
    }
}
