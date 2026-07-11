//! Built-in status portal served by `wap-gateway` — see [module docs](self).
//!
//! # Layering
//!
//! This module lives entirely inside `wap-gateway` and depends on **no other
//! FlowStation crates**. Portal handlers receive live state through the
//! [`PortalDataSource`] trait, which is implemented by the top-level binary
//! (`bluestation-bs`) as a thin adapter over `DashboardState` + `Sndcp`. That
//! keeps `wap-gateway` unit-testable in isolation and preserves the existing
//! "crisp layering" guarantee documented in [`crate`].
//!
//! # Dispatch
//!
//! [`WapPortal::route`] returns `Some(WmlcResponse)` when a URI path matches
//! the configured [`PortalConfig::path_prefix`], and `None` otherwise. The
//! WSP handler in [`crate::wsp::session`] falls through to its existing HTTP
//! upstream relay whenever the portal returns `None`, so enabling the portal
//! does not change the behaviour of non-portal URIs.
//!
//! # Payload budget
//!
//! Every page keeps its compiled WMLC body under 350 B, matching what
//! MTP3550 firmware renders reliably. See `wmlc::MAX_PAGE_BYTES`.

pub mod metar;
pub mod pages;
pub mod wmlc;

use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::wsp::pdu::ContentType;

pub use self::metar::{CachedMetar, MetarCache};

/// Compiled portal configuration, mirrored from `[wap_gateway.portal]`.
///
/// Owned by [`WapPortal`]. Kept `Clone` so `bluestation-bs` can copy it into
/// a background task without borrowing the whole gateway config.
#[derive(Debug, Clone)]
pub struct PortalConfig {
    /// URI path prefix served by the portal (e.g. `/portal`).
    pub path_prefix: String,
    /// ICAO code for METAR lookups. Empty disables the weather page.
    pub metar_icao: String,
    /// Background poll interval for METAR (seconds).
    pub metar_refresh_seconds: u32,
    /// Maximum number of radio rows on the radios page.
    pub radios_max: u8,
}

impl PortalConfig {
    /// Interval used by [`metar::spawn_metar_poller`].
    pub fn metar_refresh_interval(&self) -> Duration {
        Duration::from_secs(u64::from(self.metar_refresh_seconds.max(1)))
    }
}

/// One row on the radios page. Owned so handlers never touch a lock.
#[derive(Debug, Clone)]
pub struct RadioSnapshot {
    pub issi: u32,
    pub callsign: Option<String>,
    /// Seconds since last-seen at snapshot time.
    pub last_seen_secs: u64,
    /// Optional RSSI in dBFS (only shown when present).
    pub rssi_dbfs: Option<f32>,
}

/// Values shown on the system page.
#[derive(Debug, Clone)]
pub struct SystemSnapshot {
    pub uptime: Duration,
    /// Version string (typically `env!("CARGO_PKG_VERSION")`).
    pub version: String,
    /// Number of active SNDCP PDP contexts.
    pub pdp_contexts: usize,
    /// Optional cell-load percentage (0..=100). `None` renders as "n/a".
    pub cell_load_pct: Option<u8>,
}

/// Live state accessor for the portal. Implementations must be cheap and
/// non-blocking — handlers call these from the WSP hot-path.
///
/// Methods are **synchronous** on purpose: the underlying
/// `Arc<RwLock<DashboardStateInner>>` in FlowStation uses `std::sync::RwLock`,
/// so an async trait would just wrap sync work in `Box::pin`. Keeping it sync
/// avoids `async_trait` and one extra allocation per request.
pub trait PortalDataSource: Send + Sync + std::fmt::Debug {
    /// Top-N radios by "most recent last-seen". `max` comes from
    /// [`PortalConfig::radios_max`].
    fn radios(&self, max: usize) -> Vec<RadioSnapshot>;

    /// One-shot system snapshot.
    fn system(&self) -> SystemSnapshot;
}

/// A rendered WMLC response ready for [`crate::wsp::pdu::build_get_reply`].
#[derive(Debug, Clone)]
pub struct WmlcResponse {
    pub status: u8,
    pub content_type: ContentType,
    pub body: Vec<u8>,
}

impl WmlcResponse {
    pub fn wmlc_ok(body: Vec<u8>) -> Self {
        Self {
            status: crate::wsp::pdu::STATUS_OK,
            content_type: ContentType::WellKnown(ContentType::WMLC),
            body,
        }
    }

    pub fn text_error(status: u8, msg: &str) -> Self {
        Self {
            status,
            content_type: ContentType::WellKnown(ContentType::TEXT_PLAIN),
            body: msg.as_bytes().to_vec(),
        }
    }
}

/// Facade that owns the portal's config, live-data source, and METAR cache.
///
/// Cheap to clone (all inner state is `Arc`).
#[derive(Debug, Clone)]
pub struct WapPortal {
    config: Arc<PortalConfig>,
    data: Arc<dyn PortalDataSource>,
    metar: MetarCache,
    /// Startup instant, used by handlers if the data source doesn't expose
    /// uptime directly. Kept here so tests can construct a portal without
    /// wiring an adapter.
    #[allow(dead_code)]
    started_at: Instant,
}

impl WapPortal {
    /// Construct a portal. `metar` is passed in so callers control the
    /// background poller lifetime (see [`metar::spawn_metar_poller`]).
    pub fn new(config: PortalConfig, data: Arc<dyn PortalDataSource>, metar: MetarCache) -> Self {
        Self {
            config: Arc::new(config),
            data,
            metar,
            started_at: Instant::now(),
        }
    }

    /// Path prefix served by this portal.
    pub fn path_prefix(&self) -> &str {
        &self.config.path_prefix
    }

    /// Dispatch a URI path to a portal page. Returns `None` when the URI
    /// does not belong to the portal (caller falls through to upstream).
    pub fn route(&self, path: &str) -> Option<WmlcResponse> {
        let prefix = self.config.path_prefix.as_str();
        // Accept both "/portal" and "/portal/". Anything else that starts
        // with the prefix is treated as a portal path — that's how we get
        // "/portal/radios" to route correctly.
        let sub = if path == prefix {
            ""
        } else {
            let with_slash_prefix = format!("{prefix}/");
            if let Some(rest) = path.strip_prefix(&with_slash_prefix) {
                rest
            } else {
                return None;
            }
        };

        // Strip any trailing slash / query string.
        let sub = sub.split('?').next().unwrap_or(sub);
        let sub = sub.trim_end_matches('/');

        let body = match sub {
            "" | "index" | "index.wml" => pages::render_index(&self.config),
            "radios" => pages::render_radios(&self.config, self.data.as_ref()),
            "weather" => pages::render_weather(&self.config, &self.metar),
            "system" => pages::render_system(&self.config, self.data.as_ref()),
            _ => return Some(WmlcResponse::text_error(crate::wsp::pdu::STATUS_NOT_FOUND, "portal: page not found")),
        };

        Some(WmlcResponse::wmlc_ok(body))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use super::*;

    #[derive(Debug, Default)]
    struct StubDs {
        pub radios: Mutex<Vec<RadioSnapshot>>,
    }

    impl PortalDataSource for StubDs {
        fn radios(&self, max: usize) -> Vec<RadioSnapshot> {
            self.radios.lock().unwrap().iter().take(max).cloned().collect()
        }

        fn system(&self) -> SystemSnapshot {
            SystemSnapshot {
                uptime: Duration::from_secs(42),
                version: "0.0.0-test".to_owned(),
                pdp_contexts: 0,
                cell_load_pct: None,
            }
        }
    }

    fn test_portal() -> WapPortal {
        let cfg = PortalConfig {
            path_prefix: "/portal".to_owned(),
            metar_icao: String::new(),
            metar_refresh_seconds: 1800,
            radios_max: 3,
        };
        WapPortal::new(cfg, Arc::new(StubDs::default()), MetarCache::new())
    }

    #[test]
    fn route_matches_prefix_root() {
        assert!(test_portal().route("/portal").is_some());
        assert!(test_portal().route("/portal/").is_some());
    }

    #[test]
    fn route_matches_known_subpages() {
        let p = test_portal();
        assert!(p.route("/portal/radios").is_some());
        assert!(p.route("/portal/weather").is_some());
        assert!(p.route("/portal/system").is_some());
    }

    #[test]
    fn route_returns_none_for_non_portal_uris() {
        assert!(test_portal().route("/").is_none());
        assert!(test_portal().route("/other/page").is_none());
        // "portalx" must NOT match "/portal" (prefix boundary check).
        assert!(test_portal().route("/portalx").is_none());
    }

    #[test]
    fn route_returns_404_for_unknown_subpage() {
        let resp = test_portal().route("/portal/nope").expect("still a portal path");
        assert_eq!(resp.status, crate::wsp::pdu::STATUS_NOT_FOUND);
    }
}
