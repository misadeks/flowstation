//! Background METAR poller with a shared `RwLock` cache.
//!
//! Keeps the WSP hot path allocation-free: the weather page just reads a
//! `String` under a read-lock and drops it. The actual outbound HTTP fetch
//! runs on a dedicated tokio task, spawned by `bluestation-bs` alongside
//! [`crate::run`].
//!
//! Failures are logged once and the last-good value is served indefinitely.

use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

/// One cached METAR observation.
#[derive(Debug, Clone)]
pub struct CachedMetar {
    /// Raw METAR line as returned by the upstream API.
    pub raw: String,
    /// When the entry was fetched.
    pub fetched_at: Instant,
}

/// Cheap, clone-able handle to the shared METAR cache.
#[derive(Debug, Clone, Default)]
pub struct MetarCache(Arc<RwLock<Option<CachedMetar>>>);

impl MetarCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Read a snapshot of the current cache entry. Never blocks the writer
    /// for meaningful time — the lock is held only long enough to `Clone` a
    /// small struct.
    pub fn get(&self) -> Option<CachedMetar> {
        self.0.read().ok().and_then(|guard| guard.clone())
    }

    /// Replace the cached value.
    pub fn set(&self, value: CachedMetar) {
        if let Ok(mut guard) = self.0.write() {
            *guard = Some(value);
        }
    }
}

/// Spawn a tokio task that refreshes the METAR cache every `interval`.
///
/// Returns immediately. The task shuts down when `cancel` fires. If `icao`
/// is empty the task exits without spawning any HTTP work — the weather
/// page then renders a "not configured" hint.
pub fn spawn_metar_poller(cache: MetarCache, icao: String, interval: Duration, cancel: CancellationToken) {
    if icao.trim().is_empty() {
        info!("wap-portal: metar poller not spawned (icao unset)");
        return;
    }
    let icao = icao.to_ascii_uppercase();
    tokio::spawn(async move {
        let client = match reqwest::Client::builder().timeout(Duration::from_secs(10)).build() {
            Ok(c) => c,
            Err(e) => {
                warn!(error = %e, "wap-portal: could not build metar http client, task exiting");
                return;
            }
        };
        // tokio::time::interval fires immediately on first tick, so the first
        // fetch happens right after spawn.
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut warned_last_cycle = false;
        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    info!("wap-portal: metar poller shutting down");
                    return;
                }
                _ = ticker.tick() => {}
            }
            let url = format!("https://aviationweather.gov/api/data/metar?ids={icao}&format=raw");
            match fetch_one(&client, &url).await {
                Ok(raw) => {
                    cache.set(CachedMetar {
                        raw,
                        fetched_at: Instant::now(),
                    });
                    if warned_last_cycle {
                        info!(icao, "wap-portal: metar recovered");
                    }
                    warned_last_cycle = false;
                }
                Err(e) => {
                    if !warned_last_cycle {
                        warn!(icao, error = %e, "wap-portal: metar fetch failed (last-good served)");
                    }
                    warned_last_cycle = true;
                }
            }
        }
    });
}

async fn fetch_one(client: &reqwest::Client, url: &str) -> Result<String, String> {
    let resp = client.get(url).send().await.map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status().as_u16()));
    }
    let body = resp.text().await.map_err(|e| e.to_string())?;
    let first = body.lines().find(|l| !l.trim().is_empty()).unwrap_or("").trim().to_owned();
    if first.is_empty() {
        return Err("empty body".to_owned());
    }
    Ok(first)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_starts_empty_and_supports_set_get() {
        let c = MetarCache::new();
        assert!(c.get().is_none());
        c.set(CachedMetar {
            raw: "LROP METAR TEST".to_owned(),
            fetched_at: Instant::now(),
        });
        assert_eq!(c.get().unwrap().raw, "LROP METAR TEST");
    }
}
