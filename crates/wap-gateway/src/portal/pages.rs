//! Portal page renderers. Every function returns fully-encoded WMLC bytes
//! that respect [`crate::portal::wmlc::MAX_PAGE_BYTES`].

use super::wmlc::{self, push_anchor, push_str_i, push_text_element, tag};
use super::{MetarCache, PortalConfig, PortalDataSource};

/// Render the index / landing page.
///
/// Layout (kept ASCII-only to stay inside the byte budget):
/// ```text
/// FlowStation
/// 1 Radios
/// 2 Weather
/// 3 System
/// ```
pub fn render_index(cfg: &PortalConfig) -> Vec<u8> {
    let prefix = cfg.path_prefix.as_str();
    wmlc::wrap_card("FlowStation", |out| {
        // Each menu item lives in its own <p> paragraph so MTP UP.Browser
        // renders them on separate lines. `<br/>` inside a single `<p>` is
        // rendered inconsistently on Motorola firmware — sometimes as a
        // soft space rather than a hard line break.
        push_str_i(out, "FlowStation");
        wmlc::push_paragraph_break(out);
        push_anchor(out, &format!("{prefix}/radios"), "1 Radios");
        wmlc::push_paragraph_break(out);
        push_anchor(out, &format!("{prefix}/weather"), "2 Weather");
        wmlc::push_paragraph_break(out);
        push_anchor(out, &format!("{prefix}/system"), "3 System");
    })
}

/// Render the "connected radios" page.
///
/// Each row: `ISSI CALLSIGN [RSSI]dB Ns`. Rows separated by `<br/>`. We cap
/// at [`PortalConfig::radios_max`] rows.
pub fn render_radios(cfg: &PortalConfig, ds: &dyn PortalDataSource) -> Vec<u8> {
    let radios = ds.radios(cfg.radios_max as usize);
    wmlc::wrap_card("Radios", |out| {
        push_str_i(out, "Radios\n");
        if radios.is_empty() {
            push_str_i(out, "(none)\n");
        } else {
            for r in &radios {
                let cs = r.callsign.as_deref().unwrap_or("-");
                let rssi = match r.rssi_dbfs {
                    Some(v) => format!("{v:.0}dB "),
                    None => String::new(),
                };
                let line = format!("{} {} {}{}s", r.issi, cs, rssi, r.last_seen_secs);
                push_str_i(out, &line);
                push_text_element(out, tag::BR, "");
            }
        }
        push_anchor(out, &cfg.path_prefix, "back");
    })
}

/// Render the weather page from the METAR cache.
pub fn render_weather(cfg: &PortalConfig, cache: &MetarCache) -> Vec<u8> {
    let icao = cfg.metar_icao.as_str();
    wmlc::wrap_card("Weather", |out| {
        if icao.is_empty() {
            push_str_i(out, "METAR: not configured");
        } else {
            match cache.get() {
                Some(entry) => {
                    // Trim to fit; leave ~50 B for chrome.
                    let mut raw = entry.raw;
                    if raw.len() > 260 {
                        raw.truncate(260);
                    }
                    push_str_i(out, &format!("{icao}\n"));
                    push_str_i(out, &raw);
                }
                None => {
                    push_str_i(out, &format!("{icao}\nno data yet"));
                }
            }
        }
        push_text_element(out, tag::BR, "");
        push_anchor(out, &cfg.path_prefix, "back");
    })
}

/// Render the system page.
pub fn render_system(cfg: &PortalConfig, ds: &dyn PortalDataSource) -> Vec<u8> {
    let s = ds.system();
    wmlc::wrap_card("System", |out| {
        let up = fmt_uptime(s.uptime);
        push_str_i(out, &format!("FS {}\nup {}", s.version, up));
        push_text_element(out, tag::BR, "");
        push_str_i(out, &format!("pdp {}", s.pdp_contexts));
        push_text_element(out, tag::BR, "");
        let load = s.cell_load_pct.map(|v| format!("{v}%")).unwrap_or_else(|| "n/a".to_owned());
        push_str_i(out, &format!("load {load}"));
        push_text_element(out, tag::BR, "");
        push_anchor(out, &cfg.path_prefix, "back");
    })
}

fn fmt_uptime(d: std::time::Duration) -> String {
    let s = d.as_secs();
    let days = s / 86_400;
    let hours = (s % 86_400) / 3600;
    let mins = (s % 3600) / 60;
    if days > 0 {
        format!("{days}d{hours}h")
    } else if hours > 0 {
        format!("{hours}h{mins}m")
    } else {
        format!("{mins}m")
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    use super::*;
    use crate::portal::{RadioSnapshot, SystemSnapshot};

    #[derive(Debug, Default)]
    struct StubDs {
        radios: Mutex<Vec<RadioSnapshot>>,
        sys: Mutex<Option<SystemSnapshot>>,
    }

    impl PortalDataSource for StubDs {
        fn radios(&self, max: usize) -> Vec<RadioSnapshot> {
            self.radios.lock().unwrap().iter().take(max).cloned().collect()
        }

        fn system(&self) -> SystemSnapshot {
            self.sys.lock().unwrap().clone().unwrap_or(SystemSnapshot {
                uptime: Duration::from_secs(0),
                version: "0".into(),
                pdp_contexts: 0,
                cell_load_pct: None,
            })
        }
    }

    fn cfg() -> PortalConfig {
        PortalConfig {
            path_prefix: "/portal".into(),
            metar_icao: "LROP".into(),
            metar_refresh_seconds: 1800,
            radios_max: 3,
        }
    }

    #[test]
    fn all_pages_start_with_wbxml_v1_1_header() {
        let ds = StubDs::default();
        let cache = MetarCache::new();
        let c = cfg();
        for bytes in [
            render_index(&c),
            render_radios(&c, &ds),
            render_weather(&c, &cache),
            render_system(&c, &ds),
        ] {
            assert_eq!(&bytes[..4], &[0x01, 0x04, 0x6a, 0x00], "page len {}", bytes.len());
            assert!(bytes.len() <= wmlc::MAX_PAGE_BYTES, "page {} > budget", bytes.len());
        }
    }

    #[test]
    fn radios_page_shows_none_when_empty() {
        let ds = StubDs::default();
        let bytes = render_radios(&cfg(), &ds);
        assert!(bytes.windows(6).any(|w| w == b"(none)"));
    }

    #[test]
    fn radios_page_caps_at_radios_max() {
        let ds = StubDs::default();
        *ds.radios.lock().unwrap() = (0..10)
            .map(|i| RadioSnapshot {
                issi: 1000 + i,
                callsign: Some(format!("cs{i}")),
                last_seen_secs: i as u64,
                rssi_dbfs: None,
            })
            .collect();
        let bytes = render_radios(&cfg(), &ds);
        let hay = String::from_utf8_lossy(&bytes).to_string();
        assert!(hay.contains("cs0"));
        assert!(hay.contains("cs2"));
        assert!(!hay.contains("cs3"));
    }

    #[test]
    fn weather_page_shows_no_data_when_cache_empty() {
        let bytes = render_weather(&cfg(), &MetarCache::new());
        assert!(String::from_utf8_lossy(&bytes).contains("no data yet"));
    }

    #[test]
    fn weather_page_shows_metar_when_cached() {
        let cache = MetarCache::new();
        cache.set(super::super::CachedMetar {
            raw: "LROP 111230Z 27010KT CAVOK 28/12 Q1015".into(),
            fetched_at: Instant::now(),
        });
        let bytes = render_weather(&cfg(), &cache);
        assert!(String::from_utf8_lossy(&bytes).contains("CAVOK"));
    }

    #[test]
    fn system_page_shows_uptime_and_pdp() {
        let ds = StubDs {
            sys: Mutex::new(Some(SystemSnapshot {
                uptime: Duration::from_secs(3661),
                version: "1.2.3".into(),
                pdp_contexts: 4,
                cell_load_pct: Some(37),
            })),
            ..Default::default()
        };
        let bytes = render_system(&cfg(), &ds);
        let s = String::from_utf8_lossy(&bytes);
        assert!(s.contains("1.2.3"));
        assert!(s.contains("1h1m"));
        assert!(s.contains("pdp 4"));
        assert!(s.contains("37%"));
    }

    #[test]
    fn fmt_uptime_shapes() {
        assert_eq!(fmt_uptime(Duration::from_secs(30)), "0m");
        assert_eq!(fmt_uptime(Duration::from_secs(65)), "1m");
        assert_eq!(fmt_uptime(Duration::from_secs(3600 + 120)), "1h2m");
        assert_eq!(fmt_uptime(Duration::from_secs(86_400 * 2 + 3600 * 3)), "2d3h");
    }
}
