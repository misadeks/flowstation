//! `[wap_gateway]` — WAP 1.x gateway (PD-10) runtime configuration.
//!
//! Lives inside the main FlowStation config so operators configure it in the
//! same file they already edit for the rest of the stack. Wired into
//! `StackConfig::wap_gateway`. The gateway itself runs in-process (inside
//! `bluestation-bs`), so this section only carries the *policy* — no PID
//! file, no separate binary.
//!
//! ```toml
//! [wap_gateway]
//! enabled = true
//! listen_port = 9201                        # optional; default 9201
//! upstream_url = "http://127.0.0.1:8081"   # HTTP backend for WML fetches
//! log_level = "info"                        # optional; defaults to "info"
//! # listen_addr defaults to `packet_data.tun_addr`; set only to override:
//! # listen_addr = "10.222.0.1"
//!
//! [wap_gateway.portal]
//! enabled = true                            # serve built-in status pages
//! path_prefix = "/portal"                   # URIs under this prefix hit the portal
//! metar_icao = "LROP"                        # empty disables the weather page
//! metar_refresh_seconds = 1800              # background poll interval
//! radios_max = 5                             # rows shown on the radios page
//! ```

use std::collections::HashMap;
use std::net::Ipv4Addr;

use serde::Deserialize;
use toml::Value;

use super::sec_llc::ConfigError;

/// Default WSP connection-oriented port (WAP-230).
pub const DEFAULT_WAP_LISTEN_PORT: u16 = 9201;
/// Default upstream HTTP backend for WML/WBXML fetches.
pub const DEFAULT_WAP_UPSTREAM_URL: &str = "http://127.0.0.1:8081";
/// Default log level string (matches `tracing` env-filter syntax).
pub const DEFAULT_WAP_LOG_LEVEL: &str = "info";

/// Default URI path prefix that maps to the built-in portal.
pub const DEFAULT_WAP_PORTAL_PATH_PREFIX: &str = "/portal";
/// Default METAR refresh interval (30 min).
pub const DEFAULT_WAP_PORTAL_METAR_REFRESH_SECONDS: u32 = 1800;
/// Default number of radio rows on the radios page (kept small to fit ~350 B budget).
pub const DEFAULT_WAP_PORTAL_RADIOS_MAX: u8 = 5;

// ─── Compiled config ─────────────────────────────────────────────────────────

/// Fully-validated `[wap_gateway]` runtime config.
#[derive(Debug, Clone)]
pub struct CfgWapGateway {
    /// When `false` the gateway task is not spawned by `bluestation-bs`.
    pub enabled: bool,
    /// IPv4 address the UDP socket binds to. Defaults to
    /// `packet_data.tun_addr` at validation time.
    pub listen_addr: Ipv4Addr,
    /// UDP port to listen on. Default 9201.
    pub listen_port: u16,
    /// HTTP backend base URL. Used by PD-10c for WML/WBXML fetches.
    pub upstream_url: String,
    /// `tracing` env-filter compatible directive.
    pub log_level: String,
    /// Built-in status portal (served by `wap-gateway` directly, no upstream).
    pub portal: CfgWapGatewayPortal,
}

/// Validated `[wap_gateway.portal]` sub-section.
#[derive(Debug, Clone)]
pub struct CfgWapGatewayPortal {
    /// When `false` the portal is not constructed and every GET falls through to `upstream_url`.
    pub enabled: bool,
    /// URI path prefix that is served locally. Anything else falls through to upstream.
    pub path_prefix: String,
    /// ICAO code for METAR lookups. Empty string disables the weather page.
    pub metar_icao: String,
    /// Background poll interval for METAR (seconds).
    pub metar_refresh_seconds: u32,
    /// Maximum number of radio rows on the radios page.
    pub radios_max: u8,
}

impl CfgWapGatewayPortal {
    /// Disabled portal — matches `[wap_gateway.portal]` being absent.
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            path_prefix: DEFAULT_WAP_PORTAL_PATH_PREFIX.to_owned(),
            metar_icao: String::new(),
            metar_refresh_seconds: DEFAULT_WAP_PORTAL_METAR_REFRESH_SECONDS,
            radios_max: DEFAULT_WAP_PORTAL_RADIOS_MAX,
        }
    }
}

impl CfgWapGateway {
    /// Disabled configuration used when `[wap_gateway]` is absent.
    pub fn disabled(fallback_listen_addr: Ipv4Addr) -> Self {
        Self {
            enabled: false,
            listen_addr: fallback_listen_addr,
            listen_port: DEFAULT_WAP_LISTEN_PORT,
            upstream_url: DEFAULT_WAP_UPSTREAM_URL.to_owned(),
            log_level: DEFAULT_WAP_LOG_LEVEL.to_owned(),
            portal: CfgWapGatewayPortal::disabled(),
        }
    }

    /// Resolve the effective UDP bind address.
    ///
    /// Convenience helper for callers who prefer late-resolution instead of
    /// trusting the value materialised by [`apply_wap_gateway_patch`] at
    /// parse time. Falls back to `packet_data_tun_addr` when the operator
    /// did not set an explicit override. Kept idempotent so calling it
    /// after `apply_wap_gateway_patch` still returns the same address.
    pub fn resolved_listen_addr(&self, packet_data_tun_addr: Ipv4Addr) -> Ipv4Addr {
        // `apply_wap_gateway_patch` already materialised `listen_addr`; the
        // only case where it can still equal `Ipv4Addr::UNSPECIFIED` is if
        // the caller built a `CfgWapGateway` by hand without going through
        // the validator. Handle that gracefully.
        if self.listen_addr.is_unspecified() {
            packet_data_tun_addr
        } else {
            self.listen_addr
        }
    }
}

// ─── Serde DTO ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct CfgWapGatewayDto {
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Optional — falls back to `packet_data.tun_addr`.
    #[serde(default)]
    pub listen_addr: Option<Ipv4Addr>,

    #[serde(default = "default_listen_port")]
    pub listen_port: u16,

    #[serde(default = "default_upstream_url")]
    pub upstream_url: String,

    #[serde(default = "default_log_level")]
    pub log_level: String,

    /// Optional `[wap_gateway.portal]` sub-table.
    #[serde(default)]
    pub portal: Option<CfgWapGatewayPortalDto>,

    /// Unknown-field detector — parsing.rs rejects any entry here.
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CfgWapGatewayPortalDto {
    #[serde(default = "default_portal_enabled")]
    pub enabled: bool,

    #[serde(default = "default_portal_path_prefix")]
    pub path_prefix: String,

    #[serde(default)]
    pub metar_icao: String,

    #[serde(default = "default_portal_metar_refresh_seconds")]
    pub metar_refresh_seconds: u32,

    #[serde(default = "default_portal_radios_max")]
    pub radios_max: u8,

    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

impl Default for CfgWapGatewayPortalDto {
    fn default() -> Self {
        Self {
            enabled: default_portal_enabled(),
            path_prefix: default_portal_path_prefix(),
            metar_icao: String::new(),
            metar_refresh_seconds: default_portal_metar_refresh_seconds(),
            radios_max: default_portal_radios_max(),
            extra: HashMap::new(),
        }
    }
}

impl Default for CfgWapGatewayDto {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            listen_addr: None,
            listen_port: default_listen_port(),
            upstream_url: default_upstream_url(),
            log_level: default_log_level(),
            portal: None,
            extra: HashMap::new(),
        }
    }
}

fn default_enabled() -> bool {
    false
}
fn default_listen_port() -> u16 {
    DEFAULT_WAP_LISTEN_PORT
}
fn default_upstream_url() -> String {
    DEFAULT_WAP_UPSTREAM_URL.to_owned()
}
fn default_log_level() -> String {
    DEFAULT_WAP_LOG_LEVEL.to_owned()
}
fn default_portal_enabled() -> bool {
    false
}
fn default_portal_path_prefix() -> String {
    DEFAULT_WAP_PORTAL_PATH_PREFIX.to_owned()
}
fn default_portal_metar_refresh_seconds() -> u32 {
    DEFAULT_WAP_PORTAL_METAR_REFRESH_SECONDS
}
fn default_portal_radios_max() -> u8 {
    DEFAULT_WAP_PORTAL_RADIOS_MAX
}

// ─── Validation ──────────────────────────────────────────────────────────────

/// Validate the `[wap_gateway]` DTO and materialise the compiled config.
///
/// `packet_data_tun_addr` is used as the default `listen_addr` when the
/// operator has not set one explicitly — keeps `[packet_data]` as the single
/// source of truth for the TUN interface's IPv4.
pub fn apply_wap_gateway_patch(dto: CfgWapGatewayDto, packet_data_tun_addr: Ipv4Addr) -> Result<CfgWapGateway, ConfigError> {
    if dto.listen_port == 0 {
        return Err(ConfigError {
            field: "wap_gateway.listen_port",
            message: "must be non-zero".to_owned(),
        });
    }

    if dto.upstream_url.trim().is_empty() {
        return Err(ConfigError {
            field: "wap_gateway.upstream_url",
            message: "must be non-empty".to_owned(),
        });
    }
    if !(dto.upstream_url.starts_with("http://") || dto.upstream_url.starts_with("https://")) {
        return Err(ConfigError {
            field: "wap_gateway.upstream_url",
            message: format!("must start with http:// or https://, got {:?}", dto.upstream_url),
        });
    }

    if dto.log_level.trim().is_empty() {
        return Err(ConfigError {
            field: "wap_gateway.log_level",
            message: "must be non-empty".to_owned(),
        });
    }

    let portal = apply_wap_gateway_portal_patch(dto.portal.unwrap_or_default())?;

    Ok(CfgWapGateway {
        enabled: dto.enabled,
        listen_addr: dto.listen_addr.unwrap_or(packet_data_tun_addr),
        listen_port: dto.listen_port,
        upstream_url: dto.upstream_url,
        log_level: dto.log_level,
        portal,
    })
}

/// Validate the `[wap_gateway.portal]` DTO.
///
/// Unknown keys are rejected by the outer `parsing.rs` check (it walks
/// `dto.portal.extra`). This function only validates *values*.
pub fn apply_wap_gateway_portal_patch(dto: CfgWapGatewayPortalDto) -> Result<CfgWapGatewayPortal, ConfigError> {
    let prefix = dto.path_prefix.trim().to_owned();
    if prefix.is_empty() {
        return Err(ConfigError {
            field: "wap_gateway.portal.path_prefix",
            message: "must be non-empty".to_owned(),
        });
    }
    if !prefix.starts_with('/') {
        return Err(ConfigError {
            field: "wap_gateway.portal.path_prefix",
            message: format!("must start with '/', got {:?}", prefix),
        });
    }

    let icao = dto.metar_icao.trim().to_ascii_uppercase();
    if !icao.is_empty() && !icao.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err(ConfigError {
            field: "wap_gateway.portal.metar_icao",
            message: format!("must be ASCII alphanumeric, got {:?}", dto.metar_icao),
        });
    }

    if dto.metar_refresh_seconds == 0 {
        return Err(ConfigError {
            field: "wap_gateway.portal.metar_refresh_seconds",
            message: "must be non-zero".to_owned(),
        });
    }

    if dto.radios_max == 0 {
        return Err(ConfigError {
            field: "wap_gateway.portal.radios_max",
            message: "must be non-zero".to_owned(),
        });
    }

    Ok(CfgWapGatewayPortal {
        enabled: dto.enabled,
        path_prefix: prefix,
        metar_icao: icao,
        metar_refresh_seconds: dto.metar_refresh_seconds,
        radios_max: dto.radios_max,
    })
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const TUN: Ipv4Addr = Ipv4Addr::new(10, 222, 0, 1);

    #[test]
    fn defaults_disabled() {
        let cfg = apply_wap_gateway_patch(CfgWapGatewayDto::default(), TUN).unwrap();
        assert!(!cfg.enabled);
        assert_eq!(cfg.listen_addr, TUN);
        assert_eq!(cfg.listen_port, DEFAULT_WAP_LISTEN_PORT);
        assert_eq!(cfg.upstream_url, DEFAULT_WAP_UPSTREAM_URL);
        assert_eq!(cfg.log_level, DEFAULT_WAP_LOG_LEVEL);
    }

    #[test]
    fn listen_addr_defaults_to_tun_addr() {
        let dto = CfgWapGatewayDto {
            enabled: true,
            ..Default::default()
        };
        let cfg = apply_wap_gateway_patch(dto, TUN).unwrap();
        assert_eq!(cfg.listen_addr, TUN);
        assert!(cfg.enabled);
    }

    #[test]
    fn listen_addr_override_wins() {
        let dto = CfgWapGatewayDto {
            enabled: true,
            listen_addr: Some(Ipv4Addr::LOCALHOST),
            ..Default::default()
        };
        let cfg = apply_wap_gateway_patch(dto, TUN).unwrap();
        assert_eq!(cfg.listen_addr, Ipv4Addr::LOCALHOST);
    }

    #[test]
    fn zero_listen_port_rejected() {
        let dto = CfgWapGatewayDto {
            listen_port: 0,
            ..Default::default()
        };
        let err = apply_wap_gateway_patch(dto, TUN).unwrap_err();
        assert_eq!(err.field, "wap_gateway.listen_port");
    }

    #[test]
    fn empty_upstream_url_rejected() {
        let dto = CfgWapGatewayDto {
            upstream_url: "".into(),
            ..Default::default()
        };
        let err = apply_wap_gateway_patch(dto, TUN).unwrap_err();
        assert_eq!(err.field, "wap_gateway.upstream_url");
    }

    #[test]
    fn non_http_upstream_url_rejected() {
        let dto = CfgWapGatewayDto {
            upstream_url: "ftp://x".into(),
            ..Default::default()
        };
        let err = apply_wap_gateway_patch(dto, TUN).unwrap_err();
        assert_eq!(err.field, "wap_gateway.upstream_url");
    }

    #[test]
    fn https_upstream_url_accepted() {
        let dto = CfgWapGatewayDto {
            upstream_url: "https://backend.example/".into(),
            ..Default::default()
        };
        let cfg = apply_wap_gateway_patch(dto, TUN).unwrap();
        assert_eq!(cfg.upstream_url, "https://backend.example/");
    }

    #[test]
    fn full_toml_section_parses() {
        let toml_str = r#"
            enabled = true
            listen_port = 9201
            upstream_url = "http://127.0.0.1:8081"
            log_level = "debug"
        "#;
        let dto: CfgWapGatewayDto = toml::from_str(toml_str).unwrap();
        assert!(dto.extra.is_empty());
        let cfg = apply_wap_gateway_patch(dto, TUN).unwrap();
        assert!(cfg.enabled);
        assert_eq!(cfg.log_level, "debug");
        assert_eq!(cfg.listen_addr, TUN);
    }

    #[test]
    fn resolved_listen_addr_uses_explicit_when_set() {
        let mut cfg = CfgWapGateway::disabled(TUN);
        cfg.listen_addr = Ipv4Addr::new(127, 0, 0, 5);
        assert_eq!(cfg.resolved_listen_addr(TUN), Ipv4Addr::new(127, 0, 0, 5));
    }

    #[test]
    fn resolved_listen_addr_falls_back_to_tun_when_unspecified() {
        let mut cfg = CfgWapGateway::disabled(TUN);
        cfg.listen_addr = Ipv4Addr::UNSPECIFIED;
        assert_eq!(cfg.resolved_listen_addr(TUN), TUN);
    }

    #[test]
    fn unknown_field_captured_in_extra() {
        let toml_str = r#"
            enabled = true
            typo_field = 42
        "#;
        let dto: CfgWapGatewayDto = toml::from_str(toml_str).unwrap();
        assert!(dto.extra.contains_key("typo_field"));
    }

    #[test]
    fn portal_defaults_disabled() {
        let cfg = apply_wap_gateway_patch(CfgWapGatewayDto::default(), TUN).unwrap();
        assert!(!cfg.portal.enabled);
        assert_eq!(cfg.portal.path_prefix, DEFAULT_WAP_PORTAL_PATH_PREFIX);
        assert!(cfg.portal.metar_icao.is_empty());
        assert_eq!(cfg.portal.metar_refresh_seconds, DEFAULT_WAP_PORTAL_METAR_REFRESH_SECONDS);
        assert_eq!(cfg.portal.radios_max, DEFAULT_WAP_PORTAL_RADIOS_MAX);
    }

    #[test]
    fn portal_full_toml_parses() {
        let toml_str = r#"
            enabled = true
            upstream_url = "http://127.0.0.1:8081"
            [portal]
            enabled = true
            path_prefix = "/wap"
            metar_icao = "lrop"
            metar_refresh_seconds = 900
            radios_max = 3
        "#;
        let dto: CfgWapGatewayDto = toml::from_str(toml_str).unwrap();
        assert!(dto.extra.is_empty());
        let cfg = apply_wap_gateway_patch(dto, TUN).unwrap();
        assert!(cfg.portal.enabled);
        assert_eq!(cfg.portal.path_prefix, "/wap");
        assert_eq!(cfg.portal.metar_icao, "LROP"); // uppercased on validation
        assert_eq!(cfg.portal.metar_refresh_seconds, 900);
        assert_eq!(cfg.portal.radios_max, 3);
    }

    #[test]
    fn portal_path_prefix_must_start_with_slash() {
        let dto = CfgWapGatewayDto {
            portal: Some(CfgWapGatewayPortalDto {
                path_prefix: "portal".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let err = apply_wap_gateway_patch(dto, TUN).unwrap_err();
        assert_eq!(err.field, "wap_gateway.portal.path_prefix");
    }

    #[test]
    fn portal_empty_path_prefix_rejected() {
        let dto = CfgWapGatewayDto {
            portal: Some(CfgWapGatewayPortalDto {
                path_prefix: "   ".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let err = apply_wap_gateway_patch(dto, TUN).unwrap_err();
        assert_eq!(err.field, "wap_gateway.portal.path_prefix");
    }

    #[test]
    fn portal_metar_icao_must_be_alphanumeric() {
        let dto = CfgWapGatewayDto {
            portal: Some(CfgWapGatewayPortalDto {
                metar_icao: "LR-OP".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let err = apply_wap_gateway_patch(dto, TUN).unwrap_err();
        assert_eq!(err.field, "wap_gateway.portal.metar_icao");
    }

    #[test]
    fn portal_zero_refresh_rejected() {
        let dto = CfgWapGatewayDto {
            portal: Some(CfgWapGatewayPortalDto {
                metar_refresh_seconds: 0,
                ..Default::default()
            }),
            ..Default::default()
        };
        let err = apply_wap_gateway_patch(dto, TUN).unwrap_err();
        assert_eq!(err.field, "wap_gateway.portal.metar_refresh_seconds");
    }

    #[test]
    fn portal_zero_radios_max_rejected() {
        let dto = CfgWapGatewayDto {
            portal: Some(CfgWapGatewayPortalDto {
                radios_max: 0,
                ..Default::default()
            }),
            ..Default::default()
        };
        let err = apply_wap_gateway_patch(dto, TUN).unwrap_err();
        assert_eq!(err.field, "wap_gateway.portal.radios_max");
    }

    #[test]
    fn portal_unknown_field_captured_in_extra() {
        let toml_str = r#"
            [portal]
            enabled = true
            typo = 1
        "#;
        let dto: CfgWapGatewayDto = toml::from_str(toml_str).unwrap();
        let portal = dto.portal.expect("portal parsed");
        assert!(portal.extra.contains_key("typo"));
    }
}
