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

    /// Unknown-field detector — parsing.rs rejects any entry here.
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

impl Default for CfgWapGatewayDto {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            listen_addr: None,
            listen_port: default_listen_port(),
            upstream_url: default_upstream_url(),
            log_level: default_log_level(),
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

    Ok(CfgWapGateway {
        enabled: dto.enabled,
        listen_addr: dto.listen_addr.unwrap_or(packet_data_tun_addr),
        listen_port: dto.listen_port,
        upstream_url: dto.upstream_url,
        log_level: dto.log_level,
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
}
