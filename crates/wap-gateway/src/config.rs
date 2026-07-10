//! Configuration loading for the `wap-gateway` binary.
//!
//! The gateway has its own tiny TOML config file that points at the main
//! FlowStation configuration to resolve the `tun_addr` on which UDP port 9201
//! should be bound. The TOML shape:
//!
//! ```toml
//! flowstation_config = "/home/pi/flowstation-config.toml"
//! listen_port = 9201
//! upstream_url = "http://127.0.0.1:8081"
//! log_level = "info"
//! # Optional explicit override; when set, skips reading flowstation_config.
//! # listen_addr = "10.222.0.1"
//! ```
//!
//! ## `sndcp.tun_addr` resolution
//!
//! The design note references `sndcp.tun_addr`. In the actual FlowStation
//! configuration schema the field lives at `packet_data.tun_addr` (see
//! `crates/tetra-config`). We accept either section name for
//! forward-compatibility: `packet_data.tun_addr` takes precedence, then
//! `sndcp.tun_addr`. The literal string `sndcp.tun_addr` from the design note
//! is treated as an alias for the same field.

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::error::{WapError, WapResult};

/// Default UDP port used by WSP-CO (WAP over connection-oriented WTP).
pub const DEFAULT_LISTEN_PORT: u16 = 9201;

/// Default upstream HTTP backend.
pub const DEFAULT_UPSTREAM_URL: &str = "http://127.0.0.1:8081";

/// Default log level (`tracing_subscriber` env-filter compatible).
pub const DEFAULT_LOG_LEVEL: &str = "info";

// ── Wire-level TOML DTOs ──────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GatewayConfigDto {
    #[serde(default)]
    flowstation_config: Option<PathBuf>,

    #[serde(default = "default_listen_port")]
    listen_port: u16,

    /// If set, skips reading `flowstation_config` and uses this address directly.
    #[serde(default)]
    listen_addr: Option<Ipv4Addr>,

    #[serde(default = "default_upstream_url")]
    upstream_url: String,

    #[serde(default = "default_log_level")]
    log_level: String,
}

fn default_listen_port() -> u16 {
    DEFAULT_LISTEN_PORT
}
fn default_upstream_url() -> String {
    DEFAULT_UPSTREAM_URL.to_owned()
}
fn default_log_level() -> String {
    DEFAULT_LOG_LEVEL.to_owned()
}

#[derive(Debug, Deserialize)]
struct FlowstationConfigDto {
    #[serde(default)]
    packet_data: Option<PacketDataSubsetDto>,
    /// Alias for `packet_data`, matching the design note wording.
    #[serde(default)]
    sndcp: Option<PacketDataSubsetDto>,
}

#[derive(Debug, Deserialize)]
struct PacketDataSubsetDto {
    tun_addr: Option<Ipv4Addr>,
}

// ── Resolved configuration ────────────────────────────────────────────────────

/// Fully resolved gateway configuration ready for runtime consumption.
#[derive(Debug, Clone)]
pub struct GatewayConfig {
    /// IPv4 address the UDP socket binds to.
    pub listen_addr: Ipv4Addr,
    /// UDP port the gateway listens on (WSP-CO default: 9201).
    pub listen_port: u16,
    /// Upstream HTTP backend base URL (no trailing slash preserved verbatim).
    pub upstream_url: String,
    /// `tracing_subscriber::EnvFilter` compatible directive.
    pub log_level: String,
}

impl GatewayConfig {
    /// Load and resolve a config from a TOML file path.
    pub fn from_path(path: &Path) -> WapResult<Self> {
        let raw = std::fs::read_to_string(path).map_err(|e| WapError::Config(format!("reading gateway config {}: {e}", path.display())))?;
        Self::from_toml_str(&raw)
    }

    /// Parse from a TOML string (test-friendly).
    pub fn from_toml_str(raw: &str) -> WapResult<Self> {
        let dto: GatewayConfigDto = toml::from_str(raw)?;
        Self::from_dto(dto)
    }

    fn from_dto(dto: GatewayConfigDto) -> WapResult<Self> {
        // Resolve the listen address.
        let listen_addr = if let Some(addr) = dto.listen_addr {
            addr
        } else if let Some(ref fs_path) = dto.flowstation_config {
            resolve_tun_addr_from_flowstation(fs_path)?
        } else {
            return Err(WapError::Config(
                "must set either `listen_addr` or `flowstation_config` in \
                 wap-gateway-config.toml"
                    .into(),
            ));
        };

        Ok(Self {
            listen_addr,
            listen_port: dto.listen_port,
            upstream_url: dto.upstream_url,
            log_level: dto.log_level,
        })
    }
}

/// Read `packet_data.tun_addr` (or the `sndcp.tun_addr` alias) from a
/// FlowStation config file.
fn resolve_tun_addr_from_flowstation(path: &Path) -> WapResult<Ipv4Addr> {
    let raw = std::fs::read_to_string(path).map_err(|e| WapError::Config(format!("reading flowstation config {}: {e}", path.display())))?;

    // Deliberately lenient — we only care about one field and want to survive
    // unrelated schema drift in the rest of the file.
    let parsed: FlowstationConfigDto =
        toml::from_str(&raw).map_err(|e| WapError::Config(format!("parsing flowstation config {}: {e}", path.display())))?;

    let tun_addr = parsed
        .packet_data
        .as_ref()
        .and_then(|pd| pd.tun_addr)
        .or_else(|| parsed.sndcp.as_ref().and_then(|s| s.tun_addr))
        .ok_or_else(|| {
            WapError::Config(format!(
                "neither `packet_data.tun_addr` nor `sndcp.tun_addr` set in {}",
                path.display()
            ))
        })?;

    Ok(tun_addr)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_explicit_listen_addr() {
        let toml = r#"
            listen_addr = "10.222.0.1"
            listen_port = 9201
            upstream_url = "http://127.0.0.1:8081"
            log_level = "debug"
        "#;
        let cfg = GatewayConfig::from_toml_str(toml).unwrap();
        assert_eq!(cfg.listen_addr, Ipv4Addr::new(10, 222, 0, 1));
        assert_eq!(cfg.listen_port, 9201);
        assert_eq!(cfg.upstream_url, "http://127.0.0.1:8081");
        assert_eq!(cfg.log_level, "debug");
    }

    #[test]
    fn defaults_fill_in() {
        let toml = r#"listen_addr = "127.0.0.1""#;
        let cfg = GatewayConfig::from_toml_str(toml).unwrap();
        assert_eq!(cfg.listen_port, DEFAULT_LISTEN_PORT);
        assert_eq!(cfg.upstream_url, DEFAULT_UPSTREAM_URL);
        assert_eq!(cfg.log_level, DEFAULT_LOG_LEVEL);
    }

    #[test]
    fn missing_addr_and_flowstation_errors() {
        let toml = r#"listen_port = 9201"#;
        let err = GatewayConfig::from_toml_str(toml).unwrap_err();
        assert!(matches!(err, WapError::Config(_)));
    }

    #[test]
    fn resolves_from_flowstation_packet_data() {
        let dir = tempdir();
        let fs_path = dir.join("flowstation.toml");
        std::fs::write(&fs_path, "[packet_data]\ntun_addr = \"10.222.0.1\"\n").unwrap();

        let toml = format!("flowstation_config = \"{}\"\n", fs_path.display().to_string().replace('\\', "/"));
        let cfg = GatewayConfig::from_toml_str(&toml).unwrap();
        assert_eq!(cfg.listen_addr, Ipv4Addr::new(10, 222, 0, 1));
    }

    #[test]
    fn resolves_from_flowstation_sndcp_alias() {
        let dir = tempdir();
        let fs_path = dir.join("flowstation.toml");
        std::fs::write(&fs_path, "[sndcp]\ntun_addr = \"10.10.0.1\"\n").unwrap();

        let toml = format!("flowstation_config = \"{}\"\n", fs_path.display().to_string().replace('\\', "/"));
        let cfg = GatewayConfig::from_toml_str(&toml).unwrap();
        assert_eq!(cfg.listen_addr, Ipv4Addr::new(10, 10, 0, 1));
    }

    #[test]
    fn explicit_listen_addr_takes_precedence_over_flowstation() {
        let dir = tempdir();
        let fs_path = dir.join("flowstation.toml");
        std::fs::write(&fs_path, "[packet_data]\ntun_addr = \"10.222.0.1\"\n").unwrap();

        let toml = format!(
            "flowstation_config = \"{}\"\nlisten_addr = \"127.0.0.1\"\n",
            fs_path.display().to_string().replace('\\', "/")
        );
        let cfg = GatewayConfig::from_toml_str(&toml).unwrap();
        assert_eq!(cfg.listen_addr, Ipv4Addr::LOCALHOST);
    }

    /// Cross-platform tempdir helper for tests only.
    fn tempdir() -> PathBuf {
        let mut p = std::env::temp_dir();
        let unique = format!(
            "wap-gateway-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        p.push(unique);
        std::fs::create_dir_all(&p).unwrap();
        p
    }
}
