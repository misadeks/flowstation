//! Packet-data runtime configuration — `[packet_data]` config block.
//!
//! Added by PD-7.  Controls the IPv4 pool, TUN interface, MTU, per-ISSI static
//! leases, SNDCP on-wire timer encoded values, and PDCH allocator knobs.
//!
//! All defaults reproduce the hardcoded values that PD-4 (SNDCP entity) and
//! PD-5 (UMAC PDCH allocator) used before this config block existed, so omitting
//! `[packet_data]` from a config file produces the same runtime behaviour as
//! an earlier FlowStation build.

use std::collections::HashSet;
use std::net::Ipv4Addr;

use serde::Deserialize;

// Re-export ConfigError from sec_llc so the whole config crate uses one type.
pub use super::sec_llc::ConfigError;

// ─── Compiled config structs ──────────────────────────────────────────────────

/// Packet-data cell configuration (compiled, no serde).
///
/// Built from the TOML `[packet_data]` section by [`validate_packet_data_config`].
/// Construct directly (via [`Default`]) in tests or when no config file is loaded.
#[derive(Debug, Clone)]
pub struct CfgPacketData {
    /// Enable packet data cell-wide.
    ///
    /// When `false` (default) the PDCH allocator and SNDCP state machine are
    /// dormant.  When `true` the BS actively serves packet-data MSes.
    pub enabled: bool,

    /// Network address of the dynamic IPv4 pool.
    ///
    /// Must be CIDR-aligned: `base & subnet_mask(prefix) == base`.
    /// Default: `192.168.100.0`.
    pub ipv4_pool_base: Ipv4Addr,

    /// CIDR prefix length for the IPv4 pool.  Valid range: 24..=30 (pool of
    /// 2..=254 host addresses before tun/lease exclusions).
    /// Default: 24.
    pub ipv4_pool_prefix: u8,

    /// TUN interface name consumed by the pd-gateway binary.
    /// Default: `"flowstation-pd0"`.
    pub tun_name: String,

    /// IPv4 address assigned to the TUN interface (gateway address on the
    /// pool subnet).  Must lie inside the pool subnet and is excluded from
    /// dynamic allocation.  Default: `192.168.100.1`.
    pub tun_addr: Ipv4Addr,

    /// IPv4 MTU (bytes) advertised in SN-ACTIVATE PDP CONTEXT ACCEPT.
    ///
    /// Must be one of the ETSI TS 100 392-2 table 28.79 encoded values:
    /// 256 | 512 | 1024 | 1280 | 1500 | 2048 | 4096.  Default: 1500.
    pub mtu: u16,

    /// Per-ISSI static IPv4 leases checked before dynamic allocation.
    pub static_lease: Vec<CfgStaticLease>,

    /// SNDCP on-wire timer encoded values.
    pub timers: CfgPacketDataTimers,

    /// PDCH allocator settings consumed by UMAC.
    pub pdch: CfgPacketDataPdch,
}

impl Default for CfgPacketData {
    fn default() -> Self {
        CfgPacketData {
            enabled: false,
            ipv4_pool_base: Ipv4Addr::new(192, 168, 100, 0),
            ipv4_pool_prefix: 24,
            tun_name: default_tun_name(),
            tun_addr: Ipv4Addr::new(192, 168, 100, 1),
            mtu: 1500,
            static_lease: Vec::new(),
            timers: CfgPacketDataTimers::default(),
            pdch: CfgPacketDataPdch::default(),
        }
    }
}

/// Per-ISSI static IPv4 lease (compiled).
#[derive(Debug, Clone)]
pub struct CfgStaticLease {
    /// ISSI of the subscriber.
    pub issi: u32,
    /// Static IPv4 address to assign.  Must be inside the pool subnet,
    /// must not equal `tun_addr`, and must not duplicate any other lease.
    pub ipv4: Ipv4Addr,
}

/// SNDCP on-wire timer encoded values.
///
/// The fields hold the 4-bit or 3-bit codes that appear verbatim in
/// SN-ACTIVATE PDP CONTEXT ACCEPT PDU fields, not actual durations.
/// See ETSI TS 100 392-2 v3.10.1 tables 28.112, 28.116, 28.122, 28.103.
#[derive(Debug, Clone)]
pub struct CfgPacketDataTimers {
    /// ReadyTimer encoded value (table 28.112, 4-bit, 0..=15).
    /// Default: 8 → 10 s.
    pub ready_timer: u8,
    /// StandbyTimer encoded value (table 28.122, 4-bit, 0..=15).
    /// Default: 5 → 10 min.
    pub standby_timer: u8,
    /// ResponseWaitTimer encoded value (table 28.116, 4-bit, 0..=15).
    /// Default: 8 → 10 s.
    pub resp_wait_timer: u8,
    /// PDU priority ceiling (table 28.103, 3-bit, 0..=7).
    /// Default: 4 (mid priority).
    pub pdu_priority_max: u8,
}

impl Default for CfgPacketDataTimers {
    fn default() -> Self {
        CfgPacketDataTimers {
            ready_timer: default_ready_timer(),
            standby_timer: default_standby_timer(),
            resp_wait_timer: default_resp_wait_timer(),
            pdu_priority_max: default_pdu_priority_max(),
        }
    }
}

/// PDCH allocator knobs consumed by UMAC.
#[derive(Debug, Clone)]
pub struct CfgPacketDataPdch {
    /// Release a PDCH assignment after this many idle MAC frames.
    /// Default: 300 (≈ 17 s at 56 ms/frame). Real hardware needs enough
    /// time for the browser to form and send an HTTP request after PDP
    /// context activation — 18 frames (~1 s) is too aggressive and
    /// causes MS to bounce SNDCP repeatedly. Valid range: 1..=1024.
    pub idle_release_frames: u32,
    /// Permit multi-slot PDCH.  V1 default: `false`.
    pub multi_slot: bool,
    /// Channel width code: 0 = 25 kHz (V1 default); 1 = 50 kHz TEDS;
    /// 2 = 100 kHz; 3 = 150 kHz.  Valid range: 0..=3.
    pub channel_width: u8,
    /// Maximum number of DL timeslots the PDCH pool may occupy per frame
    /// when `multi_slot = true`.  Ignored when `multi_slot = false`.
    /// Valid range: 1..=3 (TS2/TS3/TS4 are the eligible DL slots; TS1
    /// is always the control channel).  Default: 1.
    pub dl_max_slots_per_frame: u8,
    /// When `true` (default), an ISSI whose stored `multislot_phase_mod`
    /// (ETSI TS 100 392-2 §6.5 bit 22) is not `Some(true)` is capped to
    /// 1 slot per tick even while the global pool holds N slots.  Set to
    /// `false` only for lab testing with known-capable hardware.
    pub require_ms_capability: bool,
}

impl Default for CfgPacketDataPdch {
    fn default() -> Self {
        CfgPacketDataPdch {
            idle_release_frames: default_idle_release_frames(),
            multi_slot: false,
            channel_width: 0,
            dl_max_slots_per_frame: default_dl_max_slots_per_frame(),
            require_ms_capability: default_require_ms_capability(),
        }
    }
}

// ─── Serde DTOs ───────────────────────────────────────────────────────────────

/// Serde DTO for `[packet_data]`.
///
/// `deny_unknown_fields` is used instead of the flatten-HashMap pattern because
/// `[[packet_data.static_lease]]` (array-of-tables) conflicts with serde's
/// flatten field capture.  Unknown key errors are therefore emitted by serde
/// at deserialisation time rather than by a post-check in parsing.rs.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketDataDto {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default = "default_pool_base")]
    pub ipv4_pool_base: Ipv4Addr,
    #[serde(default = "default_pool_prefix")]
    pub ipv4_pool_prefix: u8,
    #[serde(default = "default_tun_name")]
    pub tun_name: String,
    #[serde(default = "default_tun_addr")]
    pub tun_addr: Ipv4Addr,
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    /// Per-ISSI static leases (`[[packet_data.static_lease]]` in TOML).
    #[serde(default)]
    pub static_lease: Vec<StaticLeaseDto>,
    #[serde(default)]
    pub timers: PacketDataTimersDto,
    #[serde(default)]
    pub pdch: PacketDataPdchDto,
}

impl Default for PacketDataDto {
    fn default() -> Self {
        PacketDataDto {
            enabled: default_enabled(),
            ipv4_pool_base: default_pool_base(),
            ipv4_pool_prefix: default_pool_prefix(),
            tun_name: default_tun_name(),
            tun_addr: default_tun_addr(),
            mtu: default_mtu(),
            static_lease: Vec::new(),
            timers: PacketDataTimersDto::default(),
            pdch: PacketDataPdchDto::default(),
        }
    }
}

/// Serde DTO for `[[packet_data.static_lease]]` entries.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaticLeaseDto {
    pub issi: u32,
    pub ipv4: Ipv4Addr,
}

/// Serde DTO for `[packet_data.timers]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketDataTimersDto {
    #[serde(default = "default_ready_timer")]
    pub ready_timer: u8,
    #[serde(default = "default_standby_timer")]
    pub standby_timer: u8,
    #[serde(default = "default_resp_wait_timer")]
    pub resp_wait_timer: u8,
    #[serde(default = "default_pdu_priority_max")]
    pub pdu_priority_max: u8,
}

impl Default for PacketDataTimersDto {
    fn default() -> Self {
        PacketDataTimersDto {
            ready_timer: default_ready_timer(),
            standby_timer: default_standby_timer(),
            resp_wait_timer: default_resp_wait_timer(),
            pdu_priority_max: default_pdu_priority_max(),
        }
    }
}

/// Serde DTO for `[packet_data.pdch]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketDataPdchDto {
    #[serde(default = "default_idle_release_frames")]
    pub idle_release_frames: u32,
    #[serde(default)]
    pub multi_slot: bool,
    #[serde(default = "default_channel_width")]
    pub channel_width: u8,
    #[serde(default = "default_dl_max_slots_per_frame")]
    pub dl_max_slots_per_frame: u8,
    #[serde(default = "default_require_ms_capability")]
    pub require_ms_capability: bool,
}

impl Default for PacketDataPdchDto {
    fn default() -> Self {
        PacketDataPdchDto {
            idle_release_frames: default_idle_release_frames(),
            multi_slot: false,
            channel_width: default_channel_width(),
            dl_max_slots_per_frame: default_dl_max_slots_per_frame(),
            require_ms_capability: default_require_ms_capability(),
        }
    }
}

// ─── Default value helpers ────────────────────────────────────────────────────

fn default_enabled() -> bool { false }
fn default_pool_base() -> Ipv4Addr { Ipv4Addr::new(192, 168, 100, 0) }
fn default_pool_prefix() -> u8 { 24 }
fn default_tun_name() -> String { "flowstation-pd0".to_owned() }
fn default_tun_addr() -> Ipv4Addr { Ipv4Addr::new(192, 168, 100, 1) }
fn default_mtu() -> u16 { 1500 }
fn default_ready_timer() -> u8 { 8 }
fn default_standby_timer() -> u8 { 5 }
fn default_resp_wait_timer() -> u8 { 8 }
fn default_pdu_priority_max() -> u8 { 4 }
fn default_idle_release_frames() -> u32 { 300 }
fn default_channel_width() -> u8 { 0 }
fn default_dl_max_slots_per_frame() -> u8 { 1 }
fn default_require_ms_capability() -> bool { true }

// ─── Public helpers ───────────────────────────────────────────────────────────

/// MTU byte values with a valid ETSI TS 100 392-2 table 28.79 encoding.
pub const VALID_MTU_VALUES: [u16; 7] = [256, 512, 1024, 1280, 1500, 2048, 4096];

/// Convert an MTU byte value to its ETSI table 28.79 encoded 3-bit code.
///
/// Returns `None` if `mtu` is not one of the valid table entries.
/// Always call after [`validate_packet_data_config`] to guarantee a `Some`.
pub fn mtu_to_code(mtu: u16) -> Option<u8> {
    VALID_MTU_VALUES.iter().position(|&v| v == mtu).map(|i| i as u8)
}

// ─── Validation & conversion ──────────────────────────────────────────────────

/// Validate a [`PacketDataDto`] against all spec ranges and convert it to the
/// compiled [`CfgPacketData`].
///
/// Returns [`ConfigError`] on the first failing field, with the full dotted
/// TOML path and a human-readable description of the constraint violated.
pub fn validate_packet_data_config(dto: PacketDataDto) -> Result<CfgPacketData, ConfigError> {
    // ── ipv4_pool_prefix ──────────────────────────────────────────────────────
    if dto.ipv4_pool_prefix < 24 || dto.ipv4_pool_prefix > 30 {
        return Err(ConfigError {
            field: "packet_data.ipv4_pool_prefix",
            message: format!(
                "must be 24..=30 (pool of 2..=254 addresses), got {}",
                dto.ipv4_pool_prefix
            ),
        });
    }

    // ── ipv4_pool_base alignment ──────────────────────────────────────────────
    // Mask for the prefix: all-ones in the top `prefix` bits.
    let mask: u32 = !((1u32 << (32 - dto.ipv4_pool_prefix)) - 1);
    let base_u32 = u32::from(dto.ipv4_pool_base);
    if base_u32 & mask != base_u32 {
        let aligned = Ipv4Addr::from(base_u32 & mask);
        return Err(ConfigError {
            field: "packet_data.ipv4_pool_base",
            message: format!(
                "must be network-aligned for prefix /{} (base & mask == base); \
                 got {}, nearest aligned address is {}",
                dto.ipv4_pool_prefix, dto.ipv4_pool_base, aligned
            ),
        });
    }
    let total: u32 = 1u32 << (32 - dto.ipv4_pool_prefix);
    let broadcast: u32 = base_u32 + total - 1;

    // ── tun_addr ──────────────────────────────────────────────────────────────
    let tun_u32 = u32::from(dto.tun_addr);
    if (tun_u32 & mask) != base_u32 {
        return Err(ConfigError {
            field: "packet_data.tun_addr",
            message: format!(
                "must lie inside pool subnet {}/{}, got {}",
                dto.ipv4_pool_base, dto.ipv4_pool_prefix, dto.tun_addr
            ),
        });
    }
    if tun_u32 == broadcast {
        return Err(ConfigError {
            field: "packet_data.tun_addr",
            message: format!(
                "must not be the broadcast address {} of the pool subnet",
                dto.tun_addr
            ),
        });
    }

    // ── mtu ───────────────────────────────────────────────────────────────────
    if !VALID_MTU_VALUES.contains(&dto.mtu) {
        return Err(ConfigError {
            field: "packet_data.mtu",
            message: format!(
                "must be one of {:?} (ETSI TS 100 392-2 table 28.79), got {}",
                VALID_MTU_VALUES, dto.mtu
            ),
        });
    }

    // ── static_lease ──────────────────────────────────────────────────────────
    let mut seen_issis: HashSet<u32> = HashSet::new();
    let mut seen_ips: HashSet<u32> = HashSet::new();
    seen_ips.insert(tun_u32); // tun_addr pre-blocks its slot

    for (idx, lease) in dto.static_lease.iter().enumerate() {
        let lease_u32 = u32::from(lease.ipv4);

        if (lease_u32 & mask) != base_u32 {
            return Err(ConfigError {
                field: "packet_data.static_lease[].ipv4",
                message: format!(
                    "static_lease[{idx}]: IP {} is outside pool subnet {}/{}",
                    lease.ipv4, dto.ipv4_pool_base, dto.ipv4_pool_prefix
                ),
            });
        }
        if !seen_ips.insert(lease_u32) {
            return Err(ConfigError {
                field: "packet_data.static_lease[].ipv4",
                message: format!(
                    "static_lease[{idx}]: IP {} collides with tun_addr or another static lease",
                    lease.ipv4
                ),
            });
        }
        if !seen_issis.insert(lease.issi) {
            return Err(ConfigError {
                field: "packet_data.static_lease[].issi",
                message: format!(
                    "static_lease[{idx}]: ISSI {} appears more than once in static_lease",
                    lease.issi
                ),
            });
        }
    }

    // ── timer encoded values ──────────────────────────────────────────────────
    if dto.timers.ready_timer > 15 {
        return Err(ConfigError {
            field: "packet_data.timers.ready_timer",
            message: format!(
                "must be 0..=15 (4-bit table 28.112 field), got {}",
                dto.timers.ready_timer
            ),
        });
    }
    if dto.timers.standby_timer > 15 {
        return Err(ConfigError {
            field: "packet_data.timers.standby_timer",
            message: format!(
                "must be 0..=15 (4-bit table 28.122 field), got {}",
                dto.timers.standby_timer
            ),
        });
    }
    if dto.timers.resp_wait_timer > 15 {
        return Err(ConfigError {
            field: "packet_data.timers.resp_wait_timer",
            message: format!(
                "must be 0..=15 (4-bit table 28.116 field), got {}",
                dto.timers.resp_wait_timer
            ),
        });
    }
    if dto.timers.pdu_priority_max > 7 {
        return Err(ConfigError {
            field: "packet_data.timers.pdu_priority_max",
            message: format!(
                "must be 0..=7 (3-bit table 28.103 field), got {}",
                dto.timers.pdu_priority_max
            ),
        });
    }

    // ── PDCH knobs ────────────────────────────────────────────────────────────
    if dto.pdch.idle_release_frames == 0 || dto.pdch.idle_release_frames > 1024 {
        return Err(ConfigError {
            field: "packet_data.pdch.idle_release_frames",
            message: format!(
                "must be 1..=1024, got {}",
                dto.pdch.idle_release_frames
            ),
        });
    }
    if dto.pdch.channel_width > 3 {
        return Err(ConfigError {
            field: "packet_data.pdch.channel_width",
            message: format!(
                "must be 0..=3 (0=25 kHz, 1=50 kHz TEDS, 2=100 kHz, 3=150 kHz), got {}",
                dto.pdch.channel_width
            ),
        });
    }
    if dto.pdch.dl_max_slots_per_frame < 1 || dto.pdch.dl_max_slots_per_frame > 3 {
        return Err(ConfigError {
            field: "packet_data.pdch.dl_max_slots_per_frame",
            message: format!(
                "must be 1..=3 (eligible DL timeslots TS2/TS3/TS4), got {}",
                dto.pdch.dl_max_slots_per_frame
            ),
        });
    }

    Ok(CfgPacketData {
        enabled: dto.enabled,
        ipv4_pool_base: dto.ipv4_pool_base,
        ipv4_pool_prefix: dto.ipv4_pool_prefix,
        tun_name: dto.tun_name,
        tun_addr: dto.tun_addr,
        mtu: dto.mtu,
        static_lease: dto
            .static_lease
            .into_iter()
            .map(|l| CfgStaticLease { issi: l.issi, ipv4: l.ipv4 })
            .collect(),
        timers: CfgPacketDataTimers {
            ready_timer: dto.timers.ready_timer,
            standby_timer: dto.timers.standby_timer,
            resp_wait_timer: dto.timers.resp_wait_timer,
            pdu_priority_max: dto.timers.pdu_priority_max,
        },
        pdch: CfgPacketDataPdch {
            idle_release_frames: dto.pdch.idle_release_frames,
            multi_slot: dto.pdch.multi_slot,
            channel_width: dto.pdch.channel_width,
            dl_max_slots_per_frame: dto.pdch.dl_max_slots_per_frame,
            require_ms_capability: dto.pdch.require_ms_capability,
        },
    })
}

/// Apply the optional `[packet_data]` patch: validate and convert the DTO when
/// present, or return [`CfgPacketData::default()`] when the section is absent.
pub fn apply_packet_data_patch(dto: Option<PacketDataDto>) -> Result<CfgPacketData, ConfigError> {
    match dto {
        Some(d) => validate_packet_data_config(d),
        None => Ok(CfgPacketData::default()),
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn defaults() -> PacketDataDto {
        PacketDataDto::default()
    }

    // ── Happy-path ────────────────────────────────────────────────────────────

    #[test]
    fn valid_defaults_accepted() {
        let cfg = validate_packet_data_config(defaults()).expect("defaults must be valid");
        assert!(!cfg.enabled);
        assert_eq!(cfg.ipv4_pool_base, Ipv4Addr::new(192, 168, 100, 0));
        assert_eq!(cfg.ipv4_pool_prefix, 24);
        assert_eq!(cfg.tun_addr, Ipv4Addr::new(192, 168, 100, 1));
        assert_eq!(cfg.mtu, 1500);
        assert!(cfg.static_lease.is_empty());
        assert_eq!(cfg.timers.ready_timer, 8);
        assert_eq!(cfg.timers.standby_timer, 5);
        assert_eq!(cfg.timers.resp_wait_timer, 8);
        assert_eq!(cfg.timers.pdu_priority_max, 4);
        assert_eq!(cfg.pdch.idle_release_frames, 300);
        assert!(!cfg.pdch.multi_slot);
        assert_eq!(cfg.pdch.channel_width, 0);
    }

    #[test]
    fn apply_patch_absent_section_yields_defaults() {
        let cfg = apply_packet_data_patch(None).expect("None must yield defaults");
        assert_eq!(cfg.ipv4_pool_prefix, 24);
        assert_eq!(cfg.tun_addr, Ipv4Addr::new(192, 168, 100, 1));
        assert!(!cfg.enabled);
    }

    #[test]
    fn full_toml_section_parses_and_validates() {
        let toml_str = r#"
            enabled = true
            ipv4_pool_base = "10.10.0.0"
            ipv4_pool_prefix = 24
            tun_name = "pd0"
            tun_addr = "10.10.0.1"
            mtu = 1500

            [[static_lease]]
            issi = 1234
            ipv4 = "10.10.0.10"

            [timers]
            ready_timer = 5
            standby_timer = 3
            resp_wait_timer = 4
            pdu_priority_max = 2

            [pdch]
            idle_release_frames = 36
            multi_slot = false
            channel_width = 0
        "#;
        let dto: PacketDataDto = toml::from_str(toml_str).expect("TOML must parse");
        let cfg = validate_packet_data_config(dto).expect("must validate");
        assert!(cfg.enabled);
        assert_eq!(cfg.ipv4_pool_base, Ipv4Addr::new(10, 10, 0, 0));
        assert_eq!(cfg.tun_addr, Ipv4Addr::new(10, 10, 0, 1));
        assert_eq!(cfg.static_lease.len(), 1);
        assert_eq!(cfg.static_lease[0].issi, 1234);
        assert_eq!(cfg.static_lease[0].ipv4, Ipv4Addr::new(10, 10, 0, 10));
        assert_eq!(cfg.timers.ready_timer, 5);
        assert_eq!(cfg.pdch.idle_release_frames, 36);
    }

    // ── mtu_to_code ───────────────────────────────────────────────────────────

    #[test]
    fn mtu_to_code_1500_is_4() {
        assert_eq!(mtu_to_code(1500), Some(4));
    }

    #[test]
    fn mtu_to_code_invalid_returns_none() {
        assert_eq!(mtu_to_code(1499), None);
        assert_eq!(mtu_to_code(0), None);
    }

    // ── ipv4_pool_prefix ──────────────────────────────────────────────────────

    #[test]
    fn pool_prefix_23_rejected() {
        let dto = PacketDataDto { ipv4_pool_prefix: 23, ..defaults() };
        let err = validate_packet_data_config(dto).unwrap_err();
        assert_eq!(err.field, "packet_data.ipv4_pool_prefix");
    }

    #[test]
    fn pool_prefix_31_rejected() {
        let dto = PacketDataDto { ipv4_pool_prefix: 31, ..defaults() };
        let err = validate_packet_data_config(dto).unwrap_err();
        assert_eq!(err.field, "packet_data.ipv4_pool_prefix");
    }

    #[test]
    fn pool_prefix_30_accepted() {
        // /30 is the tightest valid prefix (2 host addresses).
        let dto = PacketDataDto {
            ipv4_pool_base: Ipv4Addr::new(10, 0, 0, 0),
            ipv4_pool_prefix: 30,
            tun_addr: Ipv4Addr::new(10, 0, 0, 1),
            ..defaults()
        };
        assert!(validate_packet_data_config(dto).is_ok());
    }

    // ── ipv4_pool_base alignment ──────────────────────────────────────────────

    #[test]
    fn pool_base_misaligned_rejected() {
        // 192.168.100.1 is not /24-aligned (network address is .0).
        let dto = PacketDataDto {
            ipv4_pool_base: Ipv4Addr::new(192, 168, 100, 1),
            ipv4_pool_prefix: 24,
            ..defaults()
        };
        let err = validate_packet_data_config(dto).unwrap_err();
        assert_eq!(err.field, "packet_data.ipv4_pool_base");
    }

    // ── tun_addr ──────────────────────────────────────────────────────────────

    #[test]
    fn tun_addr_outside_pool_rejected() {
        let dto = PacketDataDto {
            tun_addr: Ipv4Addr::new(10, 0, 0, 1), // different network
            ..defaults()
        };
        let err = validate_packet_data_config(dto).unwrap_err();
        assert_eq!(err.field, "packet_data.tun_addr");
    }

    #[test]
    fn tun_addr_at_broadcast_rejected() {
        // 192.168.100.255 is the broadcast address of a /24.
        let dto = PacketDataDto {
            tun_addr: Ipv4Addr::new(192, 168, 100, 255),
            ..defaults()
        };
        let err = validate_packet_data_config(dto).unwrap_err();
        assert_eq!(err.field, "packet_data.tun_addr");
    }

    // ── mtu ───────────────────────────────────────────────────────────────────

    #[test]
    fn invalid_mtu_rejected() {
        let dto = PacketDataDto { mtu: 1234, ..defaults() };
        let err = validate_packet_data_config(dto).unwrap_err();
        assert_eq!(err.field, "packet_data.mtu");
        // Error message should mention the valid values.
        assert!(err.message.contains("table 28.79"), "expected table reference in: {}", err.message);
    }

    // ── static_lease ──────────────────────────────────────────────────────────

    #[test]
    fn static_lease_outside_pool_rejected() {
        let dto = PacketDataDto {
            static_lease: vec![StaticLeaseDto {
                issi: 999,
                ipv4: Ipv4Addr::new(10, 0, 0, 5), // outside 192.168.100.0/24
            }],
            ..defaults()
        };
        let err = validate_packet_data_config(dto).unwrap_err();
        assert_eq!(err.field, "packet_data.static_lease[].ipv4");
    }

    #[test]
    fn static_lease_duplicates_tun_addr_rejected() {
        let dto = PacketDataDto {
            tun_addr: Ipv4Addr::new(192, 168, 100, 1),
            static_lease: vec![StaticLeaseDto {
                issi: 111,
                ipv4: Ipv4Addr::new(192, 168, 100, 1), // same as tun_addr
            }],
            ..defaults()
        };
        let err = validate_packet_data_config(dto).unwrap_err();
        assert_eq!(err.field, "packet_data.static_lease[].ipv4");
    }

    #[test]
    fn static_leases_duplicate_ip_rejected() {
        let dto = PacketDataDto {
            static_lease: vec![
                StaticLeaseDto { issi: 1, ipv4: Ipv4Addr::new(192, 168, 100, 10) },
                StaticLeaseDto { issi: 2, ipv4: Ipv4Addr::new(192, 168, 100, 10) }, // duplicate IP
            ],
            ..defaults()
        };
        let err = validate_packet_data_config(dto).unwrap_err();
        assert_eq!(err.field, "packet_data.static_lease[].ipv4");
    }

    #[test]
    fn static_leases_duplicate_issi_rejected() {
        let dto = PacketDataDto {
            static_lease: vec![
                StaticLeaseDto { issi: 42, ipv4: Ipv4Addr::new(192, 168, 100, 10) },
                StaticLeaseDto { issi: 42, ipv4: Ipv4Addr::new(192, 168, 100, 11) }, // duplicate ISSI
            ],
            ..defaults()
        };
        let err = validate_packet_data_config(dto).unwrap_err();
        assert_eq!(err.field, "packet_data.static_lease[].issi");
    }

    // ── timer fields ──────────────────────────────────────────────────────────

    #[test]
    fn invalid_ready_timer_rejected() {
        let mut dto = defaults();
        dto.timers.ready_timer = 16; // exceeds 0..=15
        let err = validate_packet_data_config(dto).unwrap_err();
        assert_eq!(err.field, "packet_data.timers.ready_timer");
    }

    #[test]
    fn invalid_standby_timer_rejected() {
        let mut dto = defaults();
        dto.timers.standby_timer = 16;
        let err = validate_packet_data_config(dto).unwrap_err();
        assert_eq!(err.field, "packet_data.timers.standby_timer");
    }

    #[test]
    fn invalid_resp_wait_timer_rejected() {
        let mut dto = defaults();
        dto.timers.resp_wait_timer = 16;
        let err = validate_packet_data_config(dto).unwrap_err();
        assert_eq!(err.field, "packet_data.timers.resp_wait_timer");
    }

    #[test]
    fn invalid_pdu_priority_max_rejected() {
        let mut dto = defaults();
        dto.timers.pdu_priority_max = 8; // exceeds 0..=7
        let err = validate_packet_data_config(dto).unwrap_err();
        assert_eq!(err.field, "packet_data.timers.pdu_priority_max");
    }

    // ── PDCH knobs ────────────────────────────────────────────────────────────

    #[test]
    fn invalid_idle_release_frames_zero_rejected() {
        let mut dto = defaults();
        dto.pdch.idle_release_frames = 0;
        let err = validate_packet_data_config(dto).unwrap_err();
        assert_eq!(err.field, "packet_data.pdch.idle_release_frames");
    }

    #[test]
    fn invalid_idle_release_frames_over_max_rejected() {
        let mut dto = defaults();
        dto.pdch.idle_release_frames = 1025;
        let err = validate_packet_data_config(dto).unwrap_err();
        assert_eq!(err.field, "packet_data.pdch.idle_release_frames");
    }

    #[test]
    fn invalid_channel_width_rejected() {
        let mut dto = defaults();
        dto.pdch.channel_width = 4; // exceeds 0..=3
        let err = validate_packet_data_config(dto).unwrap_err();
        assert_eq!(err.field, "packet_data.pdch.channel_width");
    }

    // ── error display ─────────────────────────────────────────────────────────

    #[test]
    fn error_display_contains_field_path() {
        let mut dto = defaults();
        dto.pdch.channel_width = 4;
        let err = validate_packet_data_config(dto).unwrap_err();
        let s = err.to_string();
        assert!(s.contains("packet_data.pdch.channel_width"), "error display should contain field path: {s}");
    }

    // ── PD-5c-H52: dl_max_slots_per_frame / require_ms_capability ─────────────

    #[test]
    fn pdch_h52_defaults_accepted() {
        let cfg = validate_packet_data_config(defaults()).expect("defaults must be valid");
        assert_eq!(cfg.pdch.dl_max_slots_per_frame, 1);
        assert!(cfg.pdch.require_ms_capability);
    }

    #[test]
    fn pdch_h52_roundtrip_via_toml() {
        let toml_str = r#"
            idle_release_frames = 100
            multi_slot = true
            channel_width = 0
            dl_max_slots_per_frame = 2
            require_ms_capability = false
        "#;
        let dto: PacketDataPdchDto = toml::from_str(toml_str).expect("TOML must parse");
        assert_eq!(dto.dl_max_slots_per_frame, 2);
        assert!(!dto.require_ms_capability);
        // Wrap into PacketDataDto to drive the full validator.
        let full = PacketDataDto { pdch: dto, ..defaults() };
        let cfg = validate_packet_data_config(full).expect("must validate");
        assert_eq!(cfg.pdch.dl_max_slots_per_frame, 2);
        assert!(!cfg.pdch.require_ms_capability);
        assert!(cfg.pdch.multi_slot);
    }

    #[test]
    fn pdch_h52_dl_max_slots_zero_rejected() {
        let mut dto = defaults();
        dto.pdch.dl_max_slots_per_frame = 0;
        let err = validate_packet_data_config(dto).unwrap_err();
        assert_eq!(err.field, "packet_data.pdch.dl_max_slots_per_frame");
        assert!(err.message.contains("1..=3"), "expected range in: {}", err.message);
    }

    #[test]
    fn pdch_h52_dl_max_slots_four_rejected() {
        let mut dto = defaults();
        dto.pdch.dl_max_slots_per_frame = 4;
        let err = validate_packet_data_config(dto).unwrap_err();
        assert_eq!(err.field, "packet_data.pdch.dl_max_slots_per_frame");
    }

    #[test]
    fn pdch_h52_dl_max_slots_three_accepted() {
        let mut dto = defaults();
        dto.pdch.dl_max_slots_per_frame = 3;
        assert!(validate_packet_data_config(dto).is_ok());
    }
}
