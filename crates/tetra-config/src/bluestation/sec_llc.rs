use serde::Deserialize;
use std::collections::HashMap;
use toml::Value;

/// Validation error for LLC/AL configuration fields.
///
/// Returned by [`validate_advanced_link_config`] when a field is out of its
/// spec-defined range.  Implements [`std::error::Error`] so it propagates
/// cleanly through the `Box<dyn Error>` surface used by the config loader.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError {
    /// Dotted TOML path that failed (e.g. `"llc.advanced_link.tx_window"`).
    pub field: &'static str,
    /// Human-readable description of the constraint that was violated.
    pub message: String,
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.field, self.message)
    }
}

impl std::error::Error for ConfigError {}

// ─── Compiled config ──────────────────────────────────────────────────────────

/// Advanced Link (AL) LLC state machine runtime configuration.
///
/// ETSI TS 100 392-2 v3.10.1 annex A.2 LLC constants (N.262 – N.274).
/// All defaults are identical to the values that AL-3 (`llc_bs_ms.rs`) had
/// hardcoded, so omitting `[llc.advanced_link]` from the config file produces
/// exactly the same behaviour as before AL-5.
#[derive(Debug, Clone)]
pub struct CfgAdvancedLink {
    /// Number of octets available for the `tl_sdu_segment` payload inside each
    /// AL-DATA / AL-FINAL PDU (excludes LLC header and FCS).
    /// Corresponds to AL-3's `al_segment_payload_bits = 400 / 8 = 50`.
    pub segment_payload_octets: u16,

    /// TX window size (N.272).  Original AL: 1..=3.
    /// NOTE: spec ambiguous — chosen behaviour: cap at 3 for original AL;
    /// extended AL widens to 15 but flowstation V1 only implements original AL.
    pub tx_window: u8,

    /// Maximum TL-SDU retransmissions (N.273).  3-bit spec field (0..=7).
    pub max_sdu_retx: u8,

    /// Maximum per-segment retransmissions (N.274).  4-bit spec field (0..=15).
    pub max_segment_retx: u8,

    /// Maximum AL-SETUP retries (N.262).  Spec range 1..=5.
    pub max_setup_retries: u8,

    /// Maximum AL-DISC retries (N.263).  Spec range 3..=5.
    pub max_disc_retries: u8,

    /// Maximum AL-RECONNECT retries (N.265).  Spec range 0..=5.
    pub max_reconnect_retries: u8,

    /// Maximum TL-SDU length (N.271) in octets.  Must be a spec-valid
    /// power-of-two: 32 | 64 | 128 | 256 | 512 | 1024 | 2048 | 4096.
    pub max_tl_sdu_octets: u16,
}

impl Default for CfgAdvancedLink {
    fn default() -> Self {
        CfgAdvancedLink {
            segment_payload_octets: 50,  // = 400 bits / 8 — AL-3 default
            tx_window: 3,
            max_sdu_retx: 3,
            max_segment_retx: 3,
            max_setup_retries: 3,
            max_disc_retries: 3,
            max_reconnect_retries: 3,
            max_tl_sdu_octets: 4096,
        }
    }
}

/// Top-level LLC config (currently only carries `advanced_link`; reserved for
/// future basic-link knobs).
#[derive(Debug, Clone, Default)]
pub struct CfgLlc {
    pub advanced_link: CfgAdvancedLink,
}

// ─── Serde DTOs ───────────────────────────────────────────────────────────────

/// Serde DTO for `[llc.advanced_link]`.
#[derive(Debug, Clone, Deserialize)]
pub struct AdvancedLinkDto {
    #[serde(default = "default_segment_payload_octets")]
    pub segment_payload_octets: u16,
    #[serde(default = "default_tx_window")]
    pub tx_window: u8,
    #[serde(default = "default_max_sdu_retx")]
    pub max_sdu_retx: u8,
    #[serde(default = "default_max_segment_retx")]
    pub max_segment_retx: u8,
    #[serde(default = "default_max_setup_retries")]
    pub max_setup_retries: u8,
    #[serde(default = "default_max_disc_retries")]
    pub max_disc_retries: u8,
    #[serde(default = "default_max_reconnect_retries")]
    pub max_reconnect_retries: u8,
    #[serde(default = "default_max_tl_sdu_octets")]
    pub max_tl_sdu_octets: u16,

    /// Unknown-field detector — parsing.rs rejects any entry present here.
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

impl Default for AdvancedLinkDto {
    fn default() -> Self {
        AdvancedLinkDto {
            segment_payload_octets: default_segment_payload_octets(),
            tx_window: default_tx_window(),
            max_sdu_retx: default_max_sdu_retx(),
            max_segment_retx: default_max_segment_retx(),
            max_setup_retries: default_max_setup_retries(),
            max_disc_retries: default_max_disc_retries(),
            max_reconnect_retries: default_max_reconnect_retries(),
            max_tl_sdu_octets: default_max_tl_sdu_octets(),
            extra: HashMap::new(),
        }
    }
}

fn default_segment_payload_octets() -> u16 { 50 }
fn default_tx_window() -> u8 { 3 }
fn default_max_sdu_retx() -> u8 { 3 }
fn default_max_segment_retx() -> u8 { 3 }
fn default_max_setup_retries() -> u8 { 3 }
fn default_max_disc_retries() -> u8 { 3 }
fn default_max_reconnect_retries() -> u8 { 3 }
fn default_max_tl_sdu_octets() -> u16 { 4096 }

/// Serde DTO for `[llc]`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct CfgLlcDto {
    /// Advanced-link sub-section.  When absent, all AL fields default to
    /// their AL-3 hardcoded values.
    #[serde(default)]
    pub advanced_link: Option<AdvancedLinkDto>,

    /// Unknown-field detector — parsing.rs rejects any entry present here.
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

// ─── Validation & conversion ─────────────────────────────────────────────────

/// Validate an `AdvancedLinkDto` against spec ranges and convert it to the
/// compiled [`CfgAdvancedLink`].
///
/// Returns [`ConfigError`] on the first failing field, with the full dotted
/// TOML path and a human-readable bound description.
pub fn validate_advanced_link_config(dto: AdvancedLinkDto) -> Result<CfgAdvancedLink, ConfigError> {
    if dto.segment_payload_octets < 1 || dto.segment_payload_octets > 512 {
        return Err(ConfigError {
            field: "llc.advanced_link.segment_payload_octets",
            message: format!(
                "must be 1..=512 octets (MAC block budget), got {}",
                dto.segment_payload_octets
            ),
        });
    }

    // NOTE: spec ambiguous — chosen behaviour: cap tx_window at 3 for original AL;
    // extended AL (N.281 augmented) widens to 1..=15 but flowstation V1 only implements
    // original AL per the AL-3 design, so we enforce the original-AL range here.
    if dto.tx_window < 1 || dto.tx_window > 3 {
        return Err(ConfigError {
            field: "llc.advanced_link.tx_window",
            message: format!(
                "must be 1..=3 for original AL (N.272), got {}",
                dto.tx_window
            ),
        });
    }

    if dto.max_sdu_retx > 7 {
        return Err(ConfigError {
            field: "llc.advanced_link.max_sdu_retx",
            message: format!(
                "must be 0..=7 (3-bit N.273 field), got {}",
                dto.max_sdu_retx
            ),
        });
    }

    if dto.max_segment_retx > 15 {
        return Err(ConfigError {
            field: "llc.advanced_link.max_segment_retx",
            message: format!(
                "must be 0..=15 (4-bit N.274 field), got {}",
                dto.max_segment_retx
            ),
        });
    }

    if dto.max_setup_retries < 1 || dto.max_setup_retries > 5 {
        return Err(ConfigError {
            field: "llc.advanced_link.max_setup_retries",
            message: format!(
                "must be 1..=5 (N.262 spec range), got {}",
                dto.max_setup_retries
            ),
        });
    }

    if dto.max_disc_retries < 3 || dto.max_disc_retries > 5 {
        return Err(ConfigError {
            field: "llc.advanced_link.max_disc_retries",
            message: format!(
                "must be 3..=5 (N.263 spec range), got {}",
                dto.max_disc_retries
            ),
        });
    }

    if dto.max_reconnect_retries > 5 {
        return Err(ConfigError {
            field: "llc.advanced_link.max_reconnect_retries",
            message: format!(
                "must be 0..=5 (N.265 spec range), got {}",
                dto.max_reconnect_retries
            ),
        });
    }

    const VALID_N271: [u16; 8] = [32, 64, 128, 256, 512, 1024, 2048, 4096];
    if !VALID_N271.contains(&dto.max_tl_sdu_octets) {
        return Err(ConfigError {
            field: "llc.advanced_link.max_tl_sdu_octets",
            message: format!(
                "must be one of {:?} (N.271 power-of-two encoding), got {}",
                VALID_N271, dto.max_tl_sdu_octets
            ),
        });
    }

    Ok(CfgAdvancedLink {
        segment_payload_octets: dto.segment_payload_octets,
        tx_window: dto.tx_window,
        max_sdu_retx: dto.max_sdu_retx,
        max_segment_retx: dto.max_segment_retx,
        max_setup_retries: dto.max_setup_retries,
        max_disc_retries: dto.max_disc_retries,
        max_reconnect_retries: dto.max_reconnect_retries,
        max_tl_sdu_octets: dto.max_tl_sdu_octets,
    })
}

/// Convert a `CfgLlcDto` to the compiled [`CfgLlc`].
pub fn apply_llc_patch(dto: CfgLlcDto) -> Result<CfgLlc, ConfigError> {
    let advanced_link = match dto.advanced_link {
        Some(al_dto) => validate_advanced_link_config(al_dto)?,
        None => CfgAdvancedLink::default(),
    };
    Ok(CfgLlc { advanced_link })
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn defaults() -> AdvancedLinkDto {
        AdvancedLinkDto::default()
    }

    // ── Happy-path ────────────────────────────────────────────────────────────

    #[test]
    fn valid_defaults_accepted() {
        let cfg = validate_advanced_link_config(defaults()).expect("defaults must be valid");
        assert_eq!(cfg.segment_payload_octets, 50);
        assert_eq!(cfg.tx_window, 3);
        assert_eq!(cfg.max_sdu_retx, 3);
        assert_eq!(cfg.max_segment_retx, 3);
        assert_eq!(cfg.max_setup_retries, 3);
        assert_eq!(cfg.max_disc_retries, 3);
        assert_eq!(cfg.max_reconnect_retries, 3);
        assert_eq!(cfg.max_tl_sdu_octets, 4096);
    }

    #[test]
    fn valid_non_default_values_accepted() {
        let dto = AdvancedLinkDto {
            segment_payload_octets: 48,
            tx_window: 1,
            max_sdu_retx: 0,
            max_segment_retx: 0,
            max_setup_retries: 5,
            max_disc_retries: 5,
            max_reconnect_retries: 0,
            max_tl_sdu_octets: 256,
            ..defaults()
        };
        let cfg = validate_advanced_link_config(dto).expect("should be valid");
        assert_eq!(cfg.segment_payload_octets, 48);
        assert_eq!(cfg.tx_window, 1);
        assert_eq!(cfg.max_tl_sdu_octets, 256);
    }

    #[test]
    fn full_toml_section_parses_and_validates() {
        let toml_str = r#"
            segment_payload_octets = 40
            tx_window = 2
            max_sdu_retx = 5
            max_segment_retx = 10
            max_setup_retries = 4
            max_disc_retries = 4
            max_reconnect_retries = 3
            max_tl_sdu_octets = 512
        "#;
        let dto: AdvancedLinkDto = toml::from_str(toml_str).expect("TOML must parse");
        let cfg = validate_advanced_link_config(dto).expect("must validate");
        assert_eq!(cfg.segment_payload_octets, 40);
        assert_eq!(cfg.tx_window, 2);
        assert_eq!(cfg.max_tl_sdu_octets, 512);
    }

    #[test]
    fn apply_llc_patch_absent_section_yields_defaults() {
        let dto = CfgLlcDto::default();
        let cfg = apply_llc_patch(dto).expect("defaults must apply");
        assert_eq!(cfg.advanced_link.tx_window, 3);
        assert_eq!(cfg.advanced_link.segment_payload_octets, 50);
    }

    // ── segment_payload_octets ────────────────────────────────────────────────

    #[test]
    fn segment_payload_octets_zero_rejected() {
        let dto = AdvancedLinkDto { segment_payload_octets: 0, ..defaults() };
        let err = validate_advanced_link_config(dto).unwrap_err();
        assert_eq!(err.field, "llc.advanced_link.segment_payload_octets");
    }

    #[test]
    fn segment_payload_octets_513_rejected() {
        let dto = AdvancedLinkDto { segment_payload_octets: 513, ..defaults() };
        let err = validate_advanced_link_config(dto).unwrap_err();
        assert_eq!(err.field, "llc.advanced_link.segment_payload_octets");
    }

    // ── tx_window ─────────────────────────────────────────────────────────────

    #[test]
    fn tx_window_zero_rejected() {
        let dto = AdvancedLinkDto { tx_window: 0, ..defaults() };
        let err = validate_advanced_link_config(dto).unwrap_err();
        assert_eq!(err.field, "llc.advanced_link.tx_window");
    }

    #[test]
    fn tx_window_4_rejected() {
        let dto = AdvancedLinkDto { tx_window: 4, ..defaults() };
        let err = validate_advanced_link_config(dto).unwrap_err();
        assert_eq!(err.field, "llc.advanced_link.tx_window");
    }

    // ── max_sdu_retx ──────────────────────────────────────────────────────────

    #[test]
    fn max_sdu_retx_8_rejected() {
        let dto = AdvancedLinkDto { max_sdu_retx: 8, ..defaults() };
        let err = validate_advanced_link_config(dto).unwrap_err();
        assert_eq!(err.field, "llc.advanced_link.max_sdu_retx");
    }

    // ── max_segment_retx ──────────────────────────────────────────────────────

    #[test]
    fn max_segment_retx_16_rejected() {
        let dto = AdvancedLinkDto { max_segment_retx: 16, ..defaults() };
        let err = validate_advanced_link_config(dto).unwrap_err();
        assert_eq!(err.field, "llc.advanced_link.max_segment_retx");
    }

    // ── max_setup_retries ─────────────────────────────────────────────────────

    #[test]
    fn max_setup_retries_zero_rejected() {
        let dto = AdvancedLinkDto { max_setup_retries: 0, ..defaults() };
        let err = validate_advanced_link_config(dto).unwrap_err();
        assert_eq!(err.field, "llc.advanced_link.max_setup_retries");
    }

    #[test]
    fn max_setup_retries_6_rejected() {
        let dto = AdvancedLinkDto { max_setup_retries: 6, ..defaults() };
        let err = validate_advanced_link_config(dto).unwrap_err();
        assert_eq!(err.field, "llc.advanced_link.max_setup_retries");
    }

    // ── max_disc_retries ──────────────────────────────────────────────────────

    #[test]
    fn max_disc_retries_2_rejected() {
        let dto = AdvancedLinkDto { max_disc_retries: 2, ..defaults() };
        let err = validate_advanced_link_config(dto).unwrap_err();
        assert_eq!(err.field, "llc.advanced_link.max_disc_retries");
    }

    #[test]
    fn max_disc_retries_6_rejected() {
        let dto = AdvancedLinkDto { max_disc_retries: 6, ..defaults() };
        let err = validate_advanced_link_config(dto).unwrap_err();
        assert_eq!(err.field, "llc.advanced_link.max_disc_retries");
    }

    // ── max_reconnect_retries ─────────────────────────────────────────────────

    #[test]
    fn max_reconnect_retries_6_rejected() {
        let dto = AdvancedLinkDto { max_reconnect_retries: 6, ..defaults() };
        let err = validate_advanced_link_config(dto).unwrap_err();
        assert_eq!(err.field, "llc.advanced_link.max_reconnect_retries");
    }

    // ── max_tl_sdu_octets ─────────────────────────────────────────────────────

    #[test]
    fn max_tl_sdu_octets_non_power_of_two_rejected() {
        let dto = AdvancedLinkDto { max_tl_sdu_octets: 300, ..defaults() };
        let err = validate_advanced_link_config(dto).unwrap_err();
        assert_eq!(err.field, "llc.advanced_link.max_tl_sdu_octets");
    }

    #[test]
    fn max_tl_sdu_octets_16_rejected() {
        // 16 is a power of two but below 32 (smallest N.271 value)
        let dto = AdvancedLinkDto { max_tl_sdu_octets: 16, ..defaults() };
        let err = validate_advanced_link_config(dto).unwrap_err();
        assert_eq!(err.field, "llc.advanced_link.max_tl_sdu_octets");
    }

    #[test]
    fn max_tl_sdu_octets_8192_rejected() {
        // 8192 is a power of two but above 4096 (largest N.271 value)
        let dto = AdvancedLinkDto { max_tl_sdu_octets: 8192, ..defaults() };
        let err = validate_advanced_link_config(dto).unwrap_err();
        assert_eq!(err.field, "llc.advanced_link.max_tl_sdu_octets");
    }

    #[test]
    fn all_valid_n271_values_accepted() {
        for &v in &[32u16, 64, 128, 256, 512, 1024, 2048, 4096] {
            let dto = AdvancedLinkDto { max_tl_sdu_octets: v, ..defaults() };
            assert!(
                validate_advanced_link_config(dto).is_ok(),
                "N.271 value {} should be valid",
                v
            );
        }
    }

    #[test]
    fn error_display_contains_field_path() {
        let dto = AdvancedLinkDto { tx_window: 0, ..defaults() };
        let err = validate_advanced_link_config(dto).unwrap_err();
        let s = err.to_string();
        assert!(s.contains("llc.advanced_link.tx_window"), "error display should contain field path: {s}");
    }
}
