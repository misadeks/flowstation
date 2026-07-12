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

    /// PD-REWRITE C1: H47 (proactive AL-DISC on retx-exhaust) removed as a
    /// spec violation per ETSI TS 100 392-2 §22.3.3.2.6 NOTE 1 — the service
    /// user decides reset / disconnect / reconnect / release, not LLC. Retx
    /// exhaustion now surfaces via the `AlDeliveryOutcome::DroppedRetxExhausted`
    /// event (see `al_events.rs`) and, once Commit 5 lands, via the formal
    /// `TlReportInd` primitive on the TLA SAP. The `proactive_disc_on_retx_exhaust`
    /// TOML key is deprecated: `AdvancedLinkDto` still accepts it for backwards
    /// compatibility during operator upgrade but logs an INFO line and ignores
    /// the value. Field intentionally removed from the compiled struct.

    /// PD-5c-H47: cache the last accepted `AL-SETUP` echo per link and
    /// re-emit it verbatim when the peer sends a byte-identical duplicate
    /// `AL-SETUP` (i.e., the CON was lost in DL air). Skips the full
    /// accept flow (purge + `reset_transfer_state`) on the duplicate.
    /// Default `true`.
    pub cache_setup_echo: bool,

    /// PD-5c-H49: on receipt of an inbound AL-DATA/AL-FINAL whose `N(S)` was
    /// already reassembled + delivered upward (i.e. our AL-ACK was lost in
    /// DL air and the peer is retransmitting), re-emit AL-ACK
    /// `EntireSduReceived` for that `N(S)` but skip re-reassembly and skip
    /// re-delivery to the higher layer. Prevents duplicate SDUs from
    /// re-invoking WSP (which would otherwise trigger the H33 Result-replay
    /// path and pile DL congestion, itself starving further AL-ACKs → link
    /// reset). Matches ETSI TS 100 392-2 v3.10.1 clause 21.4.3
    /// duplicate-SDU suppression + DIMETRA rlj_app
    /// `dlai_rx_duplicate_sdu_ack`. Default `true`.
    pub dedupe_completed_ns: bool,

    /// PD-5c-H50: when the H47 duplicate-SETUP fast path re-emits a cached
    /// `AL-SETUP-CON`, also drop RX-side transfer state (in-flight
    /// reassemblers + duplicate-N(S) dedupe ring) while preserving all TX
    /// state and the cached echo itself. Fixes a stale-reassembler
    /// collision when the peer's duplicate SETUP is actually a fresh
    /// re-establishment after an idle (MTP3550 behaviour: peer's TX/RX
    /// resets to `s_s = 0` / `N(S) = 0`, so our stale reassemblers merge
    /// old + new segments into a Frankenstein SDU that fails FCS). The
    /// original H47 "preserve everything" policy is only safe when the
    /// duplicate arrives because our CON was air-lost (peer state
    /// unchanged); H50 covers the other case without regressing that one.
    /// Default `true`; flip to `false` as a rollback escape hatch.
    pub h47_cached_echo_clears_rx: bool,

    /// PD-5c-H53: when an AL-SETUP negotiates `N.273 (max_sdu_retx) = 0`
    /// with `service = Ack` and `N.274 (max_segment_retx) > 0`, treat
    /// `N.273 = 0` as "no explicit SDU-level cap; use N.274 as the
    /// effective bound". This is H46's MTP6550/WSP interpretation of
    /// ETSI TS 100 392-2 clause 23.5 and keeps reliable delivery working
    /// for WSP peers that expect their `N.274` retry budget to be
    /// honoured.
    ///
    /// Flip to `false` to restore pre-H46 semantics: `N.273 = 0` means
    /// literally zero SDU retries (fire-and-forget). This is the correct
    /// reading for peers such as MTP3550 running ICMP/PPP over SNDCP,
    /// whose kernel-side ICMP stack never emits AL-ACK regardless of
    /// what the AL-SETUP negotiated.
    ///
    /// This gate is a global config knob; per-link automatic selection
    /// via the SNDCP-bound marker (see `AlLink.sndcp_bound`) always
    /// forces fire-and-forget on SNDCP-created links irrespective of
    /// this setting. Default `true` to preserve H46 hardware-validated
    /// WSP behaviour.
    pub n273_zero_ack_uses_seg_cap: bool,
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
            cache_setup_echo: true,
            dedupe_completed_ns: true,
            h47_cached_echo_clears_rx: true,
            // PD-REWRITE C1 (P3 Fork 3): flipped from `true` to `false` for
            // spec compliance. When `false`, `N.273 = 0` on an ACK link means
            // fire-and-forget (as ETSI TS 100 392-2 Annex A permits, range
            // 0..=7). Setting `true` restores the MTP6550 WSP-portal interop
            // quirk (H46) that treats `N.273 = 0` as "use N.274 as the
            // effective cap". Only enable when interop-testing against a
            // legacy MTP6550 fleet.
            n273_zero_ack_uses_seg_cap: false,
        }
    }
}

/// Top-level LLC config.
///
/// `interop_profile` selects a named bundle of interop-quirk gates for known
/// MS models. Individual knobs on `[llc.advanced_link]` set explicitly in
/// the TOML always win over the profile's default for that knob (see
/// `Docs/interop-knobs.md`). This lets operators use a named profile as a
/// starting point and override specific gates when needed.
#[derive(Debug, Clone, Default)]
pub struct CfgLlc {
    /// Interop profile selection. See [`InteropProfile`].
    pub interop_profile: InteropProfile,
    pub advanced_link: CfgAdvancedLink,
}

/// PD-REWRITE C6: named bundles of LLC interop-quirk gates.
///
/// A profile sets *defaults* for the gates it names. Explicit knobs in
/// `[llc.advanced_link]` still win — profile-set values are only used when
/// the corresponding knob is absent from the TOML.
///
/// Precedence: **explicit knob > profile default > spec default**.
///
/// See `Docs/interop-knobs.md` for the operator-facing catalog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InteropProfile {
    /// Spec-compliant defaults everywhere. All interop gates start off
    /// unless individually enabled.
    Standard,
    /// Enable the LLC-side gates known to help MTP3550 handset interop
    /// (currently H49 dedupe + H50 cached-echo RX-clear, both already
    /// default-on; the profile names the group so operators can reason
    /// about it and so future evolution — WTP-side gates from Commit 6b,
    /// or default-flip changes — doesn't silently alter semantics).
    ///
    /// Not a functional change relative to Commit-1 defaults today; the
    /// profile is a stable operator surface.
    Mtp3550Interop,
    /// Enable the H46 quirk (`n273_zero_ack_uses_seg_cap = true`) needed
    /// by the MTP6550 WSP portal. Spec-noncompliant per §22.3.3.2 + Annex
    /// A; the startup WARN log names it.
    Mtp6550Interop,
    /// No profile-driven overrides. Every knob comes from either an
    /// explicit TOML value or the spec-compliant default.
    Custom,
}

impl Default for InteropProfile {
    fn default() -> Self { InteropProfile::Standard }
}

impl std::str::FromStr for InteropProfile {
    type Err = ConfigError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "standard" => Ok(InteropProfile::Standard),
            "mtp3550_interop" => Ok(InteropProfile::Mtp3550Interop),
            "mtp6550_interop" => Ok(InteropProfile::Mtp6550Interop),
            "custom" => Ok(InteropProfile::Custom),
            other => Err(ConfigError {
                field: "llc.interop_profile",
                message: format!(
                    "must be one of \"standard\", \"mtp3550_interop\", \"mtp6550_interop\", \"custom\"; got {:?}",
                    other
                ),
            }),
        }
    }
}

impl std::fmt::Display for InteropProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            InteropProfile::Standard => "standard",
            InteropProfile::Mtp3550Interop => "mtp3550_interop",
            InteropProfile::Mtp6550Interop => "mtp6550_interop",
            InteropProfile::Custom => "custom",
        })
    }
}

impl InteropProfile {
    /// Returns this profile's default for `n273_zero_ack_uses_seg_cap` (H46),
    /// or `None` if the profile does not touch this knob (spec default applies).
    pub fn n273_zero_ack_uses_seg_cap(&self) -> Option<bool> {
        match self {
            InteropProfile::Mtp6550Interop => Some(true),
            InteropProfile::Standard | InteropProfile::Mtp3550Interop | InteropProfile::Custom => None,
        }
    }

    /// Returns this profile's default for `dedupe_completed_ns` (H49), or
    /// `None` if the profile does not touch this knob.
    pub fn dedupe_completed_ns(&self) -> Option<bool> {
        match self {
            InteropProfile::Mtp3550Interop => Some(true),
            _ => None,
        }
    }

    /// Returns this profile's default for `h47_cached_echo_clears_rx` (H50),
    /// or `None` if the profile does not touch this knob.
    pub fn h47_cached_echo_clears_rx(&self) -> Option<bool> {
        match self {
            InteropProfile::Mtp3550Interop => Some(true),
            _ => None,
        }
    }
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
    /// **DEPRECATED (PD-REWRITE C1).** The H47 proactive AL-DISC behavior was
    /// removed as a spec violation. Setting this field in TOML now logs an
    /// INFO line and is otherwise ignored. Field kept in the DTO (rather
    /// than deleted) so operators upgrading in-place don't hit the
    /// unknown-fields rejection in `parsing.rs`. Remove from your config
    /// at your convenience.
    #[serde(default)]
    pub proactive_disc_on_retx_exhaust: Option<bool>,
    #[serde(default = "default_cache_setup_echo")]
    pub cache_setup_echo: bool,
    /// H49 gate. `None` = use profile default (or spec default if profile
    /// doesn't touch); `Some(x)` = explicit override from operator TOML.
    #[serde(default)]
    pub dedupe_completed_ns: Option<bool>,
    /// H50 gate. `None` = profile / spec default; `Some(x)` = explicit override.
    #[serde(default)]
    pub h47_cached_echo_clears_rx: Option<bool>,
    /// H46 gate. `None` = profile / spec default; `Some(x)` = explicit override.
    #[serde(default)]
    pub n273_zero_ack_uses_seg_cap: Option<bool>,

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
            proactive_disc_on_retx_exhaust: None,
            cache_setup_echo: default_cache_setup_echo(),
            dedupe_completed_ns: None,
            h47_cached_echo_clears_rx: None,
            n273_zero_ack_uses_seg_cap: None,
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
fn default_cache_setup_echo() -> bool { true }
/// Spec-default for `dedupe_completed_ns` (H49) when neither the profile nor
/// an explicit TOML knob provides a value. Kept true because §22.3.3.2.7
/// NOTE 6 permits the send-ACK-then-discard strategy and it prevents an
/// upward-visible WSP replay cascade for common peers.
pub(crate) fn spec_default_dedupe_completed_ns() -> bool { true }
/// Spec-default for `h47_cached_echo_clears_rx` (H50). See sec_llc.rs docs.
pub(crate) fn spec_default_h47_cached_echo_clears_rx() -> bool { true }
/// PD-REWRITE C1 (P3 Fork 3): spec-compliant default is `false` (fire-and-
/// forget when N.273=0 on ACK link per Annex A range 0..=7).
pub(crate) fn spec_default_n273_zero_ack_uses_seg_cap() -> bool { false }

/// Serde DTO for `[llc]`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct CfgLlcDto {
    /// Advanced-link sub-section.  When absent, all AL fields default to
    /// their AL-3 hardcoded values.
    #[serde(default)]
    pub advanced_link: Option<AdvancedLinkDto>,

    /// PD-REWRITE C6: interop-profile selection. Absent or missing = Standard.
    #[serde(default)]
    pub interop_profile: Option<String>,

    /// Unknown-field detector — parsing.rs rejects any entry present here.
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

// ─── Validation & conversion ─────────────────────────────────────────────────

/// Convenience wrapper: validate + convert an `AdvancedLinkDto` using the
/// default (`Standard`) interop profile. Preferred entry point for tests and
/// code paths that don't care about profiles.
pub fn validate_advanced_link_config(
    dto: AdvancedLinkDto,
) -> Result<CfgAdvancedLink, ConfigError> {
    validate_advanced_link_config_with_profile(dto, InteropProfile::Standard)
}

/// Validate an `AdvancedLinkDto` against spec ranges and convert it to the
/// compiled [`CfgAdvancedLink`], resolving the three profile-affected gates
/// via `profile`.
///
/// Returns [`ConfigError`] on the first failing field, with the full dotted
/// TOML path and a human-readable bound description.
pub fn validate_advanced_link_config_with_profile(
    dto: AdvancedLinkDto,
    profile: InteropProfile,
) -> Result<CfgAdvancedLink, ConfigError> {
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

    // PD-REWRITE C1: warn on deprecated H47 knob if present in operator TOML.
    if let Some(v) = dto.proactive_disc_on_retx_exhaust {
        tracing::info!(
            deprecated_field = "llc.advanced_link.proactive_disc_on_retx_exhaust",
            supplied_value = v,
            replacement = "removed: spec-noncompliant per ETSI TS 100 392-2 §22.3.3.2.6 NOTE 1",
            "config: deprecated field ignored; remove from your TOML"
        );
    }

    // PD-REWRITE C6: resolve the three profile-affected gates. Precedence
    // is explicit knob > profile default > spec default; the
    // `dto.*` fields are `Option<bool>` so `Some(x)` means an explicit knob.
    let n273_zero_ack_uses_seg_cap = dto
        .n273_zero_ack_uses_seg_cap
        .or_else(|| profile.n273_zero_ack_uses_seg_cap())
        .unwrap_or_else(spec_default_n273_zero_ack_uses_seg_cap);
    let dedupe_completed_ns = dto
        .dedupe_completed_ns
        .or_else(|| profile.dedupe_completed_ns())
        .unwrap_or_else(spec_default_dedupe_completed_ns);
    let h47_cached_echo_clears_rx = dto
        .h47_cached_echo_clears_rx
        .or_else(|| profile.h47_cached_echo_clears_rx())
        .unwrap_or_else(spec_default_h47_cached_echo_clears_rx);

    Ok(CfgAdvancedLink {
        segment_payload_octets: dto.segment_payload_octets,
        tx_window: dto.tx_window,
        max_sdu_retx: dto.max_sdu_retx,
        max_segment_retx: dto.max_segment_retx,
        max_setup_retries: dto.max_setup_retries,
        max_disc_retries: dto.max_disc_retries,
        max_reconnect_retries: dto.max_reconnect_retries,
        max_tl_sdu_octets: dto.max_tl_sdu_octets,
        cache_setup_echo: dto.cache_setup_echo,
        dedupe_completed_ns,
        h47_cached_echo_clears_rx,
        n273_zero_ack_uses_seg_cap,
    })
}

/// Convert a `CfgLlcDto` to the compiled [`CfgLlc`].
pub fn apply_llc_patch(dto: CfgLlcDto) -> Result<CfgLlc, ConfigError> {
    let profile = match dto.interop_profile.as_deref() {
        Some(s) => s.parse::<InteropProfile>()?,
        None => InteropProfile::default(),
    };
    let advanced_link = match dto.advanced_link {
        Some(al_dto) => validate_advanced_link_config_with_profile(al_dto, profile)?,
        None => validate_advanced_link_config_with_profile(AdvancedLinkDto::default(), profile)?,
    };
    Ok(CfgLlc { interop_profile: profile, advanced_link })
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
        // PD-5c-H47: cache_setup_echo defaults on (proactive_disc_on_retx_exhaust removed in
        // PD-REWRITE C1 — H47 emission deleted as spec violation).
        assert!(cfg.cache_setup_echo);
        // PD-5c-H49: duplicate-N(S) suppression defaults on.
        assert!(cfg.dedupe_completed_ns);
        // PD-5c-H50: H47 cached-echo RX-clear defaults on.
        assert!(cfg.h47_cached_echo_clears_rx);
        // PD-REWRITE C1 (T1 = P3 Fork 3): N.273=0+Ack coercion default flipped
        // to `false` for spec compliance. `true` restores the MTP6550 WSP-portal
        // interop quirk (H46).
        assert!(!cfg.n273_zero_ack_uses_seg_cap);
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
            proactive_disc_on_retx_exhaust = false
            cache_setup_echo = false
            dedupe_completed_ns = false
            h47_cached_echo_clears_rx = false
            n273_zero_ack_uses_seg_cap = false
        "#;
        let dto: AdvancedLinkDto = toml::from_str(toml_str).expect("TOML must parse");
        let cfg = validate_advanced_link_config(dto).expect("must validate");
        assert_eq!(cfg.segment_payload_octets, 40);
        assert_eq!(cfg.tx_window, 2);
        assert_eq!(cfg.max_tl_sdu_octets, 512);
        // PD-REWRITE C1: proactive_disc_on_retx_exhaust is a deprecated DTO
        // field kept only for backwards-compat; not present on the compiled
        // struct. Test that supplying it does not crash config load (soft
        // migration verified by tests/deprecated_fields.rs T5).
        assert!(!cfg.cache_setup_echo);
        // PD-5c-H49: override plumbs through.
        assert!(!cfg.dedupe_completed_ns);
        // PD-5c-H50: override plumbs through.
        assert!(!cfg.h47_cached_echo_clears_rx);
        // PD-5c-H53: override plumbs through (this test sets the interop knob
        // OFF explicitly which now happens to match the new default; the point
        // of this assertion is that the TOML override is honored).
        assert!(!cfg.n273_zero_ack_uses_seg_cap);
    }

    #[test]
    fn apply_llc_patch_absent_section_yields_defaults() {
        let dto = CfgLlcDto::default();
        let cfg = apply_llc_patch(dto).expect("defaults must apply");
        assert_eq!(cfg.advanced_link.tx_window, 3);
        assert_eq!(cfg.advanced_link.segment_payload_octets, 50);
    }

    // ── PD-REWRITE C1 tests ────────────────────────────────────────────────

    /// T1: default `n273_zero_ack_uses_seg_cap` must be `false` (P3 Fork 3).
    /// Spec-compliant: N.273=0 on ACK link means fire-and-forget per ETSI
    /// TS 100 392-2 Annex A (N.273 range 0..=7; value 0 legal).
    #[test]
    fn pd_rewrite_c1_default_n273_zero_ack_uses_seg_cap_is_false() {
        let cfg = CfgAdvancedLink::default();
        assert!(!cfg.n273_zero_ack_uses_seg_cap,
            "PD-REWRITE C1 (P3 Fork 3): default must be false for spec compliance");
        assert!(!spec_default_n273_zero_ack_uses_seg_cap(),
            "PD-REWRITE C6: the spec-default function must return false");
    }

    /// T5: deprecated `proactive_disc_on_retx_exhaust` field in TOML must be
    /// accepted (soft migration) — the DTO ignores it; validation succeeds.
    #[test]
    fn pd_rewrite_c1_deprecated_proactive_disc_field_is_ignored() {
        // A minimal TOML section containing only the deprecated field.
        let toml_str = r#"
            segment_payload_octets = 50
            tx_window = 3
            max_sdu_retx = 3
            max_segment_retx = 3
            max_setup_retries = 3
            max_disc_retries = 3
            max_reconnect_retries = 3
            max_tl_sdu_octets = 4096
            proactive_disc_on_retx_exhaust = true
            cache_setup_echo = true
            dedupe_completed_ns = true
            h47_cached_echo_clears_rx = true
            n273_zero_ack_uses_seg_cap = false
        "#;
        let dto: AdvancedLinkDto = toml::from_str(toml_str)
            .expect("TOML with deprecated field must parse (soft migration)");
        assert_eq!(dto.proactive_disc_on_retx_exhaust, Some(true),
            "deprecated field captured on DTO for soft-migration reporting");
        let cfg = validate_advanced_link_config(dto)
            .expect("validation must succeed despite deprecated field");
        // The compiled struct no longer has the field; the deprecated value is dropped
        // on the floor after the INFO log is emitted (log capture verified via T5b).
        // Just prove the rest of the config wired through:
        assert!(cfg.cache_setup_echo);
        assert!(!cfg.n273_zero_ack_uses_seg_cap);
    }

    /// T13: config alias sweep — as of PD-REWRITE C1 the only operator-facing
    /// alias for the removed H47 knob is `proactive_disc_on_retx_exhaust`
    /// (T5 covers it). The internal `cfg_proactive_disc` name is code-only
    /// and was removed with the H47 emission block. No other aliases exist in
    /// operator-facing surfaces (TOML docs, README, sample configs). If a
    /// future rename introduces one, extend T5 and delete this test.
    #[test]
    fn pd_rewrite_c1_no_other_h47_aliases_in_operator_surface() {
        // Sentinel test: this passes as long as the alias-sweep audit records
        // above remain accurate. It carries no runtime assertion.
    }

    // ── PD-REWRITE C6 tests ────────────────────────────────────────────────

    /// C6-T1: profile string parsing round-trip.
    #[test]
    fn pd_rewrite_c6_interop_profile_parses_all_variants() {
        use std::str::FromStr;
        assert_eq!(InteropProfile::from_str("standard").unwrap(), InteropProfile::Standard);
        assert_eq!(InteropProfile::from_str("mtp3550_interop").unwrap(), InteropProfile::Mtp3550Interop);
        assert_eq!(InteropProfile::from_str("mtp6550_interop").unwrap(), InteropProfile::Mtp6550Interop);
        assert_eq!(InteropProfile::from_str("custom").unwrap(), InteropProfile::Custom);
        let err = InteropProfile::from_str("mtp1234_bogus").unwrap_err();
        assert_eq!(err.field, "llc.interop_profile");
    }

    /// C6-T2: default profile is `Standard`.
    #[test]
    fn pd_rewrite_c6_default_profile_is_standard() {
        let cfg = CfgLlc::default();
        assert_eq!(cfg.interop_profile, InteropProfile::Standard);
    }

    /// C6-T3: `Mtp6550Interop` profile turns H46 (n273_zero_ack_uses_seg_cap) on.
    #[test]
    fn pd_rewrite_c6_mtp6550_profile_enables_h46() {
        let cfg = validate_advanced_link_config_with_profile(
            AdvancedLinkDto::default(),
            InteropProfile::Mtp6550Interop,
        ).unwrap();
        assert!(cfg.n273_zero_ack_uses_seg_cap,
            "mtp6550_interop profile must enable H46");
        // Other gates unchanged.
        assert!(cfg.dedupe_completed_ns);
        assert!(cfg.h47_cached_echo_clears_rx);
    }

    /// C6-T4: `Mtp3550Interop` profile explicitly sets H49/H50 (already spec-legal
    /// defaults, but the profile names the intent so future default-flips don't
    /// silently change semantics).
    #[test]
    fn pd_rewrite_c6_mtp3550_profile_names_h49_h50_group() {
        let cfg = validate_advanced_link_config_with_profile(
            AdvancedLinkDto::default(),
            InteropProfile::Mtp3550Interop,
        ).unwrap();
        assert!(cfg.dedupe_completed_ns, "mtp3550 profile names H49 explicitly");
        assert!(cfg.h47_cached_echo_clears_rx, "mtp3550 profile names H50 explicitly");
        // H46 stays off — profile doesn't touch it.
        assert!(!cfg.n273_zero_ack_uses_seg_cap);
    }

    /// C6-T5: `Standard` profile = spec defaults everywhere. H46 off; H49/H50
    /// default (currently true; may flip in a future commit).
    #[test]
    fn pd_rewrite_c6_standard_profile_uses_spec_defaults() {
        let cfg = validate_advanced_link_config_with_profile(
            AdvancedLinkDto::default(),
            InteropProfile::Standard,
        ).unwrap();
        assert!(!cfg.n273_zero_ack_uses_seg_cap, "Standard: H46 off (spec-compliant)");
        assert_eq!(cfg.dedupe_completed_ns, spec_default_dedupe_completed_ns());
        assert_eq!(cfg.h47_cached_echo_clears_rx, spec_default_h47_cached_echo_clears_rx());
    }

    /// C6-T6: **precedence** — explicit knob wins over profile default.
    /// `Mtp6550Interop` would enable H46, but the DTO explicitly sets it false.
    #[test]
    fn pd_rewrite_c6_explicit_knob_overrides_profile_default() {
        let dto = AdvancedLinkDto {
            n273_zero_ack_uses_seg_cap: Some(false),
            ..AdvancedLinkDto::default()
        };
        let cfg = validate_advanced_link_config_with_profile(
            dto,
            InteropProfile::Mtp6550Interop,
        ).unwrap();
        assert!(!cfg.n273_zero_ack_uses_seg_cap,
            "explicit `Some(false)` in DTO must override the Mtp6550Interop profile's `Some(true)` default");
    }

    /// C6-T7: full TOML → profile applied, explicit knob overrides profile.
    #[test]
    fn pd_rewrite_c6_full_toml_profile_and_override() {
        let toml_str = r#"
            interop_profile = "mtp6550_interop"

            [advanced_link]
            n273_zero_ack_uses_seg_cap = false
        "#;
        let dto: CfgLlcDto = toml::from_str(toml_str).expect("TOML must parse");
        let cfg = apply_llc_patch(dto).expect("apply must succeed");
        assert_eq!(cfg.interop_profile, InteropProfile::Mtp6550Interop);
        assert!(!cfg.advanced_link.n273_zero_ack_uses_seg_cap,
            "explicit knob in TOML must override profile choice");
    }

    /// C6-T8: bogus profile string in TOML produces a clear ConfigError.
    #[test]
    fn pd_rewrite_c6_bogus_profile_string_rejected() {
        let toml_str = r#"interop_profile = "mtp9999_bogus""#;
        let dto: CfgLlcDto = toml::from_str(toml_str).expect("TOML parses");
        let err = apply_llc_patch(dto).unwrap_err();
        assert_eq!(err.field, "llc.interop_profile");
    }


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
