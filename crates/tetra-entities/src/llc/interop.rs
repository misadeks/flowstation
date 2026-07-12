//! PD-REWRITE C1: interop-gate visibility helper.
//!
//! LLC has several config knobs that intentionally trade spec-compliance for
//! interop with specific MS-firmware quirks. Every such knob:
//!
//! * defaults to spec-correct behavior (gate off / value spec-legal)
//! * can be flipped on to restore vendor-quirk-friendly behavior
//! * emits a WARN log at BS startup naming itself + the spec section it
//!   deviates from, so operators can inventory every active quirk by
//!   grepping the boot log for `interop gate`.
//!
//! PD-REWRITE C6 adds `interop_profile` — a named bundle of gates operators
//! can select as a set. This module emits an INFO log naming the active
//! profile alongside the per-gate WARN inventory.
//!
//! Call [`log_enabled_interop_gates`] from `bluestation-bs`' boot path after
//! config load, before any packet-data traffic starts.
//!
//! See `Docs/interop-knobs.md` for the operator-facing catalog.

use tetra_config::bluestation::{CfgLlc, InteropProfile};

/// Emit one WARN log per currently-enabled spec-noncompliant interop gate, plus
/// one INFO log naming the active `interop_profile`. Silent when the LLC
/// config is at spec-compliant defaults AND the profile is `Standard`.
///
/// Returns the count of WARN-emitted gates (useful for observability metrics).
pub fn log_enabled_interop_gates(cfg: &CfgLlc) -> usize {
    // PD-REWRITE C6: always name the profile so operators can grep boot logs
    // for `interop_profile` and know which named bundle is active.
    tracing::info!(
        interop_profile = %cfg.interop_profile,
        "PD-REWRITE C6: interop profile active"
    );

    let mut count = 0;

    // H46: N.273=0 on ACK link → use N.274 as effective cap.
    // Spec: ETSI TS 100 392-2 §22.3.3.2 + Annex A (N.273 range 0..=7; value
    // 0 means literally zero SDU retries, fire-and-forget on the reliable AL).
    // Interop: MTP6550 WSP portal expects N.274-driven retries even when the
    // negotiation reports N.273=0. Enabling this gate honors that expectation.
    if cfg.advanced_link.n273_zero_ack_uses_seg_cap {
        tracing::warn!(
            gate = "llc.advanced_link.n273_zero_ack_uses_seg_cap",
            spec = "ETSI TS 100 392-2 §22.3.3.2 + Annex A",
            interop_target = "MTP6550 WSP portal",
            profile_hint = %cfg.interop_profile,
            "interop gate enabled: N.273=0 on ACK link coerced to N.274 (spec-noncompliant)"
        );
        count += 1;
    }

    // H49: on receipt of an already-delivered N(S), re-ACK without redelivery.
    // Spec: §22.3.3.2.7 NOTE 6 permits/expects the send-ACK-then-discard
    // strategy for below-window TL-SDUs. The knob is spec-legal but the
    // Commit-1 parent review (note 2) asked for a WARN when active as part
    // of the Commit-6 mtp3550_interop bundle, so operators see the full
    // interop inventory when the profile is enabled. C6: warn when true.
    if cfg.advanced_link.dedupe_completed_ns {
        tracing::warn!(
            gate = "llc.advanced_link.dedupe_completed_ns",
            spec = "ETSI TS 100 392-2 §22.3.3.2.7 NOTE 6 (spec-legal)",
            interop_target = "MTP3550 WSP portal / WTP replay-cascade prevention",
            profile_hint = %cfg.interop_profile,
            "interop gate enabled: LLC dedupes below-window N(S) segments and re-ACKs without redelivery"
        );
        count += 1;
    }

    // H50: RX-side transfer state cleared on H47 cached-echo re-emission.
    // Spec-legal (§22.3.3.2 Frankenstein-SDU prevention on peer re-setup).
    // Same PR note 2 rationale as H49.
    if cfg.advanced_link.h47_cached_echo_clears_rx {
        tracing::warn!(
            gate = "llc.advanced_link.h47_cached_echo_clears_rx",
            spec = "ETSI TS 100 392-2 §22.3.3.2 + duplicate-SETUP handling (spec-legal)",
            interop_target = "MTP3550 fresh-re-establishment after cached-echo",
            profile_hint = %cfg.interop_profile,
            "interop gate enabled: cached-echo re-emission clears RX reassembler state"
        );
        count += 1;
    }

    let _ = InteropProfile::Standard;  // touch to keep the import warning-free.
    count
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tetra_config::bluestation::{
        AdvancedLinkDto, CfgLlc, InteropProfile, validate_advanced_link_config_with_profile,
    };
    use tracing::subscriber;
    use tracing::field::{Field, Visit};
    use tracing::span::{Attributes, Id, Record};
    use tracing::{Event, Metadata, Subscriber};

    /// Minimal in-memory subscriber that records structured field values from
    /// every event alongside the event's level and message string. Used by
    /// T6/T7 to assert on WARN log emission without adding a new dev-dep.
    #[derive(Clone, Default)]
    struct CaptureSubscriber {
        events: Arc<Mutex<Vec<CapturedEvent>>>,
    }

    #[derive(Debug, Clone)]
    struct CapturedEvent {
        level: tracing::Level,
        _target: String,
        fields: std::collections::HashMap<String, String>,
    }

    impl Subscriber for CaptureSubscriber {
        fn enabled(&self, _md: &Metadata<'_>) -> bool { true }
        fn new_span(&self, _attrs: &Attributes<'_>) -> Id { Id::from_u64(1) }
        fn record(&self, _span: &Id, _values: &Record<'_>) {}
        fn record_follows_from(&self, _span: &Id, _follows: &Id) {}
        fn event(&self, event: &Event<'_>) {
            let md = event.metadata();
            let mut visitor = FieldVisitor { fields: std::collections::HashMap::new() };
            event.record(&mut visitor);
            self.events.lock().unwrap().push(CapturedEvent {
                level: *md.level(),
                _target: md.target().to_string(),
                fields: visitor.fields,
            });
        }
        fn enter(&self, _span: &Id) {}
        fn exit(&self, _span: &Id) {}
    }

    struct FieldVisitor {
        fields: std::collections::HashMap<String, String>,
    }
    impl Visit for FieldVisitor {
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            self.fields.insert(field.name().to_string(), format!("{:?}", value));
        }
        fn record_str(&mut self, field: &Field, value: &str) {
            self.fields.insert(field.name().to_string(), value.to_string());
        }
    }

    fn cfg_with_profile(profile: InteropProfile) -> CfgLlc {
        let al = validate_advanced_link_config_with_profile(
            AdvancedLinkDto::default(),
            profile,
        ).unwrap();
        CfgLlc { interop_profile: profile, advanced_link: al }
    }

    /// T6: WARN log fires when `n273_zero_ack_uses_seg_cap` is enabled (via
    /// explicit knob).
    #[test]
    fn t6_warn_log_when_n273_zero_ack_uses_seg_cap_enabled() {
        let capture = CaptureSubscriber::default();
        let sub = capture.clone();
        subscriber::with_default(sub, || {
            let mut cfg = CfgLlc::default();
            cfg.advanced_link.n273_zero_ack_uses_seg_cap = true;
            let _ = log_enabled_interop_gates(&cfg);
        });
        let events = capture.events.lock().unwrap();
        let warn = events.iter()
            .find(|e| e.level == tracing::Level::WARN
                && e.fields.get("gate")
                    .map(|g| g.contains("n273_zero_ack_uses_seg_cap"))
                    .unwrap_or(false))
            .expect("T6: expected a WARN log naming the gate");
        assert!(warn.fields.get("spec")
            .map(|s| s.contains("§22.3.3.2"))
            .unwrap_or(false),
            "T6: WARN log must cite ETSI §22.3.3.2");
    }

    /// T7: no interop-gate WARN log when profile is Standard and all knobs
    /// are false. (Note: the profile-name INFO log always fires; that's
    /// intentional. T7 asserts on WARN-level noise only.)
    #[test]
    fn t7_no_warn_log_when_all_gates_off() {
        let capture = CaptureSubscriber::default();
        let sub = capture.clone();
        subscriber::with_default(sub, || {
            // Custom profile so no profile-driven defaults; all knobs explicit off.
            let mut cfg = CfgLlc { interop_profile: InteropProfile::Custom, ..CfgLlc::default() };
            cfg.advanced_link.dedupe_completed_ns = false;
            cfg.advanced_link.h47_cached_echo_clears_rx = false;
            cfg.advanced_link.n273_zero_ack_uses_seg_cap = false;
            let count = log_enabled_interop_gates(&cfg);
            assert_eq!(count, 0, "no gates should be reported enabled");
        });
        let events = capture.events.lock().unwrap();
        let interop_warns = events.iter()
            .filter(|e| e.level == tracing::Level::WARN
                && e.fields.get("gate").is_some())
            .count();
        assert_eq!(interop_warns, 0,
            "T7: no WARN 'interop gate' log expected when all gates are off");
    }

    /// C6: profile-name INFO log always fires (regardless of gate state).
    #[test]
    fn c6_profile_info_log_always_fires() {
        for profile in [InteropProfile::Standard, InteropProfile::Mtp3550Interop,
                        InteropProfile::Mtp6550Interop, InteropProfile::Custom] {
            let capture = CaptureSubscriber::default();
            let sub = capture.clone();
            subscriber::with_default(sub, || {
                let cfg = cfg_with_profile(profile);
                let _ = log_enabled_interop_gates(&cfg);
            });
            let events = capture.events.lock().unwrap();
            let info_line = events.iter()
                .find(|e| e.level == tracing::Level::INFO
                    && e.fields.get("interop_profile").is_some())
                .unwrap_or_else(|| panic!("profile {:?}: missing INFO 'interop_profile' log", profile));
            assert!(info_line.fields.get("interop_profile")
                .map(|s| s.contains(&format!("{}", profile)))
                .unwrap_or(false),
                "profile {:?}: INFO log must name the profile", profile);
        }
    }

    /// C6: `Mtp3550Interop` profile with default DTO enables H49+H50 → two
    /// WARNs fire alongside the profile INFO.
    #[test]
    fn c6_mtp3550_profile_fires_h49_h50_warns() {
        let capture = CaptureSubscriber::default();
        let sub = capture.clone();
        subscriber::with_default(sub, || {
            let cfg = cfg_with_profile(InteropProfile::Mtp3550Interop);
            let count = log_enabled_interop_gates(&cfg);
            assert_eq!(count, 2, "H49 + H50 must WARN under mtp3550_interop");
        });
        let events = capture.events.lock().unwrap();
        let has_dedupe = events.iter().any(|e| e.level == tracing::Level::WARN
            && e.fields.get("gate").map(|g| g.contains("dedupe_completed_ns")).unwrap_or(false));
        let has_h50 = events.iter().any(|e| e.level == tracing::Level::WARN
            && e.fields.get("gate").map(|g| g.contains("h47_cached_echo_clears_rx")).unwrap_or(false));
        assert!(has_dedupe, "H49 WARN must fire under mtp3550_interop profile");
        assert!(has_h50, "H50 WARN must fire under mtp3550_interop profile");
    }
}
