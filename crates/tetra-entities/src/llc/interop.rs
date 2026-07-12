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
//! Call [`log_enabled_interop_gates`] from `bluestation-bs`' boot path after
//! config load, before any packet-data traffic starts.
//!
//! See `Docs/interop-knobs.md` for the operator-facing catalog.

use tetra_config::bluestation::CfgLlc;

/// Emit one WARN log per currently-enabled interop gate. Silent when the LLC
/// config is at spec-compliant defaults.
///
/// Returns the count of enabled gates (useful for observability metrics).
pub fn log_enabled_interop_gates(cfg: &CfgLlc) -> usize {
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
            "interop gate enabled: N.273=0 on ACK link coerced to N.274 (spec-noncompliant)"
        );
        count += 1;
    }

    // H49: on receipt of an already-delivered N(S), re-ACK without redelivery.
    // Spec: §22.3.3.2.7 NOTE 6 permits/expects this behavior for below-window
    // TL-SDUs; this gate simply turns the strategy on/off. Kept as a gate so
    // operators can disable during debugging when the dedupe interferes with
    // reproducing a bug.
    // Not currently WARN-worthy (spec-legal), but included in the operator
    // knob catalog. Change to warn! if operator visibility becomes needed.

    // H50: RX-side transfer state cleared on H47 cached-echo re-emission.
    // Similarly spec-legal (Frankenstein-SDU prevention); not warned.

    count
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tetra_config::bluestation::{CfgAdvancedLink, CfgLlc};
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
        target: String,
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
                target: md.target().to_string(),
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

    /// T6: WARN log fires when `n273_zero_ack_uses_seg_cap` is enabled.
    #[test]
    fn t6_warn_log_when_n273_zero_ack_uses_seg_cap_enabled() {
        let capture = CaptureSubscriber::default();
        let sub = capture.clone();
        subscriber::with_default(sub, || {
            let mut cfg = CfgLlc::default();
            cfg.advanced_link = CfgAdvancedLink {
                n273_zero_ack_uses_seg_cap: true,
                ..CfgAdvancedLink::default()
            };
            let n = log_enabled_interop_gates(&cfg);
            assert_eq!(n, 1, "exactly one gate reported");
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

    /// T7: no WARN log about interop gates when all defaults are used.
    #[test]
    fn t7_no_warn_log_when_all_defaults() {
        let capture = CaptureSubscriber::default();
        let sub = capture.clone();
        subscriber::with_default(sub, || {
            let cfg = CfgLlc::default();
            let n = log_enabled_interop_gates(&cfg);
            assert_eq!(n, 0, "no gates should be enabled by default");
        });
        let events = capture.events.lock().unwrap();
        let interop_warns = events.iter()
            .filter(|e| e.level == tracing::Level::WARN
                && e.fields.get("gate").is_some())
            .count();
        assert_eq!(interop_warns, 0,
            "T7: no WARN 'interop gate' log expected at spec-compliant defaults");
    }
}
