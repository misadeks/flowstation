//! WSP — Wireless Session Protocol (WAP-230).
//!
//! Layered on top of WTP: every completed Class-2 Invoke carries a WSP PDU
//! (Connect / Get / Post / …), and the reply we emit as the WTP Result
//! carries a WSP PDU too (ConnectReply / Reply / …).
//!
//! # Sub-modules
//!
//! * [`uintvar`] — WAP-230 §8.1.2 base-128 variable-length integer codec.
//! * [`caps`]    — WSP capability list codec (§8.2.4), including the
//!   Openwave-quirk-preserving well-known variants.
//! * [`pdu`]     — Connect / ConnectReply / Reply / Disconnect PDU codec.
//! * [`session`] — per-`(peer, session-id)` session state machine and the
//!   WTP-handler adapter that dispatches PDUs to it.

pub mod caps;
pub mod pdu;
pub mod session;
pub mod uintvar;

/// How the gateway builds the capability list in an outbound WSP ConnectReply.
///
/// PD-11-H1 (2026-07-12): the choice is genuinely MS-firmware-dependent.
/// `caps.rs` and `lib.rs` document that Motorola MTP3550 / UP.Browser 6.3
/// **rejects the session and re-Invokes on ~40 s loop** when we strip the
/// Openwave-quirky capabilities (Protocol-Options `0xF0`, Extended-Method
/// `x-up-1`). PD-10b-H5 later switched to Kannel-style sanitization on the
/// theory that echoing capabilities we can't service is dishonest — that
/// fixed one firmware revision and re-broke others. Making it a config
/// knob lets operators flip on hardware without recompiling.
///
/// Default is [`Self::VerbatimEcho`] because that's what the older
/// `caps.rs::Openwave quirk` note and `lib.rs::Motivation` block explicitly
/// call out as the tested-working behaviour for UP.Browser 6.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WspCapabilityMode {
    /// Echo every MS-proposed capability back byte-for-byte. Matches what
    /// `caps.rs` / `lib.rs` document as tested-working for UP.Browser 6.3
    /// on Motorola MTP3550.
    VerbatimEcho,
    /// Kannel `sanitize_capabilities()` parity: clear top 4 bits of
    /// Protocol-Options, refuse Extended-Methods / Header-Code-Pages with
    /// an empty payload. Historic PD-10b-H5 default that stopped working
    /// against newer / different UP.Browser builds.
    Sanitize,
}

impl Default for WspCapabilityMode {
    fn default() -> Self {
        Self::VerbatimEcho
    }
}

impl std::fmt::Display for WspCapabilityMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::VerbatimEcho => f.write_str("verbatim_echo"),
            Self::Sanitize => f.write_str("sanitize"),
        }
    }
}

impl std::str::FromStr for WspCapabilityMode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "verbatim_echo" | "verbatim" => Ok(Self::VerbatimEcho),
            "sanitize" | "kannel" => Ok(Self::Sanitize),
            other => Err(format!(
                "unknown wsp_capability_mode {other:?}: expected 'verbatim_echo' or 'sanitize'"
            )),
        }
    }
}
