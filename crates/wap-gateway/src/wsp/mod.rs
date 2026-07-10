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
pub mod uintvar;
