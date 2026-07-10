//! WTP — Wireless Transaction Protocol (WAP-201).
//!
//! Currently exposes the pure PDU codec (PD-10a-2). The responder state
//! machine lands in PD-10a-3.

pub mod pdu;

pub use pdu::{PduType, WtpPdu};
