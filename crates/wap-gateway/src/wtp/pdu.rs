//! WTP PDU codec — WAP-201 §8.
//!
//! Pure encode / decode of on-wire bytes. No I/O, no state machine, no
//! logging: this file must stay easily unit-testable and (later) fuzzable.
//!
//! # Fixed header (3 octets, shared by every WTP PDU)
//!
//! ```text
//!  octet 0   | 7 | 6 5 4 3 |  2  |  1  |  0  |
//!            | C |  Type   | GTR | TTR | RID |
//!  octet 1-2 |             TID (16 bit BE)              |
//! ```
//!
//! * **C** — *Continue* flag: 1 means another PDU is concatenated in the
//!   same UDP datagram (unused by v0.1, decoded but rejected).
//! * **Type** — 4-bit PDU Type; see [`PduType`].
//! * **GTR** — *Group Trailer*: last segment of a group when SAR is in use.
//! * **TTR** — *Transmission Trailer*: last segment overall.
//! * **RID** — *Retransmission Indicator*: 1 on retransmissions.
//! * **TID** — 16-bit transaction identifier. Top bit is not special at the
//!   WTP fixed-header layer (the "TIDnew" flag lives in the Invoke type-
//!   specific header). We expose it as a `u16` verbatim.
//!
//! # Per-type extensions
//!
//! **Invoke** (Type = 1) adds one octet:
//! ```text
//!  octet 3 | 7 6 | 5 | 4 |  3  2  | 1 0 |
//!          | Ver | T | UP| Reserv | TCL |
//! ```
//! Ver = 0 (WAP 1.x). T = "TIDnew" flag. UP = "User acknowledgement".
//! TCL = Transaction Class (0/1/2).
//!
//! **Result** (Type = 2) — no extra octet; user data follows the fixed header.
//!
//! **Ack** (Type = 3) adds one octet:
//! ```text
//!  octet 3 | 7 | 6 5 4 3 2 1 0 |
//!          |TVE|   Reserved    |
//! ```
//! TVE = 1 indicates one or more TPIs follow (unsupported in v0.1 — we
//! decode/encode with TVE=0).
//!
//! **Abort** (Type = 4) adds two octets:
//! ```text
//!  octet 3  | 7 6 5 4 | 3 2 1 0 |
//!           | AbortT  | Reserv  |
//!  octet 4  |    Abort Reason   |
//! ```
//! AbortT: 0 = Provider, 1 = User.
//!
//! **Segmented Invoke** (Type = 5) / **Segmented Result** (Type = 6) add one
//! octet: `PSN` (Packet Sequence Number) — segment 0 is the initial
//! Invoke/Result PDU, segment 1 is the first Segmented\* PDU, and so on.
//!
//! **Negative Ack** (Type = 7) adds one octet count followed by that many PSNs;
//! not implemented in v0.1 (decoded to `NegativeAck { .. }` with the raw
//! missing-list preserved so we can log it, but the responder ignores it).

#![allow(clippy::unusual_byte_groupings)]

use crate::error::{WapError, WapResult};

// ── PDU type codes (WAP-201 §8.1) ─────────────────────────────────────────────

/// WTP PDU type field — 4 bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PduType {
    Invoke = 1,
    Result = 2,
    Ack = 3,
    Abort = 4,
    SegmentedInvoke = 5,
    SegmentedResult = 6,
    NegativeAck = 7,
}

impl PduType {
    fn from_bits(bits: u8) -> WapResult<Self> {
        Ok(match bits {
            1 => Self::Invoke,
            2 => Self::Result,
            3 => Self::Ack,
            4 => Self::Abort,
            5 => Self::SegmentedInvoke,
            6 => Self::SegmentedResult,
            7 => Self::NegativeAck,
            other => {
                return Err(WapError::WtpDecode(format!("unknown WTP PDU type: {other}")));
            }
        })
    }
}

// ── Transaction class ────────────────────────────────────────────────────────

/// WTP Transaction Class (WAP-201 §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TransactionClass {
    /// Class 0 — unconfirmed. No response, no ack.
    Class0 = 0,
    /// Class 1 — reliable Invoke, no Result.
    Class1 = 1,
    /// Class 2 — reliable Invoke + reliable Result (the one we support).
    Class2 = 2,
}

impl TransactionClass {
    fn from_bits(bits: u8) -> WapResult<Self> {
        Ok(match bits & 0b11 {
            0 => Self::Class0,
            1 => Self::Class1,
            2 => Self::Class2,
            _ => {
                return Err(WapError::WtpDecode("invalid WTP transaction class 3".into()));
            }
        })
    }
}

// ── Fixed-header helper bits ─────────────────────────────────────────────────

/// The three trailer / retransmission flags in octet 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HeaderFlags {
    pub gtr: bool,
    pub ttr: bool,
    pub rid: bool,
}

impl HeaderFlags {
    fn from_octet0(o0: u8) -> Self {
        Self {
            gtr: (o0 & 0b0000_0100) != 0,
            ttr: (o0 & 0b0000_0010) != 0,
            rid: (o0 & 0b0000_0001) != 0,
        }
    }

    fn into_octet0_bits(self) -> u8 {
        (u8::from(self.gtr) << 2) | (u8::from(self.ttr) << 1) | u8::from(self.rid)
    }
}

// ── Abort codes ──────────────────────────────────────────────────────────────

/// WTP Abort *type* — Provider (0) vs. User (1) origin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AbortType {
    Provider = 0,
    User = 1,
}

impl AbortType {
    fn from_nibble(n: u8) -> WapResult<Self> {
        Ok(match n & 0x0F {
            0 => Self::Provider,
            1 => Self::User,
            other => {
                return Err(WapError::WtpDecode(format!("invalid WTP abort type {other}")));
            }
        })
    }
}

/// Common Provider-side abort reason codes (WAP-201 §9.7). Kept as `u8` to
/// preserve unknown values from the peer for logging.
#[allow(dead_code)]
pub mod abort_reason {
    pub const UNKNOWN: u8 = 0x00;
    pub const PROTOERR: u8 = 0x01;
    pub const INVALIDTID: u8 = 0x02;
    pub const NOTIMPLEMENTEDCL2: u8 = 0x03;
    pub const NOTIMPLEMENTEDSAR: u8 = 0x04;
    pub const NOTIMPLEMENTEDUACK: u8 = 0x05;
    pub const WTPVERSIONZERO: u8 = 0x06;
    pub const CAPTEMPEXCEEDED: u8 = 0x07;
    pub const NORESPONSE: u8 = 0x08;
    pub const MESSAGETOOLARGE: u8 = 0x09;
}

// ── High-level PDU ADT ───────────────────────────────────────────────────────

/// A decoded (or to-be-encoded) WTP PDU.
///
/// Byte layout is documented on each variant. Round-trip: for every PDU
/// `p`, `decode(&encode(&p))` returns a PDU equal to `p` (see tests).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WtpPdu {
    /// S-Invoke — starts a class 0/1/2 transaction.
    Invoke {
        flags: HeaderFlags,
        tid: u16,
        version: u8,
        tid_new: bool,
        user_ack: bool,
        class: TransactionClass,
        /// User data (WSP PDU for our use case).
        payload: Vec<u8>,
    },
    /// S-Result — carries the response for class 2 (and 1 with UACK=0 only
    /// occasionally). Follows a matching Invoke on the same TID.
    Result { flags: HeaderFlags, tid: u16, payload: Vec<u8> },
    /// Ack — either acknowledges an Invoke (from responder) or a Result
    /// (from initiator).
    Ack { flags: HeaderFlags, tid: u16, tve: bool },
    /// Abort — either party may send. Terminates the transaction.
    Abort {
        flags: HeaderFlags,
        tid: u16,
        abort_type: AbortType,
        reason: u8,
    },
    /// Segmented Invoke — SAR continuation of an Invoke.
    SegmentedInvoke {
        flags: HeaderFlags,
        tid: u16,
        psn: u8,
        payload: Vec<u8>,
    },
    /// Segmented Result — SAR continuation of a Result.
    SegmentedResult {
        flags: HeaderFlags,
        tid: u16,
        psn: u8,
        payload: Vec<u8>,
    },
    /// Negative Ack — decoded verbatim so we can log missing-list; not
    /// generated by us in v0.1.
    NegativeAck {
        flags: HeaderFlags,
        tid: u16,
        missing_psns: Vec<u8>,
    },
}

impl WtpPdu {
    pub fn pdu_type(&self) -> PduType {
        match self {
            Self::Invoke { .. } => PduType::Invoke,
            Self::Result { .. } => PduType::Result,
            Self::Ack { .. } => PduType::Ack,
            Self::Abort { .. } => PduType::Abort,
            Self::SegmentedInvoke { .. } => PduType::SegmentedInvoke,
            Self::SegmentedResult { .. } => PduType::SegmentedResult,
            Self::NegativeAck { .. } => PduType::NegativeAck,
        }
    }

    pub fn tid(&self) -> u16 {
        match self {
            Self::Invoke { tid, .. }
            | Self::Result { tid, .. }
            | Self::Ack { tid, .. }
            | Self::Abort { tid, .. }
            | Self::SegmentedInvoke { tid, .. }
            | Self::SegmentedResult { tid, .. }
            | Self::NegativeAck { tid, .. } => *tid,
        }
    }

    // ── Encoding ────────────────────────────────────────────────────────────

    /// Serialize this PDU into the provided sink.
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        let (ty, flags) = (self.pdu_type() as u8, self.header_flags());
        let octet0 = (ty << 3) | flags.into_octet0_bits();
        out.push(octet0);
        out.extend_from_slice(&self.tid().to_be_bytes());

        match self {
            Self::Invoke {
                version,
                tid_new,
                user_ack,
                class,
                payload,
                ..
            } => {
                let octet3 = ((version & 0b11) << 6) | (u8::from(*tid_new) << 5) | (u8::from(*user_ack) << 4) | (*class as u8 & 0b11);
                out.push(octet3);
                out.extend_from_slice(payload);
            }
            Self::Result { payload, .. } => {
                out.extend_from_slice(payload);
            }
            Self::Ack { tve, .. } => {
                out.push(u8::from(*tve) << 7);
            }
            Self::Abort { abort_type, reason, .. } => {
                // Abort type occupies bits 7-4; low nibble reserved.
                out.push(((*abort_type as u8) & 0x0F) << 4);
                out.push(*reason);
            }
            Self::SegmentedInvoke { psn, payload, .. } | Self::SegmentedResult { psn, payload, .. } => {
                out.push(*psn);
                out.extend_from_slice(payload);
            }
            Self::NegativeAck { missing_psns, .. } => {
                out.push(missing_psns.len() as u8);
                out.extend_from_slice(missing_psns);
            }
        }
    }

    /// Convenience: encode into a fresh `Vec<u8>`.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(8 + self.payload_len_hint());
        self.encode_into(&mut buf);
        buf
    }

    fn payload_len_hint(&self) -> usize {
        match self {
            Self::Invoke { payload, .. }
            | Self::Result { payload, .. }
            | Self::SegmentedInvoke { payload, .. }
            | Self::SegmentedResult { payload, .. } => payload.len(),
            _ => 0,
        }
    }

    fn header_flags(&self) -> HeaderFlags {
        match self {
            Self::Invoke { flags, .. }
            | Self::Result { flags, .. }
            | Self::Ack { flags, .. }
            | Self::Abort { flags, .. }
            | Self::SegmentedInvoke { flags, .. }
            | Self::SegmentedResult { flags, .. }
            | Self::NegativeAck { flags, .. } => *flags,
        }
    }

    // ── Decoding ────────────────────────────────────────────────────────────

    /// Parse a single WTP PDU from the beginning of `bytes`.
    ///
    /// Returns `Err(WapError::WtpDecode)` if the bytes are shorter than the
    /// PDU requires, or if the type / class fields are invalid. Trailing bytes
    /// after the PDU's user data (if any) are consumed into the payload.
    pub fn decode(bytes: &[u8]) -> WapResult<Self> {
        if bytes.len() < 3 {
            return Err(WapError::Truncated {
                expected: 3,
                actual: bytes.len(),
            });
        }
        let o0 = bytes[0];
        if (o0 & 0b1000_0000) != 0 {
            // Con flag: v0.1 does not implement PDU concatenation.
            return Err(WapError::WtpDecode("concatenated PDUs (Con=1) not supported in v0.1".into()));
        }
        let ty = PduType::from_bits((o0 >> 3) & 0x0F)?;
        let flags = HeaderFlags::from_octet0(o0);
        let tid = u16::from_be_bytes([bytes[1], bytes[2]]);
        let rest = &bytes[3..];

        Ok(match ty {
            PduType::Invoke => {
                if rest.is_empty() {
                    return Err(WapError::Truncated {
                        expected: 4,
                        actual: bytes.len(),
                    });
                }
                let o3 = rest[0];
                let version = (o3 >> 6) & 0b11;
                let tid_new = (o3 & 0b0010_0000) != 0;
                let user_ack = (o3 & 0b0001_0000) != 0;
                let class = TransactionClass::from_bits(o3)?;
                Self::Invoke {
                    flags,
                    tid,
                    version,
                    tid_new,
                    user_ack,
                    class,
                    payload: rest[1..].to_vec(),
                }
            }
            PduType::Result => Self::Result {
                flags,
                tid,
                payload: rest.to_vec(),
            },
            PduType::Ack => {
                // Ack MAY be 3 octets (no TVE nibble) on some Openwave stacks;
                // real UP.Browser observed both. Tolerate either length.
                let tve = rest.first().is_some_and(|b| (*b & 0b1000_0000) != 0);
                Self::Ack { flags, tid, tve }
            }
            PduType::Abort => {
                if rest.len() < 2 {
                    return Err(WapError::Truncated {
                        expected: 5,
                        actual: bytes.len(),
                    });
                }
                Self::Abort {
                    flags,
                    tid,
                    abort_type: AbortType::from_nibble(rest[0] >> 4)?,
                    reason: rest[1],
                }
            }
            PduType::SegmentedInvoke | PduType::SegmentedResult => {
                if rest.is_empty() {
                    return Err(WapError::Truncated {
                        expected: 4,
                        actual: bytes.len(),
                    });
                }
                let psn = rest[0];
                let payload = rest[1..].to_vec();
                if matches!(ty, PduType::SegmentedInvoke) {
                    Self::SegmentedInvoke { flags, tid, psn, payload }
                } else {
                    Self::SegmentedResult { flags, tid, psn, payload }
                }
            }
            PduType::NegativeAck => {
                if rest.is_empty() {
                    return Err(WapError::Truncated {
                        expected: 4,
                        actual: bytes.len(),
                    });
                }
                let n = rest[0] as usize;
                if rest.len() < 1 + n {
                    return Err(WapError::Truncated {
                        expected: 4 + n,
                        actual: bytes.len(),
                    });
                }
                Self::NegativeAck {
                    flags,
                    tid,
                    missing_psns: rest[1..1 + n].to_vec(),
                }
            }
        })
    }
}

// ── Convenience constructors ─────────────────────────────────────────────────

impl WtpPdu {
    /// Build a responder Ack (TTR=1 by default; a positive final Ack).
    pub fn ack(tid: u16) -> Self {
        Self::Ack {
            flags: HeaderFlags {
                gtr: false,
                ttr: true,
                rid: false,
            },
            tid,
            tve: false,
        }
    }

    /// Build a single-segment Result. Set TTR=true to mark it terminal.
    pub fn result(tid: u16, payload: Vec<u8>) -> Self {
        Self::Result {
            flags: HeaderFlags {
                gtr: false,
                ttr: true,
                rid: false,
            },
            tid,
            payload,
        }
    }

    /// Build a Provider-side Abort.
    pub fn provider_abort(tid: u16, reason: u8) -> Self {
        Self::Abort {
            flags: HeaderFlags {
                gtr: false,
                ttr: true,
                rid: false,
            },
            tid,
            abort_type: AbortType::Provider,
            reason,
        }
    }
}

// ── Round-trip tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn rt(pdu: &WtpPdu) {
        let bytes = pdu.encode();
        let back = WtpPdu::decode(&bytes).expect("decode round-trip");
        assert_eq!(&back, pdu, "round-trip mismatch\n  bytes={bytes:02x?}");
    }

    #[test]
    fn invoke_class2_roundtrip() {
        rt(&WtpPdu::Invoke {
            flags: HeaderFlags {
                gtr: false,
                ttr: true,
                rid: false,
            },
            tid: 0x1234,
            version: 0,
            tid_new: true,
            user_ack: false,
            class: TransactionClass::Class2,
            payload: vec![0x01, 0x02, 0x03],
        });
    }

    #[test]
    fn invoke_class0_no_payload_roundtrip() {
        rt(&WtpPdu::Invoke {
            flags: HeaderFlags::default(),
            tid: 0x0001,
            version: 0,
            tid_new: false,
            user_ack: false,
            class: TransactionClass::Class0,
            payload: vec![],
        });
    }

    #[test]
    fn result_roundtrip() {
        rt(&WtpPdu::Result {
            flags: HeaderFlags {
                gtr: false,
                ttr: true,
                rid: false,
            },
            tid: 0xABCD,
            payload: vec![0xDE, 0xAD, 0xBE, 0xEF],
        });
    }

    #[test]
    fn ack_roundtrip() {
        rt(&WtpPdu::ack(0x5678));
    }

    #[test]
    fn ack_with_rid_roundtrip() {
        rt(&WtpPdu::Ack {
            flags: HeaderFlags {
                gtr: false,
                ttr: true,
                rid: true,
            },
            tid: 0x0042,
            tve: false,
        });
    }

    #[test]
    fn abort_roundtrip() {
        rt(&WtpPdu::provider_abort(0x1111, abort_reason::INVALIDTID));
        rt(&WtpPdu::Abort {
            flags: HeaderFlags::default(),
            tid: 0x2222,
            abort_type: AbortType::User,
            reason: 0x81,
        });
    }

    #[test]
    fn segmented_result_roundtrip() {
        rt(&WtpPdu::SegmentedResult {
            flags: HeaderFlags {
                gtr: true,
                ttr: false,
                rid: false,
            },
            tid: 0x0100,
            psn: 3,
            payload: vec![0xAA; 200],
        });
    }

    #[test]
    fn segmented_invoke_roundtrip() {
        rt(&WtpPdu::SegmentedInvoke {
            flags: HeaderFlags {
                gtr: true,
                ttr: true,
                rid: false,
            },
            tid: 0x0300,
            psn: 5,
            payload: vec![0x55; 32],
        });
    }

    #[test]
    fn negative_ack_roundtrip() {
        rt(&WtpPdu::NegativeAck {
            flags: HeaderFlags::default(),
            tid: 0x00FF,
            missing_psns: vec![1, 4, 7],
        });
    }

    #[test]
    fn decode_rejects_short_buffer() {
        assert!(matches!(WtpPdu::decode(&[0x0A]), Err(WapError::Truncated { .. })));
    }

    #[test]
    fn decode_rejects_concatenated_pdus() {
        // Con=1 (top bit), Type=Invoke, TID=1, dummy octet3
        let bytes = [0b1_0001_000, 0x00, 0x01, 0b00_1_0_00_10];
        assert!(matches!(WtpPdu::decode(&bytes), Err(WapError::WtpDecode(_))));
    }

    #[test]
    fn decode_rejects_unknown_type() {
        // Type=0 is "not used" in the spec.
        let bytes = [0b0_0000_000, 0x00, 0x01];
        assert!(matches!(WtpPdu::decode(&bytes), Err(WapError::WtpDecode(_))));
    }

    #[test]
    fn ack_short_form_decodes() {
        // Some real UP.Browser Acks omit the TVE octet: only 3 bytes total.
        let bytes = [0b0_0011_010, 0x12, 0x34]; // Type=3 (Ack), TTR=1
        let pdu = WtpPdu::decode(&bytes).unwrap();
        assert_eq!(pdu, WtpPdu::ack(0x1234));
    }

    #[test]
    fn invoke_header_flags_encode_bits() {
        let pdu = WtpPdu::Invoke {
            flags: HeaderFlags {
                gtr: true,
                ttr: true,
                rid: false,
            },
            tid: 0x0000,
            version: 0,
            tid_new: true,
            user_ack: false,
            class: TransactionClass::Class2,
            payload: vec![],
        };
        let bytes = pdu.encode();
        //   type=1 shifted << 3 = 0b0000_1000, GTR|TTR = 0b0000_0110
        assert_eq!(bytes[0], 0b0000_1110);
        //   version=0, TIDnew=1, UP=0, class=2
        assert_eq!(bytes[3], 0b00_1_0_00_10);
    }
}
