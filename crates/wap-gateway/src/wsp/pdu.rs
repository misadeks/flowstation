//! WSP PDU codec (WAP-230 §8.2).
//!
//! Only the four PDU types we actually see in the PD-10b Connect exchange
//! are modelled here as typed variants:
//!
//! * [`WspPdu::Connect`]      — MS → gateway, opens a session.
//! * [`WspPdu::ConnectReply`] — gateway → MS, accepts the session.
//! * [`WspPdu::Disconnect`]   — either party, tears down a session.
//! * [`WspPdu::Reply`]        — gateway → MS, response to Get / Post.
//!
//! Anything else (Get, Post, Resume, …) decodes to [`WspPdu::Unknown`] with
//! the raw payload preserved so upper layers can log it and answer with a
//! `Reply` status of 501 (Not Implemented) — that stub arrives in PD-10c.
//!
//! # Connect PDU on the wire (WAP-230 §8.2.2.1)
//!
//! ```text
//!   Type           = 0x01
//!   Version        = 1 uint8      (0x10 = protocol version 1.0)
//!   CapabilitiesLength uintvar
//!   HeadersLength      uintvar
//!   Capabilities   = <CapabilitiesLength> bytes  (see [`crate::wsp::caps`])
//!   Headers        = <HeadersLength> bytes       (opaque here; see [`Header`])
//! ```
//!
//! # ConnectReply PDU (WAP-230 §8.2.2.2)
//!
//! ```text
//!   Type           = 0x02
//!   ServerSessionId  uintvar
//!   CapabilitiesLength uintvar
//!   HeadersLength      uintvar
//!   Capabilities
//!   Headers
//! ```
//!
//! # Headers
//!
//! WAP-230 §8.4 defines a wire-compact header encoding using well-known
//! header codes and value tokens. For PD-10b we do not need to interpret
//! most headers — we only need to be able to (a) decode the block
//! non-destructively enough to spot a few well-known names we care about
//! (Encoding-Version, User-Agent, Accept-Language, Profile), and (b)
//! preserve the raw bytes of every other header so we can echo them or
//! ignore them safely. The [`HeaderBlock`] type keeps the original bytes
//! verbatim and offers small helpers to peek at well-known values.

use crate::error::{WapError, WapResult};
use crate::wsp::caps::{self, Capability};
use crate::wsp::uintvar;

/// WSP PDU type codes (WAP-230 §8.2.2). Only the ones we implement are named.
pub mod pdu_type {
    pub const CONNECT: u8 = 0x01;
    pub const CONNECT_REPLY: u8 = 0x02;
    pub const REDIRECT: u8 = 0x03;
    pub const REPLY: u8 = 0x04;
    pub const DISCONNECT: u8 = 0x05;
    pub const PUSH: u8 = 0x06;
    pub const CONFIRMED_PUSH: u8 = 0x07;
    pub const SUSPEND: u8 = 0x08;
    pub const RESUME: u8 = 0x09;
    // 0x40..=0x5F: Get variants (Get / Options / Head / Delete / Trace).
    pub const GET: u8 = 0x40;
    // 0x60..=0x7F: Post variants.
    pub const POST: u8 = 0x60;
}

/// A WSP PDU as it appears on the wire between the MS and this gateway.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WspPdu {
    /// S-Connect — MS-initiated session establishment.
    Connect {
        /// Protocol version octet as sent (0x10 = 1.0 in practice).
        version: u8,
        capabilities: Vec<Capability>,
        headers: HeaderBlock,
    },
    /// S-ConnectReply — gateway acceptance, echoing (some / most of) the
    /// proposed capabilities.
    ConnectReply {
        server_session_id: u32,
        capabilities: Vec<Capability>,
        headers: HeaderBlock,
    },
    /// S-Disconnect — session teardown. Payload is the session id (uintvar).
    Disconnect { server_session_id: u32 },
    /// S-Reply — response to a method (Get / Post). PD-10c wires up the
    /// real HTTP relay; PD-10b only needs the encoder to answer "501 Not
    /// Implemented" for anything that isn't Connect.
    Reply { status: u8, headers: HeaderBlock, body: Vec<u8> },
    /// Any PDU type we haven't modelled — payload preserved verbatim.
    Unknown { pdu_type: u8, payload: Vec<u8> },
}

/// Opaque header block. WAP-230 §8.4 defines the internal encoding; we do
/// not need to interpret it for PD-10b, so this type just wraps the raw
/// bytes plus a couple of lookup helpers used by tests.
///
/// Preserving raw bytes is what lets us echo the block back on
/// ConnectReply / Reply without risking any lossy re-encoding.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HeaderBlock {
    pub raw: Vec<u8>,
}

impl HeaderBlock {
    pub fn empty() -> Self {
        Self { raw: Vec::new() }
    }

    pub fn from_bytes(raw: impl Into<Vec<u8>>) -> Self {
        Self { raw: raw.into() }
    }

    pub fn is_empty(&self) -> bool {
        self.raw.is_empty()
    }

    pub fn len(&self) -> usize {
        self.raw.len()
    }

    /// True iff `needle` appears verbatim as a byte substring anywhere in
    /// the header block. Used by the golden fixture test to check for
    /// e.g. `b"UP.Browser/6.3.0.1"` without a full header decoder.
    pub fn contains(&self, needle: &[u8]) -> bool {
        if needle.is_empty() || needle.len() > self.raw.len() {
            return needle.is_empty();
        }
        self.raw.windows(needle.len()).any(|w| w == needle)
    }
}

impl WspPdu {
    /// Decode a WSP PDU from the raw WTP user-payload.
    pub fn decode(bytes: &[u8]) -> WapResult<Self> {
        let pdu_type = *bytes.first().ok_or(WapError::Truncated { expected: 1, actual: 0 })?;
        let rest = &bytes[1..];
        match pdu_type {
            pdu_type::CONNECT => decode_connect(rest),
            pdu_type::CONNECT_REPLY => decode_connect_reply(rest),
            pdu_type::DISCONNECT => {
                let (sid, n) = uintvar::decode(rest)?;
                if n != rest.len() {
                    return Err(WapError::WspDecode(format!("Disconnect has {} trailing bytes", rest.len() - n)));
                }
                Ok(Self::Disconnect { server_session_id: sid })
            }
            pdu_type::REPLY => decode_reply(rest),
            other => Ok(Self::Unknown {
                pdu_type: other,
                payload: rest.to_vec(),
            }),
        }
    }

    /// Encode a WSP PDU as bytes suitable for the WTP user payload.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Self::Connect {
                version,
                capabilities,
                headers,
            } => {
                out.push(pdu_type::CONNECT);
                out.push(*version);
                let caps = caps::encode_list(capabilities);
                uintvar::encode(caps.len() as u32, &mut out);
                uintvar::encode(headers.len() as u32, &mut out);
                out.extend_from_slice(&caps);
                out.extend_from_slice(&headers.raw);
            }
            Self::ConnectReply {
                server_session_id,
                capabilities,
                headers,
            } => {
                out.push(pdu_type::CONNECT_REPLY);
                uintvar::encode(*server_session_id, &mut out);
                let caps = caps::encode_list(capabilities);
                uintvar::encode(caps.len() as u32, &mut out);
                uintvar::encode(headers.len() as u32, &mut out);
                out.extend_from_slice(&caps);
                out.extend_from_slice(&headers.raw);
            }
            Self::Disconnect { server_session_id } => {
                out.push(pdu_type::DISCONNECT);
                uintvar::encode(*server_session_id, &mut out);
            }
            Self::Reply { status, headers, body } => {
                out.push(pdu_type::REPLY);
                out.push(*status);
                uintvar::encode(headers.len() as u32, &mut out);
                out.extend_from_slice(&headers.raw);
                out.extend_from_slice(body);
            }
            Self::Unknown { pdu_type, payload } => {
                out.push(*pdu_type);
                out.extend_from_slice(payload);
            }
        }
        out
    }

    /// One-byte PDU type code.
    pub fn pdu_type_code(&self) -> u8 {
        match self {
            Self::Connect { .. } => pdu_type::CONNECT,
            Self::ConnectReply { .. } => pdu_type::CONNECT_REPLY,
            Self::Disconnect { .. } => pdu_type::DISCONNECT,
            Self::Reply { .. } => pdu_type::REPLY,
            Self::Unknown { pdu_type, .. } => *pdu_type,
        }
    }
}

// ── Decoders ─────────────────────────────────────────────────────────────────

fn decode_connect(rest: &[u8]) -> WapResult<WspPdu> {
    // Type is already consumed. `rest` starts at Version.
    let version = *rest.first().ok_or(WapError::Truncated { expected: 1, actual: 0 })?;
    let mut cursor = 1;
    let (caps_len, n) = uintvar::decode(&rest[cursor..])?;
    cursor += n;
    let (hdrs_len, n) = uintvar::decode(&rest[cursor..])?;
    cursor += n;
    let caps_end = cursor
        .checked_add(caps_len as usize)
        .ok_or_else(|| WapError::WspDecode("Connect caps length overflow".to_owned()))?;
    let hdrs_end = caps_end
        .checked_add(hdrs_len as usize)
        .ok_or_else(|| WapError::WspDecode("Connect headers length overflow".to_owned()))?;
    if rest.len() < hdrs_end {
        return Err(WapError::Truncated {
            expected: hdrs_end + 1, // +1 for the type byte the caller ate
            actual: rest.len() + 1,
        });
    }
    let capabilities = caps::decode_list(&rest[cursor..caps_end])?;
    let headers = HeaderBlock::from_bytes(&rest[caps_end..hdrs_end]);
    Ok(WspPdu::Connect {
        version,
        capabilities,
        headers,
    })
}

fn decode_connect_reply(rest: &[u8]) -> WapResult<WspPdu> {
    let (sid, n) = uintvar::decode(rest)?;
    let mut cursor = n;
    let (caps_len, n) = uintvar::decode(&rest[cursor..])?;
    cursor += n;
    let (hdrs_len, n) = uintvar::decode(&rest[cursor..])?;
    cursor += n;
    let caps_end = cursor + caps_len as usize;
    let hdrs_end = caps_end + hdrs_len as usize;
    if rest.len() < hdrs_end {
        return Err(WapError::Truncated {
            expected: hdrs_end + 1,
            actual: rest.len() + 1,
        });
    }
    let capabilities = caps::decode_list(&rest[cursor..caps_end])?;
    let headers = HeaderBlock::from_bytes(&rest[caps_end..hdrs_end]);
    Ok(WspPdu::ConnectReply {
        server_session_id: sid,
        capabilities,
        headers,
    })
}

fn decode_reply(rest: &[u8]) -> WapResult<WspPdu> {
    let status = *rest.first().ok_or(WapError::Truncated { expected: 1, actual: 0 })?;
    let (hdrs_len, n) = uintvar::decode(&rest[1..])?;
    let hdrs_start = 1 + n;
    let hdrs_end = hdrs_start
        .checked_add(hdrs_len as usize)
        .ok_or_else(|| WapError::WspDecode("Reply headers length overflow".to_owned()))?;
    if rest.len() < hdrs_end {
        return Err(WapError::Truncated {
            expected: hdrs_end + 1,
            actual: rest.len() + 1,
        });
    }
    Ok(WspPdu::Reply {
        status,
        headers: HeaderBlock::from_bytes(&rest[hdrs_start..hdrs_end]),
        body: rest[hdrs_end..].to_vec(),
    })
}

// ── Builders ─────────────────────────────────────────────────────────────────

/// Build the ConnectReply that answers a given Connect. The reply echoes
/// **every** capability the MS proposed, verbatim — this is the whole
/// point of PD-10b, since Kannel's `sanitize_capabilities()` strips the
/// Openwave-specific caps and breaks UP.Browser.
///
/// `server_session_id` is chosen by the gateway (see [`crate::wsp::session`]).
/// `headers` is what we want to echo back to the MS in the header block;
/// callers typically pass [`HeaderBlock::empty`] for now — WSP allows an
/// empty header block on ConnectReply and Kannel does the same in practice.
pub fn build_connect_reply(connect: &WspPdu, server_session_id: u32, headers: HeaderBlock) -> WapResult<WspPdu> {
    let capabilities = match connect {
        WspPdu::Connect { capabilities, .. } => capabilities.clone(),
        other => {
            return Err(WapError::WspDecode(format!(
                "build_connect_reply called with non-Connect PDU {:?}",
                other.pdu_type_code()
            )));
        }
    };
    Ok(WspPdu::ConnectReply {
        server_session_id,
        capabilities,
        headers,
    })
}

/// Build a WSP Reply carrying an HTTP-style status code and no body.
/// Used by PD-10b's stub handler to answer any non-Connect PDU with
/// `501 Not Implemented`. Status codes follow WAP-230 §8.7.3 (they are
/// abbreviated forms of HTTP status codes).
pub fn build_status_reply(status: u8) -> WspPdu {
    WspPdu::Reply {
        status,
        headers: HeaderBlock::empty(),
        body: Vec::new(),
    }
}

/// WAP-230 §8.7.3.5 — Status = "Not Implemented".
pub const STATUS_NOT_IMPLEMENTED: u8 = 0x60;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_disconnect() {
        let pdu = WspPdu::Disconnect { server_session_id: 42 };
        let bytes = pdu.encode();
        assert_eq!(bytes, vec![0x05, 42]);
        assert_eq!(WspPdu::decode(&bytes).unwrap(), pdu);
    }

    #[test]
    fn round_trips_reply_stub() {
        let pdu = build_status_reply(STATUS_NOT_IMPLEMENTED);
        let bytes = pdu.encode();
        let back = WspPdu::decode(&bytes).unwrap();
        assert_eq!(back, pdu);
    }

    #[test]
    fn unknown_pdu_preserves_bytes() {
        let bytes = [0x40, 0xAA, 0xBB, 0xCC];
        let pdu = WspPdu::decode(&bytes).unwrap();
        assert_eq!(
            pdu,
            WspPdu::Unknown {
                pdu_type: 0x40,
                payload: vec![0xAA, 0xBB, 0xCC],
            }
        );
        assert_eq!(pdu.encode(), bytes);
    }

    #[test]
    fn build_connect_reply_echoes_capabilities_verbatim() {
        // Hand-craft a minimal Connect with the two Openwave-critical caps.
        let connect = WspPdu::Connect {
            version: 0x10,
            capabilities: vec![
                Capability::ProtocolOptions(0xF0),
                Capability::ExtendedMethods(vec![(0x10, b"x-up-1".to_vec())]),
            ],
            headers: HeaderBlock::empty(),
        };
        let reply = build_connect_reply(&connect, 1, HeaderBlock::empty()).unwrap();
        let WspPdu::ConnectReply { capabilities, .. } = &reply else {
            panic!("build_connect_reply returned non-ConnectReply: {reply:?}");
        };
        assert_eq!(capabilities.len(), 2);
        assert_eq!(capabilities[0], Capability::ProtocolOptions(0xF0));
        assert_eq!(capabilities[1], Capability::ExtendedMethods(vec![(0x10, b"x-up-1".to_vec())]));
    }

    #[test]
    fn decode_rejects_empty_input() {
        assert!(matches!(WspPdu::decode(&[]), Err(WapError::Truncated { .. })));
    }

    #[test]
    fn decode_rejects_truncated_connect() {
        // Type=Connect, version=0x10, caps-len=5, headers-len=0, only 1 cap-byte.
        let bytes = [0x01, 0x10, 0x05, 0x00, 0xAA];
        assert!(matches!(WspPdu::decode(&bytes), Err(WapError::Truncated { .. })));
    }

    #[test]
    fn header_block_contains_finds_substrings() {
        let hb = HeaderBlock::from_bytes(b"...UP.Browser/6.3.0.1...".to_vec());
        assert!(hb.contains(b"UP.Browser/6.3.0.1"));
        assert!(!hb.contains(b"MSIE"));
        assert!(hb.contains(b"")); // empty needle is trivially present
    }
}
