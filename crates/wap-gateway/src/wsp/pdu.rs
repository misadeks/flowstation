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
    // 0x40..=0x5F: GET-like methods (Get / Options / Head / Delete / Trace + extended).
    pub const GET: u8 = 0x40;
    pub const OPTIONS: u8 = 0x41;
    pub const HEAD: u8 = 0x42;
    pub const DELETE: u8 = 0x43;
    pub const TRACE: u8 = 0x44;
    // 0x60..=0x7F: POST-like methods (Post / Put + extended).
    pub const POST: u8 = 0x60;
    pub const PUT: u8 = 0x61;

    /// True iff `code` is in the GET-like method range (0x40..=0x5F).
    /// GET-like methods share the wire format `[code][uri-len][uri][headers]`.
    pub fn is_get_like(code: u8) -> bool {
        (0x40..=0x5F).contains(&code)
    }
    /// True iff `code` is in the POST-like method range (0x60..=0x7F).
    /// POST-like methods add `content-type` + `data` after the URI.
    pub fn is_post_like(code: u8) -> bool {
        (0x60..=0x7F).contains(&code)
    }
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
    /// S-MethodInvoke for a GET-like method (0x40..=0x5F). Wire format is
    /// `[type][uri-len uintvar][uri][headers]` where `headers` implicitly
    /// consumes the rest of the PDU (WAP-230 §8.5.2). PD-10c dispatches
    /// `Get` (0x40) to the HTTP relay; other codes are answered 405.
    MethodInvoke {
        method_code: u8,
        uri: String,
        headers: HeaderBlock,
    },
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
            code if pdu_type::is_get_like(code) => decode_get_like(code, rest),
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
            Self::MethodInvoke { method_code, uri, headers } => {
                out.push(*method_code);
                uintvar::encode(uri.len() as u32, &mut out);
                out.extend_from_slice(uri.as_bytes());
                out.extend_from_slice(&headers.raw);
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
            Self::MethodInvoke { method_code, .. } => *method_code,
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

/// Decode a GET-like method PDU (WAP-230 §8.5.2). Wire format:
///
/// ```text
///   [type] [URI-length uintvar] [URI bytes] [headers ...]
/// ```
///
/// `headers` implicitly consumes the rest of the PDU (there is no explicit
/// headers-length field for GET-like methods). If nothing follows the URI —
/// which is what MTP3550 / UP.Browser 6.3 does in the observed capture —
/// the header block is empty. The URI is ASCII per WAP-230, never
/// NUL-terminated on the wire.
fn decode_get_like(method_code: u8, rest: &[u8]) -> WapResult<WspPdu> {
    let (uri_len, n) = uintvar::decode(rest)?;
    let uri_start = n;
    let uri_end = uri_start
        .checked_add(uri_len as usize)
        .ok_or_else(|| WapError::WspDecode("Get URI length overflow".to_owned()))?;
    if rest.len() < uri_end {
        return Err(WapError::Truncated {
            expected: uri_end + 1,
            actual: rest.len() + 1,
        });
    }
    let uri_bytes = &rest[uri_start..uri_end];
    let uri = std::str::from_utf8(uri_bytes)
        .map_err(|e| WapError::WspDecode(format!("Get URI is not valid UTF-8/ASCII: {e}")))?
        .to_owned();
    let headers = HeaderBlock::from_bytes(&rest[uri_end..]);
    Ok(WspPdu::MethodInvoke { method_code, uri, headers })
}

// ── Builders ─────────────────────────────────────────────────────────────────

/// Build the ConnectReply that answers a given Connect.
///
/// Historically we tried to echo every MS-proposed capability verbatim
/// (against Kannel's `sanitize_capabilities()`). Hardware testing 2026-07-10
/// with Motorola MTP3550 / UP.Browser 6.3 showed that pure echoing works
/// through the WTP layer but MS silently drops the WSP ConnectReply if we
/// claim capabilities we can't actually service. The three sanitizations
/// applied here mirror Kannel's WAP-230-compliant behaviour and are the
/// difference between UP.Browser accepting the session and looping:
///
/// 1. **Protocol-Options top 4 bits cleared** — MS proposes `0xF0` (Confirmed
///    Push + Push + Suspend/Resume + Ack Headers). We don't implement any of
///    those, so echoing `0xF0` is dishonest and causes MS to abort later.
///    Per `wsp_session.c::sanitize_capabilities()`, mask with `0x0F`.
/// 2. **Header-Code-Pages refused** — MS proposes `x-up-1` (Openwave's
///    proprietary header encoding). We can't decode it, so accepting means
///    every subsequent request breaks. Kannel replaces the accepted list
///    with a zero-data refusal entry (`01 86` on the wire).
/// 3. **Encoding-Version: 1.3 in the headers block** — WAP-230 §8.4.2.70:
///    absence defaults MS to WSP 1.2 encoding. Kannel always echoes `1.3`.
///    Wire bytes: `C3 93` (field code 0x43 | 0x80 = 0xC3; version value
///    (1<<4)|3 = 0x13 | 0x80 = 0x93).
///
/// `server_session_id` is chosen by the gateway (see [`crate::wsp::session`]).
pub fn build_connect_reply(connect: &WspPdu, server_session_id: u32, _headers: HeaderBlock) -> WapResult<WspPdu> {
    let ms_caps = match connect {
        WspPdu::Connect { capabilities, .. } => capabilities,
        other => {
            return Err(WapError::WspDecode(format!(
                "build_connect_reply called with non-Connect PDU {:?}",
                other.pdu_type_code()
            )));
        }
    };

    let mut capabilities: Vec<Capability> = Vec::with_capacity(ms_caps.len());
    for cap in ms_caps {
        match cap {
            // Sanitize (1): clear top 4 bits of Protocol-Options. MS proposes
            // 0xF0 (Confirmed Push + Push + Suspend/Resume + Ack Headers)
            // which we don't implement — echoing it dishonestly causes MS
            // to later Abort the session.
            Capability::ProtocolOptions(bits) => {
                capabilities.push(Capability::ProtocolOptions(*bits & 0x0F));
            }
            // Sanitize (2): refuse Header-Code-Pages / Extended-Methods (both
            // land under cap id 0x06 in our codec). Per WAP-230 §8.2.4.1 the
            // server signals refusal by echoing the capability id with a
            // zero-length payload → wire bytes `01 86`. Accepting means we
            // claim to understand Openwave's `x-up-1` header encoding, and
            // subsequent GETs would arrive with headers we can't decode.
            Capability::ExtendedMethods(_) | Capability::HeaderCodePages(_) => {
                capabilities.push(Capability::ExtendedMethods(Vec::new()));
            }
            // Everything else is echoed byte-for-byte.
            other => capabilities.push(other.clone()),
        }
    }

    // Sanitize (3): always emit Encoding-Version: 1.3 in the headers block.
    // WAP-230 §8.4.1 well-known header encoding: field name = short-integer
    // (bit 7 set + code in bits 6-0); Encoding-Version code = 0x43 → 0xC3.
    // Value = version-value short-integer form for "1.3": (1<<4)|3 = 0x13 → 0x93.
    let headers = HeaderBlock::from_bytes(vec![0xC3, 0x93]);

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
/// WAP-230 §8.7.3.1 — Status = "OK" (200).
pub const STATUS_OK: u8 = 0x20;
/// WAP-230 §8.7.3.4 — Status = "Bad Request" (400).
pub const STATUS_BAD_REQUEST: u8 = 0x40;
/// WAP-230 §8.7.3.4 — Status = "Not Found" (404).
pub const STATUS_NOT_FOUND: u8 = 0x44;
/// WAP-230 §8.7.3.4 — Status = "Method Not Allowed" (405).
pub const STATUS_METHOD_NOT_ALLOWED: u8 = 0x45;
/// WAP-230 §8.7.3.5 — Status = "Internal Server Error" (500).
pub const STATUS_INTERNAL_ERROR: u8 = 0x50;
/// WAP-230 §8.7.3.5 — Status = "Bad Gateway" (502).
pub const STATUS_BAD_GATEWAY: u8 = 0x52;

/// WSP Content-Type value (WAP-230 §8.4.2.24). Two representations map onto
/// the two spec forms:
///
/// * [`ContentType::WellKnown`] — a single-byte short-integer form; the
///   raw well-known code is stored WITHOUT the 0x80 continuation flag and
///   is OR'd on at encode time. E.g. `application/vnd.wap.wmlc` is
///   well-known code `0x08`, encoded as the single byte `0x88`.
/// * [`ContentType::Text`] — the fallback text-string form for MIME types
///   we don't have a well-known code for; encoded as the ASCII bytes
///   followed by a single 0x00 terminator.
///
/// The well-known table lives at WAP-230 §Appendix A / assigned numbers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContentType {
    WellKnown(u8),
    Text(String),
}

impl ContentType {
    /// WAP well-known code for `application/vnd.wap.wmlc` (compiled WML).
    pub const WMLC: u8 = 0x14;
    /// WAP well-known code for `text/vnd.wap.wml` (WML source).
    pub const WML: u8 = 0x08;
    /// WAP well-known code for `image/vnd.wap.wbmp`.
    pub const WBMP: u8 = 0x21;
    /// WAP well-known code for `text/plain`.
    pub const TEXT_PLAIN: u8 = 0x03;
    /// WAP well-known code for `application/octet-stream`.
    pub const OCTET_STREAM: u8 = 0x11;

    /// Map an HTTP `Content-Type` MIME token (bare, no `; charset=…`) to the
    /// most compact WSP encoding we can. Anything unknown falls through to
    /// the text-string form.
    ///
    /// The well-known table is per WAP-230 Appendix A (WSP Content-Type
    /// Assignments). We only enumerate the handful of MIME types the WAP
    /// browser fleet in this deployment actually asks for; adding more is
    /// a one-line append here.
    pub fn from_http(mime: &str) -> Self {
        // Ignore parameters after ';' and trim whitespace.
        let bare = mime.split(';').next().unwrap_or(mime).trim();
        let lower = bare.to_ascii_lowercase();
        match lower.as_str() {
            "text/plain" => Self::WellKnown(Self::TEXT_PLAIN),
            "text/html" => Self::WellKnown(0x02),
            "text/vnd.wap.wml" => Self::WellKnown(Self::WML),
            "text/vnd.wap.wmlscript" => Self::WellKnown(0x09),
            "application/octet-stream" => Self::WellKnown(Self::OCTET_STREAM),
            "application/vnd.wap.wmlc" => Self::WellKnown(Self::WMLC),
            "application/vnd.wap.wmlscriptc" => Self::WellKnown(0x15),
            "application/vnd.wap.wbxml" => Self::WellKnown(0x29),
            "image/gif" => Self::WellKnown(0x1D),
            "image/jpeg" => Self::WellKnown(0x1E),
            "image/vnd.wap.wbmp" => Self::WellKnown(Self::WBMP),
            _ => Self::Text(bare.to_owned()),
        }
    }

    /// Serialize as WSP wire bytes (WAP-230 §8.4.2.24 Content-general-form
    /// — restricted to the two forms we emit).
    pub fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Self::WellKnown(code) => out.push(0x80 | (code & 0x7F)),
            Self::Text(s) => {
                // WAP-230 §8.4.2.1 text-string: characters MUST be > 0x7F
                // for the first byte to disambiguate from short-integer.
                // Content-types are always US-ASCII, so we're fine emitting
                // them raw + NUL terminator. If the first byte is high we
                // must prefix with a 0x7F "quote" per §8.4.2.1; MIME never
                // starts with such a char, so skip that branch.
                out.extend_from_slice(s.as_bytes());
                out.push(0x00);
            }
        }
    }
}

/// Build a WSP Reply for a successful (or unsuccessful) HTTP relay.
///
/// Headers block layout (matches Kannel `wsp/wsp_headers.c::wsp_headers_pack`
/// with content-type flag = 1):
///   1. Content-Type value at position 0 (no field-code prefix — the WAP-230
///      §8.5.1.1 "implicit content type" convention that UP.Browser 6.3 relies
///      on for the very first header of a Reply).
///   2. Content-Length as a well-known header (field 0x0D → short-int 0x8D,
///      followed by short-integer or long-integer value depending on size).
///      Some browsers (including UP.Browser 6.3) reject Replies without an
///      explicit Content-Length despite WSP body length being implicit —
///      hardware-observed 2026-07-10.
pub fn build_get_reply(status: u8, content_type: ContentType, body: Vec<u8>) -> WspPdu {
    let mut headers = Vec::with_capacity(8);
    // (1) Content-Type at head of block, no field prefix.
    content_type.encode(&mut headers);
    // (2) Content-Length: <body.len()>. Field code 0x0D → short-int 0x8D.
    headers.push(0x8D);
    encode_integer_value(&mut headers, body.len() as u32);
    WspPdu::Reply {
        status,
        headers: HeaderBlock::from_bytes(headers),
        body,
    }
}

/// Encode a WSP integer-value per WAP-230 §8.4.2.3.
/// - Short-integer form (value 0..=127) = single byte 0x80|value.
/// - Long-integer form otherwise = length byte + big-endian value bytes.
fn encode_integer_value(out: &mut Vec<u8>, value: u32) {
    if value < 0x80 {
        out.push(0x80 | (value as u8));
        return;
    }
    let bytes = value.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(3);
    let num = 4 - start;
    out.push(num as u8);
    out.extend_from_slice(&bytes[start..]);
}

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
        // Use 0x30 which is not in any implemented range (Connect=0x01..0x09,
        // Reply=0x04, method PDUs=0x40..=0x7F).
        let bytes = [0x30, 0xAA, 0xBB, 0xCC];
        let pdu = WspPdu::decode(&bytes).unwrap();
        assert_eq!(
            pdu,
            WspPdu::Unknown {
                pdu_type: 0x30,
                payload: vec![0xAA, 0xBB, 0xCC],
            }
        );
        assert_eq!(pdu.encode(), bytes);
    }

    #[test]
    fn build_connect_reply_sanitizes_openwave_caps() {
        // Hand-craft a Connect matching what MTP3550 sends.
        let connect = WspPdu::Connect {
            version: 0x10,
            capabilities: vec![
                Capability::ProtocolOptions(0xF0),
                Capability::ExtendedMethods(vec![(0x10, b"x-up-1".to_vec())]),
            ],
            headers: HeaderBlock::empty(),
        };
        let reply = build_connect_reply(&connect, 1, HeaderBlock::empty()).unwrap();
        let WspPdu::ConnectReply { capabilities, headers, .. } = &reply else {
            panic!("build_connect_reply returned non-ConnectReply: {reply:?}");
        };
        // (1) Protocol-Options: top 4 bits cleared.
        assert_eq!(capabilities[0], Capability::ProtocolOptions(0x00));
        // (2) ExtendedMethods (cap id 0x06 in our codec = Header-Code-Pages
        //     on the wire) refused with empty list.
        assert_eq!(capabilities[1], Capability::ExtendedMethods(Vec::new()));
        // (3) Headers block contains Encoding-Version: 1.3 short-integer form.
        assert_eq!(headers.raw, vec![0xC3, 0x93]);
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

    // ── PD-10c: WSP Get decoder + Reply builder tests ────────────────────

    /// The WSP payload MTP3550 emits after ConnectReply (WTP header stripped).
    /// Wire bytes from tcpdump 2026-07-10 22:33:53. Notice there is NO
    /// headers-length byte or headers block after the URI — the packet
    /// simply ends. Our decoder must treat the remainder as an empty
    /// [`HeaderBlock`] rather than error out.
    const MTP3550_GET_WSP_PAYLOAD: &[u8] = &[
        0x40, // WSP Get PDU type
        0x20, // URI-length uintvar = 32
        b'h', b't', b't', b'p', b':', b'/', b'/', b'1', b'0', b'.', b'2', b'2', b'2', b'.', b'0', b'.', b'1', b':', b'8', b'0', b'8', b'1',
        b'/', b'i', b'n', b'd', b'e', b'x', b'.', b'w', b'm', b'l',
    ];

    #[test]
    fn decodes_get_with_uri_and_no_headers() {
        let pdu = WspPdu::decode(MTP3550_GET_WSP_PAYLOAD).unwrap();
        let WspPdu::MethodInvoke { method_code, uri, headers } = pdu else {
            panic!("expected MethodInvoke, got {pdu:?}");
        };
        assert_eq!(method_code, pdu_type::GET);
        assert_eq!(uri, "http://10.222.0.1:8081/index.wml");
        assert!(headers.is_empty(), "MTP3550 sends no headers-length after URI; block must be empty");
    }

    #[test]
    fn decodes_get_with_uri_and_headers() {
        // Synthetic Get with a trailing 3-byte "header block" (opaque —
        // decoder just preserves it verbatim).
        let mut bytes = vec![pdu_type::GET, 0x03, b'/', b'a', b'b'];
        bytes.extend_from_slice(&[0xAA, 0xBB, 0xCC]);
        let pdu = WspPdu::decode(&bytes).unwrap();
        let WspPdu::MethodInvoke { uri, headers, .. } = pdu else {
            panic!("expected MethodInvoke");
        };
        assert_eq!(uri, "/ab");
        assert_eq!(headers.raw, vec![0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn decodes_all_get_like_method_codes() {
        // 0x40..=0x5F should all round-trip through MethodInvoke, preserving
        // the exact method code so the handler can return 405 for anything
        // that isn't 0x40 (Get).
        for code in [pdu_type::OPTIONS, pdu_type::HEAD, pdu_type::DELETE, 0x5F] {
            let bytes = [code, 0x01, b'/'];
            let pdu = WspPdu::decode(&bytes).unwrap();
            assert!(
                matches!(pdu, WspPdu::MethodInvoke { method_code, .. } if method_code == code),
                "code {code:#x} did not decode as MethodInvoke: {pdu:?}",
            );
        }
    }

    #[test]
    fn decode_rejects_get_with_truncated_uri() {
        // URI-length says 10 but only 2 bytes present.
        let bytes = [pdu_type::GET, 0x0A, b'/', b'a'];
        assert!(matches!(WspPdu::decode(&bytes), Err(WapError::Truncated { .. })));
    }

    #[test]
    fn decode_rejects_get_with_non_utf8_uri() {
        let bytes = [pdu_type::GET, 0x02, 0xFF, 0xFE];
        assert!(matches!(WspPdu::decode(&bytes), Err(WapError::WspDecode(_))));
    }

    #[test]
    fn method_invoke_round_trips() {
        let pdu = WspPdu::MethodInvoke {
            method_code: pdu_type::GET,
            uri: "/index.wml".to_owned(),
            headers: HeaderBlock::from_bytes(vec![0xDE, 0xAD]),
        };
        let bytes = pdu.encode();
        let back = WspPdu::decode(&bytes).unwrap();
        assert_eq!(back, pdu);
    }

    #[test]
    fn content_type_wellknown_encodes_as_short_int() {
        let mut buf = Vec::new();
        ContentType::WellKnown(ContentType::WMLC).encode(&mut buf);
        assert_eq!(buf, vec![0x80 | ContentType::WMLC]);
        // wmlc code = 0x14, so short-int = 0x94.
        assert_eq!(buf, vec![0x94]);
    }

    #[test]
    fn content_type_from_http_maps_wellknown_mimes() {
        assert_eq!(
            ContentType::from_http("application/vnd.wap.wmlc"),
            ContentType::WellKnown(ContentType::WMLC)
        );
        // Case- and parameter-insensitive.
        assert_eq!(
            ContentType::from_http("Application/vnd.wap.WMLC; charset=utf-8"),
            ContentType::WellKnown(ContentType::WMLC)
        );
        assert_eq!(
            ContentType::from_http("text/plain"),
            ContentType::WellKnown(ContentType::TEXT_PLAIN)
        );
    }

    #[test]
    fn content_type_from_http_falls_back_to_text_for_unknown() {
        assert_eq!(
            ContentType::from_http("application/x-flowstation"),
            ContentType::Text("application/x-flowstation".to_owned())
        );
    }

    #[test]
    fn content_type_text_encodes_null_terminated() {
        let mut buf = Vec::new();
        ContentType::Text("application/x-flowstation".to_owned()).encode(&mut buf);
        assert_eq!(&buf[..buf.len() - 1], b"application/x-flowstation");
        assert_eq!(*buf.last().unwrap(), 0x00);
    }

    #[test]
    fn build_get_reply_encodes_content_type_and_length() {
        let reply = build_get_reply(STATUS_OK, ContentType::WellKnown(ContentType::WMLC), b"hello".to_vec());
        let bytes = reply.encode();
        // 04 (Reply) | 20 (200 OK) | 03 (headers-len=3) | 94 (CT wmlc) | 8D (Content-Length field) | 85 (short-int 5) | body
        assert_eq!(&bytes[..6], &[0x04, 0x20, 0x03, 0x94, 0x8D, 0x85]);
        assert_eq!(&bytes[6..], b"hello");
    }

    #[test]
    fn build_get_reply_content_length_long_form_for_large_body() {
        let body = vec![0xAA; 200];
        let reply = build_get_reply(STATUS_OK, ContentType::WellKnown(ContentType::WMLC), body.clone());
        let bytes = reply.encode();
        // 04 20 04 94 8D 01 C8 (headers-len=4: wmlc + Content-Length long-int length=1 value=0xC8=200)
        assert_eq!(&bytes[..7], &[0x04, 0x20, 0x04, 0x94, 0x8D, 0x01, 0xC8]);
        assert_eq!(&bytes[7..], &body[..]);
    }

    #[test]
    fn build_get_reply_encodes_content_type_literal_with_length() {
        let reply = build_get_reply(STATUS_OK, ContentType::from_http("application/x-flowstation"), b"x".to_vec());
        let bytes = reply.encode();
        assert_eq!(&bytes[..2], &[0x04, 0x20]);
        // headers-len = 25 chars + NUL + Content-Length(8D 81) = 26 + 2 = 28 = 0x1C
        assert_eq!(bytes[2], 0x1C);
        assert_eq!(&bytes[3..3 + 25], b"application/x-flowstation");
        assert_eq!(bytes[3 + 25], 0x00);
        // Then Content-Length header: 0x8D 0x81 (short-int 1)
        assert_eq!(bytes[3 + 26], 0x8D);
        assert_eq!(bytes[3 + 27], 0x81);
        assert_eq!(bytes[3 + 28], b'x');
    }

    #[test]
    fn build_get_reply_round_trip_matches_kannel_wire_format() {
        let reply = build_get_reply(STATUS_OK, ContentType::WellKnown(ContentType::WMLC), vec![0xDE, 0xAD]);
        let bytes = reply.encode();
        // 04 20 03 94 8D 82 DE AD -- headers block = wmlc CT + Content-Length: 2
        assert_eq!(bytes, vec![0x04, 0x20, 0x03, 0x94, 0x8D, 0x82, 0xDE, 0xAD]);
        let back = WspPdu::decode(&bytes).unwrap();
        assert_eq!(back, reply);
    }
}
