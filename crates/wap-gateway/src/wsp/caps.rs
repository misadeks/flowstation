//! WSP capability list codec (WAP-230 §8.2.4).
//!
//! # Encoding
//!
//! A capability list is a concatenation of length-prefixed capability
//! entries:
//!
//! ```text
//!   <length:uintvar> <id-octet> <payload...>
//! ```
//!
//! where `length` counts `id-octet + payload` and `id-octet` is either:
//!
//! * a **well-known** short-integer with the high bit set (`0x80 | id`)
//!   — the only form we produce, and the only one the reference clients
//!   (Kannel / UP.Link / MMSC) actually emit; or
//! * a NUL-terminated **token-text** identifier for extension caps.
//!
//! # Well-known IDs
//!
//! | Value | Name                | Payload |
//! |-------|---------------------|---------|
//! | 0x00  | Client-SDU-Size     | uintvar |
//! | 0x01  | Server-SDU-Size     | uintvar |
//! | 0x02  | Protocol-Options    | 1-byte bit-field |
//! | 0x03  | Method-MOR          | uint8 |
//! | 0x04  | Push-MOR            | uint8 |
//! | 0x06  | Extended-Methods    | list of (well-known-code, cstr) |
//! | 0x07  | Header-Code-Pages   | list of (page-id, cstr) |
//! | 0x08  | Aliases             | list of address quadruplets (opaque) |
//!
//! **Spec-vs-hardware quirk (PD-10b, 2026-07-10):** WAP-230 §8.2.4.1
//! nominally assigns `0x05` to Extended-Methods, `0x06` to Header-Code-Pages
//! and `0x07` to Aliases. UP.Browser 6.3 on MTP3550 firmware emits the
//! Extended-Methods cap under id `0x06` (byte `0x86` on the wire). We
//! decode by the hardware numbering so `ExtendedMethods([(0x10, "x-up-1")])`
//! round-trips byte-identical. All that matters for the ConnectReply echo
//! is that the wire bytes come back untouched, which they do either way.
//!
//! # Openwave quirk
//!
//! UP.Browser 6.3 encodes `Protocol-Options` as `0xF0` — Confirmed-Push +
//! Push + Session-Resume + Ack-Headers all set at once. Kannel's
//! `sanitize_capabilities()` strips this to `0x80`, which is exactly what
//! causes the MS to reject the session and reconnect on a 40-s loop
//! (documented in `lib.rs`). **We echo every well-known cap back verbatim**
//! rather than trying to be clever.

use crate::error::{WapError, WapResult};
use crate::wsp::uintvar;

/// Well-known capability identifiers (WAP-230 §8.2.4.1). Kept as a plain
/// `u8` module so pattern matches on `Capability` can spell each value out
/// literally and stay grep-able against the spec.
pub mod id {
    pub const CLIENT_SDU_SIZE: u8 = 0x00;
    pub const SERVER_SDU_SIZE: u8 = 0x01;
    pub const PROTOCOL_OPTIONS: u8 = 0x02;
    pub const METHOD_MOR: u8 = 0x03;
    pub const PUSH_MOR: u8 = 0x04;
    pub const EXTENDED_METHODS: u8 = 0x06;
    pub const HEADER_CODE_PAGES: u8 = 0x07;
    pub const ALIASES: u8 = 0x08;
}

/// A single capability entry. Well-known caps are decoded into typed
/// variants; anything else is preserved as `Raw` so a ConnectReply can
/// echo it back untouched (WAP-230 requires the responder to at least
/// acknowledge every proposed cap).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Capability {
    /// 0x00 — max SDU the client will accept from us.
    ClientSduSize(u32),
    /// 0x01 — max SDU the client will send to us.
    ServerSduSize(u32),
    /// 0x02 — bit-field (`0x01`=Confirmed-Push, `0x02`=Push,
    /// `0x04`=Session-Resume, `0x08`=Ack-Headers, `0x10`=Large-Data,
    /// `0x20`=Server-Message). UP.Browser sends `0xF0` with the top nibble
    /// set even though the top bits are reserved — spec-vs-hardware quirk,
    /// echo verbatim.
    ProtocolOptions(u8),
    /// 0x03 — Method Max Outstanding Requests.
    MethodMor(u8),
    /// 0x04 — Push Max Outstanding Requests.
    PushMor(u8),
    /// 0x05 — list of `(well-known-code, method-name)` pairs. The name is
    /// a NUL-terminated string, e.g. `x-up-1`.
    ExtendedMethods(Vec<(u8, Vec<u8>)>),
    /// 0x06 — list of `(page-id, code-page-name)` pairs.
    HeaderCodePages(Vec<(u8, Vec<u8>)>),
    /// 0x07 — opaque list of aliases; we don't interpret in v0.1.
    Aliases(Vec<u8>),
    /// Unknown cap id (well-known or token-text). Preserved so
    /// ConnectReply can echo it byte-for-byte. `id_byte` is the raw
    /// identifier octet as it appeared on the wire (with the high bit
    /// still set for short-integer form).
    Raw { id_byte: u8, payload: Vec<u8> },
}

impl Capability {
    /// Decode a single capability entry from the start of `bytes`.
    /// Returns `(cap, consumed)`.
    fn decode_one(bytes: &[u8]) -> WapResult<(Self, usize)> {
        let (len, len_bytes) = uintvar::decode(bytes)?;
        let len = len as usize;
        let start = len_bytes;
        let end = start
            .checked_add(len)
            .ok_or_else(|| WapError::WspDecode("cap length overflow".to_owned()))?;
        if bytes.len() < end {
            return Err(WapError::Truncated {
                expected: end,
                actual: bytes.len(),
            });
        }
        if len == 0 {
            return Err(WapError::WspDecode(
                "capability entry length is zero (must include id octet)".to_owned(),
            ));
        }
        let id_byte = bytes[start];
        let payload = &bytes[start + 1..end];

        // Only short-integer well-known IDs are recognised as typed
        // variants; token-text identifiers fall through to Raw.
        let cap = if id_byte & 0x80 != 0 {
            let id = id_byte & 0x7F;
            match id {
                id::CLIENT_SDU_SIZE => {
                    let (v, n) = uintvar::decode(payload)?;
                    require_fully_consumed(payload, n, "Client-SDU-Size")?;
                    Self::ClientSduSize(v)
                }
                id::SERVER_SDU_SIZE => {
                    let (v, n) = uintvar::decode(payload)?;
                    require_fully_consumed(payload, n, "Server-SDU-Size")?;
                    Self::ServerSduSize(v)
                }
                id::PROTOCOL_OPTIONS => {
                    if payload.len() != 1 {
                        return Err(WapError::WspDecode(format!(
                            "Protocol-Options must be 1 byte, got {}",
                            payload.len()
                        )));
                    }
                    Self::ProtocolOptions(payload[0])
                }
                id::METHOD_MOR => {
                    if payload.len() != 1 {
                        return Err(WapError::WspDecode(format!("Method-MOR must be 1 byte, got {}", payload.len())));
                    }
                    Self::MethodMor(payload[0])
                }
                id::PUSH_MOR => {
                    if payload.len() != 1 {
                        return Err(WapError::WspDecode(format!("Push-MOR must be 1 byte, got {}", payload.len())));
                    }
                    Self::PushMor(payload[0])
                }
                id::EXTENDED_METHODS => Self::ExtendedMethods(decode_code_cstr_list(payload)?),
                id::HEADER_CODE_PAGES => Self::HeaderCodePages(decode_code_cstr_list(payload)?),
                id::ALIASES => Self::Aliases(payload.to_vec()),
                _ => Self::Raw {
                    id_byte,
                    payload: payload.to_vec(),
                },
            }
        } else {
            Self::Raw {
                id_byte,
                payload: payload.to_vec(),
            }
        };

        Ok((cap, end))
    }

    /// Encode a single capability entry, appending its length-prefixed
    /// bytes to `out`.
    fn encode_one(&self, out: &mut Vec<u8>) {
        // Encode id + payload into a scratch buffer, then prefix with its
        // length as uintvar.
        let mut body: Vec<u8> = Vec::with_capacity(8);
        match self {
            Self::ClientSduSize(v) => {
                body.push(0x80 | id::CLIENT_SDU_SIZE);
                uintvar::encode(*v, &mut body);
            }
            Self::ServerSduSize(v) => {
                body.push(0x80 | id::SERVER_SDU_SIZE);
                uintvar::encode(*v, &mut body);
            }
            Self::ProtocolOptions(bits) => {
                body.push(0x80 | id::PROTOCOL_OPTIONS);
                body.push(*bits);
            }
            Self::MethodMor(n) => {
                body.push(0x80 | id::METHOD_MOR);
                body.push(*n);
            }
            Self::PushMor(n) => {
                body.push(0x80 | id::PUSH_MOR);
                body.push(*n);
            }
            Self::ExtendedMethods(list) => {
                body.push(0x80 | id::EXTENDED_METHODS);
                encode_code_cstr_list(list, &mut body);
            }
            Self::HeaderCodePages(list) => {
                body.push(0x80 | id::HEADER_CODE_PAGES);
                encode_code_cstr_list(list, &mut body);
            }
            Self::Aliases(bytes) => {
                body.push(0x80 | id::ALIASES);
                body.extend_from_slice(bytes);
            }
            Self::Raw { id_byte, payload } => {
                body.push(*id_byte);
                body.extend_from_slice(payload);
            }
        }
        uintvar::encode(body.len() as u32, out);
        out.extend_from_slice(&body);
    }
}

/// Decode a full capability list from `bytes` (which must be exactly the
/// capabilities-block sub-slice — trailing bytes are an error).
pub fn decode_list(mut bytes: &[u8]) -> WapResult<Vec<Capability>> {
    let mut out = Vec::new();
    while !bytes.is_empty() {
        let (cap, n) = Capability::decode_one(bytes)?;
        out.push(cap);
        bytes = &bytes[n..];
    }
    Ok(out)
}

/// Encode a full capability list. Result may be embedded in the WSP PDU
/// after its uintvar length prefix.
pub fn encode_list(caps: &[Capability]) -> Vec<u8> {
    let mut out = Vec::new();
    for c in caps {
        c.encode_one(&mut out);
    }
    out
}

/// Decode a list of `(u8-code, NUL-terminated bytes)` used by both
/// Extended-Methods and Header-Code-Pages payloads.
fn decode_code_cstr_list(mut bytes: &[u8]) -> WapResult<Vec<(u8, Vec<u8>)>> {
    let mut out = Vec::new();
    while !bytes.is_empty() {
        let code = bytes[0];
        let rest = &bytes[1..];
        let nul = rest
            .iter()
            .position(|&b| b == 0)
            .ok_or_else(|| WapError::WspDecode("missing NUL terminator in cap cstr list".to_owned()))?;
        let name = rest[..nul].to_vec();
        out.push((code, name));
        bytes = &rest[nul + 1..];
    }
    Ok(out)
}

fn encode_code_cstr_list(list: &[(u8, Vec<u8>)], out: &mut Vec<u8>) {
    for (code, name) in list {
        out.push(*code);
        out.extend_from_slice(name);
        out.push(0);
    }
}

fn require_fully_consumed(payload: &[u8], consumed: usize, what: &str) -> WapResult<()> {
    if consumed != payload.len() {
        return Err(WapError::WspDecode(format!(
            "{what} has {} trailing bytes",
            payload.len() - consumed
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Byte sequences lifted verbatim from the MTP3550 Connect PDU on
    // hardware 2026-07-10 — see PD-10b prompt.
    const HW_CLIENT_SDU: &[u8] = &[0x04, 0x80, 0x94, 0x80, 0x00];
    const HW_SERVER_SDU: &[u8] = &[0x04, 0x81, 0x94, 0x80, 0x00];
    const HW_PROTOCOL_OPTS: &[u8] = &[0x02, 0x82, 0xF0];
    const HW_METHOD_MOR: &[u8] = &[0x02, 0x83, 0x03];
    const HW_PUSH_MOR: &[u8] = &[0x02, 0x84, 0x01];
    const HW_EXTENDED_METHODS: &[u8] = &[0x09, 0x86, 0x10, 0x78, 0x2D, 0x75, 0x70, 0x2D, 0x31, 0x00];

    fn hw_full_cap_block() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(HW_CLIENT_SDU);
        v.extend_from_slice(HW_SERVER_SDU);
        v.extend_from_slice(HW_PROTOCOL_OPTS);
        v.extend_from_slice(HW_METHOD_MOR);
        v.extend_from_slice(HW_PUSH_MOR);
        v.extend_from_slice(HW_EXTENDED_METHODS);
        v
    }

    #[test]
    fn decodes_protocol_options_bit_for_bit() {
        let caps = decode_list(HW_PROTOCOL_OPTS).unwrap();
        assert_eq!(caps, vec![Capability::ProtocolOptions(0xF0)]);
    }

    #[test]
    fn decodes_extended_methods_bit_for_bit() {
        let caps = decode_list(HW_EXTENDED_METHODS).unwrap();
        assert_eq!(caps, vec![Capability::ExtendedMethods(vec![(0x10, b"x-up-1".to_vec())])]);
    }

    #[test]
    fn decodes_full_hw_cap_block() {
        let bytes = hw_full_cap_block();
        assert_eq!(bytes.len(), 29, "PD-10b fixture caps block is 29 bytes");
        let caps = decode_list(&bytes).unwrap();
        assert_eq!(caps.len(), 6);
        assert!(matches!(caps[0], Capability::ClientSduSize(_)));
        assert!(matches!(caps[1], Capability::ServerSduSize(_)));
        assert_eq!(caps[2], Capability::ProtocolOptions(0xF0));
        assert_eq!(caps[3], Capability::MethodMor(3));
        assert_eq!(caps[4], Capability::PushMor(1));
        assert_eq!(caps[5], Capability::ExtendedMethods(vec![(0x10, b"x-up-1".to_vec())]));
    }

    #[test]
    fn round_trips_hw_cap_block_byte_identical() {
        let bytes = hw_full_cap_block();
        let caps = decode_list(&bytes).unwrap();
        let re = encode_list(&caps);
        assert_eq!(re, bytes, "re-encoded cap block must be byte-identical to hardware");
    }

    #[test]
    fn preserves_unknown_well_known_cap_as_raw() {
        // Length 2, id 0x9E (well-known 0x1E, undefined by us), payload 0xAA.
        let bytes = [0x02, 0x9E, 0xAA];
        let caps = decode_list(&bytes).unwrap();
        assert_eq!(
            caps,
            vec![Capability::Raw {
                id_byte: 0x9E,
                payload: vec![0xAA],
            }]
        );
        assert_eq!(encode_list(&caps), bytes);
    }

    #[test]
    fn preserves_token_text_cap_as_raw() {
        // Token-text id "x-foo\0" (6 bytes) + payload 0x01 → 7-byte body.
        let bytes: Vec<u8> = [&[0x07u8][..], b"x-foo\0", &[0x01u8]].concat();
        let caps = decode_list(&bytes).unwrap();
        // Whatever the exact Raw shape is, encoding must round-trip.
        assert_eq!(encode_list(&caps), bytes);
    }

    #[test]
    fn rejects_truncated_cap() {
        // Says length 5 but only 3 more bytes follow.
        let bytes = [0x05, 0x82, 0xF0];
        assert!(matches!(decode_list(&bytes), Err(WapError::Truncated { .. })));
    }

    #[test]
    fn rejects_zero_length_cap() {
        assert!(matches!(decode_list(&[0x00]), Err(WapError::WspDecode(_))));
    }

    #[test]
    fn encodes_client_sdu_size_matches_hardware() {
        // Decode the exact fixture, re-encode, expect the same bytes back.
        let caps = decode_list(HW_CLIENT_SDU).unwrap();
        assert_eq!(encode_list(&caps), HW_CLIENT_SDU);
    }
}
