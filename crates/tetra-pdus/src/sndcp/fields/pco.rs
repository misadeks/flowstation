//! Protocol configuration options (PCO) element body, ETSI EN 300 392-2 table 28.105,
//! plus the PPP CHAP helpers duplicated from the legacy SNDCP entity stub.

use tetra_core::{BitBuffer, pdu_parse_error::PduParseErr};

use crate::sndcp::enums::configuration_protocol::ConfigurationProtocol;
use crate::sndcp::enums::protocol_identity::ProtocolIdentity;

// CHAP / PCO constants (mirrors crates/tetra-entities/src/sndcp/sndcp_bs.rs).
const PCO_TYPE34_ID: u64 = 1;
const PPP_PROTO_CHAP: u64 = 0xC223;
const PPP_CONFIG_PROTOCOL_PPP: u64 = 0;
const CHAP_CODE_SUCCESS: u64 = 3;
const PCO_CHAP_SUCCESS_BITS: u64 = 60;

/// A single protocol entry inside the PCO element.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcoEntry {
    pub protocol_identity: ProtocolIdentity,
    /// Contents octets (`length_of_contents` bytes).
    pub contents: Vec<u8>,
}

/// PCO element body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pco {
    pub configuration_protocol: ConfigurationProtocol,
    pub entries: Vec<PcoEntry>,
}

impl Pco {
    /// Decode a PCO body advertised to be exactly `contents_bits` bits long.
    pub fn from_bitbuf(buffer: &mut BitBuffer, contents_bits: usize) -> Result<Self, PduParseErr> {
        let start = buffer.get_pos();
        let cp_raw = buffer.read_field(4, "configuration_protocol")?;
        let configuration_protocol = ConfigurationProtocol::try_from(cp_raw)
            .map_err(|_| PduParseErr::InvalidValue { field: "configuration_protocol", value: cp_raw })?;

        let mut entries = Vec::new();
        while buffer.get_pos() - start < contents_bits {
            let pid_raw = buffer.read_field(16, "protocol_identity")?;
            let protocol_identity = ProtocolIdentity::from_raw(pid_raw as u16);
            let len = buffer.read_field(8, "length_of_contents")? as usize;
            let mut contents = Vec::with_capacity(len);
            for _ in 0..len {
                contents.push(buffer.read_field(8, "pco_content_octet")? as u8);
            }
            entries.push(PcoEntry { protocol_identity, contents });
        }

        let consumed = buffer.get_pos() - start;
        if consumed != contents_bits {
            return Err(PduParseErr::InconsistentLength { expected: contents_bits, found: consumed });
        }
        Ok(Pco { configuration_protocol, entries })
    }

    /// Encode this PCO body, returning the number of bits written.
    pub fn to_bitbuf(&self, buffer: &mut BitBuffer) -> Result<usize, PduParseErr> {
        let start = buffer.get_pos();
        buffer.write_bits(self.configuration_protocol.into_raw(), 4);
        for entry in &self.entries {
            buffer.write_bits(entry.protocol_identity.into_raw() as u64, 16);
            buffer.write_bits(entry.contents.len() as u64, 8);
            for &b in &entry.contents {
                buffer.write_bits(b as u64, 8);
            }
        }
        Ok(buffer.get_pos() - start)
    }
}

/// NOTE: kept string-based for byte-identical parity with the legacy stub.
///
/// Scan an SN-ACTIVATE PDP CONTEXT DEMAND bit-string for a PPP CHAP packet carried in its Protocol
/// configuration options element and return the identifier of the MS's CHAP Response (RFC 1994 code
/// 2), to be echoed in the Success we send back. Falls back to a Challenge's (code 1) identifier if
/// no Response is present, or `None` if the DEMAND carries no CHAP at all.
pub fn find_chap_response_id(demand: &str) -> Option<u8> {
    const CHAP_PROTO_ID: &str = "1100001000100011"; // C223H, MSB first
    let read = |off: usize| -> Option<u8> { demand.get(off..off + 8).and_then(|s| u8::from_str_radix(s, 2).ok()) };
    let mut fallback = None;
    let mut from = 0;
    while let Some(rel) = demand.get(from..).and_then(|s| s.find(CHAP_PROTO_ID)) {
        let marker = from + rel;
        match (read(marker + 16 + 8), read(marker + 16 + 16)) {
            (Some(2), Some(id)) => return Some(id),
            (Some(1), Some(id)) if fallback.is_none() => fallback = Some(id),
            _ => {}
        }
        from = marker + CHAP_PROTO_ID.len();
    }
    fallback
}

/// NOTE: kept string-based for byte-identical parity with the legacy stub.
///
/// Build the optional-element section (annex E.1) of an ACCEPT that grants a CHAP Success with the
/// given identifier: the o-bit, the three absent type-2 presence bits, the PCO type-3 element, and
/// the closing m-bit. Returned MSB-first as a bit string.
pub fn chap_success_optional_section(chap_id: u8) -> String {
    let mut s = String::with_capacity(81);
    s.push('1'); // o-bit = 1: optional elements follow
    s.push_str("000"); // type-2 presence bits, in table order, all absent
    s.push('1'); // M-bit = 1: a type-3/4 element follows
    s.push_str(&format!("{PCO_TYPE34_ID:04b}")); // type-3/4 element identifier (PCO = 1)
    s.push_str(&format!("{PCO_CHAP_SUCCESS_BITS:011b}")); // length indicator (bits)
    s.push_str(&format!("{PPP_CONFIG_PROTOCOL_PPP:04b}")); // configuration protocol = PPP
    s.push_str(&format!("{PPP_PROTO_CHAP:016b}")); // protocol identity = CHAP (C223H)
    s.push_str(&format!("{:08b}", 4)); // length of protocol identity contents = 4 octets
    s.push_str(&format!("{CHAP_CODE_SUCCESS:08b}"));
    s.push_str(&format!("{chap_id:08b}"));
    s.push_str(&format!("{:016b}", 4));
    s.push('0'); // M-bit = 0: no more type-3/4 elements
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_to_bits(hex: &str) -> String {
        hex.chars().map(|c| format!("{:04b}", c.to_digit(16).unwrap())).collect()
    }

    #[test]
    fn finds_chap_response_identifier_in_real_demand_pco() {
        let pco = hex_to_bits(
            "0c22318010500180aac20e0caf974bc75e02f44494d455452415f50\
             c2231a0205001a10db3b2df8c57cce0db8712b16aa9cb5a361646d696",
        );
        assert_eq!(find_chap_response_id(&pco), Some(5));
    }

    #[test]
    fn prefers_response_over_challenge_and_skips_non_chap_bits() {
        let mut s = String::from("101");
        s.push_str("1100001000100011"); // C223H
        s.push_str("00000110"); // length-of-contents (ignored)
        s.push_str("00000001"); // CHAP code = 1 (Challenge)
        s.push_str("00001001"); // identifier = 9
        s.push_str("1100001000100011"); // C223H
        s.push_str("00000110"); // length-of-contents
        s.push_str("00000010"); // CHAP code = 2 (Response)
        s.push_str("00000111"); // identifier = 7
        assert_eq!(find_chap_response_id(&s), Some(7));
    }

    #[test]
    fn no_chap_in_demand_returns_none() {
        assert_eq!(find_chap_response_id(&"0".repeat(256)), None);
    }

    #[test]
    fn optional_section_layout_matches_spec() {
        let sec = chap_success_optional_section(5);
        assert_eq!(sec.len(), 81);
        assert_eq!(&sec[0..4], "1000");
        assert_eq!(&sec[4..5], "1");
        assert_eq!(&sec[5..9], "0001");
        assert_eq!(&sec[9..20], &format!("{PCO_CHAP_SUCCESS_BITS:011b}"));
        assert_eq!(&sec[20..24], "0000");
        assert_eq!(&sec[24..40], "1100001000100011");
        assert_eq!(&sec[40..48], "00000100");
        assert_eq!(&sec[48..56], "00000011");
        assert_eq!(&sec[56..64], "00000101");
        assert_eq!(&sec[64..80], "0000000000000100");
        assert_eq!(&sec[80..81], "0");
    }

    #[test]
    fn pco_round_trip_chap_success() {
        let pco = Pco {
            configuration_protocol: ConfigurationProtocol::Ppp,
            entries: vec![PcoEntry {
                protocol_identity: ProtocolIdentity::Chap,
                contents: vec![3, 5, 0, 4],
            }],
        };
        let mut buf = BitBuffer::new_autoexpand(128);
        let bits = pco.to_bitbuf(&mut buf).unwrap();
        buf.seek(0);
        let decoded = Pco::from_bitbuf(&mut buf, bits).unwrap();
        assert_eq!(decoded.entries.len(), 1);
        assert_eq!(decoded.entries[0].protocol_identity, ProtocolIdentity::Chap);
        assert_eq!(decoded.entries[0].contents, vec![3, 5, 0, 4]);
        assert_eq!(decoded, pco);
    }
}
