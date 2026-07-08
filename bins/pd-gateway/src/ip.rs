//! Minimal IPv4 header helpers.
//!
//! These operate only on the fixed 20-byte IPv4 header to avoid pulling in
//! a full packet-parsing library.  SNDCP always forwards complete IP packets
//! so the assumption of a ≥20-byte buffer is safe.

use crate::GatewayError;
use std::net::Ipv4Addr;

/// Extract the destination address from a raw IPv4 packet (bytes 16–19).
///
/// # Errors
/// - [`GatewayError::IpTooSmall`] — fewer than 20 bytes.
/// - [`GatewayError::IpNotV4`]   — version nibble is not 4.
pub fn parse_ipv4_dest(packet: &[u8]) -> Result<Ipv4Addr, GatewayError> {
    if packet.len() < 20 {
        return Err(GatewayError::IpTooSmall);
    }
    if (packet[0] >> 4) != 4 {
        return Err(GatewayError::IpNotV4);
    }
    Ok(Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]))
}

/// Returns `true` when the buffer looks like a valid IPv4 packet (≥20 bytes,
/// version nibble == 4).  Used as a fast pre-filter before full parsing.
pub fn ipv4_min_valid(packet: &[u8]) -> bool {
    packet.len() >= 20 && (packet[0] >> 4) == 4
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal 20-byte IPv4 header with version=4, IHL=5.
    fn make_ipv4_header(dest: [u8; 4]) -> Vec<u8> {
        let mut h = vec![0u8; 20];
        h[0] = 0x45; // version=4, IHL=5
        h[16] = dest[0];
        h[17] = dest[1];
        h[18] = dest[2];
        h[19] = dest[3];
        h
    }

    #[test]
    fn parse_ipv4_dest_extracts_bytes_16_to_19() {
        let header = make_ipv4_header([10, 11, 12, 13]);
        let dest = parse_ipv4_dest(&header).expect("should parse");
        assert_eq!(dest, Ipv4Addr::new(10, 11, 12, 13));
    }

    #[test]
    fn parse_ipv4_rejects_too_short_packet() {
        let short = vec![0x45u8; 19];
        assert!(matches!(parse_ipv4_dest(&short), Err(GatewayError::IpTooSmall)));
    }

    #[test]
    fn parse_ipv4_rejects_ipv6_version_nibble() {
        let mut header = make_ipv4_header([10, 0, 0, 1]);
        header[0] = 0x60; // version = 6
        assert!(matches!(parse_ipv4_dest(&header), Err(GatewayError::IpNotV4)));
    }

    #[test]
    fn ipv4_min_valid_rejects_short_packet() {
        assert!(!ipv4_min_valid(&[0x45u8; 19]));
    }

    #[test]
    fn ipv4_min_valid_rejects_non_ipv4_version() {
        let mut h = vec![0u8; 20];
        h[0] = 0x60; // IPv6
        assert!(!ipv4_min_valid(&h));
    }

    #[test]
    fn ipv4_min_valid_accepts_valid_ipv4_header() {
        let header = make_ipv4_header([192, 168, 1, 1]);
        assert!(ipv4_min_valid(&header));
    }
}
