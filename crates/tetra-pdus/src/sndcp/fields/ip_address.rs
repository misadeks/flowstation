//! IP address helpers for SNDCP PDUs.

use std::net::{Ipv4Addr, Ipv6Addr};

use tetra_core::{BitBuffer, pdu_parse_error::PduParseErr};

/// An IP address carried in an SNDCP PDU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpAddress {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
}

/// Read a 32-bit IPv4 address (MSB-first).
pub fn read_ipv4(buffer: &mut BitBuffer) -> Result<Ipv4Addr, PduParseErr> {
    let raw = buffer.read_field(32, "ipv4_address")?;
    Ok(Ipv4Addr::from((raw as u32).to_be_bytes()))
}

/// Write a 32-bit IPv4 address (MSB-first).
pub fn write_ipv4(buffer: &mut BitBuffer, addr: &Ipv4Addr) {
    buffer.write_bits(u32::from(*addr) as u64, 32);
}

/// Read a 128-bit IPv6 address (MSB-first).
pub fn read_ipv6(buffer: &mut BitBuffer) -> Result<Ipv6Addr, PduParseErr> {
    let hi = buffer.read_field(64, "ipv6_address_hi")?;
    let lo = buffer.read_field(64, "ipv6_address_lo")?;
    let val = ((hi as u128) << 64) | (lo as u128);
    Ok(Ipv6Addr::from(val))
}

/// Write a 128-bit IPv6 address (MSB-first).
pub fn write_ipv6(buffer: &mut BitBuffer, addr: &Ipv6Addr) {
    let val = u128::from(*addr);
    buffer.write_bits((val >> 64) as u64, 64);
    buffer.write_bits(val as u64, 64);
}

impl IpAddress {
    pub fn from_bitbuf_v4(buffer: &mut BitBuffer) -> Result<Self, PduParseErr> {
        Ok(IpAddress::V4(read_ipv4(buffer)?))
    }

    pub fn from_bitbuf_v6(buffer: &mut BitBuffer) -> Result<Self, PduParseErr> {
        Ok(IpAddress::V6(read_ipv6(buffer)?))
    }

    pub fn to_bitbuf(&self, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
        match self {
            IpAddress::V4(a) => write_ipv4(buffer, a),
            IpAddress::V6(a) => write_ipv6(buffer, a),
        }
        Ok(())
    }
}

impl core::fmt::Display for IpAddress {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            IpAddress::V4(a) => write!(f, "{a}"),
            IpAddress::V6(a) => write!(f, "{a}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_round_trip() {
        let addr = Ipv4Addr::new(192, 168, 1, 180);
        let mut buf = BitBuffer::new_autoexpand(32);
        write_ipv4(&mut buf, &addr);
        buf.seek(0);
        assert_eq!(read_ipv4(&mut buf).unwrap(), addr);
    }

    #[test]
    fn ipv6_round_trip() {
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let mut buf = BitBuffer::new_autoexpand(128);
        write_ipv6(&mut buf, &addr);
        buf.seek(0);
        assert_eq!(read_ipv6(&mut buf).unwrap(), addr);
    }
}
