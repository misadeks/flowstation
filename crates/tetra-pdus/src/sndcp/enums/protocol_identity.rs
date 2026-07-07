//! Protocol identity, 16 bits, PPP/RFC 3232 configuration protocol identifiers.

/// Protocol identity in a PCO entry (16 bits).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolIdentity {
    Lcp,
    Pap,
    Chap,
    Ipcp,
    Ipv4,
    /// Any other 16-bit protocol identifier.
    Other(u16),
}

impl ProtocolIdentity {
    pub fn from_raw(x: u16) -> Self {
        match x {
            0xC021 => ProtocolIdentity::Lcp,
            0xC023 => ProtocolIdentity::Pap,
            0xC223 => ProtocolIdentity::Chap,
            0x8021 => ProtocolIdentity::Ipcp,
            0x0021 => ProtocolIdentity::Ipv4,
            other => ProtocolIdentity::Other(other),
        }
    }

    pub fn into_raw(self) -> u16 {
        match self {
            ProtocolIdentity::Lcp => 0xC021,
            ProtocolIdentity::Pap => 0xC023,
            ProtocolIdentity::Chap => 0xC223,
            ProtocolIdentity::Ipcp => 0x8021,
            ProtocolIdentity::Ipv4 => 0x0021,
            ProtocolIdentity::Other(v) => v,
        }
    }
}

impl std::convert::TryFrom<u64> for ProtocolIdentity {
    type Error = ();
    fn try_from(x: u64) -> Result<Self, Self::Error> {
        if x <= 0xFFFF {
            Ok(ProtocolIdentity::from_raw(x as u16))
        } else {
            Err(())
        }
    }
}

impl From<ProtocolIdentity> for u64 {
    fn from(e: ProtocolIdentity) -> Self {
        e.into_raw() as u64
    }
}

impl core::fmt::Display for ProtocolIdentity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_known_values() {
        for raw in [0xC021u16, 0xC023, 0xC223, 0x8021, 0x0021, 0x1234] {
            let p = ProtocolIdentity::from_raw(raw);
            assert_eq!(p.into_raw(), raw);
        }
        assert_eq!(ProtocolIdentity::from_raw(0x1234), ProtocolIdentity::Other(0x1234));
    }
}
