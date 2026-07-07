//! Type Identifier in Accept (TIA), 3 bits, ETSI EN 300 392-2 table 28.126.

/// TIA field in SN-ACTIVATE PDP CONTEXT ACCEPT (3 bits).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tia {
    NoIpAddress,
    Ipv4Static,
    Ipv4Dynamic,
    Ipv6Static,
    Ipv6Dynamic,
    /// Reserved values 5..=7.
    Reserved(u8),
}

impl Tia {
    pub fn into_raw(self) -> u64 {
        match self {
            Tia::NoIpAddress => 0,
            Tia::Ipv4Static => 1,
            Tia::Ipv4Dynamic => 2,
            Tia::Ipv6Static => 3,
            Tia::Ipv6Dynamic => 4,
            Tia::Reserved(v) => v as u64,
        }
    }
}

impl std::convert::TryFrom<u64> for Tia {
    type Error = ();
    fn try_from(x: u64) -> Result<Self, Self::Error> {
        match x {
            0 => Ok(Tia::NoIpAddress),
            1 => Ok(Tia::Ipv4Static),
            2 => Ok(Tia::Ipv4Dynamic),
            3 => Ok(Tia::Ipv6Static),
            4 => Ok(Tia::Ipv6Dynamic),
            5..=7 => Ok(Tia::Reserved(x as u8)),
            _ => Err(()),
        }
    }
}

impl From<Tia> for u64 {
    fn from(e: Tia) -> Self {
        e.into_raw()
    }
}

impl core::fmt::Display for Tia {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Tia::NoIpAddress => write!(f, "NoIpAddress"),
            Tia::Ipv4Static => write!(f, "Ipv4Static"),
            Tia::Ipv4Dynamic => write!(f, "Ipv4Dynamic"),
            Tia::Ipv6Static => write!(f, "Ipv6Static"),
            Tia::Ipv6Dynamic => write!(f, "Ipv6Dynamic"),
            Tia::Reserved(v) => write!(f, "Reserved({v})"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_all_values() {
        for raw in 0u64..=7 {
            let t = Tia::try_from(raw).unwrap();
            assert_eq!(t.into_raw(), raw);
        }
        assert!(Tia::try_from(8).is_err());
    }
}
