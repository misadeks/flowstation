//! MTU field, 3 bits, ETSI EN 300 392-2 table 28.79.

/// MTU (3 bits). Maps the 3-bit code to a maximum-transfer-unit size in octets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mtu(pub u8);

impl Mtu {
    /// Maximum transfer unit in octets.
    pub fn octets(&self) -> u16 {
        match self.0 {
            0 => 128,
            1 => 296,
            2 => 500,
            3 => 1000,
            4 => 1500,
            5 => 2000,
            6 => 4096,
            _ => 8192,
        }
    }

    pub fn into_raw(self) -> u64 {
        self.0 as u64
    }
}

impl std::convert::TryFrom<u8> for Mtu {
    type Error = ();
    fn try_from(x: u8) -> Result<Self, Self::Error> {
        if x <= 7 { Ok(Mtu(x)) } else { Err(()) }
    }
}

impl core::fmt::Display for Mtu {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Mtu({} octets)", self.octets())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn octet_mapping() {
        assert_eq!(Mtu(0).octets(), 128);
        assert_eq!(Mtu(4).octets(), 1500);
        assert_eq!(Mtu(7).octets(), 8192);
    }

    #[test]
    fn round_trip_all_values() {
        for v in 0u8..=7 {
            assert_eq!(Mtu::try_from(v).unwrap().into_raw(), v as u64);
        }
        assert!(Mtu::try_from(8).is_err());
    }
}
