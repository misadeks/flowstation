//! Configuration protocol, 4 bits, ETSI EN 300 392-2 table 28.105.

/// Configuration protocol in the PCO element (4 bits).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigurationProtocol {
    Ppp,
    /// Reserved values 1..=15.
    Reserved(u8),
}

impl ConfigurationProtocol {
    pub fn into_raw(self) -> u64 {
        match self {
            ConfigurationProtocol::Ppp => 0,
            ConfigurationProtocol::Reserved(v) => v as u64,
        }
    }
}

impl std::convert::TryFrom<u64> for ConfigurationProtocol {
    type Error = ();
    fn try_from(x: u64) -> Result<Self, Self::Error> {
        match x {
            0 => Ok(ConfigurationProtocol::Ppp),
            1..=15 => Ok(ConfigurationProtocol::Reserved(x as u8)),
            _ => Err(()),
        }
    }
}

impl From<ConfigurationProtocol> for u64 {
    fn from(e: ConfigurationProtocol) -> Self {
        e.into_raw()
    }
}

impl core::fmt::Display for ConfigurationProtocol {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ConfigurationProtocol::Ppp => write!(f, "Ppp"),
            ConfigurationProtocol::Reserved(v) => write!(f, "Reserved({v})"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_all_values() {
        for raw in 0u64..=15 {
            let t = ConfigurationProtocol::try_from(raw).unwrap();
            assert_eq!(t.into_raw(), raw);
        }
        assert!(ConfigurationProtocol::try_from(16).is_err());
    }
}
