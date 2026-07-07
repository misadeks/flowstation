//! Deactivation type, 8 bits, ETSI EN 300 392-2 table 28.65.

/// Deactivation type in SN-DEACTIVATE PDP CONTEXT DEMAND (8 bits).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeactivationType {
    Normal,
    Regulatory,
    NetworkInitiated,
    /// Any other (reserved) value.
    Reserved(u8),
}

impl DeactivationType {
    pub fn into_raw(self) -> u64 {
        match self {
            DeactivationType::Normal => 0,
            DeactivationType::Regulatory => 1,
            DeactivationType::NetworkInitiated => 2,
            DeactivationType::Reserved(v) => v as u64,
        }
    }
}

impl std::convert::TryFrom<u64> for DeactivationType {
    type Error = ();
    fn try_from(x: u64) -> Result<Self, Self::Error> {
        match x {
            0 => Ok(DeactivationType::Normal),
            1 => Ok(DeactivationType::Regulatory),
            2 => Ok(DeactivationType::NetworkInitiated),
            3..=255 => Ok(DeactivationType::Reserved(x as u8)),
            _ => Err(()),
        }
    }
}

impl From<DeactivationType> for u64 {
    fn from(e: DeactivationType) -> Self {
        e.into_raw()
    }
}

impl core::fmt::Display for DeactivationType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DeactivationType::Normal => write!(f, "Normal"),
            DeactivationType::Regulatory => write!(f, "Regulatory"),
            DeactivationType::NetworkInitiated => write!(f, "NetworkInitiated"),
            DeactivationType::Reserved(v) => write!(f, "Reserved({v})"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_known_values() {
        for raw in 0u64..=5 {
            let t = DeactivationType::try_from(raw).unwrap();
            assert_eq!(t.into_raw(), raw);
        }
        assert_eq!(DeactivationType::try_from(255).unwrap().into_raw(), 255);
    }
}
