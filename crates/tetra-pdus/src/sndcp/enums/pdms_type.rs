//! PDMS type, 4 bits, ETSI EN 300 392-2 clause 28.

/// PDMSType field in SN-ACTIVATE PDP CONTEXT DEMAND (4 bits).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PdmsType {
    Standard,
    /// Reserved values 1..=15.
    Reserved(u8),
}

impl PdmsType {
    pub fn into_raw(self) -> u64 {
        match self {
            PdmsType::Standard => 0,
            PdmsType::Reserved(v) => v as u64,
        }
    }
}

impl std::convert::TryFrom<u64> for PdmsType {
    type Error = ();
    fn try_from(x: u64) -> Result<Self, Self::Error> {
        match x {
            0 => Ok(PdmsType::Standard),
            1..=15 => Ok(PdmsType::Reserved(x as u8)),
            _ => Err(()),
        }
    }
}

impl From<PdmsType> for u64 {
    fn from(e: PdmsType) -> Self {
        e.into_raw()
    }
}

impl core::fmt::Display for PdmsType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PdmsType::Standard => write!(f, "Standard"),
            PdmsType::Reserved(v) => write!(f, "Reserved({v})"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_all_values() {
        for raw in 0u64..=15 {
            let t = PdmsType::try_from(raw).unwrap();
            assert_eq!(t.into_raw(), raw);
        }
        assert!(PdmsType::try_from(16).is_err());
    }
}
