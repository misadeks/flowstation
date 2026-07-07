use core::fmt;

/// Advanced link symmetry — whether uplink and downlink window sizes match.
///
/// ETSI TS 100 392-2 v3.10.1 clause 21.2.3.5, table 21.23.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AdvancedLinkSymmetry {
    /// Symmetric link (0).
    Symmetric = 0,
    /// Asymmetric link (1).
    Asymmetric = 1,
}

impl AdvancedLinkSymmetry {
    pub fn into_raw(self) -> u64 {
        self as u64
    }
}

impl TryFrom<u64> for AdvancedLinkSymmetry {
    type Error = ();
    fn try_from(v: u64) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(AdvancedLinkSymmetry::Symmetric),
            1 => Ok(AdvancedLinkSymmetry::Asymmetric),
            _ => Err(()),
        }
    }
}

impl fmt::Display for AdvancedLinkSymmetry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AdvancedLinkSymmetry::Symmetric => write!(f, "Symmetric"),
            AdvancedLinkSymmetry::Asymmetric => write!(f, "Asymmetric"),
        }
    }
}
