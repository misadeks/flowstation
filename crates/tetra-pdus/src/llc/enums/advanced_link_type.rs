use core::fmt;

/// Advanced link type — original (window ≤ 3) or extended (window ≤ 15).
///
/// Present in AL-SETUP when the augmented window mode is selected
/// (`tl_sdu_window_size_n272_n281 == 0`).
///
/// ETSI TS 100 392-2 v3.10.1 clause 21.2.3.5, table 21.23.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AdvancedLinkType {
    /// Original AL (window 1..3).
    Original = 0,
    /// Extended AL (window 1..15).
    Extended = 1,
}

impl AdvancedLinkType {
    pub fn into_raw(self) -> u64 {
        self as u64
    }
}

impl TryFrom<u64> for AdvancedLinkType {
    type Error = ();
    fn try_from(v: u64) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(AdvancedLinkType::Original),
            1 => Ok(AdvancedLinkType::Extended),
            _ => Err(()),
        }
    }
}

impl fmt::Display for AdvancedLinkType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AdvancedLinkType::Original => write!(f, "Original"),
            AdvancedLinkType::Extended => write!(f, "Extended"),
        }
    }
}
