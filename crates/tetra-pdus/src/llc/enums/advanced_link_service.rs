use core::fmt;

/// Advanced link service type — acknowledged or unacknowledged.
///
/// ETSI TS 100 392-2 v3.10.1 clause 21.2.3.5, table 21.23.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AdvancedLinkService {
    /// Unacknowledged service (0).
    Unack = 0,
    /// Acknowledged service (1).
    Ack = 1,
}

impl AdvancedLinkService {
    pub fn into_raw(self) -> u64 {
        self as u64
    }
}

impl TryFrom<u64> for AdvancedLinkService {
    type Error = ();
    fn try_from(v: u64) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(AdvancedLinkService::Unack),
            1 => Ok(AdvancedLinkService::Ack),
            _ => Err(()),
        }
    }
}

impl fmt::Display for AdvancedLinkService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AdvancedLinkService::Unack => write!(f, "Unack"),
            AdvancedLinkService::Ack => write!(f, "Ack"),
        }
    }
}
