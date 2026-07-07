use core::fmt;

/// AL-RECONNECT outcome code (2 bits).
///
/// ETSI TS 100 392-2 v3.10.1 clause 21.2.3.4a, table 21.22.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ReconnectReport {
    /// Propose reconnection (0).
    Propose = 0,
    /// Reject reconnection (1).
    Reject = 1,
    /// Accept reconnection (2).
    Accept = 2,
    /// Reserved (3).
    Reserved = 3,
}

impl ReconnectReport {
    pub fn into_raw(self) -> u64 {
        self as u64
    }
}

impl TryFrom<u64> for ReconnectReport {
    type Error = ();
    fn try_from(v: u64) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(ReconnectReport::Propose),
            1 => Ok(ReconnectReport::Reject),
            2 => Ok(ReconnectReport::Accept),
            3 => Ok(ReconnectReport::Reserved),
            _ => Err(()),
        }
    }
}

impl fmt::Display for ReconnectReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReconnectReport::Propose => write!(f, "Propose"),
            ReconnectReport::Reject => write!(f, "Reject"),
            ReconnectReport::Accept => write!(f, "Accept"),
            ReconnectReport::Reserved => write!(f, "Reserved"),
        }
    }
}
