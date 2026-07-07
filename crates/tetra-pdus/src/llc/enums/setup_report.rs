use core::fmt;

/// AL-SETUP result/report code (3 bits).
///
/// ETSI TS 100 392-2 v3.10.1 clause 21.2.3.5, table 21.23.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetupReport {
    /// Setup succeeded (0).
    Success,
    /// Service definition (1).
    ServiceDefinition,
    /// Service change (2).
    ServiceChange,
    /// Reset (3).
    Reset,
    /// Setup succeeded but SNDCP QoS was incomplete (4).
    SuccessSndcpQosIncomplete,
    /// Reserved (5..7).
    Reserved(u8),
}

impl SetupReport {
    pub fn into_raw(self) -> u64 {
        match self {
            SetupReport::Success => 0,
            SetupReport::ServiceDefinition => 1,
            SetupReport::ServiceChange => 2,
            SetupReport::Reset => 3,
            SetupReport::SuccessSndcpQosIncomplete => 4,
            SetupReport::Reserved(v) => v as u64,
        }
    }
}

impl TryFrom<u64> for SetupReport {
    type Error = ();
    fn try_from(v: u64) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(SetupReport::Success),
            1 => Ok(SetupReport::ServiceDefinition),
            2 => Ok(SetupReport::ServiceChange),
            3 => Ok(SetupReport::Reset),
            4 => Ok(SetupReport::SuccessSndcpQosIncomplete),
            5..=7 => Ok(SetupReport::Reserved(v as u8)),
            _ => Err(()),
        }
    }
}

impl fmt::Display for SetupReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SetupReport::Success => write!(f, "Success"),
            SetupReport::ServiceDefinition => write!(f, "ServiceDefinition"),
            SetupReport::ServiceChange => write!(f, "ServiceChange"),
            SetupReport::Reset => write!(f, "Reset"),
            SetupReport::SuccessSndcpQosIncomplete => write!(f, "SuccessSndcpQosIncomplete"),
            SetupReport::Reserved(v) => write!(f, "Reserved({})", v),
        }
    }
}
