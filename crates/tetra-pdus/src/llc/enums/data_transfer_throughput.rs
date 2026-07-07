use core::fmt;

/// Data transfer throughput class negotiated in AL-SETUP.
///
/// 3-bit field.
///
/// NOTE: value `ContextDependent` (6 / `110`) has a dual meaning depending on
/// `connection_width` — see ETSI TS 100 392-2 v3.10.1 clause 21.2.3.5 table 21.23.
///
/// ETSI TS 100 392-2 v3.10.1 clause 21.2.3.5, table 21.23.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DataTransferThroughput {
    /// Network-dependent minimum (0).
    NetworkDependentMin = 0,
    /// 1/32 of channel capacity (1).
    OneOver32 = 1,
    /// 1/16 of channel capacity (2).
    OneOver16 = 2,
    /// 1/8 of channel capacity (3).
    OneOver8 = 3,
    /// 1/4 of channel capacity (4).
    OneOver4 = 4,
    /// 1/2 of channel capacity (5).
    OneOver2 = 5,
    /// Context-dependent (6).
    ///
    /// NOTE: spec — value 110 has dual meaning based on `connection_width`; see
    /// ETSI TS 100 392-2 v3.10.1 clause 21.2.3.5 table 21.23.
    ContextDependent = 6,
    /// Maximum channel capacity (7).
    Maximum = 7,
}

impl DataTransferThroughput {
    pub fn into_raw(self) -> u64 {
        self as u64
    }
}

impl TryFrom<u64> for DataTransferThroughput {
    type Error = ();
    fn try_from(v: u64) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(DataTransferThroughput::NetworkDependentMin),
            1 => Ok(DataTransferThroughput::OneOver32),
            2 => Ok(DataTransferThroughput::OneOver16),
            3 => Ok(DataTransferThroughput::OneOver8),
            4 => Ok(DataTransferThroughput::OneOver4),
            5 => Ok(DataTransferThroughput::OneOver2),
            6 => Ok(DataTransferThroughput::ContextDependent),
            7 => Ok(DataTransferThroughput::Maximum),
            _ => Err(()),
        }
    }
}

impl fmt::Display for DataTransferThroughput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DataTransferThroughput::NetworkDependentMin => write!(f, "NetworkDependentMin"),
            DataTransferThroughput::OneOver32 => write!(f, "1/32"),
            DataTransferThroughput::OneOver16 => write!(f, "1/16"),
            DataTransferThroughput::OneOver8 => write!(f, "1/8"),
            DataTransferThroughput::OneOver4 => write!(f, "1/4"),
            DataTransferThroughput::OneOver2 => write!(f, "1/2"),
            DataTransferThroughput::ContextDependent => write!(f, "ContextDependent"),
            DataTransferThroughput::Maximum => write!(f, "Maximum"),
        }
    }
}
