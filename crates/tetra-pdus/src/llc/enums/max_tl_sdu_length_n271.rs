use core::fmt;

/// Encoded maximum TL-SDU length negotiated in AL-SETUP (N271).
///
/// 3-bit field; value 0 = 32 octets, each step doubles, value 7 = 4096 octets.
///
/// ETSI TS 100 392-2 v3.10.1 clause 21.2.3.5, table 21.23.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MaxTlSduLengthN271 {
    Bytes32 = 0,
    Bytes64 = 1,
    Bytes128 = 2,
    Bytes256 = 3,
    Bytes512 = 4,
    Bytes1024 = 5,
    Bytes2048 = 6,
    Bytes4096 = 7,
}

impl MaxTlSduLengthN271 {
    pub fn into_raw(self) -> u64 {
        self as u64
    }

    /// Returns the actual maximum TL-SDU length in octets.
    pub fn octets(self) -> u16 {
        32u16 << (self as u16)
    }
}

impl TryFrom<u64> for MaxTlSduLengthN271 {
    type Error = ();
    fn try_from(v: u64) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(MaxTlSduLengthN271::Bytes32),
            1 => Ok(MaxTlSduLengthN271::Bytes64),
            2 => Ok(MaxTlSduLengthN271::Bytes128),
            3 => Ok(MaxTlSduLengthN271::Bytes256),
            4 => Ok(MaxTlSduLengthN271::Bytes512),
            5 => Ok(MaxTlSduLengthN271::Bytes1024),
            6 => Ok(MaxTlSduLengthN271::Bytes2048),
            7 => Ok(MaxTlSduLengthN271::Bytes4096),
            _ => Err(()),
        }
    }
}

impl fmt::Display for MaxTlSduLengthN271 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}B", self.octets())
    }
}
