//! Logical Link Status field in SN-DATA-TRANSMIT-REQUEST (1 bit).
//!
//! ETSI TS 100 392-2 v3.10.1 clause 28.4.4.5, Table 28.30.

/// Whether the Advanced Link is already connected when the MS sends
/// SN-DATA-TRANSMIT-REQUEST.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LogicalLinkStatus {
    /// AL not yet connected (0).
    NotConnected = 0,
    /// AL already connected (1).
    Connected = 1,
}

impl TryFrom<u64> for LogicalLinkStatus {
    type Error = ();
    fn try_from(v: u64) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(LogicalLinkStatus::NotConnected),
            1 => Ok(LogicalLinkStatus::Connected),
            _ => Err(()),
        }
    }
}

impl LogicalLinkStatus {
    pub fn into_raw(self) -> u64 {
        self as u64
    }
}
