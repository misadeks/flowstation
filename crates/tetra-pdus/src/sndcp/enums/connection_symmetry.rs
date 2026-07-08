//! Connection symmetry field in SN-DATA-TRANSMIT-REQUEST's ResourceRequest (1 bit).
//!
//! ETSI TS 100 392-2 v3.10.1 clause 28.4.4.5, Table 28.30 / Table 28.115.

/// Whether the requested connection is symmetric or asymmetric.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ConnectionSymmetry {
    /// Symmetric: equal UL and DL slot counts (0).
    Symmetric = 0,
    /// Asymmetric: separate UL and DL slot counts follow (1).
    Asymmetric = 1,
}

impl TryFrom<u64> for ConnectionSymmetry {
    type Error = ();
    fn try_from(v: u64) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(ConnectionSymmetry::Symmetric),
            1 => Ok(ConnectionSymmetry::Asymmetric),
            _ => Err(()),
        }
    }
}

impl ConnectionSymmetry {
    pub fn into_raw(self) -> u64 {
        self as u64
    }
}
