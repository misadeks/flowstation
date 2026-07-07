use core::fmt;

/// AL-DISC disconnect report code (3 bits).
///
/// Cross-referenced against Motorola DIMETRA tsc.elf disassembly:
/// `z_PDTypes_5C_AL_DISC_SUCCESS`, `z_PDTypes_5D_AL_DISC_REJECT` constants confirm
/// 3-bit field width and variant assignments.
///
/// ETSI TS 100 392-2 v3.10.1 clause 21.2.3.4, table 21.21.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlDiscCause {
    /// Disconnect completed successfully (0).
    Success,
    /// Link closed by peer (1).
    Close,
    /// Disconnect rejected (2).
    ///
    /// Confirmed by DIMETRA `z_PDTypes_5D_AL_DISC_REJECT`.
    Reject,
    /// Requested service not supported (3).
    ServiceNotSupported,
    /// Service temporarily unavailable (4).
    ServiceTemporarilyUnavailable,
    /// Reserved (5..7).
    Reserved(u8),
}

impl AlDiscCause {
    pub fn into_raw(self) -> u64 {
        match self {
            AlDiscCause::Success => 0,
            AlDiscCause::Close => 1,
            AlDiscCause::Reject => 2,
            AlDiscCause::ServiceNotSupported => 3,
            AlDiscCause::ServiceTemporarilyUnavailable => 4,
            AlDiscCause::Reserved(v) => v as u64,
        }
    }
}

impl TryFrom<u64> for AlDiscCause {
    type Error = ();
    fn try_from(v: u64) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(AlDiscCause::Success),
            1 => Ok(AlDiscCause::Close),
            2 => Ok(AlDiscCause::Reject),
            3 => Ok(AlDiscCause::ServiceNotSupported),
            4 => Ok(AlDiscCause::ServiceTemporarilyUnavailable),
            5..=7 => Ok(AlDiscCause::Reserved(v as u8)),
            _ => Err(()),
        }
    }
}

impl fmt::Display for AlDiscCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AlDiscCause::Success => write!(f, "Success"),
            AlDiscCause::Close => write!(f, "Close"),
            AlDiscCause::Reject => write!(f, "Reject"),
            AlDiscCause::ServiceNotSupported => write!(f, "ServiceNotSupported"),
            AlDiscCause::ServiceTemporarilyUnavailable => write!(f, "ServiceTemporarilyUnavailable"),
            AlDiscCause::Reserved(v) => write!(f, "Reserved({})", v),
        }
    }
}
