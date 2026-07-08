//! Reject-cause values for SN-DATA-TRANSMIT-RESPONSE (8 bits).
//!
//! ETSI TS 100 392-2 v3.10.1 clause 28.4.4.6, Table 28.31 / Table 28.125.

/// Cause returned in SN-DATA-TRANSMIT-RESPONSE when `accept = false`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransmitResponseRejectCause {
    Undefined,
    UnknownNsapi,
    SystemResourcesNotAvailable,
    RequestedMinimumPeakThroughputNotAvailable,
    RequestedScheduleNotAvailable,
    SndcpServiceTemporarilyNotAvailable,
    /// Catch-all for values 3..=22, 24, 26..=33, 35..=255.
    Reserved(u8),
}

impl TransmitResponseRejectCause {
    pub fn into_raw(self) -> u8 {
        match self {
            TransmitResponseRejectCause::Undefined => 0,
            TransmitResponseRejectCause::UnknownNsapi => 1,
            TransmitResponseRejectCause::SystemResourcesNotAvailable => 2,
            TransmitResponseRejectCause::RequestedMinimumPeakThroughputNotAvailable => 23,
            TransmitResponseRejectCause::RequestedScheduleNotAvailable => 25,
            TransmitResponseRejectCause::SndcpServiceTemporarilyNotAvailable => 34,
            TransmitResponseRejectCause::Reserved(v) => v,
        }
    }
}

impl From<u8> for TransmitResponseRejectCause {
    fn from(v: u8) -> Self {
        match v {
            0 => TransmitResponseRejectCause::Undefined,
            1 => TransmitResponseRejectCause::UnknownNsapi,
            2 => TransmitResponseRejectCause::SystemResourcesNotAvailable,
            23 => TransmitResponseRejectCause::RequestedMinimumPeakThroughputNotAvailable,
            25 => TransmitResponseRejectCause::RequestedScheduleNotAvailable,
            34 => TransmitResponseRejectCause::SndcpServiceTemporarilyNotAvailable,
            other => TransmitResponseRejectCause::Reserved(other),
        }
    }
}

