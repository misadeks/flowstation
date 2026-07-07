//! Reject cause, 8 bits, ETSI EN 300 392-2 table 28.108.

/// Reject cause in SN-ACTIVATE PDP CONTEXT REJECT (8 bits).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectCause {
    SubscriberUnknown,
    IssiNotAuthorised,
    PdpContextAlreadyActive,
    PdpTypeNotSupported,
    RequestedStaticIpv4NotAvailable,
    NoResource,
    ActivationNotAllowed,
    NetworkFailure,
    AuthenticationFailure,
    PcoNotSupported,
    ApnNotSupported,
    TransientFailure,
    /// Any other value (including 0 and 13..=255).
    Reserved(u8),
}

impl RejectCause {
    pub fn from_raw(x: u8) -> Self {
        match x {
            1 => RejectCause::SubscriberUnknown,
            2 => RejectCause::IssiNotAuthorised,
            3 => RejectCause::PdpContextAlreadyActive,
            4 => RejectCause::PdpTypeNotSupported,
            5 => RejectCause::RequestedStaticIpv4NotAvailable,
            6 => RejectCause::NoResource,
            7 => RejectCause::ActivationNotAllowed,
            8 => RejectCause::NetworkFailure,
            9 => RejectCause::AuthenticationFailure,
            10 => RejectCause::PcoNotSupported,
            11 => RejectCause::ApnNotSupported,
            12 => RejectCause::TransientFailure,
            other => RejectCause::Reserved(other),
        }
    }

    pub fn into_raw(self) -> u8 {
        match self {
            RejectCause::SubscriberUnknown => 1,
            RejectCause::IssiNotAuthorised => 2,
            RejectCause::PdpContextAlreadyActive => 3,
            RejectCause::PdpTypeNotSupported => 4,
            RejectCause::RequestedStaticIpv4NotAvailable => 5,
            RejectCause::NoResource => 6,
            RejectCause::ActivationNotAllowed => 7,
            RejectCause::NetworkFailure => 8,
            RejectCause::AuthenticationFailure => 9,
            RejectCause::PcoNotSupported => 10,
            RejectCause::ApnNotSupported => 11,
            RejectCause::TransientFailure => 12,
            RejectCause::Reserved(v) => v,
        }
    }
}

impl std::convert::TryFrom<u64> for RejectCause {
    type Error = ();
    fn try_from(x: u64) -> Result<Self, Self::Error> {
        if x <= 255 {
            Ok(RejectCause::from_raw(x as u8))
        } else {
            Err(())
        }
    }
}

impl From<RejectCause> for u64 {
    fn from(e: RejectCause) -> Self {
        e.into_raw() as u64
    }
}

impl core::fmt::Display for RejectCause {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_known_values() {
        for raw in 1u8..=12 {
            let c = RejectCause::from_raw(raw);
            assert_eq!(c.into_raw(), raw);
            assert_eq!(RejectCause::try_from(raw as u64).unwrap().into_raw(), raw);
        }
        assert_eq!(RejectCause::from_raw(0), RejectCause::Reserved(0));
        assert_eq!(RejectCause::from_raw(200).into_raw(), 200);
    }
}
