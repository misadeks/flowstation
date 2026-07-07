//! SN-PDU type (4 bits, ETSI EN 300 392-2 clause 28.4.5).

/// SN-PDU type discriminator (4 bits). Values 14 and 15 are reserved and modelled
/// via `Reserved(u8)` so the codec can round-trip them without loss.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnPduType {
    ActivatePdpContext,
    DeactivatePdpContextAccept,
    DeactivatePdpContextDemand,
    ActivatePdpContextReject,
    Unitdata,
    Data,
    DataTransmitRequest,
    DataTransmitResponse,
    EndOfData,
    Reconnect,
    Page,
    NotSupported,
    DataPriority,
    Modify,
    /// Reserved values 14 and 15.
    Reserved(u8),
}

impl SnPduType {
    /// Convert this enum back into the raw 4-bit value.
    pub fn into_raw(self) -> u64 {
        match self {
            SnPduType::ActivatePdpContext => 0,
            SnPduType::DeactivatePdpContextAccept => 1,
            SnPduType::DeactivatePdpContextDemand => 2,
            SnPduType::ActivatePdpContextReject => 3,
            SnPduType::Unitdata => 4,
            SnPduType::Data => 5,
            SnPduType::DataTransmitRequest => 6,
            SnPduType::DataTransmitResponse => 7,
            SnPduType::EndOfData => 8,
            SnPduType::Reconnect => 9,
            SnPduType::Page => 10,
            SnPduType::NotSupported => 11,
            SnPduType::DataPriority => 12,
            SnPduType::Modify => 13,
            SnPduType::Reserved(v) => v as u64,
        }
    }
}

impl std::convert::TryFrom<u64> for SnPduType {
    type Error = ();
    fn try_from(x: u64) -> Result<Self, Self::Error> {
        match x {
            0 => Ok(SnPduType::ActivatePdpContext),
            1 => Ok(SnPduType::DeactivatePdpContextAccept),
            2 => Ok(SnPduType::DeactivatePdpContextDemand),
            3 => Ok(SnPduType::ActivatePdpContextReject),
            4 => Ok(SnPduType::Unitdata),
            5 => Ok(SnPduType::Data),
            6 => Ok(SnPduType::DataTransmitRequest),
            7 => Ok(SnPduType::DataTransmitResponse),
            8 => Ok(SnPduType::EndOfData),
            9 => Ok(SnPduType::Reconnect),
            10 => Ok(SnPduType::Page),
            11 => Ok(SnPduType::NotSupported),
            12 => Ok(SnPduType::DataPriority),
            13 => Ok(SnPduType::Modify),
            14 => Ok(SnPduType::Reserved(14)),
            15 => Ok(SnPduType::Reserved(15)),
            _ => Err(()),
        }
    }
}

impl From<SnPduType> for u64 {
    fn from(e: SnPduType) -> Self {
        e.into_raw()
    }
}

impl core::fmt::Display for SnPduType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SnPduType::ActivatePdpContext => write!(f, "ActivatePdpContext"),
            SnPduType::DeactivatePdpContextAccept => write!(f, "DeactivatePdpContextAccept"),
            SnPduType::DeactivatePdpContextDemand => write!(f, "DeactivatePdpContextDemand"),
            SnPduType::ActivatePdpContextReject => write!(f, "ActivatePdpContextReject"),
            SnPduType::Unitdata => write!(f, "Unitdata"),
            SnPduType::Data => write!(f, "Data"),
            SnPduType::DataTransmitRequest => write!(f, "DataTransmitRequest"),
            SnPduType::DataTransmitResponse => write!(f, "DataTransmitResponse"),
            SnPduType::EndOfData => write!(f, "EndOfData"),
            SnPduType::Reconnect => write!(f, "Reconnect"),
            SnPduType::Page => write!(f, "Page"),
            SnPduType::NotSupported => write!(f, "NotSupported"),
            SnPduType::DataPriority => write!(f, "DataPriority"),
            SnPduType::Modify => write!(f, "Modify"),
            SnPduType::Reserved(v) => write!(f, "Reserved({v})"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_all_values() {
        for raw in 0u64..=15 {
            let t = SnPduType::try_from(raw).unwrap();
            assert_eq!(t.into_raw(), raw);
        }
        assert!(SnPduType::try_from(16).is_err());
    }
}
