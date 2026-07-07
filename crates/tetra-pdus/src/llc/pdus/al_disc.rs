use core::fmt;

use tetra_core::BitBuffer;
use tetra_core::pdu_parse_error::*;
use tetra_core::let_field;

use crate::llc::enums::advanced_link_service::AdvancedLinkService;
use crate::llc::enums::al_disc_cause::AlDiscCause;

/// AL-DISC PDU — Advanced-link disconnect.
///
/// Non-octet-aligned: 6 bits of body (after the 4-bit type). MAC framing handles padding.
///
/// ETSI TS 100 392-2 v3.10.1 clause 21.2.3.4, table 21.21.
///
/// Wire layout after the 4-bit `LlcPduType` (= 15):
/// ```text
/// advanced_link_service   1   0 = unack, 1 = ack  (AdvancedLinkService)
/// advanced_link_number    2   0..3 → link 1..4    (N261)
/// report                  3   disconnect cause     (AlDiscCause)
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AlDisc {
    /// Service type of the link being disconnected.
    pub advanced_link_service: AdvancedLinkService,
    /// Link number 0..3 (N261, maps to physical link 1..4).
    pub advanced_link_number_n261: u8,
    /// 3-bit disconnect cause/report code.
    pub report: AlDiscCause,
}

impl AlDisc {
    /// Decode from a `BitBuffer` positioned immediately **after** the 4-bit `LlcPduType`.
    pub fn from_bitbuf(buf: &mut BitBuffer) -> Result<Self, PduParseErr> {
        let_field!(buf, svc, 1);
        let advanced_link_service =
            AdvancedLinkService::try_from(svc).map_err(|_| PduParseErr::InvalidValue {
                field: "advanced_link_service",
                value: svc,
            })?;

        let_field!(buf, link_num, 2);

        let_field!(buf, cause_raw, 3);
        let report =
            AlDiscCause::try_from(cause_raw).map_err(|_| PduParseErr::InvalidValue {
                field: "report",
                value: cause_raw,
            })?;

        Ok(AlDisc {
            advanced_link_service,
            advanced_link_number_n261: link_num as u8,
            report,
        })
    }

    /// Encode into a `BitBuffer`, writing the 4-bit `LlcPduType` (15) first.
    pub fn to_bitbuf(&self, buf: &mut BitBuffer) {
        // 4-bit LlcPduType = 15 (AlDisc)
        buf.write_bits(15, 4);
        buf.write_bits(self.advanced_link_service.into_raw(), 1);
        buf.write_bits(self.advanced_link_number_n261 as u64, 2);
        buf.write_bits(self.report.into_raw(), 3);
    }
}

impl fmt::Display for AlDisc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "al_disc {{ service: {}, link: {}, report: {} }}",
            self.advanced_link_service, self.advanced_link_number_n261, self.report,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(pdu: &AlDisc) -> AlDisc {
        let mut enc = BitBuffer::new_autoexpand(64);
        pdu.to_bitbuf(&mut enc);
        enc.seek(0);
        enc.read_bits(4).unwrap();
        AlDisc::from_bitbuf(&mut enc).expect("decode failed")
    }

    #[test]
    fn al_disc_default_round_trip() {
        let pdu = AlDisc {
            advanced_link_service: AdvancedLinkService::Ack,
            advanced_link_number_n261: 0,
            report: AlDiscCause::Success,
        };
        assert_eq!(round_trip(&pdu), pdu);
    }

    #[test]
    fn al_disc_populated_round_trip() {
        let pdu = AlDisc {
            advanced_link_service: AdvancedLinkService::Unack,
            advanced_link_number_n261: 3,
            report: AlDiscCause::Reject,
        };
        assert_eq!(round_trip(&pdu), pdu);
    }

    #[test]
    fn al_disc_service_not_supported_round_trip() {
        let pdu = AlDisc {
            advanced_link_service: AdvancedLinkService::Ack,
            advanced_link_number_n261: 1,
            report: AlDiscCause::ServiceNotSupported,
        };
        assert_eq!(round_trip(&pdu), pdu);
    }

    #[test]
    fn al_disc_reserved_cause_round_trip() {
        let pdu = AlDisc {
            advanced_link_service: AdvancedLinkService::Ack,
            advanced_link_number_n261: 2,
            report: AlDiscCause::Reserved(7),
        };
        assert_eq!(round_trip(&pdu), pdu);
    }
}
