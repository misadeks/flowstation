use core::fmt;

use tetra_core::BitBuffer;
use tetra_core::pdu_parse_error::*;
use tetra_core::let_field;

use crate::llc::enums::advanced_link_service::AdvancedLinkService;
use crate::llc::enums::reconnect_report::ReconnectReport;

/// AL-RECONNECT PDU — re-establish an AL after temporary failure without full re-SETUP.
///
/// Non-octet-aligned: 5 bits of body (after the 4-bit type). MAC framing handles padding.
///
/// ETSI TS 100 392-2 v3.10.1 clause 21.2.3.4a, table 21.22.
///
/// Wire layout after the 4-bit `LlcPduType` (= 12):
/// ```text
/// advanced_link_service   1   0 = unack, 1 = ack  (AdvancedLinkService)
/// advanced_link_number    2   0..3 → link 1..4    (N261)
/// reconnect_report        2   outcome/proposal     (ReconnectReport)
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AlReconnect {
    /// Service type of the link being reconnected.
    pub advanced_link_service: AdvancedLinkService,
    /// Link number 0..3 (N261, maps to physical link 1..4).
    pub advanced_link_number_n261: u8,
    /// Reconnect outcome / proposal code.
    pub reconnect_report: ReconnectReport,
}

impl AlReconnect {
    /// Decode from a `BitBuffer` positioned immediately **after** the 4-bit `LlcPduType`.
    pub fn from_bitbuf(buf: &mut BitBuffer) -> Result<Self, PduParseErr> {
        let_field!(buf, svc, 1);
        let advanced_link_service =
            AdvancedLinkService::try_from(svc).map_err(|_| PduParseErr::InvalidValue {
                field: "advanced_link_service",
                value: svc,
            })?;

        let_field!(buf, link_num, 2);

        let_field!(buf, report_raw, 2);
        let reconnect_report =
            ReconnectReport::try_from(report_raw).map_err(|_| PduParseErr::InvalidValue {
                field: "reconnect_report",
                value: report_raw,
            })?;

        Ok(AlReconnect {
            advanced_link_service,
            advanced_link_number_n261: link_num as u8,
            reconnect_report,
        })
    }

    /// Encode into a `BitBuffer`, writing the 4-bit `LlcPduType` (12) first.
    pub fn to_bitbuf(&self, buf: &mut BitBuffer) {
        // 4-bit LlcPduType = 12 (AlReconnect)
        buf.write_bits(12, 4);
        buf.write_bits(self.advanced_link_service.into_raw(), 1);
        buf.write_bits(self.advanced_link_number_n261 as u64, 2);
        buf.write_bits(self.reconnect_report.into_raw(), 2);
    }
}

impl fmt::Display for AlReconnect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "al_reconnect {{ service: {}, link: {}, report: {} }}",
            self.advanced_link_service, self.advanced_link_number_n261, self.reconnect_report,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(pdu: &AlReconnect) -> AlReconnect {
        let mut enc = BitBuffer::new_autoexpand(64);
        pdu.to_bitbuf(&mut enc);
        enc.seek(0);
        enc.read_bits(4).unwrap();
        AlReconnect::from_bitbuf(&mut enc).expect("decode failed")
    }

    #[test]
    fn al_reconnect_default_round_trip() {
        let pdu = AlReconnect {
            advanced_link_service: AdvancedLinkService::Ack,
            advanced_link_number_n261: 0,
            reconnect_report: ReconnectReport::Propose,
        };
        assert_eq!(round_trip(&pdu), pdu);
    }

    #[test]
    fn al_reconnect_populated_round_trip() {
        let pdu = AlReconnect {
            advanced_link_service: AdvancedLinkService::Unack,
            advanced_link_number_n261: 3,
            reconnect_report: ReconnectReport::Accept,
        };
        assert_eq!(round_trip(&pdu), pdu);
    }

    #[test]
    fn al_reconnect_reject_round_trip() {
        let pdu = AlReconnect {
            advanced_link_service: AdvancedLinkService::Ack,
            advanced_link_number_n261: 2,
            reconnect_report: ReconnectReport::Reject,
        };
        assert_eq!(round_trip(&pdu), pdu);
    }
}
