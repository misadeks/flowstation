use core::fmt;

use tetra_core::BitBuffer;
use tetra_core::pdu_parse_error::*;
use tetra_core::let_field;

use crate::llc::enums::advanced_link_service::AdvancedLinkService;
use crate::llc::enums::advanced_link_symmetry::AdvancedLinkSymmetry;
use crate::llc::enums::advanced_link_type::AdvancedLinkType;
use crate::llc::enums::data_transfer_throughput::DataTransferThroughput;
use crate::llc::enums::max_tl_sdu_length_n271::MaxTlSduLengthN271;
use crate::llc::enums::setup_report::SetupReport;

/// AL-SETUP PDU — negotiate Advanced Link parameters.
///
/// Negotiates service type (ack/unack), SDU length (N271), throughput, window sizes
/// (N272/N281), retransmission limits (N273/N274), and DQPSK timeslots (N264).
///
/// Field presence rules (all conditional on earlier fields):
/// - `n264_dqpsk_ts_uplink`: present iff `connection_width == 1`.
///   NOTE: spec — also conditional on unspecified phase-modulation; AL-1 codec
///   treats it as present iff `connection_width == 1`.
/// - `n264_dqpsk_ts_downlink`: present iff `connection_width == 1` AND
///   `advanced_link_symmetry == Asymmetric`.
/// - `n_s`: present iff `advanced_link_service == Unack`.
/// - Augmented window fields (`advanced_link_type`, `n272_n281_augmented`, `reserved`):
///   present iff `tl_sdu_window_size_n272_n281 == 0`.
///   When augmented: `n272_n281_augmented` is 2 bits if `Original`, 4 bits if `Extended`.
///
/// ETSI TS 100 392-2 v3.10.1 clause 21.2.3.5, table 21.23.
///
/// Wire layout after the 4-bit `LlcPduType` (= 8):
/// ```text
/// advanced_link_service     1   AdvancedLinkService
/// advanced_link_number      2   N261 (0..3 → link 1..4)
/// max_tl_sdu_length_n271    3   MaxTlSduLengthN271 (encoded)
/// connection_width          1   context-dependent 1-bit flag
/// advanced_link_symmetry    1   AdvancedLinkSymmetry
/// [connection_width == 1]
///   n264_dqpsk_ts_uplink    2
///   [asymmetric]
///     n264_dqpsk_ts_downlink 2
/// data_transfer_throughput  3   DataTransferThroughput
/// tl_sdu_window_size        2   00 = augmented, 01..11 → window 1..3 (N272/N281)
/// max_retx_or_repetitions   3   0..7 (N273 or N282)
/// max_segment_retx_n274     4   0..15
/// setup_report              3   SetupReport
/// [service == Unack]
///   n_s                     8
/// [window_size == 0 (augmented)]
///   advanced_link_type      1   AdvancedLinkType
///   n272_n281_augmented     2 (Original) or 4 (Extended)
///   reserved                3
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlSetup {
    /// Service type: acknowledged or unacknowledged.
    pub advanced_link_service: AdvancedLinkService,
    /// Link number 0..3 (N261, maps to physical link 1..4).
    pub advanced_link_number_n261: u8,
    /// Maximum TL-SDU length code (N271).
    pub max_tl_sdu_length_n271: MaxTlSduLengthN271,
    /// Connection width flag (1 bit, context-dependent per spec).
    pub connection_width: u8,
    /// Link symmetry.
    pub advanced_link_symmetry: AdvancedLinkSymmetry,
    /// DQPSK uplink timeslot count, 2 bits; present iff `connection_width == 1`.
    pub n264_dqpsk_ts_uplink: Option<u8>,
    /// DQPSK downlink timeslot count, 2 bits; present iff `connection_width == 1` AND asymmetric.
    pub n264_dqpsk_ts_downlink: Option<u8>,
    /// Data transfer throughput class.
    pub data_transfer_throughput: DataTransferThroughput,
    /// TL-SDU window size: 0 = augmented, 1..3 = window 1..3 (N272/N281).
    pub tl_sdu_window_size_n272_n281: u8,
    /// Max retransmissions (N273) or repetitions (N282), 3 bits (0..7).
    pub max_retx_n273_or_repetition_n282: u8,
    /// Max segment retransmissions (N274), 4 bits (0..15).
    pub max_segment_retx_n274: u8,
    /// Setup result / report code.
    pub setup_report: SetupReport,
    /// Send sequence number, 8 bits; present iff `advanced_link_service == Unack`.
    pub n_s: Option<u8>,
    /// AL type (original/extended); present iff `tl_sdu_window_size_n272_n281 == 0`.
    pub advanced_link_type: Option<AdvancedLinkType>,
    /// Augmented window size value; present iff `tl_sdu_window_size_n272_n281 == 0`.
    /// 2 bits when `advanced_link_type == Original`, 4 bits when `Extended`.
    pub n272_n281_augmented: Option<u8>,
    /// 3-bit reserved field; present iff `tl_sdu_window_size_n272_n281 == 0`.
    pub reserved: Option<u8>,
}

impl AlSetup {
    /// Decode from a `BitBuffer` positioned immediately **after** the 4-bit `LlcPduType`.
    pub fn from_bitbuf(buf: &mut BitBuffer) -> Result<Self, PduParseErr> {
        let_field!(buf, svc, 1);
        let advanced_link_service =
            AdvancedLinkService::try_from(svc).map_err(|_| PduParseErr::InvalidValue {
                field: "advanced_link_service",
                value: svc,
            })?;

        let_field!(buf, link_num, 2);

        let_field!(buf, sdu_len_code, 3);
        let max_tl_sdu_length_n271 =
            MaxTlSduLengthN271::try_from(sdu_len_code).map_err(|_| PduParseErr::InvalidValue {
                field: "max_tl_sdu_length_n271",
                value: sdu_len_code,
            })?;

        let_field!(buf, conn_width, 1);

        let_field!(buf, sym, 1);
        let advanced_link_symmetry =
            AdvancedLinkSymmetry::try_from(sym).map_err(|_| PduParseErr::InvalidValue {
                field: "advanced_link_symmetry",
                value: sym,
            })?;

        let (n264_up, n264_dn) = if conn_width != 0 {
            let_field!(buf, up, 2);
            let dn = if advanced_link_symmetry == AdvancedLinkSymmetry::Asymmetric {
                let_field!(buf, dn, 2);
                Some(dn as u8)
            } else {
                None
            };
            (Some(up as u8), dn)
        } else {
            (None, None)
        };

        let_field!(buf, throughput, 3);
        let data_transfer_throughput =
            DataTransferThroughput::try_from(throughput).map_err(|_| PduParseErr::InvalidValue {
                field: "data_transfer_throughput",
                value: throughput,
            })?;

        let_field!(buf, win_size, 2);
        let_field!(buf, max_retx, 3);
        let_field!(buf, max_seg_retx, 4);
        let_field!(buf, setup_rep, 3);
        let setup_report =
            SetupReport::try_from(setup_rep).map_err(|_| PduParseErr::InvalidValue {
                field: "setup_report",
                value: setup_rep,
            })?;

        let n_s = if advanced_link_service == AdvancedLinkService::Unack {
            let_field!(buf, ns, 8);
            Some(ns as u8)
        } else {
            None
        };

        let (advanced_link_type, n272_n281_augmented, reserved) = if win_size == 0 {
            let_field!(buf, al_type_raw, 1);
            let al_type =
                AdvancedLinkType::try_from(al_type_raw).map_err(|_| PduParseErr::InvalidValue {
                    field: "advanced_link_type",
                    value: al_type_raw,
                })?;
            let aug_bits = match al_type {
                AdvancedLinkType::Original => 2,
                AdvancedLinkType::Extended => 4,
            };
            let aug = buf.read_field(aug_bits, "n272_n281_augmented")?;
            let_field!(buf, rsv, 3);
            (Some(al_type), Some(aug as u8), Some(rsv as u8))
        } else {
            (None, None, None)
        };

        Ok(AlSetup {
            advanced_link_service,
            advanced_link_number_n261: link_num as u8,
            max_tl_sdu_length_n271,
            connection_width: conn_width as u8,
            advanced_link_symmetry,
            n264_dqpsk_ts_uplink: n264_up,
            n264_dqpsk_ts_downlink: n264_dn,
            data_transfer_throughput,
            tl_sdu_window_size_n272_n281: win_size as u8,
            max_retx_n273_or_repetition_n282: max_retx as u8,
            max_segment_retx_n274: max_seg_retx as u8,
            setup_report,
            n_s,
            advanced_link_type,
            n272_n281_augmented,
            reserved,
        })
    }

    /// Encode into a `BitBuffer`, writing the 4-bit `LlcPduType` (8) first.
    pub fn to_bitbuf(&self, buf: &mut BitBuffer) {
        // 4-bit LlcPduType = 8 (AlSetup)
        buf.write_bits(8, 4);

        buf.write_bits(self.advanced_link_service.into_raw(), 1);
        buf.write_bits(self.advanced_link_number_n261 as u64, 2);
        buf.write_bits(self.max_tl_sdu_length_n271.into_raw(), 3);
        buf.write_bits(self.connection_width as u64, 1);
        buf.write_bits(self.advanced_link_symmetry.into_raw(), 1);

        if self.connection_width != 0 {
            buf.write_bits(self.n264_dqpsk_ts_uplink.unwrap_or(0) as u64, 2);
            if self.advanced_link_symmetry == AdvancedLinkSymmetry::Asymmetric {
                buf.write_bits(self.n264_dqpsk_ts_downlink.unwrap_or(0) as u64, 2);
            }
        }

        buf.write_bits(self.data_transfer_throughput.into_raw(), 3);
        buf.write_bits(self.tl_sdu_window_size_n272_n281 as u64, 2);
        buf.write_bits(self.max_retx_n273_or_repetition_n282 as u64, 3);
        buf.write_bits(self.max_segment_retx_n274 as u64, 4);
        buf.write_bits(self.setup_report.into_raw(), 3);

        if self.advanced_link_service == AdvancedLinkService::Unack {
            buf.write_bits(self.n_s.unwrap_or(0) as u64, 8);
        }

        if self.tl_sdu_window_size_n272_n281 == 0 {
            let al_type = self.advanced_link_type.unwrap_or(AdvancedLinkType::Original);
            buf.write_bits(al_type.into_raw(), 1);
            let aug_bits = match al_type {
                AdvancedLinkType::Original => 2,
                AdvancedLinkType::Extended => 4,
            };
            buf.write_bits(self.n272_n281_augmented.unwrap_or(0) as u64, aug_bits);
            buf.write_bits(self.reserved.unwrap_or(0) as u64, 3);
        }
    }
}

impl fmt::Display for AlSetup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "al_setup {{ service: {}, link: {}, n271: {}, conn_w: {}, sym: {}, throughput: {}, win: {}, max_retx: {}, max_seg_retx: {}, report: {}",
            self.advanced_link_service,
            self.advanced_link_number_n261,
            self.max_tl_sdu_length_n271,
            self.connection_width,
            self.advanced_link_symmetry,
            self.data_transfer_throughput,
            self.tl_sdu_window_size_n272_n281,
            self.max_retx_n273_or_repetition_n282,
            self.max_segment_retx_n274,
            self.setup_report,
        )?;
        if let Some(ns) = self.n_s {
            write!(f, ", n_s: {}", ns)?;
        }
        if let Some(al_type) = self.advanced_link_type {
            write!(f, ", al_type: {}", al_type)?;
        }
        write!(f, " }}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(pdu: &AlSetup) -> AlSetup {
        let mut enc = BitBuffer::new_autoexpand(128);
        pdu.to_bitbuf(&mut enc);
        enc.seek(0);
        enc.read_bits(4).unwrap();
        AlSetup::from_bitbuf(&mut enc).expect("decode failed")
    }

    fn base_setup() -> AlSetup {
        AlSetup {
            advanced_link_service: AdvancedLinkService::Ack,
            advanced_link_number_n261: 0,
            max_tl_sdu_length_n271: MaxTlSduLengthN271::Bytes256,
            connection_width: 0,
            advanced_link_symmetry: AdvancedLinkSymmetry::Symmetric,
            n264_dqpsk_ts_uplink: None,
            n264_dqpsk_ts_downlink: None,
            data_transfer_throughput: DataTransferThroughput::Maximum,
            tl_sdu_window_size_n272_n281: 1,
            max_retx_n273_or_repetition_n282: 3,
            max_segment_retx_n274: 5,
            setup_report: SetupReport::Success,
            n_s: None,
            advanced_link_type: None,
            n272_n281_augmented: None,
            reserved: None,
        }
    }

    #[test]
    fn al_setup_default_round_trip() {
        assert_eq!(round_trip(&base_setup()), base_setup());
    }

    #[test]
    fn al_setup_unack_with_ns_round_trip() {
        let pdu = AlSetup {
            advanced_link_service: AdvancedLinkService::Unack,
            n_s: Some(42),
            setup_report: SetupReport::ServiceDefinition,
            ..base_setup()
        };
        assert_eq!(round_trip(&pdu), pdu);
    }

    #[test]
    fn al_setup_asymmetric_with_n264_round_trip() {
        let pdu = AlSetup {
            connection_width: 1,
            advanced_link_symmetry: AdvancedLinkSymmetry::Asymmetric,
            n264_dqpsk_ts_uplink: Some(3),
            n264_dqpsk_ts_downlink: Some(1),
            advanced_link_number_n261: 2,
            ..base_setup()
        };
        assert_eq!(round_trip(&pdu), pdu);
    }

    #[test]
    fn al_setup_augmented_original_round_trip() {
        let pdu = AlSetup {
            tl_sdu_window_size_n272_n281: 0,
            advanced_link_type: Some(AdvancedLinkType::Original),
            n272_n281_augmented: Some(2),
            reserved: Some(0),
            ..base_setup()
        };
        assert_eq!(round_trip(&pdu), pdu);
    }

    #[test]
    fn al_setup_augmented_extended_round_trip() {
        let pdu = AlSetup {
            tl_sdu_window_size_n272_n281: 0,
            advanced_link_type: Some(AdvancedLinkType::Extended),
            n272_n281_augmented: Some(11),
            reserved: Some(5),
            ..base_setup()
        };
        assert_eq!(round_trip(&pdu), pdu);
    }
}
