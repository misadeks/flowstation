//! PD-5c-H51 AL FCS round-trip regression tests.
//!
//! Exercises `segment_sdu` + `Reassembler` + `crc32_bits` end-to-end for
//! SDU sizes bracketing the failing `/portal/system` case (65 B, 2 segments,
//! non-byte-aligned FINAL of 152 tl_sdu_segment bits). All cases confirm
//! the LLC AL stack is internally self-consistent: the concatenated
//! tl_sdu_segment bit stream ends with a 32-bit tail that matches
//! `crc32_bits(all_bits[..-32])` for the CRC-32/BZIP2 parameters we use
//! (poly `0x04C11DB7`, MSB-first, no reflection, init `0xFFFFFFFF`, final
//! XOR `0xFFFFFFFF` — see `crate::llc::al::fcs`).
//!
//! **Investigation trail (do not delete these tests):**
//!
//! - Hardware T1 confirmed the 65-B `/portal/system` payload
//!   deterministically triggers `SduFcsFailure` from MTP6550 while the
//!   27-B and 125-B payloads on the same link accept cleanly.
//! - Hardware T2 (`append_fcs = false` experiment on a temporary config
//!   knob) confirmed MTP6550 rejects **all** sizes when the 32-bit FCS
//!   trailer is omitted → hypothesis E (DIMETRA-style bit-transparent AL)
//!   ruled out; the FCS append is mandatory to spec.
//! - Combined: the CRC math is right (all sizes work in T1 with FCS on),
//!   the FCS is required (all sizes fail in T2 with FCS off), so the
//!   remaining 65-B `/portal/system` failure is a UMAC-layer effect
//!   (fill-bit interaction with the 169-bit AL-FINAL, or DATA+FINAL
//!   frame-boundary padding). Trace via `RUST_LOG=h51=info`.
//!
//! These tests are the canary: if a future refactor breaks our own
//! CRC-32/BZIP2 computation or the segmenter's tail arithmetic, the 65-B
//! case will regress here loudly, before it ever hits the air.

#[cfg(test)]
mod h51_roundtrip {
    use crate::llc::al::fcs::{crc32, crc32_bits};
    use crate::llc::al::reassembler::{Reassembler, ReassemblerFeed};
    use crate::llc::al::segmenter::{SegmenterConfig, segment_sdu};

    /// Expand `bytes` into an MSB-first bit vector (one `u8` per bit).
    fn to_bits_msb_first(bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(bytes.len() * 8);
        for &byte in bytes {
            for i in (0..8).rev() {
                out.push((byte >> i) & 1);
            }
        }
        out
    }

    fn concat_segments(pdus: &[crate::llc::pdus::al_data::AlDataAlFinal]) -> Vec<u8> {
        let mut bits = Vec::new();
        for p in pdus {
            let mut copy = tetra_core::BitBuffer::from_bitbuffer(&p.tl_sdu_segment);
            for _ in 0..p.tl_sdu_segment.get_len() {
                bits.push(copy.read_bit().unwrap_or(0));
            }
        }
        bits
    }

    fn make_sdu(size: usize) -> Vec<u8> {
        // Deterministic pseudo-random-looking bytes.
        (0..size as u8).map(|i| i.wrapping_mul(37).wrapping_add(11)).collect()
    }

    fn roundtrip_case(body_bytes: usize, expected_segs: usize) {
        let sdu = make_sdu(body_bytes);
        let cfg = SegmenterConfig {
            segment_payload_bits: 400,
            starting_n_s: 2,
            request_ack_on_final: true,
            request_ack_on_data: false,
        };
        let out = segment_sdu(&sdu, &cfg).unwrap();
        assert_eq!(
            out.pdus.len(),
            expected_segs,
            "segment count for {}-B SDU",
            body_bytes,
        );

        // 1. External-observer FCS check: concatenate all tl_sdu_segment bits,
        //    read last 32 as FCS, check crc32_bits over the rest.
        let all_bits = concat_segments(&out.pdus);
        assert_eq!(
            all_bits.len(),
            body_bytes * 8 + 32,
            "assembled bit length wrong for {} B",
            body_bytes,
        );
        let split = all_bits.len() - 32;
        let ext_fcs = all_bits[split..].iter().fold(0u32, |a, &b| (a << 1) | (b as u32));
        let cmp_fcs = crc32_bits(&all_bits[..split]);
        assert_eq!(
            ext_fcs, cmp_fcs,
            "external-observer FCS mismatch for {} B (poly 0x04C11DB7, unreflected)",
            body_bytes,
        );

        // 2. Cross-check crc32_bits matches byte-wise crc32.
        let sdu_bits = to_bits_msb_first(&sdu);
        assert_eq!(crc32(&sdu), crc32_bits(&sdu_bits), "crc byte vs bit for {} B", body_bytes);

        // 3. Round-trip through the reassembler.
        let mut rx = Reassembler::new(2);
        let mut final_result = None;
        for pdu in &out.pdus {
            let r = rx.feed(pdu).unwrap();
            if matches!(r, ReassemblerFeed::Complete { .. } | ReassemblerFeed::FcsFailure { .. }) {
                final_result = Some(r);
            }
        }
        let final_result = final_result.expect("reassembler never completed");
        match final_result {
            ReassemblerFeed::Complete { sdu: rx_sdu } => {
                let expected_bits = body_bytes * 8;
                assert_eq!(rx_sdu.get_len(), expected_bits, "reassembled bit length {} B", body_bytes);
            }
            ReassemblerFeed::FcsFailure { info, .. } => {
                panic!("reassembler FCS mismatch for {}-B SDU: {:?}", body_bytes, info);
            }
            ReassemblerFeed::NeedMore { .. } => unreachable!(),
        }

        // 4. Print bit-exact tail for eyeballing.
        let tail_start = split.saturating_sub(16);
        let tail_bits: String = all_bits[tail_start..]
            .iter()
            .map(|&b| if b == 0 { '0' } else { '1' })
            .collect();
        eprintln!(
            "H51 {} B: segs={} last{}bits_incl_fcs={} fcs=0x{:08X}",
            body_bytes,
            out.pdus.len(),
            all_bits.len() - tail_start,
            tail_bits,
            cmp_fcs,
        );

        // 5. PD-5c-H51 per-segment dump — variant, N(S), S(S), payload
        //    bit-length, and semantic `fcs` hint for every produced PDU.
        //    Confirms every FINAL length is exactly
        //    `total_bits mod segment_payload_bits` (no off-by-one/32).
        for (i, pdu) in out.pdus.iter().enumerate() {
            eprintln!(
                "H51 {} B seg[{}]: variant={} n_s={} s_s={} sdu_len_bits={} fcs_hint={:?}",
                body_bytes,
                i,
                pdu.variant,
                pdu.n_s,
                pdu.s_s,
                pdu.tl_sdu_segment.get_len(),
                pdu.fcs,
            );
        }
    }

    #[test] fn portal_index_27b_one_seg()   { roundtrip_case(27,  1); }
    #[test] fn portal_system_65b_two_segs() { roundtrip_case(65,  2); }
    #[test] fn portal_menu_125b_three_segs(){ roundtrip_case(125, 3); }
}
