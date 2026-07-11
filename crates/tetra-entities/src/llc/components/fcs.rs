use tetra_core::BitBuffer;

/// Compute FCS checksum for a range of bits in a BitBuffer
/// Offsets are relative to the bitbuffer window start.
pub fn compute_fcs(bitbuf: &BitBuffer, start: usize, end: usize) -> u32 {
    assert!(start <= end);
    assert!(end <= bitbuf.get_len());

    let mut crc: u32 = 0xFFFFFFFF;
    let len = end - start;
    // Guard against a 32-bit shift overflow when the protected region is empty
    // (e.g. an FCS-flagged PDU with no payload): `crc <<= 32` panics in debug and is
    // a silent no-op in release. Skipping the pre-shift makes such a PDU simply fail
    // the FCS comparison and be rejected, which is the desired outcome.
    if len > 0 && len < 32 {
        crc <<= 32 - len;
    }

    // TODO optimize by fetching up to 64 bits per iteration
    for i in 0..len {
        let bit_pos = start + i;
        let bit = bitbuf.peek_bits_startoffset(bit_pos, 1).unwrap() as u8;
        let feedback = (bit ^ (crc >> 31) as u8) & 1;
        crc <<= 1;
        if feedback != 0 {
            crc ^= 0x04C11DB7;
        }
    }

    !crc
}

/// Computes and checks the FCS checksum.
///
/// Computes over bitbuffer range `[pos, end-32]`. Checks against FCS at
/// `[end - 32, end]`.
///
/// **FCS coverage window (PD-5c-H41 / audit LLC-03):** the caller is expected
/// to have already consumed the LLC PDU header (4 bits of type + N(S)/N(R)
/// bits) before invoking `check_fcs`; the checksum therefore protects the
/// TL-SDU payload only, not the LLC header. This is intentional and matches
/// the wire behaviour of Motorola DIMETRA TSC (`_append_fcs_to_l3_pdu` in
/// rlj_app operates on the L3 SDU, i.e. after LLC header stripping) and is
/// confirmed by the real-hardware capture in the `fcs_test` unit test below,
/// which computes FCS starting at bit 5 (after BL-DATA header) and matches
/// the FCS embedded in the frame. Corrupting a header bit will not be caught
/// by FCS; corrupting a payload bit will.
pub fn check_fcs(bitbuf: &BitBuffer) -> bool {
    if bitbuf.get_len_remaining() < 32 {
        tracing::warn!(
            "check_fcs: Not enough bits for FCS, length remaining: {}",
            bitbuf.get_len_remaining()
        );
        return false;
    }
    let fcs_computed = compute_fcs(bitbuf, bitbuf.get_pos(), bitbuf.get_len() - 32);
    let fcs_extracted = bitbuf.peek_bits_startoffset(bitbuf.get_len() - 32, 32).unwrap() as u32;
    fcs_computed == fcs_extracted
}

#[cfg(test)]
mod tests {
    use tetra_pdus::llc::pdus::bl_data::BlData;

    use super::*;

    #[test]
    fn fcs_test() {
        let testvec = "010100100111101011010111110000100110000110001011000011000000000000000011000100000001001100110011000000110010001011000011001000110000001100100011000100110001001100010011000100110101001100100011000000110010001100000011000000110001011001111010000010101011000110101";
        let mut bitbuf = BitBuffer::from_bitstr(testvec);
        bitbuf.seek(5);
        let fcs = compute_fcs(&bitbuf, 5, 5 + 224);
        let extracted_fcs = bitbuf.peek_bits_startoffset(5 + 224, 32).unwrap() as u32;
        assert_eq!(fcs, extracted_fcs);
    }

    #[test]
    fn bldata_with_fcs() {
        let testvec = "010100100111101011010111110000100110000110001011000011000000000000000011000100000001001100110011000000110010001011000011001000110000001100100011000100110001001100010011000100110101001100100011000000110010001100000011000000110001011001111010000010101011000110101";
        let mut bitbuf = BitBuffer::from_bitstr(testvec);
        let pdu = BlData::from_bitbuf(&mut bitbuf).expect("Failed to parse BL-DATA PDU");
        assert!(pdu.has_fcs, "PDU should have FCS");
        let fcs_ok = check_fcs(&bitbuf);
        assert!(fcs_ok, "FCS check failed");
    }

    // PD-5c-H41 (audit LLC-03): FCS coverage window is TL-SDU only, not the
    // full LLC PDU. The two tests below pin down this deviation so a future
    // change to `check_fcs` that extends the window to bit 0 will fail loudly.
    //
    // Evidence: Motorola DIMETRA TSC's `_append_fcs_to_l3_pdu` (rlj_app
    // 0x001ebe88) operates on the L3 SDU (after LLC header stripping),
    // matching the flowstation TL-SDU-only computation. The real-frame
    // capture used in `fcs_test` above confirms bit range [5..229] matches
    // the embedded FCS for a BL-DATA frame.

    #[test]
    fn fcs_covers_tl_sdu_only_hw_deviation() {
        // Flipping a bit in the LLC header (bit 2 of the type field) must NOT
        // be caught by FCS — the header is outside the protected window. This
        // documents an intentional deviation from a strict reading of ETSI
        // clause 21.4.3 that matches the wire behaviour of Motorola hardware.
        let testvec = "010100100111101011010111110000100110000110001011000011000000000000000011000100000001001100110011000000110010001011000011001000110000001100100011000100110001001100010011000100110101001100100011000000110010001100000011000000110001011001111010000010101011000110101";
        let mut bytes: Vec<char> = testvec.chars().collect();
        // Flip bit 2 (part of the LLC PDU type field, outside the FCS window).
        bytes[2] = if bytes[2] == '0' { '1' } else { '0' };
        let corrupted: String = bytes.into_iter().collect();
        let mut bitbuf = BitBuffer::from_bitstr(&corrupted);
        // Skip past the 5-bit BL-DATA header (matches what a real parser does).
        bitbuf.seek(5);
        assert!(
            check_fcs(&bitbuf),
            "FCS must still pass when a header bit is flipped — header is outside the protected window (matches TSC behaviour)"
        );
    }

    #[test]
    fn fcs_covers_tl_sdu_payload_bit_flip_caught() {
        // Flipping a bit inside the TL-SDU payload MUST be caught by FCS —
        // this is the actual data-integrity guarantee we provide.
        let testvec = "010100100111101011010111110000100110000110001011000011000000000000000011000100000001001100110011000000110010001011000011001000110000001100100011000100110001001100010011000100110101001100100011000000110010001100000011000000110001011001111010000010101011000110101";
        let mut bytes: Vec<char> = testvec.chars().collect();
        // Flip a bit well inside the TL-SDU body (index 100 is comfortably
        // between the 5-bit header and the trailing 32-bit FCS).
        bytes[100] = if bytes[100] == '0' { '1' } else { '0' };
        let corrupted: String = bytes.into_iter().collect();
        let mut bitbuf = BitBuffer::from_bitstr(&corrupted);
        bitbuf.seek(5);
        assert!(
            !check_fcs(&bitbuf),
            "FCS must reject a payload bit-flip"
        );
    }
}
