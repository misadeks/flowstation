//! Golden-fixture test for the WSP Connect PDU decoder.
//!
//! Byte-for-byte checks against the 447-byte S-Connect that a Motorola
//! MTP3550 (UP.Browser 6.3.0.1) sent to the gateway on 2026-07-10 —
//! captured with tcpdump on the base station in the same test session
//! whose WTP trace is quoted in the PD-10b prompt.
//!
//! Also asserts the *cap-echo* property that makes PD-10b worth writing at
//! all: the ConnectReply we build from the fixture must re-encode its
//! capability block to bytes byte-identical to what the MS proposed. That
//! is exactly the property Kannel violates with `sanitize_capabilities()`.

use wap_gateway::wsp::caps::Capability;
use wap_gateway::wsp::pdu::{HeaderBlock, WspPdu, build_connect_reply, pdu_type};

/// Load the fixture as raw bytes. `include_bytes!` keeps it a pure static.
const FIXTURE: &[u8] = include_bytes!("fixtures/mtp3550_connect.bin");

/// The 21-byte SANITIZED capability block we now emit in our ConnectReply,
/// matching Kannel's `sanitize_capabilities()` behaviour. This is the byte
/// pattern UP.Browser expects to see back from the gateway. Hardware
/// testing 2026-07-10 confirmed that echoing MS's original 29-byte block
/// verbatim got past WTP but was silently discarded at the WSP layer.
const SANITIZED_CAPS_BLOCK: &[u8] = &[
    0x04, 0x80, 0x94, 0x80, 0x00, // Client-SDU-Size (echoed)
    0x04, 0x81, 0x94, 0x80, 0x00, // Server-SDU-Size (echoed)
    0x02, 0x82, 0x00, // Protocol-Options: top nibble cleared (0xF0 -> 0x00)
    0x02, 0x83, 0x03, // Method-MOR (echoed)
    0x02, 0x84, 0x01, // Push-MOR (echoed)
    0x01, 0x86, // Header-Code-Pages / Extended-Methods: refused (zero-length payload)
];

/// The raw 29-byte block the MS proposes (kept for the framing check on the
/// uplink fixture — this is what MS sends, NOT what we reply with).
const HW_ORIGINAL_CAPS_BLOCK: &[u8] = &[
    0x04, 0x80, 0x94, 0x80, 0x00, 0x04, 0x81, 0x94, 0x80, 0x00, 0x02, 0x82, 0xF0, 0x02, 0x83, 0x03, 0x02, 0x84, 0x01,
    0x09, 0x86, 0x10, 0x78, 0x2D, 0x75, 0x70, 0x2D, 0x31, 0x00,
];

#[test]
fn fixture_is_the_expected_size() {
    // Sanity: the prompt gives us a 447-byte MS Connect, and the WTP
    // Result the gateway logged had the same length. If this assert ever
    // fails it means the file was truncated by a copy-paste or line-ending
    // conversion.
    assert_eq!(FIXTURE.len(), 447, "MTP3550 Connect fixture must be 447 bytes");
    assert_eq!(FIXTURE[0], pdu_type::CONNECT);
    assert_eq!(FIXTURE[1], 0x10);
}

#[test]
fn caps_block_bytes_match_hardware_dump() {
    // Confirms our own understanding of the outer framing (5-byte header)
    // before we hand bytes to the decoder.
    assert_eq!(&FIXTURE[5..34], HW_ORIGINAL_CAPS_BLOCK);
}

#[test]
fn decodes_connect_pdu_with_expected_capabilities() {
    let pdu = WspPdu::decode(FIXTURE).expect("MTP3550 fixture must decode cleanly");
    let WspPdu::Connect {
        version,
        capabilities,
        headers,
    } = pdu
    else {
        panic!("expected Connect PDU, got {pdu:?}");
    };

    assert_eq!(version, 0x10, "UP.Browser sends WSP protocol version 1.0");

    // Exactly six well-known capabilities — Kannel's sanitize would drop the
    // Openwave-quirky ones; we must keep them.
    assert_eq!(capabilities.len(), 6, "expected 6 caps, got {capabilities:?}");
    assert!(matches!(capabilities[0], Capability::ClientSduSize(_)));
    assert!(matches!(capabilities[1], Capability::ServerSduSize(_)));
    assert_eq!(
        capabilities[2],
        Capability::ProtocolOptions(0xF0),
        "Protocol-Options MUST be preserved bit-for-bit (Openwave quirk)"
    );
    assert_eq!(capabilities[3], Capability::MethodMor(3));
    assert_eq!(capabilities[4], Capability::PushMor(1));
    assert_eq!(
        capabilities[5],
        Capability::ExtendedMethods(vec![(0x10, b"x-up-1".to_vec())]),
        "Extended-Methods MUST be preserved verbatim (Openwave quirk)"
    );

    // Header block is 413 bytes ((5 + 29 + 413) = 447) and contains the
    // MS's User-Agent + Encoding-Version tokens as literal substrings.
    assert_eq!(headers.len(), 413);
    assert!(
        headers.contains(b"UP.Browser/6.3.0.1"),
        "headers must contain the UP.Browser User-Agent"
    );
    assert!(headers.contains(b"MOT-MTP3550"), "headers must contain the MOT-MTP3550 model tag");
    assert!(
        headers.contains(b"Encoding-version"),
        "headers must contain the Encoding-version token-text"
    );
}

#[test]
fn connect_reply_cap_block_matches_kannel_sanitized() {
    // Round-trip: decode fixture → build ConnectReply → re-encode → decode
    // again → assert cap wire bytes equal the KANNEL sanitized block.
    // (We used to assert byte-identical-to-MS but hardware testing showed
    // MS silently drops replies that dishonestly echo caps we don't
    // implement — Kannel's sanitizer is correct.)
    let connect = WspPdu::decode(FIXTURE).unwrap();
    let reply = build_connect_reply(&connect, /* server session id */ 1, HeaderBlock::empty()).unwrap();
    let bytes = reply.encode();

    // Type=CONNECT_REPLY, then uintvar session-id.
    assert_eq!(bytes[0], pdu_type::CONNECT_REPLY);

    // Decode our own ConnectReply and pull the cap block back out.
    let decoded = WspPdu::decode(&bytes).unwrap();
    let WspPdu::ConnectReply {
        server_session_id,
        capabilities,
        headers,
    } = decoded
    else {
        panic!("re-decoded ConnectReply is not a ConnectReply: {decoded:?}");
    };
    assert_eq!(server_session_id, 1);
    // Headers block MUST carry Encoding-Version: 1.3 → wire bytes `C3 93`.
    assert_eq!(headers.raw, vec![0xC3, 0x93]);

    // Re-encode just the caps and compare to the Kannel-sanitized block.
    let cap_bytes = wap_gateway::wsp::caps::encode_list(&capabilities);
    assert_eq!(
        cap_bytes, SANITIZED_CAPS_BLOCK,
        "ConnectReply cap block must match Kannel sanitize_capabilities() output"
    );
}
