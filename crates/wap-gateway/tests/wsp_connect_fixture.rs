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

/// The 29-byte capability block as it appears in the fixture (bytes 5..34).
/// Kept as a separate const so a failing assertion prints the exact
/// hardware bytes we're comparing against.
const HW_CAPS_BLOCK: &[u8] = &[
    0x04, 0x80, 0x94, 0x80, 0x00, // Client-SDU-Size
    0x04, 0x81, 0x94, 0x80, 0x00, // Server-SDU-Size
    0x02, 0x82, 0xF0, // Protocol-Options (Openwave critical)
    0x02, 0x83, 0x03, // Method-MOR
    0x02, 0x84, 0x01, // Push-MOR
    0x09, 0x86, 0x10, 0x78, 0x2D, 0x75, 0x70, 0x2D, 0x31, 0x00, // Extended-Methods x-up-1
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
    assert_eq!(&FIXTURE[5..34], HW_CAPS_BLOCK);
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
fn connect_reply_cap_block_is_byte_identical_to_hardware() {
    // Round-trip: decode fixture → build ConnectReply → re-encode → decode
    // again → assert cap wire bytes equal HW_CAPS_BLOCK.
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
    assert!(headers.is_empty());

    // Re-encode just the caps and compare to hardware.
    let cap_bytes = wap_gateway::wsp::caps::encode_list(&capabilities);
    assert_eq!(
        cap_bytes, HW_CAPS_BLOCK,
        "ConnectReply cap block must be byte-identical to the MS's proposal"
    );
}
