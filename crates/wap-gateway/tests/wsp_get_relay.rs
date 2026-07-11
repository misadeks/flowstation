//! PD-10c end-to-end: MS Get → gateway → mock HTTP upstream → WSP Reply.
//!
//! The mock upstream is a hand-rolled minimal HTTP/1.1 server on a
//! [`TcpListener`] — no `hyper` dependency needed because we only serve
//! one canned response per accepted connection. The gateway is spun up on
//! the same tokio runtime, then we drive it with:
//!
//!   1. A synthetic WSP Connect (bare Protocol-Options cap only, so the
//!      handshake fits in one WTP segment on a loopback socket).
//!   2. A WSP Get for `http://127.0.0.1:<mock port>/index.wml`.
//!
//! The test asserts:
//!
//! * We get back a WTP Ack + Result for the Get.
//! * The Result payload decodes to a `WspPdu::Reply` with status = OK.
//! * The Reply body is exactly the bytes the mock returned.
//! * The Reply's headers block starts with the WSP well-known short-int
//!   for `application/vnd.wap.wmlc` (`0x94`), proving the Content-Type
//!   round-trip works on the real WTP → WSP encode path.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio_util::sync::CancellationToken;
use wap_gateway::wsp::caps::Capability;
use wap_gateway::wsp::pdu::{ContentType, HeaderBlock, WspPdu, pdu_type};
use wap_gateway::wtp::pdu::{HeaderFlags, TransactionClass, WtpPdu};
use wap_gateway::{RunConfig, run};

/// Fixed body the mock HTTP server returns on every request. Not real
/// compiled WML — just a byte pattern we can assert byte-for-byte on the
/// way out of the gateway.
const MOCK_WMLC_BODY: &[u8] = &[0x02, 0x00, 0x00, 0xEF, 0xBB, 0xBF, 0xDE, 0xAD, 0xBE, 0xEF];

/// Spawn a one-shot mock HTTP/1.1 upstream on 127.0.0.1:<random>. Accepts
/// exactly one connection, reads until it sees the end of the request
/// headers (`\r\n\r\n`), and replies with `MOCK_WMLC_BODY` under a
/// `Content-Type: application/vnd.wap.wmlc` header.
async fn spawn_mock_http() -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut sock, _peer) = listener.accept().await.expect("mock accept");
        let mut buf = Vec::with_capacity(256);
        let mut tmp = [0u8; 512];
        loop {
            let n = match sock.read(&mut tmp).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };
            buf.extend_from_slice(&tmp[..n]);
            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        let mut resp = Vec::new();
        resp.extend_from_slice(b"HTTP/1.1 200 OK\r\n");
        resp.extend_from_slice(b"Content-Type: application/vnd.wap.wmlc\r\n");
        resp.extend_from_slice(format!("Content-Length: {}\r\n", MOCK_WMLC_BODY.len()).as_bytes());
        resp.extend_from_slice(b"Connection: close\r\n\r\n");
        resp.extend_from_slice(MOCK_WMLC_BODY);
        let _ = sock.write_all(&resp).await;
        let _ = sock.shutdown().await;
    });
    addr
}

/// Encode a minimal WSP Connect the gateway will accept: version 1.0,
/// one Protocol-Options capability, no headers. Small enough to fit in a
/// single WTP Invoke on loopback.
fn minimal_connect_bytes() -> Vec<u8> {
    WspPdu::Connect {
        version: 0x10,
        capabilities: vec![Capability::ProtocolOptions(0x00)],
        headers: HeaderBlock::empty(),
    }
    .encode()
}

/// Drive one Class-2 WTP transaction (`invoke` as request payload).
/// Returns the reassembled Result payload after Ack'ing every Result /
/// SegmentedResult segment. Panics on timeout.
async fn wtp_class2_roundtrip(client: &UdpSocket, gw: SocketAddr, tid: u16, invoke_payload: Vec<u8>) -> Vec<u8> {
    let invoke = WtpPdu::Invoke {
        flags: HeaderFlags {
            gtr: true,
            ttr: true,
            rid: false,
        },
        tid,
        version: 0,
        tid_new: true,
        user_ack: false,
        class: TransactionClass::Class2,
        payload: invoke_payload,
    };
    client.send_to(&invoke.encode(), gw).await.unwrap();

    let mut result_segments: Vec<(u8, Vec<u8>)> = Vec::new(); // (psn, payload)
    let mut got_final = false;

    for _ in 0..16 {
        let mut buf = [0u8; 4096];
        let (n, _peer) = match tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut buf)).await {
            Ok(v) => v.unwrap(),
            Err(_) => break,
        };
        let pdu = WtpPdu::decode(&buf[..n]).expect("valid PDU from gateway");
        match pdu {
            WtpPdu::Ack { .. } => {
                // Ignore the Ack of our Invoke; keep waiting for the Result.
            }
            WtpPdu::Result { flags, payload, .. } => {
                result_segments.push((0, payload));
                if flags.ttr {
                    got_final = true;
                }
                // Ack it so the responder stops retransmitting.
                let ack = WtpPdu::Ack {
                    flags: HeaderFlags {
                        gtr: false,
                        ttr: false,
                        rid: false,
                    },
                    tid,
                    tve: false,
                };
                let _ = client.send_to(&ack.encode(), gw).await;
            }
            WtpPdu::SegmentedResult { flags, psn, payload, .. } => {
                result_segments.push((psn, payload));
                if flags.ttr {
                    got_final = true;
                }
                let ack = WtpPdu::Ack {
                    flags: HeaderFlags {
                        gtr: false,
                        ttr: false,
                        rid: false,
                    },
                    tid,
                    tve: false,
                };
                let _ = client.send_to(&ack.encode(), gw).await;
            }
            other => panic!("unexpected PDU from gateway during class-2 roundtrip: {other:?}"),
        }
        if got_final {
            break;
        }
    }
    assert!(got_final, "gateway must send a final Result segment (TTR=1)");
    result_segments.sort_by_key(|(psn, _)| *psn);
    let mut reassembled = Vec::new();
    for (_, seg) in result_segments {
        reassembled.extend_from_slice(&seg);
    }
    reassembled
}

#[tokio::test]
async fn end_to_end_get_relays_to_http_upstream_and_carries_body() {
    // Spin up mock HTTP first so we know its port before we build the
    // gateway config (gateway needs upstream_url — although in this test
    // the MS sends an absolute URL, so the value we pass here isn't
    // actually consulted; we still fill it with the mock's URL to
    // exercise the production wiring).
    let mock_addr = spawn_mock_http().await;
    let upstream_url = format!("http://{}", mock_addr);

    // Bind a random UDP port for the gateway.
    let probe = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let listen = probe.local_addr().unwrap();
    drop(probe);

    let cfg = RunConfig {
        listen_addr: Ipv4Addr::LOCALHOST,
        listen_port: listen.port(),
        upstream_url: upstream_url.clone(),
        portal: None,
    };
    let shutdown = CancellationToken::new();
    let gw_task = tokio::spawn({
        let shutdown = shutdown.clone();
        async move { run(cfg, shutdown).await }
    });
    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let gw = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), listen.port());

    // Step 1: Connect. Assert we get a ConnectReply so we know the WSP
    // layer is happy before we send the Get.
    let connect_reply_bytes = wtp_class2_roundtrip(&client, gw, 0x2001, minimal_connect_bytes()).await;
    match WspPdu::decode(&connect_reply_bytes).unwrap() {
        WspPdu::ConnectReply { .. } => {}
        other => panic!("expected ConnectReply, got {other:?}"),
    }

    // Step 2: Get. Use an absolute URL pointing at the mock HTTP server.
    let get = WspPdu::MethodInvoke {
        method_code: pdu_type::GET,
        uri: format!("http://{}/index.wml", mock_addr),
        headers: HeaderBlock::empty(),
    }
    .encode();
    let reply_bytes = wtp_class2_roundtrip(&client, gw, 0x2002, get).await;

    let reply = WspPdu::decode(&reply_bytes).expect("Result carries a valid WSP Reply");
    let WspPdu::Reply { status, headers, body } = reply else {
        panic!("expected Reply, got {reply:?}");
    };

    // Status: HTTP 200 → WSP 0x20 (OK).
    assert_eq!(status, 0x20, "WSP status must be OK (0x20)");

    // Content-Type: first byte of headers block must be the WSP well-known
    // short-int for application/vnd.wap.wmlc = 0x14 → 0x94.
    assert!(!headers.is_empty(), "Reply must carry a Content-Type header");
    assert_eq!(
        headers.raw[0],
        0x80 | ContentType::WMLC,
        "first header byte must be the wmlc well-known short-int (0x94), got {:#04x}",
        headers.raw[0],
    );

    // Body: verbatim copy of what the mock returned.
    assert_eq!(body, MOCK_WMLC_BODY, "Reply body must match the mock upstream body");

    shutdown.cancel();
    let outcome = tokio::time::timeout(Duration::from_secs(2), gw_task)
        .await
        .expect("gateway did not shut down in time")
        .unwrap();
    assert!(outcome.is_ok(), "gateway returned error: {outcome:?}");
}
