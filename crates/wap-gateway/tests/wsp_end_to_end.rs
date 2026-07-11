//! End-to-end integration: hand the gateway a real MTP3550 Connect PDU
//! over UDP (wrapped in a Class-2 WTP Invoke) and assert we get back a
//! WTP Ack + WTP Result carrying a WSP ConnectReply that echoes every
//! Openwave-quirky capability the MS proposed.
//!
//! This closes the PD-10b loop: the codec (PD-10b-1, PD-10b-2), the
//! session state machine (PD-10b-3), the WTP responder (PD-10a-3), and
//! the public `run()` entry point (PD-10a-4/5) all working together on
//! real bytes captured from hardware 2026-07-10.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;
use wap_gateway::wsp::caps::Capability;
use wap_gateway::wsp::pdu::WspPdu;
use wap_gateway::wtp::pdu::{HeaderFlags, TransactionClass, WtpPdu};
use wap_gateway::{RunConfig, run};

const MTP3550_CONNECT: &[u8] = include_bytes!("fixtures/mtp3550_connect.bin");

#[tokio::test]
async fn end_to_end_mtp3550_connect_gets_openwave_connect_reply() {
    let probe = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let listen = probe.local_addr().unwrap();
    drop(probe);

    let cfg = RunConfig {
        listen_addr: Ipv4Addr::LOCALHOST,
        listen_port: listen.port(),
        upstream_url: "http://127.0.0.1:8081".to_owned(),
        portal: None,
        al_feedback: None,
    };
    let shutdown = CancellationToken::new();
    let task = tokio::spawn({
        let shutdown = shutdown.clone();
        async move { run(cfg, shutdown).await }
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let gw = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), listen.port());

    // Wrap the raw 447-byte hardware Connect in a Class-2 Invoke, TID
    // 0x14B1 (arbitrary — matches the tcpdump reference in the PD-10b
    // prompt within a couple of digits; the exact value doesn't matter as
    // long as we can pattern-match it on the way back).
    let invoke = WtpPdu::Invoke {
        flags: HeaderFlags {
            gtr: true, // last (and only) segment
            ttr: true,
            rid: false,
        },
        tid: 0x14B1,
        version: 0,
        tid_new: true,
        user_ack: false,
        class: TransactionClass::Class2,
        payload: MTP3550_CONNECT.to_vec(),
    };
    client.send_to(&invoke.encode(), gw).await.unwrap();

    let mut connect_reply: Option<WspPdu> = None;

    // On TETRA hardware the Result may be segmented across several
    // Result / SegmentedResult PDUs. In the loopback happy-path an empty
    // header block keeps the ConnectReply < 300 B so it fits in one
    // Result. Read up to 8 PDUs to be safe.
    for _ in 0..8 {
        let mut buf = [0u8; 2048];
        let (n, _peer) = match tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf)).await {
            Ok(v) => v.unwrap(),
            Err(_) => break,
        };
        let pdu = WtpPdu::decode(&buf[..n]).expect("valid PDU from gateway");
        match pdu {
            WtpPdu::Result { tid, payload, .. } => {
                assert_eq!(tid, 0x14B1 ^ 0x8000, "gateway must send SendTID");
                let reply = WspPdu::decode(&payload).expect("Result carries a valid WSP PDU");
                connect_reply = Some(reply);
                // Send back our own Ack of the Result so responder retx stops.
                // As the initiator we still use RcvTID unmodified here (our
                // send direction, MS-side, wouldn't XOR).
                let ack = WtpPdu::Ack {
                    flags: HeaderFlags {
                        gtr: false,
                        ttr: false,
                        rid: false,
                    },
                    tid: 0x14B1,
                    tve: false,
                };
                let _ = client.send_to(&ack.encode(), gw).await;
            }
            other => panic!("unexpected PDU from gateway: {other:?}"),
        }
        if connect_reply.is_some() {
            break;
        }
    }

    let reply = connect_reply.expect("gateway must send a WSP ConnectReply");
    let WspPdu::ConnectReply {
        server_session_id,
        capabilities,
        ..
    } = reply
    else {
        panic!("expected ConnectReply, got {reply:?}");
    };
    assert!(server_session_id >= 1);
    assert!(
        capabilities.contains(&Capability::ProtocolOptions(0x00)),
        "ConnectReply must SANITIZE Protocol-Options (0xF0 → 0x00) per Kannel"
    );
    assert!(
        capabilities.contains(&Capability::ExtendedMethods(Vec::new())),
        "ConnectReply must REFUSE Extended-Methods (empty payload)"
    );
    assert!(
        capabilities.contains(&Capability::MethodMor(3)),
        "ConnectReply must echo Method-MOR = 3"
    );

    shutdown.cancel();
    let outcome = tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .expect("gateway did not shut down in time")
        .unwrap();
    assert!(outcome.is_ok(), "gateway returned error: {outcome:?}");
}
