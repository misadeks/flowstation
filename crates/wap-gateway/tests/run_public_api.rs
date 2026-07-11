//! Integration test for the public `wap_gateway::run` entry point.
//!
//! Boots the gateway on `127.0.0.1:0`, sends a class-2 Invoke carrying a
//! synthetic WSP Connect PDU as if we were the MS, and confirms we
//! receive an Ack followed by a Result whose payload is a WSP
//! ConnectReply that echoes the Openwave-critical `Protocol-Options 0xF0`
//! and `Extended-Methods x-up-1` capabilities verbatim. Then cancels the
//! shutdown token and confirms the task exits cleanly with `Ok(())`.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;
use wap_gateway::wsp::caps::Capability;
use wap_gateway::wsp::pdu::{HeaderBlock, WspPdu};
use wap_gateway::wtp::pdu::{HeaderFlags, TransactionClass, WtpPdu};
use wap_gateway::{RunConfig, run};

#[tokio::test]
async fn run_serves_wsp_connect_and_shuts_down_on_cancel() {
    // Pick a free port on loopback first, then hand it to the gateway.
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

    // Give the gateway a beat to bind.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Client side: build a minimal WSP Connect and wrap it in a class-2
    // Invoke. The two caps we assert on are the exact quirks that
    // motivate this crate's existence.
    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let gw = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), listen.port());

    let connect = WspPdu::Connect {
        version: 0x10,
        capabilities: vec![
            Capability::ProtocolOptions(0xF0),
            Capability::ExtendedMethods(vec![(0x10, b"x-up-1".to_vec())]),
        ],
        headers: HeaderBlock::empty(),
    }
    .encode();

    let invoke = WtpPdu::Invoke {
        flags: HeaderFlags {
            gtr: false,
            ttr: true,
            rid: false,
        },
        tid: 0x00CD,
        version: 0,
        tid_new: true,
        user_ack: false,
        class: TransactionClass::Class2,
        payload: connect,
    };
    client.send_to(&invoke.encode(), gw).await.unwrap();

    // H24: fast handlers skip the intermediate Ack — expect only the Result.
    let mut buf = [0u8; 2048];
    let (n, _peer) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
        .await
        .expect("recv timed out")
        .unwrap();
    let pdu = WtpPdu::decode(&buf[..n]).expect("valid PDU from gateway");
    let payload = match pdu {
        WtpPdu::Result { tid, payload, .. } => {
            assert_eq!(tid, 0x00CD ^ 0x8000);
            payload
        }
        other => panic!("expected Result, got: {other:?}"),
    };
    // Payload must be a WSP ConnectReply matching Kannel's
    // sanitize_capabilities() behaviour (see build_connect_reply).
    let reply = WspPdu::decode(&payload).expect("Result carries a valid WSP PDU");
    let WspPdu::ConnectReply {
        server_session_id,
        capabilities,
        headers,
        ..
    } = reply
    else {
        panic!("expected ConnectReply, got {reply:?}");
    };
    assert!(server_session_id >= 1);
    assert!(
        capabilities.contains(&Capability::ProtocolOptions(0x00)),
        "ConnectReply must SANITIZE Protocol-Options (0xF0 → 0x00) to match Kannel"
    );
    assert!(
        capabilities.contains(&Capability::ExtendedMethods(Vec::new())),
        "ConnectReply must REFUSE Extended-Methods / Header-Code-Pages (empty payload = refusal)"
    );
    assert_eq!(
        headers.raw,
        vec![0xC3, 0x93],
        "ConnectReply headers block must contain Encoding-Version: 1.3"
    );

    // Now cooperative shutdown.
    shutdown.cancel();
    let outcome = tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .expect("gateway did not shut down in time")
        .unwrap();
    assert!(outcome.is_ok(), "gateway returned error: {outcome:?}");
}
