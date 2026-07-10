//! WTP responder — per-transaction state machine (WAP-201 §6.3).
//!
//! Runs on top of [`crate::wdp::Wdp`]. For every incoming PDU we look up (or
//! create) a `Transaction` keyed by `(peer_addr, tid)` and drive it forward:
//!
//! ```text
//!   MS                             Gateway
//!   ── Invoke (TTR=0, GTR=0) ──▶
//!   ── S-Invoke PSN=1 ─────────▶      (reassemble)
//!   ── S-Invoke PSN=2 GTR=1 ───▶      (reassemble complete)
//!                              ◀── Ack (positive) ──
//!                                  (call user handler → payload)
//!                              ◀── Result (or Segmented Result*) ──
//!   ── Ack (positive) ────────▶      (transaction terminated)
//! ```
//!
//! # Handler contract
//!
//! [`Responder::run`] takes a `Handler` closure that is called once per
//! completed Invoke with the reassembled user payload. It returns the WSP
//! response bytes that the responder wraps into a Result (with SAR).
//!
//! # SAR
//!
//! **Inbound**: multi-segment Invokes are reassembled by concatenating
//! segments in PSN order. Out-of-order segments are dropped (fine — the
//! initiator will retransmit; we do not send Negative Ack in v0.1).
//!
//! **Outbound**: Result payloads longer than [`SEGMENT_SIZE`] bytes are
//! chopped into a `Result` PDU (segment 0) followed by `SegmentedResult`
//! PDUs (segments 1..N) with the last carrying `GTR=1`, `TTR=1`.
//!
//! # Retransmission
//!
//! Class-2 responders re-send the Result on `T_ACK` expiry until the
//! initiator's Ack arrives. Timings are Openwave/TETRA-tuned in
//! [`ResponderConfig::default`].

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use tokio::sync::Mutex;
use tokio::time::Instant;
use tracing::{debug, info, warn};

use crate::error::WapResult;
use crate::wdp::Wdp;
use crate::wtp::pdu::{HeaderFlags, TransactionClass, WtpPdu, abort_reason};

/// Payload bytes per WTP segment. WAP UDP MTU is 1500; leaving ~100 bytes for
/// IP + UDP + WTP framing gives us a comfortable body size that fits on the
/// TETRA link without further fragmentation.
pub const SEGMENT_SIZE: usize = 1300;

// ── Config ───────────────────────────────────────────────────────────────────

/// Tunable timers / retry policy.
#[derive(Debug, Clone, Copy)]
pub struct ResponderConfig {
    /// Retransmit interval for un-Ack'd Results.
    pub t_ack: Duration,
    /// Maximum number of Result retransmissions before giving up.
    pub max_retx: u8,
    /// Idle transaction eviction age (no PDUs for this long → drop state).
    pub idle_timeout: Duration,
    /// Interval at which we sweep the transaction table for idle entries.
    pub sweep_interval: Duration,
}

impl Default for ResponderConfig {
    fn default() -> Self {
        Self {
            // TETRA RTT can reach 1.5 s; 4 s gives headroom over the WAP-201
            // default of 3 s without triggering MS-side Abort (~15 s).
            t_ack: Duration::from_secs(4),
            max_retx: 3,
            idle_timeout: Duration::from_secs(90),
            sweep_interval: Duration::from_secs(15),
        }
    }
}

// ── Handler trait ────────────────────────────────────────────────────────────

/// Boxed async handler: `(peer, reassembled_invoke_payload) -> result_payload`.
pub type Handler = Arc<dyn Fn(SocketAddr, Vec<u8>) -> Pin<Box<dyn Future<Output = Vec<u8>> + Send>> + Send + Sync>;

/// Convenience: wrap an async closure as a [`Handler`].
pub fn handler_fn<F, Fut>(f: F) -> Handler
where
    F: Fn(SocketAddr, Vec<u8>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Vec<u8>> + Send + 'static,
{
    Arc::new(move |peer, bytes| Box::pin(f(peer, bytes)))
}

// ── Per-transaction state ────────────────────────────────────────────────────

#[derive(Debug)]
enum Phase {
    /// Received one or more Invoke/SegmentedInvoke PDUs, still waiting for
    /// the segment carrying `TTR=1` (or a single Invoke with TTR=1).
    Reassembling { class: TransactionClass, next_psn: u8 },
    /// Full Invoke assembled; user handler is running.
    Handling { class: TransactionClass },
    /// Result has been (fully) sent; awaiting the initiator's final Ack.
    ResultSent { segments: Vec<Vec<u8>> },
    /// Terminal — safe to evict.
    Done,
}

#[derive(Debug)]
struct Transaction {
    peer: SocketAddr,
    tid: u16,
    phase: Phase,
    /// Reassembled Invoke payload so far (segment 0 first, then S-Invokes).
    invoke_buf: Vec<u8>,
    /// Wall-clock of the last event on this transaction (used for eviction).
    last_activity: Instant,
    /// Retransmission counter for the outstanding Result.
    retx_count: u8,
    /// Deadline at which we retransmit the Result (`Some` while awaiting Ack).
    retx_at: Option<Instant>,
}

impl Transaction {
    fn touch(&mut self) {
        self.last_activity = Instant::now();
    }
}

// ── Responder ────────────────────────────────────────────────────────────────

type TxnRef = Arc<Mutex<Transaction>>;
type TxnKey = (SocketAddr, u16);

/// The WTP responder. Owns the UDP socket, the transaction table, and the
/// retry timer loop.
#[derive(Clone)]
pub struct Responder {
    wdp: Wdp,
    handler: Handler,
    cfg: ResponderConfig,
    txns: Arc<DashMap<TxnKey, TxnRef>>,
}

impl Responder {
    pub fn new(wdp: Wdp, handler: Handler, cfg: ResponderConfig) -> Self {
        Self {
            wdp,
            handler,
            cfg,
            txns: Arc::new(DashMap::new()),
        }
    }

    /// Run the responder forever. Returns only on a fatal I/O error.
    #[tracing::instrument(skip(self))]
    pub async fn run(self) -> WapResult<()> {
        // Spawn a background sweeper for idle transactions + retx.
        let sweeper = tokio::spawn(sweep_loop(self.clone()));

        let result = self.recv_loop().await;

        sweeper.abort();
        result
    }

    async fn recv_loop(&self) -> WapResult<()> {
        loop {
            let (peer, bytes) = self.wdp.recv().await?;
            match WtpPdu::decode(&bytes) {
                Ok(pdu) => {
                    if let Err(e) = self.handle_pdu(peer, pdu).await {
                        warn!(%peer, err = %e, "handler error");
                    }
                }
                Err(e) => {
                    debug!(%peer, err = %e, len = bytes.len(), "malformed WTP PDU dropped");
                }
            }
        }
    }

    async fn handle_pdu(&self, peer: SocketAddr, pdu: WtpPdu) -> WapResult<()> {
        let tid = pdu.tid();
        match pdu {
            WtpPdu::Invoke {
                flags,
                class,
                payload,
                tid_new,
                ..
            } => self.on_invoke(peer, tid, flags, class, payload, tid_new).await,
            WtpPdu::SegmentedInvoke { flags, psn, payload, .. } => self.on_segmented_invoke(peer, tid, flags, psn, payload).await,
            WtpPdu::Ack { .. } => {
                self.on_ack(peer, tid).await;
                Ok(())
            }
            WtpPdu::Abort { abort_type, reason, .. } => {
                info!(%peer, tid, ?abort_type, reason, "peer aborted transaction");
                self.txns.remove(&(peer, tid));
                Ok(())
            }
            WtpPdu::NegativeAck { missing_psns, .. } => {
                // v0.1 ignores N-Ack (initiator will retx anyway on our silence).
                debug!(%peer, tid, ?missing_psns, "N-Ack ignored (v0.1)");
                Ok(())
            }
            WtpPdu::Result { .. } | WtpPdu::SegmentedResult { .. } => {
                // We are a responder, not an initiator.
                warn!(%peer, tid, "unexpected Result PDU from initiator; ignoring");
                Ok(())
            }
        }
    }

    // ── Inbound events ─────────────────────────────────────────────────────

    async fn on_invoke(
        &self,
        peer: SocketAddr,
        tid: u16,
        flags: HeaderFlags,
        class: TransactionClass,
        payload: Vec<u8>,
        _tid_new: bool,
    ) -> WapResult<()> {
        info!(%peer, tid, ?class, len = payload.len(), ttr = flags.ttr, "invoke");

        // Class 0 = unconfirmed, no Ack, no Result. Just deliver.
        if class == TransactionClass::Class0 {
            let handler = self.handler.clone();
            tokio::spawn(async move {
                let _ = (handler)(peer, payload).await;
            });
            return Ok(());
        }

        let key = (peer, tid);
        let entry = self
            .txns
            .entry(key)
            .or_insert_with(|| {
                Arc::new(Mutex::new(Transaction {
                    peer,
                    tid,
                    phase: Phase::Reassembling { class, next_psn: 1 },
                    invoke_buf: Vec::new(),
                    last_activity: Instant::now(),
                    retx_count: 0,
                    retx_at: None,
                }))
            })
            .clone();
        let mut txn = entry.lock().await;
        txn.touch();
        txn.invoke_buf.extend_from_slice(&payload);

        if flags.ttr {
            // Single-segment Invoke (or last-and-only). Complete.
            self.complete_invoke(&mut txn).await;
        } else {
            debug!(%peer, tid, buf_len = txn.invoke_buf.len(), "invoke seg 0 stored; awaiting continuation");
        }
        Ok(())
    }

    async fn on_segmented_invoke(&self, peer: SocketAddr, tid: u16, flags: HeaderFlags, psn: u8, payload: Vec<u8>) -> WapResult<()> {
        let key = (peer, tid);
        let Some(entry) = self.txns.get(&key).map(|r| r.clone()) else {
            warn!(%peer, tid, psn, "S-Invoke for unknown TID; sending Abort");
            let abort = WtpPdu::provider_abort(tid, abort_reason::INVALIDTID);
            self.wdp.send(peer, &abort.encode()).await?;
            return Ok(());
        };
        let mut txn = entry.lock().await;
        txn.touch();

        let expected = match &txn.phase {
            Phase::Reassembling { next_psn, .. } => *next_psn,
            _ => {
                debug!(%peer, tid, psn, phase = ?txn.phase, "S-Invoke ignored (bad phase)");
                return Ok(());
            }
        };
        if psn != expected {
            debug!(%peer, tid, psn, expected, "out-of-order S-Invoke dropped");
            return Ok(());
        }

        txn.invoke_buf.extend_from_slice(&payload);
        if let Phase::Reassembling { next_psn, .. } = &mut txn.phase {
            *next_psn = next_psn.wrapping_add(1);
        }

        if flags.ttr {
            self.complete_invoke(&mut txn).await;
        }
        Ok(())
    }

    async fn on_ack(&self, peer: SocketAddr, tid: u16) {
        let Some(entry) = self.txns.get(&(peer, tid)).map(|r| r.clone()) else {
            debug!(%peer, tid, "Ack for unknown TID; ignoring");
            return;
        };
        let mut txn = entry.lock().await;
        txn.touch();
        match txn.phase {
            Phase::ResultSent { .. } => {
                info!(%peer, tid, "result Ack'd; terminating transaction");
                txn.phase = Phase::Done;
                txn.retx_at = None;
                drop(txn);
                self.txns.remove(&(peer, tid));
            }
            _ => debug!(%peer, tid, phase = ?txn.phase, "stray Ack ignored"),
        }
    }

    // ── Transaction progression ────────────────────────────────────────────

    async fn complete_invoke(&self, txn: &mut Transaction) {
        // 1. Ack the Invoke.
        let ack = WtpPdu::ack(txn.tid);
        if let Err(e) = self.wdp.send(txn.peer, &ack.encode()).await {
            warn!(peer = %txn.peer, tid = txn.tid, err = %e, "failed to send Ack");
            return;
        }
        info!(peer = %txn.peer, tid = txn.tid, "sent Ack for Invoke");

        // 2. Dispatch to the user handler.
        let class = match txn.phase {
            Phase::Reassembling { class, .. } => class,
            Phase::Handling { class } => class,
            _ => TransactionClass::Class2,
        };
        txn.phase = Phase::Handling { class };
        let payload = std::mem::take(&mut txn.invoke_buf);
        let handler = self.handler.clone();
        let peer = txn.peer;
        let response = (handler)(peer, payload).await;

        // Class 1 = "reliable Invoke, no Result". Just terminate.
        if class == TransactionClass::Class1 {
            txn.phase = Phase::Done;
            return;
        }

        // 3. Segment the Result and send.
        let segments = segment_result(txn.tid, &response);
        for bytes in &segments {
            if let Err(e) = self.wdp.send(txn.peer, bytes).await {
                warn!(peer = %txn.peer, tid = txn.tid, err = %e, "failed to send Result segment");
                return;
            }
        }
        info!(
            peer = %txn.peer,
            tid = txn.tid,
            segments = segments.len(),
            body = response.len(),
            "sent Result"
        );

        txn.phase = Phase::ResultSent { segments };
        txn.retx_count = 0;
        txn.retx_at = Some(Instant::now() + self.cfg.t_ack);
    }

    async fn retransmit_result(&self, key: TxnKey) {
        let Some(entry) = self.txns.get(&key).map(|r| r.clone()) else {
            return;
        };
        let mut txn = entry.lock().await;
        let (peer, tid) = key;
        let segments = if let Phase::ResultSent { segments } = &txn.phase {
            segments.clone()
        } else {
            return;
        };
        if txn.retx_count >= self.cfg.max_retx {
            warn!(%peer, tid, retx = txn.retx_count, "max retx reached; giving up");
            txn.phase = Phase::Done;
            txn.retx_at = None;
            drop(txn);
            self.txns.remove(&key);
            return;
        }
        txn.retx_count += 1;
        for bytes in &segments {
            // Flip the RID bit on retransmissions.
            let mut retx = bytes.clone();
            if let Some(first) = retx.first_mut() {
                *first |= 0b0000_0001;
            }
            let _ = self.wdp.send(peer, &retx).await;
        }
        info!(%peer, tid, retx = txn.retx_count, "retransmitted Result");
        txn.retx_at = Some(Instant::now() + self.cfg.t_ack);
    }
}

// ── Sweeper ──────────────────────────────────────────────────────────────────

async fn sweep_loop(resp: Responder) {
    let mut ticker = tokio::time::interval(resp.cfg.sweep_interval);
    loop {
        ticker.tick().await;
        let now = Instant::now();
        let mut to_retx: Vec<TxnKey> = Vec::new();
        let mut to_evict: Vec<TxnKey> = Vec::new();

        for r in resp.txns.iter() {
            let key = *r.key();
            let txn = r.value().clone();
            let txn = txn.lock().await;
            if let Some(deadline) = txn.retx_at {
                if now >= deadline {
                    to_retx.push(key);
                }
            }
            if now.duration_since(txn.last_activity) >= resp.cfg.idle_timeout {
                to_evict.push(key);
            }
        }

        for key in to_retx {
            resp.retransmit_result(key).await;
        }
        for key in to_evict {
            debug!(?key, "evicting idle transaction");
            resp.txns.remove(&key);
        }
    }
}

// ── Result segmentation ──────────────────────────────────────────────────────

/// Chop `payload` into a `Result` PDU followed by zero or more
/// `SegmentedResult` PDUs, all sharing `tid`. For a group of N>1 segments the
/// closing Segmented Result carries `GTR=1, TTR=1`; single-segment (unsegmented)
/// Results carry `GTR=0, TTR=1` only, per WAP-201 §8.4.3.
pub(crate) fn segment_result(tid: u16, payload: &[u8]) -> Vec<Vec<u8>> {
    let chunks: Vec<&[u8]> = if payload.is_empty() {
        vec![&[][..]]
    } else {
        payload.chunks(SEGMENT_SIZE).collect()
    };
    let n = chunks.len();
    let mut out = Vec::with_capacity(n);

    for (i, chunk) in chunks.iter().enumerate() {
        let is_last = i == n - 1;
        // WAP-201 §8.4.3 unsegmented Result: GTR=0, TTR=1.
        // For a group of N>1 segments the closing Segmented Result carries
        // GTR=1, TTR=1; intermediate segments GTR=0, TTR=0.
        let is_segmented_group = n > 1;
        let flags = HeaderFlags {
            gtr: is_last && is_segmented_group,
            ttr: is_last,
            rid: false,
        };
        let pdu = if i == 0 {
            WtpPdu::Result {
                flags,
                tid,
                payload: chunk.to_vec(),
            }
        } else {
            WtpPdu::SegmentedResult {
                flags,
                tid,
                psn: i as u8,
                payload: chunk.to_vec(),
            }
        };
        out.push(pdu.encode());
    }
    out
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wtp::pdu::{PduType, TransactionClass};
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn segment_result_single_segment() {
        let out = segment_result(0x1234, b"hello");
        assert_eq!(out.len(), 1);
        let pdu = WtpPdu::decode(&out[0]).unwrap();
        match pdu {
            WtpPdu::Result { flags, tid, payload } => {
                assert_eq!(tid, 0x1234);
                // WAP-201 §8.4.3: unsegmented Result = TTR=1, GTR=0.
                assert!(flags.ttr);
                assert!(!flags.gtr);
                assert!(!flags.rid);
                assert_eq!(payload, b"hello");
            }
            _ => panic!("expected Result"),
        }
    }

    /// Regression: on hardware, MS UP.Browser silently discarded our single-segment
    /// Result and re-Invoked repeatedly when we set GTR=1 alongside TTR=1. The fix
    /// (GTR=0 on unsegmented Results) is validated by the wire byte here: octet 0
    /// must be exactly 0x12 (Type=Result=0010, GTR=0, TTR=1, RID=0).
    #[test]
    fn segment_result_single_segment_octet0_is_0x12() {
        let out = segment_result(0x14b1, b"abc");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0][0], 0x12, "unsegmented Result octet 0 must be 0x12 for UP.Browser compat");
    }

    #[test]
    fn segment_result_multi_segment_reassembles() {
        let payload: Vec<u8> = (0..3500).map(|i| (i & 0xFF) as u8).collect();
        let out = segment_result(0xAA, &payload);
        assert_eq!(out.len(), 3, "3500 bytes over 1300-byte MTU = 3 segments");

        // Decode + reassemble.
        let mut reassembled = Vec::new();
        for (i, bytes) in out.iter().enumerate() {
            let pdu = WtpPdu::decode(bytes).unwrap();
            match pdu {
                WtpPdu::Result { payload, flags, .. } if i == 0 => {
                    assert!(!flags.ttr);
                    reassembled.extend_from_slice(&payload);
                }
                WtpPdu::SegmentedResult { psn, payload, flags, .. } => {
                    assert_eq!(psn as usize, i);
                    let is_last = i == out.len() - 1;
                    assert_eq!(flags.ttr, is_last);
                    assert_eq!(flags.gtr, is_last);
                    reassembled.extend_from_slice(&payload);
                }
                _ => panic!("unexpected pdu at index {i}"),
            }
        }
        assert_eq!(reassembled, payload);
    }

    #[test]
    fn segment_result_empty_payload_still_produces_one_pdu() {
        let out = segment_result(1, b"");
        assert_eq!(out.len(), 1);
        let pdu = WtpPdu::decode(&out[0]).unwrap();
        assert_eq!(pdu.pdu_type(), PduType::Result);
    }

    /// End-to-end integration test: bind the responder on loopback, send a
    /// single-segment Class-2 Invoke as if we were the MS, and expect an Ack
    /// then a Result whose body is what the handler returned.
    #[tokio::test]
    async fn responder_invoke_ack_result_roundtrip() {
        let server_wdp = Wdp::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).await.unwrap();
        let client_wdp = Wdp::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).await.unwrap();
        let server_addr = server_wdp.local_addr();

        let handler = handler_fn(|_peer, req| async move {
            let mut resp = b"echo:".to_vec();
            resp.extend_from_slice(&req);
            resp
        });
        let resp = Responder::new(server_wdp, handler, ResponderConfig::default());
        tokio::spawn(async move {
            let _ = resp.run().await;
        });

        // Send an Invoke.
        let invoke = WtpPdu::Invoke {
            flags: HeaderFlags {
                gtr: false,
                ttr: true,
                rid: false,
            },
            tid: 0x0042,
            version: 0,
            tid_new: true,
            user_ack: false,
            class: TransactionClass::Class2,
            payload: b"hi".to_vec(),
        };
        client_wdp.send(server_addr, &invoke.encode()).await.unwrap();

        // Expect Ack + Result (order Ack first).
        let mut got_ack = false;
        let mut got_result = None;
        for _ in 0..2 {
            let (_peer, bytes) = tokio::time::timeout(Duration::from_secs(2), client_wdp.recv())
                .await
                .expect("receive timed out")
                .unwrap();
            let pdu = WtpPdu::decode(&bytes).unwrap();
            match pdu {
                WtpPdu::Ack { tid, .. } => {
                    assert_eq!(tid, 0x0042);
                    got_ack = true;
                }
                WtpPdu::Result { tid, payload, .. } => {
                    assert_eq!(tid, 0x0042);
                    got_result = Some(payload);
                }
                other => panic!("unexpected PDU from responder: {other:?}"),
            }
        }
        assert!(got_ack, "responder never sent Ack");
        assert_eq!(got_result.unwrap(), b"echo:hi");
    }

    /// A multi-segment Invoke (TTR=0 on segment 0 + S-Invoke with TTR=1) is
    /// reassembled and the handler sees the concatenated payload.
    #[tokio::test]
    async fn responder_reassembles_multi_segment_invoke() {
        let server_wdp = Wdp::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).await.unwrap();
        let client_wdp = Wdp::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).await.unwrap();
        let server_addr = server_wdp.local_addr();

        let handler = handler_fn(|_peer, req| async move {
            // Echo back the exact reassembled bytes so we can verify.
            req
        });
        let resp = Responder::new(server_wdp, handler, ResponderConfig::default());
        tokio::spawn(async move {
            let _ = resp.run().await;
        });

        // Segment 0: Invoke with TTR=0.
        let s0 = WtpPdu::Invoke {
            flags: HeaderFlags {
                gtr: false,
                ttr: false,
                rid: false,
            },
            tid: 0x0100,
            version: 0,
            tid_new: true,
            user_ack: false,
            class: TransactionClass::Class2,
            payload: b"AAAA".to_vec(),
        };
        client_wdp.send(server_addr, &s0.encode()).await.unwrap();
        // Segment 1: S-Invoke, TTR=1.
        let s1 = WtpPdu::SegmentedInvoke {
            flags: HeaderFlags {
                gtr: true,
                ttr: true,
                rid: false,
            },
            tid: 0x0100,
            psn: 1,
            payload: b"BBBB".to_vec(),
        };
        client_wdp.send(server_addr, &s1.encode()).await.unwrap();

        // Read PDUs until we see the Result.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        let mut result_body = None;
        while tokio::time::Instant::now() < deadline {
            let (_peer, bytes) = tokio::time::timeout(Duration::from_millis(500), client_wdp.recv())
                .await
                .expect("timed out waiting for responder")
                .unwrap();
            if let WtpPdu::Result { payload, .. } = WtpPdu::decode(&bytes).unwrap() {
                result_body = Some(payload);
                break;
            }
        }
        assert_eq!(result_body.expect("no Result received"), b"AAAABBBB");
    }
}
