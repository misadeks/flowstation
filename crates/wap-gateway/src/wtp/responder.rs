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
    /// PD-10c-H24: if the handler produces the Result within this window, skip
    /// the intermediate "hold-on" Ack — the Result is an implicit Ack. Sending
    /// Ack+Result back-to-back on the same TETRA AL link crashed MTP3550's AL
    /// state machine. Set to just below the initiator's Invoke retx timer
    /// (WAP-201 §11 Awt ≈ 3 s).
    pub hold_on_ack_delay: Duration,
}

impl Default for ResponderConfig {
    fn default() -> Self {
        Self {
            // PD-10c-H28 (2026-07-11): tightened from 4 s → 2 s. Hardware log
            // showed every WSP transaction takes at least one WTP retx before
            // MS ACKs (MTP3550 firmware skips the WAP-201 §9.5.7 final Ack in
            // many cases). Faster retx = faster time-to-render. Still above
            // TETRA one-way RTT (~1 s single-slot PDCH) so we don't spuriously
            // retx while a genuine Ack is in flight.
            t_ack: Duration::from_secs(2),
            // PD-10c-H30 (2026-07-11): max_retx from 1 → 0. Hardware log
            // 01:09 proved MS receives our Result cleanly — the LLC layer
            // reports "AL N(S)=X fully acknowledged" ~1.4s after we send it.
            // MS just doesn't send the WAP-201 §9.5.7 WTP final Ack.
            // Retransmitting was retx'ing content that MS already had; each
            // duplicate AL SDU was confusing MTP3550's session state and
            // causing the red-blink UI symptom. Zero retries + rely on the
            // LLC AL-ACK for delivery confirmation. If MS actually loses the
            // Result (rare, one-off air loss with no LLC ACK), MS re-invokes
            // with a fresh TID and H25 evicts the stale txn.
            max_retx: 0,
            idle_timeout: Duration::from_secs(90),
            // PD-10c-H28: sweep every 5 s (was 15 s). H25 evicts stale txns
            // when a new Invoke arrives on the same peer, so this only affects
            // txns that idle out without any follow-up. Faster sweep = tighter
            // resource use with negligible CPU overhead.
            sweep_interval: Duration::from_secs(5),
            hold_on_ack_delay: Duration::from_millis(2500),
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

        // PD-10c-H25 (2026-07-11 MTP3550 fix): a fresh Invoke from this peer
        // with a NEW TID implicitly confirms that any earlier class-2
        // transaction on the same peer is done from the MS's perspective —
        // the MS wouldn't be starting a new request if it was still processing
        // an outstanding Result. MTP3550 in particular never sends the WAP-201
        // §9.5.7 "final Ack" for the Result, so our responder kept retx'ing
        // the ConnectReply every ~15 s (sweeper interval) after CONNECT had
        // already succeeded — each retx being another AL SDU that MTP3550
        // couldn't reconcile with its state, causing the radio to blink red.
        //
        // Evict stale non-Done transactions in ResultSent/Handling for this
        // peer whose TID differs from the incoming one.
        let mut stale_keys: Vec<TxnKey> = Vec::new();
        for entry in self.txns.iter() {
            let k = *entry.key();
            if k.0 == peer && k.1 != tid {
                stale_keys.push(k);
            }
        }
        for k in stale_keys {
            if let Some((_k, txn_ref)) = self.txns.remove(&k) {
                let txn = txn_ref.lock().await;
                info!(
                    %peer,
                    stale_tid = k.1,
                    new_tid = tid,
                    phase = ?txn.phase,
                    "H25: evicting stale txn on new Invoke from same peer"
                );
            }
        }

        let key = (peer, tid);

        // PD-10c-H33 (2026-07-11 hardware fix): if this is a retry of an
        // already-served Class-2 Invoke (same peer, same TID, phase =
        // ResultSent), just re-send the cached Result. The old code fell
        // through to invoke_buf.extend_from_slice() which appended the retry
        // payload to the previous one and then re-ran the handler with the
        // concatenated garbage — every WSP retry produced a bad Result and
        // MS entered an infinite loop showing 'request timed out'. Standard
        // WTP-Class-2 responder behavior is to cache the Result and re-send
        // on Invoke retry (WAP-201 §8.3).
        if let Some(existing) = self.txns.get(&key).map(|r| r.clone()) {
            let mut txn = existing.lock().await;
            if let Phase::ResultSent { segments } = &txn.phase {
                let segments = segments.clone();
                txn.touch();
                drop(txn);
                info!(%peer, tid, "H33: re-Invoke on ResultSent txn — replaying cached Result");
                for bytes in &segments {
                    // H33+H34: flip WTP RID bit on the replayed bytes so MS
                    // sees this as a retransmission (matches retransmit_result
                    // behavior). Some MS-side WTP clients discard duplicate
                    // Results with RID=0 and only accept RID=1 for retries.
                    let mut retx = bytes.clone();
                    if let Some(first) = retx.first_mut() {
                        *first |= 0b0000_0001;
                    }
                    if let Err(e) = self.wdp.send(peer, &retx).await {
                        warn!(peer = %peer, tid, err = %e, "H33: failed to replay Result");
                        return Ok(());
                    }
                }
                return Ok(());
            }
            // Not in ResultSent — allow normal path (reassembly continuation etc.)
        }

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
        // PD-10c-H24 (2026-07-11 MTP3550 fix): dispatch to the handler FIRST,
        // then decide whether to send a "hold-on" Ack. Per WAP-201 §8.3 the
        // Result implicitly acknowledges the Invoke; the intermediate Ack is
        // only required when the handler cannot produce the Result before the
        // initiator's retransmission timer fires (~3 s). Kannel behaves the
        // same way — no hold-on Ack for fast responses.
        //
        // Old flow (Ack-then-Result back-to-back) crashed MTP3550's AL state
        // machine: two rapid downlink AL SDUs on the same link within
        // milliseconds caused the MS to fail to AL-ACK the second SDU (the
        // Result), triggering T252, WTP retx, and eventual "connecting" hang
        // with a red-blinking radio. MTP6550 handled it fine, so it's an
        // MTP3550 firmware quirk exposed by rapid consecutive AR requests.

        // 1. Dispatch to the user handler.
        let class = match txn.phase {
            Phase::Reassembling { class, .. } => class,
            Phase::Handling { class } => class,
            _ => TransactionClass::Class2,
        };
        txn.phase = Phase::Handling { class };
        let payload = std::mem::take(&mut txn.invoke_buf);
        let handler = self.handler.clone();
        let peer = txn.peer;
        let handler_started = Instant::now();
        let response = (handler)(peer, payload).await;
        let handler_elapsed = handler_started.elapsed();

        // Class 1 = "reliable Invoke, no Result". Just terminate.
        if class == TransactionClass::Class1 {
            // Class 1 has no Result to carry an implicit Ack; always send Ack.
            let ack = WtpPdu::ack(txn.tid);
            if let Err(e) = self.wdp.send(txn.peer, &ack.encode()).await {
                warn!(peer = %txn.peer, tid = txn.tid, err = %e, "failed to send Ack");
            }
            txn.phase = Phase::Done;
            return;
        }

        // 2. Class 2: only send the "hold-on" Ack if the handler was slow
        //    enough that the initiator might have retransmitted the Invoke.
        //    Threshold matches WAP-201 §11 Awt default (~3 s), leaving margin
        //    below the initiator's Invoke retx timer.
        if handler_elapsed >= self.cfg.hold_on_ack_delay {
            let ack = WtpPdu::ack(txn.tid);
            if let Err(e) = self.wdp.send(txn.peer, &ack.encode()).await {
                warn!(peer = %txn.peer, tid = txn.tid, err = %e, "failed to send hold-on Ack");
                return;
            }
            info!(peer = %txn.peer, tid = txn.tid, elapsed_ms = handler_elapsed.as_millis(), "sent hold-on Ack for slow handler");
        }

        // 3. Segment the Result and send. The Result carries the implicit Ack
        //    for the original Invoke via TID matching.
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
            handler_ms = handler_elapsed.as_millis(),
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
            // PD-10c-H34 (2026-07-11 hardware fix): with max_retx=0 (H30) we
            // used to remove the txn immediately here. That created a window
            // where MS's WTP-layer retry (typically 4-9 s later on MTP3550)
            // landed on an empty slot, forcing us to re-run the handler
            // from scratch. Instead, keep the txn alive in ResultSent state
            // so H33 (re-Invoke replay) catches MS retries and re-sends the
            // byte-identical cached Result. The txn is still evicted by
            // last_activity + idle_timeout (default 90 s) so no permanent
            // memory pressure.
            debug!(%peer, tid, retx = txn.retx_count, "max retx reached; keeping txn cached for potential MS re-Invoke (H34)");
            txn.retx_at = None;
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
/// `SegmentedResult` PDUs. Every outbound PDU uses the WTP **SendTID**
/// (`rcv_tid ^ 0x8000`) per WAP-201 §8.1.2 — the initiator matches PDUs
/// against SendTID, so any outbound PDU that echoes the incoming RcvTID
/// unchanged is silently discarded by the peer.
///
/// Both single-segment (unsegmented) and closing-segment (of a segmented
/// group) Results carry `GTR=1, TTR=1` per WAP-201 §8.7.3. Intermediate
/// segments in a group carry `GTR=0, TTR=0`.
pub(crate) fn segment_result(rcv_tid: u16, payload: &[u8]) -> Vec<Vec<u8>> {
    let send_tid = rcv_tid ^ 0x8000;
    let chunks: Vec<&[u8]> = if payload.is_empty() {
        vec![&[][..]]
    } else {
        payload.chunks(SEGMENT_SIZE).collect()
    };
    let n = chunks.len();
    let mut out = Vec::with_capacity(n);

    for (i, chunk) in chunks.iter().enumerate() {
        let is_last = i == n - 1;
        let flags = HeaderFlags {
            gtr: is_last,
            ttr: is_last,
            rid: false,
        };
        let pdu = if i == 0 {
            WtpPdu::Result {
                flags,
                tid: send_tid,
                payload: chunk.to_vec(),
            }
        } else {
            WtpPdu::SegmentedResult {
                flags,
                tid: send_tid,
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
        // segment_result takes rcv_tid and internally XORs 0x8000 for SendTID.
        let out = segment_result(0x1234, b"hello");
        assert_eq!(out.len(), 1);
        let pdu = WtpPdu::decode(&out[0]).unwrap();
        match pdu {
            WtpPdu::Result { flags, tid, payload } => {
                // SendTID = 0x1234 ^ 0x8000 = 0x9234.
                assert_eq!(tid, 0x9234);
                // WAP-201 §8.7.3: unsegmented Result = GTR=1, TTR=1.
                assert!(flags.ttr);
                assert!(flags.gtr);
                assert!(!flags.rid);
                assert_eq!(payload, b"hello");
            }
            _ => panic!("expected Result"),
        }
    }

    /// Regression: on hardware, MS UP.Browser silently discarded our single-segment
    /// Result because (a) TID wasn't SendTID (XOR 0x8000), and (b) GTR was 0.
    /// Both fixes must land together to produce a byte-identical WAP-201 §8.7.3
    /// compliant Result the initiator will accept.
    #[test]
    fn segment_result_single_segment_wire_matches_kannel() {
        let out = segment_result(0x14b1, b"abc");
        assert_eq!(out.len(), 1);
        // Byte 0 = 0x16 (Type=Result, GTR=1, TTR=1, RID=0).
        assert_eq!(out[0][0], 0x16, "unsegmented Result byte 0 must be 0x16 (GTR=TTR=1)");
        // Byte 1-2 = SendTID = 0x14b1 ^ 0x8000 = 0x94b1.
        assert_eq!(out[0][1], 0x94, "byte 1 must be SendTID hi (XOR of RcvTID hi with 0x80)");
        assert_eq!(out[0][2], 0xb1);
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
    /// single-segment Class-2 Invoke as if we were the MS, and expect a
    /// Result whose body is what the handler returned. Post-H24 the responder
    /// skips the intermediate "hold-on" Ack for fast handlers, so only the
    /// Result should arrive.
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

        // H24: with a fast handler the intermediate Ack is suppressed — the
        // Result carries the implicit ack. Responder XORs TID with 0x8000 per
        // WAP-201 §8.1.2 (SendTID). Our Invoke used RcvTID=0x0042, so the
        // outbound Result carries SendTID=0x8042.
        let (_peer, bytes) = tokio::time::timeout(Duration::from_secs(2), client_wdp.recv())
            .await
            .expect("receive timed out")
            .unwrap();
        let pdu = WtpPdu::decode(&bytes).unwrap();
        let payload = match pdu {
            WtpPdu::Result { tid, payload, .. } => {
                assert_eq!(tid, 0x8042);
                payload
            }
            other => panic!("expected Result, got: {other:?}"),
        };
        assert_eq!(payload, b"echo:hi");
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
