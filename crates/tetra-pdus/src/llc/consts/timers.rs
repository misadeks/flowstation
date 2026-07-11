use tetra_core::frames;

// Timers as defined in Annex A.1 LLC timers.
//
// Hardware-tuned 2026-07-10 vs Motorola MTP3550: T252 default (9 frames ≈ 510 ms)
// was too short for large SDUs on single-slot PDCH — a ~600-bit WSP Reply takes
// ~500 ms to transmit, leaving no time for the MS AL-ACK round-trip before T252
// expires. With max_retx=0 (MS default) that means the SDU is dropped mid-flight.
//
// 2026-07-11 (H22): 30 frames (~1.7 s) still not enough for ~400-byte WSP
// Result bodies — those segment into ~15-20 AL fragments over ~1 s of PDCH TX,
// plus MS reassembly + WTP hand-up + uplink AL-ACK. Observed drop at N(S)=3
// after 1.7 s wait, triggering ~11 s of MS WTP-layer re-invocation retries
// (page loads but slowly). Bumped to 90 frames (~5 s) to comfortably cover
// large-SDU round-trip on single-slot PDCH.
//
// 2026-07-11 (H47): retuned back to 36 frames (~2.04 s) after the H17
// tail-tracking fix (llc_bs_ms.rs:2231-2289) — the ACK-wait clock now only
// opens *after* UMAC reports the tail on air, so the timer only has to cover
// peer reassembly + AL-ACK round-trip (~200-400 ms typical, ~800 ms
// worst-case). 5.1 s was leaving 3 retries stretched over ~15 s of wall
// clock when air conditions clipped a single segment (MTP6550 field trace
// 2026-07-11 16:27:07-16:27:17). 36 frames matches the ETSI TS 100 392-2
// v3.7.1 Annex A.1 Table A.1 spec default of ~2 s while still being ~6×
// the measured ACK RTT, so premature-retx risk is negligible.
pub const T251_SENDER_RETRY_TIMER: u32 = frames!(4); // 4 signalling frames
pub const T252_ACK_WAITING_TIMER: u32 = frames!(36);
pub const T261_SETUP_WAITING_TIMER: u32 = frames!(4);
pub const T263_DISCONNECT_WAITING_TIMER: u32 = frames!(4);
pub const T265_RECONNECT_WAITING_TIMER: u32 = frames!(4);
pub const T271_RECEIVER_NOT_READY_FOR_TX_TIMER: u32 = frames!(36);
pub const T272_RECEIVER_NOT_READY_FOR_RX_TIMER: u32 = frames!(18);
