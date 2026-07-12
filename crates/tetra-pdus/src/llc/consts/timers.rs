use tetra_core::frames;

// PD-REWRITE C2: T.252 comment updated to cite the current spec (v3.10.1)
// and reframe the flowstation value as a vendor over-provision above spec
// default. The old comment cited v3.7.1 which we couldn't verify on-disk;
// v3.10.1 Annex A defines T.252 default = 9 signalling frames (~510 ms).
// flowstation runs T.252 at 36 frames (~2.04 s), which is ~4× the v3.10.1
// default and ~6× the measured single-slot PDCH ACK RTT (~200-400 ms
// typical, ~800 ms worst case). The over-provision keeps premature-retx
// risk negligible during interop with high-latency MTP-class MS radios
// while remaining well within Annex A's u8 encoding range.
//
// History (preserved so the tuning journey is legible):
// 2026-07-10: T252 default of 9 signalling frames (~510 ms) too short for
// large SDUs on single-slot PDCH.
// 2026-07-11 (H22): 30 frames (~1.7 s) still insufficient for ~400-byte
// WSP Result bodies; bumped to 90 frames (~5 s).
// 2026-07-11 (H47): retuned to 36 frames (~2.04 s) after the H17
// tail-tracking fix (llc_bs_ms.rs:2231-2289) — the ACK-wait clock now
// opens only after UMAC reports the tail on air, so the timer only
// covers peer reassembly + AL-ACK round-trip.
pub const T251_SENDER_RETRY_TIMER: u32 = frames!(4); // 4 signalling frames
pub const T252_ACK_WAITING_TIMER: u32 = frames!(36);
pub const T261_SETUP_WAITING_TIMER: u32 = frames!(4);
pub const T263_DISCONNECT_WAITING_TIMER: u32 = frames!(4);
pub const T265_RECONNECT_WAITING_TIMER: u32 = frames!(4);
pub const T271_RECEIVER_NOT_READY_FOR_TX_TIMER: u32 = frames!(36);
pub const T272_RECEIVER_NOT_READY_FOR_RX_TIMER: u32 = frames!(18);
