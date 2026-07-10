use tetra_core::frames;

// Timers as defined in Annex A.1 LLC timers.
//
// Hardware-tuned 2026-07-10 vs Motorola MTP3550: T252 default (9 frames ≈ 510 ms)
// was too short for large SDUs on single-slot PDCH — a ~600-bit WSP Reply takes
// ~500 ms to transmit, leaving no time for the MS AL-ACK round-trip before T252
// expires. With max_retx=0 (MS default) that means the SDU is dropped mid-flight.
// Bumped T252 to 30 frames (~1700 ms) per ETSI spec default, giving ample window
// for full-SDU transmission + MS processing + ACK on real TETRA links.
pub const T251_SENDER_RETRY_TIMER: u32 = frames!(4); // 4 signalling frames
pub const T252_ACK_WAITING_TIMER: u32 = frames!(30);
pub const T261_SETUP_WAITING_TIMER: u32 = frames!(4);
pub const T263_DISCONNECT_WAITING_TIMER: u32 = frames!(4);
pub const T265_RECONNECT_WAITING_TIMER: u32 = frames!(4);
pub const T271_RECEIVER_NOT_READY_FOR_TX_TIMER: u32 = frames!(36);
pub const T272_RECEIVER_NOT_READY_FOR_RX_TIMER: u32 = frames!(18);
