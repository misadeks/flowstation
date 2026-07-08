use std::collections::HashMap;

use tetra_core::TdmaTime;

/// How many frames of idle time before a PDCH reservation is automatically
/// released. At 18 frames/second this is approximately 1 second.
/// NOTE: spec ambiguous — chosen behaviour: 18 frames (~1 s idle release).
pub const PDCH_IDLE_RELEASE_FRAMES: u32 = 18;

/// A single per-ISSI PDCH reservation.
#[derive(Debug, Clone)]
pub struct PdchReservation {
    /// The ISSI that holds this reservation.
    pub issi: u32,
    /// NSAPI (Network-layer Service Access Point Identifier) for this reservation.
    pub nsapi: u8,
    /// Frame at which the reservation was created (used for age accounting).
    pub reserved_at: TdmaTime,
    /// Frame of the most recent packet-data activity for this ISSI.
    pub last_used_at: TdmaTime,
    /// Traffic usage marker (UMt) assigned to this PDCH reservation so the MS
    /// can identify the PDCH slot in the AACH per ETSI TS 100 392-2 §23.5.1.
    /// NOTE: spec ambiguous — chosen behaviour: assigned at reservation time,
    /// advertised in MAC-RESOURCE, echoed in AACH Traffic(UMt) field.
    pub umt: u8,
}

/// Tracks per-ISSI PDCH reservations and handles idle-release.
pub struct PdchAllocator {
    /// Active reservations keyed by ISSI.
    pub reservations: HashMap<u32, PdchReservation>,
    /// Number of idle frames before a reservation is auto-released.
    pub idle_release_frames: u32,
    /// The timeslot currently allocated for PDCH use, or `None` if no PDCH slot
    /// could be picked this hyperframe (e.g. voice took all eligible slots).
    /// Updated each hyperframe by the UMAC scheduler.
    pub current_timeslot: Option<u8>,
    /// Rotating cursor for UMt allocation. Valid range is [4, 62] per ETSI TS 100 392-2
    /// §23.5.1 (0 = unallocated, 1–3 and 63 reserved). Wraps back to 4 after 62.
    /// NOTE: spec ambiguous — chosen behaviour: per-allocator cursor, not per-timeslot,
    /// since PDCH uses a single dynamic timeslot per cell.
    next_umt: u8,
}

impl PdchAllocator {
    pub fn new(idle_release_frames: u32) -> Self {
        Self {
            reservations: HashMap::new(),
            idle_release_frames,
            current_timeslot: None,
            next_umt: 4, // Start at 4; range [4, 62] per spec
        }
    }

    /// Allocate the next traffic usage marker (UMt) from the rotating cursor.
    /// Wraps in the range [4, 62]; 0 is "unallocated", 1–3 and 63 are reserved.
    pub fn alloc_umt(&mut self) -> u8 {
        let umt = self.next_umt;
        self.next_umt = if umt >= 62 { 4 } else { umt + 1 };
        umt
    }

    /// Create or refresh a reservation for `issi`.
    /// If a reservation already exists it is refreshed (last_used_at updated).
    /// Returns `true` if this was a NEW reservation (not a refresh).
    pub fn reserve(&mut self, issi: u32, nsapi: u8, now: TdmaTime) -> bool {
        if self.reservations.contains_key(&issi) {
            self.reservations.get_mut(&issi).unwrap().last_used_at = now;
            false
        } else {
            let umt = self.alloc_umt();
            self.reservations.insert(
                issi,
                PdchReservation {
                    issi,
                    nsapi,
                    reserved_at: now,
                    last_used_at: now,
                    umt,
                },
            );
            true
        }
    }

    /// Update `last_used_at` for `issi` without creating a new reservation.
    pub fn touch(&mut self, issi: u32, now: TdmaTime) {
        if let Some(r) = self.reservations.get_mut(&issi) {
            r.last_used_at = now;
        }
    }

    /// Explicitly release the reservation for `issi`.
    pub fn release(&mut self, issi: u32) {
        self.reservations.remove(&issi);
    }

    /// Release reservations whose `last_used_at` is more than `idle_release_frames`
    /// frames ago.  Returns the list of released ISSIs (for logging).
    ///
    /// NOTE: spec ambiguous — chosen behaviour: "frame count" is computed as
    /// `(now.diff(last_used_at) / 4).abs()` — dividing timeslot distance by 4
    /// gives TDMA frames (each frame = 4 timeslots).
    pub fn expire_idle(&mut self, now: TdmaTime) -> Vec<u32> {
        let threshold = self.idle_release_frames;
        let mut released = Vec::new();
        self.reservations.retain(|&issi, r| {
            // diff() returns timeslots; 4 timeslots = 1 frame
            let idle_timeslots = now.diff(r.last_used_at);
            let idle_frames = (idle_timeslots / 4).unsigned_abs();
            if idle_frames >= threshold {
                released.push(issi);
                false // remove
            } else {
                true // keep
            }
        });
        released
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(h: u16, m: u8, f: u8, ts: u8) -> TdmaTime {
        TdmaTime { h, m, f, t: ts }
    }

    #[test]
    fn reserve_creates_entry() {
        let mut alloc = PdchAllocator::new(PDCH_IDLE_RELEASE_FRAMES);
        let is_new = alloc.reserve(1234, 0, t(0, 1, 1, 1));
        assert!(is_new, "first reserve must return true");
        assert!(alloc.reservations.contains_key(&1234));
        assert_eq!(alloc.reservations[&1234].nsapi, 0);
        // UMt must be in the valid range [4, 62]
        assert!((4..=62).contains(&alloc.reservations[&1234].umt));
    }

    #[test]
    fn double_reserve_refreshes_last_used() {
        let mut alloc = PdchAllocator::new(PDCH_IDLE_RELEASE_FRAMES);
        let t0 = t(0, 1, 1, 1);
        let t1 = t(0, 1, 5, 1);
        let first = alloc.reserve(1234, 0, t0);
        let second = alloc.reserve(1234, 0, t1);
        assert!(first, "first reserve must be new");
        assert!(!second, "second reserve must be a refresh");
        assert_eq!(alloc.reservations[&1234].last_used_at, t1);
        assert_eq!(alloc.reservations[&1234].reserved_at, t0);
    }

    #[test]
    fn release_removes_entry() {
        let mut alloc = PdchAllocator::new(PDCH_IDLE_RELEASE_FRAMES);
        alloc.reserve(1234, 0, t(0, 1, 1, 1));
        alloc.release(1234);
        assert!(!alloc.reservations.contains_key(&1234));
    }

    #[test]
    fn expire_idle_removes_stale_reservation() {
        let mut alloc = PdchAllocator::new(18);
        let start = t(0, 1, 1, 1);
        alloc.reserve(1234, 0, start);
        // Advance 18 frames = 18 * 4 = 72 timeslots (exactly at threshold → released)
        let now = start.add_timeslots(18 * 4);
        let released = alloc.expire_idle(now);
        assert!(released.contains(&1234), "stale reservation must be released");
        assert!(!alloc.reservations.contains_key(&1234));
    }

    #[test]
    fn expire_idle_keeps_active_reservation() {
        let mut alloc = PdchAllocator::new(18);
        let start = t(0, 1, 1, 1);
        alloc.reserve(1234, 0, start);
        // Only 5 frames = 20 timeslots elapsed — still active
        let now = start.add_timeslots(5 * 4);
        let released = alloc.expire_idle(now);
        assert!(released.is_empty());
        assert!(alloc.reservations.contains_key(&1234));
    }
}
