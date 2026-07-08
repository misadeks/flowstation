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
}

/// Tracks per-ISSI PDCH reservations and handles idle-release.
pub struct PdchAllocator {
    /// Active reservations keyed by ISSI.
    pub reservations: HashMap<u32, PdchReservation>,
    /// Number of idle frames before a reservation is auto-released.
    pub idle_release_frames: u32,
}

impl PdchAllocator {
    pub fn new(idle_release_frames: u32) -> Self {
        Self {
            reservations: HashMap::new(),
            idle_release_frames,
        }
    }

    /// Create or refresh a reservation for `issi`.
    /// If a reservation already exists it is refreshed (last_used_at updated).
    pub fn reserve(&mut self, issi: u32, nsapi: u8, now: TdmaTime) {
        self.reservations
            .entry(issi)
            .and_modify(|r| {
                r.last_used_at = now;
            })
            .or_insert_with(|| PdchReservation {
                issi,
                nsapi,
                reserved_at: now,
                last_used_at: now,
            });
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
        alloc.reserve(1234, 0, t(0, 1, 1, 1));
        assert!(alloc.reservations.contains_key(&1234));
        assert_eq!(alloc.reservations[&1234].nsapi, 0);
    }

    #[test]
    fn double_reserve_refreshes_last_used() {
        let mut alloc = PdchAllocator::new(PDCH_IDLE_RELEASE_FRAMES);
        let t0 = t(0, 1, 1, 1);
        let t1 = t(0, 1, 5, 1);
        alloc.reserve(1234, 0, t0);
        alloc.reserve(1234, 0, t1);
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
