use std::collections::HashMap;

use tetra_core::TdmaTime;

/// How many frames of idle time before a PDCH reservation is automatically
/// released. At 18 frames/second this is approximately 1 second.
/// NOTE: spec ambiguous — chosen behaviour: 18 frames (~1 s idle release).
pub const PDCH_IDLE_RELEASE_FRAMES: u32 = 300;

/// Hard cap on the number of concurrent PDCH reservations.
///
/// PD-5c-H40: the traffic usage marker (UMt) field in the AACH is 6 bits
/// but ETSI TS 100 392-2 §23.5.1 reserves values 0 (unallocated), 1–3, and
/// 63, leaving only [4, 62] = 59 slots for live PDCH reservations. If we
/// let `reserve()` insert unconditionally past that, the rotating cursor in
/// `alloc_umt` would eventually hand the same UMt to two ISSIs → downlink
/// packets delivered to the wrong subscriber ("UMt cross-talk").
///
/// We cap at 56 rather than 59 to keep 3 UMt values as headroom for
/// concurrency corner cases (e.g. an old reservation about to expire on the
/// next `expire_idle` sweep while a new one races to allocate). Motorola
/// exposes the equivalent limit via the `M_MAXUSERSPERDYNPDCHAN` MIB
/// parameter and rejects new `PDCH_RESOURCE_REQUEST`s over that threshold
/// (see `Docs/audit/03-pdch-aach.md` §P5).
pub const PDCH_MAX_RESERVATIONS: usize = 56;

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
    /// The timeslots currently allocated for PDCH use (ordered by preference: TS4 first).
    /// Empty when no PDCH slot could be picked this hyperframe (e.g. voice took all eligible
    /// slots).  Updated each hyperframe by the UMAC scheduler.
    pub current_timeslots: Vec<u8>,
    /// PD-5c-H52c: per-eligible-TS consecutive-voice-free-tick counter
    /// (keyed by TS 2..=4). Incremented once per UMAC tick for each TS
    /// observed voice-free, capped at the caller-supplied stability
    /// threshold; reset to 0 the moment a TS becomes voice-busy. Used by
    /// `tick_stability` to debounce AACH announcements so transient voice
    /// contention doesn't churn the PDCH pool and cause MS lock-loss.
    pub consec_free_ticks: HashMap<u8, u8>,
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
            current_timeslots: Vec::new(),
            consec_free_ticks: HashMap::new(),
            next_umt: 4, // Start at 4; range [4, 62] per spec
        }
    }

    /// PD-5c-H52c: advance the per-TS AACH-stability counters for this tick.
    ///
    /// Given the set of candidate timeslots observed voice-free in the
    /// current tick, increment their counters (saturating at
    /// `stability_ticks`) and reset counters for any TS not in `free_ts`
    /// (i.e. voice/circuit is contending). Returns the subset of `free_ts`
    /// whose counter has reached `stability_ticks` and are therefore
    /// eligible to be labelled PDCH this tick, preserving the input order.
    ///
    /// `stability_ticks == 0` disables hysteresis: every free candidate is
    /// returned immediately (H52b behaviour).
    ///
    /// This is called once per UMAC tick from `UmacBs::tick_start`. Only
    /// candidates TS2/TS3/TS4 are tracked (TS1 is control channel).
    pub fn tick_stability(&mut self, free_ts: &[u8], stability_ticks: u8) -> Vec<u8> {
        // Update counters for all three eligible timeslots so a TS falling
        // out of `free_ts` immediately resets, even if not queried this tick.
        for ts in [2u8, 3, 4] {
            let is_free = free_ts.contains(&ts);
            let counter = self.consec_free_ticks.entry(ts).or_insert(0);
            if is_free {
                let cap = stability_ticks.max(1);
                *counter = counter.saturating_add(1).min(cap);
            } else {
                *counter = 0;
            }
        }
        if stability_ticks == 0 {
            return free_ts.to_vec();
        }
        free_ts
            .iter()
            .filter(|ts| self.consec_free_ticks.get(ts).copied().unwrap_or(0) >= stability_ticks)
            .copied()
            .collect()
    }

    /// Allocate the next traffic usage marker (UMt) that is NOT currently
    /// held by any live reservation.
    ///
    /// PD-5c-H40: the naive cursor increment could wrap into a UMt value
    /// still held by an existing reservation, producing two ISSIs with the
    /// same UMt → downlink cross-talk. We scan forward through the [4, 62]
    /// range until we find an unheld slot. Returns `None` if every slot is
    /// occupied (which is only reachable if the caller has already exceeded
    /// PDCH_MAX_RESERVATIONS via a bypass path — reserve() guards against
    /// that at the entry point).
    fn alloc_umt(&mut self) -> Option<u8> {
        let held: std::collections::HashSet<u8> =
            self.reservations.values().map(|r| r.umt).collect();
        // Scan up to 59 candidate values ([4, 62] inclusive is 59 slots).
        for _ in 0..59 {
            let candidate = self.next_umt;
            self.next_umt = if candidate >= 62 { 4 } else { candidate + 1 };
            if !held.contains(&candidate) {
                return Some(candidate);
            }
        }
        None
    }

    /// Create or refresh a reservation for `issi`.
    ///
    /// Returns:
    /// - `Some(true)`  — this was a NEW reservation.
    /// - `Some(false)` — the reservation already existed and was refreshed.
    /// - `None`        — the reservation cap (`PDCH_MAX_RESERVATIONS`) is
    ///   reached; the caller must not grant PDCH access to this MS on this
    ///   transaction. The MS will retry via SN-DATA-TRANSMIT-REQUEST and can
    ///   get admitted after another MS's reservation is released.
    ///
    /// PD-5c-H40: refresh paths are ALWAYS accepted even when the cap is
    /// reached — refusing a refresh would drop a live subscriber for no
    /// benefit; the cap only gates admission of NEW ISSIs.
    pub fn reserve(&mut self, issi: u32, nsapi: u8, now: TdmaTime) -> Option<bool> {
        if self.reservations.contains_key(&issi) {
            self.reservations.get_mut(&issi).unwrap().last_used_at = now;
            return Some(false);
        }
        if self.reservations.len() >= PDCH_MAX_RESERVATIONS {
            tracing::warn!(
                "PDCH reservation cap ({}) reached; rejecting new reservation for issi={}",
                PDCH_MAX_RESERVATIONS,
                issi,
            );
            return None;
        }
        let umt = match self.alloc_umt() {
            Some(u) => u,
            None => {
                // Should be unreachable given the cap check above, but be
                // defensive: if UMt space is exhausted, refuse admission.
                tracing::warn!(
                    "PDCH UMt space exhausted; rejecting new reservation for issi={}",
                    issi
                );
                return None;
            }
        };
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
        Some(true)
    }

    /// Update `last_used_at` for `issi` without creating a new reservation.
    pub fn touch(&mut self, issi: u32, now: TdmaTime) {
        if let Some(r) = self.reservations.get_mut(&issi) {
            r.last_used_at = now;
        }
    }

    /// Return the primary (first-preference) PDCH timeslot, or `None` when the set is empty.
    ///
    /// Compat helper for callers that only need a single slot (single-slot paths and
    /// legacy code that hasn't been widened to the full set yet).
    pub fn primary_timeslot(&self) -> Option<u8> {
        self.current_timeslots.first().copied()
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
        assert_eq!(is_new, Some(true), "first reserve must return Some(true)");
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
        assert_eq!(first, Some(true), "first reserve must be new");
        assert_eq!(second, Some(false), "second reserve must be a refresh");
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

    // ─── PD-5c-H40: cap + UMt collision-avoidance tests ────────────────────

    #[test]
    fn reserve_up_to_cap_succeeds() {
        let mut alloc = PdchAllocator::new(PDCH_IDLE_RELEASE_FRAMES);
        let now = t(0, 1, 1, 1);
        for i in 0..PDCH_MAX_RESERVATIONS as u32 {
            let r = alloc.reserve(1_000_000 + i, 0, now);
            assert_eq!(r, Some(true), "reserve #{i} must succeed");
        }
        assert_eq!(alloc.reservations.len(), PDCH_MAX_RESERVATIONS);
    }

    #[test]
    fn reserve_beyond_cap_returns_none() {
        let mut alloc = PdchAllocator::new(PDCH_IDLE_RELEASE_FRAMES);
        let now = t(0, 1, 1, 1);
        for i in 0..PDCH_MAX_RESERVATIONS as u32 {
            assert_eq!(alloc.reserve(1_000_000 + i, 0, now), Some(true));
        }
        // The (cap+1)-th new ISSI must be rejected.
        let over = alloc.reserve(9_999_999, 0, now);
        assert_eq!(over, None, "reservation past cap must be rejected");
        assert_eq!(alloc.reservations.len(), PDCH_MAX_RESERVATIONS);

        // But a refresh on an existing ISSI must still succeed even at cap.
        let refresh = alloc.reserve(1_000_000, 0, now);
        assert_eq!(refresh, Some(false));
    }

    #[test]
    fn release_then_reserve_at_cap_succeeds() {
        let mut alloc = PdchAllocator::new(PDCH_IDLE_RELEASE_FRAMES);
        let now = t(0, 1, 1, 1);
        for i in 0..PDCH_MAX_RESERVATIONS as u32 {
            assert_eq!(alloc.reserve(1_000_000 + i, 0, now), Some(true));
        }
        // At cap → new ISSI fails.
        assert_eq!(alloc.reserve(7_777_777, 0, now), None);
        // Release one, retry → succeeds.
        alloc.release(1_000_000);
        assert_eq!(alloc.reserve(7_777_777, 0, now), Some(true));
        assert_eq!(alloc.reservations.len(), PDCH_MAX_RESERVATIONS);
    }

    #[test]
    fn umt_never_collides_between_live_reservations() {
        let mut alloc = PdchAllocator::new(PDCH_IDLE_RELEASE_FRAMES);
        let now = t(0, 1, 1, 1);
        for i in 0..PDCH_MAX_RESERVATIONS as u32 {
            assert_eq!(alloc.reserve(1_000_000 + i, 0, now), Some(true));
        }
        let mut seen = std::collections::HashSet::new();
        for r in alloc.reservations.values() {
            assert!(
                (4..=62).contains(&r.umt),
                "umt {} out of spec [4,62]",
                r.umt
            );
            assert!(seen.insert(r.umt), "duplicate UMt {} across live reservations", r.umt);
        }
    }

    #[test]
    fn umt_reuse_after_release_does_not_collide_with_live() {
        // Drive the cursor forward, release some slots, then keep reserving
        // and confirm no two live reservations share a UMt.
        let mut alloc = PdchAllocator::new(PDCH_IDLE_RELEASE_FRAMES);
        let now = t(0, 1, 1, 1);
        for i in 0..30 {
            alloc.reserve(2_000_000 + i, 0, now);
        }
        // Release a scattered subset.
        for i in [3, 7, 11, 19, 25] {
            alloc.release(2_000_000 + i);
        }
        // Fill up to cap.
        let existing = alloc.reservations.len();
        for i in 0..(PDCH_MAX_RESERVATIONS - existing) as u32 {
            let r = alloc.reserve(3_000_000 + i, 0, now);
            assert_eq!(r, Some(true), "refill reserve #{i} must succeed");
        }
        let mut seen = std::collections::HashSet::new();
        for r in alloc.reservations.values() {
            assert!(seen.insert(r.umt), "duplicate UMt {} across live reservations", r.umt);
        }
    }

    // ── PD-5c-H52: current_timeslots ────────────────────────────────────────

    #[test]
    fn current_timeslots_ordered_ts4_first() {
        let mut alloc = PdchAllocator::new(PDCH_IDLE_RELEASE_FRAMES);
        // Simulate the scheduler assigning TS4 then TS3 (preference order).
        alloc.current_timeslots = vec![4, 3];
        assert_eq!(alloc.primary_timeslot(), Some(4), "primary must be TS4 (first in preference order)");
        // Single-slot assignment matches primary.
        alloc.current_timeslots = vec![3];
        assert_eq!(alloc.primary_timeslot(), Some(3));
        // Empty → None.
        alloc.current_timeslots.clear();
        assert_eq!(alloc.primary_timeslot(), None);
    }

    // ── PD-5c-H52c: AACH stability debounce (`tick_stability`) ──────────────

    #[test]
    fn stability_zero_ticks_returns_free_immediately() {
        // stability_ticks = 0 disables hysteresis → all free candidates
        // are promoted the first tick they appear (H52b behaviour).
        let mut alloc = PdchAllocator::new(PDCH_IDLE_RELEASE_FRAMES);
        let out = alloc.tick_stability(&[4, 3, 2], 0);
        assert_eq!(out, vec![4, 3, 2], "K=0 must return every free candidate on tick 1");
    }

    #[test]
    fn stability_debounce_delays_ts_addition_by_k_ticks() {
        let mut alloc = PdchAllocator::new(PDCH_IDLE_RELEASE_FRAMES);
        // Tick 1..K-1: TS4 is free but not yet stable.
        for i in 1..4 {
            let out = alloc.tick_stability(&[4], 4);
            assert!(out.is_empty(), "tick {i}: TS4 must not be promoted before K ticks");
        }
        // Tick 4: threshold reached, TS4 admitted.
        let out = alloc.tick_stability(&[4], 4);
        assert_eq!(out, vec![4], "TS4 must be promoted at tick K=4");
    }

    #[test]
    fn stability_resets_on_voice_contention() {
        let mut alloc = PdchAllocator::new(PDCH_IDLE_RELEASE_FRAMES);
        // Warm up TS4 counter close to threshold.
        for _ in 0..3 {
            alloc.tick_stability(&[4], 4);
        }
        // Voice grabs TS4 → counter resets.
        let out = alloc.tick_stability(&[3], 4);
        assert!(out.is_empty(), "voice contention on TS4 must reset its stability counter");
        assert_eq!(alloc.consec_free_ticks.get(&4).copied(), Some(0));
        // TS4 free again — must wait another full K ticks.
        for i in 1..4 {
            let out = alloc.tick_stability(&[4], 4);
            assert!(out.is_empty(), "post-reset tick {i}: TS4 must not be promoted before K ticks");
        }
        let out = alloc.tick_stability(&[4], 4);
        assert_eq!(out, vec![4], "TS4 re-admitted at post-reset tick K");
    }

    #[test]
    fn stability_independent_counters_per_ts() {
        let mut alloc = PdchAllocator::new(PDCH_IDLE_RELEASE_FRAMES);
        // TS4 free for 4 ticks, TS3 only free for the last tick.
        for _ in 0..3 {
            alloc.tick_stability(&[4], 4);
        }
        let out = alloc.tick_stability(&[4, 3], 4);
        assert_eq!(out, vec![4], "TS4 promoted, TS3 still warming up");
        // Advance three more ticks with both free — TS3 should catch up.
        for _ in 0..2 {
            alloc.tick_stability(&[4, 3], 4);
        }
        let out = alloc.tick_stability(&[4, 3], 4);
        assert_eq!(out, vec![4, 3], "both TS promoted after independent warm-ups");
    }
}