//! Repeat-offset history for RAR1 short matches.
//!
//! `XADRAR15Handle.m` keeps `oldoffset[4]` (a 4-deep ring of recent match
//! offsets) plus `oldoffsetindex` (the write cursor), and `lastoffset` /
//! `lastlength` for the single most-recent match. The short-match branch
//! ("selector 9..13" in the reverse-engineered notes) selects between
//! "repeat the immediately-prior match" and "reuse one of the four
//! recently-recorded offsets" — a coarse LZX-style LRU.
//!
//! We surface that as two pieces:
//!
//! - [`OffsetHistory`]: the 4-slot ring and the "last" record. Pushing a
//!   new offset moves the ring forward and updates "last". A read at
//!   logical position `0..4` returns one of the historical offsets without
//!   any reordering — RAR1's `EmitShortMatch` reads at
//!   `(oldoffsetindex - (selector - 9)) & 3`, treating the ring as a plain
//!   ring buffer (not a move-to-front list).
//! - [`RepeatLastTracker`]: the `numrepeatedlastmatches` counter that
//!   gates whether the next "repeat last" needs an extra bit (after 2
//!   repeats, the next decision is bit-driven).

// Building-block; consumer is the future RAR1 state machine.
#![allow(dead_code)]

/// Number of recent offsets retained for the short-match LRU.
pub const RECENT_OFFSETS: usize = 4;

/// 4-slot LRU of recent match offsets.
#[derive(Debug, Clone)]
pub struct OffsetHistory {
    ring: [u32; RECENT_OFFSETS],
    /// Index of the slot that the *next* push will write into. The most
    /// recent push lives at `(write_idx - 1) & 3`.
    write_idx: u8,
    /// The most recent (offset, length). Mirrors RAR1's `lastoffset` /
    /// `lastlength` globals used by selector 9 ("repeat last match").
    last_offset: u32,
    last_length: u32,
}

impl OffsetHistory {
    pub const fn new() -> Self {
        Self {
            ring: [0u32; RECENT_OFFSETS],
            write_idx: 0,
            last_offset: 0,
            last_length: 0,
        }
    }

    /// Record a new match. The 4-deep ring rotates; `last_offset` /
    /// `last_length` are updated.
    pub fn push(&mut self, offset: u32, length: u32) {
        self.ring[self.write_idx as usize] = offset;
        self.write_idx = (self.write_idx + 1) & (RECENT_OFFSETS as u8 - 1);
        self.last_offset = offset;
        self.last_length = length;
    }

    /// Return the offset that the original code would access as
    /// `oldoffset[(oldoffsetindex - back) & 3]`, where `back` is `1..=4`.
    /// `back=1` is the most-recently-pushed offset, `back=4` is the oldest
    /// of the four still in the ring.
    pub fn peek_back(&self, back: u8) -> u32 {
        debug_assert!((1..=RECENT_OFFSETS as u8).contains(&back));
        let idx = (self.write_idx + RECENT_OFFSETS as u8 - back) & (RECENT_OFFSETS as u8 - 1);
        self.ring[idx as usize]
    }

    pub fn last_offset(&self) -> u32 {
        self.last_offset
    }

    pub fn last_length(&self) -> u32 {
        self.last_length
    }

    pub fn reset(&mut self) {
        *self = Self::new();
    }
}

impl Default for OffsetHistory {
    fn default() -> Self {
        Self::new()
    }
}

/// `numrepeatedlastmatches` counter. After two back-to-back "repeat the
/// last match" decisions, the third one is bit-driven: the decoder reads a
/// single flag bit and uses it to decide whether to keep repeating.
#[derive(Debug, Clone, Copy, Default)]
pub struct RepeatLastTracker {
    pub repeats: u8,
}

impl RepeatLastTracker {
    pub const fn new() -> Self {
        Self { repeats: 0 }
    }

    /// Tally a "repeat last" event. Returns `true` if the next decision is
    /// implicit (≤ 2 prior repeats); `false` if it must be bit-driven.
    pub fn observe_repeat(&mut self) -> bool {
        self.repeats = self.repeats.saturating_add(1);
        self.repeats <= 2
    }

    /// Reset the counter (called on a non-repeat short match).
    pub fn reset(&mut self) {
        self.repeats = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_records_recent() {
        let mut h = OffsetHistory::new();
        h.push(10, 3);
        h.push(20, 4);
        h.push(30, 5);
        h.push(40, 6);
        // peek_back(1) = most recent = 40
        assert_eq!(h.peek_back(1), 40);
        assert_eq!(h.peek_back(2), 30);
        assert_eq!(h.peek_back(3), 20);
        assert_eq!(h.peek_back(4), 10);
        assert_eq!(h.last_offset(), 40);
        assert_eq!(h.last_length(), 6);
    }

    #[test]
    fn ring_wraps_after_four_pushes() {
        let mut h = OffsetHistory::new();
        for v in [1u32, 2, 3, 4, 5] {
            h.push(v, v);
        }
        // The oldest (1) was evicted; ring now holds 2,3,4,5 in some order.
        // peek_back(1) is always the most recent.
        assert_eq!(h.peek_back(1), 5);
        assert_eq!(h.peek_back(2), 4);
        assert_eq!(h.peek_back(3), 3);
        assert_eq!(h.peek_back(4), 2);
    }

    #[test]
    fn last_offset_and_length_update() {
        let mut h = OffsetHistory::new();
        h.push(42, 7);
        assert_eq!(h.last_offset(), 42);
        assert_eq!(h.last_length(), 7);
        h.push(99, 11);
        assert_eq!(h.last_offset(), 99);
        assert_eq!(h.last_length(), 11);
    }

    #[test]
    fn reset_clears_ring() {
        let mut h = OffsetHistory::new();
        h.push(1, 2);
        h.reset();
        assert_eq!(h.last_offset(), 0);
        assert_eq!(h.last_length(), 0);
        for back in 1..=RECENT_OFFSETS as u8 {
            assert_eq!(h.peek_back(back), 0);
        }
    }

    #[test]
    fn repeat_tracker_first_two_implicit() {
        let mut r = RepeatLastTracker::new();
        assert!(r.observe_repeat()); // 1st: implicit
        assert!(r.observe_repeat()); // 2nd: implicit
        assert!(!r.observe_repeat()); // 3rd: bit-driven
        assert!(!r.observe_repeat()); // 4th+: bit-driven
        r.reset();
        assert!(r.observe_repeat()); // back to implicit after reset
    }
}
