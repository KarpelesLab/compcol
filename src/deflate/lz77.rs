//! Hash-chain LZ77 match finder used by the deflate encoder.
//!
//! Positions in the chains are *absolute* byte offsets into the input
//! stream. The `prev` array is indexed by `pos & PREV_MASK` (a power-of-two
//! mask) so wrap-around is implicit; the caller is responsible for only
//! following links that fall within the sliding window of the current
//! position. This avoids any rehashing cost when a block boundary is
//! crossed: the chains simply keep being extended.

use alloc::boxed::Box;

use super::tables::{MAX_MATCH, MIN_MATCH, WINDOW_SIZE};

pub const HASH_BITS: u32 = 15;
pub const HASH_SIZE: usize = 1 << HASH_BITS;

/// Sentinel value meaning "no entry".
const NIL: u32 = u32::MAX;

/// Size of the `prev` ring buffer. Must be a power of two ≥ WINDOW_SIZE so
/// any in-window absolute position maps uniquely.
pub const PREV_SIZE: usize = WINDOW_SIZE;
const PREV_MASK: usize = PREV_SIZE - 1;

/// Hash function over three bytes. zlib uses a rotated XOR; we use the same
/// shape for deterministic, well-distributed output.
fn hash3(b0: u8, b1: u8, b2: u8) -> u32 {
    ((b0 as u32) << 10) ^ ((b1 as u32) << 5) ^ (b2 as u32)
}

pub struct MatchFinder {
    /// `head[hash]` is the absolute position of the most recent occurrence
    /// of the 3-byte sequence with this hash, or NIL.
    head: Box<[u32; HASH_SIZE]>,
    /// `prev[pos & PREV_MASK]` is the absolute position of the previous
    /// occurrence of the same hash before `pos`, or NIL.
    prev: Box<[u32; PREV_SIZE]>,
}

impl MatchFinder {
    pub fn new() -> Self {
        Self {
            head: Box::new([NIL; HASH_SIZE]),
            prev: Box::new([NIL; PREV_SIZE]),
        }
    }

    /// Forget every position recorded so far.
    pub fn reset(&mut self) {
        for h in self.head.iter_mut() {
            *h = NIL;
        }
        for p in self.prev.iter_mut() {
            *p = NIL;
        }
    }

    /// Splice the 3-byte sequence starting at absolute position `abs_pos`
    /// (whose bytes are `b0`, `b1`, `b2`) into the hash chain. The caller
    /// guarantees the three bytes are available.
    #[inline]
    pub fn insert(&mut self, abs_pos: u32, b0: u8, b1: u8, b2: u8) {
        let h = hash3(b0, b1, b2);
        let idx = (h as usize) & (HASH_SIZE - 1);
        self.prev[(abs_pos as usize) & PREV_MASK] = self.head[idx];
        self.head[idx] = abs_pos;
    }

    /// Find the longest prior match for `window[rel..]`, where `window`
    /// holds at least the deflate sliding window's worth of recent bytes
    /// plus the current lookahead, and `rel` is the index inside `window`
    /// corresponding to absolute position `abs_pos`.
    ///
    /// `max_chain` caps how many hash-chain links we walk before giving up;
    /// `nice_match` is the length at which we stop searching for a longer
    /// candidate. When `have_good` is true we already hold a "good enough"
    /// match elsewhere and quarter the chain budget — this is the lazy-match
    /// speed-up.
    ///
    /// Returns `Some((length, distance))` with `length ≥ MIN_MATCH` if a
    /// match was found within the 32 KiB deflate window, else `None`.
    pub fn find_match(
        &self,
        window: &[u8],
        rel: usize,
        abs_pos: u32,
        have_good: bool,
        max_chain: usize,
        nice_match: usize,
    ) -> Option<(u16, u16)> {
        if rel + MIN_MATCH > window.len() {
            return None;
        }
        let h = hash3(window[rel], window[rel + 1], window[rel + 2]);
        let idx = (h as usize) & (HASH_SIZE - 1);

        let max_dist = WINDOW_SIZE.min(abs_pos as usize);
        let max_len = MAX_MATCH.min(window.len() - rel);
        if max_len < MIN_MATCH {
            return None;
        }

        let mut best_len: usize = 0;
        let mut best_dist: usize = 0;

        let mut cur = self.head[idx];
        // If we already have a "good" match, quarter the chain budget.
        let mut chain_left = if have_good { max_chain / 4 } else { max_chain };

        while cur != NIL && chain_left > 0 {
            let cur_abs = cur as usize;
            // Stale entries: ignore positions ≥ our own.
            if cur_abs >= abs_pos as usize {
                cur = self.prev[cur_abs & PREV_MASK];
                chain_left -= 1;
                continue;
            }
            let dist = abs_pos as usize - cur_abs;
            if dist > max_dist {
                break;
            }
            let cur_rel = rel - dist; // safe: dist ≤ rel because the candidate is in-window

            // Cheap rejection: if we already have a match of length `best_len`,
            // a candidate can only improve it if its byte at position
            // `best_len` matches. Apply when both buffers have a byte there.
            if best_len > 0
                && best_len < max_len
                && window[cur_rel + best_len] != window[rel + best_len]
            {
                cur = self.prev[cur_abs & PREV_MASK];
                chain_left -= 1;
                continue;
            }

            // Extend the match from the start.
            let mut len = 0;
            while len < max_len && window[cur_rel + len] == window[rel + len] {
                len += 1;
            }

            if len >= MIN_MATCH && len > best_len {
                best_len = len;
                best_dist = dist;
                if best_len >= nice_match {
                    break;
                }
            }

            cur = self.prev[cur_abs & PREV_MASK];
            chain_left -= 1;
        }

        if best_len >= MIN_MATCH {
            Some((best_len as u16, best_dist as u16))
        } else {
            None
        }
    }
}

impl Default for MatchFinder {
    fn default() -> Self {
        Self::new()
    }
}
