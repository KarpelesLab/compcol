//! Hash-chain LZ77 match finder used by the deflate encoder.
//!
//! Per-block: at each position the encoder calls [`MatchFinder::insert`] to
//! splice that position into the per-3-byte hash chain, then optionally
//! calls [`MatchFinder::find_match`] to find the longest prior occurrence of
//! the next 3+ bytes within the deflate window (32 KiB). The chain walk is
//! bounded by [`MAX_CHAIN`] steps.

use alloc::boxed::Box;

use super::tables::{MAX_MATCH, MIN_MATCH, WINDOW_SIZE};

pub const HASH_BITS: u32 = 15;
pub const HASH_SIZE: usize = 1 << HASH_BITS;

/// Stop searching once we've found a match this long.
const NICE_MATCH: usize = 258;

/// Maximum number of chain links the match finder walks before giving up.
/// `128` is the value zlib uses at compression level 6 — a reasonable
/// quality/speed trade-off.
const MAX_CHAIN: usize = 128;

/// Sentinel value meaning "no entry".
const NIL: u32 = u32::MAX;

/// Hash function over three bytes. zlib uses a rotated XOR; we use the same
/// shape for deterministic, well-distributed output.
fn hash3(b0: u8, b1: u8, b2: u8) -> u32 {
    ((b0 as u32) << 10) ^ ((b1 as u32) << 5) ^ (b2 as u32)
}

/// Size of the per-block buffer the encoder feeds us. The `prev` array
/// needs one slot per buffer position.
pub const BUFFER_SIZE: usize = 16 * 1024;

pub struct MatchFinder {
    head: Box<[u32; HASH_SIZE]>,
    prev: Box<[u32; BUFFER_SIZE]>,
}

impl MatchFinder {
    pub fn new() -> Self {
        Self {
            head: Box::new([NIL; HASH_SIZE]),
            prev: Box::new([NIL; BUFFER_SIZE]),
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

    /// Record that the three bytes at `buffer[pos..pos+3]` start at `pos`.
    /// No-op if there aren't three bytes available there.
    pub fn insert(&mut self, buffer: &[u8], pos: usize) {
        if pos + 3 > buffer.len() {
            return;
        }
        let h = hash3(buffer[pos], buffer[pos + 1], buffer[pos + 2]);
        let idx = (h as usize) & (HASH_SIZE - 1);
        self.prev[pos] = self.head[idx];
        self.head[idx] = pos as u32;
    }

    /// Find the longest prior match for the bytes at `buffer[pos..]`.
    ///
    /// Returns `Some((length, distance))` with `length ≥ MIN_MATCH` if a
    /// match was found within the 32 KiB deflate window, else `None`.
    pub fn find_match(&self, buffer: &[u8], pos: usize) -> Option<(u16, u16)> {
        if pos + MIN_MATCH > buffer.len() {
            return None;
        }
        let h = hash3(buffer[pos], buffer[pos + 1], buffer[pos + 2]);
        let idx = (h as usize) & (HASH_SIZE - 1);

        let max_dist = WINDOW_SIZE.min(pos);
        let max_len = MAX_MATCH.min(buffer.len() - pos);
        if max_len < MIN_MATCH {
            return None;
        }

        let mut best_len: usize = 0;
        let mut best_dist: usize = 0;

        let mut cur = self.head[idx];
        let mut steps = 0usize;

        while cur != NIL && steps < MAX_CHAIN {
            let cur_pos = cur as usize;
            // Hash chain may have stale entries from earlier blocks; ignore
            // anything not strictly before `pos`.
            if cur_pos >= pos {
                cur = self.prev[cur_pos];
                steps += 1;
                continue;
            }
            let dist = pos - cur_pos;
            if dist > max_dist {
                break;
            }

            // Cheap rejection: if we already have a match of length `best_len`,
            // a candidate can only improve it if its byte at position
            // `best_len` matches. We only apply the test when both buffers
            // have a byte at that offset (i.e. `best_len < max_len`); when
            // the current best already reaches the end of the lookahead,
            // skipping this test costs nothing because the extend loop
            // below will bail immediately.
            if best_len > 0
                && best_len < max_len
                && buffer[cur_pos + best_len] != buffer[pos + best_len]
            {
                cur = self.prev[cur_pos];
                steps += 1;
                continue;
            }

            // Extend the match from the start.
            let mut len = 0;
            while len < max_len && buffer[cur_pos + len] == buffer[pos + len] {
                len += 1;
            }

            if len >= MIN_MATCH && len > best_len {
                best_len = len;
                best_dist = dist;
                if best_len >= NICE_MATCH {
                    break;
                }
            }

            cur = self.prev[cur_pos];
            steps += 1;
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
