//! Hash-chain LZ77 match finder used by the deflate64 encoder.
//!
//! Structurally identical to the deflate match finder, but parameterised
//! to deflate64's 64 KiB window and 65538-byte maximum match. The `prev`
//! ring is sized to the window so any in-window absolute position maps
//! uniquely.

use alloc::boxed::Box;

use super::tables::{MAX_MATCH, MIN_MATCH, WINDOW_SIZE};

pub const HASH_BITS: u32 = 16;
pub const HASH_SIZE: usize = 1 << HASH_BITS;

/// Sentinel value meaning "no entry".
const NIL: u32 = u32::MAX;

/// Size of the `prev` ring buffer. Must be a power of two ≥ WINDOW_SIZE so
/// any in-window absolute position maps uniquely.
pub const PREV_SIZE: usize = WINDOW_SIZE;
const PREV_MASK: usize = PREV_SIZE - 1;

/// Hash function over three bytes. Same rotated-XOR shape as deflate's
/// match finder, widened to a 16-bit table for the larger window.
#[inline(always)]
fn hash3(b0: u8, b1: u8, b2: u8) -> u32 {
    ((b0 as u32) << 11) ^ ((b1 as u32) << 6) ^ ((b2 as u32) << 1)
}

pub struct MatchFinder {
    head: Box<[u32; HASH_SIZE]>,
    prev: Box<[u32; PREV_SIZE]>,
}

impl MatchFinder {
    pub fn new() -> Self {
        Self {
            head: Box::new([NIL; HASH_SIZE]),
            prev: Box::new([NIL; PREV_SIZE]),
        }
    }

    pub fn reset(&mut self) {
        for h in self.head.iter_mut() {
            *h = NIL;
        }
        for p in self.prev.iter_mut() {
            *p = NIL;
        }
    }

    #[inline]
    pub fn insert(&mut self, abs_pos: u32, b0: u8, b1: u8, b2: u8) {
        let h = hash3(b0, b1, b2);
        let idx = (h as usize) & (HASH_SIZE - 1);
        self.prev[(abs_pos as usize) & PREV_MASK] = self.head[idx];
        self.head[idx] = abs_pos;
    }

    /// Find the longest prior match for `window[rel..]`. Returns
    /// `Some((length, distance))` with `length ≥ MIN_MATCH`. The length is
    /// returned as `u32` because deflate64 matches can be up to 65538 bytes.
    #[inline]
    pub fn find_match(
        &self,
        window: &[u8],
        rel: usize,
        abs_pos: u32,
        have_good: bool,
        max_chain: usize,
        nice_match: usize,
    ) -> Option<(u32, u32)> {
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
        let mut chain_left = if have_good { max_chain / 4 } else { max_chain };
        let mut tail_pair: [u8; 2] = [0, 0];

        while cur != NIL && chain_left > 0 {
            let cur_abs = cur as usize;
            if cur_abs >= abs_pos as usize {
                cur = self.prev[cur_abs & PREV_MASK];
                chain_left -= 1;
                continue;
            }
            let dist = abs_pos as usize - cur_abs;
            if dist > max_dist {
                break;
            }
            let cur_rel = rel - dist;

            if best_len >= MIN_MATCH && best_len < max_len {
                let cand_pair: [u8; 2] =
                    [window[cur_rel + best_len - 1], window[cur_rel + best_len]];
                if cand_pair != tail_pair {
                    cur = self.prev[cur_abs & PREV_MASK];
                    chain_left -= 1;
                    continue;
                }
            }

            let mut len = 0usize;
            while len + 8 <= max_len {
                let a: [u8; 8] = window[cur_rel + len..cur_rel + len + 8].try_into().unwrap();
                let b: [u8; 8] = window[rel + len..rel + len + 8].try_into().unwrap();
                let av = u64::from_ne_bytes(a);
                let bv = u64::from_ne_bytes(b);
                let diff = av ^ bv;
                if diff == 0 {
                    len += 8;
                } else {
                    #[cfg(target_endian = "little")]
                    let add = (diff.trailing_zeros() / 8) as usize;
                    #[cfg(target_endian = "big")]
                    let add = (diff.leading_zeros() / 8) as usize;
                    len += add;
                    break;
                }
            }
            while len < max_len && window[cur_rel + len] == window[rel + len] {
                len += 1;
            }

            if len >= MIN_MATCH && len > best_len {
                best_len = len;
                best_dist = dist;
                if best_len >= nice_match {
                    break;
                }
                if best_len < max_len {
                    tail_pair = [window[rel + best_len - 1], window[rel + best_len]];
                }
            }

            cur = self.prev[cur_abs & PREV_MASK];
            chain_left -= 1;
        }

        if best_len >= MIN_MATCH {
            Some((best_len as u32, best_dist as u32))
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
