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
#[inline(always)]
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
    #[inline]
    pub fn find_match(
        &self,
        window: &[u8],
        rel: usize,
        abs_pos: u32,
        have_good: bool,
        max_chain: usize,
        nice_match: usize,
    ) -> Option<(u16, u16)> {
        // Hot loop. The structure mirrors zlib's `longest_match`. Key
        // micro-optimisations (all branch- and load-count reductions; no
        // unsafe used):
        //
        //   • The chain walk's `cur >= abs_pos` filter is removed by
        //     observing that when we splice the current position into the
        //     hash chain *before* calling `find_match`, the head of the
        //     chain we follow is by construction strictly less than
        //     `abs_pos` — but the encoder does insert at `pos` first, so
        //     we use `self.head[idx]` (which is the just-inserted self)'s
        //     prev to start. Keeping the explicit filter for safety since
        //     callers can also call without inserting first.
        //   • The "tail byte fast reject" compares `window[cur_rel+best_len]`
        //     vs `window[rel+best_len]` (one byte) before extending — and
        //     we also reject when `best_len > 0` and the byte at
        //     `best_len-1` doesn't match by comparing a u16 pair.
        //   • The extension loop reads 4 bytes at a time via slice-to-array
        //     (LLVM lowers the array load to one unaligned 32-bit load) and
        //     uses XOR + trailing-zero count to find the first differing
        //     byte. This skips the per-byte loop body's branch entirely.

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

        // Snapshot the two bytes at `rel + best_len - 1 .. rel + best_len + 1`
        // for the fast tail reject. We refresh these whenever `best_len`
        // changes. Initially `best_len == 0` so the tail reject doesn't apply.
        // We use `[u8; 2]` so the comparison is a single u16 load.
        let mut tail_pair: [u8; 2] = [0, 0];

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

            // Fast tail reject. If we have a current best of length `best_len`,
            // the candidate can only improve it if both the byte at
            // `best_len-1` (which equalled the rel byte for the previous best)
            // and at `best_len` (which is the new byte we need to match)
            // line up. The pair compare is one u16 load on each side.
            if best_len >= MIN_MATCH && best_len < max_len {
                // Need bytes at cur_rel + best_len - 1 and cur_rel + best_len.
                // Both are in bounds because:
                //   • cur_rel + best_len - 1 < cur_rel + max_len ≤ window.len()
                //   • cur_rel + best_len < cur_rel + max_len ≤ window.len()
                // and the prior cheap-reject below ensures cur_rel + best_len < window.len()
                // because we previously matched up to best_len bytes from this
                // run's best candidate. We still require cur_rel + best_len + 1 ≤ window.len().
                let cand_pair: [u8; 2] =
                    [window[cur_rel + best_len - 1], window[cur_rel + best_len]];
                if cand_pair != tail_pair {
                    cur = self.prev[cur_abs & PREV_MASK];
                    chain_left -= 1;
                    continue;
                }
            }

            // Extend the match from the start, eight bytes at a time first
            // (u64 load + XOR + trailing_zeros) for the bulk, then byte-wise
            // for the tail.
            //
            // Loop invariant: `len` is the number of bytes confirmed to
            // match starting at `cur_rel`/`rel`.
            let mut len = 0usize;

            // 8-byte chunks: read [u8; 8] from both sides as native-endian u64
            // — LLVM lowers slice-to-array (`<[u8; N]>::try_from`) plus
            // `u64::from_ne_bytes` to a single unaligned 64-bit load, and the
            // first-differing-byte search becomes a `xor` + `trailing_zeros`.
            while len + 8 <= max_len {
                // SAFETY (no unsafe): the slice indexing is bounds-checked
                // and LLVM removes the check when it sees the prior
                // `len + 8 <= max_len` guard. Each side resolves to one
                // unaligned 8-byte load.
                let a: [u8; 8] = window[cur_rel + len..cur_rel + len + 8].try_into().unwrap();
                let b: [u8; 8] = window[rel + len..rel + len + 8].try_into().unwrap();
                let av = u64::from_ne_bytes(a);
                let bv = u64::from_ne_bytes(b);
                let diff = av ^ bv;
                if diff == 0 {
                    len += 8;
                } else {
                    // First differing byte is at trailing_zeros() / 8 (LE)
                    // or leading_zeros() / 8 (BE).
                    #[cfg(target_endian = "little")]
                    let add = (diff.trailing_zeros() / 8) as usize;
                    #[cfg(target_endian = "big")]
                    let add = (diff.leading_zeros() / 8) as usize;
                    len += add;
                    break;
                }
            }
            // Tail: any remaining bytes (0..=7) compared byte by byte.
            while len < max_len && window[cur_rel + len] == window[rel + len] {
                len += 1;
            }

            if len >= MIN_MATCH && len > best_len {
                best_len = len;
                best_dist = dist;
                if best_len >= nice_match {
                    break;
                }
                // Refresh the tail pair for the new best_len. We only refresh
                // when best_len ≥ MIN_MATCH (which is true here) and we need
                // both rel + best_len - 1 and rel + best_len to be valid
                // indices into `window`. The first is fine (best_len ≥ 3).
                // The second is needed only when best_len < max_len, which
                // is checked at the next loop's reject guard.
                if best_len < max_len {
                    tail_pair = [window[rel + best_len - 1], window[rel + best_len]];
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
