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
pub const NIL: u32 = u32::MAX;

/// Size of the `prev` ring buffer. Must be a power of two ≥ WINDOW_SIZE so
/// any in-window absolute position maps uniquely.
pub const PREV_SIZE: usize = WINDOW_SIZE;
const PREV_MASK: usize = PREV_SIZE - 1;

/// Smallest and largest hash-table sizes (in bits) the finder accepts.
const MIN_HASH_BITS: u32 = 8;
const MAX_HASH_BITS: u32 = HASH_BITS;

/// Length of the common prefix of `a` and `b`. Compares eight bytes at a
/// time (one unaligned load per side, XOR, count trailing zeros).
#[inline(always)]
pub fn common_prefix(a: &[u8], b: &[u8]) -> usize {
    let n = a.len().min(b.len());
    let (a, b) = (&a[..n], &b[..n]);
    let mut len = 0usize;
    for (ca, cb) in a.as_chunks::<8>().0.iter().zip(b.as_chunks::<8>().0) {
        let x = u64::from_le_bytes(*ca);
        let y = u64::from_le_bytes(*cb);
        let diff = x ^ y;
        if diff != 0 {
            return len + (diff.trailing_zeros() / 8) as usize;
        }
        len += 8;
    }
    while len < n && a[len] == b[len] {
        len += 1;
    }
    len
}

pub struct MatchFinder {
    /// `head[hash]` is the absolute position of the most recent occurrence
    /// of the 3-byte sequence with this hash, or NIL.
    /// Only the first `hash_mask + 1` entries are used.
    head: Box<[u32; HASH_SIZE]>,
    /// `prev[pos & PREV_MASK]` is the absolute position of the previous
    /// occurrence of the same hash before `pos`, or NIL.
    prev: Box<[u32; PREV_SIZE]>,
    /// Hard cap on the match distance the finder will emit, in bytes
    /// (effective range `1..=WINDOW_SIZE`). The full deflate window is
    /// `WINDOW_SIZE`; a smaller value lets the encoder produce a stream a
    /// decoder running a smaller sliding window can still inflate — e.g.
    /// qemu/qcow2 inflates compressed clusters with a 4 KiB window
    /// (`inflateInit2(-12)`), which rejects any back-reference farther than
    /// 4096 bytes.
    max_distance: usize,
    /// `32 - hash_bits`: the multiplicative hash keeps the top bits.
    hash_shift: u32,
}

impl MatchFinder {
    /// Match finder using the full `WINDOW_SIZE` (32 KiB) distance window.
    pub fn new() -> Self {
        Self::with_max_distance(WINDOW_SIZE)
    }

    /// Match finder that never emits a back-reference farther than
    /// `max_distance` bytes. The value is clamped to `1..=WINDOW_SIZE`
    /// (0 is treated as 1; values above the window are capped to it).
    pub fn with_max_distance(max_distance: usize) -> Self {
        Self::with_hash_bits(max_distance, HASH_BITS)
    }

    /// Like [`MatchFinder::with_max_distance`], with a hash table of
    /// `1 << hash_bits` heads (`hash_bits` clamped to `8..=15`). The table
    /// is always allocated at full size; smaller ones just use a prefix.
    pub(crate) fn with_hash_bits(max_distance: usize, hash_bits: u32) -> Self {
        let hash_bits = hash_bits.clamp(MIN_HASH_BITS, MAX_HASH_BITS);
        Self {
            head: Box::new([NIL; HASH_SIZE]),
            prev: Box::new([NIL; PREV_SIZE]),
            max_distance: max_distance.clamp(1, WINDOW_SIZE),
            hash_shift: 32 - hash_bits,
        }
    }

    /// Forget every position recorded so far.
    pub fn reset(&mut self) {
        let used = 1usize << (32 - self.hash_shift);
        self.head[..used].fill(NIL);
        self.prev.fill(NIL);
    }

    /// Hash of the three bytes at `window[rel..]`; the caller guarantees
    /// `rel + 3 <= window.len()`.
    #[inline(always)]
    fn hash(&self, window: &[u8], rel: usize) -> usize {
        let v = match window.get(rel..rel + 4) {
            Some(s) => u32::from_le_bytes(s.try_into().unwrap()),
            None => {
                u32::from(window[rel])
                    | (u32::from(window[rel + 1]) << 8)
                    | (u32::from(window[rel + 2]) << 16)
            }
        };
        self.hash24(v)
    }

    /// Multiplicative hash of the low 24 bits of `v` (the next three bytes,
    /// little-endian), spread over the top `hash_bits` bits. Always
    /// `< HASH_SIZE`.
    #[inline(always)]
    fn hash24(&self, v: u32) -> usize {
        ((v << 8).wrapping_mul(0x9E37_79B1) >> self.hash_shift) as usize & (HASH_SIZE - 1)
    }

    /// Splice the 3-byte sequence at `window[rel..]` (absolute position
    /// `abs_pos`) into its hash chain and return the previous chain head
    /// (the most recent earlier position with the same hash, or [`NIL`]).
    /// The caller guarantees `rel + 3 <= window.len()`.
    #[inline(always)]
    pub fn insert(&mut self, window: &[u8], rel: usize, abs_pos: u32) -> u32 {
        let idx = self.hash(window, rel);
        self.link(idx, abs_pos)
    }

    #[inline(always)]
    fn link(&mut self, idx: usize, abs_pos: u32) -> u32 {
        let old = self.head[idx];
        self.prev[(abs_pos as usize) & PREV_MASK] = old;
        self.head[idx] = abs_pos;
        old
    }

    /// Insert every position in `window[from..to]` that has three bytes
    /// available. `abs_base` is the absolute position of `window[0]`.
    #[inline]
    pub fn insert_range(&mut self, window: &[u8], from: usize, to: usize, abs_base: u64) {
        let to = to.min(window.len().saturating_sub(2));
        if from >= to {
            return;
        }
        let mut abs = (abs_base + from as u64) as u32;
        // Positions with four bytes available: one load each.
        let fast_end = to.min(window.len() - 3);
        if from < fast_end {
            for w in window[from..fast_end + 3].windows(4) {
                let v = u32::from_le_bytes(w.try_into().unwrap());
                let idx = self.hash24(v);
                self.link(idx, abs);
                abs = abs.wrapping_add(1);
            }
        }
        for k in fast_end.max(from)..to {
            self.insert(window, k, abs);
            abs = abs.wrapping_add(1);
        }
    }

    /// Find the longest match for `window[rel..]` (absolute position
    /// `abs_pos`) that is longer than `best_len`, walking the hash chain
    /// from `cand` (the head returned by [`insert`](Self::insert) for this
    /// position).
    ///
    /// `max_chain` caps how many chain links are walked; the search stops as
    /// soon as a match of `nice_match` bytes is found. Returns
    /// `(length, distance)`; `length` is `0` when nothing longer than
    /// `best_len` (and at least `MIN_MATCH`) was found.
    #[inline]
    #[allow(clippy::too_many_arguments)]
    pub fn longest_match(
        &self,
        window: &[u8],
        rel: usize,
        abs_pos: u32,
        mut cand: u32,
        best_len: usize,
        max_chain: usize,
        nice_match: usize,
    ) -> (usize, usize) {
        let max_len = MAX_MATCH.min(window.len() - rel);
        let mut best_len = best_len.max(MIN_MATCH - 1);
        if best_len >= max_len {
            return (0, 0);
        }
        let nice = nice_match.min(max_len);
        let max_dist = self.max_distance.min(abs_pos as usize) as u32;
        let cur = &window[rel..rel + max_len];
        let mut best_dist = 0usize;
        let mut chain_left = max_chain;
        // Quick reject: a candidate can only beat the current best if the
        // four bytes ending at offset `best_len` match too (just the first
        // three while nothing has been found and `best_len` is 2; the
        // window then needs a fourth byte, which only the last three bytes
        // of the input lack — no reject there).
        let (mut scan_off, mut scan_mask) = scan_window(best_len);
        if max_len < 4 {
            scan_mask = 0;
        }
        let mut scan_end = load4(window, rel + scan_off) & scan_mask;

        loop {
            // NIL and stale (not-yet-behind-us) entries give a distance of 0
            // or one beyond `max_dist`, ending the walk like a too-far one.
            let dist = abs_pos.wrapping_sub(cand);
            if dist.wrapping_sub(1) >= max_dist {
                break;
            }
            let next = self.prev[cand as usize & PREV_MASK];
            // `dist <= rel` because the window keeps the full history the
            // finder can reach.
            let cpos = rel - dist as usize;
            if load4(window, cpos + scan_off) & scan_mask == scan_end {
                let len = common_prefix(&window[cpos..cpos + max_len], cur);
                if len > best_len {
                    best_len = len;
                    best_dist = dist as usize;
                    if len >= nice {
                        break;
                    }
                    (scan_off, scan_mask) = scan_window(best_len);
                    scan_end = load4(window, rel + scan_off) & scan_mask;
                }
            }
            chain_left -= 1;
            if chain_left == 0 {
                break;
            }
            cand = next;
        }

        if best_dist != 0 {
            (best_len, best_dist)
        } else {
            (0, 0)
        }
    }
}

/// Offset and mask of the quick-reject window for a current best of
/// `best_len` bytes (`2 <= best_len < max_len`): the four bytes ending at
/// offset `best_len`, or the first three while `best_len` is 2.
#[inline(always)]
fn scan_window(best_len: usize) -> (usize, u32) {
    if best_len >= 3 {
        (best_len - 3, u32::MAX)
    } else {
        (0, 0x00FF_FFFF)
    }
}

/// Little-endian `u32` at `s[i..i + 4]`, or 0 past the end (callers mask
/// such reads away).
#[inline(always)]
fn load4(s: &[u8], i: usize) -> u32 {
    match s.get(i..i + 4) {
        Some(b) => u32::from_le_bytes(b.try_into().unwrap()),
        None => 0,
    }
}

impl Default for MatchFinder {
    fn default() -> Self {
        Self::new()
    }
}
