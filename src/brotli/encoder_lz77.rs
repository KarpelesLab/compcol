//! Hash-chain LZ77 match finder used by the brotli encoder.
//!
//! Same shape as the deflate encoder's match finder
//! (`crate::deflate::lz77`) but parameterised for brotli: minimum match
//! length 4 (deflate uses 3 to stay competitive at small windows;
//! brotli's minimum copy code is `2`, but back-references below 4 bytes
//! rarely beat encoding them as literals so we set our floor at 4),
//! and the maximum match length is capped by the largest representable
//! copy length 2118 + 2^24 — well above anything we'd find in a 16 KiB
//! search window.
//!
//! The window size is fixed at 64 KiB (WBITS=16, max-back-distance =
//! 65520) to match the encoder's choice of stream header.
//!
//! The match-finder's `MAX_CHAIN` (chain depth) and `NICE_MATCH` (early
//! exit threshold) are not compile-time constants — they're supplied by
//! the caller as a `FinderParams` and ultimately driven by the encoder's
//! quality knob.

use alloc::boxed::Box;

/// Minimum match length we'll consider — anything shorter is cheaper
/// as literals.
pub(crate) const MIN_MATCH: usize = 4;

/// Maximum match length we'll search for. Capped well below the
/// largest representable copy length (`COPY_BASE[23] + 2^24 ≈ 16M`)
/// to keep the inner loop fast on long matches; in practice 4096 is
/// plenty for our window size.
pub(crate) const MAX_MATCH: usize = 4096;

/// Maximum back-distance the encoder will consider (matches WBITS=16
/// less the 16-byte safety margin from §9.1).
pub(crate) const WINDOW_SIZE: usize = 65_520;

const HASH_BITS: u32 = 15;
const HASH_SIZE: usize = 1 << HASH_BITS;
const NIL: u32 = u32::MAX;

/// Per-block buffer size — at most this many positions are tracked at
/// once. The encoder feeds a fresh `MatchFinder` per meta-block.
pub(crate) const BUFFER_SIZE: usize = 65_536;

/// Tuning knobs for the hash-chain probe. Lower numbers go faster and
/// produce larger output; higher numbers walk deeper and find longer
/// matches at higher cost.
#[derive(Debug, Clone, Copy)]
pub(crate) struct FinderParams {
    /// Maximum number of hash-chain links the finder walks per probe.
    pub max_chain: usize,
    /// Length at which the finder stops looking for a longer candidate.
    pub nice_match: usize,
    /// When `true`, the encoder selects matches by [`find_match_cost`]
    /// (maximise bit gain — prefer closer/cheaper distances) instead of
    /// [`find_match`] (longest match). Distance coding dominates our
    /// output, so cost-aware selection meaningfully cuts distance extra
    /// bits at higher qualities.
    pub cost_match: bool,
}

pub(crate) struct MatchFinder {
    head: Box<[u32; HASH_SIZE]>,
    prev: Box<[u32; BUFFER_SIZE]>,
}

impl MatchFinder {
    pub(crate) fn new() -> Self {
        Self {
            head: Box::new([NIL; HASH_SIZE]),
            prev: Box::new([NIL; BUFFER_SIZE]),
        }
    }

    /// Reset the hash chains in place — cheaper than re-allocating a
    /// fresh `MatchFinder` between meta-blocks. (Only `head` needs to
    /// be cleared; `prev[pos]` is written before it is read.)
    pub(crate) fn reset(&mut self) {
        // Zeroing 32K * 4 = 128 KiB through `fill` lowers to a tight
        // memset; cheaper than re-allocating the boxes.
        self.head.fill(NIL);
    }

    /// Splice position `pos` into the hash chain for the 4 bytes at
    /// `buffer[pos..pos+4]`.
    #[inline]
    pub(crate) fn insert(&mut self, buffer: &[u8], pos: usize) {
        if pos + 4 > buffer.len() || pos >= BUFFER_SIZE {
            return;
        }
        let h = hash4_at(buffer, pos);
        let idx = (h as usize) & (HASH_SIZE - 1);
        self.prev[pos] = self.head[idx];
        self.head[idx] = pos as u32;
    }

    /// Find the longest prior occurrence of the bytes starting at `pos`.
    /// Returns Some((length, distance)) with length ≥ MIN_MATCH, or None.
    pub(crate) fn find_match(
        &self,
        buffer: &[u8],
        pos: usize,
        params: FinderParams,
    ) -> Option<(usize, usize)> {
        let buf_len = buffer.len();
        if pos + MIN_MATCH > buf_len {
            return None;
        }
        let h = hash4_at(buffer, pos);
        let idx = (h as usize) & (HASH_SIZE - 1);

        let max_dist = WINDOW_SIZE.min(pos);
        let max_len = MAX_MATCH.min(buf_len - pos);
        if max_len < MIN_MATCH {
            return None;
        }
        // Cap nice_match so the inner compare loop bails at the slice
        // end without needing a per-iteration bounds check on the tail.
        let nice = params.nice_match.min(max_len);
        let chain_cap = params.max_chain;
        // Slice view starting at `pos` — lets LLVM hoist a single
        // bounds check covering the whole comparison loop.
        let target = &buffer[pos..pos + max_len];

        let mut best_len: usize = 0;
        let mut best_dist: usize = 0;

        // Track the byte at `target[best_len]` separately so the
        // "tail byte mismatch" fast path is a single byte compare with
        // no slice indexing.
        let mut best_tail: u8 = 0;

        let prev = &self.prev[..];
        let head = &self.head[..];
        let mut cur = head[idx];
        let mut steps = 0usize;
        while cur != NIL && steps < chain_cap {
            let cur_pos = cur as usize;
            if cur_pos >= pos {
                // Stale chain entry (overran us); just keep walking.
                cur = prev[cur_pos];
                steps += 1;
                continue;
            }
            let dist = pos - cur_pos;
            if dist > max_dist {
                break;
            }

            // Fast reject: if we already have a match of length `best_len`,
            // the new candidate must match at least `target[best_len]` to
            // be a longer match.
            if best_len > 0 && buffer[cur_pos + best_len] != best_tail {
                cur = prev[cur_pos];
                steps += 1;
                continue;
            }

            // Compare candidate (`buffer[cur_pos..]`) against `target`.
            // `target` has length `max_len`, and the worst-case read is
            // `cur_pos + max_len - 1` < `pos + max_len` ≤ `buf_len`
            // so the candidate slice is also in-bounds.
            let cand = &buffer[cur_pos..cur_pos + max_len];
            let mut len = 0usize;
            // Unrolled 4-byte compare: hot text strides 4 bytes per
            // iteration on average. Each `<8>` LLVM lowers to a single
            // 64-bit load + xor + tzcnt on x86-64; well beyond a
            // bytewise compare's reach.
            while len + 8 <= max_len {
                // Read 8 bytes from each side; xor; first mismatch byte
                // is `tz/8`. We rely on slice access here so LLVM can
                // emit unaligned loads without an unsafe cast.
                let a = u64::from_le_bytes([
                    cand[len],
                    cand[len + 1],
                    cand[len + 2],
                    cand[len + 3],
                    cand[len + 4],
                    cand[len + 5],
                    cand[len + 6],
                    cand[len + 7],
                ]);
                let b = u64::from_le_bytes([
                    target[len],
                    target[len + 1],
                    target[len + 2],
                    target[len + 3],
                    target[len + 4],
                    target[len + 5],
                    target[len + 6],
                    target[len + 7],
                ]);
                let diff = a ^ b;
                if diff != 0 {
                    len += (diff.trailing_zeros() / 8) as usize;
                    break;
                }
                len += 8;
            }
            // Tail (< 8 bytes remaining).
            while len < max_len && cand[len] == target[len] {
                len += 1;
            }

            if len >= MIN_MATCH && len > best_len {
                best_len = len;
                best_dist = dist;
                if best_len >= nice {
                    break;
                }
                // Refresh the tail byte for the next iteration's fast
                // reject. `best_len < max_len` here because nice ≤ max_len
                // and we would have broken otherwise.
                if best_len < max_len {
                    best_tail = target[best_len];
                }
            }
            cur = prev[cur_pos];
            steps += 1;
        }

        if best_len >= MIN_MATCH {
            Some((best_len, best_dist))
        } else {
            None
        }
    }

    /// Cost-aware variant of [`find_match`]. Instead of returning the
    /// strictly longest match, it returns the match that maximises an
    /// approximate bit *gain*:
    ///
    /// ```text
    /// gain(len, dist) = len * VALUE_PER_BYTE - distance_cost(dist)
    /// ```
    ///
    /// where `distance_cost ≈ floor(log2(dist))` charges far distances for
    /// their extra bits. This makes the finder prefer a slightly shorter
    /// but much closer match when the closer distance is cheaper to code —
    /// the dominant cost in our output is distance extra bits, so trading a
    /// byte of length for a far smaller distance is frequently a net win.
    ///
    /// `VALUE_PER_BYTE` is tuned so a one-byte length sacrifice is accepted
    /// only when it saves at least that many distance bits.
    pub(crate) fn find_match_cost(
        &self,
        buffer: &[u8],
        pos: usize,
        params: FinderParams,
    ) -> Option<(usize, usize)> {
        const VALUE_PER_BYTE: i64 = 3;
        let buf_len = buffer.len();
        if pos + MIN_MATCH > buf_len {
            return None;
        }
        let h = hash4_at(buffer, pos);
        let idx = (h as usize) & (HASH_SIZE - 1);

        let max_dist = WINDOW_SIZE.min(pos);
        let max_len = MAX_MATCH.min(buf_len - pos);
        if max_len < MIN_MATCH {
            return None;
        }
        let nice = params.nice_match.min(max_len);
        let chain_cap = params.max_chain;
        let target = &buffer[pos..pos + max_len];

        let mut best_len: usize = 0;
        let mut best_dist: usize = 0;
        let mut best_gain: i64 = i64::MIN;

        let prev = &self.prev[..];
        let head = &self.head[..];
        let mut cur = head[idx];
        let mut steps = 0usize;
        while cur != NIL && steps < chain_cap {
            let cur_pos = cur as usize;
            if cur_pos >= pos {
                cur = prev[cur_pos];
                steps += 1;
                continue;
            }
            let dist = pos - cur_pos;
            if dist > max_dist {
                break;
            }
            // Cheap reject: this candidate can only beat the incumbent if
            // it matches at least one byte past the current best length
            // (a shorter match would need an implausibly tiny distance to
            // win on gain; the explicit gain check below is the arbiter,
            // but extending the compare to `best_len` first is wasted work
            // when even a full-length match here would lose).
            let cand = &buffer[cur_pos..cur_pos + max_len];
            let mut len = 0usize;
            while len + 8 <= max_len {
                let a = u64::from_le_bytes([
                    cand[len],
                    cand[len + 1],
                    cand[len + 2],
                    cand[len + 3],
                    cand[len + 4],
                    cand[len + 5],
                    cand[len + 6],
                    cand[len + 7],
                ]);
                let b = u64::from_le_bytes([
                    target[len],
                    target[len + 1],
                    target[len + 2],
                    target[len + 3],
                    target[len + 4],
                    target[len + 5],
                    target[len + 6],
                    target[len + 7],
                ]);
                let diff = a ^ b;
                if diff != 0 {
                    len += (diff.trailing_zeros() / 8) as usize;
                    break;
                }
                len += 8;
            }
            while len < max_len && cand[len] == target[len] {
                len += 1;
            }

            if len >= MIN_MATCH {
                let dist_cost = 32 - (dist as u32).leading_zeros(); // ≈ log2(dist)+1
                let gain = len as i64 * VALUE_PER_BYTE - dist_cost as i64;
                if gain > best_gain {
                    best_gain = gain;
                    best_len = len;
                    best_dist = dist;
                    // Stop once we have a long-enough match at this (closest
                    // so far) distance; deeper chain entries are strictly
                    // farther, so they can only win with extra length, which
                    // is rare past `nice`.
                    if len >= nice {
                        break;
                    }
                }
            }
            cur = prev[cur_pos];
            steps += 1;
        }

        if best_len >= MIN_MATCH {
            Some((best_len, best_dist))
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

/// Compute the match length at a *specific* back-distance `dist` starting
/// at `pos`. Returns the number of bytes that match (capped at
/// [`MAX_MATCH`] and the slice tail), or 0 when `dist` is out of range.
///
/// Used by the encoder's repeat-distance preference: a match reachable at
/// a recently-used distance costs only a 2–6 bit short code instead of a
/// full distance symbol plus up to 24 extra bits, so even a somewhat
/// shorter repeat-distance match can win on total bits.
pub(crate) fn match_len_at(buffer: &[u8], pos: usize, dist: usize) -> usize {
    if dist == 0 || dist > pos {
        return 0;
    }
    let buf_len = buffer.len();
    let max_len = MAX_MATCH.min(buf_len - pos);
    if max_len == 0 {
        return 0;
    }
    let src = pos - dist;
    let cand = &buffer[src..src + max_len];
    let target = &buffer[pos..pos + max_len];
    let mut len = 0usize;
    while len + 8 <= max_len {
        let a = u64::from_le_bytes([
            cand[len],
            cand[len + 1],
            cand[len + 2],
            cand[len + 3],
            cand[len + 4],
            cand[len + 5],
            cand[len + 6],
            cand[len + 7],
        ]);
        let b = u64::from_le_bytes([
            target[len],
            target[len + 1],
            target[len + 2],
            target[len + 3],
            target[len + 4],
            target[len + 5],
            target[len + 6],
            target[len + 7],
        ]);
        let diff = a ^ b;
        if diff != 0 {
            len += (diff.trailing_zeros() / 8) as usize;
            return len;
        }
        len += 8;
    }
    while len < max_len && cand[len] == target[len] {
        len += 1;
    }
    len
}

/// Hash four bytes into a 15-bit bucket.
#[inline]
fn hash4_at(buffer: &[u8], pos: usize) -> u32 {
    debug_assert!(pos + 4 <= buffer.len());
    // Read 4 bytes via slice access so LLVM can emit a single
    // unaligned 32-bit load; per-byte hash dispatch is dead.
    let b = &buffer[pos..pos + 4];
    let v = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    // Knuth multiplicative hash, then take top HASH_BITS.
    v.wrapping_mul(0x9E37_79B1) >> (32 - HASH_BITS)
}
