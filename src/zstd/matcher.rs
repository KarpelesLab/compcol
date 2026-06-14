//! Hash-chain LZ77 match finder for the Zstandard encoder.
//!
//! Per-block: at each input position we hash the next 4 bytes, splice the
//! position into the per-hash chain, and (optionally) walk the chain to find
//! the longest prior match within a back-reference window. The chain walk is
//! bounded by a runtime `max_chain` value (derived from the encoder's
//! compression level) to cap the per-byte work.
//!
//! The design is a stripped-down variant of the deflate match finder at
//! `src/deflate/lz77.rs`. Differences:
//!
//! - 4-byte hash (zstd's minimum match length is 3 but most matches that
//!   matter are ≥ 4 bytes; using a 4-byte hash reduces chain collisions).
//! - Back-reference window grows up to the buffer size; zstd's minimum window
//!   per the spec is 1 KiB but for our encoder we just use the full block.
//! - `Match { length, distance }` returned by value, with `MIN_MATCH = 3`
//!   (zstd's minimum) and a generous `MAX_MATCH` cap.

use alloc::boxed::Box;

/// Minimum match length the matcher will report (RFC 8478 §3.1.1.3.2 implies
/// a hard minimum of 3 via the match-length base table).
pub const MIN_MATCH: usize = 3;
/// Maximum match length we cap each match at. Zstd's match-length FSE base
/// table tops out at code 52 (base 65539 + 15 extra bits), so any match of
/// length ≥ 65539 can still be represented as a single sequence — we cap at
/// 65535 because that's the largest match where the ML code fits in 16 bits
/// of base+extra in our encoder and decoder. Allowing matches this long
/// matters for highly repetitive inputs (e.g. Lorem with phrase-level
/// periodicity at distance ~445 bytes): each long match amortises the
/// per-sequence FSE-table cost across thousands more output bytes.
pub const MAX_MATCH: usize = 65535;
/// Hash table size (must be a power of two).
const HASH_BITS: u32 = 15;
const HASH_SIZE: usize = 1 << HASH_BITS;
/// "Empty" marker in the hash table.
const NIL: u32 = u32::MAX;

/// A found LZ77 match.
#[derive(Clone, Copy, Debug)]
pub struct Match {
    pub length: usize,
    /// Back-reference distance (bytes from `pos` to the match start).
    pub distance: usize,
}

/// Per-block matcher state.
pub struct MatchFinder {
    head: Box<[u32; HASH_SIZE]>,
    /// Linked-list chain `prev[pos]` = position of the previous occurrence of
    /// the same 4-byte prefix.
    prev: Vec<u32>,
}

use alloc::vec;
use alloc::vec::Vec;

/// Hash function over four bytes. A multiplicative hash with a prime
/// multiplier gives reasonable distribution and is cheap to compute.
fn hash4(b: &[u8]) -> u32 {
    let v = (b[0] as u32) | ((b[1] as u32) << 8) | ((b[2] as u32) << 16) | ((b[3] as u32) << 24);
    // 0x9E3779B1 = golden-ratio multiplier; high bits are the well-distributed ones.
    v.wrapping_mul(0x9E37_79B1) >> (32 - HASH_BITS)
}

impl MatchFinder {
    pub fn new(buffer_len: usize) -> Self {
        Self {
            head: Box::new([NIL; HASH_SIZE]),
            prev: vec![NIL; buffer_len.max(1)],
        }
    }

    /// Forget every position recorded so far. The buffer length stays the
    /// same. Not currently called — [`MatchFinder::resize_for`] is used on
    /// each new block — but kept for completeness / future tuning.
    #[allow(dead_code)]
    pub fn reset(&mut self) {
        for h in self.head.iter_mut() {
            *h = NIL;
        }
        for p in self.prev.iter_mut() {
            *p = NIL;
        }
    }

    /// Resize the per-position chain array. Required when the encoder reuses
    /// the matcher with a different block size.
    pub fn resize_for(&mut self, buffer_len: usize) {
        self.prev.clear();
        self.prev.resize(buffer_len.max(1), NIL);
        for h in self.head.iter_mut() {
            *h = NIL;
        }
    }

    /// Record `buffer[pos..pos+4]`.
    pub fn insert(&mut self, buffer: &[u8], pos: usize) {
        if pos + 4 > buffer.len() {
            return;
        }
        let h = hash4(&buffer[pos..pos + 4]) as usize;
        // Safety: head is fixed size HASH_SIZE, h < HASH_SIZE.
        self.prev[pos] = self.head[h];
        self.head[h] = pos as u32;
    }

    /// Find the longest match for `buffer[pos..]` against any earlier
    /// occurrence within the window.
    ///
    /// `max_chain` caps the number of hash-chain links walked per probe;
    /// `nice_match` short-circuits the search once a match of that length is
    /// found. Both knobs come from [`super::encoder::EncoderConfig`].
    pub fn find_match(
        &self,
        buffer: &[u8],
        pos: usize,
        window: usize,
        max_chain: usize,
        nice_match: usize,
    ) -> Option<Match> {
        if pos + MIN_MATCH > buffer.len() {
            return None;
        }
        if pos + 4 > buffer.len() {
            // Can't compute the 4-byte hash; just fail (rare; near end of buf).
            return None;
        }
        let h = hash4(&buffer[pos..pos + 4]) as usize;
        let max_dist = window.min(pos);
        let max_len = MAX_MATCH.min(buffer.len() - pos);
        if max_len < MIN_MATCH {
            return None;
        }

        let mut best_len: usize = 0;
        let mut best_dist: usize = 0;
        let mut cur = self.head[h];
        let mut steps = 0usize;

        while cur != NIL && steps < max_chain {
            let cur_pos = cur as usize;
            if cur_pos >= pos {
                cur = self.prev[cur_pos];
                steps += 1;
                continue;
            }
            let dist = pos - cur_pos;
            if dist > max_dist {
                break;
            }

            // Cheap rejection at best_len boundary.
            if best_len > 0
                && best_len < max_len
                && buffer[cur_pos + best_len] != buffer[pos + best_len]
            {
                cur = self.prev[cur_pos];
                steps += 1;
                continue;
            }

            let len = match_extend(buffer, cur_pos, pos, max_len);
            if len >= MIN_MATCH && len > best_len {
                best_len = len;
                best_dist = dist;
                if best_len >= nice_match {
                    break;
                }
            }
            cur = self.prev[cur_pos];
            steps += 1;
        }

        if best_len >= MIN_MATCH {
            Some(Match {
                length: best_len,
                distance: best_dist,
            })
        } else {
            None
        }
    }

    /// Probe a specific repeat-offset distance at `pos`: extend the match as
    /// far as it goes (capped by [`MAX_MATCH`]). Returns the match length, or
    /// 0 if it doesn't reach [`MIN_MATCH`].
    ///
    /// Used to look for "free" repeat-offset matches before the hash-chain
    /// walk. Repeat offsets cost 1 bit of FSE output (codes 1..=3) versus the
    /// `floor(log2(distance + 3))` bits a fresh offset spends, so even short
    /// repeat-offset matches frequently beat the alternatives.
    pub fn check_repeat_offset(&self, buffer: &[u8], pos: usize, distance: usize) -> usize {
        if distance == 0 || distance > pos {
            return 0;
        }
        let max_len = MAX_MATCH.min(buffer.len() - pos);
        if max_len < MIN_MATCH {
            return 0;
        }
        let src = pos - distance;
        let len = match_extend(buffer, src, pos, max_len);
        if len >= MIN_MATCH { len } else { 0 }
    }

    /// Collect distinct-length match candidates for `buffer[pos..]` for the
    /// optimal parser. Walks the hash chain (bounded by `max_chain`) and, for
    /// each length value reachable, records the *smallest distance* that
    /// achieves it — a shorter distance is always at least as cheap to encode.
    ///
    /// Returns `(length, distance)` pairs with strictly increasing length, so
    /// the price DP can try every length tier from `MIN_MATCH` up to the
    /// longest match and weigh each against its offset cost. Stops early once a
    /// match reaches `nice_match`.
    pub fn collect_matches(
        &self,
        buffer: &[u8],
        pos: usize,
        window: usize,
        max_chain: usize,
        nice_match: usize,
        out: &mut Vec<Match>,
    ) {
        out.clear();
        if pos + MIN_MATCH > buffer.len() || pos + 4 > buffer.len() {
            return;
        }
        let h = hash4(&buffer[pos..pos + 4]) as usize;
        let max_dist = window.min(pos);
        let max_len = MAX_MATCH.min(buffer.len() - pos);
        if max_len < MIN_MATCH {
            return;
        }

        let mut best_len: usize = MIN_MATCH - 1;
        let mut cur = self.head[h];
        let mut steps = 0usize;

        while cur != NIL && steps < max_chain {
            let cur_pos = cur as usize;
            if cur_pos >= pos {
                cur = self.prev[cur_pos];
                steps += 1;
                continue;
            }
            let dist = pos - cur_pos;
            if dist > max_dist {
                break;
            }
            // Cheap rejection: can't beat the longest length we already have.
            if best_len >= max_len {
                break;
            }
            if buffer[cur_pos + best_len] == buffer[pos + best_len] {
                let len = match_extend(buffer, cur_pos, pos, max_len);
                if len > best_len {
                    // New longest tier. Because we walk the chain from the most
                    // recent position downward, the first candidate to reach a
                    // given length is at the smallest distance — exactly what
                    // we want for cheap offsets.
                    out.push(Match {
                        length: len,
                        distance: dist,
                    });
                    best_len = len;
                    if len >= nice_match {
                        break;
                    }
                }
            }
            cur = self.prev[cur_pos];
            steps += 1;
        }
    }
}

/// Extend a match forward up to `max_len` bytes, comparing `buffer[a..]`
/// against `buffer[b..]`. Loads u64 chunks and uses XOR + trailing_zeros
/// to locate the first differing byte, falling back to a byte loop for
/// the tail. Mirrors the deflate lz77 implementation.
fn match_extend(buffer: &[u8], a: usize, b: usize, max_len: usize) -> usize {
    let mut len = 0usize;
    while len + 8 <= max_len {
        let av: [u8; 8] = buffer[a + len..a + len + 8].try_into().unwrap();
        let bv: [u8; 8] = buffer[b + len..b + len + 8].try_into().unwrap();
        let av = u64::from_ne_bytes(av);
        let bv = u64::from_ne_bytes(bv);
        let diff = av ^ bv;
        if diff == 0 {
            len += 8;
        } else {
            #[cfg(target_endian = "little")]
            let add = (diff.trailing_zeros() / 8) as usize;
            #[cfg(target_endian = "big")]
            let add = (diff.leading_zeros() / 8) as usize;
            len += add;
            return len;
        }
    }
    while len < max_len && buffer[a + len] == buffer[b + len] {
        len += 1;
    }
    len
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_simple_match() {
        let data = b"abcdefg__abcdefg__"; // matches at offset 9 starting "abcdefg"
        let mut mf = MatchFinder::new(data.len());
        for pos in 0..(data.len().saturating_sub(3)) {
            mf.insert(data, pos);
            if pos == 9 {
                // First position where a match should be findable.
                let m = mf.find_match(data, 9, data.len(), 16, 64).unwrap();
                assert!(m.length >= 7);
                assert_eq!(m.distance, 9);
            }
        }
    }

    #[test]
    fn rejects_short_match() {
        // "abXdefXX..." vs later "abY" — only 2-byte common prefix, below MIN_MATCH.
        let data = b"abcXabd";
        let mut mf = MatchFinder::new(data.len());
        mf.insert(data, 0);
        mf.insert(data, 1);
        mf.insert(data, 2);
        mf.insert(data, 3);
        let m = mf.find_match(data, 4, data.len(), 16, 64);
        // The 2-byte match "ab" is below MIN_MATCH; should be None.
        assert!(m.is_none());
    }
}
