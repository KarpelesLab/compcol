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

/// Stop searching once we hit this match length.
const NICE_MATCH: usize = 128;

/// Maximum chain depth.
const MAX_CHAIN: usize = 64;

/// Hash four bytes into a 15-bit bucket.
fn hash4(b0: u8, b1: u8, b2: u8, b3: u8) -> u32 {
    let v = (b0 as u32) | ((b1 as u32) << 8) | ((b2 as u32) << 16) | ((b3 as u32) << 24);
    // Knuth multiplicative hash, then take top HASH_BITS.
    v.wrapping_mul(0x9E37_79B1) >> (32 - HASH_BITS)
}

/// Per-block buffer size — at most this many positions are tracked at
/// once. The encoder feeds a fresh `MatchFinder` per meta-block.
pub(crate) const BUFFER_SIZE: usize = 65_536;

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

    /// Splice position `pos` into the hash chain for the 4 bytes at
    /// `buffer[pos..pos+4]`.
    pub(crate) fn insert(&mut self, buffer: &[u8], pos: usize) {
        if pos + 4 > buffer.len() || pos >= BUFFER_SIZE {
            return;
        }
        let h = hash4(
            buffer[pos],
            buffer[pos + 1],
            buffer[pos + 2],
            buffer[pos + 3],
        );
        let idx = (h as usize) & (HASH_SIZE - 1);
        self.prev[pos] = self.head[idx];
        self.head[idx] = pos as u32;
    }

    /// Find the longest prior occurrence of the bytes starting at `pos`.
    /// Returns Some((length, distance)) with length ≥ MIN_MATCH, or None.
    pub(crate) fn find_match(&self, buffer: &[u8], pos: usize) -> Option<(usize, usize)> {
        if pos + MIN_MATCH > buffer.len() {
            return None;
        }
        let h = hash4(
            buffer[pos],
            buffer[pos + 1],
            buffer[pos + 2],
            buffer[pos + 3],
        );
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
            if cur_pos >= pos {
                cur = self.prev[cur_pos];
                steps += 1;
                continue;
            }
            let dist = pos - cur_pos;
            if dist > max_dist {
                break;
            }
            if best_len > 0
                && best_len < max_len
                && buffer[cur_pos + best_len] != buffer[pos + best_len]
            {
                cur = self.prev[cur_pos];
                steps += 1;
                continue;
            }
            let mut len = 0usize;
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
