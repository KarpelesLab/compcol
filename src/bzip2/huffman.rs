#![allow(dead_code)] // max_len() exposed for diagnostics / future use

//! Canonical Huffman codes for bzip2, MSB-first.
//!
//! bzip2 caps code lengths at 20 bits and uses canonical encoding (the
//! 5-bit "first length" plus a delta-coded sequence of length changes
//! is just a compact way to ship per-symbol code-length tables).
//!
//! ## Decoding
//!
//! Given a length-per-symbol table, we build canonical codes the
//! standard way:
//! 1. Sort symbols by (length, symbol_index).
//! 2. Assign codes starting at 0, incrementing within a length, and
//!    left-shifting by 1 when length increases.
//!
//! For decode-side throughput we precompute per-length tables of
//! (base_code, base_index) and a sorted permutation of symbols so we
//! can use the classical "extend code one bit at a time" decode loop.
//!
//! ## Encoding (length design + emit)
//!
//! For the encoder we just need a length-limited prefix code over the
//! observed symbol frequencies of one Huffman group; bzip2's reference
//! design uses an iterative "moffat" package-merge fallback, but for
//! correctness alone a textbook Huffman tree with depth clamping to
//! the 20-bit ceiling is sufficient. We implement Huffman by repeated
//! merging of the two smallest-weight nodes; if any code length
//! exceeds the ceiling, we scale weights up and retry, which is the
//! simple fixpoint mentioned in *Managing Gigabytes* (Witten, Moffat,
//! Bell) §2.4 and in the bzip2 source's `sendMTFValues` epilogue.

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;

/// Maximum code length bzip2 will accept on the wire.
pub(crate) const MAX_CODE_LEN: usize = 20;

/// A decoded Huffman table: canonical-code metadata plus a symbol
/// permutation, sufficient to decode one bit at a time.
pub(crate) struct DecodeTable {
    /// Number of symbols (0..N inclusive of the EOB).
    n: usize,
    /// Smallest code value at each length (`MAX_CODE_LEN + 1` entries;
    /// position 0 is unused).
    base: [i32; MAX_CODE_LEN + 2],
    /// Largest code value at each length, sentinel-extended to detect
    /// "consume more bits". Position 0 is unused; we sentinel index
    /// MAX_CODE_LEN+1 with -1.
    limit: [i32; MAX_CODE_LEN + 2],
    /// `perm[i]` = symbol at the i-th position of the
    /// length-then-symbol sorted code list.
    perm: Vec<u16>,
    /// Min and max non-zero lengths.
    min_len: u8,
    max_len: u8,
}

impl DecodeTable {
    /// Build a decode table from a per-symbol code-length array.
    ///
    /// Returns `Err(Error::InvalidHuffmanTree)` if the lengths don't
    /// describe a valid prefix code (Kraft–McMillan check).
    pub(crate) fn from_lengths(lengths: &[u8]) -> Result<Self, Error> {
        let n = lengths.len();
        if n == 0 {
            return Err(Error::InvalidHuffmanTree);
        }

        let mut min_len: u8 = 0xFF;
        let mut max_len: u8 = 0;
        for &l in lengths {
            if l == 0 || l as usize > MAX_CODE_LEN {
                return Err(Error::InvalidHuffmanTree);
            }
            if l < min_len {
                min_len = l;
            }
            if l > max_len {
                max_len = l;
            }
        }
        if max_len == 0 {
            return Err(Error::InvalidHuffmanTree);
        }

        // Count symbols at each length.
        let mut count = [0i32; MAX_CODE_LEN + 2];
        for &l in lengths {
            count[l as usize] += 1;
        }

        // Kraft–McMillan validity check. A canonical prefix code is valid
        // iff, accumulating `left = (left << 1) + count[len]` from len 1
        // upward, `left` never exceeds the code space `1 << len` (no
        // over-subscription) and exactly fills it at the end
        // (`left == 1 << max_len`, no under-subscription). This matches the
        // discipline in `src/huffman.rs` and rejects malformed tables here
        // rather than deferring detection to the block CRC.
        let mut left: i64 = 0;
        for (i, &c) in count[1..=(max_len as usize)].iter().enumerate() {
            let len = i + 1;
            left = (left << 1) + c as i64;
            if left > (1i64 << len) {
                return Err(Error::InvalidHuffmanTree);
            }
        }
        if left != (1i64 << max_len) {
            return Err(Error::InvalidHuffmanTree);
        }

        // Build base/limit tables in the bzip2 / RFC1951 canonical style.
        // base[len]  = first symbol index at length `len` (in the sorted
        //              symbol order)
        // limit[len] = largest code value at length `len` (inclusive)
        let mut base = [0i32; MAX_CODE_LEN + 2];
        let mut limit = [0i32; MAX_CODE_LEN + 2];

        let mut vec_pos: i32 = 0;
        for len in 1..=MAX_CODE_LEN {
            // Start of this length's slice in the sorted-by-length symbol
            // ordering.
            base[len] = vec_pos;
            vec_pos += count[len];
        }

        let mut code: i32 = 0;
        for len in 1..=MAX_CODE_LEN {
            let cnt = count[len];
            // `code` is the first canonical code value at this length.
            // `limit[len]` is the inclusive upper bound: code + cnt - 1.
            // If `cnt == 0` we set limit[len] = -1 so the read loop
            // never matches.
            //
            // For symbol lookup we want pos = code - (code_start - perm_start)
            //                              = code - code_start + perm_start
            // Storing `base[len] = code_start - perm_start` makes
            // `pos = read_code - base[len]` give the perm index. Note
            // this is a *positive* shift of code-toward-start unless
            // perm_start > code_start (always true once we get past
            // the first non-empty length, since perm_start grows by
            // cnt and code_start grows by 2*cnt — until base goes
            // negative).
            if cnt == 0 {
                limit[len] = -1;
            } else {
                limit[len] = code + cnt - 1;
                // Reinterpret base[len] (currently perm_start) as
                // (code_start - perm_start). Note: this can go
                // negative when code_start > perm_start, which is
                // normal as codes grow faster than perm indices.
                base[len] = code - base[len];
            }
            code = (code + cnt) << 1;
        }
        // Final sentinel limit so the decode loop can probe at
        // (max_len + 1) safely.
        limit[MAX_CODE_LEN + 1] = -1;

        // Build the permutation: symbols sorted by (length, symbol_index).
        // We need a per-length cursor to drop each symbol into the right
        // bucket.
        let mut cursor = [0usize; MAX_CODE_LEN + 2];
        let mut acc = 0usize;
        for len in 1..=MAX_CODE_LEN {
            cursor[len] = acc;
            acc += count[len] as usize;
        }
        let mut perm = vec![0u16; n];
        for (sym, &l) in lengths.iter().enumerate() {
            let len = l as usize;
            perm[cursor[len]] = sym as u16;
            cursor[len] += 1;
        }

        Ok(Self {
            n,
            base,
            limit,
            perm,
            min_len,
            max_len,
        })
    }

    /// Decode one symbol from a bit reader.
    pub(crate) fn decode_symbol(&self, br: &mut super::bits::BitReader<'_>) -> Result<u16, Error> {
        // Start by reading `min_len` bits straight up.
        let mut len = self.min_len as usize;
        let mut code = br.read_bits(len as u32)? as i32;
        while len <= MAX_CODE_LEN {
            if code <= self.limit[len] {
                let pos = (code - self.base[len]) as usize;
                if pos >= self.n {
                    return Err(Error::InvalidHuffmanTree);
                }
                return Ok(self.perm[pos]);
            }
            len += 1;
            code = (code << 1) | (br.read_bit()? as i32);
        }
        Err(Error::InvalidHuffmanTree)
    }

    pub(crate) fn max_len(&self) -> u8 {
        self.max_len
    }
}

// ─── encoder side: canonical lengths + canonical codes ──────────────────

/// Compute per-symbol Huffman code lengths from frequency counts.
///
/// `freqs[i] > 0` is treated as "symbol i is used"; symbols with
/// `freqs[i] == 0` are assigned the smallest possible nonzero length
/// (so the table still covers them even if they don't appear). The
/// returned lengths are clamped to `max_len` by iteratively scaling
/// down the weights when the natural Huffman depth exceeds the cap.
///
/// This is a textbook two-pass Huffman: build a tree by repeatedly
/// merging the two minimum-weight items; if the resulting longest path
/// exceeds the cap, halve all weights and try again. Halving converges
/// because the alphabet is at most 258 symbols (256 bytes + RUNA/RUNB +
/// EOB) so the natural Huffman depth is bounded by O(log φ(n)) ≈ 14 at
/// reasonable distributions; the cap of 20 bits is loose, so we rarely
/// need more than one or two retries even on degenerate inputs.
pub(crate) fn build_canonical_lengths(freqs: &[u32], max_len: usize) -> Vec<u8> {
    let n = freqs.len();
    let mut weights: Vec<u32> = freqs.iter().map(|&f| if f == 0 { 1 } else { f }).collect();

    loop {
        let lengths = compute_lengths(&weights);
        let mx = lengths.iter().copied().max().unwrap_or(0) as usize;
        if mx <= max_len {
            // Symbols that weren't actually used still get a non-zero
            // length (we initialised their weights to 1); the table
            // serialiser may treat them however it wants. bzip2 just
            // emits the canonical code anyway.
            return lengths;
        }
        // Scale weights down by halving (rounding up to keep all
        // values > 0) and retry.
        for w in weights.iter_mut() {
            *w = (*w).div_ceil(2).max(1);
        }
        // After scaling everything to 1 the natural Huffman depth is
        // ⌈log₂ n⌉ which for n ≤ 258 is at most 9 — well under 20 —
        // so the loop always terminates within a few iterations.
        if n <= 1 {
            // Degenerate alphabet; just return the singletons at len 1.
            return vec![1u8; n.max(1)];
        }
    }
}

/// Compute Huffman lengths from a weight vector using the textbook
/// two-pass tree-build.
///
/// We represent the partial tree as an array of length 2N parents:
/// internal nodes occupy indices ≥ N, leaves occupy 0..N. Each merge
/// step links two minimum-weight active nodes under a fresh internal
/// node; once the tree is built we walk parent links to compute each
/// leaf's depth.
fn compute_lengths(weights: &[u32]) -> Vec<u8> {
    let n = weights.len();
    if n == 0 {
        return Vec::new();
    }
    if n == 1 {
        return vec![1];
    }

    // Heap of (weight, node_id). Implemented as a sorted vector since
    // n ≤ 258; the constant factor on the binary-heap path is not
    // worth the complexity for this size.
    let mut alive: Vec<(u64, usize)> = weights
        .iter()
        .enumerate()
        .map(|(i, &w)| (w as u64, i))
        .collect();
    let mut parent: Vec<usize> = vec![usize::MAX; 2 * n];
    let mut next_node = n;

    while alive.len() > 1 {
        // Sort descending so we pop the two smallest off the back.
        alive.sort_by_key(|b| core::cmp::Reverse(b.0));
        let (w1, n1) = alive.pop().unwrap();
        let (w2, n2) = alive.pop().unwrap();
        parent[n1] = next_node;
        parent[n2] = next_node;
        alive.push((w1 + w2, next_node));
        next_node += 1;
    }

    // Walk parent links from each leaf to the root counting depth.
    let mut lengths = vec![0u8; n];
    for leaf in 0..n {
        let mut depth = 0u32;
        let mut node = parent[leaf];
        while node != usize::MAX {
            depth += 1;
            node = parent[node];
        }
        // depth 0 only happens when n == 1 (root = leaf); that case
        // was returned above.
        lengths[leaf] = depth.max(1) as u8;
    }
    lengths
}

/// Build the canonical (code, length) table from a per-symbol length
/// array. Returns `(codes, lengths)` where `codes[i]` is the MSB-first
/// canonical code for symbol `i`, and `lengths[i]` is the bit length.
pub(crate) fn build_canonical_codes(lengths: &[u8]) -> Vec<u32> {
    let n = lengths.len();
    let max_len = lengths.iter().copied().max().unwrap_or(0) as usize;

    // Count symbols per length.
    let mut bl_count = vec![0u32; max_len + 2];
    for &l in lengths {
        bl_count[l as usize] += 1;
    }
    bl_count[0] = 0;

    // First code at each length.
    let mut next_code = vec![0u32; max_len + 2];
    let mut code = 0u32;
    for bits in 1..=max_len {
        code = (code + bl_count[bits - 1]) << 1;
        next_code[bits] = code;
    }

    let mut codes = vec![0u32; n];
    for (sym, &l) in lengths.iter().enumerate() {
        if l > 0 {
            codes[sym] = next_code[l as usize];
            next_code[l as usize] += 1;
        }
    }
    codes
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn round_trip_decode_table_simple() {
        // Trivial uniform code: 4 symbols at length 2 each.
        let lengths = [2u8, 2, 2, 2];
        let tbl = DecodeTable::from_lengths(&lengths).unwrap();
        let codes = build_canonical_codes(&lengths);
        // Symbol 0 → code 00, symbol 1 → 01, symbol 2 → 10, symbol 3 → 11.
        assert_eq!(codes, vec![0b00, 0b01, 0b10, 0b11]);
        assert_eq!(tbl.max_len(), 2);
    }

    #[test]
    fn round_trip_encode_decode() {
        // Encode a symbol stream and round-trip through the bit packer.
        // Lengths satisfy Kraft: 4 × 1/8 + 4 × 1/4 = 0.5 + 1 oops wrong;
        // 2 × 1/4 + 6 × 1/8 = 0.5 + 0.75 = 1.25 fails.
        // Use 2 × 1/4 + 4 × 1/8 = 0.5 + 0.5 = 1: lengths [3,3,3,3,2,2].
        let lengths = [3u8, 3, 3, 3, 2, 2];
        let codes = build_canonical_codes(&lengths);

        let mut bw = super::super::bits::BitWriter::new();
        let stream = [0u16, 5, 3, 1, 4];
        for &s in &stream {
            bw.write_bits(lengths[s as usize] as u32, codes[s as usize]);
        }
        bw.align_to_byte();
        let buf = bw.into_bytes();

        let tbl = DecodeTable::from_lengths(&lengths).unwrap();
        let mut br = super::super::bits::BitReader::new(&buf);
        for &expect in &stream {
            let got = tbl.decode_symbol(&mut br).unwrap();
            assert_eq!(got, expect);
        }
    }

    #[test]
    fn build_lengths_does_not_explode() {
        let freqs = [50u32, 30, 20, 10, 5, 3, 2, 1];
        let lens = build_canonical_lengths(&freqs, MAX_CODE_LEN);
        assert!(lens.iter().all(|&l| (1..=20).contains(&l)));
        assert_eq!(lens.len(), freqs.len());
    }
}
