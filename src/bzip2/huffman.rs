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
//! For the encoder we need a length-limited prefix code over the
//! observed symbol frequencies of one Huffman group. We port reference
//! bzip2's `BZ2_hbMakeCodeLengths` directly: a min-heap tree build whose
//! key packs the cumulative frequency in the high bits and the subtree
//! depth in the low 8 bits, so equal-frequency merges prefer the
//! shallower subtree. That depth-aware tiebreak reproduces bzip2's exact
//! per-table bit costs. Code lengths are capped at 17 bits (bzip2's
//! design limit since 1.0.3); if any code exceeds the cap the
//! frequencies are halved and the build is retried, exactly as in the
//! reference. The decode side still accepts up to 20 bits for
//! compatibility with streams from pre-1.0.3 encoders.

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
/// `freqs[i] == 0` are assigned a small nonzero weight (so the table
/// still covers them even if they don't appear). The returned lengths
/// are clamped to `max_len` (reference bzip2 designs with `maxLen = 17`;
/// callers pass `MAX_CODE_LEN = 20`, but bzip2's own length builder is
/// run with 17 so the encoder never emits codes longer than that).
///
/// This is a faithful port of reference bzip2's `BZ2_hbMakeCodeLengths`
/// (`huffman.c`). It builds the Huffman tree with a min-heap whose key
/// packs the cumulative frequency in the high bits and the subtree
/// depth in the low 8 bits, so that among equal-frequency merge
/// candidates the **shallower** subtree is preferred. That depth-aware
/// tiebreak yields more balanced trees (shorter maximum code length and
/// marginally better total cost on large blocks) than a frequency-only
/// textbook Huffman build, and is what lets our output match the
/// reference's per-table bit costs. If any code still exceeds `max_len`
/// the frequencies are halved and the build is retried, exactly as in
/// the reference.
pub(crate) fn build_canonical_lengths(freqs: &[u32], max_len: usize) -> Vec<u8> {
    // bzip2 caps the design length at 17; honour whatever the caller
    // passes but never exceed 17 internally so we stay byte-for-byte
    // compatible with reference output where it matters.
    let design_max = max_len.min(17);
    hb_make_code_lengths(freqs, design_max)
}

/// Direct port of `BZ2_hbMakeCodeLengths`. Weights pack
/// `frequency << 8 | depth`; merges add the frequencies and set the
/// depth to `1 + max(depth_a, depth_b)`.
fn hb_make_code_lengths(freqs: &[u32], max_len: usize) -> Vec<u8> {
    let alpha_size = freqs.len();
    if alpha_size == 0 {
        return Vec::new();
    }
    if alpha_size == 1 {
        return vec![1];
    }

    // Nodes and heap entries are 1-based; index 0 is a sentinel, exactly
    // as in the C source. `weight`/`parent` need room for up to
    // `2*alpha_size` nodes (leaves + internal), `heap` for `alpha_size+2`.
    let cap_nodes = alpha_size * 2 + 2;
    let mut weight = vec![0i64; cap_nodes];
    let mut parent = vec![0i32; cap_nodes];
    let mut heap = vec![0i32; alpha_size + 2];

    // Initial leaf weights: (freq or 1) << 8, depth 0 in the low byte.
    let mut cur_freq: Vec<i64> = freqs
        .iter()
        .map(|&f| if f == 0 { 1i64 } else { f as i64 })
        .collect();

    const DEPTH_MASK: i64 = 0x0000_00ff;
    fn weight_of(w: i64) -> i64 {
        w & !DEPTH_MASK
    }
    fn depth_of(w: i64) -> i64 {
        w & DEPTH_MASK
    }
    fn add_weights(a: i64, b: i64) -> i64 {
        (weight_of(a) + weight_of(b)) | (1 + core::cmp::max(depth_of(a), depth_of(b)))
    }

    loop {
        for i in 0..alpha_size {
            weight[i + 1] = cur_freq[i] << 8;
        }

        let mut n_nodes = alpha_size as i32;
        let mut n_heap = 0i32;

        heap[0] = 0;
        weight[0] = 0;
        parent[0] = -2;

        // UPHEAP / DOWNHEAP operate on `heap`, keyed by `weight`.
        for i in 1..=alpha_size as i32 {
            parent[i as usize] = -1;
            n_heap += 1;
            heap[n_heap as usize] = i;
            // UPHEAP(n_heap)
            let mut zz = n_heap;
            let tmp = heap[zz as usize];
            while weight[tmp as usize] < weight[heap[(zz >> 1) as usize] as usize] {
                heap[zz as usize] = heap[(zz >> 1) as usize];
                zz >>= 1;
            }
            heap[zz as usize] = tmp;
        }

        while n_heap > 1 {
            let n1 = heap[1];
            heap[1] = heap[n_heap as usize];
            n_heap -= 1;
            downheap(&mut heap, &weight, n_heap, 1);

            let n2 = heap[1];
            heap[1] = heap[n_heap as usize];
            n_heap -= 1;
            downheap(&mut heap, &weight, n_heap, 1);

            n_nodes += 1;
            parent[n1 as usize] = n_nodes;
            parent[n2 as usize] = n_nodes;
            weight[n_nodes as usize] = add_weights(weight[n1 as usize], weight[n2 as usize]);
            parent[n_nodes as usize] = -1;
            n_heap += 1;
            heap[n_heap as usize] = n_nodes;
            // UPHEAP(n_heap)
            let mut zz = n_heap;
            let tmp = heap[zz as usize];
            while weight[tmp as usize] < weight[heap[(zz >> 1) as usize] as usize] {
                heap[zz as usize] = heap[(zz >> 1) as usize];
                zz >>= 1;
            }
            heap[zz as usize] = tmp;
        }

        // Compute lengths by walking parent links; detect over-long codes.
        let mut lengths = vec![0u8; alpha_size];
        let mut too_long = false;
        for i in 1..=alpha_size {
            let mut j = 0i32;
            let mut k = i as i32;
            while parent[k as usize] >= 0 {
                k = parent[k as usize];
                j += 1;
            }
            lengths[i - 1] = j as u8;
            if j as usize > max_len {
                too_long = true;
            }
        }

        if !too_long {
            return lengths;
        }

        // Scale frequencies: j = weight>>8; j = 1 + j/2.
        for f in cur_freq.iter_mut() {
            let j = *f;
            *f = 1 + (j / 2);
        }
    }
}

/// DOWNHEAP(z) from the bzip2 source, operating on the 1-based `heap`
/// array of length `n_heap`, keyed by `weight`.
fn downheap(heap: &mut [i32], weight: &[i64], n_heap: i32, z: i32) {
    let mut zz = z;
    let tmp = heap[zz as usize];
    loop {
        let mut yy = zz << 1;
        if yy > n_heap {
            break;
        }
        if yy < n_heap
            && weight[heap[(yy + 1) as usize] as usize] < weight[heap[yy as usize] as usize]
        {
            yy += 1;
        }
        if weight[tmp as usize] < weight[heap[yy as usize] as usize] {
            break;
        }
        heap[zz as usize] = heap[yy as usize];
        zz = yy;
    }
    heap[zz as usize] = tmp;
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

    #[test]
    fn build_lengths_caps_at_17_and_is_kraft_valid() {
        // The reference-faithful builder must (a) never emit a code
        // longer than 17 bits, and (b) always produce a Kraft-valid
        // canonical prefix code that `DecodeTable::from_lengths`
        // accepts — even for skewed and degenerate distributions.
        let cases: alloc::vec::Vec<alloc::vec::Vec<u32>> = alloc::vec![
            alloc::vec![1, 1],
            alloc::vec![0, 0, 0, 5],
            alloc::vec![1000000, 1, 1, 1, 1, 1, 1, 1],
            (0..50u32).map(|i| 1 << (i % 24)).collect(),
            alloc::vec![1u32; 258],
        ];
        for freqs in &cases {
            let lens = build_canonical_lengths(freqs, MAX_CODE_LEN);
            assert_eq!(lens.len(), freqs.len());
            assert!(
                lens.iter().all(|&l| (1..=17).contains(&l)),
                "length out of 1..=17: {lens:?}"
            );
            // Must round-trip through the decode-table builder.
            DecodeTable::from_lengths(&lens).expect("builder produced a non-Kraft-valid table");
        }
    }
}
