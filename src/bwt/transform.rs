//! The BWT forward and inverse transforms for a single block.
//!
//! Kept separate from the streaming/framing wrapper in `mod.rs` so the core
//! permutation logic can be unit-tested in isolation.

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;

/// Forward BWT of a single non-empty block.
///
/// Returns `(last_column, primary_index)` where `last_column.len() ==
/// block.len()` and `primary_index < block.len()`.
///
/// # Panics
///
/// Never panics for `block.len() >= 1`. Callers must not pass an empty block
/// (the encoder never produces zero-length blocks); an empty block would yield
/// an empty column and a meaningless primary index.
pub(super) fn forward(block: &[u8]) -> (Vec<u8>, usize) {
    let n = block.len();
    debug_assert!(n >= 1);

    // `sa[r]` = starting offset of the cyclic rotation ranked `r`.
    let sa = sort_rotations(block);

    // Last column: the byte just before the rotation's start, cyclically.
    // L[r] = block[(sa[r] + n - 1) mod n].
    let mut last_col = vec![0u8; n];
    let mut primary = 0usize;
    for (r, &start) in sa.iter().enumerate() {
        let start = start as usize;
        // (start + n - 1) % n, computed without underflow.
        let prev = if start == 0 { n - 1 } else { start - 1 };
        last_col[r] = block[prev];
        if start == 0 {
            primary = r;
        }
    }
    (last_col, primary)
}

/// Sort the `n` cyclic rotations of `block` and return their starting offsets
/// in sorted order (`sa[r]` = offset of the rotation ranked `r`).
///
/// Uses prefix doubling (Manber–Myers): start with rank = byte value, then
/// repeatedly refine ranks by the pair `(rank[i], rank[(i + k) mod n])` for
/// doubling `k`, until every rotation has a distinct rank (or `k >= n`). Each
/// round is an `O(n)` counting sort over the rank pairs, and there are
/// `O(log n)` rounds, so the whole thing is `O(n log n)`.
fn sort_rotations(block: &[u8]) -> Vec<u32> {
    let n = block.len();
    debug_assert!(n >= 1);

    // Order array: the rotation offsets, to be permuted into sorted order.
    let mut order: Vec<u32> = (0..n as u32).collect();

    if n == 1 {
        return order;
    }

    // `rank[i]` = current rank of the rotation starting at offset `i`.
    //
    // Initialise from the byte at each offset, but *densely*: map each
    // distinct byte value to its 0-based order among the values that actually
    // occur. This keeps every rank in `0..n` from the very first round, which
    // is what the counting sort's bucket sizing (`n_keys = n`) relies on —
    // raw byte values would reach 255 and overflow the buckets on small
    // blocks.
    let mut present = [false; 256];
    for &b in block {
        present[b as usize] = true;
    }
    let mut byte_rank = [0u32; 256];
    let mut next_rank = 0u32;
    for (v, &seen) in present.iter().enumerate() {
        if seen {
            byte_rank[v] = next_rank;
            next_rank += 1;
        }
    }
    let mut rank: Vec<u32> = block.iter().map(|&b| byte_rank[b as usize]).collect();
    // Scratch buffers reused across rounds.
    let mut new_rank: Vec<u32> = vec![0; n];
    let mut tmp_order: Vec<u32> = vec![0; n];

    let mut k = 1usize;
    loop {
        // Sort `order` by the key (rank[i], rank[(i + k) mod n]) using a
        // stable two-pass counting sort (LSD radix on the two rank fields).
        // Pass 1: by the second key, rank[(i + k) mod n].
        counting_sort_by(&order, &mut tmp_order, n, |i| {
            rank[(i as usize + k) % n] as usize
        });
        // Pass 2: by the first key, rank[i]. Stable, so ties keep the
        // second-key order established above.
        counting_sort_by(&tmp_order, &mut order, n, |i| rank[i as usize] as usize);

        // Recompute ranks from the freshly sorted order. Two adjacent
        // rotations share a rank iff both key components are equal.
        new_rank[order[0] as usize] = 0;
        let mut r = 0u32;
        for w in 1..n {
            let prev = order[w - 1] as usize;
            let cur = order[w] as usize;
            let prev_key = (rank[prev], rank[(prev + k) % n]);
            let cur_key = (rank[cur], rank[(cur + k) % n]);
            if cur_key != prev_key {
                r += 1;
            }
            new_rank[cur] = r;
        }
        rank.copy_from_slice(&new_rank);

        // All rotations distinct → fully sorted.
        if r as usize == n - 1 {
            break;
        }
        // Doubling. Once k >= n the second key spans the whole rotation, so
        // one more round (already done above) suffices; guard anyway.
        k <<= 1;
        if k >= n {
            break;
        }
    }
    order
}

/// Stable counting sort of `src` (a permutation of rotation offsets) into
/// `dst`, keyed by `key(offset)` which must return a value in `0..n_keys`.
///
/// `n_keys` is an upper bound on the key range; we use `n` (the block length)
/// since every rank lies in `0..n`.
fn counting_sort_by<F>(src: &[u32], dst: &mut [u32], n_keys: usize, key: F)
where
    F: Fn(u32) -> usize,
{
    let mut counts = vec![0usize; n_keys + 1];
    for &i in src {
        counts[key(i)] += 1;
    }
    // Prefix sums → starting offset for each key bucket.
    let mut acc = 0usize;
    for c in counts.iter_mut() {
        let cur = *c;
        *c = acc;
        acc += cur;
    }
    // Scatter, preserving input order within a bucket (stability).
    for &i in src {
        let slot = key(i);
        dst[counts[slot]] = i;
        counts[slot] += 1;
    }
}

/// Inverse BWT: reconstruct the original block from its last column and
/// primary index, appending the result to `out`.
///
/// `last_col.len()` is the block length `n`; `primary < n` is guaranteed by
/// the caller (the framing layer validates it). Uses the standard LF-mapping
/// walk.
pub(super) fn inverse(last_col: &[u8], primary: usize, out: &mut Vec<u8>) -> Result<(), Error> {
    let n = last_col.len();
    // Defensive: the framing layer already checks these, but the transform
    // must be safe in isolation and never panic on bad arguments.
    if n == 0 || primary >= n {
        return Err(Error::Corrupt);
    }

    // Count occurrences of each byte value in the last column.
    let mut counts = [0usize; 256];
    for &b in last_col {
        counts[b as usize] += 1;
    }
    // `start[c]` = index in the (sorted) first column where value `c` begins.
    let mut start = [0usize; 256];
    let mut acc = 0usize;
    for c in 0..256 {
        start[c] = acc;
        acc += counts[c];
    }

    // `next[i]` links row `i` of the last column to the row whose first-column
    // entry is the same physical symbol. Walking `next` from the primary index
    // yields the original bytes in order.
    let mut next = vec![0u32; n];
    let mut cursor = start; // mutable copy of bucket starts
    for (i, &b) in last_col.iter().enumerate() {
        let c = b as usize;
        next[cursor[c]] = i as u32;
        cursor[c] += 1;
    }

    // Walk: start at the primary row, follow `next` n times, emitting the
    // last-column byte at each visited row.
    out.reserve(n);
    let mut p = next[primary] as usize;
    for _ in 0..n {
        out.push(last_col[p]);
        p = next[p] as usize;
    }
    Ok(())
}

#[cfg(test)]
mod transform_tests {
    use super::*;
    use alloc::vec::Vec;

    /// Reference O(n² log n) rotation sort, used to cross-check the fast
    /// prefix-doubling sort. Builds every rotation explicitly and sorts.
    fn reference_forward(block: &[u8]) -> (Vec<u8>, usize) {
        let n = block.len();
        let mut idx: Vec<usize> = (0..n).collect();
        idx.sort_by(|&a, &b| {
            for off in 0..n {
                let ca = block[(a + off) % n];
                let cb = block[(b + off) % n];
                if ca != cb {
                    return ca.cmp(&cb);
                }
            }
            core::cmp::Ordering::Equal
        });
        let mut last = Vec::with_capacity(n);
        let mut primary = 0;
        for (r, &start) in idx.iter().enumerate() {
            let prev = if start == 0 { n - 1 } else { start - 1 };
            last.push(block[prev]);
            if start == 0 {
                primary = r;
            }
        }
        (last, primary)
    }

    fn roundtrip(block: &[u8]) {
        let (l, p) = forward(block);
        assert_eq!(l.len(), block.len());
        let mut out = Vec::new();
        inverse(&l, p, &mut out).unwrap();
        assert_eq!(out, block, "roundtrip mismatch for {block:?}");
    }

    #[test]
    fn forward_matches_reference() {
        let cases: &[&[u8]] = &[
            b"banana",
            b"mississippi",
            b"abracadabra",
            b"aaaaaa",
            b"a",
            b"ab",
            b"ba",
            b"the quick brown fox jumps over the lazy dog",
            &[0, 0, 0, 1, 0, 0],
            &[255, 0, 255, 0, 255],
        ];
        for &c in cases {
            let fast = forward(c);
            let reference = reference_forward(c);
            assert_eq!(fast, reference, "forward mismatch for {c:?}");
            roundtrip(c);
        }
    }

    #[test]
    fn single_byte() {
        let (l, p) = forward(b"Z");
        assert_eq!(l, b"Z");
        assert_eq!(p, 0);
        roundtrip(b"Z");
    }

    #[test]
    fn all_same_byte() {
        let block = [7u8; 64];
        let (l, p) = forward(&block);
        // Every rotation is identical, so the last column is all 7s and the
        // primary index is well-defined (the stable sort keeps offset 0 first
        // among equal rotations, so primary == 0).
        assert_eq!(l, block);
        assert_eq!(p, 0);
        roundtrip(&block);
    }

    #[test]
    fn inverse_rejects_bad_primary() {
        let mut out = Vec::new();
        assert_eq!(inverse(b"abc", 3, &mut out), Err(Error::Corrupt));
        assert_eq!(inverse(b"", 0, &mut out), Err(Error::Corrupt));
    }

    #[test]
    fn banana_known_last_column() {
        // Classic worked example. Rotations of "banana" sorted:
        //   abanan, anaban, ananab, banana, nabana, nanaba
        // last column = "nnbaaa", primary index of "banana" is row 3.
        let (l, p) = forward(b"banana");
        assert_eq!(l, b"nnbaaa");
        assert_eq!(p, 3);
    }
}
