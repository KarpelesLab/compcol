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
/// Sorting cyclic rotations is reduced to an ordinary suffix sort over the
/// **doubled** block `T + T` followed by a sentinel strictly smaller than any
/// byte. Suffix `i` of `T + T + $` for `0 <= i < n` begins with the i-th
/// cyclic rotation of `T` (its first `n` characters are exactly that
/// rotation), so the suffix-sort order restricted to those `n` positions is a
/// valid cyclic-rotation order. The suffix array itself is built with **SA-IS**
/// (Suffix Array by Induced Sorting; Nong, Zhang & Chan, IEEE TC 2009), a
/// linear-time `O(n)` algorithm — several times faster than the previous
/// `O(n log n)` prefix-doubling sort.
///
/// For periodic `T` two rotations can be equal; any consistent tie-break
/// yields a valid BWT (the emitted `L` bytes are identical for tied rotations
/// anyway), and the inverse transform recovers the original regardless.
fn sort_rotations(block: &[u8]) -> Vec<u32> {
    let n = block.len();
    debug_assert!(n >= 1);

    if n == 1 {
        return vec![0u32];
    }

    // Doubled text `T + T + sentinel`. Bytes map to 1..=256, sentinel to 0,
    // giving an unsigned alphabet of size 257. `n` is bounded by the BWT
    // block size (<= 64 MiB), so `2 * n + 1` stays well within `i32`.
    let mut text: Vec<i32> = Vec::with_capacity(2 * n + 1);
    for &b in block {
        text.push(b as i32 + 1);
    }
    for &b in block {
        text.push(b as i32 + 1);
    }
    text.push(0); // sentinel

    let sa = sa_is(&text, 257);

    // Keep only suffixes that start in the first half (`< n`): those are the
    // `n` cyclic rotations of `T`. The sentinel-only suffix sorts first and is
    // skipped, as are the second-half suffixes (each dominated by the matching
    // first-half rotation).
    let mut order: Vec<u32> = Vec::with_capacity(n);
    for &s in sa.iter() {
        let s = s as usize;
        if s < n {
            order.push(s as u32);
        }
    }
    debug_assert_eq!(order.len(), n);

    // Tie-break normalization. For periodic blocks several cyclic rotations
    // can be *equal*; the doubled-suffix order breaks those ties by the
    // distance to the sentinel (favouring larger offsets), whereas a stable
    // rotation sort favours the smaller offset. Equal rotations share an
    // identical last column, so reordering within a tied run never changes
    // `L` — but it can change which row is the primary index. To keep the BWT
    // output byte-identical to a stable cyclic sort, reorder each maximal run
    // of equal rotations by ascending starting offset.
    //
    // Equal rotations are contiguous in `order`. We need the smallest period
    // `p` of the block: rotation `a` equals rotation `b` iff `p` divides
    // `b - a`. With `p` known, equality of adjacent rotations is an O(1) test
    // and the whole normalization is O(n).
    let period = smallest_period(block);
    if period < n {
        let mut i = 0usize;
        while i < n {
            // Extend a run while consecutive rotations are equal. With the
            // block fully periodic, rotations are equal iff their starting
            // offsets are congruent modulo `period`, an O(1) test.
            let base = order[i] as usize % period;
            let mut j = i + 1;
            while j < n && order[j] as usize % period == base {
                j += 1;
            }
            if j - i > 1 {
                order[i..j].sort_unstable();
            }
            i = j;
        }
    }
    order
}

/// Smallest period `p` (1 <= p <= n) such that `block[k] == block[k + p]` for
/// all valid `k` *and* `p` divides `n` — i.e. `block` is `n/p` repetitions of
/// its length-`p` prefix. Returns `n` when the block is not periodic. Computed
/// in O(n) with the Knuth–Morris–Pratt failure function.
fn smallest_period(block: &[u8]) -> usize {
    let n = block.len();
    if n <= 1 {
        return n;
    }
    // KMP prefix-function (longest proper border length).
    let mut fail = vec![0usize; n];
    let mut k = 0usize;
    for i in 1..n {
        while k > 0 && block[i] != block[k] {
            k = fail[k - 1];
        }
        if block[i] == block[k] {
            k += 1;
        }
        fail[i] = k;
    }
    let p = n - fail[n - 1];
    if n.is_multiple_of(p) { p } else { n }
}

// ─── SA-IS suffix array construction ──────────────────────────────────────

/// Build the suffix array of `text` over an integer alphabet whose largest
/// symbol is `< alphabet_size`. The text MUST end with a unique sentinel
/// strictly smaller than every other symbol (we use 0; real bytes are shifted
/// into `1..=256`). Returns an array of length `text.len()`, where `sa[i]` is
/// the start index of the i-th smallest suffix. Linear time, linear space,
/// pure safe Rust.
fn sa_is(text: &[i32], alphabet_size: usize) -> Vec<i32> {
    let n = text.len();
    let mut sa = vec![-1i32; n];
    sa_is_inner(text, &mut sa, alphabet_size);
    sa
}

/// SA-IS core. Writes the suffix array into `sa` (length must equal
/// `text.len()`).
fn sa_is_inner(text: &[i32], sa: &mut [i32], alphabet_size: usize) {
    let n = text.len();
    debug_assert_eq!(sa.len(), n);

    if n == 0 {
        return;
    }
    if n == 1 {
        sa[0] = 0;
        return;
    }
    if n == 2 {
        if text[0] < text[1] {
            sa[0] = 0;
            sa[1] = 1;
        } else {
            sa[0] = 1;
            sa[1] = 0;
        }
        return;
    }

    // 1. Classify each suffix as S-type (`t[i] == true`) or L-type. The last
    //    suffix (sentinel only) is S-type. Suffix i is S-type iff
    //    text[i] < text[i+1], or text[i] == text[i+1] and i+1 is S-type.
    //    Collect LMS positions (an S-type with an L-type left neighbour) while
    //    classifying.
    let mut t = vec![false; n];
    t[n - 1] = true;
    let mut lms_positions: Vec<i32> = Vec::new();
    for i in (0..n - 1).rev() {
        let si = match text[i].cmp(&text[i + 1]) {
            core::cmp::Ordering::Less => true,
            core::cmp::Ordering::Equal => t[i + 1],
            core::cmp::Ordering::Greater => false,
        };
        t[i] = si;
        if t[i + 1] && !si {
            lms_positions.push((i + 1) as i32);
        }
    }
    lms_positions.reverse();
    let n1 = lms_positions.len();

    // 2. Bucket sizes (per-symbol counts in `text`).
    let mut counts = vec![0i32; alphabet_size];
    for &c in text {
        counts[c as usize] += 1;
    }
    let mut bucket = vec![0i32; alphabet_size];

    // 3. Place LMS suffixes at the END of their buckets.
    sa.fill(-1);
    fill_bucket_ends(&counts, &mut bucket);
    for &p in &lms_positions {
        let c = text[p as usize] as usize;
        bucket[c] -= 1;
        sa[bucket[c] as usize] = p;
    }

    // 4-5. Induced sort: L-suffixes (left-to-right), then S-suffixes
    //      (right-to-left).
    induce_sort_l(text, sa, &t, &counts, &mut bucket);
    induce_sort_s(text, sa, &t, &counts, &mut bucket);

    // 6. Compact the induced LMS suffixes to the front of `sa`, then name
    //    each by its LMS-substring identity.
    let mut j1 = 0usize;
    for i in 0..n {
        if sa[i] >= 0 && is_lms(&t, sa[i] as usize) {
            sa[j1] = sa[i];
            j1 += 1;
        }
    }
    debug_assert_eq!(j1, n1);
    for slot in sa.iter_mut().take(n).skip(n1) {
        *slot = -1;
    }

    let mut name: i32 = 0;
    let mut prev: i32 = -1;
    for i in 0..n1 {
        let pos = sa[i] as usize;
        let mut diff = false;
        if prev == -1 {
            diff = true;
        } else {
            let p = prev as usize;
            let mut d = 0usize;
            loop {
                if pos + d >= n || p + d >= n {
                    diff = true;
                    break;
                }
                if text[pos + d] != text[p + d] || t[pos + d] != t[p + d] {
                    diff = true;
                    break;
                }
                if d > 0 && (is_lms(&t, pos + d) || is_lms(&t, p + d)) {
                    if is_lms(&t, pos + d) != is_lms(&t, p + d) {
                        diff = true;
                    }
                    break;
                }
                d += 1;
            }
        }
        if diff {
            name += 1;
            prev = pos as i32;
        }
        sa[n1 + pos / 2] = name - 1;
    }
    let mut j = n - 1;
    for i in (n1..n).rev() {
        if sa[i] >= 0 {
            sa[j] = sa[i];
            j -= 1;
        }
    }

    // 7. Solve the reduced problem (recursively if names collide).
    let new_alpha = (name as usize) + 1;
    let (sa1_area, t1_area) = sa.split_at_mut(n - n1);
    if (name as usize) == n1 {
        for (i, &name_of_pos) in t1_area.iter().enumerate() {
            sa1_area[name_of_pos as usize] = i as i32;
        }
    } else {
        let reduced_text: &[i32] = &t1_area[..n1];
        let sa1 = &mut sa1_area[..n1];
        sa_is_inner(reduced_text, sa1, new_alpha);
    }

    // 8. Map the sorted reduced suffixes back to original LMS positions.
    for slot in sa.iter_mut().take(n1) {
        let idx = *slot as usize;
        *slot = lms_positions[idx];
    }
    for slot in sa.iter_mut().take(n).skip(n1) {
        *slot = -1;
    }

    // 9. Re-place the now-sorted LMS suffixes at bucket ends, then 10. final
    //    induced sorts. Snapshot the sorted LMS positions first so the
    //    scatter cannot clobber a not-yet-read entry.
    let mut lms_sorted: Vec<i32> = Vec::with_capacity(n1);
    lms_sorted.extend_from_slice(&sa[..n1]);
    for slot in sa.iter_mut().take(n) {
        *slot = -1;
    }
    fill_bucket_ends(&counts, &mut bucket);
    for &pos in lms_sorted.iter().rev() {
        let c = text[pos as usize] as usize;
        bucket[c] -= 1;
        sa[bucket[c] as usize] = pos;
    }

    induce_sort_l(text, sa, &t, &counts, &mut bucket);
    induce_sort_s(text, sa, &t, &counts, &mut bucket);
}

/// `true` iff suffix `i` is S-type AND suffix `i-1` is L-type (left-most S in
/// a run). Suffix 0 is never an LMS in our convention.
#[inline(always)]
fn is_lms(t: &[bool], i: usize) -> bool {
    i > 0 && t[i] && !t[i - 1]
}

/// Materialise each bucket *start* (exclusive prefix sum of `counts`).
#[inline]
fn fill_bucket_starts(counts: &[i32], out: &mut [i32]) {
    let mut acc = 0i32;
    for (o, &c) in out.iter_mut().zip(counts.iter()) {
        *o = acc;
        acc += c;
    }
}

/// Materialise each bucket *end* (inclusive prefix sum of `counts`).
#[inline]
fn fill_bucket_ends(counts: &[i32], out: &mut [i32]) {
    let mut acc = 0i32;
    for (o, &c) in out.iter_mut().zip(counts.iter()) {
        acc += c;
        *o = acc;
    }
}

/// Induced sort of L-type suffixes (left-to-right scan over `sa`).
fn induce_sort_l(text: &[i32], sa: &mut [i32], t: &[bool], counts: &[i32], bucket: &mut [i32]) {
    let n = text.len();
    fill_bucket_starts(counts, bucket);
    for i in 0..n {
        let v = sa[i];
        if v <= 0 {
            continue;
        }
        let j = (v as usize) - 1;
        if !t[j] {
            let c = text[j] as usize;
            let slot = bucket[c];
            sa[slot as usize] = j as i32;
            bucket[c] = slot + 1;
        }
    }
}

/// Induced sort of S-type suffixes (right-to-left scan over `sa`).
fn induce_sort_s(text: &[i32], sa: &mut [i32], t: &[bool], counts: &[i32], bucket: &mut [i32]) {
    let n = text.len();
    fill_bucket_ends(counts, bucket);
    for i in (0..n).rev() {
        let v = sa[i];
        if v <= 0 {
            continue;
        }
        let j = (v as usize) - 1;
        if t[j] {
            let c = text[j] as usize;
            let slot = bucket[c] - 1;
            bucket[c] = slot;
            sa[slot as usize] = j as i32;
        }
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
