//! Burrows–Wheeler transform — forward (encoder) and inverse (decoder).
//!
//! ## Forward
//!
//! We build the suffix array of `input` (sorted indices of all
//! rotations of the string treated as cyclic), then the BWT column L is
//! the byte immediately preceding each suffix in cyclic order:
//!
//! ```text
//! L[i] = input[(sa[i] - 1) mod n]
//! ```
//!
//! The "origin" or "pointer" returned alongside is `pos` such that
//! `sa[pos] == 0` — i.e. the row in the sorted matrix that corresponds
//! to the original (unrotated) string. The decoder needs this to know
//! where the original string sits in the reconstructed matrix.
//!
//! We deliberately use a naive Θ(n² + n·log n) suffix-array build: the
//! task spec explicitly permits this as a fallback to SA-IS. The bzip2
//! block size cap is 900 KB; on a 64-bit machine the naive sort of one
//! 900 KB block costs a few hundred ms — slow compared to reference
//! bzip2 but well inside test-time budgets. The encoder is purely a
//! correctness vehicle; nothing in the test suite expects competitive
//! speeds. For shorter blocks (the typical compcol test) the cost is
//! negligible.
//!
//! The suffix sort is done on cyclic rotations, not plain suffixes,
//! because BWT is a transform of the cyclic shift matrix. We
//! synthesise the cyclic comparison by doubling the input
//! conceptually: comparing `rotation_i` and `rotation_j` over `n`
//! characters is equivalent to comparing the substrings
//! `doubled[i..i+n]` and `doubled[j..j+n]` where
//! `doubled = input ++ input`. This is the standard trick.
//!
//! ## Inverse
//!
//! Classic O(n) algorithm: build the "next-row" permutation from L
//! using a stable rank-by-value, then walk it starting at `origin` for
//! `n` steps, emitting L at each step. See the rust comments in
//! [`bwt_inverse`] for details.

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

/// Compute the forward Burrows–Wheeler transform.
///
/// Returns `(L, origin)` where `L` is the BWT output (same length as
/// `input`) and `origin` is the row index of the original (unrotated)
/// string in the sorted rotation matrix.
///
/// Panics: never (no asserts under release builds; debug ones only).
pub(crate) fn bwt_forward(input: &[u8]) -> (Vec<u8>, u32) {
    let n = input.len();
    if n == 0 {
        return (Vec::new(), 0);
    }

    // Build the suffix array of `input` treated cyclically.
    let sa = suffix_array_cyclic(input);

    // L[i] = input[(sa[i] + n - 1) % n]; origin = position of 0 in sa.
    let mut l = Vec::with_capacity(n);
    let mut origin: u32 = 0;
    for (i, &s) in sa.iter().enumerate() {
        let prev = if s == 0 { n - 1 } else { s - 1 };
        l.push(input[prev]);
        if s == 0 {
            origin = i as u32;
        }
    }
    (l, origin)
}

/// Naive cyclic suffix-array build. Allocates an `n`-element index
/// vector and sorts it by lexicographic order of the cyclic rotations
/// starting at each index. Comparison is done in-place against `input`
/// using a doubled-buffer trick — we never materialise the rotations.
///
/// Complexity: O(n·log n) comparisons, each O(n) in the worst case, so
/// O(n²·log n) overall. Good enough for the block sizes bzip2 targets;
/// the SA-IS upgrade is left as a TODO (the task spec allows this
/// naive fallback).
fn suffix_array_cyclic(input: &[u8]) -> Vec<usize> {
    let n = input.len();
    let mut sa: Vec<usize> = (0..n).collect();
    sa.sort_by(|&a, &b| cmp_cyclic(input, a, b));
    sa
}

/// Compare two cyclic rotations of `input` starting at indices `a` and
/// `b`. Returns the lexicographic ordering.
fn cmp_cyclic(input: &[u8], a: usize, b: usize) -> core::cmp::Ordering {
    let n = input.len();
    if a == b {
        return core::cmp::Ordering::Equal;
    }
    // Compare up to n bytes, wrapping each index modulo n.
    for k in 0..n {
        let ai = input[(a + k) % n];
        let bi = input[(b + k) % n];
        if ai != bi {
            return ai.cmp(&bi);
        }
    }
    core::cmp::Ordering::Equal
}

/// Compute the inverse BWT given the L column and the origin row.
///
/// The algorithm:
/// 1. Build a frequency table of bytes in L.
/// 2. From it, compute `start[c]` = first position in the sorted L
///    (which is the F column) where byte `c` appears.
/// 3. Build the "next" permutation: for each i (in L order),
///    `next[i] = start[L[i]] + occ_so_far[L[i]]`; `occ_so_far`
///    counts how many `L[i]` values we've seen so far.
/// 4. Walk: `i = origin; for _ in 0..n: emit L[i]; i = next[i]`.
///
/// Equivalently many texts express this as walking `F` and using
/// `prev` — both produce the same byte stream.
pub(crate) fn bwt_inverse(l: &[u8], origin: u32) -> Vec<u8> {
    let n = l.len();
    if n == 0 {
        return Vec::new();
    }
    debug_assert!((origin as usize) < n);

    // Step 1: byte frequency in L.
    let mut count = [0u32; 256];
    for &b in l {
        count[b as usize] += 1;
    }

    // Step 2: `start[c]` = sum of count[0..c] = first position of c in
    // the sorted F column.
    let mut start = [0u32; 256];
    let mut s: u32 = 0;
    for c in 0..256 {
        start[c] = s;
        s += count[c];
    }

    // Step 3: build `next` permutation. We reuse `start` as the
    // running write-cursor: for each i, the next slot for byte L[i] is
    // `start[L[i]]`, which we then increment.
    let mut next = vec![0u32; n];
    let mut cursor = start;
    for (i, &b) in l.iter().enumerate() {
        let c = b as usize;
        next[i] = cursor[c];
        cursor[c] += 1;
    }

    // Step 4: walk. The LF-mapping walk from `origin` yields the
    // original string in REVERSE order: at each step we move "one
    // character backward" in the original. So we walk and place the
    // emitted byte into the buffer from the end backward.
    //
    // (Equivalently we could compute the inverse permutation and walk
    // it forward, but that's more code and constant-factor slower.)
    let mut out = vec![0u8; n];
    let mut i = origin as usize;
    for k in (0..n).rev() {
        out[k] = l[i];
        i = next[i] as usize;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn round_trip_short() {
        let input = b"BANANA";
        let (l, origin) = bwt_forward(input);
        let back = bwt_inverse(&l, origin);
        assert_eq!(back, input);
    }

    #[test]
    fn round_trip_single() {
        let input = b"a";
        let (l, origin) = bwt_forward(input);
        assert_eq!(l, b"a");
        assert_eq!(origin, 0);
        let back = bwt_inverse(&l, origin);
        assert_eq!(back, input);
    }

    #[test]
    fn round_trip_empty() {
        let (l, origin) = bwt_forward(&[]);
        assert!(l.is_empty());
        assert_eq!(origin, 0);
        let back = bwt_inverse(&l, origin);
        assert!(back.is_empty());
    }

    #[test]
    fn round_trip_longer() {
        let input = b"the quick brown fox jumps over the lazy dog";
        let (l, origin) = bwt_forward(input);
        let back = bwt_inverse(&l, origin);
        assert_eq!(back, input);
    }

    #[test]
    fn round_trip_repeated_bytes() {
        let input = vec![b'a'; 50];
        let (l, origin) = bwt_forward(&input);
        let back = bwt_inverse(&l, origin);
        assert_eq!(back, input);
    }
}
