//! Literal context modeling for the brotli encoder (RFC 7932 §7.1).
//!
//! The decoder selects a literal Huffman tree per byte using a context
//! id derived from the two previous output bytes (`literal_context`),
//! then maps `context_id` → tree index through the literal context map
//! `cmapl`. The base encoder declared a single literal tree (NTREESL=1),
//! leaving the whole context-modeling lever on the table.
//!
//! This module builds, for one meta-block:
//!   1. a per-context literal histogram (64 contexts × 256 symbols),
//!   2. a clustering of those 64 contexts into a small number of trees
//!      (agglomerative, merging contexts whose distributions are close),
//!   3. the resulting context map `cmapl[0..64]` (tree index per context).
//!
//! The encoder picks the UTF8 context mode — the same default the
//! reference uses for text — and emits the map plus one literal tree per
//! cluster. Everything stays spec-compliant; only encoder choices change.

use alloc::vec::Vec;

use super::context::{self, ContextMode};

/// Number of literal contexts (context id ∈ 0..=63).
pub(crate) const NUM_CONTEXTS: usize = 64;

/// Upper bound on the number of literal trees we will emit. More trees
/// model the input more tightly but cost a full prefix-code header each;
/// 16 is a good balance and keeps the context-map alphabet small.
pub(crate) const MAX_LITERAL_TREES: usize = 16;

/// Context modes the encoder evaluates per meta-block, picking the one
/// with the lowest estimated total cost. UTF8 distinguishes UTF8 byte
/// classes (good for mixed/multibyte text); MSB6/LSB6 split on the high
/// or low six bits of the previous byte and give near-order-1 separation
/// on ASCII text and source code — which UTF8 collapses into a couple of
/// buckets. Signed helps numeric/binary-ish data.
pub(crate) const CANDIDATE_MODES: [ContextMode; 4] = [
    ContextMode::Utf8,
    ContextMode::Msb6,
    ContextMode::Lsb6,
    ContextMode::Signed,
];

/// Per-context literal histograms plus the cluster assignment.
pub(crate) struct LiteralContextModel {
    /// The context mode this model was built for.
    pub mode: ContextMode,
    /// `histograms[c][b]` = count of literal byte `b` under context `c`,
    /// folded across clusters after merging (so a cluster's representative
    /// context carries the merged histogram). Only used to derive per-tree
    /// frequencies, which are reconstructed by the caller from `cmap`, so
    /// the post-merge layout does not matter to correctness.
    pub histograms: Vec<[u32; 256]>,
    /// `cmap[c]` = tree index assigned to context `c` (0..num_trees).
    pub cmap: Vec<u8>,
    /// Number of distinct trees actually used.
    pub num_trees: u32,
    /// Estimated encoded cost of the literals under this model, in bits
    /// (data + a rough per-tree header allowance). Used to compare modes.
    pub est_cost_bits: u64,
}

/// Shannon-style bit cost of a histogram: `Σ count·log2(total/count)`.
/// Returned in fixed-point (bits × 256) to stay in integer arithmetic
/// (this is a no_std crate; `f64::log2` is unavailable without `std`).
fn histogram_bits(hist: &[u32; 256], total: u32) -> u64 {
    if total == 0 {
        return 0;
    }
    let log_total = log2_fixed(total as u64);
    let mut bits: u64 = 0;
    for &c in hist.iter() {
        if c != 0 {
            // count * (log2(total) - log2(count))
            bits += (c as u64) * (log_total - log2_fixed(c as u64));
        }
    }
    bits
}

/// `log2(x) * 256` for `x ≥ 1`, integer math. Combines an integer
/// floor-log2 with a small fractional interpolation table.
fn log2_fixed(x: u64) -> u64 {
    debug_assert!(x >= 1);
    if x == 1 {
        return 0;
    }
    let floor = 63 - x.leading_zeros() as u64; // floor(log2(x))
    // Fractional part via linear interpolation between 2^floor and
    // 2^(floor+1). frac = (x - 2^floor) / 2^floor, scaled to 0..256.
    let base = 1u64 << floor;
    let frac = ((x - base) << 8) / base; // 0..256
    floor * 256 + frac
}

/// Combined bit cost of two histograms merged into one.
fn merged_bits(a: &[u32; 256], at: u32, b: &[u32; 256], bt: u32) -> u64 {
    let total = at + bt;
    if total == 0 {
        return 0;
    }
    let log_total = log2_fixed(total as u64);
    let mut bits: u64 = 0;
    for i in 0..256 {
        let c = a[i] + b[i];
        if c != 0 {
            bits += (c as u64) * (log_total - log2_fixed(c as u64));
        }
    }
    bits
}

/// Rough fixed-point (bits×256) allowance for one literal prefix-code
/// header (256-symbol complex code) plus its share of the context map.
/// Used both as the merge "bonus" and in the cross-mode cost estimate so
/// the two stay consistent.
const HEADER_COST_BITS: u64 = 140 * 256;

/// Cluster the per-context histograms (already tallied for `mode`) into
/// at most `max_trees` literal trees, then estimate the model's total
/// encoded cost so the caller can compare context modes.
///
/// The histograms are tallied over exactly the literal bytes the encoder
/// will emit (see `build_literal_context_model` in `mod.rs`). The merge
/// is agglomerative: repeatedly fuse the pair of clusters whose union
/// costs the fewest extra data bits, charging each surviving cluster a
/// fixed header allowance so similar contexts coalesce.
pub(crate) fn cluster(
    mode: ContextMode,
    mut histograms: Vec<[u32; 256]>,
    max_trees: usize,
) -> LiteralContextModel {
    debug_assert_eq!(histograms.len(), NUM_CONTEXTS);

    // Per-context totals.
    let mut totals: Vec<u32> = histograms.iter().map(|h| h.iter().sum::<u32>()).collect();

    // Cluster id per context.
    let mut cluster_of: Vec<i32> = (0..NUM_CONTEXTS as i32).collect();

    // Active cluster set: start with one cluster per non-empty context.
    let mut active: Vec<usize> = (0..NUM_CONTEXTS).filter(|&c| totals[c] > 0).collect();

    if active.is_empty() {
        return LiteralContextModel {
            mode,
            histograms,
            cmap: alloc::vec![0u8; NUM_CONTEXTS],
            num_trees: 1,
            est_cost_bits: 0,
        };
    }

    // Park empty contexts onto the first active cluster.
    let first_active = active[0];
    for c in 0..NUM_CONTEXTS {
        if totals[c] == 0 {
            cluster_of[c] = first_active as i32;
        }
    }

    // Agglomerative clustering. The naive form recomputes every pair's merge
    // delta — including each cluster's own `histogram_bits` — on every iteration,
    // which is O(active³ · 256) and blows up on dense histograms (e.g. random
    // input, where every context spans all 256 symbols). Instead cache each
    // cluster's self-cost and the pairwise deltas, keyed by stable cluster id,
    // and after each merge recompute only the merged cluster's row. The merge
    // sequence — and therefore the resulting model and compressed output — is
    // byte-for-byte identical to the naive version; only redundant work is cut.
    let mut self_bits = alloc::vec![0u64; NUM_CONTEXTS];
    for &c in &active {
        self_bits[c] = histogram_bits(&histograms[c], totals[c]);
    }
    // `delta[ci][cj]` for `ci < cj`; valid only for currently-active pairs.
    let mut delta = alloc::vec![alloc::vec![0i64; NUM_CONTEXTS]; NUM_CONTEXTS];
    let pair_delta = |ci: usize, cj: usize, sb: &[u64], hs: &[[u32; 256]], ts: &[u32]| -> i64 {
        let bm = merged_bits(&hs[ci], ts[ci], &hs[cj], ts[cj]);
        bm as i64 - sb[ci] as i64 - sb[cj] as i64 - HEADER_COST_BITS as i64
    };
    for ai in 0..active.len() {
        for aj in (ai + 1)..active.len() {
            let (ci, cj) = (active[ai], active[aj]);
            delta[ci][cj] = pair_delta(ci, cj, &self_bits, &histograms, &totals);
        }
    }

    while active.len() > 1 {
        let force = active.len() > max_trees;
        let mut best_i = 0usize;
        let mut best_j = 0usize;
        let mut best_delta: i64 = i64::MAX;
        // Same scan order and strict `<` tie-break as the naive loop, so the
        // chosen pair is identical — but now a cheap matrix lookup, not a
        // 256-symbol recomputation.
        for ai in 0..active.len() {
            for aj in (ai + 1)..active.len() {
                let (ci, cj) = (active[ai], active[aj]);
                let d = if ci < cj {
                    delta[ci][cj]
                } else {
                    delta[cj][ci]
                };
                if d < best_delta {
                    best_delta = d;
                    best_i = ai;
                    best_j = aj;
                }
            }
        }
        // Stop when not forced and the cheapest merge is a net loss.
        if !force && best_delta > 0 {
            break;
        }
        let ci = active[best_i];
        let cj = active[best_j];
        let src = histograms[cj];
        for (dst, s) in histograms[ci].iter_mut().zip(src.iter()) {
            *dst += *s;
        }
        totals[ci] += totals[cj];
        for slot in cluster_of.iter_mut() {
            if *slot == cj as i32 {
                *slot = ci as i32;
            }
        }
        active.swap_remove(best_j);
        // Only the merged cluster `ci`'s costs changed; refresh its self-cost
        // and its delta against every other surviving cluster.
        self_bits[ci] = histogram_bits(&histograms[ci], totals[ci]);
        for &ck in &active {
            if ck != ci {
                let (lo, hi) = if ci < ck { (ci, ck) } else { (ck, ci) };
                delta[lo][hi] = pair_delta(lo, hi, &self_bits, &histograms, &totals);
            }
        }
    }

    // Compress cluster ids to a dense 0..num_trees range.
    let mut remap = alloc::vec![-1i32; NUM_CONTEXTS];
    let mut next = 0u8;
    let mut cmap = alloc::vec![0u8; NUM_CONTEXTS];
    for c in 0..NUM_CONTEXTS {
        let cl = cluster_of[c] as usize;
        if remap[cl] < 0 {
            remap[cl] = next as i32;
            next += 1;
        }
        cmap[c] = remap[cl] as u8;
    }
    let num_trees = next.max(1) as u32;

    // Estimate total cost: data bits across surviving clusters + a header
    // allowance per tree. `active` now holds the surviving cluster reps.
    let mut data_bits: u64 = 0;
    for &ci in &active {
        data_bits += histogram_bits(&histograms[ci], totals[ci]);
    }
    let est_cost_bits = data_bits / 256 + num_trees as u64 * (HEADER_COST_BITS / 256);

    LiteralContextModel {
        mode,
        histograms,
        cmap,
        num_trees,
        est_cost_bits,
    }
}

/// Compute the literal context id from the two preceding output bytes
/// under the given mode. `prev1`/`prev2` are the bytes at `g-1`/`g-2` in
/// the full output stream.
#[inline]
pub(crate) fn context_id(mode: ContextMode, prev1: u8, prev2: u8) -> u8 {
    context::literal_context(mode, prev1, prev2)
}
