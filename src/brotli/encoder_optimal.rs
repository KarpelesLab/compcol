//! Iterative, statistics-driven optimal LZ77 parse for the brotli
//! encoder (a zopfli-style forward dynamic program).
//!
//! The greedy parse in `mod.rs` picks one match per position. This module
//! instead computes a least-cost command sequence for a whole meta-block
//! via forward DP, where the per-command bit cost comes from a
//! [`CostModel`]. The model is rebuilt from the *actual* command / literal
//! / distance histograms of the previous pass and the DP is re-run, so the
//! second pass optimises against the data's real statistics — the same
//! distance-reuse feedback loop that gives reference brotli q10/q11 its
//! edge over a single greedy pass.
//!
//! The output is a `Vec<Command>` in exactly the same shape the greedy
//! `lz77_to_commands` produces, so `plan_commands`, the ring-buffer
//! tracking, and the meta-block emitter are all unchanged and the stream
//! stays spec-valid. The chosen commands are re-planned by `plan_commands`
//! against the real distance ring afterwards, so an imperfect ring
//! approximation in the DP costs only a little ratio, never correctness.

use alloc::vec;
use alloc::vec::Vec;

use super::encoder_dict::{self, DictIndex, IdTransform};
use super::encoder_iac::{
    COPY_EXTRA, INS_EXTRA, copy_to_code, distance_to_normal_code, ic_command_sym, insert_to_code,
};
use super::encoder_lz77::{FinderParams, MAX_MATCH, MIN_MATCH, MatchFinder, match_len_at};
use super::{Command, CopyKind, DistRing, dictionary};

/// Per-symbol bit-cost model derived from a histogram. `cost[s]` is the
/// estimated code length (in bits) of symbol `s`.
struct SymCost {
    cost: Vec<f32>,
    /// Cost charged to a symbol that never appeared in the histogram.
    missing: f32,
}

impl SymCost {
    /// Shannon-style cost: `log2(total) - log2(count[s])`, floored at 1
    /// bit (a present symbol cannot be coded in less). Absent symbols get
    /// `log2(total) + 2` so the parse still considers them but pays a
    /// realistic penalty.
    fn from_hist(hist: &[u32]) -> Self {
        let total: u64 = hist.iter().map(|&h| h as u64).sum();
        let len = hist.len();
        if total == 0 {
            let flat = (len as f32).max(2.0).log2();
            return Self {
                cost: vec![flat; len],
                missing: flat,
            };
        }
        let log2_total = (total as f32).log2();
        let mut cost = vec![0.0f32; len];
        for (i, &h) in hist.iter().enumerate() {
            cost[i] = if h == 0 {
                log2_total + 2.0
            } else {
                let c = log2_total - (h as f32).log2();
                if c < 1.0 { 1.0 } else { c }
            };
        }
        Self {
            cost,
            missing: log2_total + 2.0,
        }
    }

    #[inline]
    fn get(&self, sym: usize) -> f32 {
        self.cost.get(sym).copied().unwrap_or(self.missing)
    }
}

/// Bit-cost model for one DP pass.
struct CostModel {
    lit: SymCost,
    cmd: SymCost,
    dist: SymCost,
}

impl CostModel {
    /// Seed an estimate before any commands have been chosen: literal
    /// costs from the raw byte histogram, command / distance costs flat
    /// (≈ reference brotli's `FastLog2(11)` / `FastLog2(20)` seeds).
    fn estimate(payload: &[u8]) -> Self {
        let mut lit_hist = [0u32; 256];
        for &b in payload {
            lit_hist[b as usize] += 1;
        }
        Self {
            lit: SymCost::from_hist(&lit_hist),
            cmd: SymCost {
                cost: vec![(11.0f32).log2(); 704],
                missing: (11.0f32).log2(),
            },
            dist: SymCost {
                cost: vec![(20.0f32).log2(); 64],
                missing: (20.0f32).log2(),
            },
        }
    }

    /// Build a model from the histograms of a previous pass's commands.
    fn from_hist(
        lit_hist: &[u32; 256],
        cmd_hist: &[u32; 704],
        dist_hist: &[u32; 64],
    ) -> Self {
        Self {
            lit: SymCost::from_hist(lit_hist),
            cmd: SymCost::from_hist(cmd_hist),
            dist: SymCost::from_hist(dist_hist),
        }
    }
}

/// A DP node: the optimal way to have encoded `payload[0..pos]`, where
/// `pos` is the node's index. Literal-only progress sets `copy_len == 0`
/// and accumulates `insert_len`; a copy resets the run.
#[derive(Clone, Copy)]
struct Node {
    /// Minimal cost in bits to reach this byte position.
    cost: f32,
    /// Insert-run length of the command that ends here (literals consumed
    /// immediately before the copy, or the running literal count).
    insert_len: u32,
    /// Bytes consumed by the copy (0 for a literal step / stream start).
    copy_len: u32,
    /// Back-distance for a normal copy. For a dictionary ref this is the
    /// synthesised dict distance (used only for the histogram/plan).
    dist: u32,
    dict_word_idx: u32,
    dict_tr_id: u8,
    /// Dictionary word length placed in the copy field.
    dict_word_len: u8,
    is_dict: bool,
}

impl Node {
    const INF: Node = Node {
        cost: f32::INFINITY,
        insert_len: 0,
        copy_len: 0,
        dist: 0,
        dict_word_idx: 0,
        dict_tr_id: 0,
        dict_word_len: 0,
        is_dict: false,
    };
}

/// Command bit cost (everything except the literal run, already priced
/// incrementally): IC symbol + insert/copy extra bits + distance symbol +
/// distance extra bits.
#[inline]
fn command_cost(
    model: &CostModel,
    insert_len: u32,
    copy_len: u32,
    dcode: u32,
    dextra_bits: u32,
) -> f32 {
    let (ins_code, _, _) = insert_to_code(insert_len);
    let (copy_code, _, _) = copy_to_code(copy_len);
    let ic_sym = ic_command_sym(ins_code, copy_code, false);
    model.cmd.get(ic_sym as usize)
        + INS_EXTRA[ins_code as usize] as f32
        + COPY_EXTRA[copy_code as usize] as f32
        + model.dist.get(dcode as usize)
        + dextra_bits as f32
}

/// Command bit cost for a copy reusing a recent distance (short code, no
/// extra bits). `short_code` is the 0..=15 ring code.
#[inline]
fn repeat_command_cost(model: &CostModel, insert_len: u32, copy_len: u32, short_code: u32) -> f32 {
    let (ins_code, _, _) = insert_to_code(insert_len);
    let (copy_code, _, _) = copy_to_code(copy_len);
    let ic_sym = ic_command_sym(ins_code, copy_code, false);
    model.cmd.get(ic_sym as usize)
        + INS_EXTRA[ins_code as usize] as f32
        + COPY_EXTRA[copy_code as usize] as f32
        + model.dist.get(short_code as usize)
}

/// Recover the four most-recent distances reaching `pos` (decoder ring
/// order; `out[0]` most recent) by following the chosen back-pointers.
/// Dictionary refs and literal-only steps do not push the ring.
fn dist_ring_at(nodes: &[Node], mut pos: usize, out: &mut [u32; 4]) {
    *out = [0; 4];
    let mut filled = 0usize;
    let mut guard = 0;
    while pos > 0 && filled < 4 && guard < 256 {
        let n = nodes[pos];
        if n.copy_len == 0 && n.insert_len == 0 {
            break;
        }
        let back = n.copy_len as usize + n.insert_len as usize;
        if !n.is_dict && n.copy_len != 0 && n.dist != 0 {
            // Skip duplicates of the most recent (code-0 reuse does not
            // push a fresh ring entry).
            if filled == 0 || out[filled - 1] != n.dist {
                out[filled] = n.dist;
                filled += 1;
            }
        }
        if back == 0 || back > pos {
            break;
        }
        pos -= back;
        guard += 1;
    }
}

/// Run the iterative optimal parse and append the chosen commands to
/// `cmds`. On any internal inconsistency `cmds` is cleared so the caller
/// can fall back to the greedy parse.
#[allow(clippy::too_many_arguments)]
pub(crate) fn optimal_parse(
    payload: &[u8],
    mf: &mut MatchFinder,
    dict_index: Option<&DictIndex>,
    id_transforms: Option<&[IdTransform]>,
    prev_total_out: u64,
    ring_start: DistRing,
    iterations: u32,
    finder: FinderParams,
    cmds: &mut Vec<Command>,
    insert_pool: &mut Vec<Vec<u8>>,
) {
    let n = payload.len();
    if n == 0 {
        return;
    }

    let use_dict = dict_index.is_some() && id_transforms.is_some();

    // Populate the hash chains, then precompute every position's match
    // candidates *once*. The candidates don't change between passes (only
    // the cost model does), so caching them makes the extra iterations
    // nearly free — the per-pass work is just the DP relaxation.
    mf.reset();
    for pos in 0..n {
        mf.insert(payload, pos);
    }
    let cache = MatchCache::build(
        payload,
        mf,
        dict_index,
        id_transforms,
        prev_total_out,
        use_dict,
        finder,
    );

    let mut model = CostModel::estimate(payload);
    let mut nodes: Vec<Node> = vec![Node::INF; n + 1];

    let passes = iterations.max(1);
    for iter in 0..passes {
        forward_dp(payload, &cache, ring_start, &model, &mut nodes);
        if !nodes[n].cost.is_finite() {
            cmds.clear();
            return;
        }
        if iter + 1 == passes {
            break;
        }
        let (lit_hist, cmd_hist, dist_hist) = histogram_path(payload, &nodes, ring_start);
        model = CostModel::from_hist(&lit_hist, &cmd_hist, &dist_hist);
    }

    emit_path(payload, &nodes, cmds, insert_pool);
}

/// A dictionary-match candidate at some position.
#[derive(Clone, Copy)]
struct DictCand {
    distance: u32,
    dcode: u32,
    dextra_bits: u32,
    emit_len: u32,
    word_idx: u32,
    tr_id: u8,
    word_len: u8,
}

/// Per-position precomputed match candidates, shared across DP passes.
struct MatchCache {
    /// Flat list of `(len, dist)` explicit-match candidates.
    cand: Vec<(u32, u32)>,
    /// `cand_off[p]..cand_off[p+1]` is position `p`'s candidate slice.
    cand_off: Vec<u32>,
    /// Precomputed `(dcode, dextra_bits)` for each explicit candidate,
    /// aligned with `cand`.
    cand_dcode: Vec<(u32, u32)>,
    /// One optional dictionary candidate per position.
    dict: Vec<Option<DictCand>>,
}

impl MatchCache {
    fn build(
        payload: &[u8],
        mf: &MatchFinder,
        dict_index: Option<&DictIndex>,
        id_transforms: Option<&[IdTransform]>,
        prev_total_out: u64,
        use_dict: bool,
        finder: FinderParams,
    ) -> Self {
        let n = payload.len();
        let mut cand: Vec<(u32, u32)> = Vec::with_capacity(n);
        let mut cand_dcode: Vec<(u32, u32)> = Vec::with_capacity(n);
        let mut cand_off: Vec<u32> = Vec::with_capacity(n + 1);
        let mut dict: Vec<Option<DictCand>> = Vec::with_capacity(n);

        let mut buf = [(0u32, 0u32); 8];
        for p in 0..n {
            cand_off.push(cand.len() as u32);
            if p + MIN_MATCH <= n {
                let cnt = mf.find_matches(payload, p, finder, &mut buf);
                for &(clen, cdist) in &buf[..cnt] {
                    if let Some((dcode, ndb, _)) = distance_to_normal_code(cdist) {
                        cand.push((clen, cdist));
                        cand_dcode.push((dcode, ndb));
                    }
                }
            }
            dict.push(dict_candidate(
                payload,
                dict_index,
                id_transforms,
                prev_total_out,
                use_dict,
                p,
            ));
        }
        cand_off.push(cand.len() as u32);
        Self {
            cand,
            cand_off,
            cand_dcode,
            dict,
        }
    }

    #[inline]
    fn explicit(&self, p: usize) -> ExplicitCands<'_> {
        let lo = self.cand_off[p] as usize;
        let hi = self.cand_off[p + 1] as usize;
        (&self.cand[lo..hi], &self.cand_dcode[lo..hi])
    }
}

/// `(len, dist)` candidates paired with their precomputed
/// `(dcode, dist_extra_bits)`.
type ExplicitCands<'a> = (&'a [(u32, u32)], &'a [(u32, u32)]);

/// Compute the single dictionary-match candidate at position `p`, if any.
fn dict_candidate(
    payload: &[u8],
    dict_index: Option<&DictIndex>,
    id_transforms: Option<&[IdTransform]>,
    prev_total_out: u64,
    use_dict: bool,
    p: usize,
) -> Option<DictCand> {
    let n = payload.len();
    if !use_dict || p + 4 > n {
        return None;
    }
    let dm = encoder_dict::find_dict_match(dict_index?, id_transforms?, payload, p, 4)?;
    let total_out_at_pos: u64 = prev_total_out + p as u64;
    let max_dist: u64 = core::cmp::min((1u64 << 16) - 16, total_out_at_pos);
    let wl = dm.word_len as usize;
    let nwords_bits = dictionary::SIZE_BITS_BY_LENGTH[wl] as u32;
    let off = (dm.word_idx as u64) | ((dm.transform_id as u64) << nwords_bits);
    let distance = max_dist + 1 + off;
    if distance == 0 || distance > u32::MAX as u64 {
        return None;
    }
    let (dcode, ndb, _) = distance_to_normal_code(distance as u32)?;
    let emit_len = dm.emit_len as usize;
    if p + emit_len > n {
        return None;
    }
    Some(DictCand {
        distance: distance as u32,
        dcode,
        dextra_bits: ndb,
        emit_len: emit_len as u32,
        word_idx: dm.word_idx,
        tr_id: dm.transform_id,
        word_len: dm.word_len,
    })
}

/// One forward DP pass: fill `nodes[1..=n]` with least-cost arrivals,
/// using the precomputed match cache.
fn forward_dp(
    payload: &[u8],
    cache: &MatchCache,
    ring_start: DistRing,
    model: &CostModel,
    nodes: &mut [Node],
) {
    let n = payload.len();
    for node in nodes.iter_mut() {
        *node = Node::INF;
    }
    nodes[0] = Node {
        cost: 0.0,
        ..Node::INF
    };

    let mut ring4 = [0u32; 4];
    for p in 0..n {
        let here = nodes[p];
        if !here.cost.is_finite() {
            continue;
        }

        // The running literal-run length entering position `p` is the
        // accumulated insert for the *next* command. A copy-end node
        // restarts the run at 0; a literal-step node carries its count.
        let run_in = if here.copy_len == 0 { here.insert_len } else { 0 };

        // (a) Literal step: extend the running insert run by one byte. The
        //     per-literal cost is added incrementally so a copy starting
        //     later pays only its command overhead.
        {
            let lit_c = here.cost + model.lit.get(payload[p] as usize);
            let nx = &mut nodes[p + 1];
            if lit_c < nx.cost {
                *nx = Node {
                    cost: lit_c,
                    insert_len: run_in.wrapping_add(1),
                    copy_len: 0,
                    dist: 0,
                    dict_word_idx: 0,
                    dict_tr_id: 0,
                    dict_word_len: 0,
                    is_dict: false,
                };
            }
        }

        // The insert run for a copy starting here is whatever literals we
        // have accumulated; its bits are already in `here.cost`.
        let insert_len = run_in;
        let copy_start_cost = here.cost;

        // (b) Copy transitions.
        if p + MIN_MATCH <= n {
            dist_ring_at(nodes, p, &mut ring4);
            let seed = ring_start;
            let ring_get = |k: usize| -> u32 {
                if ring4[k] != 0 {
                    ring4[k]
                } else {
                    let v = seed.nth_last((k + 1) as u32);
                    if v > 0 {
                        v as u32
                    } else {
                        0
                    }
                }
            };

            // Repeat-distance candidates: cheap short codes 0..=3. We try
            // every length from MIN_MATCH up to the match length so the DP
            // can break a long copy when a better-aligned match starts a
            // few bytes in (the key zopfli win over greedy).
            for k in 0..4usize {
                let d = ring_get(k);
                if d == 0 || d as usize > p {
                    continue;
                }
                let rl = match_len_at(payload, p, d as usize);
                if rl < MIN_MATCH {
                    continue;
                }
                let maxl = rl.min(MAX_MATCH).min(n - p);
                let mut len = MIN_MATCH;
                while len <= maxl {
                    let cost =
                        copy_start_cost + repeat_command_cost(model, insert_len, len as u32, k as u32);
                    relax(nodes, p + len, cost, insert_len, len as u32, d, None);
                    len += 1;
                }
            }

            // Explicit chain matches (precomputed). Candidates have
            // strictly increasing length, each at the closest distance
            // achieving that length. For candidate `j` spanning lengths
            // `(prev_len, len_j]`, that distance is the cheapest available
            // for every length in the band, so we relax all of them.
            //
            // If an explicit distance coincides with a recent ring
            // distance it can be coded as a cheap short code instead of a
            // full distance symbol + extra bits — price it as the cheaper
            // of the two so the DP prefers ring-reusing matches.
            let (cands, dcodes) = cache.explicit(p);
            let mut prev_len = MIN_MATCH - 1;
            for (&(clen, cdist), &(dcode, ndb)) in cands.iter().zip(dcodes.iter()) {
                let maxl = (clen as usize).min(MAX_MATCH).min(n - p);
                if maxl <= prev_len {
                    continue;
                }
                let short = ring_short_code(&ring4, &seed, cdist);
                let mut l = prev_len + 1;
                while l <= maxl {
                    let full = command_cost(model, insert_len, l as u32, dcode, ndb);
                    let cost = match short {
                        Some(sc) => {
                            let rep = repeat_command_cost(model, insert_len, l as u32, sc);
                            copy_start_cost + full.min(rep)
                        }
                        None => copy_start_cost + full,
                    };
                    relax(nodes, p + l, cost, insert_len, l as u32, cdist, None);
                    l += 1;
                }
                prev_len = maxl;
            }
        }

        // (c) Dictionary reference (precomputed).
        if let Some(dc) = cache.dict[p] {
            let dest = p + dc.emit_len as usize;
            let cost = copy_start_cost
                + command_cost(model, insert_len, dc.word_len as u32, dc.dcode, dc.dextra_bits);
            relax(
                nodes,
                dest,
                cost,
                insert_len,
                dc.emit_len,
                dc.distance,
                Some((dc.word_idx, dc.tr_id, dc.word_len)),
            );
        }
    }
}

/// Return the short distance code (0..=15) for `dist` given the recent
/// ring (reconstructed `ring4`, falling back to the block-start `seed`),
/// or `None` if `dist` needs a full distance symbol. Mirrors the subset
/// of `DistRing::try_short_code` the DP relies on.
#[inline]
fn ring_short_code(ring4: &[u32; 4], seed: &DistRing, dist: u32) -> Option<u32> {
    let slot = |k: usize| -> i32 {
        if ring4[k] != 0 {
            ring4[k] as i32
        } else {
            seed.nth_last((k + 1) as u32)
        }
    };
    let d = dist as i32;
    let last = slot(0);
    let last2 = slot(1);
    if d == last {
        return Some(0);
    }
    if d == last2 {
        return Some(1);
    }
    if d == slot(2) {
        return Some(2);
    }
    if d == slot(3) {
        return Some(3);
    }
    if d > 0 {
        if d == last - 1 {
            return Some(4);
        }
        if d == last + 1 {
            return Some(5);
        }
        if d == last - 2 {
            return Some(6);
        }
        if d == last + 2 {
            return Some(7);
        }
        if d == last - 3 {
            return Some(8);
        }
        if d == last + 3 {
            return Some(9);
        }
        if d == last2 - 1 {
            return Some(10);
        }
        if d == last2 + 1 {
            return Some(11);
        }
        if d == last2 - 2 {
            return Some(12);
        }
        if d == last2 + 2 {
            return Some(13);
        }
        if d == last2 - 3 {
            return Some(14);
        }
        if d == last2 + 3 {
            return Some(15);
        }
    }
    None
}

/// Relax a copy transition landing at `dest`.
#[inline]
fn relax(
    nodes: &mut [Node],
    dest: usize,
    cost: f32,
    insert_len: u32,
    copy_len: u32,
    dist: u32,
    dict: Option<(u32, u8, u8)>,
) {
    let nd = &mut nodes[dest];
    if cost < nd.cost {
        match dict {
            Some((word_idx, tr_id, word_len)) => {
                *nd = Node {
                    cost,
                    insert_len,
                    copy_len,
                    dist,
                    dict_word_idx: word_idx,
                    dict_tr_id: tr_id,
                    dict_word_len: word_len,
                    is_dict: true,
                };
            }
            None => {
                *nd = Node {
                    cost,
                    insert_len,
                    copy_len,
                    dist,
                    dict_word_idx: 0,
                    dict_tr_id: 0,
                    dict_word_len: 0,
                    is_dict: false,
                };
            }
        }
    }
}

/// Walk the DP back-pointers to recover command boundaries: a list of
/// `(start, end, node)` in forward order.
fn collect_path(payload: &[u8], nodes: &[Node]) -> Option<Vec<(usize, usize, Node)>> {
    let n = payload.len();
    let mut bounds: Vec<(usize, usize, Node)> = Vec::new();
    let mut pos = n;
    let mut guard = 0usize;
    while pos > 0 {
        guard += 1;
        if guard > n + 4 {
            return None;
        }
        let node = nodes[pos];
        if !node.cost.is_finite() {
            return None;
        }
        let span = node.copy_len as usize + node.insert_len as usize;
        if span == 0 || span > pos {
            return None;
        }
        bounds.push((pos - span, pos, node));
        pos -= span;
    }
    bounds.reverse();
    Some(bounds)
}

/// Tally literal / command / distance histograms for the chosen path so
/// the next iteration can reprice. Resolves distances against the real
/// ring (mirroring `plan_commands`) to get accurate short-code stats.
fn histogram_path(
    payload: &[u8],
    nodes: &[Node],
    ring_start: DistRing,
) -> ([u32; 256], [u32; 704], [u32; 64]) {
    let mut lit_hist = [0u32; 256];
    let mut cmd_hist = [0u32; 704];
    let mut dist_hist = [0u32; 64];

    let bounds = match collect_path(payload, nodes) {
        Some(b) => b,
        None => return (lit_hist, cmd_hist, dist_hist),
    };

    let mut ring = ring_start;
    for (start, _end, node) in bounds {
        let ins = node.insert_len as usize;
        let copy_start = start + ins;
        for &b in &payload[start..copy_start] {
            lit_hist[b as usize] += 1;
        }
        if node.copy_len == 0 {
            let (ins_code, _, _) = insert_to_code(ins as u32);
            cmd_hist[ic_command_sym(ins_code, 0, false) as usize] += 1;
            continue;
        }
        let copy_field = if node.is_dict {
            node.dict_word_len as u32
        } else {
            node.copy_len
        };
        let (ins_code, _, _) = insert_to_code(ins as u32);
        let (copy_code, _, _) = copy_to_code(copy_field);
        cmd_hist[ic_command_sym(ins_code, copy_code, false) as usize] += 1;

        if node.is_dict {
            if let Some((dcode, _, _)) = distance_to_normal_code(node.dist) {
                dist_hist[dcode as usize] += 1;
            }
        } else {
            let d = node.dist;
            if let Some(short) = ring.try_short_code(d) {
                dist_hist[short as usize] += 1;
                if short != 0 {
                    ring.push(d as i32);
                }
            } else if let Some((dcode, _, _)) = distance_to_normal_code(d) {
                dist_hist[dcode as usize] += 1;
                ring.push(d as i32);
            }
        }
    }
    (lit_hist, cmd_hist, dist_hist)
}

/// Materialise the chosen path into `Command`s appended to `cmds`.
fn emit_path(
    payload: &[u8],
    nodes: &[Node],
    cmds: &mut Vec<Command>,
    insert_pool: &mut Vec<Vec<u8>>,
) {
    let bounds = match collect_path(payload, nodes) {
        Some(b) => b,
        None => {
            cmds.clear();
            return;
        }
    };

    for (start, _end, node) in bounds {
        let ins = node.insert_len as usize;
        let copy_start = start + ins;
        let mut buf = insert_pool.pop().unwrap_or_default();
        buf.clear();
        buf.extend_from_slice(&payload[start..copy_start]);
        if node.copy_len == 0 {
            cmds.push(Command {
                insert: buf,
                copy_len: 0,
                kind: CopyKind::None,
            });
        } else if node.is_dict {
            cmds.push(Command {
                insert: buf,
                copy_len: node.dict_word_len as u32,
                kind: CopyKind::Dict {
                    word_idx: node.dict_word_idx,
                    transform_id: node.dict_tr_id,
                    emit_len: node.copy_len,
                },
            });
        } else {
            cmds.push(Command {
                insert: buf,
                copy_len: node.copy_len,
                kind: CopyKind::Backref { distance: node.dist },
            });
        }
    }
}
