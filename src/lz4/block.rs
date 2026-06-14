//! LZ4 block-format codec (single-block, in-memory).
//!
//! Reference: <https://github.com/lz4/lz4/blob/dev/doc/lz4_Block_format.md>.
//!
//! These functions operate on a single LZ4 block: they take a complete input
//! buffer and produce a complete output buffer. The streaming wrapper in
//! [`super`] is responsible for chunking arbitrarily large inputs into blocks
//! of bounded size and re-assembling them on decode.
//!
//! Two parses share the same bitstream emitter, so every block — fast or
//! high-compression — decodes with the exact same decoder (ours and the
//! reference `lz4` tool):
//!
//! * The **fast** parse ([`encode_block`]) is a single-hash greedy matcher
//!   with LZ4's skip-step acceleration. It is the speed-crown path used for
//!   low levels.
//! * The **HC** parse ([`encode_block_level`] at higher levels) is an
//!   LZ4-HC-style match finder: a hash-chain (head + prev) walk that finds the
//!   *longest* match within the 64 KiB window, plus one-step lazy matching.
//!   Search depth scales with the level.

use alloc::vec::Vec;

use crate::error::Error;

/// Minimum match length encoded by an LZ4 sequence.
const MIN_MATCH: usize = 4;
/// Maximum back-reference distance (16-bit LE offset).
const MAX_DISTANCE: usize = 65_535;
/// Last 5 bytes of every block must be literals.
const LAST_LITERALS: usize = 5;
/// Last match must start at least 12 bytes before the end of the block.
const MFLIMIT: usize = 12;

/// Size of the fast encoder's hash table (entries are `u32` block offsets).
///
/// 12 bits = 4096 entries × 4 bytes = 16 KiB scratch — small enough to fit
/// comfortably in cache, large enough to find most useful matches in a
/// 64 KiB block.
const HASH_LOG: u32 = 12;
const HASH_TABLE_SIZE: usize = 1 << HASH_LOG;

/// Hash-table size for the HC (hash-chain) match finder. A wider table than
/// the fast path reduces collisions so chains stay short and on-topic, which
/// improves both match quality and the cost of the bounded chain walk.
const HC_HASH_LOG: u32 = 15;
const HC_HASH_TABLE_SIZE: usize = 1 << HC_HASH_LOG;

/// Sentinel for an empty hash slot. `u32::MAX` is safe because block sizes
/// are bounded by the streaming wrapper to fit in a `u32`.
const HASH_EMPTY: u32 = u32::MAX;

/// Lowest level that engages the HC (hash-chain + lazy) parse. Levels below
/// this use the fast greedy parse (preserving LZ4's speed crown).
const HC_LEVEL_THRESHOLD: u8 = 3;

/// Lowest level that engages the price-based optimal parse. Levels in
/// `HC_LEVEL_THRESHOLD..OPT_LEVEL_THRESHOLD` use the lazy HC parse; this level
/// and above run a forward dynamic-programming parse that minimises the
/// encoded byte cost.
const OPT_LEVEL_THRESHOLD: u8 = 10;

/// Hash 4 bytes down to `HASH_LOG` bits.
///
/// Uses the classic LZ4 multiply-and-shift hash. `2654435761` is Knuth's
/// golden-ratio constant — any good odd 32-bit multiplier works here.
#[inline]
fn hash4(bytes: [u8; 4]) -> usize {
    let v = u32::from_le_bytes(bytes);
    ((v.wrapping_mul(2_654_435_761)) >> (32 - HASH_LOG)) as usize
}

/// Hash 4 bytes down to `HC_HASH_LOG` bits (HC parse).
#[inline]
fn hc_hash4(bytes: [u8; 4]) -> usize {
    let v = u32::from_le_bytes(bytes);
    ((v.wrapping_mul(2_654_435_761)) >> (32 - HC_HASH_LOG)) as usize
}

/// Worst-case encoded-length bound for `input_len` bytes of input.
///
/// Matches the canonical `LZ4_compressBound` formula. The encoder uses this
/// to right-size its scratch buffer.
pub fn compress_bound(input_len: usize) -> usize {
    input_len + (input_len / 255) + 16
}

/// Encode `input` as a single LZ4 block into `out` (which is cleared first).
///
/// This is the fast greedy parse (low-level / default speed path). Inputs of
/// any length are accepted; inputs shorter than `MFLIMIT + 1` are emitted as a
/// literal-only sequence, as required by the spec.
pub fn encode_block(input: &[u8], out: &mut Vec<u8>) {
    out.clear();
    if input.is_empty() {
        return;
    }

    // Tiny inputs cannot contain a match satisfying the end-of-block rules
    // (last match start >= MFLIMIT before block end, last 5 bytes literals).
    if input.len() < MFLIMIT + 1 {
        emit_last_literals(input, out);
        return;
    }

    let mut table = [HASH_EMPTY; HASH_TABLE_SIZE];

    let mut ip: usize = 0; // current input position
    let mut anchor: usize = 0; // start of the current pending literal run

    // Position of the last byte we are allowed to start a match at. Anything
    // past `match_limit` must be emitted as trailing literals. (Note this is
    // the *match-start* bound, len - MFLIMIT, which is stricter than the
    // hashable bound len - MIN_MATCH - LAST_LITERALS — the spec forbids a
    // match starting in the final MFLIMIT bytes.)
    let match_limit = input.len() - MFLIMIT;

    // The first byte is never the start of a match in our matcher; insert it
    // into the table so subsequent positions can refer to it.
    let mut next_ip = ip;

    while next_ip <= match_limit {
        ip = next_ip;
        let mut step = 1usize;
        let mut search_match_nb = 1u32 << 6; // skip-step accelerator

        // Hash-table probe loop: walk forward until we find a 4-byte match or
        // run out of room. The probe step grows the further we search without
        // a hit — this is LZ4's "acceleration" trick: it makes the matcher
        // skip faster over incompressible data instead of probing every byte.
        let mut match_pos;
        loop {
            // A match may only *start* at or before `match_limit` (the spec
            // requires the last match to begin at least MFLIMIT bytes before
            // the block end). `hash_limit` (len - 4 - 5) is larger than
            // `match_limit` (len - 12), so bounding the probe at `hash_limit`
            // could find a match starting in the forbidden tail region — a
            // block the strict reference decoder rejects. Stop at
            // `match_limit`; the rest becomes trailing literals.
            if ip > match_limit {
                emit_last_literals(&input[anchor..], out);
                return;
            }
            let h = hash4([input[ip], input[ip + 1], input[ip + 2], input[ip + 3]]);
            let candidate = table[h];
            table[h] = ip as u32;

            // Found a candidate within the 64 KiB window with a real 4-byte
            // match? Take it.
            if candidate != HASH_EMPTY {
                let cand = candidate as usize;
                if ip - cand <= MAX_DISTANCE
                    && input[cand] == input[ip]
                    && input[cand + 1] == input[ip + 1]
                    && input[cand + 2] == input[ip + 2]
                    && input[cand + 3] == input[ip + 3]
                {
                    match_pos = cand;
                    break;
                }
            }
            next_ip = ip + step;
            step = (search_match_nb >> 6) as usize;
            search_match_nb += 1;
            ip = next_ip;
        }

        // We have ip and match_pos with a guaranteed 4-byte match. Try to
        // walk the match backward as far as the anchor (catch a longer match
        // when the hash hit fell on a misaligned start).
        while ip > anchor && match_pos > 0 && input[ip - 1] == input[match_pos - 1] {
            ip -= 1;
            match_pos -= 1;
        }

        // Extend the match forward. The forward limit is `input.len() -
        // LAST_LITERALS` because the last 5 bytes must be literals.
        let forward_limit = input.len() - LAST_LITERALS;
        let mut match_len = MIN_MATCH;
        while ip + match_len < forward_limit
            && input[match_pos + match_len] == input[ip + match_len]
        {
            match_len += 1;
        }

        // Emit the sequence: literals from anchor..ip, then offset, then
        // match-length excess.
        let literal_len = ip - anchor;
        let offset = (ip - match_pos) as u16;
        let match_excess = match_len - MIN_MATCH;
        emit_sequence(&input[anchor..ip], literal_len, offset, match_excess, out);

        ip += match_len;
        anchor = ip;

        // Seed the hash table for the byte two before the match end. This
        // helps the *next* probe find a longer back-reference without
        // pointing at the position we're about to probe ourselves (which
        // would yield a zero-distance match).
        if ip >= 2 {
            let seed = ip - 2;
            if seed + MIN_MATCH <= input.len() {
                let h = hash4([
                    input[seed],
                    input[seed + 1],
                    input[seed + 2],
                    input[seed + 3],
                ]);
                table[h] = seed as u32;
            }
        }
        next_ip = ip;
    }

    // Emit anything past the last match as literals.
    emit_last_literals(&input[anchor..], out);
}

/// Encode `input` as a single LZ4 block at compression `level`.
///
/// `level` selects the parse strategy and search effort:
///
/// * `level <` [`HC_LEVEL_THRESHOLD`] — delegate to the fast greedy
///   [`encode_block`] (LZ4's speed path).
/// * `level >=` [`HC_LEVEL_THRESHOLD`] — the HC parse: a hash-chain match
///   finder that searches up to `nb_attempts` candidates per position for the
///   *longest* match, plus one-step lazy matching. `nb_attempts` grows with
///   the level, so higher levels trade speed for ratio.
///
/// The emitted bitstream is byte-for-byte a valid LZ4 block in every case —
/// only the parse changes, so the reference `lz4` decoder reads it unchanged.
pub fn encode_block_level(input: &[u8], out: &mut Vec<u8>, level: u8) {
    if level < HC_LEVEL_THRESHOLD {
        encode_block(input, out);
        return;
    }
    if level < OPT_LEVEL_THRESHOLD {
        encode_block_hc(input, out, level);
        return;
    }
    encode_block_optimal(input, out, level);
}

/// Map a compression level to a hash-chain search depth (`nb_attempts`).
///
/// Depth roughly doubles every level, mirroring the spirit of reference
/// LZ4-HC: higher levels search deeper for the longest match. The window is
/// only 64 KiB so even the deepest setting stays bounded.
fn nb_attempts_for_level(level: u8) -> u32 {
    match level {
        0..=3 => 8,
        4 => 16,
        5 => 32,
        6 => 64,
        7 => 128,
        8 => 256,
        9 => 512,
        10 => 1024,
        11 => 2048,
        _ => 4096,
    }
}

/// Insert position `p` into the hash chain. The 4-byte read requires
/// `p + 4 <= input.len()`, guaranteed by the caller (`p <= hash_limit`).
#[inline]
fn hc_insert(input: &[u8], p: usize, head: &mut [u32], chain: &mut [u32]) {
    let h = hc_hash4([input[p], input[p + 1], input[p + 2], input[p + 3]]);
    chain[p] = head[h];
    head[h] = p as u32;
}

/// Find the longest match for the 4 bytes at `pos` by walking the hash chain.
///
/// Returns `(match_pos, match_len)` for the best forward match whose length is
/// at least `MIN_MATCH`, or `None`. Forward extension only — the caller applies
/// backward extension so it can clamp the start at the current anchor.
/// Candidates are strictly older positions on the chain, so self-matches are
/// impossible regardless of whether `pos` has been inserted yet.
fn hc_longest_match(
    input: &[u8],
    pos: usize,
    head: &[u32],
    chain: &[u32],
    nb_attempts: u32,
    forward_limit: usize,
) -> Option<(usize, usize)> {
    let h = hc_hash4([input[pos], input[pos + 1], input[pos + 2], input[pos + 3]]);
    let mut cand = head[h];
    let min_pos = pos.saturating_sub(MAX_DISTANCE);

    let mut best_len = MIN_MATCH - 1;
    let mut best_pos = 0usize;
    let mut attempts = nb_attempts;

    while cand != HASH_EMPTY && attempts > 0 {
        let c = cand as usize;
        if c >= pos {
            // Only older positions are valid back-references. (Can only happen
            // for a stale/self entry; skip defensively without trusting it.)
            cand = chain[c];
            attempts -= 1;
            continue;
        }
        if c < min_pos {
            break; // chain is ordered newest->oldest; we've left the window.
        }
        // Cheap reject: a longer match requires the byte at `best_len` to
        // agree (and the first byte, as a quick filter).
        if pos + best_len < forward_limit
            && input[c + best_len] == input[pos + best_len]
            && input[c] == input[pos]
        {
            let mut l = 0usize;
            while pos + l < forward_limit && input[c + l] == input[pos + l] {
                l += 1;
            }
            if l > best_len {
                best_len = l;
                best_pos = c;
                if pos + best_len >= forward_limit {
                    break; // cannot grow further
                }
            }
        }
        cand = chain[c];
        attempts -= 1;
    }

    if best_len < MIN_MATCH {
        None
    } else {
        Some((best_pos, best_len))
    }
}

/// Apply backward extension to a forward match `(match_pos, len)` found at
/// `pos`, sliding the start earlier while bytes agree, clamped so the start
/// never crosses `anchor`. Returns `(start, match_pos, len)`.
#[inline]
fn hc_resolve(
    input: &[u8],
    pos: usize,
    found: (usize, usize),
    anchor: usize,
) -> (usize, usize, usize) {
    let (mut mpos, mut mlen) = found;
    let mut spos = pos;
    while spos > anchor && mpos > 0 && input[spos - 1] == input[mpos - 1] {
        spos -= 1;
        mpos -= 1;
        mlen += 1;
    }
    (spos, mpos, mlen)
}

/// LZ4-HC-style match finder + parse (used for higher levels).
///
/// Maintains a hash-chain over 4-byte sequences (`head[hash]` = most recent
/// position; `chain[pos]` = previous position sharing that hash). For each
/// candidate start it walks the chain up to `nb_attempts` links and keeps the
/// longest match inside the 64 KiB window. A one-step lazy heuristic defers a
/// match when the next position offers a strictly longer one.
fn encode_block_hc(input: &[u8], out: &mut Vec<u8>, level: u8) {
    out.clear();
    if input.is_empty() {
        return;
    }
    if input.len() < MFLIMIT + 1 {
        emit_last_literals(input, out);
        return;
    }

    let n = input.len();
    let nb_attempts = nb_attempts_for_level(level);

    let mut head = alloc::vec![HASH_EMPTY; HC_HASH_TABLE_SIZE];
    let mut chain = alloc::vec![HASH_EMPTY; n];

    let match_limit = n - MFLIMIT; // last position a match may start at
    let hash_limit = n - MIN_MATCH - LAST_LITERALS; // last hashable position
    let forward_limit = n - LAST_LITERALS; // last 5 bytes stay literal

    // `inserted_through` is the count of positions already recorded in the
    // chain: positions [0, inserted_through) are inserted. We insert lazily so
    // each position is inserted exactly once and the chain stays strictly
    // ordered newest-first.
    let mut inserted_through: usize = 0;
    let mut anchor: usize = 0;
    let mut ip: usize = 0;

    // Insert all hashable positions in [inserted_through, up_to).
    macro_rules! insert_up_to {
        ($up_to:expr) => {{
            let up_to = $up_to;
            while inserted_through < up_to && inserted_through <= hash_limit {
                hc_insert(input, inserted_through, &mut head, &mut chain);
                inserted_through += 1;
            }
        }};
    }

    while ip <= match_limit && ip <= hash_limit {
        // Ensure positions up to and including `ip` are in the chain.
        insert_up_to!(ip + 1);

        let found = hc_longest_match(input, ip, &head, &chain, nb_attempts, forward_limit);
        let (mut cur_start, mut cur_mpos, mut cur_len) = match found {
            None => {
                ip += 1;
                continue;
            }
            Some(f) => hc_resolve(input, ip, f, anchor),
        };

        // One-step lazy matching: while the next position offers a strictly
        // longer match, defer (the current first byte becomes a literal) and
        // chase the better match from there.
        loop {
            let next = cur_start + 1;
            if next > match_limit || next > hash_limit {
                break;
            }
            insert_up_to!(next + 1);
            if let Some(f) =
                hc_longest_match(input, next, &head, &chain, nb_attempts, forward_limit)
            {
                let (ns, nmp, nl) = hc_resolve(input, next, f, anchor);
                if nl > cur_len {
                    cur_start = ns;
                    cur_mpos = nmp;
                    cur_len = nl;
                    continue;
                }
            }
            break;
        }

        // Emit literals [anchor, cur_start) followed by the match.
        let literal_len = cur_start - anchor;
        let offset = (cur_start - cur_mpos) as u16;
        let match_excess = cur_len - MIN_MATCH;
        emit_sequence(
            &input[anchor..cur_start],
            literal_len,
            offset,
            match_excess,
            out,
        );

        let match_end = cur_start + cur_len;
        // Insert every position the match covers so later matches can point
        // inside it. `insert_up_to!` skips any already inserted by the lazy
        // walk, keeping the chain strictly ordered.
        insert_up_to!(match_end);

        anchor = match_end;
        ip = match_end;
    }

    emit_last_literals(&input[anchor..], out);
}

/// Encoded byte cost of `litlen` literals, per the LZ4 token/run-length rules.
///
/// The literal payload is `litlen` bytes; if `litlen >= 15` the run-length
/// nibble overflows and one or more extension bytes are appended:
/// `1 + (litlen - 15) / 255`. The token nibble itself is billed once per
/// sequence (see [`sequence_overhead`]), not here.
#[inline]
fn literals_price(litlen: usize) -> usize {
    let mut price = litlen;
    if litlen >= 15 {
        price += 1 + (litlen - 15) / 255;
    }
    price
}

/// Marginal cost of extending a literal run from length `run` to `run + 1`:
/// always 1 byte for the new literal, plus 1 more whenever the new length
/// crosses a run-length extension boundary (15, then every 255 after).
#[inline]
fn marginal_literal_price(run: usize) -> usize {
    1 + (literals_price(run + 1) - literals_price(run) - 1)
}

/// Fixed per-sequence overhead beyond the coupled literals: 1 token byte +
/// 2 offset bytes, plus the match-length run-extension bytes once the match
/// length nibble overflows (`mlen >= 19`).
#[inline]
fn sequence_overhead(mlen: usize) -> usize {
    let mut price = 1 + 2; // token + 16-bit offset
    if mlen >= ML_MASK_PLUS_MIN {
        price += 1 + (mlen - ML_MASK_PLUS_MIN) / 255;
    }
    price
}

/// `ML_MASK (15) + MINMATCH (4)` — the match length at which the match-length
/// nibble first overflows into extension bytes.
const ML_MASK_PLUS_MIN: usize = 15 + MIN_MATCH;

/// Match length at or beyond which the optimal parse stops enumerating every
/// shorter length and simply takes the whole match. A match this long is
/// effectively always worth taking in full (3 bytes of overhead amortised over
/// 64+ bytes), and the cap keeps the per-position inner loop bounded so highly
/// repetitive inputs stay near-linear instead of O(n²). Mirrors the role of
/// `sufficient_len` in the reference LZ4-HC optimal parser.
const OPT_SUFFICIENT_LEN: usize = 64;

/// One step of the chosen parse path, recovered by backtracking the DP.
#[derive(Clone, Copy)]
struct OptStep {
    /// Length of the literal run preceding this position's incoming edge.
    litlen: usize,
    /// `match_pos` of the incoming match, or `usize::MAX` for a literal step.
    match_pos: usize,
    /// Match length of the incoming edge (0 for a literal step).
    match_len: usize,
}

/// Price-based optimal parse (top levels).
///
/// Runs a forward dynamic program over the block: `price[i]` is the minimal
/// encoded byte cost to reach position `i`. Each position can advance by a
/// single literal (marginal literal price, tracking the run length so the
/// run-length token overflow is charged accurately) or by any match found via
/// the hash-chain finder (sequence overhead + the literal run it terminates).
/// Backtracking recovers the cheapest path, which is then emitted with the
/// shared sequence emitter — so the bitstream stays a valid LZ4 block.
fn encode_block_optimal(input: &[u8], out: &mut Vec<u8>, level: u8) {
    out.clear();
    if input.is_empty() {
        return;
    }
    if input.len() < MFLIMIT + 1 {
        emit_last_literals(input, out);
        return;
    }

    let n = input.len();
    let nb_attempts = nb_attempts_for_level(level);

    let mut head = alloc::vec![HASH_EMPTY; HC_HASH_TABLE_SIZE];
    let mut chain = alloc::vec![HASH_EMPTY; n];

    let match_limit = n - MFLIMIT; // last position a match may start at
    let hash_limit = n - MIN_MATCH - LAST_LITERALS; // last hashable position
    let forward_limit = n - LAST_LITERALS; // last 5 bytes stay literal

    // DP arrays over positions 0..=n.
    // `price[i]` = min cost to encode input[0..i].
    // `run[i]` = literal-run length ending at i on the best path to i.
    // `step[i]` = the incoming edge used to reach i (for backtracking).
    let mut price = alloc::vec![usize::MAX; n + 1];
    let mut run = alloc::vec![0usize; n + 1];
    let mut step = alloc::vec![
        OptStep {
            litlen: 0,
            match_pos: usize::MAX,
            match_len: 0,
        };
        n + 1
    ];
    price[0] = 0;

    // Insert all positions up to `up_to` (exclusive) that are hashable.
    let mut inserted_through = 0usize;
    macro_rules! insert_up_to {
        ($up_to:expr) => {{
            let up_to = $up_to;
            while inserted_through < up_to && inserted_through <= hash_limit {
                hc_insert(input, inserted_through, &mut head, &mut chain);
                inserted_through += 1;
            }
        }};
    }

    let mut i = 0usize;
    while i < n {
        if price[i] == usize::MAX {
            i += 1;
            continue; // unreachable position
        }
        let cur_price = price[i];
        let cur_run = run[i];

        // Literal edge: advance one byte, extending the literal run.
        {
            let lit_cost = cur_price + marginal_literal_price(cur_run);
            if lit_cost < price[i + 1] {
                price[i + 1] = lit_cost;
                run[i + 1] = cur_run + 1;
                step[i + 1] = OptStep {
                    litlen: cur_run + 1,
                    match_pos: usize::MAX,
                    match_len: 0,
                };
            }
        }

        // Match edges: only valid starting positions can begin a match, and
        // only where a 4-byte hash is readable.
        if i > match_limit || i > hash_limit {
            i += 1;
            continue;
        }
        insert_up_to!(i + 1);
        let found = hc_longest_match(input, i, &head, &chain, nb_attempts, forward_limit);
        let (best_pos, best_len) = match found {
            Some(f) => f,
            None => {
                i += 1;
                continue;
            }
        };

        // The literal run that *would* precede this match was already paid for
        // in `cur_price`/`cur_run`. Emitting a match terminates that run, so
        // the new sequence's coupled-literal price equals what we already
        // charged for the run — i.e. taking the match adds only the sequence
        // overhead. (The token nibble that also encodes the literal length is
        // the single token byte we add here.)
        //
        // For a sufficiently long match, shorter splits are never preferable:
        // record the full-length edge, insert the positions it covers so later
        // matches can chain inside it, and fast-forward past the interior. This
        // keeps highly-repetitive inputs near-linear (no O(n²) DP sweep), while
        // the global DP still chooses among long matches and literal runs.
        if best_len >= OPT_SUFFICIENT_LEN {
            let end = i + best_len;
            let cost = cur_price + sequence_overhead(best_len);
            if cost < price[end] {
                price[end] = cost;
                run[end] = 0;
                step[end] = OptStep {
                    litlen: cur_run,
                    match_pos: best_pos,
                    match_len: best_len,
                };
            }
            insert_up_to!(end);
            i = end;
            continue;
        }

        // Short match: enumerate every length in [MIN_MATCH, best_len]; a
        // shorter match can line up a cheaper continuation, which is exactly
        // what the DP weighs.
        for mlen in MIN_MATCH..=best_len {
            let end = i + mlen;
            if end > n {
                break;
            }
            let cost = cur_price + sequence_overhead(mlen);
            if cost < price[end] {
                price[end] = cost;
                run[end] = 0;
                step[end] = OptStep {
                    litlen: cur_run,
                    match_pos: best_pos,
                    match_len: mlen,
                };
            }
        }
        i += 1;
    }

    // Backtrack from n to 0, collecting the path edges in reverse.
    let mut path: Vec<OptStep> = Vec::new();
    let mut pos = n;
    while pos > 0 {
        let s = step[pos];
        if s.match_pos == usize::MAX {
            // Literal edge: step back one byte. Collapse a contiguous literal
            // run into the match step that follows; here we just step.
            pos -= 1;
        } else {
            path.push(s);
            pos -= s.match_len;
        }
    }
    path.reverse();

    // Replay forward, emitting literals then each match.
    let mut anchor = 0usize;
    for s in &path {
        let match_start = {
            // The match's start position is the end-of-literal-run point. We
            // reconstruct it from the literal run length recorded on the edge.
            anchor + s.litlen
        };
        let offset = (match_start - s.match_pos) as u16;
        let match_excess = s.match_len - MIN_MATCH;
        emit_sequence(
            &input[anchor..match_start],
            s.litlen,
            offset,
            match_excess,
            out,
        );
        anchor = match_start + s.match_len;
    }
    emit_last_literals(&input[anchor..], out);
}

/// Write a single sequence (literals + offset + match-length excess).
fn emit_sequence(
    literals: &[u8],
    literal_len: usize,
    offset: u16,
    match_excess: usize,
    out: &mut Vec<u8>,
) {
    let lit_high = if literal_len >= 15 {
        15u8
    } else {
        literal_len as u8
    };
    let match_low = if match_excess >= 15 {
        15u8
    } else {
        match_excess as u8
    };
    let token = (lit_high << 4) | match_low;
    out.push(token);

    if literal_len >= 15 {
        let mut rem = literal_len - 15;
        while rem >= 255 {
            out.push(255);
            rem -= 255;
        }
        out.push(rem as u8);
    }
    out.extend_from_slice(literals);

    out.push((offset & 0xFF) as u8);
    out.push((offset >> 8) as u8);

    if match_excess >= 15 {
        let mut rem = match_excess - 15;
        while rem >= 255 {
            out.push(255);
            rem -= 255;
        }
        out.push(rem as u8);
    }
}

/// Emit the closing literal-only sequence (no offset, no match-length).
fn emit_last_literals(literals: &[u8], out: &mut Vec<u8>) {
    let literal_len = literals.len();
    let lit_high = if literal_len >= 15 {
        15u8
    } else {
        literal_len as u8
    };
    out.push(lit_high << 4);
    if literal_len >= 15 {
        let mut rem = literal_len - 15;
        while rem >= 255 {
            out.push(255);
            rem -= 255;
        }
        out.push(rem as u8);
    }
    out.extend_from_slice(literals);
}

/// Decode one LZ4 block from `input` into `out`.
///
/// `out` is cleared first; on success it contains the decompressed bytes.
///
/// `raw_max` bounds the decoded output: a single LZ4 block can expand a
/// match-copy by up to ~255×, so without a ceiling a small malicious block
/// could be coaxed into a multi-gigabyte allocation (decompression bomb).
/// Any literal or match append that would push `out.len()` past `raw_max`
/// returns [`Error::Corrupt`].
pub fn decode_block(input: &[u8], out: &mut Vec<u8>, raw_max: usize) -> Result<(), Error> {
    out.clear();
    if input.is_empty() {
        return Ok(());
    }
    let mut ip = 0usize;
    let n = input.len();

    loop {
        if ip >= n {
            return Err(Error::UnexpectedEnd);
        }
        let token = input[ip];
        ip += 1;

        // Literal length
        let mut lit_len = (token >> 4) as usize;
        if lit_len == 15 {
            loop {
                if ip >= n {
                    return Err(Error::UnexpectedEnd);
                }
                let b = input[ip];
                ip += 1;
                lit_len = lit_len.checked_add(b as usize).ok_or(Error::Corrupt)?;
                if b != 255 {
                    break;
                }
            }
        }

        if lit_len > 0 {
            if ip + lit_len > n {
                return Err(Error::UnexpectedEnd);
            }
            if out.len() + lit_len > raw_max {
                return Err(Error::Corrupt);
            }
            out.extend_from_slice(&input[ip..ip + lit_len]);
            ip += lit_len;
        }

        // End of block: if no offset bytes follow, this was the closing
        // literal-only sequence.
        if ip == n {
            return Ok(());
        }
        if ip + 2 > n {
            return Err(Error::UnexpectedEnd);
        }
        let offset = (input[ip] as usize) | ((input[ip + 1] as usize) << 8);
        ip += 2;
        if offset == 0 {
            return Err(Error::InvalidDistance);
        }
        if offset > out.len() {
            return Err(Error::InvalidDistance);
        }

        let mut match_excess = (token & 0x0F) as usize;
        if match_excess == 15 {
            loop {
                if ip >= n {
                    return Err(Error::UnexpectedEnd);
                }
                let b = input[ip];
                ip += 1;
                match_excess = match_excess.checked_add(b as usize).ok_or(Error::Corrupt)?;
                if b != 255 {
                    break;
                }
            }
        }
        let match_len = MIN_MATCH + match_excess;
        if out.len() + match_len > raw_max {
            return Err(Error::Corrupt);
        }

        // Non-overlapping match collapses to memcpy; offset==1 is a byte-splat;
        // otherwise replicate in `offset`-sized chunks to handle LZ77
        // self-overlap while still copying in bulk.
        let start = out.len() - offset;
        if offset >= match_len {
            out.extend_from_within(start..start + match_len);
        } else if offset == 1 {
            let b = out[start];
            out.resize(out.len() + match_len, b);
        } else {
            // Overlapping: each round copies the `offset`-byte tail produced so
            // far. The source region doubles every round, so the number of
            // rounds is logarithmic in `match_len`.
            let mut remaining = match_len;
            while remaining > 0 {
                let chunk = remaining.min(offset);
                let s = out.len() - offset;
                out.extend_from_within(s..s + chunk);
                remaining -= chunk;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(data: &[u8]) {
        let mut encoded = Vec::new();
        encode_block(data, &mut encoded);
        let mut decoded = Vec::new();
        decode_block(&encoded, &mut decoded, usize::MAX).expect("decode");
        assert_eq!(decoded, data);
    }

    fn round_trip_level(data: &[u8], level: u8) {
        let mut encoded = Vec::new();
        encode_block_level(data, &mut encoded, level);
        let mut decoded = Vec::new();
        decode_block(&encoded, &mut decoded, usize::MAX).expect("decode");
        assert_eq!(decoded, data, "round-trip mismatch at level {level}");
    }

    #[test]
    fn empty() {
        round_trip(&[]);
    }

    #[test]
    fn short() {
        round_trip(b"hello");
    }

    #[test]
    fn run() {
        let v = alloc::vec![b'a'; 1024];
        round_trip(&v);
    }

    #[test]
    fn repeated_text() {
        let mut v = Vec::new();
        for _ in 0..200 {
            v.extend_from_slice(b"the quick brown fox jumps over the lazy dog. ");
        }
        round_trip(&v);
    }

    #[test]
    fn hc_round_trip_all_levels() {
        let mut text = Vec::new();
        for _ in 0..200 {
            text.extend_from_slice(b"the quick brown fox jumps over the lazy dog. ");
        }
        // Pseudo-random data exercises the no-match / chain-miss paths.
        let mut prng = Vec::new();
        let mut s: u32 = 0x1234_5678;
        for _ in 0..8192 {
            s = s.wrapping_mul(1_103_515_245).wrapping_add(12345);
            prng.push((s >> 16) as u8);
        }
        for level in 0..=12u8 {
            round_trip_level(&text, level);
            round_trip_level(b"hello", level);
            round_trip_level(&[], level);
            round_trip_level(&alloc::vec![b'x'; 5000], level);
            round_trip_level(&prng, level);
        }
    }

    #[test]
    fn hc_not_worse_than_fast() {
        let mut v = Vec::new();
        for i in 0..5000u32 {
            v.extend_from_slice(&i.to_le_bytes());
            v.extend_from_slice(b"common suffix string here ");
        }
        let mut fast = Vec::new();
        encode_block(&v, &mut fast);
        let mut hc = Vec::new();
        encode_block_level(&v, &mut hc, 9);
        assert!(
            hc.len() <= fast.len(),
            "hc {} should be <= fast {}",
            hc.len(),
            fast.len()
        );
    }

    /// Walk an encoded block and assert it obeys the strict end-of-block rules
    /// the reference `lz4` decoder enforces: the last 5 bytes are literals, and
    /// no match starts within the final `MFLIMIT` (12) bytes of the block.
    ///
    /// `raw_len` is the decoded length (so we can compute output positions).
    fn assert_eob_rules(encoded: &[u8], raw_len: usize) {
        if encoded.is_empty() {
            assert_eq!(raw_len, 0);
            return;
        }
        let mut i = 0usize;
        let mut outpos = 0usize;
        let n = encoded.len();
        loop {
            let token = encoded[i];
            i += 1;
            let mut lit = (token >> 4) as usize;
            if lit == 15 {
                loop {
                    let b = encoded[i];
                    i += 1;
                    lit += b as usize;
                    if b != 255 {
                        break;
                    }
                }
            }
            i += lit;
            outpos += lit;
            if i == n {
                // Closing literal-only sequence: the spec requires the final
                // run be at least LAST_LITERALS bytes (unless the whole block
                // is shorter than that).
                if raw_len >= LAST_LITERALS {
                    assert!(
                        lit >= LAST_LITERALS,
                        "final literal run {lit} < {LAST_LITERALS}"
                    );
                }
                break;
            }
            // A match follows. Its start in the decoded stream is `outpos`.
            let match_start = outpos;
            assert!(
                match_start + MFLIMIT <= raw_len,
                "match starts at {match_start}, within MFLIMIT of end {raw_len}"
            );
            i += 2; // offset
            let mut ml = (token & 0x0F) as usize;
            if ml == 15 {
                loop {
                    let b = encoded[i];
                    i += 1;
                    ml += b as usize;
                    if b != 255 {
                        break;
                    }
                }
            }
            ml += MIN_MATCH;
            outpos += ml;
        }
        assert_eq!(outpos, raw_len, "decoded length mismatch");
    }

    #[test]
    fn end_of_block_rules_all_levels() {
        // Construct an input whose best parse lands a match right up against
        // the end of the block — exactly the case that previously produced a
        // block the reference decoder rejected (a match starting inside the
        // final MFLIMIT bytes).
        let mut v = Vec::new();
        for _ in 0..400 {
            v.extend_from_slice(b"alpha beta gamma delta epsilon ");
        }
        // Append a tail that repeats earlier content so a match is tempting at
        // the very end.
        v.extend_from_slice(b"alpha beta gamma delta epsilon");

        for level in 0..=12u8 {
            let mut enc = Vec::new();
            encode_block_level(&v, &mut enc, level);
            assert_eob_rules(&enc, v.len());
            // And it must still round-trip.
            let mut dec = Vec::new();
            decode_block(&enc, &mut dec, usize::MAX).expect("decode");
            assert_eq!(dec, v, "round-trip at level {level}");
        }
    }
}
