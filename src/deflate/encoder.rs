//! Streaming RFC 1951 deflate encoder.
//!
//! Maintains a sliding window of up to 32 KiB of history plus the current
//! lookahead. Per block (target ~16 KiB of fresh input): runs LZ77 over the
//! lookahead with **lazy matching** (gzip's `--max-lazy` heuristic) to
//! produce a sequence of literals and (length, distance) matches; then
//! chooses the cheapest of three block encodings (stored, fixed Huffman, or
//! dynamic Huffman) and emits it.
//!
//! Cross-block matching: the hash chain is keyed by absolute positions and
//! is **not** reset between blocks, so back-references reach into earlier
//! blocks (up to the 32 KiB window).

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::bits::{BitWriter, reverse_bits};
use crate::error::Error;
use crate::huffman::{canonical_codes_from_lengths, length_limited_huffman};
use crate::traits::{RawEncoder, RawProgress};

use super::lz77::MatchFinder;
use super::tables::{
    CODE_LENGTH_ORDER, DIST_BASE, DIST_EXTRA, END_OF_BLOCK, FIXED_DIST_LENGTHS, FIXED_LIT_LENGTHS,
    LENGTH_BASE, LENGTH_EXTRA, MAX_MATCH, MIN_MATCH, WINDOW_SIZE,
};

/// How many fresh bytes we try to gather before flushing a block. zlib uses
/// a similar block-size target around 16 KiB.
const BLOCK_SIZE: usize = 16 * 1024;

/// Maximum size the window buffer is allowed to grow before we slide. Keeping
/// up to 2×WINDOW_SIZE means we slide at most once per BLOCK_SIZE worth of
/// input, which amortises the memmove cost.
const WINDOW_MAX: usize = 2 * WINDOW_SIZE;

// ─── compression level ──────────────────────────────────────────────────

/// Tunables for the deflate encoder.
///
/// `level` controls the speed/ratio trade-off: `1` is fastest and produces
/// the largest output, `9` is slowest and produces the smallest output. The
/// default of `6` mirrors zlib's default and is a reasonable starting point
/// for most use cases.
///
/// Values outside `1..=9` are clamped at encoder construction time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncoderConfig {
    /// Compression level in `1..=9`.
    pub level: u8,
}

impl Default for EncoderConfig {
    fn default() -> Self {
        Self { level: 6 }
    }
}

/// Internal expansion of [`EncoderConfig::level`] into the match-finder
/// tuning knobs the LZ77 pass actually consults. The table mirrors zlib's
/// `configuration_table`: higher levels widen the chain budget and raise
/// the "nice match" / "good match" thresholds, trading CPU for ratio.
#[derive(Debug, Clone, Copy)]
struct LevelParams {
    /// Maximum number of hash-chain links the match finder walks.
    max_chain: usize,
    /// Length at which the match finder stops looking for a longer candidate.
    nice_match: usize,
    /// Length at which lazy matching considers the current match "good
    /// enough" and quarters the chain budget on the lookahead probe.
    good_match: usize,
    /// Whether to perform lazy matching at all. Levels 1..=3 skip it
    /// entirely (greedy parsing) to save the per-position probe.
    use_lazy: bool,
}

impl LevelParams {
    /// Clamp `level` to `1..=9` and expand to the matching tuning knobs.
    fn from_level(level: u8) -> Self {
        // Clamp instead of returning Err — keeping the public surface
        // infallible matches zlib's behaviour of silently snapping Z_BEST_*
        // values into range.
        let level = level.clamp(1, 9);
        // Mirrors zlib's configuration_table: (good_length, max_lazy/nice,
        // nice_length, max_chain) tuned per level. We collapse the
        // greedy-vs-lazy switch into a single `use_lazy` flag; zlib does
        // the same internally via `func == fast`.
        match level {
            1 => Self {
                max_chain: 4,
                nice_match: 8,
                good_match: 4,
                use_lazy: false,
            },
            2 => Self {
                max_chain: 8,
                nice_match: 16,
                good_match: 5,
                use_lazy: false,
            },
            3 => Self {
                max_chain: 32,
                nice_match: 32,
                good_match: 6,
                use_lazy: false,
            },
            4 => Self {
                max_chain: 16,
                nice_match: 16,
                good_match: 4,
                use_lazy: true,
            },
            5 => Self {
                max_chain: 32,
                nice_match: 32,
                good_match: 8,
                use_lazy: true,
            },
            6 => Self {
                max_chain: 128,
                nice_match: 128,
                good_match: 16,
                use_lazy: true,
            },
            7 => Self {
                max_chain: 256,
                nice_match: 128,
                good_match: 32,
                use_lazy: true,
            },
            8 => Self {
                max_chain: 1024,
                nice_match: 258,
                good_match: 32,
                use_lazy: true,
            },
            // 9 (and clamp-from-above)
            _ => Self {
                max_chain: 4096,
                nice_match: 258,
                good_match: 32,
                use_lazy: true,
            },
        }
    }
}

// ─── helpers for the length/distance -> code mapping ─────────────────────

// ─── precomputed fixed Huffman tables (const) ───────────────────────────
//
// The fixed-Huffman code lengths in `FIXED_LIT_LENGTHS` / `FIXED_DIST_LENGTHS`
// never change, so we can precompute the canonical codes, bit-reverse them
// once, and stash both alongside the lengths as `u32` arrays. The encoder
// then writes a fixed-Huffman literal/length with one table lookup instead
// of `canonical_codes_from_lengths` + `reverse_bits` per symbol.

const FIXED_LIT_REV: [u32; 288] = compute_canonical_reversed::<288>(&FIXED_LIT_LENGTHS);
const FIXED_DIST_REV: [u32; 32] = compute_canonical_reversed::<32>(&FIXED_DIST_LENGTHS);

/// Compile-time canonical-code generator that also bit-reverses each code so
/// the encoder can write it LSB-first without a runtime reverse.
const fn compute_canonical_reversed<const N: usize>(lengths: &[u8; N]) -> [u32; N] {
    let mut count = [0u32; 16];
    let mut i = 0;
    while i < N {
        let l = lengths[i] as usize;
        if l > 0 {
            count[l] += 1;
        }
        i += 1;
    }
    let mut next_code = [0u32; 16];
    let mut code: u32 = 0;
    let mut bits = 1;
    while bits <= 15 {
        code = (code + count[bits - 1]) << 1;
        next_code[bits] = code;
        bits += 1;
    }
    let mut out = [0u32; N];
    let mut i = 0;
    while i < N {
        let len = lengths[i] as u32;
        if len > 0 {
            let c = next_code[len as usize];
            // Reverse the low `len` bits of `c`.
            let mut v = c;
            let mut rev: u32 = 0;
            let mut j = 0;
            while j < len {
                rev = (rev << 1) | (v & 1);
                v >>= 1;
                j += 1;
            }
            out[i] = rev;
            next_code[len as usize] = c + 1;
        }
        i += 1;
    }
    out
}

/// Maps a match length in 3..=258 to its base code (subtract 257 to get
/// `LENGTH_BASE`/`LENGTH_EXTRA` index). Built at compile time.
const LENGTH_CODE_OFFSET: [u8; 256] = {
    let mut t = [0u8; 256];
    let mut len = MIN_MATCH;
    while len <= MAX_MATCH {
        let mut c = 0usize;
        while c < 28 && (LENGTH_BASE[c + 1] as usize) <= len {
            c += 1;
        }
        t[len - MIN_MATCH] = c as u8;
        len += 1;
    }
    t
};

/// Maps a distance in 1..=512 to its base code. For distances above 512 we
/// fall through to a short linear scan. Built at compile time. Indexed
/// `[distance - 1]`.
const SMALL_DIST_CODE: [u8; 512] = {
    let mut t = [0u8; 512];
    let mut d = 1u16;
    while d <= 512 {
        let mut c = 0usize;
        while c < 29 && DIST_BASE[c + 1] <= d {
            c += 1;
        }
        t[(d - 1) as usize] = c as u8;
        d += 1;
    }
    t
};

#[inline(always)]
fn length_to_code(length: u16) -> (u16, u16, u8) {
    let l = (length as usize) - MIN_MATCH;
    let c = LENGTH_CODE_OFFSET[l] as usize;
    let code = c as u16 + 257;
    let extra_value = length - LENGTH_BASE[c];
    let extra_bits = LENGTH_EXTRA[c];
    (code, extra_value, extra_bits)
}

#[inline(always)]
fn distance_to_code(distance: u16) -> (u16, u16, u8) {
    // Fast path: distances 1..=512 cover the bulk of real inputs (32 KiB
    // window, but English text and binary structures tend to back-reference
    // recent bytes) — one table lookup, no branches.
    let c = if distance <= 512 {
        SMALL_DIST_CODE[(distance - 1) as usize] as usize
    } else {
        // 30 candidates; small enough for a linear scan from the top.
        let mut c = 29usize;
        while c > 0 && distance < DIST_BASE[c] {
            c -= 1;
        }
        c
    };
    let extra_value = distance - DIST_BASE[c];
    let extra_bits = DIST_EXTRA[c];
    (c as u16, extra_value, extra_bits)
}

// ─── per-block symbol stream ─────────────────────────────────────────────

#[derive(Clone, Copy)]
enum Symbol {
    Literal(u8),
    Match { length: u16, distance: u16 },
}

// ─── code-length RLE encoding (RFC 1951 §3.2.7) ──────────────────────────

#[derive(Clone, Copy)]
struct ClSymbol {
    sym: u8,          // 0..=18
    extra_value: u16, // 0..=127
    extra_bits: u8,   // 0, 2, 3, or 7
}

fn rle_encode_lengths_into(lengths: &[u8], out: &mut Vec<ClSymbol>) {
    out.clear();
    let mut i = 0usize;
    while i < lengths.len() {
        let cur = lengths[i];
        // Count consecutive identical values.
        let mut run = 1usize;
        while i + run < lengths.len() && lengths[i + run] == cur {
            run += 1;
        }

        if cur == 0 {
            // Zero runs use codes 17 (3..=10 zeros) and 18 (11..=138 zeros).
            let mut left = run;
            while left > 0 {
                if left >= 11 {
                    let n = left.min(138);
                    out.push(ClSymbol {
                        sym: 18,
                        extra_value: (n - 11) as u16,
                        extra_bits: 7,
                    });
                    left -= n;
                } else if left >= 3 {
                    out.push(ClSymbol {
                        sym: 17,
                        extra_value: (left - 3) as u16,
                        extra_bits: 3,
                    });
                    left = 0;
                } else {
                    out.push(ClSymbol {
                        sym: 0,
                        extra_value: 0,
                        extra_bits: 0,
                    });
                    left -= 1;
                }
            }
        } else {
            // Always emit the first occurrence literally; code 16 ("repeat
            // previous") covers the next 3..=6 occurrences.
            out.push(ClSymbol {
                sym: cur,
                extra_value: 0,
                extra_bits: 0,
            });
            let mut left = run - 1;
            while left >= 3 {
                let n = left.min(6);
                out.push(ClSymbol {
                    sym: 16,
                    extra_value: (n - 3) as u16,
                    extra_bits: 2,
                });
                left -= n;
            }
            while left > 0 {
                out.push(ClSymbol {
                    sym: cur,
                    extra_value: 0,
                    extra_bits: 0,
                });
                left -= 1;
            }
        }

        i += run;
    }
}

// ─── cost estimation (in bits) ──────────────────────────────────────────

/// Estimate the bit cost of emitting `symbols` (plus EOB) with code lengths
/// `lit_lengths` and `dist_lengths`. Used to compare encoding choices.
fn payload_cost_bits(symbols: &[Symbol], lit_lengths: &[u8], dist_lengths: &[u8]) -> u64 {
    let mut bits: u64 = 0;
    for s in symbols {
        match s {
            Symbol::Literal(b) => {
                bits += lit_lengths[*b as usize] as u64;
            }
            Symbol::Match { length, distance } => {
                let (lc, _, leb) = length_to_code(*length);
                bits += lit_lengths[lc as usize] as u64 + leb as u64;
                let (dc, _, deb) = distance_to_code(*distance);
                bits += dist_lengths[dc as usize] as u64 + deb as u64;
            }
        }
    }
    bits += lit_lengths[END_OF_BLOCK as usize] as u64;
    bits
}

// ─── encoder state ───────────────────────────────────────────────────────

enum EncState {
    Accepting,
    Emitting,
    Done,
}

pub struct Encoder {
    /// Rolling buffer of input bytes since the last slide. Holds at most
    /// `WINDOW_MAX` bytes; once the prefix older than the current cursor
    /// exceeds WINDOW_SIZE, we drop bytes from the front.
    window: Vec<u8>,
    /// Index in `window` of the next byte to compress.
    cursor: usize,
    /// Absolute byte position corresponding to `window[0]`.
    window_start_abs: u64,
    match_finder: Box<MatchFinder>,
    /// Pending symbols for the current block.
    block_symbols: Vec<Symbol>,
    /// Pending raw bytes (literals + match-expansion) for the current block,
    /// kept so we can fall back to a stored encoding cheaply.
    block_bytes: Vec<u8>,
    bit_writer: BitWriter,
    out_buffer: Vec<u8>,
    out_pos: usize,
    state: EncState,
    /// True once we've emitted a BFINAL=1 block; finish() will not produce more.
    final_emitted: bool,
    /// Match-finder tuning derived from [`EncoderConfig::level`]. Persisted
    /// across `reset` since configuration is meant to survive resets.
    params: LevelParams,

    // ─── reusable scratch buffers (avoid per-block allocation) ───
    /// Literal/length code frequencies for the current block.
    lit_freq: [u32; 286],
    /// Distance code frequencies for the current block.
    dist_freq: [u32; 30],
    /// Code lengths for literal/length alphabet (dynamic block).
    lit_lengths: [u8; 286],
    /// Code lengths for distance alphabet (dynamic block).
    dist_lengths: [u8; 30],
    /// Code lengths for the code-length alphabet (dynamic block header).
    cl_lengths: [u8; 19],
    /// Code-length-code frequencies (dynamic block header).
    cl_freq: [u32; 19],
    /// Reused RLE buffer for the dynamic-Huffman header.
    rle_buf: Vec<ClSymbol>,
    /// Reused buffer for `combined = lit_lengths ++ dist_lengths` in the
    /// dynamic-Huffman header RLE.
    combined_lengths: Vec<u8>,
    /// Number of literal/length code lengths (after trimming trailing zeros).
    hlit_count: usize,
    /// Number of distance code lengths (after trimming trailing zeros).
    hdist_count: usize,
    /// Number of code-length codes emitted in CODE_LENGTH_ORDER.
    hclen_count: usize,
}

impl Encoder {
    /// Build an encoder at the default compression level (6).
    pub fn new() -> Self {
        Self::with_config(EncoderConfig::default())
    }

    /// Build an encoder with explicit configuration. `config.level` is
    /// clamped to `1..=9` internally — out-of-range values are snapped to
    /// the nearest valid level rather than rejected.
    pub fn with_config(config: EncoderConfig) -> Self {
        Self {
            window: Vec::with_capacity(WINDOW_MAX),
            cursor: 0,
            window_start_abs: 0,
            match_finder: Box::new(MatchFinder::new()),
            block_symbols: Vec::new(),
            block_bytes: Vec::new(),
            bit_writer: BitWriter::new(),
            out_buffer: Vec::new(),
            out_pos: 0,
            state: EncState::Accepting,
            final_emitted: false,
            params: LevelParams::from_level(config.level),
            lit_freq: [0u32; 286],
            dist_freq: [0u32; 30],
            lit_lengths: [0u8; 286],
            dist_lengths: [0u8; 30],
            cl_lengths: [0u8; 19],
            cl_freq: [0u32; 19],
            rle_buf: Vec::new(),
            combined_lengths: Vec::new(),
            hlit_count: 0,
            hdist_count: 0,
            hclen_count: 0,
        }
    }

    /// Drain accumulated block bytes into the caller's output. Returns true
    /// when the current `out_buffer` has been fully forwarded.
    fn drain(&mut self, output: &mut [u8], written: &mut usize) -> bool {
        while self.out_pos < self.out_buffer.len() && *written < output.len() {
            output[*written] = self.out_buffer[self.out_pos];
            self.out_pos += 1;
            *written += 1;
        }
        self.out_pos >= self.out_buffer.len()
    }

    /// Slide the window if we've accumulated too much history. Drops the
    /// oldest prefix so the kept buffer is at most WINDOW_SIZE + lookahead.
    fn maybe_slide(&mut self) {
        // We slide once the back-history exceeds WINDOW_SIZE — keeping
        // exactly WINDOW_SIZE bytes of history is enough for any in-window
        // distance to be reachable.
        if self.cursor > WINDOW_SIZE {
            let drop = self.cursor - WINDOW_SIZE;
            self.window.drain(..drop);
            self.cursor -= drop;
            self.window_start_abs += drop as u64;
        }
    }

    /// Run LZ77 over `window[cursor..end]`, appending the result to
    /// `block_symbols` and `block_bytes`. Advances `cursor`. Uses greedy
    /// parsing when `params.use_lazy` is false (low levels) and gzip-style
    /// lazy matching otherwise.
    fn lz77_pass(&mut self, end: usize) {
        let abs_base = self.window_start_abs;
        let max_chain = self.params.max_chain;
        let nice_match = self.params.nice_match;
        let good_match = self.params.good_match;
        let use_lazy = self.params.use_lazy;
        let mut pos = self.cursor;

        // Lazy-matching state: at any iteration we may have a "pending"
        // best match starting at `prev_match_start` that we haven't
        // committed yet — we hold it back to see if the next position
        // offers something strictly better. With greedy parsing
        // (`use_lazy = false`) this branch is never taken.
        let mut have_pending = false;
        let mut prev_match_len: usize = 0;
        let mut prev_match_dist: usize = 0;
        let mut prev_match_start: usize = 0;

        while pos < end {
            // Splice the 3-gram starting at `pos` into the hash chain.
            if pos + 3 <= self.window.len() {
                let abs = abs_base + pos as u64;
                self.match_finder.insert(
                    abs as u32,
                    self.window[pos],
                    self.window[pos + 1],
                    self.window[pos + 2],
                );
            }

            // Find the best match at `pos`.
            let cur = if pos + MIN_MATCH <= end {
                let abs = abs_base + pos as u64;
                // If we already hold a long-enough pending match, the
                // lookahead probe gets a smaller chain budget.
                let have_good = have_pending && prev_match_len >= good_match;
                self.match_finder
                    .find_match(
                        &self.window,
                        pos,
                        abs as u32,
                        have_good,
                        max_chain,
                        nice_match,
                    )
                    .map(|(l, d)| (l as usize, d as usize))
            } else {
                None
            };

            if have_pending {
                // We have a match from `prev_match_start`. Decide whether
                // to keep it or drop it in favour of `cur`.
                let strictly_better = match cur {
                    Some((cl, _)) => cl > prev_match_len,
                    None => false,
                };
                if strictly_better {
                    // Emit a literal at the previous position, advance one
                    // byte, and replace pending with `cur`.
                    let lit = self.window[prev_match_start];
                    self.block_symbols.push(Symbol::Literal(lit));
                    self.block_bytes.push(lit);
                    // Drop the old pending; the new pending is `cur` at `pos`.
                    let (cl, cd) = cur.unwrap();
                    prev_match_len = cl;
                    prev_match_dist = cd;
                    prev_match_start = pos;
                    have_pending = true;
                    pos += 1;
                } else {
                    // Commit the pending match. Insert every interior
                    // position of the match so later code can reference
                    // into the middle, then jump past it.
                    self.block_symbols.push(Symbol::Match {
                        length: prev_match_len as u16,
                        distance: prev_match_dist as u16,
                    });
                    self.block_bytes.extend_from_slice(
                        &self.window[prev_match_start..prev_match_start + prev_match_len],
                    );
                    // Insert positions [prev_match_start+1 .. prev_match_start+prev_match_len)
                    // We already inserted `prev_match_start` and `pos` (=prev_match_start+1).
                    // So insert from `pos+1` upward.
                    let match_end = prev_match_start + prev_match_len;
                    let mut k = pos + 1;
                    while k < match_end {
                        if k + 3 <= self.window.len() {
                            let abs = abs_base + k as u64;
                            self.match_finder.insert(
                                abs as u32,
                                self.window[k],
                                self.window[k + 1],
                                self.window[k + 2],
                            );
                        }
                        k += 1;
                    }
                    pos = match_end;
                    have_pending = false;
                }
            } else if let Some((cl, cd)) = cur {
                if !use_lazy {
                    // Greedy: commit this match immediately, no lookahead probe.
                    self.block_symbols.push(Symbol::Match {
                        length: cl as u16,
                        distance: cd as u16,
                    });
                    self.block_bytes
                        .extend_from_slice(&self.window[pos..pos + cl]);
                    let match_end = pos + cl;
                    let mut k = pos + 1;
                    while k < match_end {
                        if k + 3 <= self.window.len() {
                            let abs = abs_base + k as u64;
                            self.match_finder.insert(
                                abs as u32,
                                self.window[k],
                                self.window[k + 1],
                                self.window[k + 2],
                            );
                        }
                        k += 1;
                    }
                    pos = match_end;
                } else {
                    // Lazy: hold this match back as pending; try one more
                    // position to see if a longer match is available.
                    prev_match_len = cl;
                    prev_match_dist = cd;
                    prev_match_start = pos;
                    have_pending = true;
                    // If the match is already at MAX_MATCH there is no point
                    // probing further; commit immediately.
                    if cl >= MAX_MATCH {
                        self.block_symbols.push(Symbol::Match {
                            length: cl as u16,
                            distance: cd as u16,
                        });
                        self.block_bytes
                            .extend_from_slice(&self.window[pos..pos + cl]);
                        let match_end = pos + cl;
                        let mut k = pos + 1;
                        while k < match_end {
                            if k + 3 <= self.window.len() {
                                let abs = abs_base + k as u64;
                                self.match_finder.insert(
                                    abs as u32,
                                    self.window[k],
                                    self.window[k + 1],
                                    self.window[k + 2],
                                );
                            }
                            k += 1;
                        }
                        pos = match_end;
                        have_pending = false;
                    } else {
                        pos += 1;
                    }
                }
            } else {
                // No match here. Emit a literal.
                let lit = self.window[pos];
                self.block_symbols.push(Symbol::Literal(lit));
                self.block_bytes.push(lit);
                pos += 1;
            }
        }

        // Flush pending at end-of-block.
        if have_pending {
            // Commit the held-back match even though we ran out of lookahead.
            self.block_symbols.push(Symbol::Match {
                length: prev_match_len as u16,
                distance: prev_match_dist as u16,
            });
            self.block_bytes.extend_from_slice(
                &self.window[prev_match_start..prev_match_start + prev_match_len],
            );
            let match_end = prev_match_start + prev_match_len;
            // All positions in [prev_match_start, end) were already inserted
            // by the main loop. We only need to splice in the tail [end, match_end).
            let mut k = end;
            while k < match_end {
                if k + 3 <= self.window.len() {
                    let abs = abs_base + k as u64;
                    self.match_finder.insert(
                        abs as u32,
                        self.window[k],
                        self.window[k + 1],
                        self.window[k + 2],
                    );
                }
                k += 1;
            }
            pos = match_end;
        }

        self.cursor = pos;
    }

    /// Build code lengths and the dynamic-block header into `self.*` from
    /// frequency histograms. Returns `(header_bits, payload_bits)`. The
    /// header preparation (RLE + code-length-code Huffman + HLIT/HDIST/HCLEN
    /// trims) is stashed on `self` so `emit_dynamic_block` can consume it
    /// without redoing the work.
    fn build_dynamic(&mut self) -> (u64, u64) {
        let lit_lengths_vec = length_limited_huffman(&self.lit_freq, 15);
        let dist_lengths_vec = length_limited_huffman(&self.dist_freq, 15);

        // Reset and fill the persistent code-length arrays. The vecs from
        // length_limited_huffman are sized to the input frequency table, so
        // they're exactly 286 / 30 entries.
        debug_assert_eq!(lit_lengths_vec.len(), 286);
        debug_assert_eq!(dist_lengths_vec.len(), 30);
        self.lit_lengths.copy_from_slice(&lit_lengths_vec);
        self.dist_lengths.copy_from_slice(&dist_lengths_vec);

        // Trim trailing zeros for HLIT/HDIST.
        let mut hlit_count = 286usize;
        while hlit_count > 257 && self.lit_lengths[hlit_count - 1] == 0 {
            hlit_count -= 1;
        }
        let mut hdist_count = 30usize;
        while hdist_count > 1 && self.dist_lengths[hdist_count - 1] == 0 {
            hdist_count -= 1;
        }
        self.hlit_count = hlit_count;
        self.hdist_count = hdist_count;

        // RLE-encode the combined code-lengths.
        self.combined_lengths.clear();
        self.combined_lengths
            .extend_from_slice(&self.lit_lengths[..hlit_count]);
        self.combined_lengths
            .extend_from_slice(&self.dist_lengths[..hdist_count]);
        rle_encode_lengths_into(&self.combined_lengths, &mut self.rle_buf);

        // Code-length-code Huffman (max length 7).
        self.cl_freq = [0u32; 19];
        for s in &self.rle_buf {
            self.cl_freq[s.sym as usize] += 1;
        }
        let cl_lengths_vec = length_limited_huffman(&self.cl_freq, 7);
        debug_assert_eq!(cl_lengths_vec.len(), 19);
        self.cl_lengths.copy_from_slice(&cl_lengths_vec);

        // HCLEN: trim trailing zeros in CODE_LENGTH_ORDER permutation.
        let mut hclen_count = 19usize;
        while hclen_count > 4 && self.cl_lengths[CODE_LENGTH_ORDER[hclen_count - 1]] == 0 {
            hclen_count -= 1;
        }
        self.hclen_count = hclen_count;

        // Header bits:
        //   3 (BFINAL+BTYPE) + 5+5+4 (HLIT,HDIST,HCLEN) + 3·hclen_count
        //   + sum_over_rle(cl_lengths[sym] + extra_bits)
        let mut header_bits: u64 = 3 + 5 + 5 + 4 + 3 * hclen_count as u64;
        for s in &self.rle_buf {
            header_bits += self.cl_lengths[s.sym as usize] as u64 + s.extra_bits as u64;
        }

        // Payload bits.
        let payload_bits =
            payload_cost_bits(&self.block_symbols, &self.lit_lengths, &self.dist_lengths);

        (header_bits, payload_bits)
    }

    /// Compute the bit cost of encoding `block_symbols` with the fixed
    /// Huffman tables. Returns total bits including 3-bit block header.
    fn fixed_cost_bits(&self) -> u64 {
        // FIXED_LIT_LENGTHS / FIXED_DIST_LENGTHS are 288 / 32 long, but our
        // payload_cost_bits only indexes [0, 286) / [0, 30) so taking a
        // sub-slice is a zero-cost no-op.
        3 + payload_cost_bits(
            &self.block_symbols,
            &FIXED_LIT_LENGTHS[..286],
            &FIXED_DIST_LENGTHS[..30],
        )
    }

    /// Compute the bit cost of encoding the current block as a single
    /// stored block. Returns total bits including the byte-alignment pad.
    /// Assumes block fits in 65535 bytes (it always does at BLOCK_SIZE=16K).
    fn stored_cost_bits(&self) -> u64 {
        // 3-bit header, pad to byte boundary, then 4 bytes (LEN, NLEN) + payload.
        // The alignment pad varies depending on the current `bit_writer.pending_bits`.
        let pending = self.bit_writer.pending_bits() as u64;
        // After writing the 3-bit header, total bits since last byte boundary is
        // (pending + 3) mod 8. Pad to next byte → add (8 - that) mod 8 bits.
        let after_header = (pending + 3) & 7;
        let pad = (8 - after_header) & 7;
        3 + pad + 32 + (self.block_bytes.len() as u64) * 8
    }

    /// Encode the accumulated block to `out_buffer` using the fixed Huffman tables.
    fn emit_fixed_block(&mut self, bfinal: bool) {
        let bw = &mut self.bit_writer;
        let out = &mut self.out_buffer;

        bw.write(if bfinal { 1 } else { 0 }, 1, out);
        bw.write(1, 2, out); // BTYPE = 01 (fixed Huffman)

        // Use the precomputed reversed-code tables. These are computed once
        // at module load and don't depend on the block content.
        let lit_rev = &FIXED_LIT_REV;
        let lit_len_tbl = &FIXED_LIT_LENGTHS;
        let dist_rev = &FIXED_DIST_REV;
        let dist_len_tbl = &FIXED_DIST_LENGTHS;

        for s in &self.block_symbols {
            match s {
                Symbol::Literal(b) => {
                    let bi = *b as usize;
                    bw.write(lit_rev[bi], lit_len_tbl[bi] as u32, out);
                }
                Symbol::Match { length, distance } => {
                    let (lc, lex, leb) = length_to_code(*length);
                    let lci = lc as usize;
                    bw.write(lit_rev[lci], lit_len_tbl[lci] as u32, out);
                    if leb > 0 {
                        bw.write(lex as u32, leb as u32, out);
                    }
                    let (dc, dex, deb) = distance_to_code(*distance);
                    let dci = dc as usize;
                    bw.write(dist_rev[dci], dist_len_tbl[dci] as u32, out);
                    if deb > 0 {
                        bw.write(dex as u32, deb as u32, out);
                    }
                }
            }
        }
        // End-of-block (symbol 256).
        let eob = END_OF_BLOCK as usize;
        bw.write(lit_rev[eob], lit_len_tbl[eob] as u32, out);

        if bfinal {
            bw.align(out);
        }
    }

    /// Encode the accumulated block as a stored (uncompressed) block.
    fn emit_stored_block(&mut self, bfinal: bool) {
        let bw = &mut self.bit_writer;
        let out = &mut self.out_buffer;

        bw.write(if bfinal { 1 } else { 0 }, 1, out);
        bw.write(0, 2, out); // BTYPE = 00
        bw.align(out); // pad to byte boundary

        let len = self.block_bytes.len() as u16;
        let nlen = !len;
        out.push((len & 0xff) as u8);
        out.push((len >> 8) as u8);
        out.push((nlen & 0xff) as u8);
        out.push((nlen >> 8) as u8);
        out.extend_from_slice(&self.block_bytes);
        // Stored blocks naturally end on a byte boundary; if this is the
        // final block we don't need an additional align.
        let _ = bfinal;
    }

    /// Encode the accumulated block as a dynamic-Huffman block.
    ///
    /// Consumes the dynamic-header preparation stashed on `self` by the
    /// preceding [`build_dynamic`] call (lit/dist/cl lengths, RLE, HLIT /
    /// HDIST / HCLEN counts) — they're already in scratch fields, no recompute.
    fn emit_dynamic_block(&mut self, bfinal: bool) {
        let hlit_count = self.hlit_count;
        let hdist_count = self.hdist_count;
        let hclen_count = self.hclen_count;
        let hlit = (hlit_count - 257) as u8;
        let hdist = (hdist_count - 1) as u8;
        let hclen = (hclen_count - 4) as u8;

        // Pre-reverse the Huffman codes once so the inner emission loop is
        // a single `bw.write(rev, len, out)` per symbol.
        let lit_codes = canonical_codes_from_lengths(&self.lit_lengths);
        let dist_codes = canonical_codes_from_lengths(&self.dist_lengths);
        let cl_codes = canonical_codes_from_lengths(&self.cl_lengths);

        // Build per-symbol (reversed_code, length) tables for the two main
        // alphabets. This converts the inner emission loop from three loads
        // + a reverse_bits to two loads.
        let mut lit_rev = [0u32; 286];
        for i in 0..hlit_count {
            let l = self.lit_lengths[i] as u32;
            if l > 0 {
                lit_rev[i] = reverse_bits(lit_codes[i] as u32, l);
            }
        }
        let mut dist_rev = [0u32; 30];
        for i in 0..hdist_count {
            let l = self.dist_lengths[i] as u32;
            if l > 0 {
                dist_rev[i] = reverse_bits(dist_codes[i] as u32, l);
            }
        }
        let mut cl_rev = [0u32; 19];
        for i in 0..19 {
            let l = self.cl_lengths[i] as u32;
            if l > 0 {
                cl_rev[i] = reverse_bits(cl_codes[i] as u32, l);
            }
        }

        let bw = &mut self.bit_writer;
        let out = &mut self.out_buffer;

        bw.write(if bfinal { 1 } else { 0 }, 1, out);
        bw.write(2, 2, out); // BTYPE = 10 (dynamic Huffman)

        bw.write(hlit as u32, 5, out);
        bw.write(hdist as u32, 5, out);
        bw.write(hclen as u32, 4, out);

        for &idx in CODE_LENGTH_ORDER.iter().take(hclen_count) {
            let len = self.cl_lengths[idx];
            bw.write(len as u32, 3, out);
        }

        for s in &self.rle_buf {
            let si = s.sym as usize;
            bw.write(cl_rev[si], self.cl_lengths[si] as u32, out);
            if s.extra_bits > 0 {
                bw.write(s.extra_value as u32, s.extra_bits as u32, out);
            }
        }

        for s in &self.block_symbols {
            match s {
                Symbol::Literal(b) => {
                    let bi = *b as usize;
                    debug_assert!(
                        self.lit_lengths[bi] > 0,
                        "literal {} has zero-length Huffman code",
                        bi
                    );
                    bw.write(lit_rev[bi], self.lit_lengths[bi] as u32, out);
                }
                Symbol::Match { length, distance } => {
                    let (lc, lex, leb) = length_to_code(*length);
                    let lci = lc as usize;
                    bw.write(lit_rev[lci], self.lit_lengths[lci] as u32, out);
                    if leb > 0 {
                        bw.write(lex as u32, leb as u32, out);
                    }
                    let (dc, dex, deb) = distance_to_code(*distance);
                    let dci = dc as usize;
                    bw.write(dist_rev[dci], self.dist_lengths[dci] as u32, out);
                    if deb > 0 {
                        bw.write(dex as u32, deb as u32, out);
                    }
                }
            }
        }

        // End-of-block.
        let eob = END_OF_BLOCK as usize;
        bw.write(lit_rev[eob], self.lit_lengths[eob] as u32, out);

        if bfinal {
            bw.align(out);
        }
    }

    /// Run LZ77 over the bytes in `[cursor, end_rel)`, then emit a single
    /// deflate block (choosing whichever of stored / fixed / dynamic is
    /// cheapest). `bfinal` controls BFINAL on the emitted block.
    fn compress_and_emit_block(&mut self, end_rel: usize, bfinal: bool) {
        self.block_symbols.clear();
        self.block_bytes.clear();

        self.lz77_pass(end_rel);

        // Tally frequencies into the persistent scratch arrays.
        for f in self.lit_freq.iter_mut() {
            *f = 0;
        }
        for f in self.dist_freq.iter_mut() {
            *f = 0;
        }
        for s in &self.block_symbols {
            match s {
                Symbol::Literal(b) => self.lit_freq[*b as usize] += 1,
                Symbol::Match { length, distance } => {
                    let (lc, _, _) = length_to_code(*length);
                    self.lit_freq[lc as usize] += 1;
                    let (dc, _, _) = distance_to_code(*distance);
                    self.dist_freq[dc as usize] += 1;
                }
            }
        }
        self.lit_freq[END_OF_BLOCK as usize] += 1;

        // Compute dynamic-Huffman cost. This also stashes the header preparation
        // (RLE, cl_lengths, hlit/hdist/hclen counts) on `self` so the subsequent
        // emit_dynamic_block call doesn't redo the work.
        let (dyn_header_bits, dyn_payload_bits) = self.build_dynamic();
        let dynamic_total = dyn_header_bits + dyn_payload_bits;

        // Compute fixed-Huffman cost.
        let fixed_total = self.fixed_cost_bits();

        // Compute stored cost — only valid when the block fits in u16.
        let stored_total = if self.block_bytes.len() <= u16::MAX as usize {
            self.stored_cost_bits()
        } else {
            u64::MAX
        };

        // Pick the smallest.
        if stored_total <= dynamic_total && stored_total <= fixed_total {
            self.emit_stored_block(bfinal);
        } else if fixed_total <= dynamic_total {
            self.emit_fixed_block(bfinal);
        } else {
            self.emit_dynamic_block(bfinal);
        }

        self.maybe_slide();
    }
}

impl Default for Encoder {
    fn default() -> Self {
        Self::new()
    }
}

impl RawEncoder for Encoder {
    fn raw_encode(&mut self, input: &[u8], output: &mut [u8]) -> Result<RawProgress, Error> {
        if matches!(self.state, EncState::Done) || self.final_emitted {
            return Err(Error::Corrupt);
        }
        let mut consumed = 0usize;
        let mut written = 0usize;

        loop {
            if matches!(self.state, EncState::Emitting) {
                if self.drain(output, &mut written) {
                    self.out_buffer.clear();
                    self.out_pos = 0;
                    self.state = EncState::Accepting;
                } else {
                    break; // caller's output is full
                }
            }

            if matches!(self.state, EncState::Accepting) {
                // Copy as much input as we can — but cap so we keep some
                // bounded buffer growth. Once we have ≥ BLOCK_SIZE bytes of
                // fresh lookahead (cursor + BLOCK_SIZE <= window.len()),
                // emit a block.
                let space = WINDOW_MAX.saturating_sub(self.window.len());
                let to_copy = (input.len() - consumed).min(space);
                self.window
                    .extend_from_slice(&input[consumed..consumed + to_copy]);
                consumed += to_copy;

                let lookahead = self.window.len() - self.cursor;
                if lookahead >= BLOCK_SIZE {
                    // We have a full block of lookahead. Compress
                    // [cursor, cursor + BLOCK_SIZE). For lazy matching to
                    // see one more byte beyond the end, we leave that
                    // remaining lookahead in the window for the *next* block.
                    let end_rel = self.cursor + BLOCK_SIZE;
                    self.compress_and_emit_block(end_rel, false);
                    self.state = EncState::Emitting;
                } else if to_copy == 0 {
                    // Input exhausted and not enough for a full block.
                    break;
                }
                // Otherwise loop and grab more input.
            }
        }

        Ok(RawProgress {
            consumed,
            written,
            done: false,
        })
    }

    fn raw_finish(&mut self, output: &mut [u8]) -> Result<RawProgress, Error> {
        let mut written = 0usize;
        if matches!(self.state, EncState::Done) {
            return Ok(RawProgress {
                consumed: 0,
                written: 0,
                done: true,
            });
        }

        loop {
            if matches!(self.state, EncState::Emitting) {
                if self.drain(output, &mut written) {
                    self.out_buffer.clear();
                    self.out_pos = 0;
                    if self.final_emitted {
                        self.state = EncState::Done;
                        return Ok(RawProgress {
                            consumed: 0,
                            written,
                            done: true,
                        });
                    }
                    self.state = EncState::Accepting;
                } else {
                    break;
                }
            }

            if matches!(self.state, EncState::Accepting) {
                let remaining = self.window.len() - self.cursor;
                if remaining >= BLOCK_SIZE {
                    // Emit a non-final block, leave the rest for the next
                    // (final) one.
                    let end_rel = self.cursor + BLOCK_SIZE;
                    self.compress_and_emit_block(end_rel, false);
                    self.state = EncState::Emitting;
                } else {
                    // Last block. May be empty, in which case we still need
                    // to emit a final empty stored block.
                    let end_rel = self.window.len();
                    self.compress_and_emit_block(end_rel, true);
                    self.final_emitted = true;
                    self.state = EncState::Emitting;
                }
            }
        }

        Ok(RawProgress {
            consumed: 0,
            written,
            done: false,
        })
    }

    fn raw_reset(&mut self) {
        self.window.clear();
        self.cursor = 0;
        self.window_start_abs = 0;
        self.match_finder.reset();
        self.block_symbols.clear();
        self.block_bytes.clear();
        self.bit_writer = BitWriter::new();
        self.out_buffer.clear();
        self.out_pos = 0;
        self.state = EncState::Accepting;
        self.final_emitted = false;
    }
}
