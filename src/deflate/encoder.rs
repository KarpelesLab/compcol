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
//!
//! The zlib `deflateInit2` knobs are covered too: level 0 (stored blocks
//! only), [`Strategy`], memory level, window size (`max_distance`), a
//! preset dictionary ([`Encoder::with_dictionary`]), `deflateParams`
//! ([`Encoder::set_params`]) and the partial / block flushes
//! ([`Encoder::flush_partial`], [`Encoder::flush_block`]).

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::bits::reverse_bits;
use crate::error::Error;
use crate::huffman::{canonical_codes_from_lengths, length_limited_huffman};
use crate::traits::{Flush, Progress, RawEncoder, RawProgress, Status};

use super::lz77::{MatchFinder, NIL};
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

/// Default memory level, as in zlib. Gives a 15-bit hash table and 16 KiB
/// blocks.
const DEFAULT_MEM_LEVEL: u8 = 8;

/// How the encoder looks for matches, after zlib's `strategy` argument to
/// `deflateInit2`. Output differs from zlib's byte for byte, but each
/// strategy keeps the same limits on what goes into the stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum Strategy {
    /// Normal LZ77 + Huffman coding (`Z_DEFAULT_STRATEGY`).
    #[default]
    Default,
    /// Drop short matches (under 6 bytes) and lean on Huffman coding, for
    /// data like filtered images with small, noisy values (`Z_FILTERED`).
    Filtered,
    /// Literals only, no matches (`Z_HUFFMAN_ONLY`).
    HuffmanOnly,
    /// Only distance-1 matches, i.e. runs of one byte (`Z_RLE`).
    Rle,
    /// Normal matching, but every block uses the fixed Huffman codes
    /// (`Z_FIXED`).
    Fixed,
}

/// Tunables for the deflate encoder.
///
/// `level` controls the speed/ratio trade-off: `0` stores the data in
/// uncompressed (stored) blocks, `1` is the fastest compressing level and
/// `9` the slowest and smallest. The default of `6` mirrors zlib's default.
/// Values above `9` are treated as `9`.
///
/// `max_distance` caps the LZ77 back-reference distance, in bytes. The full
/// deflate window is 32 KiB (`WINDOW_SIZE`) and that is the default. Lower
/// it to produce a stream that a decoder using a *smaller* sliding window can
/// still inflate — for example qemu/qcow2 decompresses clusters with a 4 KiB
/// window (`inflateInit2(-12)`) and fails with `Z_DATA_ERROR` on any
/// back-reference farther than 4096 bytes, so set `max_distance: 4096` to
/// target it. The value is clamped to `1..=WINDOW_SIZE`; it only constrains
/// the encoder (decoding always supports the full window).
/// [`EncoderConfig::with_window_bits`] sets it from zlib-style window bits.
///
/// `strategy` picks how matches are searched (see [`Strategy`]), and
/// `mem_level` (`1..=9`, default `8`) is zlib's `memLevel`, taken as a
/// tuning hint: it sets how much of the hash table is used
/// (`1 << (mem_level + 7)` entries, at most 32768) and the block size
/// (`1 << (mem_level + 6)` bytes). Lower values compress worse; they do not
/// currently shrink the encoder's allocations.
///
/// `#[non_exhaustive]`: construct via [`EncoderConfig::default`] and the
/// `with_*` builders rather than a struct literal, so new tuning knobs can be
/// added in future without breaking downstream code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct EncoderConfig {
    /// Compression level in `0..=9` (`0` = stored blocks only).
    pub level: u8,
    /// Maximum LZ77 match distance in bytes (clamped to `1..=WINDOW_SIZE`).
    /// Default is `WINDOW_SIZE` (the full 32 KiB window).
    pub max_distance: usize,
    /// Match-finding strategy. Default is [`Strategy::Default`].
    pub strategy: Strategy,
    /// zlib-style memory level in `1..=9` (clamped). Default is `8`.
    pub mem_level: u8,
}

impl Default for EncoderConfig {
    fn default() -> Self {
        Self {
            level: 6,
            max_distance: WINDOW_SIZE,
            strategy: Strategy::Default,
            mem_level: DEFAULT_MEM_LEVEL,
        }
    }
}

impl EncoderConfig {
    /// Default configuration: level 6, full 32 KiB window.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the compression level: `0` = stored, `1..=9` = compressed
    /// (values above 9 act as 9).
    #[must_use]
    pub fn with_level(mut self, level: u8) -> Self {
        self.level = level;
        self
    }

    /// Cap the LZ77 match distance (clamped to `1..=WINDOW_SIZE`). Lower it to
    /// target a decoder with a smaller sliding window (e.g. `4096` for
    /// qemu/qcow2's 4 KiB inflate window).
    #[must_use]
    pub fn with_max_distance(mut self, max_distance: usize) -> Self {
        self.max_distance = max_distance;
        self
    }

    /// Set the window from zlib-style window bits: `max_distance` becomes
    /// `1 << bits`. `bits` is clamped to `8..=15`, and `8` is treated as `9`
    /// as zlib does. The zlib container writes the matching `CINFO`.
    #[must_use]
    pub fn with_window_bits(mut self, bits: u8) -> Self {
        self.max_distance = 1usize << bits.clamp(9, 15);
        self
    }

    /// Set the match-finding strategy.
    #[must_use]
    pub fn with_strategy(mut self, strategy: Strategy) -> Self {
        self.strategy = strategy;
        self
    }

    /// Set zlib's memory level (`1..=9`, clamped at encoder build time).
    #[must_use]
    pub fn with_mem_level(mut self, mem_level: u8) -> Self {
        self.mem_level = mem_level;
        self
    }

    /// Window bits matching `max_distance`: the smallest `bits` in `9..=15`
    /// with `1 << bits >= max_distance`. Used for the zlib `CINFO` field.
    pub(crate) fn window_bits(&self) -> u8 {
        let d = self.max_distance.clamp(1, WINDOW_SIZE);
        let mut bits = 9u8;
        while (1usize << bits) < d {
            bits += 1;
        }
        bits
    }
}

/// Internal expansion of [`EncoderConfig::level`] into the match-finder
/// tuning knobs the LZ77 pass actually consults. The shape follows zlib's
/// `configuration_table`: higher levels widen the chain budget and raise
/// the "nice match" / "good match" / "lazy" thresholds, trading CPU for
/// ratio.
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
    /// Lazy parsing only: a match at least this long is committed without
    /// probing the next position (zlib's `max_lazy`).
    max_lazy: usize,
}

impl LevelParams {
    /// Clamp `level` to `1..=9` and expand to the matching tuning knobs
    /// (level 0 is handled before the match finder is consulted).
    fn from_level(level: u8) -> Self {
        // Clamp instead of returning Err — keeping the public surface
        // infallible matches zlib's behaviour of silently snapping Z_BEST_*
        // values into range.
        let level = level.clamp(1, 9);
        let (max_chain, nice_match, good_match, use_lazy, max_lazy) = match level {
            1 => (4, 8, 4, false, MAX_MATCH),
            2 => (8, 16, 5, false, MAX_MATCH),
            3 => (32, 32, 6, false, MAX_MATCH),
            4 => (16, 16, 4, true, MAX_MATCH),
            5 => (32, 32, 8, true, MAX_MATCH),
            6 => (128, 128, 8, true, 32),
            7 => (256, 128, 8, true, 32),
            8 => (1024, 258, 32, true, MAX_MATCH),
            // 9 (and clamp-from-above)
            _ => (4096, 258, 32, true, MAX_MATCH),
        };
        Self {
            max_chain,
            nice_match,
            good_match,
            use_lazy,
            max_lazy,
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

/// Maps a match length in 3..=258 (indexed `length - 3`) to its length code
/// minus 257 (the `LENGTH_BASE`/`LENGTH_EXTRA` index). Built at compile time.
const LENGTH_CODE: [u8; 256] = {
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

/// zlib's `_dist_code` layout: entries `0..256` give the code of distances
/// `1..=256` (indexed `distance - 1`); entries `256..512` give the code of
/// larger distances, indexed `256 + ((distance - 1) >> 7)`. Built at compile
/// time.
const DIST_CODE: [u8; 512] = {
    let mut t = [0u8; 512];
    let mut i = 0usize;
    while i < 512 {
        // Smallest distance mapping to this slot.
        let d = if i < 256 { i + 1 } else { ((i - 256) << 7) + 1 };
        let mut c = 0usize;
        while c < 29 && (DIST_BASE[c + 1] as usize) <= d {
            c += 1;
        }
        t[i] = c as u8;
        i += 1;
    }
    t
};

/// Distance code (`0..30`) for a distance in `1..=32768`.
#[inline(always)]
fn dist_code(distance: usize) -> usize {
    let d = distance - 1;
    let i = if d < 256 { d } else { 256 + (d >> 7) };
    DIST_CODE[i & 511] as usize
}

// ─── packed symbol stream ────────────────────────────────────────────────
//
// Each LZ77 symbol of the current block is one `u32`: a literal is its byte
// value (`< 256`); a match is `distance << 8 | (length - 3)`, which is
// always `>= 256` since `distance >= 1`.

#[inline(always)]
fn sym_literal(byte: u8) -> u32 {
    u32::from(byte)
}

#[inline(always)]
fn sym_match(length: usize, distance: usize) -> u32 {
    ((distance as u32) << 8) | (length - MIN_MATCH) as u32
}

/// Unpack a match symbol into `(length - 3, distance)`.
#[inline(always)]
fn sym_unpack(s: u32) -> (usize, usize) {
    ((s & 0xFF) as usize, (s >> 8) as usize)
}

/// Appends LZ77 symbols to the block and tallies their Huffman
/// frequencies on the fly.
struct SymSink<'a> {
    syms: &'a mut Vec<u32>,
    lit_freq: &'a mut [u32; 286],
    dist_freq: &'a mut [u32; 30],
}

impl SymSink<'_> {
    #[inline(always)]
    fn literal(&mut self, byte: u8) {
        self.syms.push(sym_literal(byte));
        self.lit_freq[byte as usize] += 1;
    }

    #[inline(always)]
    fn matched(&mut self, length: usize, distance: usize) {
        self.syms.push(sym_match(length, distance));
        self.lit_freq[257 + LENGTH_CODE[(length - MIN_MATCH) & 0xFF] as usize] += 1;
        self.dist_freq[dist_code(distance)] += 1;
    }
}

// ─── bit writer ──────────────────────────────────────────────────────────

/// LSB-first bit writer with a 64-bit accumulator that spills four bytes at
/// a time. Outside the symbol-emission loops it holds fewer than 8 bits
/// (whole bytes are always pushed to the output), so the caller can tell
/// how far the stream is from a byte boundary.
#[derive(Debug, Clone, Default)]
struct BitWriter {
    acc: u64,
    nbits: u32,
}

impl BitWriter {
    const fn new() -> Self {
        Self { acc: 0, nbits: 0 }
    }

    /// Append the low `n` bits of `bits` (`n <= 32`, no bits set above
    /// `n`). May leave up to 31 bits buffered; call [`flush_bytes`] after a
    /// run of `put`s.
    ///
    /// [`flush_bytes`]: Self::flush_bytes
    #[inline(always)]
    fn put(&mut self, bits: u32, n: u32, out: &mut Vec<u8>) {
        debug_assert!(n <= 32 && self.nbits < 32);
        debug_assert!(n == 32 || bits >> n == 0);
        self.acc |= u64::from(bits) << self.nbits;
        self.nbits += n;
        if self.nbits >= 32 {
            out.extend_from_slice(&(self.acc as u32).to_le_bytes());
            self.acc >>= 32;
            self.nbits -= 32;
        }
    }

    /// Push every whole buffered byte to `out`.
    #[inline]
    fn flush_bytes(&mut self, out: &mut Vec<u8>) {
        while self.nbits >= 8 {
            out.push(self.acc as u8);
            self.acc >>= 8;
            self.nbits -= 8;
        }
    }

    /// Append `n <= 32` LSB-first bits of `value` (higher bits ignored),
    /// then push whole bytes to `out`.
    fn write(&mut self, value: u32, n: u32, out: &mut Vec<u8>) {
        let masked = if n >= 32 {
            value
        } else {
            value & ((1u32 << n) - 1)
        };
        self.put(masked, n, out);
        self.flush_bytes(out);
    }

    /// Pad with zero bits to the next byte boundary, flushing everything.
    fn align(&mut self, out: &mut Vec<u8>) {
        self.flush_bytes(out);
        if self.nbits > 0 {
            out.push(self.acc as u8);
        }
        self.acc = 0;
        self.nbits = 0;
    }

    /// Bits buffered past the last whole byte (`< 8` between blocks).
    const fn pending_bits(&self) -> u32 {
        self.nbits
    }
}

// ─── flush modes ─────────────────────────────────────────────────────────

/// Every flush the deflate encoder knows: the two of [`Flush`] plus zlib's
/// `Z_PARTIAL_FLUSH` and `Z_BLOCK`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FlushKind {
    Sync,
    Full,
    Partial,
    Block,
}

/// Map a `raw_flush`-style result to the public `(Progress, Status)` pair,
/// the same way the [`crate::Encoder::flush`] bridge does.
pub(crate) fn flush_result(p: RawProgress) -> (Progress, Status) {
    let status = if p.done {
        Status::InputEmpty
    } else {
        Status::OutputFull
    };
    (
        Progress {
            consumed: 0,
            written: p.written,
        },
        status,
    )
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

/// Estimate the Huffman bit cost of emitting a block given its symbol
/// frequency histograms and code lengths: Σ freq·len over the lit/length
/// alphabet plus Σ freq·len over the distance alphabet. The extra-bits term
/// (length/distance suffix bits) is independent of the chosen Huffman
/// encoding and is computed once per block by [`extra_bits_total`].
#[inline]
fn huffman_cost_from_histogram(
    lit_freq: &[u32; 286],
    dist_freq: &[u32; 30],
    lit_lengths: &[u8],
    dist_lengths: &[u8],
) -> u64 {
    let mut bits: u64 = 0;
    for i in 0..286 {
        bits += lit_freq[i] as u64 * lit_lengths[i] as u64;
    }
    for i in 0..30 {
        bits += dist_freq[i] as u64 * dist_lengths[i] as u64;
    }
    bits
}

/// Total length/distance extra bits of a block, from its histograms.
fn extra_bits_total(lit_freq: &[u32; 286], dist_freq: &[u32; 30]) -> u64 {
    let mut bits = 0u64;
    for c in 0..29 {
        bits += lit_freq[257 + c] as u64 * LENGTH_EXTRA[c] as u64;
    }
    for c in 0..30 {
        bits += dist_freq[c] as u64 * DIST_EXTRA[c] as u64;
    }
    bits
}

/// Slow reference version: walk the symbol stream and sum bit costs. Kept
/// for debug-assert cross-checks against `huffman_cost_from_histogram` +
/// the precomputed extra-bits total. Dead-code-eliminated in release.
#[allow(dead_code)]
fn payload_cost_bits(symbols: &[u32], lit_lengths: &[u8], dist_lengths: &[u8]) -> u64 {
    let mut bits: u64 = 0;
    for &s in symbols {
        if s < 256 {
            bits += lit_lengths[s as usize] as u64;
        } else {
            let (l, d) = sym_unpack(s);
            let lc = LENGTH_CODE[l] as usize;
            bits += lit_lengths[257 + lc] as u64 + LENGTH_EXTRA[lc] as u64;
            let dc = dist_code(d);
            bits += dist_lengths[dc] as u64 + DIST_EXTRA[dc] as u64;
        }
    }
    bits += lit_lengths[END_OF_BLOCK as usize] as u64;
    bits
}

/// Write `syms` followed by end-of-block with the given canonical codes
/// (`*_rev` already bit-reversed for LSB-first output) and code lengths.
/// `payload_bits` is the exact size of what gets written (as computed from
/// the histograms), used to size the output up front.
#[allow(clippy::too_many_arguments)]
fn emit_symbols(
    syms: &[u32],
    lit_rev: &[u32],
    lit_len: &[u8],
    dist_rev: &[u32],
    dist_len: &[u8],
    payload_bits: u64,
    bw: &mut BitWriter,
    out: &mut Vec<u8>,
) {
    // Per-symbol packed `bits | nbits << 32` tables: literals carry their
    // code; lengths carry code + extra bits pre-combined; distances carry
    // the code, the extra value being added per symbol.
    let mut lit_tbl = [0u64; 256];
    for (i, e) in lit_tbl.iter_mut().enumerate() {
        *e = u64::from(lit_rev[i]) | (u64::from(lit_len[i]) << 32);
    }
    let mut len_tbl = [0u64; 256];
    for (l, e) in len_tbl.iter_mut().enumerate() {
        let c = LENGTH_CODE[l] as usize;
        let cl = u32::from(lit_len[257 + c]);
        let extra = (l + MIN_MATCH) as u32 - u32::from(LENGTH_BASE[c]);
        let bits = lit_rev[257 + c] | (extra << cl);
        *e = u64::from(bits) | (u64::from(cl + u32::from(LENGTH_EXTRA[c])) << 32);
    }
    let mut dist_tbl = [(0u64, 0u32, 0u32); 32];
    for (c, e) in dist_tbl.iter_mut().take(30).enumerate() {
        *e = (
            u64::from(dist_rev[c]),
            u32::from(dist_len[c]),
            u32::from(dist_len[c]) + u32::from(DIST_EXTRA[c]),
        );
    }

    // Branch-free writer over a pre-sized buffer: each step stores the whole
    // 64-bit accumulator, then advances by the whole bytes it held. The
    // accumulator never holds more than 7 + 48 bits.
    let start = out.len();
    out.resize(start + (payload_bits / 8) as usize + 16, 0);
    let buf = &mut out[start..];
    let mut pos = 0usize;
    let mut acc = bw.acc;
    let mut nbits = bw.nbits;
    {
        let mut put = |bits: u64, n: u32| {
            acc |= bits << nbits;
            nbits += n;
            buf[pos..pos + 8].copy_from_slice(&acc.to_le_bytes());
            let whole = nbits >> 3;
            pos += whole as usize;
            acc >>= whole << 3;
            nbits &= 7;
        };

        for &s in syms {
            if s < 256 {
                let e = lit_tbl[s as usize];
                put(e & 0xFFFF_FFFF, (e >> 32) as u32);
            } else {
                let (l, d) = sym_unpack(s);
                let e = len_tbl[l];
                let ln = (e >> 32) as u32;
                let dc = dist_code(d);
                let (code, cl, dn) = dist_tbl[dc];
                let extra = (d as u64 - u64::from(DIST_BASE[dc])) << cl;
                put((e & 0xFFFF_FFFF) | ((code | extra) << ln), ln + dn);
            }
        }
        let eob = END_OF_BLOCK as usize;
        put(u64::from(lit_rev[eob]), u32::from(lit_len[eob]));
    }
    out.truncate(start + pos);
    bw.acc = acc;
    bw.nbits = nbits;
}

// ─── Huffman code lengths ────────────────────────────────────────────────

/// Optimal code lengths for `freqs`, at most `max_len` bits, into `out`
/// (same length as `freqs`; `0` for unused symbols, `1` for a lone used
/// symbol).
///
/// Builds an unconstrained minimum-redundancy code with Moffat and
/// Katajainen's in-place algorithm (sort, then linear time, no
/// allocation). Only when that code is deeper than `max_len` — rare for
/// deflate's 15-bit limit — it falls back to the package-merge
/// [`length_limited_huffman`]. Both give codes of the same, optimal, total
/// size when the limit does not bind.
fn huffman_lengths(freqs: &[u32], max_len: u8, out: &mut [u8]) {
    debug_assert_eq!(freqs.len(), out.len());
    debug_assert!(freqs.len() <= 512);
    out.fill(0);
    // (frequency << 9 | symbol), sorted ascending: ties broken by symbol.
    let mut keys = [0u64; 512];
    let mut n = 0usize;
    for (i, &f) in freqs.iter().enumerate() {
        if f > 0 {
            keys[n] = (u64::from(f) << 9) | i as u64;
            n += 1;
        }
    }
    match n {
        0 => return,
        1 => {
            out[(keys[0] & 511) as usize] = 1;
            return;
        }
        _ => {}
    }
    let keys = &mut keys[..n];
    keys.sort_unstable();

    // In-place minimum-redundancy code (Moffat & Katajainen 1995). `a`
    // starts as the sorted weights and ends as the code lengths.
    let mut a = [0u64; 512];
    let a = &mut a[..n];
    for (w, &k) in a.iter_mut().zip(keys.iter()) {
        *w = k >> 9;
    }
    // Phase 1: build the tree; internal nodes overwrite the weights and
    // store their parent's index.
    a[0] += a[1];
    let (mut root, mut leaf) = (0usize, 2usize);
    for next in 1..n - 1 {
        // First child.
        if leaf >= n || a[root] < a[leaf] {
            a[next] = a[root];
            a[root] = next as u64;
            root += 1;
        } else {
            a[next] = a[leaf];
            leaf += 1;
        }
        // Second child.
        if leaf >= n || (root < next && a[root] < a[leaf]) {
            a[next] += a[root];
            a[root] = next as u64;
            root += 1;
        } else {
            a[next] += a[leaf];
            leaf += 1;
        }
    }
    // Phase 2: internal node depths.
    a[n - 2] = 0;
    for next in (0..n - 2).rev() {
        a[next] = a[a[next] as usize] + 1;
    }
    // Phase 3: leaf depths, deepest first from index 0.
    let (mut avail, mut used, mut depth) = (1i64, 0i64, 0u64);
    let mut root = n as isize - 2;
    let mut next = n as isize - 1;
    while avail > 0 {
        while root >= 0 && a[root as usize] == depth {
            used += 1;
            root -= 1;
        }
        while avail > used {
            a[next as usize] = depth;
            next -= 1;
            avail -= 1;
        }
        avail = 2 * used;
        depth += 1;
        used = 0;
    }

    if a[0] > u64::from(max_len) {
        out.copy_from_slice(&length_limited_huffman(freqs, max_len));
        return;
    }
    for (&k, &len) in keys.iter().zip(a.iter()) {
        out[(k & 511) as usize] = len as u8;
    }
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
    /// Pending symbols for the current block, packed (see `sym_match`).
    block_symbols: Vec<u32>,
    /// Index in `window` where the current block's bytes start; the block
    /// covers `window[block_start..cursor]`, which is what a stored
    /// encoding copies.
    block_start: usize,
    bit_writer: BitWriter,
    out_buffer: Vec<u8>,
    out_pos: usize,
    state: EncState,
    /// True once we've emitted a BFINAL=1 block; finish() will not produce more.
    final_emitted: bool,
    /// True while `raw_flush` is mid-emission of a sync marker — distinguishes
    /// "out_buffer holds the marker from a prior partial flush" (drain only)
    /// from "out_buffer is empty at entry" (emit marker, then drain).
    /// Cleared once the marker has been fully forwarded to the caller.
    mid_flush: bool,
    /// Match-finder tuning derived from [`EncoderConfig::level`]. Persisted
    /// across `reset` since configuration is meant to survive resets.
    params: LevelParams,
    /// Compression level after clamping to `0..=9`; `0` = stored blocks.
    level: u8,
    strategy: Strategy,
    /// Fresh-input bytes per block, from the memory level.
    block_size: usize,
    /// Absolute position before which nothing may be referenced (moved
    /// forward by a full flush). Only the RLE pass needs it; the hash
    /// chains are cleared instead.
    history_floor: u64,
    /// Preset dictionary (its last `WINDOW_SIZE` bytes), primed into the
    /// window on construction and on every reset.
    dictionary: Vec<u8>,

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

    /// Build an encoder with explicit configuration. Levels above 9 act as
    /// 9 and memory levels are clamped to `1..=9`, rather than rejected.
    pub fn with_config(config: EncoderConfig) -> Self {
        let mem_level = config.mem_level.clamp(1, 9);
        let level = config.level.min(9);
        Self {
            window: Vec::with_capacity(WINDOW_MAX),
            cursor: 0,
            window_start_abs: 0,
            match_finder: Box::new(MatchFinder::with_hash_bits(
                config.max_distance,
                mem_level as u32 + 7,
            )),
            block_symbols: Vec::new(),
            block_start: 0,
            bit_writer: BitWriter::new(),
            out_buffer: Vec::new(),
            out_pos: 0,
            state: EncState::Accepting,
            final_emitted: false,
            mid_flush: false,
            params: LevelParams::from_level(level),
            level,
            strategy: config.strategy,
            block_size: 1 << (mem_level as usize + 6),
            history_floor: 0,
            dictionary: Vec::new(),
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

    /// Use `dictionary` as a preset dictionary (zlib's
    /// `deflateSetDictionary`): matches may refer back into it, so the
    /// decoder must be given the same bytes. Only the last 32 KiB matter.
    /// The dictionary is kept across [`reset`](crate::Encoder::reset).
    /// Calling this resets the encoder, so do it before encoding.
    #[must_use]
    pub fn with_dictionary(mut self, dictionary: &[u8]) -> Self {
        let keep = dictionary.len().min(WINDOW_SIZE);
        self.dictionary.clear();
        self.dictionary
            .extend_from_slice(&dictionary[dictionary.len() - keep..]);
        self.raw_reset();
        self
    }

    /// Change the level and strategy mid-stream (zlib's `deflateParams`).
    /// The new settings apply to input not yet compressed into a block; call
    /// [`flush_block`](Self::flush_block) first to switch at an exact byte
    /// position. Levels above 9 act as 9.
    pub fn set_params(&mut self, level: u8, strategy: Strategy) {
        self.level = level.min(9);
        self.params = LevelParams::from_level(self.level);
        self.strategy = strategy;
    }

    /// Like [`Flush::Sync`] (zlib's `Z_PARTIAL_FLUSH`), but instead of the
    /// byte-aligning empty stored block it emits an empty fixed-Huffman
    /// block (10 bits). The peer can decode all input so far; the output is
    /// not byte-aligned. Call again with fresh output while it returns
    /// [`Status::OutputFull`]; it returns [`Status::InputEmpty`] when done.
    pub fn flush_partial(&mut self, output: &mut [u8]) -> Result<(Progress, Status), Error> {
        self.raw_flush_kind(output, FlushKind::Partial)
            .map(flush_result)
    }

    /// Close the current block without any marker or byte alignment
    /// (zlib's `Z_BLOCK`). Up to 7 bits of the last block stay held back
    /// until more output is produced, so the peer may not yet be able to
    /// decode the very end. Same calling pattern as
    /// [`flush_partial`](Self::flush_partial).
    pub fn flush_block(&mut self, output: &mut [u8]) -> Result<(Progress, Status), Error> {
        self.raw_flush_kind(output, FlushKind::Block)
            .map(flush_result)
    }

    /// Clamped level and strategy, for container headers.
    pub(crate) fn level_and_strategy(&self) -> (u8, Strategy) {
        (self.level, self.strategy)
    }

    /// Put the preset dictionary (if any) into the window and hash chains.
    fn prime_dictionary(&mut self) {
        if self.dictionary.is_empty() {
            return;
        }
        self.window.extend_from_slice(&self.dictionary);
        let n = self.window.len();
        self.match_finder.insert_range(&self.window, 0, n, 0);
        self.cursor = n;
    }

    /// Drain accumulated block bytes into the caller's output. Returns true
    /// when the current `out_buffer` has been fully forwarded.
    fn drain(&mut self, output: &mut [u8], written: &mut usize) -> bool {
        let avail = &self.out_buffer[self.out_pos..];
        let n = avail.len().min(output.len() - *written);
        output[*written..*written + n].copy_from_slice(&avail[..n]);
        self.out_pos += n;
        *written += n;
        self.out_pos >= self.out_buffer.len()
    }

    /// Slide the window if we've accumulated too much history. Drops the
    /// oldest prefix so the kept buffer is at most WINDOW_SIZE + lookahead.
    fn maybe_slide(&mut self) {
        // We slide once the back-history exceeds WINDOW_SIZE — keeping
        // exactly WINDOW_SIZE bytes of history is enough for any in-window
        // distance to be reachable. With blocks smaller than the default,
        // allow more history first so we don't move 32 KiB per tiny block.
        if self.cursor > WINDOW_SIZE + BLOCK_SIZE.saturating_sub(self.block_size) {
            let drop = self.cursor - WINDOW_SIZE;
            self.window.drain(..drop);
            self.cursor -= drop;
            self.window_start_abs += drop as u64;
        }
    }

    /// Run LZ77 over `window[cursor..end]`, appending the result to
    /// `block_symbols` (and the frequency histograms). Advances `cursor`.
    /// Uses greedy parsing when `params.use_lazy` is false (low levels) and
    /// zlib-style lazy matching otherwise.
    fn lz77_pass(&mut self, end: usize) {
        let p = self.params;
        // Z_FILTERED: matches shorter than this are treated as no match.
        let min_len = if self.strategy == Strategy::Filtered {
            6
        } else {
            MIN_MATCH
        };
        let abs_base = self.window_start_abs;
        let window = &self.window[..];
        let wlen = window.len();
        let mf = &mut *self.match_finder;
        let mut sink = SymSink {
            syms: &mut self.block_symbols,
            lit_freq: &mut self.lit_freq,
            dist_freq: &mut self.dist_freq,
        };
        let mut pos = self.cursor;

        // Lazy-matching state: a match of `prev_len` bytes (0 = none)
        // starting at `pos - 1` that we hold back to see whether the match
        // at `pos` is strictly longer. Never set under greedy parsing.
        let mut prev_len = 0usize;
        let mut prev_dist = 0usize;

        while pos < end {
            let abs = (abs_base + pos as u64) as u32;
            // Splice `pos` into its hash chain; `cand` is the chain head.
            let cand = if pos + MIN_MATCH <= wlen {
                mf.insert(window, pos, abs)
            } else {
                NIL
            };

            let mut cur_len = 0usize;
            let mut cur_dist = 0usize;
            if cand != NIL && pos + MIN_MATCH <= end && prev_len < p.max_lazy {
                // Only a match strictly longer than the pending one helps;
                // a long-enough pending match quarters the chain budget.
                let (floor, chain) = if prev_len > 0 {
                    let c = if prev_len >= p.good_match {
                        p.max_chain / 4
                    } else {
                        p.max_chain
                    };
                    (prev_len, c)
                } else {
                    (min_len - 1, p.max_chain)
                };
                (cur_len, cur_dist) =
                    mf.longest_match(window, pos, abs, cand, floor, chain.max(1), p.nice_match);
            }

            if prev_len > 0 {
                if cur_len > prev_len {
                    // Better match one byte later: the held-back position
                    // becomes a literal and `cur` is the new pending match.
                    sink.literal(window[pos - 1]);
                    prev_len = cur_len;
                    prev_dist = cur_dist;
                    pos += 1;
                } else {
                    // Commit the pending match (it started at `pos - 1`;
                    // `pos - 1` and `pos` are already in the chains).
                    sink.matched(prev_len, prev_dist);
                    let match_end = pos - 1 + prev_len;
                    mf.insert_range(window, pos + 1, match_end, abs_base);
                    pos = match_end;
                    prev_len = 0;
                }
            } else if cur_len > 0 {
                if p.use_lazy && cur_len < p.max_lazy {
                    // Hold it back and probe the next position.
                    prev_len = cur_len;
                    prev_dist = cur_dist;
                    pos += 1;
                } else {
                    sink.matched(cur_len, cur_dist);
                    let match_end = pos + cur_len;
                    mf.insert_range(window, pos + 1, match_end, abs_base);
                    pos = match_end;
                }
            } else {
                sink.literal(window[pos]);
                pos += 1;
            }
        }

        // Flush pending at end-of-block.
        if prev_len > 0 {
            // Commit the held-back match even though we ran out of
            // lookahead. Positions up to `pos - 1` are in the chains.
            sink.matched(prev_len, prev_dist);
            let match_end = pos - 1 + prev_len;
            mf.insert_range(window, pos, match_end, abs_base);
            pos = match_end;
        }

        self.cursor = pos;
    }

    /// Huffman-only pass: every byte of `window[cursor..end]` is a literal.
    fn literal_pass(&mut self, end: usize) {
        let bytes = &self.window[self.cursor..end];
        self.block_symbols
            .extend(bytes.iter().map(|&b| sym_literal(b)));
        for &b in bytes {
            self.lit_freq[b as usize] += 1;
        }
        self.cursor = end;
    }

    /// RLE pass: only distance-1 matches (runs of the previous byte), greedy.
    fn rle_pass(&mut self, end: usize) {
        // Index of the first window byte a match may copy from.
        let floor_rel = self.history_floor.saturating_sub(self.window_start_abs) as usize;
        let window = &self.window[..];
        let mut sink = SymSink {
            syms: &mut self.block_symbols,
            lit_freq: &mut self.lit_freq,
            dist_freq: &mut self.dist_freq,
        };
        let mut pos = self.cursor;
        while pos < end {
            if pos > floor_rel {
                let prev = window[pos - 1];
                let max = MAX_MATCH.min(window.len() - pos);
                let len = window[pos..pos + max]
                    .iter()
                    .position(|&b| b != prev)
                    .unwrap_or(max);
                if len >= MIN_MATCH {
                    sink.matched(len, 1);
                    pos += len;
                    continue;
                }
            }
            sink.literal(window[pos]);
            pos += 1;
        }
        self.cursor = pos;
    }

    /// Level 0: emit `window[cursor..end]` as stored blocks of at most
    /// 65535 bytes each; BFINAL goes on the last one only.
    fn emit_stored_range(&mut self, end: usize, bfinal: bool) {
        let mut start = self.cursor;
        loop {
            let n = (end - start).min(u16::MAX as usize);
            let last = start + n == end;
            let bw = &mut self.bit_writer;
            let out = &mut self.out_buffer;
            bw.write(u32::from(bfinal && last), 1, out);
            bw.write(0, 2, out); // BTYPE = 00
            bw.align(out);
            let len = n as u16;
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(&(!len).to_le_bytes());
            out.extend_from_slice(&self.window[start..start + n]);
            start += n;
            if last {
                break;
            }
        }
        self.cursor = end;
    }

    /// Build code lengths and the dynamic-block header into `self.*` from
    /// frequency histograms. Returns `(header_bits, payload_bits)`. The
    /// header preparation (RLE + code-length-code Huffman + HLIT/HDIST/HCLEN
    /// trims) is stashed on `self` so `emit_dynamic_block` can consume it
    /// without redoing the work. `extra_bits_total` is the per-symbol
    /// length/distance extra-bits sum precomputed during the LZ77 pass;
    /// it's the same regardless of which Huffman encoding is chosen.
    fn build_dynamic(&mut self, extra_bits_total: u64) -> (u64, u64) {
        huffman_lengths(&self.lit_freq, 15, &mut self.lit_lengths);
        huffman_lengths(&self.dist_freq, 15, &mut self.dist_lengths);

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
        huffman_lengths(&self.cl_freq, 7, &mut self.cl_lengths);

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

        // Payload bits: Σ freq·len over the lit/length and distance alphabets,
        // plus the precomputed extra-bits total.
        let payload_bits = huffman_cost_from_histogram(
            &self.lit_freq,
            &self.dist_freq,
            &self.lit_lengths,
            &self.dist_lengths,
        ) + extra_bits_total;

        debug_assert_eq!(
            payload_bits,
            payload_cost_bits(&self.block_symbols, &self.lit_lengths, &self.dist_lengths),
        );

        (header_bits, payload_bits)
    }

    /// Compute the bit cost of encoding `block_symbols` with the fixed
    /// Huffman tables. Returns total bits including 3-bit block header.
    /// `extra_bits_total` is the length/distance extra-bits sum precomputed
    /// during the LZ77 pass.
    fn fixed_cost_bits(&self, extra_bits_total: u64) -> u64 {
        // FIXED_LIT_LENGTHS / FIXED_DIST_LENGTHS are 288 / 32 long; only the
        // first 286 / 30 entries are addressed by symbol histograms.
        let payload_bits = huffman_cost_from_histogram(
            &self.lit_freq,
            &self.dist_freq,
            &FIXED_LIT_LENGTHS[..286],
            &FIXED_DIST_LENGTHS[..30],
        ) + extra_bits_total;

        debug_assert_eq!(
            payload_bits,
            payload_cost_bits(
                &self.block_symbols,
                &FIXED_LIT_LENGTHS[..286],
                &FIXED_DIST_LENGTHS[..30],
            ),
        );

        3 + payload_bits
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
        3 + pad + 32 + ((self.cursor - self.block_start) as u64) * 8
    }

    /// Encode the accumulated block to `out_buffer` using the fixed Huffman tables.
    /// `payload_bits` bounds the size of the symbol data.
    fn emit_fixed_block(&mut self, bfinal: bool, payload_bits: u64) {
        let bw = &mut self.bit_writer;
        let out = &mut self.out_buffer;

        bw.write(if bfinal { 1 } else { 0 }, 1, out);
        bw.write(1, 2, out); // BTYPE = 01 (fixed Huffman)

        emit_symbols(
            &self.block_symbols,
            &FIXED_LIT_REV,
            &FIXED_LIT_LENGTHS,
            &FIXED_DIST_REV,
            &FIXED_DIST_LENGTHS,
            payload_bits,
            bw,
            out,
        );

        if bfinal {
            bw.align(out);
        }
    }

    /// Emit a `Z_SYNC_FLUSH` marker into `out_buffer`: a non-final empty
    /// stored block. Per RFC 1951 §3.2.4 the block header is BFINAL=0
    /// (1 bit) + BTYPE=00 (2 bits), then the byte-alignment pad, then the
    /// 4 bytes `00 00 ff ff` (LEN=0, NLEN=0xFFFF) and no payload. After
    /// the marker the bitstream is byte-aligned, so the peer can decode
    /// everything written so far. The encoder's history (window +
    /// match-finder chains) is left intact so subsequent encode calls
    /// can back-reference earlier data.
    fn emit_sync_marker(&mut self) {
        let bw = &mut self.bit_writer;
        let out = &mut self.out_buffer;
        // BFINAL = 0
        bw.write(0, 1, out);
        // BTYPE = 00 (stored)
        bw.write(0, 2, out);
        // Pad to byte boundary so the LEN/NLEN bytes are aligned.
        bw.align(out);
        // LEN = 0, NLEN = 0xFFFF, no payload.
        out.extend_from_slice(&[0x00, 0x00, 0xFF, 0xFF]);
    }

    /// Encode the accumulated block as a stored (uncompressed) block.
    fn emit_stored_block(&mut self, bfinal: bool) {
        let bw = &mut self.bit_writer;
        let out = &mut self.out_buffer;

        bw.write(if bfinal { 1 } else { 0 }, 1, out);
        bw.write(0, 2, out); // BTYPE = 00
        bw.align(out); // pad to byte boundary

        let bytes = &self.window[self.block_start..self.cursor];
        let len = bytes.len() as u16;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&(!len).to_le_bytes());
        out.extend_from_slice(bytes);
        // Stored blocks naturally end on a byte boundary.
    }

    /// Encode the accumulated block as a dynamic-Huffman block.
    ///
    /// Consumes the dynamic-header preparation stashed on `self` by the
    /// preceding [`build_dynamic`] call (lit/dist/cl lengths, RLE, HLIT /
    /// HDIST / HCLEN counts) — they're already in scratch fields, no recompute.
    /// `payload_bits` bounds the size of the symbol data.
    fn emit_dynamic_block(&mut self, bfinal: bool, payload_bits: u64) {
        let hlit_count = self.hlit_count;
        let hdist_count = self.hdist_count;
        let hclen_count = self.hclen_count;
        let hlit = (hlit_count - 257) as u8;
        let hdist = (hdist_count - 1) as u8;
        let hclen = (hclen_count - 4) as u8;

        // Pre-reverse the Huffman codes once so the inner emission loop is
        // a single `bw.put(rev, len, out)` per symbol.
        let lit_codes = canonical_codes_from_lengths(&self.lit_lengths);
        let dist_codes = canonical_codes_from_lengths(&self.dist_lengths);
        let cl_codes = canonical_codes_from_lengths(&self.cl_lengths);

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

        emit_symbols(
            &self.block_symbols,
            &lit_rev,
            &self.lit_lengths,
            &dist_rev,
            &self.dist_lengths,
            payload_bits,
            bw,
            out,
        );

        if bfinal {
            bw.align(out);
        }
    }

    /// Run LZ77 over the bytes in `[cursor, end_rel)`, then emit a single
    /// deflate block (choosing whichever of stored / fixed / dynamic is
    /// cheapest). `bfinal` controls BFINAL on the emitted block.
    fn compress_and_emit_block(&mut self, end_rel: usize, bfinal: bool) {
        if self.level == 0 {
            self.emit_stored_range(end_rel, bfinal);
            self.maybe_slide();
            return;
        }

        self.block_symbols.clear();
        self.block_symbols
            .reserve(end_rel.saturating_sub(self.cursor) + 1);
        self.block_start = self.cursor;
        self.lit_freq = [0u32; 286];
        self.dist_freq = [0u32; 30];

        // The passes tally the frequency histograms as they go.
        match self.strategy {
            Strategy::HuffmanOnly => self.literal_pass(end_rel),
            Strategy::Rle => self.rle_pass(end_rel),
            _ => self.lz77_pass(end_rel),
        }
        self.lit_freq[END_OF_BLOCK as usize] += 1;

        // The extra-bits sum is independent of which Huffman encoding is
        // chosen, so it's added equally to the dynamic and fixed estimates.
        let extra_bits_total = extra_bits_total(&self.lit_freq, &self.dist_freq);

        if self.strategy == Strategy::Fixed {
            let fixed_total = self.fixed_cost_bits(extra_bits_total);
            self.emit_fixed_block(bfinal, fixed_total);
            self.maybe_slide();
            return;
        }

        // Compute dynamic-Huffman cost. This also stashes the header preparation
        // (RLE, cl_lengths, hlit/hdist/hclen counts) on `self` so the subsequent
        // emit_dynamic_block call doesn't redo the work.
        let (dyn_header_bits, dyn_payload_bits) = self.build_dynamic(extra_bits_total);
        let dynamic_total = dyn_header_bits + dyn_payload_bits;

        // Compute fixed-Huffman cost.
        let fixed_total = self.fixed_cost_bits(extra_bits_total);

        // Compute stored cost — only valid when the block fits in u16.
        let stored_total = if self.cursor - self.block_start <= u16::MAX as usize {
            self.stored_cost_bits()
        } else {
            u64::MAX
        };

        // Pick the smallest.
        if stored_total <= dynamic_total && stored_total <= fixed_total {
            self.emit_stored_block(bfinal);
        } else if fixed_total <= dynamic_total {
            self.emit_fixed_block(bfinal, fixed_total);
        } else {
            self.out_buffer.reserve((dynamic_total / 8) as usize + 16);
            self.emit_dynamic_block(bfinal, dyn_payload_bits);
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
                if lookahead >= self.block_size {
                    // We have a full block of lookahead. Compress
                    // [cursor, cursor + BLOCK_SIZE). For lazy matching to
                    // see one more byte beyond the end, we leave that
                    // remaining lookahead in the window for the *next* block.
                    let end_rel = self.cursor + self.block_size;
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
                if remaining >= self.block_size {
                    // Emit a non-final block, leave the rest for the next
                    // (final) one.
                    let end_rel = self.cursor + self.block_size;
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
        self.block_start = 0;
        self.bit_writer = BitWriter::new();
        self.out_buffer.clear();
        self.out_pos = 0;
        self.state = EncState::Accepting;
        self.final_emitted = false;
        self.mid_flush = false;
        self.history_floor = 0;
        self.prime_dictionary();
    }

    fn raw_flush(&mut self, output: &mut [u8], mode: Flush) -> Result<RawProgress, Error> {
        let kind = match mode {
            Flush::Sync => FlushKind::Sync,
            Flush::Full => FlushKind::Full,
        };
        self.raw_flush_kind(output, kind)
    }
}

impl Encoder {
    /// Shared body of every flush mode. `RawProgress.done` means this flush
    /// call is complete, as for [`RawEncoder::raw_flush`].
    pub(crate) fn raw_flush_kind(
        &mut self,
        output: &mut [u8],
        kind: FlushKind,
    ) -> Result<RawProgress, Error> {
        if matches!(self.state, EncState::Done) || self.final_emitted {
            return Err(Error::Corrupt);
        }

        let mut written = 0usize;

        loop {
            // Drain whatever's already in out_buffer (either prior encode
            // output or our own pending marker bytes from a prior partial
            // flush call).
            if matches!(self.state, EncState::Emitting) {
                if self.drain(output, &mut written) {
                    // Buffer fully forwarded.
                    self.out_buffer.clear();
                    self.out_pos = 0;
                    self.state = EncState::Accepting;
                    if self.mid_flush {
                        // The marker we'd emitted in a previous call to
                        // raw_flush has now been fully delivered. This
                        // flush call is complete — signal with done=true
                        // so the bridge reports `Status::InputEmpty`
                        // regardless of output-buffer fullness.
                        self.mid_flush = false;
                        return Ok(RawProgress {
                            consumed: 0,
                            written,
                            done: true,
                        });
                    }
                    // Otherwise: we just finished draining prior encode
                    // output. Fall through to emit our marker.
                } else {
                    // Output buffer is full and there's still pending data.
                    return Ok(RawProgress {
                        consumed: 0,
                        written,
                        done: false,
                    });
                }
            }

            // State is Accepting and we have NOT yet emitted the marker
            // for this flush call. Encode any pending lookahead into a
            // non-final block, then emit the empty stored-block sync
            // marker into out_buffer.
            debug_assert!(!self.mid_flush);
            let remaining = self.window.len() - self.cursor;
            if remaining > 0 {
                // Compress everything we have. Use a non-final block so
                // the stream can continue.
                let end_rel = self.window.len();
                self.compress_and_emit_block(end_rel, false);
            }
            match kind {
                FlushKind::Sync => self.emit_sync_marker(),
                FlushKind::Full => {
                    self.emit_sync_marker();
                    // Reset the LZ77 hash chains so subsequent matches cannot
                    // reach back across the flush boundary. The window bytes
                    // themselves stay — they're just no longer reachable via
                    // any chain entry. This mirrors Z_FULL_FLUSH semantics.
                    self.match_finder.reset();
                    self.history_floor = self.window_start_abs + self.cursor as u64;
                }
                FlushKind::Partial => {
                    // Empty fixed-Huffman block: BFINAL=0, BTYPE=01, then
                    // the 7-bit all-zero code for end-of-block.
                    let out = &mut self.out_buffer;
                    self.bit_writer.write(0b010, 3, out);
                    self.bit_writer.write(0, 7, out);
                }
                FlushKind::Block => {}
            }
            self.mid_flush = true;
            self.state = EncState::Emitting;
            // Loop and drain the marker.
        }
    }
}
