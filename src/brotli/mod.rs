//! Brotli (RFC 7932) — partial-but-functional implementation.
//!
//! Reference: <https://datatracker.ietf.org/doc/html/rfc7932>.
//!
//! # Scope of this build
//!
//! - **Encoder**: emits compressed Brotli meta-blocks with a single
//!   block-type per category (NBLTYPESL/I/D = 1), one context (CMODE
//!   = LSB6, NTREESL = 1), and the simplest distance parameter set
//!   (NPOSTFIX = 0, NDIRECT = 0). Real LZ77 matches are found via a
//!   hash-chain match finder; insert-and-copy commands use the full
//!   704-symbol IC alphabet; Huffman trees are built from frequencies
//!   via the length-limited package-merge algorithm. **Static-dictionary
//!   references** are emitted via the private `encoder_dict::DictIndex` when a
//!   dictionary word (with one of the Identity or UppercaseFirst-ASCII
//!   transforms) sits at the current input position and would beat the
//!   in-window LZ77 match. The encoder still does not exploit multiple
//!   block types or context modelling on the literal/distance side —
//!   those would push us into the "roof" tier of the spec.
//!
//! - **Decoder**: parses the stream header, walks the meta-block chain,
//!   and decodes:
//!   - the empty last meta-block,
//!   - metadata meta-blocks (skipped),
//!   - uncompressed meta-blocks,
//!   - **compressed meta-blocks** including simple and complex prefix
//!     codes, block-type / block-count / context-map machinery,
//!     literal context modelling, distance ring buffer, and static
//!     dictionary references via the 121-entry transform table.
//!
//! The static dictionary (Appendix A) is embedded verbatim from the
//! reference `dictionary.bin` (122,784 bytes, SHA-256
//! `20e42eb1b511c21806d4d227d07e5dd06877d8ce7b3a817f378f313653f35c70`)
//! via `include_bytes!`.
//!
//! The decoder is **buffered**: each compressed meta-block is read in
//! full into an internal buffer, then decoded synchronously, then its
//! output is streamed to the caller. The streaming API is honoured at
//! the meta-block boundary. Memory use is proportional to the largest
//! meta-block in the stream (≤ 16 MiB per spec; in practice ≤ ~256 KiB
//! for level-1+ encoders).
//!
//! Bit ordering is LSB-first within each byte (same as deflate).
//!
//! # Not implemented
//!
//! - The large-window flag (WBITS first bit = 1, next 3 bits = 0,
//!   next 3 bits = 1) is rejected as `Unsupported`.
//! - Encoder-side multiple block types or non-trivial context maps.
//! - Encoder-side static-dictionary transforms beyond `Identity` /
//!   `UppercaseFirst` (ASCII). The decoder handles all 121 transforms.

use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;
use crate::traits::{Algorithm, RawDecoder, RawEncoder, RawProgress};

mod context;
mod dictionary;
mod encoder_ctx;
mod encoder_dict;
mod encoder_huffman;
mod encoder_iac;
mod encoder_lz77;
mod encoder_optimal;
mod huffman;
mod transforms;

use alloc::rc::Rc;

use context::ContextMode;
use huffman::{BitSource, HuffmanDecoder};

use encoder_dict::{DictIndex, IdTransform};
use encoder_huffman::reverse_bits;
use encoder_lz77::MatchFinder;

/// Zero-sized marker type implementing [`Algorithm`] for Brotli.
#[derive(Debug, Clone, Copy, Default)]
pub struct Brotli;

/// Tunables for the brotli encoder.
///
/// `quality` follows the reference brotli convention: `0` is fastest /
/// largest output, `11` is slowest / smallest output. The default `6`
/// mirrors the reference CLI and is a reasonable starting point. Values
/// outside `0..=11` are clamped at encoder construction time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncoderConfig {
    /// Quality level in `0..=11`. Lower is faster, higher is smaller.
    pub quality: u8,
}

impl Default for EncoderConfig {
    fn default() -> Self {
        Self { quality: 6 }
    }
}

/// Internal expansion of [`EncoderConfig::quality`] into the match-
/// finder tuning knobs and feature toggles the encoder actually
/// consults. Higher quality widens the chain budget, raises the
/// nice-match cutoff, and enables the static-dictionary path.
#[derive(Debug, Clone, Copy)]
struct LevelParams {
    finder: encoder_lz77::FinderParams,
    /// When `false`, the encoder skips the static-dictionary lookup
    /// entirely (saves ~80 KiB of working memory + per-position probe
    /// cost on the lowest quality settings).
    use_dict: bool,
    /// Number of iterative optimal-parse passes (zopfli-style). `0`
    /// selects the single-pass greedy parser; `≥1` runs the forward DP in
    /// [`encoder_optimal`], rebuilding the cost model from the previous
    /// pass's histograms each round. Only enabled at the top quality
    /// tiers where the extra parse time is worth the ratio.
    opt_passes: u32,
}

impl LevelParams {
    /// Clamp `quality` to `0..=11` and expand to the matching tuning
    /// knobs. Mirrors the spirit of the reference brotli quality table:
    /// low quality → shallow chain, no dictionary; high quality → deep
    /// chain, dictionary references, eager match acceptance.
    const fn from_quality(quality: u8) -> Self {
        // Clamp instead of returning Err — keeping the public surface
        // infallible matches the reference brotli CLI's behaviour.
        let q = if quality > 11 { 11 } else { quality };
        // (max_chain, nice_match, use_dict, cost_match)
        let (max_chain, nice_match, use_dict, cost_match) = match q {
            0 => (2, 8, false, false),
            1 => (4, 16, false, false),
            2 => (8, 24, false, false),
            3 => (16, 32, false, false),
            4 => (24, 48, true, true),
            5 => (48, 96, true, true),
            6 => (64, 128, true, true),
            7 => (96, 192, true, true),
            8 => (160, 256, true, true),
            9 => (256, 384, true, true),
            10 => (512, 768, true, true),
            // 11 (and clamp-from-above)
            _ => (1024, 1024, true, true),
        };
        // Iterative optimal parse on the slowest tiers, where the extra
        // DP passes buy meaningful ratio over greedy.
        let opt_passes = match q {
            9 => 2,
            10 => 2,
            11 => 3,
            _ => 0,
        };
        Self {
            finder: encoder_lz77::FinderParams {
                max_chain,
                nice_match,
                cost_match,
            },
            use_dict,
            opt_passes,
        }
    }
}

impl Algorithm for Brotli {
    const NAME: &'static str = "brotli";
    type Encoder = Encoder;
    type Decoder = Decoder;
    type EncoderConfig = EncoderConfig;
    type DecoderConfig = ();
    fn encoder_with(c: EncoderConfig) -> Encoder {
        Encoder::with_config(c)
    }
    fn decoder_with(_: ()) -> Decoder {
        Decoder::new()
    }
}

// ─── shared bit primitives ───────────────────────────────────────────────
//
// LSB-first throughout. The encoder uses a streaming BitWriter; the
// decoder buffers raw stream bytes and decodes from them with a
// `BitSource` (defined in `huffman.rs`).

/// LSB-first bit writer that accumulates into a u64 and drains whole
/// bytes into a `Vec<u8>`. Used only by the encoder.
#[derive(Debug, Clone, Default)]
struct BitWriter {
    acc: u64,
    nbits: u32,
}

impl BitWriter {
    const fn new() -> Self {
        Self { acc: 0, nbits: 0 }
    }
    fn write(&mut self, value: u32, n: u32, out: &mut Vec<u8>) {
        debug_assert!(n <= 32);
        let masked: u64 = if n == 0 {
            0
        } else {
            (value as u64) & ((1u64 << n) - 1)
        };
        self.acc |= masked << self.nbits;
        self.nbits += n;
        while self.nbits >= 8 {
            out.push(self.acc as u8);
            self.acc >>= 8;
            self.nbits -= 8;
        }
    }
    fn align(&mut self, out: &mut Vec<u8>) {
        if self.nbits > 0 {
            out.push(self.acc as u8);
            self.acc = 0;
            self.nbits = 0;
        }
    }
    const fn pending_bits(&self) -> u32 {
        self.nbits
    }
}

// ─── encoder ────────────────────────────────────────────────────────────
//
// Wire format produced (per RFC 7932 §9.2):
//
//   WBITS = 16            (1 bit  = 0)
//   [meta-block]*         (one compressed meta-block per ≤ MAX_BLOCK bytes
//                          of input, plus an empty ISLAST=1/ISLASTEMPTY=1
//                          terminator when input is empty)
//
// Per meta-block (compressed, single-block-type variant):
//
//   ISLAST                (1 bit, 1 on the last meta-block)
//   ISLASTEMPTY           (1 bit, only when ISLAST; we never use this path
//                          unless the entire stream is empty)
//   MNIBBLES              (2 bits) — 0 = 4 nibbles (we always use 4)
//   MLEN-1                (16 bits) — fits up to 65 536 in our chunks
//   ISUNCOMPRESSED        (1 bit, omitted when ISLAST=1) — always 0 here
//   NBLTYPESL/I/D         (1 bit each) — all "1 block type"
//   NPOSTFIX (2), NDIRECT (4) — both zero
//   CMODE[0]              (2 bits) — LSB6
//   NTREESL               (1 bit) — 1 context, no literal context map
//   NTREESD               (1 bit) — 1 distance tree, no distance context map
//   <literal prefix code> — complex or simple-NSYM=1
//   <IC prefix code>     — complex or simple-NSYM=1
//   <distance prefix code> — complex or simple-NSYM=1
//   <command stream>     — Huffman-coded commands + literals
//
// For empty input the encoder emits just the WBITS header + ISLAST=1 +
// ISLASTEMPTY=1 + pad → a single 0x06 byte, preserving the wire output
// the old uncompressed-only encoder produced for empty input.

const MAX_BLOCK: usize = 1 << 16; // 65_536

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EncStage {
    NeedHeader,
    Buffering,
    Draining,
    Done,
}

#[derive(Debug, Clone)]
pub struct Encoder {
    pending: Vec<u8>,
    out: Vec<u8>,
    out_pos: usize,
    bw: BitWriter,
    stage: EncStage,
    /// Whether we've ever pushed input. When `finish` is called and we
    /// haven't pushed anything we emit the empty-stream terminator.
    seen_any_input: bool,
    /// Distance ring buffer, persistent across meta-blocks within a
    /// single stream — must mirror the decoder's view.
    ring: DistRing,
    /// Total bytes ever emitted across all completed meta-blocks of
    /// this stream. Mirrors the decoder's `total_out` and is used to
    /// compute `max_dist` for static-dictionary references.
    prev_total_out: u64,
    /// The two output bytes immediately preceding the next meta-block —
    /// the decoder's persistent `p1`/`p2` at block start. Used by the
    /// encoder's literal-context model to compute each literal's context
    /// id. Both 0 at stream start (matching the decoder).
    prev_out1: u8,
    prev_out2: u8,
    /// Lazily built static-dictionary index for encoder-side dictionary
    /// references. The index is ~80 KiB and is reused across meta-blocks.
    dict_index: Option<Rc<DictIndex>>,
    /// Cached identity-transform table (~64 entries). Used together with
    /// `dict_index` during the LZ77 pass.
    id_transforms: Option<Rc<Vec<IdTransform>>>,
    /// Match-finder tuning + feature toggles derived from
    /// [`EncoderConfig::quality`]. Persisted across `reset` since
    /// configuration is meant to survive resets.
    params: LevelParams,
    /// Reusable per-meta-block scratch — keeps match-finder boxes,
    /// frequency tables, and command vectors out of the per-block hot
    /// path allocator. Lazily initialised so empty-input streams pay no
    /// allocation cost.
    scratch: Option<EncScratch>,
}

/// Per-meta-block scratch buffers carried on the Encoder. Each field is
/// `clear()`ed (not freed) between meta-blocks so we keep the capacity
/// across the whole stream.
struct EncScratch {
    /// Hash-chain match finder, reused via `MatchFinder::reset` between
    /// meta-blocks rather than re-allocating its 128 KiB worth of
    /// Box<[u32; …]> tables.
    mf: MatchFinder,
    /// Commands produced by the LZ77 pass — each carries an
    /// `insert: Vec<u8>`.
    cmds: Vec<Command>,
    /// Free list of `Vec<u8>` buffers used as `Command::insert`. Lets us
    /// reuse the (often large) allocations across meta-blocks instead of
    /// freeing them every iteration.
    insert_pool: Vec<Vec<u8>>,
    /// Per-command planning output — all four vecs are aligned with
    /// `cmds[]` after `plan_commands`. Reused via `clear()`.
    ic_sym: Vec<u32>,
    ins_extra: Vec<(u32, u32)>,
    copy_extra: Vec<(u32, u32)>,
    dist_enc: Vec<Option<(u32, u32, u32)>>,
    /// Per-alphabet frequency tables — fixed-size arrays so they live
    /// inline in the struct rather than as boxed Vecs.
    lit_freq: [u32; 256],
    ic_freq: [u32; 704],
    dist_freq: [u32; 64],
}

impl core::fmt::Debug for EncScratch {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EncScratch")
            .field("cmds_cap", &self.cmds.capacity())
            .finish()
    }
}

impl Clone for EncScratch {
    fn clone(&self) -> Self {
        // Cloning an encoder is rare — produce a fresh scratch.
        Self::new()
    }
}

impl EncScratch {
    fn new() -> Self {
        Self {
            mf: MatchFinder::new(),
            cmds: Vec::new(),
            insert_pool: Vec::new(),
            ic_sym: Vec::new(),
            ins_extra: Vec::new(),
            copy_extra: Vec::new(),
            dist_enc: Vec::new(),
            lit_freq: [0u32; 256],
            ic_freq: [0u32; 704],
            dist_freq: [0u32; 64],
        }
    }

    /// Reset everything for a new meta-block. Capacity is retained.
    fn prepare(&mut self) {
        self.mf.reset();
        // Move existing Command::insert buffers into the pool before
        // clearing `cmds`, so we keep their capacity across blocks.
        while let Some(c) = self.cmds.pop() {
            let mut v = c.insert;
            v.clear();
            self.insert_pool.push(v);
        }
        self.ic_sym.clear();
        self.ins_extra.clear();
        self.copy_extra.clear();
        self.dist_enc.clear();
        self.lit_freq.fill(0);
        self.ic_freq.fill(0);
        self.dist_freq.fill(0);
    }
}

impl Encoder {
    /// Build an encoder at the default quality (6).
    pub fn new() -> Self {
        Self::with_config(EncoderConfig::default())
    }

    /// Build an encoder with explicit configuration. `config.quality`
    /// is clamped to `0..=11` internally — out-of-range values are
    /// snapped to the nearest valid quality rather than rejected.
    pub fn with_config(config: EncoderConfig) -> Self {
        Self {
            pending: Vec::new(),
            out: Vec::new(),
            out_pos: 0,
            bw: BitWriter::new(),
            stage: EncStage::NeedHeader,
            seen_any_input: false,
            ring: DistRing::new(),
            prev_total_out: 0,
            prev_out1: 0,
            prev_out2: 0,
            dict_index: None,
            id_transforms: None,
            params: LevelParams::from_quality(config.quality),
            scratch: None,
        }
    }

    /// Build (or reuse) the dictionary index and identity-transform
    /// table. Both are cached on the encoder so multi-meta-block streams
    /// pay the build cost once.
    fn ensure_dict_index(&mut self) {
        if self.dict_index.is_none() {
            self.dict_index = Some(Rc::new(DictIndex::build()));
        }
        if self.id_transforms.is_none() {
            self.id_transforms = Some(Rc::new(encoder_dict::identity_transforms()));
        }
    }

    fn compact_out(&mut self) {
        if self.out_pos == 0 {
            return;
        }
        if self.out_pos >= self.out.len() {
            self.out.clear();
        } else {
            self.out.drain(..self.out_pos);
        }
        self.out_pos = 0;
    }

    fn drain_out_into(&mut self, dst: &mut [u8]) -> usize {
        let avail = self.out.len() - self.out_pos;
        let n = avail.min(dst.len());
        if n > 0 {
            dst[..n].copy_from_slice(&self.out[self.out_pos..self.out_pos + n]);
            self.out_pos += n;
        }
        n
    }

    fn ensure_header(&mut self) {
        if self.stage == EncStage::NeedHeader {
            self.bw.write(0, 1, &mut self.out);
            self.stage = EncStage::Buffering;
        }
    }

    /// Emit one compressed meta-block. `is_last` controls the ISLAST
    /// bit; when set, ISLASTEMPTY=0 and ISUNCOMPRESSED is omitted.
    fn emit_compressed_block(&mut self, mlen: usize, is_last: bool) {
        debug_assert!((1..=MAX_BLOCK).contains(&mlen));
        debug_assert!(mlen <= self.pending.len());
        // Only pay the (~80 KiB) dictionary-index build cost on
        // quality tiers that actually consult the dictionary.
        if self.params.use_dict {
            self.ensure_dict_index();
        }
        if self.scratch.is_none() {
            self.scratch = Some(EncScratch::new());
        }
        let dict_index = self.dict_index.clone();
        let id_transforms = self.id_transforms.clone();
        let scratch = self.scratch.as_mut().expect("scratch initialised above");
        scratch.prepare();
        // We treat `pending[..mlen]` as the payload in place — no need
        // to allocate a separate Vec and drain. The drain happens after
        // we've finished encoding so the borrow doesn't conflict.
        let pending_view = &self.pending[..mlen];
        let prev_out1 = self.prev_out1;
        let prev_out2 = self.prev_out2;
        encode_meta_block(
            &mut self.bw,
            &mut self.out,
            pending_view,
            is_last,
            &mut self.ring,
            self.prev_total_out,
            prev_out1,
            prev_out2,
            dict_index.as_deref(),
            id_transforms.as_deref().map(|v| v.as_slice()),
            self.params,
            scratch,
        );
        // Carry the last two output bytes of this block into the next
        // block's literal-context state (mirrors the decoder's p1/p2).
        if mlen >= 2 {
            self.prev_out2 = self.pending[mlen - 2];
            self.prev_out1 = self.pending[mlen - 1];
        } else if mlen == 1 {
            self.prev_out2 = self.prev_out1;
            self.prev_out1 = self.pending[0];
        }
        self.pending.drain(..mlen);
        self.prev_total_out += mlen as u64;
    }

    /// Pre-emit any complete-and-not-possibly-last blocks. We keep the
    /// final MAX_BLOCK bytes pending so `finish` can emit them with
    /// ISLAST=1, avoiding an extra empty terminator block when input
    /// size is an exact multiple of MAX_BLOCK.
    fn flush_full_blocks(&mut self) {
        while self.pending.len() > MAX_BLOCK {
            self.emit_compressed_block(MAX_BLOCK, false);
        }
    }

    /// Emit the stream tail. Three cases:
    ///   - never saw any input → empty-stream terminator (single byte).
    ///   - pending data left → emit it in one final compressed block.
    ///   - pending is empty but we've emitted earlier non-final blocks
    ///     → emit the empty-last terminator (ISLAST=1, ISLASTEMPTY=1).
    fn emit_terminator(&mut self) {
        if !self.seen_any_input || self.pending.is_empty() {
            self.bw.write(1, 1, &mut self.out);
            self.bw.write(1, 1, &mut self.out);
            self.bw.align(&mut self.out);
            debug_assert_eq!(self.bw.pending_bits(), 0);
            return;
        }
        let n = self.pending.len();
        debug_assert!(n <= MAX_BLOCK);
        self.emit_compressed_block(n, true);
        debug_assert_eq!(self.bw.pending_bits(), 0);
    }
}

impl Default for Encoder {
    fn default() -> Self {
        Self::new()
    }
}

impl RawEncoder for Encoder {
    fn raw_encode(&mut self, input: &[u8], output: &mut [u8]) -> Result<RawProgress, Error> {
        if self.stage == EncStage::Done {
            return Err(Error::Corrupt);
        }
        let mut written = 0usize;
        if self.out_pos < self.out.len() {
            written += self.drain_out_into(&mut output[written..]);
            if written == output.len() {
                return Ok(RawProgress {
                    consumed: 0,
                    written,
                    done: false,
                });
            }
        }
        self.compact_out();
        self.ensure_header();
        if !input.is_empty() {
            self.seen_any_input = true;
        }
        self.pending.extend_from_slice(input);
        let consumed = input.len();
        self.flush_full_blocks();
        written += self.drain_out_into(&mut output[written..]);
        self.compact_out();
        Ok(RawProgress {
            consumed,
            written,
            done: false,
        })
    }

    fn raw_finish(&mut self, output: &mut [u8]) -> Result<RawProgress, Error> {
        if self.stage == EncStage::Done {
            return Ok(RawProgress {
                consumed: 0,
                written: 0,
                done: true,
            });
        }
        let mut written = 0usize;
        if self.out_pos < self.out.len() {
            written += self.drain_out_into(&mut output[written..]);
            if written == output.len() {
                return Ok(RawProgress {
                    consumed: 0,
                    written,
                    done: false,
                });
            }
        }
        self.compact_out();
        if self.stage != EncStage::Draining {
            self.ensure_header();
            self.flush_full_blocks();
            self.emit_terminator();
            self.stage = EncStage::Draining;
        }
        written += self.drain_out_into(&mut output[written..]);
        self.compact_out();
        let done = self.out_pos == self.out.len();
        if done {
            self.stage = EncStage::Done;
        }
        Ok(RawProgress {
            consumed: 0,
            written,
            done,
        })
    }

    fn raw_reset(&mut self) {
        self.pending.clear();
        self.out.clear();
        self.out_pos = 0;
        self.bw = BitWriter::new();
        self.stage = EncStage::NeedHeader;
        self.seen_any_input = false;
        self.ring = DistRing::new();
        self.prev_total_out = 0;
        self.prev_out1 = 0;
        self.prev_out2 = 0;
        // Keep `dict_index`, `id_transforms`, `params`, and `scratch` —
        // they're immutable tables / configuration / capacity we'd
        // rebuild identically. `scratch` is `prepare()`d before the next
        // meta-block so any stale state from the previous run is wiped.
    }
}

// ─── encoder helpers (compressed meta-block emission) ───────────────────

/// Count distinct literal bytes in `payload` (capped at 32 — we only
/// need a rough proxy for "literal entropy is high enough to make
/// dictionary references pay off").
fn distinct_bytes_low(payload: &[u8]) -> usize {
    let mut seen = [false; 256];
    let mut n = 0usize;
    for &b in payload {
        let s = &mut seen[b as usize];
        if !*s {
            *s = true;
            n += 1;
            if n >= 32 {
                return n;
            }
        }
    }
    n
}

/// LZ77 pass over the payload. Writes commands directly into
/// `scratch.cmds`, fusing what used to be `lz77_pass` (per-position
/// atoms) and `commands_from_atoms` (atom → command) into a single
/// walk. Each command pairs an insert-run of literals with the next
/// copy event.
///
/// At each position we consider both a real LZ77 match (via the
/// hash-chain finder) and a static-dictionary reference (via
/// [`encoder_dict::find_dict_match`]). The longer winner is emitted.
/// `prev_total_out` is the number of bytes emitted in prior meta-blocks
/// of the same stream; dictionary references are gated on the per-
/// command `max_dist`, which depends on the running output total.
///
/// When `dict_index` / `id_transforms` are `None` (low quality tiers),
/// the static-dictionary path is skipped entirely.
fn lz77_to_commands(
    payload: &[u8],
    dict_index: Option<&encoder_dict::DictIndex>,
    id_transforms: Option<&[encoder_dict::IdTransform]>,
    prev_total_out: u64,
    finder_params: encoder_lz77::FinderParams,
    ring_start: DistRing,
    scratch: &mut EncScratch,
) {
    use encoder_lz77::{MAX_MATCH, MIN_MATCH};
    // Disable dict-ref matching for inputs with very low literal
    // entropy (≤ 4 distinct bytes). On such inputs the literal
    // Huffman tree collapses to NSYM=1/2 (≤ 1 bit per literal) and
    // any dict ref's IC+distance overhead is pure loss.
    //
    // We also disable it when the caller passed no dictionary index
    // (low quality tier).
    let use_dict =
        dict_index.is_some() && id_transforms.is_some() && distinct_bytes_low(payload) >= 5;

    // Pre-reserve enough capacity for a worst-case command-count
    // estimate (one per ~8 input bytes is generous for compressible
    // text; for random input the upper bound is bytes/MIN_MATCH ≈
    // bytes/4). Keeping `cmds` from re-allocating during the hot loop
    // is a measurable win.
    let estimate = (payload.len() / 4).max(16);
    if scratch.cmds.capacity() < estimate {
        scratch.cmds.reserve(estimate - scratch.cmds.capacity());
    }

    // Split-borrow the scratch up-front so the hot inner loop talks to
    // raw fields rather than going through method calls on
    // `&mut EncScratch`.
    let EncScratch {
        mf,
        cmds,
        insert_pool,
        ..
    } = scratch;

    // Pending literal-run accumulator for the next command. Reuses an
    // existing `Vec<u8>` from the insert-buffer free list to keep the
    // allocator out of the hot path. Pre-reserve a chunk so the first
    // few pushes don't trigger a tiny initial allocation.
    let mut pending: Vec<u8> = insert_pool.pop().unwrap_or_default();
    if pending.capacity() < 64 {
        pending.reserve(64 - pending.capacity());
    }
    let payload_len = payload.len();
    let mut pos = 0usize;
    // Local distance ring, mirroring the one `plan_commands` will rebuild,
    // so the repeat-distance preference sees the same recent distances the
    // decoder will. Backref distances push (unless they equal the current
    // last distance — short code 0 does not push); dictionary refs never
    // push. This must stay in lockstep with `plan_commands`.
    let mut ring = ring_start;

    // We mirror the decoder's `total_out`: it's `prev_total_out` plus
    // the number of input bytes encoded so far in this meta-block. For
    // dictionary references this drives `max_dist` so the chosen
    // distance survives the magnitude comparison against `max_dist`.
    while pos < payload_len {
        mf.insert(payload, pos);

        let mut best_len: usize = 0;
        // 0 = none, 1 = match, 2 = dict
        let mut best_kind: u8 = 0;
        let mut best_match_dist: u32 = 0;
        let mut best_dict_word_len: u8 = 0;
        let mut best_dict_word_idx: u32 = 0;
        let mut best_dict_tr_id: u8 = 0;
        let mut best_dict_emit_len: u32 = 0;

        // 1) In-window LZ77 match. At higher qualities we use the
        //    cost-aware finder, which prefers closer (cheaper-distance)
        //    matches over marginally longer far ones.
        let found = if pos + MIN_MATCH <= payload_len {
            if finder_params.cost_match {
                mf.find_match_cost(payload, pos, finder_params)
            } else {
                mf.find_match(payload, pos, finder_params)
            }
        } else {
            None
        };
        if let Some((len, dist)) = found {
            let len = len.min(MAX_MATCH).min(payload_len - pos);
            if len >= MIN_MATCH {
                best_len = len;
                best_kind = 1;
                best_match_dist = dist as u32;
            }
        }

        // 1b) Repeat-distance preference. A match reachable at one of the
        //     four most-recent distances encodes its distance as a cheap
        //     short code (≈4 bits, no extra) instead of a full symbol plus
        //     up to 24 extra bits, so even a shorter repeat-distance match
        //     usually wins on total bits. Distance coding is ~58% of our
        //     output, so this is the dominant ratio lever.
        //
        //     We compare candidates by an approximate *gain* model:
        //       gain(len, dist) = len * VALUE_PER_BYTE - distance_cost(dist)
        //     where a covered byte is worth ~`VALUE_PER_BYTE` bits and a
        //     far distance costs ~log2(dist) extra bits plus its symbol.
        //     The candidate with the highest gain is taken; ties favour the
        //     longer match.
        if pos + MIN_MATCH <= payload_len && best_kind != 2 {
            // Bit cost of a distance: ring distances are short codes;
            // everything else pays its symbol + extra bits (~log2(d)).
            let last1 = ring.nth_last(1);
            let dist_cost = |d: u32, is_repeat: bool| -> i64 {
                if is_repeat {
                    // Short code: ~2 bits when it is the last distance
                    // (code 0), ~5 bits for the other ring slots.
                    if d as i32 == last1 { 2 } else { 5 }
                } else {
                    // Symbol (~6 bits) + extra (~floor(log2(d))).
                    let lg = 31 - d.max(1).leading_zeros();
                    (6 + lg) as i64
                }
            };
            const VALUE_PER_BYTE: i64 = 6;

            // Baseline gain from the longest match (if any).
            let mut best_gain: i64 = if best_kind == 1 {
                best_len as i64 * VALUE_PER_BYTE - dist_cost(best_match_dist, false)
            } else {
                i64::MIN
            };

            for n in 1u32..=4 {
                let rd = ring.nth_last(n);
                if rd <= 0 {
                    continue;
                }
                let rd = rd as usize;
                if rd > pos {
                    continue;
                }
                let rl = encoder_lz77::match_len_at(payload, pos, rd);
                if rl < MIN_MATCH {
                    continue;
                }
                let gain = rl as i64 * VALUE_PER_BYTE - dist_cost(rd as u32, true);
                if gain > best_gain {
                    best_gain = gain;
                    best_len = rl;
                    best_kind = 1;
                    best_match_dist = rd as u32;
                }
            }
        }

        // 2) Static-dictionary reference. Heuristic: only consider dict
        //    refs when emitted length is long enough to amortise the
        //    distance-code cost (≥ 6 bytes with no LZ77 alternative,
        //    ≥ best_len + 3 when LZ77 found something).
        if use_dict {
            let dict_min_emit = if best_len >= 4 {
                (best_len + 3) as u32
            } else {
                6u32
            };
            if let Some(dm) = encoder_dict::find_dict_match(
                dict_index.unwrap(),
                id_transforms.unwrap(),
                payload,
                pos,
                dict_min_emit,
            ) {
                let total_out_at_pos: u64 = prev_total_out + pos as u64;
                let max_dist: u64 = core::cmp::min((1u64 << 16) - 16, total_out_at_pos);
                let len = dm.word_len as usize;
                let nwords_bits = dictionary::SIZE_BITS_BY_LENGTH[len] as u32;
                let off = (dm.word_idx as u64) | ((dm.transform_id as u64) << nwords_bits);
                let distance = max_dist + 1 + off;
                if distance <= u32::MAX as u64 && distance > 0 && (dm.emit_len as usize) > best_len
                {
                    best_len = dm.emit_len as usize;
                    best_kind = 2;
                    best_dict_word_len = dm.word_len;
                    best_dict_word_idx = dm.word_idx;
                    best_dict_tr_id = dm.transform_id;
                    best_dict_emit_len = dm.emit_len;
                }
            }
        }

        if best_kind != 0 {
            // Splice every covered position into the hash chain.
            for j in 1..best_len {
                let p = pos + j;
                if p + MIN_MATCH <= payload_len {
                    mf.insert(payload, p);
                }
            }
            // Flush pending literals + this copy as a single Command.
            // Swap a fresh empty insert Vec in via the pool to keep
            // the next iteration's pending accumulator allocation-free.
            let next_pending = insert_pool.pop().unwrap_or_default();
            let cmd_kind = if best_kind == 1 {
                CopyKind::Backref {
                    distance: best_match_dist,
                }
            } else {
                CopyKind::Dict {
                    word_idx: best_dict_word_idx,
                    transform_id: best_dict_tr_id,
                    emit_len: best_dict_emit_len,
                }
            };
            let copy_len = if best_kind == 1 {
                best_len as u32
            } else {
                best_dict_word_len as u32
            };
            // Mirror the ring update `plan_commands` will perform: a
            // back-reference pushes its distance unless it equals the
            // current last distance (short code 0, which does not push);
            // dictionary references never push.
            if best_kind == 1 {
                let d = best_match_dist as i32;
                if d != ring.nth_last(1) {
                    ring.push(d);
                }
            }
            cmds.push(Command {
                insert: core::mem::replace(&mut pending, next_pending),
                copy_len,
                kind: cmd_kind,
            });
            pos += best_len;
            continue;
        }

        // No copy at this position — accumulate as a literal.
        pending.push(payload[pos]);
        pos += 1;
    }

    // Tail: either a final no-copy command (when literals remain), or
    // recycle the buffer if we already pushed a final command.
    if !pending.is_empty() || cmds.is_empty() {
        cmds.push(Command {
            insert: pending,
            copy_len: 0,
            kind: CopyKind::None,
        });
    } else {
        pending.clear();
        insert_pool.push(pending);
    }
}

/// What kind of copy the command carries.
#[derive(Clone, Copy)]
enum CopyKind {
    /// No copy at all (only the last command can have this).
    None,
    /// Normal back-reference. `distance` is the back-distance in bytes.
    Backref { distance: u32 },
    /// Static-dictionary reference. The encoder will compute the actual
    /// distance value at command-emit time using the running `total_out`
    /// to derive `max_dist`. `emit_len` is the number of input bytes
    /// consumed (used to advance the cursor, not the `copy_len` field).
    Dict {
        word_idx: u32,
        transform_id: u8,
        emit_len: u32,
    },
}

/// Convert the per-position LZ77 stream into brotli commands. Each
/// command consumes an insert-length run of literals followed (except
/// possibly the last) by a copy.
struct Command {
    insert: Vec<u8>,
    /// For Backref commands: copy length in bytes. For Dict commands:
    /// the dictionary word length (4..=24). Both end up in the IC
    /// command's copy-length field.
    copy_len: u32,
    kind: CopyKind,
}

/// Distance ring buffer used by the encoder to match short codes from
/// the decoder's ring buffer. Initialised per §4 to `[16, 15, 11, 4]`.
#[derive(Debug, Clone, Copy)]
struct DistRing {
    ring: [i32; 4],
    idx: u32,
}

impl DistRing {
    fn new() -> Self {
        Self {
            ring: [16, 15, 11, 4],
            idx: 0,
        }
    }

    /// Get the n-th most-recently-pushed distance (1..=4).
    fn nth_last(&self, n: u32) -> i32 {
        debug_assert!((1..=4).contains(&n));
        self.ring[((self.idx.wrapping_add(4 - n)) & 3) as usize]
    }

    fn push(&mut self, d: i32) {
        let slot = (self.idx & 3) as usize;
        self.ring[slot] = d;
        self.idx = self.idx.wrapping_add(1);
    }

    /// Try to map `distance` to a short-code 0..=15. Returns Some(code)
    /// if a short code applies; code 0 does not push to the ring, others
    /// do.
    fn try_short_code(&self, distance: u32) -> Option<u32> {
        let d = distance as i32;
        let last = self.nth_last(1);
        let last2 = self.nth_last(2);
        // Code 0: most recent distance (no ring update).
        if d == last {
            return Some(0);
        }
        if d == self.nth_last(2) {
            return Some(1);
        }
        if d == self.nth_last(3) {
            return Some(2);
        }
        if d == self.nth_last(4) {
            return Some(3);
        }
        // Codes 4..=9: last ± {1, 2, 3}.
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
            // Codes 10..=15: last2 ± {1, 2, 3}.
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
}

/// Plan how to encode each command: choose IC symbol, decide whether
/// to use a short distance code, etc. Mutates the supplied ring buffer
/// in-place so the encoder's view tracks the decoder's view across
/// meta-block boundaries.
///
/// Also folds in the per-alphabet frequency tally so we don't walk
/// every command twice.
///
/// `prev_total_out` is the number of bytes already emitted in prior
/// meta-blocks of this stream. The encoder uses it together with the
/// running per-meta-block emission count to compute `max_dist`, which
/// determines the distance value for static-dictionary references and
/// must agree exactly with what the decoder computes.
fn plan_commands(
    mlen: u32,
    ring: &mut DistRing,
    prev_total_out: u64,
    window_size: u32,
    scratch: &mut EncScratch,
) {
    use encoder_iac::{copy_to_code, distance_to_normal_code, ic_command_sym, insert_to_code};

    let cmds_len = scratch.cmds.len();
    scratch.ic_sym.reserve(cmds_len);
    scratch.ins_extra.reserve(cmds_len);
    scratch.copy_extra.reserve(cmds_len);
    scratch.dist_enc.reserve(cmds_len);

    // Split the borrow so the inner per-command iteration can read
    // scratch.cmds while writing the planning vectors and frequency
    // tables.
    let EncScratch {
        cmds,
        ic_sym,
        ins_extra,
        copy_extra,
        dist_enc,
        lit_freq,
        ic_freq,
        dist_freq,
        ..
    } = scratch;

    let mut emitted: u32 = 0;
    for (i, c) in cmds.iter().enumerate() {
        let is_last_cmd = i == cmds_len - 1;
        let insert_len = c.insert.len() as u32;
        // Fold the literal-frequency tally into the planning loop — saves
        // a second walk over every Command.
        for &b in &c.insert {
            lit_freq[b as usize] += 1;
        }
        let (ins_code, ins_eb, ins_ev) = insert_to_code(insert_len);

        // For commands without a copy (only happens on the last
        // command), we still need to pick a copy code (the decoder
        // reads its extra bits even if the copy is then skipped).
        // Use copy code 0 (copy_len base 2, zero extra bits).
        let (copy_code, copy_eb, copy_ev, use_last_dist, dist_plan) = match c.kind {
            CopyKind::Backref { distance } => {
                let (cc, ceb, cev) = copy_to_code(c.copy_len);
                // Pick distance encoding. The use_last shortcut requires
                // ins_code < 8 AND copy_code < 16, since only IC cells 0
                // and 1 support use_last_dist=true. For larger inserts or
                // copies, we must use the explicit distance encoding even
                // if the distance happens to match the ring buffer.
                let can_use_last = ins_code < 8 && cc < 16;
                let short = ring.try_short_code(distance);
                match short {
                    Some(0) if can_use_last => {
                        // use_last_dist=true. No ring update (per §4 code 0).
                        (cc, ceb, cev, true, None)
                    }
                    Some(0) => {
                        // The IC cell forbids use_last_dist=true. Emit
                        // distance code 0 explicitly — the decoder
                        // resolves it to last_dist and does NOT push
                        // to the ring (§4 code 0).
                        (cc, ceb, cev, false, Some((0u32, 0u32, 0u32)))
                    }
                    Some(code) => {
                        // Short code 1..=15. Pushes to the ring.
                        ring.push(distance as i32);
                        (cc, ceb, cev, false, Some((code, 0, 0)))
                    }
                    None => {
                        let (dcode, ndistbits, dextra) =
                            distance_to_normal_code(distance).expect("encodable distance");
                        ring.push(distance as i32);
                        (cc, ceb, cev, false, Some((dcode, ndistbits, dextra)))
                    }
                }
            }
            CopyKind::Dict {
                word_idx,
                transform_id,
                ..
            } => {
                // Dictionary references: `copy_len` here is the word
                // length (4..=24). The decoder will interpret the
                // command's copy field as the word length to look up
                // in the dictionary. We must emit an explicit distance
                // (no use_last_dist, no short code), and that distance
                // must be `> max_dist` at the decoder's read time.
                let (cc, ceb, cev) = copy_to_code(c.copy_len);
                let total_out_at_cmd: u64 = prev_total_out + emitted as u64 + insert_len as u64;
                let max_dist: u64 =
                    core::cmp::min(window_size.saturating_sub(16) as u64, total_out_at_cmd);
                let nwords_bits = dictionary::SIZE_BITS_BY_LENGTH[c.copy_len as usize] as u32;
                let off = (word_idx as u64) | ((transform_id as u64) << nwords_bits);
                let distance: u64 = max_dist + 1 + off;
                debug_assert!(distance <= u32::MAX as u64, "dictionary distance overflow");
                let (dcode, ndistbits, dextra) =
                    distance_to_normal_code(distance as u32).expect("encodable dict distance");
                // Dictionary refs DO NOT push onto the ring buffer
                // (per the decoder side).
                (cc, ceb, cev, false, Some((dcode, ndistbits, dextra)))
            }
            CopyKind::None => {
                // No copy. Pick any valid (copy_code, use_last) such that
                // the resulting IC cmd is valid. The decoder breaks out
                // of the loop before reading any distance once `emitted >=
                // mlen`, so we don't write a distance regardless of
                // use_last.
                if ins_code < 8 {
                    (0, 0, 0, true, None)
                } else {
                    // use_last_dist=false (cells 0/1 are out of range).
                    (0, 0, 0, false, None)
                }
            }
        };

        let use_last_for_ic = if is_last_cmd && matches!(c.kind, CopyKind::None) {
            ins_code < 8 // can use cell 0 if ins_code fits
        } else {
            use_last_dist
        };
        let sym = ic_command_sym(ins_code, copy_code, use_last_for_ic);

        ic_sym.push(sym);
        ins_extra.push((ins_eb, ins_ev));
        copy_extra.push((copy_eb, copy_ev));
        dist_enc.push(dist_plan);

        // Fused IC + dist frequency tally — saves an extra pass over
        // every command before Huffman tree construction.
        ic_freq[sym as usize] += 1;
        if let Some((dcode, _, _)) = dist_plan {
            dist_freq[dcode as usize] += 1;
        }

        emitted += insert_len;
        match c.kind {
            CopyKind::Backref { .. } => emitted += c.copy_len,
            CopyKind::Dict { emit_len, .. } => emitted += emit_len,
            CopyKind::None => {}
        }
    }
    debug_assert!(
        emitted == mlen,
        "command emission ({emitted}) does not match mlen ({mlen})"
    );
}

/// Build the meta-block header bits *up to but not including* the
/// literal context mode. `is_last` controls whether ISLAST/ISLASTEMPTY
/// are emitted; on the last meta-block ISUNCOMPRESSED is omitted.
///
/// The CMODE / NTREESL / literal-context-map / NTREESD fields are emitted
/// separately by the caller (see [`write_literal_context_header`]) since
/// they depend on whether the encoder chose to model literal contexts.
fn write_meta_block_header(bw: &mut BitWriter, out: &mut Vec<u8>, mlen: u32, is_last: bool) {
    debug_assert!(mlen >= 1 && mlen <= MAX_BLOCK as u32);
    // ISLAST
    bw.write(if is_last { 1 } else { 0 }, 1, out);
    if is_last {
        // ISLASTEMPTY = 0
        bw.write(0, 1, out);
    }
    // MNIBBLES = 0 → 4 nibbles
    bw.write(0, 2, out);
    // MLEN - 1 in 4 nibbles = 16 bits
    bw.write(mlen - 1, 16, out);
    if !is_last {
        // ISUNCOMPRESSED = 0
        bw.write(0, 1, out);
    }
    // NBLTYPESL = 1 → "0" (1 bit)
    bw.write(0, 1, out);
    // NBLTYPESI = 1
    bw.write(0, 1, out);
    // NBLTYPESD = 1
    bw.write(0, 1, out);
    // NPOSTFIX = 0 (2 bits)
    bw.write(0, 2, out);
    // NDIRECT = 0 (4 bits)
    bw.write(0, 4, out);
}

/// Emit CMODE[0], NTREESL + (optional) literal context map, and NTREESD.
///
/// When `num_lit_trees == 1` this reproduces the legacy single-tree
/// header: CMODE is irrelevant (one tree, all-zero map), NTREESL=1,
/// NTREESD=1. When `num_lit_trees >= 2` it emits the chosen context mode,
/// NTREESL, and the literal context map `cmap` (one tree index per
/// context, 0..63).
fn write_literal_context_header(
    bw: &mut BitWriter,
    out: &mut Vec<u8>,
    cmode: u32,
    num_lit_trees: u32,
    cmap: &[u8],
) {
    // CMODE[0] (2 bits). With a single tree the value is decode-irrelevant
    // (the context map is all zero), so 0 (LSB6) keeps the legacy bytes.
    let cmode_bits = if num_lit_trees >= 2 { cmode } else { 0 };
    bw.write(cmode_bits, 2, out);
    if num_lit_trees >= 2 {
        // NTREESL = num_lit_trees, encoded with the nbltypes scheme.
        write_nbltypes(bw, out, num_lit_trees);
        // Literal context map of size 64 * NBLTYPESL = 64.
        write_context_map(bw, out, cmap, num_lit_trees);
    } else {
        // NTREESL = 1 → "0".
        bw.write(0, 1, out);
    }
    // NTREESD = 1 → "0" (we never split distance trees).
    bw.write(0, 1, out);
}

/// Encode a count using brotli's NBLTYPES / NTREES variable-length code
/// (§9.2 "1 + ..."). Inverse of [`Decoder::read_nbltypes`].
fn write_nbltypes(bw: &mut BitWriter, out: &mut Vec<u8>, value: u32) {
    debug_assert!(value >= 1);
    if value == 1 {
        bw.write(0, 1, out);
        return;
    }
    // First bit 1, then 3-bit selector N, then N extra bits.
    bw.write(1, 1, out);
    if value == 2 {
        // N = 0 → value 2.
        bw.write(0, 3, out);
        return;
    }
    // value = (1 << n) + 1 + extra, with extra < (1 << n).
    let v = value - 1; // value - 1 = (1<<n) + extra
    let n = 31 - v.leading_zeros(); // floor(log2(v)) since v >= 2
    let extra = v - (1u32 << n);
    debug_assert!(extra < (1u32 << n));
    bw.write(n, 3, out);
    bw.write(extra, n, out);
}

/// Emit a context map (literal or distance) using the simplest valid
/// encoding: RLEMAX=0 (no zero-run codes), a prefix code over `ntrees`
/// symbols built from the map's own value frequencies, the map values
/// verbatim, then IMTF=0 (no move-to-front).
///
/// Inverse of [`read_context_map`].
fn write_context_map(bw: &mut BitWriter, out: &mut Vec<u8>, map: &[u8], ntrees: u32) {
    debug_assert!(ntrees >= 2);
    // RLEMAX = 0 → single "0" bit, no extra.
    bw.write(0, 1, out);
    // Prefix code over the `ntrees` map symbols. Build from frequencies.
    let mut freq = alloc::vec![0u32; ntrees as usize];
    for &m in map {
        freq[m as usize] += 1;
    }
    let strategy = pick_huffman_strategy(&freq, ntrees as usize);
    let codes = emit_prefix_code(bw, out, &strategy, ntrees);
    // Emit each map entry as a symbol.
    for &m in map {
        write_symbol(bw, out, &strategy, &codes, m as u32);
    }
    // IMTF = 0.
    bw.write(0, 1, out);
}

/// Huffman strategy chosen for one alphabet.
enum HuffStrategy {
    /// One symbol used, zero bits per emission.
    SingleSymbol(u32),
    /// Two symbols used, one bit each. `(symbols, codes)` are aligned —
    /// `codes[i]` is the 1-bit code for `symbols[i]`.
    TwoSymbols { symbols: [u32; 2], codes: [u32; 2] },
    /// General case: a code-length array per symbol of the alphabet.
    Complex(Vec<u8>),
}

/// Choose a prefix-code strategy for an alphabet given symbol frequencies.
///
/// Simple-NSYM=1 / NSYM=2 are preferred over complex codes when the
/// alphabet has only 1 or 2 distinct used symbols — both because they
/// save bits and because they sidestep cl-cl edge cases where the
/// RLE-encoded code lengths would lack the variety needed for a valid
/// Kraft-balanced cl-cl tree.
fn pick_huffman_strategy(freqs: &[u32], alphabet_size: usize) -> HuffStrategy {
    // Scan until we've seen three nonzero symbols. Anything beyond two
    // falls into the complex-code branch — no need to record the rest.
    let mut first: Option<u32> = None;
    let mut second: Option<u32> = None;
    for (i, &f) in freqs.iter().enumerate() {
        if f == 0 {
            continue;
        }
        if first.is_none() {
            first = Some(i as u32);
        } else if second.is_none() {
            second = Some(i as u32);
        } else {
            // Third nonzero symbol — complex code wins.
            let lengths = encoder_huffman::build_huffman_lengths(freqs, alphabet_size);
            return HuffStrategy::Complex(lengths);
        }
    }
    match (first, second) {
        (None, _) => HuffStrategy::SingleSymbol(0),
        (Some(a), None) => HuffStrategy::SingleSymbol(a),
        (Some(a), Some(b)) => HuffStrategy::TwoSymbols {
            symbols: [a, b],
            codes: [0, 1],
        },
    }
}

/// Encode a complete compressed meta-block carrying `payload` bytes.
#[allow(clippy::too_many_arguments)]
fn encode_meta_block(
    bw: &mut BitWriter,
    out: &mut Vec<u8>,
    payload: &[u8],
    is_last: bool,
    ring: &mut DistRing,
    prev_total_out: u64,
    prev1: u8,
    prev2: u8,
    dict_index: Option<&DictIndex>,
    id_transforms: Option<&[IdTransform]>,
    level: LevelParams,
    scratch: &mut EncScratch,
) {
    let mlen = payload.len() as u32;
    debug_assert!(mlen >= 1 && mlen <= MAX_BLOCK as u32);
    // Window size = 1 << WBITS = 1 << 16 (the encoder always picks WBITS=16).
    const WINDOW_SIZE: u32 = 1 << 16;

    // 1. Run LZ77 + command construction. On the top quality tiers we use
    //    the iterative optimal (zopfli-style) forward DP; otherwise the
    //    single-pass greedy parser. Both produce the same `Command`
    //    stream that `plan_commands` consumes. The match finder is given a
    //    copy of the block-start distance ring so its repeat-distance
    //    preference matches what `plan_commands`/the decoder will see;
    //    `plan_commands` then advances the real ring.
    let mut used_optimal = false;
    if level.opt_passes > 0 {
        let EncScratch {
            mf,
            cmds,
            insert_pool,
            ..
        } = scratch;
        cmds.clear();
        let dp_finder = encoder_lz77::FinderParams {
            max_chain: level.finder.max_chain,
            nice_match: level.finder.nice_match.max(258),
            cost_match: false,
        };
        encoder_optimal::optimal_parse(
            payload,
            mf,
            dict_index,
            id_transforms,
            prev_total_out,
            *ring,
            level.opt_passes,
            dp_finder,
            cmds,
            insert_pool,
        );
        used_optimal = !cmds.is_empty();
    }
    if !used_optimal {
        lz77_to_commands(
            payload,
            dict_index,
            id_transforms,
            prev_total_out,
            level.finder,
            *ring,
            scratch,
        );
    }
    // 2. Plan + tally frequencies in a single pass.
    plan_commands(mlen, ring, prev_total_out, WINDOW_SIZE, scratch);

    // 3. Decide whether to model literal contexts. We do so when the
    //    encoder is on a dictionary-enabled tier (quality ≥ 4) and the
    //    payload is large enough to amortise multiple prefix-code
    //    headers. Below that threshold the single-tree path wins on
    //    overhead.
    let lit_model = if level.use_dict && payload.len() >= 1024 {
        build_literal_context_model(payload, prev1, prev2, scratch)
    } else {
        None
    };

    // 4. Pick Huffman strategies. For literals, either a single tree
    //    (legacy) or one tree per cluster.
    let ic_strategy = pick_huffman_strategy(&scratch.ic_freq, 704);
    let dist_strategy = pick_huffman_strategy(&scratch.dist_freq, 64);

    match lit_model {
        Some(model) if model.num_trees >= 2 => {
            encode_meta_block_with_contexts(
                bw,
                out,
                payload,
                mlen,
                is_last,
                prev1,
                prev2,
                &ic_strategy,
                &dist_strategy,
                &model,
                scratch,
            );
        }
        _ => {
            // Legacy single-literal-tree path.
            let lit_strategy = pick_huffman_strategy(&scratch.lit_freq, 256);
            write_meta_block_header(bw, out, mlen, is_last);
            write_literal_context_header(bw, out, 0, 1, &[]);
            let lit_codes = emit_prefix_code(bw, out, &lit_strategy, 256);
            let ic_codes = emit_prefix_code(bw, out, &ic_strategy, 704);
            let dist_codes = emit_prefix_code(bw, out, &dist_strategy, 64);

            let scratch_view: &EncScratch = scratch;
            let cmds_len = scratch_view.cmds.len();
            for i in 0..cmds_len {
                let sym = scratch_view.ic_sym[i];
                write_symbol(bw, out, &ic_strategy, &ic_codes, sym);
                let (ieb, iev) = scratch_view.ins_extra[i];
                if ieb > 0 {
                    bw.write(iev, ieb, out);
                }
                let (ceb, cev) = scratch_view.copy_extra[i];
                if ceb > 0 {
                    bw.write(cev, ceb, out);
                }
                let insert = &scratch_view.cmds[i].insert;
                match &lit_strategy {
                    HuffStrategy::Complex(lengths) => {
                        for &b in insert {
                            let len = lengths[b as usize] as u32;
                            debug_assert!(len > 0);
                            let code = lit_codes[b as usize];
                            let rev = reverse_bits(code as u32, len);
                            bw.write(rev, len, out);
                        }
                    }
                    _ => {
                        for &b in insert {
                            write_symbol(bw, out, &lit_strategy, &lit_codes, b as u32);
                        }
                    }
                }
                if let Some((dcode, ndb, dextra)) = scratch_view.dist_enc[i] {
                    write_symbol(bw, out, &dist_strategy, &dist_codes, dcode);
                    if ndb > 0 {
                        bw.write(dextra, ndb, out);
                    }
                }
            }
        }
    }

    // 7. Byte-align the stream at the end of the meta-block? Per RFC,
    //    bit-alignment is NOT required between meta-blocks (only the
    //    uncompressed type aligns). For ISLAST we DO align (to make
    //    the stream a valid byte sequence). For non-last we don't
    //    need to — bits flow into the next meta-block's header.
    if is_last {
        bw.align(out);
    }
}

/// Build the per-context literal histograms for this meta-block and run
/// the clustering. Returns `None` when the model collapses to a single
/// tree (caller falls back to the legacy single-tree path).
///
/// `prev1`/`prev2` are the two output bytes preceding the block. The
/// literal bytes are exactly the `insert` runs of the planned commands;
/// their output positions follow the command cursor, and `p1`/`p2` for
/// each literal are the two immediately-preceding output bytes (which —
/// since the decoded output equals `payload` — we read straight from
/// `payload`).
fn build_literal_context_model(
    payload: &[u8],
    prev1: u8,
    prev2: u8,
    scratch: &EncScratch,
) -> Option<encoder_ctx::LiteralContextModel> {
    use encoder_ctx::NUM_CONTEXTS;

    // First, count total literals — bail cheaply when there are too few to
    // benefit from per-context trees.
    let total_lits: u64 = scratch.cmds.iter().map(|c| c.insert.len() as u64).sum();
    if total_lits < 256 {
        return None;
    }

    // Evaluate each candidate context mode: tally per-context histograms,
    // cluster, and keep the model with the lowest estimated cost. The
    // histogram pass is O(literals) per mode and cheap next to LZ77.
    let mut best: Option<encoder_ctx::LiteralContextModel> = None;
    for &mode in &encoder_ctx::CANDIDATE_MODES {
        let mut histograms: Vec<[u32; 256]> = alloc::vec![[0u32; 256]; NUM_CONTEXTS];
        let mut g: usize = 0;
        for c in &scratch.cmds {
            for &b in &c.insert {
                let p1 = if g >= 1 { payload[g - 1] } else { prev1 };
                let p2 = if g >= 2 {
                    payload[g - 2]
                } else if g == 1 {
                    prev1
                } else {
                    prev2
                };
                let cid = encoder_ctx::context_id(mode, p1, p2) as usize;
                histograms[cid][b as usize] += 1;
                g += 1;
            }
            match c.kind {
                CopyKind::Backref { .. } => g += c.copy_len as usize,
                CopyKind::Dict { emit_len, .. } => g += emit_len as usize,
                CopyKind::None => {}
            }
        }
        let model = encoder_ctx::cluster(mode, histograms, encoder_ctx::MAX_LITERAL_TREES);
        match &best {
            Some(b) if b.est_cost_bits <= model.est_cost_bits => {}
            _ => best = Some(model),
        }
    }

    match best {
        Some(model) if model.num_trees >= 2 => Some(model),
        _ => None,
    }
}

/// Emit a meta-block using literal context modeling: one literal Huffman
/// tree per cluster, selected per byte through the context map.
#[allow(clippy::too_many_arguments)]
fn encode_meta_block_with_contexts(
    bw: &mut BitWriter,
    out: &mut Vec<u8>,
    payload: &[u8],
    mlen: u32,
    is_last: bool,
    prev1: u8,
    prev2: u8,
    ic_strategy: &HuffStrategy,
    dist_strategy: &HuffStrategy,
    model: &encoder_ctx::LiteralContextModel,
    scratch: &EncScratch,
) {
    let _ = mlen;
    let num_trees = model.num_trees as usize;

    // Per-tree literal frequency tables: fold each context's histogram
    // into its assigned tree.
    let mut tree_freqs: Vec<[u32; 256]> = alloc::vec![[0u32; 256]; num_trees];
    for (cid, hist) in model.histograms.iter().enumerate() {
        let t = model.cmap[cid] as usize;
        let dst = &mut tree_freqs[t];
        for (d, h) in dst.iter_mut().zip(hist.iter()) {
            *d += *h;
        }
    }

    // Build a strategy + code table per tree.
    let lit_strategies: Vec<HuffStrategy> = tree_freqs
        .iter()
        .map(|f| pick_huffman_strategy(f, 256))
        .collect();

    // Header.
    write_meta_block_header(bw, out, mlen, is_last);
    write_literal_context_header(bw, out, model.mode as u32, model.num_trees, &model.cmap);

    // Literal prefix codes (one per tree), in tree-index order.
    let mut lit_codes: Vec<Vec<u16>> = Vec::with_capacity(num_trees);
    for strat in &lit_strategies {
        lit_codes.push(emit_prefix_code(bw, out, strat, 256));
    }
    // IC + distance prefix codes.
    let ic_codes = emit_prefix_code(bw, out, ic_strategy, 704);
    let dist_codes = emit_prefix_code(bw, out, dist_strategy, 64);

    // Emit the command stream, selecting a literal tree per byte from its
    // context. `g` tracks the output position so we can read p1/p2 from
    // `payload` (output == payload for this block).
    let cmds_len = scratch.cmds.len();
    let mut g: usize = 0;
    for i in 0..cmds_len {
        let sym = scratch.ic_sym[i];
        write_symbol(bw, out, ic_strategy, &ic_codes, sym);
        let (ieb, iev) = scratch.ins_extra[i];
        if ieb > 0 {
            bw.write(iev, ieb, out);
        }
        let (ceb, cev) = scratch.copy_extra[i];
        if ceb > 0 {
            bw.write(cev, ceb, out);
        }
        for &b in &scratch.cmds[i].insert {
            let p1 = if g >= 1 { payload[g - 1] } else { prev1 };
            let p2 = if g >= 2 {
                payload[g - 2]
            } else if g == 1 {
                prev1
            } else {
                prev2
            };
            let cid = encoder_ctx::context_id(model.mode, p1, p2) as usize;
            let t = model.cmap[cid] as usize;
            write_symbol(bw, out, &lit_strategies[t], &lit_codes[t], b as u32);
            g += 1;
        }
        if let Some((dcode, ndb, dextra)) = scratch.dist_enc[i] {
            write_symbol(bw, out, dist_strategy, &dist_codes, dcode);
            if ndb > 0 {
                bw.write(dextra, ndb, out);
            }
        }
        // Advance output cursor past the copy.
        match scratch.cmds[i].kind {
            CopyKind::Backref { .. } => g += scratch.cmds[i].copy_len as usize,
            CopyKind::Dict { emit_len, .. } => g += emit_len as usize,
            CopyKind::None => {}
        }
    }
}

/// Emit the prefix-code header bits for one alphabet. Returns the
/// per-symbol code values needed when later emitting data symbols.
/// Caller uses these together with the original `HuffStrategy` to
/// dispatch via `write_symbol`.
///
/// For NSYM=1 we return an empty vec — `write_symbol` ignores `codes`.
/// For NSYM=2 we return a 2-entry vec aligned with `symbols` of the
/// strategy. For complex codes we return the canonical (MSB-first)
/// code table of size `alphabet_size`.
fn emit_prefix_code(
    bw: &mut BitWriter,
    out: &mut Vec<u8>,
    strategy: &HuffStrategy,
    alphabet_size: u32,
) -> Vec<u16> {
    match strategy {
        HuffStrategy::SingleSymbol(sym) => {
            encoder_huffman::emit_simple_nsym1(bw, out, *sym, alphabet_size);
            Vec::new()
        }
        HuffStrategy::TwoSymbols { symbols, .. } => {
            let _codes = encoder_huffman::emit_simple_nsym2(bw, out, *symbols, alphabet_size);
            // `codes` already matches `symbols` ordering; write_symbol
            // looks them up directly from the strategy.
            Vec::new()
        }
        HuffStrategy::Complex(lengths) => {
            encoder_huffman::emit_complex_prefix_code(bw, out, lengths)
        }
    }
}

/// Emit one data symbol via the appropriate prefix code.
///
/// - NSYM=1: zero bits.
/// - NSYM=2: one bit, looked up via the symbol pair.
/// - Complex: bit-reverse the canonical MSB-first code for LSB-first
///   emission.
fn write_symbol(
    bw: &mut BitWriter,
    out: &mut Vec<u8>,
    strategy: &HuffStrategy,
    codes: &[u16],
    sym: u32,
) {
    match strategy {
        HuffStrategy::SingleSymbol(_) => { /* zero bits */ }
        HuffStrategy::TwoSymbols { symbols, codes: tc } => {
            // Find which slot `sym` occupies.
            let slot = if sym == symbols[0] {
                0
            } else {
                debug_assert!(sym == symbols[1], "symbol {sym} not in 2-symbol code");
                1
            };
            bw.write(tc[slot], 1, out);
        }
        HuffStrategy::Complex(lengths) => {
            let len = lengths[sym as usize] as u32;
            debug_assert!(
                len > 0,
                "symbol {sym} has no complex-prefix-code entry (length 0)"
            );
            let code = codes[sym as usize];
            let rev = reverse_bits(code as u32, len);
            bw.write(rev, len, out);
        }
    }
}

// ─── decoder ────────────────────────────────────────────────────────────
//
// Strategy:
//
//   1. Accumulate input bytes into `raw`.
//   2. While we can make progress: try to parse the next meta-block
//      from `raw` starting at `bit_pos`. If parsing fails with
//      `UnexpectedEnd`, return to the outer loop (caller must supply
//      more bytes).
//   3. Uncompressed meta-block bytes feed `out`. Compressed meta-block
//      output also feeds `out`. Metadata is silently discarded.
//   4. Drain `out` into the caller's `output` slice as room permits.
//
// `raw` keeps growing until a meta-block is fully consumed, at which
// point we compact it to the current bit position.

const NUM_LITERAL_SYMBOLS: u32 = 256;
const NUM_COMMAND_SYMBOLS: u32 = 704;
const NUM_BLOCK_LEN_SYMBOLS: u32 = 26;
/// Code-length symbol order from §3.5 (complex prefix code preamble).
const CODE_LENGTH_ORDER: [usize; 18] =
    [1, 2, 3, 4, 0, 5, 17, 6, 16, 7, 8, 9, 10, 11, 12, 13, 14, 15];

/// Block length base + extra bits per §9.2 (also used inline for
/// block-count first reads in the header).
const BLOCK_LEN_BASE: [u32; 26] = [
    1, 5, 9, 13, 17, 25, 33, 41, 49, 65, 81, 97, 113, 145, 177, 209, 241, 305, 369, 497, 753, 1265,
    2289, 4337, 8433, 16625,
];
const BLOCK_LEN_EXTRA: [u32; 26] = [
    2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 6, 6, 7, 8, 9, 10, 11, 12, 13, 24,
];

/// Insert length code → (extra bits, base) per §5.
const INS_EXTRA: [u32; 24] = [
    0, 0, 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 7, 8, 9, 10, 12, 14, 24,
];
const INS_BASE: [u32; 24] = [
    0, 1, 2, 3, 4, 5, 6, 8, 10, 14, 18, 26, 34, 50, 66, 98, 130, 194, 322, 578, 1090, 2114, 6210,
    22594,
];

/// Copy length code → (extra bits, base) per §5.
const COPY_EXTRA: [u32; 24] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 7, 8, 9, 10, 24,
];
const COPY_BASE: [u32; 24] = [
    2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 14, 18, 22, 30, 38, 54, 70, 102, 134, 198, 326, 582, 1094, 2118,
];

#[derive(Debug)]
pub struct Decoder {
    #[doc(hidden)]
    pub dbg_msgs: alloc::vec::Vec<alloc::string::String>,
    /// Buffered stream bytes. We may keep up to one meta-block's worth
    /// here; trimmed once the bit-position passes complete bytes.
    raw: Vec<u8>,
    /// Bit position into `raw`. Always references bits we have not yet
    /// committed to the output.
    bit_pos: usize,
    /// Decoded output queued for the caller. Pushed to from both the
    /// uncompressed and compressed paths.
    out: Vec<u8>,
    out_pos: usize,
    /// Decoder state.
    state: DecState,
    poisoned: bool,
    /// Window size in bytes (1 << wbits). Per §9.1 the back-reference
    /// max distance is `window_size - 16`.
    window_size: u32,
    /// Distance ring buffer (last four distances), initialised to
    /// `[16, 15, 11, 4]` with index 3 being the most recent.
    dist_ring: [i32; 4],
    /// Cursor into `dist_ring`: increments with each pushed distance.
    /// `dist_ring[(ring_idx + 3) & 3]` is the most recent distance.
    ring_idx: u32,
    /// Total bytes ever decoded (sticky across meta-blocks).
    total_out: usize,
    /// The last two bytes ever emitted (`p1` is the most recent, `p2`
    /// is the second-most-recent), used to look up literal contexts.
    p1: u8,
    p2: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DecState {
    /// Haven't read the stream header yet.
    NeedHeader,
    /// Header consumed; about to read the next meta-block.
    NeedMetaBlock,
    /// Stream finished.
    Done,
}

impl Decoder {
    pub fn _take_msgs(&mut self) -> alloc::vec::Vec<alloc::string::String> {
        core::mem::take(&mut self.dbg_msgs)
    }

    pub fn new() -> Self {
        Self {
            dbg_msgs: alloc::vec::Vec::new(),
            raw: Vec::new(),
            bit_pos: 0,
            out: Vec::new(),
            out_pos: 0,
            state: DecState::NeedHeader,
            poisoned: false,
            window_size: 1 << 16,
            // Initial ring buffer per §4. The spec lists the four
            // most recent distances as 16, 15, 11, 4 in
            // (fourth-to-last → last) order. So the *most* recent
            // initial distance is 4.
            //
            // The C reference stores the ring as
            // `dist_rb[0..4] = {16, 15, 11, 4}` with `dist_rb_idx = 0`,
            // and short-code 0 reads from `dist_rb[(idx + 3) & 3]`
            // (i.e. slot 3 initially → 4). We mirror this layout.
            dist_ring: [16, 15, 11, 4],
            ring_idx: 0,
            total_out: 0,
            p1: 0,
            p2: 0,
        }
    }

    /// Most-recently-pushed distance. Equivalent to `nth_last_dist(1)`.
    /// With the C-style indexing this is `dist_ring[(ring_idx + 3) & 3]`.
    fn last_dist(&self) -> i32 {
        self.dist_ring[((self.ring_idx.wrapping_add(3)) & 3) as usize]
    }

    /// Get the i-th most-recently-pushed distance (i = 1..=4).
    fn nth_last_dist(&self, i: u32) -> i32 {
        debug_assert!((1..=4).contains(&i));
        let idx = self.ring_idx.wrapping_add(4 - i) & 3;
        self.dist_ring[idx as usize]
    }

    fn push_dist(&mut self, d: i32) {
        let slot = (self.ring_idx & 3) as usize;
        self.dist_ring[slot] = d;
        self.ring_idx = self.ring_idx.wrapping_add(1);
    }

    fn poison(&mut self, e: Error) -> Error {
        self.poisoned = true;
        e
    }

    /// Trim `raw` to byte-align with `bit_pos`. Cheaper than re-allocating
    /// every meta-block; we just drain whole bytes that we've already
    /// committed.
    fn compact_raw(&mut self) {
        let drop_bytes = self.bit_pos >> 3;
        if drop_bytes > 0 {
            self.raw.drain(..drop_bytes);
            self.bit_pos -= drop_bytes * 8;
        }
    }

    /// Drain queued output into the caller's buffer.
    fn drain_out_into(&mut self, dst: &mut [u8]) -> usize {
        let avail = self.out.len() - self.out_pos;
        let n = avail.min(dst.len());
        if n > 0 {
            dst[..n].copy_from_slice(&self.out[self.out_pos..self.out_pos + n]);
            self.out_pos += n;
        }
        n
    }

    /// Compact the output queue, retaining the last `window_size` bytes
    /// of history for back-references. Caller-consumed bytes beyond the
    /// retained history are dropped.
    fn compact_out(&mut self) {
        if self.out_pos == 0 {
            return;
        }
        let want_history = self.window_size as usize;
        // Cap the working buffer at `want_history` bytes of history
        // plus any not-yet-delivered output. We never drop output that
        // hasn't been written to the caller.
        let unread = self.out.len() - self.out_pos;
        let total_keep_target = want_history + unread;
        if self.out.len() <= total_keep_target {
            // Everything currently in `out` fits in window+queue: leave
            // it untouched. out_pos stays as the read cursor; we just
            // don't drop anything.
            return;
        }
        let drop_n = self.out.len() - total_keep_target;
        let drop_n = drop_n.min(self.out_pos);
        if drop_n > 0 {
            self.out.drain(..drop_n);
            self.out_pos -= drop_n;
        }
    }

    /// Try to parse the stream header. Returns Ok(true) when consumed,
    /// Ok(false) when we need more bytes, Err on rejection.
    fn read_stream_header(&mut self) -> Result<bool, Error> {
        // Need at most 7 bits.
        let mut src = BitSource::at(&self.raw, self.bit_pos);
        let total_bits = self.raw.len() * 8 - self.bit_pos;
        if total_bits < 1 {
            return Ok(false);
        }
        let pos_save = src.position();
        let b0 = src.read_bit()?;
        if b0 == 0 {
            // WBITS = 16
            self.window_size = 1 << 16;
            self.bit_pos = src.position();
            return Ok(true);
        }
        if total_bits < 4 {
            return Ok(false);
        }
        let n = src.read_bits(3)? as u8;
        if n != 0 {
            // WBITS = 17 + n, in [18..=24].
            let wbits = 17 + n as u32;
            self.window_size = 1u32 << wbits;
            self.bit_pos = src.position();
            return Ok(true);
        }
        if total_bits < 7 {
            // Restore.
            src.set_position(pos_save);
            return Ok(false);
        }
        let m = src.read_bits(3)? as u8;
        match m {
            0 => {
                self.window_size = 1 << 17;
                self.bit_pos = src.position();
                Ok(true)
            }
            1 => Err(Error::Unsupported), // large-window flag
            _ => {
                // WBITS = 8 + m, in [10..=15].
                let wbits = 8 + m as u32;
                self.window_size = 1u32 << wbits;
                self.bit_pos = src.position();
                Ok(true)
            }
        }
    }

    /// Try to parse and execute the next meta-block. Returns Ok(true)
    /// when a meta-block (or the stream terminator) was processed,
    /// Ok(false) when we lack bytes, Err on a hard failure.
    fn process_next_meta_block(&mut self) -> Result<bool, Error> {
        // Snapshot in case we run out of bits mid-parse.
        let start_bit_pos = self.bit_pos;
        match self.try_process_meta_block() {
            Ok(()) => Ok(true),
            Err(Error::UnexpectedEnd) => {
                // Roll back to where we were so a later call retries.
                self.bit_pos = start_bit_pos;
                Ok(false)
            }
            Err(e) => Err(e),
        }
    }

    fn try_process_meta_block(&mut self) -> Result<(), Error> {
        if core::option_env!("BROTLI_DEBUG").is_some() {
            let s: alloc::string::String = self
                .raw
                .iter()
                .take(12)
                .map(|b| alloc::format!("{:02x} ", b))
                .collect();
            self.dbg_msgs.push(alloc::format!(
                "try_pmb: bit_pos={}, raw.len()={}, first 12 bytes: {}",
                self.bit_pos,
                self.raw.len(),
                s
            ));
        }
        // Clone the raw byte buffer for the duration of this meta-block
        // decode. The decoder mutates `self` (output, ring buffer,
        // p1/p2) while reading bits, and tying the BitSource's lifetime
        // to `self.raw` would conflict with those mutations. The clone
        // is cheap relative to the work done with it.
        let raw = self.raw.clone();
        let mut src = BitSource::at(&raw, self.bit_pos);
        let initial_pos = self.bit_pos;
        let is_last = src.read_bit()? != 0;
        let mut is_last_empty = false;
        if is_last {
            is_last_empty = src.read_bit()? != 0;
            if is_last_empty {
                // Stream terminator. Any trailing pad bits in this
                // byte must be zero per spec; we don't enforce it.
                self.bit_pos = src.position();
                self.state = DecState::Done;
                return Ok(());
            }
        }
        // MNIBBLES
        let nibbles = src.read_bits(2)?;
        if nibbles == 3 {
            // Metadata path. Per §9.2 a metadata meta-block may not be
            // the last one in a stream — but encoders in practice still
            // produce them only mid-stream, so we just verify is_last
            // is false.
            if is_last {
                return Err(Error::Corrupt);
            }
            // Reserved bit, must be 0.
            let r = src.read_bit()?;
            if r != 0 {
                return Err(Error::Corrupt);
            }
            let mskip_bytes = src.read_bits(2)?;
            let mskiplen = if mskip_bytes == 0 {
                0u32
            } else {
                let mut acc: u32 = 0;
                for i in 0..mskip_bytes {
                    let b = src.read_bits(8)?;
                    acc |= b << (i * 8);
                }
                // Top byte must not be zero when more than one byte read.
                if mskip_bytes > 1 {
                    let top = (acc >> ((mskip_bytes - 1) * 8)) & 0xFF;
                    if top == 0 {
                        return Err(Error::Corrupt);
                    }
                }
                acc + 1
            };
            src.align_to_byte();
            // Need `mskiplen` raw bytes after alignment. Check we have
            // them; otherwise UnexpectedEnd.
            let byte_pos = src.position() / 8;
            let need = byte_pos + mskiplen as usize;
            if self.raw.len() < need {
                return Err(Error::UnexpectedEnd);
            }
            // Skip metadata bytes (they aren't emitted).
            src.set_position(need * 8);
            self.bit_pos = src.position();
            self.compact_raw();
            return Ok(());
        }

        let nibbles = nibbles + 4; // 4, 5, or 6 nibbles
        let mut mlen_minus_1: u32 = 0;
        for i in 0..nibbles {
            let nb = src.read_bits(4)?;
            mlen_minus_1 |= nb << (i * 4);
        }
        if nibbles > 4 {
            let top_shift = (nibbles - 1) * 4;
            if ((mlen_minus_1 >> top_shift) & 0xF) == 0 {
                return Err(Error::Corrupt);
            }
        }
        let mlen = mlen_minus_1 + 1;

        let is_uncompressed = if !is_last {
            src.read_bit()? != 0
        } else {
            false
        };

        if is_last && is_last_empty {
            // Already handled above.
            unreachable!();
        }

        if is_uncompressed {
            // Byte-align and copy MLEN raw bytes.
            src.align_to_byte();
            let byte_pos = src.position() / 8;
            let need = byte_pos + mlen as usize;
            if self.raw.len() < need {
                return Err(Error::UnexpectedEnd);
            }
            let slice = self.raw[byte_pos..need].to_vec();
            // Push to output and update p1/p2/total.
            for b in &slice {
                self.emit_literal(*b);
            }
            src.set_position(need * 8);
            self.bit_pos = src.position();
            self.compact_raw();
            return Ok(());
        }

        // ─── compressed meta-block ───
        // Decode in one shot. For simplicity, our parsing routines
        // consume bytes from `self.raw` via the `BitSource`, and the
        // outer caller handles UnexpectedEnd by rolling back bit_pos.
        // Snapshot the global ring buffer / context state so a partial
        // decode (UnexpectedEnd mid-way) doesn't leave behind side
        // effects on the next retry.
        let snap = (
            self.dist_ring,
            self.ring_idx,
            self.p1,
            self.p2,
            self.total_out,
            self.out.len(),
        );
        if let Err(e) = self.decode_compressed_meta_block(&mut src, mlen) {
            if core::option_env!("BROTLI_DEBUG").is_some() {
                self.dbg_msgs.push(alloc::format!(
                    "decode_compressed_meta_block ERR: {:?}, mlen={}, src.position()={}",
                    e,
                    mlen,
                    src.position()
                ));
            }
            if e == Error::UnexpectedEnd {
                // Roll back. The caller will retry with more bytes.
                self.dist_ring = snap.0;
                self.ring_idx = snap.1;
                self.p1 = snap.2;
                self.p2 = snap.3;
                self.total_out = snap.4;
                self.out.truncate(snap.5);
            }
            self.bit_pos = initial_pos;
            return Err(e);
        }
        self.bit_pos = src.position();
        self.compact_raw();
        if is_last {
            self.state = DecState::Done;
        }
        Ok(())
    }

    /// Emit one literal byte to the output and rotate p1/p2.
    fn emit_literal(&mut self, b: u8) {
        self.out.push(b);
        self.p2 = self.p1;
        self.p1 = b;
        self.total_out += 1;
    }

    /// Emit a backward-reference copy of `len` bytes starting `distance`
    /// bytes before the current write position. `self.out` must contain
    /// at least the last `distance` bytes of history for this to
    /// succeed.
    fn emit_copy(&mut self, distance: u32, len: u32) -> Result<(), Error> {
        if distance as usize > self.total_out {
            return Err(Error::InvalidDistance);
        }
        if len == 0 {
            return Ok(());
        }
        let out_base = self.total_out - self.out.len();
        let g0 = (self.total_out as u64) - (distance as u64);
        if g0 < out_base as u64 {
            // Distance reaches further back than the retained window.
            // With our `compact_out` retaining `window_size` bytes this
            // should not happen for valid streams (Brotli back-references
            // are capped at `window_size - 16`).
            return Err(Error::InvalidDistance);
        }
        let src_start = (g0 - out_base as u64) as usize;
        let n = len as usize;
        if (distance as usize) >= n {
            // Non-overlapping: collapses to memcpy.
            self.out.extend_from_within(src_start..src_start + n);
            // Update last-two-bytes context from the tail of the copy.
            let end = self.out.len();
            if n >= 2 {
                self.p2 = self.out[end - 2];
                self.p1 = self.out[end - 1];
            } else {
                // n == 1
                self.p2 = self.p1;
                self.p1 = self.out[end - 1];
            }
            self.total_out += n;
        } else if distance == 1 {
            // Byte-splat.
            let b = self.out[src_start];
            self.out.resize(self.out.len() + n, b);
            if n >= 2 {
                self.p2 = b;
                self.p1 = b;
            } else {
                self.p2 = self.p1;
                self.p1 = b;
            }
            self.total_out += n;
        } else {
            // Self-overlap (distance < len): expanding copy within the
            // already-produced region. Each `extend_from_within` copies a
            // prefix of the growing tail, reproducing the exact RLE sequence
            // the per-byte loop would emit, but as bulk memcpys.
            let mut produced = 0usize;
            while produced < n {
                let chunk = (self.out.len() - src_start).min(n - produced);
                self.out.extend_from_within(src_start..src_start + chunk);
                produced += chunk;
            }
            // n >= 3 here (distance >= 2 and distance < n), so end-2 is valid.
            let end = self.out.len();
            self.p2 = self.out[end - 2];
            self.p1 = self.out[end - 1];
            self.total_out += n;
        }
        Ok(())
    }

    /// Read NBLTYPES* per §9.2 (the 1..=256 prefix-encoded counter).
    fn read_nbltypes(src: &mut BitSource<'_>) -> Result<u32, Error> {
        // 1 bit: 0 => value 1
        let first = src.read_bit()?;
        if first == 0 {
            return Ok(1);
        }
        // Next 3 bits select the range; 0..=7 → bases 1, 2, 3..=4, 5..=8, ...
        // We re-implement the standard variable-length encoder used here:
        //   read 3 bits N (the "log2-1" effectively)
        //   if N == 0 → value = 2
        //   else      → value = (1 << N) + 1 + read_bits(N)
        let n = src.read_bits(3)?;
        if n == 0 {
            return Ok(2);
        }
        let extra = src.read_bits(n)?;
        Ok((1u32 << n) + 1 + extra)
    }

    /// Read a Brotli prefix code (simple or complex) over `alphabet_size`
    /// symbols. Returns the constructed HuffmanDecoder.
    fn read_prefix_code(
        src: &mut BitSource<'_>,
        alphabet_size: u32,
    ) -> Result<HuffmanDecoder, Error> {
        let kind = src.read_bits(2)?;
        if kind == 1 {
            // Simple prefix code.
            return Self::read_simple_prefix_code(src, alphabet_size);
        }
        // Complex prefix code. `kind` here is the HSKIP (0, 2, or 3).
        let hskip = kind;
        Self::read_complex_prefix_code(src, alphabet_size, hskip)
    }

    fn read_simple_prefix_code(
        src: &mut BitSource<'_>,
        alphabet_size: u32,
    ) -> Result<HuffmanDecoder, Error> {
        let nsym = src.read_bits(2)? + 1; // 1..=4
        let alpha_bits = alphabet_bits(alphabet_size);
        let mut syms = [0u32; 4];
        for i in 0..nsym {
            let s = src.read_bits(alpha_bits)?;
            if s >= alphabet_size {
                return Err(Error::Corrupt);
            }
            for j in 0..i {
                if syms[j as usize] == s {
                    return Err(Error::Corrupt);
                }
            }
            syms[i as usize] = s;
        }
        match nsym {
            1 => Ok(HuffmanDecoder::single(syms[0])),
            2 => {
                // Both length 1, sorted ascending.
                let mut a = syms[0];
                let mut b = syms[1];
                if a > b {
                    core::mem::swap(&mut a, &mut b);
                }
                HuffmanDecoder::from_lengths_sparse(&[(a, 1), (b, 1)])
            }
            3 => {
                // Lengths 1, 2, 2 in the order of listed symbols. The
                // length-2 symbols are sorted by symbol value.
                let l1 = syms[0];
                let mut s2 = syms[1];
                let mut s3 = syms[2];
                if s2 > s3 {
                    core::mem::swap(&mut s2, &mut s3);
                }
                HuffmanDecoder::from_lengths_sparse(&[(l1, 1), (s2, 2), (s3, 2)])
            }
            4 => {
                let tree_select = src.read_bit()?;
                if tree_select == 0 {
                    // Lengths 2,2,2,2 sorted by symbol value
                    let mut all = [syms[0], syms[1], syms[2], syms[3]];
                    all.sort();
                    HuffmanDecoder::from_lengths_sparse(&[
                        (all[0], 2),
                        (all[1], 2),
                        (all[2], 2),
                        (all[3], 2),
                    ])
                } else {
                    // Lengths 1, 2, 3, 3 in symbol order. The two
                    // length-3 symbols are sorted by symbol value.
                    // Per spec, symbols are listed in this order:
                    // syms[0] length 1, syms[1] length 2, syms[2..4]
                    // length 3 (sorted).
                    let mut c = syms[2];
                    let mut d = syms[3];
                    if c > d {
                        core::mem::swap(&mut c, &mut d);
                    }
                    HuffmanDecoder::from_lengths_sparse(&[
                        (syms[0], 1),
                        (syms[1], 2),
                        (c, 3),
                        (d, 3),
                    ])
                }
            }
            _ => unreachable!(),
        }
    }

    fn read_complex_prefix_code(
        src: &mut BitSource<'_>,
        alphabet_size: u32,
        hskip: u32,
    ) -> Result<HuffmanDecoder, Error> {
        // 1. Read code-length lengths in the canonical order (skipping
        //    `hskip` initial slots which default to 0).
        //
        // The cl-cl code is a fixed 6-symbol Huffman with these
        // canonical code lengths:
        //   sym 0: 2, sym 1: 4, sym 2: 3, sym 3: 2, sym 4: 2, sym 5: 4
        // Codes follow §3.2 canonical assignment; we just build a tiny
        // canonical decoder.
        let cl_cl_lengths: [(u32, u8); 6] = [(0, 2), (1, 4), (2, 3), (3, 2), (4, 2), (5, 4)];
        let cl_decoder = HuffmanDecoder::from_lengths_sparse(&cl_cl_lengths)?;
        let mut cl_lengths = [0u8; 18];
        let mut space: i32 = 32;
        let mut idx = hskip as usize;
        while idx < 18 {
            let sym_pos = CODE_LENGTH_ORDER[idx];
            let v = cl_decoder.decode(src)?;
            if v > 5 {
                return Err(Error::InvalidHuffmanTree);
            }
            cl_lengths[sym_pos] = v as u8;
            if v != 0 {
                space -= 32 >> v;
                if space <= 0 {
                    break;
                }
            }
            idx += 1;
        }
        if space != 0 {
            return Err(Error::InvalidHuffmanTree);
        }
        // 2. Build the cl-symbol decoder.
        let mut cl_sym_pairs: Vec<(u32, u8)> = Vec::new();
        for (i, &l) in cl_lengths.iter().enumerate() {
            if l > 0 {
                cl_sym_pairs.push((i as u32, l));
            }
        }
        if cl_sym_pairs.is_empty() {
            return Err(Error::InvalidHuffmanTree);
        }
        let cl_sym_decoder = if cl_sym_pairs.len() == 1 {
            // Tree with one symbol whose code is empty (zero-length).
            HuffmanDecoder::single(cl_sym_pairs[0].0)
        } else {
            // The 18-symbol cl-cl alphabet itself must form a complete tree.
            HuffmanDecoder::from_lengths_sparse(&cl_sym_pairs)?
        };

        // 3. Decode the main code-length sequence, expanding 16/17 repeats.
        let mut sym_lengths: Vec<u8> = vec![0u8; alphabet_size as usize];
        let mut prev_nonzero: u8 = 8;
        let mut filled: u32 = 0;
        let mut space: i64 = 1 << 15;
        let mut prev_code: u32 = u32::MAX; // sentinel
        let mut prev_repeat_count: u32 = 0;
        while filled < alphabet_size && space > 0 {
            let code = cl_sym_decoder.decode(src)?;
            match code {
                0..=15 => {
                    sym_lengths[filled as usize] = code as u8;
                    if code != 0 {
                        prev_nonzero = code as u8;
                        space -= 1i64 << (15 - code);
                    }
                    filled += 1;
                    prev_code = code;
                    prev_repeat_count = 0;
                }
                16 => {
                    let extra = src.read_bits(2)?;
                    let new_count = if prev_code == 16 {
                        4 * (prev_repeat_count - 2) + (3 + extra)
                    } else {
                        3 + extra
                    };
                    let to_add = if prev_code == 16 {
                        new_count - prev_repeat_count
                    } else {
                        new_count
                    };
                    if filled + to_add > alphabet_size {
                        return Err(Error::Corrupt);
                    }
                    for _ in 0..to_add {
                        sym_lengths[filled as usize] = prev_nonzero;
                        filled += 1;
                        space -= 1i64 << (15 - prev_nonzero as u32);
                    }
                    prev_code = 16;
                    prev_repeat_count = new_count;
                }
                17 => {
                    let extra = src.read_bits(3)?;
                    let new_count = if prev_code == 17 {
                        8 * (prev_repeat_count - 2) + (3 + extra)
                    } else {
                        3 + extra
                    };
                    let to_add = if prev_code == 17 {
                        new_count - prev_repeat_count
                    } else {
                        new_count
                    };
                    if filled + to_add > alphabet_size {
                        return Err(Error::Corrupt);
                    }
                    for _ in 0..to_add {
                        sym_lengths[filled as usize] = 0;
                        filled += 1;
                    }
                    prev_code = 17;
                    prev_repeat_count = new_count;
                }
                _ => return Err(Error::Corrupt),
            }
        }
        if space < 0 {
            return Err(Error::Corrupt);
        }
        if filled < alphabet_size {
            // Trailing zeros are implicit.
            for slot in sym_lengths
                .iter_mut()
                .take(alphabet_size as usize)
                .skip(filled as usize)
            {
                *slot = 0;
            }
        }
        HuffmanDecoder::from_lengths_allow_single(&sym_lengths[..alphabet_size as usize])
    }

    /// Read a "block count" first-value pair: a 26-symbol Huffman tree
    /// (BLOCK_LEN), decoded then offset by extra bits.
    fn read_block_count(src: &mut BitSource<'_>, tree: &HuffmanDecoder) -> Result<u32, Error> {
        let sym = tree.decode(src)?;
        if sym >= NUM_BLOCK_LEN_SYMBOLS {
            return Err(Error::Corrupt);
        }
        let extra = src.read_bits(BLOCK_LEN_EXTRA[sym as usize])?;
        Ok(BLOCK_LEN_BASE[sym as usize] + extra)
    }

    /// Decode the body of a compressed meta-block: read all per-block
    /// tables, then run the literal/copy command loop until `mlen`
    /// bytes have been emitted.
    fn decode_compressed_meta_block(
        &mut self,
        src: &mut BitSource<'_>,
        mlen: u32,
    ) -> Result<(), Error> {
        // 1) Block-type / block-count groups for L, I, D.
        let group_l = read_block_group(src)?;
        let group_i = read_block_group(src)?;
        let group_d = read_block_group(src)?;

        // 2) Distance parameters.
        let npostfix = src.read_bits(2)?;
        let ndirect_bits = src.read_bits(4)?;
        let ndirect = ndirect_bits << npostfix;
        let num_dist_codes: u32 = 16 + ndirect + (48u32 << npostfix);

        // 3) Context modes for literals: NBLTYPESL × 2 bits each.
        let mut cmodes: Vec<ContextMode> = Vec::with_capacity(group_l.nbltypes as usize);
        for _ in 0..group_l.nbltypes {
            cmodes.push(ContextMode::from_bits(src.read_bits(2)?));
        }

        // 4) Literal context map.
        let ntreesl = Self::read_nbltypes(src)?;
        let cmapl_size = 64 * group_l.nbltypes;
        let cmapl = if ntreesl >= 2 {
            read_context_map(src, cmapl_size, ntreesl)?
        } else {
            vec![0u8; cmapl_size as usize]
        };

        // 5) Distance context map.
        let ntreesd = Self::read_nbltypes(src)?;
        let cmapd_size = 4 * group_d.nbltypes;
        let cmapd = if ntreesd >= 2 {
            read_context_map(src, cmapd_size, ntreesd)?
        } else {
            vec![0u8; cmapd_size as usize]
        };

        // 6) Literal prefix codes (NTREESL of them, alphabet 256).
        let mut htree_l: Vec<HuffmanDecoder> = Vec::with_capacity(ntreesl as usize);
        for _ in 0..ntreesl {
            htree_l.push(Self::read_prefix_code(src, NUM_LITERAL_SYMBOLS)?);
        }
        // 7) Insert-and-copy prefix codes (NBLTYPESI of them, alphabet 704).
        let mut htree_i: Vec<HuffmanDecoder> = Vec::with_capacity(group_i.nbltypes as usize);
        for _ in 0..group_i.nbltypes {
            htree_i.push(Self::read_prefix_code(src, NUM_COMMAND_SYMBOLS)?);
        }
        // 8) Distance prefix codes (NTREESD of them, alphabet num_dist_codes).
        let mut htree_d: Vec<HuffmanDecoder> = Vec::with_capacity(ntreesd as usize);
        for _ in 0..ntreesd {
            htree_d.push(Self::read_prefix_code(src, num_dist_codes)?);
        }

        // When there is a single literal Huffman tree the context map is
        // all zeroes, so literal decoding can skip the per-byte context
        // lookup entirely (the tree index is constant 0).
        let single_literal_tree = ntreesl == 1;

        // ─── decoding loop ───
        let mut emitted: u32 = 0;
        let mut block_type_l: u32 = 0;
        let mut block_type_i: u32 = 0;
        let mut block_type_d: u32 = 0;
        // "Previous block type" trackers, used for block-type code value 0
        // (use prev) and value 1 (use prev+1 mod NBLTYPES).
        let mut prev_block_type_l: u32 = 1;
        let mut prev_block_type_i: u32 = 1;
        let mut prev_block_type_d: u32 = 1;
        let mut block_len_l: u32 = group_l.first_count;
        let mut block_len_i: u32 = group_i.first_count;
        let mut block_len_d: u32 = group_d.first_count;

        let postfix_mask: u32 = (1u32 << npostfix) - 1;

        // Local helper: advance block-type when count reaches zero.
        macro_rules! maybe_switch {
            ($len:ident, $bt:ident, $prev:ident, $group:expr) => {
                if $len == 0 {
                    let g = &$group;
                    let nbl = g.nbltypes;
                    // When NBLTYPES == 1 the type/count trees are absent and
                    // there is only one block type, so there is never a switch.
                    // The block-length counter decrements once per command (IC)
                    // or per literal/distance, and a command can emit zero
                    // output bytes (e.g. a dictionary reference whose transform
                    // omits the whole word), so after `first_count` (1<<24) such
                    // commands the counter can reach 0. Reload it to an
                    // effectively-infinite value instead of unwrapping the
                    // `None` trees (which would panic).
                    match (g.type_tree.as_ref(), g.count_tree.as_ref()) {
                        (Some(type_tree), Some(count_tree)) => {
                            let code = type_tree.decode(src)?;
                            let next_type = if code == 0 {
                                $prev
                            } else if code == 1 {
                                ($bt + 1) % nbl
                            } else {
                                code - 2
                            };
                            if next_type >= nbl {
                                return Err(Error::Corrupt);
                            }
                            $prev = $bt;
                            $bt = next_type;
                            $len = Self::read_block_count(src, count_tree)?;
                        }
                        _ => {
                            // Single block type: never switch, just keep going.
                            $len = u32::MAX;
                        }
                    }
                }
            };
        }

        while emitted < mlen {
            // Block-type switch for IC if needed.
            maybe_switch!(block_len_i, block_type_i, prev_block_type_i, group_i);
            block_len_i -= 1;

            // Decode the IC command symbol.
            let cmd_sym = htree_i[block_type_i as usize].decode(src)?;
            if cmd_sym >= NUM_COMMAND_SYMBOLS {
                return Err(Error::Corrupt);
            }
            let (ins_code, copy_code, use_last_dist) = decode_ic_command(cmd_sym);

            let ins_extra = src.read_bits(INS_EXTRA[ins_code as usize])?;
            let insert_len = INS_BASE[ins_code as usize] + ins_extra;
            let copy_extra = src.read_bits(COPY_EXTRA[copy_code as usize])?;
            let copy_len = COPY_BASE[copy_code as usize] + copy_extra;

            // Emit `insert_len` literals.
            if single_literal_tree {
                // Single literal Huffman tree: the context map is all
                // zeroes, so the per-byte context computation and the
                // `cmapl` lookup are dead work — the tree index is always
                // 0. (Block-type switches still drive `block_len_l`, but
                // they never change which tree we use here.)
                let tree = &htree_l[0];
                for _ in 0..insert_len {
                    if emitted >= mlen {
                        return Err(Error::Corrupt);
                    }
                    maybe_switch!(block_len_l, block_type_l, prev_block_type_l, group_l);
                    block_len_l -= 1;
                    let sym = tree.decode(src)?;
                    if sym > 255 {
                        return Err(Error::Corrupt);
                    }
                    self.emit_literal(sym as u8);
                    emitted += 1;
                }
            } else {
                for _ in 0..insert_len {
                    if emitted >= mlen {
                        return Err(Error::Corrupt);
                    }
                    maybe_switch!(block_len_l, block_type_l, prev_block_type_l, group_l);
                    block_len_l -= 1;
                    let cid =
                        context::literal_context(cmodes[block_type_l as usize], self.p1, self.p2);
                    let tree_idx = cmapl[(64 * block_type_l + cid as u32) as usize] as usize;
                    let sym = htree_l[tree_idx].decode(src)?;
                    if sym > 255 {
                        return Err(Error::Corrupt);
                    }
                    self.emit_literal(sym as u8);
                    emitted += 1;
                }
            }

            if emitted >= mlen {
                // Last command is allowed to have copy_len that would
                // exceed mlen if insert filled it; in that case no copy
                // is emitted.
                break;
            }

            // Decode distance. For short codes the ring may be
            // updated immediately (per §4 those codes are "use a
            // previous distance"). For non-short codes we delay the
            // ring push until we know whether this resolves to a
            // back-reference (push) or a static-dictionary reference
            // (no push).
            let (distance, is_short_or_direct) = if use_last_dist {
                (self.last_dist() as u32, true)
            } else {
                maybe_switch!(block_len_d, block_type_d, prev_block_type_d, group_d);
                block_len_d -= 1;
                let cid = context::distance_context(copy_len) as u32;
                let tree_idx = cmapd[(4 * block_type_d + cid) as usize] as usize;
                let dcode = htree_d[tree_idx].decode(src)?;
                if dcode >= num_dist_codes {
                    return Err(Error::Corrupt);
                }
                if dcode < 16 {
                    // Short codes update the ring immediately per spec.
                    (decode_short_distance(self, dcode)?, true)
                } else if dcode < 16 + ndirect {
                    // Direct distance.
                    (dcode - 15, false)
                } else {
                    let v = dcode - ndirect - 16;
                    let ndistbits = 1 + (v >> (npostfix + 1));
                    let dextra = src.read_bits(ndistbits)?;
                    let hcode = v >> npostfix;
                    let lcode = v & postfix_mask;
                    let offset = ((2 + (hcode & 1)) << ndistbits) - 4;
                    let dist = ((offset + dextra) << npostfix) + lcode + ndirect + 1;
                    (dist, false)
                }
            };

            // Compute max-distance: min(window_size - 16, total_out so far).
            // `total_out` is a usize accumulated over the whole stream; a plain
            // `as u32` cast wraps after 4 GiB of output and collapses max_dist,
            // corrupting decoding. Do the comparison at full usize width and
            // clamp the (window-bounded) result back to u32 losslessly:
            // max_dist <= window_size - 16, which always fits in u32.
            let max_dist =
                (self.window_size.saturating_sub(16) as usize).min(self.total_out) as u32;
            if distance <= max_dist {
                // Normal back-reference. Non-short distances are
                // pushed to the ring here.
                if !is_short_or_direct {
                    self.push_dist(distance as i32);
                }
                self.emit_copy(distance, copy_len)?;
                emitted += copy_len;
                if emitted > mlen {
                    return Err(Error::Corrupt);
                }
            } else {
                // Static dictionary reference (§8). Distances that
                // resolve to dictionary entries are NOT pushed onto the
                // ring buffer.
                let n = self.emit_dictionary(distance, copy_len, max_dist)?;
                emitted += n;
                if emitted > mlen {
                    return Err(Error::Corrupt);
                }
            }
        }
        Ok(())
    }

    /// Resolve a distance code that overshoots the back-reference window
    /// as a static dictionary reference, per §8. Returns the number of
    /// bytes emitted (which is `prefix.len() + body.len() + suffix.len()`,
    /// where body may be the word truncated by omit-first/last).
    fn emit_dictionary(
        &mut self,
        distance: u32,
        copy_len: u32,
        max_dist: u32,
    ) -> Result<u32, Error> {
        // copy_len must be in 4..=24 to index a non-empty length class.
        let len = copy_len as usize;
        if !(dictionary::MIN_DICTIONARY_WORD_LENGTH..=dictionary::MAX_DICTIONARY_WORD_LENGTH)
            .contains(&len)
        {
            return Err(Error::InvalidDistance);
        }
        let nwords_bits = dictionary::SIZE_BITS_BY_LENGTH[len];
        if nwords_bits == 0 {
            return Err(Error::InvalidDistance);
        }
        let nwords: u32 = 1 << nwords_bits;
        let off = distance
            .checked_sub(max_dist)
            .ok_or(Error::InvalidDistance)?;
        let off = off.checked_sub(1).ok_or(Error::InvalidDistance)?;
        let word_id = off & (nwords - 1);
        let transform_id = off >> nwords_bits;
        if transform_id >= 121 {
            return Err(Error::InvalidDistance);
        }
        let word = dictionary::word(len, word_id).ok_or(Error::InvalidDistance)?;
        let mut scratch: Vec<u8> = Vec::with_capacity(64);
        let n = transforms::apply_transform(&mut scratch, word, transform_id as usize);
        for b in scratch {
            self.emit_literal(b);
        }
        Ok(n as u32)
    }
}

/// Minimum number of bits to encode `alphabet_size` symbol values.
fn alphabet_bits(alphabet_size: u32) -> u32 {
    debug_assert!(alphabet_size >= 1);
    // ceil(log2(alphabet_size)). For size 1 use 1 bit per spec? The
    // simple-prefix-NSYM=1 case still reads one symbol; that symbol
    // must fit in ceil(log2(alphabet_size)) bits, which is 0 for
    // alphabet_size=1. RFC actually says: "the value is in the range
    // [0, alphabet_size-1] and is encoded with ceil(log2(alphabet_size))
    // bits." That gives 0 bits for size 1, which means simple-NSYM=1
    // with a single-element alphabet reads no symbol bits. We retain
    // the same behavior.
    if alphabet_size <= 1 {
        return 0;
    }
    let mut n = 1u32;
    while (1u32 << n) < alphabet_size {
        n += 1;
    }
    n
}

/// Decode a 0..=15 short distance code into an actual back-distance.
/// Updates the ring buffer per spec.
fn decode_short_distance(dec: &mut Decoder, code: u32) -> Result<u32, Error> {
    // Per §4:
    //   code 0..3  → use nth_last_dist(1..=4) as-is, but only code 0
    //                is "do not push to ring"; codes 1..=15 push.
    //   code 4..15 → modified previous distance.
    let last = dec.nth_last_dist(1);
    let last2 = dec.nth_last_dist(2);
    let dist: i32 = match code {
        0 => last,
        1 => dec.nth_last_dist(2),
        2 => dec.nth_last_dist(3),
        3 => dec.nth_last_dist(4),
        4 => last - 1,
        5 => last + 1,
        6 => last - 2,
        7 => last + 2,
        8 => last - 3,
        9 => last + 3,
        10 => last2 - 1,
        11 => last2 + 1,
        12 => last2 - 2,
        13 => last2 + 2,
        14 => last2 - 3,
        15 => last2 + 3,
        _ => unreachable!(),
    };
    if dist <= 0 {
        return Err(Error::InvalidDistance);
    }
    if code != 0 {
        dec.push_dist(dist);
    }
    Ok(dist as u32)
}

/// Decode a 0..=703 insert-and-copy command symbol into
/// `(insert_len_code, copy_len_code, use_last_dist)`.
///
/// Cell layout from §5:
///
/// ```text
///           Copy code:    0..7      8..15     16..23
///                       +---------+---------+---------+
///  Ins 0..7 (dist=0)    |  0..63  |  64..127|   ---   |
///  Ins 0..7             | 128..191| 192..255| 384..447|
///  Ins 8..15            | 256..319| 320..383| 512..575|
///  Ins 16..23           | 448..511| 576..639| 640..703|
/// ```
fn decode_ic_command(cmd: u32) -> (u32, u32, bool) {
    // The full table:
    //   cmd in 0..64  : ins 0..7,  copy 0..7,  use_last=true
    //   cmd in 64..128: ins 0..7,  copy 8..15, use_last=true
    //   cmd in 128..192: ins 0..7,  copy 0..7
    //   cmd in 192..256: ins 0..7,  copy 8..15
    //   cmd in 256..320: ins 8..15, copy 0..7
    //   cmd in 320..384: ins 8..15, copy 8..15
    //   cmd in 384..448: ins 0..7,  copy 16..23
    //   cmd in 448..512: ins 16..23, copy 0..7
    //   cmd in 512..576: ins 8..15, copy 16..23
    //   cmd in 576..640: ins 16..23, copy 8..15
    //   cmd in 640..704: ins 16..23, copy 16..23
    let (ins_base, copy_base, use_last) = match cmd / 64 {
        0 => (0u32, 0u32, true),
        1 => (0, 8, true),
        2 => (0, 0, false),
        3 => (0, 8, false),
        4 => (8, 0, false),
        5 => (8, 8, false),
        6 => (0, 16, false),
        7 => (16, 0, false),
        8 => (8, 16, false),
        9 => (16, 8, false),
        10 => (16, 16, false),
        _ => unreachable!(),
    };
    let cell_local = cmd & 0x3F;
    let copy_code = copy_base + (cell_local & 7);
    let ins_code = ins_base + (cell_local >> 3);
    (ins_code, copy_code, use_last)
}

/// Read a context map of `size` entries with `ntrees` distinct trees.
fn read_context_map(src: &mut BitSource<'_>, size: u32, ntrees: u32) -> Result<Vec<u8>, Error> {
    // RLEMAX: 1 bit; if 1, 4 more bits give RLEMAX in 1..=16.
    let has_rle = src.read_bit()?;
    let rlemax = if has_rle == 1 {
        src.read_bits(4)? + 1
    } else {
        0
    };
    let alphabet = ntrees + rlemax;
    let tree = Decoder::read_prefix_code(src, alphabet)?;
    let mut map: Vec<u8> = Vec::with_capacity(size as usize);
    while (map.len() as u32) < size {
        let sym = tree.decode(src)?;
        if sym == 0 {
            map.push(0);
        } else if sym <= rlemax {
            // Run-length-coded run of zeros.
            let extra = src.read_bits(sym)?;
            let run = (1u32 << sym) + extra;
            for _ in 0..run {
                if (map.len() as u32) >= size {
                    return Err(Error::Corrupt);
                }
                map.push(0);
            }
        } else {
            map.push((sym - rlemax) as u8);
        }
    }
    if map.len() as u32 != size {
        return Err(Error::Corrupt);
    }
    // Inverse MTF if requested.
    let imtf = src.read_bit()?;
    if imtf == 1 {
        inverse_mtf(&mut map);
    }
    Ok(map)
}

fn inverse_mtf(v: &mut [u8]) {
    let mut mtf = [0u8; 256];
    for (i, slot) in mtf.iter_mut().enumerate() {
        *slot = i as u8;
    }
    for slot in v.iter_mut() {
        let index = *slot as usize;
        let value = mtf[index];
        *slot = value;
        for i in (1..=index).rev() {
            mtf[i] = mtf[i - 1];
        }
        mtf[0] = value;
    }
}

/// Per-category state read from the meta-block header (literals,
/// insert-copy, distance). When NBLTYPES = 1, the type/count trees are
/// absent and only `first_count` matters (and equals `1<<24` to
/// effectively disable block-switch).
struct BlockGroup {
    nbltypes: u32,
    type_tree: Option<HuffmanDecoder>,
    count_tree: Option<HuffmanDecoder>,
    first_count: u32,
}

fn read_block_group(src: &mut BitSource<'_>) -> Result<BlockGroup, Error> {
    let nbltypes = Decoder::read_nbltypes(src)?;
    if nbltypes >= 2 {
        let alphabet_type = nbltypes + 2;
        let type_tree = Decoder::read_prefix_code(src, alphabet_type)?;
        let count_tree = Decoder::read_prefix_code(src, NUM_BLOCK_LEN_SYMBOLS)?;
        let first_count = Decoder::read_block_count(src, &count_tree)?;
        Ok(BlockGroup {
            nbltypes,
            type_tree: Some(type_tree),
            count_tree: Some(count_tree),
            first_count,
        })
    } else {
        Ok(BlockGroup {
            nbltypes,
            type_tree: None,
            count_tree: None,
            // Effectively infinite block (will never reach zero).
            first_count: 1u32 << 24,
        })
    }
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

impl RawDecoder for Decoder {
    fn raw_decode(&mut self, input: &[u8], output: &mut [u8]) -> Result<RawProgress, Error> {
        if self.poisoned {
            return Err(Error::Corrupt);
        }
        let consumed = input.len();
        self.raw.extend_from_slice(input);

        let mut written = 0usize;

        loop {
            // Drain any already-queued output first.
            if self.out_pos < self.out.len() {
                let drained = self.drain_out_into(&mut output[written..]);
                written += drained;
                if written == output.len() {
                    break;
                }
            }

            // Then make whatever forward progress we can.
            match self.state {
                DecState::NeedHeader => match self.read_stream_header() {
                    Ok(true) => {
                        self.compact_raw();
                        self.state = DecState::NeedMetaBlock;
                    }
                    Ok(false) => break,
                    Err(e) => return Err(self.poison(e)),
                },
                DecState::NeedMetaBlock => match self.process_next_meta_block() {
                    Ok(true) => {
                        if self.state == DecState::Done {
                            // Final flush below.
                            continue;
                        }
                        // Loop to drain any newly-queued output.
                    }
                    Ok(false) => break,
                    Err(e) => return Err(self.poison(e)),
                },
                DecState::Done => {
                    // Drain remaining queued output.
                    if self.out_pos >= self.out.len() {
                        break;
                    }
                }
            }
        }
        self.compact_out();
        Ok(RawProgress {
            consumed,
            written,
            done: false,
        })
    }

    fn raw_finish(&mut self, output: &mut [u8]) -> Result<RawProgress, Error> {
        if self.poisoned {
            return Err(Error::Corrupt);
        }
        let mut written = 0usize;
        // Why a finish-side loop? raw_decode returns as soon as the
        // caller's output slice fills, even if there are still meta-blocks
        // pending in `self.raw`. The caller naturally responds by calling
        // finish (input is exhausted from their POV). finish then has to
        // do both: drain queued output AND keep processing any pending
        // meta-blocks until either output fills again or the stream ends.
        // The outcome is encoded by `output_full` so we can distinguish
        // "buffer overflowed, retry" from "genuinely out of input".
        let mut output_full = false;
        loop {
            if self.out_pos < self.out.len() {
                let drained = self.drain_out_into(&mut output[written..]);
                written += drained;
                if written == output.len() {
                    output_full = true;
                    break;
                }
            }
            match self.state {
                DecState::NeedHeader => match self.read_stream_header() {
                    Ok(true) => {
                        self.compact_raw();
                        self.state = DecState::NeedMetaBlock;
                    }
                    Ok(false) => break,
                    Err(e) => return Err(self.poison(e)),
                },
                DecState::NeedMetaBlock => match self.process_next_meta_block() {
                    Ok(true) => {
                        // Newly-emitted bytes wait in self.out; loop back
                        // to drain them.
                    }
                    Ok(false) => break,
                    Err(e) => return Err(self.poison(e)),
                },
                DecState::Done => {
                    if self.out_pos >= self.out.len() {
                        break;
                    }
                }
            }
        }
        self.compact_out();
        let fully_done = self.state == DecState::Done && self.out_pos == self.out.len();
        if fully_done {
            return Ok(RawProgress {
                consumed: 0,
                written,
                done: true,
            });
        }
        // Three "not fully done" cases:
        //   1. Output filled — caller should drain and call us again.
        //   2. State is Done but some bytes still queued — same.
        //   3. Stream still expects more input but the caller said
        //      "that's all". That's the real UnexpectedEnd.
        if output_full || self.state == DecState::Done || self.out_pos < self.out.len() {
            return Ok(RawProgress {
                consumed: 0,
                written,
                done: false,
            });
        }
        Err(self.poison(Error::UnexpectedEnd))
    }

    fn raw_reset(&mut self) {
        self.raw.clear();
        self.bit_pos = 0;
        self.out.clear();
        self.out_pos = 0;
        self.state = DecState::NeedHeader;
        self.poisoned = false;
        self.window_size = 1 << 16;
        self.dist_ring = [16, 15, 11, 4];
        self.ring_idx = 0;
        self.total_out = 0;
        self.p1 = 0;
        self.p2 = 0;
    }
}
