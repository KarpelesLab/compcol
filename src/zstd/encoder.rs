//! Streaming Zstandard encoder.
//!
//! Emits a single Zstd frame whose body is one or more blocks. Per block we
//! pick the smallest of three encodings:
//!
//! - `RLE_Block` (Block_Type=1) when every byte of the pending block is the
//!   same — costs just one payload byte regardless of block size.
//! - `Compressed_Block` (Block_Type=2): runs the hash-chain LZ77 matcher
//!   ([`crate::zstd::matcher`]) to produce literals + sequences. Literals are
//!   coded as `Compressed_Literals_Block` (fresh canonical Huffman tree
//!   built per block, encoded via direct nibble-packed weight encoding) or
//!   `Treeless_Literals_Block` (reusing the previous block's tree when its
//!   alphabet covers the current literals and skipping the tree saves
//!   bytes), with the 1-stream layout for ≤1023 literals and the 4-stream
//!   layout otherwise. Sequence tables (LL, OF, ML) are each independently
//!   chosen between Predefined_Mode and FSE_Compressed_Mode based on
//!   estimated FSE-bitstream byte count + custom-table header overhead.
//! - `Raw_Block` (Block_Type=0) when neither of the above wins.
//!
//! Offsets are encoded with repeat-offset awareness: when a match's distance
//! equals one of the three most recent distinct distances, we emit
//! `offset_value ∈ 1..=3` rather than `distance + 3`, with the
//! `literal_length == 0` shifting rule per RFC 8478 §3.1.1.5. The
//! `prev_offsets` ring is carried across blocks.
//!
//! Frame layout we emit:
//! - 4 bytes magic (`0x28 0xB5 0x2F 0xFD`)
//! - 1 byte Frame_Header_Descriptor = `0x00`
//! - 1 byte Window_Descriptor = `0x70` (Window_Log = 24 → 16 MiB advertised
//!   window). The actual block ceiling is 128 KiB (RFC 8478 cap).
//! - One or more blocks; the last carries `Last_Block = 1`.

use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;
use crate::traits::{RawEncoder, RawProgress};
use crate::zstd::encoder_bitwriter::RevBitWriter;
use crate::zstd::encoder_fse::{
    DEFAULT_LL_ACCURACY_LOG, DEFAULT_LL_COUNTS, DEFAULT_ML_ACCURACY_LOG, DEFAULT_ML_COUNTS,
    DEFAULT_OF_ACCURACY_LOG, DEFAULT_OF_COUNTS, FseEncoder, build_normalised_counts,
    encode_fse_table_header,
};
use crate::zstd::encoder_huffman::{
    HuffLengths, build_huff_encoder, build_huff_lengths, encode_huff_4streams, encode_huff_stream,
    encode_huff_tree_direct, encode_huff_tree_fse, histogram, lengths_to_weights, predicted_bits,
};
use crate::zstd::encoder_seq::{encode_sequence_count, ll_code, ml_code, of_code};
use crate::zstd::matcher::{MIN_MATCH, MatchFinder};

const MAGIC: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];
const FHD: u8 = 0x00;
/// Window_Descriptor = 0x70: Exponent=14, Mantissa=0 → Window_Log = 24 →
/// 16 MiB window. RFC 8478 caps block size at min(Window_Size, 128 KiB), so
/// the effective block ceiling is 128 KiB.
const WD: u8 = 0x70;

/// Block size threshold. We emit one block per [`BLOCK_SIZE`] bytes (or
/// whatever's left at `finish` time). 128 KiB is the per-block ceiling; using
/// the max size amortises the literal-section and FSE-table overhead across
/// more sequences per block.
const BLOCK_SIZE: usize = 128 * 1024;

// ─── compression level ──────────────────────────────────────────────────

/// Tunables for the Zstandard encoder.
///
/// `level` controls the speed/ratio trade-off, following Zstandard's own
/// 1..=22 range with a default of `3`:
///
/// - Levels 1..=3 use a small chain budget and short "nice match" cutoff for
///   maximum throughput (zstd's `fast`/`dfast` strategies, approximated).
/// - Levels 4..=9 grow the chain budget and nice cutoff to find better
///   matches at a moderate CPU cost (`greedy`/`lazy`/`lazy2` territory).
/// - Levels 10..=19 walk deep chains and use a very high nice cutoff
///   (`btlazy2`-ish behaviour without the actual binary-tree match finder).
/// - Levels 20..=22 max out the chain budget (`btopt`/`btultra` territory).
///   Our encoder still uses a hash chain, so the upside saturates well below
///   the reference encoder's at those levels — but the size relation
///   `level=9 ≤ level=1` continues to hold.
///
/// Values outside `1..=22` are clamped at encoder construction time rather
/// than rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncoderConfig {
    /// Compression level in `1..=22`. Defaults to `3`.
    pub level: u8,
}

impl Default for EncoderConfig {
    fn default() -> Self {
        Self { level: 3 }
    }
}

/// Internal expansion of [`EncoderConfig::level`] into the match-finder
/// tuning knobs the LZ77 pass actually consults. Mirrors the shape of the
/// reference Zstandard `ZSTD_compressionParameters` table: higher levels
/// walk deeper chains and accept longer matches before bailing out.
#[derive(Debug, Clone, Copy)]
pub(crate) struct LevelParams {
    /// Maximum number of hash-chain links the match finder walks per probe.
    pub max_chain: usize,
    /// Length at which the match finder stops looking for a longer candidate.
    pub nice_match: usize,
    /// When true, the parser uses lazy match selection: after finding a
    /// match at `pos` it also probes `pos+1`, and may emit a literal and
    /// take the later match if it's meaningfully longer. Mirrors zstd's
    /// `lazy`/`lazy2` strategies (we do single-step lookahead only).
    pub lazy_search: bool,
    /// When true, the parser runs a price-based optimal parse (forward DP over
    /// the whole block) instead of greedy/lazy. Enabled at high levels where
    /// the extra CPU is acceptable. Mirrors zstd's `btopt`/`btultra`.
    pub optimal: bool,
}

/// Lowest level at which the optimal parser is used.
const OPTIMAL_LEVEL: u8 = 13;

/// Per-position hash-chain depth cap for the optimal parser. The DP visits
/// every position, so an uncapped chain (up to 16384 at level 22) makes each
/// block quadratic; this bound keeps encode time reasonable while preserving
/// nearly all of the ratio (the DP's win comes from length/repeat pricing,
/// not from exhaustive chain walks).
const OPTIMAL_MAX_CHAIN: usize = 4096;

impl LevelParams {
    /// Clamp `level` to `1..=22` and expand to match-finder tuning. The
    /// table broadly tracks zstd's reference presets but doesn't try to
    /// reproduce them exactly — the strategy here is hash-chain greedy
    /// parsing at low levels and hash-chain lazy parsing at level ≥ 4.
    /// Repeat-offset checks fire at every level (they're cheap enough that
    /// even level 1 can afford them).
    pub(crate) fn from_level(level: u8) -> Self {
        let level = level.clamp(1, 22);
        // Lazy parsing kicks in at level 4 — matches zstd's reference table
        // where `lazy` strategies start at level 4.
        let lazy_search = level >= 4;
        let optimal = level >= OPTIMAL_LEVEL;
        let (max_chain, nice_match) = match level {
            1 => (4, 8),
            2 => (8, 12),
            3 => (16, 16),
            4 => (24, 24),
            5 => (32, 32),
            6 => (48, 48),
            7 => (64, 64),
            8 => (96, 96),
            9 => (128, 128),
            10 => (192, 160),
            11 => (256, 192),
            12 => (384, 224),
            13 => (512, 256),
            14 => (768, 384),
            15 => (1024, 512),
            16 => (1536, 768),
            17 => (2048, 1024),
            18 => (3072, 1536),
            19 => (4096, 2048),
            20 => (6144, 3072),
            21 => (8192, 4096),
            // 22 (and clamp-from-above)
            _ => (16384, super::matcher::MAX_MATCH),
        };
        Self {
            max_chain,
            nice_match,
            lazy_search,
            optimal,
        }
    }
}

/// Streaming Zstandard encoder.
pub struct Encoder {
    state: State,
    /// Input buffer pending block emission.
    pending: Vec<u8>,
    /// Output bytes ready to drain into the caller's buffer.
    out_buf: Vec<u8>,
    /// Cursor into `out_buf`.
    out_idx: usize,
    /// Reusable matcher.
    matcher: MatchFinder,
    /// Have we written the frame header yet?
    header_written: bool,
    /// Repeat-offset ring (last three distinct match distances), carried across
    /// blocks. Initial state per RFC 8478 §3.1.1.5: `[1, 4, 8]`.
    prev_offsets: [u32; 3],
    /// Previous block's Huffman table (length array). When the next block's
    /// literal frequencies are similar, we emit a Treeless_Literals_Block and
    /// skip the tree description entirely. `None` until at least one
    /// Compressed_Literals_Block has been emitted.
    prev_huff_lengths: Option<HuffLengths>,
    /// Match-finder tuning derived from [`EncoderConfig::level`]. Persisted
    /// across `reset` since configuration is meant to survive resets.
    params: LevelParams,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum State {
    /// Accepting new input and accumulating into `pending`.
    Accepting,
    /// `out_buf[out_idx..]` is being drained into the caller's output.
    Draining { last: bool },
    /// All output drained; the codec is fully finished.
    Done,
}

impl Encoder {
    /// Build an encoder at the default compression level (3).
    pub fn new() -> Self {
        Self::with_config(EncoderConfig::default())
    }

    /// Build an encoder with explicit configuration. `config.level` is
    /// clamped to `1..=22` internally — out-of-range values are snapped to
    /// the nearest valid level rather than rejected.
    pub fn with_config(config: EncoderConfig) -> Self {
        Self {
            state: State::Accepting,
            pending: Vec::with_capacity(BLOCK_SIZE),
            out_buf: Vec::new(),
            out_idx: 0,
            matcher: MatchFinder::new(BLOCK_SIZE),
            header_written: false,
            prev_offsets: [1, 4, 8],
            prev_huff_lengths: None,
            params: LevelParams::from_level(config.level),
        }
    }

    /// Append frame magic + FHD + WD to `out_buf`.
    fn write_frame_header(&mut self) {
        self.out_buf.extend_from_slice(&MAGIC);
        self.out_buf.push(FHD);
        self.out_buf.push(WD);
    }

    /// Append a 3-byte block header for the given body size, type, and
    /// last-block flag.
    fn push_block_header(out: &mut Vec<u8>, body_size: u32, block_type: u32, last: bool) {
        debug_assert!(body_size < (1u32 << 21));
        debug_assert!(block_type < 4);
        let bh: u32 = (if last { 1 } else { 0 }) | (block_type << 1) | (body_size << 3);
        out.push((bh & 0xFF) as u8);
        out.push(((bh >> 8) & 0xFF) as u8);
        out.push(((bh >> 16) & 0xFF) as u8);
    }

    /// Append a Raw_Block (header + payload) for `body`.
    fn append_raw_block(out: &mut Vec<u8>, body: &[u8], last: bool) {
        Self::push_block_header(out, body.len() as u32, 0, last);
        out.extend_from_slice(body);
    }

    /// Try to encode `pending` as a Compressed_Block. Returns the block body
    /// (without the 3-byte block header) if successful and smaller than a
    /// Raw_Block; otherwise `None`.
    ///
    /// Side effect: on success, updates [`Self::prev_offsets`] from the
    /// sequences emitted. On failure (return `None`), `prev_offsets` is left
    /// unchanged so the next block sees the same pre-block state.
    fn try_compress_block(&mut self) -> Option<Vec<u8>> {
        if self.pending.len() < 16 {
            // Too small to bother — the framing overhead eats any savings.
            return None;
        }
        let buffer = self.pending.as_slice();
        self.matcher.resize_for(buffer.len());

        // Run LZ77 with repeat-offset awareness. We track a per-block ring
        // copy of `prev_offsets` and rewrite each emitted match's offset
        // through `assign_offset` so equal distances collapse to codes 1..=3.
        //
        // Two strategies depending on level:
        //   - level ≤ 3: greedy. Take the best match at the current position.
        //   - level ≥ 4: lazy. After finding a match at pos, also probe at
        //     pos+1; if it gives a meaningfully longer match, emit a literal
        //     and use that one instead.
        //
        // Independent of level, we always check the three repeat offsets at
        // each position first — a repeat-offset match costs 1 bit in the
        // offset stream vs. ~log2(distance) bits for a fresh offset, so even
        // short repeats are cheap wins.
        let lazy = self.params.lazy_search;
        let buf_len = buffer.len();
        let max_chain = self.params.max_chain;
        let nice_match = self.params.nice_match;

        // High levels: price-based optimal parse over the whole block. The DP
        // probes a match candidate at every input position, so we cap the
        // per-position chain depth to keep the per-block cost bounded — the DP
        // recovers most of the ratio from trying lengths and repeat offsets
        // rather than from exhaustive chain walks.
        if self.params.optimal {
            let opt_chain = max_chain.min(OPTIMAL_MAX_CHAIN);
            let (sequences, new_offsets) = optimal_parse(
                &mut self.matcher,
                buffer,
                self.prev_offsets,
                opt_chain,
                nice_match,
            );
            if sequences.is_empty() {
                return None;
            }
            return finish_compressed_block(
                buffer,
                &sequences,
                new_offsets,
                self.prev_huff_lengths.as_ref(),
            )
            .map(|(body, new_lengths, committed_offsets)| {
                self.prev_offsets = committed_offsets;
                if let Some(lengths) = new_lengths {
                    self.prev_huff_lengths = Some(lengths);
                }
                body
            });
        }

        let mut sequences: Vec<Seq> = Vec::new();
        let mut lit_start: usize = 0;
        let mut pos: usize = 0;
        let mut block_offsets = self.prev_offsets;

        // Invariant: positions in [0, next_insert) have already been spliced
        // into the matcher's hash chain. We advance `next_insert` lazily.
        let mut next_insert: usize = 0;
        while pos + MIN_MATCH < buf_len {
            // Make sure `pos` is in the chain.
            while next_insert <= pos {
                self.matcher.insert(buffer, next_insert);
                next_insert += 1;
            }

            // Step 1: best-match selection at `pos`.
            let (m_dist, m_len, m_is_rep1) = best_at(
                &self.matcher,
                buffer,
                pos,
                &block_offsets,
                max_chain,
                nice_match,
            );

            if m_len == 0 {
                pos += 1;
                continue;
            }

            // Step 2 (lazy only): probe pos+1 for a meaningfully better match.
            // "Meaningfully better" = strictly longer by at least 1 byte when
            // the current isn't already long. We skip the probe when the
            // current match is already at least `nice_match` — there's no
            // plausible win at that point.
            let (best_pos, best_dist, best_len) =
                if lazy && m_len < nice_match && pos + 1 + MIN_MATCH < buf_len {
                    // Insert pos+1 into the chain so its hash bucket includes it.
                    while next_insert <= pos + 1 {
                        self.matcher.insert(buffer, next_insert);
                        next_insert += 1;
                    }
                    let (n_dist, n_len, _) = best_at(
                        &self.matcher,
                        buffer,
                        pos + 1,
                        &block_offsets,
                        max_chain,
                        nice_match,
                    );
                    // Score: prefer longer-match. A repeat-offset hit at pos
                    // saves bits in the offset stream — bias slightly in its
                    // favour by requiring the lazy match to beat by ≥2.
                    let margin = if m_is_rep1 { 2 } else { 1 };
                    if n_len >= m_len + margin {
                        (pos + 1, n_dist, n_len)
                    } else {
                        (pos, m_dist, m_len)
                    }
                } else {
                    (pos, m_dist, m_len)
                };

            // Emit the literals run up to `best_pos`, then the chosen match.
            let literal_run = best_pos - lit_start;
            let offset_value =
                assign_offset(best_dist as u32, literal_run as u32, &mut block_offsets);
            sequences.push(Seq {
                literal_length: literal_run as u32,
                match_length: best_len as u32,
                offset_value,
            });
            // Splice the interior positions of the match into the chain so
            // later positions can match against them. We only insert
            // positions that aren't already in.
            let match_end = best_pos + best_len;
            while next_insert < match_end {
                self.matcher.insert(buffer, next_insert);
                next_insert += 1;
            }
            pos = match_end;
            lit_start = pos;
        }

        let _ = lit_start;
        if sequences.is_empty() {
            return None;
        }

        finish_compressed_block(
            buffer,
            &sequences,
            block_offsets,
            self.prev_huff_lengths.as_ref(),
        )
        .map(|(body, new_lengths, committed_offsets)| {
            self.prev_offsets = committed_offsets;
            if let Some(lengths) = new_lengths {
                self.prev_huff_lengths = Some(lengths);
            }
            body
        })
    }
}

/// Shared back half of block compression: reconstruct the literal byte stream
/// from the chosen sequences, build the literals + sequences sections, and
/// return `(body, new_huff_lengths, committed_offsets)` if the compressed body
/// beats a Raw_Block. The caller commits the returned state. Free function so
/// both the greedy/lazy and the optimal parsers can share it without aliasing
/// `self.pending` (which `buffer` borrows) against `&mut self`.
fn finish_compressed_block(
    buffer: &[u8],
    sequences: &[Seq],
    block_offsets: [u32; 3],
    prev_huff_lengths: Option<&HuffLengths>,
) -> Option<(Vec<u8>, Option<HuffLengths>, [u32; 3])> {
    // Reconstruct all literal bytes by replaying the sequences: each sequence
    // emits `literal_length` literals from the cursor, then skips
    // `match_length` matched bytes. Trailing bytes after the last sequence are
    // literals too.
    let mut all_literals: Vec<u8> = Vec::with_capacity(buffer.len());
    let mut cursor = 0usize;
    for s in sequences {
        let ll = s.literal_length as usize;
        all_literals.extend_from_slice(&buffer[cursor..cursor + ll]);
        cursor += ll + s.match_length as usize;
    }
    all_literals.extend_from_slice(&buffer[cursor..]);

    let (lit_section, new_lengths) = build_literals_section(&all_literals, prev_huff_lengths);
    let seq_section = build_sequences_section(sequences);

    let total = lit_section.len() + seq_section.len();
    if total >= buffer.len() {
        return None; // Not worth compressing.
    }

    let mut body = Vec::with_capacity(total);
    body.extend_from_slice(&lit_section);
    body.extend_from_slice(&seq_section);
    Some((body, new_lengths, block_offsets))
}

/// Build the sequence section bytes: header (count + symbol-modes byte)
/// followed by the FSE-encoded sequence bitstream.
///
/// Per-table mode selection: for each of LL/OF/ML we try the predefined
/// distribution against a custom FSE_Compressed_Mode distribution built from
/// this block's actual code histogram. Whichever produces the smaller
/// estimated byte count wins.
fn build_sequences_section(sequences: &[Seq]) -> Vec<u8> {
    let n = sequences.len() as u32;

    // Pre-compute (code, extra_bits, extra_val) for each sequence.
    let mut ll_codes: Vec<u8> = Vec::with_capacity(sequences.len());
    let mut ml_codes: Vec<u8> = Vec::with_capacity(sequences.len());
    let mut of_codes: Vec<u8> = Vec::with_capacity(sequences.len());
    let mut ll_extras: Vec<(u32, u32)> = Vec::with_capacity(sequences.len());
    let mut ml_extras: Vec<(u32, u32)> = Vec::with_capacity(sequences.len());
    let mut of_extras: Vec<(u32, u32)> = Vec::with_capacity(sequences.len());

    for s in sequences {
        let (oc, oe_bits, oe_val) = of_code(s.offset_value);
        of_codes.push(oc);
        of_extras.push((oe_bits, oe_val));

        let (lc, le_bits, le_val) = ll_code(s.literal_length);
        ll_codes.push(lc);
        ll_extras.push((le_bits, le_val));

        let (mc, me_bits, me_val) = ml_code(s.match_length);
        ml_codes.push(mc);
        ml_extras.push((me_bits, me_val));
    }

    // Pick per-table mode and build the encoders + any header bytes.
    let (ll_enc, ll_mode, ll_header) = pick_table(
        &ll_codes,
        &DEFAULT_LL_COUNTS,
        DEFAULT_LL_ACCURACY_LOG,
        9,
        35,
    );
    let (of_enc, of_mode, of_header) = pick_table(
        &of_codes,
        &DEFAULT_OF_COUNTS,
        DEFAULT_OF_ACCURACY_LOG,
        8,
        31,
    );
    let (ml_enc, ml_mode, ml_header) = pick_table(
        &ml_codes,
        &DEFAULT_ML_COUNTS,
        DEFAULT_ML_ACCURACY_LOG,
        9,
        52,
    );

    // Build the sequences-section bytes.
    let mut out = encode_sequence_count(n);
    // Symbol_Compression_Modes byte: bits [7:6]=LL_Mode, [5:4]=OF_Mode,
    // [3:2]=ML_Mode, [1:0]=Reserved.
    let modes: u8 = (ll_mode << 6) | (of_mode << 4) | (ml_mode << 2);
    out.push(modes);
    out.extend_from_slice(&ll_header);
    out.extend_from_slice(&of_header);
    out.extend_from_slice(&ml_header);

    // FSE-encode the symbol streams.
    let mut writer = RevBitWriter::new();
    let n_seq = sequences.len();

    // Reverse encoding pattern. Init states from the LAST sequence.
    let mut ll_state = ll_enc.init_state(ll_codes[n_seq - 1] as usize);
    let mut of_state = of_enc.init_state(of_codes[n_seq - 1] as usize);
    let mut ml_state = ml_enc.init_state(ml_codes[n_seq - 1] as usize);

    // For each sequence (processed in reverse), write to the bitstream
    // in the EXACT REVERSE of the decoder's read order.
    //
    // Decoder per-sequence read order (recall §3.1.1.3.2.1):
    //   1. OF_extra_bits (number = of_code value)
    //   2. ML_extra_bits
    //   3. LL_extra_bits
    //   4. (only if not last sequence): LL_advance, ML_advance, OF_advance.
    //
    // The reverse-bitstream writer is "first-written = last-read". So if
    // we walk sequences i = n-1 → 0:
    //   For i = n-1 (DECODER's last sequence): write extras only, in
    //     reverse read order: write LL_extra first, then ML_extra, then
    //     OF_extra.
    //   For i < n-1: write the FSE advance bits for THIS sequence's
    //     transition (out_OF, then out_ML, then out_LL — reverse of the
    //     decoder's LL, ML, OF advance read order), THEN write the
    //     extras (LL, ML, OF reversed).
    //
    // FSE advance bits are emitted by `encode_symbol(state, sym)`.
    // The bits returned correspond to the decoder's read at that
    // advance step.
    //
    // To produce the correct interleaving, we structure the loop:
    //   for i in (0..n_seq).rev() {
    //       if i == n_seq - 1 {
    //           // No advance for the last decoder-side sequence.
    //       } else {
    //           // Advance: encode the transition FROM sequence i+1's
    //           // state INTO sequence i's state for each of OF, ML, LL.
    //           // Decoder reads advance order LL, ML, OF — so we write
    //           // OF first (most recently read), then ML, then LL.
    //           of_state = self.of_enc.encode_symbol(of_state, of_codes[i] as usize, &mut writer);
    //           ml_state = self.ml_enc.encode_symbol(ml_state, ml_codes[i] as usize, &mut writer);
    //           ll_state = self.ll_enc.encode_symbol(ll_state, ll_codes[i] as usize, &mut writer);
    //       }
    //       // Extras: decoder reads OF, ML, LL — write LL, ML, OF.
    //       writer.write_bits(ll_extras[i].1 as u64, ll_extras[i].0);
    //       writer.write_bits(ml_extras[i].1 as u64, ml_extras[i].0);
    //       writer.write_bits(of_extras[i].1 as u64, of_extras[i].0);
    //   }
    //
    // Hmm wait — encode_symbol(state, sym) consumes the CURRENT state
    // (which corresponds to the decoder's PRE-advance state) and
    // produces NEW state (decoder's POST-advance state). The bits
    // written are the bits the decoder reads to perform the advance.
    //
    // The decoder advances at the END of sequence i (using sequence i's
    // current state to compute next_state for sequence i+1). So the
    // bits FOR THIS ADVANCE are read at the END of sequence i's
    // processing. From sequence i+1's POV, the state was set up by
    // this advance.
    //
    // We're processing sequences in reverse (i from n-1 to 0). When
    // i = n-2, we're handling the SECOND-TO-LAST sequence (decoder-
    // side). The advance bits at this point are the ones the decoder
    // reads at the END of i=n-2 to set up i=n-1's state. So we encode
    // the transition FROM sequence n-2's state INTO n-1's state.
    //
    // In our reverse loop, "current state" represents sequence n-1's
    // initial state (set up via init_state). After encode_symbol with
    // ll_codes[n-2], the state will represent sequence n-2's initial
    // state. The BITS written reflect the (current → new) transition
    // i.e. n-2 → n-1 advance (since current = n-1 before).
    //
    // So `encode_symbol(state_for_seq_iplus1, codes[i])` writes the
    // bits the decoder reads at the end of seq i to advance from
    // seq_i.state to seq_(i+1).state. ✓
    for i in (0..n_seq).rev() {
        if i == n_seq - 1 {
            // No advance bits for the decoder's last sequence.
        } else {
            of_state = of_enc.encode_symbol(of_state, of_codes[i] as usize, &mut writer);
            ml_state = ml_enc.encode_symbol(ml_state, ml_codes[i] as usize, &mut writer);
            ll_state = ll_enc.encode_symbol(ll_state, ll_codes[i] as usize, &mut writer);
        }
        // Extras: decoder reads OF, ML, LL — write LL, ML, OF.
        writer.write_bits(ll_extras[i].1 as u64, ll_extras[i].0);
        writer.write_bits(ml_extras[i].1 as u64, ml_extras[i].0);
        writer.write_bits(of_extras[i].1 as u64, of_extras[i].0);
    }

    // Write final FSE states (decoder reads these via init in order
    // LL, OF, ML — we write reverse: ML, OF, LL).
    ml_enc.write_final_state(ml_state, &mut writer);
    of_enc.write_final_state(of_state, &mut writer);
    ll_enc.write_final_state(ll_state, &mut writer);

    let bitstream = writer.finish();
    out.extend_from_slice(&bitstream);
    out
}

impl Encoder {
    /// Flush `pending` as a single block (RLE / compressed / raw — whichever
    /// is smallest). Sets `last` on the block header.
    fn flush_block(&mut self, last: bool) {
        // RLE_Block: 4-byte total (3-byte header + 1 payload byte) iff every
        // byte of `pending` is identical. A clear win on any single-byte run
        // longer than 4 bytes.
        if self.pending.len() >= 4 && all_same(&self.pending) {
            let body_size = self.pending.len() as u32;
            Self::push_block_header(&mut self.out_buf, body_size, 1, last);
            self.out_buf.push(self.pending[0]);
            self.pending.clear();
            return;
        }
        if let Some(body) = self.try_compress_block() {
            Self::push_block_header(&mut self.out_buf, body.len() as u32, 2, last);
            self.out_buf.extend_from_slice(&body);
        } else {
            // Fall back to Raw_Block.
            let pending_snapshot = core::mem::take(&mut self.pending);
            Self::append_raw_block(&mut self.out_buf, &pending_snapshot, last);
            self.pending = pending_snapshot;
        }
        self.pending.clear();
    }

    /// Copy as much of `out_buf[out_idx..]` into `output[*written..]` as fits.
    fn drain_into(&mut self, output: &mut [u8], written: &mut usize) -> bool {
        let avail = output.len() - *written;
        let remaining = self.out_buf.len() - self.out_idx;
        let n = core::cmp::min(avail, remaining);
        if n > 0 {
            output[*written..*written + n]
                .copy_from_slice(&self.out_buf[self.out_idx..self.out_idx + n]);
            *written += n;
            self.out_idx += n;
        }
        let drained = self.out_idx == self.out_buf.len();
        if drained {
            self.out_buf.clear();
            self.out_idx = 0;
        }
        drained
    }
}

// ─── price-based optimal parser ───────────────────────────────────────────

/// Estimated bit cost of a literal byte (~Huffman-coded text/code literal).
/// Only the literal-vs-match trade-off depends on it, not correctness.
const LIT_PRICE: u32 = 9;

/// Estimated bit cost of the offset part of a match: the FSE offset code plus
/// its extra bits, with a distance matching one of the active repeat offsets
/// priced near-free (repeats emit a tiny FSE code and NO offset extra bits).
fn offset_price(distance: u32, reps: &[u32; 3], ll: u32) -> u32 {
    let is_rep = if ll > 0 {
        distance == reps[0] || distance == reps[1] || distance == reps[2]
    } else {
        distance == reps[1] || distance == reps[2] || (reps[0] > 1 && distance == reps[0] - 1)
    };
    if is_rep {
        return 4;
    }
    // Fresh offset: `code` extra bits (the literal low bits of the distance)
    // plus the FSE-coded offset code itself (~5 bits amortised). The FSE code
    // adapts to the block, so it is NOT another `log2(D)` — charging that would
    // double-count and push the DP away from good long-distance matches.
    let val = distance + 3;
    let code = 31 - val.leading_zeros();
    code + 5
}

/// Estimated bit cost of the literal-length / match-length FSE codes plus
/// their extra bits for a sequence with the given run/length.
fn ll_ml_price(literal_length: u32, match_length: u32) -> u32 {
    let (_lc, lb, _lv) = ll_code(literal_length);
    let (_mc, mb, _mv) = ml_code(match_length);
    10 + lb + mb
}

/// Update the repeat-offset ring after a match (mirrors `assign_offset`'s
/// transitions) and return the new ring. Used to carry rep state along the
/// optimal-parse DP path.
fn advance_reps(distance: u32, literal_length: u32, reps: &[u32; 3]) -> [u32; 3] {
    let mut r = *reps;
    let _ = assign_offset(distance, literal_length, &mut r);
    r
}

/// Price-based optimal parse of `buffer` into a sequence list.
///
/// Forward dynamic program: `price[i]` is the cheapest estimated bit cost to
/// encode `buffer[0..i]`. Each position can be reached by emitting a literal
/// (advance 1) or a match of some length (advance L). Match candidates come
/// from the hash chain plus the three active repeat offsets, and every length
/// from `MIN_MATCH` up to a candidate's max is priced — so the DP can pick a
/// slightly shorter match that lands on a cheaper (closer or repeated) offset.
/// Repeat offsets are priced near-free, which is where most of the win over
/// greedy/lazy parsing comes from (their offset extra bits dominate output).
///
/// Returns the chosen sequences (in order) and the final repeat-offset ring.
fn optimal_parse(
    matcher: &mut MatchFinder,
    buffer: &[u8],
    init_offsets: [u32; 3],
    max_chain: usize,
    nice_match: usize,
) -> (Vec<Seq>, [u32; 3]) {
    let n = buffer.len();
    if n < MIN_MATCH + 1 {
        return (Vec::new(), init_offsets);
    }

    // Insert every hashable position up front so chain walks see the whole
    // block (back-references only look earlier, so insertion order within the
    // block doesn't affect correctness).
    matcher.resize_for(n);
    for i in 0..n.saturating_sub(3) {
        matcher.insert(buffer, i);
    }

    const INF: u32 = u32::MAX;
    let mut price: Vec<u32> = vec![INF; n + 1];
    // Back-pointer: (prev_pos, match_len, match_dist). match_len == 0 → literal.
    let mut back: Vec<(u32, u32, u32)> = vec![(0, 0, 0); n + 1];
    let mut reps_at: Vec<[u32; 3]> = vec![init_offsets; n + 1];
    price[0] = 0;

    // Step length sparsely for long matches to bound DP work. Dense up to 128
    // (where most matches live), then coarser.
    let push_len = |l: usize, max_l: usize| -> usize {
        let step = if l < 128 { 1 } else { 32 };
        let next = l + step;
        if next > max_l && l < max_l {
            max_l
        } else {
            next
        }
    };

    let mut cands: Vec<crate::zstd::matcher::Match> = Vec::new();

    for i in 0..n {
        let base = price[i];
        if base == INF {
            continue;
        }
        let cur_reps = reps_at[i];

        // Option A: emit a literal.
        let lit_cand = base.saturating_add(LIT_PRICE);
        if lit_cand < price[i + 1] {
            price[i + 1] = lit_cand;
            back[i + 1] = (i as u32, 0, 0);
            reps_at[i + 1] = cur_reps;
        }

        if i + MIN_MATCH > n {
            continue;
        }
        // Proxy literal-length for offset rep-aliasing: the common case is a
        // sequence following some literals (LL>0, reps map to codes 1..=3).
        let ll_proxy = 1u32;

        // Option B1: repeat-offset matches at the three active distances.
        for &d in &cur_reps {
            if d == 0 || (d as usize) > i {
                continue;
            }
            let m = matcher.check_repeat_offset(buffer, i, d as usize);
            if m >= MIN_MATCH {
                let max_l = m.min(n - i);
                let off = offset_price(d, &cur_reps, ll_proxy);
                let mut l = MIN_MATCH;
                while l <= max_l {
                    let cost = base
                        .saturating_add(off)
                        .saturating_add(ll_ml_price(0, l as u32));
                    if cost < price[i + l] {
                        price[i + l] = cost;
                        back[i + l] = (i as u32, l as u32, d);
                        reps_at[i + l] = advance_reps(d, ll_proxy, &cur_reps);
                    }
                    if l == max_l {
                        break;
                    }
                    l = push_len(l, max_l);
                }
            }
        }

        // Option B2: fresh hash-chain matches.
        matcher.collect_matches(buffer, i, n, max_chain, nice_match, &mut cands);
        for c in &cands {
            let d = c.distance as u32;
            let max_l = c.length.min(n - i);
            let off = offset_price(d, &cur_reps, ll_proxy);
            let mut l = MIN_MATCH;
            while l <= max_l {
                let cost = base
                    .saturating_add(off)
                    .saturating_add(ll_ml_price(0, l as u32));
                if cost < price[i + l] {
                    price[i + l] = cost;
                    back[i + l] = (i as u32, l as u32, d);
                    reps_at[i + l] = advance_reps(d, ll_proxy, &cur_reps);
                }
                if l == max_l {
                    break;
                }
                l = push_len(l, max_l);
            }
        }
    }

    // Backtrack to recover the chosen steps, then emit sequences forward.
    let mut steps: Vec<(u32, u32)> = Vec::new(); // (match_len, match_dist); 0 = literal
    let mut i = n;
    while i > 0 {
        let (prev, mlen, mdist) = back[i];
        steps.push((mlen, mdist));
        i = prev as usize;
    }
    steps.reverse();

    let mut sequences: Vec<Seq> = Vec::new();
    let mut block_offsets = init_offsets;
    let mut pending_literals: u32 = 0;
    for (mlen, mdist) in steps {
        if mlen == 0 {
            pending_literals += 1;
            continue;
        }
        let offset_value = assign_offset(mdist, pending_literals, &mut block_offsets);
        sequences.push(Seq {
            literal_length: pending_literals,
            match_length: mlen,
            offset_value,
        });
        pending_literals = 0;
    }
    // Trailing literals are emitted by the block builder; drop the counter.
    let _ = pending_literals;

    (sequences, block_offsets)
}

/// Find the best (distance, length) match at `pos`, mixing repeat-offset
/// probes with a hash-chain search.
///
/// Repeat-offset candidates are checked first: the three slots in
/// `block_offsets` (per RFC 8478 §3.1.1.5, the most-recent offset is at
/// index 0). Repeat-offset matches cost only the FSE code 1..=3 in the
/// offset stream (1 to ~5 bits depending on FSE table) versus the
/// `floor(log2(distance + 3))` extra bits a fresh offset spends, so we
/// prefer them over a fresh-offset match of equal length.
///
/// The third return value flags whether the chosen match is the most-recent
/// repeat offset (`offset_value == 1`). That's a useful hint for the lazy
/// parser: a rep-0 match is so cheap that the lazy probe should require a
/// larger gain before throwing it away.
fn best_at(
    matcher: &MatchFinder,
    buffer: &[u8],
    pos: usize,
    block_offsets: &[u32; 3],
    max_chain: usize,
    nice_match: usize,
) -> (usize, usize, bool) {
    // Repeat-offset probes. A repeat offset costs only the FSE code (1..=3) in
    // the offset stream and — crucially — emits NO offset extra bits, whereas
    // a fresh offset at distance D spends ~log2(D) FSE-code bits PLUS ~log2(D)
    // extra bits. On real corpora those offset extra bits are the single
    // largest part of the output, so a repeat match that is several bytes
    // shorter than the best fresh match is often still the cheaper encoding.
    let mut rep_len: usize = 0;
    let mut rep_dist: usize = 0;
    let mut rep_is_rep1: bool = false;
    for (i, &d) in block_offsets.iter().enumerate() {
        let len = matcher.check_repeat_offset(buffer, pos, d as usize);
        // Prefer earlier rep slots on ties (they encode in fewer bits and
        // don't perturb the ring).
        if len > rep_len {
            rep_len = len;
            rep_dist = d as usize;
            rep_is_rep1 = i == 0;
        }
    }
    if rep_len >= nice_match {
        return (rep_dist, rep_len, rep_is_rep1);
    }

    // Hash-chain probe (longest fresh match).
    let fresh = matcher.find_match(buffer, pos, buffer.len(), max_chain, nice_match);

    match fresh {
        Some(m) if rep_len >= MIN_MATCH => {
            // Both a repeat and a fresh candidate exist. The fresh match must
            // beat the repeat by enough length to pay for the offset bits it
            // spends that the repeat avoids. A fresh offset at distance D costs
            // roughly `2 * log2(D + 3)` bits more than a repeat; each matched
            // byte is worth ~6 bits, so require the fresh match to be longer by
            // at least `2 * log2(D) / 6` bytes.
            let val = m.distance as u32 + 3;
            let log2d = 31 - val.leading_zeros();
            let margin = ((2 * log2d) / 6).max(1) as usize;
            if m.length >= rep_len + margin {
                (
                    m.distance,
                    m.length,
                    m.distance == block_offsets[0] as usize,
                )
            } else {
                (rep_dist, rep_len, rep_is_rep1)
            }
        }
        Some(m) => (
            m.distance,
            m.length,
            m.distance == block_offsets[0] as usize,
        ),
        None => (rep_dist, rep_len, rep_is_rep1),
    }
}

/// Pick the best per-table FSE mode (Predefined or FSE_Compressed) given the
/// codes used. Returns `(encoder, mode_bits, header_bytes)`. `mode_bits` is
/// the 2-bit field stored in the Symbol_Compression_Modes byte
/// (`0b00`=Predefined, `0b10`=FSE_Compressed). `header_bytes` is empty for
/// Predefined.
///
/// We pick FSE_Compressed only when its predicted FSE-bitstream byte count
/// plus header bytes is smaller than the predefined-table's predicted
/// bitstream bytes by at least a 4-byte threshold (to avoid noisy wins from
/// short blocks).
fn pick_table(
    codes: &[u8],
    default_counts: &[i16],
    default_al: u8,
    max_al: u8,
    max_symbol: u16,
) -> (FseEncoder, u8, Vec<u8>) {
    let alphabet = (max_symbol as usize) + 1;
    let mut hist = vec![0u32; alphabet];
    for &c in codes {
        if (c as usize) < alphabet {
            hist[c as usize] += 1;
        }
    }
    let n = codes.len();

    // Predicted bits using predefined distribution.
    let pred_bits_default = predict_fse_bits(default_counts, &hist, default_al);

    // Pick an accuracy_log for custom: roughly log2(n) but capped.
    let mut al = max_al;
    while al > 5 && (1u32 << al) > (n as u32) * 4 {
        al -= 1;
    }
    if al < 5 {
        al = 5;
    }

    // Try to build normalised counts.
    let custom = build_normalised_counts(&hist, n as u32, al);
    if let Some(counts) = custom {
        let pred_bits_custom = predict_fse_bits(&counts, &hist, al);
        let header = encode_fse_table_header(&counts, al);
        let custom_bytes = (pred_bits_custom / 8 + 1) as usize + header.len();
        let default_bytes = (pred_bits_default / 8 + 1) as usize;
        // Threshold: only switch to custom if it saves at least 2 bytes (to
        // pay for noise in the estimates without being too greedy).
        if custom_bytes + 2 < default_bytes {
            let enc = FseEncoder::from_normalized(&counts, al);
            return (enc, 0b10, header);
        }
    }
    let predef_enc = FseEncoder::from_normalized(default_counts, default_al);
    (predef_enc, 0b00, Vec::new())
}

/// Predict the bit count of an FSE bitstream over `codes_hist` (per-code
/// occurrence counts) under the distribution given by `counts` /
/// `accuracy_log`.
///
/// For each code `s` with count `n_s` occurrences and normalised count
/// `c_s`, the average FSE step uses `accuracy_log - floor(log2(c_s))` bits
/// (with `c_s = -1` treated as a single state always reading
/// `accuracy_log` bits). We just sum that across all occurrences.
fn predict_fse_bits(counts: &[i16], hist: &[u32], accuracy_log: u8) -> u64 {
    let mut total: u64 = 0;
    for s in 0..hist.len().min(counts.len()) {
        let n = hist[s] as u64;
        if n == 0 {
            continue;
        }
        let c = counts[s];
        let bits = if c == -1 || c == 1 {
            accuracy_log as u64
        } else if c > 1 {
            let log2 = 31u32 - (c as u32).leading_zeros();
            (accuracy_log as u64).saturating_sub(log2 as u64)
        } else {
            // Code present in the stream but has count 0 in distribution —
            // can't actually be FSE-encoded. Return a huge cost.
            return u64::MAX;
        };
        total += n * bits;
    }
    total
}

/// Are all bytes of `s` the same value? Used to detect RLE_Block opportunities.
fn all_same(s: &[u8]) -> bool {
    if s.is_empty() {
        return true;
    }
    let first = s[0];
    s.iter().all(|&b| b == first)
}

/// One LZ77 sequence after repeat-offset assignment. `offset_value` is the
/// number the FSE/extra-bits encoder will emit — either `distance + 3` for a
/// fresh offset, or `1..=3` aliasing one of the three previous offsets.
#[derive(Clone, Copy, Debug)]
struct Seq {
    literal_length: u32,
    match_length: u32,
    offset_value: u32,
}

/// Build a Raw_Literals_Block section: literal-section header + raw bytes.
fn build_raw_literals_section_one(literals: &[u8]) -> Vec<u8> {
    let regen = literals.len();
    let mut out = Vec::with_capacity(3 + regen);
    // Raw_Literals_Block = type 0. Choose Size_Format to fit `regen`.
    if regen < 32 {
        // 1-byte header: SF=00, type=00. Size in upper 5 bits.
        let hdr = (regen as u8) << 3;
        out.push(hdr);
    } else if regen < 4096 {
        // 2-byte header: SF=01, 12-bit regen.
        let byte0 = (((regen & 0xF) as u8) << 4) | (0b01 << 2);
        let byte1 = (regen >> 4) as u8;
        out.push(byte0);
        out.push(byte1);
    } else {
        // 3-byte header: SF=11, 20-bit regen.
        let byte0 = (((regen & 0xF) as u8) << 4) | (0b11 << 2);
        let byte1 = ((regen >> 4) & 0xFF) as u8;
        let byte2 = ((regen >> 12) & 0xFF) as u8;
        out.push(byte0);
        out.push(byte1);
        out.push(byte2);
    }
    out.extend_from_slice(literals);
    out
}

/// Build the literals section, choosing the smallest of: Compressed
/// (Block_Type=10, fresh Huffman tree), Treeless (Block_Type=11, reusing
/// `prev_lengths`), or Raw (Block_Type=00). Returns `(section_bytes, new_huff_lengths)`
/// where `new_huff_lengths` is `Some` iff the picked section carries — or
/// reuses — a Huffman tree (i.e. the next block could use Treeless from it).
fn build_literals_section(
    literals: &[u8],
    prev_lengths: Option<&HuffLengths>,
) -> (Vec<u8>, Option<HuffLengths>) {
    let regen = literals.len();

    let mut best: Option<(Vec<u8>, Option<HuffLengths>)> = None;
    let raw_len = raw_literals_section_len(regen);

    // Helper: keep the smallest candidate so far.
    let take_candidate =
        |section: Vec<u8>,
         lengths: Option<HuffLengths>,
         current: &mut Option<(Vec<u8>, Option<HuffLengths>)>| {
            if section.len() < raw_len
                && current
                    .as_ref()
                    .map(|(b, _)| section.len() < b.len())
                    .unwrap_or(true)
            {
                *current = Some((section, lengths));
            }
        };

    if regen >= 32 {
        // Try Treeless (reuse) if we have a previous tree compatible with the
        // current literal alphabet.
        if let Some(prev) = prev_lengths {
            let mut compatible = true;
            for &b in literals {
                if prev[b as usize] == 0 {
                    compatible = false;
                    break;
                }
            }
            if compatible
                && let Some(section) = try_build_huffman_literals_section_with(
                    literals, prev, /* fresh_tree = */ false,
                )
            {
                take_candidate(section, Some(*prev), &mut best);
            }
        }
        // Try fresh tree. This also tells us the "new" tree for chaining.
        let freq = histogram(literals);
        if let Some(lengths) = build_huff_lengths(&freq)
            && let Some(section) = try_build_huffman_literals_section_with(
                literals, &lengths, /* fresh_tree = */ true,
            )
        {
            take_candidate(section, Some(lengths), &mut best);
        }
    }

    if let Some((section, lengths)) = best {
        (section, lengths)
    } else {
        (build_raw_literals_section_one(literals), None)
    }
}

/// Compute the byte size a Raw_Literals_Block section will take for `regen`
/// bytes (header + payload).
fn raw_literals_section_len(regen: usize) -> usize {
    let header = if regen < 32 {
        1
    } else if regen < 4096 {
        2
    } else {
        3
    };
    header + regen
}

/// Try building a literals section using a Huffman tree.
///
/// When `fresh_tree=true`, emits a Compressed_Literals_Block (Block_Type=10)
/// whose payload starts with the tree description. When `fresh_tree=false`,
/// emits a Treeless_Literals_Block (Block_Type=11): no tree bytes; the
/// decoder is expected to reuse the previously transmitted tree (whose
/// lengths must equal `lengths`). The caller is responsible for ensuring the
/// previous-block tree is compatible with all bytes in `literals` and that
/// at least one Compressed_Literals_Block has preceded this one in the
/// stream.
///
/// Returns `Some(section_bytes)` if successful, or `None` if a structural
/// limit is exceeded (alphabet too large for the direct nibble weight
/// encoding, regen/comp size beyond 18 bits, etc.).
fn try_build_huffman_literals_section_with(
    literals: &[u8],
    lengths: &HuffLengths,
    fresh_tree: bool,
) -> Option<Vec<u8>> {
    let regen = literals.len();
    if regen == 0 {
        return None;
    }
    if regen > (1 << 18) - 1 {
        return None; // Exceeds the SF=11 18-bit field.
    }
    let enc = build_huff_encoder(lengths);
    // Compute or skip the tree-description bytes depending on `fresh_tree`.
    // When emitting a fresh tree we choose the smaller of two serialisations:
    //   - direct nibble-packed weights (only valid for ≤ 128 weights), and
    //   - FSE-compressed weights (mandatory above 128 weights, and often
    //     smaller for large skewed alphabets even below the cap).
    let tree_bytes: Vec<u8> = if fresh_tree {
        let (weights, _max_num_bits) = lengths_to_weights(lengths);
        let direct: Option<Vec<u8>> = if weights.len() <= 128 {
            Some(encode_huff_tree_direct(&weights))
        } else {
            None
        };
        let fse = encode_huff_tree_fse(&weights);
        match (direct, fse) {
            (Some(d), Some(f)) => {
                if f.len() < d.len() {
                    f
                } else {
                    d
                }
            }
            (Some(d), None) => d,
            (None, Some(f)) => f,
            (None, None) => return None, // alphabet too large for either path
        }
    } else {
        Vec::new()
    };

    // Quick reject: bits prediction + tree overhead vs. raw size.
    let mut freq = [0u32; 256];
    for &b in literals {
        freq[b as usize] += 1;
        // While iterating, also catch the "byte not in this tree" case for
        // Treeless mode — the caller checked but be defensive.
        if !fresh_tree && lengths[b as usize] == 0 {
            return None;
        }
    }
    let pred_bits = predicted_bits(lengths, &freq);
    let est_payload = pred_bits.div_ceil(8) as usize + tree_bytes.len() + 8;
    if est_payload >= regen + 3 {
        return None;
    }

    // Encode the literal stream(s) and assemble the payload.
    let (use_4_stream, streams): (bool, Vec<Vec<u8>>) = if regen <= 1023 {
        (false, vec![encode_huff_stream(&enc, literals)])
    } else {
        let (s1, s2, s3, s4) = encode_huff_4streams(&enc, literals);
        (true, vec![s1, s2, s3, s4])
    };

    let stream_total: usize = streams.iter().map(|s| s.len()).sum();
    let jump_table_len = if use_4_stream { 6 } else { 0 };
    let mut payload = Vec::with_capacity(tree_bytes.len() + jump_table_len + stream_total);
    payload.extend_from_slice(&tree_bytes);
    if use_4_stream {
        let l1 = streams[0].len();
        let l2 = streams[1].len();
        let l3 = streams[2].len();
        if l1 > 0xFFFF || l2 > 0xFFFF || l3 > 0xFFFF {
            return None;
        }
        payload.push((l1 & 0xFF) as u8);
        payload.push(((l1 >> 8) & 0xFF) as u8);
        payload.push((l2 & 0xFF) as u8);
        payload.push(((l2 >> 8) & 0xFF) as u8);
        payload.push((l3 & 0xFF) as u8);
        payload.push(((l3 >> 8) & 0xFF) as u8);
        for s in &streams {
            payload.extend_from_slice(s);
        }
    } else {
        payload.extend_from_slice(&streams[0]);
    }

    let comp_size = payload.len();

    // Pick Size_Format / header layout.
    let (sf, header_bytes): (u8, usize) = if !use_4_stream {
        if regen >= 1024 || comp_size >= 1024 {
            return None;
        }
        (0b00, 3)
    } else if regen < 1024 && comp_size < 1024 {
        (0b01, 3)
    } else if regen < 16384 && comp_size < 16384 {
        (0b10, 4)
    } else if regen < (1 << 18) && comp_size < (1 << 18) {
        (0b11, 5)
    } else {
        return None;
    };

    let lit_block_type: u8 = if fresh_tree { 0b10 } else { 0b11 };
    let lhd_low_4_bits = lit_block_type | (sf << 2); // bits 0..3 of byte 0.

    let mut out = Vec::with_capacity(header_bytes + comp_size);
    match (sf, header_bytes) {
        (0b00, 3) | (0b01, 3) => {
            // 24-bit field: [LHD low 4 = type+sf][regen 10][comp 10] = 24 bits.
            // Layout (decoder formula):
            //   byte0 = lhd_low_4 | ((regen & 0xF) << 4)
            //   byte1 = (regen >> 4) | ((comp & 0x3) << 6)
            //   byte2 = (comp >> 2)
            let b0 = lhd_low_4_bits | (((regen & 0xF) as u8) << 4);
            let b1 = ((regen >> 4) as u8 & 0x3F) | (((comp_size & 0x3) as u8) << 6);
            let b2 = (comp_size >> 2) as u8;
            out.push(b0);
            out.push(b1);
            out.push(b2);
        }
        (0b10, 4) => {
            // 32-bit field: [LHD low 4][regen 14][comp 14].
            //   byte0 = lhd_low_4 | ((regen & 0xF) << 4)
            //   byte1 = (regen >> 4) & 0xFF
            //   byte2 = ((regen >> 12) & 0x3) | ((comp & 0x3F) << 2)
            //   byte3 = (comp >> 6)
            let b0 = lhd_low_4_bits | (((regen & 0xF) as u8) << 4);
            let b1 = ((regen >> 4) & 0xFF) as u8;
            let b2 = (((regen >> 12) & 0x3) as u8) | (((comp_size & 0x3F) as u8) << 2);
            let b3 = (comp_size >> 6) as u8;
            out.push(b0);
            out.push(b1);
            out.push(b2);
            out.push(b3);
        }
        (0b11, 5) => {
            // 40-bit field: [LHD low 4][regen 18][comp 18].
            // bits = byte0 | (byte1<<8) | (byte2<<16) | (byte3<<24) | (byte4<<32)
            // regen = (bits >> 4) & 0x3FFFF
            // comp  = (bits >> 22) & 0x3FFFF
            let bits: u64 = (lhd_low_4_bits as u64)
                | ((regen as u64 & 0x3_FFFF) << 4)
                | ((comp_size as u64 & 0x3_FFFF) << 22);
            out.push((bits & 0xFF) as u8);
            out.push(((bits >> 8) & 0xFF) as u8);
            out.push(((bits >> 16) & 0xFF) as u8);
            out.push(((bits >> 24) & 0xFF) as u8);
            out.push(((bits >> 32) & 0xFF) as u8);
        }
        _ => unreachable!(),
    }
    out.extend_from_slice(&payload);
    Some(out)
}

/// Map an LZ77 (distance, literal_length) into the encoded `offset_value`
/// the bitstream will carry, updating the per-block repeat-offset ring per
/// RFC 8478 §3.1.1.5 ("Repeat Offsets").
///
/// For a distance equal to one of the three most recent offsets, we emit a
/// code in 1..=3 — much shorter than `distance + 3` for any meaningful
/// distance. The special case `LL == 0` makes code 1 alias the second offset
/// (saving the slot when literal-less back-references repeat).
fn assign_offset(distance: u32, literal_length: u32, prev: &mut [u32; 3]) -> u32 {
    debug_assert!(distance > 0);
    if literal_length > 0 {
        // Normal case.
        if distance == prev[0] {
            // No history change.
            return 1;
        }
        if distance == prev[1] {
            prev.swap(0, 1);
            return 2;
        }
        if distance == prev[2] {
            // [prev[2], prev[0], prev[1]]
            let tmp = prev[2];
            prev[2] = prev[1];
            prev[1] = prev[0];
            prev[0] = tmp;
            return 3;
        }
    } else {
        // LL == 0: codes shift by one.
        //   code 1 → prev[1]
        //   code 2 → prev[2]
        //   code 3 → prev[0] - 1
        if distance == prev[1] {
            prev.swap(0, 1);
            return 1;
        }
        if distance == prev[2] {
            let tmp = prev[2];
            prev[2] = prev[1];
            prev[1] = prev[0];
            prev[0] = tmp;
            return 2;
        }
        if prev[0] > 1 && distance == prev[0] - 1 {
            prev[2] = prev[1];
            prev[1] = prev[0];
            prev[0] = distance;
            return 3;
        }
    }
    // No match → encode as a "literal" offset (distance + 3) and push it.
    prev[2] = prev[1];
    prev[1] = prev[0];
    prev[0] = distance;
    distance + 3
}

impl Default for Encoder {
    fn default() -> Self {
        Self::new()
    }
}

impl RawEncoder for Encoder {
    fn raw_encode(&mut self, input: &[u8], output: &mut [u8]) -> Result<RawProgress, Error> {
        let mut consumed = 0usize;
        let mut written = 0usize;

        loop {
            match self.state {
                State::Accepting => {
                    // Lazily emit the frame header.
                    if !self.header_written {
                        self.write_frame_header();
                        self.header_written = true;
                    }
                    // Accept input up to BLOCK_SIZE.
                    let space = BLOCK_SIZE - self.pending.len();
                    let take = core::cmp::min(space, input.len() - consumed);
                    if take > 0 {
                        self.pending
                            .extend_from_slice(&input[consumed..consumed + take]);
                        consumed += take;
                    }
                    if self.pending.len() == BLOCK_SIZE {
                        // Flush a non-final block.
                        self.flush_block(false);
                        self.state = State::Draining { last: false };
                    } else if !self.out_buf.is_empty() {
                        // We have header bytes pending; drain them.
                        self.state = State::Draining { last: false };
                    } else {
                        return Ok(RawProgress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                }
                State::Draining { last } => {
                    let drained = self.drain_into(output, &mut written);
                    if !drained {
                        return Ok(RawProgress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                    if last {
                        self.state = State::Done;
                    } else {
                        self.state = State::Accepting;
                    }
                }
                State::Done => {
                    return Ok(RawProgress {
                        consumed,
                        written,
                        done: false,
                    });
                }
            }
        }
    }

    fn raw_finish(&mut self, output: &mut [u8]) -> Result<RawProgress, Error> {
        let mut written = 0usize;

        loop {
            match self.state {
                State::Accepting => {
                    if !self.header_written {
                        self.write_frame_header();
                        self.header_written = true;
                    }
                    // Emit the final block (carries Last_Block = 1).
                    if self.pending.is_empty() {
                        // Empty last block (Raw_Block, size 0).
                        Self::push_block_header(&mut self.out_buf, 0, 0, true);
                    } else {
                        self.flush_block(true);
                    }
                    self.state = State::Draining { last: true };
                }
                State::Draining { last } => {
                    let drained = self.drain_into(output, &mut written);
                    if !drained {
                        return Ok(RawProgress {
                            consumed: 0,
                            written,
                            done: false,
                        });
                    }
                    if last {
                        self.state = State::Done;
                    } else {
                        self.state = State::Accepting;
                    }
                }
                State::Done => {
                    return Ok(RawProgress {
                        consumed: 0,
                        written,
                        done: true,
                    });
                }
            }
        }
    }

    fn raw_reset(&mut self) {
        self.state = State::Accepting;
        self.pending.clear();
        self.out_buf.clear();
        self.out_idx = 0;
        self.matcher = MatchFinder::new(BLOCK_SIZE);
        self.header_written = false;
        self.prev_offsets = [1, 4, 8];
        self.prev_huff_lengths = None;
    }
}
