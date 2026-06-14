//! bzip2 streaming encoder.
//!
//! The encoder buffers input up to the configured block size, then
//! produces an encoded block on `raw_finish` (or whenever the buffer
//! fills). The pipeline per block is:
//!
//! ```text
//! raw bytes → RLE-1 → BWT → MTF → RLE-2 → multi-table Huffman → bitstream
//! ```
//!
//! The output is staged into a `Vec<u8>` that we drain into the
//! caller's output buffer. We emit:
//! - The 4-byte stream header `"BZh<level>"` exactly once, on the first
//!   `raw_encode`/`raw_finish` call.
//! - One block payload per filled or finished block.
//! - The stream footer (end-of-stream magic + combined CRC + byte-
//!   align padding) once `raw_finish` runs.

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;
use crate::traits::{RawEncoder, RawProgress};

use super::bits::BitWriter;
use super::bwt::bwt_forward;
use super::crc::Crc32;
use super::huffman::{MAX_CODE_LEN, build_canonical_codes, build_canonical_lengths};
use super::mtf::mtf_forward_reduced;
use super::rle::{Rle1Encoder, rle1_forward, rle2_forward};

/// Tunables for the bzip2 encoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncoderConfig {
    /// Block size in 100 KB units, 1..=9. Default 6 (matches reference
    /// bzip2). The post-RLE-1 buffer is capped at
    /// `level * 100_000 - 19` bytes.
    pub level: u8,
}

impl Default for EncoderConfig {
    fn default() -> Self {
        Self { level: 6 }
    }
}

/// Bzip2 stream/block magic numbers as 48-bit fields (high 48 bits of
/// the long-magic constants).
const BLOCK_MAGIC: u64 = 0x3141_5926_5359; // "1AY&SY"
const STREAM_END_MAGIC: u64 = 0x1772_4538_5090; // "sqrt(pi)"

/// Maximum number of Huffman selector groups per block. bzip2 splits
/// the symbol stream into 50-symbol groups and assigns each group one
/// of the (2..=6) Huffman tables. We cap the per-block selector count
/// at this value to bound encoder memory.
const MAX_SELECTORS: usize = 18002; // matches bzip2 reference

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Accepting raw input into `pending`. Header may or may not be
    /// flushed yet (header bytes live in `out` if not).
    Accepting,
    /// All pending input has been consumed, encoded blocks (if any)
    /// drained, and the stream footer written. `out` may still hold
    /// bytes to drain to the caller.
    Flushed,
    /// Stream footer fully drained.
    Done,
}

pub struct Encoder {
    config: EncoderConfig,
    /// Per-block raw input buffer. Retained verbatim because the block
    /// CRC is computed over the raw bytes; `encode_block` re-runs RLE-1
    /// over it. Block boundaries, however, are governed by the *post*-
    /// RLE-1 size tracked in `rle1` (matching reference bzip2's
    /// `nblock`-based blocking), not by `pending.len()`.
    pending: Vec<u8>,
    /// Streaming RLE-1 size tracker mirroring `pending`. Used only to
    /// decide when the current block has reached the post-RLE-1 cap.
    rle1: Rle1Encoder,
    /// Encoded bytes waiting to be returned to the caller.
    out: Vec<u8>,
    /// Index into `out` of the next byte to deliver.
    out_idx: usize,
    /// Whether the stream header has been queued into `out`.
    header_written: bool,
    /// Running combined CRC across all blocks so far.
    combined_crc: u32,
    /// In-flight bit accumulator used to splice the per-block bit
    /// streams into one contiguous bitstream. `None` before the
    /// header is written.
    bw: Option<BitWriter>,
    phase: Phase,
}

impl Encoder {
    pub fn new() -> Self {
        Self::with_config(EncoderConfig::default())
    }

    pub fn with_config(mut config: EncoderConfig) -> Self {
        // Clamp the level to 1..=9 (reference bzip2 behaviour).
        config.level = config.level.clamp(1, 9);
        Self {
            config,
            pending: Vec::new(),
            rle1: Rle1Encoder::new(),
            out: Vec::new(),
            out_idx: 0,
            header_written: false,
            combined_crc: 0,
            bw: None,
            phase: Phase::Accepting,
        }
    }

    /// Maximum number of post-RLE-1 bytes per block. We follow the
    /// reference upper bound `level * 100_000 - 19`; the
    /// `-19` cushions the worst-case expansion of pathological inputs
    /// passing through the post-MTF / Huffman layers.
    fn block_input_cap(&self) -> usize {
        (self.config.level as usize) * 100_000 - 19
    }

    /// Lazy-init the stream header bit accumulator.
    fn ensure_header(&mut self) {
        if self.header_written {
            return;
        }
        // "BZh" + ASCII level digit.
        self.out.push(b'B');
        self.out.push(b'Z');
        self.out.push(b'h');
        self.out.push(b'0' + self.config.level);
        self.bw = Some(BitWriter::new());
        self.header_written = true;
    }

    /// Encode the bytes currently buffered in `pending` into a single
    /// bzip2 block, appending its bit-stream to `self.bw`. Resets
    /// `pending` to empty afterwards.
    fn encode_block(&mut self) {
        let block: Vec<u8> = core::mem::take(&mut self.pending);
        // Reset the RLE-1 size tracker for the next block.
        self.rle1 = Rle1Encoder::new();
        // Sanity: a "no input" block is not produced — we only call
        // encode_block when pending is non-empty.
        debug_assert!(!block.is_empty());

        // Step 1: per-block CRC of the **raw** bytes (CRC-32/MPEG-2).
        let mut crc = Crc32::new();
        crc.update(&block);
        let block_crc = crc.value();

        // Update the running combined CRC: rotate-left then XOR.
        self.combined_crc = self.combined_crc.rotate_left(1) ^ block_crc;

        // Step 2: RLE-1.
        let rle1 = rle1_forward(&block);

        // Step 3: BWT.
        let (l_column, origin) = bwt_forward(&rle1);

        // Step 4: reduced alphabet of the bytes that appear in L. The
        // 16-byte stripe map encoding (in the header) needs this.
        let mut present = [false; 256];
        for &b in &l_column {
            present[b as usize] = true;
        }
        let alphabet: Vec<u8> = (0..=255u8).filter(|&b| present[b as usize]).collect();
        let num_used = alphabet.len();
        // bzip2 forbids the degenerate empty alphabet case; rle1 of a
        // non-empty input is non-empty, so num_used ≥ 1.

        // Step 5: MTF over the reduced alphabet.
        let mtf = mtf_forward_reduced(&l_column, &alphabet);
        // Free the BWT output before RLE-2 — it can be large at the
        // 900 KB block size.
        drop(l_column);

        // Step 6: RLE-2. The output uses symbols 0..=num_used + 1
        // (0/1 = RUNA/RUNB, 2..=num_used = MTF idx 1..=num_used-1,
        // num_used + 1 = EOB). We append the EOB after the last RLE-2
        // symbol so the decoder has an unambiguous stop signal.
        let mut symbols = rle2_forward(&mtf, num_used);
        let eob_symbol: u16 = (num_used as u16) + 1;
        symbols.push(eob_symbol);
        drop(mtf);

        let alpha_size = num_used + 2; // includes EOB
        // Step 7: choose number of Huffman tables. bzip2 chooses
        // 2..=6 based on the per-block symbol-count buckets.
        let num_tables = pick_num_tables(symbols.len());

        // Step 8: build the multi-table Huffman assignment exactly the
        // way reference bzip2's `sendMTFValues` does: initialise the
        // tables by partitioning the cumulative-frequency space, then
        // run a fixed number of refinement passes that (a) assign each
        // 50-symbol group to whichever table codes it cheapest and
        // (b) rebuild each table from the symbols of the groups
        // assigned to it. This is where the compression edge over a
        // single shared table comes from.
        let num_selectors_total = symbols.len().div_ceil(50);
        debug_assert!(num_selectors_total >= 1);
        debug_assert!(num_selectors_total <= MAX_SELECTORS);

        let (tables, selectors) =
            optimize_tables(&symbols, alpha_size, num_tables, num_selectors_total);

        // Build canonical codes for each table.
        let codes: Vec<Vec<u32>> = tables
            .iter()
            .map(|lens| build_canonical_codes(lens))
            .collect();

        // ─── Now write the block to self.bw ──────────────────────
        let bw = self.bw.as_mut().expect("header must be written first");

        // Block magic (48 bits).
        bw.write_bits_48(BLOCK_MAGIC);
        // Per-block CRC (32 bits, MSB-first).
        bw.write_bits(32, block_crc);
        // Randomized flag (1 bit) — always 0 for modern bzip2.
        bw.write_bit(0);
        // BWT origin (24 bits).
        bw.write_bits(24, origin);

        // Symbol map: 16 bits saying which 16-byte stripes have any
        // present symbol, then for each used stripe a 16-bit mask.
        let mut stripe_used = [false; 16];
        for &b in &alphabet {
            stripe_used[(b >> 4) as usize] = true;
        }
        let mut stripe_top: u16 = 0;
        for (i, &u) in stripe_used.iter().enumerate() {
            if u {
                stripe_top |= 1 << (15 - i);
            }
        }
        bw.write_bits(16, stripe_top as u32);
        for (stripe, &used) in stripe_used.iter().enumerate() {
            if !used {
                continue;
            }
            let mut mask: u16 = 0;
            for byte in 0..16 {
                let candidate = (stripe << 4) | byte;
                if present[candidate] {
                    mask |= 1 << (15 - byte);
                }
            }
            bw.write_bits(16, mask as u32);
        }

        // Number of Huffman tables (3 bits, 2..=6).
        bw.write_bits(3, num_tables as u32);
        // Number of selectors (15 bits, ≥1).
        bw.write_bits(15, num_selectors_total as u32);

        // MTF-encoded selector list. Each selector is encoded under a
        // local MTF over 0..num_tables: unary prefix of N zeros to
        // pick the value at MTF position N, followed by a 0 stop bit.
        // For num_tables=2 and all selectors=0, the MTF position is
        // always 0 → each selector is just a single "0" bit.
        // We implement the general MTF-then-unary scheme anyway.
        let mut mtf_list: Vec<u8> = (0..num_tables as u8).collect();
        for &sel in &selectors {
            // Find sel's position in mtf_list.
            let mut pos = 0;
            while mtf_list[pos] != sel {
                pos += 1;
            }
            // Emit `pos` 1-bits then a 0-bit (unary stop-coded).
            for _ in 0..pos {
                bw.write_bit(1);
            }
            bw.write_bit(0);
            // Move sel to the front of mtf_list.
            if pos > 0 {
                let v = mtf_list.remove(pos);
                mtf_list.insert(0, v);
            }
        }

        // Per-table code lengths: 5-bit start length + delta-coded
        // changes (10 = +1, 11 = -1, stop on 0).
        for table in &tables {
            let mut cur = table[0] as i32;
            bw.write_bits(5, cur as u32);
            for &l in table.iter() {
                let target = l as i32;
                while cur != target {
                    if target > cur {
                        // 10 = +1
                        bw.write_bit(1);
                        bw.write_bit(0);
                        cur += 1;
                    } else {
                        // 11 = -1
                        bw.write_bit(1);
                        bw.write_bit(1);
                        cur -= 1;
                    }
                }
                // 0 = "stop, this symbol's length is cur".
                bw.write_bit(0);
            }
        }

        // The post-MTF symbol stream, group by group, using the
        // selector for each group's table.
        let mut group_idx = 0usize;
        let mut i = 0usize;
        while i < symbols.len() {
            let end = (i + 50).min(symbols.len());
            let sel = selectors[group_idx] as usize;
            let lens = &tables[sel];
            let cds = &codes[sel];
            for &s in &symbols[i..end] {
                let len = lens[s as usize] as u32;
                let code = cds[s as usize];
                bw.write_bits(len, code);
            }
            group_idx += 1;
            i = end;
        }
        // tables, codes, selectors no longer needed; let the borrow
        // end before we move on to the next block.
        drop(tables);
        drop(codes);
        drop(selectors);
    }

    /// Drain currently-pending bytes from `self.out` into `output`.
    fn drain_out(&mut self, output: &mut [u8], written: &mut usize) {
        let avail = self.out.len() - self.out_idx;
        let space = output.len() - *written;
        let n = avail.min(space);
        if n > 0 {
            output[*written..*written + n]
                .copy_from_slice(&self.out[self.out_idx..self.out_idx + n]);
            self.out_idx += n;
            *written += n;
        }
        if self.out_idx == self.out.len() {
            self.out.clear();
            self.out_idx = 0;
        }
    }

    /// Flush the in-progress bit writer's whole-byte content into
    /// `self.out` (the writer keeps any partial byte still buffered).
    fn flush_full_bytes(&mut self) {
        if let Some(ref mut bw) = self.bw {
            // The BitWriter's API exposes `into_bytes` (consuming) and
            // `align_to_byte` — neither is "give me the complete bytes
            // and keep the partial byte". We work around this by
            // taking the writer out, splitting the assembled bytes,
            // and reinstalling a fresh writer with the partial bits
            // restored.
            //
            // Practical detail: between blocks bzip2 streams may be at
            // an unaligned boundary, so we MUST preserve the partial
            // byte across calls. We achieve this by always emitting
            // bits eagerly into `bw` (BitWriter pushes a whole byte to
            // its internal Vec as soon as 8 bits accumulate) and
            // periodically extracting those whole bytes into `out`.
            let taken = core::mem::replace(bw, BitWriter::new());
            // Split the internal vector from the trailing partial byte
            // by going through the writer's internals — which we
            // expose via a dedicated helper.
            let (bytes, cur, nbits) = bw_internals(taken);
            self.out.extend_from_slice(&bytes);
            *bw = bw_rehydrate(cur, nbits);
        }
    }

    /// Write the stream footer (end-of-stream magic + combined CRC + byte align).
    fn write_footer(&mut self) {
        let bw = self.bw.as_mut().expect("header must be written first");
        bw.write_bits_48(STREAM_END_MAGIC);
        bw.write_bits(32, self.combined_crc);
        bw.align_to_byte();
        let taken = core::mem::replace(bw, BitWriter::new());
        let (bytes, _, _) = bw_internals(taken);
        self.out.extend_from_slice(&bytes);
        self.bw = None;
    }
}

// ─── BitWriter internals access helpers ──────────────────────────────────
//
// These let us peek into the writer to extract its complete-byte buffer
// without losing the partial-byte state. We keep them tightly scoped to
// this module so the BitWriter remains a regular type elsewhere.

fn bw_internals(bw: BitWriter) -> (Vec<u8>, u8, u8) {
    bw.internals_for_encoder()
}

fn bw_rehydrate(cur: u8, nbits: u8) -> BitWriter {
    BitWriter::rehydrate(cur, nbits)
}

// ─── Huffman table count chooser ────────────────────────────────────────

/// Pick the number of Huffman tables (2..=6) for a block with
/// `n_symbols` post-RLE-2 symbols (including the EOB marker).
///
/// Reference bzip2 uses: 2 if n<200, 3 if n<600, 4 if n<1200, 5 if
/// n<2400, else 6. We mirror that.
fn pick_num_tables(n_symbols: usize) -> usize {
    if n_symbols < 200 {
        2
    } else if n_symbols < 600 {
        3
    } else if n_symbols < 1200 {
        4
    } else if n_symbols < 2400 {
        5
    } else {
        6
    }
}

/// Number of refinement passes over the table/selector assignment.
/// Reference bzip2 uses `BZ_N_ITERS = 4`.
const HUFF_N_ITERS: usize = 4;

/// Symbol-group size used when assigning selectors. Reference bzip2
/// uses `BZ_G_SIZE = 50`.
const HUFF_GROUP_SIZE: usize = 50;

/// A code length placeholder used during table initialisation/cost
/// scoring. Mirrors reference bzip2's `BZ_LESSER_ICOST` (0) and
/// `BZ_GREATER_ICOST` (15).
const ICOST_LESSER: u8 = 0;
const ICOST_GREATER: u8 = 15;

/// Build `num_tables` Huffman code-length tables and a per-group
/// selector list using reference bzip2's `sendMTFValues` strategy.
///
/// Returns `(tables, selectors)` where `tables[t]` is the per-symbol
/// code-length array (length `alpha_size`) for table `t`, and
/// `selectors[g]` is the table id (0..num_tables) chosen for the g-th
/// 50-symbol group.
fn optimize_tables(
    symbols: &[u16],
    alpha_size: usize,
    num_tables: usize,
    num_groups: usize,
) -> (Vec<Vec<u8>>, Vec<u8>) {
    // Global symbol frequencies across the whole block.
    let mut global_freq = vec![0u32; alpha_size];
    for &s in symbols {
        global_freq[s as usize] += 1;
    }

    // ── Initial table construction ────────────────────────────────
    //
    // Faithful port of reference bzip2's `sendMTFValues` initialiser:
    // partition the alphabet into `num_tables` contiguous bands of
    // (roughly) equal total frequency, walking symbols low→high. Band
    // `nPart-1` (i.e. tables fill from the highest id down to 0) covers
    // the next slice of low symbols; in-band symbols get the cheap
    // placeholder length, the rest the expensive one. There is an
    // odd-iteration back-off that nudges the band boundary, matching
    // the reference exactly so our initial assignment — and therefore
    // the refinement that follows — tracks bzip2's.
    let mut tables: Vec<Vec<u8>> = (0..num_tables)
        .map(|_| vec![ICOST_GREATER; alpha_size])
        .collect();
    {
        let n_mtf = symbols.len() as i64;
        let mut n_part = num_tables as i64;
        let mut rem_f = n_mtf;
        let mut gs = 0i64;
        while n_part > 0 {
            let t_freq = rem_f / n_part;
            let mut ge = gs - 1;
            let mut a_freq = 0i64;
            while a_freq < t_freq && ge < alpha_size as i64 - 1 {
                ge += 1;
                a_freq += global_freq[ge as usize] as i64;
            }
            // Odd-iteration back-off: if this isn't the first part, the
            // boundary lands above `gs`, the part index parity is odd,
            // and backing off keeps `a_freq` closer to the target.
            if ge > gs
                && n_part != num_tables as i64
                && n_part != 1
                && ((num_tables as i64 - n_part) % 2 == 1)
            {
                a_freq -= global_freq[ge as usize] as i64;
                ge -= 1;
            }

            let lens = &mut tables[(n_part - 1) as usize];
            for (v, slot) in lens.iter_mut().enumerate() {
                let vi = v as i64;
                if vi >= gs && vi <= ge {
                    *slot = ICOST_LESSER;
                } else {
                    *slot = ICOST_GREATER;
                }
            }

            n_part -= 1;
            gs = ge + 1;
            rem_f -= a_freq;
        }
    }

    let mut selectors = vec![0u8; num_groups];

    // ── Refinement passes ─────────────────────────────────────────
    for _iter in 0..HUFF_N_ITERS {
        // Per-table accumulated frequencies for this pass.
        let mut table_freq: Vec<Vec<u32>> = vec![vec![0u32; alpha_size]; num_tables];

        // For each group: score it under every table, pick the cheapest,
        // record the selector, and fold the group's symbols into the
        // winning table's frequency accumulator.
        let mut g = 0usize;
        let mut group_idx = 0usize;
        while g < symbols.len() {
            let end = (g + HUFF_GROUP_SIZE).min(symbols.len());
            let group = &symbols[g..end];

            // Cost of coding this group under each table.
            let mut best_table = 0usize;
            let mut best_cost = u64::MAX;
            for (t, lens) in tables.iter().enumerate() {
                let mut cost = 0u64;
                for &s in group {
                    cost += lens[s as usize] as u64;
                }
                if cost < best_cost {
                    best_cost = cost;
                    best_table = t;
                }
            }

            selectors[group_idx] = best_table as u8;
            let acc = &mut table_freq[best_table];
            for &s in group {
                acc[s as usize] += 1;
            }

            group_idx += 1;
            g = end;
        }

        // Rebuild each table from the frequencies of the groups assigned
        // to it. A table with no assigned groups keeps coverage via the
        // `+1` floor inside `build_canonical_lengths`.
        for (t, freq) in table_freq.iter().enumerate() {
            tables[t] = build_canonical_lengths(freq, MAX_CODE_LEN);
        }
    }

    (tables, selectors)
}

impl Default for Encoder {
    fn default() -> Self {
        Self::new()
    }
}

impl RawEncoder for Encoder {
    fn raw_encode(&mut self, input: &[u8], output: &mut [u8]) -> Result<RawProgress, Error> {
        if matches!(self.phase, Phase::Done | Phase::Flushed) {
            return Ok(RawProgress {
                consumed: 0,
                written: 0,
                done: false,
            });
        }
        self.ensure_header();

        let cap = self.block_input_cap();
        let mut consumed = 0usize;
        let mut written = 0usize;

        // First drain any already-encoded bytes that didn't fit on the
        // previous call.
        self.drain_out(output, &mut written);
        if written == output.len() && !self.out.is_empty() {
            return Ok(RawProgress {
                consumed,
                written,
                done: false,
            });
        }

        // Now accept input, filling each block up to the per-block
        // *post-RLE-1* cap (reference bzip2 sizes blocks by `nblock`,
        // the RLE-1 output length). We feed bytes through both the raw
        // buffer (kept for the CRC and the in-block RLE-1 re-run) and
        // the streaming size tracker, cutting a block the moment the
        // tracked RLE-1 length reaches the cap. When a block fills we
        // encode it, drain to output, and continue.
        while consumed < input.len() {
            let b = input[consumed];
            self.pending.push(b);
            self.rle1.push(b);
            consumed += 1;

            if self.rle1.encoded_len() >= cap {
                self.encode_block();
                self.flush_full_bytes();
                self.drain_out(output, &mut written);
                if written == output.len() && !self.out.is_empty() {
                    // Pending output didn't fit — caller must drain.
                    return Ok(RawProgress {
                        consumed,
                        written,
                        done: false,
                    });
                }
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
        self.ensure_header();

        // First: drain any already-encoded bytes from prior calls.
        self.drain_out(output, &mut written);
        if !self.out.is_empty() {
            return Ok(RawProgress {
                consumed: 0,
                written,
                done: false,
            });
        }

        // Encode any pending bytes into a final block.
        if matches!(self.phase, Phase::Accepting) {
            if !self.pending.is_empty() {
                self.encode_block();
                self.flush_full_bytes();
            }
            self.write_footer();
            self.phase = Phase::Flushed;
            self.drain_out(output, &mut written);
            if !self.out.is_empty() {
                return Ok(RawProgress {
                    consumed: 0,
                    written,
                    done: false,
                });
            }
        }

        // Anything left to drain?
        if matches!(self.phase, Phase::Flushed) {
            self.drain_out(output, &mut written);
            if self.out.is_empty() {
                self.phase = Phase::Done;
            }
        }

        Ok(RawProgress {
            consumed: 0,
            written,
            done: matches!(self.phase, Phase::Done),
        })
    }

    fn raw_reset(&mut self) {
        self.pending.clear();
        self.rle1 = Rle1Encoder::new();
        self.out.clear();
        self.out_idx = 0;
        self.header_written = false;
        self.combined_crc = 0;
        self.bw = None;
        self.phase = Phase::Accepting;
    }
}
