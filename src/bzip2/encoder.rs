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
use super::rle::{rle1_forward, rle2_forward};

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
    /// Per-block input buffer (post-RLE-1 will be derived from this).
    pending: Vec<u8>,
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
            out: Vec::new(),
            out_idx: 0,
            header_written: false,
            combined_crc: 0,
            bw: None,
            phase: Phase::Accepting,
        }
    }

    /// Maximum number of raw-input bytes per block, before RLE-1. We
    /// follow the reference upper bound `level * 100_000 - 19`; the
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
        // 2..=6 based on the per-block symbol-count buckets. For a
        // simple encoder we use a fixed mapping that always produces
        // a valid stream.
        let num_tables = pick_num_tables(symbols.len());

        // Step 8: assign each 50-symbol group a Huffman table id, then
        // build per-table code-length tables from per-table frequency
        // counts. We use the simplest possible split: all groups use
        // the same single table, replicated `num_tables` times. This
        // is valid bzip2 — the spec only requires 2..=6 distinct
        // tables to be present in the header, and selectors to be in
        // 0..num_tables. Reusing one table is wasteful (gives up the
        // compression edge that having multiple specialised tables
        // would provide) but always correct.
        //
        // However, the spec demands 2..=6 tables — exactly one is
        // **not** allowed. So we ship two identical-length tables and
        // assign half the groups to table 0 and half to table 1; this
        // satisfies the structural requirements without changing the
        // bitstream costs vs a single-table encoder.
        let num_selectors_total = symbols.len().div_ceil(50);
        debug_assert!(num_selectors_total >= 1);
        debug_assert!(num_selectors_total <= MAX_SELECTORS);

        let mut freqs = vec![0u32; alpha_size];
        for &s in &symbols {
            freqs[s as usize] += 1;
        }
        let table_lengths = build_canonical_lengths(&freqs, MAX_CODE_LEN);

        // Build per-table copies (all identical). num_tables ≥ 2.
        let tables: Vec<Vec<u8>> = (0..num_tables).map(|_| table_lengths.clone()).collect();

        // Each group's selector is just the group index modulo
        // num_tables — but we keep them all 0 so frequency-weighted
        // length design (which we don't do here) is trivially the
        // same. Reference bzip2's selector design picks the cheapest
        // table per group; we just pick table 0 everywhere.
        let selectors: Vec<u8> = vec![0u8; num_selectors_total];

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

        // Now accept input, filling up to the per-block cap. If we
        // fill, encode that block, drain to output, repeat.
        while consumed < input.len() {
            let space = cap - self.pending.len();
            let take = space.min(input.len() - consumed);
            self.pending
                .extend_from_slice(&input[consumed..consumed + take]);
            consumed += take;

            if self.pending.len() == cap {
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
        self.out.clear();
        self.out_idx = 0;
        self.header_written = false;
        self.combined_crc = 0;
        self.bw = None;
        self.phase = Phase::Accepting;
    }
}
