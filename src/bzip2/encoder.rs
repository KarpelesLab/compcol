//! bzip2 streaming encoder.
//!
//! The encoder RLE-1-encodes input into a block as it arrives and
//! produces an encoded block whenever the block fills, on `flush`, and
//! on `finish`. The pipeline per block is:
//!
//! ```text
//! raw bytes → RLE-1 → BWT → MTF → RLE-2 → multi-table Huffman → bitstream
//! ```
//!
//! Block boundaries, and everything else that decides the output bytes,
//! follow libbzip2 (`bzlib.c` / `compress.c`): fed the same input through
//! `encode` and then `finish`, the stream is byte-identical to what
//! `BZ2_bzCompress` produces with `BZ_RUN` then `BZ_FINISH` (the `bzip2`
//! tool, `BZ2_bzWrite`) at work factor 30.
//!
//! The output is staged into a `Vec<u8>` that we drain into the
//! caller's output buffer. We emit:
//! - The 4-byte stream header `"BZh<level>"` exactly once, on the first
//!   `raw_encode`/`raw_finish` call.
//! - One block payload per filled, flushed or finished block.
//! - The stream footer (end-of-stream magic + combined CRC + byte-
//!   align padding) once `raw_finish` runs.

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;
use crate::traits::{Flush, RawEncoder, RawProgress};

use super::bits::BitWriter;
use super::bwt::bwt_forward;
use super::crc::Crc32;
use super::huffman::{MAX_CODE_LEN, build_canonical_codes, build_canonical_lengths};
use super::mtf::mtf_forward_reduced;
use super::rle::rle2_forward;

/// Tunables for the bzip2 encoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncoderConfig {
    /// Block size in 100 KB units, 1..=9. Default 6 (matches reference
    /// bzip2). A block is closed once its post-RLE-1 size reaches
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
    /// Accepting raw input into `block`. Header may or may not be
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
    /// The current block after RLE-1 (libbzip2's `block[0..nblock]`).
    /// Runs enter it only once they end, so it never holds the run in
    /// progress.
    block: Vec<u8>,
    /// CRC of the raw bytes behind `block` (libbzip2's `blockCRC`).
    block_crc: Crc32,
    /// The run in progress: `in_len` copies of `in_ch`, 0..=255 of them
    /// (libbzip2's `state_in_ch` / `state_in_len`). It is not part of
    /// any block yet: when a block fills, the run carries over and
    /// starts the next one, exactly as in libbzip2.
    in_ch: u8,
    in_len: u32,
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
            block: Vec::new(),
            block_crc: Crc32::new(),
            in_ch: 0,
            in_len: 0,
            out: Vec::new(),
            out_idx: 0,
            header_written: false,
            combined_crc: 0,
            bw: None,
            phase: Phase::Accepting,
        }
    }

    /// Post-RLE-1 size at which a block is closed (libbzip2's
    /// `nblockMAX`). A run of 4+ enters the block as 5 bytes at once, so
    /// a block can end up to 4 bytes past this; the `-19` keeps that,
    /// and the run `finish` adds, within `level * 100_000`.
    fn block_input_cap(&self) -> usize {
        (self.config.level as usize) * 100_000 - 19
    }

    /// Move the finished run into the block (libbzip2's
    /// `add_pair_to_block`): 1..=3 copies verbatim, 4..=255 as four
    /// copies and a count of the rest.
    fn add_pair_to_block(&mut self) {
        let ch = self.in_ch;
        let len = self.in_len as usize;
        if len == 1 {
            self.block_crc.update(&[ch]);
            self.block.push(ch);
            return;
        }
        self.block_crc.update(&[ch; 255][..len]);
        if len < 4 {
            self.block.extend_from_slice(&[ch; 3][..len]);
        } else {
            self.block
                .extend_from_slice(&[ch, ch, ch, ch, (len - 4) as u8]);
        }
    }

    /// Feed one raw byte (libbzip2's `ADD_CHAR_TO_BLOCK`).
    #[inline]
    fn add_char(&mut self, b: u8) {
        if b == self.in_ch && self.in_len != 0 && self.in_len < 255 {
            self.in_len += 1;
        } else {
            if self.in_len != 0 {
                self.add_pair_to_block();
            }
            self.in_ch = b;
            self.in_len = 1;
        }
    }

    /// End the run in progress so the block can be closed (libbzip2's
    /// `flush_RL`), as `flush` and `finish` do.
    fn flush_run(&mut self) {
        if self.in_len != 0 {
            self.add_pair_to_block();
            self.in_len = 0;
        }
    }

    /// Lazy-init the stream header bit accumulator.
    fn ensure_header(&mut self) {
        if self.header_written {
            return;
        }
        // "BZh" + ASCII level digit, through the bit writer so a flush
        // right after it holds the last byte back as libbzip2 does.
        let mut bw = BitWriter::new();
        for b in [b'B', b'Z', b'h', b'0' + self.config.level] {
            bw.write_bits(8, b as u32);
        }
        self.bw = Some(bw);
        self.header_written = true;
    }

    /// Encode `self.block` (already RLE-1'd) as one bzip2 block,
    /// appending its bit-stream to `self.bw`, and start an empty block.
    fn encode_block(&mut self) {
        let rle1: Vec<u8> = core::mem::take(&mut self.block);
        // Sanity: a "no input" block is not produced — we only call
        // encode_block when the block is non-empty.
        debug_assert!(!rle1.is_empty());

        // Step 1: per-block CRC of the **raw** bytes (CRC-32/MPEG-2),
        // accumulated as runs entered the block.
        let block_crc = self.block_crc.value();
        self.block_crc = Crc32::new();

        // Update the running combined CRC: rotate-left then XOR.
        self.combined_crc = self.combined_crc.rotate_left(1) ^ block_crc;

        // Steps 2 and 3: RLE-1 already happened on the way in; BWT.
        let (l_column, origin) = bwt_forward(&rle1);
        // Keep the allocation for the next block.
        self.block = rle1;
        self.block.clear();

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

    /// Move the encoded bytes libbzip2 would have output by now from
    /// the bit writer into `self.out`; see [`BitWriter::take_settled`].
    fn flush_full_bytes(&mut self) {
        if let Some(ref mut bw) = self.bw {
            bw.take_settled(&mut self.out);
        }
    }

    /// Write the stream footer (end-of-stream magic + combined CRC + byte align).
    fn write_footer(&mut self) {
        let bw = self.bw.as_mut().expect("header must be written first");
        bw.write_bits_48(STREAM_END_MAGIC);
        bw.write_bits(32, self.combined_crc);
        bw.align_to_byte();
        bw.take_all(&mut self.out);
        self.bw = None;
    }
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
        // The tables' code lengths transposed, six per symbol, so one
        // pass over a group scores it under every table at once (what
        // libbzip2 does with its packed `len_pack`). Unused table slots
        // stay 0 and are never chosen.
        let mut lens_by_sym = vec![[0u16; 6]; alpha_size];
        for (t, lens) in tables.iter().enumerate() {
            for (row, &l) in lens_by_sym.iter_mut().zip(lens) {
                row[t] = l as u16;
            }
        }

        // For each group: score it under every table, pick the cheapest,
        // record the selector, and fold the group's symbols into the
        // winning table's frequency accumulator.
        let mut g = 0usize;
        let mut group_idx = 0usize;
        while g < symbols.len() {
            let end = (g + HUFF_GROUP_SIZE).min(symbols.len());
            let group = &symbols[g..end];

            // Cost of coding this group under each table (at most
            // 50 * 20 bits, so u16 cannot overflow).
            let mut cost = [0u16; 6];
            for &s in group {
                let row = &lens_by_sym[s as usize];
                for t in 0..6 {
                    cost[t] += row[t];
                }
            }
            // The first cheapest table wins ties, as in libbzip2.
            let mut best_table = 0usize;
            let mut best_cost = u16::MAX;
            for (t, &c) in cost[..num_tables].iter().enumerate() {
                if c < best_cost {
                    best_cost = c;
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

        // Now accept input. As in libbzip2, the block is measured
        // after RLE-1 and without the run in progress, and it is closed
        // as soon as it reaches the cap; the run in progress then
        // starts the next block. When a block fills we encode it, drain
        // to output, and continue.
        while consumed < input.len() {
            self.add_char(input[consumed]);
            consumed += 1;

            if self.block.len() >= cap {
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
            self.flush_run();
            if !self.block.is_empty() {
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

    fn raw_flush(&mut self, output: &mut [u8], _mode: Flush) -> Result<RawProgress, Error> {
        let mut written = 0usize;
        if matches!(self.phase, Phase::Accepting) {
            self.ensure_header();
            // libbzip2's BZ_FLUSH: end the run, close the block (blocks
            // are independent, so Sync and Full are the same thing) and
            // hand out every whole byte. A bzip2 stream has no padding
            // or sync marker, so the block's last 0..=7 bits stay in the
            // bit writer until the next block or the footer follows
            // them, exactly as with libbzip2.
            self.flush_run();
            if !self.block.is_empty() {
                self.encode_block();
            }
            self.flush_full_bytes();
        }
        self.drain_out(output, &mut written);
        Ok(RawProgress {
            consumed: 0,
            written,
            done: self.out.is_empty(),
        })
    }

    fn raw_reset(&mut self) {
        self.block.clear();
        self.block_crc = Crc32::new();
        self.in_len = 0;
        self.out.clear();
        self.out_idx = 0;
        self.header_written = false;
        self.combined_crc = 0;
        self.bw = None;
        self.phase = Phase::Accepting;
    }
}
