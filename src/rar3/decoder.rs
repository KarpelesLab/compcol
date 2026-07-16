//! RAR 3.x LZ77+Huffman decoder.
//!
//! ## Calling convention
//!
//! RAR3 streams are not self-delimiting: the archive container records the
//! uncompressed size separately, and the compressed payload itself has no
//! end-of-stream marker that the decoder can rely on without overrunning the
//! requested size. Callers therefore construct the decoder with
//! [`Decoder::with_unpack_size`] and feed the raw compressed bytes that
//! immediately follow the RAR file header — see the module-level
//! `//!` block for details. [`Decoder::new`] is provided as a default that
//! decodes up to `u64::MAX` bytes (suitable for tests where the caller
//! independently tracks output length).
//!
//! ## What's supported
//!
//! - Non-PPMd blocks (the "LZ77 + Huffman" path used by the vast majority
//!   of RAR3 archives).
//! - All five Huffman codes (precode + main + offset + low-offset + length).
//! - The 4-deep rolling-offset buffer, short offsets (codes 263..=270), and
//!   the full match-length / offset machinery.
//! - The keep-table flag — successive blocks may reuse the previous code
//!   lengths.
//! - **In-band standard filters** (main symbol 257): Delta and x86
//!   E8/E8E9 declarations are recognized by their bytecode fingerprint and
//!   run natively over their declared output windows — see
//!   `super::filters` for the recognition scheme and provenance.
//! - The standalone E8/E9 post-pass filter when enabled via
//!   [`Decoder::with_e8_filter`].
//!
//! ## What's refused
//!
//! - **PPMd-II blocks** (the bit-0 flag in the block header). PPMd-II is a
//!   ~1500-line context-mixed arithmetic coder; implementing it faithfully
//!   is out of scope for this build. Streams containing a PPMd block fail
//!   with `Error::Unsupported`.
//! - **Filter declarations carrying any other VM program** (custom
//!   bytecode, or legacy standard programs no current archiver emits —
//!   Itanium, RGB, the audio predictor). These fail with
//!   `Error::Unsupported` rather than interpreting RarVM bytecode.
//! - **Dictionary sizes** other than the default 4 MiB. Streams compressed
//!   with smaller dictionaries decode correctly with the larger window —
//!   the larger window doesn't change semantics.

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;
use crate::traits::{RawDecoder, RawProgress};

use super::bits::BitReader;
use super::filters::{
    PendingFilter, StdProgram, apply_e8_filter, apply_pending, recognize_program,
};
use super::huffman::Huffman;
use super::tables::{
    DICT_DEFAULT_SIZE, HUFF_TABLE_SIZE, LENGTH_BASE, LENGTH_EXTRA_BITS, LENGTH_SIZE,
    LOW_OFFSET_SIZE, MAIN_SIZE, OFFSET_BASE, OFFSET_EXTRA_BITS, OFFSET_SIZE, PRECODE_SIZE,
    SHORT_BASE, SHORT_EXTRA_BITS,
};

/// Streaming RAR 3.x decoder. See module docs for the calling convention.
pub struct Decoder {
    /// Pending compressed bytes the caller has supplied but we haven't yet
    /// consumed.
    state: State,
    /// Sink we hand decoded output to before the caller drains it.
    out_buf: Vec<u8>,
    out_drained: usize,
    /// Caller-declared maximum unpacked size. The decoder stops emitting
    /// once this is reached. The default is `u64::MAX`.
    unpack_size: u64,
    /// Apply the E8/E9 filter once decompression finishes? When `true`, the
    /// filter is applied as a single post-pass over the full output buffer
    /// after the unpack_size is reached.
    e8_enabled: bool,
    e8_translate_e9: bool,
    /// Set on any irrecoverable error.
    poisoned: bool,
}

enum State {
    /// Buffering input until [`finish`] is called.
    Buffering { input: Vec<u8> },
    /// Decoding is finished; bytes are in `out_buf`. After all `out_buf`
    /// bytes are drained to the caller, transitions to `Done`.
    Draining,
    /// Stream is fully decoded and output drained.
    Done,
}

impl Decoder {
    /// Construct a decoder with no explicit unpacked-size cap. The decoder
    /// will produce as much output as the compressed stream encodes.
    ///
    /// Most callers should prefer [`Decoder::with_unpack_size`] so the
    /// decoder knows when to stop — RAR3 streams do not carry their
    /// uncompressed length in-band.
    pub fn new() -> Self {
        Self {
            state: State::Buffering { input: Vec::new() },
            out_buf: Vec::new(),
            out_drained: 0,
            unpack_size: u64::MAX,
            e8_enabled: false,
            e8_translate_e9: false,
            poisoned: false,
        }
    }

    /// Construct a decoder that will produce at most `n` uncompressed bytes.
    pub fn with_unpack_size(n: u64) -> Self {
        Self {
            state: State::Buffering { input: Vec::new() },
            out_buf: Vec::new(),
            out_drained: 0,
            unpack_size: n,
            e8_enabled: false,
            e8_translate_e9: false,
            poisoned: false,
        }
    }

    /// Enable the standalone E8 (and optionally E9) filter as a post-pass.
    pub fn with_e8_filter(mut self, translate_e9: bool) -> Self {
        self.e8_enabled = true;
        self.e8_translate_e9 = translate_e9;
        self
    }

    fn poison<T>(&mut self, e: Error) -> Result<T, Error> {
        self.poisoned = true;
        Err(e)
    }

    /// Drain `out_buf` into the caller's `output`. Returns bytes written.
    fn drain_into(&mut self, output: &mut [u8]) -> usize {
        let mut written = 0usize;
        while self.out_drained < self.out_buf.len() && written < output.len() {
            let n = (self.out_buf.len() - self.out_drained).min(output.len() - written);
            output[written..written + n]
                .copy_from_slice(&self.out_buf[self.out_drained..self.out_drained + n]);
            written += n;
            self.out_drained += n;
        }
        if self.out_drained == self.out_buf.len() {
            // Once everything is drained, free the buffer.
            self.out_buf.clear();
            self.out_drained = 0;
            self.state = State::Done;
        }
        written
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
        let mut consumed = 0usize;
        let mut written = 0usize;
        // RAR3 needs the entire compressed stream before it can decode —
        // we don't snapshot the inner state to handle mid-symbol stalls,
        // so the streaming model is buffer-then-drain. The caller may
        // however interleave `decode` calls (to push input) with periodic
        // drains, which we honour here.
        match &mut self.state {
            State::Buffering { input: buf } => {
                buf.extend_from_slice(input);
                consumed = input.len();
            }
            State::Draining => {
                written = self.drain_into(output);
            }
            State::Done => {}
        }
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
        // If we still need to decode, do it now.
        if let State::Buffering { input } = &mut self.state {
            let input = core::mem::take(input);
            // Move into a separate scope so the `match` borrow ends before
            // we mutate `self.state`.
            match run_decode(
                input,
                self.unpack_size,
                self.e8_enabled,
                self.e8_translate_e9,
            ) {
                Ok(out) => {
                    self.out_buf = out;
                    self.out_drained = 0;
                    self.state = State::Draining;
                }
                Err(e) => return self.poison(e),
            }
        }
        let written = self.drain_into(output);
        let done = matches!(self.state, State::Done);
        Ok(RawProgress {
            consumed: 0,
            written,
            done,
        })
    }

    fn raw_reset(&mut self) {
        self.state = State::Buffering { input: Vec::new() };
        self.out_buf.clear();
        self.out_drained = 0;
        self.poisoned = false;
        // unpack_size and filter flags are configuration; preserved across
        // reset to match the LZX/Quantum conventions.
    }
}

// ─── Internal decode pipeline ─────────────────────────────────────────────

fn run_decode(
    input: Vec<u8>,
    unpack_size: u64,
    e8_enabled: bool,
    e8_translate_e9: bool,
) -> Result<Vec<u8>, Error> {
    if unpack_size == 0 {
        return Ok(Vec::new());
    }
    let mut br = BitReader::new();
    br.feed_slice(&input);

    let mut ctx = Box::new(RunCtx {
        bits: br,
        // The length table survives across blocks: a successive block can
        // signal "keep table" with a single header bit and reuse what was
        // most recently decoded.
        lengths: vec![0u8; HUFF_TABLE_SIZE],
        main: None,
        offset: None,
        low_offset: None,
        length: None,
        old_offsets: [1u32, 1, 1, 1],
        last_offset: 0,
        last_length: 0,
        last_low_offset: 0,
        num_low_offset_repeats: 0,
        out: Vec::new(),
        window: vec![0u8; DICT_DEFAULT_SIZE],
        wmask: {
            debug_assert!(DICT_DEFAULT_SIZE.is_power_of_two());
            DICT_DEFAULT_SIZE - 1
        },
        window_pos: 0,
        unpack_size,
        programs: Vec::new(),
        last_filter_slot: 0,
        pending_filters: VecDeque::new(),
    });

    // The decoder starts by parsing the first block header.
    parse_block_header(&mut ctx)?;
    expand(&mut ctx)?;

    // Run any in-band filters whose windows the stream completed. A filter
    // still pending here declared a window the stream never finished
    // producing — a truncated or malformed stream. unrar in that situation
    // writes the raw bytes and relies on the container CRC to flag the
    // file; this crate's policy is to surface the error instead of
    // returning pre-filter bytes as a success.
    ctx.flush_completed_filters()?;
    if !ctx.pending_filters.is_empty() {
        return Err(Error::Corrupt);
    }

    let mut out = core::mem::take(&mut ctx.out);
    if e8_enabled {
        apply_e8_filter(&mut out, 0, e8_translate_e9);
    }
    Ok(out)
}

struct RunCtx {
    bits: BitReader,
    lengths: Vec<u8>,
    main: Option<Box<Huffman>>,
    offset: Option<Box<Huffman>>,
    low_offset: Option<Box<Huffman>>,
    length: Option<Box<Huffman>>,
    /// 4-deep rolling offset history; index 0 is the most recent.
    old_offsets: [u32; 4],
    /// Most-recently-used (offset, length) pair, used by main symbol 258.
    last_offset: u32,
    last_length: u32,
    /// Last low-offset value, plus a repeat counter for the LowOffset
    /// "16" symbol.
    last_low_offset: u32,
    num_low_offset_repeats: u32,
    /// The decoded output stream.
    out: Vec<u8>,
    /// Sliding window — kept in sync with `out` for back-reference lookups.
    /// We use a plain Vec sized to DICT_DEFAULT_SIZE so wrap-around at the
    /// end is cheap; reads use bitwise masking.
    window: Vec<u8>,
    /// Cached `window.len() - 1`. The window length is always a power of two
    /// so wrap-around is a single AND.
    wmask: usize,
    window_pos: usize,
    unpack_size: u64,
    /// RarVM program slots declared so far (recognized standard programs
    /// only) with the per-slot remembered block length — a declaration may
    /// omit the length and reuse the slot's previous one.
    programs: Vec<ProgramSlot>,
    /// Slot used by the most recent declaration; a declaration without an
    /// explicit slot field reuses it.
    last_filter_slot: usize,
    /// Scheduled filter instances, in declaration order. Applied (and
    /// popped from the front) as soon as their windows are fully decoded —
    /// see [`RunCtx::flush_completed_filters`].
    pending_filters: VecDeque<PendingFilter>,
}

/// A declared filter program plus its per-slot remembered block length.
#[derive(Debug, Clone, Copy)]
struct ProgramSlot {
    program: StdProgram,
    last_block_length: u32,
}

impl RunCtx {
    fn emit_literal(&mut self, b: u8) {
        self.out.push(b);
        self.window[self.window_pos] = b;
        self.window_pos = (self.window_pos + 1) & self.wmask;
    }

    fn emit_match(&mut self, offset: u32, length: u32) -> Result<(), Error> {
        if offset == 0 {
            return Err(Error::InvalidDistance);
        }
        // Copy `length` bytes from `offset` behind the window head.
        let wlen = self.window.len();
        let wmask = self.wmask;
        let off = offset as usize;
        if off > wlen {
            return Err(Error::InvalidDistance);
        }
        // Clamp the run to the declared unpack size (the old loop broke per
        // byte once `out` reached it — produce exactly the same byte count).
        let remaining_out = self.unpack_size.saturating_sub(self.out.len() as u64);
        let length = (length as u64).min(remaining_out) as usize;
        let mut src = (self.window_pos + wlen - off) & wmask;
        self.out.reserve(length);

        if off == 1 {
            // Distance-1 run: one repeated byte. Fill directly.
            let b = self.window[src];
            for _ in 0..length {
                self.out.push(b);
                self.window[self.window_pos] = b;
                self.window_pos = (self.window_pos + 1) & wmask;
            }
        } else if off >= length {
            // Non-overlapping: src and dst regions are disjoint. Copy in
            // contiguous window segments (no per-byte recompute of `src`).
            let mut done = 0usize;
            while done < length {
                let run = (length - done).min(wlen - src).min(wlen - self.window_pos);
                for k in 0..run {
                    let b = self.window[src + k];
                    self.out.push(b);
                    self.window[self.window_pos + k] = b;
                }
                src = (src + run) & wmask;
                self.window_pos = (self.window_pos + run) & wmask;
                done += run;
            }
        } else {
            // Overlapping match: each written byte feeds a later read.
            for _ in 0..length {
                let b = self.window[src];
                self.out.push(b);
                self.window[self.window_pos] = b;
                src = (src + 1) & wmask;
                self.window_pos = (self.window_pos + 1) & wmask;
            }
        }
        Ok(())
    }

    fn done(&self) -> bool {
        (self.out.len() as u64) >= self.unpack_size
    }

    /// Apply and drop every filter at the *front* of the pending queue
    /// whose window `[start, start + length)` is fully decoded.
    ///
    /// Only a prefix is flushed: a filter behind one whose window is still
    /// incomplete stays queued even if its own window is complete, so
    /// overlapping windows (filter chains) always apply in declaration
    /// order — the same order unrar's stack executes them. `out` is
    /// append-only and LZ back-references read the (unfiltered) window,
    /// not `out`, so applying a filter as soon as its window completes is
    /// equivalent to applying it at the end of the stream.
    fn flush_completed_filters(&mut self) -> Result<(), Error> {
        while let Some(&f) = self.pending_filters.front() {
            let end = f.start + f.length as u64;
            if end > self.out.len() as u64 {
                break;
            }
            apply_pending(&f, &mut self.out[f.start as usize..end as usize])?;
            self.pending_filters.pop_front();
        }
        Ok(())
    }
}

/// Cap on concurrently scheduled filters, matching unrar's
/// `MAX_UNPACK_FILTERS` (8192). Without a cap, a stream of tiny reused
/// declarations could grow the pending queue without bound.
const MAX_PENDING_FILTERS: usize = 8192;

// ─── Block header parsing ────────────────────────────────────────────────

fn parse_block_header(ctx: &mut RunCtx) -> Result<(), Error> {
    // RAR3 byte-aligns the bitstream before reading every block header,
    // including the very first one (where alignment is a no-op since we
    // start on a byte boundary).
    ctx.bits.byte_align();
    // 1 bit: PPMd-block flag. We reject PPMd unconditionally.
    let is_ppmd = ctx.bits.read_bits(1)?;
    if is_ppmd != 0 {
        // PPMd-II would consume 7 more flag bits and possibly 2 more
        // bytes here; we don't bother reading them since we're refusing
        // the stream.
        return Err(Error::Unsupported);
    }
    // 1 bit: keep-table flag. 0 ⇒ reset the persistent length table.
    let keep_table = ctx.bits.read_bits(1)? != 0;
    if !keep_table {
        for slot in ctx.lengths.iter_mut() {
            *slot = 0;
        }
    }

    // Read 20 precode lengths, 4 bits each, with the 0xF run-of-zeros
    // escape: a value of 0xF is followed by another 4-bit field whose
    // value plus 2 is the run of subsequent zeros to emit. A value of 0
    // after 0xF means "this entry is just 15".
    let mut precode = [0u8; PRECODE_SIZE];
    let mut i = 0usize;
    while i < PRECODE_SIZE {
        let v = ctx.bits.read_bits(4)? as u8;
        if v == 0x0F {
            let runcount = ctx.bits.read_bits(4)? as u8;
            if runcount == 0 {
                precode[i] = 0x0F;
                i += 1;
            } else {
                let n = (runcount as usize) + 2;
                let mut k = 0;
                while k < n && i < PRECODE_SIZE {
                    precode[i] = 0;
                    i += 1;
                    k += 1;
                }
            }
        } else {
            precode[i] = v;
            i += 1;
        }
    }

    let pre_tree = Huffman::from_lengths(&precode)?;

    // Decode the HUFF_TABLE_SIZE-length code-length array using the precode.
    let mut idx = 0usize;
    while idx < HUFF_TABLE_SIZE {
        let sym = pre_tree.decode(&mut ctx.bits)?;
        if sym < 16 {
            // Incremental: add to existing value mod 16.
            ctx.lengths[idx] = ((ctx.lengths[idx] as u16 + sym) & 0xF) as u8;
            idx += 1;
        } else if sym == 16 {
            if idx == 0 {
                return Err(Error::Corrupt);
            }
            let n = (ctx.bits.read_bits(3)? as usize) + 3;
            let prev = ctx.lengths[idx - 1];
            for _ in 0..n {
                if idx >= HUFF_TABLE_SIZE {
                    break;
                }
                ctx.lengths[idx] = prev;
                idx += 1;
            }
        } else if sym == 17 {
            if idx == 0 {
                return Err(Error::Corrupt);
            }
            let n = (ctx.bits.read_bits(7)? as usize) + 11;
            let prev = ctx.lengths[idx - 1];
            for _ in 0..n {
                if idx >= HUFF_TABLE_SIZE {
                    break;
                }
                ctx.lengths[idx] = prev;
                idx += 1;
            }
        } else if sym == 18 {
            let n = (ctx.bits.read_bits(3)? as usize) + 3;
            for _ in 0..n {
                if idx >= HUFF_TABLE_SIZE {
                    break;
                }
                ctx.lengths[idx] = 0;
                idx += 1;
            }
        } else if sym == 19 {
            let n = (ctx.bits.read_bits(7)? as usize) + 11;
            for _ in 0..n {
                if idx >= HUFF_TABLE_SIZE {
                    break;
                }
                ctx.lengths[idx] = 0;
                idx += 1;
            }
        } else {
            return Err(Error::Corrupt);
        }
    }

    // Build the four data-Huffman codes.
    ctx.main = Some(Box::new(Huffman::from_lengths(&ctx.lengths[..MAIN_SIZE])?));
    ctx.offset = Some(Box::new(Huffman::from_lengths(
        &ctx.lengths[MAIN_SIZE..MAIN_SIZE + OFFSET_SIZE],
    )?));
    ctx.low_offset = Some(Box::new(Huffman::from_lengths(
        &ctx.lengths[MAIN_SIZE + OFFSET_SIZE..MAIN_SIZE + OFFSET_SIZE + LOW_OFFSET_SIZE],
    )?));
    ctx.length = Some(Box::new(Huffman::from_lengths(
        &ctx.lengths[MAIN_SIZE + OFFSET_SIZE + LOW_OFFSET_SIZE
            ..MAIN_SIZE + OFFSET_SIZE + LOW_OFFSET_SIZE + LENGTH_SIZE],
    )?));
    Ok(())
}

// ─── Expansion ───────────────────────────────────────────────────────────

fn expand(ctx: &mut RunCtx) -> Result<(), Error> {
    loop {
        if ctx.done() {
            return Ok(());
        }

        // Decode the next main-tree symbol.
        let main_tree = ctx.main.as_ref().ok_or(Error::InvalidHuffmanTree)?;
        let sym = match main_tree.decode(&mut ctx.bits) {
            Ok(s) => s,
            Err(Error::UnexpectedEnd) => {
                // Stream ran out before we've reached unpack_size. The
                // caller's count of output bytes is authoritative.
                return Ok(());
            }
            Err(e) => return Err(e),
        };

        if sym < 256 {
            ctx.emit_literal(sym as u8);
            continue;
        }

        match sym {
            256 => {
                // End-of-block marker; followed by a single bit deciding
                // between "this is the end of the stream" and "a new code
                // table follows". The PPMd-vs-Huffman test makes one more
                // bit (the "new file" flag) optional in libarchive's port,
                // but unarr just reads `start_new_table` directly. We
                // follow unarr here: one bit = start_new_table.
                let new_table = ctx.bits.read_bits(1)? != 0;
                if new_table {
                    parse_block_header(ctx)?;
                } else {
                    // End of stream marker: any further bytes belong to a
                    // separate stream.
                    return Ok(());
                }
            }
            257 => {
                // Filter declaration: a standard-program instance gets
                // scheduled over a window of upcoming output; anything we
                // can't run natively fails the stream (inside the parser).
                read_filter_declaration(ctx)?;
            }
            258 => {
                // Repeat last (offset, length).
                if ctx.last_length == 0 {
                    return Err(Error::Corrupt);
                }
                let (o, l) = (ctx.last_offset, ctx.last_length);
                ctx.emit_match(o, l)?;
            }
            259..=262 => {
                let idx = (sym - 259) as usize;
                let offs = ctx.old_offsets[idx];
                // Length comes from the length tree.
                let length_tree = ctx.length.as_ref().ok_or(Error::InvalidHuffmanTree)?;
                let lensym = length_tree.decode(&mut ctx.bits)? as usize;
                if lensym >= LENGTH_BASE.len() {
                    return Err(Error::Corrupt);
                }
                let lbase = LENGTH_BASE[lensym] as u32 + 2;
                let lbits = LENGTH_EXTRA_BITS[lensym] as u32;
                let extra = if lbits > 0 {
                    ctx.bits.read_bits(lbits)?
                } else {
                    0
                };
                let length = lbase + extra;

                // Promote `offs` to the front of the rolling buffer.
                promote_offset(ctx, idx, offs);

                ctx.last_offset = offs;
                ctx.last_length = length;
                ctx.emit_match(offs, length)?;
            }
            263..=270 => {
                let idx = (sym - 263) as usize;
                let sbase = SHORT_BASE[idx];
                let sbits = SHORT_EXTRA_BITS[idx] as u32;
                let extra = if sbits > 0 {
                    ctx.bits.read_bits(sbits)?
                } else {
                    0
                };
                let offs = sbase + extra + 1;
                let length: u32 = 2;
                // Rotate the offset history.
                ctx.old_offsets[3] = ctx.old_offsets[2];
                ctx.old_offsets[2] = ctx.old_offsets[1];
                ctx.old_offsets[1] = ctx.old_offsets[0];
                ctx.old_offsets[0] = offs;
                ctx.last_offset = offs;
                ctx.last_length = length;
                ctx.emit_match(offs, length)?;
            }
            271..=298 => {
                let idx = (sym - 271) as usize;
                if idx >= LENGTH_BASE.len() {
                    return Err(Error::Corrupt);
                }
                let lbase = LENGTH_BASE[idx] as u32 + 3;
                let lbits = LENGTH_EXTRA_BITS[idx] as u32;
                let lextra = if lbits > 0 {
                    ctx.bits.read_bits(lbits)?
                } else {
                    0
                };
                let mut length = lbase + lextra;

                // Read an offset code.
                let offset_tree = ctx.offset.as_ref().ok_or(Error::InvalidHuffmanTree)?;
                let osym = offset_tree.decode(&mut ctx.bits)? as usize;
                if osym >= OFFSET_BASE.len() {
                    return Err(Error::Corrupt);
                }
                let mut offs = OFFSET_BASE[osym] + 1;
                let obits = OFFSET_EXTRA_BITS[osym] as u32;

                if osym > 9 {
                    // Large offset: read (obits - 4) high bits raw, then
                    // 4 low bits from the LowOffset tree.
                    if obits > 4 {
                        let high = ctx.bits.read_bits(obits - 4)?;
                        offs = offs.wrapping_add(high << 4);
                    }
                    if ctx.num_low_offset_repeats > 0 {
                        ctx.num_low_offset_repeats -= 1;
                        offs = offs.wrapping_add(ctx.last_low_offset);
                    } else {
                        let low_tree = ctx.low_offset.as_ref().ok_or(Error::InvalidHuffmanTree)?;
                        let lowsym = low_tree.decode(&mut ctx.bits)?;
                        if lowsym == 16 {
                            ctx.num_low_offset_repeats = 15;
                            offs = offs.wrapping_add(ctx.last_low_offset);
                        } else {
                            offs = offs.wrapping_add(lowsym as u32);
                            ctx.last_low_offset = lowsym as u32;
                        }
                    }
                } else if obits > 0 {
                    let extra = ctx.bits.read_bits(obits)?;
                    offs = offs.wrapping_add(extra);
                }

                if offs >= 0x4_0000 {
                    length += 1;
                }
                if offs >= 0x2000 {
                    length += 1;
                }

                ctx.old_offsets[3] = ctx.old_offsets[2];
                ctx.old_offsets[2] = ctx.old_offsets[1];
                ctx.old_offsets[1] = ctx.old_offsets[0];
                ctx.old_offsets[0] = offs;
                ctx.last_offset = offs;
                ctx.last_length = length;
                ctx.emit_match(offs, length)?;
            }
            _ => return Err(Error::Corrupt),
        }
    }
}

// ─── In-band filter declarations (main symbol 257) ──────────────────────

/// Upper bound on a filter's block length, derived from the RarVM memory
/// the standard programs operate in (0x40000 bytes, of which 0x3C000 lie
/// below the global-data area). Delta needs separate source and
/// destination halves, so its windows are capped at half that. Real
/// encoders stay far below both caps and split large regions into several
/// filter blocks.
const FILTER_MAX_BLOCK: u32 = 0x3C000;
const FILTER_MAX_BLOCK_DELTA: u32 = 0x1E000;

/// Read a RarVM variable-length number: a 2-bit tag selects a 4-, 8-
/// (with a sign-extension-style escape for values below 16), 16- or 32-bit
/// payload.
fn read_vm_number(bits: &mut BitReader) -> Result<u32, Error> {
    Ok(match bits.read_bits(2)? {
        0 => bits.read_bits(4)?,
        1 => {
            let v = bits.read_bits(8)?;
            if v >= 16 {
                v
            } else {
                0xFFFF_FF00 | (v << 4) | bits.read_bits(4)?
            }
        }
        2 => bits.read_bits(16)?,
        _ => bits.read_bits(32)?,
    })
}

/// Parse the declaration that follows main symbol 257 and schedule the
/// filter it describes.
///
/// Wire layout (validated bit-exact against rar 6.24 archives; see the
/// module docs in `filters.rs` for provenance): an 8-bit flags byte and a
/// 1/2/3-byte length field are read from the main bitstream, then `length`
/// payload bytes (8 bits each, unaligned). The payload forms its own
/// MSB-first bit domain containing, in order:
///
/// 1. flags bit 7: a program-slot number (RarVM number; 0 resets all
///    declared programs and selects slot 0, n>0 selects slot n-1). Absent →
///    reuse the most recent slot.
/// 2. Window start relative to the current output position (RarVM number;
///    flags bit 6 adds 258).
/// 3. flags bit 5: explicit window length (RarVM number). Absent → the
///    slot's remembered length.
/// 4. flags bit 4: a 7-bit register mask followed by a RarVM number per set
///    bit (registers r0..r6; Delta receives its channel count in r0).
/// 5. For a first-use slot: bytecode as a RarVM number length plus that
///    many bytes, the first being an XOR checksum of the rest.
/// 6. flags bit 3: trailing global data — not needed by any standard
///    program, ignored here.
fn read_filter_declaration(ctx: &mut RunCtx) -> Result<(), Error> {
    let flags = ctx.bits.read_bits(8)?;
    let mut decl_len = (flags & 0x07) + 1;
    if decl_len == 7 {
        decl_len = ctx.bits.read_bits(8)? + 7;
    } else if decl_len == 8 {
        decl_len = ctx.bits.read_bits(16)?;
    }
    if decl_len == 0 {
        return Err(Error::Corrupt);
    }
    let mut payload = vec![0u8; decl_len as usize];
    for b in payload.iter_mut() {
        *b = ctx.bits.read_bits(8)? as u8;
    }
    // The payload is its own bit domain; running out of payload bits means
    // the declaration is malformed, not that the caller should feed more
    // input, so map UnexpectedEnd to Corrupt.
    let mut db = BitReader::new();
    db.feed_slice(&payload);
    parse_declaration_payload(ctx, flags, &mut db).map_err(|e| match e {
        Error::UnexpectedEnd => Error::Corrupt,
        other => other,
    })
}

fn parse_declaration_payload(
    ctx: &mut RunCtx,
    flags: u32,
    db: &mut BitReader,
) -> Result<(), Error> {
    let slot = if flags & 0x80 != 0 {
        let v = read_vm_number(db)?;
        if v == 0 {
            // Full reset (unrar's InitFilters): apply the filters whose
            // windows the stream already completed, then cancel everything
            // else — a canceled filter must never run, or it would rewrite
            // output the encoder didn't transform.
            ctx.flush_completed_filters()?;
            ctx.pending_filters.clear();
            ctx.programs.clear();
            0
        } else {
            (v - 1) as usize
        }
    } else {
        ctx.last_filter_slot
    };
    // A slot may reference an existing program or append exactly one new
    // one; skipping ahead is malformed.
    if slot > ctx.programs.len() {
        return Err(Error::Corrupt);
    }
    ctx.last_filter_slot = slot;

    let mut start = read_vm_number(db)? as u64;
    if flags & 0x40 != 0 {
        start += 258;
    }
    let start = ctx.out.len() as u64 + start;

    let explicit_length = if flags & 0x20 != 0 {
        Some(read_vm_number(db)?)
    } else {
        None
    };

    // Registers r0..r6. Only r0 matters to the standard transforms (Delta's
    // channel count), but all present values must be consumed to stay in
    // sync with the fields that follow.
    let mut r0 = 0u32;
    if flags & 0x10 != 0 {
        let mask = db.read_bits(7)?;
        for r in 0..7 {
            if mask & (1 << r) != 0 {
                let v = read_vm_number(db)?;
                if r == 0 {
                    r0 = v;
                }
            }
        }
    }

    if slot == ctx.programs.len() {
        // First use of this slot: bytecode follows.
        let code_len = read_vm_number(db)?;
        if code_len == 0 || code_len >= 0x1_0000 {
            return Err(Error::Corrupt);
        }
        let mut code = vec![0u8; code_len as usize];
        for b in code.iter_mut() {
            *b = db.read_bits(8)? as u8;
        }
        // The first bytecode byte is an XOR checksum of the rest.
        let checksum = code[1..].iter().fold(0u8, |acc, &b| acc ^ b);
        if checksum != code[0] {
            return Err(Error::Corrupt);
        }
        let program = recognize_program(&code).ok_or(Error::Unsupported)?;
        ctx.programs.push(ProgramSlot {
            program,
            last_block_length: 0,
        });
    }
    // (flags bit 3: global data would follow here; no standard program
    // reads it, so it stays unparsed — the payload is self-contained.)

    let length = explicit_length.unwrap_or(ctx.programs[slot].last_block_length);
    ctx.programs[slot].last_block_length = length;
    if length == 0 {
        // A zero-length window is a no-op declaration.
        return Ok(());
    }
    let program = ctx.programs[slot].program;
    let cap = if program == StdProgram::Delta {
        FILTER_MAX_BLOCK_DELTA
    } else {
        FILTER_MAX_BLOCK
    };
    if length > cap {
        return Err(Error::Corrupt);
    }
    ctx.pending_filters.push_back(PendingFilter {
        start,
        length,
        program,
        channels: r0,
    });
    if ctx.pending_filters.len() > MAX_PENDING_FILTERS {
        // Match unrar's cap on concurrently scheduled filters: try to
        // drain completed windows first; a stream that still exceeds the
        // cap is hostile or malformed.
        ctx.flush_completed_filters()?;
        if ctx.pending_filters.len() > MAX_PENDING_FILTERS {
            return Err(Error::Corrupt);
        }
    }
    Ok(())
}

/// Promote the offset at `idx` (in the rolling buffer) to position 0,
/// shifting everything above it down. Used by symbols 259..=262.
fn promote_offset(ctx: &mut RunCtx, idx: usize, offs: u32) {
    // Shift indices 0..idx by one slot down, then store `offs` at 0.
    let mut i = idx;
    while i > 0 {
        ctx.old_offsets[i] = ctx.old_offsets[i - 1];
        i -= 1;
    }
    ctx.old_offsets[0] = offs;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::Decoder as _;
    extern crate std;
    use std::vec;

    /// MSB-first bit writer used to hand-build declaration payloads.
    struct BitWriter {
        bytes: std::vec::Vec<u8>,
        nbits: u32,
    }
    impl BitWriter {
        fn new() -> Self {
            Self {
                bytes: std::vec::Vec::new(),
                nbits: 0,
            }
        }
        fn push(&mut self, value: u32, n: u32) {
            for i in (0..n).rev() {
                let bit = ((value >> i) & 1) as u8;
                if self.nbits.is_multiple_of(8) {
                    self.bytes.push(0);
                }
                let last = self.bytes.len() - 1;
                self.bytes[last] |= bit << (7 - (self.nbits % 8));
                self.nbits += 1;
            }
        }
        /// Push a value in RarVM variable-number encoding (shortest form).
        fn push_vm_number(&mut self, v: u32) {
            if v < 16 {
                self.push(0, 2);
                self.push(v, 4);
            } else if v < 256 {
                self.push(1, 2);
                self.push(v, 8);
            } else if v < 0x1_0000 {
                self.push(2, 2);
                self.push(v, 16);
            } else {
                self.push(3, 2);
                self.push(v, 32);
            }
        }
    }

    fn test_ctx() -> RunCtx {
        RunCtx {
            bits: BitReader::new(),
            lengths: vec![],
            main: None,
            offset: None,
            low_offset: None,
            length: None,
            old_offsets: [1, 1, 1, 1],
            last_offset: 0,
            last_length: 0,
            last_low_offset: 0,
            num_low_offset_repeats: 0,
            out: vec![],
            window: vec![0u8; 16],
            wmask: 15,
            window_pos: 0,
            unpack_size: 0,
            programs: vec![],
            last_filter_slot: 0,
            pending_filters: VecDeque::new(),
        }
    }

    #[test]
    fn vm_number_all_tag_widths() {
        let mut w = BitWriter::new();
        w.push_vm_number(9); // tag 0, 4-bit
        w.push_vm_number(200); // tag 1, 8-bit (>= 16)
        w.push_vm_number(0x1234); // tag 2, 16-bit
        w.push_vm_number(0x0102_0304); // tag 3, 32-bit
        // tag 1 with an 8-bit value below 16: extends to 0xFFFFFF00-form.
        w.push(1, 2);
        w.push(5, 8);
        w.push(0xA, 4);
        let mut r = BitReader::new();
        r.feed_slice(&w.bytes);
        assert_eq!(read_vm_number(&mut r).unwrap(), 9);
        assert_eq!(read_vm_number(&mut r).unwrap(), 200);
        assert_eq!(read_vm_number(&mut r).unwrap(), 0x1234);
        assert_eq!(read_vm_number(&mut r).unwrap(), 0x0102_0304);
        assert_eq!(read_vm_number(&mut r).unwrap(), 0xFFFF_FF5A);
    }

    /// Build the payload of a declaration introducing a fresh program.
    /// `code` must carry a valid XOR checksum byte already.
    fn new_program_payload(block_start: u32, block_len: u32, code: &[u8]) -> std::vec::Vec<u8> {
        let mut w = BitWriter::new();
        w.push_vm_number(0); // slot field: reset-all + slot 0
        w.push_vm_number(block_start);
        w.push_vm_number(block_len);
        w.push_vm_number(code.len() as u32);
        for &b in code {
            w.push(b as u32, 8);
        }
        w.bytes
    }

    /// Wrap arbitrary bytecode with its XOR checksum byte.
    fn with_checksum(body: &[u8]) -> std::vec::Vec<u8> {
        let mut code = std::vec::Vec::with_capacity(body.len() + 1);
        code.push(body.iter().fold(0u8, |a, &b| a ^ b));
        code.extend_from_slice(body);
        code
    }

    /// The 29-byte standard Delta program as WinRAR emits it, lifted from
    /// `tests/fixtures/rar3/filter_delta_gradient_bmp.bin` (rar 6.24
    /// archive of gradient.bmp). CRC-32 0x0E06077D; byte 0 is the XOR
    /// checksum of the rest.
    const DELTA_PROG: [u8; 29] = [
        0x2F, 0x01, 0x9A, 0x41, 0x80, 0xEC, 0x27, 0x48, 0x2F, 0x09, 0x76, 0x6D, 0xD3, 0xEA, 0x41,
        0x5B, 0x59, 0x44, 0xE8, 0x17, 0x5C, 0xE1, 0x6C, 0x91, 0x4C, 0x4E, 0x3F, 0x77, 0x00,
    ];

    fn incomplete_filter(start: u64) -> PendingFilter {
        PendingFilter {
            start,
            length: 100,
            program: StdProgram::Delta,
            channels: 1,
        }
    }

    #[test]
    fn delta_program_is_recognized() {
        assert_eq!(recognize_program(&DELTA_PROG), Some(StdProgram::Delta));
    }

    /// A reset declaration (slot field 0) must first run the filters whose
    /// windows are already complete, then cancel everything still pending —
    /// a canceled filter must never rewrite output.
    #[test]
    fn reset_applies_completed_and_cancels_pending() {
        let mut ctx = test_ctx();
        ctx.out = vec![1, 0, 0, 0, 9, 9, 9, 9];
        ctx.programs.push(ProgramSlot {
            program: StdProgram::Delta,
            last_block_length: 4,
        });
        ctx.pending_filters.push_back(PendingFilter {
            start: 0,
            length: 4,
            program: StdProgram::Delta,
            channels: 1,
        });
        ctx.pending_filters.push_back(incomplete_filter(4));

        // Payload: slot reset, block_start 0, explicit length 4, r0 = 1
        // channel, then the (new, post-reset) Delta program bytecode.
        let mut w = BitWriter::new();
        w.push_vm_number(0);
        w.push_vm_number(0);
        w.push_vm_number(4);
        w.push(0x01, 7); // register mask: r0 only
        w.push_vm_number(1);
        w.push_vm_number(DELTA_PROG.len() as u32);
        for &b in &DELTA_PROG {
            w.push(b as u32, 8);
        }
        let mut db = BitReader::new();
        db.feed_slice(&w.bytes);
        parse_declaration_payload(&mut ctx, 0xB0, &mut db).unwrap();

        // The completed 1-channel delta over [1,0,0,0] ran: prev-integrate
        // gives [0xFF; 4]. The trailing bytes stay raw.
        assert_eq!(&ctx.out[..4], &[0xFF; 4]);
        assert_eq!(&ctx.out[4..], &[9; 4]);
        // The incomplete filter was canceled; only the fresh declaration
        // (window at out position 8) is scheduled against the fresh slot.
        assert_eq!(ctx.pending_filters.len(), 1);
        assert_eq!(ctx.pending_filters[0].start, 8);
        assert_eq!(ctx.programs.len(), 1);
    }

    /// The pending queue is capped (unrar's MAX_UNPACK_FILTERS): once no
    /// completed window can be drained, further declarations are corrupt.
    #[test]
    fn pending_filter_cap_is_enforced() {
        let mut ctx = test_ctx();
        ctx.programs.push(ProgramSlot {
            program: StdProgram::Delta,
            last_block_length: 5,
        });
        for _ in 0..MAX_PENDING_FILTERS {
            ctx.pending_filters.push_back(incomplete_filter(1_000_000));
        }
        // Reuse-slot declaration: block_start only, remembered length.
        let mut w = BitWriter::new();
        w.push_vm_number(0);
        let mut db = BitReader::new();
        db.feed_slice(&w.bytes);
        assert_eq!(
            parse_declaration_payload(&mut ctx, 0x00, &mut db),
            Err(Error::Corrupt)
        );
    }

    /// A declaration without an explicit length (flags bit 5 clear) reuses
    /// the slot's remembered length from the previous declaration.
    #[test]
    fn slot_reuse_inherits_remembered_length() {
        let mut ctx = test_ctx();
        // First declaration: fresh Delta program, explicit length 4.
        let mut w = BitWriter::new();
        w.push_vm_number(0);
        w.push_vm_number(0);
        w.push_vm_number(4);
        w.push(0x01, 7);
        w.push_vm_number(1);
        w.push_vm_number(DELTA_PROG.len() as u32);
        for &b in &DELTA_PROG {
            w.push(b as u32, 8);
        }
        let mut db = BitReader::new();
        db.feed_slice(&w.bytes);
        parse_declaration_payload(&mut ctx, 0xB0, &mut db).unwrap();

        // Second declaration: no slot field, no explicit length — inherits
        // slot 0's remembered length; window 16 bytes further out.
        let mut w = BitWriter::new();
        w.push_vm_number(16);
        let mut db = BitReader::new();
        db.feed_slice(&w.bytes);
        parse_declaration_payload(&mut ctx, 0x00, &mut db).unwrap();

        assert_eq!(ctx.pending_filters.len(), 2);
        assert_eq!(ctx.pending_filters[1].start, 16);
        assert_eq!(ctx.pending_filters[1].length, 4);
    }

    /// Only a *prefix* of completed windows may flush: a completed filter
    /// queued behind an incomplete one must wait so that overlapping
    /// windows always apply in declaration order.
    #[test]
    fn flush_is_prefix_ordered() {
        let mut ctx = test_ctx();
        ctx.out = vec![7; 8];
        ctx.pending_filters.push_back(incomplete_filter(4));
        ctx.pending_filters.push_back(PendingFilter {
            start: 0,
            length: 4,
            program: StdProgram::Delta,
            channels: 1,
        });
        ctx.flush_completed_filters().unwrap();
        assert_eq!(ctx.pending_filters.len(), 2, "nothing may flush");
        assert_eq!(ctx.out, vec![7; 8], "output must be untouched");
    }

    #[test]
    fn unknown_program_is_unsupported() {
        // Valid declaration framing around bytecode we don't recognize
        // (flags: slot present + explicit length = 0xA0).
        let code = with_checksum(&[0x12, 0x34, 0x56, 0x78]);
        let payload = new_program_payload(0, 64, &code);
        let mut ctx = test_ctx();
        let mut db = BitReader::new();
        db.feed_slice(&payload);
        assert_eq!(
            parse_declaration_payload(&mut ctx, 0xA0, &mut db),
            Err(Error::Unsupported)
        );
    }

    #[test]
    fn bad_bytecode_checksum_is_corrupt() {
        let mut code = with_checksum(&[0x12, 0x34]);
        code[0] ^= 0xFF; // break the checksum
        let payload = new_program_payload(0, 64, &code);
        let mut ctx = test_ctx();
        let mut db = BitReader::new();
        db.feed_slice(&payload);
        assert_eq!(
            parse_declaration_payload(&mut ctx, 0xA0, &mut db),
            Err(Error::Corrupt)
        );
    }

    #[test]
    fn slot_skipping_ahead_is_corrupt() {
        // Slot field 3 => slot index 2 with no programs declared.
        let mut w = BitWriter::new();
        w.push_vm_number(3);
        let mut ctx = test_ctx();
        let mut db = BitReader::new();
        db.feed_slice(&w.bytes);
        assert_eq!(
            parse_declaration_payload(&mut ctx, 0x80, &mut db),
            Err(Error::Corrupt)
        );
    }

    #[test]
    fn truncated_main_stream_mid_declaration_is_unexpected_end() {
        // flags byte 0x86 declares (6&7)+1 = 7 → an extra 8-bit length
        // field must follow, but the stream ends first.
        let mut ctx = test_ctx();
        ctx.bits.feed_slice(&[0x86]);
        assert!(matches!(
            read_filter_declaration(&mut ctx),
            Err(Error::UnexpectedEnd)
        ));
    }

    #[test]
    fn payload_bits_running_out_is_corrupt() {
        // flags 0xA0, decl_len 1, payload [0xFF]: the slot field's 2-bit
        // tag reads 0b11 → a 32-bit number that the 1-byte payload can't
        // hold. Inside the payload's own bit domain that's a malformed
        // declaration, so the wrapper maps it to Corrupt.
        let mut ctx = test_ctx();
        ctx.bits.feed_slice(&[0xA0, 0xFF]);
        assert_eq!(read_filter_declaration(&mut ctx), Err(Error::Corrupt));
    }

    #[test]
    fn unpack_size_zero_is_immediate_done() {
        let mut dec = Decoder::with_unpack_size(0);
        let mut out = [0u8; 8];
        let (p, status) = dec.finish(&mut out).unwrap();
        assert_eq!(p.written, 0);
        assert!(matches!(status, crate::Status::StreamEnd));
    }

    #[test]
    fn promote_offset_rotates_correctly() {
        // Construct a context-shaped struct just to test the helper.
        let mut ctx = RunCtx {
            bits: BitReader::new(),
            lengths: vec![],
            main: None,
            offset: None,
            low_offset: None,
            length: None,
            old_offsets: [10, 20, 30, 40],
            last_offset: 0,
            last_length: 0,
            last_low_offset: 0,
            num_low_offset_repeats: 0,
            out: vec![],
            window: vec![0u8; 16],
            wmask: 15,
            window_pos: 0,
            unpack_size: 0,
            programs: vec![],
            last_filter_slot: 0,
            pending_filters: VecDeque::new(),
        };
        // Promote slot 2 (value 30) — result should be [30, 10, 20, 40].
        promote_offset(&mut ctx, 2, 30);
        assert_eq!(ctx.old_offsets, [30, 10, 20, 40]);
    }
}
