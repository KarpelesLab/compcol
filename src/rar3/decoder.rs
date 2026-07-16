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
//! - The **LZ77 + Huffman path** used by the vast majority of RAR3
//!   archives: all five Huffman codes (precode, main, offset, low-offset,
//!   length), the 4-deep rolling-offset buffer, short offsets (codes 263
//!   through 270), the full match-length / offset machinery, and the
//!   keep-table flag (successive blocks reusing the previous code lengths).
//! - **In-band standard filters** (main symbol 257, or escape code 3 in a
//!   PPMd block): Delta and x86 E8/E8E9 declarations are recognized by
//!   their bytecode fingerprint and run natively over their declared
//!   output windows — see `super::filters` for the recognition scheme and
//!   provenance.
//! - **PPMd-II variant H blocks** (bit-0 of the block header): the full
//!   PPMII model in [`crate::ppmd`] driven by the RAR range decoder, with
//!   the RAR escape layer (literals, LZ matches, filters, end-of-data) on
//!   top — see [`run_ppmd`]. Mid-stream switches between LZ and PPMd (the
//!   `start-new-table` paths in both domains) are followed, including PPMd
//!   continuation headers that reuse the live model.
//! - **Solid groups** ([`Decoder::with_solid`] +
//!   [`Decoder::begin_solid_member`]): the LZ window, code tables, offset
//!   history, filter programs and PPMd model persist across members. Each
//!   member's payload is decoded as its own byte-aligned stream, with the
//!   end-of-member markers consumed through the shared state (a PPMd
//!   member's marker updates the model, exactly as the encoder's did).
//! - The standalone E8/E9 post-pass filter when enabled via
//!   [`Decoder::with_e8_filter`].
//!
//! ## What's refused
//!
//! - **Cross-member range-coder state**: a PPMd block whose range coder
//!   would have to straddle a solid member boundary (a member ending
//!   without an end-of-data marker mid-PPMd, or a new PPMd block starting
//!   exactly at the boundary via an inline table announcement). rar 6.24
//!   always ends PPMd members with a marker and starts PPMd blocks with a
//!   header in the member that uses them, so these arise only in crafted
//!   streams; they fail with `Error::Unsupported`.
//! - **Filter declarations carrying any other VM program** (custom
//!   bytecode, or legacy standard programs no current archiver emits —
//!   Itanium, RGB, the audio predictor). These fail with
//!   `Error::Unsupported` rather than interpreting RarVM bytecode.
//! - **Dictionary sizes** other than the default 4 MiB for the LZ path.
//!   Streams compressed with smaller dictionaries decode correctly with the
//!   larger window — the larger window doesn't change semantics.

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
use crate::ppmd::{Ppmd7, RangeDec, RangeMode};

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
    /// Solid-group mode: end-of-member markers are consumed (through the
    /// PPMd model where applicable) and the decode context persists across
    /// [`Decoder::begin_solid_member`] calls.
    solid: bool,
    /// The persistent decode context (window, code tables, offset history,
    /// filter programs, PPMd model). Created on the first `finish`; dropped
    /// after each stream unless `solid`.
    ctx: Option<Box<RunCtx>>,
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
            solid: false,
            ctx: None,
        }
    }

    /// Construct a decoder that will produce at most `n` uncompressed bytes.
    pub fn with_unpack_size(n: u64) -> Self {
        let mut d = Self::new();
        d.unpack_size = n;
        d
    }

    /// Enable the standalone E8 (and optionally E9) filter as a post-pass.
    pub fn with_e8_filter(mut self, translate_e9: bool) -> Self {
        self.e8_enabled = true;
        self.e8_translate_e9 = translate_e9;
        self
    }

    /// Enable solid-group mode. In a RAR3 **solid** archive the members of
    /// a solid group share one compression history: the LZ window, code
    /// tables, offset history, declared filter programs and any live PPMd
    /// model all persist from one member to the next, while each member's
    /// compressed payload is its own byte-aligned stream. Decode the first
    /// member as usual, then call [`Decoder::begin_solid_member`] before
    /// feeding each subsequent member.
    ///
    /// Solid mode also makes truncation a hard error: a member whose stream
    /// ends before its declared unpacked size poisons the whole group (the
    /// shared history would desync every later member), where the default
    /// mode returns the short output and leaves the verdict to the caller.
    pub fn with_solid(mut self) -> Self {
        self.solid = true;
        self
    }

    /// Prepare to decode the next member of a solid group: keeps the shared
    /// compression history and expects `unpack_size` uncompressed bytes from
    /// the next member's compressed payload (fed via `decode`/`finish` as
    /// usual). Only valid on a [`Decoder::with_solid`] decoder whose current
    /// member has fully drained.
    pub fn begin_solid_member(&mut self, unpack_size: u64) -> Result<(), Error> {
        if self.poisoned {
            return Err(Error::Corrupt);
        }
        if !self.solid || !matches!(self.state, State::Done) {
            return Err(Error::Unsupported);
        }
        self.unpack_size = unpack_size;
        self.state = State::Buffering { input: Vec::new() };
        Ok(())
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
            let ctx = self
                .ctx
                .get_or_insert_with(|| Box::new(RunCtx::new(self.unpack_size)));
            ctx.unpack_size = self.unpack_size;
            let result = if self.unpack_size == 0 {
                Ok(Vec::new())
            } else {
                run_member(ctx, &input, self.solid)
            };
            match result {
                Ok(mut out) => {
                    if self.e8_enabled {
                        apply_e8_filter(&mut out, 0, self.e8_translate_e9);
                    }
                    if !self.solid {
                        // Match the pre-solid memory profile: a one-shot
                        // stream has no further use for the 4 MiB window.
                        self.ctx = None;
                    }
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
        // A reset starts a fresh stream: any solid history is gone.
        self.ctx = None;
        // unpack_size, solid and filter flags are configuration; preserved
        // across reset to match the LZX/Quantum conventions.
    }
}

// ─── Internal decode pipeline ─────────────────────────────────────────────

/// Decode one member's compressed payload against the (possibly carried-
/// over) context. In solid mode the end-of-member marker is consumed so the
/// persistent state is exactly what the next member's stream expects.
fn run_member(ctx: &mut RunCtx, input: &[u8], solid: bool) -> Result<Vec<u8>, Error> {
    // Each member's payload is its own byte-aligned stream (the container
    // resets the bit input at every member boundary), so the reader is
    // rebuilt even when the rest of the context carries over.
    ctx.bits = BitReader::new();
    ctx.bits.feed_slice(input);
    ctx.out = Vec::new();
    // Filter *programs* persist across solid members, but scheduled filter
    // instances never span a member boundary.
    ctx.pending_filters.clear();

    // A fresh stream — or a previous member that announced new tables —
    // starts with a block header; otherwise symbol decoding continues
    // directly under the carried-over tables (or PPMd model).
    if !ctx.tables_read {
        parse_block_header(ctx)?;
    }
    loop {
        let seg = match ctx.block {
            BlockKind::Lz => expand(ctx, solid)?,
            BlockKind::Ppm => run_ppmd(ctx, input, solid)?,
        };
        match seg {
            Segment::MemberEnd => break,
            Segment::NewTable => parse_block_header(ctx)?,
            Segment::NewTableThenEnd => {
                parse_block_header(ctx)?;
                if matches!(ctx.block, BlockKind::Ppm) {
                    // A PPMd block starting exactly at the member boundary
                    // would prime its range coder from this member's tail
                    // bytes and keep pulling from the next member's payload
                    // — cross-member coder state we don't support (rar 6.24
                    // starts such blocks with a header in the next member
                    // instead).
                    return Err(Error::Unsupported);
                }
                break;
            }
        }
    }

    if solid && (ctx.out.len() as u64) < ctx.unpack_size {
        // A short member desyncs the shared history for every member after
        // it; fail the group rather than hand back silently-short output.
        return Err(Error::UnexpectedEnd);
    }

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

    Ok(core::mem::take(&mut ctx.out))
}

/// How a run of symbol decoding ended.
enum Segment {
    /// The member is complete (declared size produced and, in solid mode,
    /// the end-of-member marker consumed).
    MemberEnd,
    /// An in-band "new code tables follow" boundary mid-member: parse a
    /// block header and continue decoding this member.
    NewTable,
    /// "New code tables follow" arrived exactly at the member's declared
    /// size: the tables land in this member's tail bytes and the *next*
    /// member continues under them without a header of its own.
    NewTableThenEnd,
}

/// Which decoding mode the current block uses. Persists across solid
/// members: a member may continue a block the previous member started.
enum BlockKind {
    Lz,
    Ppm,
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
    /// The live PPMd model, if any block has created one. Persists across
    /// blocks and solid members: a later PPMd block header without the
    /// reset flag reuses it (with a freshly initialised range coder).
    ppmd: Option<Box<PpmdBlock>>,
    /// Decoding mode of the current block (LZ+Huffman or PPMd).
    block: BlockKind,
    /// Whether valid LZ code tables are in effect, i.e. whether the next
    /// member of a solid group starts decoding symbols directly instead of
    /// parsing a block header first. Cleared by PPMd block headers (a
    /// member after a PPMd block always re-reads a header) and by an
    /// end-of-member marker announcing new tables.
    tables_read: bool,
}

/// A live PPMd model plus the RAR escape layer's current escape byte.
struct PpmdBlock {
    model: Ppmd7,
    /// The RAR-layer escape byte (a decoded symbol equal to this introduces
    /// a control code rather than a literal). Persists across blocks and
    /// members; updated by headers carrying an explicit escape byte.
    escape: u8,
}

/// A declared filter program plus its per-slot remembered block length.
#[derive(Debug, Clone, Copy)]
struct ProgramSlot {
    program: StdProgram,
    last_block_length: u32,
}

impl RunCtx {
    fn new(unpack_size: u64) -> Self {
        RunCtx {
            bits: BitReader::new(),
            // The length table survives across blocks (and solid members):
            // a successive block can signal "keep table" with a single
            // header bit and delta-code against what was most recently
            // decoded.
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
            ppmd: None,
            block: BlockKind::Lz,
            tables_read: false,
        }
    }

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
            // Distance-1 run: one repeated byte, read once before any
            // window write (src is behind window_pos). Bulk-fill both the
            // output and the window in wrap-capped segments.
            let b = self.window[src];
            self.out.resize(self.out.len() + length, b);
            let mut done = 0usize;
            while done < length {
                let run = (length - done).min(wlen - self.window_pos);
                let sp = self.window_pos;
                self.window[sp..sp + run].fill(b);
                self.window_pos = (self.window_pos + run) & wmask;
                done += run;
            }
        } else if off >= length {
            // Non-overlapping: src and dst regions are disjoint (or dst
            // precedes src in the ring, where a forward copy is still
            // exact). `off >= length >= run` and the run is capped against
            // ring wrap on both cursors, so the bulk copies match the
            // per-byte writes exactly — same transformation as the rar2/
            // rar5 match-copy vectorization (#115).
            let mut done = 0usize;
            while done < length {
                let run = (length - done).min(wlen - src).min(wlen - self.window_pos);
                let sp = self.window_pos;
                self.out.extend_from_slice(&self.window[src..src + run]);
                self.window.copy_within(src..src + run, sp);
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
    // 1 bit: PPMd-block flag.
    let is_ppmd = ctx.bits.read_bits(1)?;
    if is_ppmd != 0 {
        // PPMd block header: 7 flag bits, then (per flags) a memory byte
        // and an escape byte.
        //   flag 0x20: model reset — read 8-bit mem → suballocator =
        //              (mem+1)<<20, and order = (flags & 0x1F) + 1 (values
        //              > 16 expand as 16 + (order-16)*3). Without 0x20 the
        //              block *continues* the live model from an earlier
        //              block or solid member (fresh range coder, same
        //              statistics); there must be one.
        //   flag 0x40: read 8-bit escape/InitEsc seed (else escape = 2 on
        //              reset; unchanged on continuation).
        let flags = ctx.bits.read_bits(7)?;
        if flags & 0x20 != 0 {
            let mem_mb = ctx.bits.read_bits(8)?;
            let mem_size = (mem_mb + 1).saturating_mul(1 << 20);
            let mut max_order = (flags & 0x1F) + 1;
            if max_order > 16 {
                max_order = 16 + (max_order - 16) * 3;
            }
            if max_order < 2 {
                return Err(Error::Corrupt);
            }
            let (escape, init_esc) = if flags & 0x40 != 0 {
                let e = ctx.bits.read_bits(8)? as u8;
                (e, Some(e))
            } else {
                (2u8, None)
            };
            let mut model = Ppmd7::new(mem_size)?;
            model.init(max_order);
            if let Some(e) = init_esc {
                model.set_init_esc(e as u32);
            }
            ctx.ppmd = Some(Box::new(PpmdBlock { model, escape }));
        } else {
            let ppmd = ctx.ppmd.as_deref_mut().ok_or(Error::Corrupt)?;
            if flags & 0x40 != 0 {
                // An explicit escape byte updates the escape layer; the
                // live model's InitEsc is a model-creation parameter and
                // stays as-is.
                ppmd.escape = ctx.bits.read_bits(8)? as u8;
            }
            // The order bits are informational on a continuation — the
            // live model keeps the order it was built with.
        }
        ctx.bits.byte_align();
        ctx.block = BlockKind::Ppm;
        // A PPMd block never leaves LZ tables in effect: after a PPMd
        // member, the next member always starts with its own header.
        ctx.tables_read = false;
        return Ok(());
    }
    ctx.block = BlockKind::Lz;
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
    ctx.tables_read = true;
    Ok(())
}

// ─── Expansion ───────────────────────────────────────────────────────────

fn expand(ctx: &mut RunCtx, solid: bool) -> Result<Segment, Error> {
    loop {
        if ctx.done() {
            if solid {
                return read_member_end_lz(ctx);
            }
            return Ok(Segment::MemberEnd);
        }

        // Decode the next main-tree symbol.
        let main_tree = ctx.main.as_ref().ok_or(Error::InvalidHuffmanTree)?;
        let sym = match main_tree.decode(&mut ctx.bits) {
            Ok(s) => s,
            Err(Error::UnexpectedEnd) => {
                if solid {
                    // A short member desyncs the group; `run_member` turns
                    // this into a hard error rather than short output.
                    return Err(Error::UnexpectedEnd);
                }
                // Stream ran out before we've reached unpack_size. The
                // caller's count of output bytes is authoritative.
                return Ok(Segment::MemberEnd);
            }
            Err(e) => return Err(e),
        };

        if sym < 256 {
            ctx.emit_literal(sym as u8);
            continue;
        }

        match sym {
            256 => {
                // End-of-block marker. One bit: set ⇒ new code tables
                // follow immediately (the caller parses a block header —
                // which may also switch this member to PPMd — and decoding
                // continues). Clear ⇒ this member's data ends here; a
                // second bit then announces whether the *next* member of a
                // solid group starts with its own table header or keeps
                // decoding under the current tables. (Framing per the
                // libarchive/unarr RAR readers' descriptions, validated
                // against the solid corpus.)
                let new_table = ctx.bits.read_bits(1)? != 0;
                if new_table {
                    return Ok(Segment::NewTable);
                }
                if solid {
                    let next_has_header = ctx.bits.read_bits(1)? != 0;
                    ctx.tables_read = !next_has_header;
                }
                // For a one-shot stream any further bytes belong to a
                // separate stream; the second marker bit is irrelevant.
                return Ok(Segment::MemberEnd);
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

/// In solid mode, consume the end-of-member marker once the member's
/// declared size has been produced, so `tables_read` reflects what the
/// next member's stream expects. A well-formed member ends with the 256
/// marker; a stream that simply stops (no marker) leaves the tables in
/// effect, and anything else is data beyond the declared size, which we
/// leave unread (the next member's payload is a fresh stream regardless).
fn read_member_end_lz(ctx: &mut RunCtx) -> Result<Segment, Error> {
    let main_tree = ctx.main.as_ref().ok_or(Error::InvalidHuffmanTree)?;
    let sym = match main_tree.decode(&mut ctx.bits) {
        Ok(s) => s,
        Err(Error::UnexpectedEnd) => return Ok(Segment::MemberEnd),
        Err(e) => return Err(e),
    };
    if sym != 256 {
        return Ok(Segment::MemberEnd);
    }
    if ctx.bits.read_bits(1)? != 0 {
        // New tables land in this member's tail; the next member continues
        // symbol decoding under them directly.
        return Ok(Segment::NewTableThenEnd);
    }
    let next_has_header = ctx.bits.read_bits(1)? != 0;
    ctx.tables_read = !next_has_header;
    Ok(Segment::MemberEnd)
}

// ─── PPMd-II variant H block ─────────────────────────────────────────────

/// Drive a RAR PPMd block: the range-coded payload (starting at the bit
/// reader's current byte position) feeds the live [`Ppmd7`] model through
/// the RAR range decoder. Decoded byte symbols are literals unless they
/// equal the escape byte, which introduces a control code (end-of-data, an
/// LZ match, a filter declaration, a new table, or a literal-escape).
/// Matches copy through the same sliding window as the LZ path so they
/// interleave seamlessly. On return the bit reader is repositioned to the
/// byte where the range-coded data ended.
fn run_ppmd(ctx: &mut RunCtx, input: &[u8], solid: bool) -> Result<Segment, Error> {
    ctx.bits.byte_align();
    let payload_start = ctx.bits.consumed_bytes();
    if payload_start > input.len() {
        return Err(Error::UnexpectedEnd);
    }
    // Take the model out of the context so the emit helpers can borrow the
    // context mutably alongside it; it is put back on every path.
    let mut pb = ctx.ppmd.take().ok_or(Error::Corrupt)?;
    let result = run_ppmd_inner(ctx, input, payload_start, &mut pb, solid);
    ctx.ppmd = Some(pb);
    let (seg, end_pos) = result?;
    ctx.bits.seek_byte(end_pos);
    Ok(seg)
}

/// Decode one PPMd symbol, failing closed on range-coder errors and on
/// payload overrun (a truncated payload makes the coder read fabricated
/// zero bytes).
fn ppmd_symbol(m: &mut Ppmd7, rc: &mut RangeDec) -> Result<u8, Error> {
    let s = m.decode_symbol(rc)?;
    if rc.err() {
        return Err(Error::Corrupt);
    }
    if rc.overran() {
        return Err(Error::UnexpectedEnd);
    }
    Ok(s)
}

fn run_ppmd_inner(
    ctx: &mut RunCtx,
    input: &[u8],
    payload_start: usize,
    pb: &mut PpmdBlock,
    solid: bool,
) -> Result<(Segment, usize), Error> {
    let (mut rc, _) = RangeDec::init(RangeMode::Rar, input, payload_start)?;

    loop {
        if ctx.done() {
            if !solid {
                return Ok((Segment::MemberEnd, rc.pos()));
            }
            // The encoder coded this member's end marker through the model;
            // decode it the same way or the shared statistics desync from
            // the encoder's for every later member. If the payload is
            // exhausted right here instead, the member boundary splits a
            // still-running range coder across payloads — cross-member
            // coder state we don't support (rar 6.24 ends PPMd members
            // with an explicit marker).
            let s = ppmd_symbol(&mut pb.model, &mut rc).map_err(|e| match e {
                Error::UnexpectedEnd => Error::Unsupported,
                other => other,
            })?;
            if s != pb.escape {
                return Err(Error::Corrupt);
            }
            let code = ppmd_symbol(&mut pb.model, &mut rc)?;
            return match code {
                2 => Ok((Segment::MemberEnd, rc.pos())),
                0 => Ok((Segment::NewTableThenEnd, rc.pos())),
                _ => Err(Error::Corrupt),
            };
        }
        let s = ppmd_symbol(&mut pb.model, &mut rc)?;
        if s != pb.escape {
            ctx.emit_literal(s);
            continue;
        }
        let code = ppmd_symbol(&mut pb.model, &mut rc)?;
        match code {
            0 => {
                // start-new-table: a fresh block header follows in the bit
                // domain at the coder's byte position (it may keep PPMd
                // with or without a model reset, or switch back to LZ).
                return Ok((Segment::NewTable, rc.pos()));
            }
            2 => {
                // End of PPMd data before the declared size: short member.
                // Solid mode turns this into an error in `run_member`.
                return Ok((Segment::MemberEnd, rc.pos()));
            }
            3 => {
                // A filter declaration carried in the PPMd stream: the same
                // wire layout as main symbol 257, with every byte decoded
                // through the model.
                read_filter_declaration_ppmd(ctx, &mut pb.model, &mut rc)?;
            }
            4 => {
                // 24-bit distance from three symbols (big-endian), then a
                // length symbol. Distance +2, length +32.
                let mut dist = 0u32;
                for i in (0..3).rev() {
                    let b = ppmd_symbol(&mut pb.model, &mut rc)? as u32;
                    dist |= b << (i * 8);
                }
                let len = ppmd_symbol(&mut pb.model, &mut rc)? as u32;
                ctx.emit_match(dist + 2, len + 32)?;
            }
            5 => {
                // Distance-1 run: length symbol, length +4.
                let len = ppmd_symbol(&mut pb.model, &mut rc)? as u32;
                ctx.emit_match(1, len + 4)?;
            }
            _ => {
                // Any other control code encodes a literal equal to the
                // escape byte (the control symbol is consumed and dropped).
                ctx.emit_literal(pb.escape);
            }
        }
    }
}

/// Parse a filter declaration whose bytes arrive as PPMd symbols (escape
/// code 3): an 8-bit flags byte, a 1/2/3-byte length field, then `length`
/// payload bytes forming the same self-contained declaration payload the
/// bit-domain parser (main symbol 257) reads.
fn read_filter_declaration_ppmd(
    ctx: &mut RunCtx,
    model: &mut Ppmd7,
    rc: &mut RangeDec,
) -> Result<(), Error> {
    let flags = ppmd_symbol(model, rc)? as u32;
    let mut decl_len = (flags & 0x07) + 1;
    if decl_len == 7 {
        decl_len = ppmd_symbol(model, rc)? as u32 + 7;
    } else if decl_len == 8 {
        let hi = ppmd_symbol(model, rc)? as u32;
        let lo = ppmd_symbol(model, rc)? as u32;
        decl_len = (hi << 8) | lo;
    }
    if decl_len == 0 {
        return Err(Error::Corrupt);
    }
    let mut payload = vec![0u8; decl_len as usize];
    for b in payload.iter_mut() {
        *b = ppmd_symbol(model, rc)?;
    }
    let mut db = BitReader::new();
    db.feed_slice(&payload);
    parse_declaration_payload(ctx, flags, &mut db).map_err(|e| match e {
        Error::UnexpectedEnd => Error::Corrupt,
        other => other,
    })
}

// ─── In-band filter declarations (main symbol 257) ──────────────────────

/// Upper bound on a filter's block length: the RarVM memory the standard
/// programs operate in (0x40000 bytes — modern unrar lets a block use all
/// of it). Delta needs separate source and destination halves, so its
/// windows are capped at half that. Real encoders stay far below both caps
/// and split large regions into several filter blocks. Beyond the cap
/// UnRAR 7.23 skips the transform and emits the raw bytes with success;
/// this crate fails closed instead (same policy as unfinished windows).
const FILTER_MAX_BLOCK: u32 = 0x40000;
const FILTER_MAX_BLOCK_DELTA: u32 = 0x20000;

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
            // Full reset (unrar's InitFilters30): cancel every scheduled
            // filter — *including* ones whose windows are complete but not
            // yet applied. unrar executes filters only when it flushes
            // decoded output, which lags decoding by up to a window, so a
            // reset discards them and their windows stay raw bytes. (For
            // multi-window outputs the reference may have flushed — and
            // applied — earlier filters before the reset; real encoders
            // only reset at stream start, so that corner stays unmodeled.)
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
            ppmd: None,
            block: BlockKind::Lz,
            tables_read: false,
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

    /// A reset declaration (slot field 0) cancels every scheduled filter —
    /// including completed-but-unapplied windows. unrar's InitFilters30
    /// discards its whole filter stack (execution happens at output-flush
    /// time, which lags decoding), so those windows stay raw bytes; a
    /// canceled filter must never rewrite output.
    #[test]
    fn reset_cancels_all_pending_without_applying() {
        let mut ctx = test_ctx();
        ctx.out = vec![1, 0, 0, 0, 9, 9, 9, 9];
        ctx.programs.push(ProgramSlot {
            program: StdProgram::Delta,
            last_block_length: 4,
        });
        // A completed-but-unapplied window plus an incomplete one.
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

        // Nothing ran: both prior filters were canceled outright.
        assert_eq!(ctx.out, vec![1, 0, 0, 0, 9, 9, 9, 9]);
        // Only the fresh declaration (window at out position 8) is
        // scheduled against the fresh slot table.
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
        let mut ctx = test_ctx();
        ctx.old_offsets = [10, 20, 30, 40];
        // Promote slot 2 (value 30) — result should be [30, 10, 20, 40].
        promote_offset(&mut ctx, 2, 30);
        assert_eq!(ctx.old_offsets, [30, 10, 20, 40]);
    }
}
