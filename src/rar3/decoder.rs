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
//! - The standalone E8/E9 post-pass filter when enabled via
//!   [`Decoder::with_e8_filter`].
//!
//! ## What's refused
//!
//! - **PPMd-II blocks** (the bit-0 flag in the block header). PPMd-II is a
//!   ~1500-line context-mixed arithmetic coder; implementing it faithfully
//!   is out of scope for this build. Streams containing a PPMd block fail
//!   with `Error::Unsupported`.
//! - **In-band VM filter declarations** (main symbols 257..=261 that emit
//!   bytecode for the RarVM interpreter). These also fail with
//!   `Error::Unsupported`. The standalone E8/E9 filter remains available.
//! - **Dictionary sizes** other than the default 4 MiB. Streams compressed
//!   with smaller dictionaries decode correctly with the larger window —
//!   the larger window doesn't change semantics.

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;
use crate::traits::{RawDecoder, RawProgress};

use super::bits::BitReader;
use super::filters::apply_e8_filter;
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
    });

    // The decoder starts by parsing the first block header.
    parse_block_header(&mut ctx)?;
    expand(&mut ctx)?;

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
        for _ in 0..length {
            let src = (self.window_pos + wlen - off) & wmask;
            let b = self.window[src];
            self.out.push(b);
            self.window[self.window_pos] = b;
            self.window_pos = (self.window_pos + 1) & wmask;
            if (self.out.len() as u64) >= self.unpack_size {
                break;
            }
        }
        Ok(())
    }

    fn done(&self) -> bool {
        (self.out.len() as u64) >= self.unpack_size
    }
}

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
                // Filter program declaration — refuse.
                return Err(Error::Unsupported);
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
        };
        // Promote slot 2 (value 30) — result should be [30, 10, 20, 40].
        promote_offset(&mut ctx, 2, 30);
        assert_eq!(ctx.old_offsets, [30, 10, 20, 40]);
    }
}
