//! RAR 2.x decoder.
//!
//! The decoder consumes a single contiguous compressed block produced by the
//! historical `rar` 2.0–2.9 archiver. It supports both regular blocks
//! (literal-or-match) and audio blocks (per-channel delta prediction).
//!
//! ## Streaming model
//!
//! RAR2 does not carry an in-band block-length field; the decoder is told the
//! decompressed size out of band via [`Decoder::with_unpack_size`]. Bytes are
//! buffered until [`finish`](crate::Decoder::finish) is called, at which point
//! the entire block is decoded into an internal output buffer and then drained
//! to the caller across one or more `finish` calls.
//!
//! `decode` simply accumulates input; it never emits output and never returns
//! `consumed == 0` unless the caller supplied an empty slice.
//!
//! Output is bounded by the `unpack_size` configured on the decoder; once that
//! many bytes have been produced, the decoder stops requesting Huffman symbols
//! and signals `done` from `finish`.
//!
//! ## Format summary (re-implementation, not copied)
//!
//! Each block begins with two flag bits:
//! - **audio_block** (1 bit): if set, the block is an audio block.
//! - **keep_lengths** (1 bit): if clear, the length table is zeroed before
//!   reading; if set, deltas from the previous block's lengths are kept.
//!
//! For audio blocks, two more bits encode `numchannels-1`, then the length
//! table is `numchannels * 257` entries long; for regular blocks the length
//! table covers `298 + 48 + 28 = 374` entries: main tree, offset tree,
//! length tree.
//!
//! The length table is itself Huffman-coded. First, 19 4-bit lengths form a
//! "pretree" prefix code; then the pretree decodes a sequence of values:
//! - `0..=15`: `lens[i] = (lens[i] + val) & 0x0F; i++;` (delta from prior)
//! - `16`: read 2 bits → `n = val + 3`; repeat `lens[i-1]` `n` times.
//! - `17`: read 3 bits → `n = val + 3`; insert `n` zeros.
//! - `18`: read 7 bits → `n = val + 11`; insert `n` zeros.
//!
//! Once trees are built, the main loop pulls symbols from `maincode` until
//! the unpack_size is reached:
//! - `0..=255`: literal byte.
//! - `256`: repeat the last match (same length & offset).
//! - `257..=260`: pick one of the last four offsets, read a length symbol
//!   for the length, and adjust the length by 0..=3 if offset is large.
//! - `261..=268`: short match of length 2; the offset is `SHORT_BASE +
//!   read_bits(SHORT_EXTRA)`.
//! - `269`: re-read the trees (start a new sub-block).
//! - `270..=297`: long match; the length comes from `LENGTH_BASE[sym-270] +
//!   read(LENGTH_EXTRA)`, the offset comes from an offset-tree symbol.

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;
use crate::traits::{Decoder as DecoderTrait, Progress};

use super::audio::{AudioState, decode_sample};
use super::bitreader::BitReader;
use super::huffman::Rar2Huffman;
use super::tables::{
    AUDIO_TREE_SIZE, LENGTH_BASE, LENGTH_EXTRA, LENGTH_TABLE_SIZE, LENGTH_TREE_SIZE,
    MAIN_TREE_SIZE, NON_AUDIO_LENGTHS, OFFSET_BASE, OFFSET_EXTRA, OFFSET_TREE_SIZE, PRETREE_SIZE,
    SHORT_BASE, SHORT_EXTRA, SYM_LONG_FIRST, SYM_OLD_OFFSET_END, SYM_REPEAT_LAST, SYM_REREAD_TREES,
    SYM_SHORT_FIRST, SYM_SHORT_LAST, WINDOW_MASK, WINDOW_SIZE,
};

/// Streaming RAR 2.x decoder. See module docs for the streaming model.
pub struct Decoder {
    /// Configured unpacked output size in bytes. `None` means "unknown" — the
    /// caller created the decoder with [`Decoder::new`] and must use
    /// [`Decoder::with_unpack_size`] (or its setter equivalent) before
    /// feeding input.
    unpack_size: u64,
    /// Have we been given an unpack size? `new()` defaults to 0, which is
    /// treated as a zero-output stream (trivially-empty).
    have_unpack_size: bool,
    /// Buffered compressed input.
    input_buf: Vec<u8>,
    /// Internal decompressed output buffer.
    output: Vec<u8>,
    /// How many bytes of `output` have been drained to the caller.
    drained: usize,
    /// Has `finish` been called and the decode actually run?
    decoded: bool,
    /// Sticky error (after one corrupt return everything errors).
    poisoned: bool,
}

impl Decoder {
    /// Construct a decoder. Without [`with_unpack_size`] the decoder treats
    /// the stream as zero-length — useful for the trait-default factory
    /// path. Call [`set_unpack_size`] before `decode` to actually decompress
    /// data.
    pub const fn new() -> Self {
        Self {
            unpack_size: 0,
            have_unpack_size: false,
            input_buf: Vec::new(),
            output: Vec::new(),
            drained: 0,
            decoded: false,
            poisoned: false,
        }
    }

    /// Construct a decoder configured to produce exactly `n` decompressed
    /// bytes. RAR2 streams don't self-delimit so callers must supply this
    /// out of band (it lives in the file header, not the data block).
    pub fn with_unpack_size(n: u64) -> Self {
        let mut d = Self::new();
        d.set_unpack_size(n);
        d
    }

    /// Set the expected decompressed length. May only be called before any
    /// input has been fed.
    pub fn set_unpack_size(&mut self, n: u64) {
        self.unpack_size = n;
        self.have_unpack_size = true;
    }
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

impl DecoderTrait for Decoder {
    fn decode(&mut self, input: &[u8], _output: &mut [u8]) -> Result<Progress, Error> {
        if self.poisoned {
            return Err(Error::Corrupt);
        }
        if self.decoded {
            // After finish has triggered the decode, more input is illegal —
            // tolerate empty calls but reject content.
            if !input.is_empty() {
                return Err(self.poison(Error::Corrupt));
            }
            return Ok(Progress::default());
        }
        // Buffer everything; we don't have a way to know where a sub-block
        // ends without decoding it, so we keep the whole compressed payload
        // in memory until finish is called.
        self.input_buf.extend_from_slice(input);
        Ok(Progress {
            consumed: input.len(),
            written: 0,
            done: false,
        })
    }

    fn finish(&mut self, output: &mut [u8]) -> Result<Progress, Error> {
        if self.poisoned {
            return Err(Error::Corrupt);
        }
        if !self.decoded {
            // First call: run the actual decompression now that we've seen
            // the whole compressed payload.
            self.run_decode()?;
            self.decoded = true;
        }
        let remaining = self.output.len() - self.drained;
        let n = remaining.min(output.len());
        if n > 0 {
            output[..n].copy_from_slice(&self.output[self.drained..self.drained + n]);
            self.drained += n;
        }
        let done = self.drained == self.output.len();
        Ok(Progress {
            consumed: 0,
            written: n,
            done,
        })
    }

    fn reset(&mut self) {
        self.input_buf.clear();
        self.output.clear();
        self.drained = 0;
        self.decoded = false;
        self.poisoned = false;
        // unpack_size and have_unpack_size persist; callers re-set them if
        // the next stream is a different size.
    }
}

impl Decoder {
    fn poison(&mut self, e: Error) -> Error {
        self.poisoned = true;
        e
    }

    /// Run the full decompression. Called once, from the first `finish`.
    fn run_decode(&mut self) -> Result<(), Error> {
        // Trivial cases.
        if self.unpack_size == 0 {
            return Ok(());
        }
        // Sanity: refuse pathological sizes that would overflow usize on
        // 32-bit hosts.
        if self.unpack_size > usize::MAX as u64 {
            return Err(self.poison(Error::Unsupported));
        }
        let target = self.unpack_size as usize;
        self.output.reserve_exact(target);

        let mut ctx = Box::new(RunCtx::new(target));
        let input = core::mem::take(&mut self.input_buf);
        let result = ctx.run(&input, &mut self.output);
        // Even on error, hand back the buffer so subsequent reset() doesn't
        // need to reallocate (cosmetic; we ignore on failure).
        self.input_buf = input;
        if let Err(e) = result {
            return Err(self.poison(e));
        }
        if self.output.len() != target {
            return Err(self.poison(Error::UnexpectedEnd));
        }
        Ok(())
    }
}

// ----------------------------------------------------------------------------
// Decompression context
// ----------------------------------------------------------------------------

struct RunCtx {
    target: usize,

    bit: BitReader,
    window: Vec<u8>,
    window_pos: usize,

    /// Cumulative length table; spans both audio (1028) and non-audio (374)
    /// alphabets. After block 1, the previous block's values are kept and
    /// further deltas are applied on top (per the 16-modulo wrap).
    lengths: [u8; LENGTH_TABLE_SIZE],

    /// Most recent main symbol — used by sym 256 ("repeat last match").
    last_length: u16,
    last_offset: u32,
    /// Sliding window of the last four offsets, indexed by `(idx - k) & 3`.
    old_offset: [u32; 4],
    /// Next write slot in `old_offset` (post-increment).
    old_offset_index: usize,

    /// Per-block flags / state.
    in_audio_block: bool,
    num_channels: usize,
    channel: usize,
    channel_delta: i32,
    audio_state: [AudioState; 4],

    main_code: Option<Box<Rar2Huffman<MAIN_TREE_SIZE>>>,
    offset_code: Option<Box<Rar2Huffman<OFFSET_TREE_SIZE>>>,
    length_code: Option<Box<Rar2Huffman<LENGTH_TREE_SIZE>>>,
    audio_code: [Option<Box<Rar2Huffman<AUDIO_TREE_SIZE>>>; 4],
}

impl RunCtx {
    fn new(target: usize) -> Self {
        Self {
            target,
            bit: BitReader::new(),
            window: vec![0u8; WINDOW_SIZE],
            window_pos: 0,
            lengths: [0u8; LENGTH_TABLE_SIZE],
            last_length: 0,
            last_offset: 0,
            old_offset: [0u32; 4],
            old_offset_index: 0,
            in_audio_block: false,
            num_channels: 0,
            channel: 0,
            channel_delta: 0,
            audio_state: [
                AudioState::new(),
                AudioState::new(),
                AudioState::new(),
                AudioState::new(),
            ],
            main_code: None,
            offset_code: None,
            length_code: None,
            audio_code: [None, None, None, None],
        }
    }

    fn run(&mut self, input: &[u8], output: &mut Vec<u8>) -> Result<(), Error> {
        // Read first block header.
        self.read_block_header(input)?;

        while output.len() < self.target {
            if self.in_audio_block {
                let tree = self.audio_code[self.channel]
                    .as_ref()
                    .ok_or(Error::Corrupt)?;
                let sym = tree.decode(&mut self.bit, input)?;
                if sym == 256 {
                    // Re-read trees and continue.
                    self.read_block_header(input)?;
                    continue;
                }
                if sym > 255 {
                    return Err(Error::Corrupt);
                }
                let byte = decode_sample(
                    &mut self.audio_state[self.channel],
                    &mut self.channel_delta,
                    sym as u8,
                );
                self.emit_literal(byte, output);
                self.channel += 1;
                if self.channel >= self.num_channels {
                    self.channel = 0;
                }
            } else {
                let tree = self.main_code.as_ref().ok_or(Error::Corrupt)?;
                let sym = tree.decode(&mut self.bit, input)?;
                if sym < 256 {
                    self.emit_literal(sym as u8, output);
                    continue;
                }
                if sym == SYM_REPEAT_LAST {
                    let len = self.last_length;
                    let off = self.last_offset;
                    if len == 0 || off == 0 {
                        return Err(Error::Corrupt);
                    }
                    self.emit_match(off, len, output)?;
                } else if sym <= SYM_OLD_OFFSET_END {
                    let slot = (self
                        .old_offset_index
                        .wrapping_sub((sym - SYM_REPEAT_LAST) as usize))
                        & 3;
                    let off = self.old_offset[slot];
                    if off == 0 {
                        return Err(Error::Corrupt);
                    }
                    let length_tree = self.length_code.as_ref().ok_or(Error::Corrupt)?;
                    let len_sym = length_tree.decode(&mut self.bit, input)? as usize;
                    if len_sym >= LENGTH_BASE.len() {
                        return Err(Error::Corrupt);
                    }
                    let mut len = LENGTH_BASE[len_sym] as u32 + 2;
                    let extra = LENGTH_EXTRA[len_sym] as u32;
                    if extra > 0 {
                        len += self.bit.read_bits(extra, input)?;
                    }
                    if off >= 0x40000 {
                        len += 1;
                    }
                    if off >= 0x2000 {
                        len += 1;
                    }
                    if off >= 0x101 {
                        len += 1;
                    }
                    // XADRAR20Handle pushes `offs` into both `lastoffset` and
                    // `oldoffset[idx&3]` unconditionally — even for symbols
                    // that originally read it from the LRU. We match that.
                    self.commit_match_offset(off);
                    self.last_length = len as u16;
                    self.emit_match(self.last_offset, len as u16, output)?;
                } else if sym <= SYM_SHORT_LAST {
                    let idx = (sym - SYM_SHORT_FIRST) as usize;
                    let mut off = SHORT_BASE[idx] + 1;
                    let extra = SHORT_EXTRA[idx] as u32;
                    if extra > 0 {
                        off += self.bit.read_bits(extra, input)?;
                    }
                    self.commit_match_offset(off);
                    self.last_length = 2;
                    self.emit_match(off, 2, output)?;
                } else if sym == SYM_REREAD_TREES {
                    self.read_block_header(input)?;
                    continue;
                } else if (SYM_LONG_FIRST..(SYM_LONG_FIRST + LENGTH_BASE.len() as u16))
                    .contains(&sym)
                {
                    let len_idx = (sym - SYM_LONG_FIRST) as usize;
                    let mut len = LENGTH_BASE[len_idx] as u32 + 3;
                    let extra = LENGTH_EXTRA[len_idx] as u32;
                    if extra > 0 {
                        len += self.bit.read_bits(extra, input)?;
                    }
                    let offset_tree = self.offset_code.as_ref().ok_or(Error::Corrupt)?;
                    let off_sym = offset_tree.decode(&mut self.bit, input)? as usize;
                    if off_sym >= OFFSET_BASE.len() {
                        return Err(Error::Corrupt);
                    }
                    let mut off = OFFSET_BASE[off_sym] + 1;
                    let off_extra = OFFSET_EXTRA[off_sym] as u32;
                    if off_extra > 0 {
                        off += self.bit.read_bits(off_extra, input)?;
                    }
                    if off >= 0x40000 {
                        len += 1;
                    }
                    if off >= 0x2000 {
                        len += 1;
                    }
                    self.commit_match_offset(off);
                    self.last_length = len as u16;
                    self.emit_match(off, len as u16, output)?;
                } else {
                    return Err(Error::Corrupt);
                }
            }
        }
        Ok(())
    }

    /// Read the per-block header: flag bits + length-table delta + tree
    /// construction. Called at the start of every block and on every
    /// `sym == 269` / audio `sym == 256` "restart" signal.
    fn read_block_header(&mut self, input: &[u8]) -> Result<(), Error> {
        self.in_audio_block = self.bit.read_bits(1, input)? == 1;
        let keep_lengths = self.bit.read_bits(1, input)? == 1;
        if !keep_lengths {
            self.lengths = [0u8; LENGTH_TABLE_SIZE];
        }

        let count: usize = if self.in_audio_block {
            self.num_channels = self.bit.read_bits(2, input)? as usize + 1;
            if self.channel >= self.num_channels {
                self.channel = 0;
            }
            self.num_channels * AUDIO_TREE_SIZE
        } else {
            NON_AUDIO_LENGTHS
        };
        if count > LENGTH_TABLE_SIZE {
            return Err(Error::Corrupt);
        }

        // Read the 19 pretree lengths (4 bits each).
        let mut pre_lens = [0u8; PRETREE_SIZE];
        for slot in pre_lens.iter_mut() {
            *slot = self.bit.read_bits(4, input)? as u8;
        }
        let pre = Rar2Huffman::<PRETREE_SIZE>::from_lengths(&pre_lens)?;

        // Decode `count` symbols into the length table.
        let mut i = 0usize;
        while i < count {
            let val = pre.decode(&mut self.bit, input)?;
            if val < 16 {
                self.lengths[i] = (self.lengths[i].wrapping_add(val as u8)) & 0x0F;
                i += 1;
            } else if val == 16 {
                if i == 0 {
                    return Err(Error::Corrupt);
                }
                let n = self.bit.read_bits(2, input)? as usize + 3;
                let v = self.lengths[i - 1];
                let stop = (i + n).min(count);
                while i < stop {
                    self.lengths[i] = v;
                    i += 1;
                }
            } else {
                let n: usize = if val == 17 {
                    self.bit.read_bits(3, input)? as usize + 3
                } else {
                    self.bit.read_bits(7, input)? as usize + 11
                };
                let stop = (i + n).min(count);
                while i < stop {
                    self.lengths[i] = 0;
                    i += 1;
                }
            }
        }

        if self.in_audio_block {
            // Build per-channel audio codes.
            for c in 0..self.num_channels {
                let start = c * AUDIO_TREE_SIZE;
                let slice = &self.lengths[start..start + AUDIO_TREE_SIZE];
                self.audio_code[c] = Some(Box::new(Rar2Huffman::from_lengths(slice)?));
            }
            for c in self.num_channels..4 {
                self.audio_code[c] = None;
            }
            self.main_code = None;
            self.offset_code = None;
            self.length_code = None;
        } else {
            let main =
                Rar2Huffman::<MAIN_TREE_SIZE>::from_lengths(&self.lengths[0..MAIN_TREE_SIZE])?;
            let offset = Rar2Huffman::<OFFSET_TREE_SIZE>::from_lengths(
                &self.lengths[MAIN_TREE_SIZE..MAIN_TREE_SIZE + OFFSET_TREE_SIZE],
            )?;
            let length = Rar2Huffman::<LENGTH_TREE_SIZE>::from_lengths(
                &self.lengths[MAIN_TREE_SIZE + OFFSET_TREE_SIZE
                    ..MAIN_TREE_SIZE + OFFSET_TREE_SIZE + LENGTH_TREE_SIZE],
            )?;
            self.main_code = Some(Box::new(main));
            self.offset_code = Some(Box::new(offset));
            self.length_code = Some(Box::new(length));
            for c in 0..4 {
                self.audio_code[c] = None;
            }
        }
        Ok(())
    }

    /// Stash `off` into the LRU slot and update `last_offset`. Mirrors
    /// XADRAR20Handle's
    ///   lastoffset = oldoffset[oldoffsetindex++ & 3] = offs;
    fn commit_match_offset(&mut self, off: u32) {
        let slot = self.old_offset_index & 3;
        self.old_offset[slot] = off;
        self.last_offset = off;
        self.old_offset_index = self.old_offset_index.wrapping_add(1);
    }

    fn emit_literal(&mut self, byte: u8, output: &mut Vec<u8>) {
        self.window[self.window_pos] = byte;
        self.window_pos = (self.window_pos + 1) & WINDOW_MASK;
        output.push(byte);
    }

    fn emit_match(&mut self, offset: u32, length: u16, output: &mut Vec<u8>) -> Result<(), Error> {
        if length == 0 {
            return Err(Error::Corrupt);
        }
        let off = offset as usize;
        if off == 0 || off > WINDOW_SIZE {
            return Err(Error::InvalidDistance);
        }
        // We allow `off` to point anywhere in the window — including bytes
        // that have never been written (they're zero-initialized). This
        // matches XADRAR20Handle's behaviour and the LZSS contract.
        let mut remaining = length as usize;
        // Cap remaining at the unpack target so a runaway match length can't
        // overshoot the buffer.
        let cap = self.target - output.len();
        if remaining > cap {
            remaining = cap;
        }
        while remaining > 0 {
            let src = (self.window_pos + WINDOW_SIZE - off) & WINDOW_MASK;
            let b = self.window[src];
            self.window[self.window_pos] = b;
            self.window_pos = (self.window_pos + 1) & WINDOW_MASK;
            output.push(b);
            remaining -= 1;
        }
        Ok(())
    }
}
