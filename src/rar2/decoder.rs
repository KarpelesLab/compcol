//! RAR 2.x decoder.
//!
//! The decoder consumes a single contiguous compressed block produced by the
//! historical `rar` 2.0–2.9 archiver. It supports both regular blocks
//! (literal-or-match) and audio blocks (per-channel delta prediction).
//!
//! ## Streaming model
//!
//! RAR2 does not carry an in-band length or end marker; the decoder is told
//! the decompressed size out of band via [`Decoder::with_unpack_size`] and
//! stops after exactly that many bytes.
//!
//! Output is streamed. The decoder keeps the fixed 1 MiB sliding window and
//! decodes symbols only while fewer than 64 KiB of decoded bytes are waiting
//! for the caller, so what it holds of the *output* never depends on the
//! declared size: a hostile `unpack_size` costs nothing until the caller has
//! actually taken the bytes. Both [`decode`](crate::Decoder::decode) and
//! [`finish`](crate::Decoder::finish) hand bytes out as they are produced.
//!
//! Input is buffered: `decode` always accepts everything it is given (so a
//! call with an empty output slice just queues input), and the consumed
//! prefix is dropped as decoding moves past it. A symbol that needs more
//! bits than are buffered is retried from its saved bit position once more
//! input arrives; in `finish` it is a truncation error instead.
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
use crate::traits::{RawDecoder, RawProgress};

use super::audio::{AudioState, decode_sample};
use super::bitreader::BitReader;
use super::huffman::Rar2Huffman;
use super::tables::{
    AUDIO_TREE_SIZE, LENGTH_BASE, LENGTH_EXTRA, LENGTH_TABLE_SIZE, LENGTH_TREE_SIZE,
    MAIN_TREE_SIZE, NON_AUDIO_LENGTHS, OFFSET_BASE, OFFSET_EXTRA, OFFSET_TREE_SIZE, PRETREE_SIZE,
    SHORT_BASE, SHORT_EXTRA, SYM_LONG_FIRST, SYM_OLD_OFFSET_END, SYM_REPEAT_LAST, SYM_REREAD_TREES,
    SYM_SHORT_FIRST, SYM_SHORT_LAST, WINDOW_MASK, WINDOW_SIZE,
};

/// Symbol decoding pauses once this many decoded bytes are waiting for the
/// caller. The waiting bytes live in the sliding window itself, so the bound
/// (plus one match, [`MAX_MATCH_LEN`]) must stay well below the window size
/// or a paused decoder could overwrite bytes it has not handed out yet.
const PENDING_HIGH_WATER: usize = 64 * 1024;

/// Longest match the format can express: length base 224 + 31 from five
/// extra bits, + 3 for a long match, + 2 distance adjustments (the
/// old-offset form is + 2 and + 3 adjustments, the same total).
const MAX_MATCH_LEN: usize = 224 + 31 + 3 + 2;

const _: () = assert!(PENDING_HIGH_WATER + MAX_MATCH_LEN < WINDOW_SIZE);

/// Consumed input is dropped from the front of the buffer once at least
/// this much of it (and at least half the buffer) is behind the bit reader.
const INPUT_COMPACT_MIN: usize = 4096;

/// Streaming RAR 2.x decoder. See module docs for the streaming model.
pub struct Decoder {
    /// Configured unpacked output size in bytes.
    unpack_size: u64,
    /// Have we been given an unpack size? `new()` defaults to 0, which is
    /// treated as a zero-output stream (trivially-empty).
    have_unpack_size: bool,
    /// Compressed input not yet moved past by the bit reader.
    input_buf: Vec<u8>,
    /// Decompression state (window, trees, bit position). Allocated when
    /// the first symbol is decoded, dropped by `reset`.
    ctx: Option<Box<RunCtx>>,
    /// `finish` has been called: no more input is coming, so running out of
    /// bits is an error rather than a reason to wait.
    finishing: bool,
    /// A decode error raised while bytes decoded before it were still
    /// waiting; reported once those bytes have been handed out.
    pending_err: Option<Error>,
    /// Sticky error (after one corrupt return everything errors).
    poisoned: bool,
}

impl Decoder {
    /// Construct a decoder. Without [`Self::with_unpack_size`] the decoder
    /// treats the stream as zero-length — useful for the trait-default
    /// factory path. Call [`Self::set_unpack_size`] before `decode` to
    /// actually decompress data.
    pub const fn new() -> Self {
        Self {
            unpack_size: 0,
            have_unpack_size: false,
            input_buf: Vec::new(),
            ctx: None,
            finishing: false,
            pending_err: None,
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

    /// Decoded bytes currently held for the caller (testing aid: shows the
    /// decoder does not build its output ahead of the caller's reads).
    #[doc(hidden)]
    pub fn buffered_output_len(&self) -> usize {
        self.ctx.as_ref().map_or(0, |c| c.pending)
    }

    /// Compressed bytes currently buffered (testing aid).
    #[doc(hidden)]
    pub fn buffered_input_len(&self) -> usize {
        self.input_buf.len()
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
        if self.finishing && !input.is_empty() {
            // `finish` declared the input complete; more of it is illegal.
            return Err(self.poison(Error::Corrupt));
        }
        if self.is_done() {
            // Terminal: whatever follows the member (padding, the next
            // archive header) is not ours to consume.
            return Ok(RawProgress {
                consumed: 0,
                written: 0,
                done: true,
            });
        }
        // Take all of it: without decoding there is no way to know how many
        // bytes the next symbols need, and callers may pass an empty output
        // slice just to queue input.
        self.input_buf.extend_from_slice(input);
        let (written, done) = self.pump(output)?;
        Ok(RawProgress {
            consumed: input.len(),
            written,
            done,
        })
    }

    fn raw_finish(&mut self, output: &mut [u8]) -> Result<RawProgress, Error> {
        if self.poisoned {
            return Err(Error::Corrupt);
        }
        self.finishing = true;
        let (written, done) = self.pump(output)?;
        Ok(RawProgress {
            consumed: 0,
            written,
            done,
        })
    }

    fn raw_reset(&mut self) {
        self.input_buf.clear();
        // The window must read as zeros again, so drop it rather than keep
        // it; the next stream allocates a fresh one.
        self.ctx = None;
        self.finishing = false;
        self.pending_err = None;
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

    /// Everything declared has been decoded and handed out.
    fn is_done(&self) -> bool {
        if self.pending_err.is_some() {
            return false;
        }
        match &self.ctx {
            Some(c) => c.pending == 0 && c.produced == self.unpack_size,
            None => self.unpack_size == 0,
        }
    }

    /// Hand waiting bytes to `output` and decode more while there is room
    /// for them. Returns `(written, done)`.
    fn pump(&mut self, output: &mut [u8]) -> Result<(usize, bool), Error> {
        let target = self.unpack_size;
        let mut written = 0usize;
        loop {
            let (pending, produced) = match &mut self.ctx {
                Some(c) => {
                    written += c.drain(&mut output[written..]);
                    (c.pending, c.produced)
                }
                None => (0, 0),
            };
            if pending == 0 {
                if let Some(e) = self.pending_err {
                    if written > 0 {
                        // Report the bytes that preceded the error first;
                        // the next call returns it.
                        return Ok((written, false));
                    }
                    self.pending_err = None;
                    return Err(self.poison(e));
                }
                if produced == target {
                    return Ok((written, true));
                }
            }
            // Decode only when the caller has room for the result. The one
            // exception is a `finish` with nothing waiting: it has to decode
            // to find out whether the stream ends or is truncated, even when
            // `output` is full (or empty).
            if written == output.len() && (pending > 0 || !self.finishing) {
                return Ok((written, false));
            }

            let ctx = self.ctx.get_or_insert_with(|| Box::new(RunCtx::new()));
            let result = ctx.fill(&self.input_buf, target);
            let more_pending = ctx.pending > pending;

            // Drop the input the bit reader has moved past. Only whole
            // steps move it (a failed step rewinds), so nothing still
            // needed is discarded.
            let pos = ctx.bit.byte_pos();
            if pos >= INPUT_COMPACT_MIN && pos >= self.input_buf.len() / 2 {
                self.input_buf.drain(..pos);
                ctx.bit.rebase(pos);
            }

            match result {
                Ok(()) => {}
                Err(Error::UnexpectedEnd) if !self.finishing => {
                    // The next symbol needs input that has not arrived yet.
                    if !more_pending {
                        return Ok((written, false));
                    }
                }
                Err(e) => self.pending_err = Some(e),
            }
        }
    }
}

// ----------------------------------------------------------------------------
// Decompression context
// ----------------------------------------------------------------------------

struct RunCtx {
    bit: BitReader,
    window: Vec<u8>,
    window_pos: usize,
    /// Bytes written to the window that the caller has not been given yet:
    /// the `pending` bytes ending at `window_pos`.
    pending: usize,
    /// Total bytes decoded so far.
    produced: u64,
    /// Has the first block header been read?
    started: bool,

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
    fn new() -> Self {
        Self {
            bit: BitReader::new(),
            window: vec![0u8; WINDOW_SIZE],
            window_pos: 0,
            pending: 0,
            produced: 0,
            started: false,
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

    /// Move waiting bytes out of the window into `out`; returns how many.
    fn drain(&mut self, out: &mut [u8]) -> usize {
        let n = self.pending.min(out.len());
        if n == 0 {
            return 0;
        }
        let start = (self.window_pos + WINDOW_SIZE - self.pending) & WINDOW_MASK;
        let first = n.min(WINDOW_SIZE - start);
        out[..first].copy_from_slice(&self.window[start..start + first]);
        out[first..n].copy_from_slice(&self.window[..n - first]);
        self.pending -= n;
        n
    }

    /// Decode until [`PENDING_HIGH_WATER`] bytes are waiting, `target` bytes
    /// have been produced in total, or a step fails.
    ///
    /// Each step (one symbol with everything that belongs to it, or a block
    /// header) is atomic with respect to running out of input: nothing but
    /// the bit position changes before its last read, and that is rewound
    /// here, so after `Err(UnexpectedEnd)` the same step can simply be
    /// retried with more input.
    fn fill(&mut self, input: &[u8], target: u64) -> Result<(), Error> {
        while self.pending < PENDING_HIGH_WATER && self.produced < target {
            let saved = self.bit;
            if let Err(e) = self.step(input, target) {
                self.bit = saved;
                return Err(e);
            }
        }
        Ok(())
    }

    fn step(&mut self, input: &[u8], target: u64) -> Result<(), Error> {
        if !self.started {
            self.read_block_header(input)?;
            self.started = true;
            return Ok(());
        }
        if self.in_audio_block {
            let tree = self.audio_code[self.channel]
                .as_ref()
                .ok_or(Error::Corrupt)?;
            let sym = tree.decode(&mut self.bit, input)?;
            if sym == 256 {
                // Re-read trees and continue.
                return self.read_block_header(input);
            }
            if sym > 255 {
                return Err(Error::Corrupt);
            }
            let byte = decode_sample(
                &mut self.audio_state[self.channel],
                &mut self.channel_delta,
                sym as u8,
            );
            self.emit_literal(byte);
            self.channel += 1;
            if self.channel >= self.num_channels {
                self.channel = 0;
            }
            return Ok(());
        }

        let tree = self.main_code.as_ref().ok_or(Error::Corrupt)?;
        let sym = tree.decode(&mut self.bit, input)?;
        if sym < 256 {
            self.emit_literal(sym as u8);
            return Ok(());
        }
        if sym == SYM_REPEAT_LAST {
            let len = self.last_length;
            let off = self.last_offset;
            if len == 0 || off == 0 {
                return Err(Error::Corrupt);
            }
            // Like every RAR 2.x match (unrar's `CopyString20`), the
            // repeat pushes its distance into the old-offset ring;
            // skipping this shifts every later 257..=260 reference.
            self.commit_match_offset(off);
            self.emit_match(off, len, target)
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
            self.emit_match(off, len as u16, target)
        } else if sym <= SYM_SHORT_LAST {
            let idx = (sym - SYM_SHORT_FIRST) as usize;
            let mut off = SHORT_BASE[idx] + 1;
            let extra = SHORT_EXTRA[idx] as u32;
            if extra > 0 {
                off += self.bit.read_bits(extra, input)?;
            }
            self.commit_match_offset(off);
            self.last_length = 2;
            self.emit_match(off, 2, target)
        } else if sym == SYM_REREAD_TREES {
            self.read_block_header(input)
        } else if (SYM_LONG_FIRST..(SYM_LONG_FIRST + LENGTH_BASE.len() as u16)).contains(&sym) {
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
            self.emit_match(off, len as u16, target)
        } else {
            Err(Error::Corrupt)
        }
    }

    /// Read the per-block header: flag bits + length-table delta + tree
    /// construction. Called at the start of every block and on every
    /// `sym == 269` / audio `sym == 256` "restart" signal.
    ///
    /// Works on a copy of the length table and commits only once the whole
    /// header has been read and its trees built, so a header cut short by
    /// the end of the buffered input leaves no trace and can be re-read.
    fn read_block_header(&mut self, input: &[u8]) -> Result<(), Error> {
        let in_audio_block = self.bit.read_bits(1, input)? == 1;
        let keep_lengths = self.bit.read_bits(1, input)? == 1;
        let mut lengths = if keep_lengths {
            self.lengths
        } else {
            [0u8; LENGTH_TABLE_SIZE]
        };

        let mut num_channels = self.num_channels;
        let count: usize = if in_audio_block {
            num_channels = self.bit.read_bits(2, input)? as usize + 1;
            num_channels * AUDIO_TREE_SIZE
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
                lengths[i] = (lengths[i].wrapping_add(val as u8)) & 0x0F;
                i += 1;
            } else if val == 16 {
                if i == 0 {
                    return Err(Error::Corrupt);
                }
                let n = self.bit.read_bits(2, input)? as usize + 3;
                let v = lengths[i - 1];
                let stop = (i + n).min(count);
                while i < stop {
                    lengths[i] = v;
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
                    lengths[i] = 0;
                    i += 1;
                }
            }
        }

        // All bits of the header are in: from here on only hard errors.
        if in_audio_block {
            // Build per-channel audio codes.
            let mut codes: [Option<Box<Rar2Huffman<AUDIO_TREE_SIZE>>>; 4] =
                [None, None, None, None];
            for (c, code) in codes.iter_mut().enumerate().take(num_channels) {
                let start = c * AUDIO_TREE_SIZE;
                let slice = &lengths[start..start + AUDIO_TREE_SIZE];
                *code = Some(Box::new(Rar2Huffman::from_lengths(slice)?));
            }
            self.audio_code = codes;
            self.main_code = None;
            self.offset_code = None;
            self.length_code = None;
            if self.channel >= num_channels {
                self.channel = 0;
            }
        } else {
            let main = Rar2Huffman::<MAIN_TREE_SIZE>::from_lengths(&lengths[0..MAIN_TREE_SIZE])?;
            let offset = Rar2Huffman::<OFFSET_TREE_SIZE>::from_lengths(
                &lengths[MAIN_TREE_SIZE..MAIN_TREE_SIZE + OFFSET_TREE_SIZE],
            )?;
            let length = Rar2Huffman::<LENGTH_TREE_SIZE>::from_lengths(
                &lengths[MAIN_TREE_SIZE + OFFSET_TREE_SIZE
                    ..MAIN_TREE_SIZE + OFFSET_TREE_SIZE + LENGTH_TREE_SIZE],
            )?;
            self.main_code = Some(Box::new(main));
            self.offset_code = Some(Box::new(offset));
            self.length_code = Some(Box::new(length));
            self.audio_code = [None, None, None, None];
        }
        self.in_audio_block = in_audio_block;
        self.num_channels = num_channels;
        self.lengths = lengths;
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

    fn emit_literal(&mut self, byte: u8) {
        self.window[self.window_pos] = byte;
        self.window_pos = (self.window_pos + 1) & WINDOW_MASK;
        self.pending += 1;
        self.produced += 1;
    }

    fn emit_match(&mut self, offset: u32, length: u16, target: u64) -> Result<(), Error> {
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
        //
        // Cap the length at the unpack target so a match running past the
        // declared end stops exactly on it.
        let remaining = (length as u64).min(target - self.produced) as usize;
        debug_assert!(self.pending + remaining < WINDOW_SIZE);
        let mut src = (self.window_pos + WINDOW_SIZE - off) & WINDOW_MASK;

        if off == 1 {
            // Distance-1 run: one repeated byte.
            let b = self.window[src];
            for _ in 0..remaining {
                self.window[self.window_pos] = b;
                self.window_pos = (self.window_pos + 1) & WINDOW_MASK;
            }
        } else if off >= remaining {
            // Non-overlapping: copy in contiguous window segments.
            let mut done = 0usize;
            while done < remaining {
                let run = (remaining - done)
                    .min(WINDOW_SIZE - src)
                    .min(WINDOW_SIZE - self.window_pos);
                let sp = self.window_pos;
                // off >= remaining >= run and no wrap inside the run, so the
                // source and destination ranges are disjoint (or, at
                // off == WINDOW_SIZE, identical): one block copy matches the
                // per-byte writes exactly.
                self.window.copy_within(src..src + run, sp);
                src = (src + run) & WINDOW_MASK;
                self.window_pos = (self.window_pos + run) & WINDOW_MASK;
                done += run;
            }
        } else {
            // Overlapping match: each written byte feeds a later read.
            for _ in 0..remaining {
                let b = self.window[src];
                self.window[self.window_pos] = b;
                src = (src + 1) & WINDOW_MASK;
                self.window_pos = (self.window_pos + 1) & WINDOW_MASK;
            }
        }
        self.pending += remaining;
        self.produced += remaining as u64;
        Ok(())
    }
}
