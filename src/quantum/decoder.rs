//! Quantum decoder state machine.
//!
//! Streaming model: input bytes are accumulated in `self.input_buf` and
//! drained from the front once safely consumed. Output bytes pass through
//! the window (a circular buffer sized by `window_bits`) and from there into
//! the caller's `output` slice.
//!
//! Per `decode(input, output)` call we loop attempting one Quantum *packet*
//! (literal or match) at a time. Before each attempt we snapshot the arith
//! decoder, the bit reader, and all nine models. If the attempt hits
//! [`Error::UnexpectedEnd`] (the bit reader ran past the end of the buffered
//! input) we restore the snapshot, return progress so far, and wait for the
//! caller to supply more input.

use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;
use crate::quantum::bits::BitReader;
use crate::quantum::model::{ArithDecoder, Model};
use crate::quantum::tables::{EXTRA_BITS, LENGTH_BASE, LENGTH_EXTRA, POSITION_BASE};
use crate::traits::{RawDecoder, RawProgress};

/// One Quantum frame is 32 KiB of output. After each frame the bit reader
/// realigns to a byte boundary and a small trailer is consumed.
const FRAME_SIZE: u32 = 32_768;

/// Default window size if the caller did not specify one.
/// Quantum window_bits ranges from 10 (1 KiB) to 21 (2 MiB); 21 is the max
/// any real CAB stream can use and decodes any smaller stream just fine
/// from the decoder's perspective. But it allocates 2 MiB up front, which
/// is wasteful for small inputs — pick 15 (32 KiB, same as a frame) as a
/// reasonable middle ground.
pub(crate) const DEFAULT_WINDOW_BITS: u32 = 15;

/// State of a single match-copy that wasn't fully drained into the caller's
/// output on the previous call. The match has already been *written into
/// the window*; this struct just tracks how many of those window bytes still
/// need to be sent to the caller.
#[derive(Debug, Clone, Copy)]
struct PendingOutput {
    /// Window byte index of the next byte to emit.
    start: usize,
    /// Bytes still to emit.
    remaining: usize,
}

/// One Quantum "frame trailer" state. After each 32 KiB frame the decoder
/// must (a) discard any bits in the current byte to realign and (b) consume
/// bytes until it sees a `0xFF`. CAB injects 0–4 NULs to allow the alignment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TrailerState {
    /// No trailer in progress.
    None,
    /// We're in the middle of the trailer (post-realignment), waiting for a
    /// `0xFF` byte from the bitstream.
    SeekingFF,
}

/// State during a possibly-multi-call match copy: we have decoded the
/// length and offset and need to perform the LZ copy into the window. We
/// stage the source/dest indices and walk the loop one byte at a time so
/// the caller's output can be drained incrementally.
#[derive(Debug, Clone, Copy)]
struct PendingMatch {
    /// Match offset (1-based, as in libmspack).
    match_offset: usize,
    /// Bytes of match left to write into the window.
    remaining: usize,
}

/// Quantum streaming decoder.
pub struct Decoder {
    // --- Configuration ----------------------------------------------------
    window_bits: u32,
    window_size: usize,
    /// Mask for `window_size - 1` (since window_size is a power of two).
    window_mask: usize,

    // --- Streaming I/O buffers -------------------------------------------
    /// Compressed input not yet consumed by the bit reader.
    input_buf: Vec<u8>,
    /// LZ window. Initialised to zero.
    window: Vec<u8>,
    /// Next write offset into the window.
    window_posn: usize,
    /// True once we've allocated the window and models.
    initialised: bool,

    // --- Bit reader + arithmetic decoder ---------------------------------
    bit_reader: BitReader,
    arith: ArithDecoder,
    /// Whether the per-frame header (H/L/C init) has been read.
    header_read: bool,

    // --- Frame accounting -------------------------------------------------
    frame_todo: u32,
    trailer_state: TrailerState,

    // --- Pending mid-packet work -----------------------------------------
    /// A match whose length+offset have been decoded but whose bytes
    /// haven't all been copied into the window yet. We need this so a
    /// single get-symbol call's worth of work isn't lost if the caller's
    /// output buffer fills up halfway through a long match.
    pending_match: Option<PendingMatch>,
    /// Window-resident bytes that still need to be emitted to the caller.
    pending_output: Option<PendingOutput>,

    // --- Probability models ----------------------------------------------
    model0: Model,
    model1: Model,
    model2: Model,
    model3: Model,
    model4: Model,
    model5: Model,
    model6: Model,
    model6len: Model,
    model7: Model,
}

impl Decoder {
    /// Construct a decoder with the default window size (32 KiB).
    pub fn new() -> Self {
        Self::with_window_bits(DEFAULT_WINDOW_BITS).expect("default window bits are valid")
    }

    /// Construct a decoder with the given window size, in bits
    /// (`10..=21`, i.e. 1 KiB to 2 MiB). CAB folder headers carry this
    /// value out-of-band, so callers parsing CAB streams must thread it in.
    ///
    /// Returns [`Error::BadHeader`] if `window_bits` is outside `10..=21`.
    pub fn with_window_bits(window_bits: u32) -> Result<Self, Error> {
        if !(10..=21).contains(&window_bits) {
            return Err(Error::BadHeader);
        }
        let window_size = 1usize << window_bits;
        // i = window_bits * 2, used to size the offset models.
        let i = (window_bits * 2) as usize;
        let model4_size = i.min(24);
        let model5_size = i.min(36);
        let model6_size = i; // capped at 42 by the constraint window_bits ≤ 21.
        debug_assert!(model6_size <= 42);

        Ok(Self {
            window_bits,
            window_size,
            window_mask: window_size - 1,

            input_buf: Vec::new(),
            window: Vec::new(),
            window_posn: 0,
            initialised: false,

            bit_reader: BitReader::new(),
            arith: ArithDecoder::new(),
            header_read: false,

            frame_todo: FRAME_SIZE,
            trailer_state: TrailerState::None,

            pending_match: None,
            pending_output: None,

            model0: Model::new(0, 64),
            model1: Model::new(64, 64),
            model2: Model::new(128, 64),
            model3: Model::new(192, 64),
            model4: Model::new(0, model4_size),
            model5: Model::new(0, model5_size),
            model6: Model::new(0, model6_size),
            model6len: Model::new(0, 27),
            model7: Model::new(0, 7),
        })
    }

    /// Initialise the window (zero it) on first use.
    fn ensure_window(&mut self) {
        if !self.initialised {
            self.window = vec![0u8; self.window_size];
            self.initialised = true;
        }
    }

    /// Snapshot just the fields that can be mutated while attempting one
    /// packet. We don't snapshot the window or output buffers since they
    /// are only written *after* the get_symbol calls succeed (we re-do
    /// the writes from scratch if we have to rewind).
    fn snapshot(&self) -> Snapshot {
        Snapshot {
            bit_reader: self.bit_reader,
            arith: self.arith,
            header_read: self.header_read,
            model0: self.model0.clone(),
            model1: self.model1.clone(),
            model2: self.model2.clone(),
            model3: self.model3.clone(),
            model4: self.model4.clone(),
            model5: self.model5.clone(),
            model6: self.model6.clone(),
            model6len: self.model6len.clone(),
            model7: self.model7.clone(),
            trailer_state: self.trailer_state,
        }
    }

    fn restore(&mut self, s: Snapshot) {
        self.bit_reader = s.bit_reader;
        self.arith = s.arith;
        self.header_read = s.header_read;
        self.model0 = s.model0;
        self.model1 = s.model1;
        self.model2 = s.model2;
        self.model3 = s.model3;
        self.model4 = s.model4;
        self.model5 = s.model5;
        self.model6 = s.model6;
        self.model6len = s.model6len;
        self.model7 = s.model7;
        self.trailer_state = s.trailer_state;
    }

    /// Drain any pending in-window bytes into `output`.
    /// Returns bytes written.
    fn drain_pending_output(&mut self, output: &mut [u8], written: &mut usize) -> bool {
        if let Some(po) = self.pending_output {
            if po.remaining == 0 {
                self.pending_output = None;
                return false;
            }
            let n = po.remaining.min(output.len() - *written);
            for k in 0..n {
                output[*written + k] = self.window[(po.start + k) & self.window_mask];
            }
            *written += n;
            let new_rem = po.remaining - n;
            if new_rem == 0 {
                self.pending_output = None;
            } else {
                self.pending_output = Some(PendingOutput {
                    start: (po.start + n) & self.window_mask,
                    remaining: new_rem,
                });
            }
            return *written == output.len();
        }
        false
    }

    /// Queue `n` newly-written window bytes (starting at `start`) for
    /// emission to the caller.
    fn enqueue_output(&mut self, start: usize, n: usize) {
        if n == 0 {
            return;
        }
        // Coalesce with any existing pending range if contiguous (which it
        // always is — we only enqueue after writing to window_posn).
        match self.pending_output {
            Some(po) => {
                let expected_end = (po.start + po.remaining) & self.window_mask;
                if expected_end == start {
                    self.pending_output = Some(PendingOutput {
                        start: po.start,
                        remaining: po.remaining + n,
                    });
                } else {
                    // Should not happen given our flow, but be defensive.
                    self.pending_output = Some(PendingOutput {
                        start,
                        remaining: n,
                    });
                }
            }
            None => {
                self.pending_output = Some(PendingOutput {
                    start,
                    remaining: n,
                });
            }
        }
    }

    /// Step the trailer state machine. Returns `Ok(true)` if the trailer is
    /// complete and the next frame can begin.
    fn process_trailer(&mut self) -> Result<bool, Error> {
        if self.trailer_state == TrailerState::None {
            return Ok(true);
        }
        // SeekingFF: read bytes until we see 0xFF.
        loop {
            let b = self.bit_reader.read_bits(8, &self.input_buf)?;
            if b == 0xFF {
                self.trailer_state = TrailerState::None;
                self.header_read = false;
                self.frame_todo = FRAME_SIZE;
                return Ok(true);
            }
            if b != 0 {
                // Per cabd.c/qtmd.c only 0x00 or 0xFF are valid trailer bytes.
                return Err(Error::Corrupt);
            }
        }
    }

    /// Decode one packet (literal or match) from the bitstream, writing into
    /// the window, queuing the new window bytes for output, and updating
    /// `window_posn` and `frame_todo`. Returns `Ok(())` on success.
    fn decode_one_packet(&mut self) -> Result<(), Error> {
        // Decide selector.
        let selector =
            self.arith
                .get_symbol(&mut self.model7, &mut self.bit_reader, &self.input_buf)?;
        if selector >= 7 {
            return Err(Error::Corrupt);
        }
        if selector < 4 {
            // Literal.
            let sym = match selector {
                0 => self.arith.get_symbol(
                    &mut self.model0,
                    &mut self.bit_reader,
                    &self.input_buf,
                )?,
                1 => self.arith.get_symbol(
                    &mut self.model1,
                    &mut self.bit_reader,
                    &self.input_buf,
                )?,
                2 => self.arith.get_symbol(
                    &mut self.model2,
                    &mut self.bit_reader,
                    &self.input_buf,
                )?,
                _ => self.arith.get_symbol(
                    &mut self.model3,
                    &mut self.bit_reader,
                    &self.input_buf,
                )?,
            };
            let byte = (sym & 0xFF) as u8;
            self.window[self.window_posn & self.window_mask] = byte;
            let start = self.window_posn & self.window_mask;
            self.window_posn += 1;
            self.frame_todo = self.frame_todo.wrapping_sub(1);
            self.enqueue_output(start, 1);
            return Ok(());
        }
        // Match.
        let (match_length, match_offset) = match selector {
            4 => {
                let sym = self.arith.get_symbol(
                    &mut self.model4,
                    &mut self.bit_reader,
                    &self.input_buf,
                )? as usize;
                if sym >= EXTRA_BITS.len() {
                    return Err(Error::Corrupt);
                }
                let eb = EXTRA_BITS[sym] as u32;
                let extra = if eb == 0 {
                    0
                } else {
                    self.bit_reader.read_many_bits(eb, &self.input_buf)?
                } as usize;
                let off = POSITION_BASE[sym] as usize + extra + 1;
                (3usize, off)
            }
            5 => {
                let sym = self.arith.get_symbol(
                    &mut self.model5,
                    &mut self.bit_reader,
                    &self.input_buf,
                )? as usize;
                if sym >= EXTRA_BITS.len() {
                    return Err(Error::Corrupt);
                }
                let eb = EXTRA_BITS[sym] as u32;
                let extra = if eb == 0 {
                    0
                } else {
                    self.bit_reader.read_many_bits(eb, &self.input_buf)?
                } as usize;
                let off = POSITION_BASE[sym] as usize + extra + 1;
                (4usize, off)
            }
            6 => {
                let sym_len = self.arith.get_symbol(
                    &mut self.model6len,
                    &mut self.bit_reader,
                    &self.input_buf,
                )? as usize;
                if sym_len >= LENGTH_EXTRA.len() {
                    return Err(Error::Corrupt);
                }
                let le = LENGTH_EXTRA[sym_len] as u32;
                let extra_len = if le == 0 {
                    0
                } else {
                    self.bit_reader.read_many_bits(le, &self.input_buf)?
                } as usize;
                let match_length = LENGTH_BASE[sym_len] as usize + extra_len + 5;

                let sym_off = self.arith.get_symbol(
                    &mut self.model6,
                    &mut self.bit_reader,
                    &self.input_buf,
                )? as usize;
                if sym_off >= EXTRA_BITS.len() {
                    return Err(Error::Corrupt);
                }
                let eb = EXTRA_BITS[sym_off] as u32;
                let extra_off = if eb == 0 {
                    0
                } else {
                    self.bit_reader.read_many_bits(eb, &self.input_buf)?
                } as usize;
                let match_offset = POSITION_BASE[sym_off] as usize + extra_off + 1;
                (match_length, match_offset)
            }
            _ => return Err(Error::Corrupt),
        };

        // Validate offset.
        if match_offset == 0 || match_offset > self.window_size {
            return Err(Error::InvalidDistance);
        }
        // Stage as a pending match — the actual window copy happens in
        // [`copy_pending_match`] so that the caller's output can be drained
        // incrementally for very long matches.
        self.pending_match = Some(PendingMatch {
            match_offset,
            remaining: match_length,
        });
        // frame_todo is decremented up front for matches, matching libmspack.
        self.frame_todo = self.frame_todo.wrapping_sub(match_length as u32);
        Ok(())
    }

    /// Copy a pending match into the window byte-by-byte, queuing the new
    /// window bytes for emission. Returns when the match is finished or when
    /// the window wraps (caller restarts on next iteration).
    fn copy_pending_match(&mut self) {
        let Some(pm) = self.pending_match.take() else {
            return;
        };
        let match_offset = pm.match_offset;
        let mut remaining = pm.remaining;
        let mut emit_start = self.window_posn & self.window_mask;
        let mut emit_count = 0usize;
        while remaining > 0 {
            let dest = self.window_posn & self.window_mask;
            let src = (self.window_posn.wrapping_sub(match_offset)) & self.window_mask;
            self.window[dest] = self.window[src];
            self.window_posn += 1;
            remaining -= 1;
            emit_count += 1;
            // If we're about to wrap the window, flush this run as one
            // contiguous emit and start a new one at offset 0.
            let next = self.window_posn & self.window_mask;
            if next == 0 && remaining > 0 {
                self.enqueue_output(emit_start, emit_count);
                emit_start = 0;
                emit_count = 0;
            }
        }
        if emit_count > 0 {
            self.enqueue_output(emit_start, emit_count);
        }
    }

    /// Main streaming loop. Drives packet decoding until either output is
    /// full, input runs out (with snapshot rewind), or end of stream is
    /// reached.
    fn drain(&mut self, output: &mut [u8], written: &mut usize) -> Result<bool, Error> {
        // First, drain anything we owe.
        if self.drain_pending_output(output, written) {
            return Ok(false);
        }

        // If there's a pending match copy mid-flight, finish writing it into
        // the window before pulling more packets.
        if self.pending_match.is_some() {
            self.copy_pending_match();
            if self.drain_pending_output(output, written) {
                return Ok(false);
            }
        }

        loop {
            // Check if output is full.
            if *written == output.len() {
                return Ok(false);
            }
            // Step trailer if needed.
            if self.trailer_state != TrailerState::None {
                let snap = self.snapshot();
                match self.process_trailer() {
                    Ok(true) => {}
                    Ok(false) => unreachable!(),
                    Err(Error::UnexpectedEnd) => {
                        self.restore(snap);
                        return Ok(false);
                    }
                    Err(e) => return Err(e),
                }
            }
            // Init the per-frame header if not done.
            if !self.header_read {
                let snap = self.snapshot();
                match self.arith.init_frame(&mut self.bit_reader, &self.input_buf) {
                    Ok(()) => {
                        self.header_read = true;
                    }
                    Err(Error::UnexpectedEnd) => {
                        self.restore(snap);
                        return Ok(false);
                    }
                    Err(e) => return Err(e),
                }
            }

            // If frame is full, switch to trailer.
            if self.frame_todo == 0 {
                // Realign: discard the remaining bits in the current byte.
                let leftover = self.bit_reader.bits_left() & 7;
                self.bit_reader.remove_bits(leftover);
                self.trailer_state = TrailerState::SeekingFF;
                continue;
            }

            // Otherwise attempt one packet. We snapshot enough state to
            // roll back to a packet boundary if the bit reader runs out of
            // input. The window writes are reproduced from scratch after
            // the input refill, so rewinding `window_posn` is enough — the
            // bytes we wrote past it will be overwritten by the same data.
            let snap = self.snapshot();
            let saved_window_posn = self.window_posn;
            let saved_frame_todo = self.frame_todo;
            let saved_pending_match = self.pending_match;

            match self.decode_one_packet() {
                Ok(()) => {
                    // If the packet was a match, copy bytes into the window now.
                    if self.pending_match.is_some() {
                        self.copy_pending_match();
                    }
                    if self.drain_pending_output(output, written) {
                        return Ok(false);
                    }
                }
                Err(Error::UnexpectedEnd) => {
                    self.restore(snap);
                    self.window_posn = saved_window_posn;
                    self.frame_todo = saved_frame_todo;
                    self.pending_match = saved_pending_match;
                    return Ok(false);
                }
                Err(e) => return Err(e),
            }

            // If frame just got filled and we have output room, loop will
            // pick up the trailer next iteration.
        }
    }

    /// Compact `input_buf` by dropping the prefix already consumed by the
    /// bit reader.
    fn compact_input(&mut self) {
        let bp = self.bit_reader.byte_pos();
        if bp == 0 {
            return;
        }
        self.input_buf.drain(0..bp);
        self.bit_reader.rebase(bp);
    }
}

#[derive(Clone)]
struct Snapshot {
    bit_reader: BitReader,
    arith: ArithDecoder,
    header_read: bool,
    model0: Model,
    model1: Model,
    model2: Model,
    model3: Model,
    model4: Model,
    model5: Model,
    model6: Model,
    model6len: Model,
    model7: Model,
    trailer_state: TrailerState,
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

impl RawDecoder for Decoder {
    fn raw_decode(&mut self, input: &[u8], output: &mut [u8]) -> Result<RawProgress, Error> {
        self.ensure_window();
        self.input_buf.extend_from_slice(input);
        let mut written = 0usize;
        self.drain(output, &mut written)?;
        self.compact_input();
        Ok(RawProgress {
            consumed: input.len(),
            written,
            done: false,
        })
    }

    fn raw_finish(&mut self, output: &mut [u8]) -> Result<RawProgress, Error> {
        self.ensure_window();
        self.bit_reader.set_eof(true);
        let mut written = 0usize;
        // Drain anything we can with current buffered input.
        self.drain(output, &mut written)?;
        self.compact_input();

        // We treat the stream as finished once we have no pending in-window
        // output to emit and the caller's output buffer wasn't filled to the
        // brim (i.e. we stopped because we ran out of work, not because we
        // ran out of space). Residual `0x00` trailer-padding bytes after a
        // 32 KiB frame may legitimately sit in `input_buf` — Quantum has no
        // true end-of-stream marker; the container tells the caller when
        // they're done.
        let done =
            self.pending_output.is_none() && self.pending_match.is_none() && written < output.len();
        Ok(RawProgress {
            consumed: 0,
            written,
            done,
        })
    }

    fn raw_reset(&mut self) {
        self.input_buf.clear();
        if self.initialised {
            // Zero the window so back-references into it are deterministic.
            for b in self.window.iter_mut() {
                *b = 0;
            }
        }
        self.window_posn = 0;
        // A fresh BitReader has eof=false, so this also clears the EOF flag.
        self.bit_reader = BitReader::new();
        self.arith = ArithDecoder::new();
        self.header_read = false;
        self.frame_todo = FRAME_SIZE;
        self.trailer_state = TrailerState::None;
        self.pending_match = None;
        self.pending_output = None;
        // Reinitialise models to their starting state.
        let i = (self.window_bits * 2) as usize;
        self.model0 = Model::new(0, 64);
        self.model1 = Model::new(64, 64);
        self.model2 = Model::new(128, 64);
        self.model3 = Model::new(192, 64);
        self.model4 = Model::new(0, i.min(24));
        self.model5 = Model::new(0, i.min(36));
        self.model6 = Model::new(0, i);
        self.model6len = Model::new(0, 27);
        self.model7 = Model::new(0, 7);
    }
}
