//! PackBits — Apple's tag-byte RLE used in TIFF, PSD, BMP, and macOS
//! metadata.
//!
//! Wire format: source-byte oriented. Each control byte `n` is signed
//! (`-128..=127`):
//!
//! * `0..=127`   — copy the next `n + 1` literal bytes from the input.
//! * `-1..=-127` — replicate the next byte `-n + 1` times.
//! * `-128`      — no-op (skip the header byte; emit nothing).
//!
//! The stream has no header, no trailer, no length prefix. Decoding
//! ends when the input is exhausted. The encoder in this module
//! emits no terminator and the decoder treats input exhaustion at a
//! control-byte boundary as success — the framing of "how many bytes
//! is the encoded blob?" lives outside this codec, exactly as it does
//! in TIFF strips and PSD scanlines.
//!
//! ## Encoder strategy
//!
//! Greedy two-pass per chunk: a small lookahead distinguishes runs
//! (3+ identical bytes) from literals. Runs are emitted as soon as
//! they end (or hit the 128-byte cap); literals accumulate until the
//! next run begins or the 128-byte literal cap is hit. This matches
//! libtiff's `PackBitsEncode` and produces output byte-for-byte
//! identical to PIL's TIFF PackBits writer on every input we tested.
//!
//! References:
//! * Apple TN1023, <https://developer.apple.com/library/archive/technotes/tn/tn1023.html>
//! * Adobe TIFF 6.0 §9 "PackBits Compression"
//! * libtiff `tif_packbits.c` (BSD)

#![cfg_attr(docsrs, doc(cfg(feature = "packbits")))]

use alloc::vec::Vec;

use crate::error::Error;
use crate::traits::{Algorithm, RawDecoder, RawEncoder, RawProgress};

/// Zero-sized marker type implementing [`Algorithm`] for PackBits.
#[derive(Debug, Clone, Copy, Default)]
pub struct PackBits;

impl Algorithm for PackBits {
    const NAME: &'static str = "packbits";
    type Encoder = Encoder;
    type Decoder = Decoder;
    type EncoderConfig = ();
    type DecoderConfig = ();
    fn encoder_with(_: ()) -> Encoder {
        Encoder::new()
    }
    fn decoder_with(_: ()) -> Decoder {
        Decoder::new()
    }
}

/// Maximum bytes a single literal-run header can describe (header byte = 0x7F).
const MAX_LITERAL: usize = 128;
/// Maximum bytes a single replicate-run header can describe (header byte = 0x81).
const MAX_RUN: usize = 128;
/// Minimum run length we'll encode as a replicate. Two identical bytes
/// cost as much as two literal bytes (2 output for 2 input), so we only
/// switch to a run at length 3+.
const MIN_RUN: usize = 3;

// ─── encoder ─────────────────────────────────────────────────────────────

/// Streaming PackBits encoder.
///
/// The state machine buffers up to one pending literal/run plus a small
/// emit queue so callers can drive it with arbitrarily small input or
/// output slices.
#[derive(Debug, Default)]
pub struct Encoder {
    /// Pending literal bytes that haven't been flushed yet. Capped at
    /// `MAX_LITERAL` — when full we emit, when a run starts we emit.
    literal: Vec<u8>,
    /// Current run: the byte being repeated and the count of how many
    /// times it's been seen so far (always `>= 1` while we're tracking
    /// a run). `None` means "no run in progress; the next input byte
    /// either extends the literal buffer or starts a new run".
    run: Option<(u8, usize)>,
    /// Already-encoded output that the caller hasn't drained yet.
    pending: Vec<u8>,
    head: usize,
    finished: bool,
}

impl Encoder {
    /// Construct a fresh encoder.
    pub const fn new() -> Self {
        Self {
            literal: Vec::new(),
            run: None,
            pending: Vec::new(),
            head: 0,
            finished: false,
        }
    }

    fn drain_pending(&mut self, out: &mut [u8]) -> usize {
        let avail = self.pending.len() - self.head;
        let n = avail.min(out.len());
        out[..n].copy_from_slice(&self.pending[self.head..self.head + n]);
        self.head += n;
        if self.head == self.pending.len() {
            self.pending.clear();
            self.head = 0;
        }
        n
    }

    /// Emit the literal buffer as a `0..=127` header + bytes.
    fn flush_literal(&mut self) {
        if self.literal.is_empty() {
            return;
        }
        debug_assert!(self.literal.len() <= MAX_LITERAL);
        self.pending.push((self.literal.len() - 1) as u8);
        self.pending.extend_from_slice(&self.literal);
        self.literal.clear();
    }

    /// Emit a replicate-run as a `-1..=-127` header + the byte. The
    /// caller is responsible for flushing any preceding literal first,
    /// or the run will appear before the literal in the output stream.
    fn flush_run(&mut self) {
        if let Some((byte, count)) = self.run.take() {
            debug_assert!((MIN_RUN..=MAX_RUN).contains(&count));
            // Header is `-(count - 1)` as i8 → cast through i8 → u8.
            let hdr = -((count as i32) - 1) as i8 as u8;
            self.pending.push(hdr);
            self.pending.push(byte);
        }
    }

    /// Push one input byte through the state machine, possibly emitting
    /// to `self.pending`. Tracks runs of 3+ identical bytes; shorter
    /// runs collapse into the literal buffer.
    fn feed(&mut self, b: u8) {
        match self.run {
            Some((byte, count)) if byte == b && count < MAX_RUN => {
                // Extend the current run.
                self.run = Some((byte, count + 1));
            }
            Some((byte, count)) => {
                // Either we hit the cap, or `b` breaks the run.
                if byte == b {
                    // Cap reached — flush and start a fresh run with `b`.
                    // Order matters: the literal buffer (if any) was
                    // accumulated *before* this run started, so it must
                    // hit the wire first.
                    self.flush_literal();
                    self.flush_run();
                    self.run = Some((b, 1));
                } else if count >= MIN_RUN {
                    // Real run ending: flush literal-then-run so the
                    // wire order matches input order.
                    self.flush_literal();
                    self.flush_run();
                    self.run = Some((b, 1));
                } else {
                    // Tracked bytes that never reached the run
                    // threshold get demoted to literals.
                    self.run = None;
                    for _ in 0..count {
                        self.push_literal(byte);
                    }
                    self.run = Some((b, 1));
                }
            }
            None => {
                self.run = Some((b, 1));
            }
        }
    }

    /// Append one byte to the literal buffer, emitting a chunk if the
    /// buffer hits `MAX_LITERAL`.
    fn push_literal(&mut self, b: u8) {
        self.literal.push(b);
        if self.literal.len() == MAX_LITERAL {
            self.flush_literal();
        }
    }

    /// Commit any pending state at end-of-stream: short runs collapse
    /// into the literal buffer, real runs flush in literal-then-run
    /// order. Idempotent.
    fn finalize(&mut self) {
        if let Some((byte, count)) = self.run.take() {
            if count >= MIN_RUN {
                // Real run: emit any preceding literal first, then
                // the run header. (`flush_literal` no-ops on empty.)
                self.flush_literal();
                self.run = Some((byte, count));
                self.flush_run();
            } else {
                // Short tail: demote to literals and flush together.
                for _ in 0..count {
                    self.push_literal(byte);
                }
                self.flush_literal();
            }
        } else {
            self.flush_literal();
        }
    }
}

impl RawEncoder for Encoder {
    fn raw_encode(&mut self, input: &[u8], output: &mut [u8]) -> Result<RawProgress, Error> {
        let mut consumed = 0usize;
        let mut written = 0usize;

        // Always drain whatever we have queued before doing more work.
        if self.head < self.pending.len() {
            written += self.drain_pending(&mut output[written..]);
        }

        while consumed < input.len() {
            // Bound how much pending can grow per call so a small
            // output slice doesn't make us buffer the whole input.
            // Worst case for one input byte is two output bytes
            // (run header + byte), and `feed` can emit at most one
            // header pair per call.
            if self.pending.len().saturating_sub(self.head) >= output.len().saturating_sub(written)
            {
                if written < output.len() {
                    written += self.drain_pending(&mut output[written..]);
                }
                if self.head < self.pending.len() {
                    break;
                }
            }

            self.feed(input[consumed]);
            consumed += 1;

            if self.head < self.pending.len() && written < output.len() {
                written += self.drain_pending(&mut output[written..]);
            }
        }

        // Final drain.
        if self.head < self.pending.len() && written < output.len() {
            written += self.drain_pending(&mut output[written..]);
        }

        Ok(RawProgress {
            consumed,
            written,
            done: false,
        })
    }

    fn raw_finish(&mut self, output: &mut [u8]) -> Result<RawProgress, Error> {
        if self.finished && self.head >= self.pending.len() {
            return Ok(RawProgress {
                consumed: 0,
                written: 0,
                done: true,
            });
        }

        if !self.finished {
            self.finalize();
            self.finished = true;
        }

        let mut written = 0usize;
        if self.head < self.pending.len() {
            written += self.drain_pending(&mut output[written..]);
        }
        let done = self.head >= self.pending.len();
        Ok(RawProgress {
            consumed: 0,
            written,
            done,
        })
    }

    fn raw_reset(&mut self) {
        self.literal.clear();
        self.run = None;
        self.pending.clear();
        self.head = 0;
        self.finished = false;
    }
}

// ─── decoder ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
enum DecState {
    /// Waiting for the next control byte.
    Header,
    /// Last header was a literal copy; `remaining` more raw bytes to
    /// pass through.
    Literal { remaining: u8 },
    /// Last header was a replicate; need to read the byte to repeat.
    NeedRunByte { count: u8 },
    /// Mid-replicate; emit `byte` `remaining` more times.
    Run { byte: u8, remaining: u8 },
}

/// Streaming PackBits decoder.
#[derive(Debug, Clone, Copy)]
pub struct Decoder {
    state: DecState,
}

impl Decoder {
    pub const fn new() -> Self {
        Self {
            state: DecState::Header,
        }
    }
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

impl RawDecoder for Decoder {
    fn raw_decode(&mut self, input: &[u8], output: &mut [u8]) -> Result<RawProgress, Error> {
        let mut consumed = 0usize;
        let mut written = 0usize;

        loop {
            match self.state {
                DecState::Header => {
                    if consumed == input.len() {
                        return Ok(RawProgress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                    let n = input[consumed] as i8;
                    consumed += 1;
                    if n >= 0 {
                        // Literal copy of n+1 bytes.
                        self.state = DecState::Literal {
                            remaining: (n as u8) + 1,
                        };
                    } else if n == -128 {
                        // No-op header; stay in Header.
                    } else {
                        // Replicate -n+1 times. `n` is in `-127..=-1`,
                        // so `-n + 1` is in `2..=128`, well within u8.
                        self.state = DecState::NeedRunByte {
                            count: ((-(n as i16)) as u8) + 1,
                        };
                    }
                }
                DecState::Literal { remaining } => {
                    if remaining == 0 {
                        self.state = DecState::Header;
                        continue;
                    }
                    if consumed == input.len() || written == output.len() {
                        return Ok(RawProgress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                    let in_avail = input.len() - consumed;
                    let out_avail = output.len() - written;
                    let n = (remaining as usize).min(in_avail).min(out_avail);
                    output[written..written + n].copy_from_slice(&input[consumed..consumed + n]);
                    consumed += n;
                    written += n;
                    let new_remaining = remaining - n as u8;
                    self.state = if new_remaining == 0 {
                        DecState::Header
                    } else {
                        DecState::Literal {
                            remaining: new_remaining,
                        }
                    };
                }
                DecState::NeedRunByte { count } => {
                    if consumed == input.len() {
                        return Ok(RawProgress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                    let byte = input[consumed];
                    consumed += 1;
                    self.state = DecState::Run {
                        byte,
                        remaining: count,
                    };
                }
                DecState::Run { byte, remaining } => {
                    if remaining == 0 {
                        self.state = DecState::Header;
                        continue;
                    }
                    if written == output.len() {
                        return Ok(RawProgress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                    let out_avail = output.len() - written;
                    let n = (remaining as usize).min(out_avail);
                    for slot in &mut output[written..written + n] {
                        *slot = byte;
                    }
                    written += n;
                    let new_remaining = remaining - n as u8;
                    self.state = if new_remaining == 0 {
                        DecState::Header
                    } else {
                        DecState::Run {
                            byte,
                            remaining: new_remaining,
                        }
                    };
                }
            }
        }
    }

    fn raw_finish(&mut self, output: &mut [u8]) -> Result<RawProgress, Error> {
        let mut written = 0usize;

        // Drain any in-progress run; literal/run-byte states mid-symbol
        // mean the input was truncated.
        if let DecState::Run { byte, remaining } = self.state {
            let out_avail = output.len() - written;
            let n = (remaining as usize).min(out_avail);
            for slot in &mut output[written..written + n] {
                *slot = byte;
            }
            written += n;
            let new_remaining = remaining - n as u8;
            self.state = if new_remaining == 0 {
                DecState::Header
            } else {
                DecState::Run {
                    byte,
                    remaining: new_remaining,
                }
            };
        }

        match self.state {
            DecState::Header => Ok(RawProgress {
                consumed: 0,
                written,
                done: true,
            }),
            DecState::Run { .. } => Ok(RawProgress {
                consumed: 0,
                written,
                done: false,
            }),
            // Mid-literal or waiting for the replicate's data byte:
            // input ended in the middle of a symbol.
            DecState::Literal { .. } | DecState::NeedRunByte { .. } => Err(Error::UnexpectedEnd),
        }
    }

    fn raw_reset(&mut self) {
        self.state = DecState::Header;
    }
}
