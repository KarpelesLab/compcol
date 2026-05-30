//! Streaming Arsenic decoder.
//!
//! Arsenic self-terminates: each block ends with an end-of-blocks flag and,
//! after the final block, a 32-bit CRC trailer (FORMAT-SPEC §5.4/§6.5/§6.6).
//! The decoder therefore needs no out-of-band length.
//!
//! Because the carry-less range coder cannot be cheaply check-pointed
//! mid-symbol, this implementation buffers the whole compressed fork, then
//! decodes it to completion in one shot once enough input is present, and
//! drains the decoded bytes into the caller's `output` slice across as many
//! `decode` calls as the caller needs. A decode attempt that runs off the
//! end of the buffered input (bit-reader underflow) before reaching the
//! end-of-blocks/CRC trailer is treated as "need more input": the partial
//! work is discarded and the attempt is retried when more bytes arrive (or
//! reported as truncation at `finish`). This keeps the decoder correct under
//! arbitrary input/output chunking.

use alloc::vec::Vec;

use crate::arsenic::pipeline::{self, DecodeOutcome};
use crate::error::Error;
use crate::traits::{RawDecoder, RawProgress};

/// Streaming Arsenic decoder.
pub struct Decoder {
    /// All compressed bytes fed so far (the raw method-15 fork payload).
    input: Vec<u8>,
    /// Fully decoded output, produced once the whole stream is decodable.
    output: Vec<u8>,
    /// Read cursor into `output`.
    out_pos: usize,
    /// True once `output` has been populated by a successful full decode.
    decoded: bool,
    /// Buffered-input length at which the next decode attempt is worthwhile.
    /// Decoding the carry-less range stream cannot be cheaply check-pointed,
    /// so a failed (underflowing) attempt costs O(buffered). To keep the
    /// amortised cost O(n log n) under tiny input chunks, we only retry once
    /// the buffer has grown geometrically past the last failed attempt (and
    /// always retry on `finish`).
    next_attempt_len: usize,
    /// True once every decoded byte has been delivered to the caller.
    finished: bool,
    /// Set on any hard error so callers cannot resume.
    poisoned: bool,
}

impl Decoder {
    /// Construct a decoder with the default configuration.
    pub fn new() -> Self {
        Self {
            input: Vec::new(),
            output: Vec::new(),
            out_pos: 0,
            decoded: false,
            next_attempt_len: 1,
            finished: false,
            poisoned: false,
        }
    }

    /// Drain decoded bytes into `output`, advancing the read cursor.
    fn drain(&mut self, output: &mut [u8]) -> usize {
        let avail = self.output.len() - self.out_pos;
        let n = avail.min(output.len());
        output[..n].copy_from_slice(&self.output[self.out_pos..self.out_pos + n]);
        self.out_pos += n;
        if self.out_pos == self.output.len() {
            self.finished = true;
        }
        n
    }

    /// Attempt to decode the whole buffered stream. On underflow before the
    /// trailer, leaves `decoded` false and returns `Ok(false)` (need more
    /// input). On success, populates `output` and returns `Ok(true)`.
    fn try_decode(&mut self) -> Result<bool, Error> {
        match pipeline::decode_stream(&self.input)? {
            DecodeOutcome::Complete(out) => {
                self.output = out;
                self.decoded = true;
                Ok(true)
            }
            DecodeOutcome::NeedMore => {
                // Don't retry until the buffer has grown geometrically.
                self.next_attempt_len = (self.input.len() * 2).max(self.input.len() + 1);
                Ok(false)
            }
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
        if self.poisoned {
            return Err(Error::Corrupt);
        }

        // If we've already finished delivering output, this is a no-op.
        if self.finished {
            return Ok(RawProgress {
                consumed: 0,
                written: 0,
                done: true,
            });
        }

        // If we've already decoded everything, just drain (consume no input).
        if self.decoded {
            let written = self.drain(output);
            return Ok(RawProgress {
                consumed: 0,
                written,
                done: self.finished,
            });
        }

        // Otherwise accumulate input.
        let consumed = input.len();
        if consumed > 0 {
            self.input.extend_from_slice(input);
        }

        // Only attempt a (possibly expensive) full decode once the buffer has
        // grown past the geometric retry threshold; otherwise just buffer.
        if self.input.len() < self.next_attempt_len {
            return Ok(RawProgress {
                consumed,
                written: 0,
                done: false,
            });
        }

        match self.try_decode() {
            Ok(true) => {
                let written = self.drain(output);
                Ok(RawProgress {
                    consumed,
                    written,
                    done: self.finished,
                })
            }
            Ok(false) => {
                // Need more input; nothing to write yet.
                Ok(RawProgress {
                    consumed,
                    written: 0,
                    done: false,
                })
            }
            Err(e) => {
                self.poisoned = true;
                Err(e)
            }
        }
    }

    fn raw_finish(&mut self, output: &mut [u8]) -> Result<RawProgress, Error> {
        if self.poisoned {
            return Err(Error::Corrupt);
        }
        if self.finished {
            return Ok(RawProgress {
                consumed: 0,
                written: 0,
                done: true,
            });
        }
        if !self.decoded {
            // Last chance: try a full decode of whatever we have.
            match self.try_decode() {
                Ok(true) => {}
                Ok(false) => {
                    // Stream never reached its in-band terminator.
                    self.poisoned = true;
                    return Err(Error::UnexpectedEnd);
                }
                Err(e) => {
                    self.poisoned = true;
                    return Err(e);
                }
            }
        }
        let written = self.drain(output);
        Ok(RawProgress {
            consumed: 0,
            written,
            done: self.finished,
        })
    }

    fn raw_reset(&mut self) {
        self.input.clear();
        self.output.clear();
        self.out_pos = 0;
        self.decoded = false;
        self.next_attempt_len = 1;
        self.finished = false;
        self.poisoned = false;
    }
}
