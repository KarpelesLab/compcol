//! LZNT1 decoder: chunk-at-a-time state machine.
//!
//! The decoder buffers each chunk's compressed body until it has all the
//! bytes, then decodes it into a 4 KiB scratch buffer and drains the
//! scratch to the caller's output. This sidesteps the otherwise tricky
//! problem of carrying mid-token state (current flag-byte bit position,
//! partial back-reference offset/length) across `raw_decode` calls.
//!
//! A 4 KiB chunk produces at most 4096 output bytes, so the scratch
//! buffer is bounded.

extern crate alloc;
use alloc::vec::Vec;

use crate::error::Error;
use crate::traits::{RawDecoder, RawProgress};

use super::{CHUNK_SIZE, split_for_pos};

/// Number of body bytes a chunk header may report (header field is 12
/// bits + 1). Uncompressed chunks must report exactly 4096; compressed
/// chunks may report anything from 1..=4096.
const MAX_CHUNK_BODY: usize = 4096;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Reading the first header byte (low byte, contains low 8 bits of
    /// chunk_size-1 plus the high bit of the size field).
    HeaderLow,
    /// Reading the second header byte (high byte, contains the
    /// signature/compressed-flag plus the high 4 bits of size).
    HeaderHigh { hdr_lo: u8 },
    /// Accumulating `body_remaining` more bytes of chunk body into
    /// `chunk_buf`. `compressed` selects how the body is interpreted
    /// once complete.
    Body {
        compressed: bool,
        body_remaining: u16,
    },
    /// All bytes of a decoded chunk sit in `out_buf`; drain to caller.
    Draining,
    /// A zero terminator (or input EOF) was observed. Subsequent
    /// `raw_decode` calls are no-ops; `raw_finish` reports done.
    Done,
}

pub struct Decoder {
    /// Buffer holding the compressed body of the chunk being read in.
    chunk_buf: Vec<u8>,
    /// Buffer holding decoded chunk bytes ready to drain to the caller.
    out_buf: Vec<u8>,
    out_idx: usize,
    phase: Phase,
    poisoned: bool,
}

impl Decoder {
    pub fn new() -> Self {
        Self {
            chunk_buf: Vec::with_capacity(MAX_CHUNK_BODY),
            out_buf: Vec::with_capacity(MAX_CHUNK_BODY),
            out_idx: 0,
            phase: Phase::HeaderLow,
            poisoned: false,
        }
    }

    /// Drain `out_buf[out_idx..]` into `output`. Returns the number of
    /// bytes copied. When the drain empties `out_buf`, transitions to
    /// `HeaderLow` to start the next chunk.
    fn drain(&mut self, output: &mut [u8], written: &mut usize) {
        let avail = self.out_buf.len() - self.out_idx;
        let room = output.len() - *written;
        let n = avail.min(room);
        if n > 0 {
            output[*written..*written + n]
                .copy_from_slice(&self.out_buf[self.out_idx..self.out_idx + n]);
            self.out_idx += n;
            *written += n;
        }
        if self.out_idx == self.out_buf.len() {
            self.out_buf.clear();
            self.out_idx = 0;
            self.phase = Phase::HeaderLow;
        }
    }

    /// Decode `chunk_buf` (a compressed chunk body) into `out_buf`.
    ///
    /// `body_size` is the size declared in the chunk header; on entry
    /// `chunk_buf.len() == body_size`. The decoded output is appended to
    /// `out_buf` (which is empty on entry).
    fn decode_compressed_chunk(&mut self) -> Result<(), Error> {
        let body = &self.chunk_buf[..];
        let mut i = 0usize;
        let mut out: Vec<u8> = Vec::with_capacity(CHUNK_SIZE);

        while i < body.len() {
            let flag = body[i];
            i += 1;
            // Walk the 8 tokens LSB-first. The loop terminates early if
            // the chunk body runs out before all 8 tokens are read; this
            // is legal at the very end of a chunk where the encoder
            // emitted fewer than 8 tokens in the final flag group.
            for bit in 0..8 {
                if i >= body.len() {
                    break;
                }
                let is_match = (flag >> bit) & 1 != 0;
                if !is_match {
                    // Literal byte.
                    out.push(body[i]);
                    i += 1;
                    if out.len() > CHUNK_SIZE {
                        return Err(Error::Corrupt);
                    }
                } else {
                    // 2-byte little-endian match token.
                    if i + 2 > body.len() {
                        return Err(Error::Corrupt);
                    }
                    let token = u16::from_le_bytes([body[i], body[i + 1]]);
                    i += 2;
                    // A match token requires that at least one byte has
                    // been emitted in this chunk so that the split can
                    // be computed.
                    let pos = out.len();
                    if pos == 0 {
                        return Err(Error::Corrupt);
                    }
                    let (_off_bits, length_bits) = split_for_pos(pos);
                    let length_mask: u16 = (1u16 << length_bits) - 1;
                    let length = ((token & length_mask) as usize) + 3;
                    let offset = ((token >> length_bits) as usize) + 1;
                    if offset > pos {
                        return Err(Error::InvalidDistance);
                    }
                    if out.len() + length > CHUNK_SIZE {
                        return Err(Error::Corrupt);
                    }
                    let src_start = pos - offset;
                    if offset >= length {
                        // Non-overlapping: the source range is fully
                        // populated already, so grow the buffer and bulk
                        // copy in one shot instead of byte-by-byte.
                        out.resize(pos + length, 0);
                        out.copy_within(src_start..src_start + length, pos);
                    } else {
                        // Self-overlapping run (offset < length): each
                        // emitted byte feeds the next, so copy one at a time.
                        for k in 0..length {
                            let b = out[src_start + k];
                            out.push(b);
                        }
                    }
                }
            }
        }
        self.out_buf = out;
        self.out_idx = 0;
        Ok(())
    }

    /// Decode an uncompressed chunk: copy `chunk_buf` straight to
    /// `out_buf`.
    fn decode_uncompressed_chunk(&mut self) -> Result<(), Error> {
        // An uncompressed chunk is just literal bytes; MS-XCA fixes the
        // body length at 4096 except possibly at end-of-stream where the
        // chunk may be short. We accept any length 1..=4096.
        self.out_buf.clear();
        self.out_buf.extend_from_slice(&self.chunk_buf);
        self.out_idx = 0;
        Ok(())
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

        loop {
            // Always drain pending decoded bytes first — they may be the
            // only thing left to do and they need output room, not input.
            if self.phase == Phase::Draining {
                self.drain(output, &mut written);
                if self.phase == Phase::Draining {
                    // out_buf still has bytes; output is full.
                    return Ok(RawProgress {
                        consumed,
                        written,
                        done: false,
                    });
                }
                // Drained: phase moved to HeaderLow. Continue.
                continue;
            }

            if self.phase == Phase::Done {
                return Ok(RawProgress {
                    consumed,
                    written,
                    done: true,
                });
            }

            // Everything else needs input.
            if consumed >= input.len() {
                return Ok(RawProgress {
                    consumed,
                    written,
                    done: false,
                });
            }

            match self.phase {
                Phase::HeaderLow => {
                    let hdr_lo = input[consumed];
                    consumed += 1;
                    self.phase = Phase::HeaderHigh { hdr_lo };
                }
                Phase::HeaderHigh { hdr_lo } => {
                    let hdr_hi = input[consumed];
                    consumed += 1;
                    let header = u16::from_le_bytes([hdr_lo, hdr_hi]);
                    // Two-byte all-zero word terminates the stream per
                    // MS-XCA; treat it as end-of-stream.
                    if header == 0 {
                        self.phase = Phase::Done;
                        return Ok(RawProgress {
                            consumed,
                            written,
                            done: true,
                        });
                    }
                    let compressed = (header & 0x8000) != 0;
                    let signature = (header >> 12) & 0x7;
                    // Signature must be 0b011 = 3 for any non-zero chunk
                    // header. Reject other values up front.
                    if signature != 0b011 {
                        self.poisoned = true;
                        return Err(Error::BadHeader);
                    }
                    let body_size = (header & 0x0FFF) as usize + 1;
                    // Per MS-XCA an uncompressed chunk must declare
                    // exactly 4096 bytes. Some producers may emit a
                    // smaller trailing uncompressed chunk; we tolerate
                    // 1..=4096 here.
                    if body_size > MAX_CHUNK_BODY {
                        self.poisoned = true;
                        return Err(Error::BadHeader);
                    }
                    self.chunk_buf.clear();
                    self.phase = Phase::Body {
                        compressed,
                        body_remaining: body_size as u16,
                    };
                }
                Phase::Body {
                    compressed,
                    mut body_remaining,
                } => {
                    let avail = input.len() - consumed;
                    let want = body_remaining as usize;
                    let take = avail.min(want);
                    self.chunk_buf
                        .extend_from_slice(&input[consumed..consumed + take]);
                    consumed += take;
                    body_remaining -= take as u16;
                    if body_remaining == 0 {
                        // Whole body in chunk_buf — decode it.
                        let res = if compressed {
                            self.decode_compressed_chunk()
                        } else {
                            self.decode_uncompressed_chunk()
                        };
                        if let Err(e) = res {
                            self.poisoned = true;
                            return Err(e);
                        }
                        self.phase = if self.out_buf.is_empty() {
                            // Empty chunk produces no output; loop to
                            // read the next header.
                            Phase::HeaderLow
                        } else {
                            Phase::Draining
                        };
                    } else {
                        self.phase = Phase::Body {
                            compressed,
                            body_remaining,
                        };
                        // Out of input mid-body; loop will catch.
                    }
                }
                Phase::Draining | Phase::Done => {
                    debug_assert!(false, "handled at top of loop");
                }
            }
        }
    }

    fn raw_finish(&mut self, output: &mut [u8]) -> Result<RawProgress, Error> {
        if self.poisoned {
            return Err(Error::Corrupt);
        }
        let mut written = 0usize;

        // Drain any pending decoded bytes.
        if self.phase == Phase::Draining {
            self.drain(output, &mut written);
            if self.phase == Phase::Draining {
                return Ok(RawProgress {
                    consumed: 0,
                    written,
                    done: false,
                });
            }
        }

        match self.phase {
            // Either we never started a chunk or we finished one cleanly.
            // No header started → stream ended cleanly. A chunk
            // mid-header or mid-body counts as truncated.
            Phase::HeaderLow | Phase::Done => Ok(RawProgress {
                consumed: 0,
                written,
                done: true,
            }),
            Phase::HeaderHigh { .. } | Phase::Body { .. } => {
                self.poisoned = true;
                Err(Error::UnexpectedEnd)
            }
            Phase::Draining => Ok(RawProgress {
                consumed: 0,
                written,
                done: false,
            }),
        }
    }

    fn raw_reset(&mut self) {
        self.chunk_buf.clear();
        self.out_buf.clear();
        self.out_idx = 0;
        self.phase = Phase::HeaderLow;
        self.poisoned = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_stream_finishes_cleanly() {
        let mut dec = Decoder::new();
        let mut out = [0u8; 16];
        let p = dec.raw_finish(&mut out).unwrap();
        assert!(p.done);
        assert_eq!(p.written, 0);
    }

    #[test]
    fn zero_terminator_ends_cleanly() {
        let mut dec = Decoder::new();
        let mut out = [0u8; 16];
        let p = dec.raw_decode(&[0u8, 0u8], &mut out).unwrap();
        assert!(p.done);
        assert_eq!(p.written, 0);
    }
}
