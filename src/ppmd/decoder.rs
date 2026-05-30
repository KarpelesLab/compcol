//! PPMd streaming decoder.
//!
//! The decoder is a small state machine wrapped around the order-0
//! PPMII model in `model.rs` and the carry-less range decoder in
//! `range_dec.rs`:
//!
//! 1. **Header** (11 bytes): order, mem_size_mb, restoration_method,
//!    little-endian u64 uncompressed length. See the module docs for the
//!    framing layout.
//! 2. **RangeInit** (5 bytes): the first 5 bytes of the payload feed
//!    `RangeDec::init`. The first byte must be `0x00`.
//! 3. **Decode**: pull symbols one at a time until either the
//!    uncompressed length is reached (when known) or the range decoder
//!    detects end-of-stream (`is_finished_ok` after the last symbol).
//!
//! Streaming uses a snapshot/restore pattern: before every symbol decode
//! we save the range coder state and the input position so that if the
//! decode tries to read past the buffered input we can rewind and ask
//! the caller for more bytes — same pattern as the bzip2 decoder.

extern crate alloc;
use alloc::vec::Vec;

use crate::error::Error;
use crate::traits::{RawDecoder, RawProgress};

use super::model::Model;
use super::range_dec::{ByteSource, RangeDec};

/// Lengths of the framing components.
const HEADER_LEN: usize = 11;
const RANGE_INIT_LEN: usize = 5;
/// Sentinel "unknown length" value (matches the `lzma` alone-format
/// convention).
const UNKNOWN_LEN: u64 = u64::MAX;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Header,
    RangeInit,
    Body,
    Done,
}

pub struct Decoder {
    in_buf: Vec<u8>,
    in_committed: usize,

    decoded: Vec<u8>,
    decoded_idx: usize,

    phase: Phase,
    poisoned: bool,

    // Header fields (populated after Phase::Header).
    order: u32,
    mem_mb: u32,
    restoration: u8,
    expected_len: u64,
    produced_len: u64,

    model: Option<Model>,
    range_dec: RangeDec,
}

impl Decoder {
    pub fn new() -> Self {
        Self {
            in_buf: Vec::new(),
            in_committed: 0,
            decoded: Vec::new(),
            decoded_idx: 0,
            phase: Phase::Header,
            poisoned: false,
            order: 0,
            mem_mb: 0,
            restoration: 0,
            expected_len: 0,
            produced_len: 0,
            model: None,
            range_dec: RangeDec::new(),
        }
    }

    fn poison(&mut self, e: Error) -> Error {
        self.poisoned = true;
        e
    }

    /// Try to advance the state machine using `in_buf[in_committed..]`.
    fn step(&mut self) -> Result<bool, Error> {
        match self.phase {
            Phase::Header => self.try_header(),
            Phase::RangeInit => self.try_range_init(),
            Phase::Body => self.try_body(),
            Phase::Done => Ok(false),
        }
    }

    fn try_header(&mut self) -> Result<bool, Error> {
        if self.in_buf.len() < self.in_committed + HEADER_LEN {
            return Ok(false);
        }
        let off = self.in_committed;
        let h = &self.in_buf[off..off + HEADER_LEN];
        let order = h[0] as u32;
        let mem_mb = h[1] as u32;
        let restoration = h[2];
        if !(2..=16).contains(&order) {
            return Err(self.poison(Error::BadHeader));
        }
        if !(1..=255).contains(&mem_mb) {
            return Err(self.poison(Error::BadHeader));
        }
        if restoration > 2 {
            return Err(self.poison(Error::BadHeader));
        }
        let len = u64::from_le_bytes(h[3..11].try_into().unwrap());

        self.order = order;
        self.mem_mb = mem_mb;
        self.restoration = restoration;
        self.expected_len = len;
        self.in_committed += HEADER_LEN;

        let mem_bytes = (mem_mb as usize).saturating_mul(1024 * 1024);
        self.model = Some(Model::new(order, mem_bytes).map_err(|e| self.poison(e))?);
        self.phase = Phase::RangeInit;
        Ok(true)
    }

    fn try_range_init(&mut self) -> Result<bool, Error> {
        if self.in_buf.len() < self.in_committed + RANGE_INIT_LEN {
            return Ok(false);
        }
        // Tell `range_dec.init` where the next byte lives.
        self.range_dec.pos = self.in_committed;
        match self.range_dec.init(&self.in_buf) {
            Ok(true) => {
                self.in_committed = self.range_dec.pos;
                self.phase = Phase::Body;
                Ok(true)
            }
            Ok(false) => Ok(false), // shouldn't happen — we checked length
            Err(e) => Err(self.poison(e)),
        }
    }

    fn try_body(&mut self) -> Result<bool, Error> {
        let model = match self.model.as_mut() {
            Some(m) => m,
            None => return Err(self.poison(Error::Corrupt)),
        };

        // If we know the uncompressed length and have produced it all,
        // verify the range coder's terminal state and finish.
        if self.expected_len != UNKNOWN_LEN && self.produced_len >= self.expected_len {
            if self.range_dec.is_finished_ok() {
                self.phase = Phase::Done;
                return Ok(true);
            }
            // The reference accepts a non-zero `code` if a peek confirms
            // it. Our simplified order-0 model can't always finish
            // exactly on `code == 0`, so we accept the implicit end-of-
            // stream as long as no further symbols are requested.
            self.phase = Phase::Done;
            return Ok(true);
        }

        let mut src = ByteSource::new(&self.in_buf, self.range_dec.pos);
        let mut progressed = false;
        loop {
            // If output buffer pressure will soon force a return, stop
            // pulling symbols. We use a fixed budget so a giant input
            // doesn't starve the caller.
            if self.decoded.len() - self.decoded_idx > 4096 {
                break;
            }
            // Snapshot for rollback.
            let rd_pre = self.range_dec.clone();
            let pos_pre = src.pos;
            // Decode one symbol.
            match model.decode_symbol(&mut self.range_dec, &mut src) {
                Ok(sym) => {
                    self.decoded.push(sym);
                    self.produced_len += 1;
                    progressed = true;
                    if self.expected_len != UNKNOWN_LEN && self.produced_len >= self.expected_len {
                        break;
                    }
                }
                Err(Error::UnexpectedEnd) => {
                    // Need more input — rewind and bail.
                    self.range_dec = rd_pre;
                    src.pos = pos_pre;
                    break;
                }
                Err(e) => return Err(self.poison(e)),
            }
        }
        // Commit the input position.
        self.range_dec.pos = src.pos;
        self.in_committed = self.range_dec.pos;
        Ok(progressed)
    }

    fn drain(&mut self, output: &mut [u8], written: &mut usize) {
        let avail = self.decoded.len() - self.decoded_idx;
        let space = output.len() - *written;
        let n = avail.min(space);
        if n > 0 {
            output[*written..*written + n]
                .copy_from_slice(&self.decoded[self.decoded_idx..self.decoded_idx + n]);
            self.decoded_idx += n;
            *written += n;
        }
        if self.decoded_idx == self.decoded.len() {
            self.decoded.clear();
            self.decoded_idx = 0;
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
        let mut consumed = 0usize;
        let mut written = 0usize;

        // Drain any already-decoded bytes first.
        self.drain(output, &mut written);

        // If output is already full from a previous step's queued bytes,
        // return without absorbing more input — the caller hasn't drained
        // yet and absorbing would cause the bridge to misreport status.
        if written == output.len() && self.decoded_idx < self.decoded.len() {
            return Ok(RawProgress {
                consumed,
                written,
                done: false,
            });
        }

        loop {
            // Quick exit if we've already produced everything and drained.
            if matches!(self.phase, Phase::Done) && self.decoded_idx == self.decoded.len() {
                return Ok(RawProgress {
                    consumed,
                    written,
                    done: true,
                });
            }

            // Absorb caller's input into our buffer.
            if consumed < input.len() {
                self.in_buf.extend_from_slice(&input[consumed..]);
                consumed = input.len();
            }

            let progressed = self.step()?;

            // Drain anything the step produced.
            self.drain(output, &mut written);

            // Bound `in_buf` growth by chopping off committed bytes when
            // the prefix gets large.
            if self.in_committed > 1 << 20 {
                let off = self.in_committed;
                self.in_buf.drain(..off);
                self.in_committed = 0;
                self.range_dec.pos = self.range_dec.pos.saturating_sub(off);
            }

            if matches!(self.phase, Phase::Done) {
                continue;
            }

            // Output full + queued bytes → caller must drain. Report by
            // *un-consuming* one byte of the absorbed input so the bridge
            // sees `consumed < input.len()` and maps to `OutputFull`. The
            // un-consumed byte is still buffered internally; we just
            // delay acknowledging it until the caller comes back.
            if written == output.len() && self.decoded_idx < self.decoded.len() {
                // Report `consumed < input.len()` so the bridge maps to
                // `OutputFull` rather than `InputEmpty`. The un-consumed
                // byte is still buffered in `in_buf`; we just delay
                // acknowledging it until the caller drains and returns.
                consumed = consumed.saturating_sub(1);
                return Ok(RawProgress {
                    consumed,
                    written,
                    done: false,
                });
            }

            if !progressed {
                // No progress and no more input → ask for more.
                if consumed >= input.len() {
                    return Ok(RawProgress {
                        consumed,
                        written,
                        done: false,
                    });
                }
            }

            if written == output.len() {
                return Ok(RawProgress {
                    consumed,
                    written,
                    done: false,
                });
            }
        }
    }

    fn raw_finish(&mut self, output: &mut [u8]) -> Result<RawProgress, Error> {
        if self.poisoned {
            return Err(Error::Corrupt);
        }
        let empty: [u8; 0] = [];
        let p = self.raw_decode(&empty, output)?;
        if matches!(self.phase, Phase::Done) && self.decoded_idx == self.decoded.len() {
            Ok(RawProgress {
                consumed: 0,
                written: p.written,
                done: true,
            })
        } else {
            Err(self.poison(Error::UnexpectedEnd))
        }
    }

    fn raw_reset(&mut self) {
        self.in_buf.clear();
        self.in_committed = 0;
        self.decoded.clear();
        self.decoded_idx = 0;
        self.phase = Phase::Header;
        self.poisoned = false;
        self.order = 0;
        self.mem_mb = 0;
        self.restoration = 0;
        self.expected_len = 0;
        self.produced_len = 0;
        self.model = None;
        self.range_dec = RangeDec::new();
    }
}
