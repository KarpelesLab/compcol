//! PPMd streaming decoder (standalone `.ppmd` framing).
//!
//! PPMd streams carry no in-band end marker, so like the RAR3 decoder this
//! one is *buffer-then-drain*: [`raw_decode`] absorbs input, and the actual
//! model decode runs once [`raw_finish`] is called and the whole payload is
//! available. The decoded bytes are then drained to the caller across as
//! many `finish` calls as the output buffer size requires.
//!
//! See the module docs (`super`) for the 11-byte framing header. The model
//! is the full PPMII variant H core in [`super::ppmd7`], driven by the 7z
//! range decoder.

extern crate alloc;
use alloc::vec::Vec;

use crate::error::Error;
use crate::traits::{RawDecoder, RawProgress};

use super::ppmd7::Ppmd7;
use super::range_dec::{Mode, RangeDec};

const HEADER_LEN: usize = 11;
const UNKNOWN_LEN: u64 = u64::MAX;
/// Hard cap on decoded output when the header length is unknown, so a tiny
/// crafted stream can't drive unbounded work.
const MAX_UNKNOWN_OUTPUT: usize = 64 * 1024 * 1024;

pub struct Decoder {
    in_buf: Vec<u8>,
    decoded: Vec<u8>,
    decoded_idx: usize,
    started: bool,
    finished_decode: bool,
    poisoned: bool,
}

impl Decoder {
    pub fn new() -> Self {
        Self {
            in_buf: Vec::new(),
            decoded: Vec::new(),
            decoded_idx: 0,
            started: false,
            finished_decode: false,
            poisoned: false,
        }
    }

    fn poison(&mut self, e: Error) -> Error {
        self.poisoned = true;
        e
    }

    /// Decode the whole payload into `self.decoded`. Called once, lazily.
    fn run_decode(&mut self) -> Result<(), Error> {
        if self.in_buf.len() < HEADER_LEN {
            return Err(Error::UnexpectedEnd);
        }
        let h = &self.in_buf[..HEADER_LEN];
        let order = h[0] as u32;
        let mem_mb = h[1] as u32;
        let restoration = h[2];
        if !(2..=64).contains(&order) {
            return Err(Error::BadHeader);
        }
        if !(1..=255).contains(&mem_mb) {
            return Err(Error::BadHeader);
        }
        if restoration > 2 {
            return Err(Error::BadHeader);
        }
        let expected_len = u64::from_le_bytes(h[3..11].try_into().unwrap());

        let mem_bytes = mem_mb.saturating_mul(1024 * 1024);
        let mut model = Ppmd7::new(mem_bytes)?;
        model.init(order);

        let (mut rc, consumed) = RangeDec::init(Mode::SevenZip, &self.in_buf, HEADER_LEN)?;
        let _ = consumed;

        let cap = if expected_len == UNKNOWN_LEN {
            MAX_UNKNOWN_OUTPUT
        } else {
            expected_len.min(MAX_UNKNOWN_OUTPUT as u64) as usize
        };
        let mut out = Vec::with_capacity(cap.min(1 << 20));

        if expected_len == UNKNOWN_LEN {
            while out.len() < MAX_UNKNOWN_OUTPUT {
                if rc.overran() {
                    break;
                }
                let sym = model.decode_symbol(&mut rc)?;
                if rc.overran() {
                    break;
                }
                out.push(sym);
            }
        } else {
            // A declared length larger than the buffer-then-decode ceiling
            // can't be produced here; reject it up front rather than growing
            // `out` toward OOM. (A high-probability PPMd symbol can decode
            // many times without consuming input, so `overran()` alone is not
            // a sufficient bound.)
            if expected_len > MAX_UNKNOWN_OUTPUT as u64 {
                return Err(Error::OutputLimitExceeded);
            }
            for _ in 0..expected_len {
                // Truncated input can't supply more symbols; stop before the
                // model starts decoding from zero-filled reads.
                if rc.overran() {
                    return Err(Error::UnexpectedEnd);
                }
                let sym = model.decode_symbol(&mut rc)?;
                out.push(sym);
            }
            if rc.overran() {
                return Err(Error::UnexpectedEnd);
            }
            // 7z streams leave the range coder at `code == 0` after the last
            // symbol; a non-zero residue means truncation or corruption.
            if !rc.is_finished_ok() {
                return Err(Error::Corrupt);
            }
        }

        self.decoded = out;
        Ok(())
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

    fn all_drained(&self) -> bool {
        self.finished_decode && self.decoded_idx == self.decoded.len()
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
        // Absorb input; real decoding is deferred to `finish`.
        self.in_buf.extend_from_slice(input);
        let mut written = 0usize;
        if self.finished_decode {
            self.drain(output, &mut written);
        }
        Ok(RawProgress {
            consumed: input.len(),
            written,
            done: self.all_drained(),
        })
    }

    fn raw_finish(&mut self, output: &mut [u8]) -> Result<RawProgress, Error> {
        if self.poisoned {
            return Err(Error::Corrupt);
        }
        if !self.started {
            self.started = true;
            match self.run_decode() {
                Ok(()) => self.finished_decode = true,
                Err(e) => return Err(self.poison(e)),
            }
        }
        let mut written = 0usize;
        self.drain(output, &mut written);
        Ok(RawProgress {
            consumed: 0,
            written,
            done: self.all_drained(),
        })
    }

    fn raw_reset(&mut self) {
        self.in_buf.clear();
        self.decoded.clear();
        self.decoded_idx = 0;
        self.started = false;
        self.finished_decode = false;
        self.poisoned = false;
    }
}
