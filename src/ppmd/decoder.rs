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
/// Sentinel length meaning "unknown". PPMd has no in-band end-of-stream
/// marker, so a stream framed with this length can't be decoded reliably
/// (see [`Decoder::run_decode`]) — it's refused rather than decoded to a
/// guess.
const UNKNOWN_LEN: u64 = u64::MAX;
/// Hard cap on decoded output, so a tiny crafted stream declaring a huge
/// length can't drive unbounded allocation/work.
const MAX_OUTPUT: usize = 64 * 1024 * 1024;

pub struct Decoder {
    in_buf: Vec<u8>,
    decoded: Vec<u8>,
    decoded_idx: usize,
    started: bool,
    header_checked: bool,
    finished_decode: bool,
    /// Set on the first irrecoverable error; every later call re-reports
    /// the same error (so an early header rejection in `decode` reads the
    /// same from a follow-up `finish`).
    poisoned: Option<Error>,
}

/// Validate the 11-byte framing header, returning the declared unpacked
/// length. Called from `raw_decode` as soon as 11 bytes have been buffered
/// (so a hostile stream with a bad header is rejected immediately instead
/// of after buffering its whole payload) and again from `run_decode`.
fn validate_header(h: &[u8]) -> Result<u64, Error> {
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
    // PPMd carries no in-band end-of-stream marker, so a stream whose
    // header declares an unknown length has no reliable terminal
    // condition: after the true last symbol the range coder's finalisation
    // bytes keep decoding into extra (garbage) symbols, and exhausting the
    // physical input is not an end signal (a high-probability symbol
    // decodes without consuming any input). Refuse rather than emit a
    // guess.
    if expected_len == UNKNOWN_LEN {
        return Err(Error::Unsupported);
    }
    // A declared length larger than the buffer-then-decode ceiling can't
    // be produced here; reject it up front rather than growing the output
    // toward OOM.
    if expected_len > MAX_OUTPUT as u64 {
        return Err(Error::OutputLimitExceeded);
    }
    Ok(expected_len)
}

impl Decoder {
    pub fn new() -> Self {
        Self {
            in_buf: Vec::new(),
            decoded: Vec::new(),
            decoded_idx: 0,
            started: false,
            header_checked: false,
            finished_decode: false,
            poisoned: None,
        }
    }

    fn poison(&mut self, e: Error) -> Error {
        self.poisoned = Some(e);
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
        let expected_len = validate_header(h)?;

        let mem_bytes = mem_mb.saturating_mul(1024 * 1024);
        let mut model = Ppmd7::new(mem_bytes)?;
        model.init(order);

        let (mut rc, consumed) = RangeDec::init(Mode::SevenZip, &self.in_buf, HEADER_LEN)?;
        let _ = consumed;

        let mut out = Vec::with_capacity((expected_len as usize).min(1 << 20));

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
        if let Some(e) = self.poisoned {
            return Err(e);
        }
        // Absorb input; real decoding is deferred to `finish`. The header
        // is validated as soon as it is complete so a hostile stream fails
        // after 11 bytes instead of after buffering its whole payload.
        self.in_buf.extend_from_slice(input);
        if !self.header_checked && self.in_buf.len() >= HEADER_LEN {
            self.header_checked = true;
            if let Err(e) = validate_header(&self.in_buf[..HEADER_LEN]) {
                return Err(self.poison(e));
            }
        }
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
        if let Some(e) = self.poisoned {
            return Err(e);
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
        self.header_checked = false;
        self.finished_decode = false;
        self.poisoned = None;
    }
}
