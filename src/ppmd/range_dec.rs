//! Carry-less 7z range decoder used by PPMd variant H.
//!
//! Differences from the LZMA range decoder:
//!
//! - **No "first byte must be zero" rule** in the encoder/decoder
//!   protocol per se, but the reference `Ppmd7z_RangeDec_Init` requires
//!   the first byte read to be `0x00`. (Hand-rolled fixtures and every
//!   7z-/RAR-/ZIP-produced stream do start with `0x00`.)
//! - **`code` is initialised from the next four bytes** big-endian, and
//!   `range` starts at `0xFFFF_FFFF`. The decoder calls
//!   `Range_Normalize` which conditionally pulls one byte at a time and
//!   handles two consecutive shifts.
//! - **`Range_GetThreshold(total)` divides `range /= total`** (mutating
//!   `range`!), then returns `code / range`. The decoder uses that
//!   quotient as the symbol index into the frequency table.
//! - **`Range_DecodeBit(size0)`** uses an explicit 14-bit shift
//!   (`range >> 14`) and never updates probabilities (the model owns
//!   that — see `PPMD_UPDATE_PROB_*`).
//!
//! Streaming: callers pull bytes from an internal buffered byte source.
//! When the decoder needs a byte and the buffer is empty, the symbol
//! decode aborts upward via `NeedInput` so the outer loop can refill.

use crate::error::Error;

const K_TOP_VALUE: u32 = 1 << 24;

/// Trait-free byte source so the decoder can be driven either from a
/// pre-buffered slice (during a decode call) or from a "we already read
/// past the end" sentinel during init.
pub(super) struct ByteSource<'a> {
    pub buf: &'a [u8],
    pub pos: usize,
}

impl<'a> ByteSource<'a> {
    pub fn new(buf: &'a [u8], pos: usize) -> Self {
        Self { buf, pos }
    }

    /// Returns the next byte and advances `pos`. `Err(UnexpectedEnd)`
    /// when starved — the outer streaming machinery is expected to
    /// translate that into a `NeedInput` rollback by snapshotting state
    /// before the symbol decode begins.
    #[inline]
    pub fn read(&mut self) -> Result<u8, Error> {
        let b = *self.buf.get(self.pos).ok_or(Error::UnexpectedEnd)?;
        self.pos += 1;
        Ok(b)
    }
}

#[derive(Clone, Debug)]
pub(super) struct RangeDec {
    pub range: u32,
    pub code: u32,
    /// Position into the caller's buffered input where the next byte
    /// will be read from.
    pub pos: usize,
}

impl RangeDec {
    pub fn new() -> Self {
        Self {
            range: 0,
            code: 0,
            pos: 0,
        }
    }

    /// Initialise from the first 5 bytes of the PPMd payload. First byte
    /// must be zero; the remaining four are big-endian and form the
    /// initial `code`.
    ///
    /// Returns `Ok(true)` on successful init, `Ok(false)` if input was
    /// short. On `code == 0xFFFF_FFFF` (reference rejects it) returns
    /// `Err(Corrupt)`.
    pub fn init(&mut self, buf: &[u8]) -> Result<bool, Error> {
        if buf.len() < self.pos + 5 {
            return Ok(false);
        }
        if buf[self.pos] != 0 {
            return Err(Error::Corrupt);
        }
        let b1 = buf[self.pos + 1] as u32;
        let b2 = buf[self.pos + 2] as u32;
        let b3 = buf[self.pos + 3] as u32;
        let b4 = buf[self.pos + 4] as u32;
        self.code = (b1 << 24) | (b2 << 16) | (b3 << 8) | b4;
        self.range = 0xFFFF_FFFF;
        self.pos += 5;
        if self.code == 0xFFFF_FFFF {
            return Err(Error::Corrupt);
        }
        Ok(true)
    }

    /// `range /= total; return code / range`. Mutates `self.range`.
    #[inline]
    pub fn get_threshold(&mut self, total: u32) -> u32 {
        self.range /= total;
        self.code / self.range
    }

    /// `range *= size`; advance `code` by `start * range_before`.
    /// `range` has already been divided by `total` by `get_threshold`.
    #[inline]
    pub fn decode(&mut self, src: &mut ByteSource<'_>, start: u32, size: u32) -> Result<(), Error> {
        self.code = self.code.wrapping_sub(start.wrapping_mul(self.range));
        self.range = self.range.wrapping_mul(size);
        self.normalize(src)
    }

    /// Pull bytes while `range < 1<<24`. The reference loops at most
    /// twice (`range` is shifted by 8 per iteration, so two iterations
    /// take `range` from anywhere in `1..1<<24` to `>=1<<24`).
    #[inline]
    pub fn normalize(&mut self, src: &mut ByteSource<'_>) -> Result<(), Error> {
        if self.range < K_TOP_VALUE {
            self.code = (self.code << 8) | src.read()? as u32;
            self.range <<= 8;
            if self.range < K_TOP_VALUE {
                self.code = (self.code << 8) | src.read()? as u32;
                self.range <<= 8;
            }
        }
        Ok(())
    }

    /// Reference's `Ppmd7z_RangeDec_IsFinishedOK`. After draining the
    /// final symbol the encoder leaves `code == 0`; anything else means
    /// the stream was truncated or the model dropped a symbol.
    #[inline]
    pub fn is_finished_ok(&self) -> bool {
        self.code == 0
    }
}
