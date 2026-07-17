//! Carry-less range decoder for PPMd variant H, in both flavours:
//!
//! - **7z** (`Ppmd7z_RangeDec`) — used by 7-Zip's `PPMd` method and the
//!   standalone `.ppmd` framing in this crate. Init consumes a leading
//!   `0x00` byte plus four big-endian bytes; `decode` subtracts from
//!   `code`; `Bottom == 0`.
//! - **RAR** (`PpmdRAR_RangeDec`) — used by RAR3/4 PPMd blocks. Init
//!   consumes four big-endian bytes (no leading zero); `decode` adds to a
//!   tracked `low`; `Bottom == 0x8000`; bit decoding routes through
//!   `get_threshold` + `decode` rather than the 7z fast path.
//!
//! Both share `get_threshold` (`range /= total; (code - low) / range`) and
//! the `low`/`bottom`-aware normalisation. Derived from the public-domain
//! `Ppmd7Dec.c` (LZMA SDK) and the RAR variant described in libarchive's
//! BSD RAR reader; no license-restricted code was copied.

use crate::error::Error;

const K_TOP_VALUE: u32 = 1 << 24;
const PPMD_BIN_SCALE: u32 = 1 << 14;
/// Safety cap on normalisation iterations (a well-formed stream needs at
/// most a few); prevents a crafted/truncated stream from spinning.
const MAX_NORMALIZE_STEPS: u32 = 64;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    SevenZip,
    /// RAR3/4 PPMd blocks. Only constructed behind the `rar3` feature.
    #[cfg_attr(not(feature = "rar3"), allow(dead_code))]
    Rar,
}

pub(crate) struct RangeDec<'a> {
    range: u32,
    code: u32,
    low: u32,
    bottom: u32,
    mode: Mode,
    input: &'a [u8],
    pos: usize,
    err: bool,
}

impl<'a> RangeDec<'a> {
    /// Construct and initialise from `input[start..]`. Returns the decoder
    /// and the number of input bytes the init consumed.
    pub(crate) fn init(mode: Mode, input: &'a [u8], start: usize) -> Result<(Self, usize), Error> {
        let mut d = RangeDec {
            range: 0xFFFF_FFFF,
            code: 0,
            low: 0,
            bottom: 0,
            mode,
            input,
            pos: start,
            err: false,
        };
        let consumed = match mode {
            Mode::SevenZip => {
                // First byte must be zero, then 4 big-endian bytes.
                if input.len() < start + 5 {
                    return Err(Error::UnexpectedEnd);
                }
                if input[start] != 0 {
                    return Err(Error::Corrupt);
                }
                d.pos = start + 1;
                for _ in 0..4 {
                    d.code = (d.code << 8) | d.read_byte() as u32;
                }
                d.bottom = 0;
                5
            }
            Mode::Rar => {
                if input.len() < start + 4 {
                    return Err(Error::UnexpectedEnd);
                }
                for _ in 0..4 {
                    d.code = (d.code << 8) | d.read_byte() as u32;
                }
                d.bottom = 0x8000;
                4
            }
        };
        Ok((d, consumed))
    }

    #[inline]
    pub(crate) fn err(&self) -> bool {
        self.err
    }

    /// The stream read past the end of the available input.
    #[inline]
    pub(crate) fn overran(&self) -> bool {
        self.pos > self.input.len()
    }

    /// Byte position in the input the decoder has consumed up to (including
    /// the init bytes and any normalisation look-ahead). RAR3 resumes its
    /// bit-domain block headers at this offset when a PPMd block ends.
    #[inline]
    #[cfg_attr(not(feature = "rar3"), allow(dead_code))]
    pub(crate) fn pos(&self) -> usize {
        self.pos.min(self.input.len())
    }

    #[inline]
    fn read_byte(&mut self) -> u8 {
        let b = self.input.get(self.pos).copied().unwrap_or(0);
        // Advance regardless so `pos`/`overran` reflect demand; a real
        // stream never reads past the last symbol's bytes.
        self.pos += 1;
        b
    }

    /// `range /= total; return (code - low) / range`.
    #[inline]
    pub(crate) fn get_threshold(&mut self, total: u32) -> u32 {
        if total == 0 {
            self.err = true;
            return 0;
        }
        self.range /= total;
        if self.range == 0 {
            self.err = true;
            return 0;
        }
        self.code.wrapping_sub(self.low) / self.range
    }

    /// Advance past a decoded interval `[start, start+size)`.
    #[inline]
    pub(crate) fn decode(&mut self, start: u32, size: u32) {
        match self.mode {
            Mode::SevenZip => {
                self.code = self.code.wrapping_sub(start.wrapping_mul(self.range));
            }
            Mode::Rar => {
                self.low = self.low.wrapping_add(start.wrapping_mul(self.range));
            }
        }
        self.range = self.range.wrapping_mul(size);
        self.normalize();
    }

    /// Decode one binary decision with probability `size0` (out of
    /// `PPMD_BIN_SCALE`). Returns the bit.
    #[inline]
    pub(crate) fn decode_bit(&mut self, size0: u32) -> u32 {
        match self.mode {
            Mode::SevenZip => {
                let new_bound = (self.range >> 14) * size0;
                if self.code < new_bound {
                    self.range = new_bound;
                    self.normalize();
                    0
                } else {
                    self.code -= new_bound;
                    self.range -= new_bound;
                    self.normalize();
                    1
                }
            }
            Mode::Rar => {
                let value = self.get_threshold(PPMD_BIN_SCALE);
                if value < size0 {
                    self.decode(0, size0);
                    0
                } else {
                    self.decode(size0, PPMD_BIN_SCALE - size0);
                    1
                }
            }
        }
    }

    #[inline]
    fn normalize(&mut self) {
        let mut steps = 0u32;
        loop {
            if (self.low ^ self.low.wrapping_add(self.range)) >= K_TOP_VALUE {
                if self.range >= self.bottom {
                    break;
                }
                // range too small: clamp to the bottom window (RAR path).
                self.range = self.low.wrapping_neg() & self.bottom.wrapping_sub(1);
            }
            self.code = (self.code << 8) | self.read_byte() as u32;
            self.range <<= 8;
            self.low <<= 8;
            steps += 1;
            if steps > MAX_NORMALIZE_STEPS {
                self.err = true;
                break;
            }
        }
    }

    /// 7z terminal check: after the final symbol the encoder leaves
    /// `code == 0`.
    #[inline]
    pub(crate) fn is_finished_ok(&self) -> bool {
        self.code == 0
    }
}
