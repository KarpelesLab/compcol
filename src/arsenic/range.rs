//! Carry-less binary range/arithmetic decoder and its adaptive models.
//!
//! `NUMBITS = 26`, `ONE = 2^25` (initial `range`), `HALF = 2^24`
//! (renormalisation threshold). Bits are pulled MSB-first from the
//! compressed stream. See FORMAT-SPEC §4.

use alloc::vec;
use alloc::vec::Vec;

use crate::arsenic::tables::ModelParams;
use crate::error::Error;

/// Working precision of the coder.
const NUMBITS: u32 = 26;
/// Initial `range` value (`2^25`).
const ONE: i64 = 1 << (NUMBITS - 1);
/// Renormalisation threshold (`2^24`).
const HALF: i64 = 1 << (NUMBITS - 2);

/// MSB-first bit source over a borrowed compressed slice. Tracks an
/// absolute bit position so the caller can detect underflow without the
/// decoder ever indexing out of bounds.
pub(crate) struct BitReader<'a> {
    data: &'a [u8],
    /// Next bit position (in bits) to read.
    pos: usize,
    /// Set once a read ran past the end of `data`.
    underflow: bool,
}

impl<'a> BitReader<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            underflow: false,
        }
    }

    /// Read one bit (MSB-first). Past end-of-data returns 0 and latches the
    /// underflow flag; callers must check [`Self::underflowed`] after a
    /// decode step and treat a latched underflow as truncation.
    #[inline]
    fn next_bit(&mut self) -> i64 {
        let byte_idx = self.pos >> 3;
        if byte_idx >= self.data.len() {
            self.underflow = true;
            return 0;
        }
        let bit = (self.data[byte_idx] >> (7 - (self.pos & 7))) & 1;
        self.pos += 1;
        bit as i64
    }

    #[inline]
    pub(crate) fn underflowed(&self) -> bool {
        self.underflow
    }
}

/// One adaptive frequency model: fixed value range plus per-symbol
/// frequencies that adapt as symbols are decoded.
pub(crate) struct Model {
    first: u16,
    increment: u32,
    limit: u32,
    freq: Vec<u32>,
    total: u32,
}

impl Model {
    pub(crate) fn new(p: &ModelParams) -> Self {
        let n = p.num_symbols();
        Self {
            first: p.first,
            increment: p.increment,
            limit: p.limit,
            freq: vec![p.increment; n],
            total: p.increment * n as u32,
        }
    }

    /// Reset every frequency back to `increment` (FORMAT-SPEC §4.6 reset).
    pub(crate) fn reset(&mut self) {
        for f in self.freq.iter_mut() {
            *f = self.increment;
        }
        self.total = self.increment * self.freq.len() as u32;
    }

    /// Adapt after decoding symbol index `n`, applying the rescale rule.
    fn adapt(&mut self, n: usize) {
        self.freq[n] += self.increment;
        self.total += self.increment;
        if self.total > self.limit {
            let mut new_total = 0u32;
            for f in self.freq.iter_mut() {
                *f = (*f + 1) >> 1;
                new_total += *f;
            }
            self.total = new_total;
        }
    }
}

/// The carry-less range decoder.
pub(crate) struct RangeDecoder<'a> {
    reader: BitReader<'a>,
    range: i64,
    code: i64,
}

impl<'a> RangeDecoder<'a> {
    /// Initialise: `range = ONE`, `code` = the next 26 bits (MSB-first).
    pub(crate) fn new(data: &'a [u8]) -> Self {
        let mut reader = BitReader::new(data);
        let mut code: i64 = 0;
        for _ in 0..NUMBITS {
            code = (code << 1) | reader.next_bit();
        }
        Self {
            reader,
            range: ONE,
            code,
        }
    }

    #[inline]
    pub(crate) fn underflowed(&self) -> bool {
        self.reader.underflowed()
    }

    /// Decode one symbol from `model`, returning its index within the model
    /// (0-based). The caller maps index → value via `first + index`.
    pub(crate) fn decode_index(&mut self, model: &mut Model) -> Result<usize, Error> {
        let total = model.total as i64;
        // totalfrequency is kept >= 1 by construction (every freq >= 1), so
        // this division can never be by zero.
        if total < 1 {
            return Err(Error::Corrupt);
        }
        let r = self.range / total;
        // r could be 0 only if range < total; range >= HALF+1 after every
        // renorm and totals are bounded by 1024, so r >= 1 in practice. Guard
        // anyway to avoid a divide-by-zero on the next step.
        if r < 1 {
            return Err(Error::Corrupt);
        }
        let mut f = self.code / r;
        // Clamp the frequency target into range so a crafted stream cannot
        // select past the last symbol.
        if f >= total {
            f = total - 1;
        }

        let mut cumulative: i64 = 0;
        let mut n = model.freq.len() - 1;
        for (i, &fr) in model.freq.iter().enumerate() {
            let next = cumulative + fr as i64;
            if f < next {
                n = i;
                break;
            }
            cumulative = next;
        }
        let size = model.freq[n] as i64;
        let low = cumulative;

        let lowincr = r * low;
        self.code -= lowincr;
        if low + size == total {
            self.range -= lowincr;
        } else {
            self.range = size * r;
        }

        // Renormalise.
        let mut guard = 0u32;
        while self.range <= HALF {
            self.range <<= 1;
            self.code = (self.code << 1) | self.reader.next_bit();
            guard += 1;
            // range is positive and at least doubles each step; NUMBITS+2
            // iterations is a hard upper bound. This only triggers on a
            // corrupt/zero range, which the divide guards already catch.
            if guard > NUMBITS + 2 {
                return Err(Error::Corrupt);
            }
        }

        model.adapt(n);
        Ok(n)
    }

    /// Decode one symbol and return its *value* (`first + index`).
    #[inline]
    pub(crate) fn decode_value(&mut self, model: &mut Model) -> Result<u16, Error> {
        let n = self.decode_index(model)?;
        Ok(model.first + n as u16)
    }

    /// Decode `bits` one-bit symbols through `model`, assembling with the
    /// first decoded bit as the least-significant (FORMAT-SPEC §3).
    pub(crate) fn decode_bits(&mut self, model: &mut Model, bits: u32) -> Result<u32, Error> {
        let mut value = 0u32;
        for i in 0..bits {
            let bit = self.decode_index(model)? as u32;
            value |= bit << i;
        }
        Ok(value)
    }
}
