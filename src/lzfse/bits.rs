//! Bit readers used by the LZFSE v2 decoder.
//!
//! LZFSE v2 has two distinct bit-stream conventions:
//!
//! - **`HeaderBits`** — used only inside the v2 block header to crack the
//!   packed 8-byte sequence of small-bit-width fields (20, 20, 10, …).
//!   Pure LSB-first over a small contiguous byte slice.
//! - **`FseBits`** — used by the literal-stream and LMD-stream FSE decoders.
//!   Reads the bitstream **from the end of the payload toward the start**,
//!   most-significant bit first: the FSE encoder works LIFO so the decoder
//!   undoes the encoder by pulling bits in reverse. This mirrors Apple's
//!   reference `fse_in_stream`.
//!
//! ## Status
//!
//! Both readers are wired in but only used by [`super::fse`] which itself
//! is gated off pending the `bvx2` decoder. They're kept here so the v2
//! work doesn't have to redo the bit-reader scaffolding.

#![allow(dead_code)]

use crate::error::Error;

/// LSB-first reader over a small contiguous byte slice. Used to crack the
/// packed v2 header fields, which are not byte-aligned.
pub(crate) struct HeaderBits<'a> {
    bytes: &'a [u8],
    /// Bit position (0 = first bit of first byte).
    pos: usize,
}

impl<'a> HeaderBits<'a> {
    pub(crate) const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    /// Read `n` bits (`n <= 32`). Returns `Error::Corrupt` if the request
    /// runs off the end of the slice.
    pub(crate) fn read(&mut self, n: u32) -> Result<u32, Error> {
        debug_assert!(n <= 32);
        if n == 0 {
            return Ok(0);
        }
        let end = self.pos + n as usize;
        if end > self.bytes.len() * 8 {
            return Err(Error::Corrupt);
        }
        let mut value: u32 = 0;
        for i in 0..n as usize {
            let bit_idx = self.pos + i;
            let b = (self.bytes[bit_idx / 8] >> (bit_idx % 8)) & 1;
            value |= (b as u32) << i;
        }
        self.pos = end;
        Ok(value)
    }

    pub(crate) fn read_u64(&mut self, n: u32) -> Result<u64, Error> {
        debug_assert!(n <= 64);
        if n == 0 {
            return Ok(0);
        }
        let end = self.pos + n as usize;
        if end > self.bytes.len() * 8 {
            return Err(Error::Corrupt);
        }
        let mut value: u64 = 0;
        for i in 0..n as usize {
            let bit_idx = self.pos + i;
            let b = (self.bytes[bit_idx / 8] >> (bit_idx % 8)) & 1;
            value |= (b as u64) << i;
        }
        self.pos = end;
        Ok(value)
    }
}

/// FSE bit-stream reader. Reads from the END of `payload` toward the start.
///
/// Apple's reference layout (`fse_in_stream` in `lzfse_internal.h`): the
/// payload is a little-endian bit string whose **most significant** bits are
/// read first. Bit `b` of the stream is bit `b % 8` of byte `b / 8`; the
/// reader starts at the top of the payload and every `pull(n)` returns the
/// `n` bits immediately below the current position as an integer (the
/// first-pulled bit is the value's MSB), then moves down.
///
/// The block header stores a 3-bit field `f` per stream; Apple's decoder
/// initialises with `nbits = f - 7`, i.e. the top `7 - f` bits of the
/// payload's last byte are unused and the stream starts below them.
///
/// The caller passes the slice that ends exactly at the end of the stream
/// being decoded — the literal payload or the LMD payload.
pub(crate) struct FseBits<'a> {
    /// Buffer the bitstream lives in.
    pub(crate) payload: &'a [u8],
    /// Number of unread bits: the next `pull(n)` returns bits
    /// `[pos - n, pos)`.
    pub(crate) pos: usize,
}

impl<'a> FseBits<'a> {
    /// Initialise the reader from the header's 3-bit `bits_field`
    /// (`literal_bits` / `lmd_bits`, `0..=7`): the top `7 - bits_field`
    /// bits of the final payload byte are skipped.
    pub(crate) fn new_with_stub(payload: &'a [u8], bits_field: u32) -> Result<Self, Error> {
        if bits_field > 7 {
            return Err(Error::Corrupt);
        }
        let unused = (7 - bits_field) as usize;
        // An empty payload can only back a stream that never pulls a bit.
        let pos = (payload.len() * 8).saturating_sub(unused);
        Ok(Self { payload, pos })
    }

    /// Counterpart of Apple's `fse_in_flush`. This reader addresses the
    /// payload directly, so there is nothing to top up.
    #[inline]
    pub(crate) fn refill(&mut self) {}

    /// Pull `n` bits (`n <= 32`) from the top of the remaining stream.
    pub(crate) fn pull(&mut self, n: u32) -> Result<u64, Error> {
        debug_assert!(n <= 32);
        let n = n as usize;
        if n == 0 {
            return Ok(0);
        }
        if self.pos < n {
            return Err(Error::Corrupt);
        }
        let lo = self.pos - n;
        let mut word = 0u64;
        for (i, &b) in self.payload[lo / 8..=(self.pos - 1) / 8].iter().enumerate() {
            word |= (b as u64) << (8 * i);
        }
        self.pos = lo;
        Ok((word >> (lo % 8)) & ((1u64 << n) - 1))
    }
}
