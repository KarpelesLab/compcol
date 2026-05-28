//! Bit readers used by the LZFSE v2 decoder.
//!
//! LZFSE v2 has two distinct bit-stream conventions:
//!
//! - **`HeaderBits`** — used only inside the v2 block header to crack the
//!   packed 8-byte sequence of small-bit-width fields (20, 20, 10, …).
//!   Pure LSB-first over a small contiguous byte slice.
//! - **`FseBits`** — used by the literal-stream and LMD-stream FSE decoders.
//!   Reads the bitstream **from the end of the payload toward the start**:
//!   the FSE encoder works LIFO so the decoder undoes the encoder by
//!   pulling bits in reverse. State is `(accum: u64, n_bits: i32, end: i32)`
//!   where `end` is the byte index of the next unread byte (working down).
//!   This mirrors Apple's reference `fse_in_stream` precisely.
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
/// Apple's reference layout (`fse_in_stream`):
/// - The encoder, after appending the last FSE state-pull bits to its output
///   buffer, flushes any remaining bits as a "stub" at the very end. The
///   decoder restores that stub from the LMD payload's final byte and then
///   pulls fresh bytes off the end of the payload as needed.
/// - `n_bits` may be negative immediately after init (we owe up to 7 bits to
///   the buffer); after the first `pull` it is in `0..=63`.
///
/// `payload` is the FSE encoded bitstream (concatenation of literal stream
/// then LMD stream, in the v2 block's outer layout). The caller passes the
/// slice that ends exactly at the end of the stream being decoded — for the
/// literal stream that's the last byte of the literal payload, for the LMD
/// stream that's the last byte of the LMD payload.
pub(crate) struct FseBits<'a> {
    /// Buffer the bitstream lives in. The decoder consumes bytes from the
    /// end (index `end - 1`, then `end - 2`, …).
    pub(crate) payload: &'a [u8],
    /// Number of bits currently buffered in `accum` (high bits unused if
    /// `n_bits < 64`).
    pub(crate) n_bits: i32,
    /// Bits, right-justified. The high `n_bits` bits are valid; the bottom
    /// `64 - n_bits` are pending.
    pub(crate) accum: u64,
    /// Index of the next-byte-to-pull. Bytes are pulled from `end - 1`
    /// down to `0`. Once `end == 0` no more bytes are available.
    pub(crate) end: usize,
}

impl<'a> FseBits<'a> {
    /// Initialise the reader with the encoder's last-byte "stub":
    /// after the encoder finished pushing FSE bits its accumulator had
    /// `n_bits` (0..=7) bits left. The encoder writes those `n_bits` bits
    /// at the top of the final byte. The decoder starts by reading exactly
    /// that final byte and treating its top `n_bits` bits as the initial
    /// buffer state.
    ///
    /// `stub_bits` must be `0..=7`.
    pub(crate) fn new_with_stub(payload: &'a [u8], stub_bits: u32) -> Result<Self, Error> {
        debug_assert!(stub_bits <= 7);
        if payload.is_empty() {
            // Stream is the entirety of zero bytes — only acceptable when
            // the FSE decoder will not actually need to pull anything.
            return Ok(Self {
                payload,
                n_bits: -(stub_bits as i32),
                accum: 0,
                end: 0,
            });
        }
        let mut s = Self {
            payload,
            n_bits: 0,
            accum: 0,
            end: payload.len(),
        };
        // Read the final byte, take the top stub_bits bits.
        s.end -= 1;
        let last = payload[s.end] as u64;
        // Apple uses 7 - stub_bits as the right-shift but the encoder writes
        // the stub in the lower bits of that byte (LSB-first packing for the
        // last bits). The reference is subtle; we mirror it: accumulate the
        // stub bits into accum's bottom.
        s.accum = last & ((1u64 << stub_bits) - 1);
        s.n_bits = stub_bits as i32;
        Ok(s)
    }

    /// Top up the bit buffer by pulling fresh bytes from the end of the
    /// payload. After this call, `n_bits >= 56` (or we ran out of input).
    pub(crate) fn refill(&mut self) {
        while self.n_bits <= 56 && self.end > 0 {
            self.end -= 1;
            let b = self.payload[self.end] as u64;
            // Bytes pulled from the end of the stream go to the high end of
            // accum (the next bits the decoder will read).
            self.accum |= b << self.n_bits;
            self.n_bits += 8;
        }
    }

    /// Pull `n` bits (`n <= 56` after the first refill) from the bottom of
    /// the buffer. Caller is responsible for refilling before each pull.
    pub(crate) fn pull(&mut self, n: u32) -> Result<u64, Error> {
        if (self.n_bits as u32) < n {
            return Err(Error::Corrupt);
        }
        let mask = if n == 64 { u64::MAX } else { (1u64 << n) - 1 };
        let v = self.accum & mask;
        self.accum >>= n;
        self.n_bits -= n as i32;
        Ok(v)
    }
}
