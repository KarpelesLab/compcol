#![allow(dead_code)] // some helpers are read only by tests / future encoder polish

//! MSB-first bit reader and bit writer for the bzip2 wire format.
//!
//! bzip2 packs bits **high bit first**: byte `0xAB` is the bitstring
//! `1010 1011` reading left-to-right; reading `read_bits(4)` from a
//! fresh stream that starts at `0xAB` returns `0b1010 = 0xA`.
//!
//! This is the opposite of deflate's LSB-first packing (which is why we
//! don't reuse `src/bits.rs` here — its layout is the wrong way round
//! for bzip2).
//!
//! The reader operates on an immutable input slice plus a cursor; the
//! writer accumulates into a `Vec<u8>`. Both keep an 8-bit "current
//! byte" register with a count of how many bits in it are already
//! valid; the reader fills it from the input as needed, the writer
//! flushes it to the vector once it fills up.

extern crate alloc;
use alloc::vec::Vec;

use crate::error::Error;

/// MSB-first bit reader over a borrowed input slice.
///
/// Constructed once per block-decode attempt; rewinds via the
/// borrow-checker rules (caller restarts decoding from the beginning of
/// a new input buffer when more data arrives). Tracks a position in
/// **bits**, but exposes byte-aligned reads where the wire format calls
/// for them.
pub(crate) struct BitReader<'a> {
    buf: &'a [u8],
    /// Current bit position from the start of `buf`. Bit 0 of byte 0
    /// is the MSB of `buf[0]`.
    bit_pos: usize,
}

impl<'a> BitReader<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self { buf, bit_pos: 0 }
    }

    /// Construct a reader pre-positioned at `bit_pos` bits from the
    /// start of `buf`. Used by the bzip2 decoder to resume from a
    /// snapshotted position without paying the cost of re-walking
    /// every previously-read bit.
    pub(crate) fn new_at(buf: &'a [u8], bit_pos: usize) -> Self {
        Self { buf, bit_pos }
    }

    /// Total number of bits available in the underlying buffer.
    #[inline]
    pub(crate) fn total_bits(&self) -> usize {
        self.buf.len() * 8
    }

    /// Bits remaining from the current position.
    #[inline]
    pub(crate) fn remaining(&self) -> usize {
        self.total_bits().saturating_sub(self.bit_pos)
    }

    /// Bits already consumed.
    #[inline]
    pub(crate) fn position(&self) -> usize {
        self.bit_pos
    }

    /// Number of whole bytes fully consumed so far (rounding the bit
    /// position down).
    #[inline]
    pub(crate) fn bytes_consumed(&self) -> usize {
        self.bit_pos / 8
    }

    /// Skip ahead to the next byte boundary.
    pub(crate) fn align_to_byte(&mut self) {
        let rem = self.bit_pos & 7;
        if rem != 0 {
            self.bit_pos += 8 - rem;
        }
    }

    /// Read a single bit. Returns the bit as 0 or 1.
    #[inline]
    pub(crate) fn read_bit(&mut self) -> Result<u32, Error> {
        if self.bit_pos >= self.total_bits() {
            return Err(Error::UnexpectedEnd);
        }
        let byte = self.buf[self.bit_pos >> 3];
        // MSB-first: bit index within byte is (7 - (bit_pos % 8)).
        let shift = 7 - (self.bit_pos & 7);
        let v = (byte >> shift) & 1;
        self.bit_pos += 1;
        Ok(v as u32)
    }

    /// Read `n` bits (1..=32), MSB-first, packed into a `u32`.
    ///
    /// The first bit read becomes the highest bit of the returned value
    /// (so `read_bits(8)` on a stream starting with byte 0xAB returns
    /// 0xAB).
    pub(crate) fn read_bits(&mut self, n: u32) -> Result<u32, Error> {
        debug_assert!(n <= 32);
        let mut v: u32 = 0;
        for _ in 0..n {
            v = (v << 1) | self.read_bit()?;
        }
        Ok(v)
    }

    /// Read 48 bits in MSB-first order; used for the block and stream
    /// magic numbers.
    pub(crate) fn read_bits_48(&mut self) -> Result<u64, Error> {
        let hi = self.read_bits(24)? as u64;
        let lo = self.read_bits(24)? as u64;
        Ok((hi << 24) | lo)
    }
}

/// MSB-first bit writer accumulating into an output `Vec<u8>`.
pub(crate) struct BitWriter {
    out: Vec<u8>,
    /// Bits-in-flight in the high portion of `cur`; `nbits` of them
    /// are valid (left-aligned), with `8 - nbits` zero placeholders at
    /// the low end.
    cur: u8,
    nbits: u8,
}

impl BitWriter {
    pub(crate) fn new() -> Self {
        Self {
            out: Vec::new(),
            cur: 0,
            nbits: 0,
        }
    }

    pub(crate) fn with_capacity(cap: usize) -> Self {
        Self {
            out: Vec::with_capacity(cap),
            cur: 0,
            nbits: 0,
        }
    }

    /// Write a single bit (0 or 1).
    #[inline]
    pub(crate) fn write_bit(&mut self, b: u32) {
        self.cur = (self.cur << 1) | ((b & 1) as u8);
        self.nbits += 1;
        if self.nbits == 8 {
            self.out.push(self.cur);
            self.cur = 0;
            self.nbits = 0;
        }
    }

    /// Write `n` bits (1..=32) of `v`, MSB-first.
    pub(crate) fn write_bits(&mut self, n: u32, v: u32) {
        debug_assert!(n <= 32);
        // Walk from MSB of the n-bit field down to bit 0.
        let mut i = n;
        while i > 0 {
            i -= 1;
            self.write_bit((v >> i) & 1);
        }
    }

    /// Write a 48-bit field (used for the bzip2 block and stream magic
    /// numbers).
    pub(crate) fn write_bits_48(&mut self, v: u64) {
        // Top 24 bits first, then low 24 bits.
        let hi = ((v >> 24) & 0x00FF_FFFF) as u32;
        let lo = (v & 0x00FF_FFFF) as u32;
        self.write_bits(24, hi);
        self.write_bits(24, lo);
    }

    /// Flush any in-flight bits, padding the final byte with zeros at
    /// the LSB end (as bzip2 specifies for its end-of-stream alignment).
    pub(crate) fn align_to_byte(&mut self) {
        if self.nbits > 0 {
            // Shift the partial byte so the valid bits sit in the high
            // positions, then push.
            self.cur <<= 8 - self.nbits;
            self.out.push(self.cur);
            self.cur = 0;
            self.nbits = 0;
        }
    }

    /// Consume the writer, returning the assembled bytes. The caller
    /// should usually call `align_to_byte` first; if there are pending
    /// bits, this will silently drop them.
    pub(crate) fn into_bytes(mut self) -> Vec<u8> {
        // Defensive flush. Real call sites call align_to_byte() at the
        // end of the stream footer; this just makes the writer
        // accident-proof when used elsewhere.
        if self.nbits > 0 {
            self.cur <<= 8 - self.nbits;
            self.out.push(self.cur);
        }
        self.out
    }

    /// Bypass for the bzip2 encoder: split out the assembled whole-byte
    /// buffer and the partial trailing byte (with its bit count) so the
    /// encoder can periodically drain whole bytes without losing the
    /// partial byte across calls. The partial byte is returned with the
    /// valid bits **left-aligned** into the low end of the count — i.e.
    /// the same internal representation the writer uses.
    pub(crate) fn internals_for_encoder(self) -> (Vec<u8>, u8, u8) {
        (self.out, self.cur, self.nbits)
    }

    /// Reverse of `internals_for_encoder` — start a writer with a
    /// pre-existing partial byte. The output buffer starts empty; only
    /// the partial-byte state is restored.
    pub(crate) fn rehydrate(cur: u8, nbits: u8) -> Self {
        debug_assert!(nbits < 8, "partial byte should hold fewer than 8 bits");
        Self {
            out: Vec::new(),
            cur,
            nbits,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn round_trip_msb_first() {
        // Write 0xAB byte = 1010 1011 as 8 bits, read back, get 0xAB.
        let mut w = BitWriter::new();
        w.write_bits(8, 0xAB);
        let bytes = w.into_bytes();
        assert_eq!(bytes, vec![0xAB]);
        let mut r = BitReader::new(&bytes);
        assert_eq!(r.read_bits(8).unwrap(), 0xAB);
    }

    #[test]
    fn nibble_split() {
        // Top nibble is read first.
        let mut w = BitWriter::new();
        w.write_bits(4, 0xA);
        w.write_bits(4, 0xB);
        let bytes = w.into_bytes();
        assert_eq!(bytes, vec![0xAB]);
        let mut r = BitReader::new(&bytes);
        assert_eq!(r.read_bits(4).unwrap(), 0xA);
        assert_eq!(r.read_bits(4).unwrap(), 0xB);
    }

    #[test]
    fn cross_byte_field() {
        // A 12-bit field spanning a byte boundary should preserve order.
        let mut w = BitWriter::new();
        w.write_bits(12, 0xABC);
        w.write_bits(4, 0xD);
        let bytes = w.into_bytes();
        assert_eq!(bytes, vec![0xAB, 0xCD]);
        let mut r = BitReader::new(&bytes);
        assert_eq!(r.read_bits(12).unwrap(), 0xABC);
        assert_eq!(r.read_bits(4).unwrap(), 0xD);
    }

    #[test]
    fn magic_48() {
        // bzip2 block magic = 0x31_4159_2653_59.
        let mut w = BitWriter::new();
        w.write_bits_48(0x3141_5926_5359);
        let bytes = w.into_bytes();
        assert_eq!(bytes, vec![0x31, 0x41, 0x59, 0x26, 0x53, 0x59]);
        let mut r = BitReader::new(&bytes);
        assert_eq!(r.read_bits_48().unwrap(), 0x3141_5926_5359);
    }

    #[test]
    fn unexpected_end() {
        let buf = [0u8; 0];
        let mut r = BitReader::new(&buf);
        assert!(r.read_bit().is_err());
    }
}
