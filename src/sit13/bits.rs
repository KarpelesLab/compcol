//! MSB-first streaming bit reader.
//!
//! StuffIt's Huffman-coded methods consume bits from the most-significant
//! end of each input byte. The reader keeps a 32-bit accumulator and a
//! "bits left" count; bytes are fed in one at a time as input becomes
//! available, so the reader works under arbitrary input chunking (down to
//! one byte per call). The consumer [`peek`](BitReader::peek)s or
//! [`read`](BitReader::read)s from the top of the accumulator.
//!
//! Shares its shape with [`crate::rar1::bits`] and [`crate::quantum::bits`]
//! (both also MSB-first, also feed bytes into the high end of an
//! accumulator). No `unsafe`; never panics on valid use (`debug_assert`s
//! guard the documented preconditions, and the public `read`/`feed`
//! entry points bounds-check at runtime).

// Building block; the consumer is a future method-13 state machine.
#![allow(dead_code)]

use crate::error::Error;

/// Width of the bit buffer in bits.
const BITBUF_WIDTH: u32 = 32;

/// MSB-first bit reader. Bytes are fed via [`feed_byte`](BitReader::feed_byte);
/// the consumer inspects them by [`peek`](BitReader::peek) /
/// [`drop_bits`](BitReader::drop_bits) / [`read`](BitReader::read) from the
/// most-significant end of the accumulator.
#[derive(Debug, Clone, Copy)]
pub struct BitReader {
    /// Bits packed MSB-first into the high end of the accumulator; the next
    /// bit to consume is bit 31.
    acc: u32,
    /// Number of valid bits currently in `acc` (0..=32).
    nbits: u32,
}

impl Default for BitReader {
    fn default() -> Self {
        Self::new()
    }
}

impl BitReader {
    pub const fn new() -> Self {
        Self { acc: 0, nbits: 0 }
    }

    /// True while there is room for at least one more whole byte.
    pub const fn can_accept_byte(&self) -> bool {
        self.nbits + 8 <= BITBUF_WIDTH
    }

    /// Push one input byte onto the low-significance side of the
    /// accumulator. Caller must check [`can_accept_byte`](BitReader::can_accept_byte)
    /// first.
    pub fn feed_byte(&mut self, byte: u8) {
        debug_assert!(self.can_accept_byte());
        let shift = BITBUF_WIDTH - 8 - self.nbits;
        self.acc |= (byte as u32) << shift;
        self.nbits += 8;
    }

    /// Number of bits currently available to read.
    pub const fn bits_available(&self) -> u32 {
        self.nbits
    }

    /// Look at the next `n` bits, MSB-first, right-justified.
    /// Requires `1 <= n <= 32` and `n <= bits_available()`.
    pub fn peek(&self, n: u32) -> u32 {
        debug_assert!((1..=BITBUF_WIDTH).contains(&n));
        debug_assert!(n <= self.nbits);
        if n == BITBUF_WIDTH {
            self.acc
        } else {
            self.acc >> (BITBUF_WIDTH - n)
        }
    }

    /// Drop the next `n` bits without returning them. Requires `n <= bits_available()`.
    pub fn drop_bits(&mut self, n: u32) {
        debug_assert!(n <= self.nbits);
        if n == BITBUF_WIDTH {
            self.acc = 0;
        } else {
            self.acc <<= n;
        }
        self.nbits -= n;
    }

    /// Read and remove the next `n` bits. Returns `Err(UnexpectedEnd)` if
    /// fewer than `n` bits are buffered (the reader is left untouched).
    pub fn read(&mut self, n: u32) -> Result<u32, Error> {
        debug_assert!((1..=BITBUF_WIDTH).contains(&n));
        if self.nbits < n {
            return Err(Error::UnexpectedEnd);
        }
        let v = self.peek(n);
        self.drop_bits(n);
        Ok(v)
    }

    /// Read a single MSB-first bit; convenience wrapper for `read(1)`.
    pub fn read_bit(&mut self) -> Result<u32, Error> {
        self.read(1)
    }

    /// Reset to a fresh empty state.
    pub fn reset(&mut self) {
        self.acc = 0;
        self.nbits = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn msb_first_one_byte() {
        let mut r = BitReader::new();
        r.feed_byte(0b1011_0001);
        assert_eq!(r.bits_available(), 8);
        for expected in [1u32, 0, 1, 1, 0, 0, 0, 1] {
            assert_eq!(r.read_bit().unwrap(), expected);
        }
        assert_eq!(r.bits_available(), 0);
    }

    #[test]
    fn read_groups_of_bits() {
        let mut r = BitReader::new();
        r.feed_byte(0xAB);
        r.feed_byte(0xCD);
        assert_eq!(r.read(4).unwrap(), 0xA);
        assert_eq!(r.read(8).unwrap(), 0xBC);
        assert_eq!(r.read(4).unwrap(), 0xD);
        assert_eq!(r.bits_available(), 0);
    }

    #[test]
    fn peek_does_not_consume() {
        let mut r = BitReader::new();
        r.feed_byte(0xF0);
        assert_eq!(r.peek(4), 0xF);
        assert_eq!(r.bits_available(), 8);
        r.drop_bits(4);
        assert_eq!(r.peek(4), 0x0);
        assert_eq!(r.bits_available(), 4);
    }

    #[test]
    fn read_15_bits_across_two_bytes() {
        let mut r = BitReader::new();
        r.feed_byte(0xAB);
        r.feed_byte(0xCD);
        assert_eq!(r.read(15).unwrap(), 0x55E6);
        assert_eq!(r.bits_available(), 1);
        assert_eq!(r.read_bit().unwrap(), 1);
    }

    #[test]
    fn full_32_bit_word() {
        let mut r = BitReader::new();
        r.feed_byte(0xDE);
        r.feed_byte(0xAD);
        r.feed_byte(0xBE);
        r.feed_byte(0xEF);
        assert!(!r.can_accept_byte());
        assert_eq!(r.read(32).unwrap(), 0xDEADBEEF);
        assert!(r.can_accept_byte());
    }

    #[test]
    fn underrun_errors_without_consuming() {
        let mut r = BitReader::new();
        r.feed_byte(0xFF);
        assert!(matches!(r.read(16), Err(Error::UnexpectedEnd)));
        assert_eq!(r.bits_available(), 8, "failed read must leave reader alone");
        assert_eq!(r.read(8).unwrap(), 0xFF);
    }

    #[test]
    fn can_accept_byte_reflects_headroom() {
        let mut r = BitReader::new();
        for _ in 0..4 {
            assert!(r.can_accept_byte());
            r.feed_byte(0xAA);
        }
        assert!(!r.can_accept_byte());
        r.drop_bits(8);
        assert!(r.can_accept_byte());
    }

    #[test]
    fn reset_clears_state() {
        let mut r = BitReader::new();
        r.feed_byte(0x12);
        r.feed_byte(0x34);
        r.drop_bits(4);
        r.reset();
        assert_eq!(r.bits_available(), 0);
        r.feed_byte(0xFF);
        assert_eq!(r.read(8).unwrap(), 0xFF);
    }
}
