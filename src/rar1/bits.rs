//! MSB-first streaming bit reader.
//!
//! RAR 1.x reads bits from the most-significant end of each input byte.
//! Reverse-engineered notes (and The Unarchiver's `XADRAR15Handle.m`
//! consuming bits through `CSInputNextBit` / `CSInputNextBitString` with
//! Huffman codes flagged `shortestCodeIsZeros:YES`) confirm MSB-first.
//!
//! The reader keeps a 32-bit accumulator and a "bits left" count: bytes are
//! fed in one at a time as input becomes available, and the consumer
//! [`peek`]s or [`read`]s the top-of-accumulator bits. The accumulator has
//! room for at least two whole bytes of headroom (always ≤ 16 bits used
//! before [`can_accept_byte`] returns true), so a consumer that needs ≤ 17
//! bits in a single [`read`] is safe.
//!
//! This shape is the same one used by [`crate::quantum::bits`] (Quantum is
//! also MSB-first, also feeds bytes into the high end of an accumulator).

// Building-block; consumer is the future RAR1 state machine.
#![allow(dead_code)]

use crate::error::Error;

/// Width of the bit buffer in bits. 32 is enough for any single-symbol
/// Huffman code we will encounter (RAR1 caps Huffman codes at 12 bits per
/// the static tables; the LZSS short-offset path reads up to 15 raw bits).
const BITBUF_WIDTH: u32 = 32;

/// MSB-first bit reader. Bytes are fed via [`feed_byte`]; the consumer
/// inspects them by [`peek`] / [`drop_bits`] / [`read`] from the
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

    /// True while there is room for at least one more whole byte. The caller
    /// should drain consumed bits or stop feeding once this is `false`.
    pub const fn can_accept_byte(&self) -> bool {
        self.nbits + 8 <= BITBUF_WIDTH
    }

    /// Push one input byte onto the bottom (low-significance side) of the
    /// accumulator. Caller must check [`can_accept_byte`] first.
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

    /// Look at the next `n` bits, MSB-first, returning them right-justified.
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

    /// Drop the next `n` bits without returning them.
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
    /// fewer than `n` bits are buffered.
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
        // 0b1011_0001 → MSB-first bits: 1 0 1 1 0 0 0 1
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
        // 0xAB 0xCD = 1010_1011 1100_1101
        // top 4 = 0xA, next 8 = 0xBC, last 4 = 0xD
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
        // 0xAB 0xCD, take 15 high bits: 1010_1011 1100_110_(1 left).
        // 15-bit MSB value = 0b101010111100110 = 0x55E6.
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
