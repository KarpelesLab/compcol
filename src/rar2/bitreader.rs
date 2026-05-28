//! MSB-first byte-stream bit reader for RAR 2.x.
//!
//! Unlike LZX (16-bit little-endian word stream, MSB-first within each word),
//! RAR2's bitstream is a flat byte stream consumed MSB-first. Byte `B0` is
//! consumed before `B1`; within each byte the top bit (`(B>>7)&1`) is read
//! first.
//!
//! The reader works over a borrowed `&[u8]` and never panics on truncation —
//! [`read_bits`] returns [`Error::UnexpectedEnd`] if the requested span runs
//! past the buffer end. Bits are tracked by a 64-bit accumulator that lazily
//! pulls fresh bytes only when needed.

use crate::error::Error;

#[derive(Debug, Clone, Copy, Default)]
pub struct BitReader {
    /// Next byte position to consume from the input slice.
    byte_pos: usize,
    /// Bit accumulator (top `nbits` bits are valid; high bits MSB-first).
    acc: u64,
    /// Number of valid bits in `acc`.
    nbits: u32,
}

impl BitReader {
    pub const fn new() -> Self {
        Self {
            byte_pos: 0,
            acc: 0,
            nbits: 0,
        }
    }

    /// How many input bytes the reader has consumed so far (rounded up).
    #[allow(dead_code)]
    pub const fn byte_pos(&self) -> usize {
        self.byte_pos
    }

    /// Refill the accumulator from `input` until it holds at least `want`
    /// bits, or the input is exhausted. Returns `Err(UnexpectedEnd)` if the
    /// input ran out before reaching `want`.
    fn refill(&mut self, want: u32, input: &[u8]) -> Result<(), Error> {
        debug_assert!(want <= 64);
        while self.nbits < want {
            if self.byte_pos >= input.len() {
                return Err(Error::UnexpectedEnd);
            }
            let b = input[self.byte_pos] as u64;
            self.byte_pos += 1;
            // The MSB-first convention: this byte's high bit becomes the
            // most-significant bit of the next chunk inserted below the
            // already-buffered bits.
            self.acc |= b << (56 - self.nbits);
            self.nbits += 8;
        }
        Ok(())
    }

    /// Read `n` bits (0..=32) MSB-first, returning them right-justified.
    pub fn read_bits(&mut self, n: u32, input: &[u8]) -> Result<u32, Error> {
        if n == 0 {
            return Ok(0);
        }
        debug_assert!(n <= 32);
        self.refill(n, input)?;
        let v = ((self.acc >> (64 - n)) & ((1u64 << n) - 1)) as u32;
        self.acc <<= n;
        self.nbits -= n;
        Ok(v)
    }

    /// Peek up to 16 bits without consuming them. If fewer bits are available
    /// in the accumulator, refills first. Returns the bits right-justified at
    /// width `n` along with the actual number of bits available (≤ `n`) — when
    /// the available count is less than `n`, the missing low bits are zero.
    ///
    /// This is used by the Huffman decoder, which needs a lookahead window of
    /// the maximum code length (15 bits for RAR2) but can fall back to a
    /// shorter code if the available bits already determine a unique symbol.
    pub fn peek_up_to(&mut self, n: u32, input: &[u8]) -> (u32, u32) {
        debug_assert!(n <= 32);
        // Refill what we can, ignoring UnexpectedEnd.
        let _ = self.refill(n, input);
        let have = self.nbits.min(n);
        if have == 0 {
            return (0, 0);
        }
        // We want the top `have` bits as a value, but left-justified to width
        // `n` (so the caller can walk code lengths from 1..=n by stripping
        // bits off the top).
        let v = (self.acc >> (64 - n)) as u32;
        // Mask off the part below `have` (which corresponds to bits we don't
        // actually have).
        let shift = n - have;
        let masked = (v >> shift) << shift;
        (masked, have)
    }

    /// Consume `n` bits without returning them. Caller must ensure the bits
    /// are present (e.g. via a previous `peek_up_to` confirming `have >= n`).
    pub fn drop_bits(&mut self, n: u32) {
        debug_assert!(n <= self.nbits);
        self.acc <<= n;
        self.nbits -= n;
    }

    /// Total bits the reader can still surface from `input` (buffered + remaining bytes).
    #[allow(dead_code)]
    pub fn bits_remaining(&self, input: &[u8]) -> u64 {
        self.nbits as u64 + (input.len().saturating_sub(self.byte_pos) as u64) * 8
    }

    #[allow(dead_code)]
    pub fn reset(&mut self) {
        self.byte_pos = 0;
        self.acc = 0;
        self.nbits = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_bits_msb_first() {
        // bytes: 0b1100_1010, 0b0101_0011
        let input = [0xCA, 0x53];
        let mut r = BitReader::new();
        assert_eq!(r.read_bits(4, &input).unwrap(), 0xC);
        assert_eq!(r.read_bits(4, &input).unwrap(), 0xA);
        assert_eq!(r.read_bits(8, &input).unwrap(), 0x53);
        // Exhausted: next read errors.
        assert_eq!(r.read_bits(1, &input), Err(Error::UnexpectedEnd));
    }

    #[test]
    fn read_bits_crossing_byte() {
        // bytes 0xAB 0xCD: binary 1010_1011 1100_1101
        // First 12 bits should be 1010_1011_1100 = 0xABC.
        let input = [0xAB, 0xCD];
        let mut r = BitReader::new();
        assert_eq!(r.read_bits(12, &input).unwrap(), 0xABC);
        assert_eq!(r.read_bits(4, &input).unwrap(), 0xD);
    }

    #[test]
    fn read_zero_bits_is_noop() {
        let input = [];
        let mut r = BitReader::new();
        assert_eq!(r.read_bits(0, &input).unwrap(), 0);
    }

    #[test]
    fn peek_up_to_handles_short_input() {
        // Single byte 0xF0 = 1111_0000.
        let input = [0xF0];
        let mut r = BitReader::new();
        let (v, have) = r.peek_up_to(15, &input);
        assert_eq!(have, 8);
        // top 8 bits of the 15-bit value = 0xF0, but left-shifted by (15-8)=7.
        // We zeroed the missing-low bits, so value = 0xF0 << 7 = 0x7800.
        assert_eq!(v, 0xF0 << 7);
        // Peek doesn't consume.
        assert_eq!(r.read_bits(8, &input).unwrap(), 0xF0);
    }

    #[test]
    fn bits_remaining_tracks_buffered_and_unread() {
        let input = [0xFF, 0xFF, 0xFF];
        let mut r = BitReader::new();
        assert_eq!(r.bits_remaining(&input), 24);
        r.read_bits(4, &input).unwrap();
        assert_eq!(r.bits_remaining(&input), 20);
        r.read_bits(12, &input).unwrap();
        assert_eq!(r.bits_remaining(&input), 8);
    }
}
