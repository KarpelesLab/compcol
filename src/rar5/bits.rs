//! MSB-first bit reader over a buffered slice for RAR5.
//!
//! RAR5 reads bits from a byte-addressable buffer with two cursors:
//!   - `byte_pos`: the byte index of the byte currently being consumed.
//!   - `bit_pos`: the bit offset (0..=7) inside that byte, where bit 0 is the
//!     most-significant bit of the byte and bit 7 is the least.
//!
//! Reads return values right-justified. The reader can look ahead by up to 16
//! bits (the maximum Huffman code length the RAR5 format permits) without
//! consuming them, and a dedicated `consume_bits` skips bits in bulk.
//!
//! The reader owns the buffer; the decoder feeds it whole blocks at a time so
//! that the bit reader has random access to its own bytes — this matches the
//! RAR5 wire layout where each compressed block is self-delimited at the byte
//! level and the final byte's valid-bit count is encoded in the block header.

use alloc::vec::Vec;

use crate::error::Error;

/// Byte-buffered MSB-first bit reader sized for a single compressed block.
#[derive(Debug, Default)]
pub struct BitBuf {
    /// All bytes of the current block, copied from the caller's input.
    pub buf: Vec<u8>,
    /// Current byte offset within `buf`.
    pub byte_pos: usize,
    /// Current bit offset within `buf[byte_pos]`, counting from the MSB
    /// (0 = MSB, 7 = LSB).
    pub bit_pos: u8,
    /// Index of the *last* valid byte in the block (`buf.len() - 1`); kept
    /// as a separate field so that callers can also check end-of-block via
    /// `last_bit` for the very last byte.
    pub last_byte: usize,
    /// Bit position (0..=7) inside `buf[last_byte]` *after* the final valid
    /// bit. End-of-block is reached when `(byte_pos, bit_pos) >= (last_byte,
    /// last_bit)`.
    pub last_bit: u8,
}

impl BitBuf {
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the buffer with `bytes`. `last_bit` is the bit position (1..=8)
    /// after the final valid bit in the final byte, per RAR5's block header.
    pub fn reset(&mut self, bytes: &[u8], last_bit: u8) {
        self.buf.clear();
        self.buf.extend_from_slice(bytes);
        self.byte_pos = 0;
        self.bit_pos = 0;
        self.last_byte = self.buf.len().saturating_sub(1);
        self.last_bit = last_bit;
    }

    /// True once the cursor has reached or passed the declared end of block.
    pub fn at_end(&self) -> bool {
        if self.buf.is_empty() {
            return true;
        }
        if self.byte_pos > self.last_byte {
            return true;
        }
        self.byte_pos == self.last_byte && self.bit_pos >= self.last_bit
    }

    /// Bits still remaining in the block, conservatively.
    pub fn bits_remaining(&self) -> u32 {
        if self.buf.is_empty() {
            return 0;
        }
        let end_bit = (self.last_byte as u64) * 8 + self.last_bit as u64;
        let cur_bit = (self.byte_pos as u64) * 8 + self.bit_pos as u64;
        end_bit.saturating_sub(cur_bit) as u32
    }

    /// Peek up to 16 bits MSB-first, right-justified. If fewer than 16 bits
    /// remain in the buffer the missing low bits read as zero.
    pub fn peek16(&self) -> u16 {
        let b0 = *self.buf.get(self.byte_pos).unwrap_or(&0) as u32;
        let b1 = *self.buf.get(self.byte_pos + 1).unwrap_or(&0) as u32;
        let b2 = *self.buf.get(self.byte_pos + 2).unwrap_or(&0) as u32;
        // 24 bits big-endian starting at byte_pos.
        let w = (b0 << 16) | (b1 << 8) | b2;
        // Shift down so that bit_pos lands at the top of the result.
        ((w >> (8 - self.bit_pos as u32)) & 0xFFFF) as u16
    }

    /// Peek up to 32 bits MSB-first. Bits beyond the end of the buffer read
    /// as zero. The result is right-justified at width `n` (with `n <= 32`).
    pub fn peek_bits(&self, n: u32) -> u32 {
        debug_assert!(n <= 32);
        if n == 0 {
            return 0;
        }
        let mut acc: u64 = 0;
        // Pull up to 5 bytes to cover 32 bits + a partial-byte offset.
        for i in 0..5 {
            let b = *self.buf.get(self.byte_pos + i).unwrap_or(&0) as u64;
            acc = (acc << 8) | b;
        }
        // We have 40 bits MSB-first starting at byte_pos.bit 0; we want bits
        // [bit_pos .. bit_pos + n], MSB-first.
        let top = 40 - self.bit_pos as u32;
        ((acc >> (top - n)) & ((1u64 << n) - 1)) as u32
    }

    /// Advance the cursor by `n` bits without bounds-checking the end of the
    /// declared block.
    pub fn skip(&mut self, n: u32) {
        let total = self.bit_pos as u32 + n;
        self.byte_pos += (total >> 3) as usize;
        self.bit_pos = (total & 7) as u8;
    }

    /// Read `n` bits (`1..=16`) MSB-first and consume them. Returns
    /// `Error::UnexpectedEnd` if fewer than `n` bits remain in the block.
    pub fn read(&mut self, n: u32) -> Result<u32, Error> {
        debug_assert!(n <= 16);
        if self.bits_remaining() < n {
            return Err(Error::UnexpectedEnd);
        }
        let v = self.peek_bits(n);
        self.skip(n);
        Ok(v)
    }

    /// Read a single bit. Convenience wrapper around `read(1)`.
    #[allow(dead_code)]
    pub fn read1(&mut self) -> Result<u32, Error> {
        self.read(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn msb_first_packed_reads() {
        // 0b10110100_11100001 → bits MSB-first: 1,0,1,1,0,1,0,0,1,1,1,0,0,0,0,1
        let mut br = BitBuf::new();
        br.reset(&[0xB4, 0xE1], 8);
        assert_eq!(br.read(4).unwrap(), 0b1011);
        assert_eq!(br.read(4).unwrap(), 0b0100);
        assert_eq!(br.read(8).unwrap(), 0xE1);
        assert!(br.at_end());
    }

    #[test]
    fn cross_byte_reads() {
        // 0x12_34 = 0001 0010 0011 0100. Read 3, then 9, then 4.
        let mut br = BitBuf::new();
        br.reset(&[0x12, 0x34], 8);
        assert_eq!(br.read(3).unwrap(), 0b000);
        assert_eq!(br.read(9).unwrap(), 0b1_0010_0011);
        assert_eq!(br.read(4).unwrap(), 0b0100);
    }

    #[test]
    fn read_past_end_errors() {
        let mut br = BitBuf::new();
        br.reset(&[0xFF], 4);
        assert_eq!(br.read(3).unwrap(), 0b111);
        assert_eq!(br.read(2), Err(Error::UnexpectedEnd));
    }

    #[test]
    fn peek_bits_independent_of_skip() {
        let mut br = BitBuf::new();
        br.reset(&[0xAB, 0xCD, 0xEF, 0x12], 8);
        assert_eq!(br.peek_bits(16), 0xABCD);
        br.skip(4);
        assert_eq!(br.peek_bits(16), 0xBCDE);
    }
}
