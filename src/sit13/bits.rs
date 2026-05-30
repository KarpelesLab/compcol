//! LSB-first streaming bit reader.
//!
//! StuffIt **method 13** reads its bitstream least-significant-bit first:
//! bytes are consumed in order and, within each byte, the lowest-order bit is
//! consumed first. A "read `n` bits" field is assembled with the first bit
//! read landing in the least-significant position of the result. This is the
//! opposite order from method 5 ("LZAH"), and getting it wrong is the single
//! most common interop pitfall between the two methods.
//!
//! The reader buffers the whole compressed payload (the consumer
//! [`super::decoder`] accumulates input across streaming calls, then decodes
//! in one pass) and tracks a bit cursor. Every read is bounds-checked and
//! returns [`Error::UnexpectedEnd`] on underrun; no `unsafe`, no panic
//! reachable from any input.

use crate::error::Error;

/// LSB-first bit reader over a borrowed byte slice with a bit cursor.
pub(crate) struct BitReader<'a> {
    data: &'a [u8],
    /// Absolute bit position of the next bit to consume.
    bit_pos: usize,
}

impl<'a> BitReader<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self { data, bit_pos: 0 }
    }

    /// Total number of bits remaining (not yet consumed).
    pub(crate) fn bits_remaining(&self) -> usize {
        (self.data.len() * 8).saturating_sub(self.bit_pos)
    }

    /// Read a single bit (LSB-first). `Err(UnexpectedEnd)` past the end.
    #[inline]
    pub(crate) fn read_bit(&mut self) -> Result<u32, Error> {
        let byte_idx = self.bit_pos >> 3;
        if byte_idx >= self.data.len() {
            return Err(Error::UnexpectedEnd);
        }
        let bit = (self.data[byte_idx] >> (self.bit_pos & 7)) & 1;
        self.bit_pos += 1;
        Ok(bit as u32)
    }

    /// Read `n` bits LSB-first (`0 <= n <= 32`); the first bit read is the
    /// least-significant bit of the result. `Err(UnexpectedEnd)` on underrun.
    pub(crate) fn read_bits(&mut self, n: u32) -> Result<u32, Error> {
        debug_assert!(n <= 32);
        if n == 0 {
            return Ok(0);
        }
        if self.bits_remaining() < n as usize {
            return Err(Error::UnexpectedEnd);
        }
        let mut value: u32 = 0;
        for i in 0..n {
            // bounds already guaranteed by the bits_remaining check above.
            let bit = self.read_bit()?;
            value |= bit << i;
        }
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lsb_first_single_bits() {
        // 0b1011_0001 → LSB-first: 1,0,0,0,1,1,0,1
        let data = [0b1011_0001u8];
        let mut r = BitReader::new(&data);
        for expected in [1u32, 0, 0, 0, 1, 1, 0, 1] {
            assert_eq!(r.read_bit().unwrap(), expected);
        }
        assert!(matches!(r.read_bit(), Err(Error::UnexpectedEnd)));
    }

    #[test]
    fn lsb_first_multibit_field() {
        // byte 0xAB = 1010_1011. Reading 4 bits LSB-first → 0b1011 = 0xB.
        let data = [0xABu8, 0xCD];
        let mut r = BitReader::new(&data);
        assert_eq!(r.read_bits(4).unwrap(), 0xB);
        // next 4 bits of 0xAB → 0b1010 = 0xA
        assert_eq!(r.read_bits(4).unwrap(), 0xA);
        // 0xCD = 1100_1101, low nibble 0b1101 = 0xD
        assert_eq!(r.read_bits(4).unwrap(), 0xD);
        assert_eq!(r.read_bits(4).unwrap(), 0xC);
    }

    #[test]
    fn read_across_byte_boundary() {
        // bytes 0x01 0x00 → first bit set, rest clear. Reading 9 bits LSB-first
        // gives value 1 (bit 0 set, bits 1..8 clear).
        let data = [0x01u8, 0x00];
        let mut r = BitReader::new(&data);
        assert_eq!(r.read_bits(9).unwrap(), 1);
    }

    #[test]
    fn underrun_is_clean() {
        let data = [0xFFu8];
        let mut r = BitReader::new(&data);
        assert!(matches!(r.read_bits(16), Err(Error::UnexpectedEnd)));
    }

    #[test]
    fn zero_bits_is_zero() {
        let data = [0xFFu8];
        let mut r = BitReader::new(&data);
        assert_eq!(r.read_bits(0).unwrap(), 0);
    }
}
