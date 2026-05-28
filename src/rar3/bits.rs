//! MSB-first byte-by-byte bit reader for RAR 3.x.
//!
//! Unlike LZX (which streams 16-bit little-endian words), RAR3's wire format
//! is a plain byte stream with bits consumed most-significant-first within
//! each byte. The bit reader holds at most 56 bits of look-ahead so the
//! caller can request up to 32 bits in a single call as long as the input
//! has been refilled appropriately.
//!
//! The reader stores its bits packed at the *high* end of a 64-bit
//! accumulator so a simple right-shift by `(64 - n)` extracts the next `n`
//! bits as an integer.

use crate::error::Error;

/// MSB-first bit reader.
#[derive(Debug, Clone, Default)]
pub struct BitReader {
    /// Underlying byte buffer; the caller (the decoder) owns the bytes and
    /// hands them in via [`feed_slice`] or one byte at a time.
    buf: alloc::vec::Vec<u8>,
    /// Position of the next byte we haven't yet pushed into `acc` (in bytes).
    byte_pos: usize,
    /// Accumulator: high end is the next bit to consume.
    acc: u64,
    /// Number of valid bits currently in `acc`.
    nbits: u32,
}

impl BitReader {
    pub fn new() -> Self {
        Self::default()
    }

    /// Append raw bytes to the input buffer.
    pub fn feed_slice(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// Refill the accumulator with up to 7 input bytes (56 bits) so the next
    /// `peek` / `read` of up to 32 bits is guaranteed to succeed if there are
    /// enough source bytes left.
    fn refill(&mut self) {
        while self.nbits <= 56 && self.byte_pos < self.buf.len() {
            let b = self.buf[self.byte_pos] as u64;
            self.byte_pos += 1;
            self.acc |= b << (56 - self.nbits);
            self.nbits += 8;
        }
    }

    /// Look at the next `n` bits MSB-first without consuming them.
    ///
    /// Returns `Ok(value)` with the bits right-justified. Returns
    /// `Err(UnexpectedEnd)` when the stream is exhausted; the caller can
    /// then surface more input and retry.
    pub fn peek(&mut self, n: u32) -> Result<u32, Error> {
        debug_assert!(n <= 32);
        if n == 0 {
            return Ok(0);
        }
        if self.nbits < n {
            self.refill();
        }
        if self.nbits < n {
            return Err(Error::UnexpectedEnd);
        }
        Ok(((self.acc >> (64 - n)) & ((1u64 << n) - 1)) as u32)
    }

    /// Consume `n` bits previously peeked at.
    pub fn drop_bits(&mut self, n: u32) -> Result<(), Error> {
        debug_assert!(n <= 32);
        if n == 0 {
            return Ok(());
        }
        if self.nbits < n {
            self.refill();
        }
        if self.nbits < n {
            return Err(Error::UnexpectedEnd);
        }
        self.acc <<= n;
        self.nbits -= n;
        Ok(())
    }

    /// Read and consume `n` bits in a single call.
    pub fn read_bits(&mut self, n: u32) -> Result<u32, Error> {
        let v = self.peek(n)?;
        self.drop_bits(n)?;
        Ok(v)
    }

    /// Byte-align the bit reader: discard 0..=7 bits to land on a byte
    /// boundary. This matches RAR3's `rar_br_consume_unaligned_bits` which is
    /// called at the start of every new code block.
    pub fn byte_align(&mut self) {
        let drop = self.nbits & 7;
        if drop > 0 {
            // Best-effort drop; the bits are already buffered so this can't
            // fail, but use `drop_bits` to keep one code path.
            let _ = self.drop_bits(drop);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;

    #[test]
    fn msb_first_within_byte() {
        // Byte 0xAB = 1010_1011 — top bit is 1, next 1, next 1, next 0...
        let mut r = BitReader::new();
        r.feed_slice(&[0xAB, 0xCD]);
        assert_eq!(r.read_bits(4).unwrap(), 0xA);
        assert_eq!(r.read_bits(4).unwrap(), 0xB);
        assert_eq!(r.read_bits(8).unwrap(), 0xCD);
    }

    #[test]
    fn read_across_bytes() {
        // bits MSB-first: 0xA = 1010, then 0xB = 1011, then 0xC = 1100, ...
        // pulling 12 bits at once should give 0xABC.
        let mut r = BitReader::new();
        r.feed_slice(&[0xAB, 0xCD]);
        assert_eq!(r.read_bits(12).unwrap(), 0xABC);
        assert_eq!(r.read_bits(4).unwrap(), 0xD);
    }

    #[test]
    fn byte_align_discards_partial_byte() {
        let mut r = BitReader::new();
        r.feed_slice(&[0xAB, 0xCD]);
        r.drop_bits(3).unwrap();
        r.byte_align();
        // After dropping 3 bits and aligning, the next read should start at
        // the second byte 0xCD.
        assert_eq!(r.read_bits(8).unwrap(), 0xCD);
    }

    #[test]
    fn underflow_yields_unexpected_end() {
        let mut r = BitReader::new();
        r.feed_slice(&[0xFF]);
        assert_eq!(r.read_bits(8).unwrap(), 0xFF);
        assert!(matches!(r.read_bits(1), Err(Error::UnexpectedEnd)));
    }

    #[test]
    fn peek_does_not_consume() {
        let mut r = BitReader::new();
        r.feed_slice(&[0x12, 0x34]);
        assert_eq!(r.peek(8).unwrap(), 0x12);
        assert_eq!(r.peek(8).unwrap(), 0x12);
        r.drop_bits(8).unwrap();
        assert_eq!(r.peek(8).unwrap(), 0x34);
    }
}
