//! MSB-first bit reader over an in-memory byte buffer.
//!
//! Quantum reads bits from the most-significant end of the byte, in contrast
//! to deflate's LSB-first scheme. Bytes are pulled into the buffer 16 bits
//! at a time, matching libmspack's `READ_BYTES` macro:
//!
//! ```text
//! b0 = *i_ptr++;
//! b1 = *i_ptr++;
//! INJECT_BITS((b0 << 8) | b1, 16);
//! ```
//!
//! The libmspack code-style is to defer "do we have enough input?" decisions
//! to a read callback; we instead validate buffer length explicitly. The
//! reader returns [`Error::UnexpectedEnd`] when more bytes are needed.

use crate::error::Error;

/// Width of the bit buffer in bits. Must be ≥ 32 so we can `ENSURE_BITS(17)`
/// (i.e. add 16 bits when 15 are already buffered).
const BITBUF_WIDTH: u32 = 32;

/// MSB-first bit reader. State is `(bit_buffer, bits_left, byte_pos)`.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct BitReader {
    bit_buffer: u32,
    bits_left: u32,
    /// Byte offset into the underlying buffer (set by the caller via
    /// [`Self::rebase`] after consuming bytes between calls).
    byte_pos: usize,
    /// When set, [`read_bytes`] supplies two zero bytes the first time it
    /// would otherwise return `UnexpectedEnd`, then errors on subsequent
    /// underruns. This mirrors libmspack's `read_input` EOF behaviour:
    /// the renormalisation loop sometimes asks for bits that the encoder
    /// never wrote, and the decoder is expected to treat them as zero.
    eof_padding_used: bool,
    eof: bool,
}

impl BitReader {
    pub(crate) const fn new() -> Self {
        Self {
            bit_buffer: 0,
            bits_left: 0,
            byte_pos: 0,
            eof_padding_used: false,
            eof: false,
        }
    }

    pub(crate) fn byte_pos(&self) -> usize {
        self.byte_pos
    }

    /// Mark the underlying byte stream as fully delivered. Subsequent
    /// reads past the end produce one round of zero-bit padding (matching
    /// libmspack's `read_input` EOF behaviour) and then error.
    pub(crate) fn set_eof(&mut self, eof: bool) {
        self.eof = eof;
    }

    /// Pull two bytes from `buf[byte_pos..]` into the bit buffer.
    /// Returns `Err(UnexpectedEnd)` if fewer than two bytes are available,
    /// unless EOF padding is enabled, in which case the call succeeds
    /// (with two zero bytes) the first time and errors thereafter.
    fn read_bytes(&mut self, buf: &[u8]) -> Result<(), Error> {
        if self.byte_pos + 2 <= buf.len() {
            let b0 = buf[self.byte_pos] as u32;
            let b1 = buf[self.byte_pos + 1] as u32;
            self.byte_pos += 2;
            let combined = (b0 << 8) | b1;
            self.bit_buffer |= combined << (BITBUF_WIDTH - 16 - self.bits_left);
            self.bits_left += 16;
            Ok(())
        } else if self.eof && !self.eof_padding_used {
            // Inject 16 zero bits exactly once at EOF.
            self.eof_padding_used = true;
            self.bits_left += 16;
            Ok(())
        } else {
            Err(Error::UnexpectedEnd)
        }
    }

    /// Ensure at least `nbits` bits are present (1..=16). Errors if not enough
    /// input to top up.
    pub(crate) fn ensure_bits(&mut self, nbits: u32, buf: &[u8]) -> Result<(), Error> {
        debug_assert!(nbits <= 16);
        while self.bits_left < nbits {
            self.read_bytes(buf)?;
        }
        Ok(())
    }

    /// Look at the top `nbits` bits without removing them. Requires
    /// `bits_left >= nbits`. `nbits` must be 1..=16.
    pub(crate) fn peek_bits(&self, nbits: u32) -> u32 {
        debug_assert!((1..=16).contains(&nbits));
        self.bit_buffer >> (BITBUF_WIDTH - nbits)
    }

    /// Drop the top `nbits` bits from the bit buffer. `nbits` must satisfy
    /// `bits_left >= nbits`. `nbits` may be 0 (no-op).
    pub(crate) fn remove_bits(&mut self, nbits: u32) {
        debug_assert!(nbits <= self.bits_left);
        // Shift left by 32 is UB in C and panics in debug Rust; guard explicitly.
        if nbits == BITBUF_WIDTH {
            self.bit_buffer = 0;
        } else {
            self.bit_buffer <<= nbits;
        }
        self.bits_left -= nbits;
    }

    /// Read and return `nbits` bits (1..=16). Pulls more bytes from `buf` if
    /// the bit buffer is short.
    pub(crate) fn read_bits(&mut self, nbits: u32, buf: &[u8]) -> Result<u32, Error> {
        self.ensure_bits(nbits, buf)?;
        let v = self.peek_bits(nbits);
        self.remove_bits(nbits);
        Ok(v)
    }

    /// Read any number of bits (0..=32) by chunking through 16-bit reads.
    /// Mirrors libmspack's `READ_MANY_BITS`.
    pub(crate) fn read_many_bits(&mut self, bits: u32, buf: &[u8]) -> Result<u32, Error> {
        debug_assert!(bits <= 32);
        let mut needed = bits;
        let mut val: u32 = 0;
        while needed > 0 {
            // If we have ≤ (BITBUF_WIDTH - 16) bits buffered, top up 16 more.
            if self.bits_left <= BITBUF_WIDTH - 16 {
                self.read_bytes(buf)?;
            }
            let bitrun = self.bits_left.min(needed);
            // Safe: bitrun is in 1..=16 (because bits_left was just topped up
            // by 16 if it was ≤ 16, and we never request more than 32 total).
            // Edge case: if bitrun == 0 we would loop forever. The top-up
            // above guarantees bits_left ≥ 1 going in.
            debug_assert!(bitrun >= 1);
            val = (val << bitrun) | self.peek_bits(bitrun);
            self.remove_bits(bitrun);
            needed -= bitrun;
        }
        Ok(val)
    }

    /// Reset to an empty buffer, advancing past `byte_pos` bytes. Used after
    /// the caller drains the underlying input vector.
    pub(crate) fn rebase(&mut self, drop_bytes: usize) {
        debug_assert!(drop_bytes <= self.byte_pos);
        self.byte_pos -= drop_bytes;
    }

    /// Number of bits currently buffered.
    pub(crate) fn bits_left(&self) -> u32 {
        self.bits_left
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

    #[test]
    fn reads_one_bit_at_a_time_msb_first() {
        // 0b1011_0001 0b0110_1010 — first bit (MSB) is 1.
        let buf = [0b1011_0001u8, 0b0110_1010u8];
        let mut br = BitReader::new();
        let bits: Vec<u32> = (0..16).map(|_| br.read_bits(1, &buf).unwrap()).collect();
        assert_eq!(bits, vec![1, 0, 1, 1, 0, 0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0]);
    }

    #[test]
    fn reads_groups_of_bits() {
        // 0xAB 0xCD = 1010_1011 1100_1101.
        // First 4 bits MSB-first: 0xA. Next 8: 0xBC. Last 4: 0xD.
        let buf = [0xAB, 0xCD];
        let mut br = BitReader::new();
        assert_eq!(br.read_bits(4, &buf).unwrap(), 0xA);
        assert_eq!(br.read_bits(8, &buf).unwrap(), 0xBC);
        assert_eq!(br.read_bits(4, &buf).unwrap(), 0xD);
    }

    #[test]
    fn read_many_handles_more_than_16_bits() {
        // Place known 24-bit pattern across three bytes (padded to 4 since
        // we read in pairs). 0xAA_BB_CC, then a filler 0x00.
        let buf = [0xAA, 0xBB, 0xCC, 0x00];
        let mut br = BitReader::new();
        let v = br.read_many_bits(24, &buf).unwrap();
        assert_eq!(v, 0xAA_BB_CC);
    }

    #[test]
    fn returns_unexpected_end_when_buf_short() {
        let buf = [0x12];
        let mut br = BitReader::new();
        assert_eq!(
            br.read_bits(1, &buf).unwrap_err(),
            crate::error::Error::UnexpectedEnd
        );
    }

    #[test]
    fn rebase_keeps_byte_pos_consistent() {
        let buf = [0xFF, 0x00, 0xAA, 0xBB];
        let mut br = BitReader::new();
        let _ = br.read_bits(16, &buf).unwrap();
        assert_eq!(br.byte_pos(), 2);
        br.rebase(2);
        assert_eq!(br.byte_pos(), 0);
        // Now `&buf[2..]` is the logical start.
        let v = br.read_bits(16, &buf[2..]).unwrap();
        assert_eq!(v, 0xAABB);
    }
}
