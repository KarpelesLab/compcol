//! Reverse bit reader for Zstandard.
//!
//! Zstd's FSE/Huffman bitstreams are read **backwards from the end** of the
//! payload, MSB-first. The stream is terminated by a single `1`-bit "start"
//! marker placed in the most-significant position of the last byte; the bits
//! immediately before that marker are the first bits read.
//!
//! The reader presented here owns a borrow of the bytestream and a cursor.
//! [`Self::new`] locates the start marker, validates that the last byte is
//! non-zero (an all-zero last byte is corrupt), and positions the cursor just
//! below the marker. Subsequent [`Self::read`] / [`Self::read_signed`] calls
//! pull bits from the current cursor toward byte 0.
//!
//! All reads return their result right-justified in a `u64`. The reader
//! signals `unexpected end of stream` by returning an `Err(Error::Corrupt)`
//! once a caller asks for more bits than remain.

use crate::error::Error;

/// Backward MSB-first bit reader over a byte slice.
///
/// Used by the FSE decoder, the Huffman decoder, and any zstd component that
/// reads from a stream terminated by a high-bit "1" marker.
pub struct RevBitReader<'a> {
    data: &'a [u8],
    /// Total number of payload bits available (after the start marker).
    available: usize,
    /// Number of bits already consumed.
    consumed: usize,
}

impl<'a> RevBitReader<'a> {
    /// Create a reader for `data`, locating the start marker in the last byte.
    ///
    /// Returns `Err(Error::Corrupt)` if `data` is empty or its last byte is
    /// zero (no start marker present).
    pub fn new(data: &'a [u8]) -> Result<Self, Error> {
        if data.is_empty() {
            return Err(Error::Corrupt);
        }
        let last = *data.last().unwrap();
        if last == 0 {
            return Err(Error::Corrupt);
        }
        // The position of the highest set bit in `last` is the marker.
        // Available bits = (data.len() - 1) * 8 + position_of_marker.
        // `leading_zeros` on a u8 returns count of leading zero bits.
        let marker_pos = 7 - last.leading_zeros() as usize;
        let available = (data.len() - 1) * 8 + marker_pos;
        Ok(Self {
            data,
            available,
            consumed: 0,
        })
    }

    /// Bits not yet read.
    pub fn remaining(&self) -> usize {
        self.available - self.consumed
    }

    /// Are all bits consumed (only the start marker is left)?
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.consumed >= self.available
    }

    /// Give back `n` previously-read bits. Required by the Huffman decoder
    /// which peeks `max_bits` and then keeps only the actual code length.
    pub fn unread(&mut self, n: u32) {
        let n = n as usize;
        debug_assert!(self.consumed >= n);
        self.consumed -= n;
    }

    /// Read `n` bits (0..=64) MSB-first from the current backward cursor.
    ///
    /// Bits returned right-justified.
    pub fn read(&mut self, n: u32) -> Result<u64, Error> {
        if n == 0 {
            return Ok(0);
        }
        if n > 64 {
            return Err(Error::Corrupt);
        }
        if self.consumed + n as usize > self.available {
            return Err(Error::Corrupt);
        }
        // Bit numbering: bit index 0 = LSB of byte 0.
        // The bit just below the start marker is `available - 1`.
        // After reading `consumed` bits we're looking at bit
        // `(available - 1) - consumed` next.
        //
        // We need `n` consecutive bits ending at `(available - 1) - consumed`
        // (high) and starting at `(available - 1) - consumed - n + 1` (low),
        // returned as MSB-first.
        let high_bit = self.available - 1 - self.consumed;
        let low_bit = high_bit + 1 - n as usize;

        // Read byte by byte. Touching at most 9 bytes for n=64.
        let mut acc: u64 = 0;
        let mut bits_read: u32 = 0;
        // Walk from the high byte down.
        let mut cur_bit = high_bit;
        while bits_read < n {
            let byte_idx = cur_bit / 8;
            let bit_in_byte = cur_bit % 8; // 0..=7, where 7 is MSB
            // Number of bits we can pull from this byte's low side.
            let take_from_this_byte = core::cmp::min(bit_in_byte as u32 + 1, n - bits_read);
            // The bits we want are positions
            //   (bit_in_byte) downto (bit_in_byte - take_from_this_byte + 1)
            // i.e. the top `take_from_this_byte` bits of a `bit_in_byte+1`-wide
            // window into this byte's low side.
            let byte = self.data[byte_idx] as u64;
            let shift_down = bit_in_byte as u32 + 1 - take_from_this_byte;
            let mask = (1u64 << take_from_this_byte) - 1;
            let chunk = (byte >> shift_down) & mask;
            acc = (acc << take_from_this_byte) | chunk;
            bits_read += take_from_this_byte;
            if bits_read == n {
                break;
            }
            cur_bit = (byte_idx * 8) - 1; // step down into the previous byte
        }
        // Guard the unused-variable lint for low_bit; we computed it for clarity.
        let _ = low_bit;
        self.consumed += n as usize;
        Ok(acc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marker_in_last_byte() {
        // data = [0xAB, 0x01]
        //   last byte 0x01: marker at bit 0 → available = 1*8 + 0 = 8 bits
        //   payload = 0xAB (10101011)
        // Reading MSB-first 8 bits should give 0xAB.
        let data = [0xAB, 0x01];
        let mut r = RevBitReader::new(&data).unwrap();
        assert_eq!(r.remaining(), 8);
        let v = r.read(8).unwrap();
        assert_eq!(v, 0xAB);
        assert!(r.is_empty());
    }

    #[test]
    fn read_individual_bits() {
        // data = [0b10110100, 0b00000010]
        // last byte 0x02: marker at bit 1 → available = 8 + 1 = 9
        // bit just below marker (bit 8) is bit 0 of byte 1 = 0
        // Then bits 7..0 of byte 0 in order: 1,0,1,1,0,1,0,0
        let data = [0b1011_0100, 0b0000_0010];
        let mut r = RevBitReader::new(&data).unwrap();
        assert_eq!(r.remaining(), 9);
        assert_eq!(r.read(1).unwrap(), 0); // bit 8 → bit 0 of last byte
        assert_eq!(r.read(1).unwrap(), 1); // bit 7
        assert_eq!(r.read(1).unwrap(), 0); // bit 6
        assert_eq!(r.read(1).unwrap(), 1); // bit 5
        assert_eq!(r.read(1).unwrap(), 1); // bit 4
        assert_eq!(r.read(4).unwrap(), 0b0100); // bits 3..0
    }

    #[test]
    fn empty_data_corrupt() {
        let r = RevBitReader::new(&[]);
        assert!(r.is_err());
    }

    #[test]
    fn zero_last_byte_corrupt() {
        let r = RevBitReader::new(&[0x01, 0x00]);
        assert!(r.is_err());
    }

    #[test]
    fn cross_byte_read() {
        // [0xFF, 0xA0, 0x01]
        //   last byte 0x01: marker at bit 0 of byte 2, available = 16
        //   bits MSB-first: byte 1 then byte 0
        //   byte 1 = 0xA0 = 10100000
        //   byte 0 = 0xFF = 11111111
        //   so MSB-first 16 bits = 0xA0FF
        let data = [0xFF, 0xA0, 0x01];
        let mut r = RevBitReader::new(&data).unwrap();
        assert_eq!(r.remaining(), 16);
        // Read 12 bits across the byte boundary: top 8 of byte1 + top 4 of byte0
        // = 0xA0F
        let v = r.read(12).unwrap();
        assert_eq!(v, 0xA0F);
        // Remaining 4 bits = low nibble of byte 0 = 0xF
        let v = r.read(4).unwrap();
        assert_eq!(v, 0xF);
    }
}
