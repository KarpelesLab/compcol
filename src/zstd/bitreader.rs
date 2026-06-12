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
///
/// Internally maintains a 64-bit accumulator top-aligned with the next bit to
/// deliver in the MSB. Bytes are pulled from the payload tail toward byte 0
/// and shifted into the accumulator's low end, so each refill brings in up to
/// 8 bits with two arithmetic ops instead of touching memory per bit.
pub struct RevBitReader<'a> {
    data: &'a [u8],
    /// Total number of payload bits available (after the start marker).
    available: usize,
    /// Number of bits already consumed (semantic; drives `remaining`).
    consumed: usize,
    /// Top-aligned bit accumulator: next bit to read is `acc >> 63`.
    acc: u64,
    /// Number of valid bits at the top of `acc`. Always in 0..=64.
    bits_in_acc: u32,
    /// Number of source bytes still available for refill. The next byte to
    /// pull is `data[bytes_left - 1]`.
    bytes_left: usize,
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

        // Seed the accumulator with the partial last byte's payload bits
        // (everything below the marker), MSB-first at the top of `acc`.
        let mut acc: u64 = 0;
        let mut bits_in_acc: u32 = 0;
        if marker_pos > 0 {
            let payload = (last as u64) & ((1u64 << marker_pos) - 1);
            acc = payload << (64 - marker_pos as u32);
            bits_in_acc = marker_pos as u32;
        }

        Ok(Self {
            data,
            available,
            consumed: 0,
            acc,
            bits_in_acc,
            bytes_left: data.len() - 1,
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

    /// Give back `n` previously-read bits by rewinding the cursor and rebuilding
    /// the accumulator. Retained as a general bit-reader primitive (and exercised
    /// by tests); the Huffman decoder now uses the cheaper [`Self::peek_bits`] +
    /// [`Self::consume`] pair instead, which avoids this per-symbol reseed.
    #[allow(dead_code)]
    pub fn unread(&mut self, n: u32) {
        let n_usize = n as usize;
        debug_assert!(self.consumed >= n_usize);
        self.consumed -= n_usize;
        // Rewind the accumulator. Because the source is read backward and
        // there is no cheap way to recover prior bits already shifted off,
        // we rebuild `acc`/`bits_in_acc`/`bytes_left` from the new cursor.
        self.reseed_from_consumed();
    }

    /// Rebuild the internal accumulator from `consumed`. Called from `unread`.
    #[allow(dead_code)]
    fn reseed_from_consumed(&mut self) {
        // Position of the next bit to deliver in global bit numbering.
        let next_bit = self.available - 1 - self.consumed;
        let next_byte = next_bit / 8;
        let bit_in_byte = (next_bit % 8) as u32; // 0..=7, 7=MSB
        // The high byte contributes `bit_in_byte + 1` bits at the top of acc.
        let high_byte_val = self.data[next_byte] as u64;
        let take = bit_in_byte + 1;
        let payload = high_byte_val & ((1u64 << take) - 1);
        self.acc = payload << (64 - take);
        self.bits_in_acc = take;
        // The next byte to refill is the one just below.
        self.bytes_left = next_byte;
    }

    /// Refill `acc` from the byte stream until at least 57 bits are buffered
    /// (or the source is exhausted). Each iteration loads one byte's worth of
    /// payload bits into the low end of the valid window.
    #[inline]
    fn refill(&mut self) {
        while self.bits_in_acc <= 56 && self.bytes_left > 0 {
            let byte = self.data[self.bytes_left - 1] as u64;
            self.acc |= byte << (56 - self.bits_in_acc);
            self.bits_in_acc += 8;
            self.bytes_left -= 1;
        }
    }

    /// Peek up to `peek_bits` bits MSB-first **without** consuming them,
    /// returning them right-justified in a `u64` alongside the number of real
    /// payload bits available in that window.
    ///
    /// `peek_bits` must be in `1..=56`. When fewer than `peek_bits` payload
    /// bits remain, the low-order positions of the returned value are zero
    /// (the accumulator shifts in zeros at the bottom), which is exactly what
    /// a left-justified canonical-code lookup expects. The second return value
    /// is `min(peek_bits, remaining)` so the caller can detect truncation.
    ///
    /// Used by the Huffman decoder to index a fixed-width lookup table and then
    /// [`Self::consume`] only the matched code's actual length — avoiding the
    /// expensive `read` + `unread` reseed that the old per-symbol path paid.
    #[inline]
    pub fn peek_bits(&mut self, peek_bits: u32) -> (u64, u32) {
        debug_assert!((1..=56).contains(&peek_bits));
        if self.bits_in_acc < peek_bits {
            self.refill();
        }
        let remaining = self.available - self.consumed;
        let avail = core::cmp::min(peek_bits as usize, remaining) as u32;
        let raw = self.acc >> (64 - peek_bits);
        (raw, avail)
    }

    /// Consume `n` bits previously inspected via [`Self::peek_bits`]. The caller
    /// must ensure `n` does not exceed the bits the matching peek reported as
    /// available and that `consumed + n <= available`.
    #[inline]
    pub fn consume(&mut self, n: u32) {
        debug_assert!(n <= self.bits_in_acc);
        debug_assert!(self.consumed + n as usize <= self.available);
        if n == 0 {
            return;
        }
        self.acc <<= n;
        self.bits_in_acc -= n;
        self.consumed += n as usize;
    }

    /// Read `n` bits (0..=64) MSB-first from the current backward cursor.
    ///
    /// Bits returned right-justified.
    #[inline]
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

        if n <= 56 {
            // Fast path: one refill suffices.
            if self.bits_in_acc < n {
                self.refill();
            }
            let result = self.acc >> (64 - n);
            self.acc <<= n;
            self.bits_in_acc -= n;
            self.consumed += n as usize;
            Ok(result)
        } else {
            // Wide-read path (n in 57..=64): take the top 56 bits in one
            // shot, then the remaining n-56 bits with a second refill. This
            // matches the byte-by-byte version's semantics without needing
            // a u128 accumulator.
            let high_n = 56u32;
            let low_n = n - 56;
            // Top chunk.
            if self.bits_in_acc < high_n {
                self.refill();
            }
            let high = self.acc >> (64 - high_n);
            self.acc <<= high_n;
            self.bits_in_acc -= high_n;
            // Low chunk.
            if self.bits_in_acc < low_n {
                self.refill();
            }
            let low = self.acc >> (64 - low_n);
            self.acc <<= low_n;
            self.bits_in_acc -= low_n;
            self.consumed += n as usize;
            Ok((high << low_n) | low)
        }
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

    #[test]
    fn wide_read_64_bits() {
        // Nine bytes: low eight are payload, last byte is a bare marker (0x01).
        // available = 8*8 + 0 = 64.
        // MSB-first 64-bit read = the eight payload bytes interpreted big-endian.
        let data = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01];
        let mut r = RevBitReader::new(&data).unwrap();
        assert_eq!(r.remaining(), 64);
        let v = r.read(64).unwrap();
        // Order: byte 7 = 0xEF (MSB), byte 6 = 0xCD, ..., byte 0 = 0x01 (LSB).
        assert_eq!(v, 0xEFCD_AB89_6745_2301);
        assert!(r.is_empty());
    }

    #[test]
    fn wide_read_60_bits_then_4() {
        let data = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01];
        let mut r = RevBitReader::new(&data).unwrap();
        // Top 60 bits then bottom 4.
        let high = r.read(60).unwrap();
        let low = r.read(4).unwrap();
        let combined = (high << 4) | low;
        assert_eq!(combined, 0xEFCD_AB89_6745_2301);
    }

    #[test]
    fn unread_round_trip() {
        // Eight bytes plus a marker. Read 12 bits, unread 4, then read 4 — the
        // unread 4 should reappear as the next 4 bits.
        let data = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01];
        let mut r = RevBitReader::new(&data).unwrap();
        let first12 = r.read(12).unwrap();
        // The first 12 MSB-first bits are the top 12 of the 64-bit value
        // 0xEFCD_AB89_6745_2301, i.e. 0xEFC.
        assert_eq!(first12, 0xEFC);
        r.unread(4);
        // Now the next 4 bits should be the lower nibble of the just-read 12.
        let nibble = r.read(4).unwrap();
        assert_eq!(nibble, 0xC);
        // Continue reading the next 8.
        let next8 = r.read(8).unwrap();
        assert_eq!(next8, 0xDA);
    }
}
