//! Reverse bit writer for the Zstandard sequence/FSE bitstream.
//!
//! Mirror image of [`crate::zstd::bitreader::RevBitReader`]. The output is
//! laid out so that the byte the decoder reads first (highest-indexed byte
//! holding the start marker) corresponds to the bits the encoder *most
//! recently* wrote — i.e. the decoder reads them in reverse-write order.
//!
//! Internally we accumulate bits LSB-first into a `u64` and flush whole bytes
//! little-endian to a [`Vec<u8>`] as the accumulator overflows; the start
//! marker (a single `1`-bit) is appended at [`finish`].
//!
//! Per RFC 8478 §3.1.1.3.2 the FSE sequence stream is written in *reverse
//! sequence order* — the last sequence is encoded first, so that the decoder
//! (which reads from the marker downward) recovers the original order.

use alloc::vec::Vec;

/// Streaming reverse bit writer.
pub struct RevBitWriter {
    buf: Vec<u8>,
    /// Pending bits, with newest at LSB.
    acc: u64,
    /// Number of pending bits in `acc` (0..=56 after each call).
    n_bits: u32,
}

impl RevBitWriter {
    pub fn new() -> Self {
        Self {
            buf: Vec::new(),
            acc: 0,
            n_bits: 0,
        }
    }

    /// Write the low `n` bits of `value`. `n` must be ≤ 56 so we never
    /// overflow the accumulator before a flush.
    pub fn write_bits(&mut self, value: u64, n: u32) {
        debug_assert!(n <= 56, "write_bits n={} > 56", n);
        if n == 0 {
            return;
        }
        let mask = if n == 64 { u64::MAX } else { (1u64 << n) - 1 };
        self.acc |= (value & mask) << self.n_bits;
        self.n_bits += n;
        while self.n_bits >= 8 {
            self.buf.push((self.acc & 0xFF) as u8);
            self.acc >>= 8;
            self.n_bits -= 8;
        }
    }

    /// Finalise: append the 1-bit start marker and return the produced bytes.
    pub fn finish(mut self) -> Vec<u8> {
        // Marker is the lone "1" bit at the highest position used.
        self.acc |= 1u64 << self.n_bits;
        self.n_bits += 1;
        while self.n_bits > 0 {
            self.buf.push((self.acc & 0xFF) as u8);
            self.acc >>= 8;
            self.n_bits = self.n_bits.saturating_sub(8);
        }
        self.buf
    }
}

impl Default for RevBitWriter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zstd::bitreader::RevBitReader;

    #[test]
    fn single_bit_round_trip() {
        let mut w = RevBitWriter::new();
        w.write_bits(1, 1);
        let bytes = w.finish();
        let mut r = RevBitReader::new(&bytes).unwrap();
        assert_eq!(r.remaining(), 1);
        assert_eq!(r.read(1).unwrap(), 1);
    }

    #[test]
    fn three_bit_value_round_trip() {
        let mut w = RevBitWriter::new();
        w.write_bits(0b101, 3);
        let bytes = w.finish();
        let mut r = RevBitReader::new(&bytes).unwrap();
        assert_eq!(r.remaining(), 3);
        assert_eq!(r.read(3).unwrap(), 0b101);
    }

    #[test]
    fn multiple_writes_reverse_order() {
        // Decoder reads in REVERSE-write order. We write three sequences
        // backwards and the decoder should see them in their original order.
        let seqs = [(0b101u64, 3), (0b00u64, 2), (0b1111u64, 4)];
        let mut w = RevBitWriter::new();
        for (v, n) in seqs.iter().rev() {
            w.write_bits(*v, *n);
        }
        let bytes = w.finish();
        let mut r = RevBitReader::new(&bytes).unwrap();
        for (v, n) in &seqs {
            assert_eq!(r.read(*n).unwrap(), *v);
        }
    }

    #[test]
    fn long_stream_round_trip() {
        // 100 values of 5 bits each → 500 bits → spans many bytes.
        let values: Vec<u64> = (0..100).map(|i| (i * 7) & 0b11111).collect();
        let mut w = RevBitWriter::new();
        for v in values.iter().rev() {
            w.write_bits(*v, 5);
        }
        let bytes = w.finish();
        let mut r = RevBitReader::new(&bytes).unwrap();
        for v in &values {
            assert_eq!(r.read(5).unwrap(), *v);
        }
    }

    #[test]
    fn byte_aligned_no_marker_byte_added() {
        // Exactly 8 bits written → 1 byte output for payload plus marker.
        // Marker should be at bit 0 of a new byte.
        let mut w = RevBitWriter::new();
        w.write_bits(0xAB, 8);
        let bytes = w.finish();
        let mut r = RevBitReader::new(&bytes).unwrap();
        assert_eq!(r.remaining(), 8);
        assert_eq!(r.read(8).unwrap(), 0xAB);
    }
}
