//! MSB-first bit reader / writer for the LZS payload.
//!
//! LZS packs bits high-bit-first within each byte (the same order as
//! bzip2's container — but the bit field semantics are independent). We
//! keep a small dedicated reader/writer here rather than pulling in
//! `crate::bzip2::bits` so the `lzs` feature stays decoupled from
//! `bzip2`.

extern crate alloc;
use alloc::vec::Vec;

/// MSB-first bit reader streaming over an internal `Vec<u8>` buffer.
///
/// The decoder accumulates compressed bytes into this reader as the
/// caller feeds input slices. `position()` is in **bits** from the start
/// of the buffer; the head is compacted periodically to keep memory
/// bounded.
#[derive(Debug, Default)]
pub(crate) struct BitReader {
    buf: Vec<u8>,
    /// Bit cursor: bit 0 of byte 0 is the MSB of `buf[0]`.
    bit_pos: usize,
}

impl BitReader {
    pub(crate) fn new() -> Self {
        Self {
            buf: Vec::new(),
            bit_pos: 0,
        }
    }

    /// Append raw bytes to the read window.
    pub(crate) fn push_bytes(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// Total bits available from the current read position onward.
    #[inline]
    pub(crate) fn remaining(&self) -> usize {
        (self.buf.len() * 8).saturating_sub(self.bit_pos)
    }

    /// Save the current bit cursor for `restore()`. Used when a token
    /// can't be fully decoded with the bytes currently buffered.
    #[inline]
    pub(crate) fn snapshot(&self) -> usize {
        self.bit_pos
    }

    /// Roll back to a previous `snapshot`.
    #[inline]
    pub(crate) fn restore(&mut self, snap: usize) {
        self.bit_pos = snap;
    }

    /// Try to read `n` bits (1..=16). Returns `None` if fewer than `n`
    /// bits are buffered.
    pub(crate) fn read_bits(&mut self, n: u32) -> Option<u32> {
        debug_assert!(n <= 16);
        if self.remaining() < n as usize {
            return None;
        }
        let mut v: u32 = 0;
        for _ in 0..n {
            let byte = self.buf[self.bit_pos >> 3];
            let shift = 7 - (self.bit_pos & 7);
            v = (v << 1) | (((byte >> shift) & 1) as u32);
            self.bit_pos += 1;
        }
        Some(v)
    }

    /// Compact the buffer: discard fully-consumed bytes so memory stays
    /// bounded on long streams. Should be called after a token has
    /// committed.
    pub(crate) fn compact(&mut self) {
        let drop = self.bit_pos / 8;
        if drop >= 4096 {
            self.buf.drain(..drop);
            self.bit_pos -= drop * 8;
        }
    }

    /// Drop all buffered state.
    pub(crate) fn clear(&mut self) {
        self.buf.clear();
        self.bit_pos = 0;
    }
}

/// MSB-first bit writer accumulating into an output `Vec<u8>`.
#[derive(Debug, Default)]
pub(crate) struct BitWriter {
    out: Vec<u8>,
    /// Pending bits held left-aligned in `cur`'s high portion. `nbits`
    /// of them are valid; the rest are zero placeholders.
    cur: u8,
    nbits: u8,
}

impl BitWriter {
    pub(crate) fn new() -> Self {
        Self {
            out: Vec::new(),
            cur: 0,
            nbits: 0,
        }
    }

    /// Write `n` bits (1..=16) of `v` MSB-first.
    pub(crate) fn write_bits(&mut self, n: u32, v: u32) {
        debug_assert!(n <= 16);
        let mut i = n;
        while i > 0 {
            i -= 1;
            let bit = ((v >> i) & 1) as u8;
            self.cur = (self.cur << 1) | bit;
            self.nbits += 1;
            if self.nbits == 8 {
                self.out.push(self.cur);
                self.cur = 0;
                self.nbits = 0;
            }
        }
    }

    /// Pad the final partial byte to a byte boundary with `1` bits — the
    /// RFC 1974 §2 termination convention.
    pub(crate) fn pad_with_ones_to_byte(&mut self) {
        while self.nbits != 0 {
            self.cur = (self.cur << 1) | 1;
            self.nbits += 1;
            if self.nbits == 8 {
                self.out.push(self.cur);
                self.cur = 0;
                self.nbits = 0;
            }
        }
    }

    /// Consume the writer, returning the assembled bytes. Does **not**
    /// flush any in-flight partial byte — callers normally call
    /// `pad_with_ones_to_byte` first.
    pub(crate) fn into_bytes(self) -> Vec<u8> {
        self.out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate alloc;
    use alloc::vec;

    #[test]
    fn round_trip_msb_first() {
        let mut w = BitWriter::new();
        w.write_bits(8, 0xAB);
        let bytes = w.into_bytes();
        assert_eq!(bytes, vec![0xAB]);
        let mut r = BitReader::new();
        r.push_bytes(&bytes);
        assert_eq!(r.read_bits(8), Some(0xAB));
    }

    #[test]
    fn cross_byte_field() {
        let mut w = BitWriter::new();
        w.write_bits(12, 0xABC);
        w.write_bits(4, 0xD);
        let bytes = w.into_bytes();
        assert_eq!(bytes, vec![0xAB, 0xCD]);
        let mut r = BitReader::new();
        r.push_bytes(&bytes);
        assert_eq!(r.read_bits(12), Some(0xABC));
        assert_eq!(r.read_bits(4), Some(0xD));
    }

    #[test]
    fn pad_with_ones() {
        let mut w = BitWriter::new();
        // 9 bits: end-of-stream marker.
        w.write_bits(9, 0b1_1000_0000);
        w.pad_with_ones_to_byte();
        let bytes = w.into_bytes();
        // First byte: 1100 0000 = 0xC0; second byte starts with the
        // final bit of the marker (0) then 7 padding 1s = 0x7F.
        assert_eq!(bytes, vec![0xC0, 0x7F]);
    }

    #[test]
    fn snapshot_restore() {
        let mut r = BitReader::new();
        r.push_bytes(&[0xAB, 0xCD]);
        let snap = r.snapshot();
        assert_eq!(r.read_bits(4), Some(0xA));
        r.restore(snap);
        assert_eq!(r.read_bits(8), Some(0xAB));
    }
}
