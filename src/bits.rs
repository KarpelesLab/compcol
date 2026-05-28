//! LSB-first bit I/O used by deflate / zlib / gzip codecs.
//!
//! Deflate (RFC 1951 §3.1.1) packs non-Huffman fields LSB-first within each
//! byte, and Huffman codes MSB-first. This module exposes the underlying
//! LSB-first stream; bit-order reversal for Huffman codes is the caller's
//! responsibility (the canonical Huffman builder reverses the codes once
//! at table-construction time so the writer can splat them out LSB-first).

/// Streaming LSB-first bit reader.
///
/// Bytes are pushed via [`feed`](BitReader::feed) as the caller consumes them
/// from the codec's input slice. Bits are peeked / consumed by the caller.
/// Persists across streaming calls — the codec holds one of these per stream.
#[derive(Debug, Clone, Copy, Default)]
pub struct BitReader {
    acc: u64,
    nbits: u32,
}

impl BitReader {
    pub const fn new() -> Self {
        Self { acc: 0, nbits: 0 }
    }

    /// Push one byte into the accumulator at the high end. Caller must
    /// ensure `bits_available() <= 56` first — i.e. drain before refilling.
    pub fn feed(&mut self, byte: u8) {
        debug_assert!(self.nbits <= 56, "BitReader overflow: drain before feeding");
        self.acc |= (byte as u64) << self.nbits;
        self.nbits += 8;
    }

    pub const fn bits_available(&self) -> u32 {
        self.nbits
    }

    /// Look at the next `n` bits (LSB-first) without consuming. Requires
    /// `n <= bits_available()`.
    pub fn peek(&self, n: u32) -> u64 {
        debug_assert!(n <= self.nbits);
        if n == 0 {
            0
        } else {
            self.acc & ((1u64 << n) - 1)
        }
    }

    /// Drop the next `n` bits. Requires `n <= bits_available()`.
    pub fn drop_bits(&mut self, n: u32) {
        debug_assert!(n <= self.nbits);
        self.acc >>= n;
        self.nbits -= n;
    }

    /// Discard partial-byte bits so subsequent reads start at a byte boundary.
    pub fn align_to_byte(&mut self) {
        let drop = self.nbits & 7;
        self.drop_bits(drop);
    }

    /// Erase all pending state.
    pub fn reset(&mut self) {
        self.acc = 0;
        self.nbits = 0;
    }
}

/// LSB-first bit writer that appends to a caller-supplied byte sink.
///
/// Used by the deflate encoder. Each `write` shifts up to 32 LSB-first bits
/// into the accumulator then drains any whole bytes into the output `Vec`.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, Default)]
pub struct BitWriter {
    acc: u64,
    nbits: u32,
}

#[cfg(feature = "alloc")]
impl BitWriter {
    pub const fn new() -> Self {
        Self { acc: 0, nbits: 0 }
    }

    /// Append `n` LSB-first bits of `value`, draining whole bytes into `out`.
    /// Requires `n <= 32`.
    pub fn write(&mut self, value: u32, n: u32, out: &mut alloc::vec::Vec<u8>) {
        debug_assert!(n <= 32);
        // After the drain loop below `self.nbits` is always < 8, so
        // pre-write nbits (<8) + n (<=32) <= 40, well below 64.
        let masked = if n == 0 {
            0
        } else if n == 64 {
            value as u64
        } else {
            (value as u64) & ((1u64 << n) - 1)
        };
        self.acc |= masked << self.nbits;
        self.nbits += n;
        while self.nbits >= 8 {
            out.push(self.acc as u8);
            self.acc >>= 8;
            self.nbits -= 8;
        }
    }

    /// Pad with zero bits to the next byte boundary, flushing the final byte
    /// into `out` if there are pending bits.
    pub fn align(&mut self, out: &mut alloc::vec::Vec<u8>) {
        if self.nbits > 0 {
            out.push(self.acc as u8);
            self.acc = 0;
            self.nbits = 0;
        }
    }

    #[allow(dead_code)]
    pub const fn pending_bits(&self) -> u32 {
        self.nbits
    }
}

/// Reverse the lowest `n` bits of `v`. Used by the Huffman builder to
/// pre-reverse code values so they can be written LSB-first by [`BitWriter`].
pub const fn reverse_bits(mut v: u32, n: u32) -> u32 {
    let mut out = 0u32;
    let mut i = 0;
    while i < n {
        out = (out << 1) | (v & 1);
        v >>= 1;
        i += 1;
    }
    out
}
