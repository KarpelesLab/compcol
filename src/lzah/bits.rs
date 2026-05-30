//! MSB-first bit reader for the StuffIt method-5 (LZAH) bitstream.
//!
//! Method 5 consumes its payload most-significant-bit-first (spec section 6).
//! Reads past the end of the buffered input are reported via `exhausted`
//! so the decoder can reject truncated streams rather than fabricate
//! symbols from zero-padding.

/// MSB-first bit reader over a fully-buffered input slice.
pub struct BitReader<'a> {
    data: &'a [u8],
    /// Next byte index to pull from `data`.
    byte_pos: usize,
    /// Bit accumulator (right-aligned, holds up to `nbits` valid low bits).
    acc: u32,
    /// Number of valid bits currently in `acc`.
    nbits: u32,
    /// Set once a read needed bits that the input did not contain.
    exhausted: bool,
}

impl<'a> BitReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            byte_pos: 0,
            acc: 0,
            nbits: 0,
            exhausted: false,
        }
    }

    /// True once a read ran past the real input (zero-padding kicked in).
    pub fn exhausted(&self) -> bool {
        self.exhausted
    }

    /// Read a single bit MSB-first. Past EOF returns 0 and sets `exhausted`.
    pub fn get_bit(&mut self) -> u32 {
        if self.nbits == 0 {
            if self.byte_pos < self.data.len() {
                self.acc = self.data[self.byte_pos] as u32;
                self.byte_pos += 1;
                self.nbits = 8;
            } else {
                self.exhausted = true;
                return 0;
            }
        }
        self.nbits -= 1;
        (self.acc >> self.nbits) & 1
    }

    /// Read `n` bits MSB-first (`0 <= n <= 16`), most significant bit first.
    pub fn get_bits(&mut self, n: u32) -> u32 {
        let mut v = 0u32;
        for _ in 0..n {
            v = (v << 1) | self.get_bit();
        }
        v
    }
}
