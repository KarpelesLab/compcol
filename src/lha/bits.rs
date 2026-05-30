//! MSB-first bit reader and writer for the LHA/LZH Huffman streams.
//!
//! LHA reads bits most-significant-first from a byte stream. Okumura's
//! reference `getbits`/`fillbuf` keep a 16-bit window and refill a byte
//! at a time; reading past the end of input yields zero bits (the
//! original code zero-pads, which is how the final partial code in a
//! block is consumed). We mirror that zero-padding behaviour but track
//! whether we *actually* ran past the end so the decoder can reject
//! truncated streams when it still owes output.

extern crate alloc;
use alloc::vec::Vec;

/// MSB-first bit reader over a fully-buffered input slice.
pub struct BitReader<'a> {
    data: &'a [u8],
    /// Next byte index to pull from `data`.
    byte_pos: usize,
    /// Bit accumulator (right-aligned, up to 32 valid low bits).
    acc: u32,
    /// Number of valid bits currently in `acc`.
    nbits: u32,
    /// Total real (non-padding) bits available in `data`.
    avail_bits: u64,
    /// Total bits actually *consumed* (peeking does not count).
    consumed_bits: u64,
}

impl<'a> BitReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            byte_pos: 0,
            acc: 0,
            nbits: 0,
            avail_bits: (data.len() as u64) * 8,
            consumed_bits: 0,
        }
    }

    /// True once more bits have been *consumed* than the input actually
    /// holds — i.e. a real symbol needed zero-padding past EOF. Peeking
    /// the tail (e.g. a 12-bit table index whose real code is shorter)
    /// does not trip this.
    pub fn overran(&self) -> bool {
        self.consumed_bits > self.avail_bits
    }

    /// Pull bytes into the accumulator until at least `n` bits are
    /// available (zero-padding past EOF). `n` is at most 24.
    fn fill(&mut self, n: u32) {
        while self.nbits < n {
            let byte = if self.byte_pos < self.data.len() {
                let b = self.data[self.byte_pos];
                self.byte_pos += 1;
                b as u32
            } else {
                0
            };
            self.acc = (self.acc << 8) | byte;
            self.nbits += 8;
        }
    }

    /// Read `n` bits MSB-first (`0 <= n <= 16`). Returns the value.
    pub fn get_bits(&mut self, n: u32) -> u32 {
        if n == 0 {
            return 0;
        }
        self.fill(n);
        let shift = self.nbits - n;
        let val = (self.acc >> shift) & ((1u32 << n) - 1);
        self.nbits = shift;
        // Keep only the still-valid low bits to bound `acc` growth.
        self.acc &= (1u32 << self.nbits).wrapping_sub(1);
        self.consumed_bits += n as u64;
        val
    }

    /// Peek the next `n` bits MSB-first without consuming them
    /// (`0 <= n <= 16`).
    pub fn peek_bits(&mut self, n: u32) -> u32 {
        if n == 0 {
            return 0;
        }
        self.fill(n);
        let shift = self.nbits - n;
        (self.acc >> shift) & ((1u32 << n) - 1)
    }

    /// Consume `n` previously-peeked bits.
    pub fn consume(&mut self, n: u32) {
        self.fill(n);
        self.nbits -= n;
        self.acc &= (1u32 << self.nbits).wrapping_sub(1);
        self.consumed_bits += n as u64;
    }
}

/// MSB-first bit writer collecting into a `Vec<u8>`.
pub struct BitWriter {
    out: Vec<u8>,
    acc: u32,
    nbits: u32,
}

impl BitWriter {
    pub fn new() -> Self {
        Self {
            out: Vec::new(),
            acc: 0,
            nbits: 0,
        }
    }

    /// Append the low `n` bits of `val` MSB-first (`0 <= n <= 24`).
    pub fn put_bits(&mut self, n: u32, val: u32) {
        if n == 0 {
            return;
        }
        let masked = val & ((1u32.checked_shl(n).unwrap_or(0)).wrapping_sub(1));
        self.acc = (self.acc << n) | masked;
        self.nbits += n;
        while self.nbits >= 8 {
            let shift = self.nbits - 8;
            self.out.push(((self.acc >> shift) & 0xFF) as u8);
            self.nbits = shift;
        }
        self.acc &= (1u32 << self.nbits).wrapping_sub(1);
    }

    /// Flush any remaining bits, zero-padding the final byte (MSB-first).
    pub fn finish(mut self) -> Vec<u8> {
        if self.nbits > 0 {
            let pad = 8 - self.nbits;
            self.out.push(((self.acc << pad) & 0xFF) as u8);
            self.nbits = 0;
        }
        self.out
    }
}
