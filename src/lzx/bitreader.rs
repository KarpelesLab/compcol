//! MSB-first, 16-bit-LE-word bit reader for LZX.
//!
//! LZX's bitstream is a sequence of little-endian 16-bit words, but bits
//! within each word are consumed most-significant-first. So the wire byte
//! sequence `B0 B1 B2 B3 …` is conceptually the bit stream
//! `(B1<<8)|B0`, then `(B3<<8)|B2`, …, with each word feeding 16 bits MSB-first.
//!
//! Bytes are pushed in via [`feed`]; reads pull from the MSB end of the
//! accumulator. The accumulator is 64 bits wide so up to four whole input
//! bytes (two words) can be buffered, leaving enough headroom to refill
//! whenever fewer than 17 bits remain. The reader never panics on
//! over-consumption — callers must check [`bits_available`] first.

#[derive(Debug, Clone, Copy, Default)]
pub struct BitReader {
    /// Bits packed MSB-first into the high end of the accumulator; the next
    /// bit to consume is bit `(63)`.
    acc: u64,
    nbits: u32,
    /// Tracks whether the half-word pair we're building is on its low byte
    /// (false) or its high byte (true). LZX words are little-endian, so the
    /// low byte arrives first and forms the *bottom* 8 bits of the 16-bit
    /// MSB-first chunk that lands in the accumulator.
    half: HalfWord,
    /// How many bits at the tail of the accumulator were put there by
    /// [`pad_eof`](Self::pad_eof) rather than read from the stream. Zero
    /// until the end of input is reached. Those bits exist only so a Huffman
    /// decode can look ahead; once `nbits` drops below this count, padding
    /// has been consumed as if it were data.
    eof_bits: u32,
    /// The stream ended half-way through a word: the word just before the
    /// zero padding holds one real byte (its low byte) and counts as
    /// padding. See [`take_eof_half_byte`](Self::take_eof_half_byte).
    eof_half: bool,
}

#[derive(Debug, Clone, Copy, Default)]
struct HalfWord {
    /// `Some(byte)` if we've received the low byte of a 16-bit word and are
    /// waiting on its high byte. Always `None` after a full word lands.
    pending_low: Option<u8>,
}

impl BitReader {
    pub const fn new() -> Self {
        Self {
            acc: 0,
            nbits: 0,
            half: HalfWord { pending_low: None },
            eof_bits: 0,
            eof_half: false,
        }
    }

    /// Push one input byte. Caller must verify `bits_available() <= 48` first;
    /// the worst case is feeding a whole 16-bit word at once, which costs 16
    /// bits of accumulator space.
    pub fn feed(&mut self, byte: u8) {
        match self.half.pending_low {
            None => {
                self.half.pending_low = Some(byte);
            }
            Some(low) => {
                self.half.pending_low = None;
                debug_assert!(self.nbits + 16 <= 64);
                let word = ((byte as u64) << 8) | (low as u64);
                self.acc |= word << (48 - self.nbits);
                self.nbits += 16;
            }
        }
    }

    /// True if a 16-bit word is half-buffered (low byte received, high byte
    /// still pending). Used by `finish` to detect a truncated stream.
    #[allow(dead_code)]
    pub const fn has_partial_word(&self) -> bool {
        self.half.pending_low.is_some()
    }

    /// Headroom check: caller drains the input slice until this returns true.
    pub const fn can_accept_word(&self) -> bool {
        self.nbits + 16 <= 64
    }

    pub const fn bits_available(&self) -> u32 {
        self.nbits
    }

    /// Look at the next `n` bits, MSB-first. Requires `n <= 32` and
    /// `n <= bits_available()`. Returns the bits right-justified.
    pub fn peek(&self, n: u32) -> u32 {
        debug_assert!(n <= 32);
        debug_assert!(n <= self.nbits);
        if n == 0 {
            return 0;
        }
        ((self.acc >> (64 - n)) & ((1u64 << n) - 1)) as u32
    }

    pub fn drop_bits(&mut self, n: u32) {
        debug_assert!(n <= self.nbits);
        self.acc <<= n;
        self.nbits -= n;
    }

    /// Read and discard 0..=15 bits to reach the next 16-bit word boundary
    /// (relative to the wire stream). Used by uncompressed blocks per spec
    /// §2.2 — "the bitstream is aligned to a 16-bit boundary before the 12-byte
    /// R0/R1/R2 dump and after the raw payload (if length is odd, an extra
    /// pad byte follows)".
    pub fn align_to_word(&mut self) {
        // bits_available % 16: drop the partial-word fragment we have
        // buffered. Caller must guarantee that fragment is present.
        let drop = self.nbits & 15;
        self.drop_bits(drop);
    }

    /// Room check for [`pad_eof`](Self::pad_eof), which adds up to two words.
    pub const fn can_pad_eof(&self) -> bool {
        self.nbits + 32 <= 64
    }

    /// Mark the end of the input: append one zero word so a Huffman decode
    /// near the end of the stream can look ahead by the tree's longest code
    /// (libmspack pads its input the same way). The padding may be peeked
    /// but never consumed — see [`eof_pad_consumed`](Self::eof_pad_consumed).
    ///
    /// A trailing half word (the stream had an odd number of bytes) is
    /// completed with a zero high byte and counted as padding too: its bits
    /// cannot be told apart from the missing ones, except by
    /// [`take_eof_half_byte`](Self::take_eof_half_byte).
    ///
    /// Call once, with `can_pad_eof()` true.
    pub fn pad_eof(&mut self) {
        debug_assert!(self.can_pad_eof());
        debug_assert_eq!(self.eof_bits, 0);
        if let Some(low) = self.half.pending_low.take() {
            self.acc |= (low as u64) << (48 - self.nbits);
            self.nbits += 16;
            self.eof_bits = 16;
            self.eof_half = true;
        }
        // The zero word itself: the accumulator is already zero there.
        self.nbits += 16;
        self.eof_bits += 16;
    }

    /// True once bits that came from [`pad_eof`](Self::pad_eof) have been
    /// consumed: the stream ended before the data did.
    pub const fn eof_pad_consumed(&self) -> bool {
        self.nbits < self.eof_bits
    }

    /// If the next word is the trailing half word of the stream, consume it
    /// and return its one real byte. This is the final byte of an odd-sized
    /// uncompressed block whose pad byte was left off the end of the stream.
    pub fn take_eof_half_byte(&mut self) -> Option<u8> {
        if !self.eof_half || self.nbits != self.eof_bits {
            return None;
        }
        let byte = (self.peek(16) & 0xFF) as u8;
        self.drop_bits(16);
        self.eof_half = false;
        self.eof_bits = 16;
        Some(byte)
    }

    #[allow(dead_code)]
    pub fn reset(&mut self) {
        *self = Self::new();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn msb_first_within_word() {
        // wire bytes: 0xAB, 0xCD → word = 0xCDAB
        // MSB-first the bits are: 1100 1101 1010 1011
        let mut r = BitReader::new();
        r.feed(0xAB);
        assert_eq!(r.bits_available(), 0); // half buffered
        r.feed(0xCD);
        assert_eq!(r.bits_available(), 16);
        // top 4 bits = 0xC
        assert_eq!(r.peek(4), 0xC);
        r.drop_bits(4);
        assert_eq!(r.peek(4), 0xD);
        r.drop_bits(4);
        assert_eq!(r.peek(8), 0xAB);
    }

    #[test]
    fn eof_pad_may_be_peeked_but_not_consumed() {
        let mut r = BitReader::new();
        r.feed(0xAB);
        r.feed(0xCD);
        r.pad_eof();
        assert_eq!(r.bits_available(), 32);
        assert_eq!(r.peek(32), 0xCDAB_0000);
        r.drop_bits(16);
        assert!(!r.eof_pad_consumed());
        assert_eq!(r.take_eof_half_byte(), None);
        r.drop_bits(1);
        assert!(r.eof_pad_consumed());
    }

    #[test]
    fn eof_half_word_is_padding_except_as_a_byte() {
        let mut r = BitReader::new();
        r.feed(0x11);
        r.feed(0x22);
        r.feed(0x33); // odd trailing byte
        r.pad_eof();
        assert_eq!(r.bits_available(), 48);
        assert_eq!(r.take_eof_half_byte(), None); // not there yet
        r.drop_bits(16);
        assert!(!r.eof_pad_consumed());
        let mut bits = r;
        bits.drop_bits(1);
        assert!(bits.eof_pad_consumed());
        assert_eq!(r.take_eof_half_byte(), Some(0x33));
        assert!(!r.eof_pad_consumed());
        assert_eq!(r.bits_available(), 16);
        assert_eq!(r.take_eof_half_byte(), None);
    }

    #[test]
    fn aligned_drops_fragment() {
        let mut r = BitReader::new();
        r.feed(0x00);
        r.feed(0xFF);
        r.drop_bits(3);
        assert_eq!(r.bits_available(), 13);
        r.align_to_word();
        assert_eq!(r.bits_available(), 0);
    }
}
