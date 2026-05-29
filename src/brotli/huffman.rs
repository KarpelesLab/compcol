//! Brotli-flavoured canonical Huffman decoder.
//!
//! Brotli prefix codes are MSB-first canonical codes with length cap 15
//! (literal/IC/distance) or smaller. Codes are emitted MSB-first into an
//! LSB-first bit stream, so each new bit appended to a code value reads
//! out of the LSB-first accumulator at the next bit position.
//!
//! Unlike the deflate-family decoder in `crate::huffman`, this one is
//! built dynamically (heap-allocated) because the alphabet sizes vary
//! per Brotli structure (18, 26, 256, 704, up to ~1128 distance symbols)
//! and we can't pick a single `const N`.
//!
//! A code length of 0 means "symbol is unused"; a Huffman tree with
//! exactly one symbol of length 0 (the simple-NSYM=1 case) is supported
//! and consumes zero bits per decode.

use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;

/// Primary-LUT width for the fast-path symbol lookup. Codes of length
/// ≤ `PRIMARY_BITS` resolve in O(1); longer codes fall back to the
/// per-bit walk.
const PRIMARY_BITS: u32 = 9;
const PRIMARY_SIZE: usize = 1 << PRIMARY_BITS;

/// Packed (symbol, length) entry in the primary LUT. The low 16 bits hold
/// the symbol (brotli alphabets fit in 16 bits) and the top 5 bits hold
/// the code length. A length of 0 marks "long code -- take the slow path".
const LUT_LEN_SHIFT: u32 = 16;
const LUT_SYM_MASK: u32 = (1 << LUT_LEN_SHIFT) - 1;

/// Canonical Huffman decoder for one Brotli prefix code.
#[derive(Debug, Clone)]
pub(crate) struct HuffmanDecoder {
    /// `counts[l]` = number of symbols with code length `l`. `counts[0]`
    /// is unused except as the "single symbol with length 0" sentinel
    /// (see `single_symbol`).
    counts: [u32; 16],
    /// Symbols in canonical order grouped by ascending length.
    symbols: Vec<u32>,
    /// First numeric code value at each length.
    first_code: [u32; 16],
    /// Index into `symbols` where length-l codes start.
    first_idx: [u32; 16],
    /// Longest code length in the table; 0 if and only if `single_symbol`
    /// is `Some` or there are no symbols at all.
    max_length: u8,
    /// Set when there is exactly one defined symbol; that symbol is
    /// returned without consuming any bits (length-0 case from §3.4).
    single_symbol: Option<u32>,
    /// Primary lookup table: indexed by the next `PRIMARY_BITS` LSB-first
    /// stream bits. Each slot packs `(symbol, length)`; a length of 0
    /// means the code is longer than `PRIMARY_BITS` and the slow path
    /// has to walk per-bit.
    lut: alloc::boxed::Box<[u32; PRIMARY_SIZE]>,
}

impl HuffmanDecoder {
    /// Build a decoder where exactly one symbol is defined and consumes
    /// zero bits. Used by simple prefix codes with NSYM=1.
    pub(crate) fn single(sym: u32) -> Self {
        Self {
            counts: [0; 16],
            symbols: Vec::new(),
            first_code: [0; 16],
            first_idx: [0; 16],
            max_length: 0,
            single_symbol: Some(sym),
            lut: alloc::boxed::Box::new([0u32; PRIMARY_SIZE]),
        }
    }

    /// Build a decoder from an array of `(symbol, code_length)` pairs.
    /// Code lengths must be in 1..=15. Symbols with the same length are
    /// assigned codes in ascending symbol order.
    pub(crate) fn from_lengths_sparse(pairs: &[(u32, u8)]) -> Result<Self, Error> {
        // Sort by (length, symbol) so canonical assignment is just a walk.
        let mut owned: Vec<(u32, u8)> = pairs.to_vec();
        owned.sort_by(|a, b| a.1.cmp(&b.1).then(a.0.cmp(&b.0)));

        let mut counts = [0u32; 16];
        let mut max_length = 0u8;
        for &(_sym, len) in &owned {
            if len == 0 || len > 15 {
                return Err(Error::InvalidHuffmanTree);
            }
            counts[len as usize] += 1;
            if len > max_length {
                max_length = len;
            }
        }
        if max_length == 0 {
            return Err(Error::InvalidHuffmanTree);
        }

        // Kraft check: sum of count[l] * 2^(15-l) == 2^15 for a full tree.
        // Brotli requires a full tree.
        let mut kraft: u32 = 0;
        for l in 1..=15u32 {
            kraft += counts[l as usize] << (15 - l);
        }
        if kraft != (1 << 15) {
            return Err(Error::InvalidHuffmanTree);
        }

        let mut first_code = [0u32; 16];
        let mut first_idx = [0u32; 16];
        let mut code: u32 = 0;
        let mut idx: u32 = 0;
        for l in 1..=15 {
            code <<= 1;
            first_code[l] = code;
            first_idx[l] = idx;
            code += counts[l];
            idx += counts[l];
        }

        let mut symbols = vec![0u32; owned.len()];
        let mut next = first_idx;
        for &(sym, len) in &owned {
            let slot = next[len as usize] as usize;
            symbols[slot] = sym;
            next[len as usize] += 1;
        }

        // Build the primary LUT. Brotli's Huffman codes are MSB-first
        // within the LSB-first bit stream (same convention as deflate),
        // so a canonical code value `c` of length `L` appears in the
        // stream as `reverse_bits(c, L)`. Each symbol of length
        // L ≤ PRIMARY_BITS populates every entry whose low L bits match
        // its reversed code value.
        let mut lut = alloc::boxed::Box::new([0u32; PRIMARY_SIZE]);
        let mut next_code = first_code;
        for &(sym, len) in &owned {
            let code = next_code[len as usize];
            next_code[len as usize] += 1;
            if (len as u32) > PRIMARY_BITS {
                continue;
            }
            let reversed = reverse_bits_lo(code, len as u32);
            let entry = sym | ((len as u32) << LUT_LEN_SHIFT);
            let stride = 1usize << len;
            let mut slot = reversed as usize;
            while slot < PRIMARY_SIZE {
                lut[slot] = entry;
                slot += stride;
            }
        }

        Ok(Self {
            counts,
            symbols,
            first_code,
            first_idx,
            max_length,
            single_symbol: None,
            lut,
        })
    }

    /// Build a decoder from a dense array where `lengths[i]` is the code
    /// length for symbol `i` (0 = unused).
    pub(crate) fn from_lengths(lengths: &[u8]) -> Result<Self, Error> {
        let mut pairs: Vec<(u32, u8)> = Vec::new();
        for (i, &l) in lengths.iter().enumerate() {
            if l > 0 {
                pairs.push((i as u32, l));
            }
        }
        // Special case: zero or one defined symbol.
        if pairs.is_empty() {
            return Err(Error::InvalidHuffmanTree);
        }
        if pairs.len() == 1 {
            // RFC: a one-symbol prefix code is encoded as simple-NSYM=1
            // (length 0); a complex code with a single length-1 symbol
            // would not satisfy the Kraft equality. The caller is
            // responsible for using simple-NSYM=1 in this case, but we
            // accept length-1 too for robustness.
            if pairs[0].1 == 1 {
                // Degenerate: a single 1-bit code. Build as a normal
                // decoder anyway — it occupies only one of the two
                // 1-bit code positions; decoding the other is an error.
                // We treat it as a single_symbol with no bit consumption
                // since the Kraft sum would otherwise be 2^14, not 2^15.
                // Reject: not a full tree.
                return Err(Error::InvalidHuffmanTree);
            }
            return Err(Error::InvalidHuffmanTree);
        }
        Self::from_lengths_sparse(&pairs)
    }

    /// Build from explicit code lengths but accept incomplete (single-
    /// symbol) trees by promoting them to `single_symbol` style. This
    /// matches the simple-NSYM=1 convention from §3.4.
    pub(crate) fn from_lengths_allow_single(lengths: &[u8]) -> Result<Self, Error> {
        let nonzero = lengths.iter().filter(|&&l| l > 0).count();
        if nonzero == 1 {
            let sym = lengths.iter().position(|&l| l > 0).unwrap() as u32;
            return Ok(Self::single(sym));
        }
        Self::from_lengths(lengths)
    }

    /// Decode one symbol synchronously from the bit source. Assumes the
    /// caller has at least `max_length` bits available (or, in the
    /// length-0 case, none required). Returns `Err(InvalidHuffmanTree)`
    /// if the read bits don't match any code.
    pub(crate) fn decode(&self, br: &mut BitSource<'_>) -> Result<u32, Error> {
        if let Some(s) = self.single_symbol {
            return Ok(s);
        }
        if self.max_length == 0 {
            return Err(Error::InvalidHuffmanTree);
        }
        let max = self.max_length as u32;

        // Fast path: peek PRIMARY_BITS bits, index the LUT, advance the
        // bit position by the actual code length.
        if br.remaining() >= PRIMARY_BITS as usize {
            let idx = br.peek_bits(PRIMARY_BITS) as usize;
            let entry = self.lut[idx];
            let len = entry >> LUT_LEN_SHIFT;
            if len > 0 {
                br.set_position(br.position() + len as usize);
                return Ok(entry & LUT_SYM_MASK);
            }
            // Long code (> PRIMARY_BITS) -- fall through to the slow path.
        }

        let mut code: u32 = 0;
        for length in 1..=max {
            let bit = br.read_bit()?;
            code = (code << 1) | bit;
            let count = self.counts[length as usize];
            if count > 0 {
                let first = self.first_code[length as usize];
                if code >= first && code < first + count {
                    let sym_idx = self.first_idx[length as usize] + (code - first);
                    return Ok(self.symbols[sym_idx as usize]);
                }
            }
        }
        Err(Error::InvalidHuffmanTree)
    }
}

/// Reverse the lowest `n` bits of `v`. Used at LUT-build time so the
/// table can be indexed directly by the next `n` LSB-first stream bits.
const fn reverse_bits_lo(mut v: u32, n: u32) -> u32 {
    let mut out = 0u32;
    let mut i = 0;
    while i < n {
        out = (out << 1) | (v & 1);
        v >>= 1;
        i += 1;
    }
    out
}

/// Synchronous bit source that the synchronous Huffman decoder reads
/// from. Wraps a borrowed byte slice plus a starting bit offset and
/// exposes single-bit and multi-bit reads.
///
/// All bit ordering is LSB-first within bytes (same as deflate).
///
/// Internally holds a 64-bit accumulator filled from `data` on demand so
/// the hot path (`read_bit`, `read_bits` for small `n`) services reads
/// out of registers instead of touching `data` every bit. The logical
/// bit position exposed via [`BitSource::position`] is
/// `load_pos - nbits`, i.e. consumed bits up to but not including the
/// next bit the caller will see.
#[derive(Debug)]
pub(crate) struct BitSource<'a> {
    data: &'a [u8],
    /// Absolute bit offset into `data` of the next bit not yet pulled
    /// into `acc`. Always satisfies `load_pos <= data.len() * 8`.
    load_pos: usize,
    /// Up to 64 bits, LSB-first, holding the next `nbits` bits the
    /// caller will consume.
    acc: u64,
    /// Number of valid bits currently in `acc`.
    nbits: u32,
}

impl<'a> BitSource<'a> {
    /// Construct from an existing slice and a starting bit position.
    pub(crate) fn at(data: &'a [u8], pos: usize) -> Self {
        Self {
            data,
            load_pos: pos,
            acc: 0,
            nbits: 0,
        }
    }

    pub(crate) fn position(&self) -> usize {
        self.load_pos - self.nbits as usize
    }

    pub(crate) fn set_position(&mut self, p: usize) {
        self.load_pos = p;
        self.acc = 0;
        self.nbits = 0;
    }

    /// Remaining bits available (still in `data` plus held in `acc`).
    #[allow(dead_code)]
    pub(crate) fn remaining(&self) -> usize {
        (self.data.len() * 8 - self.load_pos) + self.nbits as usize
    }

    /// Pull more bits from `data` into `acc` until at least 57 bits are
    /// buffered or input is exhausted. Bytes are read LSB-first.
    fn refill(&mut self) {
        // Byte-aligned fast path: a single u64::from_le_bytes covers the
        // common case where the caller is mid-stream and the input slice
        // has 8 spare bytes ahead.
        if (self.load_pos & 7) == 0 && self.nbits <= 56 {
            let byte_pos = self.load_pos >> 3;
            if byte_pos + 8 <= self.data.len() {
                let bytes: [u8; 8] = self.data[byte_pos..byte_pos + 8]
                    .try_into()
                    .expect("8-byte slice");
                let chunk = u64::from_le_bytes(bytes);
                self.acc |= chunk << self.nbits;
                let added = 64 - self.nbits;
                self.load_pos += added as usize;
                self.nbits = 64;
                return;
            }
        }
        // Slow path: byte-by-byte (handles unaligned start and tail).
        while self.nbits <= 56 {
            let byte_pos = self.load_pos >> 3;
            if byte_pos >= self.data.len() {
                break;
            }
            let bit_off = (self.load_pos & 7) as u32;
            let take = 8 - bit_off;
            let chunk = (self.data[byte_pos] as u64) >> bit_off;
            self.acc |= chunk << self.nbits;
            self.nbits += take;
            self.load_pos += take as usize;
        }
    }

    pub(crate) fn read_bit(&mut self) -> Result<u32, Error> {
        if self.nbits == 0 {
            self.refill();
            if self.nbits == 0 {
                return Err(Error::UnexpectedEnd);
            }
        }
        let bit = (self.acc & 1) as u32;
        self.acc >>= 1;
        self.nbits -= 1;
        Ok(bit)
    }

    /// Peek `n` bits (0 < n ≤ 32) without advancing. Caller must
    /// guarantee `n <= remaining()`.
    pub(crate) fn peek_bits(&self, n: u32) -> u32 {
        debug_assert!(n > 0 && n <= 32);
        debug_assert!(n as usize <= self.remaining());
        let mut acc: u32 = 0;
        let mut got: u32 = 0;
        let mut pos = self.pos;
        while got < n {
            let byte_pos = pos >> 3;
            let bit_off = (pos & 7) as u32;
            let take = (8 - bit_off).min(n - got);
            let mask: u32 = if take == 32 {
                u32::MAX
            } else {
                (1u32 << take) - 1
            };
            let chunk = ((self.data[byte_pos] as u32) >> bit_off) & mask;
            acc |= chunk << got;
            got += take;
            pos += take as usize;
        }
        acc
    }

    /// Read `n` bits (0..=32) as a little-endian integer.
    pub(crate) fn read_bits(&mut self, n: u32) -> Result<u32, Error> {
        debug_assert!(n <= 32);
        if n == 0 {
            return Ok(0);
        }
        if self.nbits < n {
            self.refill();
            if self.nbits < n {
                return Err(Error::UnexpectedEnd);
            }
        }
        let v = (self.acc & ((1u64 << n) - 1)) as u32;
        self.acc >>= n;
        self.nbits -= n;
        Ok(v)
    }

    /// Align the bit position up to the next byte boundary.
    pub(crate) fn align_to_byte(&mut self) {
        let r = (self.position() & 7) as u32;
        if r != 0 {
            let drop = 8 - r;
            if drop <= self.nbits {
                self.acc >>= drop;
                self.nbits -= drop;
            } else {
                let extra = drop - self.nbits;
                self.acc = 0;
                self.nbits = 0;
                self.load_pos += extra as usize;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_symbol_zero_bits() {
        let d = HuffmanDecoder::single(42);
        let data = [0u8; 1];
        let mut src = BitSource::at(&data, 0);
        assert_eq!(d.decode(&mut src).unwrap(), 42);
        assert_eq!(src.position(), 0);
    }

    #[test]
    fn two_symbols_one_bit_each() {
        // symbol 0 -> length 1 -> code 0, symbol 1 -> length 1 -> code 1
        let d = HuffmanDecoder::from_lengths_sparse(&[(0, 1), (1, 1)]).unwrap();
        // bits LSB-first in byte: 0,1,0,1,...
        let data = [0b1010_1010u8];
        let mut src = BitSource::at(&data, 0);
        // First bit is 0 (LSB) -> symbol 0
        assert_eq!(d.decode(&mut src).unwrap(), 0);
        // Next bit is 1 -> symbol 1
        assert_eq!(d.decode(&mut src).unwrap(), 1);
    }

    #[test]
    fn read_bits_lsb_first() {
        let data = [0b1011_0100u8, 0b0000_0001];
        let mut src = BitSource::at(&data, 0);
        // Read 4 bits -> 0100 = 4
        assert_eq!(src.read_bits(4).unwrap(), 4);
        // Read 8 bits spanning byte boundary -> 0001_1011 = 0x1B = 27
        // After first 4 bits: pos=4. Next 8 bits: bits 4..12.
        // Byte 0 bits 4..7 = 1011 (LSB-first), Byte 1 bits 0..3 = 0001
        // Combined LSB-first: 1011 then 0001 -> 0001_1011 = 0x1B
        assert_eq!(src.read_bits(8).unwrap(), 0x1B);
    }

    #[test]
    fn fast_path_byte_aligned_refill() {
        // 9 bytes so the byte-aligned 8-byte fast path fires on the first
        // refill, then the slow path handles the final byte.
        let data: [u8; 9] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0xFF];
        let mut src = BitSource::at(&data, 0);
        // Read a u64-sized field worth of bits in pieces.
        for &expected in &[0x01u32, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0xFF] {
            assert_eq!(src.read_bits(8).unwrap(), expected);
        }
        assert_eq!(src.position(), 9 * 8);
    }

    #[test]
    fn unaligned_start_refill() {
        // Resume mid-byte: the slow path must service partial-byte heads.
        let data: [u8; 5] = [0xAB, 0xCD, 0xEF, 0x12, 0x34];
        let mut src = BitSource::at(&data, 3);
        // Position 3 means we skip the low 3 bits of 0xAB; remaining bits
        // of byte 0 are the high 5: 0xAB >> 3 = 0b10101 = 21.
        assert_eq!(src.read_bits(5).unwrap(), 0xAB >> 3);
        // Now byte-aligned at byte 1.
        assert_eq!(src.read_bits(8).unwrap(), 0xCD);
        assert_eq!(src.position(), 16);
    }

    #[test]
    fn unexpected_end_short_input() {
        let data = [0x55u8];
        let mut src = BitSource::at(&data, 0);
        // 5 bits available out of 8; asking for 16 must fail without
        // mutating the visible position.
        let before = src.position();
        assert!(src.read_bits(16).is_err());
        // Implementation may have buffered the byte into acc; position()
        // should still report the un-consumed bit offset.
        assert_eq!(src.position(), before);
        // The bits still readable byte-by-byte.
        assert_eq!(src.read_bits(8).unwrap(), 0x55);
        assert!(src.read_bit().is_err());
    }

    #[test]
    fn set_position_rolls_back_accumulator() {
        let data = [0xFFu8, 0x00, 0xAA, 0x55];
        let mut src = BitSource::at(&data, 0);
        let saved = src.position();
        assert_eq!(src.read_bits(12).unwrap(), 0x0FF);
        src.set_position(saved);
        // After rollback, re-reading must produce the same bits.
        assert_eq!(src.read_bits(8).unwrap(), 0xFF);
        assert_eq!(src.read_bits(8).unwrap(), 0x00);
    }

    #[test]
    fn align_to_byte_drops_partial() {
        let data = [0b1111_0000u8, 0b1010_1010];
        let mut src = BitSource::at(&data, 0);
        // Read 3 bits, then align to byte boundary, then read next byte.
        assert_eq!(src.read_bits(3).unwrap(), 0b000);
        src.align_to_byte();
        assert_eq!(src.position(), 8);
        assert_eq!(src.read_bits(8).unwrap(), 0b1010_1010);
    }
}
