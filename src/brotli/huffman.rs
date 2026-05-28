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

        Ok(Self {
            counts,
            symbols,
            first_code,
            first_idx,
            max_length,
            single_symbol: None,
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

/// Synchronous bit source that the synchronous Huffman decoder reads
/// from. Wraps a borrowed byte slice plus a starting bit offset and
/// exposes single-bit and multi-bit reads.
///
/// All bit ordering is LSB-first within bytes (same as deflate).
#[derive(Debug)]
pub(crate) struct BitSource<'a> {
    data: &'a [u8],
    /// Absolute bit offset into `data`. Reading past `data.len() * 8`
    /// yields `Error::UnexpectedEnd`.
    pos: usize,
}

impl<'a> BitSource<'a> {
    /// Construct from an existing slice and a starting bit position.
    pub(crate) fn at(data: &'a [u8], pos: usize) -> Self {
        Self { data, pos }
    }

    pub(crate) fn position(&self) -> usize {
        self.pos
    }

    pub(crate) fn set_position(&mut self, p: usize) {
        self.pos = p;
    }

    /// Remaining bits available.
    pub(crate) fn remaining(&self) -> usize {
        self.data.len() * 8 - self.pos
    }

    pub(crate) fn read_bit(&mut self) -> Result<u32, Error> {
        if self.pos >= self.data.len() * 8 {
            return Err(Error::UnexpectedEnd);
        }
        let byte = self.data[self.pos >> 3];
        let bit = (byte >> (self.pos & 7)) & 1;
        self.pos += 1;
        Ok(bit as u32)
    }

    /// Read `n` bits (0..=32) as a little-endian integer.
    pub(crate) fn read_bits(&mut self, n: u32) -> Result<u32, Error> {
        debug_assert!(n <= 32);
        if n == 0 {
            return Ok(0);
        }
        if self.remaining() < n as usize {
            return Err(Error::UnexpectedEnd);
        }
        let mut acc: u32 = 0;
        let mut got: u32 = 0;
        while got < n {
            let byte_pos = self.pos >> 3;
            let bit_off = (self.pos & 7) as u32;
            let take = (8 - bit_off).min(n - got);
            let mask: u32 = if take == 32 {
                u32::MAX
            } else {
                (1u32 << take) - 1
            };
            let chunk = ((self.data[byte_pos] as u32) >> bit_off) & mask;
            acc |= chunk << got;
            got += take;
            self.pos += take as usize;
        }
        Ok(acc)
    }

    /// Align the bit position up to the next byte boundary.
    pub(crate) fn align_to_byte(&mut self) {
        let r = self.pos & 7;
        if r != 0 {
            self.pos += 8 - r;
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
}
