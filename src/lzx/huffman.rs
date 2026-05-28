//! Canonical Huffman decoder sized for LZX trees.
//!
//! LZX writes its Huffman codes MSB-first, which matches the natural reading
//! direction of [`super::bitreader::BitReader`]. This is conceptually the
//! same as [`crate::huffman::CanonicalDecoder`] (used by deflate) but it
//! consumes bits from an MSB-first stream rather than reconstructing
//! MSB-first codes from an LSB-first one.
//!
//! Code lengths are capped at 16 bits per the LZX spec.

use crate::error::Error;

use super::bitreader::BitReader;

/// Fixed-capacity canonical Huffman decoder.
///
/// `N` is the alphabet size; for LZX trees it's MAIN_TREE_MAX (656),
/// NUM_SECONDARY_LENGTHS (249), PRETREE_NUM_ELEMENTS (20), or
/// ALIGNED_NUM_ELEMENTS (8).
#[derive(Debug, Clone)]
pub struct LzxHuffman<const N: usize> {
    counts: [u16; 17],
    /// Symbols in canonical order: length-1 first, then length-2, etc.
    symbols: [u16; N],
    first_code: [u32; 17],
    first_idx: [u16; 17],
    max_length: u8,
}

impl<const N: usize> LzxHuffman<N> {
    /// Build from `code_lengths`. The LZX LENGTH_TREE may be empty (every
    /// length is zero); we still return a decoder, but `decode` then returns
    /// `Err(InvalidHuffmanTree)` when used. Callers gate this with their own
    /// "was the tree expected to be empty?" check.
    pub fn from_lengths(code_lengths: &[u8]) -> Result<Self, Error> {
        assert!(code_lengths.len() <= N);

        let mut counts = [0u16; 17];
        let mut max_length: u8 = 0;
        for &len in code_lengths {
            if len > 16 {
                return Err(Error::InvalidHuffmanTree);
            }
            if len > 0 {
                counts[len as usize] += 1;
                if len > max_length {
                    max_length = len;
                }
            }
        }

        // Empty tree is acceptable for LENGTH_TREE / ALIGNED_TREE; allow it.
        if max_length == 0 {
            return Ok(Self {
                counts,
                symbols: [0u16; N],
                first_code: [0u32; 17],
                first_idx: [0u16; 17],
                max_length: 0,
            });
        }

        // Kraft inequality: Σ counts[l] · 2^(16-l) ≤ 2^16.
        let mut kraft: u32 = 0;
        for l in 1..=16u32 {
            kraft += (counts[l as usize] as u32) << (16 - l);
        }
        if kraft > (1 << 16) {
            return Err(Error::InvalidHuffmanTree);
        }
        // A code with exactly one symbol of length 1 (kraft == half) is OK;
        // anything that under-fills with multiple symbols isn't. The LZX
        // streams we accept have complete trees (kraft == 1<<16) except when
        // only one symbol is present — like deflate, we accept either.

        let mut first_code = [0u32; 17];
        let mut first_idx = [0u16; 17];
        let mut code: u32 = 0;
        let mut idx: u16 = 0;
        for l in 1..=16 {
            code <<= 1;
            first_code[l] = code;
            first_idx[l] = idx;
            code += counts[l] as u32;
            idx += counts[l];
        }

        let mut symbols = [0u16; N];
        let mut next = first_idx;
        for (sym, &len) in code_lengths.iter().enumerate() {
            if len > 0 {
                symbols[next[len as usize] as usize] = sym as u16;
                next[len as usize] += 1;
            }
        }

        Ok(Self {
            counts,
            symbols,
            first_code,
            first_idx,
            max_length,
        })
    }

    pub const fn is_empty(&self) -> bool {
        self.max_length == 0
    }

    /// Attempt to decode one symbol. Returns `Ok(Some(sym))` on success,
    /// `Ok(None)` if `reader` doesn't have enough bits yet (reader untouched),
    /// or `Err(InvalidHuffmanTree)` on a malformed code.
    pub fn decode(&self, reader: &mut BitReader) -> Result<Option<u16>, Error> {
        if self.max_length == 0 {
            return Err(Error::InvalidHuffmanTree);
        }

        let max = self.max_length as u32;
        if reader.bits_available() < max {
            // Not enough bits to guarantee a full decode even in the worst
            // case. We could still try if the symbol's actual length happens
            // to be shorter, but checking up-front simplifies the code path
            // and never costs more than one extra refill.
            return Ok(None);
        }

        // Read `max` bits in MSB-first order, then walk code lengths 1..=max
        // by stripping off the topmost bits one at a time.
        let lookahead = reader.peek(max);
        for length in 1..=max {
            // The first `length` MSB-first bits of `lookahead` (which is
            // right-justified at width `max`) are the top `length` bits of
            // `lookahead`, i.e. `lookahead >> (max - length)`.
            let code = lookahead >> (max - length);
            let count = self.counts[length as usize] as u32;
            if count > 0 {
                let first = self.first_code[length as usize];
                if code >= first && code < first + count {
                    let sym_idx = self.first_idx[length as usize] as u32 + (code - first);
                    reader.drop_bits(length);
                    return Ok(Some(self.symbols[sym_idx as usize]));
                }
            }
        }
        Err(Error::InvalidHuffmanTree)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_decoder_msb_walk() {
        // Code lengths [2, 1, 3, 3] →
        //   sym 0: code 10 (length 2)
        //   sym 1: code 0  (length 1)
        //   sym 2: code 110 (length 3)
        //   sym 3: code 111 (length 3)
        let dec = LzxHuffman::<4>::from_lengths(&[2, 1, 3, 3]).unwrap();

        // Encode the MSB-first stream "0 10 111" then drop into the bit reader
        // as little-endian 16-bit words. Pack as: 0|10|111 = 0b0_10_111 = bits
        // [0,1,0,1,1,1] MSB-first → high bits of a 16-bit word.
        // Combined into a 16-bit MSB-first word:
        //   bits: 0 1 0 1 1 1 0 0 0 0 0 0 0 0 0 0
        //   = 0b0101_1100_0000_0000 = 0x5C00
        // Wire bytes LE: 0x00, 0x5C
        let mut r = BitReader::new();
        r.feed(0x00);
        r.feed(0x5C);

        assert_eq!(dec.decode(&mut r).unwrap(), Some(1)); // "0"
        assert_eq!(dec.decode(&mut r).unwrap(), Some(0)); // "10"
        assert_eq!(dec.decode(&mut r).unwrap(), Some(3)); // "111"
    }

    #[test]
    fn empty_tree_rejects_decode() {
        let dec = LzxHuffman::<4>::from_lengths(&[0, 0, 0, 0]).unwrap();
        assert!(dec.is_empty());
        let mut r = BitReader::new();
        r.feed(0xFF);
        r.feed(0xFF);
        assert_eq!(dec.decode(&mut r), Err(Error::InvalidHuffmanTree));
    }

    #[test]
    fn invalid_lengths_rejected() {
        // Length > 16
        assert!(LzxHuffman::<4>::from_lengths(&[17, 0, 0, 0]).is_err());
        // Over-full Kraft inequality: two length-1 codes already saturate;
        // adding a third length-2 code overflows.
        assert!(LzxHuffman::<3>::from_lengths(&[1, 1, 2]).is_err());
    }
}
