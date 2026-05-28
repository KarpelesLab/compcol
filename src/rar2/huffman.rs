//! Canonical Huffman decoder for RAR 2.x.
//!
//! RAR 2.x uses an old-style canonical Huffman code where:
//! - Code lengths are bounded by 15 bits (the "pretree" of 19 symbols is
//!   itself bounded to 15 too, although in practice it never exceeds 4).
//! - The shortest code starts at all-zeros (`shortestCodeIsZeros:YES` in
//!   XADPrefixCode terminology). Codes are emitted MSB-first.
//! - Within a given length, symbols are ordered by their index in the
//!   length table (i.e. standard canonical order).
//!
//! A length table of all zeros is a valid (but trivially-empty) tree; the
//! decoder rejects any attempt to actually pull a symbol from it.
//!
//! The decoder uses a direct length-walk: peek up to MAX_BITS bits, then for
//! each length 1..=MAX_BITS check whether the top `length` bits fall inside
//! the canonical range for that length. This is `O(MAX_BITS)` per symbol but
//! avoids building a lookup table (kept simple — RAR2 is a slow archival
//! decoder anyway).

use crate::error::Error;

use super::bitreader::BitReader;

/// Maximum Huffman code length used by RAR2 streams (15 bits per
/// XADRAR20Handle.m).
pub const MAX_BITS: u32 = 15;

/// Canonical Huffman decoder over an alphabet of up to `N` symbols.
#[derive(Debug, Clone)]
pub struct Rar2Huffman<const N: usize> {
    /// Number of codes of each length, indexed 1..=MAX_BITS.
    counts: [u16; (MAX_BITS as usize) + 1],
    /// Symbols in canonical order: all length-1 syms first, then length-2, etc.
    symbols: [u16; N],
    /// First canonical code value for each length.
    first_code: [u32; (MAX_BITS as usize) + 1],
    /// First symbol-table index for each length.
    first_idx: [u16; (MAX_BITS as usize) + 1],
    max_length: u8,
    n_symbols: u16,
}

impl<const N: usize> Rar2Huffman<N> {
    /// Build a decoder from `code_lengths`. Each length must be 0..=MAX_BITS;
    /// `len == 0` means the symbol is absent.
    ///
    /// Empty trees (all-zero lengths) are accepted as a valid construction
    /// state but [`decode`](Self::decode) on an empty tree returns
    /// [`Error::InvalidHuffmanTree`].
    pub fn from_lengths(code_lengths: &[u8]) -> Result<Self, Error> {
        let n = code_lengths.len();
        assert!(n <= N);

        let mut counts = [0u16; (MAX_BITS as usize) + 1];
        let mut max_length: u8 = 0;
        for &len in code_lengths {
            if len as u32 > MAX_BITS {
                return Err(Error::InvalidHuffmanTree);
            }
            if len > 0 {
                counts[len as usize] += 1;
                if len > max_length {
                    max_length = len;
                }
            }
        }

        if max_length == 0 {
            return Ok(Self {
                counts,
                symbols: [0u16; N],
                first_code: [0u32; (MAX_BITS as usize) + 1],
                first_idx: [0u16; (MAX_BITS as usize) + 1],
                max_length: 0,
                n_symbols: n as u16,
            });
        }

        // Kraft inequality check, normalised against 2^MAX_BITS.
        let mut kraft: u64 = 0;
        for l in 1..=MAX_BITS {
            kraft += (counts[l as usize] as u64) << (MAX_BITS - l);
        }
        if kraft > (1u64 << MAX_BITS) {
            return Err(Error::InvalidHuffmanTree);
        }

        let mut first_code = [0u32; (MAX_BITS as usize) + 1];
        let mut first_idx = [0u16; (MAX_BITS as usize) + 1];
        let mut code: u32 = 0;
        let mut idx: u16 = 0;
        for l in 1..=(MAX_BITS as usize) {
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
            n_symbols: n as u16,
        })
    }

    #[allow(dead_code)]
    pub const fn is_empty(&self) -> bool {
        self.max_length == 0
    }

    /// Decode one symbol from the bit stream. Returns
    /// `Err(UnexpectedEnd)` if `input` runs out before a symbol can be
    /// resolved unambiguously, `Err(InvalidHuffmanTree)` on a malformed code.
    pub fn decode(&self, reader: &mut BitReader, input: &[u8]) -> Result<u16, Error> {
        if self.max_length == 0 {
            return Err(Error::InvalidHuffmanTree);
        }
        let max = self.max_length as u32;
        let (peeked, have) = reader.peek_up_to(max, input);

        // For each candidate length, see if the top `length` bits of `peeked`
        // (which is right-aligned to width `max`) fall inside the canonical
        // range. Because peek_up_to zeros out missing low bits, a length
        // that exceeds `have` would let us *accidentally* match a code whose
        // last bits we don't actually possess — guard with `length <= have`.
        for length in 1..=max {
            let count = self.counts[length as usize] as u32;
            if count == 0 {
                continue;
            }
            let code = peeked >> (max - length);
            let first = self.first_code[length as usize];
            if code >= first && code < first + count {
                if length > have {
                    // We *would* match at this length, but we don't have
                    // enough bits yet to commit. Anything shorter would have
                    // matched earlier, so we need more input.
                    return Err(Error::UnexpectedEnd);
                }
                let sym_idx = self.first_idx[length as usize] as u32 + (code - first);
                if sym_idx >= self.n_symbols as u32 {
                    return Err(Error::InvalidHuffmanTree);
                }
                reader.drop_bits(length);
                return Ok(self.symbols[sym_idx as usize]);
            }
        }
        if have < max {
            return Err(Error::UnexpectedEnd);
        }
        Err(Error::InvalidHuffmanTree)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_tree_roundtrip() {
        // Lengths [2, 1, 3, 3]:
        //   sym 1 → "0"
        //   sym 0 → "10"
        //   sym 2 → "110"
        //   sym 3 → "111"
        let h = Rar2Huffman::<4>::from_lengths(&[2, 1, 3, 3]).unwrap();
        // Bitstream "0 10 110 111" → 0_10_110_111_00000000 = 0b0101_1011_1100_0000 = 0x5BC0.
        // Byte 1: 0x5B, byte 2: 0xC0.
        let input = [0x5B, 0xC0];
        let mut r = BitReader::new();
        assert_eq!(h.decode(&mut r, &input).unwrap(), 1);
        assert_eq!(h.decode(&mut r, &input).unwrap(), 0);
        assert_eq!(h.decode(&mut r, &input).unwrap(), 2);
        assert_eq!(h.decode(&mut r, &input).unwrap(), 3);
    }

    #[test]
    fn empty_tree_rejects() {
        let h = Rar2Huffman::<4>::from_lengths(&[0, 0, 0, 0]).unwrap();
        assert!(h.is_empty());
        let mut r = BitReader::new();
        let input = [0xFF];
        assert!(matches!(
            h.decode(&mut r, &input),
            Err(Error::InvalidHuffmanTree)
        ));
    }

    #[test]
    fn over_long_code_rejected() {
        let mut lens = [0u8; 2];
        lens[0] = 16; // > MAX_BITS
        assert!(Rar2Huffman::<2>::from_lengths(&lens).is_err());
    }

    #[test]
    fn over_full_kraft_rejected() {
        // 1, 1, 2 → two length-1 codes already exhaust the budget; a third
        // length-2 code can't fit.
        assert!(Rar2Huffman::<3>::from_lengths(&[1, 1, 2]).is_err());
    }

    #[test]
    fn unexpected_end_when_bits_short() {
        // Lengths [3, 3, 2, 2, 2]:
        //   sym 2 → "00"
        //   sym 3 → "01"
        //   sym 4 → "10"
        //   sym 0 → "110"
        //   sym 1 → "111"
        let h = Rar2Huffman::<5>::from_lengths(&[3, 3, 2, 2, 2]).unwrap();
        // Empty input → first decode returns UnexpectedEnd.
        let input: [u8; 0] = [];
        let mut r = BitReader::new();
        assert!(matches!(
            h.decode(&mut r, &input),
            Err(Error::UnexpectedEnd)
        ));
    }

    #[test]
    fn single_symbol_tree() {
        // One length-1 symbol: encodes/decodes as a single "0" bit each time.
        let h = Rar2Huffman::<1>::from_lengths(&[1]).unwrap();
        let input = [0x00];
        let mut r = BitReader::new();
        assert_eq!(h.decode(&mut r, &input).unwrap(), 0);
    }
}
