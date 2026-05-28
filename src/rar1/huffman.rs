//! Canonical Huffman decoder for RAR1.
//!
//! All of RAR1's Huffman trees are **static** — they are pre-baked into the
//! algorithm and never transmitted. The wire format only carries the
//! decoded symbols. We still need a canonical-Huffman decoder so that, when
//! the static code-length tables are supplied, decoding follows the
//! ordinary "shortest-code-is-all-zeros" canonical layout that
//! `XADRAR15Handle.m` constructs with `shortestCodeIsZeros:YES` /
//! `forCodeWithHighBitFirst:length:`.
//!
//! Per the reverse-engineered notes there are:
//!
//! - Two **length** trees (`lengthcode1`, `lengthcode2`), 256-symbol
//!   alphabets, max code length 12 bits.
//! - Five **literal / offset / flag** trees (`huffmancode0`..`huffmancode4`),
//!   257-symbol alphabets, max code lengths 12, 12, 10, 10, 9 bits.
//! - Four **short-match selector** trees with 14 or 15 explicit entries.
//!
//! We don't ship the static tables themselves — they are the bulk of the
//! algorithm and we have no clean-room source for them — but [`StaticHuffman`]
//! is parameterised by alphabet size and accepts any caller-supplied
//! `code_lengths` slice, so tests can build trees with known shapes and an
//! eventual implementation can drop the tables in without further plumbing.
//!
//! This decoder shares its general shape with [`crate::lzx::huffman::LzxHuffman`]
//! (MSB-first canonical, walk lengths shortest-to-longest, drop bits only on
//! success). The two differ only in numerical caps: RAR1's longest code is
//! 12 bits whereas LZX allows up to 16.

// Building-block; consumer is the future RAR1 state machine.
#![allow(dead_code)]

use crate::error::Error;

use super::bits::BitReader;

/// Maximum Huffman code length seen anywhere in RAR1's static tables.
/// 12 is the limit for the long-match length / literal trees per the
/// reverse-engineered references; the shorter trees (10, 9, 4) all fit
/// comfortably under it.
pub const MAX_CODE_LENGTH: u32 = 12;

/// Fixed-capacity canonical-Huffman decoder.
///
/// `N` is the alphabet size:
/// - 256 for `lengthcode1` / `lengthcode2`
/// - 257 for `huffmancode0..4`
/// - up to 16 for the short-match selector trees
///
/// Code lengths are passed in as a slice and may be at most `N` long. A
/// length of 0 means "symbol is unused"; non-zero lengths must satisfy the
/// Kraft inequality.
#[derive(Debug, Clone)]
pub struct StaticHuffman<const N: usize> {
    /// `counts[l]` = number of symbols whose canonical code has length `l`.
    counts: [u16; MAX_CODE_LENGTH as usize + 1],
    /// First numeric code value used at each length.
    first_code: [u32; MAX_CODE_LENGTH as usize + 1],
    /// Index into `symbols` where length-`l` codes start.
    first_idx: [u16; MAX_CODE_LENGTH as usize + 1],
    /// Symbols in canonical order: all length-1 symbols first, then
    /// length-2, etc., each group in ascending symbol order.
    symbols: [u16; N],
    /// Longest code length actually present.
    max_length: u8,
}

impl<const N: usize> StaticHuffman<N> {
    /// Build a decoder from a slice of code lengths.
    ///
    /// The slice index is the symbol index; the value is the length in bits
    /// (0 = symbol unused, otherwise 1..=12). Returns
    /// `Err(InvalidHuffmanTree)` for lengths > 12 or Kraft-overflowing
    /// tables.
    pub fn from_lengths(code_lengths: &[u8]) -> Result<Self, Error> {
        assert!(code_lengths.len() <= N, "alphabet too large for N");

        let mut counts = [0u16; MAX_CODE_LENGTH as usize + 1];
        let mut max_length: u8 = 0;
        for &len in code_lengths {
            if len as u32 > MAX_CODE_LENGTH {
                return Err(Error::InvalidHuffmanTree);
            }
            if len > 0 {
                counts[len as usize] += 1;
                if len > max_length {
                    max_length = len;
                }
            }
        }

        // Empty tree allowed — same convention as the LZX decoder.
        if max_length == 0 {
            return Ok(Self {
                counts,
                first_code: [0u32; MAX_CODE_LENGTH as usize + 1],
                first_idx: [0u16; MAX_CODE_LENGTH as usize + 1],
                symbols: [0u16; N],
                max_length: 0,
            });
        }

        // Kraft inequality: Σ counts[l] · 2^(MAX-l) ≤ 2^MAX.
        let mut kraft: u32 = 0;
        for l in 1..=MAX_CODE_LENGTH {
            kraft += (counts[l as usize] as u32) << (MAX_CODE_LENGTH - l);
        }
        if kraft > (1 << MAX_CODE_LENGTH) {
            return Err(Error::InvalidHuffmanTree);
        }

        let mut first_code = [0u32; MAX_CODE_LENGTH as usize + 1];
        let mut first_idx = [0u16; MAX_CODE_LENGTH as usize + 1];
        let mut code: u32 = 0;
        let mut idx: u16 = 0;
        for l in 1..=MAX_CODE_LENGTH as usize {
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
            first_code,
            first_idx,
            symbols,
            max_length,
        })
    }

    pub const fn is_empty(&self) -> bool {
        self.max_length == 0
    }

    pub const fn max_length(&self) -> u8 {
        self.max_length
    }

    /// Attempt to decode one symbol.
    ///
    /// Returns:
    /// - `Ok(Some(sym))` on success (the reader has advanced past the code).
    /// - `Ok(None)` if `reader` doesn't yet have enough bits for the worst
    ///   case length (`max_length`). The reader is untouched, so the caller
    ///   can feed more bytes and retry.
    /// - `Err(InvalidHuffmanTree)` if the table is empty or the buffered
    ///   bits do not match any valid code at any length up to `max_length`.
    pub fn decode(&self, reader: &mut BitReader) -> Result<Option<u16>, Error> {
        if self.max_length == 0 {
            return Err(Error::InvalidHuffmanTree);
        }
        let max = self.max_length as u32;
        if reader.bits_available() < max {
            return Ok(None);
        }

        // Peek max bits MSB-first, then walk lengths 1..=max stripping off
        // the top bits one at a time and looking each candidate up against
        // the canonical first_code window.
        let lookahead = reader.peek(max);
        for length in 1..=max {
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
    fn canonical_msb_decode() {
        // Code lengths [2, 1, 3, 3] →
        //   sym 0 → "10"
        //   sym 1 → "0"
        //   sym 2 → "110"
        //   sym 3 → "111"
        let dec = StaticHuffman::<4>::from_lengths(&[2, 1, 3, 3]).unwrap();
        assert!(!dec.is_empty());
        assert_eq!(dec.max_length(), 3);

        // Pack the MSB-first stream "0 10 111" into a single byte:
        // bits: 0, 1, 0, 1, 1, 1, _, _ → 0b0101_1100 = 0x5C
        let mut r = BitReader::new();
        r.feed_byte(0x5C);
        assert_eq!(dec.decode(&mut r).unwrap(), Some(1)); // "0"  (1 bit)
        assert_eq!(dec.decode(&mut r).unwrap(), Some(0)); // "10" (2 bits)
        // 3 of 8 bits consumed; 5 remain. The next decode needs at least
        // `max_length` = 3 bits and we have 5, so the call returns Some.
        assert_eq!(r.bits_available(), 5);
        assert_eq!(dec.decode(&mut r).unwrap(), Some(3)); // "111" (3 bits)
        // 2 bits left of zero padding; those decode as "0" again (sym 1).
        assert_eq!(r.bits_available(), 2);
        // 2 < max_length (3), so the next decode returns None (need more bits).
        assert_eq!(dec.decode(&mut r).unwrap(), None);
    }

    #[test]
    fn underflow_returns_none() {
        // Two-symbol tree, longest code 2 bits.
        let dec = StaticHuffman::<3>::from_lengths(&[2, 2, 1]).unwrap();
        let mut r = BitReader::new();
        // Need at least 2 bits buffered; we only have 1.
        // Can't feed a single bit, so feed a byte and consume 7 of its 8.
        r.feed_byte(0b1000_0000);
        r.drop_bits(7);
        assert_eq!(r.bits_available(), 1);
        assert_eq!(dec.decode(&mut r).unwrap(), None);
        assert_eq!(r.bits_available(), 1, "reader must be untouched");
    }

    #[test]
    fn empty_tree_errors_on_decode() {
        let dec = StaticHuffman::<4>::from_lengths(&[0, 0, 0, 0]).unwrap();
        assert!(dec.is_empty());
        let mut r = BitReader::new();
        r.feed_byte(0xFF);
        assert!(matches!(dec.decode(&mut r), Err(Error::InvalidHuffmanTree)));
    }

    #[test]
    fn rejects_length_above_cap() {
        // 13 > MAX_CODE_LENGTH (12).
        assert!(StaticHuffman::<2>::from_lengths(&[13, 1]).is_err());
    }

    #[test]
    fn rejects_kraft_overflow() {
        // Two length-1 codes already saturate; a third length-2 makes it
        // over-full.
        assert!(StaticHuffman::<3>::from_lengths(&[1, 1, 2]).is_err());
    }

    #[test]
    fn accepts_kraft_underflow() {
        // Single length-1 code: Kraft = 0.5 ≤ 1. Decoder builds, but
        // decode() must error on bit patterns outside the assigned code.
        let dec = StaticHuffman::<2>::from_lengths(&[1, 0]).unwrap();
        // Drain the reader so we test a clean "1" bit.
        let mut r = BitReader::new();
        r.feed_byte(0xFF); // all-ones, top bit is 1
        // The only assigned code is "0" (symbol 0). A "1" bit doesn't
        // match anything at length 1, and max_length is 1 so the loop
        // can't extend → InvalidHuffmanTree.
        assert!(matches!(dec.decode(&mut r), Err(Error::InvalidHuffmanTree)));

        // And the "0" code itself still works.
        let mut r2 = BitReader::new();
        r2.feed_byte(0x00);
        assert_eq!(dec.decode(&mut r2).unwrap(), Some(0));
    }

    #[test]
    fn larger_alphabet_canonical() {
        // 12-symbol tree resembling the small Huffman trees used by
        // RAR1's short-match selectors (`shortmatchcode0..3`).
        //   4 symbols × len 3 + 8 symbols × len 4 → Kraft = 4·2 + 8·1 = 16. OK.
        // Canonical code assignment (shortest-code-is-zeros):
        //   sym 0  → "000"
        //   sym 1  → "001"
        //   sym 2  → "010"
        //   sym 3  → "011"
        //   sym 4  → "1000"
        //   sym 5  → "1001"
        //   sym 6  → "1010"
        //   sym 7  → "1011"
        //   sym 8  → "1100"
        //   sym 9  → "1101"
        //   sym 10 → "1110"
        //   sym 11 → "1111"
        let lens: [u8; 12] = [3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4];
        let dec = StaticHuffman::<12>::from_lengths(&lens).unwrap();
        assert_eq!(dec.max_length(), 4);
        // Feed a stream that decodes to sym 0 ("000"), sym 7 ("1011"),
        // sym 11 ("1111"), sym 1 ("001"), sym 5 ("1001"). Total 18 bits.
        //   000 1011 1111 001 1001 → 0001_0111 1110_0110 01.._.... (last 2 bits unused)
        // High byte: 0001_0111 = 0x17
        // Mid byte:  1110_0110 = 0xE6
        // Low byte (top 2 bits used, rest is padding): 0100_0000 = 0x40
        let mut r = BitReader::new();
        r.feed_byte(0x17);
        r.feed_byte(0xE6);
        r.feed_byte(0x40);
        assert_eq!(dec.decode(&mut r).unwrap(), Some(0));
        assert_eq!(dec.decode(&mut r).unwrap(), Some(7));
        assert_eq!(dec.decode(&mut r).unwrap(), Some(11));
        assert_eq!(dec.decode(&mut r).unwrap(), Some(1));
        assert_eq!(dec.decode(&mut r).unwrap(), Some(5));
    }
}
