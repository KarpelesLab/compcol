//! Canonical, Kraft-validated Huffman decoder.
//!
//! StuffIt method 13 partitions its symbol stream into Huffman-coded
//! literal / length / distance alphabets (the classic LZ+Huffman shape).
//! The exact alphabet sizes and code-length transmission are part of the
//! undocumented format, but the *decoding* machinery is the ordinary
//! canonical Huffman scheme used by DEFLATE, LZX, RAR, etc. — "shortest
//! code is all-zeros", codes assigned shortest-to-longest in ascending
//! symbol order.
//!
//! This decoder is parameterised by alphabet size (`N`) so the same type
//! covers whatever alphabets the eventual state machine needs. It is built
//! from a slice of per-symbol code lengths (0 = unused) and **validates
//! the Kraft inequality**: over-full tables (which would otherwise let a
//! crafted stream index past the symbol array) are rejected up front with
//! [`Error::InvalidHuffmanTree`]. No `unsafe`; no panic reachable from any
//! input.
//!
//! Shares its shape with [`crate::rar1::huffman`] and
//! [`crate::lzx::huffman`].

// Building block; the consumer is a future method-13 state machine.
#![allow(dead_code)]

use crate::error::Error;

use super::bits::BitReader;

/// Maximum supported Huffman code length, in bits. Generous upper bound:
/// canonical LZ+Huffman alphabets of this era cap well under 16, and any
/// length above this is rejected as an invalid tree.
pub const MAX_CODE_LENGTH: u32 = 16;

/// Fixed-capacity canonical-Huffman decoder over an alphabet of size `N`.
///
/// Code lengths are passed in as a slice (index = symbol, value = length
/// in bits, 0 = unused). The slice may be at most `N` long. Non-zero
/// lengths must satisfy the Kraft inequality.
#[derive(Debug, Clone)]
pub struct Huffman<const N: usize> {
    /// `counts[l]` = number of symbols whose canonical code has length `l`.
    counts: [u16; MAX_CODE_LENGTH as usize + 1],
    /// First numeric code value used at each length.
    first_code: [u32; MAX_CODE_LENGTH as usize + 1],
    /// Index into `symbols` where length-`l` codes start.
    first_idx: [u16; MAX_CODE_LENGTH as usize + 1],
    /// Symbols in canonical order.
    symbols: [u16; N],
    /// Longest code length actually present (0 = empty tree).
    max_length: u8,
}

impl<const N: usize> Huffman<N> {
    /// Build a decoder from a slice of code lengths.
    ///
    /// Returns `Err(InvalidHuffmanTree)` if any length exceeds
    /// [`MAX_CODE_LENGTH`], if the slice is longer than `N`, or if the
    /// lengths over-fill the code space (Kraft inequality violated). An
    /// all-zero (empty) table is accepted and yields an empty tree whose
    /// [`decode`](Huffman::decode) always errors.
    pub fn from_lengths(code_lengths: &[u8]) -> Result<Self, Error> {
        // Reject rather than panic: a crafted header could declare more
        // symbols than the alphabet holds.
        if code_lengths.len() > N {
            return Err(Error::InvalidHuffmanTree);
        }

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

        // Empty tree allowed.
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
    /// - `Ok(None)` if `reader` doesn't yet have enough bits for the
    ///   worst-case length. The reader is untouched; feed more bytes and
    ///   retry.
    /// - `Err(InvalidHuffmanTree)` if the table is empty or the buffered
    ///   bits match no valid code.
    pub fn decode(&self, reader: &mut BitReader) -> Result<Option<u16>, Error> {
        if self.max_length == 0 {
            return Err(Error::InvalidHuffmanTree);
        }
        let max = self.max_length as u32;
        if reader.bits_available() < max {
            return Ok(None);
        }

        let lookahead = reader.peek(max);
        for length in 1..=max {
            let code = lookahead >> (max - length);
            let count = self.counts[length as usize] as u32;
            if count > 0 {
                let first = self.first_code[length as usize];
                if code >= first && code < first + count {
                    let sym_idx = self.first_idx[length as usize] as u32 + (code - first);
                    reader.drop_bits(length);
                    // `sym_idx` is in-range by construction (Kraft-validated,
                    // counts sum to the number of assigned symbols ≤ N).
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
        // lengths [2,1,3,3] → 0:"10" 1:"0" 2:"110" 3:"111"
        let dec = Huffman::<4>::from_lengths(&[2, 1, 3, 3]).unwrap();
        assert!(!dec.is_empty());
        assert_eq!(dec.max_length(), 3);
        // stream "0 10 111" → 0b0101_1100 = 0x5C
        let mut r = BitReader::new();
        r.feed_byte(0x5C);
        assert_eq!(dec.decode(&mut r).unwrap(), Some(1));
        assert_eq!(dec.decode(&mut r).unwrap(), Some(0));
        assert_eq!(r.bits_available(), 5);
        assert_eq!(dec.decode(&mut r).unwrap(), Some(3));
        assert_eq!(r.bits_available(), 2);
        assert_eq!(dec.decode(&mut r).unwrap(), None);
    }

    #[test]
    fn underflow_returns_none_untouched() {
        let dec = Huffman::<3>::from_lengths(&[2, 2, 1]).unwrap();
        let mut r = BitReader::new();
        r.feed_byte(0b1000_0000);
        r.drop_bits(7);
        assert_eq!(r.bits_available(), 1);
        assert_eq!(dec.decode(&mut r).unwrap(), None);
        assert_eq!(r.bits_available(), 1, "reader must be untouched");
    }

    #[test]
    fn empty_tree_errors_on_decode() {
        let dec = Huffman::<4>::from_lengths(&[0, 0, 0, 0]).unwrap();
        assert!(dec.is_empty());
        let mut r = BitReader::new();
        r.feed_byte(0xFF);
        assert!(matches!(dec.decode(&mut r), Err(Error::InvalidHuffmanTree)));
    }

    #[test]
    fn rejects_length_above_cap() {
        assert!(matches!(
            Huffman::<2>::from_lengths(&[17, 1]),
            Err(Error::InvalidHuffmanTree)
        ));
    }

    #[test]
    fn rejects_kraft_overflow() {
        // Two length-1 codes saturate; a third length-2 over-fills.
        assert!(matches!(
            Huffman::<3>::from_lengths(&[1, 1, 2]),
            Err(Error::InvalidHuffmanTree)
        ));
    }

    #[test]
    fn rejects_too_many_symbols() {
        // 5 lengths for an alphabet of 4.
        assert!(matches!(
            Huffman::<4>::from_lengths(&[1, 2, 3, 4, 4]),
            Err(Error::InvalidHuffmanTree)
        ));
    }

    #[test]
    fn accepts_kraft_underflow_but_rejects_unassigned_pattern() {
        let dec = Huffman::<2>::from_lengths(&[1, 0]).unwrap();
        let mut r = BitReader::new();
        r.feed_byte(0xFF); // top bit 1 — no assigned length-1 "1" code
        assert!(matches!(dec.decode(&mut r), Err(Error::InvalidHuffmanTree)));
        let mut r2 = BitReader::new();
        r2.feed_byte(0x00);
        assert_eq!(dec.decode(&mut r2).unwrap(), Some(0));
    }

    #[test]
    fn larger_alphabet_canonical() {
        // 4×len3 + 8×len4 → Kraft = 4·2 + 8·1 = 16 (full). OK.
        let lens: [u8; 12] = [3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4];
        let dec = Huffman::<12>::from_lengths(&lens).unwrap();
        assert_eq!(dec.max_length(), 4);
        // 000 1011 1111 001 1001 → 0x17 0xE6 0x40
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
