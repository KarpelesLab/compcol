//! Canonical Huffman decoder for RAR 3.x trees.
//!
//! RAR3 uses canonical Huffman codes with a maximum length of 15 bits. There
//! are five trees in play:
//!   - the 20-symbol "precode" used to encode the lengths of the other four,
//!   - the 299-symbol main code,
//!   - the 60-symbol offset code,
//!   - the 17-symbol low-offset code,
//!   - the 28-symbol length code.
//!
//! The codec uses MSB-first bit reading (see [`super::bits::BitReader`]),
//! which matches the natural reading direction of canonical codes.
//!
//! The implementation matches the canonical-decoder shape used elsewhere in
//! this crate (see `lzx/huffman.rs`, `huffman.rs` for deflate).

use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;

use super::bits::BitReader;

const MAX_CODE_LEN: u8 = 15;

/// Primary-LUT width for the fast-path symbol lookup. Codes of length
/// ≤ `PRIMARY_BITS` resolve in O(1); longer codes fall back to the
/// per-length walk.
const PRIMARY_BITS: u32 = 9;
const PRIMARY_SIZE: usize = 1 << PRIMARY_BITS;

/// Packed (symbol, length) entry in the primary LUT. The low 11 bits hold
/// the symbol (rar3 main alphabet is 299 symbols, well under 2^11) and the
/// top 5 bits hold the code length. A length of 0 marks "long code -- take
/// the slow path".
const LUT_LEN_SHIFT: u32 = 11;
const LUT_SYM_MASK: u16 = (1 << LUT_LEN_SHIFT) - 1;

/// Canonical Huffman decoder over an alphabet of up to `cap` symbols.
#[derive(Debug, Clone)]
pub struct Huffman {
    counts: [u16; (MAX_CODE_LEN as usize) + 1],
    symbols: Vec<u16>,
    first_code: [u32; (MAX_CODE_LEN as usize) + 1],
    first_idx: [u16; (MAX_CODE_LEN as usize) + 1],
    max_length: u8,
    /// Primary lookup table: indexed by the next `PRIMARY_BITS` MSB-first
    /// stream bits. Each slot holds a packed `(symbol, length)` for codes
    /// of length ≤ `PRIMARY_BITS`, or `0` to signal the slow path.
    lut: alloc::boxed::Box<[u16; PRIMARY_SIZE]>,
}

impl Huffman {
    /// Build a decoder from a length-per-symbol array. Lengths of 0 mean
    /// the symbol does not appear in the code. Lengths > 15 are rejected.
    pub fn from_lengths(lengths: &[u8]) -> Result<Self, Error> {
        let mut counts = [0u16; (MAX_CODE_LEN as usize) + 1];
        let mut max_length: u8 = 0;
        for &len in lengths {
            if len > MAX_CODE_LEN {
                return Err(Error::InvalidHuffmanTree);
            }
            if len > 0 {
                counts[len as usize] += 1;
                if len > max_length {
                    max_length = len;
                }
            }
        }

        let symbols_cap = lengths.len();

        if max_length == 0 {
            // Empty tree: only the precode might legitimately be empty if no
            // input at all; main/offset trees being empty in real RAR3
            // streams is a decode error caught on first use.
            return Ok(Self {
                counts,
                symbols: vec![0u16; symbols_cap],
                first_code: [0u32; (MAX_CODE_LEN as usize) + 1],
                first_idx: [0u16; (MAX_CODE_LEN as usize) + 1],
                max_length: 0,
                lut: alloc::boxed::Box::new([0u16; PRIMARY_SIZE]),
            });
        }

        // Kraft inequality check.
        let mut kraft: u32 = 0;
        for l in 1..=(MAX_CODE_LEN as u32) {
            kraft += (counts[l as usize] as u32) << (MAX_CODE_LEN as u32 - l);
        }
        if kraft > (1u32 << MAX_CODE_LEN) {
            return Err(Error::InvalidHuffmanTree);
        }

        let mut first_code = [0u32; (MAX_CODE_LEN as usize) + 1];
        let mut first_idx = [0u16; (MAX_CODE_LEN as usize) + 1];
        let mut code: u32 = 0;
        let mut idx: u16 = 0;
        for l in 1..=(MAX_CODE_LEN as usize) {
            code <<= 1;
            first_code[l] = code;
            first_idx[l] = idx;
            code += counts[l] as u32;
            idx += counts[l];
        }

        let mut symbols = vec![0u16; symbols_cap];
        let mut next = first_idx;
        for (sym, &len) in lengths.iter().enumerate() {
            if len > 0 {
                let slot = next[len as usize] as usize;
                symbols[slot] = sym as u16;
                next[len as usize] += 1;
            }
        }

        // Build the primary LUT. RAR3 consumes MSB-first, so the top
        // `PRIMARY_BITS` bits of the accumulator give the index directly.
        // A code value `c` of length `L ≤ PRIMARY_BITS` occupies the
        // index range `[c << (PRIMARY_BITS-L), (c+1) << (PRIMARY_BITS-L))`.
        let mut lut = alloc::boxed::Box::new([0u16; PRIMARY_SIZE]);
        let mut next_code = first_code;
        for (sym, &len) in lengths.iter().enumerate() {
            if len == 0 {
                continue;
            }
            let code = next_code[len as usize];
            next_code[len as usize] += 1;
            if (len as u32) > PRIMARY_BITS {
                continue;
            }
            let shift = PRIMARY_BITS - len as u32;
            let start = (code << shift) as usize;
            let end = start + (1usize << shift);
            let entry = (sym as u16) | ((len as u16) << LUT_LEN_SHIFT);
            for slot in lut.iter_mut().take(end).skip(start) {
                *slot = entry;
            }
        }

        Ok(Self {
            counts,
            symbols,
            first_code,
            first_idx,
            max_length,
            lut,
        })
    }

    /// Decode one symbol from the bit reader.
    pub fn decode(&self, reader: &mut BitReader) -> Result<u16, Error> {
        if self.max_length == 0 {
            return Err(Error::InvalidHuffmanTree);
        }
        let max = self.max_length as u32;
        // Slow-path scan lower bound. A LUT miss below (peek succeeded but no
        // code ≤ PRIMARY_BITS matched) proves the code is longer than
        // PRIMARY_BITS, so the canonical scan can skip lengths 1..=PRIMARY_BITS
        // entirely. It stays 1 only when the fast-path peek itself failed
        // (stream near end), where a short code may still be valid.
        let mut min_len = 1u32;

        // Fast path: when we can peek PRIMARY_BITS bits, a single LUT
        // lookup resolves any code of length ≤ PRIMARY_BITS.
        if let Ok(idx) = reader.peek(PRIMARY_BITS) {
            let entry = self.lut[idx as usize];
            let len = (entry >> LUT_LEN_SHIFT) as u32;
            if len > 0 {
                // `peek(PRIMARY_BITS)` succeeded and `len <= PRIMARY_BITS`, so
                // the bits are buffered — consume without re-checking.
                reader.consume(len);
                return Ok(entry & LUT_SYM_MASK);
            }
            // Long code (> PRIMARY_BITS) -- fall through to the slow path.
            min_len = PRIMARY_BITS + 1;
        }

        // Peek `max` bits; if not enough, peek the remaining smaller widths
        // one at a time. For RAR3 trees this is unlikely to matter -- most
        // codes fit in the buffer easily.
        let lookahead = self.peek_padded(reader, max)?;
        for length in min_len..=max {
            let code = lookahead >> (max - length);
            let count = self.counts[length as usize] as u32;
            if count > 0 {
                let first = self.first_code[length as usize];
                if code >= first && code < first + count {
                    let slot = self.first_idx[length as usize] as u32 + (code - first);
                    if (slot as usize) >= self.symbols.len() {
                        return Err(Error::InvalidHuffmanTree);
                    }
                    reader.drop_bits(length)?;
                    return Ok(self.symbols[slot as usize]);
                }
            }
        }
        Err(Error::InvalidHuffmanTree)
    }

    /// Read up to `n` bits, padding with zeros if the stream is short. This is
    /// only used to look at potential codes; the caller consumes the actual
    /// length once the symbol is identified.
    fn peek_padded(&self, reader: &mut BitReader, n: u32) -> Result<u32, Error> {
        match reader.peek(n) {
            Ok(v) => Ok(v),
            Err(_) => {
                // Try smaller widths until we can satisfy at least one. For a
                // truncated stream this still lets the shortest-length codes
                // (length 1..k) be matched. If even 1 bit isn't available,
                // surface UnexpectedEnd.
                let mut try_n = n;
                while try_n > 0 {
                    try_n -= 1;
                    if let Ok(v) = reader.peek(try_n) {
                        return Ok(v << (n - try_n));
                    }
                }
                Err(Error::UnexpectedEnd)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;

    #[test]
    fn round_trip_simple_tree() {
        // Lengths [2, 1, 3, 3]:
        //   sym 0: code 10  (length 2)
        //   sym 1: code 0   (length 1)
        //   sym 2: code 110 (length 3)
        //   sym 3: code 111 (length 3)
        let dec = Huffman::from_lengths(&[2, 1, 3, 3]).unwrap();
        let mut r = BitReader::new();
        // Stream "0 10 111 110" packs MSB-first into:
        //   bits: 0 1 0 1 1 1 1 1 0
        //   pad to 16 bits: 0101_1111_1000_0000 → wait that puts a 1 in the
        //   9th slot. We actually want 0 in the 9th slot (last bit of code
        //   110 for sym 2). The correct packing is 0101_1111_0000_0000 = 0x5F00.
        r.feed_slice(&[0x5F, 0x00]);
        assert_eq!(dec.decode(&mut r).unwrap(), 1);
        assert_eq!(dec.decode(&mut r).unwrap(), 0);
        assert_eq!(dec.decode(&mut r).unwrap(), 3);
        assert_eq!(dec.decode(&mut r).unwrap(), 2);
    }

    #[test]
    fn invalid_lengths_rejected() {
        assert!(Huffman::from_lengths(&[16, 0, 0, 0]).is_err());
        // [1, 1, 2] over-fills (Kraft sum exceeds 1<<15).
        assert!(Huffman::from_lengths(&[1, 1, 2]).is_err());
    }

    #[test]
    fn empty_tree_rejects_decode() {
        let dec = Huffman::from_lengths(&[0, 0, 0, 0]).unwrap();
        let mut r = BitReader::new();
        r.feed_slice(&[0xFF]);
        assert!(matches!(dec.decode(&mut r), Err(Error::InvalidHuffmanTree)));
    }
}
