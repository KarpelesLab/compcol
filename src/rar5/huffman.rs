//! Canonical Huffman decoder for RAR5.
//!
//! Code lengths are 0..=15 (RAR5 caps at 15 bits per code). A zero length
//! means the symbol is absent. We build a canonical code in the standard
//! MSB-first way: shorter codes get the smaller numerical values.
//!
//! The decoder walks lengths 1..=15 with a 16-bit lookahead from the
//! bit-reader and returns the symbol that matches.

use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;

use super::bits::BitBuf;

/// Primary-LUT width for the fast-path symbol lookup. Codes of length
/// ≤ `PRIMARY_BITS` resolve in O(1); longer codes fall back to the
/// per-length walk.
const PRIMARY_BITS: u32 = 9;
const PRIMARY_SIZE: usize = 1 << PRIMARY_BITS;

/// Packed (symbol, length) entry in the primary LUT. The low 11 bits hold
/// the symbol; the top 5 bits hold the code length. A length of 0 marks
/// "long code -- take the slow path".
const LUT_LEN_SHIFT: u32 = 11;
const LUT_SYM_MASK: u16 = (1 << LUT_LEN_SHIFT) - 1;

#[derive(Debug, Clone)]
pub struct Huffman {
    /// `counts[l]` = number of symbols with code-length `l`. `counts[0]` is
    /// unused.
    counts: [u16; 17],
    /// Symbols in canonical order (length 1 first, then length 2, etc.).
    symbols: Vec<u16>,
    /// First code at each length, left-justified to the maximum code length.
    first_code: [u32; 17],
    /// First index into `symbols[]` for the run at each length.
    first_idx: [u16; 17],
    /// Largest code length actually used (0 for an empty table).
    max_length: u8,
    /// Primary lookup table: indexed by the top `PRIMARY_BITS` MSB-first
    /// stream bits (peek16 >> (16 - PRIMARY_BITS)). Each slot holds a
    /// packed `(symbol, length)` for codes of length ≤ `PRIMARY_BITS`,
    /// or `0` to signal the slow path.
    lut: alloc::boxed::Box<[u16; PRIMARY_SIZE]>,
}

impl Huffman {
    /// Build from `code_lengths`. Lengths must each be 0..=15.
    pub fn from_lengths(code_lengths: &[u8]) -> Result<Self, Error> {
        let mut counts = [0u16; 17];
        let mut max_length: u8 = 0;
        for &len in code_lengths {
            if len > 15 {
                return Err(Error::InvalidHuffmanTree);
            }
            if len > 0 {
                counts[len as usize] += 1;
                if len > max_length {
                    max_length = len;
                }
            }
        }

        // Empty table is permitted (e.g. degenerate low-distance code with
        // no entries). It returns Err on decode if anyone tries to use it.
        if max_length == 0 {
            return Ok(Self {
                counts,
                symbols: Vec::new(),
                first_code: [0u32; 17],
                first_idx: [0u16; 17],
                max_length: 0,
                lut: alloc::boxed::Box::new([0u16; PRIMARY_SIZE]),
            });
        }

        // Kraft inequality, normalised to 2^15 since we cap at 15-bit codes.
        let mut kraft: u32 = 0;
        for l in 1..=15u32 {
            kraft = kraft.wrapping_add((counts[l as usize] as u32) << (15 - l));
        }
        if kraft > (1 << 15) {
            return Err(Error::InvalidHuffmanTree);
        }

        let mut first_code = [0u32; 17];
        let mut first_idx = [0u16; 17];
        let mut code: u32 = 0;
        let mut idx: u16 = 0;
        for l in 1..=15 {
            code <<= 1;
            first_code[l] = code;
            first_idx[l] = idx;
            code = code.wrapping_add(counts[l] as u32);
            idx = idx.wrapping_add(counts[l]);
        }

        let total: usize = counts[1..=15].iter().map(|&c| c as usize).sum();
        let mut symbols = vec![0u16; total];
        let mut next = first_idx;
        for (sym, &len) in code_lengths.iter().enumerate() {
            if len > 0 {
                symbols[next[len as usize] as usize] = sym as u16;
                next[len as usize] += 1;
            }
        }

        // Build the primary LUT. RAR5 reads MSB-first, so the top
        // PRIMARY_BITS bits of peek16 give the index directly. A code
        // value `c` of length `L ≤ PRIMARY_BITS` occupies the index
        // range `[c << (PRIMARY_BITS-L), (c+1) << (PRIMARY_BITS-L))`.
        let mut lut = alloc::boxed::Box::new([0u16; PRIMARY_SIZE]);
        let mut next_code = first_code;
        for (sym, &len) in code_lengths.iter().enumerate() {
            if len == 0 {
                continue;
            }
            let code = next_code[len as usize];
            next_code[len as usize] = next_code[len as usize].wrapping_add(1);
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

    pub const fn is_empty(&self) -> bool {
        self.max_length == 0
    }

    /// Decode one symbol from `br`, consuming as many bits as the code
    /// length requires.
    pub fn decode(&self, br: &mut BitBuf) -> Result<u16, Error> {
        if self.max_length == 0 {
            return Err(Error::InvalidHuffmanTree);
        }
        // peek16 always returns 16 bits even past end-of-block (zero-padded);
        // we still check `bits_remaining` against the *actual* code length
        // after we've identified the matching length so that a corrupted
        // table can't silently consume bits we don't have.
        let look = br.peek16() as u32;

        // Fast path: top PRIMARY_BITS of peek16 index the LUT. Codes ≤
        // PRIMARY_BITS resolve here; longer codes fall through.
        let idx = (look >> (16 - PRIMARY_BITS)) as usize;
        let entry = self.lut[idx];
        let len = (entry >> LUT_LEN_SHIFT) as u32;
        if len > 0 {
            if br.bits_remaining() < len {
                return Err(Error::UnexpectedEnd);
            }
            br.skip(len);
            return Ok(entry & LUT_SYM_MASK);
        }

        for length in 1..=self.max_length as u32 {
            let code = look >> (16 - length);
            let count = self.counts[length as usize] as u32;
            if count > 0 {
                let first = self.first_code[length as usize];
                if code >= first && code < first + count {
                    if br.bits_remaining() < length {
                        return Err(Error::UnexpectedEnd);
                    }
                    let sym_idx = self.first_idx[length as usize] as u32 + (code - first);
                    br.skip(length);
                    return Ok(self.symbols[sym_idx as usize]);
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
    fn build_and_decode_minimal_tree() {
        // 4 symbols with lengths [2, 1, 3, 3]:
        //   sym 1 → 0
        //   sym 0 → 10
        //   sym 2 → 110
        //   sym 3 → 111
        let huff = Huffman::from_lengths(&[2, 1, 3, 3]).unwrap();

        // bit stream "0 10 111 110" packed MSB-first =
        // 0_10_111_110 = 0b0101_1111_0... (need a full byte)
        // bits: 0,1,0,1,1,1,1,1 → 0b0101_1111 = 0x5F
        let mut br = BitBuf::new();
        br.reset(&[0x5F], 8);
        assert_eq!(huff.decode(&mut br).unwrap(), 1);
        assert_eq!(huff.decode(&mut br).unwrap(), 0);
        assert_eq!(huff.decode(&mut br).unwrap(), 3);
        // We've only consumed 6 bits so far, so the last 2 bits remain.
    }

    #[test]
    fn empty_table_rejects_decode() {
        let huff = Huffman::from_lengths(&[0, 0]).unwrap();
        let mut br = BitBuf::new();
        br.reset(&[0], 8);
        assert!(huff.decode(&mut br).is_err());
    }

    #[test]
    fn invalid_length_rejected() {
        assert!(Huffman::from_lengths(&[16, 0]).is_err());
        // Two length-1 codes already saturate; a third length-2 overflows.
        assert!(Huffman::from_lengths(&[1, 1, 2]).is_err());
    }
}
