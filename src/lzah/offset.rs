//! Static canonical prefix code for the high 6 bits of a match offset.
//!
//! StuffIt method 5 codes the top 6 bits of every 12-bit window offset with
//! a fixed 64-symbol canonical Huffman code (spec section 8.1). The code-
//! length table is derived from the length-count rule:
//!
//! ```text
//! length 3: 1 symbol  (0)
//! length 4: 3 symbols (1..3)
//! length 5: 8 symbols (4..11)
//! length 6: 12 symbols (12..23)
//! length 7: 24 symbols (24..47)
//! length 8: 16 symbols (48..63)
//! ```
//!
//! Codes are canonical, assigned shortest-first with the shortest code all
//! zeros (the standard "first_code per length" assignment). Decoding walks
//! the bitstream MSB-first, accumulating one bit per step and matching
//! against the canonical code ranges.

use super::bits::BitReader;
use crate::error::Error;

/// Per-symbol code lengths for symbols 0..63, derived from the count rule.
const fn code_lengths() -> [u8; 64] {
    let mut lens = [0u8; 64];
    let counts: [(u8, usize); 6] = [(3, 1), (4, 3), (5, 8), (6, 12), (7, 24), (8, 16)];
    let mut sym = 0usize;
    let mut ci = 0usize;
    while ci < counts.len() {
        let (len, count) = counts[ci];
        let mut k = 0usize;
        while k < count {
            lens[sym] = len;
            sym += 1;
            k += 1;
        }
        ci += 1;
    }
    lens
}

/// Canonical decode table: for each length 1..=8, the first canonical code at
/// that length and the symbol index that code maps to.
pub struct OffsetCode {
    /// `first_code[l]` = smallest canonical codeword of length `l`.
    first_code: [u32; 9],
    /// `first_sym[l]` = symbol assigned to `first_code[l]`.
    first_sym: [u16; 9],
    /// Number of symbols at each length.
    count: [u16; 9],
}

impl OffsetCode {
    pub fn new() -> Self {
        let lengths = code_lengths();
        let mut count = [0u16; 9];
        for &l in lengths.iter() {
            count[l as usize] += 1;
        }
        // Canonical first-code per length: shortest code is all zeros.
        let mut first_code = [0u32; 9];
        let mut first_sym = [0u16; 9];
        let mut code = 0u32;
        let mut sym_seen = 0u16;
        for l in 1..=8usize {
            first_code[l] = code;
            first_sym[l] = sym_seen;
            sym_seen += count[l];
            code = (code + count[l] as u32) << 1;
        }
        // `lengths` is consumed only to populate `count`; the canonical rank
        // equals the symbol index because lengths are non-decreasing across
        // symbols 0..63.
        let _ = lengths;
        Self {
            first_code,
            first_sym,
            count,
        }
    }

    /// Decode one offset-high value (0..63) from the bitstream.
    pub fn decode(&self, br: &mut BitReader<'_>) -> Result<u32, Error> {
        let mut code = 0u32;
        for l in 1..=8usize {
            code = (code << 1) | br.get_bit();
            if br.exhausted() {
                return Err(Error::UnexpectedEnd);
            }
            if self.count[l] != 0 {
                let first = self.first_code[l];
                let cnt = self.count[l] as u32;
                if code >= first && code < first + cnt {
                    // The canonical assignment walks symbols 0..63 in order
                    // with non-decreasing lengths, so the rank is the symbol.
                    return Ok(self.first_sym[l] as u32 + (code - first));
                }
            }
        }
        Err(Error::Corrupt)
    }
}
