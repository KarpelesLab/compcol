//! Canonical Huffman tables.
//!
//! - [`CanonicalDecoder`] decodes one symbol per call by walking codes from
//!   length 1 upward against the bit reader. Slow per-symbol (~3× a lookup
//!   table) but small, allocation-free, easy to verify, and streaming-safe:
//!   if the reader runs out of bits mid-symbol the call returns
//!   `Ok(None)` and the reader is left unchanged.
//!
//! - [`length_limited_huffman`] computes optimal code lengths bounded by a
//!   maximum length, using the Larmore–Hirschberg package-merge algorithm.
//!   Required by the deflate encoder because RFC 1951 caps code lengths at
//!   15 (and the code-lengths-code at 7).
//!
//! - [`canonical_codes_from_lengths`] turns a code-length array into the
//!   actual MSB-first canonical code values per RFC 1951 §3.2.2. The deflate
//!   encoder bit-reverses each code before writing because the bit stream
//!   is LSB-first.

use crate::bits::BitReader;
use crate::error::Error;

/// Primary-LUT width for the fast-path symbol lookup. Codes of length
/// ≤ `PRIMARY_BITS` resolve in O(1); longer codes fall back to the
/// per-bit walk. 9 matches zlib's `inflate_fast` and covers the vast
/// majority of literals in practice.
const PRIMARY_BITS: u32 = 9;
const PRIMARY_SIZE: usize = 1 << PRIMARY_BITS;

/// Packed (symbol, length) entry in the primary LUT. The low 12 bits hold
/// the symbol (deflate symbols fit in 9 bits, so 12 is plenty) and the
/// top 4 bits hold the code length. A length of 0 marks "long code —
/// take the slow path".
const LUT_LEN_SHIFT: u32 = 12;
const LUT_SYM_MASK: u16 = (1 << LUT_LEN_SHIFT) - 1;

/// Try to decode one symbol from `reader`.
///
/// Returns `Ok(Some(symbol))` on success, `Ok(None)` if the reader doesn't
/// have enough bits yet (in which case it is left unchanged), or an error
/// if the bits don't match any valid code in this table.
#[derive(Debug, Clone)]
pub struct CanonicalDecoder<const N: usize> {
    /// `counts[l]` = number of symbols whose code is exactly `l` bits.
    counts: [u16; 16],
    /// Symbols in canonical order: all length-1 symbols (ascending), then
    /// length-2, etc.
    symbols: [u16; N],
    /// First numeric code value used at each length.
    first_code: [u32; 16],
    /// Index into [`Self::symbols`] where length-`l` codes start.
    first_idx: [u16; 16],
    /// Longest code length actually present; 0 if no symbols.
    max_length: u8,
    /// Primary lookup table: indexed by the next `PRIMARY_BITS` LSB-first
    /// stream bits. Each slot holds a packed `(symbol, length)` for codes
    /// of length ≤ `PRIMARY_BITS`, or `0` to signal the slow path.
    lut: [u16; PRIMARY_SIZE],
}

impl<const N: usize> CanonicalDecoder<N> {
    /// Build a decoder from `code_lengths` per RFC 1951 §3.2.2.
    ///
    /// Rejects code lengths > 15 (deflate cap) and tables that violate
    /// the Kraft inequality.
    pub fn from_lengths(code_lengths: &[u8]) -> Result<Self, Error> {
        assert!(code_lengths.len() <= N);

        let mut counts = [0u16; 16];
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

        // Kraft inequality: Σ counts[l] / 2^l ≤ 1.
        // Equivalent integer test: Σ counts[l] · 2^(15-l) ≤ 2^15.
        let mut kraft: u32 = 0;
        for l in 1..=15u32 {
            kraft += (counts[l as usize] as u32) << (15 - l);
        }
        if kraft > (1 << 15) {
            return Err(Error::InvalidHuffmanTree);
        }

        let mut first_code = [0u32; 16];
        let mut first_idx = [0u16; 16];
        let mut code: u32 = 0;
        let mut idx: u16 = 0;
        for l in 1..=15 {
            code <<= 1;
            first_code[l] = code;
            first_idx[l] = idx;
            code += counts[l] as u32;
            idx += counts[l];
        }

        // Place each symbol at its canonical slot.
        let mut symbols = [0u16; N];
        let mut next = first_idx;
        for (sym, &len) in code_lengths.iter().enumerate() {
            if len > 0 {
                symbols[next[len as usize] as usize] = sym as u16;
                next[len as usize] += 1;
            }
        }

        // Build the primary LUT. For each symbol whose code length is
        // ≤ PRIMARY_BITS, compute its LSB-first stream representation
        // (= bit-reverse of the canonical MSB-first code value) and
        // populate every entry whose low `len` bits match.
        let mut lut = [0u16; PRIMARY_SIZE];
        if max_length > 0 {
            // Same recurrence as `canonical_codes_from_lengths`: the
            // first code at length `l` is `(first_at_l-1 + count[l-1]) << 1`.
            let mut next_code = [0u32; 16];
            let mut acc: u32 = 0;
            for l in 1..=15usize {
                acc = (acc + counts[l - 1] as u32) << 1;
                next_code[l] = acc;
            }
            for (sym, &len) in code_lengths.iter().enumerate() {
                if len == 0 {
                    continue;
                }
                let code = next_code[len as usize];
                next_code[len as usize] += 1;
                if (len as u32) > PRIMARY_BITS {
                    continue;
                }
                let reversed = reverse_bits_lo(code, len as u32);
                let entry = (sym as u16) | ((len as u16) << LUT_LEN_SHIFT);
                let stride = 1usize << len;
                let mut slot = reversed as usize;
                while slot < PRIMARY_SIZE {
                    lut[slot] = entry;
                    slot += stride;
                }
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

    /// Try to decode the next symbol. See struct docs for streaming semantics.
    pub fn decode(&self, reader: &mut BitReader) -> Result<Option<u16>, Error> {
        if self.max_length == 0 {
            // No symbols defined; any input is invalid.
            return Err(Error::InvalidHuffmanTree);
        }

        let available = reader.bits_available();
        let max = self.max_length as u32;

        // Fast path: if we have ≥ PRIMARY_BITS bits buffered, one peek +
        // one table lookup resolves any code of length ≤ PRIMARY_BITS.
        if available >= PRIMARY_BITS {
            let idx = reader.peek(PRIMARY_BITS) as usize;
            let entry = self.lut[idx];
            let len = (entry >> LUT_LEN_SHIFT) as u32;
            if len > 0 {
                reader.drop_bits(len);
                return Ok(Some(entry & LUT_SYM_MASK));
            }
            // Long code (>PRIMARY_BITS) — fall through to the slow path.
        }

        // Slow path: walk lengths one bit at a time. Used for codes
        // longer than PRIMARY_BITS and during the tail of a stream where
        // fewer than PRIMARY_BITS bits are buffered.
        let mut code: u32 = 0;
        for length in 1..=max {
            if length > available {
                // Not enough bits in the accumulator yet. Reader untouched.
                return Ok(None);
            }
            // The bit at position (length-1) in the LSB-first accumulator is
            // the most-recently-fed bit. Because Huffman codes are written
            // MSB-first into the LSB-first stream, that bit is the next code
            // bit in MSB order — append it as the new LSB of `code`.
            let bit = ((reader.peek(length) >> (length - 1)) & 1) as u32;
            code = (code << 1) | bit;

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

/// Reverse the lowest `n` bits of `v`. Used at table-build time so the
/// LUT can be indexed directly by the next `n` LSB-first stream bits.
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

// ─── encoder side: length-limited Huffman + canonical code generation ───
#[cfg(feature = "alloc")]
use alloc::vec;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// Compute optimal code lengths bounded by `max_length` for the given
/// frequency vector via Larmore–Hirschberg package-merge.
///
/// `out[i]` is `0` iff `freqs[i] == 0`; otherwise `1 ≤ out[i] ≤ max_length`.
/// The returned codes form a valid prefix code (Kraft equality / inequality
/// per the number of symbols).
///
/// Panics if `max_length == 0` or `max_length > 15`, or if the alphabet has
/// more symbols than can fit in `max_length` bits (`freqs.len() > 1 << max_length`).
// Pool element used by `length_limited_huffman`. Kept module-private.
#[cfg(feature = "alloc")]
#[derive(Clone, Copy)]
enum PoolKind {
    Coin(u16),
    Pair(u32, u32),
}
#[cfg(feature = "alloc")]
struct PoolElement {
    cost: u64,
    kind: PoolKind,
}

#[cfg(feature = "alloc")]
pub fn length_limited_huffman(freqs: &[u32], max_length: u8) -> Vec<u8> {
    assert!(
        max_length > 0 && max_length <= 15,
        "max_length must be 1..=15"
    );

    let mut out = vec![0u8; freqs.len()];

    // Collect nonzero coins, sorted ascending by frequency.
    let mut coins: Vec<(u32, u16)> = freqs
        .iter()
        .enumerate()
        .filter_map(|(i, &f)| if f > 0 { Some((f, i as u16)) } else { None })
        .collect();
    let n = coins.len();
    if n == 0 {
        return out;
    }
    if n == 1 {
        // Single symbol — RFC 1951 implies a code length of 1 (the other
        // 1-bit code value is unused). The caller normally avoids this case
        // by inserting a sentinel symbol.
        out[coins[0].1 as usize] = 1;
        return out;
    }
    assert!(n <= 1usize << max_length, "alphabet too big for max_length");
    coins.sort_by_key(|&(f, _)| f);

    let mut pool: Vec<PoolElement> = Vec::with_capacity(n * (max_length as usize) * 2 + 8);

    // Level `max_length` (deepest): one coin per nonzero symbol, ascending.
    let mut current: Vec<u32> = Vec::with_capacity(2 * n);
    for &(f, sym) in &coins {
        pool.push(PoolElement {
            cost: f as u64,
            kind: PoolKind::Coin(sym),
        });
        current.push((pool.len() - 1) as u32);
    }

    // Build levels max_length-1 down to 1.
    for _ in 1..max_length {
        // Pair consecutive entries of `current` into packages.
        let mut packages: Vec<u32> = Vec::with_capacity(current.len() / 2);
        let mut i = 0;
        while i + 1 < current.len() {
            let a = current[i];
            let b = current[i + 1];
            let cost = pool[a as usize].cost + pool[b as usize].cost;
            pool.push(PoolElement {
                cost,
                kind: PoolKind::Pair(a, b),
            });
            packages.push((pool.len() - 1) as u32);
            i += 2;
        }

        // Fresh coins for this level.
        let coin_start = pool.len();
        for &(f, sym) in &coins {
            pool.push(PoolElement {
                cost: f as u64,
                kind: PoolKind::Coin(sym),
            });
        }
        let fresh_coins: Vec<u32> = (coin_start..pool.len()).map(|i| i as u32).collect();

        // Merge two cost-sorted lists.
        let mut merged: Vec<u32> = Vec::with_capacity(fresh_coins.len() + packages.len());
        let (mut ci, mut pi) = (0usize, 0usize);
        while ci < fresh_coins.len() && pi < packages.len() {
            if pool[fresh_coins[ci] as usize].cost <= pool[packages[pi] as usize].cost {
                merged.push(fresh_coins[ci]);
                ci += 1;
            } else {
                merged.push(packages[pi]);
                pi += 1;
            }
        }
        merged.extend_from_slice(&fresh_coins[ci..]);
        merged.extend_from_slice(&packages[pi..]);
        current = merged;
    }

    // Pick the 2n − 2 smallest items from level 1 (already sorted ascending).
    let pick = 2 * n - 2;
    let mut stack: Vec<u32> = Vec::with_capacity(32);
    for &root in &current[..pick] {
        stack.clear();
        stack.push(root);
        while let Some(idx) = stack.pop() {
            match pool[idx as usize].kind {
                PoolKind::Coin(sym) => out[sym as usize] += 1,
                PoolKind::Pair(a, b) => {
                    stack.push(a);
                    stack.push(b);
                }
            }
        }
    }

    out
}

/// Compute the canonical (MSB-first) Huffman codes for an array of code
/// lengths per RFC 1951 §3.2.2. Slot `i` holds the code for symbol `i`;
/// the value is meaningless when `lengths[i] == 0`.
#[cfg(feature = "alloc")]
pub fn canonical_codes_from_lengths(lengths: &[u8]) -> Vec<u16> {
    let mut count = [0u32; 16];
    for &len in lengths {
        debug_assert!(len <= 15);
        if len > 0 {
            count[len as usize] += 1;
        }
    }

    let mut next_code = [0u32; 16];
    let mut code: u32 = 0;
    for bits in 1..=15 {
        code = (code + count[bits - 1]) << 1;
        next_code[bits] = code;
    }

    let mut out = vec![0u16; lengths.len()];
    for (i, &len) in lengths.iter().enumerate() {
        if len > 0 {
            out[i] = next_code[len as usize] as u16;
            next_code[len as usize] += 1;
        }
    }
    out
}

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use super::*;

    #[test]
    fn canonical_decoder_rfc1951_example() {
        // RFC 1951 §3.2.2 example: code lengths [3, 3, 3, 3, 3, 2, 4, 4].
        // Resulting canonical codes:
        //   A=010, B=011, C=100, D=101, E=110, F=00, G=1110, H=1111
        let lens = [3u8, 3, 3, 3, 3, 2, 4, 4];
        let dec = CanonicalDecoder::<8>::from_lengths(&lens).unwrap();

        // Try decoding "00" → F.
        let mut r = BitReader::new();
        // "F" code MSB-first = "00" → in LSB-first stream that's 0b00 (two zero bits).
        r.feed(0b0000_0000);
        let sym = dec.decode(&mut r).unwrap().unwrap();
        assert_eq!(sym, 5); // F = symbol 5

        // Decoding "010" → A. MSB-first "010" → bits in order 0,1,0 → LSB-first acc = 0b010
        let mut r = BitReader::new();
        r.feed(0b0000_0010); // bits 0,1,0 followed by zeros
        let sym = dec.decode(&mut r).unwrap().unwrap();
        assert_eq!(sym, 0); // A = symbol 0
    }

    #[test]
    fn canonical_codes_roundtrip() {
        let lens = [3u8, 3, 3, 3, 3, 2, 4, 4];
        let codes = canonical_codes_from_lengths(&lens);
        // Spec values:
        assert_eq!(codes[5], 0b00); // F
        assert_eq!(codes[0], 0b010); // A
        assert_eq!(codes[1], 0b011); // B
        assert_eq!(codes[6], 0b1110); // G
        assert_eq!(codes[7], 0b1111); // H
    }

    #[test]
    fn length_limited_basic() {
        // Frequencies [1, 1, 1, 1]: all equal -> all codes get length 2 with no limit.
        let lens = length_limited_huffman(&[1, 1, 1, 1], 15);
        assert_eq!(lens, vec![2, 2, 2, 2]);
    }

    #[test]
    fn length_limited_enforces_cap() {
        // Highly skewed frequencies that would naturally produce a very deep
        // tree but must be clamped to max_length = 3.
        // 8 symbols force codes of at least 3 bits with max_length=3.
        let freqs = [1u32, 1, 1, 1, 1, 1, 1, 100];
        let lens = length_limited_huffman(&freqs, 3);
        // Every symbol gets at most 3 bits.
        assert!(lens.iter().all(|&l| l <= 3));
        // The most frequent symbol gets the shortest code.
        let min_len = *lens.iter().filter(|&&l| l > 0).min().unwrap();
        assert!(lens[7] <= min_len); // 7 (freq 100) is among shortest
    }

    #[test]
    fn single_symbol_gets_length_one() {
        let lens = length_limited_huffman(&[0, 0, 5, 0], 15);
        assert_eq!(lens[2], 1);
        assert!(lens.iter().enumerate().all(|(i, &l)| (i == 2) == (l > 0)));
    }
}
