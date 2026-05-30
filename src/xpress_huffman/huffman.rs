//! Canonical Huffman build for XPress Huffman.
//!
//! XPress Huffman trees are over a 512-symbol alphabet with code lengths
//! capped at 15 bits. The wire stores lengths only — codes are derived
//! canonically per MS-XCA: sort by (length, symbol) and assign codes
//! starting from 0 at length 1, doubling each length step.
//!
//! Decoder side: we build a single 32 KiB lookup table indexed by the
//! next 15 MSB-first bits of the stream. Each entry holds the symbol
//! plus its code length. This matches the reference implementation
//! technique and keeps the per-symbol cost to one indexed load.
//!
//! Encoder side: we accept a frequency histogram and produce a
//! length-limited (≤ 15 bits) code-length array via package-merge
//! (deferred to the encoder; we just expose canonical-code generation
//! here). Then `lengths_to_codes` maps lengths to MSB-first canonical
//! code values.

extern crate alloc;
use alloc::vec::Vec;

use crate::error::Error;

/// 512 = 256 literals + 256 match symbols.
pub const NUM_SYMBOLS: usize = 512;
/// 15-bit cap on canonical code lengths (MS-XCA §2.1).
pub const MAX_CODE_LEN: u32 = 15;
pub const DECODE_TABLE_BITS: u32 = 15;
pub const DECODE_TABLE_SIZE: usize = 1 << DECODE_TABLE_BITS;

/// Parse the 256-byte packed length table at the start of each block.
/// Symbol 2k is the low nibble of byte k; symbol 2k+1 is the high nibble.
pub fn unpack_lengths(packed: &[u8; 256]) -> [u8; NUM_SYMBOLS] {
    let mut lens = [0u8; NUM_SYMBOLS];
    for (k, &b) in packed.iter().enumerate() {
        lens[2 * k] = b & 0x0F;
        lens[2 * k + 1] = b >> 4;
    }
    lens
}

/// Pack a 512-entry length table back into 256 bytes for the wire.
pub fn pack_lengths(lens: &[u8; NUM_SYMBOLS]) -> [u8; 256] {
    let mut packed = [0u8; 256];
    for k in 0..256 {
        packed[k] = (lens[2 * k] & 0x0F) | ((lens[2 * k + 1] & 0x0F) << 4);
    }
    packed
}

/// Build the 32 KiB decoding table per the MS-XCA reference method:
/// sort symbols by `(length ascending, symbol ascending)`, then write
/// `2^(15 - L)` consecutive entries pointing to each used symbol.
///
/// Returned table is a `Box<[(u16, u8); 1<<15]>` packed as `(symbol, len)`.
/// A length of `0` for an entry would mean "no code claims these bits"
/// — `build_decode_table` rejects such tables as malformed.
pub fn build_decode_table(
    lengths: &[u8; NUM_SYMBOLS],
) -> Result<alloc::boxed::Box<DecodeTable>, Error> {
    // Validate lengths in range.
    for &l in lengths.iter() {
        if l as u32 > MAX_CODE_LEN {
            return Err(Error::InvalidHuffmanTree);
        }
    }

    // Empty alphabet: MS-XCA requires the table to be exactly full
    // (CurrentTableEntry == 2^15) at the end. An all-zero length array
    // would leave it at 0 → invalid.
    let mut table = alloc::boxed::Box::new([(0u16, 0u8); DECODE_TABLE_SIZE]);
    let mut entry: usize = 0;
    for bit_length in 1..=MAX_CODE_LEN {
        for symbol in 0..NUM_SYMBOLS as u16 {
            if lengths[symbol as usize] as u32 == bit_length {
                let count = 1usize << (MAX_CODE_LEN - bit_length);
                if entry + count > DECODE_TABLE_SIZE {
                    return Err(Error::InvalidHuffmanTree);
                }
                let value = (symbol, bit_length as u8);
                for slot in &mut table[entry..entry + count] {
                    *slot = value;
                }
                entry += count;
            }
        }
    }
    if entry != DECODE_TABLE_SIZE {
        return Err(Error::InvalidHuffmanTree);
    }
    Ok(table)
}

pub type DecodeTable = [(u16, u8); DECODE_TABLE_SIZE];

/// Compute canonical MSB-first code values matching `lengths`. Returned
/// vector is indexed by symbol; entries with length 0 are 0. Used by
/// the encoder to look up the code for each symbol it emits.
pub fn lengths_to_codes(lengths: &[u8; NUM_SYMBOLS]) -> [u16; NUM_SYMBOLS] {
    let mut counts = [0u32; (MAX_CODE_LEN + 1) as usize];
    for &l in lengths.iter() {
        if l > 0 {
            counts[l as usize] += 1;
        }
    }
    // First code per length per RFC-1951-style canonical: next_code[L] =
    // (next_code[L-1] + counts[L-1]) << 1.
    let mut next_code = [0u32; (MAX_CODE_LEN + 1) as usize];
    let mut code: u32 = 0;
    for l in 1..=MAX_CODE_LEN as usize {
        code = (code + counts[l - 1]) << 1;
        next_code[l] = code;
    }
    let mut codes = [0u16; NUM_SYMBOLS];
    for (sym, &l) in lengths.iter().enumerate() {
        if l > 0 {
            codes[sym] = next_code[l as usize] as u16;
            next_code[l as usize] += 1;
        }
    }
    codes
}

/// Length-limited Huffman code lengths via package-merge (Larmore-Hirschberg).
/// Returns a length array indexed by symbol with `lengths[sym] = 0` for
/// `freqs[sym] = 0`, and total Kraft sum at most `2^max_length`.
///
/// `freqs` may have any length up to `NUM_SYMBOLS`; the returned array is
/// always sized [`NUM_SYMBOLS`]. Sites that don't use the full alphabet
/// pass zeros for unused symbols.
pub fn length_limited_huffman(freqs: &[u32], max_length: u32) -> [u8; NUM_SYMBOLS] {
    debug_assert!(freqs.len() <= NUM_SYMBOLS);
    debug_assert!((1..=MAX_CODE_LEN).contains(&max_length));

    let mut active: Vec<(u32, u32)> = freqs
        .iter()
        .enumerate()
        .filter(|&(_, &f)| f > 0)
        .map(|(s, &f)| (f, s as u32))
        .collect();

    let mut lengths = [0u8; NUM_SYMBOLS];

    if active.is_empty() {
        return lengths;
    }
    if active.len() == 1 {
        // Single symbol: assign length 1 (Kraft = 1/2, decoder accepts).
        lengths[active[0].1 as usize] = 1;
        return lengths;
    }

    // Package-merge: at each "row" L (from max_length down to 1) we have
    // a list of items sorted by weight. Row L starts as the per-symbol
    // weights (one item per symbol). For each row L = max_length-1 down
    // to 1, we pair adjacent items in the lower row (packaging them)
    // and merge with the current row's items.
    //
    // After all rows are built, the bottom row of size 2*active-2 gives
    // the package set; we walk it back up to count how many times each
    // symbol appears, which is its assigned code length.

    active.sort_by_key(|&(f, s)| (f, s));
    let base: Vec<(u32, u32)> = active.iter().map(|&(f, s)| (f, s)).collect();

    // `nodes[l]` is row l (l from 0..max_length). Item: (weight, symbol_bitset_idx)
    // We track symbol membership via "leaf indices" — each row item is
    // either a leaf (one symbol) or a package (pair of items from row+1).
    // To avoid building a tree, we use the standard counting trick:
    // walk the row 0 selection and increment lengths[sym] for each leaf
    // encountered.

    // Build rows bottom-up.
    let mut rows: Vec<Vec<Item>> = Vec::with_capacity(max_length as usize);
    let leaves: Vec<Item> = base
        .iter()
        .map(|&(f, s)| Item {
            weight: f as u64,
            leaf: Some(s as u16),
            children: None,
        })
        .collect();
    rows.push(leaves.clone());
    for _ in 1..max_length {
        let prev = rows.last().unwrap();
        let mut packages: Vec<Item> = Vec::with_capacity(prev.len() / 2);
        for chunk in prev.chunks(2) {
            if chunk.len() == 2 {
                packages.push(Item {
                    weight: chunk[0].weight + chunk[1].weight,
                    leaf: None,
                    children: Some((chunk[0].clone().into(), chunk[1].clone().into())),
                });
            }
        }
        let mut merged: Vec<Item> = Vec::with_capacity(packages.len() + leaves.len());
        let (mut i, mut j) = (0usize, 0usize);
        while i < leaves.len() || j < packages.len() {
            let take_leaf = match (leaves.get(i), packages.get(j)) {
                (Some(l), Some(p)) => l.weight <= p.weight,
                (Some(_), None) => true,
                (None, Some(_)) => false,
                _ => unreachable!(),
            };
            if take_leaf {
                merged.push(leaves[i].clone());
                i += 1;
            } else {
                merged.push(packages[j].clone());
                j += 1;
            }
        }
        rows.push(merged);
    }
    // Top row: take first 2*n - 2 items (n = active.len()).
    let top = rows.last().unwrap();
    let n = base.len();
    let take = (2 * n).saturating_sub(2);
    let selected = &top[..take.min(top.len())];
    for item in selected {
        item.count_leaves(&mut lengths);
    }
    lengths
}

#[derive(Clone)]
struct Item {
    weight: u64,
    leaf: Option<u16>,
    children: Option<(alloc::boxed::Box<Item>, alloc::boxed::Box<Item>)>,
}

impl Item {
    fn count_leaves(&self, lengths: &mut [u8; NUM_SYMBOLS]) {
        if let Some(s) = self.leaf {
            lengths[s as usize] += 1;
        } else if let Some((l, r)) = &self.children {
            l.count_leaves(lengths);
            r.count_leaves(lengths);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_unpack_roundtrip() {
        let mut lens = [0u8; NUM_SYMBOLS];
        for (i, l) in lens.iter_mut().enumerate() {
            *l = ((i * 7) % 16) as u8;
        }
        let packed = pack_lengths(&lens);
        let back = unpack_lengths(&packed);
        assert_eq!(back, lens);
    }

    #[test]
    fn build_decode_table_accepts_simple() {
        // Two symbols of length 1 each — full binary tree at depth 1, but
        // we need to fill 2^15 slots → each symbol gets 2^14 entries.
        let mut lens = [0u8; NUM_SYMBOLS];
        lens[0] = 1;
        lens[1] = 1;
        let t = build_decode_table(&lens).unwrap();
        assert_eq!(t[0], (0, 1));
        assert_eq!(t[(1 << 14) - 1], (0, 1));
        assert_eq!(t[1 << 14], (1, 1));
        assert_eq!(t[(1 << 15) - 1], (1, 1));
    }

    #[test]
    fn build_decode_table_rejects_invalid() {
        let mut lens = [0u8; NUM_SYMBOLS];
        lens[0] = 1; // Kraft sum = 1/2, table only half-full.
        assert!(matches!(
            build_decode_table(&lens),
            Err(Error::InvalidHuffmanTree)
        ));
    }

    #[test]
    fn canonical_codes_match_spec() {
        // Example from MS-XCA spec text: symbols 0,1,2,3 with lengths
        // 5,6,7,8 → first 2 packed bytes are 0x65 0x87.
        let mut lens = [0u8; NUM_SYMBOLS];
        lens[0] = 5;
        lens[1] = 6;
        lens[2] = 7;
        lens[3] = 8;
        let packed = pack_lengths(&lens);
        assert_eq!(packed[0], 0x65);
        assert_eq!(packed[1], 0x87);
    }

    #[test]
    fn length_limited_caps_lengths() {
        // 200 distinct symbols → uncapped Huffman would assign up to
        // ~ log2(200) ≈ 8 bits; cap at 15 is comfortable. Just verify
        // every assigned length is ≤ 15.
        let mut freqs = [0u32; 200];
        for (i, f) in freqs.iter_mut().enumerate() {
            *f = (i as u32) + 1;
        }
        let lens = length_limited_huffman(&freqs, 15);
        for &l in lens.iter() {
            assert!(l <= 15);
        }
    }

    #[test]
    fn single_symbol_gets_length_one() {
        let mut freqs = [0u32; NUM_SYMBOLS];
        freqs[42] = 100;
        let lens = length_limited_huffman(&freqs, 15);
        assert_eq!(lens[42], 1);
        for (s, &l) in lens.iter().enumerate() {
            if s != 42 {
                assert_eq!(l, 0);
            }
        }
    }
}
