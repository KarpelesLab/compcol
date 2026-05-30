//! Canonical Huffman tables for the LHA/LZH static-Huffman methods.
//!
//! LHA transmits only code *lengths* (never codes); both sides assign
//! canonical MSB-first codes in symbol order, shortest-length-first.
//! Okumura's reference decoder builds a flat lookup table indexed by the
//! next `tablebits` bits; codes longer than `tablebits` chain through a
//! small binary tree appended after the table. We use the same scheme so
//! decoding is a single indexed load for the common (short-code) case.
//!
//! Everything here is clean-room from the public-domain ar002 format
//! description: counts/first-code canonical assignment (identical to RFC
//! 1951's), plus a Kraft-sum validation so malformed length sets are
//! rejected with [`Error::InvalidHuffmanTree`] rather than producing a
//! lopsided table.

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;

/// Maximum Huffman code length LHA permits (matches the reference `16`).
pub const MAX_BITS: u32 = 16;

/// A canonical Huffman decode table built from code lengths.
///
/// `table` is indexed by the next `table_bits` bits (MSB-first). An entry
/// is either a leaf symbol (`< SYMBOL_BASE`-style: any value, since we
/// store symbols directly) or, for codes longer than `table_bits`, an
/// index into `tree` (encoded as `value >= tree_marker`). To keep things
/// simple and 100% safe we store, per table slot, a `(symbol, len)` pair
/// for codes that fit, and for over-long codes a pointer into a secondary
/// per-leaf chain resolved bit-by-bit.
pub struct HuffTable {
    /// Fast table: `1 << table_bits` entries. Each holds the decoded
    /// symbol and its code length when `len <= table_bits`. For longer
    /// codes the entry's `len` is `> table_bits` and `sym` indexes into
    /// `long`.
    table: Vec<TableEntry>,
    table_bits: u32,
    /// Overflow nodes for codes longer than `table_bits`: a binary tree.
    /// Each node is `[left, right]`; values `>= LEAF` are leaves holding
    /// `value - LEAF` as the symbol.
    long: Vec<[u32; 2]>,
    /// Number of symbols in the alphabet (for bounds documentation).
    num_symbols: usize,
    /// Set when the alphabet has exactly one symbol with a zero length
    /// table (degenerate single-symbol block): every decode returns
    /// `single`.
    single: Option<u16>,
}

#[derive(Clone, Copy)]
struct TableEntry {
    /// Decoded symbol (if `len <= table_bits`) or root overflow node index.
    sym: u32,
    /// Code length; `0` = unused slot, `> table_bits` = overflow.
    len: u8,
}

/// Marker added to a `long` slot value to flag it as a leaf.
const LEAF: u32 = 0x8000_0000;

impl HuffTable {
    /// Build a decode table from `lengths` (one entry per symbol). A
    /// length of `0` means the symbol is absent. `table_bits` is the
    /// fast-table width (`<= MAX_BITS`).
    pub fn build(lengths: &[u8], table_bits: u32) -> Result<Self, Error> {
        let num_symbols = lengths.len();
        // Validate lengths and count occurrences per length.
        let mut count = [0u32; (MAX_BITS + 1) as usize];
        let mut used = 0u32;
        let mut last_sym = 0u16;
        for (s, &l) in lengths.iter().enumerate() {
            if l as u32 > MAX_BITS {
                return Err(Error::InvalidHuffmanTree);
            }
            if l > 0 {
                count[l as usize] += 1;
                used += 1;
                last_sym = s as u16;
            }
        }

        // Degenerate cases: zero or one used symbol. The LHA format does
        // emit single-symbol position/length tables (a block that uses
        // only one distance, say); the reference handles this by a
        // special "all codes decode to this symbol" path.
        if used == 0 {
            // No symbols at all. A valid block must reference at least
            // one symbol, but an empty table is only reached for tables
            // that are never consulted; treat as degenerate-empty.
            return Ok(Self {
                table: Vec::new(),
                table_bits,
                long: Vec::new(),
                num_symbols,
                single: None,
            });
        }
        if used == 1 {
            return Ok(Self {
                table: Vec::new(),
                table_bits,
                long: Vec::new(),
                num_symbols,
                single: Some(last_sym),
            });
        }

        // Kraft equality check: a complete prefix code must satisfy
        // sum(count[l] * 2^-l) == 1, i.e. sum(count[l] << (MAX-l)) ==
        // 1 << MAX. Reject over- or under-subscribed sets.
        let mut total: u64 = 0;
        for l in 1..=MAX_BITS {
            total += (count[l as usize] as u64) << (MAX_BITS - l);
        }
        if total != (1u64 << MAX_BITS) {
            return Err(Error::InvalidHuffmanTree);
        }

        // Canonical first-code per length (RFC-1951 style).
        let mut next_code = [0u32; (MAX_BITS + 1) as usize];
        let mut code = 0u32;
        for l in 1..=MAX_BITS as usize {
            code = (code + count[l - 1]) << 1;
            next_code[l] = code;
        }

        let table_size = 1usize << table_bits;
        let mut table = vec![TableEntry { sym: 0, len: 0 }; table_size];
        let mut long: Vec<[u32; 2]> = Vec::new();

        for (sym, &l) in lengths.iter().enumerate() {
            let l = l as u32;
            if l == 0 {
                continue;
            }
            let c = next_code[l as usize];
            next_code[l as usize] += 1;

            if l <= table_bits {
                // Fill the 2^(table_bits - l) slots whose top `l` bits
                // equal `c`.
                let shift = table_bits - l;
                let start = (c << shift) as usize;
                let span = 1usize << shift;
                if start + span > table_size {
                    return Err(Error::InvalidHuffmanTree);
                }
                for slot in &mut table[start..start + span] {
                    slot.sym = sym as u32;
                    slot.len = l as u8;
                }
            } else {
                // Over-long code: the top `table_bits` bits select a
                // root overflow node; remaining bits walk a binary tree.
                let top = (c >> (l - table_bits)) as usize;
                if top >= table_size {
                    return Err(Error::InvalidHuffmanTree);
                }
                // Ensure a root node exists for this table slot.
                if table[top].len as u32 <= table_bits {
                    // Allocate a fresh overflow root.
                    long.push([0, 0]);
                    table[top].sym = (long.len() - 1) as u32;
                    table[top].len = (table_bits + 1) as u8; // marker > table_bits
                }
                let mut node = table[top].sym as usize;
                // Walk bits below the table_bits prefix, MSB-first.
                let extra = l - table_bits;
                for i in (0..extra).rev() {
                    let bit = ((c >> i) & 1) as usize;
                    if i == 0 {
                        // Leaf level.
                        if node >= long.len() {
                            return Err(Error::InvalidHuffmanTree);
                        }
                        if long[node][bit] != 0 {
                            return Err(Error::InvalidHuffmanTree);
                        }
                        long[node][bit] = LEAF | sym as u32;
                    } else {
                        if node >= long.len() {
                            return Err(Error::InvalidHuffmanTree);
                        }
                        let child = long[node][bit];
                        if child == 0 {
                            long.push([0, 0]);
                            let idx = (long.len() - 1) as u32;
                            long[node][bit] = idx;
                            node = idx as usize;
                        } else if child & LEAF != 0 {
                            // Prefix collision: a shorter code already
                            // claimed this path.
                            return Err(Error::InvalidHuffmanTree);
                        } else {
                            node = child as usize;
                        }
                    }
                }
            }
        }

        Ok(Self {
            table,
            table_bits,
            long,
            num_symbols,
            single: None,
        })
    }

    /// Build a degenerate single-symbol table: every decode returns
    /// `sym` and consumes no bits (matching the reference single-code
    /// path used when a transmitted count is zero). `num_symbols` is the
    /// alphabet size for bounds checking; `sym` must be in range.
    pub fn build_single(num_symbols: usize, sym: u16, table_bits: u32) -> Result<Self, Error> {
        if sym as usize >= num_symbols {
            return Err(Error::InvalidHuffmanTree);
        }
        Ok(Self {
            table: Vec::new(),
            table_bits,
            long: Vec::new(),
            num_symbols,
            single: Some(sym),
        })
    }

    /// Decode one symbol from `br`. Returns the symbol or
    /// [`Error::Corrupt`] if the bits select an unused code.
    pub fn decode(&self, br: &mut super::bits::BitReader<'_>) -> Result<u16, Error> {
        if let Some(s) = self.single {
            // Single-symbol table: the reference consumes no bits for
            // the symbol itself (the code length is zero).
            return Ok(s);
        }
        if self.table.is_empty() {
            return Err(Error::Corrupt);
        }
        let idx = br.peek_bits(self.table_bits) as usize;
        let entry = self.table[idx];
        if entry.len == 0 {
            return Err(Error::Corrupt);
        }
        if (entry.len as u32) <= self.table_bits {
            br.consume(entry.len as u32);
            let sym = entry.sym as usize;
            if sym >= self.num_symbols {
                return Err(Error::Corrupt);
            }
            return Ok(entry.sym as u16);
        }
        // Over-long: consume the prefix, then walk the overflow tree.
        br.consume(self.table_bits);
        let mut node = entry.sym as usize;
        loop {
            let bit = br.get_bits(1) as usize;
            if node >= self.long.len() {
                return Err(Error::Corrupt);
            }
            let next = self.long[node][bit];
            if next == 0 {
                return Err(Error::Corrupt);
            }
            if next & LEAF != 0 {
                let sym = (next & !LEAF) as usize;
                if sym >= self.num_symbols {
                    return Err(Error::Corrupt);
                }
                return Ok(sym as u16);
            }
            node = next as usize;
        }
    }
}

/// Assign canonical code lengths from a frequency histogram, capped at
/// `max_bits`. Returns a per-symbol length array; symbols with zero
/// frequency get length 0. Used by the static-Huffman encoder.
///
/// Uses the package-merge algorithm (length-limited Huffman). Clean-room
/// implementation; the resulting lengths satisfy the Kraft equality the
/// decoder enforces.
pub fn assign_lengths(freqs: &[u32], max_bits: u32) -> Vec<u8> {
    let n = freqs.len();
    let mut lengths = vec![0u8; n];

    // Collect used symbols.
    let mut active: Vec<(u64, usize)> = freqs
        .iter()
        .enumerate()
        .filter(|&(_, &f)| f > 0)
        .map(|(s, &f)| (f as u64, s))
        .collect();

    if active.is_empty() {
        return lengths;
    }
    if active.len() == 1 {
        lengths[active[0].1] = 1;
        return lengths;
    }

    active.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));

    // Package-merge. Each item is either a leaf (one symbol) or a package
    // of two lower-row items. We count, for each symbol, how many times
    // it appears across the final selection of `2*m - 2` items.
    #[derive(Clone)]
    enum Node {
        Leaf(usize),
        Pkg(alloc::boxed::Box<Node>, alloc::boxed::Box<Node>),
    }
    let leaves: Vec<(u64, Node)> = active.iter().map(|&(f, s)| (f, Node::Leaf(s))).collect();

    let mut row: Vec<(u64, Node)> = leaves.clone();
    for _ in 1..max_bits {
        // Package adjacent pairs of the current row.
        let mut packages: Vec<(u64, Node)> = Vec::with_capacity(row.len() / 2);
        let mut i = 0;
        while i + 1 < row.len() {
            let w = row[i].0 + row[i + 1].0;
            let left = alloc::boxed::Box::new(row[i].1.clone());
            let right = alloc::boxed::Box::new(row[i + 1].1.clone());
            packages.push((w, Node::Pkg(left, right)));
            i += 2;
        }
        // Merge packages with the leaf list, keeping sorted by weight.
        let mut merged: Vec<(u64, Node)> = Vec::with_capacity(packages.len() + leaves.len());
        let (mut a, mut b) = (0usize, 0usize);
        while a < leaves.len() || b < packages.len() {
            let take_leaf = match (leaves.get(a), packages.get(b)) {
                (Some(l), Some(p)) => l.0 <= p.0,
                (Some(_), None) => true,
                (None, Some(_)) => false,
                (None, None) => break,
            };
            if take_leaf {
                merged.push(leaves[a].clone());
                a += 1;
            } else {
                merged.push(packages[b].clone());
                b += 1;
            }
        }
        row = merged;
    }

    // Select the first 2*m - 2 items and count leaf occurrences.
    let m = active.len();
    let take = 2 * m - 2;
    fn count_leaves(node: &Node, lengths: &mut [u8]) {
        match node {
            Node::Leaf(s) => lengths[*s] = lengths[*s].saturating_add(1),
            Node::Pkg(l, r) => {
                count_leaves(l, lengths);
                count_leaves(r, lengths);
            }
        }
    }
    for item in row.iter().take(take) {
        count_leaves(&item.1, &mut lengths);
    }

    lengths
}

/// Compute canonical MSB-first codes for `lengths`. Returns per-symbol
/// code values (0 for unused). Encoder counterpart to [`HuffTable`].
pub fn lengths_to_codes(lengths: &[u8]) -> Vec<u32> {
    let mut count = [0u32; (MAX_BITS + 1) as usize];
    for &l in lengths {
        if l > 0 {
            count[l as usize] += 1;
        }
    }
    let mut next_code = [0u32; (MAX_BITS + 1) as usize];
    let mut code = 0u32;
    for l in 1..=MAX_BITS as usize {
        code = (code + count[l - 1]) << 1;
        next_code[l] = code;
    }
    let mut codes = vec![0u32; lengths.len()];
    for (s, &l) in lengths.iter().enumerate() {
        if l > 0 {
            codes[s] = next_code[l as usize];
            next_code[l as usize] += 1;
        }
    }
    codes
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate alloc;
    use alloc::vec::Vec;

    /// Round-trip a single symbol's canonical code through build/decode.
    fn check(lens: &[u8], codes: &[u32], sym: usize, table: &HuffTable) {
        let l = lens[sym] as u32;
        let code = codes[sym];
        let total = (l.div_ceil(8) * 8).max(24);
        let val = (code as u64) << (total - l);
        let mut bits = Vec::new();
        for b in (0..total / 8).rev() {
            bits.push(((val >> (b * 8)) & 0xFF) as u8);
        }
        let mut br = crate::lha::bits::BitReader::new(&bits);
        let got = table.decode(&mut br).expect("decode ok");
        assert_eq!(got as usize, sym, "sym {sym} len {l}");
    }

    #[test]
    fn short_codes_roundtrip() {
        let mut freqs = vec![0u32; 510];
        for (i, f) in freqs.iter_mut().take(300).enumerate() {
            *f = (i as u32 % 7) + 1;
        }
        let lens = assign_lengths(&freqs, MAX_BITS);
        let codes = lengths_to_codes(&lens);
        let table = HuffTable::build(&lens, 12).expect("build ok");
        for sym in 0..510 {
            if lens[sym] != 0 {
                check(&lens, &codes, sym, &table);
            }
        }
    }

    #[test]
    fn long_codes_roundtrip() {
        // Skewed (Fibonacci) frequencies force codes well past the 12-bit
        // fast-table width, exercising the overflow-tree decode path.
        let mut freqs = vec![0u32; 510];
        let (mut a, mut b) = (1u32, 1u32);
        for f in freqs.iter_mut().take(40) {
            *f = a;
            let c = a.wrapping_add(b);
            a = b;
            b = c.min(1_000_000);
        }
        for f in freqs.iter_mut().take(300).skip(40) {
            *f = 1;
        }
        let lens = assign_lengths(&freqs, MAX_BITS);
        assert!(
            lens.iter().copied().max().unwrap() > 12,
            "test should force long codes"
        );
        let codes = lengths_to_codes(&lens);
        let table = HuffTable::build(&lens, 12).expect("build ok");
        for sym in 0..510 {
            if lens[sym] != 0 {
                check(&lens, &codes, sym, &table);
            }
        }
    }

    #[test]
    fn rejects_incomplete_code() {
        // A single length-2 symbol leaves the Kraft sum < 1 with >1 used
        // symbols: build must reject incomplete sets.
        let mut lens = vec![0u8; 8];
        lens[0] = 2;
        lens[1] = 2;
        // Only two length-2 codes => Kraft 2*2^-2 = 0.5 != 1 => invalid.
        assert!(matches!(
            HuffTable::build(&lens, 4),
            Err(Error::InvalidHuffmanTree)
        ));
    }
}
