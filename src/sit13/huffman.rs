//! LSB-first prefix-code decoder for StuffIt method 13.
//!
//! Method 13 uses four prefix codes: a fixed, hand-tuned (non-canonical)
//! meta-code given as explicit (code value, length) pairs, plus three
//! per-stream canonical codes (literal/length code A, code B, and the offset
//! bit-length code) reconstructed from per-symbol bit-length lists. All four
//! are decoded the same way: bits are consumed **least-significant-bit first**
//! and walked down a binary trie until a leaf (symbol) is reached.
//!
//! Using a trie makes the decoder agnostic to whether a code is canonical: it
//! handles the tuned meta-code and the canonical codes uniformly, and it is
//! prefix-correct by construction. Construction validates that the codes form
//! a proper prefix set (no code is a prefix of another, no two codes collide);
//! a malformed length list (over- or under-subscribed, or exceeding the 32-bit
//! length cap) is rejected with [`Error::InvalidHuffmanTree`]. No `unsafe`; no
//! panic reachable from any input.

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;

use super::bits::BitReader;

/// Maximum supported prefix-code length, in bits (per the format spec).
pub(crate) const MAX_CODE_LENGTH: u32 = 32;

/// A trie node. `children[bit]` is the next node index, or `NONE` if absent.
/// A `symbol` of `Some` marks a leaf.
const NONE: u32 = u32::MAX;

/// LSB-first prefix-code decoder backed by a binary trie.
pub(crate) struct Huffman {
    /// Flattened trie: two child links per node (`[2*i]` = bit 0, `[2*i+1]`
    /// = bit 1). `NONE` = no child.
    links: Vec<u32>,
    /// Per-node leaf symbol (`u32::MAX` = internal node).
    leaf: Vec<u32>,
}

impl Huffman {
    /// Build a decoder from a canonical bit-length list (index = symbol,
    /// value = code length in bits, 0 = symbol absent).
    ///
    /// The canonical assignment is the "shortest code is all-zero bits"
    /// variant with the standard increment, codes assigned in ascending
    /// symbol order among equal lengths; each code is then emitted/read
    /// least-significant-bit first (the MSB-canonical value is reversed to
    /// its bit length). Returns [`Error::InvalidHuffmanTree`] if a length
    /// exceeds [`MAX_CODE_LENGTH`] or the lengths do not form a valid prefix
    /// code.
    pub(crate) fn from_lengths(lengths: &[u8]) -> Result<Self, Error> {
        let mut counts = [0u32; MAX_CODE_LENGTH as usize + 1];
        let mut max_len = 0u32;
        for &l in lengths {
            let l = l as u32;
            if l > MAX_CODE_LENGTH {
                return Err(Error::InvalidHuffmanTree);
            }
            if l > 0 {
                counts[l as usize] += 1;
                if l > max_len {
                    max_len = l;
                }
            }
        }
        if max_len == 0 {
            // Empty code: valid to construct, but any decode fails.
            return Ok(Self::empty());
        }

        // Kraft equality check: a usable prefix code must be exactly full.
        // (Under-full would leave undecodable bit patterns; over-full is
        // impossible to assign.) Accumulate in u64 to avoid overflow.
        let mut kraft: u64 = 0;
        for l in 1..=max_len {
            kraft += (counts[l as usize] as u64) << (max_len - l);
        }
        let full: u64 = 1u64 << max_len;
        if kraft > full {
            return Err(Error::InvalidHuffmanTree);
        }
        // A single symbol of length 0 already returned `empty()` above; here
        // we additionally require exact fullness so under-subscribed tables
        // (which would admit bit patterns matching no symbol) are rejected.
        if kraft != full {
            return Err(Error::InvalidHuffmanTree);
        }

        // Standard canonical first-code-per-length (MSB space).
        let mut next_code = [0u32; MAX_CODE_LENGTH as usize + 1];
        let mut code: u32 = 0;
        for l in 1..=max_len {
            next_code[l as usize] = code;
            code = (code + counts[l as usize]) << 1;
        }

        let mut builder = TrieBuilder::new();
        for (sym, &l8) in lengths.iter().enumerate() {
            let l = l8 as u32;
            if l == 0 {
                continue;
            }
            let msb_code = next_code[l as usize];
            next_code[l as usize] += 1;
            // Read LSB-first ⇒ stream value is the bit-reverse of the MSB
            // canonical code, taken to `l` bits.
            let lsb_code = reverse_bits(msb_code, l);
            builder.insert(lsb_code, l, sym as u32)?;
        }
        Ok(builder.finish())
    }

    /// Build a decoder from explicit (LSB-first code value, length) pairs,
    /// used for the fixed non-canonical meta-code.
    pub(crate) fn from_codes(values: &[u32], lengths: &[u8]) -> Result<Self, Error> {
        if values.len() != lengths.len() {
            return Err(Error::InvalidHuffmanTree);
        }
        let mut builder = TrieBuilder::new();
        for (sym, (&v, &l8)) in values.iter().zip(lengths.iter()).enumerate() {
            let l = l8 as u32;
            if l == 0 {
                continue;
            }
            if l > MAX_CODE_LENGTH {
                return Err(Error::InvalidHuffmanTree);
            }
            builder.insert(v, l, sym as u32)?;
        }
        Ok(builder.finish())
    }

    fn empty() -> Self {
        Self {
            // One root node, no children, not a leaf.
            links: vec![NONE, NONE],
            leaf: vec![NONE],
        }
    }

    /// Decode one symbol, consuming bits LSB-first. Returns
    /// [`Error::InvalidHuffmanTree`] if the bits walk off the trie (no such
    /// code) and [`Error::UnexpectedEnd`] if input runs out mid-code.
    pub(crate) fn decode(&self, reader: &mut BitReader<'_>) -> Result<u32, Error> {
        let mut node: u32 = 0;
        loop {
            if self.leaf[node as usize] != NONE {
                return Ok(self.leaf[node as usize]);
            }
            let bit = reader.read_bit()?;
            let next = self.links[(node as usize) * 2 + bit as usize];
            if next == NONE {
                return Err(Error::InvalidHuffmanTree);
            }
            node = next;
        }
    }
}

/// Reverse the low `n` bits of `v` (LSB ↔ MSB within an `n`-bit field).
fn reverse_bits(v: u32, n: u32) -> u32 {
    let mut out = 0u32;
    for i in 0..n {
        out |= ((v >> i) & 1) << (n - 1 - i);
    }
    out
}

/// Incremental trie builder shared by both constructors.
struct TrieBuilder {
    links: Vec<u32>,
    leaf: Vec<u32>,
}

impl TrieBuilder {
    fn new() -> Self {
        Self {
            links: vec![NONE, NONE],
            leaf: vec![NONE],
        }
    }

    /// Insert one codeword: `code`'s bits read LSB-first over `len` bits map
    /// to `sym`. Rejects prefix conflicts and collisions.
    fn insert(&mut self, code: u32, len: u32, sym: u32) -> Result<(), Error> {
        let mut node: u32 = 0;
        for i in 0..len {
            // If we're already at a leaf, an earlier (shorter) code is a
            // prefix of this one — not a valid prefix code.
            if self.leaf[node as usize] != NONE {
                return Err(Error::InvalidHuffmanTree);
            }
            let bit = ((code >> i) & 1) as usize;
            let slot = (node as usize) * 2 + bit;
            if self.links[slot] == NONE {
                let new_idx = self.leaf.len() as u32;
                self.links.push(NONE);
                self.links.push(NONE);
                self.leaf.push(NONE);
                self.links[slot] = new_idx;
            }
            node = self.links[slot];
        }
        // Landing node must be fresh (no symbol, no children).
        if self.leaf[node as usize] != NONE
            || self.links[(node as usize) * 2] != NONE
            || self.links[(node as usize) * 2 + 1] != NONE
        {
            return Err(Error::InvalidHuffmanTree);
        }
        self.leaf[node as usize] = sym;
        Ok(())
    }

    fn finish(self) -> Huffman {
        Huffman {
            links: self.links,
            leaf: self.leaf,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reverse_bits_works() {
        assert_eq!(reverse_bits(0b001, 3), 0b100);
        assert_eq!(reverse_bits(0b10, 2), 0b01);
        assert_eq!(reverse_bits(0, 5), 0);
    }

    #[test]
    fn canonical_lsb_roundtrip() {
        // lengths [1,2,2]: canonical MSB codes 0:"0", 1:"10", 2:"11".
        // LSB-first stream values: 0→0(1b), 1→01=1(2b), 2→11=3(2b).
        let h = Huffman::from_lengths(&[1, 2, 2]).unwrap();
        // bit sequence to feed: symbol0 (bit 0), symbol1 (bits 1,0), symbol2 (bits 1,1)
        // Pack LSB-first into bytes: bits in order: 0 | 1,0 | 1,1
        // positions: b0=0,b1=1,b2=0,b3=1,b4=1 → byte = 0b0001_1010 = 0x1A
        let data = [0x1Au8];
        let mut r = BitReader::new(&data);
        assert_eq!(h.decode(&mut r).unwrap(), 0);
        assert_eq!(h.decode(&mut r).unwrap(), 1);
        assert_eq!(h.decode(&mut r).unwrap(), 2);
    }

    #[test]
    fn metacode_builds_and_decodes() {
        let h = Huffman::from_codes(
            &super::super::tables::META_CODE_VALUES,
            &super::super::tables::META_CODE_LENGTHS,
        )
        .unwrap();
        // Symbol 32 has code value 1, length 2 (LSB-first 0b01 → bits 1,0).
        let data = [0b0000_0001u8];
        let mut r = BitReader::new(&data);
        assert_eq!(h.decode(&mut r).unwrap(), 32);
    }

    #[test]
    fn rejects_oversubscribed() {
        // three length-1 codes cannot coexist.
        assert!(matches!(
            Huffman::from_lengths(&[1, 1, 1]),
            Err(Error::InvalidHuffmanTree)
        ));
    }

    #[test]
    fn rejects_undersubscribed() {
        // a single length-2 code leaves the space under-full.
        assert!(matches!(
            Huffman::from_lengths(&[2]),
            Err(Error::InvalidHuffmanTree)
        ));
    }

    #[test]
    fn rejects_length_over_cap() {
        let mut lens = [0u8; 2];
        lens[0] = 33;
        assert!(matches!(
            Huffman::from_lengths(&lens),
            Err(Error::InvalidHuffmanTree)
        ));
    }

    #[test]
    fn empty_decode_errors() {
        let h = Huffman::from_lengths(&[0, 0, 0]).unwrap();
        let data = [0xFFu8];
        let mut r = BitReader::new(&data);
        assert!(matches!(h.decode(&mut r), Err(Error::InvalidHuffmanTree)));
    }

    #[test]
    fn all_predefined_sets_build() {
        for s in 0..5 {
            Huffman::from_lengths(super::super::tables::PREDEFINED_FIRST[s]).unwrap();
            Huffman::from_lengths(super::super::tables::PREDEFINED_SECOND[s]).unwrap();
            Huffman::from_lengths(super::super::tables::PREDEFINED_OFFSET[s]).unwrap();
        }
    }
}
