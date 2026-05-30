//! Single adaptive (sibling-property) Huffman tree over 314 symbols.
//!
//! This is the entropy model for StuffIt method 5 (spec section 7): 256
//! literal symbols (0..255) plus 58 length codes (256..313), maintained as
//! a classic adaptive Huffman tree.
//!
//! The spec describes the order array with the root at index 0 and leaves at
//! the high indices. We implement the algorithmically-identical *mirror*
//! representation (the well-documented LZHUF layout: order array sorted by
//! non-decreasing frequency, root at the highest index, leaves at the low
//! indices). The spec explicitly allows any representation that yields the
//! same decoded symbol sequence; the sibling-property update, the rescale at
//! root frequency `0x8000`, the per-symbol increment-and-reorder, and the
//! rebuild's halving (rounding up) are reproduced exactly.
//!
//! The only externally-observable wire convention is the decode bit mapping:
//! a `1` bit descends to the first ("left") child, a `0` bit to the second
//! ("right") child. With root at the high index and children stored at a
//! consecutive pair `m`, `m+1` (`m < m+1`), the first/left child is the
//! lower-index member of the pair.

use crate::error::Error;

const SYMBOLS: usize = 314;
const NODES: usize = 2 * SYMBOLS - 1; // 627
const ROOT: usize = NODES - 1; // 626
const RESCALE: u32 = 0x8000;

/// Adaptive Huffman model in the LZHUF order-array layout.
///
/// * `freq[i]` — node frequency; the array stays sorted non-decreasing.
/// * `son[i]` — for an internal node, the order-array index of its first
///   child (the second child is at `son[i] + 1`); for a leaf, `son[i] >=
///   NODES` and `son[i] - NODES` is the alphabet symbol (0..313).
/// * `parent[i]` — parent order-array index.
///
/// `parent` also carries a reverse index for leaves so a symbol can be
/// located in O(1): `leaf_index[symbol]` holds the order-array slot.
pub struct Tree {
    freq: [u32; NODES + 1],
    son: [u16; NODES],
    parent: [u16; NODES + SYMBOLS],
    /// Order-array slot currently holding each symbol's leaf.
    leaf_index: [u16; SYMBOLS],
}

impl Tree {
    pub fn new() -> Self {
        let mut t = Tree {
            freq: [0; NODES + 1],
            son: [0; NODES],
            parent: [0; NODES + SYMBOLS],
            leaf_index: [0; SYMBOLS],
        };
        // Leaves at the low indices 0..SYMBOLS, each frequency 1.
        for i in 0..SYMBOLS {
            t.freq[i] = 1;
            t.son[i] = (i + NODES) as u16; // leaf marker: son >= NODES
            t.parent[i + NODES] = i as u16; // reverse: symbol i -> slot i
            t.leaf_index[i] = i as u16;
        }
        // Internal nodes at SYMBOLS..NODES, each combining a consecutive
        // pair of lower-index nodes.
        let mut i = 0usize;
        let mut j = SYMBOLS;
        while j < NODES {
            t.freq[j] = t.freq[i] + t.freq[i + 1];
            t.son[j] = i as u16; // first child = i, second = i+1
            t.parent[i] = j as u16;
            t.parent[i + 1] = j as u16;
            i += 2;
            j += 1;
        }
        // Frequency sentinel above the maximum so the reorder scan terminates.
        t.freq[NODES] = 0xFFFF;
        t
    }

    /// Decode one symbol (0..313) by walking from the root, MSB-first.
    ///
    /// At each internal node the two children occupy a consecutive pair
    /// `c`, `c+1`. In this LZHUF mirror layout a `0` bit selects the lower-
    /// index member `c` and a `1` bit the higher-index member `c+1`. This
    /// mapping is verified bit-exact against real StuffIt method-5 forks.
    pub fn decode_symbol<F: FnMut() -> u32>(&self, mut read_bit: F) -> Result<u16, Error> {
        let mut c = self.son[ROOT] as usize;
        let mut steps = 0usize;
        // Descend until we reach a leaf (son value >= NODES).
        loop {
            if c >= NODES {
                return Err(Error::Corrupt);
            }
            // `c` currently indexes the first child of the node we descended
            // from; pick which of the pair (c, c+1) by the bit.
            let bit = read_bit();
            let node = if bit == 0 { c } else { c + 1 };
            if node >= NODES {
                return Err(Error::Corrupt);
            }
            let s = self.son[node] as usize;
            if s >= NODES {
                // Leaf reached.
                return Ok((s - NODES) as u16);
            }
            c = s;
            steps += 1;
            if steps > NODES {
                return Err(Error::Corrupt);
            }
        }
    }

    /// Update the model after decoding `symbol`: rescale if the root
    /// frequency has saturated, then increment the path from the leaf to the
    /// root, repositioning each node to keep the array sorted by
    /// non-decreasing frequency (the sibling property).
    pub fn update(&mut self, symbol: u16) {
        if self.freq[ROOT] >= RESCALE {
            self.rebuild();
        }
        let mut c = self.leaf_index[symbol as usize] as usize;
        loop {
            self.freq[c] += 1;
            let f = self.freq[c];
            // If the next node up the array now has a smaller frequency, this
            // node must move up past the block of equal-frequency nodes.
            if c + 1 < NODES && f > self.freq[c + 1] {
                // Advance `l` past every node with strictly smaller
                // frequency; the `freq[NODES]` sentinel stops the scan.
                let mut l = c + 1;
                while f > self.freq[l + 1] {
                    l += 1;
                }
                // Swap node `c` with node `l` (block leader).
                self.swap_nodes(c, l);
                c = l;
            }
            if c == ROOT {
                break;
            }
            c = self.parent[c] as usize;
        }
    }

    /// Swap the contents of order-array slots `a` and `b` and repair the
    /// parent links of their children and the reverse leaf index.
    fn swap_nodes(&mut self, a: usize, b: usize) {
        if a == b {
            return;
        }
        self.freq.swap(a, b);
        self.son.swap(a, b);
        // Fix children's parent pointers (or the reverse leaf index) for each.
        self.fix_links(a);
        self.fix_links(b);
    }

    /// After slot `s` received new contents, re-point its children's parent
    /// links (internal node) or the reverse leaf index (leaf) at `s`.
    fn fix_links(&mut self, s: usize) {
        let son = self.son[s] as usize;
        if son >= NODES {
            // Leaf: update reverse maps.
            self.parent[son] = s as u16;
            self.leaf_index[son - NODES] = s as u16;
        } else {
            self.parent[son] = s as u16;
            self.parent[son + 1] = s as u16;
        }
    }

    /// Rebuild / rescale the tree when the root frequency saturates.
    ///
    /// Mirrors the canonical LZHUF `reconst`: collect the leaves (halving
    /// each frequency, rounding up), then rebuild the internal nodes by
    /// combining consecutive pairs and inserting each new internal node into
    /// its sorted position. On a frequency tie the new internal node is
    /// inserted *after* equal-frequency leaves (the `<=` rule of spec 7.4),
    /// because the insertion scan stops only at strictly larger frequencies.
    fn rebuild(&mut self) {
        // 1. Collect leaves to the low end, halving frequencies (round up).
        let mut j = 0usize;
        for i in 0..NODES {
            if self.son[i] as usize >= NODES {
                self.freq[j] = self.freq[i].div_ceil(2);
                self.son[j] = self.son[i];
                j += 1;
            }
        }
        debug_assert_eq!(j, SYMBOLS);

        // 2. Rebuild internal nodes. For each new internal node at slot `i`
        //    (i from SYMBOLS..NODES) combine the two lowest unused nodes at
        //    `f`, `f+1`, then slide it down into sorted position.
        let mut f = 0usize; // index of the next pair's first child
        let mut i = SYMBOLS; // slot for the next internal node
        while i < NODES {
            let sum = self.freq[f] + self.freq[f + 1];
            // Scan down from `i-1` while `sum < freq[k]`; the loop leaves `k`
            // at the first slot whose frequency is `<= sum` (or `k == 0`
            // when every lower entry is larger). Insertion position is one
            // past that slot, so equal-frequency leaves stay below the new
            // internal node (the `<=` tie rule).
            let mut k = i - 1;
            while sum < self.freq[k] {
                if k == 0 {
                    break;
                }
                k -= 1;
            }
            let insert_at = if sum < self.freq[k] { k } else { k + 1 };

            // Shift freq/son entries [insert_at .. i) up by one to open a slot.
            let mut m = i;
            while m > insert_at {
                self.freq[m] = self.freq[m - 1];
                self.son[m] = self.son[m - 1];
                m -= 1;
            }
            self.freq[insert_at] = sum;
            self.son[insert_at] = f as u16;

            f += 2;
            i += 1;
        }

        // 3. Rebuild parent links and the reverse leaf index from the new
        //    son table.
        for k in 0..SYMBOLS {
            self.leaf_index[k] = 0;
        }
        for slot in 0..NODES {
            let son = self.son[slot] as usize;
            if son >= NODES {
                self.parent[son] = slot as u16;
                self.leaf_index[son - NODES] = slot as u16;
            } else {
                self.parent[son] = slot as u16;
                self.parent[son + 1] = slot as u16;
            }
        }
        self.freq[NODES] = 0xFFFF;
    }
}
