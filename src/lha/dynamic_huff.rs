//! LHA -lh2- : LZSS + dynamic (adaptive) Huffman over an 8 KiB window.
//!
//! `-lh2-` is the LHarc 1.x-era dynamic-Huffman method that LHA kept for
//! compatibility. Its stream is continuous (no blocks, no tables): both
//! sides start from the same trees and update them identically after every
//! symbol.
//!
//! Coding, per symbol:
//! - A **char tree** over 286 symbols codes literals and match lengths.
//!   Symbols `0..256` are literal bytes; `256..285` are matches of length
//!   3..=31 (`symbol - 253`). Symbol 285 is an escape followed by 8 raw bits
//!   `d`, for a length of `32 + d` (the encoder emits at most 256).
//! - For a match, the **position tree** codes the top bits `pos >> 6` of the
//!   ring offset (`pos` = distance - 1, `0..8192`), followed by its low 6
//!   bits raw. The position tree starts with the single symbol 0 (coded in
//!   zero bits) and *grows*: before a position is coded, symbol `k` is added
//!   for every `64 * k` the output count (bytes produced before this match)
//!   has strictly passed, up to symbol 127.
//!
//! Both trees use the leader/block adaptive-Huffman update LHA uses for
//! `-lh1-`/`-lh2-` (nodes kept in non-increasing weight order from the root
//! at the lowest index, the incremented node first swapped with the leader of
//! its equal-weight block, the char tree halved and rebuilt when its root
//! reaches 0x8000, the position tree when 0x8000 positions have been coded).
//! The tree shapes, the order nodes are laid out in, and therefore every code
//! bit, depend on those exact rules, so they are reproduced precisely; the
//! ring starts filled with spaces. Code bits are MSB-first, root branch
//! first, with bit 0 selecting the even-indexed (lighter) child of a pair.
//!
//! Like `lh1`, the raw `-lh2-` stream has no in-band end marker, so the
//! decoder needs the uncompressed length out of band via
//! [`DecoderConfig::with_len`](super::DecoderConfig::with_len).
//!
//! Conformance: the format was checked against the behaviour of the LHa for
//! UNIX extractor (its `-lh2-` decoder); this crate's tests have `lha` verify
//! (`lha t`, CRC) and extract archives built from this encoder's output. No
//! current tool *creates* `-lh2-` data, so there is no third-party-encoded
//! fixture; the decoder shares every tree operation with the encoder that
//! `lha` validates.

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;
use crate::lha::bits::{BitReader, BitWriter};

// ─── LZSS parameters (8 KiB window) ──────────────────────────────────────

const DICBIT: usize = 13;
const N: usize = 1 << DICBIT; // 8192 ring buffer
const MIN_MATCH: usize = 3;
const MAXMATCH: usize = 256;

/// Char-tree alphabet size.
const N_MAX: usize = 286;
/// Escape symbol: followed by 8 raw bits extending the length.
const ESCAPE: usize = N_MAX - 1; // 285
/// `length = symbol - LEN_ADJUST` for symbols `>= 256`.
const LEN_ADJUST: usize = 256 - MIN_MATCH; // 253
/// Low position bits sent raw after the position-tree symbol.
const POS_LOW_BITS: u32 = 6;
/// Position-tree alphabet (`N >> POS_LOW_BITS`).
const NP: usize = N >> POS_LOW_BITS; // 128

const MAX_FREQ: u32 = 0x8000; // rebuild threshold for both trees

// Node layout. The char tree occupies `0..2 * N_MAX - 1` (root at 0) inside
// a slot range sized for lh1's larger 314-symbol alphabet, and the position
// tree grows upward from `ROOT_P`. The slack matters: the update rule peeks
// at the block of the node *after* the last one, which must be an unused
// slot (block 0, never allocated) rather than a live node.
const SLOTS_C: usize = 2 * 314;
const SLOTS_P: usize = 2 * NP;
const SLOTS: usize = SLOTS_C + SLOTS_P;
const ROOT_C: usize = 0;
const ROOT_P: usize = SLOTS_C;
/// `leaf[]` index of position symbol 0 (char symbols use `0..N_MAX`).
const LEAF_P: usize = 314;

// ─── adaptive Huffman trees (char + position) ────────────────────────────

/// Both adaptive trees of an lh2 stream.
///
/// Nodes are kept in non-increasing `freq` order by index from each root.
/// An internal node `v` has children `child[v]` (reached by bit 0) and
/// `child[v] - 1` (bit 1); a leaf stores `!symbol` (negative) instead.
/// Runs of equal-`freq` nodes form *blocks*: `block[v]` is the block id of
/// node `v`, `edge[b]` the leader (lowest index) of block `b`, and `stock`
/// is the pool of free block ids (`stock[avail..]`).
struct Trees {
    child: Vec<i32>,
    parent: Vec<usize>,
    block: Vec<usize>,
    edge: Vec<usize>,
    stock: Vec<usize>,
    /// Node index of each leaf symbol.
    leaf: Vec<usize>,
    freq: Vec<u32>,
    avail: usize,
    /// Positions coded since the last position-tree rebuild.
    total_p: u32,
    /// Highest node index in use by the position tree.
    most_p: usize,
    /// Output count past which the next position symbol is added.
    next_count: u64,
}

impl Trees {
    fn new() -> Self {
        let mut t = Self {
            child: vec![0; SLOTS],
            parent: vec![0; SLOTS],
            block: vec![0; SLOTS],
            edge: vec![0; SLOTS],
            // Ids >= SLOTS_C start as 0, as in the reference; with at most
            // ~830 live nodes the pool never actually reaches them.
            stock: (0..SLOTS + 2)
                .map(|i| if i < SLOTS_C { i } else { 0 })
                .collect(),
            leaf: vec![0; SLOTS / 2],
            freq: vec![0; SLOTS],
            avail: 2,
            total_p: 0,
            most_p: ROOT_P,
            next_count: 64,
        };
        t.start_c();
        t.start_p();
        t
    }

    fn new_block(&mut self) -> usize {
        let b = self.stock[self.avail];
        self.avail += 1;
        b
    }

    fn free_block(&mut self, b: usize) {
        self.avail -= 1;
        self.stock[self.avail] = b;
    }

    /// Initial char tree: all leaves weight 1, at the highest indices.
    fn start_c(&mut self) {
        let mut j = N_MAX * 2 - 2;
        for i in 0..N_MAX {
            self.freq[j] = 1;
            self.child[j] = !(i as i32);
            self.leaf[i] = j;
            self.block[j] = 1;
            j -= 1;
        }
        self.edge[1] = N_MAX - 1;
        // Internal nodes, pairing from the bottom up.
        let mut i = N_MAX * 2 - 2;
        let mut j = N_MAX as isize - 2;
        while j >= 0 {
            let ju = j as usize;
            let f = self.freq[i] + self.freq[i - 1];
            self.freq[ju] = f;
            self.child[ju] = i as i32;
            self.parent[i] = ju;
            self.parent[i - 1] = ju;
            if f == self.freq[ju + 1] {
                let b = self.block[ju + 1];
                self.block[ju] = b;
                self.edge[b] = ju;
            } else {
                let b = self.new_block();
                self.block[ju] = b;
                self.edge[b] = ju;
            }
            i -= 2;
            j -= 1;
        }
    }

    /// Initial position tree: the root is the single leaf for symbol 0.
    fn start_p(&mut self) {
        self.freq[ROOT_P] = 1;
        self.child[ROOT_P] = !(LEAF_P as i32);
        self.leaf[LEAF_P] = ROOT_P;
        let b = self.new_block();
        self.block[ROOT_P] = b;
        self.edge[b] = ROOT_P;
    }

    /// Halve the leaf weights of the tree in `start..end` and rebuild it.
    fn reconst(&mut self, start: usize, end: usize) {
        // Compact the leaves (halved, rounding up) to the front and release
        // every block.
        let mut j = start;
        let mut b = 0usize;
        for i in start..end {
            let k = self.child[i];
            if k < 0 {
                self.freq[j] = self.freq[i].div_ceil(2);
                self.child[j] = k;
                j += 1;
            }
            b = self.block[i];
            if self.edge[b] == i {
                self.free_block(b);
            }
        }
        // Rebuild from the bottom: leaves move down to their final slots and
        // each pair sum is inserted where it keeps the order non-increasing.
        let start_i = start as isize;
        let mut j = j as isize - 1;
        let mut i = end as isize - 1;
        let mut l = end as isize - 2;
        while i >= start_i {
            while i >= l {
                self.freq[i as usize] = self.freq[j as usize];
                self.child[i as usize] = self.child[j as usize];
                i -= 1;
                j -= 1;
            }
            let f = self.freq[l as usize] + self.freq[l as usize + 1];
            let mut k = start;
            while f < self.freq[k] {
                k += 1;
            }
            while j >= k as isize {
                self.freq[i as usize] = self.freq[j as usize];
                self.child[i as usize] = self.child[j as usize];
                i -= 1;
                j -= 1;
            }
            self.freq[i as usize] = f;
            self.child[i as usize] = (l + 1) as i32;
            i -= 1;
            l -= 2;
        }
        // Relink parents/leaves and regroup equal weights into blocks.
        let mut f = 0u32;
        for i in start..end {
            let c = self.child[i];
            if c < 0 {
                self.leaf[!c as usize] = i;
            } else {
                let c = c as usize;
                self.parent[c] = i;
                self.parent[c - 1] = i;
            }
            let g = self.freq[i];
            if g == f {
                self.block[i] = b;
            } else {
                b = self.new_block();
                self.block[i] = b;
                self.edge[b] = i;
                f = g;
            }
        }
    }

    /// Increment the weight of node `p` (first swapping it with its block
    /// leader), keeping the blocks consistent. Returns the parent of the
    /// node that was incremented.
    fn swap_inc(&mut self, mut p: usize) -> usize {
        let b = self.block[p];
        let q = self.edge[b];
        let join_or_split;
        if q != p {
            // Swap the subtrees at p and its leader q (equal weights).
            let r = self.child[p];
            let s = self.child[q];
            self.child[p] = s;
            self.child[q] = r;
            self.relink(r, q);
            self.relink(s, p);
            p = q;
            join_or_split = true;
        } else {
            join_or_split = b == self.block[p + 1];
        }
        if join_or_split {
            // p leaves the front of its block.
            self.edge[b] += 1;
            self.freq[p] += 1;
            if self.freq[p] == self.freq[p - 1] {
                self.block[p] = self.block[p - 1];
            } else {
                let nb = self.new_block();
                self.block[p] = nb;
                self.edge[nb] = p;
            }
        } else {
            // p was alone in its block.
            self.freq[p] += 1;
            if self.freq[p] == self.freq[p - 1] {
                self.free_block(b);
                self.block[p] = self.block[p - 1];
            }
        }
        self.parent[p]
    }

    /// Point the subtree/leaf `c` back at its new holder node `at`.
    fn relink(&mut self, c: i32, at: usize) {
        if c >= 0 {
            let c = c as usize;
            self.parent[c] = at;
            self.parent[c - 1] = at;
        } else {
            self.leaf[!c as usize] = at;
        }
    }

    fn update_c(&mut self, sym: usize) {
        if self.freq[ROOT_C] == MAX_FREQ {
            self.reconst(ROOT_C, N_MAX * 2 - 1);
        }
        self.freq[ROOT_C] += 1;
        let mut q = self.leaf[sym];
        loop {
            q = self.swap_inc(q);
            if q == ROOT_C {
                break;
            }
        }
    }

    fn update_p(&mut self, sym: usize) {
        if self.total_p == MAX_FREQ {
            self.reconst(ROOT_P, self.most_p + 1);
            self.total_p = self.freq[ROOT_P];
            self.freq[ROOT_P] = 0xFFFF;
        }
        let mut q = self.leaf[sym + LEAF_P];
        while q != ROOT_P {
            q = self.swap_inc(q);
        }
        self.total_p += 1;
    }

    /// Add position symbol `sym`: the current lowest leaf `most_p` becomes
    /// an internal node whose children are that leaf (moved down one slot)
    /// and the new weight-0 leaf, which is then counted once.
    fn make_new_node(&mut self, sym: usize) {
        let mp = self.most_p;
        let r = mp + 1;
        let q = r + 1;
        self.child[r] = self.child[mp];
        self.leaf[!self.child[r] as usize] = r;
        self.child[q] = !((sym + LEAF_P) as i32);
        self.child[mp] = q as i32;
        self.freq[r] = self.freq[mp];
        self.freq[q] = 0;
        self.block[r] = self.block[mp];
        if mp == ROOT_P {
            self.freq[ROOT_P] = 0xFFFF;
            let b = self.block[ROOT_P];
            self.edge[b] += 1;
        }
        self.parent[r] = mp;
        self.parent[q] = mp;
        let b = self.new_block();
        self.block[q] = b;
        self.edge[b] = q;
        self.leaf[sym + LEAF_P] = q;
        self.most_p = q;
        self.update_p(sym);
    }

    /// Grow the position tree for an output count of `count` bytes.
    fn grow_p(&mut self, count: u64) {
        while count > self.next_count {
            self.make_new_node((self.next_count / 64) as usize);
            self.next_count += 64;
            if self.next_count >= N as u64 {
                self.next_count = u64::MAX;
            }
        }
    }

    /// Walk from `root` to a leaf by input bits; returns the leaf's `leaf[]`
    /// index.
    fn walk(&self, root: usize, br: &mut BitReader<'_>) -> Result<usize, Error> {
        let mut c = self.child[root];
        let mut depth = 0usize;
        while c > 0 {
            let bit = br.get_bits(1) as usize;
            c = self.child[c as usize - bit];
            depth += 1;
            if depth > SLOTS {
                return Err(Error::Corrupt);
            }
        }
        Ok(!c as usize)
    }

    /// Emit the root-first code of the leaf at node `node` in the tree
    /// rooted at `root`. Bit = node index parity (odd = second child).
    fn put_code(&self, bw: &mut BitWriter, root: usize, mut node: usize) {
        let mut bits: Vec<u8> = Vec::with_capacity(32);
        while node != root {
            bits.push((node & 1) as u8);
            node = self.parent[node];
        }
        for &b in bits.iter().rev() {
            bw.put_bits(1, b as u32);
        }
    }

    fn decode_c(&mut self, br: &mut BitReader<'_>) -> Result<usize, Error> {
        let sym = self.walk(ROOT_C, br)?;
        if sym >= N_MAX {
            return Err(Error::Corrupt);
        }
        self.update_c(sym);
        if sym == ESCAPE {
            return Ok(sym + br.get_bits(8) as usize);
        }
        Ok(sym)
    }

    fn encode_c(&mut self, bw: &mut BitWriter, code: usize) {
        let sym = code.min(ESCAPE);
        self.put_code(bw, ROOT_C, self.leaf[sym]);
        if sym == ESCAPE {
            bw.put_bits(8, (code - ESCAPE) as u32);
        }
        self.update_c(sym);
    }

    /// Decode a ring offset (`distance - 1`) for a match starting after
    /// `count` output bytes.
    fn decode_p(&mut self, br: &mut BitReader<'_>, count: u64) -> Result<usize, Error> {
        self.grow_p(count);
        let sym = self
            .walk(ROOT_P, br)?
            .checked_sub(LEAF_P)
            .filter(|&s| s < NP)
            .ok_or(Error::Corrupt)?;
        self.update_p(sym);
        Ok((sym << POS_LOW_BITS) | br.get_bits(POS_LOW_BITS) as usize)
    }

    /// Encode ring offset `pos` (`< count`, so its symbol already exists).
    fn encode_p(&mut self, bw: &mut BitWriter, count: u64, pos: usize) {
        self.grow_p(count);
        let sym = pos >> POS_LOW_BITS;
        self.put_code(bw, ROOT_P, self.leaf[sym + LEAF_P]);
        self.update_p(sym);
        bw.put_bits(POS_LOW_BITS, (pos & ((1 << POS_LOW_BITS) - 1)) as u32);
    }
}

// ─── decoder ─────────────────────────────────────────────────────────────

/// Decode an lh2 payload (length header already stripped) of declared length
/// `expected`.
pub fn decode_payload(payload: &[u8], expected: usize) -> Result<Vec<u8>, Error> {
    let mut out: Vec<u8> = Vec::with_capacity(expected.min(1 << 20));
    if expected == 0 {
        return Ok(out);
    }

    let mut trees = Trees::new();
    let mut ring = vec![b' '; N];
    let mut r = 0usize;
    let mut br = BitReader::new(payload);

    while out.len() < expected {
        let c = trees.decode_c(&mut br)?;
        if br.overran() {
            return Err(Error::UnexpectedEnd);
        }
        if c < 256 {
            out.push(c as u8);
            ring[r] = c as u8;
            r = (r + 1) & (N - 1);
        } else {
            // Escaped lengths reach 287; the reference decoder accepts them.
            let len = c - LEN_ADJUST;
            let pos = trees.decode_p(&mut br, out.len() as u64)?;
            if br.overran() {
                return Err(Error::UnexpectedEnd);
            }
            let src0 = (r + N - pos - 1) & (N - 1);
            for k in 0..len {
                if out.len() >= expected {
                    break;
                }
                let b = ring[(src0 + k) & (N - 1)];
                out.push(b);
                ring[r] = b;
                r = (r + 1) & (N - 1);
            }
        }
    }
    Ok(out)
}

// ─── encoder ─────────────────────────────────────────────────────────────

/// Encode `data` into an lh2 payload (no length header).
pub fn encode_payload(data: &[u8]) -> Vec<u8> {
    let mut bw = BitWriter::new();
    if data.is_empty() {
        return bw.finish();
    }

    let mut trees = Trees::new();
    let mut count = 0u64;
    for t in lz_parse(data) {
        match t {
            Tok::Lit(b) => {
                trees.encode_c(&mut bw, b as usize);
                count += 1;
            }
            Tok::Match { len, pos } => {
                trees.encode_c(&mut bw, len + LEN_ADJUST);
                trees.encode_p(&mut bw, count, pos);
                count += len as u64;
            }
        }
    }
    bw.finish()
}

enum Tok {
    Lit(u8),
    Match { len: usize, pos: usize },
}

/// Greedy LZSS parse producing distance-based positions (`pos` = distance-1
/// in `0..N`), mirroring the decoder's `src = r - pos - 1`.
fn lz_parse(data: &[u8]) -> Vec<Tok> {
    let n = data.len();
    let mut tokens = Vec::new();

    const HASH_BITS: u32 = 15;
    const HASH_SIZE: usize = 1 << HASH_BITS;
    let mut head = vec![usize::MAX; HASH_SIZE];
    let mut prev = vec![usize::MAX; n];

    let hash3 = |d: &[u8], i: usize| -> usize {
        let a = d[i] as usize;
        let b = d[i + 1] as usize;
        let c = d[i + 2] as usize;
        ((a << 10) ^ (b << 5) ^ c).wrapping_mul(2654435761) >> (32 - HASH_BITS) & (HASH_SIZE - 1)
    };

    let max_chain = 128usize;
    let mut i = 0usize;
    while i < n {
        let mut best_len = 0usize;
        let mut best_pos = 0usize;
        if i + MIN_MATCH <= n {
            let h = hash3(data, i);
            let mut cand = head[h];
            let mut chain = 0usize;
            let max_match = MAXMATCH.min(n - i);
            let min_pos = i.saturating_sub(N);
            while cand != usize::MAX && cand >= min_pos && chain < max_chain {
                let mut l = 0usize;
                while l < max_match && data[cand + l] == data[i + l] {
                    l += 1;
                }
                if l > best_len {
                    best_len = l;
                    best_pos = i - cand - 1; // distance - 1
                    if l >= max_match {
                        break;
                    }
                }
                cand = prev[cand];
                chain += 1;
            }
        }

        if best_len >= MIN_MATCH {
            tokens.push(Tok::Match {
                len: best_len,
                pos: best_pos,
            });
            let end = i + best_len;
            while i < end {
                if i + MIN_MATCH <= n {
                    let h = hash3(data, i);
                    prev[i] = head[h];
                    head[h] = i;
                }
                i += 1;
            }
        } else {
            tokens.push(Tok::Lit(data[i]));
            if i + MIN_MATCH <= n {
                let h = hash3(data, i);
                prev[i] = head[h];
                head[h] = i;
            }
            i += 1;
        }
    }
    tokens
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(data: &[u8]) {
        let enc = encode_payload(data);
        let dec = decode_payload(&enc, data.len()).unwrap();
        assert_eq!(dec, data, "round-trip mismatch ({} bytes)", data.len());
    }

    #[test]
    fn round_trips() {
        round_trip(b"");
        round_trip(b"a");
        round_trip(b"abracadabra abracadabra abracadabra");
        round_trip(&[0u8; 1000]);
        let mut v = Vec::new();
        for i in 0..5000u32 {
            v.push((i.wrapping_mul(2654435761) >> 13) as u8);
        }
        round_trip(&v);
        // long run to exercise 256-byte matches over the 8 KiB window
        round_trip(&b"xyz".repeat(4000));
        // > 0x8000 symbols and positions: both trees get rebuilt
        let mut w = Vec::new();
        for i in 0..60_000u32 {
            w.extend_from_slice(&((i * 7919) % 1013).to_le_bytes()[..2]);
        }
        round_trip(&w);
    }

    #[test]
    fn first_position_costs_no_tree_bits() {
        // Until more than 64 bytes have been produced the position tree is a
        // single leaf, so a position is just its 6 raw low bits.
        let mut trees = Trees::new();
        let mut bw = BitWriter::new();
        trees.encode_p(&mut bw, 10, 5);
        assert_eq!(bw.finish(), [5 << 2]);
    }

    #[test]
    fn garbage_never_panics() {
        let mut seed = 0x1234_5678u32;
        for n in [1usize, 7, 64, 1000, 20_000, 200_000] {
            let junk: Vec<u8> = (0..n)
                .map(|_| {
                    seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                    (seed >> 16) as u8
                })
                .collect();
            let _ = decode_payload(&junk, n * 8);
        }
    }
}
