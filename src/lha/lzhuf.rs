//! LHA -lh1- : LZSS + adaptive (dynamic) Huffman — the classic LZHUF
//! scheme of Yoshizaki & Okumura.
//!
//! The literal/length alphabet (314 symbols: 256 byte literals + 58 copy
//! codes, giving matches of length 3..=60 over a 4 KiB ring) is coded with
//! an adaptive Huffman tree that both sides update identically after every
//! symbol. Positions use a *fixed* code: the top bits select an offset
//! bucket via a small generated table, then six low bits complete the
//! 12-bit ring position.
//!
//! Clean-room from the public-domain LZHUF description (Okumura placed the
//! algorithm in the public domain; the adaptive-tree update and the
//! position-bucket distribution are reproduced from the documented format,
//! not copied from any licensed source). Both an encoder and decoder are
//! provided so streams round-trip through this crate.

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;
use crate::lha::bits::{BitReader, BitWriter};

// ─── LZSS parameters ─────────────────────────────────────────────────────

const N: usize = 4096; // ring buffer size
const F: usize = 60; // max match length
const THRESHOLD: usize = 2; // matches of length <= THRESHOLD are literals
const MIN_MATCH: usize = THRESHOLD + 1; // 3
const NUM_CHAR: usize = 256 - THRESHOLD + F; // 314 leaf symbols

// ─── adaptive-Huffman parameters ─────────────────────────────────────────

const T: usize = NUM_CHAR * 2 - 1; // 627 tree nodes
const ROOT: usize = T - 1; // root index
const MAX_FREQ: u32 = 0x8000; // tree rebuild threshold

/// Offset bucket distribution: number of buckets at each high-bit code
/// length 3..=8. Sums to 64. Used to generate the fixed position tables.
const P_DIST: [usize; 6] = [1, 3, 8, 12, 24, 16];

/// Generate the position decode/encode tables, clean-room from the bucket
/// distribution. Returns `(p_len[64], p_code[64], d_code[256], d_len[256])`
/// where `d_code`/`d_len` map a peeked top byte to its bucket index and
/// high-bit length, and `p_len`/`p_code` are the encoder's per-bucket code.
fn build_pos_tables() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    // d_code[i] = bucket for top byte i; d_len[i] = number of high bits.
    let mut d_code = vec![0u8; 256];
    let mut d_len = vec![0u8; 256];
    // p_len[bucket] = number of high bits for that bucket;
    // p_code[bucket] = the canonical high-bit code (MSB-aligned in 8 bits).
    let mut p_len = vec![0u8; 64];
    let mut p_code = vec![0u8; 64];

    let mut bucket = 0usize;
    let mut top = 0usize; // running top-byte value
    let mut code_val = 0u32; // canonical code accumulator (in `bits` space)
    for (k, &count) in P_DIST.iter().enumerate() {
        let bits = (k + 3) as u8; // code length 3..=8
        for _ in 0..count {
            // This bucket occupies `1 << (8 - bits)` top-byte slots.
            let span = 1usize << (8 - bits as usize);
            for _ in 0..span {
                if top < 256 {
                    d_code[top] = bucket as u8;
                    d_len[top] = bits;
                    top += 1;
                }
            }
            p_len[bucket] = bits;
            // The high-bit code is the top `bits` bits of `code_val`
            // shifted to occupy the MSB side of an 8-bit field.
            p_code[bucket] = (code_val << (8 - bits as u32)) as u8;
            code_val += 1;
            bucket += 1;
        }
        // Moving to the next (longer) length doubles the code space.
        code_val <<= 1;
    }
    (p_len, p_code, d_code, d_len)
}

// ─── adaptive Huffman tree (shared by encoder and decoder) ───────────────

/// Adaptive Huffman tree using Okumura's classic node layout, where
/// `son[node]` is the index of the node's left child and the right child
/// is `son[node] + 1`. A node `v` is a leaf when `son[v] >= T`, in which
/// case its symbol is `son[v] - T`. `prnt[v]` is the parent of node `v`
/// for `v < T`; for leaf back-references, `prnt[symbol + T]` gives the
/// node index that holds that leaf.
struct Tree {
    freq: Vec<u32>,   // [T + 1] (extra sentinel slot)
    son: Vec<usize>,  // [T]
    prnt: Vec<usize>, // [T + NUM_CHAR]
}

impl Tree {
    fn new() -> Self {
        let mut freq = vec![0u32; T + 1];
        let mut son = vec![0usize; T];
        let mut prnt = vec![0usize; T + NUM_CHAR];

        // Leaves occupy nodes 0..NUM_CHAR: freq 1, son points past T.
        for i in 0..NUM_CHAR {
            freq[i] = 1;
            son[i] = i + T;
            prnt[i + T] = i;
        }
        // Internal nodes NUM_CHAR..=ROOT built by pairing consecutive
        // lower nodes.
        let mut i = 0usize;
        let mut j = NUM_CHAR;
        while j <= ROOT {
            freq[j] = freq[i] + freq[i + 1];
            son[j] = i;
            prnt[i] = j;
            prnt[i + 1] = j;
            i += 2;
            j += 1;
        }
        freq[T] = 0xFFFF;
        prnt[ROOT] = 0;
        Self { freq, son, prnt }
    }

    /// Rebuild the tree, halving frequencies, when the root count
    /// saturates. Clean-room reimplementation of the documented
    /// `reconst` procedure.
    fn reconstruct(&mut self) {
        // Gather leaf nodes to the front, halving frequencies.
        let mut j = 0usize;
        for i in 0..T {
            if self.son[i] >= T {
                self.freq[j] = self.freq[i].div_ceil(2);
                self.son[j] = self.son[i];
                j += 1;
            }
        }
        // Rebuild internal nodes by summing pairs and inserting at the
        // sorted position (shifting freq[]/son[] up to make room).
        let mut i = 0usize;
        for j in NUM_CHAR..T {
            let f = self.freq[i] + self.freq[i + 1];
            // Find insertion point `k`: smallest index in [NUM_CHAR..j]
            // whose freq is >= f, scanning downward.
            let mut k = j;
            while k > 0 && self.freq[k - 1] > f {
                k -= 1;
            }
            // Shift [k..j) up by one.
            let mut m = j;
            while m > k {
                self.freq[m] = self.freq[m - 1];
                self.son[m] = self.son[m - 1];
                m -= 1;
            }
            self.freq[k] = f;
            self.son[k] = i;
            i += 2;
        }
        // Reconnect parent pointers.
        for i in 0..T {
            let s = self.son[i];
            if s >= T {
                self.prnt[s] = i;
            } else {
                self.prnt[s] = i;
                self.prnt[s + 1] = i;
            }
        }
    }

    /// Increment the frequency of the leaf for symbol `c` and restore the
    /// sibling-property ordering up to the root.
    fn update(&mut self, c: usize) {
        if self.freq[ROOT] >= MAX_FREQ {
            self.reconstruct();
        }
        let mut node = self.prnt[c + T];
        loop {
            self.freq[node] += 1;
            let f = self.freq[node];
            // If `node` now outranks its successor, move it up past every
            // node of smaller frequency, then swap.
            if node < ROOT && f > self.freq[node + 1] {
                let mut l = node + 1;
                while l < ROOT && f > self.freq[l + 1] {
                    l += 1;
                }
                self.freq[node] = self.freq[l];
                self.freq[l] = f;

                let sn = self.son[node];
                let sl = self.son[l];
                // Re-parent children of the swapped nodes.
                self.prnt[sl] = node;
                if sl < T {
                    self.prnt[sl + 1] = node;
                }
                self.prnt[sn] = l;
                if sn < T {
                    self.prnt[sn + 1] = l;
                }
                self.son[node] = sl;
                self.son[l] = sn;

                node = l;
            }
            node = self.prnt[node];
            if node == 0 {
                break;
            }
        }
    }
}

// ─── decoder ─────────────────────────────────────────────────────────────

/// Decode an lh1 payload (length header already stripped) of declared
/// length `expected`.
pub fn decode_payload(payload: &[u8], expected: usize) -> Result<Vec<u8>, Error> {
    let mut out: Vec<u8> = Vec::with_capacity(expected.min(1 << 20));
    if expected == 0 {
        return Ok(out);
    }

    let (_p_len, _p_code, d_code, d_len) = build_pos_tables();
    let mut tree = Tree::new();
    let mut ring = vec![b' '; N];
    let mut r = N - F;
    let mut br = BitReader::new(payload);

    while out.len() < expected {
        let c = decode_char(&mut tree, &mut br)?;
        if br.overran() {
            return Err(Error::UnexpectedEnd);
        }
        if c < 256 {
            out.push(c as u8);
            ring[r] = c as u8;
            r = (r + 1) & (N - 1);
        } else {
            let pos = decode_position(&mut br, &d_code, &d_len)?;
            if br.overran() {
                return Err(Error::UnexpectedEnd);
            }
            let len = c - 255 + THRESHOLD; // c - 256 + MIN_MATCH
            if len > F {
                return Err(Error::Corrupt);
            }
            // Source index = (r - pos - 1) in the ring.
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

fn decode_char(tree: &mut Tree, br: &mut BitReader<'_>) -> Result<usize, Error> {
    // Start at the root's left child; descend by adding the next bit to
    // the node index and following `son[]`, until a leaf (>= T) is hit.
    let mut c = tree.son[ROOT];
    let mut guard = 0usize;
    while c < T {
        let bit = br.get_bits(1) as usize;
        let idx = c + bit;
        if idx >= T {
            return Err(Error::Corrupt);
        }
        c = tree.son[idx];
        guard += 1;
        if guard > T {
            return Err(Error::Corrupt);
        }
    }
    let sym = c - T;
    if sym >= NUM_CHAR {
        return Err(Error::Corrupt);
    }
    tree.update(sym);
    Ok(sym)
}

/// Decode a 12-bit position: read 8 bits to find the high-bit bucket, take
/// the bucket's high value, consume the bucket's bit length, then read 6
/// low bits.
fn decode_position(br: &mut BitReader<'_>, d_code: &[u8], d_len: &[u8]) -> Result<usize, Error> {
    let top = br.peek_bits(8) as usize;
    let bucket = d_code[top] as usize;
    let len = d_len[top] as u32;
    br.consume(len);
    // High 6 bits of the position come from the bucket index.
    let high = bucket << 6;
    let low = br.get_bits(6) as usize;
    Ok(high | low)
}

// ─── encoder ─────────────────────────────────────────────────────────────

/// Encode `data` into an lh1 payload (no length header).
pub fn encode_payload(data: &[u8]) -> Vec<u8> {
    let mut bw = BitWriter::new();
    if data.is_empty() {
        return bw.finish();
    }

    let (p_len, p_code, _d_code, _d_len) = build_pos_tables();
    let mut tree = Tree::new();

    // Greedy LZSS parse over a 4 KiB window (distance-based positions).
    let tokens = lz_parse(data);
    for t in &tokens {
        match *t {
            Tok::Lit(b) => {
                encode_char(&mut tree, &mut bw, b as usize);
            }
            Tok::Match { len, pos } => {
                let code = 256 + (len - MIN_MATCH);
                encode_char(&mut tree, &mut bw, code);
                encode_position(&mut bw, pos, &p_len, &p_code);
            }
        }
    }
    bw.finish()
}

enum Tok {
    Lit(u8),
    Match { len: usize, pos: usize },
}

fn encode_char(tree: &mut Tree, bw: &mut BitWriter, c: usize) {
    // Walk from the leaf's containing node up to the root, collecting the
    // branch bit at each step. The decoder descends via `c = son[c+bit]`,
    // so the bit from parent `p` to child node `k` is `k - son[p]` (0 for
    // the left child, 1 for the right). We collect bits leaf->root (which
    // is LSB-first relative to the code) then emit them MSB-first.
    let mut path: [u8; T] = [0u8; T];
    let mut depth = 0usize;
    let mut k = tree.prnt[c + T]; // leaf's node index (< T)
    loop {
        let p = tree.prnt[k];
        let bit = (k - tree.son[p]) as u8; // 0 or 1
        path[depth] = bit;
        depth += 1;
        if p == ROOT {
            break;
        }
        k = p;
        if depth >= T {
            break;
        }
    }
    // Emit root-first: the last bit collected is the edge below the root.
    for d in (0..depth).rev() {
        bw.put_bits(1, path[d] as u32);
    }
    tree.update(c);
}

fn encode_position(bw: &mut BitWriter, pos: usize, p_len: &[u8], p_code: &[u8]) {
    let bucket = (pos >> 6) & 0x3F;
    let bits = p_len[bucket] as u32;
    let code = (p_code[bucket] as u32) >> (8 - bits); // right-align high code
    bw.put_bits(bits, code);
    bw.put_bits(6, (pos & 0x3F) as u32);
}

/// Greedy LZSS parse producing distance-based positions (`pos` = distance
/// minus 1, in `0..N`). Mirrors the decoder's `src = r - pos - 1`.
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
            let max_match = F.min(n - i);
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
