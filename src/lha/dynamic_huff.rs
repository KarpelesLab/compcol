//! LHA -lh2- : LZSS + dynamic (adaptive) Huffman over an 8 KiB window.
//!
//! `-lh2-` is the transitional LHA method: it keeps the adaptive-Huffman
//! literal/length coding of [`lh1`](super::lzhuf) but enlarges the window to
//! 8 KiB (13-bit positions, matches up to 256 bytes) **and** codes the match
//! *position* with a second adaptive Huffman tree rather than lh1's fixed
//! position buckets. Both sides update both trees identically after every
//! symbol, so no tables are carried in the stream.
//!
//! Coding, per symbol:
//! - A literal/length symbol from the **char tree** (alphabet `NC` = 510:
//!   256 byte literals + 254 length codes for match lengths 3..=256). Symbol
//!   `< 256` is a literal; `256 + (len - MIN_MATCH)` is a match of that length.
//! - For a match, a **position-class** symbol `p` from the **position tree**
//!   (alphabet `NP` = 14), where `p` is the number of significant bits of the
//!   ring distance-1. For `p >= 2`, the low `p - 1` bits follow raw.
//!
//! Like `lh1`, the raw `-lh2-` stream is continuous and size-terminated (no
//! in-band end marker), so the decoder needs the uncompressed length out of
//! band via [`DecoderConfig::with_len`](super::DecoderConfig::with_len).
//!
//! Clean-room from the public LHA dynamic-Huffman *description* (the adaptive
//! sibling-property tree is Okumura's documented, public-domain `reconst` /
//! `update` procedure; the 8 KiB window, 256-byte match limit, and dynamic
//! position-class tree are reproduced from the format description, not copied
//! from any licensed source). Validated by this crate's own encoder/decoder
//! round-trip — there is no public `-lh2-` reference fixture (no mainstream
//! tool emits the method), so bit-exact interop with archives in the wild is
//! best-effort.

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
/// Char-tree alphabet: 256 literals + (MAXMATCH - MIN_MATCH + 1) length codes.
const NC: usize = 256 + (MAXMATCH - MIN_MATCH + 1); // 510
/// Position-tree alphabet: bit-length classes 0..=DICBIT.
const NP: usize = DICBIT + 1; // 14

const MAX_FREQ: u32 = 0x8000; // adaptive-tree rebuild threshold

// ─── generalized adaptive Huffman tree ───────────────────────────────────

/// Adaptive Huffman tree (Okumura's sibling-property layout, parameterized by
/// alphabet size). `son[v]` is the left child of internal node `v`, the right
/// child is `son[v] + 1`; a node is a leaf when `son[v] >= t`, with symbol
/// `son[v] - t`. `prnt[v]` is the parent; `prnt[symbol + t]` locates a leaf.
///
/// This is the same machinery as [`super::lzhuf::Tree`] but with a runtime
/// alphabet size so both the 510-symbol char tree and the 14-symbol position
/// tree share one implementation.
struct AdaptiveTree {
    t: usize,    // 2 * n_char - 1 internal+leaf nodes
    root: usize, // t - 1
    n_char: usize,
    freq: Vec<u32>,
    son: Vec<usize>,
    prnt: Vec<usize>,
}

impl AdaptiveTree {
    fn new(n_char: usize) -> Self {
        let t = n_char * 2 - 1;
        let root = t - 1;
        let mut freq = vec![0u32; t + 1];
        let mut son = vec![0usize; t];
        let mut prnt = vec![0usize; t + n_char];

        for i in 0..n_char {
            freq[i] = 1;
            son[i] = i + t;
            prnt[i + t] = i;
        }
        let mut i = 0usize;
        let mut j = n_char;
        while j <= root {
            freq[j] = freq[i] + freq[i + 1];
            son[j] = i;
            prnt[i] = j;
            prnt[i + 1] = j;
            i += 2;
            j += 1;
        }
        freq[t] = 0xFFFF;
        prnt[root] = 0;
        Self {
            t,
            root,
            n_char,
            freq,
            son,
            prnt,
        }
    }

    fn reconstruct(&mut self) {
        let t = self.t;
        let n_char = self.n_char;
        // Collect leaves to the front, halving frequencies.
        let mut j = 0usize;
        for i in 0..t {
            if self.son[i] >= t {
                self.freq[j] = self.freq[i].div_ceil(2);
                self.son[j] = self.son[i];
                j += 1;
            }
        }
        // Rebuild internal nodes, inserting each pair-sum at its sorted spot.
        let mut i = 0usize;
        for j in n_char..t {
            let f = self.freq[i] + self.freq[i + 1];
            let mut k = j;
            while k > 0 && self.freq[k - 1] > f {
                k -= 1;
            }
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
        for i in 0..t {
            let s = self.son[i];
            self.prnt[s] = i;
            if s < t {
                self.prnt[s + 1] = i;
            }
        }
    }

    fn update(&mut self, c: usize) {
        if self.freq[self.root] >= MAX_FREQ {
            self.reconstruct();
        }
        let mut node = self.prnt[c + self.t];
        loop {
            self.freq[node] += 1;
            let f = self.freq[node];
            if node < self.root && f > self.freq[node + 1] {
                let mut l = node + 1;
                while l < self.root && f > self.freq[l + 1] {
                    l += 1;
                }
                self.freq[node] = self.freq[l];
                self.freq[l] = f;

                let sn = self.son[node];
                let sl = self.son[l];
                self.prnt[sl] = node;
                if sl < self.t {
                    self.prnt[sl + 1] = node;
                }
                self.prnt[sn] = l;
                if sn < self.t {
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

    /// Decode one symbol, descending from the root by branch bits, then
    /// update the tree.
    fn decode(&mut self, br: &mut BitReader<'_>) -> Result<usize, Error> {
        let mut c = self.son[self.root];
        let mut guard = 0usize;
        while c < self.t {
            let bit = br.get_bits(1) as usize;
            let idx = c + bit;
            if idx >= self.t {
                return Err(Error::Corrupt);
            }
            c = self.son[idx];
            guard += 1;
            if guard > self.t {
                return Err(Error::Corrupt);
            }
        }
        let sym = c - self.t;
        if sym >= self.n_char {
            return Err(Error::Corrupt);
        }
        self.update(sym);
        Ok(sym)
    }

    /// Encode one symbol (root-first branch bits), then update the tree.
    fn encode(&mut self, bw: &mut BitWriter, c: usize) {
        let mut path: Vec<u8> = Vec::with_capacity(32);
        let mut k = self.prnt[c + self.t];
        loop {
            let p = self.prnt[k];
            path.push((k - self.son[p]) as u8);
            if p == self.root {
                break;
            }
            k = p;
            if path.len() >= self.t {
                break;
            }
        }
        for &bit in path.iter().rev() {
            bw.put_bits(1, bit as u32);
        }
        self.update(c);
    }
}

// ─── position bit-length class ───────────────────────────────────────────

/// Number of significant bits of `pos` (0 for `pos == 0`). This is the
/// position-tree symbol; `pos` itself is recovered from the class plus
/// `class - 1` low bits.
fn pos_class(pos: usize) -> usize {
    // pos < N = 2^13, so the class is at most DICBIT.
    (usize::BITS - pos.leading_zeros()) as usize
}

// ─── decoder ─────────────────────────────────────────────────────────────

/// Decode an lh2 payload (length header already stripped) of declared length
/// `expected`.
pub fn decode_payload(payload: &[u8], expected: usize) -> Result<Vec<u8>, Error> {
    let mut out: Vec<u8> = Vec::with_capacity(expected.min(1 << 20));
    if expected == 0 {
        return Ok(out);
    }

    let mut ctree = AdaptiveTree::new(NC);
    let mut ptree = AdaptiveTree::new(NP);
    let mut ring = vec![b' '; N];
    let mut r = 0usize;
    let mut br = BitReader::new(payload);

    while out.len() < expected {
        let c = ctree.decode(&mut br)?;
        if br.overran() {
            return Err(Error::UnexpectedEnd);
        }
        if c < 256 {
            out.push(c as u8);
            ring[r] = c as u8;
            r = (r + 1) & (N - 1);
        } else {
            let len = (c - 256) + MIN_MATCH;
            if len > MAXMATCH {
                return Err(Error::Corrupt);
            }
            let pos = decode_position(&mut ptree, &mut br)?;
            if br.overran() {
                return Err(Error::UnexpectedEnd);
            }
            if pos >= N {
                return Err(Error::Corrupt);
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

/// Decode a position: a bit-length class from the adaptive position tree,
/// then `class - 1` low bits (none for class 0 or 1).
fn decode_position(ptree: &mut AdaptiveTree, br: &mut BitReader<'_>) -> Result<usize, Error> {
    let class = ptree.decode(br)?;
    if class == 0 {
        return Ok(0);
    }
    if class == 1 {
        return Ok(1);
    }
    let low = br.get_bits((class - 1) as u32) as usize;
    Ok((1usize << (class - 1)) | low)
}

// ─── encoder ─────────────────────────────────────────────────────────────

/// Encode `data` into an lh2 payload (no length header).
pub fn encode_payload(data: &[u8]) -> Vec<u8> {
    let mut bw = BitWriter::new();
    if data.is_empty() {
        return bw.finish();
    }

    let mut ctree = AdaptiveTree::new(NC);
    let mut ptree = AdaptiveTree::new(NP);

    for t in lz_parse(data) {
        match t {
            Tok::Lit(b) => ctree.encode(&mut bw, b as usize),
            Tok::Match { len, pos } => {
                ctree.encode(&mut bw, 256 + (len - MIN_MATCH));
                encode_position(&mut ptree, &mut bw, pos);
            }
        }
    }
    bw.finish()
}

fn encode_position(ptree: &mut AdaptiveTree, bw: &mut BitWriter, pos: usize) {
    let class = pos_class(pos);
    ptree.encode(bw, class);
    if class >= 2 {
        bw.put_bits((class - 1) as u32, (pos & ((1 << (class - 1)) - 1)) as u32);
    }
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
    }

    #[test]
    fn pos_class_is_significant_bits() {
        assert_eq!(pos_class(0), 0);
        assert_eq!(pos_class(1), 1);
        assert_eq!(pos_class(2), 2);
        assert_eq!(pos_class(3), 2);
        assert_eq!(pos_class(8191), 13);
    }
}
