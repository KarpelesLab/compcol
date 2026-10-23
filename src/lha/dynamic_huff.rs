//! LHA -lh2- : LZSS + dynamic (adaptive) Huffman over an 8 KiB window.
//!
//! `-lh2-` is the transitional LHA method between `lh1` and the static
//! `lh4`..`lh7` family. Like [`lh1`](super::lzhuf) it codes literals and
//! match lengths with an adaptive Huffman tree that both sides update after
//! every symbol, but it enlarges the window to 8 KiB and codes the match
//! position with a second adaptive tree that *grows* as output accumulates.
//! No tables are carried in the stream.
//!
//! Coding, per token (bits MSB-first, no blocks, no end marker):
//! - The **C-tree** (286 symbols): `0..=255` is a literal byte, `256..=284`
//!   a match of length `symbol - 253` (3..=31), and `285` an *escape*: a
//!   match of length `32 + x`, with `x` in the next 8 raw bits.
//! - For a match, the **P-tree** codes the high bits `P >> 6` of the
//!   position `P = distance - 1`, then 6 raw bits give `P & 63`. The P-tree
//!   starts with the single symbol 0 (a 0-bit code) and gains symbol `k`
//!   once more than `64 * k` bytes have been output, so it always covers
//!   every distance into real data (up to the full 8 KiB, 128 symbols).
//!
//! The window starts filled with spaces, so a distance beyond the bytes
//! output so far copies spaces. The decoder accepts lengths up to 287 (the
//! escape's range); the encoder caps them at 256, as LHA encoders do, and
//! never reaches into the initial spaces.
//!
//! Both trees are kept in an array of slots ordered by non-increasing weight
//! (the sibling property). An update walks from the coded leaf to the root,
//! swapping each node with the lowest-numbered slot of equal weight before
//! incrementing it; a tree whose total weight reaches 32768 is rebuilt with
//! halved weights. The P-tree has two quirks the format depends on: its root
//! carries a sentinel weight, and its rebuild is triggered by a separate
//! update counter that, before the first rebuild, runs ahead of the true
//! weight total (positions coded while the tree is a single leaf change no
//! weight).
//!
//! Like `lh1`, the raw `-lh2-` stream is continuous and size-terminated, so
//! the decoder needs the uncompressed length out of band via
//! [`DecoderConfig::with_len`](super::DecoderConfig::with_len).
//!
//! Implemented clean-room from a written functional specification of the
//! format, and validated black-box against the LHa for UNIX decoder (see
//! the [module docs](super)).

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;
use crate::lha::bits::{BitReader, BitWriter};

// ─── LZSS parameters (8 KiB window) ──────────────────────────────────────

const N: usize = 1 << 13; // 8192 ring buffer
const MIN_MATCH: usize = 3;
/// Longest match the encoder emits (the decoder accepts up to 287).
const MAXMATCH: usize = 256;

// ─── tree parameters ─────────────────────────────────────────────────────

/// C-tree alphabet: 256 literals, 29 direct lengths (3..=31), the escape.
const NC: usize = 286;
/// C-tree escape symbol: a match of `32 + x` with `x` in 8 raw bits.
const ESCAPE: usize = NC - 1;
/// P-tree alphabet: the high 7 bits of a 13-bit position.
const NP: usize = N >> 6; // 128
/// Rebuild threshold: C-tree root weight, P-tree update counter.
const MAX_FREQ: u32 = 0x8000;
/// P-tree root weight: never equal to any other slot's weight.
const SENTINEL: u32 = 0xFFFF;

/// `content` tag marking a slot as a leaf (low bits are the symbol).
const LEAF: u16 = 0x8000;

// ─── adaptive Huffman tree ───────────────────────────────────────────────

/// Adaptive Huffman tree stored as an array of slots, slot 0 the root.
///
/// `content[x]` is either `LEAF | symbol` or the even slot `e` of an
/// internal node's children: slot `e` is reached by bit 0 and slot `e - 1`
/// by bit 1, so a slot's branch bit is its parity. Apart from the root,
/// weights never increase with the slot number; equal weights form a
/// contiguous run whose lowest slot is the run's *leader*.
struct Tree {
    /// Slots in use (`2 * leaves - 1`).
    slots: usize,
    weight: Vec<u32>,
    content: Vec<u16>,
    /// Parent slot of each non-root slot.
    parent: Vec<u16>,
    /// Slot holding each symbol's leaf.
    leaf: Vec<u16>,
    #[cfg(test)]
    rescales: u32,
}

impl Tree {
    /// An empty tree with room for `n_sym` leaves.
    fn with_capacity(n_sym: usize) -> Self {
        let cap = 2 * n_sym - 1;
        Self {
            slots: 0,
            weight: vec![0; cap],
            content: vec![0; cap],
            parent: vec![0; cap],
            leaf: vec![0; n_sym],
            #[cfg(test)]
            rescales: 0,
        }
    }

    /// Store `content` in `slot`, re-pointing the leaf back-reference or
    /// the children's parent links at it.
    fn set(&mut self, slot: usize, content: u16) {
        self.content[slot] = content;
        if content & LEAF != 0 {
            self.leaf[(content & !LEAF) as usize] = slot as u16;
        } else {
            let e = content as usize;
            self.parent[e] = slot as u16;
            self.parent[e - 1] = slot as u16;
        }
    }

    /// Bump the weights on the path from slot `x` up to (not including) the
    /// root, moving each node to the leader of its run first so the
    /// ordering survives the increment.
    fn increment(&mut self, mut x: usize) {
        while x != 0 {
            let w = self.weight[x];
            let mut y = x;
            while y > 1 && self.weight[y - 1] == w {
                y -= 1;
            }
            if y != x {
                // Equal weights, so only the contents trade places.
                let (cx, cy) = (self.content[x], self.content[y]);
                self.set(x, cy);
                self.set(y, cx);
            }
            self.weight[y] += 1;
            x = self.parent[y] as usize;
        }
    }

    /// Rebuild the tree with every leaf weight halved (rounding up).
    ///
    /// The leaves keep their slot order. Slots are refilled from the bottom
    /// up: each internal node joins the two highest unmerged slots and goes
    /// just above any remaining leaf no heavier than itself.
    fn rescale(&mut self) {
        #[cfg(test)]
        {
            self.rescales += 1;
        }
        let mut leaves: Vec<(u16, u32)> = (0..self.slots)
            .filter(|&x| self.content[x] & LEAF != 0)
            .map(|x| (self.content[x], self.weight[x].div_ceil(2)))
            .collect();
        // `wc`: slots still to fill (the next is `wc - 1`); `pc`: the upper
        // slot of the next pair to join (`pc - 1` and `pc`).
        let mut wc = self.slots;
        let mut pc = self.slots - 1;
        while wc > 0 {
            while wc > 0 && wc >= pc {
                let Some((c, w)) = leaves.pop() else { return };
                wc -= 1;
                self.weight[wc] = w;
                self.set(wc, c);
            }
            if wc == 0 {
                break; // a lone leaf is its own root
            }
            let s = self.weight[pc - 1] + self.weight[pc];
            while let Some(&(c, w)) = leaves.last() {
                if w > s {
                    break;
                }
                leaves.pop();
                wc -= 1;
                self.weight[wc] = w;
                self.set(wc, c);
            }
            wc -= 1;
            self.weight[wc] = s;
            self.set(wc, pc as u16);
            pc -= 2;
        }
    }

    /// The current code of `sym` as `(bits, length)`, root-first in the
    /// low `length` bits.
    fn code(&self, sym: usize) -> (u64, u32) {
        let (mut bits, mut len) = (0u64, 0u32);
        let mut x = self.leaf[sym] as usize;
        while x != 0 {
            bits |= ((x & 1) as u64) << len;
            len += 1;
            x = self.parent[x] as usize;
        }
        // Weights below 2^16 keep the depth far under 64 (Fibonacci bound).
        debug_assert!(len < 64);
        (bits, len)
    }

    /// Write the current code of `sym` (no update).
    fn put(&self, bw: &mut BitWriter, sym: usize) {
        let (bits, mut len) = self.code(sym);
        while len > 0 {
            let n = len.min(16);
            len -= n;
            bw.put_bits(n, (bits >> len) as u32);
        }
    }

    /// Read one symbol by descending from the root (no update).
    fn get(&self, br: &mut BitReader<'_>) -> Result<usize, Error> {
        let mut x = 0usize;
        // Every path is shorter than the slot count; the guard only stops a
        // (never expected) cycle.
        for _ in 0..=self.slots {
            let c = self.content[x];
            if c & LEAF != 0 {
                return Ok((c & !LEAF) as usize);
            }
            x = c as usize - br.get_bits(1) as usize;
        }
        Err(Error::Corrupt)
    }
}

/// The literal/length tree (fixed 286-symbol alphabet).
struct CTree(Tree);

impl CTree {
    /// Complete-heap start: symbol `s` at slot `570 - s`, every weight 1.
    fn new() -> Self {
        let mut t = Tree::with_capacity(NC);
        t.slots = 2 * NC - 1;
        for slot in NC - 1..t.slots {
            t.weight[slot] = 1;
            t.set(slot, LEAF | (t.slots - 1 - slot) as u16);
        }
        for j in (0..NC - 1).rev() {
            t.weight[j] = t.weight[2 * j + 1] + t.weight[2 * j + 2];
            t.set(j, (2 * j + 2) as u16);
        }
        Self(t)
    }

    fn update(&mut self, sym: usize) {
        let t = &mut self.0;
        if t.weight[0] == MAX_FREQ {
            t.rescale();
        }
        t.weight[0] += 1;
        t.increment(t.leaf[sym] as usize);
    }

    fn encode(&mut self, bw: &mut BitWriter, sym: usize) {
        self.0.put(bw, sym);
        self.update(sym);
    }

    fn decode(&mut self, br: &mut BitReader<'_>) -> Result<usize, Error> {
        let sym = self.0.get(br)?;
        self.update(sym);
        Ok(sym)
    }
}

/// The position tree: starts as the lone symbol 0 and grows with output.
struct PTree {
    tree: Tree,
    /// Symbols available (`0..k`).
    k: usize,
    /// Update counter that triggers the rebuild. It is *not* the weight
    /// total: updates while the tree is a single leaf change no weight.
    updates: u32,
}

impl PTree {
    fn new() -> Self {
        let mut tree = Tree::with_capacity(NP);
        tree.slots = 1;
        tree.weight[0] = 1;
        tree.set(0, LEAF);
        Self {
            tree,
            k: 1,
            updates: 0,
        }
    }

    /// Make symbol `k` available once more than `64 * k` bytes have been
    /// output (`count` = bytes before the match being coded).
    fn grow(&mut self, count: usize) {
        while self.k < NP && count > 64 * self.k {
            // Split the last (lightest) leaf: it moves down one level on bit
            // 1 and the new symbol joins it on bit 0, with weight 0.
            let t = &mut self.tree;
            let z = t.slots - 1;
            let f = t.weight[z];
            let old = t.content[z];
            t.weight[z + 1] = f;
            t.set(z + 1, old);
            t.weight[z + 2] = 0;
            t.set(z + 2, LEAF | self.k as u16);
            t.set(z, (z + 2) as u16);
            if z == 0 {
                t.weight[0] = SENTINEL;
            }
            t.slots += 2;
            self.k += 1;
            self.update(self.k - 1);
        }
    }

    fn update(&mut self, sym: usize) {
        let t = &mut self.tree;
        if self.updates == MAX_FREQ {
            t.rescale();
            self.updates = t.weight[0];
            t.weight[0] = SENTINEL;
        }
        t.increment(t.leaf[sym] as usize);
        self.updates += 1;
    }

    fn encode(&mut self, bw: &mut BitWriter, sym: usize) {
        self.tree.put(bw, sym);
        self.update(sym);
    }

    fn decode(&mut self, br: &mut BitReader<'_>) -> Result<usize, Error> {
        let sym = self.tree.get(br)?;
        self.update(sym);
        Ok(sym)
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

    let mut ctree = CTree::new();
    let mut ptree = PTree::new();
    let mut ring = vec![b' '; N];
    let mut r = 0usize;
    let mut br = BitReader::new(payload);

    while out.len() < expected {
        let c = ctree.decode(&mut br)?;
        if c < 256 {
            if br.overran() {
                return Err(Error::UnexpectedEnd);
            }
            out.push(c as u8);
            ring[r] = c as u8;
            r = (r + 1) & (N - 1);
            continue;
        }
        let len = if c == ESCAPE {
            32 + br.get_bits(8) as usize
        } else {
            c - 253
        };
        ptree.grow(out.len());
        let hi = ptree.decode(&mut br)?;
        let pos = (hi << 6) | br.get_bits(6) as usize;
        if br.overran() {
            return Err(Error::UnexpectedEnd);
        }
        // A match running past the declared size is cut short there.
        let src0 = (r + N - pos - 1) & (N - 1);
        for k in 0..len.min(expected - out.len()) {
            let b = ring[(src0 + k) & (N - 1)];
            out.push(b);
            ring[r] = b;
            r = (r + 1) & (N - 1);
        }
    }
    Ok(out)
}

// ─── encoder ─────────────────────────────────────────────────────────────

/// Encode `data` into an lh2 payload (no length header).
pub fn encode_payload(data: &[u8]) -> Vec<u8> {
    encode_tokens(&lz_parse(data))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tok {
    Lit(u8),
    /// `len` in `3..=287`; `dist` in `1..=64 * k` (see [`PTree::grow`]).
    Match {
        len: usize,
        dist: usize,
    },
}

/// Code a token sequence. The bits are fully determined by the tokens.
fn encode_tokens(tokens: &[Tok]) -> Vec<u8> {
    let mut bw = BitWriter::new();
    let mut ctree = CTree::new();
    let mut ptree = PTree::new();
    let mut count = 0usize;

    for &t in tokens {
        match t {
            Tok::Lit(b) => {
                ctree.encode(&mut bw, b as usize);
                count += 1;
            }
            Tok::Match { len, dist } => {
                debug_assert!((MIN_MATCH..=287).contains(&len));
                let v = len + 253;
                if v < ESCAPE {
                    ctree.encode(&mut bw, v);
                } else {
                    ctree.encode(&mut bw, ESCAPE);
                    bw.put_bits(8, (v - ESCAPE) as u32);
                }
                ptree.grow(count);
                let pos = dist - 1;
                debug_assert!(pos >> 6 < ptree.k);
                ptree.encode(&mut bw, pos >> 6);
                bw.put_bits(6, (pos & 63) as u32);
                count += len;
            }
        }
    }
    bw.finish()
}

/// Greedy LZSS parse over the 8 KiB window. Matches only reach back into
/// bytes already output (never the initial spaces), so a distance never
/// exceeds what the position tree can code at that point, and the tokens
/// total exactly `data.len()`.
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
        let mut best_dist = 0usize;
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
                    best_dist = i - cand;
                    if l >= max_match {
                        break;
                    }
                }
                cand = prev[cand];
                chain += 1;
            }
        }

        let step = if best_len >= MIN_MATCH {
            tokens.push(Tok::Match {
                len: best_len,
                dist: best_dist,
            });
            best_len
        } else {
            tokens.push(Tok::Lit(data[i]));
            1
        };
        let end = i + step;
        while i < end {
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
    use alloc::string::String;

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
        round_trip(&b"xyz".repeat(4000));
    }

    fn code_str(t: &Tree, sym: usize) -> String {
        let (bits, len) = t.code(sym);
        (0..len)
            .rev()
            .map(|i| if bits >> i & 1 == 1 { '1' } else { '0' })
            .collect()
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn initial_c_codes() {
        // Spec §9.1.
        let c = CTree::new();
        for (sym, code) in [
            (0, "111000100"),
            (1, "111000101"),
            (59, "111111111"),
            (60, "00000000"),
            (65, "00000101"),
            (97, "00100101"),
            (255, "11000011"),
            (256, "11000100"),
            (257, "11000101"),
            (284, "11100000"),
            (285, "11100001"),
        ] {
            assert_eq!(code_str(&c.0, sym), code, "symbol {sym}");
        }
        // Closed form: `571 - s` in binary, leading 1 dropped, inverted.
        for s in 0..NC {
            let y = 571 - s;
            let len = usize::BITS - 1 - y.leading_zeros();
            let want = !y & ((1 << len) - 1);
            assert_eq!(c.0.code(s), (want as u64, len), "symbol {s}");
        }
    }

    #[test]
    fn c_tree_adaptation_trace() {
        // Spec §9.2.
        let mut c = CTree::new();
        for want in ["00000101", "11100001", "1101111", "1110000"] {
            assert_eq!(code_str(&c.0, 65), want);
            c.update(65);
        }
        assert_eq!(code_str(&c.0, 66), "00000110");
        assert_eq!(code_str(&c.0, 0), "111000100");
        assert_eq!(code_str(&c.0, 285), "00000101");
    }

    fn m(len: usize, dist: usize) -> Tok {
        Tok::Match { len, dist }
    }

    /// Spec §9.3 vectors: tokens, expected stream, expected output.
    fn vectors() -> Vec<(Vec<Tok>, Vec<u8>, Vec<u8>)> {
        let lits = |s: &[u8]| s.iter().map(|&b| Tok::Lit(b)).collect::<Vec<_>>();
        let mut v2 = lits(b"hello ");
        v2.extend([m(11, 6), Tok::Lit(10)]);
        let mut v3 = vec![m(4, 1)];
        v3.extend(lits(b"abc"));
        let mut v4_out = vec![b' '; 300];
        v4_out.push(b'x');
        let mut v5 = lits(b"abcdefgh");
        v5.extend([m(57, 8), m(3, 65), m(3, 2), m(40, 100), m(287, 128)]);
        vec![
            (lits(b"A"), hex("05"), b"A".to_vec()),
            (
                v2,
                hex("2c2930df33f2660bce"),
                b"hello hello hello\n".to_vec(),
            ),
            (v3, hex("c50094989c"), b"    abc".to_vec()),
            (
                vec![m(256, 1), m(44, 1), Tok::Lit(120)],
                hex("e1e003843200f0"),
                v4_out,
            ),
            (
                v5.clone(),
                hex("25262728292a2b2c25191f1006c01d908c7abfff80"),
                replay(&v5),
            ),
        ]
    }

    /// Apply tokens to a space-filled history (independent of the codec).
    fn replay(tokens: &[Tok]) -> Vec<u8> {
        let mut out = vec![b' '; N];
        for &t in tokens {
            match t {
                Tok::Lit(b) => out.push(b),
                Tok::Match { len, dist } => {
                    for _ in 0..len {
                        out.push(out[out.len() - dist]);
                    }
                }
            }
        }
        out.split_off(N)
    }

    #[test]
    fn spec_vectors_encode_and_decode() {
        for (i, (tokens, stream, output)) in vectors().into_iter().enumerate() {
            assert_eq!(encode_tokens(&tokens), stream, "v{} stream", i + 1);
            assert_eq!(
                decode_payload(&stream, output.len()).unwrap(),
                output,
                "v{} output",
                i + 1
            );
        }
        // v4/v5 outputs as the spec gives them; v5 ends with a 287-byte
        // match (above MAXMATCH).
        assert_eq!(
            sha256(&vectors()[3].2),
            hex("5c083fa79026da320854f3178dd6e803f8fdc68a707d59be62f7ed5489f4690f")
        );
        assert_eq!(
            sha256(&vectors()[4].2),
            hex("effcaa782779f8de1637afeb8824fb842ec3d2bd69a169caba494beb27f1f216")
        );
    }

    #[test]
    fn p_tree_insertion_codes() {
        // Spec §9.3 v4: after a 256-byte first match, symbols 1..=3 are
        // inserted at once; symbol 1 then codes as `10`.
        let mut p = PTree::new();
        p.update(0);
        assert_eq!(p.tree.code(0).1, 0);
        p.grow(256);
        assert_eq!(p.k, 4);
        assert_eq!(code_str(&p.tree, 0), "10");
    }

    /// Spec §9.4 token generator.
    fn random_tokens() -> Vec<Tok> {
        let mut x = 1u32;
        let mut next = || {
            x = x.wrapping_mul(1103515245).wrapping_add(12345);
            (x >> 16) as usize
        };
        let mut count = 0usize;
        let mut tokens = Vec::with_capacity(100_000);
        for _ in 0..100_000 {
            let r = next();
            if r % 4 == 0 {
                tokens.push(Tok::Lit(next() as u8));
                count += 1;
                continue;
            }
            let len = if r % 4 != 3 {
                3 + next() % 8
            } else {
                3 + next() % 285
            };
            let k = if count <= 64 {
                1
            } else {
                NP.min(count.div_ceil(64))
            };
            let dist = 1 + next() % (64 * k);
            tokens.push(m(len, dist));
            count += len;
        }
        tokens
    }

    #[test]
    fn large_random_token_vector() {
        // Spec §9.4: rebuilds both trees several times.
        let tokens = random_tokens();
        assert_eq!(
            tokens[..5],
            [m(9, 2), m(267, 60), m(6, 21), m(8, 288), Tok::Lit(28)]
        );
        let stream = encode_tokens(&tokens);
        assert_eq!(stream.len(), 209_707);
        assert_eq!(
            sha256(&stream),
            hex("81d4df468e2fc53302e8e1056b5054e58abb4a978e2a3b85315323eca5f21b9e")
        );

        // Count the rebuilds by re-running the tree side of the encoder.
        let (mut c, mut p, mut count) = (CTree::new(), PTree::new(), 0usize);
        let mut bw = BitWriter::new();
        for &t in &tokens {
            match t {
                Tok::Lit(b) => {
                    c.update(b as usize);
                    count += 1;
                }
                Tok::Match { len, dist } => {
                    c.update((len + 253).min(ESCAPE));
                    p.grow(count);
                    p.encode(&mut bw, (dist - 1) >> 6);
                    count += len;
                }
            }
        }
        assert_eq!((c.0.rescales, p.tree.rescales), (5, 3));

        let out = decode_payload(&stream, count).unwrap();
        assert_eq!(out.len(), 4_007_308);
        assert_eq!(
            sha256(&out),
            hex("d6c1d9cedf67402e0240f87dda5e1f11ad1306f0bfbf7e185f1fd89d132787c6")
        );
    }

    #[test]
    fn sha256_known_answer() {
        assert_eq!(
            sha256(b"abc"),
            hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
    }

    /// Minimal SHA-256 (FIPS 180-4), to check the spec's digests.
    fn sha256(data: &[u8]) -> Vec<u8> {
        const K: [u32; 64] = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
            0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
            0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
            0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
            0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
            0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
            0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
            0xc67178f2,
        ];
        let mut h: [u32; 8] = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ];
        let mut msg = data.to_vec();
        msg.push(0x80);
        while msg.len() % 64 != 56 {
            msg.push(0);
        }
        msg.extend_from_slice(&((data.len() as u64) * 8).to_be_bytes());
        for block in msg.chunks(64) {
            let mut w = [0u32; 64];
            for i in 0..16 {
                w[i] = u32::from_be_bytes(block[4 * i..4 * i + 4].try_into().unwrap());
            }
            for i in 16..64 {
                let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
                let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
                w[i] = w[i - 16]
                    .wrapping_add(s0)
                    .wrapping_add(w[i - 7])
                    .wrapping_add(s1);
            }
            let mut v = h;
            for i in 0..64 {
                let s1 = v[4].rotate_right(6) ^ v[4].rotate_right(11) ^ v[4].rotate_right(25);
                let ch = (v[4] & v[5]) ^ (!v[4] & v[6]);
                let t1 = v[7]
                    .wrapping_add(s1)
                    .wrapping_add(ch)
                    .wrapping_add(K[i])
                    .wrapping_add(w[i]);
                let s0 = v[0].rotate_right(2) ^ v[0].rotate_right(13) ^ v[0].rotate_right(22);
                let maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
                let t2 = s0.wrapping_add(maj);
                v = [
                    t1.wrapping_add(t2),
                    v[0],
                    v[1],
                    v[2],
                    v[3].wrapping_add(t1),
                    v[4],
                    v[5],
                    v[6],
                ];
            }
            for (a, b) in h.iter_mut().zip(v) {
                *a = a.wrapping_add(b);
            }
        }
        h.iter().flat_map(|x| x.to_be_bytes()).collect()
    }

    #[test]
    fn parse_respects_limits() {
        // Long runs (escapes up to 256), the full window, nothing past the
        // bytes already output, and an exact total.
        let mut data = vec![b'q'; 5000];
        data.extend((0..9000u32).map(|i| (i.wrapping_mul(2654435761) >> 24) as u8));
        let tail = data[data.len() - 8000..].to_vec();
        data.extend_from_slice(&tail);
        let tokens = lz_parse(&data);
        let mut count = 0usize;
        let (mut max_len, mut max_dist) = (0, 0);
        for &t in &tokens {
            match t {
                Tok::Lit(_) => count += 1,
                Tok::Match { len, dist } => {
                    assert!((MIN_MATCH..=MAXMATCH).contains(&len));
                    assert!(dist >= 1 && dist <= count.min(N));
                    max_len = max_len.max(len);
                    max_dist = max_dist.max(dist);
                    count += len;
                }
            }
        }
        assert_eq!(count, data.len());
        assert_eq!(max_len, MAXMATCH);
        assert!(max_dist > N - 256, "max distance {max_dist}");
        assert_eq!(replay(&tokens), data);
    }
}
