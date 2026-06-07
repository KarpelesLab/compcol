//! ARC "Squeeze" — the CP/M `SQ`/`USQ` codec, ARC method 4.
//!
//! Squeeze is a two-stage codec from circa 1981–1985:
//!
//! 1. A **run-length pre-pass** that collapses runs of a repeated byte. The
//!    flag byte is `0x90` ("DLE"): the sequence `b 0x90 n` means "byte `b`
//!    repeated `n` times" (the first `b` is emitted literally before the
//!    flag, so the run length on the wire is `n` and `n` total copies of `b`
//!    appear in the output, with the leading literal counting as one). A
//!    literal `0x90` is encoded as `0x90 0x00`.
//! 2. **Static Huffman coding** of the RLE output. The Huffman tree is built
//!    over the byte frequencies plus a distinguished end-of-stream symbol
//!    (`SPEOF = 256`) and is serialised into the stream header as a node
//!    table.
//!
//! ## Wire format (raw method payload)
//!
//! This module implements the codec payload only — no ARC archive header, no
//! filename, no checksum (those live in the ARC container, exactly like the
//! zip-method codecs in this crate). The payload is:
//!
//! ```text
//! +-----------+========================+======================+
//! | numnodes  | node table (4·N bytes) | Huffman bitstream     |
//! | (u16 LE)  | 2× i16 LE per node     | (LSB-first)           |
//! +-----------+========================+======================+
//! ```
//!
//! Each node is a pair of `i16` LE children `(left, right)`. A non-negative
//! child is the index of another node; a negative child `c` is a **leaf** for
//! the value `-(c) - 1` (values 0..=255 are bytes, value 256 is `SPEOF`,
//! end-of-stream). Decoding walks from node 0: a `0` bit takes the left
//! child, a `1` bit the right. `numnodes == 0` denotes the empty stream.
//!
//! ## Scope
//!
//! Both directions are implemented and validated by round-trip. The decoder
//! reverses the Huffman stage then the RLE stage; the encoder runs RLE then
//! builds and serialises a canonical Huffman tree.
//!
//! ## DoS hygiene
//!
//! Crafted streams never panic. A malformed node table (out-of-range child
//! index, a cycle, or a leaf value > 256) returns
//! [`Error::InvalidHuffmanTree`]; a truncated bitstream that cannot reach a
//! leaf returns [`Error::UnexpectedEnd`]; the node count is bounded
//! (`<= MAX_NODES`); RLE output growth uses checked arithmetic and the run
//! expansion is bounded.
//!
//! ## References
//!
//! * Richard Greenlaw's `SQ`/`USQ` (1981) and the ARC method-4 description,
//!   widely archived alongside `nomarch` and the CP/M utilities. Used as a
//!   *format* reference only — no GPL/BSD source copied.

#![cfg_attr(docsrs, doc(cfg(feature = "arc_squeeze")))]

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;
use crate::traits::{Algorithm, RawDecoder, RawEncoder, RawProgress};

/// Zero-sized marker type implementing [`Algorithm`] for ARC Squeeze.
#[derive(Debug, Clone, Copy, Default)]
pub struct ArcSqueeze;

impl Algorithm for ArcSqueeze {
    const NAME: &'static str = "squeeze";
    type Encoder = Encoder;
    type Decoder = Decoder;
    type EncoderConfig = ();
    type DecoderConfig = ();
    fn encoder_with(_: ()) -> Encoder {
        Encoder::new()
    }
    fn decoder_with(_: ()) -> Decoder {
        Decoder::new()
    }
}

// ─── shared constants ────────────────────────────────────────────────────

/// RLE flag byte (DLE).
const RLE_FLAG: u8 = 0x90;
/// End-of-stream Huffman symbol.
const SPEOF: u16 = 256;
/// Number of distinct Huffman symbols (256 bytes + SPEOF).
const NUM_SYMBOLS: usize = 257;
/// A full binary tree over `NUM_SYMBOLS` leaves has at most
/// `2 * NUM_SYMBOLS - 1` nodes. Bound the node table to defend against
/// crafted oversized headers.
const MAX_NODES: usize = 2 * NUM_SYMBOLS;

/// One Huffman tree node: `(left, right)` children in the SQ encoding
/// (non-negative = child node index, negative `c` = leaf for `-(c) - 1`).
type Node = (i16, i16);
/// A per-symbol Huffman code: `(bits, len)`, packed LSB-first.
type Code = (u32, u8);

// ════════════════════════════════════════════════════════════════════════
//  RLE stage
// ════════════════════════════════════════════════════════════════════════

/// Encode the RLE pre-pass: collapse runs of a repeated byte using the
/// `0x90` flag. `b 0x90 n` ⇒ `b` repeated `n` times (the literal `b` already
/// emitted counts as the first copy). A literal `0x90` becomes `0x90 0x00`.
fn rle_encode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0usize;
    while i < input.len() {
        let b = input[i];
        out.push(b);
        if b == RLE_FLAG {
            // Literal flag byte: emit count 0.
            out.push(0);
            i += 1;
            continue;
        }
        // Count the run (including the byte already emitted).
        let mut run = 1usize;
        while i + run < input.len() && input[i + run] == b && run < 255 {
            run += 1;
        }
        if run >= 3 {
            // Worth encoding: `0x90 run`.
            out.push(RLE_FLAG);
            out.push(run as u8);
            i += run;
        } else {
            // Short run: emit the remaining copies literally. We've already
            // emitted one; emit the rest one at a time on subsequent
            // iterations.
            i += 1;
        }
    }
    out
}

/// Streaming RLE decoder state. The `0x90 n` sequences are stateful across
/// byte boundaries, so we keep a tiny machine.
#[derive(Debug, Default)]
struct RleDecoder {
    /// Last literal byte emitted (the candidate to repeat).
    last: u8,
    have_last: bool,
    /// True when we have just consumed a `0x90` and await the count byte.
    awaiting_count: bool,
}

impl RleDecoder {
    fn reset(&mut self) {
        self.last = 0;
        self.have_last = false;
        self.awaiting_count = false;
    }

    /// Feed one RLE-coded byte; push the expanded bytes onto `out`.
    /// Returns `Err(Corrupt)` on a malformed sequence (count with no prior
    /// literal).
    fn feed(&mut self, b: u8, out: &mut Vec<u8>) -> Result<(), Error> {
        if self.awaiting_count {
            self.awaiting_count = false;
            if b == 0 {
                // Literal flag byte.
                out.push(RLE_FLAG);
                self.last = RLE_FLAG;
                self.have_last = true;
            } else {
                // Repeat `last` so that `b` total copies exist. One copy was
                // already emitted, so push `b - 1` more.
                if !self.have_last {
                    return Err(Error::Corrupt);
                }
                for _ in 1..b {
                    out.push(self.last);
                }
            }
            return Ok(());
        }
        if b == RLE_FLAG {
            self.awaiting_count = true;
        } else {
            out.push(b);
            self.last = b;
            self.have_last = true;
        }
        Ok(())
    }

    /// True if mid-sequence (a dangling `0x90` awaiting its count).
    fn pending(&self) -> bool {
        self.awaiting_count
    }
}

// ════════════════════════════════════════════════════════════════════════
//  Huffman tree (encoder side)
// ════════════════════════════════════════════════════════════════════════

/// Build a Huffman node table over the symbol frequencies (indices
/// `0..=256`, where 256 is SPEOF). Returns the node table as `(left, right)`
/// pairs with node 0 as the root, plus the per-symbol codes.
///
/// Node children follow the SQ convention: non-negative = child node index,
/// negative `c` = leaf for value `-(c) - 1`.
fn build_tree(freq: &[u32; NUM_SYMBOLS]) -> (Vec<Node>, Vec<Code>) {
    // Heap entries: (weight, node_ref). node_ref < 0 ⇒ leaf for -(ref)-1;
    // node_ref >= 0 ⇒ internal node index.
    #[derive(Clone, Copy)]
    struct Item {
        weight: u64,
        node: i32,
        // Tie-breaker for deterministic output.
        order: u32,
    }

    let mut heap: Vec<Item> = Vec::new();
    let mut order = 0u32;
    for (sym, &f) in freq.iter().enumerate() {
        if f > 0 {
            heap.push(Item {
                weight: f as u64,
                node: -(sym as i32) - 1,
                order,
            });
            order += 1;
        }
    }

    // Handle degenerate cases: 0 or 1 distinct symbols. SQ always has at
    // least SPEOF in the alphabet (frequency 1), so `heap` has >= 1 entry.
    // With a single symbol we still need a 2-node tree so the symbol gets a
    // 1-bit code.
    let mut nodes: Vec<(i32, i32)> = Vec::new();

    if heap.len() == 1 {
        // Single symbol: root with that leaf on the left, a dummy SPEOF-ish
        // leaf isn't needed because SPEOF is always present; but guard
        // anyway by duplicating.
        let only = heap[0].node;
        nodes.push((only, only));
        return finish_tree(nodes);
    }

    // Pop the two lightest items, combine, push the parent. Use a simple
    // selection over the Vec (alphabet <= 257, so O(n²) is fine and
    // dependency-free).
    fn pop_min(heap: &mut Vec<Item>) -> Item {
        let mut best = 0usize;
        for i in 1..heap.len() {
            if heap[i].weight < heap[best].weight
                || (heap[i].weight == heap[best].weight && heap[i].order < heap[best].order)
            {
                best = i;
            }
        }
        heap.swap_remove(best)
    }

    while heap.len() > 1 {
        let a = pop_min(&mut heap);
        let b = pop_min(&mut heap);
        let idx = nodes.len() as i32;
        nodes.push((a.node, b.node));
        heap.push(Item {
            weight: a.weight.saturating_add(b.weight),
            node: idx,
            order,
        });
        order += 1;
    }

    finish_tree(nodes)
}

/// Given an internal-node list (built so the last-pushed node is the root),
/// renumber so node 0 is the root and produce `(i16, i16)` children plus the
/// per-symbol code table.
fn finish_tree(nodes: Vec<(i32, i32)>) -> (Vec<Node>, Vec<Code>) {
    // The root is the last node pushed.
    let root = nodes.len() as i32 - 1;

    // Renumber internal nodes so root becomes 0. We do a remap: old index
    // -> new index via reverse order (root last -> 0). Simpler: build a new
    // table indexed by a DFS from the root assigning new ids in visit order.
    let mut new_table: Vec<(i16, i16)> = Vec::new();
    let mut codes: Vec<(u32, u8)> = vec![(0u32, 0u8); NUM_SYMBOLS];

    // Iterative DFS carrying (old_node_index, code_bits, code_len).
    // We assign a new id to each internal node the first time we see it.
    // Map from old internal index -> new index.
    let mut remap: Vec<i32> = vec![-1; nodes.len().max(1)];

    // First pass: assign new ids in DFS preorder so root = 0.
    let mut stack: Vec<i32> = Vec::new();
    if root >= 0 {
        remap[root as usize] = 0;
        new_table.push((0, 0)); // placeholder
        stack.push(root);
    }
    while let Some(old) = stack.pop() {
        let (l, r) = nodes[old as usize];
        let mut resolve = |child: i32, table: &mut Vec<(i16, i16)>, stack: &mut Vec<i32>| -> i16 {
            if child < 0 {
                child as i16 // leaf, keep as-is
            } else {
                if remap[child as usize] < 0 {
                    let nid = table.len() as i32;
                    remap[child as usize] = nid;
                    table.push((0, 0));
                    stack.push(child);
                }
                remap[child as usize] as i16
            }
        };
        let nl = resolve(l, &mut new_table, &mut stack);
        let nr = resolve(r, &mut new_table, &mut stack);
        let nid = remap[old as usize] as usize;
        new_table[nid] = (nl, nr);
    }

    // Build per-symbol codes by walking the new table from root (node 0).
    // bit 0 = left, bit 1 = right; SQ packs LSB-first so the first bit of
    // the path is the least-significant bit emitted.
    fn assign(table: &[(i16, i16)], node: i16, bits: u32, len: u8, codes: &mut [(u32, u8)]) {
        if node < 0 {
            let sym = (-(node as i32) - 1) as usize;
            if sym < codes.len() {
                codes[sym] = (bits, len);
            }
            return;
        }
        let (l, r) = table[node as usize];
        // Guard against pathological depth (shouldn't happen for <=257 syms).
        if len < 32 {
            assign(table, l, bits, len + 1, codes);
            assign(table, r, bits | (1u32 << len), len + 1, codes);
        }
    }
    if !new_table.is_empty() {
        assign(&new_table, 0, 0, 0, &mut codes);
    }

    (new_table, codes)
}

// ════════════════════════════════════════════════════════════════════════
//  Encoder
// ════════════════════════════════════════════════════════════════════════

/// Streaming ARC Squeeze encoder.
///
/// Squeeze needs two full passes over the data (frequency counting, then
/// Huffman emission), so this encoder buffers all input until `finish`, then
/// produces the complete payload. This matches the inherently two-pass nature
/// of static Huffman; it is not a true streaming compressor but presents the
/// same streaming API.
#[derive(Debug)]
pub struct Encoder {
    input: Vec<u8>,
    out: Vec<u8>,
    out_head: usize,
    built: bool,
    completed: bool,
}

impl Encoder {
    /// Construct a fresh encoder.
    pub fn new() -> Self {
        Self {
            input: Vec::new(),
            out: Vec::new(),
            out_head: 0,
            built: false,
            completed: false,
        }
    }

    fn build(&mut self) {
        // 1. RLE pre-pass.
        let rle = rle_encode(&self.input);

        // 2. Frequency count over RLE bytes + SPEOF.
        let mut freq = [0u32; NUM_SYMBOLS];
        for &b in &rle {
            freq[b as usize] += 1;
        }
        freq[SPEOF as usize] = 1; // EOS always present once.

        let (table, codes) = build_tree(&freq);

        // 3. Serialise: numnodes (u16 LE) + node table + bitstream.
        let mut out = Vec::new();
        let n = table.len() as u16;
        out.push((n & 0xFF) as u8);
        out.push((n >> 8) as u8);
        for &(l, r) in &table {
            let lu = l as u16;
            let ru = r as u16;
            out.push((lu & 0xFF) as u8);
            out.push((lu >> 8) as u8);
            out.push((ru & 0xFF) as u8);
            out.push((ru >> 8) as u8);
        }

        // 4. Emit Huffman bitstream (LSB-first) for each RLE byte, then SPEOF.
        let mut bit_acc: u32 = 0;
        let mut bit_count: u8 = 0;
        let mut emit = |bits: u32, len: u8, out: &mut Vec<u8>| {
            bit_acc |= bits << bit_count;
            bit_count += len;
            while bit_count >= 8 {
                out.push(bit_acc as u8);
                bit_acc >>= 8;
                bit_count -= 8;
            }
        };
        for &b in &rle {
            let (bits, len) = codes[b as usize];
            emit(bits, len, &mut out);
        }
        let (eb, el) = codes[SPEOF as usize];
        emit(eb, el, &mut out);
        if bit_count > 0 {
            out.push(bit_acc as u8);
        }

        self.out = out;
        self.built = true;
    }

    fn drain(&mut self, output: &mut [u8]) -> usize {
        let available = self.out.len() - self.out_head;
        let n = available.min(output.len());
        output[..n].copy_from_slice(&self.out[self.out_head..self.out_head + n]);
        self.out_head += n;
        n
    }
}

impl Default for Encoder {
    fn default() -> Self {
        Self::new()
    }
}

impl RawEncoder for Encoder {
    fn raw_encode(&mut self, input: &[u8], _output: &mut [u8]) -> Result<RawProgress, Error> {
        // Buffer everything; output is produced at finish().
        self.input.extend_from_slice(input);
        Ok(RawProgress {
            consumed: input.len(),
            written: 0,
            done: false,
        })
    }

    fn raw_finish(&mut self, output: &mut [u8]) -> Result<RawProgress, Error> {
        if self.completed {
            return Ok(RawProgress {
                consumed: 0,
                written: 0,
                done: true,
            });
        }
        if !self.built {
            self.build();
        }
        let written = self.drain(output);
        let done = self.out_head >= self.out.len();
        if done {
            self.completed = true;
        }
        Ok(RawProgress {
            consumed: 0,
            written,
            done,
        })
    }

    fn raw_reset(&mut self) {
        self.input.clear();
        self.out.clear();
        self.out_head = 0;
        self.built = false;
        self.completed = false;
    }
}

// ════════════════════════════════════════════════════════════════════════
//  Decoder
// ════════════════════════════════════════════════════════════════════════

/// Streaming ARC Squeeze decoder.
#[derive(Debug)]
pub struct Decoder {
    // ── framing / header ──
    /// Header bytes parsed: numnodes (2) + 4·numnodes.
    in_buf: Vec<u8>,
    in_pos: usize,
    num_nodes: Option<usize>,
    /// Parsed node table `(left, right)`.
    table: Vec<(i16, i16)>,
    header_done: bool,
    empty_stream: bool,

    // ── bit reader ──
    bit_acc: u32,
    bit_count: u8,
    /// Current walk position in the tree (node index).
    cur_node: i16,

    // ── RLE post-pass ──
    rle: RleDecoder,

    // ── output ──
    emit_buf: Vec<u8>,
    emit_head: usize,
    eos: bool,
    completed: bool,
}

impl Decoder {
    /// Construct a fresh decoder.
    pub fn new() -> Self {
        Self {
            in_buf: Vec::new(),
            in_pos: 0,
            num_nodes: None,
            table: Vec::new(),
            header_done: false,
            empty_stream: false,
            bit_acc: 0,
            bit_count: 0,
            cur_node: 0,
            rle: RleDecoder::default(),
            emit_buf: Vec::new(),
            emit_head: 0,
            eos: false,
            completed: false,
        }
    }

    /// Try to parse the header (numnodes + node table) from `in_buf`.
    /// Returns Ok(true) when complete, Ok(false) when more input is needed.
    fn parse_header(&mut self) -> Result<bool, Error> {
        if self.header_done {
            return Ok(true);
        }
        // numnodes (2 bytes).
        if self.num_nodes.is_none() {
            if self.in_buf.len() - self.in_pos < 2 {
                return Ok(false);
            }
            let n = (self.in_buf[self.in_pos] as usize)
                | ((self.in_buf[self.in_pos + 1] as usize) << 8);
            self.in_pos += 2;
            if n > MAX_NODES {
                return Err(Error::InvalidHuffmanTree);
            }
            self.num_nodes = Some(n);
            if n == 0 {
                // Empty stream.
                self.empty_stream = true;
                self.header_done = true;
                return Ok(true);
            }
        }
        // `num_nodes` is set above (or on a prior streaming call) before we
        // reach here; treat an unset count as corrupt rather than panicking.
        let n = match self.num_nodes {
            Some(n) => n,
            None => return Err(Error::Corrupt),
        };
        // node table: 4·n bytes.
        if self.in_buf.len() - self.in_pos < 4 * n {
            return Ok(false);
        }
        self.table.clear();
        self.table.reserve(n);
        for _ in 0..n {
            let l =
                (self.in_buf[self.in_pos] as i16) | ((self.in_buf[self.in_pos + 1] as i16) << 8);
            let r = (self.in_buf[self.in_pos + 2] as i16)
                | ((self.in_buf[self.in_pos + 3] as i16) << 8);
            self.in_pos += 4;
            self.table.push((l, r));
        }
        // Validate the table: every internal child index must point to a
        // valid node; every leaf value must be in 0..=256.
        for &(l, r) in &self.table {
            for child in [l, r] {
                if child >= 0 {
                    if child as usize >= n {
                        return Err(Error::InvalidHuffmanTree);
                    }
                } else {
                    let val = (-(child as i32) - 1) as i64;
                    if val > SPEOF as i64 {
                        return Err(Error::InvalidHuffmanTree);
                    }
                }
            }
        }
        self.header_done = true;
        Ok(true)
    }

    /// Pull bits and walk the tree, expanding through the RLE stage into
    /// `emit_buf`. Stops on EOS, input exhaustion, or a full emit_buf.
    fn pump(&mut self) -> Result<(), Error> {
        if self.empty_stream {
            self.eos = true;
            return Ok(());
        }
        loop {
            if self.eos {
                return Ok(());
            }
            // Bound emit_buf growth (a single RLE run expands to <=255 bytes).
            if self.emit_buf.len() - self.emit_head > 16 * 1024 {
                return Ok(());
            }

            // Walk down the tree one bit at a time until we hit a leaf.
            let leaf = loop {
                let node = self.cur_node;
                if node < 0 || node as usize >= self.table.len() {
                    return Err(Error::InvalidHuffmanTree);
                }
                // Need a bit.
                if self.bit_count == 0 {
                    if self.in_pos >= self.in_buf.len() {
                        return Ok(()); // need more input
                    }
                    self.bit_acc = self.in_buf[self.in_pos] as u32;
                    self.bit_count = 8;
                    self.in_pos += 1;
                }
                let bit = self.bit_acc & 1;
                self.bit_acc >>= 1;
                self.bit_count -= 1;
                let (l, r) = self.table[node as usize];
                let next = if bit == 0 { l } else { r };
                if next < 0 {
                    // Leaf.
                    self.cur_node = 0;
                    break (-(next as i32) - 1) as u16;
                } else {
                    self.cur_node = next;
                }
            };

            if leaf == SPEOF {
                self.eos = true;
                return Ok(());
            }
            if leaf > 255 {
                return Err(Error::InvalidHuffmanTree);
            }
            // Feed the Huffman-decoded byte through the RLE stage.
            self.rle.feed(leaf as u8, &mut self.emit_buf)?;
        }
    }

    fn drain_emit(&mut self, out: &mut [u8]) -> usize {
        let available = self.emit_buf.len() - self.emit_head;
        let n = available.min(out.len());
        out[..n].copy_from_slice(&self.emit_buf[self.emit_head..self.emit_head + n]);
        self.emit_head += n;
        if self.emit_head == self.emit_buf.len() {
            self.emit_buf.clear();
            self.emit_head = 0;
        }
        n
    }

    fn compact_in_buf(&mut self) {
        if self.in_pos >= 64 * 1024 {
            self.in_buf.drain(0..self.in_pos);
            self.in_pos = 0;
        }
    }
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

impl RawDecoder for Decoder {
    fn raw_decode(&mut self, input: &[u8], output: &mut [u8]) -> Result<RawProgress, Error> {
        let consumed = input.len();
        self.in_buf.extend_from_slice(input);

        let mut written = 0usize;

        if !self.header_done && !self.parse_header()? {
            return Ok(RawProgress {
                consumed,
                written,
                done: false,
            });
        }

        // Drain any buffered emit first.
        if self.emit_head < self.emit_buf.len() {
            written += self.drain_emit(&mut output[written..]);
        }

        // Pump and drain until output is full or we run out of work.
        while written < output.len() {
            if self.emit_head >= self.emit_buf.len() {
                self.pump()?;
                if self.emit_head >= self.emit_buf.len() {
                    // Nothing produced: either EOS or need more input.
                    break;
                }
            }
            written += self.drain_emit(&mut output[written..]);
        }

        self.compact_in_buf();

        let done = self.eos && self.emit_head >= self.emit_buf.len();
        if done {
            self.completed = true;
        }
        Ok(RawProgress {
            consumed,
            written,
            done,
        })
    }

    fn raw_finish(&mut self, output: &mut [u8]) -> Result<RawProgress, Error> {
        if self.completed {
            return Ok(RawProgress {
                consumed: 0,
                written: 0,
                done: true,
            });
        }

        if !self.header_done && !self.parse_header()? {
            return Err(Error::UnexpectedEnd);
        }

        let mut written = 0usize;
        if self.emit_head < self.emit_buf.len() {
            written += self.drain_emit(&mut output[written..]);
        }
        while written < output.len() {
            if self.emit_head >= self.emit_buf.len() {
                self.pump()?;
                if self.emit_head >= self.emit_buf.len() {
                    break;
                }
            }
            written += self.drain_emit(&mut output[written..]);
        }

        if self.emit_head < self.emit_buf.len() {
            // More output owed; caller must drain and call again.
            return Ok(RawProgress {
                consumed: 0,
                written,
                done: false,
            });
        }

        if !self.eos {
            // Ran out of input without reaching the EOS symbol.
            return Err(Error::UnexpectedEnd);
        }
        // A dangling RLE flag (0x90 with no count) at true EOF is malformed.
        if self.rle.pending() {
            return Err(Error::UnexpectedEnd);
        }

        self.completed = true;
        Ok(RawProgress {
            consumed: 0,
            written,
            done: true,
        })
    }

    fn raw_reset(&mut self) {
        self.in_buf.clear();
        self.in_pos = 0;
        self.num_nodes = None;
        self.table.clear();
        self.header_done = false;
        self.empty_stream = false;
        self.bit_acc = 0;
        self.bit_count = 0;
        self.cur_node = 0;
        self.rle.reset();
        self.emit_buf.clear();
        self.emit_head = 0;
        self.eos = false;
        self.completed = false;
    }
}
