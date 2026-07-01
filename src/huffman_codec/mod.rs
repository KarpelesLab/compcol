//! Standalone canonical (order-0) Huffman codec.
//!
//! Unlike `crate::huffman` — the internal, deflate-oriented canonical
//! table builder — this module is a complete, self-delimiting byte codec:
//! it builds a length-limited canonical Huffman code from the input's own
//! byte-frequency statistics, serialises that code into the stream, and
//! emits the Huffman-coded payload. Decoding needs *nothing* out of band:
//! the original length and the full code description travel inside the
//! stream. The codec is fully self-contained — it does not depend on the
//! deflate-gated `crate::huffman` internals.
//!
//! It is an order-0 model (each byte coded independently of its
//! neighbours), so it captures only the static symbol-frequency
//! redundancy of the input — text and other skewed-histogram data shrink;
//! already-compressed or uniform-random data does not. For LZ-style
//! redundancy use one of the dictionary codecs (`deflate`, `lz4`, …).
//!
//! # Stream framing
//!
//! All bits of the Huffman payload are packed **MSB-first** (the most-
//! significant bit of the first code occupies bit 7 of the first payload
//! byte) — the same bit order RFC 1951 uses *within* a code, applied here
//! to the whole stream so the codec is trivially byte-reproducible.
//!
//! ```text
//!   ┌────────────────────────────────────────────────────────────────┐
//!   │ original length            : LEB128 varint (unsigned)           │
//!   ├────────────────────────────────────────────────────────────────┤
//!   │ code-length table          : present only when length > 0       │
//!   │   256 entries, one per byte value, each a 4-bit nibble (0..=15), │
//!   │   RLE-compressed (see below). 0 = symbol absent.                 │
//!   ├────────────────────────────────────────────────────────────────┤
//!   │ Huffman-coded payload      : `original length` symbols, MSB-first│
//!   │   then zero-bit padding to the next byte boundary.               │
//!   └────────────────────────────────────────────────────────────────┘
//! ```
//!
//! For an **empty input** the stream is just the single varint byte `0x00`;
//! no table, no payload.
//!
//! ## Code-length table RLE
//!
//! The 256 code lengths (one nibble each, `0..=15`) are run-length encoded
//! with a tiny byte-oriented scheme — flexible enough to make the common
//! cases (long runs of "absent", repeated lengths) cheap, and never larger
//! than ~257 bytes in the worst case. Each command is one control byte:
//!
//! * `0x00..=0x0F` — a single literal length `n` (the low nibble).
//! * `0x10..=0xEF` — a **short run**: the high nibble `(c>>4)` (1..=14) is
//!   the length value, the low nibble `(c&0x0F)` plus 3 is the repeat count
//!   (so 3..=18 repeats of one length in a single byte). The high nibble is
//!   never 0 (that would collide with the literal commands), so zero runs
//!   use the dedicated `0xF2` command below.
//! * `0xF0` — a **long run of zeros**: the next byte `k` encodes
//!   `k + 19` consecutive absent symbols (19..=274). Used to skip large
//!   gaps in the alphabet compactly.
//! * `0xF1` — a **long run of a length**: next byte is the length value
//!   (1..=15), the byte after is `k`, meaning `k + 19` repeats (19..=274).
//! * `0xF2` — a **short run of zeros**: the next byte `k` (0..=15) encodes
//!   `k + 3` consecutive absent symbols (3..=18).
//!
//! The decoder consumes commands until exactly 256 lengths have been
//! produced; a table that over- or under-fills 256, contains a length
//! `> 15`, or whose lengths violate the Kraft inequality is rejected as
//! [`Error::Corrupt`].
//!
//! ## Single-symbol input
//!
//! When the input is one distinct byte repeated, that byte is assigned a
//! 1-bit code (the degenerate Huffman case). The payload is then one bit
//! per input byte, i.e. `ceil(len/8)` bytes — a ~8× shrink.

#![cfg_attr(docsrs, doc(cfg(feature = "huffman")))]

use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;
use crate::traits::{Algorithm, RawDecoder, RawEncoder, RawProgress};

/// Maximum Huffman code length, in bits. Matches the deflate cap so the
/// 4-bit nibble table encoding is always sufficient (a 256-symbol alphabet
/// fits comfortably under a 15-bit length limit).
const MAX_CODE_LEN: u8 = 15;

/// Zero-sized marker type implementing [`Algorithm`] for the standalone
/// canonical Huffman codec.
#[derive(Debug, Clone, Copy, Default)]
pub struct Huffman;

impl Algorithm for Huffman {
    const NAME: &'static str = "huffman";
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

// ─── LEB128 varint ────────────────────────────────────────────────────────

fn write_varint(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let byte = (v & 0x7F) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            break;
        }
        out.push(byte | 0x80);
    }
}

/// Read a LEB128 varint, returning the value and the number of bytes
/// consumed. Rejects overlong encodings (would shift past 64 bits) and
/// truncated input as [`Error::Corrupt`].
fn read_varint(buf: &[u8]) -> Result<(u64, usize), Error> {
    let mut v: u64 = 0;
    let mut shift = 0u32;
    for (i, &byte) in buf.iter().enumerate() {
        if shift >= 64 {
            return Err(Error::Corrupt);
        }
        v |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            return Ok((v, i + 1));
        }
        shift += 7;
    }
    Err(Error::Corrupt)
}

// ─── code-length table (de)serialisation ──────────────────────────────────

/// RLE-encode the 256-entry code-length array per the scheme documented at
/// the module level.
fn encode_lengths(lengths: &[u8; 256], out: &mut Vec<u8>) {
    let mut i = 0usize;
    while i < 256 {
        let val = lengths[i];
        // Count the run of identical values starting at `i`.
        let mut run = 1usize;
        while i + run < 256 && lengths[i + run] == val {
            run += 1;
        }
        i += run;

        if val == 0 {
            // Absent symbols: emit long-zero runs first, then a short tail.
            while run >= 19 {
                let k = (run - 19).min(255);
                out.push(0xF0);
                out.push(k as u8);
                run -= k + 19;
            }
            emit_short(out, 0, run);
        } else {
            while run >= 19 {
                let k = (run - 19).min(255);
                out.push(0xF1);
                out.push(val);
                out.push(k as u8);
                run -= k + 19;
            }
            emit_short(out, val, run);
        }
    }
}

/// Emit `count` (0..=18) repeats of `val` using literal / short-run commands.
fn emit_short(out: &mut Vec<u8>, val: u8, count: usize) {
    let mut left = count;
    while left > 0 {
        if left >= 3 {
            let n = left.min(18);
            if val == 0 {
                // Zero runs can't use the high-nibble form (would collide
                // with literal commands), so use the dedicated 0xF2 command.
                out.push(0xF2);
                out.push((n - 3) as u8);
                left -= n;
            } else if val <= 14 {
                // High nibble = length value (1..=14). Low nibble = count-3.
                out.push((val << 4) | ((n - 3) as u8));
                left -= n;
            } else {
                // val == 15: no short-run form (0xF* reserved), emit a literal.
                out.push(val); // 0x0F
                left -= 1;
            }
        } else {
            out.push(val); // literal 0x00..=0x0F
            left -= 1;
        }
    }
}

/// Decode the RLE code-length table into a fresh `[u8; 256]`, returning the
/// number of input bytes consumed. Rejects malformed tables as
/// [`Error::Corrupt`].
fn decode_lengths(buf: &[u8]) -> Result<([u8; 256], usize), Error> {
    let mut lengths = [0u8; 256];
    let mut pos = 0usize; // index into output (0..=256)
    let mut i = 0usize; // index into input

    while pos < 256 {
        let c = *buf.get(i).ok_or(Error::Corrupt)?;
        i += 1;
        match c {
            0x00..=0x0F => {
                lengths[pos] = c;
                pos += 1;
            }
            0xF0 => {
                let k = *buf.get(i).ok_or(Error::Corrupt)? as usize;
                i += 1;
                let count = k + 19;
                if pos + count > 256 {
                    return Err(Error::Corrupt);
                }
                // zeros: already zero-initialised; just advance.
                pos += count;
            }
            0xF1 => {
                let val = *buf.get(i).ok_or(Error::Corrupt)?;
                i += 1;
                let k = *buf.get(i).ok_or(Error::Corrupt)? as usize;
                i += 1;
                if val == 0 || val > MAX_CODE_LEN {
                    return Err(Error::Corrupt);
                }
                let count = k + 19;
                if pos + count > 256 {
                    return Err(Error::Corrupt);
                }
                for slot in &mut lengths[pos..pos + count] {
                    *slot = val;
                }
                pos += count;
            }
            0xF2 => {
                let k = *buf.get(i).ok_or(Error::Corrupt)? as usize;
                i += 1;
                let count = k + 3;
                if pos + count > 256 {
                    return Err(Error::Corrupt);
                }
                // zeros: already zero-initialised; just advance.
                pos += count;
            }
            // Short run: high nibble = value (1..=14), low nibble = count-3.
            _ => {
                let val = c >> 4;
                let count = (c & 0x0F) as usize + 3;
                // val is 1..=14 here by construction (0xF0/0xF1 handled above,
                // 0xFE/0xFF would give val==15 which the encoder never emits;
                // accept and let Kraft validation reject if inconsistent).
                if pos + count > 256 {
                    return Err(Error::Corrupt);
                }
                for slot in &mut lengths[pos..pos + count] {
                    *slot = val;
                }
                pos += count;
            }
        }
    }

    Ok((lengths, i))
}

// ─── length-limited canonical Huffman (self-contained package-merge) ──────

/// Compute optimal code lengths bounded by `max_length` for `freqs` via the
/// Larmore–Hirschberg package-merge algorithm. `out[i] == 0` iff
/// `freqs[i] == 0`; otherwise `1 ≤ out[i] ≤ max_length`. Single-symbol
/// alphabets get a 1-bit code (the degenerate case).
///
/// Self-contained reimplementation (so the `huffman` feature does not pull
/// in the deflate-gated `crate::huffman`).
fn length_limited_lengths(freqs: &[u32; 256], max_length: u8) -> [u8; 256] {
    let mut out = [0u8; 256];

    // Coins: (freq, symbol) for present symbols, ascending by frequency.
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
        out[coins[0].1 as usize] = 1;
        return out;
    }
    coins.sort_by_key(|&(f, _)| f);

    // Pool of package-merge elements. A coin references a symbol; a pair
    // references two pool indices.
    #[derive(Clone, Copy)]
    enum Kind {
        Coin(u16),
        Pair(u32, u32),
    }
    struct Elem {
        cost: u64,
        kind: Kind,
    }
    let mut pool: Vec<Elem> = Vec::with_capacity(n * (max_length as usize) * 2 + 8);

    // Deepest level: one coin per symbol, ascending.
    let mut current: Vec<u32> = Vec::with_capacity(2 * n);
    for &(f, sym) in &coins {
        pool.push(Elem {
            cost: f as u64,
            kind: Kind::Coin(sym),
        });
        current.push((pool.len() - 1) as u32);
    }

    for _ in 1..max_length {
        // Pair consecutive entries into packages.
        let mut packages: Vec<u32> = Vec::with_capacity(current.len() / 2);
        let mut i = 0;
        while i + 1 < current.len() {
            let a = current[i];
            let b = current[i + 1];
            let cost = pool[a as usize].cost + pool[b as usize].cost;
            pool.push(Elem {
                cost,
                kind: Kind::Pair(a, b),
            });
            packages.push((pool.len() - 1) as u32);
            i += 2;
        }

        // Fresh coins for this level.
        let coin_start = pool.len();
        for &(f, sym) in &coins {
            pool.push(Elem {
                cost: f as u64,
                kind: Kind::Coin(sym),
            });
        }
        let fresh: Vec<u32> = (coin_start..pool.len()).map(|i| i as u32).collect();

        // Merge two cost-sorted lists.
        let mut merged: Vec<u32> = Vec::with_capacity(fresh.len() + packages.len());
        let (mut ci, mut pi) = (0usize, 0usize);
        while ci < fresh.len() && pi < packages.len() {
            if pool[fresh[ci] as usize].cost <= pool[packages[pi] as usize].cost {
                merged.push(fresh[ci]);
                ci += 1;
            } else {
                merged.push(packages[pi]);
                pi += 1;
            }
        }
        merged.extend_from_slice(&fresh[ci..]);
        merged.extend_from_slice(&packages[pi..]);
        current = merged;
    }

    // Take the 2n-2 smallest level-1 items; each Coin reached contributes
    // one bit to its symbol's length.
    let pick = 2 * n - 2;
    let mut stack: Vec<u32> = Vec::with_capacity(32);
    for &root in &current[..pick] {
        stack.clear();
        stack.push(root);
        while let Some(idx) = stack.pop() {
            match pool[idx as usize].kind {
                Kind::Coin(sym) => out[sym as usize] += 1,
                Kind::Pair(a, b) => {
                    stack.push(a);
                    stack.push(b);
                }
            }
        }
    }

    out
}

// ─── canonical code build (self-contained, MSB-first) ─────────────────────

/// Build the canonical MSB-first code value for each symbol from its code
/// length, per RFC 1951 §3.2.2. `codes[i]` is meaningful only when
/// `lengths[i] > 0`.
fn canonical_codes(lengths: &[u8; 256]) -> [u16; 256] {
    let mut count = [0u32; 16];
    for &len in lengths.iter() {
        if len > 0 {
            count[len as usize] += 1;
        }
    }
    let mut next_code = [0u32; 16];
    let mut code: u32 = 0;
    for bits in 1..=15usize {
        code = (code + count[bits - 1]) << 1;
        next_code[bits] = code;
    }
    let mut codes = [0u16; 256];
    for (i, &len) in lengths.iter().enumerate() {
        if len > 0 {
            codes[i] = next_code[len as usize] as u16;
            next_code[len as usize] += 1;
        }
    }
    codes
}

/// A canonical decode table: counts per length, the symbols in canonical
/// order, and the first code value at each length. Validates the Kraft
/// inequality at build time so [`decode_stream`] can trust the table.
struct CanonicalTable {
    counts: [u16; 16],
    first_code: [u32; 16],
    first_idx: [u16; 16],
    symbols: Vec<u16>,
    max_length: u8,
    /// The single symbol when the tree is degenerate (one 1-bit code).
    single: Option<u16>,
}

impl CanonicalTable {
    fn from_lengths(lengths: &[u8; 256]) -> Result<Self, Error> {
        let mut counts = [0u16; 16];
        let mut max_length = 0u8;
        let mut present = 0usize;
        for &len in lengths.iter() {
            if len > MAX_CODE_LEN {
                return Err(Error::Corrupt);
            }
            if len > 0 {
                counts[len as usize] += 1;
                present += 1;
                if len > max_length {
                    max_length = len;
                }
            }
        }

        if present == 0 {
            // No symbols: only valid for an empty stream, which never reaches
            // here (the encoder writes no table for empty input). Reject.
            return Err(Error::Corrupt);
        }

        // Degenerate single-symbol tree: exactly one symbol, 1-bit code.
        let single = if present == 1 {
            if counts[1] != 1 {
                return Err(Error::Corrupt);
            }
            let sym = lengths
                .iter()
                .position(|&l| l > 0)
                .expect("present == 1 guarantees one nonzero length") as u16;
            Some(sym)
        } else {
            None
        };

        // Kraft inequality: Σ counts[l] · 2^(15-l) compared against 2^15.
        // For a complete code (more than one symbol) we require equality so
        // the decoder can never encounter an undefined code; the encoder
        // always produces complete codes. The single-symbol 1-bit code is
        // the documented incomplete exception (kraft == 2^14).
        let mut kraft: u32 = 0;
        for l in 1..=15u32 {
            kraft += (counts[l as usize] as u32) << (15 - l);
        }
        if single.is_none() && kraft != (1 << 15) {
            return Err(Error::Corrupt);
        }

        let mut first_code = [0u32; 16];
        let mut first_idx = [0u16; 16];
        let mut code: u32 = 0;
        let mut idx: u16 = 0;
        for l in 1..=15usize {
            code <<= 1;
            first_code[l] = code;
            first_idx[l] = idx;
            code += counts[l] as u32;
            idx += counts[l];
        }

        let mut symbols = vec![0u16; present];
        let mut next = first_idx;
        for (sym, &len) in lengths.iter().enumerate() {
            if len > 0 {
                symbols[next[len as usize] as usize] = sym as u16;
                next[len as usize] += 1;
            }
        }

        Ok(Self {
            counts,
            first_code,
            first_idx,
            symbols,
            max_length,
            single,
        })
    }
}

// ─── MSB-first bit writer / reader (self-contained) ───────────────────────

struct BitWriter {
    out: Vec<u8>,
    cur: u8,
    nbits: u8,
}

impl BitWriter {
    fn new() -> Self {
        Self {
            out: Vec::new(),
            cur: 0,
            nbits: 0,
        }
    }

    /// Write the low `len` bits of `code`, MSB-first.
    fn write(&mut self, code: u16, len: u8) {
        let mut i = len;
        while i > 0 {
            i -= 1;
            let bit = ((code >> i) & 1) as u8;
            self.cur = (self.cur << 1) | bit;
            self.nbits += 1;
            if self.nbits == 8 {
                self.out.push(self.cur);
                self.cur = 0;
                self.nbits = 0;
            }
        }
    }

    /// Flush any partial byte, padding with zero bits.
    fn finish(mut self) -> Vec<u8> {
        if self.nbits > 0 {
            self.cur <<= 8 - self.nbits;
            self.out.push(self.cur);
        }
        self.out
    }
}

/// MSB-first bit reader over a borrowed slice.
struct BitReader<'a> {
    buf: &'a [u8],
    byte: usize,
    bit: u8, // 0..=7, counts from MSB
}

impl<'a> BitReader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self {
            buf,
            byte: 0,
            bit: 0,
        }
    }

    /// Bits remaining from the current position to the end of the buffer.
    #[inline]
    fn remaining(&self) -> usize {
        (self.buf.len() - self.byte) * 8 - self.bit as usize
    }

    /// Peek the next `n` bits (`1..=15`), MSB-first, right-aligned, zero-padded
    /// past end-of-buffer. Does not advance. Used to index the decode table.
    #[inline]
    fn peek(&self, n: u32) -> u32 {
        // Assemble the current byte and the next few into a 64-bit big-endian
        // accumulator, then slice out the `n` bits at offset `self.bit`.
        let mut acc: u64 = 0;
        for i in 0..8 {
            acc <<= 8;
            if self.byte + i < self.buf.len() {
                acc |= self.buf[self.byte + i] as u64;
            }
        }
        let shift = 64 - self.bit as u32 - n;
        ((acc >> shift) & ((1u64 << n) - 1)) as u32
    }

    /// Advance the cursor by `n` bits.
    #[inline]
    fn consume(&mut self, n: u32) {
        let total = self.bit as usize + n as usize;
        self.byte += total >> 3;
        self.bit = (total & 7) as u8;
    }
}

// ─── core transforms ──────────────────────────────────────────────────────

/// Encode `input` into a complete self-delimiting Huffman stream.
fn encode_stream(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    write_varint(&mut out, input.len() as u64);

    if input.is_empty() {
        return out;
    }

    // Frequencies.
    let mut freqs = [0u32; 256];
    for &b in input {
        freqs[b as usize] += 1;
    }

    // Length-limited canonical lengths (single-symbol → 1-bit code).
    let lengths = length_limited_lengths(&freqs, MAX_CODE_LEN);
    encode_lengths(&lengths, &mut out);

    let codes = canonical_codes(&lengths);
    let mut bw = BitWriter::new();
    for &b in input {
        let s = b as usize;
        bw.write(codes[s], lengths[s]);
    }
    out.extend_from_slice(&bw.finish());
    out
}

/// Decode a self-delimiting Huffman stream back into the original bytes.
fn decode_stream(input: &[u8]) -> Result<Vec<u8>, Error> {
    let (orig_len, vlen) = read_varint(input)?;
    let orig_len = orig_len as usize;
    let mut rest = &input[vlen..];

    if orig_len == 0 {
        return Ok(Vec::new());
    }

    let (lengths, consumed) = decode_lengths(rest)?;
    rest = &rest[consumed..];

    let table = CanonicalTable::from_lengths(&lengths)?;
    let mut out = Vec::with_capacity(orig_len);

    // Degenerate single-symbol stream: every code is one bit, the symbol is
    // fixed. We don't need to inspect the payload bits.
    if let Some(sym) = table.single {
        out.resize(orig_len, sym as u8);
        return Ok(out);
    }

    let mut reader = BitReader::new(rest);
    let max = table.max_length as u32;

    // Build a single-level decode table indexed by the next `max` bits: each
    // canonical code of length `L` owns the `2^(max-L)` slots whose top `L`
    // bits equal the code, so one peek + lookup decodes a symbol in O(1)
    // instead of walking the code bit-by-bit. `len_tbl[i] == 0` marks an
    // index no complete code reaches (never happens for a valid table).
    let tsize = 1usize << max;
    let mut sym_tbl = alloc::vec![0u8; tsize];
    let mut len_tbl = alloc::vec![0u8; tsize];
    for length in 1..=max as usize {
        let count = table.counts[length] as u32;
        if count == 0 {
            continue;
        }
        let first = table.first_code[length];
        let fidx = table.first_idx[length] as u32;
        let shift = max - length as u32;
        for j in 0..count {
            let sym = table.symbols[(fidx + j) as usize] as u8;
            let base = ((first + j) as usize) << shift;
            for slot in &mut sym_tbl[base..base + (1usize << shift)] {
                *slot = sym;
            }
            for slot in &mut len_tbl[base..base + (1usize << shift)] {
                *slot = length as u8;
            }
        }
    }

    while out.len() < orig_len {
        let idx = reader.peek(max) as usize;
        let len = len_tbl[idx];
        // A valid complete tree fills every slot, so `len == 0` only occurs on a
        // corrupt table; a code longer than the bits left means truncation.
        if len == 0 {
            return Err(Error::Corrupt);
        }
        if len as usize > reader.remaining() {
            return Err(Error::UnexpectedEnd);
        }
        out.push(sym_tbl[idx]);
        reader.consume(len as u32);
    }

    Ok(out)
}

// ─── encoder ──────────────────────────────────────────────────────────────

/// Streaming canonical-Huffman encoder.
///
/// Buffers all input (the code is built from whole-stream statistics, so
/// no byte can be emitted until the input ends), transforms at
/// `raw_finish`, then drains. Memory is
/// `O(input)`.
#[derive(Debug)]
pub struct Encoder {
    input: Vec<u8>,
    output: Vec<u8>,
    cursor: usize,
    finalized: bool,
}

impl Encoder {
    /// Construct a fresh encoder.
    pub const fn new() -> Self {
        Self {
            input: Vec::new(),
            output: Vec::new(),
            cursor: 0,
            finalized: false,
        }
    }
}

impl Default for Encoder {
    fn default() -> Self {
        Self::new()
    }
}

impl RawEncoder for Encoder {
    fn raw_encode(&mut self, input: &[u8], _output: &mut [u8]) -> Result<RawProgress, Error> {
        self.input.extend_from_slice(input);
        Ok(RawProgress {
            consumed: input.len(),
            written: 0,
            done: false,
        })
    }

    fn raw_finish(&mut self, output: &mut [u8]) -> Result<RawProgress, Error> {
        if !self.finalized {
            self.output = encode_stream(&self.input);
            self.finalized = true;
        }
        let remaining = self.output.len() - self.cursor;
        let take = remaining.min(output.len());
        output[..take].copy_from_slice(&self.output[self.cursor..self.cursor + take]);
        self.cursor += take;
        Ok(RawProgress {
            consumed: 0,
            written: take,
            done: self.cursor >= self.output.len(),
        })
    }

    fn raw_reset(&mut self) {
        self.input.clear();
        self.output.clear();
        self.cursor = 0;
        self.finalized = false;
    }
}

// ─── decoder ──────────────────────────────────────────────────────────────

/// Streaming canonical-Huffman decoder.
///
/// Buffers the whole compressed stream (the payload is a single MSB-first
/// bitstream that can't be resumed across `decode` calls without a
/// resumable bit-reader state machine), decodes once the stream ends, then
/// drains the decoded bytes. Output is bounded by the in-stream length
/// header, so a crafted small input cannot expand without limit.
#[derive(Debug)]
pub struct Decoder {
    input: Vec<u8>,
    output: Vec<u8>,
    cursor: usize,
    decoded: bool,
}

impl Decoder {
    /// Construct a fresh decoder.
    pub const fn new() -> Self {
        Self {
            input: Vec::new(),
            output: Vec::new(),
            cursor: 0,
            decoded: false,
        }
    }

    fn drain(&mut self, output: &mut [u8]) -> RawProgress {
        let remaining = self.output.len() - self.cursor;
        let take = remaining.min(output.len());
        output[..take].copy_from_slice(&self.output[self.cursor..self.cursor + take]);
        self.cursor += take;
        RawProgress {
            consumed: 0,
            written: take,
            done: self.cursor >= self.output.len(),
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
        if !self.decoded {
            self.input.extend_from_slice(input);
            return Ok(RawProgress {
                consumed: input.len(),
                written: 0,
                done: false,
            });
        }
        Ok(self.drain(output))
    }

    fn raw_finish(&mut self, output: &mut [u8]) -> Result<RawProgress, Error> {
        if !self.decoded {
            self.output = decode_stream(&self.input)?;
            self.decoded = true;
        }
        Ok(self.drain(output))
    }

    fn raw_reset(&mut self) {
        self.input.clear();
        self.output.clear();
        self.cursor = 0;
        self.decoded = false;
    }
}

#[cfg(test)]
mod tests;
