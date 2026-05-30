//! PKZIP Implode streaming decoder.
//!
//! Internal model: we accumulate input into `in_buf` as the caller feeds
//! it and decode in *symbol-atomic* steps. A symbol is either a literal
//! (1 bit selector + 8 raw bits or one literal-tree code) or a match
//! (1 bit + low distance bits + distance code + length code + maybe
//! extra). Each step snapshots the bit-reader position; if it underruns
//! the buffered input we roll back to the snapshot and return progress
//! so far. Decoded bytes go into the sliding window and are drained from
//! the window into the caller's output as the window fills.
//!
//! The decoder is finite: it stops as soon as the header's
//! `uncompressed_length` bytes have been emitted. Trailing input is
//! ignored. Reaching end-of-input before completing a symbol while
//! `output_left > 0` is reported as [`Error::UnexpectedEnd`] from
//! `raw_finish`.

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;
use crate::traits::{RawDecoder, RawProgress};

/// Maximum codeword length any of the three Shannon–Fano trees can use.
/// PKWARE APPNOTE caps the run-length / bit-length pair-byte nibble at
/// 16, so the longest code is 16 bits.
const MAX_CODE_LEN: usize = 16;

/// Maximum dictionary size — 8 KiB, the larger of the two Implode modes.
/// Used to size the sliding window; in 4 KiB mode only the low 4 KiB are
/// touched.
const WINDOW_SIZE: usize = 8 * 1024;

/// Header bytes carried by our wrapper framing: 1 flag byte + 4 LE-length
/// bytes.
const HEADER_LEN: usize = 5;

/// Per-tree maximum symbol count: 256 for the literal tree, 64 for the
/// length and distance trees.
const LIT_SYMBOLS: usize = 256;
const LEN_SYMBOLS: usize = 64;
const DIST_SYMBOLS: usize = 64;

// ─── canonical Shannon–Fano decode table ────────────────────────────────
//
// Implode's canonical assignment is the bit-complement of the standard
// RFC 1951 assignment over the same length distribution. The trick from
// `hwzip` is: build the table the usual way, then complement the lookup
// input. We store, for each of the 16-bit-wide LSB-first prefixes, the
// `(symbol, length)` pair so a single 16-bit table lookup resolves any
// code. That's a fixed 65 536 × 4 bytes per tree — too much for embedded
// targets — so we instead use a compact two-level table: a 9-bit primary
// table that handles short codes directly, falling through to sparse
// long-code chains via linear probing of the original codeword set.
//
// For simplicity in this build we use a single flat table keyed by the
// LSB-first 16-bit lookup window, populated by walking every length
// distribution. The codewords are computed in the standard canonical
// order and then bit-reversed to match the LSB-first emission order in
// the wire.

#[derive(Debug, Clone)]
struct ShannonFano {
    /// `lookup[prefix]` = (symbol, bits) where `prefix` is the next-up-to
    /// -16 LSB-first bits **complemented** (we apply the complement at
    /// build time so the hot path is a plain index). Length 0 means the
    /// slot is unused.
    lookup: Vec<(u16, u8)>,
    /// Number of valid symbols this tree covers (256, 64, …).
    num_symbols: u16,
}

impl ShannonFano {
    /// Build from a `lens[symbol] = bit_length` array. Returns
    /// [`Error::InvalidHuffmanTree`] if the lengths don't form a full
    /// canonical code (Kraft check ≠ 1 exactly).
    fn from_lengths(lens: &[u8]) -> Result<Self, Error> {
        // Kraft equality: sum(2^(MAX-l)) over l>0 must equal 2^MAX.
        let mut len_count = [0u32; MAX_CODE_LEN + 1];
        for &l in lens {
            if l == 0 || l as usize > MAX_CODE_LEN {
                return Err(Error::InvalidHuffmanTree);
            }
            len_count[l as usize] += 1;
        }
        // Kraft check, mirroring hwzip's "avail_codewords" walk.
        let mut avail: i64 = 2;
        for &c in len_count.iter().take(MAX_CODE_LEN + 1).skip(1) {
            avail -= c as i64;
            if avail < 0 {
                return Err(Error::InvalidHuffmanTree);
            }
            avail *= 2;
        }
        // After the loop, `avail` is 2 * (slots left at length MAX+1) and
        // must be exactly 2 * (1 << MAX) - 2 * sum(...), but the
        // shortcut: 2^(MAX+1) minus the doubled-out count must equal
        // 2^(MAX+1). We can simply require the final pre-doubling avail
        // to be zero after subtracting len_count[MAX] (the loop's last
        // iteration), which the canonical Kraft check expresses as
        // `final_avail == 0`. The mistake-prone bit is that the loop
        // doubles after subtracting, so the final value is `2 *
        // (slots_remaining_at_MAX+1)`; if it's zero the tree is full.
        if avail != 0 {
            return Err(Error::InvalidHuffmanTree);
        }

        // Compute the first canonical code for each length.
        let mut next_code = [0u32; MAX_CODE_LEN + 2];
        let mut code = 0u32;
        for bits in 1..=MAX_CODE_LEN {
            code = (code + len_count[bits - 1]) << 1;
            next_code[bits] = code;
        }
        // Assign canonical codes in symbol order, then bit-reverse so
        // the table can be indexed LSB-first off the wire.
        let mut lookup: Vec<(u16, u8)> = vec![(0, 0); 1 << MAX_CODE_LEN];
        for (sym, &l) in lens.iter().enumerate() {
            let l = l as usize;
            let canonical = next_code[l];
            next_code[l] += 1;
            // Implode's "reversed" assignment: complement the codeword
            // within its length. We absorb that into the lookup index by
            // *not* complementing here, but instead complementing the
            // wire bits at lookup time — that matches hwzip's
            // `huffman_decode(d, ~bits, &used)` pattern. Equivalently we
            // could complement here and not at lookup. We pick lookup-
            // time complement so we share one decoder type for all
            // three trees.
            let lsb = reverse_bits(canonical, l as u32);
            // Fill every slot whose low `l` bits match `lsb`.
            let step = 1usize << l;
            let mut idx = lsb as usize;
            while idx < (1 << MAX_CODE_LEN) {
                lookup[idx] = (sym as u16, l as u8);
                idx += step;
            }
        }

        Ok(Self {
            lookup,
            num_symbols: lens.len() as u16,
        })
    }

    /// Look up the symbol at `bits` (16 LSB-first wire bits). Caller is
    /// responsible for masking; we use the entire 16-bit window so any
    /// codeword from 1 to 16 bits resolves in one step. Returns
    /// `(symbol, bits_used)`. The caller must have at least
    /// `bits_used` bits accumulated.
    #[inline]
    fn decode(&self, bits: u16) -> Result<(u16, u8), Error> {
        // Implode's reversed assignment: complement the wire window
        // before indexing.
        let idx = !bits as usize & 0xFFFF;
        let (sym, l) = self.lookup[idx];
        if l == 0 || sym >= self.num_symbols {
            // Length-zero slot would mean the table wasn't fully
            // covered, which `from_lengths` rejects — keep as a safety
            // net.
            return Err(Error::InvalidHuffmanTree);
        }
        Ok((sym, l))
    }
}

const fn reverse_bits(mut v: u32, n: u32) -> u32 {
    let mut out = 0u32;
    let mut i = 0;
    while i < n {
        out = (out << 1) | (v & 1);
        v >>= 1;
        i += 1;
    }
    out
}

// ─── header decode ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
struct Header {
    large_window: bool,
    lit_tree: bool,
    uncompressed_len: u32,
}

impl Header {
    fn parse(buf: &[u8; HEADER_LEN]) -> Result<Self, Error> {
        let f = buf[0];
        if f & 0b1111_1100 != 0 {
            return Err(Error::BadHeader);
        }
        let large_window = (f & 0b0000_0001) != 0;
        let lit_tree = (f & 0b0000_0010) != 0;
        let uncompressed_len = u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]);
        Ok(Self {
            large_window,
            lit_tree,
            uncompressed_len,
        })
    }

    /// `bdl` — number of raw low-distance bits per Implode's window flag.
    fn dist_low_bits(self) -> u8 {
        if self.large_window { 7 } else { 6 }
    }

    /// `min_len` — base added to the length symbol.
    fn min_len(self) -> u16 {
        if self.lit_tree { 3 } else { 2 }
    }
}

// ─── decoder state machine ──────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    AwaitHeader,
    AwaitLitTree,
    AwaitLenTree,
    AwaitDistTree,
    Decode,
    Done,
}

/// Streaming PKZIP Implode decoder.
pub struct Decoder {
    phase: Phase,

    // Header.
    header_buf: [u8; HEADER_LEN],
    header_pos: u8,
    header: Option<Header>,

    // Buffered compressed input — appended as the caller hands it to us
    // and drained from the front once the bit reader has safely consumed
    // it. We never *copy* every input byte permanently; we hold only the
    // bytes the bit reader has not yet committed plus any extra the
    // caller has handed us this call.
    in_buf: Vec<u8>,
    /// Bit position from the start of `in_buf`, LSB-first.
    bit_pos: usize,

    // The three trees. `lit_tree` is `None` in 2-tree mode.
    lit_tree: Option<ShannonFano>,
    len_tree: Option<ShannonFano>,
    dist_tree: Option<ShannonFano>,

    // Sliding window for back-references. Initial contents are zero so
    // that PKZIP's "distance past start of window emits a zero byte"
    // behaviour works for free.
    window: Vec<u8>,
    /// Write position in `window`.
    window_pos: usize,

    // Pending decoded bytes that have been written to the window but
    // not yet drained into the caller's output. Tracked as a window
    // slice [start, end) where end is `window_pos` and start chases it.
    pending_start: usize,
    pending_len: usize,

    // Output budget remaining: starts at `uncompressed_len` and counts
    // down as we emit bytes to the window. When zero, we transition to
    // Done.
    output_left: u32,
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder {
    pub fn new() -> Self {
        Self {
            phase: Phase::AwaitHeader,
            header_buf: [0u8; HEADER_LEN],
            header_pos: 0,
            header: None,
            in_buf: Vec::new(),
            bit_pos: 0,
            lit_tree: None,
            len_tree: None,
            dist_tree: None,
            window: vec![0u8; WINDOW_SIZE],
            window_pos: 0,
            pending_start: 0,
            pending_len: 0,
            output_left: 0,
        }
    }

    // ─── helpers ────────────────────────────────────────────────────

    /// Append new input to `in_buf`. We periodically compact when the bit
    /// reader has advanced past whole bytes to keep memory bounded.
    fn ingest(&mut self, input: &[u8]) {
        self.in_buf.extend_from_slice(input);
        // Compact whenever we've consumed at least 1 KiB of buffered
        // input, otherwise leave the bytes in place for cheap incremental
        // appending.
        let consumed_bytes = self.bit_pos / 8;
        if consumed_bytes >= 1024 {
            self.in_buf.drain(..consumed_bytes);
            self.bit_pos -= consumed_bytes * 8;
        }
    }

    /// Try to peek `n` bits LSB-first from the current bit position.
    /// Returns `None` if not enough input is buffered.
    fn peek_bits(&self, n: u32) -> Option<u32> {
        let total_bits = self.in_buf.len() * 8;
        if self.bit_pos + n as usize > total_bits {
            return None;
        }
        let mut acc: u64 = 0;
        let mut got = 0u32;
        let byte_idx = self.bit_pos / 8;
        let off = (self.bit_pos % 8) as u32;
        // Pull up to 8 bytes (64 bits) starting at byte_idx, shifted
        // down by `off`.
        let take = (n + off).div_ceil(8);
        for i in 0..take {
            let b = self.in_buf[byte_idx + i as usize];
            acc |= (b as u64) << (i * 8);
        }
        acc >>= off;
        if n < 32 {
            acc &= (1u64 << n) - 1;
        }
        got += n;
        let _ = got;
        Some(acc as u32)
    }

    /// Peek a 16-bit window for Huffman decoding. Pads with zeros if
    /// fewer than 16 bits are available; the caller must distinguish
    /// "not enough bits" up front using `bits_available`.
    fn peek16(&self) -> u16 {
        let total_bits = self.in_buf.len() * 8;
        let avail = total_bits.saturating_sub(self.bit_pos);
        let need = 16.min(avail);
        if need == 0 {
            return 0;
        }
        let byte_idx = self.bit_pos / 8;
        let off = (self.bit_pos % 8) as u32;
        // Read up to 3 bytes so a 16-bit field straddling a byte boundary
        // is fully covered.
        let mut acc: u32 = 0;
        let max = (self.in_buf.len() - byte_idx).min(3);
        for i in 0..max {
            acc |= (self.in_buf[byte_idx + i] as u32) << (i * 8);
        }
        acc >>= off;
        acc as u16
    }

    fn bits_available(&self) -> usize {
        let total_bits = self.in_buf.len() * 8;
        total_bits.saturating_sub(self.bit_pos)
    }

    fn advance(&mut self, n: u32) {
        self.bit_pos += n as usize;
    }

    fn snapshot(&self) -> usize {
        self.bit_pos
    }

    fn rollback(&mut self, snap: usize) {
        self.bit_pos = snap;
    }

    /// Write one byte to the window + count it as pending output.
    fn emit_byte(&mut self, b: u8) {
        self.window[self.window_pos] = b;
        self.window_pos = (self.window_pos + 1) & (WINDOW_SIZE - 1);
        self.pending_len += 1;
        self.output_left -= 1;
    }

    /// Drain pending window bytes into the caller's `out`. Returns the
    /// number of bytes written.
    fn drain(&mut self, out: &mut [u8]) -> usize {
        if self.pending_len == 0 || out.is_empty() {
            return 0;
        }
        let n = self.pending_len.min(out.len());
        // Wrap-aware copy.
        let mut wrote = 0usize;
        while wrote < n {
            let chunk = (WINDOW_SIZE - self.pending_start).min(n - wrote);
            out[wrote..wrote + chunk]
                .copy_from_slice(&self.window[self.pending_start..self.pending_start + chunk]);
            self.pending_start = (self.pending_start + chunk) & (WINDOW_SIZE - 1);
            wrote += chunk;
        }
        self.pending_len -= n;
        n
    }

    /// Read a Shannon–Fano code description from the bitstream. Used for
    /// each of the three trees. Returns `Ok(Some(tree))` if the tree was
    /// fully read; `Ok(None)` if more input is needed (no state change);
    /// `Err(_)` if the descriptor is malformed.
    fn try_read_tree(&mut self, num_symbols: usize) -> Result<Option<ShannonFano>, Error> {
        // The tree descriptor lives at byte-aligned positions in the
        // wire when produced by a real Implode encoder (the trees come
        // before any compressed bit), but per APPNOTE they appear at
        // the start of the file *as bytes*; we already require the
        // payload to begin byte-aligned (the framing places the codec
        // immediately after the 5-byte header). All bit reads must
        // therefore be byte-aligned at this point. We assert that and
        // read whole bytes via the buffered input directly.
        debug_assert_eq!(self.bit_pos & 7, 0);
        let byte_idx = self.bit_pos / 8;
        let avail = self.in_buf.len() - byte_idx;
        if avail < 1 {
            return Ok(None);
        }
        let count = self.in_buf[byte_idx] as usize + 1;
        // Need `count` pair bytes after the count byte.
        if avail < 1 + count {
            return Ok(None);
        }
        let mut lens = vec![0u8; num_symbols];
        let mut sym = 0usize;
        for i in 0..count {
            let pair = self.in_buf[byte_idx + 1 + i];
            let bits = (pair & 0x0F) + 1;
            let run = ((pair >> 4) & 0x0F) as usize + 1;
            if sym + run > num_symbols {
                return Err(Error::Corrupt);
            }
            for _ in 0..run {
                lens[sym] = bits;
                sym += 1;
            }
        }
        if sym != num_symbols {
            return Err(Error::Corrupt);
        }
        let tree = ShannonFano::from_lengths(&lens)?;
        // Advance past the bytes we consumed.
        self.bit_pos += 8 * (1 + count);
        Ok(Some(tree))
    }

    /// Attempt one decode step (one literal or one match). Returns
    /// `Ok(true)` on a successful step (one or more bytes emitted),
    /// `Ok(false)` if we need more input (state rewound), or an error.
    fn try_step(&mut self) -> Result<bool, Error> {
        let snap = self.snapshot();
        let hdr = self.header.expect("header must be set in Decode phase");

        // 1-bit selector.
        if self.bits_available() < 1 {
            return Ok(false);
        }
        let sel = self.peek_bits(1).unwrap();
        self.advance(1);

        if sel == 1 {
            // Literal.
            if let Some(ref tree) = self.lit_tree {
                // Literal-tree mode: need up to 16 bits.
                if self.bits_available() < 1 {
                    self.rollback(snap);
                    return Ok(false);
                }
                let bits = self.peek16();
                let (sym, used) = tree.decode(bits)?;
                if (used as usize) > self.bits_available() {
                    self.rollback(snap);
                    return Ok(false);
                }
                self.advance(used as u32);
                self.emit_byte(sym as u8);
            } else {
                // No-literal-tree mode: read 8 raw bits.
                if self.bits_available() < 8 {
                    self.rollback(snap);
                    return Ok(false);
                }
                let b = self.peek_bits(8).unwrap() as u8;
                self.advance(8);
                self.emit_byte(b);
            }
            return Ok(true);
        }

        // Match: low dist bits + dist-tree code + len-tree code + maybe
        // 8-bit extra. We try to peek enough bits for the whole step
        // before committing.
        let bdl = hdr.dist_low_bits() as u32;
        if self.bits_available() < bdl as usize {
            self.rollback(snap);
            return Ok(false);
        }
        let dist_low = self.peek_bits(bdl).unwrap();
        self.advance(bdl);

        // Distance Huffman.
        let dist_tree = self
            .dist_tree
            .as_ref()
            .expect("dist_tree set before Decode phase");
        let bits = self.peek16();
        let (dist_hi, dist_used) = dist_tree.decode(bits)?;
        if (dist_used as usize) > self.bits_available() {
            self.rollback(snap);
            return Ok(false);
        }
        self.advance(dist_used as u32);

        // Length Huffman.
        let len_tree = self
            .len_tree
            .as_ref()
            .expect("len_tree set before Decode phase");
        let bits = self.peek16();
        let (len_sym, len_used) = len_tree.decode(bits)?;
        if (len_used as usize) > self.bits_available() {
            self.rollback(snap);
            return Ok(false);
        }
        self.advance(len_used as u32);

        let mut len = len_sym as u32;
        if len_sym == 63 {
            // Extra 8 bits.
            if self.bits_available() < 8 {
                self.rollback(snap);
                return Ok(false);
            }
            let extra = self.peek_bits(8).unwrap();
            self.advance(8);
            len += extra;
        }
        len += hdr.min_len() as u32;
        let dist = ((dist_hi as u32) << bdl) | dist_low;
        let dist = (dist + 1) as usize;

        // Bounds: dist > 0; PKZIP semantics treat "look-back past start of
        // window" as reading the implicit-zero pre-window. With a window
        // pre-filled with zeros and a sliding `window_pos` this works
        // naturally — we just need to never overflow the output budget.
        if len > self.output_left {
            return Err(Error::Corrupt);
        }
        for _ in 0..len {
            let src = (self.window_pos + WINDOW_SIZE - dist) & (WINDOW_SIZE - 1);
            let b = self.window[src];
            self.emit_byte(b);
        }
        Ok(true)
    }
}

impl RawDecoder for Decoder {
    fn raw_decode(&mut self, input: &[u8], output: &mut [u8]) -> Result<RawProgress, Error> {
        let in_len = input.len();
        let mut written = 0usize;

        // Snapshot pre-call in_buf length so we can compute the byte
        // count "consumed from the caller's slice". We do not consume
        // from `input` directly — everything is staged through `in_buf`
        // — but for the streaming-traits contract we report the full
        // input length as consumed once it's been ingested (the bit
        // reader's actual position may lag behind by a few bytes
        // pending future calls).
        self.ingest(input);

        loop {
            // First: drain pending bytes into the caller's output.
            if self.pending_len > 0 {
                written += self.drain(&mut output[written..]);
                if written == output.len() && self.pending_len > 0 {
                    return Ok(RawProgress {
                        consumed: in_len,
                        written,
                        done: false,
                    });
                }
            }

            match self.phase {
                Phase::AwaitHeader => {
                    let avail_bytes = self.in_buf.len() - self.bit_pos / 8;
                    let need = HEADER_LEN - self.header_pos as usize;
                    let take = need.min(avail_bytes);
                    let byte_idx = self.bit_pos / 8;
                    for i in 0..take {
                        self.header_buf[self.header_pos as usize] = self.in_buf[byte_idx + i];
                        self.header_pos += 1;
                    }
                    self.bit_pos += take * 8;
                    if (self.header_pos as usize) < HEADER_LEN {
                        return Ok(RawProgress {
                            consumed: in_len,
                            written,
                            done: false,
                        });
                    }
                    let hdr = Header::parse(&self.header_buf)?;
                    self.output_left = hdr.uncompressed_len;
                    self.header = Some(hdr);
                    self.phase = if hdr.lit_tree {
                        Phase::AwaitLitTree
                    } else {
                        Phase::AwaitLenTree
                    };
                    // Empty file shortcut: an explicitly zero-length
                    // payload still carries the tree descriptors per the
                    // wire format, so we don't fast-path to Done here.
                }
                Phase::AwaitLitTree => match self.try_read_tree(LIT_SYMBOLS)? {
                    Some(t) => {
                        self.lit_tree = Some(t);
                        self.phase = Phase::AwaitLenTree;
                    }
                    None => {
                        return Ok(RawProgress {
                            consumed: in_len,
                            written,
                            done: false,
                        });
                    }
                },
                Phase::AwaitLenTree => match self.try_read_tree(LEN_SYMBOLS)? {
                    Some(t) => {
                        self.len_tree = Some(t);
                        self.phase = Phase::AwaitDistTree;
                    }
                    None => {
                        return Ok(RawProgress {
                            consumed: in_len,
                            written,
                            done: false,
                        });
                    }
                },
                Phase::AwaitDistTree => match self.try_read_tree(DIST_SYMBOLS)? {
                    Some(t) => {
                        self.dist_tree = Some(t);
                        self.phase = if self.output_left == 0 {
                            Phase::Done
                        } else {
                            Phase::Decode
                        };
                    }
                    None => {
                        return Ok(RawProgress {
                            consumed: in_len,
                            written,
                            done: false,
                        });
                    }
                },
                Phase::Decode => {
                    if self.output_left == 0 {
                        self.phase = Phase::Done;
                        continue;
                    }
                    if !self.try_step()? {
                        return Ok(RawProgress {
                            consumed: in_len,
                            written,
                            done: false,
                        });
                    }
                    // Loop back to drain.
                }
                Phase::Done => {
                    return Ok(RawProgress {
                        consumed: in_len,
                        written,
                        done: self.pending_len == 0,
                    });
                }
            }
        }
    }

    fn raw_finish(&mut self, output: &mut [u8]) -> Result<RawProgress, Error> {
        let mut written = 0usize;
        // Drain any pending bytes first.
        if self.pending_len > 0 {
            written += self.drain(output);
        }
        // Try to make more progress without new input.
        loop {
            if self.pending_len > 0 {
                written += self.drain(&mut output[written..]);
                if written == output.len() && self.pending_len > 0 {
                    return Ok(RawProgress {
                        consumed: 0,
                        written,
                        done: false,
                    });
                }
            }
            match self.phase {
                Phase::Done => {
                    return Ok(RawProgress {
                        consumed: 0,
                        written,
                        done: self.pending_len == 0,
                    });
                }
                Phase::Decode => {
                    if self.output_left == 0 {
                        self.phase = Phase::Done;
                        continue;
                    }
                    match self.try_step() {
                        Ok(true) => continue,
                        Ok(false) => return Err(Error::UnexpectedEnd),
                        Err(e) => return Err(e),
                    }
                }
                _ => return Err(Error::UnexpectedEnd),
            }
        }
    }

    fn raw_reset(&mut self) {
        self.phase = Phase::AwaitHeader;
        self.header_buf = [0u8; HEADER_LEN];
        self.header_pos = 0;
        self.header = None;
        self.in_buf.clear();
        self.bit_pos = 0;
        self.lit_tree = None;
        self.len_tree = None;
        self.dist_tree = None;
        for b in self.window.iter_mut() {
            *b = 0;
        }
        self.window_pos = 0;
        self.pending_start = 0;
        self.pending_len = 0;
        self.output_left = 0;
    }
}

// ─── unit tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_round_trip() {
        let buf = [0b11u8, 0xAA, 0xBB, 0xCC, 0xDD];
        let h = Header::parse(&buf).unwrap();
        assert!(h.large_window);
        assert!(h.lit_tree);
        assert_eq!(h.uncompressed_len, 0xDDCC_BBAA);
        assert_eq!(h.dist_low_bits(), 7);
        assert_eq!(h.min_len(), 3);
    }

    #[test]
    fn header_rejects_reserved_bits() {
        let buf = [0b1000u8, 0, 0, 0, 0];
        assert!(matches!(Header::parse(&buf), Err(Error::BadHeader)));
    }

    #[test]
    fn shannon_fano_single_symbol_tree_rejected() {
        // A 1-symbol tree at length 1 has Kraft sum 1/2, not 1.
        let lens = [1u8];
        assert!(ShannonFano::from_lengths(&lens).is_err());
    }

    #[test]
    fn shannon_fano_two_symbols_length_one() {
        // Two symbols at 1 bit each: full canonical, codewords 0 and 1.
        // Implode reverses → symbol 0 gets code 1 (LSB), symbol 1 gets 0.
        let lens = [1u8, 1u8];
        let t = ShannonFano::from_lengths(&lens).unwrap();
        // After complementing the wire bits, idx 0 → symbol that was
        // assigned canonical code 1 (which after wire-complement is bit
        // 0). Verify the lookup works for both possible 1-bit inputs.
        let (s0, u0) = t.decode(0).unwrap();
        let (s1, u1) = t.decode(1).unwrap();
        assert_eq!(u0, 1);
        assert_eq!(u1, 1);
        // Both lookups must resolve, and they must produce different
        // symbols — exact symbol depends on canonical assignment order.
        assert_ne!(s0, s1);
    }
}
