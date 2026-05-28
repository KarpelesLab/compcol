//! Brotli (RFC 7932) — partial-but-functional implementation.
//!
//! Reference: <https://datatracker.ietf.org/doc/html/rfc7932>.
//!
//! # Scope of this build
//!
//! - **Encoder**: emits uncompressed-only Brotli streams. Output is a
//!   valid Brotli stream (the reference `brotli -d` accepts it) but is
//!   literally larger than the input — uncompressed-only is a
//!   correctness-first fallback, not a compression strategy.
//!
//! - **Decoder**: parses the stream header, walks the meta-block chain,
//!   and decodes:
//!   - the empty last meta-block,
//!   - metadata meta-blocks (skipped),
//!   - uncompressed meta-blocks,
//!   - **compressed meta-blocks** including simple and complex prefix
//!     codes, block-type / block-count / context-map machinery,
//!     literal context modelling, distance ring buffer, and static
//!     dictionary references via the 121-entry transform table.
//!
//! The static dictionary (Appendix A) is embedded verbatim from the
//! reference `dictionary.bin` (122,784 bytes, SHA-256
//! `20e42eb1b511c21806d4d227d07e5dd06877d8ce7b3a817f378f313653f35c70`)
//! via `include_bytes!`.
//!
//! The decoder is **buffered**: each compressed meta-block is read in
//! full into an internal buffer, then decoded synchronously, then its
//! output is streamed to the caller. The streaming API is honoured at
//! the meta-block boundary. Memory use is proportional to the largest
//! meta-block in the stream (≤ 16 MiB per spec; in practice ≤ ~256 KiB
//! for level-1+ encoders).
//!
//! Bit ordering is LSB-first within each byte (same as deflate).
//!
//! # Not implemented
//!
//! - The large-window flag (WBITS first bit = 1, next 3 bits = 0,
//!   next 3 bits = 1) is rejected as `Unsupported`.
//! - Compressed-meta-block **encoding** (encoder stays uncompressed).

use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;
use crate::traits::{Algorithm, Decoder as DecoderTrait, Encoder as EncoderTrait, Progress};

mod context;
mod dictionary;
mod huffman;
mod transforms;

use context::ContextMode;
use huffman::{BitSource, HuffmanDecoder};

/// Zero-sized marker type implementing [`Algorithm`] for Brotli.
#[derive(Debug, Clone, Copy, Default)]
pub struct Brotli;

impl Algorithm for Brotli {
    const NAME: &'static str = "brotli";
    type Encoder = Encoder;
    type Decoder = Decoder;
    fn encoder() -> Encoder {
        Encoder::new()
    }
    fn decoder() -> Decoder {
        Decoder::new()
    }
}

// ─── shared bit primitives ───────────────────────────────────────────────
//
// LSB-first throughout. The encoder uses a streaming BitWriter; the
// decoder buffers raw stream bytes and decodes from them with a
// `BitSource` (defined in `huffman.rs`).

/// LSB-first bit writer that accumulates into a u64 and drains whole
/// bytes into a `Vec<u8>`. Used only by the encoder.
#[derive(Debug, Clone, Default)]
struct BitWriter {
    acc: u64,
    nbits: u32,
}

impl BitWriter {
    const fn new() -> Self {
        Self { acc: 0, nbits: 0 }
    }
    fn write(&mut self, value: u32, n: u32, out: &mut Vec<u8>) {
        debug_assert!(n <= 32);
        let masked: u64 = if n == 0 {
            0
        } else {
            (value as u64) & ((1u64 << n) - 1)
        };
        self.acc |= masked << self.nbits;
        self.nbits += n;
        while self.nbits >= 8 {
            out.push(self.acc as u8);
            self.acc >>= 8;
            self.nbits -= 8;
        }
    }
    fn align(&mut self, out: &mut Vec<u8>) {
        if self.nbits > 0 {
            out.push(self.acc as u8);
            self.acc = 0;
            self.nbits = 0;
        }
    }
    const fn pending_bits(&self) -> u32 {
        self.nbits
    }
}

// ─── encoder ────────────────────────────────────────────────────────────
//
// Wire format produced:
//
//   WBITS = 16            (1 bit  = 0)
//   [meta-block]*         (zero or more non-final uncompressed meta-blocks)
//   ISLAST=1, ISLASTEMPTY=1, pad to byte

const MAX_BLOCK: usize = 1 << 16; // 65_536

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EncStage {
    NeedHeader,
    Buffering,
    Draining,
    Done,
}

#[derive(Debug, Clone)]
pub struct Encoder {
    pending: Vec<u8>,
    out: Vec<u8>,
    out_pos: usize,
    bw: BitWriter,
    stage: EncStage,
}

impl Encoder {
    pub fn new() -> Self {
        Self {
            pending: Vec::new(),
            out: Vec::new(),
            out_pos: 0,
            bw: BitWriter::new(),
            stage: EncStage::NeedHeader,
        }
    }

    fn compact_out(&mut self) {
        if self.out_pos == 0 {
            return;
        }
        if self.out_pos >= self.out.len() {
            self.out.clear();
        } else {
            self.out.drain(..self.out_pos);
        }
        self.out_pos = 0;
    }

    fn drain_out_into(&mut self, dst: &mut [u8]) -> usize {
        let avail = self.out.len() - self.out_pos;
        let n = avail.min(dst.len());
        if n > 0 {
            dst[..n].copy_from_slice(&self.out[self.out_pos..self.out_pos + n]);
            self.out_pos += n;
        }
        n
    }

    fn ensure_header(&mut self) {
        if self.stage == EncStage::NeedHeader {
            self.bw.write(0, 1, &mut self.out);
            self.stage = EncStage::Buffering;
        }
    }

    fn emit_uncompressed_block(&mut self, mlen: usize) {
        debug_assert!((1..=MAX_BLOCK).contains(&mlen));
        debug_assert!(mlen <= self.pending.len());
        self.bw.write(0, 1, &mut self.out);
        self.bw.write(0, 2, &mut self.out);
        let mlen_m1 = (mlen - 1) as u32;
        self.bw.write(mlen_m1, 16, &mut self.out);
        self.bw.write(1, 1, &mut self.out);
        self.bw.align(&mut self.out);
        self.out.extend_from_slice(&self.pending[..mlen]);
        self.pending.drain(..mlen);
    }

    fn flush_full_blocks(&mut self) {
        while self.pending.len() >= MAX_BLOCK {
            self.emit_uncompressed_block(MAX_BLOCK);
        }
    }

    fn emit_terminator(&mut self) {
        if !self.pending.is_empty() {
            let n = self.pending.len();
            debug_assert!(n < MAX_BLOCK);
            self.emit_uncompressed_block(n);
        }
        self.bw.write(1, 1, &mut self.out);
        self.bw.write(1, 1, &mut self.out);
        self.bw.align(&mut self.out);
        debug_assert_eq!(self.bw.pending_bits(), 0);
    }
}

impl Default for Encoder {
    fn default() -> Self {
        Self::new()
    }
}

impl EncoderTrait for Encoder {
    fn encode(&mut self, input: &[u8], output: &mut [u8]) -> Result<Progress, Error> {
        if self.stage == EncStage::Done {
            return Err(Error::Corrupt);
        }
        let mut written = 0usize;
        if self.out_pos < self.out.len() {
            written += self.drain_out_into(&mut output[written..]);
            if written == output.len() {
                return Ok(Progress {
                    consumed: 0,
                    written,
                    done: false,
                });
            }
        }
        self.compact_out();
        self.ensure_header();
        self.pending.extend_from_slice(input);
        let consumed = input.len();
        self.flush_full_blocks();
        written += self.drain_out_into(&mut output[written..]);
        self.compact_out();
        Ok(Progress {
            consumed,
            written,
            done: false,
        })
    }

    fn finish(&mut self, output: &mut [u8]) -> Result<Progress, Error> {
        if self.stage == EncStage::Done {
            return Ok(Progress {
                consumed: 0,
                written: 0,
                done: true,
            });
        }
        let mut written = 0usize;
        if self.out_pos < self.out.len() {
            written += self.drain_out_into(&mut output[written..]);
            if written == output.len() {
                return Ok(Progress {
                    consumed: 0,
                    written,
                    done: false,
                });
            }
        }
        self.compact_out();
        if self.stage != EncStage::Draining {
            self.ensure_header();
            self.flush_full_blocks();
            self.emit_terminator();
            self.stage = EncStage::Draining;
        }
        written += self.drain_out_into(&mut output[written..]);
        self.compact_out();
        let done = self.out_pos == self.out.len();
        if done {
            self.stage = EncStage::Done;
        }
        Ok(Progress {
            consumed: 0,
            written,
            done,
        })
    }

    fn reset(&mut self) {
        self.pending.clear();
        self.out.clear();
        self.out_pos = 0;
        self.bw = BitWriter::new();
        self.stage = EncStage::NeedHeader;
    }
}

// ─── decoder ────────────────────────────────────────────────────────────
//
// Strategy:
//
//   1. Accumulate input bytes into `raw`.
//   2. While we can make progress: try to parse the next meta-block
//      from `raw` starting at `bit_pos`. If parsing fails with
//      `UnexpectedEnd`, return to the outer loop (caller must supply
//      more bytes).
//   3. Uncompressed meta-block bytes feed `out`. Compressed meta-block
//      output also feeds `out`. Metadata is silently discarded.
//   4. Drain `out` into the caller's `output` slice as room permits.
//
// `raw` keeps growing until a meta-block is fully consumed, at which
// point we compact it to the current bit position.

const NUM_LITERAL_SYMBOLS: u32 = 256;
const NUM_COMMAND_SYMBOLS: u32 = 704;
const NUM_BLOCK_LEN_SYMBOLS: u32 = 26;
/// Code-length symbol order from §3.5 (complex prefix code preamble).
const CODE_LENGTH_ORDER: [usize; 18] =
    [1, 2, 3, 4, 0, 5, 17, 6, 16, 7, 8, 9, 10, 11, 12, 13, 14, 15];

/// Block length base + extra bits per §9.2 (also used inline for
/// block-count first reads in the header).
const BLOCK_LEN_BASE: [u32; 26] = [
    1, 5, 9, 13, 17, 25, 33, 41, 49, 65, 81, 97, 113, 145, 177, 209, 241, 305, 369, 497, 753, 1265,
    2289, 4337, 8433, 16625,
];
const BLOCK_LEN_EXTRA: [u32; 26] = [
    2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 6, 6, 7, 8, 9, 10, 11, 12, 13, 24,
];

/// Insert length code → (extra bits, base) per §5.
const INS_EXTRA: [u32; 24] = [
    0, 0, 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 7, 8, 9, 10, 12, 14, 24,
];
const INS_BASE: [u32; 24] = [
    0, 1, 2, 3, 4, 5, 6, 8, 10, 14, 18, 26, 34, 50, 66, 98, 130, 194, 322, 578, 1090, 2114, 6210,
    22594,
];

/// Copy length code → (extra bits, base) per §5.
const COPY_EXTRA: [u32; 24] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 7, 8, 9, 10, 24,
];
const COPY_BASE: [u32; 24] = [
    2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 14, 18, 22, 30, 38, 54, 70, 102, 134, 198, 326, 582, 1094, 2118,
];

#[derive(Debug)]
pub struct Decoder {
    /// Buffered stream bytes. We may keep up to one meta-block's worth
    /// here; trimmed once the bit-position passes complete bytes.
    raw: Vec<u8>,
    /// Bit position into `raw`. Always references bits we have not yet
    /// committed to the output.
    bit_pos: usize,
    /// Decoded output queued for the caller. Pushed to from both the
    /// uncompressed and compressed paths.
    out: Vec<u8>,
    out_pos: usize,
    /// Decoder state.
    state: DecState,
    poisoned: bool,
    /// Window size in bytes (1 << wbits). Per §9.1 the back-reference
    /// max distance is `window_size - 16`.
    window_size: u32,
    /// Distance ring buffer (last four distances), initialised to
    /// `[16, 15, 11, 4]` with index 3 being the most recent.
    dist_ring: [i32; 4],
    /// Cursor into `dist_ring`: increments with each pushed distance.
    /// `dist_ring[(ring_idx + 3) & 3]` is the most recent distance.
    ring_idx: u32,
    /// Total bytes ever decoded (sticky across meta-blocks).
    total_out: usize,
    /// The last two bytes ever emitted (`p1` is the most recent, `p2`
    /// is the second-most-recent), used to look up literal contexts.
    p1: u8,
    p2: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DecState {
    /// Haven't read the stream header yet.
    NeedHeader,
    /// Header consumed; about to read the next meta-block.
    NeedMetaBlock,
    /// Stream finished.
    Done,
}

impl Decoder {
    pub fn new() -> Self {
        Self {
            raw: Vec::new(),
            bit_pos: 0,
            out: Vec::new(),
            out_pos: 0,
            state: DecState::NeedHeader,
            poisoned: false,
            window_size: 1 << 16,
            // Initial ring buffer per §4. The spec lists the four
            // most recent distances as 16, 15, 11, 4 in
            // (fourth-to-last → last) order. So the *most* recent
            // initial distance is 4.
            //
            // The C reference stores the ring as
            // `dist_rb[0..4] = {16, 15, 11, 4}` with `dist_rb_idx = 0`,
            // and short-code 0 reads from `dist_rb[(idx + 3) & 3]`
            // (i.e. slot 3 initially → 4). We mirror this layout.
            dist_ring: [16, 15, 11, 4],
            ring_idx: 0,
            total_out: 0,
            p1: 0,
            p2: 0,
        }
    }

    /// Most-recently-pushed distance. Equivalent to `nth_last_dist(1)`.
    /// With the C-style indexing this is `dist_ring[(ring_idx + 3) & 3]`.
    fn last_dist(&self) -> i32 {
        self.dist_ring[((self.ring_idx.wrapping_add(3)) & 3) as usize]
    }

    /// Get the i-th most-recently-pushed distance (i = 1..=4).
    fn nth_last_dist(&self, i: u32) -> i32 {
        debug_assert!((1..=4).contains(&i));
        let idx = self.ring_idx.wrapping_add(4 - i) & 3;
        self.dist_ring[idx as usize]
    }

    fn push_dist(&mut self, d: i32) {
        let slot = (self.ring_idx & 3) as usize;
        self.dist_ring[slot] = d;
        self.ring_idx = self.ring_idx.wrapping_add(1);
    }

    fn poison(&mut self, e: Error) -> Error {
        self.poisoned = true;
        e
    }

    /// Trim `raw` to byte-align with `bit_pos`. Cheaper than re-allocating
    /// every meta-block; we just drain whole bytes that we've already
    /// committed.
    fn compact_raw(&mut self) {
        let drop_bytes = self.bit_pos >> 3;
        if drop_bytes > 0 {
            self.raw.drain(..drop_bytes);
            self.bit_pos -= drop_bytes * 8;
        }
    }

    /// Drain queued output into the caller's buffer.
    fn drain_out_into(&mut self, dst: &mut [u8]) -> usize {
        let avail = self.out.len() - self.out_pos;
        let n = avail.min(dst.len());
        if n > 0 {
            dst[..n].copy_from_slice(&self.out[self.out_pos..self.out_pos + n]);
            self.out_pos += n;
        }
        n
    }

    /// Compact the output queue, retaining the last `window_size` bytes
    /// of history for back-references. Caller-consumed bytes beyond the
    /// retained history are dropped.
    fn compact_out(&mut self) {
        if self.out_pos == 0 {
            return;
        }
        let want_history = self.window_size as usize;
        // Cap the working buffer at `want_history` bytes of history
        // plus any not-yet-delivered output. We never drop output that
        // hasn't been written to the caller.
        let unread = self.out.len() - self.out_pos;
        let total_keep_target = want_history + unread;
        if self.out.len() <= total_keep_target {
            // Everything currently in `out` fits in window+queue: leave
            // it untouched. out_pos stays as the read cursor; we just
            // don't drop anything.
            return;
        }
        let drop_n = self.out.len() - total_keep_target;
        let drop_n = drop_n.min(self.out_pos);
        if drop_n > 0 {
            self.out.drain(..drop_n);
            self.out_pos -= drop_n;
        }
    }

    /// Try to parse the stream header. Returns Ok(true) when consumed,
    /// Ok(false) when we need more bytes, Err on rejection.
    fn read_stream_header(&mut self) -> Result<bool, Error> {
        // Need at most 7 bits.
        let mut src = BitSource::at(&self.raw, self.bit_pos);
        let total_bits = self.raw.len() * 8 - self.bit_pos;
        if total_bits < 1 {
            return Ok(false);
        }
        let pos_save = src.position();
        let b0 = src.read_bit()?;
        if b0 == 0 {
            // WBITS = 16
            self.window_size = 1 << 16;
            self.bit_pos = src.position();
            return Ok(true);
        }
        if total_bits < 4 {
            return Ok(false);
        }
        let n = src.read_bits(3)? as u8;
        if n != 0 {
            // WBITS = 17 + n, in [18..=24].
            let wbits = 17 + n as u32;
            self.window_size = 1u32 << wbits;
            self.bit_pos = src.position();
            return Ok(true);
        }
        if total_bits < 7 {
            // Restore.
            src.set_position(pos_save);
            return Ok(false);
        }
        let m = src.read_bits(3)? as u8;
        match m {
            0 => {
                self.window_size = 1 << 17;
                self.bit_pos = src.position();
                Ok(true)
            }
            1 => Err(Error::Unsupported), // large-window flag
            _ => {
                // WBITS = 8 + m, in [10..=15].
                let wbits = 8 + m as u32;
                self.window_size = 1u32 << wbits;
                self.bit_pos = src.position();
                Ok(true)
            }
        }
    }

    /// Try to parse and execute the next meta-block. Returns Ok(true)
    /// when a meta-block (or the stream terminator) was processed,
    /// Ok(false) when we lack bytes, Err on a hard failure.
    fn process_next_meta_block(&mut self) -> Result<bool, Error> {
        // Snapshot in case we run out of bits mid-parse.
        let start_bit_pos = self.bit_pos;
        match self.try_process_meta_block() {
            Ok(()) => Ok(true),
            Err(Error::UnexpectedEnd) => {
                // Roll back to where we were so a later call retries.
                self.bit_pos = start_bit_pos;
                Ok(false)
            }
            Err(e) => Err(e),
        }
    }

    fn try_process_meta_block(&mut self) -> Result<(), Error> {
        // Clone the raw byte buffer for the duration of this meta-block
        // decode. The decoder mutates `self` (output, ring buffer,
        // p1/p2) while reading bits, and tying the BitSource's lifetime
        // to `self.raw` would conflict with those mutations. The clone
        // is cheap relative to the work done with it.
        let raw = self.raw.clone();
        let mut src = BitSource::at(&raw, self.bit_pos);
        let initial_pos = self.bit_pos;
        let is_last = src.read_bit()? != 0;
        let mut is_last_empty = false;
        if is_last {
            is_last_empty = src.read_bit()? != 0;
            if is_last_empty {
                // Stream terminator. Any trailing pad bits in this
                // byte must be zero per spec; we don't enforce it.
                self.bit_pos = src.position();
                self.state = DecState::Done;
                return Ok(());
            }
        }
        // MNIBBLES
        let nibbles = src.read_bits(2)?;
        if nibbles == 3 {
            // Metadata path. Per §9.2 a metadata meta-block may not be
            // the last one in a stream — but encoders in practice still
            // produce them only mid-stream, so we just verify is_last
            // is false.
            if is_last {
                return Err(Error::Corrupt);
            }
            // Reserved bit, must be 0.
            let r = src.read_bit()?;
            if r != 0 {
                return Err(Error::Corrupt);
            }
            let mskip_bytes = src.read_bits(2)?;
            let mskiplen = if mskip_bytes == 0 {
                0u32
            } else {
                let mut acc: u32 = 0;
                for i in 0..mskip_bytes {
                    let b = src.read_bits(8)?;
                    acc |= b << (i * 8);
                }
                // Top byte must not be zero when more than one byte read.
                if mskip_bytes > 1 {
                    let top = (acc >> ((mskip_bytes - 1) * 8)) & 0xFF;
                    if top == 0 {
                        return Err(Error::Corrupt);
                    }
                }
                acc + 1
            };
            src.align_to_byte();
            // Need `mskiplen` raw bytes after alignment. Check we have
            // them; otherwise UnexpectedEnd.
            let byte_pos = src.position() / 8;
            let need = byte_pos + mskiplen as usize;
            if self.raw.len() < need {
                return Err(Error::UnexpectedEnd);
            }
            // Skip metadata bytes (they aren't emitted).
            src.set_position(need * 8);
            self.bit_pos = src.position();
            self.compact_raw();
            return Ok(());
        }

        let nibbles = nibbles + 4; // 4, 5, or 6 nibbles
        let mut mlen_minus_1: u32 = 0;
        for i in 0..nibbles {
            let nb = src.read_bits(4)?;
            mlen_minus_1 |= nb << (i * 4);
        }
        if nibbles > 4 {
            let top_shift = (nibbles - 1) * 4;
            if ((mlen_minus_1 >> top_shift) & 0xF) == 0 {
                return Err(Error::Corrupt);
            }
        }
        let mlen = mlen_minus_1 + 1;

        let is_uncompressed = if !is_last {
            src.read_bit()? != 0
        } else {
            false
        };

        if is_last && is_last_empty {
            // Already handled above.
            unreachable!();
        }

        if is_uncompressed {
            // Byte-align and copy MLEN raw bytes.
            src.align_to_byte();
            let byte_pos = src.position() / 8;
            let need = byte_pos + mlen as usize;
            if self.raw.len() < need {
                return Err(Error::UnexpectedEnd);
            }
            let slice = self.raw[byte_pos..need].to_vec();
            // Push to output and update p1/p2/total.
            for b in &slice {
                self.emit_literal(*b);
            }
            src.set_position(need * 8);
            self.bit_pos = src.position();
            self.compact_raw();
            return Ok(());
        }

        // ─── compressed meta-block ───
        // Decode in one shot. For simplicity, our parsing routines
        // consume bytes from `self.raw` via the `BitSource`, and the
        // outer caller handles UnexpectedEnd by rolling back bit_pos.
        // Snapshot the global ring buffer / context state so a partial
        // decode (UnexpectedEnd mid-way) doesn't leave behind side
        // effects on the next retry.
        let snap = (
            self.dist_ring,
            self.ring_idx,
            self.p1,
            self.p2,
            self.total_out,
            self.out.len(),
        );
        if let Err(e) = self.decode_compressed_meta_block(&mut src, mlen) {
            if e == Error::UnexpectedEnd {
                // Roll back. The caller will retry with more bytes.
                self.dist_ring = snap.0;
                self.ring_idx = snap.1;
                self.p1 = snap.2;
                self.p2 = snap.3;
                self.total_out = snap.4;
                self.out.truncate(snap.5);
            }
            self.bit_pos = initial_pos;
            return Err(e);
        }
        self.bit_pos = src.position();
        self.compact_raw();
        if is_last {
            self.state = DecState::Done;
        }
        Ok(())
    }

    /// Emit one literal byte to the output and rotate p1/p2.
    fn emit_literal(&mut self, b: u8) {
        self.out.push(b);
        self.p2 = self.p1;
        self.p1 = b;
        self.total_out += 1;
    }

    /// Emit a backward-reference copy of `len` bytes starting `distance`
    /// bytes before the current write position. `self.out` must contain
    /// at least the last `distance` bytes of history for this to
    /// succeed.
    fn emit_copy(&mut self, distance: u32, len: u32) -> Result<(), Error> {
        if distance as usize > self.total_out {
            return Err(Error::InvalidDistance);
        }
        let out_base = self.total_out - self.out.len();
        for _ in 0..len {
            let g = (self.total_out as u64) - (distance as u64);
            if g < out_base as u64 {
                // Distance reaches further back than the retained
                // window. With our `compact_out` retaining
                // `window_size` bytes this should not happen for valid
                // streams (Brotli back-references are capped at
                // `window_size - 16`).
                return Err(Error::InvalidDistance);
            }
            let byte = self.out[(g - out_base as u64) as usize];
            self.emit_literal(byte);
        }
        Ok(())
    }

    /// Read NBLTYPES* per §9.2 (the 1..=256 prefix-encoded counter).
    fn read_nbltypes(src: &mut BitSource<'_>) -> Result<u32, Error> {
        // 1 bit: 0 => value 1
        let first = src.read_bit()?;
        if first == 0 {
            return Ok(1);
        }
        // Next 3 bits select the range; 0..=7 → bases 1, 2, 3..=4, 5..=8, ...
        // We re-implement the standard variable-length encoder used here:
        //   read 3 bits N (the "log2-1" effectively)
        //   if N == 0 → value = 2
        //   else      → value = (1 << N) + 1 + read_bits(N)
        let n = src.read_bits(3)?;
        if n == 0 {
            return Ok(2);
        }
        let extra = src.read_bits(n)?;
        Ok((1u32 << n) + 1 + extra)
    }

    /// Read a Brotli prefix code (simple or complex) over `alphabet_size`
    /// symbols. Returns the constructed HuffmanDecoder.
    fn read_prefix_code(
        src: &mut BitSource<'_>,
        alphabet_size: u32,
    ) -> Result<HuffmanDecoder, Error> {
        let kind = src.read_bits(2)?;
        if kind == 1 {
            // Simple prefix code.
            return Self::read_simple_prefix_code(src, alphabet_size);
        }
        // Complex prefix code. `kind` here is the HSKIP (0, 2, or 3).
        let hskip = kind;
        Self::read_complex_prefix_code(src, alphabet_size, hskip)
    }

    fn read_simple_prefix_code(
        src: &mut BitSource<'_>,
        alphabet_size: u32,
    ) -> Result<HuffmanDecoder, Error> {
        let nsym = src.read_bits(2)? + 1; // 1..=4
        let alpha_bits = alphabet_bits(alphabet_size);
        let mut syms = [0u32; 4];
        for i in 0..nsym {
            let s = src.read_bits(alpha_bits)?;
            if s >= alphabet_size {
                return Err(Error::Corrupt);
            }
            for j in 0..i {
                if syms[j as usize] == s {
                    return Err(Error::Corrupt);
                }
            }
            syms[i as usize] = s;
        }
        match nsym {
            1 => Ok(HuffmanDecoder::single(syms[0])),
            2 => {
                // Both length 1, sorted ascending.
                let mut a = syms[0];
                let mut b = syms[1];
                if a > b {
                    core::mem::swap(&mut a, &mut b);
                }
                HuffmanDecoder::from_lengths_sparse(&[(a, 1), (b, 1)])
            }
            3 => {
                // Lengths 1, 2, 2 in the order of listed symbols. The
                // length-2 symbols are sorted by symbol value.
                let l1 = syms[0];
                let mut s2 = syms[1];
                let mut s3 = syms[2];
                if s2 > s3 {
                    core::mem::swap(&mut s2, &mut s3);
                }
                HuffmanDecoder::from_lengths_sparse(&[(l1, 1), (s2, 2), (s3, 2)])
            }
            4 => {
                let tree_select = src.read_bit()?;
                if tree_select == 0 {
                    // Lengths 2,2,2,2 sorted by symbol value
                    let mut all = [syms[0], syms[1], syms[2], syms[3]];
                    all.sort();
                    HuffmanDecoder::from_lengths_sparse(&[
                        (all[0], 2),
                        (all[1], 2),
                        (all[2], 2),
                        (all[3], 2),
                    ])
                } else {
                    // Lengths 1, 2, 3, 3 in symbol order. The two
                    // length-3 symbols are sorted by symbol value.
                    // Per spec, symbols are listed in this order:
                    // syms[0] length 1, syms[1] length 2, syms[2..4]
                    // length 3 (sorted).
                    let mut c = syms[2];
                    let mut d = syms[3];
                    if c > d {
                        core::mem::swap(&mut c, &mut d);
                    }
                    HuffmanDecoder::from_lengths_sparse(&[
                        (syms[0], 1),
                        (syms[1], 2),
                        (c, 3),
                        (d, 3),
                    ])
                }
            }
            _ => unreachable!(),
        }
    }

    fn read_complex_prefix_code(
        src: &mut BitSource<'_>,
        alphabet_size: u32,
        hskip: u32,
    ) -> Result<HuffmanDecoder, Error> {
        // 1. Read code-length lengths in the canonical order (skipping
        //    `hskip` initial slots which default to 0).
        //
        // The cl-cl code is a fixed 6-symbol Huffman with these
        // canonical code lengths:
        //   sym 0: 2, sym 1: 4, sym 2: 3, sym 3: 2, sym 4: 2, sym 5: 4
        // Codes follow §3.2 canonical assignment; we just build a tiny
        // canonical decoder.
        let cl_cl_lengths: [(u32, u8); 6] = [(0, 2), (1, 4), (2, 3), (3, 2), (4, 2), (5, 4)];
        let cl_decoder = HuffmanDecoder::from_lengths_sparse(&cl_cl_lengths)?;
        let mut cl_lengths = [0u8; 18];
        let mut space: i32 = 32;
        let mut idx = hskip as usize;
        while idx < 18 {
            let sym_pos = CODE_LENGTH_ORDER[idx];
            let v = cl_decoder.decode(src)?;
            if v > 5 {
                return Err(Error::InvalidHuffmanTree);
            }
            cl_lengths[sym_pos] = v as u8;
            if v != 0 {
                space -= 32 >> v;
                if space <= 0 {
                    break;
                }
            }
            idx += 1;
        }
        if space != 0 {
            return Err(Error::InvalidHuffmanTree);
        }
        // 2. Build the cl-symbol decoder.
        let mut cl_sym_pairs: Vec<(u32, u8)> = Vec::new();
        for (i, &l) in cl_lengths.iter().enumerate() {
            if l > 0 {
                cl_sym_pairs.push((i as u32, l));
            }
        }
        if cl_sym_pairs.is_empty() {
            return Err(Error::InvalidHuffmanTree);
        }
        let cl_sym_decoder = if cl_sym_pairs.len() == 1 {
            // Tree with one symbol whose code is empty (zero-length).
            HuffmanDecoder::single(cl_sym_pairs[0].0)
        } else {
            // The 18-symbol cl-cl alphabet itself must form a complete tree.
            HuffmanDecoder::from_lengths_sparse(&cl_sym_pairs)?
        };

        // 3. Decode the main code-length sequence, expanding 16/17 repeats.
        let mut sym_lengths: Vec<u8> = vec![0u8; alphabet_size as usize];
        let mut prev_nonzero: u8 = 8;
        let mut filled: u32 = 0;
        let mut space: i64 = 1 << 15;
        let mut prev_code: u32 = u32::MAX; // sentinel
        let mut prev_repeat_count: u32 = 0;
        while filled < alphabet_size && space > 0 {
            let code = cl_sym_decoder.decode(src)?;
            match code {
                0..=15 => {
                    sym_lengths[filled as usize] = code as u8;
                    if code != 0 {
                        prev_nonzero = code as u8;
                        space -= 1i64 << (15 - code);
                    }
                    filled += 1;
                    prev_code = code;
                    prev_repeat_count = 0;
                }
                16 => {
                    let extra = src.read_bits(2)?;
                    let new_count = if prev_code == 16 {
                        4 * (prev_repeat_count - 2) + (3 + extra)
                    } else {
                        3 + extra
                    };
                    let to_add = if prev_code == 16 {
                        new_count - prev_repeat_count
                    } else {
                        new_count
                    };
                    if filled + to_add > alphabet_size {
                        return Err(Error::Corrupt);
                    }
                    for _ in 0..to_add {
                        sym_lengths[filled as usize] = prev_nonzero;
                        filled += 1;
                        space -= 1i64 << (15 - prev_nonzero as u32);
                    }
                    prev_code = 16;
                    prev_repeat_count = new_count;
                }
                17 => {
                    let extra = src.read_bits(3)?;
                    let new_count = if prev_code == 17 {
                        8 * (prev_repeat_count - 2) + (3 + extra)
                    } else {
                        3 + extra
                    };
                    let to_add = if prev_code == 17 {
                        new_count - prev_repeat_count
                    } else {
                        new_count
                    };
                    if filled + to_add > alphabet_size {
                        return Err(Error::Corrupt);
                    }
                    for _ in 0..to_add {
                        sym_lengths[filled as usize] = 0;
                        filled += 1;
                    }
                    prev_code = 17;
                    prev_repeat_count = new_count;
                }
                _ => return Err(Error::Corrupt),
            }
        }
        if space < 0 {
            return Err(Error::Corrupt);
        }
        if filled < alphabet_size {
            // Trailing zeros are implicit.
            for slot in sym_lengths
                .iter_mut()
                .take(alphabet_size as usize)
                .skip(filled as usize)
            {
                *slot = 0;
            }
        }
        HuffmanDecoder::from_lengths_allow_single(&sym_lengths[..alphabet_size as usize])
    }

    /// Read a "block count" first-value pair: a 26-symbol Huffman tree
    /// (BLOCK_LEN), decoded then offset by extra bits.
    fn read_block_count(src: &mut BitSource<'_>, tree: &HuffmanDecoder) -> Result<u32, Error> {
        let sym = tree.decode(src)?;
        if sym >= NUM_BLOCK_LEN_SYMBOLS {
            return Err(Error::Corrupt);
        }
        let extra = src.read_bits(BLOCK_LEN_EXTRA[sym as usize])?;
        Ok(BLOCK_LEN_BASE[sym as usize] + extra)
    }

    /// Decode the body of a compressed meta-block: read all per-block
    /// tables, then run the literal/copy command loop until `mlen`
    /// bytes have been emitted.
    fn decode_compressed_meta_block(
        &mut self,
        src: &mut BitSource<'_>,
        mlen: u32,
    ) -> Result<(), Error> {
        // 1) Block-type / block-count groups for L, I, D.
        let group_l = read_block_group(src)?;
        let group_i = read_block_group(src)?;
        let group_d = read_block_group(src)?;

        // 2) Distance parameters.
        let npostfix = src.read_bits(2)?;
        let ndirect_bits = src.read_bits(4)?;
        let ndirect = ndirect_bits << npostfix;
        let num_dist_codes: u32 = 16 + ndirect + (48u32 << npostfix);

        // 3) Context modes for literals: NBLTYPESL × 2 bits each.
        let mut cmodes: Vec<ContextMode> = Vec::with_capacity(group_l.nbltypes as usize);
        for _ in 0..group_l.nbltypes {
            cmodes.push(ContextMode::from_bits(src.read_bits(2)?));
        }

        // 4) Literal context map.
        let ntreesl = Self::read_nbltypes(src)?;
        let cmapl_size = 64 * group_l.nbltypes;
        let cmapl = if ntreesl >= 2 {
            read_context_map(src, cmapl_size, ntreesl)?
        } else {
            vec![0u8; cmapl_size as usize]
        };

        // 5) Distance context map.
        let ntreesd = Self::read_nbltypes(src)?;
        let cmapd_size = 4 * group_d.nbltypes;
        let cmapd = if ntreesd >= 2 {
            read_context_map(src, cmapd_size, ntreesd)?
        } else {
            vec![0u8; cmapd_size as usize]
        };

        // 6) Literal prefix codes (NTREESL of them, alphabet 256).
        let mut htree_l: Vec<HuffmanDecoder> = Vec::with_capacity(ntreesl as usize);
        for _ in 0..ntreesl {
            htree_l.push(Self::read_prefix_code(src, NUM_LITERAL_SYMBOLS)?);
        }
        // 7) Insert-and-copy prefix codes (NBLTYPESI of them, alphabet 704).
        let mut htree_i: Vec<HuffmanDecoder> = Vec::with_capacity(group_i.nbltypes as usize);
        for _ in 0..group_i.nbltypes {
            htree_i.push(Self::read_prefix_code(src, NUM_COMMAND_SYMBOLS)?);
        }
        // 8) Distance prefix codes (NTREESD of them, alphabet num_dist_codes).
        let mut htree_d: Vec<HuffmanDecoder> = Vec::with_capacity(ntreesd as usize);
        for _ in 0..ntreesd {
            htree_d.push(Self::read_prefix_code(src, num_dist_codes)?);
        }

        // ─── decoding loop ───
        let mut emitted: u32 = 0;
        let mut block_type_l: u32 = 0;
        let mut block_type_i: u32 = 0;
        let mut block_type_d: u32 = 0;
        // "Previous block type" trackers, used for block-type code value 0
        // (use prev) and value 1 (use prev+1 mod NBLTYPES).
        let mut prev_block_type_l: u32 = 1;
        let mut prev_block_type_i: u32 = 1;
        let mut prev_block_type_d: u32 = 1;
        let mut block_len_l: u32 = group_l.first_count;
        let mut block_len_i: u32 = group_i.first_count;
        let mut block_len_d: u32 = group_d.first_count;

        let postfix_mask: u32 = (1u32 << npostfix) - 1;

        // Local helper: advance block-type when count reaches zero.
        macro_rules! maybe_switch {
            ($len:ident, $bt:ident, $prev:ident, $group:expr) => {
                if $len == 0 {
                    let g = &$group;
                    let nbl = g.nbltypes;
                    let type_tree = g.type_tree.as_ref().unwrap();
                    let count_tree = g.count_tree.as_ref().unwrap();
                    let code = type_tree.decode(src)?;
                    let next_type = if code == 0 {
                        $prev
                    } else if code == 1 {
                        ($bt + 1) % nbl
                    } else {
                        code - 2
                    };
                    if next_type >= nbl {
                        return Err(Error::Corrupt);
                    }
                    $prev = $bt;
                    $bt = next_type;
                    $len = Self::read_block_count(src, count_tree)?;
                }
            };
        }

        while emitted < mlen {
            // Block-type switch for IC if needed.
            maybe_switch!(block_len_i, block_type_i, prev_block_type_i, group_i);
            block_len_i -= 1;

            // Decode the IC command symbol.
            let cmd_sym = htree_i[block_type_i as usize].decode(src)?;
            if cmd_sym >= NUM_COMMAND_SYMBOLS {
                return Err(Error::Corrupt);
            }
            let (ins_code, copy_code, use_last_dist) = decode_ic_command(cmd_sym);

            let ins_extra = src.read_bits(INS_EXTRA[ins_code as usize])?;
            let insert_len = INS_BASE[ins_code as usize] + ins_extra;
            let copy_extra = src.read_bits(COPY_EXTRA[copy_code as usize])?;
            let copy_len = COPY_BASE[copy_code as usize] + copy_extra;

            // Emit `insert_len` literals.
            for _ in 0..insert_len {
                if emitted >= mlen {
                    return Err(Error::Corrupt);
                }
                maybe_switch!(block_len_l, block_type_l, prev_block_type_l, group_l);
                block_len_l -= 1;
                let cid = context::literal_context(cmodes[block_type_l as usize], self.p1, self.p2);
                let tree_idx = cmapl[(64 * block_type_l + cid as u32) as usize] as usize;
                let sym = htree_l[tree_idx].decode(src)?;
                if sym > 255 {
                    return Err(Error::Corrupt);
                }
                self.emit_literal(sym as u8);
                emitted += 1;
            }

            if emitted >= mlen {
                // Last command is allowed to have copy_len that would
                // exceed mlen if insert filled it; in that case no copy
                // is emitted.
                break;
            }

            // Decode distance. For short codes the ring may be
            // updated immediately (per §4 those codes are "use a
            // previous distance"). For non-short codes we delay the
            // ring push until we know whether this resolves to a
            // back-reference (push) or a static-dictionary reference
            // (no push).
            let (distance, is_short_or_direct) = if use_last_dist {
                (self.last_dist() as u32, true)
            } else {
                maybe_switch!(block_len_d, block_type_d, prev_block_type_d, group_d);
                block_len_d -= 1;
                let cid = context::distance_context(copy_len) as u32;
                let tree_idx = cmapd[(4 * block_type_d + cid) as usize] as usize;
                let dcode = htree_d[tree_idx].decode(src)?;
                if dcode >= num_dist_codes {
                    return Err(Error::Corrupt);
                }
                if dcode < 16 {
                    // Short codes update the ring immediately per spec.
                    (decode_short_distance(self, dcode)?, true)
                } else if dcode < 16 + ndirect {
                    // Direct distance.
                    (dcode - 15, false)
                } else {
                    let v = dcode - ndirect - 16;
                    let ndistbits = 1 + (v >> (npostfix + 1));
                    let dextra = src.read_bits(ndistbits)?;
                    let hcode = v >> npostfix;
                    let lcode = v & postfix_mask;
                    let offset = ((2 + (hcode & 1)) << ndistbits) - 4;
                    let dist = ((offset + dextra) << npostfix) + lcode + ndirect + 1;
                    (dist, false)
                }
            };

            // Compute max-distance: min(window_size - 16, total_out so far).
            let max_dist = (self.window_size.saturating_sub(16)).min(self.total_out as u32);
            if distance <= max_dist {
                // Normal back-reference. Non-short distances are
                // pushed to the ring here.
                if !is_short_or_direct {
                    self.push_dist(distance as i32);
                }
                self.emit_copy(distance, copy_len)?;
                emitted += copy_len;
                if emitted > mlen {
                    return Err(Error::Corrupt);
                }
            } else {
                // Static dictionary reference (§8). Distances that
                // resolve to dictionary entries are NOT pushed onto the
                // ring buffer.
                let n = self.emit_dictionary(distance, copy_len, max_dist)?;
                emitted += n;
                if emitted > mlen {
                    return Err(Error::Corrupt);
                }
            }
        }
        Ok(())
    }

    /// Resolve a distance code that overshoots the back-reference window
    /// as a static dictionary reference, per §8. Returns the number of
    /// bytes emitted (which is `prefix.len() + body.len() + suffix.len()`,
    /// where body may be the word truncated by omit-first/last).
    fn emit_dictionary(
        &mut self,
        distance: u32,
        copy_len: u32,
        max_dist: u32,
    ) -> Result<u32, Error> {
        // copy_len must be in 4..=24 to index a non-empty length class.
        let len = copy_len as usize;
        if !(dictionary::MIN_DICTIONARY_WORD_LENGTH..=dictionary::MAX_DICTIONARY_WORD_LENGTH)
            .contains(&len)
        {
            return Err(Error::InvalidDistance);
        }
        let nwords_bits = dictionary::SIZE_BITS_BY_LENGTH[len];
        if nwords_bits == 0 {
            return Err(Error::InvalidDistance);
        }
        let nwords: u32 = 1 << nwords_bits;
        let off = distance
            .checked_sub(max_dist)
            .ok_or(Error::InvalidDistance)?;
        let off = off.checked_sub(1).ok_or(Error::InvalidDistance)?;
        let word_id = off & (nwords - 1);
        let transform_id = off >> nwords_bits;
        if transform_id >= 121 {
            return Err(Error::InvalidDistance);
        }
        let word = dictionary::word(len, word_id).ok_or(Error::InvalidDistance)?;
        let mut scratch: Vec<u8> = Vec::with_capacity(64);
        let n = transforms::apply_transform(&mut scratch, word, transform_id as usize);
        for b in scratch {
            self.emit_literal(b);
        }
        Ok(n as u32)
    }
}

/// Minimum number of bits to encode `alphabet_size` symbol values.
fn alphabet_bits(alphabet_size: u32) -> u32 {
    debug_assert!(alphabet_size >= 1);
    // ceil(log2(alphabet_size)). For size 1 use 1 bit per spec? The
    // simple-prefix-NSYM=1 case still reads one symbol; that symbol
    // must fit in ceil(log2(alphabet_size)) bits, which is 0 for
    // alphabet_size=1. RFC actually says: "the value is in the range
    // [0, alphabet_size-1] and is encoded with ceil(log2(alphabet_size))
    // bits." That gives 0 bits for size 1, which means simple-NSYM=1
    // with a single-element alphabet reads no symbol bits. We retain
    // the same behavior.
    if alphabet_size <= 1 {
        return 0;
    }
    let mut n = 1u32;
    while (1u32 << n) < alphabet_size {
        n += 1;
    }
    n
}

/// Decode a 0..=15 short distance code into an actual back-distance.
/// Updates the ring buffer per spec.
fn decode_short_distance(dec: &mut Decoder, code: u32) -> Result<u32, Error> {
    // Per §4:
    //   code 0..3  → use nth_last_dist(1..=4) as-is, but only code 0
    //                is "do not push to ring"; codes 1..=15 push.
    //   code 4..15 → modified previous distance.
    let last = dec.nth_last_dist(1);
    let last2 = dec.nth_last_dist(2);
    let dist: i32 = match code {
        0 => last,
        1 => dec.nth_last_dist(2),
        2 => dec.nth_last_dist(3),
        3 => dec.nth_last_dist(4),
        4 => last - 1,
        5 => last + 1,
        6 => last - 2,
        7 => last + 2,
        8 => last - 3,
        9 => last + 3,
        10 => last2 - 1,
        11 => last2 + 1,
        12 => last2 - 2,
        13 => last2 + 2,
        14 => last2 - 3,
        15 => last2 + 3,
        _ => unreachable!(),
    };
    if dist <= 0 {
        return Err(Error::InvalidDistance);
    }
    if code != 0 {
        dec.push_dist(dist);
    }
    Ok(dist as u32)
}

/// Decode a 0..=703 insert-and-copy command symbol into
/// `(insert_len_code, copy_len_code, use_last_dist)`.
///
/// Cell layout from §5:
///
/// ```text
///           Copy code:    0..7      8..15     16..23
///                       +---------+---------+---------+
///  Ins 0..7 (dist=0)    |  0..63  |  64..127|   ---   |
///  Ins 0..7             | 128..191| 192..255| 384..447|
///  Ins 8..15            | 256..319| 320..383| 512..575|
///  Ins 16..23           | 448..511| 576..639| 640..703|
/// ```
fn decode_ic_command(cmd: u32) -> (u32, u32, bool) {
    // The full table:
    //   cmd in 0..64  : ins 0..7,  copy 0..7,  use_last=true
    //   cmd in 64..128: ins 0..7,  copy 8..15, use_last=true
    //   cmd in 128..192: ins 0..7,  copy 0..7
    //   cmd in 192..256: ins 0..7,  copy 8..15
    //   cmd in 256..320: ins 8..15, copy 0..7
    //   cmd in 320..384: ins 8..15, copy 8..15
    //   cmd in 384..448: ins 0..7,  copy 16..23
    //   cmd in 448..512: ins 16..23, copy 0..7
    //   cmd in 512..576: ins 8..15, copy 16..23
    //   cmd in 576..640: ins 16..23, copy 8..15
    //   cmd in 640..704: ins 16..23, copy 16..23
    let (ins_base, copy_base, use_last) = match cmd / 64 {
        0 => (0u32, 0u32, true),
        1 => (0, 8, true),
        2 => (0, 0, false),
        3 => (0, 8, false),
        4 => (8, 0, false),
        5 => (8, 8, false),
        6 => (0, 16, false),
        7 => (16, 0, false),
        8 => (8, 16, false),
        9 => (16, 8, false),
        10 => (16, 16, false),
        _ => unreachable!(),
    };
    let cell_local = cmd & 0x3F;
    let copy_code = copy_base + (cell_local & 7);
    let ins_code = ins_base + (cell_local >> 3);
    (ins_code, copy_code, use_last)
}

/// Read a context map of `size` entries with `ntrees` distinct trees.
fn read_context_map(src: &mut BitSource<'_>, size: u32, ntrees: u32) -> Result<Vec<u8>, Error> {
    // RLEMAX: 1 bit; if 1, 4 more bits give RLEMAX in 1..=16.
    let has_rle = src.read_bit()?;
    let rlemax = if has_rle == 1 {
        src.read_bits(4)? + 1
    } else {
        0
    };
    let alphabet = ntrees + rlemax;
    let tree = Decoder::read_prefix_code(src, alphabet)?;
    let mut map: Vec<u8> = Vec::with_capacity(size as usize);
    while (map.len() as u32) < size {
        let sym = tree.decode(src)?;
        if sym == 0 {
            map.push(0);
        } else if sym <= rlemax {
            // Run-length-coded run of zeros.
            let extra = src.read_bits(sym)?;
            let run = (1u32 << sym) + extra;
            for _ in 0..run {
                if (map.len() as u32) >= size {
                    return Err(Error::Corrupt);
                }
                map.push(0);
            }
        } else {
            map.push((sym - rlemax) as u8);
        }
    }
    if map.len() as u32 != size {
        return Err(Error::Corrupt);
    }
    // Inverse MTF if requested.
    let imtf = src.read_bit()?;
    if imtf == 1 {
        inverse_mtf(&mut map);
    }
    Ok(map)
}

fn inverse_mtf(v: &mut [u8]) {
    let mut mtf = [0u8; 256];
    for (i, slot) in mtf.iter_mut().enumerate() {
        *slot = i as u8;
    }
    for slot in v.iter_mut() {
        let index = *slot as usize;
        let value = mtf[index];
        *slot = value;
        for i in (1..=index).rev() {
            mtf[i] = mtf[i - 1];
        }
        mtf[0] = value;
    }
}

/// Per-category state read from the meta-block header (literals,
/// insert-copy, distance). When NBLTYPES = 1, the type/count trees are
/// absent and only `first_count` matters (and equals `1<<24` to
/// effectively disable block-switch).
struct BlockGroup {
    nbltypes: u32,
    type_tree: Option<HuffmanDecoder>,
    count_tree: Option<HuffmanDecoder>,
    first_count: u32,
}

fn read_block_group(src: &mut BitSource<'_>) -> Result<BlockGroup, Error> {
    let nbltypes = Decoder::read_nbltypes(src)?;
    if nbltypes >= 2 {
        let alphabet_type = nbltypes + 2;
        let type_tree = Decoder::read_prefix_code(src, alphabet_type)?;
        let count_tree = Decoder::read_prefix_code(src, NUM_BLOCK_LEN_SYMBOLS)?;
        let first_count = Decoder::read_block_count(src, &count_tree)?;
        Ok(BlockGroup {
            nbltypes,
            type_tree: Some(type_tree),
            count_tree: Some(count_tree),
            first_count,
        })
    } else {
        Ok(BlockGroup {
            nbltypes,
            type_tree: None,
            count_tree: None,
            // Effectively infinite block (will never reach zero).
            first_count: 1u32 << 24,
        })
    }
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

impl DecoderTrait for Decoder {
    fn decode(&mut self, input: &[u8], output: &mut [u8]) -> Result<Progress, Error> {
        if self.poisoned {
            return Err(Error::Corrupt);
        }
        let consumed = input.len();
        self.raw.extend_from_slice(input);

        let mut written = 0usize;

        loop {
            // Drain any already-queued output first.
            if self.out_pos < self.out.len() {
                let drained = self.drain_out_into(&mut output[written..]);
                written += drained;
                if written == output.len() {
                    break;
                }
            }

            // Then make whatever forward progress we can.
            match self.state {
                DecState::NeedHeader => match self.read_stream_header() {
                    Ok(true) => {
                        self.compact_raw();
                        self.state = DecState::NeedMetaBlock;
                    }
                    Ok(false) => break,
                    Err(e) => return Err(self.poison(e)),
                },
                DecState::NeedMetaBlock => match self.process_next_meta_block() {
                    Ok(true) => {
                        if self.state == DecState::Done {
                            // Final flush below.
                            continue;
                        }
                        // Loop to drain any newly-queued output.
                    }
                    Ok(false) => break,
                    Err(e) => return Err(self.poison(e)),
                },
                DecState::Done => {
                    // Drain remaining queued output.
                    if self.out_pos >= self.out.len() {
                        break;
                    }
                }
            }
        }
        self.compact_out();
        Ok(Progress {
            consumed,
            written,
            done: false,
        })
    }

    fn finish(&mut self, output: &mut [u8]) -> Result<Progress, Error> {
        if self.poisoned {
            return Err(Error::Corrupt);
        }
        let mut written = 0usize;
        // Drain remaining output first.
        if self.out_pos < self.out.len() {
            written = self.drain_out_into(output);
            self.compact_out();
        }
        let done = self.state == DecState::Done && self.out_pos == self.out.len();
        if done {
            return Ok(Progress {
                consumed: 0,
                written,
                done: true,
            });
        }
        if self.state == DecState::Done && self.out_pos < self.out.len() {
            // More output to drain.
            return Ok(Progress {
                consumed: 0,
                written,
                done: false,
            });
        }
        Err(self.poison(Error::UnexpectedEnd))
    }

    fn reset(&mut self) {
        self.raw.clear();
        self.bit_pos = 0;
        self.out.clear();
        self.out_pos = 0;
        self.state = DecState::NeedHeader;
        self.poisoned = false;
        self.window_size = 1 << 16;
        self.dist_ring = [16, 15, 11, 4];
        self.ring_idx = 0;
        self.total_out = 0;
        self.p1 = 0;
        self.p2 = 0;
    }
}
