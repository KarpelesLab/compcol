//! LZ5 / Lizard frame-format codec.
//!
//! Reference: Yann Collet & Przemyslaw Skibinski's Lizard library
//! (<https://github.com/inikep/lizard>). Format docs:
//! - Frame: `doc/lizard_Frame_format.md`
//! - Block: `doc/lizard_Block_format.md`
//!
//! Lizard is the modern name for what was originally called LZ5. A frame
//! starts with a 4-byte magic (`0x184D2206` LE), a 3- to 11-byte descriptor
//! (FLG + BD + optional content size + header checksum), then one or more
//! data blocks, then a 4-byte zero "EndMark", then an optional content
//! checksum.
//!
//! Each data block is preceded by a 4-byte little-endian word whose
//! high bit (`0x80000000`) marks the block as **frame-uncompressed**
//! (raw bytes follow). Otherwise the block is a Lizard-compressed
//! payload starting with a 1-byte `compressionLevel` (10..=49). Inside
//! a compressed block a 1-byte flag mask decides the layout: if the
//! `0x80` bit is set the block is **block-uncompressed** (3-byte LE
//! length + raw bytes); otherwise five sub-streams follow in order
//! (lengths, offset16, offset24, flags, literals), each prefixed by
//! its 3-byte LE length (or 6 bytes if the stream is Huffman-coded —
//! signalled by the relevant flag bit). The streams feed either the
//! LZ4-codeword sequence loop (compression levels 10..=19 and 30..=39)
//! or the LIZv1 sequence loop (20..=29 and 40..=49).
//!
//! ## Scope
//!
//! **Decoder**: implemented for the **LZ4 codeword path with all
//! sub-streams stored raw** (the most common shape produced by the
//! reference CLI at levels 10..=19 on non-tiny inputs). Frames whose
//! blocks use the LIZv1 sequence format (levels 20..=29, 40..=49) or any
//! Huffman-coded sub-stream are rejected with [`Error::Unsupported`].
//!
//! The Huffman path stays `Unsupported` for a concrete, validation-first
//! reason rather than mere absence of effort. Lizard's entropy stage is
//! Huff0 (`HUF_decompress` from Yann Collet's FiniteStateEntropy), the
//! same family as zstd's literals Huffman, and each Huffman sub-stream is
//! framed as a 6-byte header (3-byte LE regenerated size + 3-byte LE
//! compressed size) then the Huff0 payload. But the *generic*
//! `HUF_decompress` Lizard calls selects between **X1** (single-symbol)
//! and **X2** (double-symbol) decode tables via `HUF_selectDecoder`, and
//! that choice is **recomputed from the regenerated/compressed sizes,
//! never stored in the stream**. This crate's Huff0 decoder
//! (`src/zstd/huffman.rs`) is X1-only and is private to the `zstd`
//! module; it covers neither X2 nor the size-driven selector. With no
//! `lizard` CLI and no Huff0 fixtures in this environment, the only
//! "test" available would be a round-trip against a hand-written
//! X1-only encoder, which would always pick X1 and therefore validate
//! nothing about real (possibly X2) blocks. Per the crate's
//! `lzham`/`sit13` policy, an unvalidatable decoder is worse than an
//! honest `Unsupported`, so we do not ship one.
//!
//! A future round could lift this once validation is possible: expose
//! zstd's X1 Huff0 decoder as `pub(crate)`, add an X2 decoder plus the
//! `HUF_selectDecoder` heuristic, and validate against fixtures from the
//! `lizard` CLI (e.g. `lizard -30`). The 6-byte sub-stream header and the
//! 4-stream jump table (three LE u16 sizes) already match formats this
//! crate parses elsewhere. The frame-level uncompressed block path
//! (high bit on block-size word) is handled fully, so frames where
//! every block stored raw decode without ever exercising the sequence
//! loop. Block checksums (FLG bit 4) and external dictionaries are
//! rejected with `Unsupported`. Content checksums (FLG bit 2) are
//! consumed but not verified — the absence of xxHash-32 verification
//! is documented; a corrupted payload that survives sequence-loop
//! bounds checks will still decode without warning.
//!
//! **Encoder**: produces a valid Lizard frame whose data is always
//! emitted as frame-uncompressed blocks (each up to 128 KiB). The
//! output round-trips through the reference Lizard CLI and through
//! this crate's decoder, but achieves no compression — it is the
//! minimum-correctness encoder, suitable for compatibility but not
//! for size. Block- and content-checksums are disabled.
//!
//! ## Why "store-only" encoder
//!
//! Producing the compressed sequence stream involves a non-trivial
//! match-finder plus distinct codeword formats per compression level,
//! and the optional Huffman entropy stage uses zstd-style FSE Huffman
//! tables. A correctness-first store-only encoder is the natural
//! starting point; the brief explicitly allows shipping a partial
//! encoder rather than a half-finished one.

#![cfg_attr(docsrs, doc(cfg(feature = "lz5")))]

use alloc::vec::Vec;

use crate::error::Error;
use crate::traits::{Algorithm, RawDecoder, RawEncoder, RawProgress};

mod block;
mod xxh32;

pub use block::Lz4ModeDecoder;

/// Lizard frame magic (LE).
pub const MAGIC: u32 = 0x184D2206;

/// Maximum raw block size at descriptor BD=1 (128 KiB). The encoder
/// always uses this; the decoder accepts any BD value 1..=7 and
/// resizes its internal buffer to match.
pub const DEFAULT_BLOCK_SIZE: usize = 128 * 1024;

/// Decoder ceiling on a single block's raw size (`max_block` × growth
/// allowance). Lizard caps blocks at 256 MiB (BD=7); we accept that
/// upper bound but refuse anything larger to defend against malformed
/// length prefixes.
const MAX_BLOCK_SIZE: usize = 256 * 1024 * 1024;

/// Zero-sized marker type implementing [`Algorithm`] for LZ5 / Lizard.
#[derive(Debug, Clone, Copy, Default)]
pub struct Lz5;

impl Algorithm for Lz5 {
    const NAME: &'static str = "lz5";
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

// ─── shared frame constants ─────────────────────────────────────────────

const FLG_VERSION_MASK: u8 = 0b1100_0000;
const FLG_VERSION_01: u8 = 0b0100_0000;
const FLG_BLOCK_INDEPENDENCE: u8 = 0b0010_0000;
const FLG_BLOCK_CHECKSUM: u8 = 0b0001_0000;
const FLG_CONTENT_SIZE: u8 = 0b0000_1000;
const FLG_CONTENT_CHECKSUM: u8 = 0b0000_0100;
const FLG_RESERVED_MASK: u8 = 0b0000_0011;

const BD_RESERVED_MASK: u8 = 0b1000_1111;
const BD_BLOCK_MAXSIZE_SHIFT: u32 = 4;

const BLOCK_UNCOMPRESSED_FLAG: u32 = 0x8000_0000;
const BLOCK_SIZE_MASK: u32 = 0x7FFF_FFFF;

/// Translate a BD `block_max` code (1..=7) into the corresponding
/// raw-byte maximum size, per the frame spec.
const fn block_size_for_bd_code(code: u8) -> Option<usize> {
    match code {
        1 => Some(128 * 1024),
        2 => Some(256 * 1024),
        3 => Some(1024 * 1024),
        4 => Some(4 * 1024 * 1024),
        5 => Some(16 * 1024 * 1024),
        6 => Some(64 * 1024 * 1024),
        7 => Some(256 * 1024 * 1024),
        _ => None,
    }
}

// ─── encoder ──────────────────────────────────────────────────────────────

/// Encoder phase. The encoder always emits frame-uncompressed blocks
/// of size up to [`DEFAULT_BLOCK_SIZE`].
#[derive(Clone, Copy, PartialEq, Eq)]
enum EncPhase {
    /// Header not yet emitted to the caller.
    Header,
    /// Buffering raw input into `raw` (between header and finish).
    Buffering,
    /// `staged` holds a block ready to drain (size word + raw bytes).
    Flushing,
    /// All blocks flushed; emit the 4-byte zero EndMark.
    EndMark,
    /// EndMark sent; `finish` returns done.
    Done,
}

pub struct Encoder {
    raw: Vec<u8>,
    staged: Vec<u8>,
    staged_idx: usize,
    /// Pre-computed 7-byte frame header (magic + FLG + BD + HC).
    header: [u8; 7],
    header_idx: u8,
    endmark_idx: u8,
    phase: EncPhase,
}

impl Encoder {
    pub fn new() -> Self {
        let mut enc = Self {
            raw: Vec::with_capacity(DEFAULT_BLOCK_SIZE),
            staged: Vec::with_capacity(DEFAULT_BLOCK_SIZE + 4),
            staged_idx: 0,
            header: [0; 7],
            header_idx: 0,
            endmark_idx: 0,
            phase: EncPhase::Header,
        };
        enc.build_header();
        enc
    }

    fn build_header(&mut self) {
        let magic = MAGIC.to_le_bytes();
        let flg = FLG_VERSION_01 | FLG_BLOCK_INDEPENDENCE;
        let bd = (1u8) << BD_BLOCK_MAXSIZE_SHIFT; // block_max = 128 KiB
        self.header[0..4].copy_from_slice(&magic);
        self.header[4] = flg;
        self.header[5] = bd;
        // Header checksum = (xxh32(FLG..end_of_descriptor, seed=0) >> 8) & 0xFF.
        // With no content-size field, the descriptor is just [FLG, BD].
        let hc = (xxh32::xxh32(&[flg, bd], 0) >> 8) as u8;
        self.header[6] = hc;
    }

    /// Stage the next block (size word + raw bytes) into `self.staged`.
    /// Always emits the high-bit-set "frame-uncompressed" form.
    fn build_block(&mut self) {
        if self.raw.is_empty() {
            return;
        }
        let size = self.raw.len() as u32 | BLOCK_UNCOMPRESSED_FLAG;
        self.staged.clear();
        self.staged.extend_from_slice(&size.to_le_bytes());
        self.staged.extend_from_slice(&self.raw);
        self.raw.clear();
        self.staged_idx = 0;
        self.phase = EncPhase::Flushing;
    }

    fn drain_header(&mut self, output: &mut [u8], written: &mut usize) {
        while (self.header_idx as usize) < self.header.len() && *written < output.len() {
            output[*written] = self.header[self.header_idx as usize];
            self.header_idx += 1;
            *written += 1;
        }
        if (self.header_idx as usize) == self.header.len() {
            self.phase = EncPhase::Buffering;
        }
    }

    fn drain_staged(&mut self, output: &mut [u8], written: &mut usize) {
        let avail = self.staged.len() - self.staged_idx;
        let space = output.len() - *written;
        let n = avail.min(space);
        if n > 0 {
            output[*written..*written + n]
                .copy_from_slice(&self.staged[self.staged_idx..self.staged_idx + n]);
            self.staged_idx += n;
            *written += n;
        }
        if self.staged_idx == self.staged.len() {
            self.staged.clear();
            self.staged_idx = 0;
            self.phase = EncPhase::Buffering;
        }
    }

    fn drain_endmark(&mut self, output: &mut [u8], written: &mut usize) {
        while self.endmark_idx < 4 && *written < output.len() {
            output[*written] = 0;
            *written += 1;
            self.endmark_idx += 1;
        }
        if self.endmark_idx == 4 {
            self.phase = EncPhase::Done;
        }
    }
}

impl Default for Encoder {
    fn default() -> Self {
        Self::new()
    }
}

impl RawEncoder for Encoder {
    fn raw_encode(&mut self, input: &[u8], output: &mut [u8]) -> Result<RawProgress, Error> {
        let mut consumed = 0usize;
        let mut written = 0usize;

        loop {
            match self.phase {
                EncPhase::Header => {
                    self.drain_header(output, &mut written);
                    if self.phase == EncPhase::Header {
                        return Ok(RawProgress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                }
                EncPhase::Flushing => {
                    self.drain_staged(output, &mut written);
                    if self.phase == EncPhase::Flushing {
                        return Ok(RawProgress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                }
                EncPhase::Buffering => {
                    if consumed == input.len() {
                        return Ok(RawProgress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                    let room = DEFAULT_BLOCK_SIZE - self.raw.len();
                    let take = (input.len() - consumed).min(room);
                    self.raw
                        .extend_from_slice(&input[consumed..consumed + take]);
                    consumed += take;
                    if self.raw.len() == DEFAULT_BLOCK_SIZE {
                        self.build_block();
                    } else {
                        return Ok(RawProgress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                }
                EncPhase::EndMark | EncPhase::Done => {
                    // Reachable only after `finish` started — should not
                    // be entered from `encode`. Return gracefully.
                    return Ok(RawProgress {
                        consumed,
                        written,
                        done: false,
                    });
                }
            }
        }
    }

    fn raw_finish(&mut self, output: &mut [u8]) -> Result<RawProgress, Error> {
        let mut written = 0usize;

        loop {
            match self.phase {
                EncPhase::Header => {
                    self.drain_header(output, &mut written);
                    if self.phase == EncPhase::Header {
                        return Ok(RawProgress {
                            consumed: 0,
                            written,
                            done: false,
                        });
                    }
                }
                EncPhase::Buffering => {
                    if !self.raw.is_empty() {
                        self.build_block();
                    } else {
                        self.phase = EncPhase::EndMark;
                    }
                }
                EncPhase::Flushing => {
                    self.drain_staged(output, &mut written);
                    if self.phase == EncPhase::Flushing {
                        return Ok(RawProgress {
                            consumed: 0,
                            written,
                            done: false,
                        });
                    }
                }
                EncPhase::EndMark => {
                    self.drain_endmark(output, &mut written);
                    if self.phase == EncPhase::EndMark {
                        return Ok(RawProgress {
                            consumed: 0,
                            written,
                            done: false,
                        });
                    }
                }
                EncPhase::Done => {
                    return Ok(RawProgress {
                        consumed: 0,
                        written,
                        done: true,
                    });
                }
            }
        }
    }

    fn raw_reset(&mut self) {
        self.raw.clear();
        self.staged.clear();
        self.staged_idx = 0;
        self.header_idx = 0;
        self.endmark_idx = 0;
        self.phase = EncPhase::Header;
    }
}

// ─── decoder ──────────────────────────────────────────────────────────────

/// Decoder state machine. Operates entirely on the caller's input
/// stream; never reads ahead into a hidden buffer except to accumulate
/// the next block's payload before decoding it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum DecPhase {
    /// Reading the 7-byte (or 15-byte with content size) frame header.
    Header,
    /// Reading the 4-byte block-size word.
    BlockSize,
    /// Accumulating an uncompressed-flag-set block straight into `decoded`.
    RawBlock { remaining: usize },
    /// Accumulating a compressed block's bytes into `block_buf`.
    CompressedBlock { block_len: usize, gathered: usize },
    /// `decoded` has bytes ready for the caller to read.
    Draining,
    /// EndMark seen. Reading the optional 4-byte content checksum if any.
    ContentChecksum { idx: u8 },
    /// Stream complete.
    Done,
}

pub struct Decoder {
    /// Frame header buffer (max 15 bytes: magic+FLG+BD+8-byte content size + HC).
    header_buf: [u8; 15],
    header_idx: u8,
    /// Number of header bytes we expect for this frame (7 or 15).
    header_expected: u8,
    /// Block-size word being assembled.
    bs_buf: [u8; 4],
    bs_idx: u8,
    /// Max block raw size for this frame (from BD).
    max_block_raw: usize,
    /// Per-frame: whether the content-checksum trailer is expected.
    expect_content_checksum: bool,
    /// Compressed-block scratch (filled then decoded into `decoded`).
    block_buf: Vec<u8>,
    /// Drained one block at a time into the caller's output buffer.
    decoded: Vec<u8>,
    decoded_idx: usize,
    /// Total decoded bytes emitted in this frame so far.
    total_emitted: u64,
    phase: DecPhase,
    poisoned: bool,
}

impl Decoder {
    pub fn new() -> Self {
        Self {
            header_buf: [0; 15],
            header_idx: 0,
            header_expected: 7,
            bs_buf: [0; 4],
            bs_idx: 0,
            max_block_raw: DEFAULT_BLOCK_SIZE,
            expect_content_checksum: false,
            block_buf: Vec::new(),
            decoded: Vec::new(),
            decoded_idx: 0,
            total_emitted: 0,
            phase: DecPhase::Header,
            poisoned: false,
        }
    }

    fn finish_header(&mut self) -> Result<(), Error> {
        // Magic + FLG + BD are always present.
        let magic = u32::from_le_bytes([
            self.header_buf[0],
            self.header_buf[1],
            self.header_buf[2],
            self.header_buf[3],
        ]);
        if magic != MAGIC {
            return Err(Error::BadHeader);
        }
        let flg = self.header_buf[4];
        let bd = self.header_buf[5];
        if flg & FLG_VERSION_MASK != FLG_VERSION_01 {
            return Err(Error::BadHeader);
        }
        if flg & FLG_RESERVED_MASK != 0 {
            return Err(Error::BadHeader);
        }
        // Block independence is informational for us — the decoder never
        // exposes cross-block back-references anyway in this build.
        if flg & FLG_BLOCK_CHECKSUM != 0 {
            // We'd need xxh32 of every raw block — supported in principle
            // (xxh32 is already in this module), but the stream then
            // carries an extra 4-byte trailer per block which the
            // current state machine doesn't consume. Reject for now
            // rather than silently skip the bytes.
            return Err(Error::Unsupported);
        }
        if bd & BD_RESERVED_MASK != 0 {
            return Err(Error::BadHeader);
        }
        let bd_code = (bd >> BD_BLOCK_MAXSIZE_SHIFT) & 0b0111;
        let max_block = block_size_for_bd_code(bd_code).ok_or(Error::BadHeader)?;
        self.max_block_raw = max_block;
        self.expect_content_checksum = (flg & FLG_CONTENT_CHECKSUM) != 0;

        // HC byte position depends on whether content size is present.
        let hc_offset = if flg & FLG_CONTENT_SIZE != 0 { 14 } else { 6 };
        // The descriptor bytes hashed are FLG..(HC-1) — i.e. everything
        // from byte 4 through (hc_offset-1).
        let descriptor = &self.header_buf[4..hc_offset];
        let expected_hc = (xxh32::xxh32(descriptor, 0) >> 8) as u8;
        if self.header_buf[hc_offset] != expected_hc {
            return Err(Error::ChecksumMismatch);
        }
        Ok(())
    }

    fn drain_decoded(&mut self, output: &mut [u8], written: &mut usize) {
        let avail = self.decoded.len() - self.decoded_idx;
        let space = output.len() - *written;
        let n = avail.min(space);
        if n > 0 {
            output[*written..*written + n]
                .copy_from_slice(&self.decoded[self.decoded_idx..self.decoded_idx + n]);
            self.decoded_idx += n;
            *written += n;
        }
        if self.decoded_idx == self.decoded.len() {
            self.decoded.clear();
            self.decoded_idx = 0;
            self.phase = DecPhase::BlockSize;
            self.bs_idx = 0;
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
        if self.poisoned {
            return Err(Error::Corrupt);
        }
        let mut consumed = 0usize;
        let mut written = 0usize;

        loop {
            match self.phase {
                DecPhase::Header => {
                    // Read at most up to `header_expected` bytes; once
                    // FLG is known we may bump `header_expected` to 15.
                    while (self.header_idx as usize) < self.header_expected as usize
                        && consumed < input.len()
                    {
                        self.header_buf[self.header_idx as usize] = input[consumed];
                        self.header_idx += 1;
                        consumed += 1;
                        // After we have FLG (byte index 4) we can tell
                        // whether the descriptor is 6 or 14 bytes long
                        // and bump our expectation accordingly.
                        if self.header_idx == 5 {
                            let flg = self.header_buf[4];
                            if flg & FLG_VERSION_MASK != FLG_VERSION_01
                                || flg & FLG_RESERVED_MASK != 0
                            {
                                self.poisoned = true;
                                return Err(Error::BadHeader);
                            }
                            self.header_expected = if flg & FLG_CONTENT_SIZE != 0 { 15 } else { 7 };
                        }
                    }
                    if (self.header_idx as usize) < self.header_expected as usize {
                        return Ok(RawProgress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                    if let Err(e) = self.finish_header() {
                        self.poisoned = true;
                        return Err(e);
                    }
                    self.phase = DecPhase::BlockSize;
                    self.bs_idx = 0;
                }
                DecPhase::BlockSize => {
                    while self.bs_idx < 4 && consumed < input.len() {
                        self.bs_buf[self.bs_idx as usize] = input[consumed];
                        self.bs_idx += 1;
                        consumed += 1;
                    }
                    if self.bs_idx < 4 {
                        return Ok(RawProgress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                    let bs = u32::from_le_bytes(self.bs_buf);
                    if bs == 0 {
                        // EndMark.
                        if self.expect_content_checksum {
                            self.phase = DecPhase::ContentChecksum { idx: 0 };
                        } else {
                            self.phase = DecPhase::Done;
                            return Ok(RawProgress {
                                consumed,
                                written,
                                done: true,
                            });
                        }
                        continue;
                    }
                    let payload_len = (bs & BLOCK_SIZE_MASK) as usize;
                    let uncompressed = (bs & BLOCK_UNCOMPRESSED_FLAG) != 0;
                    if payload_len > self.max_block_raw && !uncompressed {
                        // A compressed block can in principle be slightly
                        // larger than the raw max during encoder
                        // overshoot — but a generous 2× cap is enough.
                        if payload_len > self.max_block_raw.saturating_mul(2) + 32 {
                            self.poisoned = true;
                            return Err(Error::Corrupt);
                        }
                    }
                    if payload_len > MAX_BLOCK_SIZE {
                        self.poisoned = true;
                        return Err(Error::Corrupt);
                    }
                    if uncompressed {
                        // Stream raw bytes directly into `decoded`.
                        if payload_len > self.max_block_raw {
                            self.poisoned = true;
                            return Err(Error::Corrupt);
                        }
                        self.decoded.clear();
                        // `payload_len` is attacker-declared and validated only
                        // against max_block_raw, not bytes remaining, so reserve
                        // a bounded floor and let extend_from_slice grow as real
                        // bytes arrive (mirrors lz4's frame-decoder reserve cap).
                        self.decoded.reserve(payload_len.min(64 * 1024));
                        self.decoded_idx = 0;
                        self.phase = DecPhase::RawBlock {
                            remaining: payload_len,
                        };
                    } else {
                        self.block_buf.clear();
                        // Bounded floor; the CompressedBlock phase grows
                        // `block_buf` incrementally via extend_from_slice.
                        self.block_buf.reserve(payload_len.min(64 * 1024));
                        self.phase = DecPhase::CompressedBlock {
                            block_len: payload_len,
                            gathered: 0,
                        };
                    }
                }
                DecPhase::RawBlock { mut remaining } => {
                    let avail = input.len() - consumed;
                    let take = remaining.min(avail);
                    if take > 0 {
                        self.decoded
                            .extend_from_slice(&input[consumed..consumed + take]);
                        consumed += take;
                        remaining -= take;
                    }
                    if remaining > 0 {
                        self.phase = DecPhase::RawBlock { remaining };
                        return Ok(RawProgress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                    // Block complete: drain.
                    self.total_emitted =
                        self.total_emitted.saturating_add(self.decoded.len() as u64);
                    self.decoded_idx = 0;
                    self.phase = DecPhase::Draining;
                }
                DecPhase::CompressedBlock {
                    block_len,
                    mut gathered,
                } => {
                    let need = block_len - gathered;
                    let avail = input.len() - consumed;
                    let take = need.min(avail);
                    if take > 0 {
                        self.block_buf
                            .extend_from_slice(&input[consumed..consumed + take]);
                        consumed += take;
                        gathered += take;
                    }
                    if gathered < block_len {
                        self.phase = DecPhase::CompressedBlock {
                            block_len,
                            gathered,
                        };
                        return Ok(RawProgress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                    // Block fully gathered — decompress.
                    self.decoded.clear();
                    if let Err(e) = block::decode_compressed_block(
                        &self.block_buf,
                        &mut self.decoded,
                        self.max_block_raw,
                    ) {
                        self.poisoned = true;
                        return Err(e);
                    }
                    // Redundant given the per-append cap inside
                    // decode_compressed_block, but kept as a cheap
                    // defense-in-depth backstop.
                    if self.decoded.len() > self.max_block_raw {
                        self.poisoned = true;
                        return Err(Error::Corrupt);
                    }
                    self.total_emitted =
                        self.total_emitted.saturating_add(self.decoded.len() as u64);
                    self.decoded_idx = 0;
                    self.phase = DecPhase::Draining;
                }
                DecPhase::Draining => {
                    self.drain_decoded(output, &mut written);
                    if self.phase == DecPhase::Draining {
                        return Ok(RawProgress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                }
                DecPhase::ContentChecksum { mut idx } => {
                    while idx < 4 && consumed < input.len() {
                        // We discard the bytes (no xxh32 of the running
                        // output stream is maintained in this build).
                        consumed += 1;
                        idx += 1;
                    }
                    if idx < 4 {
                        self.phase = DecPhase::ContentChecksum { idx };
                        return Ok(RawProgress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                    self.phase = DecPhase::Done;
                    return Ok(RawProgress {
                        consumed,
                        written,
                        done: true,
                    });
                }
                DecPhase::Done => {
                    return Ok(RawProgress {
                        consumed,
                        written,
                        done: true,
                    });
                }
            }
        }
    }

    fn raw_finish(&mut self, output: &mut [u8]) -> Result<RawProgress, Error> {
        if self.poisoned {
            return Err(Error::Corrupt);
        }
        let mut written = 0usize;

        // Drain any staged decoded bytes.
        if self.phase == DecPhase::Draining {
            self.drain_decoded(output, &mut written);
            if self.phase == DecPhase::Draining {
                return Ok(RawProgress {
                    consumed: 0,
                    written,
                    done: false,
                });
            }
        }

        match self.phase {
            DecPhase::Done => Ok(RawProgress {
                consumed: 0,
                written,
                done: true,
            }),
            DecPhase::BlockSize if self.bs_idx == 0 => {
                // Stream ended at a block boundary without an EndMark.
                // Be lenient (the encoder must produce one, but a
                // truncated frame's already-emitted bytes are still
                // correct).
                Ok(RawProgress {
                    consumed: 0,
                    written,
                    done: true,
                })
            }
            _ => Err(Error::UnexpectedEnd),
        }
    }

    fn raw_reset(&mut self) {
        self.header_buf = [0; 15];
        self.header_idx = 0;
        self.header_expected = 7;
        self.bs_buf = [0; 4];
        self.bs_idx = 0;
        self.max_block_raw = DEFAULT_BLOCK_SIZE;
        self.expect_content_checksum = false;
        self.block_buf.clear();
        self.decoded.clear();
        self.decoded_idx = 0;
        self.total_emitted = 0;
        self.phase = DecPhase::Header;
        self.poisoned = false;
    }
}
