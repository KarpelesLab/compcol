//! xz container around LZMA2 — uncompressed-only.
//!
//! Reference: <https://tukaani.org/xz/xz-file-format.txt>.
//!
//! Wire format (decoder view):
//!
//! ```text
//!  Stream Header (12 B)
//!  Block Header (variable, multiple of 4, 8..=1024 B)
//!  LZMA2 payload
//!    (chunk: 01 hi lo <up-to-65536 bytes>)+
//!    00 end marker
//!  Block Padding (0..3 zero bytes, total Block size to 4 B alignment)
//!  Check (4 B CRC32 of uncompressed Block data)
//!  Index (Index Indicator 00 | NumRecords varint | (UnpaddedSize varint,
//!         UncompressedSize varint)+ | 0..3 zero pad | CRC32 of all the above)
//!  Stream Footer (12 B)
//! ```
//!
//! This implementation only supports a single filter (LZMA2, filter ID 0x21)
//! and only emits / accepts LZMA2 chunks of types `0x00` (end marker), `0x01`
//! (uncompressed + dictionary reset), and `0x02` (uncompressed, no reset).
//! Encountering an LZMA-compressed chunk type (`>= 0x80`) during decoding
//! yields [`Error::Unsupported`] cleanly. The encoder always emits a single
//! Block whose payload is a sequence of type-`0x01` uncompressed chunks
//! terminated by `0x00`; system `xz` decodes this correctly.
//!
//! Real LZMA2 compression is **not** implemented here — this module is a
//! container-only fallback that gives bit-identical xz framing without any
//! entropy coding. It is wire-compatible with `xz`(1) for both directions
//! within the uncompressed-chunk subset.
//!
//! No dependency on the sibling `lzma` / `lzma2` modules: the small amount of
//! LZMA2 framing we need (control byte, big-endian 16-bit size) and the
//! CRC-32 we use for the Block Check, Stream Header CRC, and Index CRC are
//! all defined inline below.

// The state machines in this file are written as a series of `match` arms
// each containing an `if`/`else` that either makes progress or returns; the
// shape is intentional and the alternative (a flat outer match) costs us
// duplicate "return Ok(Progress { ... })" tails. Allow the lint here.
#![allow(clippy::collapsible_match, clippy::collapsible_if)]

use alloc::vec::Vec;

use crate::error::Error;
use crate::traits::{Algorithm, Decoder as DecoderTrait, Encoder as EncoderTrait, Progress};

// ─── constants ─────────────────────────────────────────────────────────────

const STREAM_MAGIC: [u8; 6] = [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00];
const FOOTER_MAGIC: [u8; 2] = [0x59, 0x5A];

/// Stream Flags second byte: 0x01 = CRC32 check.
const STREAM_FLAGS_CHECK_CRC32: u8 = 0x01;
const STREAM_FLAGS: [u8; 2] = [0x00, STREAM_FLAGS_CHECK_CRC32];

/// Filter ID 0x21 = LZMA2.
const FILTER_ID_LZMA2: u8 = 0x21;

/// Dictionary-size flag byte. Bits 0..=5 encode dictionary size.
/// Value 0 = 4 KiB. We pick a small but standard dictionary for the
/// Filter Properties byte; the value doesn't actually constrain our
/// uncompressed-only decoder (no LZMA window is materialised) but a real
/// LZMA2 decoder reading our output will allocate this much.
const LZMA2_DICT_FLAG: u8 = 0;

/// Maximum payload bytes per LZMA2 uncompressed chunk.
const LZMA2_CHUNK_MAX: usize = 65_536;

// ─── inline CRC-32 ─────────────────────────────────────────────────────────
//
// IEEE / xz CRC-32. Polynomial 0xEDB88320 (reflected), initial 0xFFFFFFFF,
// final XOR 0xFFFFFFFF. The wider crate has a `checksum::Crc32` but it is
// feature-gated to `gzip`; in an `xz`-only build we'd lose access, so we
// keep a self-sufficient copy here.

#[derive(Clone, Copy)]
struct Crc32 {
    state: u32,
}

impl Crc32 {
    const fn new() -> Self {
        Self { state: 0xFFFF_FFFF }
    }

    fn update(&mut self, data: &[u8]) {
        let mut s = self.state;
        for &b in data {
            let idx = ((s ^ b as u32) & 0xFF) as usize;
            s = (s >> 8) ^ CRC32_TABLE[idx];
        }
        self.state = s;
    }

    const fn finalize(self) -> u32 {
        self.state ^ 0xFFFF_FFFF
    }
}

const CRC32_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0u32;
    while i < 256 {
        let mut c = i;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
            k += 1;
        }
        table[i as usize] = c;
        i += 1;
    }
    table
};

fn crc32(data: &[u8]) -> u32 {
    let mut c = Crc32::new();
    c.update(data);
    c.finalize()
}

// ─── varint (multibyte integer) ────────────────────────────────────────────
//
// LSB-first 7-bit groups; continuation bytes have the high bit set. We only
// encode/decode values that fit in `u64`; the spec caps at 63 bits / 9 bytes.

fn varint_encode(mut value: u64, out: &mut Vec<u8>) {
    while value >= 0x80 {
        out.push(((value & 0x7F) as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

/// Decode a varint from `buf` starting at `*pos`. On success advances `*pos`
/// past the varint and returns the value. Returns `None` if there aren't
/// enough bytes; returns `Err(Corrupt)` for an overlong (>9-byte) encoding
/// or a final byte whose top bit is set.
fn varint_decode(buf: &[u8], pos: &mut usize) -> Result<Option<u64>, Error> {
    let start = *pos;
    let mut value: u64 = 0;
    let mut shift: u32 = 0;
    let mut i = start;
    loop {
        if i >= buf.len() {
            return Ok(None);
        }
        let b = buf[i];
        i += 1;
        if shift >= 63 && (b as u64) >> (63 - shift.min(63)) != 0 {
            // Encoded value doesn't fit in u63.
            return Err(Error::Corrupt);
        }
        value |= ((b & 0x7F) as u64) << shift;
        if b & 0x80 == 0 {
            // Spec: the last byte cannot be 0x00 unless the whole varint is
            // a single zero byte (otherwise it's an overlong encoding).
            if b == 0 && i - start > 1 {
                return Err(Error::Corrupt);
            }
            *pos = i;
            return Ok(Some(value));
        }
        shift += 7;
        if shift > 63 {
            return Err(Error::Corrupt);
        }
    }
}

// ─── Xz algorithm marker ───────────────────────────────────────────────────

/// Zero-sized marker type implementing [`Algorithm`] for xz.
#[derive(Debug, Clone, Copy, Default)]
pub struct Xz;

impl Algorithm for Xz {
    const NAME: &'static str = "xz";
    type Encoder = Encoder;
    type Decoder = Decoder;
    fn encoder() -> Encoder {
        Encoder::new()
    }
    fn decoder() -> Decoder {
        Decoder::new()
    }
}

// ─── shared helpers ────────────────────────────────────────────────────────

/// Build the Stream Header (12 bytes): magic | flags | CRC32(flags).
fn build_stream_header() -> [u8; 12] {
    let crc = crc32(&STREAM_FLAGS).to_le_bytes();
    [
        STREAM_MAGIC[0],
        STREAM_MAGIC[1],
        STREAM_MAGIC[2],
        STREAM_MAGIC[3],
        STREAM_MAGIC[4],
        STREAM_MAGIC[5],
        STREAM_FLAGS[0],
        STREAM_FLAGS[1],
        crc[0],
        crc[1],
        crc[2],
        crc[3],
    ]
}

/// Build the Block Header for our single-LZMA2-filter block.
///
/// We set neither the "Compressed Size" nor the "Uncompressed Size" flag —
/// the decoder discovers the block's end via the LZMA2 `0x00` end marker,
/// and our own decoder relies on that too. This keeps the encoder fully
/// streaming.
///
/// Layout: `[size_byte | flags | filter_id | size_of_props | dict_flag
///          | header_padding... | crc32]`. We then pad with zero bytes so
/// the total block-header size is a multiple of 4, and append the 4-byte
/// little-endian CRC32 of everything before the CRC.
fn build_block_header() -> Vec<u8> {
    // First compute the minimum size before padding+CRC: 1 (size byte) + 1
    // (flags) + 1 (filter id) + 1 (size of props) + 1 (dict flag) + 4 (CRC)
    // = 9. Round up to next multiple of 4 => 12.
    //
    // For longer filter chains the same alignment rule applies; we hard-code
    // the layout here since we know exactly which filter we emit.
    let body_then_pad = {
        // size byte + flags + filter_id + size_of_props + dict_flag = 5
        // need total (incl. 4-byte CRC) to be multiple of 4
        // 5 + pad + 4 = next multiple of 4 >= 9
        // 9 -> 12, pad = 3.
        // Total bytes: 12 = stored size byte 0x02 (since (0x02 + 1) * 4 = 12).
        let total = 12usize;
        let mut h = Vec::with_capacity(total);
        h.push(0x02); // (0x02 + 1) * 4 = 12
        h.push(0x00); // Block Flags: 1 filter (n-1=0), no sizes stored.
        // No Compressed Size / Uncompressed Size fields (bits not set).
        // Filter Flags entry: filter id varint | size_of_props varint | props
        h.push(FILTER_ID_LZMA2);
        h.push(0x01); // size of filter properties = 1 byte
        h.push(LZMA2_DICT_FLAG);
        // Header padding (zeros) to bring total - 4 (CRC) up to 8.
        while h.len() < total - 4 {
            h.push(0x00);
        }
        h
    };
    let mut out = body_then_pad;
    let crc = crc32(&out).to_le_bytes();
    out.extend_from_slice(&crc);
    debug_assert_eq!(out.len() % 4, 0);
    out
}

/// Build the Stream Footer (12 bytes).
///
/// `backward_size` is the byte length of the Index field, which must be a
/// positive multiple of 4. The stored 4-byte little-endian value is
/// `(index_size / 4) - 1`.
fn build_stream_footer(index_size: u32) -> [u8; 12] {
    debug_assert!(index_size >= 4 && index_size.is_multiple_of(4));
    let stored_back = (index_size / 4) - 1;
    let back_le = stored_back.to_le_bytes();
    let mut body = [0u8; 6];
    body[..4].copy_from_slice(&back_le);
    body[4] = STREAM_FLAGS[0];
    body[5] = STREAM_FLAGS[1];
    let crc = crc32(&body).to_le_bytes();
    [
        crc[0],
        crc[1],
        crc[2],
        crc[3],
        body[0],
        body[1],
        body[2],
        body[3],
        body[4],
        body[5],
        FOOTER_MAGIC[0],
        FOOTER_MAGIC[1],
    ]
}

/// Build the Index field.
///
/// Layout: `00 | NumRecords varint | (UnpaddedSize, UncompressedSize)+
///          | 0..3 zero pad | CRC32`.
///
/// Returns the full index bytes; total length is always a multiple of 4 and
/// at least 8 (e.g. for zero blocks: `00 00 0..3 00 padding | CRC32`).
fn build_index(records: &[(u64, u64)]) -> Vec<u8> {
    let mut body = Vec::new();
    body.push(0x00); // Index Indicator
    varint_encode(records.len() as u64, &mut body);
    for &(unpadded, uncompressed) in records {
        varint_encode(unpadded, &mut body);
        varint_encode(uncompressed, &mut body);
    }
    // Pad to make (body.len() + 4) a multiple of 4 => body.len() % 4 == 0.
    while body.len() % 4 != 0 {
        body.push(0x00);
    }
    let crc = crc32(&body).to_le_bytes();
    body.extend_from_slice(&crc);
    debug_assert_eq!(body.len() % 4, 0);
    body
}

// ─── encoder ───────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum EncPhase {
    StreamHeader,
    BlockHeader,
    /// Buffering input and flushing LZMA2 uncompressed chunks.
    Body,
    /// Draining a fully-formed chunk (control + size + data) from `pending`.
    DrainPending,
    /// Emitting the 0x00 end marker, padding, and 4-byte CRC32 check.
    BlockTrailer,
    /// Draining Index + Stream Footer from `pending`.
    Tail,
    Done,
}

pub struct Encoder {
    phase: EncPhase,
    // Drained-piecewise byte buffer for whatever we currently want to push to
    // the caller's `output`. We push from `pending[pending_idx..]`.
    pending: Vec<u8>,
    pending_idx: usize,
    // Input buffer for the next LZMA2 chunk; flushed at LZMA2_CHUNK_MAX or
    // on finish().
    in_buf: Vec<u8>,
    // CRC32 of all uncompressed input bytes — becomes the Block Check.
    check: Crc32,
    // Bookkeeping for the Index Record.
    uncompressed_total: u64,
    /// Bytes emitted into the block's LZMA2 payload (chunks + 0x00 marker).
    compressed_payload_bytes: u64,
    /// Block Header byte length (known at construction).
    block_header_len: u64,
    /// Per-Block flag: first chunk should reset the dictionary.
    first_chunk: bool,
}

impl Encoder {
    pub fn new() -> Self {
        let header = build_stream_header();
        let mut pending = Vec::with_capacity(12);
        pending.extend_from_slice(&header);
        Self {
            phase: EncPhase::StreamHeader,
            pending,
            pending_idx: 0,
            in_buf: Vec::new(),
            check: Crc32::new(),
            uncompressed_total: 0,
            compressed_payload_bytes: 0,
            block_header_len: build_block_header().len() as u64,
            first_chunk: true,
        }
    }

    /// Push bytes from `pending[pending_idx..]` into `output`. Returns true
    /// once the buffer is fully drained.
    fn drain_pending(&mut self, output: &mut [u8], written: &mut usize) -> bool {
        while self.pending_idx < self.pending.len() && *written < output.len() {
            output[*written] = self.pending[self.pending_idx];
            *written += 1;
            self.pending_idx += 1;
        }
        if self.pending_idx >= self.pending.len() {
            self.pending.clear();
            self.pending_idx = 0;
            true
        } else {
            false
        }
    }

    /// Stage an LZMA2 uncompressed chunk for emission. `data.len()` must be
    /// in `1..=65536`.
    fn stage_chunk(&mut self, data: &[u8]) {
        debug_assert!(!data.is_empty() && data.len() <= LZMA2_CHUNK_MAX);
        let control: u8 = if self.first_chunk { 0x01 } else { 0x02 };
        self.first_chunk = false;
        let size_minus_1 = (data.len() - 1) as u16;
        self.pending.reserve(3 + data.len());
        self.pending.push(control);
        self.pending.push((size_minus_1 >> 8) as u8);
        self.pending.push((size_minus_1 & 0xFF) as u8);
        self.pending.extend_from_slice(data);
        self.pending_idx = 0;
        self.compressed_payload_bytes += 3 + data.len() as u64;
    }

    /// Stage the block trailer: 0x00 end marker, 0..=3 padding zeros, and the
    /// 4-byte CRC32 of the uncompressed block data.
    fn stage_block_trailer(&mut self) {
        // End marker for LZMA2 stream.
        self.pending.push(0x00);
        self.compressed_payload_bytes += 1;

        // Unpadded Size = Block Header Size + Compressed Size + Check Size.
        // Block Padding pads the whole Block to a multiple of 4 bytes.
        let unpadded_no_pad = self.block_header_len + self.compressed_payload_bytes + 4;
        let pad = (4 - (unpadded_no_pad % 4) as usize) % 4;
        for _ in 0..pad {
            self.pending.push(0x00);
        }

        let check = self.check.finalize().to_le_bytes();
        self.pending.extend_from_slice(&check);

        self.pending_idx = 0;
    }
}

impl Default for Encoder {
    fn default() -> Self {
        Self::new()
    }
}

impl EncoderTrait for Encoder {
    fn encode(&mut self, input: &[u8], output: &mut [u8]) -> Result<Progress, Error> {
        let mut consumed = 0usize;
        let mut written = 0usize;

        loop {
            let init_c = consumed;
            let init_w = written;
            let init_phase = self.phase;

            match self.phase {
                EncPhase::StreamHeader => {
                    if self.drain_pending(output, &mut written) {
                        // Now stage the block header.
                        let bh = build_block_header();
                        self.pending.extend_from_slice(&bh);
                        self.pending_idx = 0;
                        self.phase = EncPhase::BlockHeader;
                    } else {
                        return Ok(Progress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                }
                EncPhase::BlockHeader => {
                    if self.drain_pending(output, &mut written) {
                        self.phase = EncPhase::Body;
                    } else {
                        return Ok(Progress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                }
                EncPhase::Body => {
                    // Consume input into the buffer.
                    while consumed < input.len() && self.in_buf.len() < LZMA2_CHUNK_MAX {
                        let take =
                            (LZMA2_CHUNK_MAX - self.in_buf.len()).min(input.len() - consumed);
                        self.in_buf
                            .extend_from_slice(&input[consumed..consumed + take]);
                        consumed += take;
                    }
                    if self.in_buf.len() == LZMA2_CHUNK_MAX {
                        // Flush a full chunk.
                        let data = core::mem::take(&mut self.in_buf);
                        self.check.update(&data);
                        self.uncompressed_total += data.len() as u64;
                        self.stage_chunk(&data);
                        self.phase = EncPhase::DrainPending;
                    } else {
                        // Need more input; come back via another call.
                        return Ok(Progress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                }
                EncPhase::DrainPending => {
                    if self.drain_pending(output, &mut written) {
                        self.phase = EncPhase::Body;
                    } else {
                        return Ok(Progress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                }
                _ => {
                    // The remaining phases (BlockTrailer, Index, StreamFooter,
                    // Done) only run from `finish`. If we got here from
                    // `encode` it means the caller is misusing the API.
                    return Ok(Progress {
                        consumed,
                        written,
                        done: false,
                    });
                }
            }

            if consumed == init_c && written == init_w && self.phase == init_phase {
                return Ok(Progress {
                    consumed,
                    written,
                    done: false,
                });
            }
        }
    }

    fn finish(&mut self, output: &mut [u8]) -> Result<Progress, Error> {
        let mut written = 0usize;

        loop {
            let init_w = written;
            let init_phase = self.phase;

            match self.phase {
                EncPhase::StreamHeader => {
                    if self.drain_pending(output, &mut written) {
                        let bh = build_block_header();
                        self.pending.extend_from_slice(&bh);
                        self.pending_idx = 0;
                        self.phase = EncPhase::BlockHeader;
                    } else {
                        return Ok(Progress {
                            consumed: 0,
                            written,
                            done: false,
                        });
                    }
                }
                EncPhase::BlockHeader => {
                    if self.drain_pending(output, &mut written) {
                        self.phase = EncPhase::Body;
                    } else {
                        return Ok(Progress {
                            consumed: 0,
                            written,
                            done: false,
                        });
                    }
                }
                EncPhase::Body => {
                    if !self.in_buf.is_empty() {
                        // Flush a partial chunk.
                        let data = core::mem::take(&mut self.in_buf);
                        self.check.update(&data);
                        self.uncompressed_total += data.len() as u64;
                        self.stage_chunk(&data);
                        self.phase = EncPhase::DrainPending;
                    } else {
                        // No pending input. Move to block trailer.
                        self.stage_block_trailer();
                        self.phase = EncPhase::BlockTrailer;
                    }
                }
                EncPhase::DrainPending => {
                    if self.drain_pending(output, &mut written) {
                        // After draining a flushed chunk, see whether the
                        // body has more buffered or we're really done.
                        self.phase = EncPhase::Body;
                    } else {
                        return Ok(Progress {
                            consumed: 0,
                            written,
                            done: false,
                        });
                    }
                }
                EncPhase::BlockTrailer => {
                    if self.drain_pending(output, &mut written) {
                        // Now build the Index. We have exactly one block.
                        let unpadded_size =
                            self.block_header_len + self.compressed_payload_bytes + 4;
                        let idx = build_index(&[(unpadded_size, self.uncompressed_total)]);
                        let footer = build_stream_footer(idx.len() as u32);
                        self.pending.extend_from_slice(&idx);
                        // Stash the footer in pending after the index; we
                        // drain in two stages so the test can see the
                        // boundary if desired, but it doesn't really matter.
                        self.pending.extend_from_slice(&footer);
                        self.pending_idx = 0;
                        self.phase = EncPhase::Tail;
                    } else {
                        return Ok(Progress {
                            consumed: 0,
                            written,
                            done: false,
                        });
                    }
                }
                EncPhase::Tail => {
                    if self.drain_pending(output, &mut written) {
                        self.phase = EncPhase::Done;
                        return Ok(Progress {
                            consumed: 0,
                            written,
                            done: true,
                        });
                    }
                    return Ok(Progress {
                        consumed: 0,
                        written,
                        done: false,
                    });
                }
                EncPhase::Done => {
                    return Ok(Progress {
                        consumed: 0,
                        written,
                        done: true,
                    });
                }
            }

            if written == init_w && self.phase == init_phase {
                // No progress and no phase change — bail out.
                if matches!(self.phase, EncPhase::Done) {
                    return Ok(Progress {
                        consumed: 0,
                        written,
                        done: true,
                    });
                }
                return Ok(Progress {
                    consumed: 0,
                    written,
                    done: false,
                });
            }
        }
    }

    fn reset(&mut self) {
        *self = Self::new();
    }
}

// ─── decoder ───────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum DecPhase {
    /// Reading the 12-byte Stream Header.
    StreamHeader,
    /// Probing the first byte of the next block-or-index: 0x00 means Index,
    /// non-zero is the Block Header Size byte.
    BlockOrIndex,
    /// Buffering the rest of the Block Header. We know its total length up
    /// front (`block_header_size`).
    BlockHeader,
    /// Reading LZMA2 chunk control + size bytes; once parsed we transition
    /// to either `Lzma2Data` or `Done` (end marker) or `Lzma2BlockEnd`.
    Lzma2Control,
    Lzma2Data,
    /// After the LZMA2 end marker: skip 0..=3 padding zeros and read the
    /// 4-byte Check.
    BlockPadding,
    BlockCheck,
    /// Index: index indicator already consumed in BlockOrIndex. We now
    /// accumulate the rest of the index in a buffer (it's typically tiny).
    Index,
    /// Reading the Stream Footer (12 bytes).
    StreamFooter,
    Done,
}

pub struct Decoder {
    phase: DecPhase,
    /// Generic scratch buffer for partial structural reads.
    scratch: Vec<u8>,
    /// How many bytes of the current structural item we still need.
    scratch_want: usize,

    /// Once we have parsed the Stream Header.
    check_id: u8,

    /// Total bytes of the Block Header.
    block_header_size: usize,

    /// Remaining payload bytes to read+emit in the current chunk.
    chunk_remaining: usize,

    /// Track block sizes for cross-checking against the Index.
    block_header_size_seen: u64,
    block_compressed_seen: u64,
    block_uncompressed_seen: u64,

    /// Block check (CRC32 of all uncompressed bytes in the block).
    check: Crc32,

    /// Collected blocks for index cross-check: (unpadded_size, uncompressed).
    blocks: Vec<(u64, u64)>,

    /// Once Index starts, we accumulate it for CRC32 validation.
    index_buf: Vec<u8>,
    /// Bytes of the index we still need to read after the indicator+records:
    /// 0..=3 padding bytes + 4 CRC32 bytes.
    index_records_remaining: u64,
    index_records_total: u64,
    /// Current parse cursor within `index_buf`. Persists across decode calls
    /// so we resume varint parsing where we left off.
    index_pos: usize,

    poisoned: bool,
}

impl Decoder {
    pub fn new() -> Self {
        Self {
            phase: DecPhase::StreamHeader,
            scratch: Vec::new(),
            scratch_want: 12,
            check_id: 0,
            block_header_size: 0,
            chunk_remaining: 0,
            block_header_size_seen: 0,
            block_compressed_seen: 0,
            block_uncompressed_seen: 0,
            check: Crc32::new(),
            blocks: Vec::new(),
            index_buf: Vec::new(),
            index_records_remaining: 0,
            index_records_total: 0,
            index_pos: 0,
            poisoned: false,
        }
    }

    fn poison(&mut self, e: Error) -> Error {
        self.poisoned = true;
        e
    }

    /// Append bytes from `input[consumed..]` into `self.scratch` up to
    /// `self.scratch_want` total scratch bytes. Returns true once scratch
    /// has reached `scratch_want` bytes.
    fn fill_scratch(&mut self, input: &[u8], consumed: &mut usize) -> bool {
        let need = self.scratch_want.saturating_sub(self.scratch.len());
        let take = need.min(input.len() - *consumed);
        if take > 0 {
            self.scratch
                .extend_from_slice(&input[*consumed..*consumed + take]);
            *consumed += take;
        }
        self.scratch.len() >= self.scratch_want
    }

    fn parse_stream_header(&mut self) -> Result<(), Error> {
        if self.scratch[..6] != STREAM_MAGIC {
            return Err(self.poison(Error::BadHeader));
        }
        if self.scratch[6] != 0 {
            return Err(self.poison(Error::Unsupported));
        }
        let check_id = self.scratch[7];
        if check_id & 0xF0 != 0 {
            return Err(self.poison(Error::Unsupported));
        }
        // We accept any check type with the right size when reading, but for
        // simplicity here we only verify CRC32 checks; others get accepted
        // (their bytes are skipped without validation) when check_id != 0x01
        // and != 0x00. To keep things tight, restrict to None/CRC32.
        match check_id & 0x0F {
            0x00 | 0x01 => {}
            _ => return Err(self.poison(Error::Unsupported)),
        }
        self.check_id = check_id & 0x0F;

        let stored_crc = u32::from_le_bytes([
            self.scratch[8],
            self.scratch[9],
            self.scratch[10],
            self.scratch[11],
        ]);
        if stored_crc != crc32(&self.scratch[6..8]) {
            return Err(self.poison(Error::ChecksumMismatch));
        }
        Ok(())
    }

    fn check_size(&self) -> usize {
        match self.check_id {
            0x00 => 0,
            0x01 => 4,
            _ => 0, // unreachable: parse_stream_header rejects others
        }
    }

    fn parse_block_header(&mut self) -> Result<(), Error> {
        // self.scratch holds the full block header including the leading
        // size byte and the trailing 4-byte CRC32.
        let total = self.scratch.len();
        debug_assert_eq!(total, self.block_header_size);
        // Validate CRC32 over everything except the last 4 bytes.
        let stored = u32::from_le_bytes([
            self.scratch[total - 4],
            self.scratch[total - 3],
            self.scratch[total - 2],
            self.scratch[total - 1],
        ]);
        if stored != crc32(&self.scratch[..total - 4]) {
            return Err(self.poison(Error::ChecksumMismatch));
        }
        // Parse flags.
        let flags = self.scratch[1];
        let num_filters = ((flags & 0x03) + 1) as usize;
        if flags & 0x3C != 0 {
            return Err(self.poison(Error::Unsupported));
        }
        let has_compressed_size = flags & 0x40 != 0;
        let has_uncompressed_size = flags & 0x80 != 0;

        // Cursor starting after the size byte + flags byte.
        let mut cur = 2usize;
        let body_end = total - 4; // before CRC

        if has_compressed_size {
            // Discard the value — we still bound the block by the LZMA2 end
            // marker.
            varint_decode(&self.scratch[..body_end], &mut cur)?
                .ok_or_else(|| self.poison(Error::Corrupt))?;
        }
        if has_uncompressed_size {
            varint_decode(&self.scratch[..body_end], &mut cur)?
                .ok_or_else(|| self.poison(Error::Corrupt))?;
        }
        if num_filters != 1 {
            // We only support a single LZMA2 filter.
            return Err(self.poison(Error::Unsupported));
        }
        let filter_id = varint_decode(&self.scratch[..body_end], &mut cur)?
            .ok_or_else(|| self.poison(Error::Corrupt))?;
        if filter_id != FILTER_ID_LZMA2 as u64 {
            return Err(self.poison(Error::Unsupported));
        }
        let props_size = varint_decode(&self.scratch[..body_end], &mut cur)?
            .ok_or_else(|| self.poison(Error::Corrupt))?;
        if props_size != 1 {
            return Err(self.poison(Error::Unsupported));
        }
        if cur >= body_end {
            return Err(self.poison(Error::Corrupt));
        }
        let dict_flag = self.scratch[cur];
        cur += 1;
        if dict_flag & 0xC0 != 0 {
            return Err(self.poison(Error::Unsupported));
        }
        // Any remaining bytes before the CRC must be zero padding.
        while cur < body_end {
            if self.scratch[cur] != 0 {
                return Err(self.poison(Error::Corrupt));
            }
            cur += 1;
        }
        Ok(())
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
        let mut consumed = 0usize;
        let mut written = 0usize;

        loop {
            let init_c = consumed;
            let init_w = written;
            let init_phase = self.phase;

            match self.phase {
                DecPhase::StreamHeader => {
                    let filled = self.fill_scratch(input, &mut consumed);
                    // As soon as we have the 6-byte magic, validate it so
                    // bad magic is rejected without needing the whole 12-byte
                    // header.
                    if self.scratch.len() >= 6 && self.scratch[..6] != STREAM_MAGIC {
                        return Err(self.poison(Error::BadHeader));
                    }
                    if filled {
                        self.parse_stream_header()?;
                        self.scratch.clear();
                        self.scratch_want = 1; // peek first byte after header
                        self.phase = DecPhase::BlockOrIndex;
                    } else {
                        return Ok(Progress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                }
                DecPhase::BlockOrIndex => {
                    if self.fill_scratch(input, &mut consumed) {
                        let first = self.scratch[0];
                        if first == 0x00 {
                            // Index begins. The indicator (0x00) is part of
                            // the index for CRC purposes.
                            self.index_buf.clear();
                            self.index_buf.push(0x00);
                            self.scratch.clear();
                            self.scratch_want = 1;
                            self.index_records_total = 0;
                            self.index_records_remaining = u64::MAX; // not yet known
                            self.index_pos = 1; // ready to parse NumRecords
                            self.phase = DecPhase::Index;
                        } else {
                            // Block Header. The byte is (header_size/4 - 1).
                            self.block_header_size = ((first as usize) + 1) * 4;
                            self.scratch_want = self.block_header_size;
                            self.block_header_size_seen = self.block_header_size as u64;
                            self.block_compressed_seen = 0;
                            self.block_uncompressed_seen = 0;
                            self.check = Crc32::new();
                            self.phase = DecPhase::BlockHeader;
                        }
                    } else {
                        return Ok(Progress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                }
                DecPhase::BlockHeader => {
                    if self.fill_scratch(input, &mut consumed) {
                        self.parse_block_header()?;
                        self.scratch.clear();
                        self.scratch_want = 1;
                        self.phase = DecPhase::Lzma2Control;
                    } else {
                        return Ok(Progress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                }
                DecPhase::Lzma2Control => {
                    // We need either 1 byte (for end marker) or 3 bytes
                    // (control + 2-byte size for uncompressed chunks). Read
                    // the first byte first; once we see 0x01/0x02 we extend
                    // to 3.
                    if self.scratch.is_empty() {
                        self.scratch_want = 1;
                        if !self.fill_scratch(input, &mut consumed) {
                            return Ok(Progress {
                                consumed,
                                written,
                                done: false,
                            });
                        }
                    }
                    let control = self.scratch[0];
                    if control == 0x00 {
                        // End marker. Account for this byte.
                        self.block_compressed_seen += 1;
                        self.scratch.clear();
                        // Block Padding (0..=3 zero bytes) then Block Check.
                        let unpadded_no_pad = self.block_header_size_seen
                            + self.block_compressed_seen
                            + self.check_size() as u64;
                        let pad = (4 - (unpadded_no_pad % 4) as usize) % 4;
                        self.scratch_want = pad;
                        self.phase = DecPhase::BlockPadding;
                    } else if control == 0x01 || control == 0x02 {
                        self.scratch_want = 3;
                        if !self.fill_scratch(input, &mut consumed) {
                            return Ok(Progress {
                                consumed,
                                written,
                                done: false,
                            });
                        }
                        self.block_compressed_seen += 3;
                        let len =
                            (((self.scratch[1] as usize) << 8) | self.scratch[2] as usize) + 1;
                        let _ = control; // chunk type is informational only
                        self.chunk_remaining = len;
                        self.scratch.clear();
                        self.scratch_want = 0;
                        self.phase = DecPhase::Lzma2Data;
                    } else if control >= 0x80 {
                        return Err(self.poison(Error::Unsupported));
                    } else {
                        return Err(self.poison(Error::Corrupt));
                    }
                }
                DecPhase::Lzma2Data => {
                    while self.chunk_remaining > 0
                        && consumed < input.len()
                        && written < output.len()
                    {
                        let take = self
                            .chunk_remaining
                            .min(input.len() - consumed)
                            .min(output.len() - written);
                        let src = &input[consumed..consumed + take];
                        output[written..written + take].copy_from_slice(src);
                        self.check.update(src);
                        self.block_compressed_seen += take as u64;
                        self.block_uncompressed_seen += take as u64;
                        self.chunk_remaining -= take;
                        consumed += take;
                        written += take;
                    }
                    if self.chunk_remaining == 0 {
                        self.scratch.clear();
                        self.scratch_want = 1;
                        self.phase = DecPhase::Lzma2Control;
                    } else {
                        return Ok(Progress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                }
                DecPhase::BlockPadding => {
                    if self.scratch_want == 0 {
                        // No padding to skip; proceed to check.
                        self.scratch.clear();
                        self.scratch_want = self.check_size();
                        self.phase = DecPhase::BlockCheck;
                    } else if self.fill_scratch(input, &mut consumed) {
                        if self.scratch.iter().any(|&b| b != 0) {
                            return Err(self.poison(Error::Corrupt));
                        }
                        self.scratch.clear();
                        self.scratch_want = self.check_size();
                        self.phase = DecPhase::BlockCheck;
                    } else {
                        return Ok(Progress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                }
                DecPhase::BlockCheck => {
                    if self.scratch_want == 0 {
                        // No check; just record and proceed.
                        let unpadded_size = self.block_header_size_seen
                            + self.block_compressed_seen
                            + self.check_size() as u64;
                        self.blocks
                            .push((unpadded_size, self.block_uncompressed_seen));
                        self.scratch.clear();
                        self.scratch_want = 1;
                        self.phase = DecPhase::BlockOrIndex;
                    } else if self.fill_scratch(input, &mut consumed) {
                        if self.check_id == 0x01 {
                            let got = u32::from_le_bytes([
                                self.scratch[0],
                                self.scratch[1],
                                self.scratch[2],
                                self.scratch[3],
                            ]);
                            if got != self.check.finalize() {
                                return Err(self.poison(Error::ChecksumMismatch));
                            }
                        }
                        let unpadded_size = self.block_header_size_seen
                            + self.block_compressed_seen
                            + self.check_size() as u64;
                        self.blocks
                            .push((unpadded_size, self.block_uncompressed_seen));
                        self.scratch.clear();
                        self.scratch_want = 1;
                        self.phase = DecPhase::BlockOrIndex;
                    } else {
                        return Ok(Progress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                }
                DecPhase::Index => {
                    // Consume bytes one at a time so we can incrementally
                    // varint-parse the records, then collect padding and CRC.
                    // We need to track: index indicator (already in
                    // index_buf), then NumRecords varint, then for each
                    // record two varints, then padding to align to 4, then 4
                    // CRC bytes.
                    //
                    // Strategy: keep slurping bytes into `index_buf`. At each
                    // step, re-parse from a known offset to see if a
                    // structural element is complete.
                    //
                    // To keep this simple, we read varints lazily: after
                    // each new byte, attempt to parse the next pending
                    // varint. When all records are present, switch to
                    // "padding + CRC" mode.

                    // Pull all available input into `index_buf` first.
                    if consumed < input.len() {
                        self.index_buf.extend_from_slice(&input[consumed..]);
                        consumed = input.len();
                    }

                    // Drive the state machine until either we run out of
                    // bytes or we transition to StreamFooter.
                    loop {
                        if self.index_records_remaining == u64::MAX {
                            // NumRecords still to parse, starting at offset 1.
                            let mut p = self.index_pos;
                            match varint_decode(&self.index_buf, &mut p)? {
                                Some(n) => {
                                    self.index_records_total = n;
                                    self.index_records_remaining = n.saturating_mul(2);
                                    self.index_pos = p;
                                    self.blocks.reserve(n as usize);
                                }
                                None => break, // need more bytes
                            }
                        } else if self.index_records_remaining > 0 {
                            let mut p = self.index_pos;
                            match varint_decode(&self.index_buf, &mut p)? {
                                Some(_v) => {
                                    self.index_pos = p;
                                    self.index_records_remaining -= 1;
                                }
                                None => break,
                            }
                        } else {
                            // Records done. Need padding + CRC.
                            let body_len_so_far = self.index_pos;
                            let pad = (4 - (body_len_so_far % 4)) % 4;
                            let need_total = body_len_so_far + pad + 4;
                            if self.index_buf.len() < need_total {
                                break;
                            }
                            for &b in &self.index_buf[body_len_so_far..body_len_so_far + pad] {
                                if b != 0 {
                                    return Err(self.poison(Error::Corrupt));
                                }
                            }
                            let crc_off = body_len_so_far + pad;
                            let stored = u32::from_le_bytes([
                                self.index_buf[crc_off],
                                self.index_buf[crc_off + 1],
                                self.index_buf[crc_off + 2],
                                self.index_buf[crc_off + 3],
                            ]);
                            if stored != crc32(&self.index_buf[..crc_off]) {
                                return Err(self.poison(Error::ChecksumMismatch));
                            }
                            if self.blocks.len() as u64 != self.index_records_total {
                                return Err(self.poison(Error::Corrupt));
                            }
                            let blocks_snapshot: Vec<(u64, u64)> = self.blocks.clone();
                            let mut p = 1usize;
                            let _n = match varint_decode(&self.index_buf, &mut p)? {
                                Some(n) => n,
                                None => return Err(self.poison(Error::Corrupt)),
                            };
                            for &(blk_unpadded, blk_uncompressed) in &blocks_snapshot {
                                let unpadded = match varint_decode(&self.index_buf, &mut p)? {
                                    Some(v) => v,
                                    None => return Err(self.poison(Error::Corrupt)),
                                };
                                let uncompressed = match varint_decode(&self.index_buf, &mut p)? {
                                    Some(v) => v,
                                    None => return Err(self.poison(Error::Corrupt)),
                                };
                                if unpadded != blk_unpadded || uncompressed != blk_uncompressed {
                                    return Err(self.poison(Error::TrailerMismatch));
                                }
                            }
                            // Index size for the Stream Footer's Backward
                            // Size cross-check.
                            let index_size = need_total as u32;
                            // Stash; we re-use `block_header_size` after
                            // blocks have been processed.
                            self.block_header_size = index_size as usize;
                            // Any bytes that arrived *past* the index in
                            // `index_buf` actually belong to the Stream
                            // Footer. Pre-seed `scratch` with them.
                            self.scratch.clear();
                            self.scratch_want = 12;
                            if self.index_buf.len() > need_total {
                                self.scratch
                                    .extend_from_slice(&self.index_buf[need_total..]);
                            }
                            self.phase = DecPhase::StreamFooter;
                            break;
                        }
                    }
                }
                DecPhase::StreamFooter => {
                    if self.fill_scratch(input, &mut consumed) {
                        let s = &self.scratch[..];
                        let crc_stored = u32::from_le_bytes([s[0], s[1], s[2], s[3]]);
                        if crc_stored != crc32(&s[4..10]) {
                            return Err(self.poison(Error::ChecksumMismatch));
                        }
                        let back = u32::from_le_bytes([s[4], s[5], s[6], s[7]]);
                        let want_back = (self.block_header_size as u32 / 4) - 1;
                        if back != want_back {
                            return Err(self.poison(Error::TrailerMismatch));
                        }
                        if s[8] != STREAM_FLAGS[0] || (s[9] & 0x0F) != self.check_id {
                            return Err(self.poison(Error::Corrupt));
                        }
                        if s[10] != FOOTER_MAGIC[0] || s[11] != FOOTER_MAGIC[1] {
                            return Err(self.poison(Error::BadHeader));
                        }
                        self.phase = DecPhase::Done;
                    } else {
                        return Ok(Progress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                }
                DecPhase::Done => {
                    return Ok(Progress {
                        consumed,
                        written,
                        done: false,
                    });
                }
            }

            if consumed == init_c && written == init_w && self.phase == init_phase {
                return Ok(Progress {
                    consumed,
                    written,
                    done: false,
                });
            }
        }
    }

    fn finish(&mut self, output: &mut [u8]) -> Result<Progress, Error> {
        if self.poisoned {
            return Err(Error::Corrupt);
        }
        let empty: [u8; 0] = [];
        let p = self.decode(&empty, output)?;
        if matches!(self.phase, DecPhase::Done) {
            Ok(Progress {
                consumed: 0,
                written: p.written,
                done: true,
            })
        } else {
            Err(self.poison(Error::UnexpectedEnd))
        }
    }

    fn reset(&mut self) {
        *self = Self::new();
    }
}
