//! xz container around LZMA2.
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
//!  Check (of the uncompressed Block data: none, CRC32, CRC64 or SHA-256)
//!  Index (Index Indicator 00 | NumRecords varint | (UnpaddedSize varint,
//!         UncompressedSize varint)+ | 0..3 zero pad | CRC32 of all the above)
//!  Stream Footer (12 B)
//!  Stream Padding (zero bytes, a multiple of 4), then optionally further
//!  Streams, each followed by optional padding
//! ```
//!
//! The encoder writes a single filter (LZMA2, filter ID 0x21). The decoder
//! also accepts the filter chains the spec defines: up to three non-last
//! filters before LZMA2 — Delta (`0x03`) and the BCJ branch converters x86
//! (`0x04`), PowerPC (`0x05`), IA-64 (`0x06`), ARM (`0x07`), ARM-Thumb
//! (`0x08`), SPARC (`0x09`), ARM64 (`0x0A`) and RISC-V (`0x0B`), with
//! their start-offset properties — undone in the private `filters`
//! submodule with this crate's `delta` and `bcj` transforms (the `xz`
//! feature pulls both in). Other filter IDs fail with
//! [`Error::Unsupported`].
//!
//! Decoding handles every LZMA2 chunk type: `0x00` (end marker), `0x01`
//! (uncompressed + dictionary reset), `0x02` (uncompressed, no reset),
//! and `0x80..=0xFF` (LZMA-compressed, with the spec's full matrix of
//! state/properties/dictionary reset flags). The compressed-chunk
//! decoder is in the private `lzma2_decoder` submodule and is adapted
//! from this crate's `lzma` module.
//!
//! The encoder emits LZMA-compressed LZMA2 chunks (control byte
//! `0xE0` — compressed, with dictionary + properties + state reset on
//! every chunk so each chunk is independently decodable). When
//! compression would expand a chunk relative to its uncompressed
//! input — which happens on already-random or already-compressed
//! data — we fall back to an uncompressed chunk (control byte `0x01`).
//! Real LZMA-compressed output is produced by the private
//! `lzma2_encoder` submodule, which is a port of the `.lzma` encoder in
//! `src/lzma/` adapted to emit a raw range-coded body (no header, no
//! EOS marker).
//!
//! ## Flush
//!
//! [`Encoder::flush`](crate::Encoder::flush) encodes every byte given so far
//! into complete LZMA2 chunks and emits them. The xz Block stays open (its
//! end marker, Check, Index and Stream Footer are written only by `finish`),
//! so the bytes emitted up to a flush are a truncated `.xz` file: a streaming
//! decoder fed them outputs all the data given before the flush and then
//! waits for more input (this crate's decoder returns `InputEmpty`;
//! `xz -dc` writes the data and then reports "Unexpected end of input").
//! What the truncated stream cannot provide yet is *verification*: the Block
//! Check (CRC32) and the Index only arrive with `finish`, so flushed data is
//! decoded but not yet integrity-checked.
//!
//! [`Flush::Sync`] keeps the dictionary and the adaptive
//! model; the next chunk continues them. [`Flush::Full`]
//! makes the next chunk a dictionary reset (control `0xE0`, or `0x01` if it
//! is stored uncompressed), so nothing after the flush references data
//! before it. Both stay within the single xz Block.
//!
//! ## Concatenated Streams
//!
//! Like `xz -d`, the decoder accepts several Streams back to back, each
//! optionally followed by Stream Padding (zero bytes, a multiple of four in
//! total, else [`Error::Corrupt`]), and decodes them as one output. Bytes
//! after the last Stream that are neither padding nor another Stream Header
//! end the data: `decode` reports the end and leaves the bytes that arrived
//! in that call unconsumed, so the caller can see where the xz data stops.
//! Because another Stream may still arrive, `decode` reports the end only
//! once it sees such bytes; when the input ends right after a Stream (or its
//! padding), `finish` settles it.
//!
//! ## Integrity checks
//!
//! The encoder writes a CRC32 Block Check. The decoder verifies every check
//! type the format defines — CRC32 (`0x01`), CRC64 (`0x04`, the `xz` CLI
//! default) and SHA-256 (`0x0A`) — and fails with
//! [`Error::ChecksumMismatch`] on a mismatch. A reserved check ID still
//! fixes the Check field's size, so, like liblzma by default, such a Stream
//! decodes with its Check skipped unverified.
//!
//! No dependency on the sibling `lzma` module: the small amount of LZMA2
//! framing we need (control byte, big-endian 16-bit size), the CRC-32 used
//! for the Stream Header, Block Header and Index CRCs, and the CRC-64 and
//! SHA-256 Block Checks are all defined inline below.

// The state machines in this file are written as a series of `match` arms
// each containing an `if`/`else` that either makes progress or returns; the
// shape is intentional and the alternative (a flat outer match) costs us
// duplicate "return Ok(Progress { ... })" tails. Allow the lint here.
#![allow(clippy::collapsible_match, clippy::collapsible_if)]

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::error::Error;
use crate::traits::{Algorithm, Flush, RawDecoder, RawEncoder, RawProgress};

// The LZMA2 chunk codec lives in a crate-internal shared module
// (`crate::lzma2_internal`) so it can also back the public raw LZMA2
// decoder exposed under the `lzma2` feature without pulling in this xz
// container. See `lib.rs`.
use crate::lzma2_internal::lzma2_decoder::{Lzma2Props, LzmaCore, lzma2_dict_size};
use crate::lzma2_internal::lzma2_encoder::{
    EncoderParams, LZMA2_PROPS_BYTE, Lzma2Chunk, Lzma2StreamEncoder,
};

mod filters;
use filters::FilterChain;

// ─── constants ─────────────────────────────────────────────────────────────

const STREAM_MAGIC: [u8; 6] = [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00];
const FOOTER_MAGIC: [u8; 2] = [0x59, 0x5A];

/// Stream Flags second byte: 0x01 = CRC32 check.
const STREAM_FLAGS_CHECK_CRC32: u8 = 0x01;
const STREAM_FLAGS: [u8; 2] = [0x00, STREAM_FLAGS_CHECK_CRC32];

/// Filter ID 0x21 = LZMA2.
const FILTER_ID_LZMA2: u8 = 0x21;

/// Dictionary-size flag byte. Per the LZMA2 spec (xz-file-format.txt
/// §5.3.1), values `0..=39` map to dictionary sizes via
/// `(2 | (b & 1)) << (b/2 + 11)`, and `40` is the special "max" value
/// (0xFFFFFFFF). `0x14` = 20 → `(2 | 0) << (10 + 11)` = `2 << 21` =
/// 4 MiB, a standard mid-range choice that matches xz-utils' default
/// for small files and bounds the decoder's window allocation
/// predictably. Our compressed encoder uses this same value as the
/// `dict_size` ceiling for match distances, so the produced LZMA2
/// stream is self-consistent.
const LZMA2_DICT_FLAG: u8 = 0x14;

/// Dictionary size in bytes derived from [`LZMA2_DICT_FLAG`]. Kept in
/// sync manually: 0x14 → 4 MiB.
const LZMA2_DICT_SIZE: u32 = 4 * 1024 * 1024;

/// Maximum uncompressed payload bytes per LZMA2 chunk we emit. The
/// uncompressed-chunk size field is 16-bit + 1, capping at 65_536. The
/// compressed-chunk uncompressed-size field can carry up to 2_097_152
/// (21-bit + 1), but capping at the same 65_536 keeps the chunk header
/// shape uniform and bounds peak memory: with 96 MiB inputs we still
/// allocate just one chunk's worth of working buffers.
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

// ─── inline CRC-64 ─────────────────────────────────────────────────────────
//
// CRC-64/XZ (ECMA-182 polynomial, reflected 0xC96C5795D7870F42), initial
// and final XOR all ones: the Block Check of a Stream whose check ID is 0x04
// (`xz --check=crc64`, the CLI default).

#[derive(Clone, Copy)]
struct Crc64 {
    state: u64,
}

impl Crc64 {
    const fn new() -> Self {
        Self { state: !0 }
    }

    fn update(&mut self, data: &[u8]) {
        let mut s = self.state;
        for &b in data {
            let idx = ((s ^ b as u64) & 0xFF) as usize;
            s = (s >> 8) ^ CRC64_TABLE[idx];
        }
        self.state = s;
    }

    const fn finalize(self) -> u64 {
        !self.state
    }
}

const CRC64_TABLE: [u64; 256] = {
    let mut table = [0u64; 256];
    let mut i = 0u64;
    while i < 256 {
        let mut c = i;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 {
                0xC96C_5795_D787_0F42 ^ (c >> 1)
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

// ─── inline SHA-256 ────────────────────────────────────────────────────────
//
// FIPS 180-4 SHA-256: the Block Check of a Stream whose check ID is 0x0A
// (`xz --check=sha256`). Only the decoder needs it, to verify; a plain
// one-block-at-a-time compression function is plenty.

const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

#[derive(Clone)]
struct Sha256 {
    h: [u32; 8],
    /// Partial 64-byte message block awaiting compression.
    buf: [u8; 64],
    buf_len: usize,
    /// Message length so far, in bytes.
    total: u64,
}

impl Sha256 {
    const fn new() -> Self {
        Self {
            h: [
                0x6a09_e667,
                0xbb67_ae85,
                0x3c6e_f372,
                0xa54f_f53a,
                0x510e_527f,
                0x9b05_688c,
                0x1f83_d9ab,
                0x5be0_cd19,
            ],
            buf: [0; 64],
            buf_len: 0,
            total: 0,
        }
    }

    fn compress(h: &mut [u32; 8], block: &[u8; 64]) {
        let mut w = [0u32; 64];
        for (i, word) in block.as_chunks::<4>().0.iter().enumerate() {
            w[i] = u32::from_be_bytes(*word);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = *h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(SHA256_K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (x, v) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
            *x = x.wrapping_add(v);
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        self.total = self.total.wrapping_add(data.len() as u64);
        if self.buf_len > 0 {
            let take = (64 - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len < 64 {
                return;
            }
            Self::compress(&mut self.h, &self.buf);
            self.buf_len = 0;
        }
        let (blocks, rest) = data.as_chunks::<64>();
        for block in blocks {
            Self::compress(&mut self.h, block);
        }
        self.buf[..rest.len()].copy_from_slice(rest);
        self.buf_len = rest.len();
    }

    fn finalize(mut self) -> [u8; 32] {
        let bit_len = self.total.wrapping_mul(8);
        // 0x80 terminator, zero fill, then the 64-bit big-endian bit length
        // ending a block (spilling into a second block if it does not fit).
        let mut pad = [0u8; 72];
        pad[0] = 0x80;
        let zeros = (55usize.wrapping_sub(self.buf_len)) % 64;
        pad[1 + zeros..9 + zeros].copy_from_slice(&bit_len.to_be_bytes());
        self.update(&pad[..9 + zeros]);
        debug_assert_eq!(self.buf_len, 0);
        let mut out = [0u8; 32];
        for (o, v) in out.as_chunks_mut::<4>().0.iter_mut().zip(self.h) {
            o.copy_from_slice(&v.to_be_bytes());
        }
        out
    }
}

/// Running Block Check, selected by the Stream Flags' check ID.
#[derive(Clone)]
enum BlockCheck {
    /// Check ID 0x00 (no check), or a reserved ID this build does not
    /// implement: the Check field is skipped unverified, as liblzma does.
    Unverified,
    Crc32(Crc32),
    Crc64(Crc64),
    Sha256(Box<Sha256>),
}

impl BlockCheck {
    fn new(check_id: u8) -> Self {
        match check_id {
            0x01 => Self::Crc32(Crc32::new()),
            0x04 => Self::Crc64(Crc64::new()),
            0x0A => Self::Sha256(Box::new(Sha256::new())),
            _ => Self::Unverified,
        }
    }

    fn update(&mut self, data: &[u8]) {
        match self {
            Self::Unverified => {}
            Self::Crc32(c) => c.update(data),
            Self::Crc64(c) => c.update(data),
            Self::Sha256(s) => s.update(data),
        }
    }

    /// Compare against the stored Check field (whose length the caller
    /// sized from the check ID).
    fn matches(&self, stored: &[u8]) -> bool {
        match self {
            Self::Unverified => true,
            Self::Crc32(c) => stored == c.finalize().to_le_bytes(),
            Self::Crc64(c) => stored == c.finalize().to_le_bytes(),
            Self::Sha256(s) => stored == s.as_ref().clone().finalize(),
        }
    }
}

/// Size of the Check field for a check ID (xz-file-format.txt §3.4: IDs
/// come in groups of three sharing a size, reserved ones included).
const fn check_size_for(check_id: u8) -> usize {
    match check_id {
        0x00 => 0,
        0x01..=0x03 => 4,
        0x04..=0x06 => 8,
        0x07..=0x09 => 16,
        0x0A..=0x0C => 32,
        _ => 64,
    }
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

/// Tunables for the xz encoder.
///
/// `level` controls the speed/ratio trade-off of the inner LZMA2 chunk
/// encoder: `0` is fastest and produces the largest output, `9` is slowest
/// and produces the smallest. The default of `6` mirrors `xz-utils`' default
/// preset.
///
/// Values outside `0..=9` are clamped at encoder construction time — the
/// public surface is intentionally infallible.
///
/// Note: the level is fully threaded into our LZMA2 chunk encoder's
/// match-finder tuning (chain budget + nice-match cutoff). It does not
/// currently affect the dictionary size advertised in the Block Header
/// (we stick with `LZMA2_DICT_SIZE` = 4 MiB regardless), nor the LZMA
/// literal-context (`lc/lp/pb`) properties (we always emit the canonical
/// `lc=3, lp=0, pb=2` triple).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EncoderConfig {
    /// Compression level in `0..=9`.
    pub level: u8,
}

impl Default for EncoderConfig {
    fn default() -> Self {
        Self { level: 6 }
    }
}

/// Zero-sized marker type implementing [`Algorithm`] for xz.
#[derive(Debug, Clone, Copy, Default)]
pub struct Xz;

impl Algorithm for Xz {
    const NAME: &'static str = "xz";
    type Encoder = Encoder;
    type Decoder = Decoder;
    type EncoderConfig = EncoderConfig;
    type DecoderConfig = ();
    fn encoder_with(c: Self::EncoderConfig) -> Encoder {
        Encoder::with_config(c)
    }
    fn decoder_with(_: ()) -> Decoder {
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
    // Bounded-memory continuous-dictionary LZMA2 chunk encoder. Fed input
    // incrementally; emits framed chunks as they become fully buffered, so the
    // whole input is never accumulated. `None` until the Body phase starts.
    stream: Option<Lzma2StreamEncoder>,
    // Raw input bytes pushed into `stream` but not yet consumed by an emitted
    // chunk. Bounded by one chunk's worth (`stream` emits as soon as a full
    // chunk is buffered), so this stays `O(LZMA2_CHUNK_MAX)`. Used to frame
    // uncompressed-fallback chunks (raw bytes copied verbatim) and to feed the
    // Block Check CRC32 in encode order.
    staged_input: Vec<u8>,
    // Set once `stream.finish()` has been called, so a multi-call `raw_finish`
    // (draining across several small output buffers) doesn't re-finish.
    stream_finished: bool,
    // CRC32 of all uncompressed input bytes — becomes the Block Check.
    check: Crc32,
    // Bookkeeping for the Index Record.
    uncompressed_total: u64,
    /// Bytes emitted into the block's LZMA2 payload (chunks + 0x00 marker).
    compressed_payload_bytes: u64,
    /// Block Header byte length (known at construction).
    block_header_len: u64,
    /// Match-finder tuning, derived from [`EncoderConfig::level`]. Preserved
    /// across `reset` per the trait contract that configuration survives
    /// resets.
    enc_params: EncoderParams,
}

impl Encoder {
    /// Build an encoder at the default compression level (6).
    pub fn new() -> Self {
        Self::with_config(EncoderConfig::default())
    }

    /// Build an encoder with explicit configuration. `config.level` is
    /// clamped to `0..=9` internally — out-of-range values snap to 9.
    pub fn with_config(config: EncoderConfig) -> Self {
        let header = build_stream_header();
        let mut pending = Vec::with_capacity(12);
        pending.extend_from_slice(&header);
        Self {
            phase: EncPhase::StreamHeader,
            pending,
            pending_idx: 0,
            stream: None,
            staged_input: Vec::new(),
            stream_finished: false,
            check: Crc32::new(),
            uncompressed_total: 0,
            compressed_payload_bytes: 0,
            block_header_len: build_block_header().len() as u64,
            enc_params: EncoderParams::from_level(config.level),
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

    /// Frame each produced LZMA2 chunk into `pending`, consuming the matching
    /// raw bytes from `staged_input` (for CRC + the uncompressed fallback).
    ///
    /// The chunks come from a single continuous, **bounded-memory** match-finder
    /// ([`Lzma2StreamEncoder`]): the first chunk resets the dictionary (`0xE0`
    /// compressed / `0x01` uncompressed) and every later chunk *continues* it
    /// (`0xC0` compressed / `0x02` uncompressed), so a match in a later chunk
    /// can reference data from any earlier chunk up to the dictionary size. The
    /// range coder still resets per chunk, but the dictionary/history is
    /// continuous — this is what brings the ratio in line with the single-stream
    /// `.lzma` path, while peak memory stays `O(dict_size)`.
    /// Lazily create the bounded-memory LZMA2 stream encoder on first use.
    fn stream(&mut self) -> &mut Lzma2StreamEncoder {
        self.stream
            .get_or_insert_with(|| Lzma2StreamEncoder::new(LZMA2_DICT_SIZE, self.enc_params))
    }

    fn stage_chunks(&mut self, chunks: Vec<Lzma2Chunk>) {
        for chunk in chunks {
            let n = chunk.uncomp_len;
            debug_assert!(self.staged_input.len() >= n);
            // The bytes belonging to this chunk are the front `n` of the staged
            // buffer (chunks are produced in encode order).
            let data: Vec<u8> = self.staged_input.drain(..n).collect();
            self.check.update(&data);
            self.uncompressed_total += n as u64;
            match chunk.body {
                Some(ref body) => {
                    self.stage_compressed_chunk(&data, body, chunk.reset_dict, chunk.reset_state)
                }
                None => self.stage_uncompressed_chunk(&data, chunk.reset_dict),
            }
        }
    }

    /// Stage one compressed LZMA2 chunk. The control byte selects the reset
    /// mode: `0xE0` (first chunk — reset dict + props + state), `0xC0`
    /// (`reset_state`, dict continues — reset props + state), or `0x80`
    /// (continuation — no reset, the model carries over from the previous
    /// chunk). `0xE0`/`0xC0` set bit 6 and are followed by a 1-byte props
    /// field; `0x80` has no props byte. The low 5 bits of the control carry the
    /// top 5 bits of `uncomp_size-1`; then two big-endian `uncomp_size-1`
    /// continuation bytes, two big-endian `comp_size-1` bytes, the optional
    /// props byte, then the range-coded payload.
    ///
    /// Continuation (`0x80`) is what keeps the adaptive LZMA model warm across
    /// 64 KiB chunk boundaries, matching native `xz`; a mid-stream props/state
    /// reset every chunk would otherwise re-warm the model from scratch and
    /// bloat highly compressible output.
    fn stage_compressed_chunk(
        &mut self,
        data: &[u8],
        compressed: &[u8],
        reset_dict: bool,
        reset_state: bool,
    ) {
        // A compressed chunk's uncompressed span uses the 21-bit size field
        // (≤ 2 MiB); the compressed body must fit the 16-bit comp field.
        debug_assert!(!data.is_empty() && data.len() <= 1 << 21);
        debug_assert!(!compressed.is_empty() && compressed.len() <= 65_536);

        let uncomp_size_minus_1 = (data.len() - 1) as u32; // 0..=2^21-1
        let uncomp_top = ((uncomp_size_minus_1 >> 16) & 0x1F) as u8;
        let base: u8 = if reset_dict {
            0xE0
        } else if reset_state {
            0xC0
        } else {
            0x80
        };
        let control: u8 = base | uncomp_top;
        // Bit 6 (0x40) set ⇒ a props byte follows (0xE0/0xC0).
        let has_props = control & 0x40 != 0;

        let uncomp_mid = ((uncomp_size_minus_1 >> 8) & 0xFF) as u8;
        let uncomp_lo = (uncomp_size_minus_1 & 0xFF) as u8;
        let comp_size_minus_1 = (compressed.len() - 1) as u16;
        let comp_hi = (comp_size_minus_1 >> 8) as u8;
        let comp_lo = (comp_size_minus_1 & 0xFF) as u8;

        // Header: control + 2 uncomp + 2 comp + optional props, then payload.
        let header_len = 5 + has_props as usize;
        self.pending.reserve(header_len + compressed.len());
        self.pending.push(control);
        self.pending.push(uncomp_mid);
        self.pending.push(uncomp_lo);
        self.pending.push(comp_hi);
        self.pending.push(comp_lo);
        if has_props {
            self.pending.push(LZMA2_PROPS_BYTE);
        }
        self.pending.extend_from_slice(compressed);
        self.pending_idx = 0;
        self.compressed_payload_bytes += (header_len + compressed.len()) as u64;
    }

    /// Stage an LZMA2 uncompressed chunk: control `0x01` (dict reset) for the
    /// first chunk, `0x02` (no reset, dictionary continues) otherwise. Used as
    /// the fallback when compression would expand a chunk.
    fn stage_uncompressed_chunk(&mut self, data: &[u8], reset_dict: bool) {
        debug_assert!(!data.is_empty() && data.len() <= LZMA2_CHUNK_MAX);
        let control: u8 = if reset_dict { 0x01 } else { 0x02 };
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

impl RawEncoder for Encoder {
    fn raw_encode(&mut self, input: &[u8], output: &mut [u8]) -> Result<RawProgress, Error> {
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
                        return Ok(RawProgress {
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
                        return Ok(RawProgress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                }
                EncPhase::Body => {
                    // Feed input into the bounded-memory streaming LZMA2 encoder
                    // and frame any chunks it emits, draining them to the caller
                    // as we go. The whole input is never accumulated — the
                    // dictionary is a sliding `~dict_size` window inside the
                    // stream encoder. If a previous pass staged chunk bytes,
                    // drain those first.
                    if self.pending_idx < self.pending.len() {
                        self.phase = EncPhase::DrainPending;
                    } else if consumed < input.len() {
                        // Push a bounded slice so `staged_input` stays small.
                        let take = (input.len() - consumed).min(LZMA2_CHUNK_MAX);
                        let slice = &input[consumed..consumed + take];
                        self.staged_input.extend_from_slice(slice);
                        let chunks = self.stream().push(slice);
                        consumed += take;
                        if !chunks.is_empty() {
                            self.stage_chunks(chunks);
                        }
                        // Drain whatever was staged before consuming more input.
                        if self.pending_idx < self.pending.len() {
                            self.phase = EncPhase::DrainPending;
                        }
                    } else {
                        return Ok(RawProgress {
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
                        return Ok(RawProgress {
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
                    return Ok(RawProgress {
                        consumed,
                        written,
                        done: false,
                    });
                }
            }

            if consumed == init_c && written == init_w && self.phase == init_phase {
                return Ok(RawProgress {
                    consumed,
                    written,
                    done: false,
                });
            }
        }
    }

    fn raw_finish(&mut self, output: &mut [u8]) -> Result<RawProgress, Error> {
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
                        return Ok(RawProgress {
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
                        return Ok(RawProgress {
                            consumed: 0,
                            written,
                            done: false,
                        });
                    }
                }
                EncPhase::Body => {
                    if self.pending_idx < self.pending.len() {
                        // Drain bytes staged in a prior pass first.
                        self.phase = EncPhase::DrainPending;
                    } else {
                        // Flush the remaining buffered bytes as the final
                        // chunk(s) from the bounded-memory stream encoder (once),
                        // then frame them. Memory stays `O(dict_size)`.
                        if self.stream.is_some() && !self.stream_finished {
                            let chunks = self.stream().finish();
                            self.stream_finished = true;
                            self.stage_chunks(chunks);
                        }
                        if self.pending_idx < self.pending.len() {
                            self.phase = EncPhase::DrainPending;
                        } else {
                            // No more chunk bytes. Move to the block trailer in
                            // this same iteration so the loop makes progress
                            // even when `finish` produced nothing.
                            self.stage_block_trailer();
                            self.phase = EncPhase::BlockTrailer;
                        }
                    }
                }
                EncPhase::DrainPending => {
                    if self.drain_pending(output, &mut written) {
                        // After draining a flushed chunk, see whether the
                        // body has more buffered or we're really done.
                        self.phase = EncPhase::Body;
                    } else {
                        return Ok(RawProgress {
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
                        return Ok(RawProgress {
                            consumed: 0,
                            written,
                            done: false,
                        });
                    }
                }
                EncPhase::Tail => {
                    if self.drain_pending(output, &mut written) {
                        self.phase = EncPhase::Done;
                        return Ok(RawProgress {
                            consumed: 0,
                            written,
                            done: true,
                        });
                    }
                    return Ok(RawProgress {
                        consumed: 0,
                        written,
                        done: false,
                    });
                }
                EncPhase::Done => {
                    return Ok(RawProgress {
                        consumed: 0,
                        written,
                        done: true,
                    });
                }
            }

            if written == init_w && self.phase == init_phase {
                // No progress and no phase change — bail out.
                if matches!(self.phase, EncPhase::Done) {
                    return Ok(RawProgress {
                        consumed: 0,
                        written,
                        done: true,
                    });
                }
                return Ok(RawProgress {
                    consumed: 0,
                    written,
                    done: false,
                });
            }
        }
    }

    /// Emit every byte given so far as complete LZMA2 chunks inside the
    /// still-open Block, so a decoder fed the bytes produced so far outputs
    /// all of it (it only waits for the Block trailer, Index and Footer to
    /// *verify* the data, and decoders, ours and liblzma's, stream chunk
    /// contents out as they decode them).
    ///
    /// [`Flush::Full`] additionally starts a new LZMA2 dictionary: the next
    /// chunk is a dictionary-reset chunk, so nothing after the flush
    /// references data before it. Everything stays within one xz Block.
    fn raw_flush(&mut self, output: &mut [u8], mode: Flush) -> Result<RawProgress, Error> {
        let mut written = 0usize;
        loop {
            match self.phase {
                EncPhase::StreamHeader | EncPhase::BlockHeader => {
                    if self.stream.is_none() {
                        // No input yet: nothing to make decodable.
                        return Ok(RawProgress {
                            consumed: 0,
                            written,
                            done: true,
                        });
                    }
                    // Unreachable in practice (input implies the headers were
                    // drained by `encode`), but drain them the same way.
                    if !self.drain_pending(output, &mut written) {
                        return Ok(RawProgress {
                            consumed: 0,
                            written,
                            done: false,
                        });
                    }
                    if self.phase == EncPhase::StreamHeader {
                        self.pending.extend_from_slice(&build_block_header());
                        self.pending_idx = 0;
                        self.phase = EncPhase::BlockHeader;
                    } else {
                        self.phase = EncPhase::Body;
                    }
                }
                EncPhase::Body => {
                    if self.pending_idx < self.pending.len() {
                        self.phase = EncPhase::DrainPending;
                        continue;
                    }
                    // Encode whatever the stream encoder still buffers. Once it
                    // has been drained this is a no-op, which ends the loop.
                    if let Some(stream) = self.stream.as_mut() {
                        let chunks = stream.flush();
                        if mode == Flush::Full {
                            stream.reset_dict();
                        }
                        self.stage_chunks(chunks);
                    }
                    if self.pending_idx < self.pending.len() {
                        self.phase = EncPhase::DrainPending;
                    } else {
                        return Ok(RawProgress {
                            consumed: 0,
                            written,
                            done: true,
                        });
                    }
                }
                EncPhase::DrainPending => {
                    if !self.drain_pending(output, &mut written) {
                        return Ok(RawProgress {
                            consumed: 0,
                            written,
                            done: false,
                        });
                    }
                    self.phase = EncPhase::Body;
                }
                EncPhase::BlockTrailer | EncPhase::Tail | EncPhase::Done => {
                    // `finish` has started: the stream is being closed and
                    // everything is already on its way out.
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
        // Preserve the configured match-finder tuning across reset, per the
        // trait contract — only the streaming bookkeeping is wiped.
        let params = self.enc_params;
        let header = build_stream_header();
        let mut pending = Vec::with_capacity(12);
        pending.extend_from_slice(&header);
        *self = Self {
            phase: EncPhase::StreamHeader,
            pending,
            pending_idx: 0,
            stream: None,
            staged_input: Vec::new(),
            stream_finished: false,
            check: Crc32::new(),
            uncompressed_total: 0,
            compressed_payload_bytes: 0,
            block_header_len: build_block_header().len() as u64,
            enc_params: params,
        };
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
    /// Buffering the remaining bytes of a compressed-LZMA2 chunk header
    /// (4 or 5 more bytes after the control byte).
    Lzma2CompHeader,
    /// Buffering the compressed payload for the current chunk.
    Lzma2CompBuffer,
    /// Streaming the decoded chunk bytes out to the caller.
    Lzma2CompDrain,
    /// After the LZMA2 end marker: skip 0..=3 padding zeros and read the
    /// 4-byte Check.
    BlockPadding,
    BlockCheck,
    /// Index: index indicator already consumed in BlockOrIndex. We now
    /// accumulate the rest of the index in a buffer (it's typically tiny).
    Index,
    /// Reading the Stream Footer (12 bytes).
    StreamFooter,
    /// A Stream ended. Like `xz -d`, Stream Padding (zero bytes, a multiple
    /// of four in all) and further concatenated Streams may follow; the
    /// next non-zero bytes decide between another Stream Header and `Done`
    /// (anything else is not xz data and is left to the caller).
    StreamPadding,
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

    /// Running Block Check over the uncompressed bytes of the block, of
    /// the kind the Stream Header's check ID selects.
    check: BlockCheck,

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

    // ── compressed-LZMA2 chunk state ──────────────────────────────────
    /// LZMA2 dictionary size derived from the Block Header's filter
    /// properties byte. Set when a Block Header is parsed.
    lzma2_dict_size: u32,
    /// Lazily-instantiated LZMA core, persists across chunks subject to
    /// reset bits in each chunk's control byte. Allocated on first
    /// compressed chunk and dropped when the block ends.
    lzma_core: Option<Box<LzmaCore>>,
    /// True until the first chunk of a block is parsed. The LZMA2 spec
    /// requires the first chunk of any block to be a "full reset" chunk
    /// (control byte `0xE0..=0xFF` for compressed, or `0x01` for
    /// uncompressed); reject any other first chunk.
    expecting_block_first_chunk: bool,
    /// Control byte of the in-flight compressed chunk.
    comp_ctrl: u8,
    /// Uncompressed size of the in-flight chunk (1..=65_536 for
    /// uncompressed chunks, 1..=2_097_152 for compressed).
    comp_uncomp_size: u32,
    /// Compressed size of the in-flight chunk (1..=65_536).
    comp_size: u32,
    /// Buffer for the compressed payload of the current chunk.
    comp_buf: Vec<u8>,
    /// Decoded output of the current compressed chunk, drained byte-by-byte.
    comp_decoded: Vec<u8>,
    /// Read cursor within `comp_decoded` during streaming drain.
    comp_decoded_pos: usize,
    /// Properties byte from the most recent reset chunk; only valid when
    /// `lzma_core` is `Some`. Used to detect whether `replace_props` is
    /// required on subsequent reset chunks.
    last_props: u8,

    /// The current Block's Delta/BCJ filters, undone on the LZMA2 output
    /// before it reaches the caller; `None` for a plain LZMA2 Block. When
    /// set, all of the Block's output goes through its buffer.
    filters: Option<FilterChain>,

    /// Stream Padding bytes seen since the last Stream Footer, modulo 4.
    stream_padding: u8,
    /// Set by `finish`: no more input will arrive, so whatever follows the
    /// last Stream (nothing, or a lone partial magic) settles the end.
    finishing: bool,

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
            check: BlockCheck::Unverified,
            blocks: Vec::new(),
            index_buf: Vec::new(),
            index_records_remaining: 0,
            index_records_total: 0,
            index_pos: 0,
            lzma2_dict_size: 0,
            lzma_core: None,
            expecting_block_first_chunk: false,
            comp_ctrl: 0,
            comp_uncomp_size: 0,
            comp_size: 0,
            comp_buf: Vec::new(),
            comp_decoded: Vec::new(),
            comp_decoded_pos: 0,
            last_props: 0,
            filters: None,
            stream_padding: 0,
            finishing: false,
            poisoned: false,
        }
    }

    /// Feed raw uncompressed-chunk bytes into the LZMA2 dictionary so a later
    /// dictionary-continuing compressed chunk can reference them. Creates the
    /// `lzma_core` on first use (canonical default props; the next compressed
    /// chunk's reset bits replace them) sized to the block's dictionary.
    fn feed_uncompressed_dict(&mut self, src: &[u8]) {
        if self.lzma_core.is_none() {
            // Props are irrelevant for plain dict population; use the canonical
            // default (lc=3, lp=0, pb=2). `parse` cannot fail for this byte.
            let props = Lzma2Props::parse(LZMA2_PROPS_BYTE).unwrap_or(Lzma2Props {
                lc: 3,
                lp: 0,
                pb: 2,
            });
            let dict_size = (self.lzma2_dict_size as usize).clamp(4096, 128 * 1024 * 1024);
            self.lzma_core = Some(Box::new(LzmaCore::new(props, dict_size)));
            self.last_props = LZMA2_PROPS_BYTE;
        }
        if let Some(core) = self.lzma_core.as_mut() {
            core.append_literals(src);
        }
    }

    /// Hand the filter chain's final bytes to `output`, updating the Block
    /// Check and size. Returns `false` while some are left (output full).
    fn drain_filtered(&mut self, output: &mut [u8], written: &mut usize) -> bool {
        let Some(chain) = self.filters.as_mut() else {
            return true;
        };
        let ready = chain.ready();
        let take = ready.len().min(output.len() - *written);
        output[*written..*written + take].copy_from_slice(&ready[..take]);
        self.check.update(&ready[..take]);
        chain.consume(take);
        self.block_uncompressed_seen += take as u64;
        *written += take;
        chain.ready().is_empty()
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
        // CRC32 (0x01), CRC64 (0x04) and SHA-256 (0x0A) are verified. The
        // reserved IDs still define the Check field's size (spec §2.1.1.2),
        // so, like liblzma by default, accept them and skip the field
        // unverified.
        self.check_id = check_id;

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
        check_size_for(self.check_id)
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
        // Filter Flags: `(id varint, props size varint, props)` per filter,
        // in encode order. Only LZMA2 may (and must) be last; the others
        // are the Delta/BCJ filters `filters` undoes after it.
        let mut chain: [(u64, &[u8]); 3] = [(0, &[]); 3];
        let mut chain_len = 0;
        let mut lzma2_props: &[u8] = &[];
        for i in 0..num_filters {
            let Some(id) = varint_decode(&self.scratch[..body_end], &mut cur)? else {
                return Err(self.poison(Error::Corrupt));
            };
            let Some(size) = varint_decode(&self.scratch[..body_end], &mut cur)? else {
                return Err(self.poison(Error::Corrupt));
            };
            if size > (body_end - cur) as u64 {
                return Err(self.poison(Error::Corrupt));
            }
            let props = &self.scratch[cur..cur + size as usize];
            cur += size as usize;
            if i + 1 < num_filters {
                if id == FILTER_ID_LZMA2 as u64 {
                    return Err(self.poison(Error::Unsupported));
                }
                chain[chain_len] = (id, props);
                chain_len += 1;
            } else if id == FILTER_ID_LZMA2 as u64 {
                lzma2_props = props;
            } else {
                return Err(self.poison(Error::Unsupported));
            }
        }
        let filters = if chain_len > 0 {
            Some(FilterChain::new(&chain[..chain_len]))
        } else {
            None
        };
        let [dict_flag] = *lzma2_props else {
            return Err(self.poison(Error::Unsupported));
        };
        self.filters = match filters.transpose() {
            Ok(f) => f,
            Err(e) => return Err(self.poison(e)),
        };
        if dict_flag & 0xC0 != 0 {
            return Err(self.poison(Error::Unsupported));
        }
        // Compute and store the LZMA2 dictionary size for the compressed
        // chunk decoder. `lzma2_dict_size` already validates the flag's
        // range (only 0..=40 are legal).
        match lzma2_dict_size(dict_flag) {
            Ok(v) => self.lzma2_dict_size = v,
            Err(e) => return Err(self.poison(e)),
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

impl RawDecoder for Decoder {
    fn raw_decode(&mut self, input: &[u8], output: &mut [u8]) -> Result<RawProgress, Error> {
        if self.poisoned {
            return Err(Error::Corrupt);
        }
        let mut consumed = 0usize;
        let mut written = 0usize;

        loop {
            let init_c = consumed;
            let init_w = written;
            let init_phase = self.phase;

            // Filtered Block output goes out before anything else, so every
            // phase below runs with the chain's final bytes all handed over
            // (in particular the Block Check covers all of them).
            if !self.drain_filtered(output, &mut written) {
                return Ok(RawProgress {
                    consumed,
                    written,
                    done: false,
                });
            }

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
                        return Ok(RawProgress {
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
                            self.check = BlockCheck::new(self.check_id);
                            self.lzma_core = None;
                            self.expecting_block_first_chunk = true;
                            self.phase = DecPhase::BlockHeader;
                        }
                    } else {
                        return Ok(RawProgress {
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
                        return Ok(RawProgress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                }
                DecPhase::Lzma2Control => {
                    // We need either 1 byte (end marker), 3 bytes
                    // (uncompressed chunk header), or 5/6 bytes (compressed
                    // chunk header, with optional 1-byte properties).
                    if self.scratch.is_empty() {
                        self.scratch_want = 1;
                        if !self.fill_scratch(input, &mut consumed) {
                            return Ok(RawProgress {
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
                        // The Block's data is complete: finalise the filters'
                        // tails (drained before the Check is read).
                        if let Some(chain) = self.filters.as_mut()
                            && let Err(e) = chain.finish()
                        {
                            return Err(self.poison(e));
                        }
                        // Free the (potentially MiB-sized) compressed-chunk
                        // working buffers now that the block has ended.
                        self.lzma_core = None;
                        self.comp_buf = Vec::new();
                        self.comp_decoded = Vec::new();
                        self.phase = DecPhase::BlockPadding;
                    } else if control == 0x01 || control == 0x02 {
                        // Uncompressed chunk. First chunk in a block must
                        // be a dictionary-reset chunk; for uncompressed
                        // that means 0x01 specifically.
                        if self.expecting_block_first_chunk && control != 0x01 {
                            return Err(self.poison(Error::Corrupt));
                        }
                        // 0x01 also resets the LZ dictionary in any
                        // straddling compressed state.
                        if control == 0x01 {
                            self.lzma_core = None;
                        }
                        self.expecting_block_first_chunk = false;
                        self.scratch_want = 3;
                        if !self.fill_scratch(input, &mut consumed) {
                            return Ok(RawProgress {
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
                        // Compressed LZMA-coded chunk. Continue parsing
                        // the remaining header bytes in the next phase.
                        // First chunk in a block must perform a full dict
                        // reset, i.e. control byte in `0xE0..=0xFF`.
                        if self.expecting_block_first_chunk && control < 0xE0 {
                            return Err(self.poison(Error::Corrupt));
                        }
                        self.comp_ctrl = control;
                        // Need 5 more bytes (uncomp-mid, uncomp-lo, comp-hi,
                        // comp-lo) plus 1 properties byte when bit 6 of the
                        // control byte requires it.
                        let needs_props = (control & 0x40) != 0; // bit 6 set
                        self.scratch_want = if needs_props { 6 } else { 5 };
                        self.phase = DecPhase::Lzma2CompHeader;
                    } else {
                        return Err(self.poison(Error::Corrupt));
                    }
                }
                DecPhase::Lzma2CompHeader => {
                    if !self.fill_scratch(input, &mut consumed) {
                        return Ok(RawProgress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                    // Layout of self.scratch:
                    //   [0]   = control byte (top 5 bits of uncomp_size-1 in
                    //           bits 0-4)
                    //   [1-2] = remaining 16 bits of uncomp_size-1 (big-endian)
                    //   [3-4] = comp_size-1 (big-endian, 16 bits)
                    //   [5]?  = properties (if bit 6 of control set)
                    let control = self.scratch[0];
                    let needs_props = (control & 0x40) != 0;
                    let header_len = self.scratch.len();
                    let uncomp_top = (control & 0x1F) as u32;
                    let uncomp_mid = self.scratch[1] as u32;
                    let uncomp_lo = self.scratch[2] as u32;
                    let uncomp_size = ((uncomp_top << 16) | (uncomp_mid << 8) | uncomp_lo) + 1;
                    let comp_hi = self.scratch[3] as u32;
                    let comp_lo = self.scratch[4] as u32;
                    let comp_size = ((comp_hi << 8) | comp_lo) + 1;
                    self.comp_uncomp_size = uncomp_size;
                    self.comp_size = comp_size;
                    self.block_compressed_seen += header_len as u64;

                    // Apply reset semantics. Bits 5-6 of control:
                    //   11 → dict reset + props reset + state reset (needs
                    //         properties byte and full re-init).
                    //   10 → props reset + state reset (needs properties
                    //         byte; dict carries over).
                    //   01 → state reset (no new properties; dict carries).
                    //   00 → continuation (no resets).
                    let reset_bits = (control >> 5) & 0x03;
                    if reset_bits == 0b11 {
                        // Full reset: equivalent to a fresh `LzmaCore`.
                        // Reuse the existing instance — including its
                        // (up to 4 MiB) dictionary allocation — when the
                        // requested dictionary size matches, which is the
                        // common case for streams produced by this crate
                        // (every chunk is a full-reset chunk against a
                        // fixed block dictionary).
                        let props_byte = self.scratch[5];
                        let props = match Lzma2Props::parse(props_byte) {
                            Ok(p) => p,
                            Err(e) => return Err(self.poison(e)),
                        };
                        let dict_size = (self.lzma2_dict_size as usize).max(4096);
                        // Cap at 128 MiB to bound memory; legitimate xz
                        // outputs almost never need more than 64 MiB.
                        let dict_size = dict_size.min(128 * 1024 * 1024);
                        match self.lzma_core.as_mut() {
                            Some(core) if core.dict_capacity() == dict_size.max(1) => {
                                core.reset_full(props);
                            }
                            _ => {
                                self.lzma_core = Some(Box::new(LzmaCore::new(props, dict_size)));
                            }
                        }
                        self.last_props = props_byte;
                    } else if reset_bits == 0b10 {
                        // Props reset + state reset, dict carries over.
                        let props_byte = self.scratch[5];
                        let props = match Lzma2Props::parse(props_byte) {
                            Ok(p) => p,
                            Err(e) => return Err(self.poison(e)),
                        };
                        if self.lzma_core.is_none() {
                            // Must have had a prior full-reset chunk to
                            // carry a dict — but the first chunk in a block
                            // is required to be full-reset (we enforced
                            // that above), so this can only happen for
                            // a malformed stream that escaped that check.
                            return Err(self.poison(Error::Corrupt));
                        }
                        let core_ref = self.lzma_core.as_mut().unwrap();
                        core_ref.replace_props(props);
                        core_ref.reset_state();
                        self.last_props = props_byte;
                    } else if reset_bits == 0b01 {
                        // State reset only; properties and dict carry over.
                        // Sanity: bit 6 (`needs_props`) must be clear here.
                        let _ = needs_props;
                        if self.lzma_core.is_none() {
                            return Err(self.poison(Error::Corrupt));
                        }
                        self.lzma_core.as_mut().unwrap().reset_state();
                    } else {
                        // 00: continuation. The core must already exist.
                        if self.lzma_core.is_none() {
                            return Err(self.poison(Error::Corrupt));
                        }
                    }

                    self.expecting_block_first_chunk = false;
                    self.scratch.clear();
                    self.comp_buf.clear();
                    self.scratch_want = 0;
                    self.phase = DecPhase::Lzma2CompBuffer;
                }
                DecPhase::Lzma2CompBuffer => {
                    // Pull up to comp_size compressed bytes into comp_buf.
                    let need = self.comp_size as usize - self.comp_buf.len();
                    let take = need.min(input.len() - consumed);
                    if take > 0 {
                        self.comp_buf
                            .extend_from_slice(&input[consumed..consumed + take]);
                        consumed += take;
                    }
                    if self.comp_buf.len() < self.comp_size as usize {
                        return Ok(RawProgress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                    self.block_compressed_seen += self.comp_size as u64;
                    // Decode the entire chunk into comp_decoded.
                    self.comp_decoded.clear();
                    self.comp_decoded
                        .resize(self.comp_uncomp_size as usize, 0u8);
                    if self.lzma_core.is_none() {
                        return Err(self.poison(Error::Corrupt));
                    }
                    let init_res = self.lzma_core.as_mut().unwrap().init_range(&self.comp_buf);
                    if let Err(e) = init_res {
                        return Err(self.poison(e));
                    }
                    let dec_res = self
                        .lzma_core
                        .as_mut()
                        .unwrap()
                        .decode_chunk(&self.comp_buf, &mut self.comp_decoded);
                    if let Err(e) = dec_res {
                        return Err(self.poison(e));
                    }
                    self.comp_decoded_pos = 0;
                    self.phase = DecPhase::Lzma2CompDrain;
                }
                DecPhase::Lzma2CompDrain => {
                    let total = self.comp_decoded.len();
                    if let Some(chain) = self.filters.as_mut() {
                        // Through the filters; the top of the loop drains.
                        if let Err(e) = chain.push(&self.comp_decoded[self.comp_decoded_pos..]) {
                            return Err(self.poison(e));
                        }
                        self.comp_decoded_pos = total;
                    }
                    while self.comp_decoded_pos < total && written < output.len() {
                        let take = (total - self.comp_decoded_pos).min(output.len() - written);
                        let src =
                            &self.comp_decoded[self.comp_decoded_pos..self.comp_decoded_pos + take];
                        output[written..written + take].copy_from_slice(src);
                        self.check.update(src);
                        self.block_uncompressed_seen += take as u64;
                        self.comp_decoded_pos += take;
                        written += take;
                    }
                    if self.comp_decoded_pos >= total {
                        // Chunk drained; back to control byte parsing.
                        self.scratch.clear();
                        self.scratch_want = 1;
                        self.phase = DecPhase::Lzma2Control;
                    } else {
                        return Ok(RawProgress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                }
                DecPhase::Lzma2Data => {
                    if self.filters.is_some() && self.chunk_remaining > 0 && consumed < input.len()
                    {
                        // Through the filters; the top of the loop drains.
                        // A chunk is at most 64 KiB, so this stays bounded.
                        let take = self.chunk_remaining.min(input.len() - consumed);
                        let src = &input[consumed..consumed + take];
                        self.feed_uncompressed_dict(src);
                        if let Some(chain) = self.filters.as_mut()
                            && let Err(e) = chain.push(src)
                        {
                            return Err(self.poison(e));
                        }
                        self.block_compressed_seen += take as u64;
                        self.chunk_remaining -= take;
                        consumed += take;
                    }
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
                        // Feed the raw bytes into the LZ dictionary so a later
                        // dictionary-continuing compressed chunk (`0xC0`) can
                        // back-reference them. Lazily create the core (with the
                        // block's dict size and the canonical default props —
                        // props don't affect plain dict population, and the
                        // next compressed chunk resets them) when none exists
                        // yet, e.g. when the block opens with an uncompressed
                        // chunk.
                        self.feed_uncompressed_dict(src);
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
                        return Ok(RawProgress {
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
                        return Ok(RawProgress {
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
                        self.filters = None;
                        self.scratch.clear();
                        self.scratch_want = 1;
                        self.phase = DecPhase::BlockOrIndex;
                    } else if self.fill_scratch(input, &mut consumed) {
                        if !self.check.matches(&self.scratch) {
                            return Err(self.poison(Error::ChecksumMismatch));
                        }
                        let unpadded_size = self.block_header_size_seen
                            + self.block_compressed_seen
                            + self.check_size() as u64;
                        self.blocks
                            .push((unpadded_size, self.block_uncompressed_seen));
                        self.filters = None;
                        self.scratch.clear();
                        self.scratch_want = 1;
                        self.phase = DecPhase::BlockOrIndex;
                    } else {
                        return Ok(RawProgress {
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
                                    // NOTE: Do NOT pre-reserve based on the raw
                                    // attacker-controlled NumRecords `n` (up to
                                    // ~2^63): that would panic with "capacity
                                    // overflow" or trigger an OOM-aborting
                                    // allocation before any validation. The
                                    // `blocks` vec is built from actually-decoded
                                    // blocks and cross-checked against
                                    // `index_records_total` below.
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
                            // Any bytes slurped *past* the index belong to the
                            // Stream Footer and whatever follows the stream.
                            // They all arrived in this call (an earlier call
                            // would have completed the index), so hand them
                            // back unconsumed; the footer phase re-reads them
                            // and anything after the footer stays the
                            // caller's.
                            let extra = self.index_buf.len() - need_total;
                            consumed -= extra;
                            self.index_buf.truncate(need_total);
                            self.scratch.clear();
                            self.scratch_want = 12;
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
                        if s[8] != STREAM_FLAGS[0] || s[9] != self.check_id {
                            return Err(self.poison(Error::Corrupt));
                        }
                        if s[10] != FOOTER_MAGIC[0] || s[11] != FOOTER_MAGIC[1] {
                            return Err(self.poison(Error::BadHeader));
                        }
                        self.scratch.clear();
                        self.stream_padding = 0;
                        self.phase = DecPhase::StreamPadding;
                    } else {
                        return Ok(RawProgress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                }
                DecPhase::StreamPadding => {
                    // `scratch` holds the start of a following Stream Header's
                    // magic when an earlier call ended inside it; padding can
                    // only come before that.
                    if self.scratch.is_empty() {
                        while consumed < input.len() && input[consumed] == 0x00 {
                            self.stream_padding = (self.stream_padding + 1) % 4;
                            consumed += 1;
                        }
                    }
                    if consumed >= input.len() {
                        if !self.finishing {
                            // Another Stream or more padding may still come;
                            // `finish` settles it.
                            return Ok(RawProgress {
                                consumed,
                                written,
                                done: false,
                            });
                        }
                        if self.stream_padding != 0 {
                            return Err(self.poison(Error::Corrupt));
                        }
                        // Nothing (or a partial magic, which is not a
                        // Stream) follows: the Streams are over.
                        self.scratch.clear();
                        self.phase = DecPhase::Done;
                        continue;
                    }
                    // A non-zero byte ends the padding, which the spec
                    // requires to be a multiple of four bytes.
                    if self.stream_padding != 0 {
                        return Err(self.poison(Error::Corrupt));
                    }
                    let mut i = consumed;
                    while self.scratch.len() < STREAM_MAGIC.len() && i < input.len() {
                        if input[i] != STREAM_MAGIC[self.scratch.len()] {
                            break;
                        }
                        self.scratch.push(input[i]);
                        i += 1;
                    }
                    if self.scratch.len() == STREAM_MAGIC.len() {
                        // Another Stream: parse its header; the per-Stream
                        // state (blocks for the Index cross-check, check ID)
                        // starts afresh.
                        consumed = i;
                        self.blocks.clear();
                        self.scratch_want = 12;
                        self.phase = DecPhase::StreamHeader;
                    } else if i == input.len() {
                        // So far a magic prefix; wait for the rest.
                        consumed = i;
                        return Ok(RawProgress {
                            consumed,
                            written,
                            done: false,
                        });
                    } else {
                        // Not xz data: the Streams are over. Hand back the
                        // bytes this call matched against the magic (an
                        // earlier call's had already been buffered), so the
                        // caller sees where the xz data stops.
                        self.scratch.clear();
                        self.phase = DecPhase::Done;
                        continue;
                    }
                }
                DecPhase::Done => {
                    // Terminal: the Streams are over and the bytes after them
                    // (if any) are not ours. Report completion so the bridge
                    // yields StreamEnd, leaving those bytes unconsumed.
                    // Reporting `false` left a caller that hands over trailing
                    // bytes getting `OutputFull` with nothing consumed and
                    // nothing written, spinning on unchanged state.
                    return Ok(RawProgress {
                        consumed,
                        written,
                        done: true,
                    });
                }
            }

            if consumed == init_c && written == init_w && self.phase == init_phase {
                return Ok(RawProgress {
                    consumed,
                    written,
                    done: false,
                });
            }
        }
    }

    fn raw_finish(&mut self, output: &mut [u8]) -> Result<RawProgress, Error> {
        if self.poisoned {
            return Err(Error::Corrupt);
        }
        self.finishing = true;
        let empty: [u8; 0] = [];
        let p = self.raw_decode(&empty, output)?;
        if matches!(self.phase, DecPhase::Done) {
            Ok(RawProgress {
                consumed: 0,
                written: p.written,
                done: true,
            })
        } else if output.is_empty() || p.written > 0 {
            // Decoded bytes may still be waiting (a whole LZMA2 chunk can
            // be up to 2 MiB): `finish` must stay drainable, so report "not
            // done" and let the caller drain and call again. Failing here
            // threw away bytes already written to `output` this call; the
            // truncation is reported by the first call with nothing left
            // to hand over.
            Ok(RawProgress {
                consumed: 0,
                written: p.written,
                done: false,
            })
        } else {
            // Not done, nothing left to hand over, and no input to advance
            // with: the stream is truncated.
            Err(self.poison(Error::UnexpectedEnd))
        }
    }

    fn raw_reset(&mut self) {
        *self = Self::new();
    }
}
