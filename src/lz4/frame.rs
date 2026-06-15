//! Canonical LZ4 Frame format (`.lz4`) encoder + decoder.
//!
//! Reference: <https://github.com/lz4/lz4/blob/dev/doc/lz4_Frame_format.md>.
//!
//! ## Layout
//!
//! ```text
//! Frame   := Magic ‖ FrameDescriptor ‖ Block* ‖ EndMark ‖ ContentChecksum?
//! Magic   := 0x184D2204  (u32 LE)
//! FrameDescriptor := FLG ‖ BD ‖ ContentSize? ‖ DictID? ‖ HC
//!
//! FLG: version(7-6=01) | B.Indep(5) | B.Checksum(4)
//!      | C.Size(3) | C.Checksum(2) | Reserved(1=0) | DictID(0)
//! BD : Reserved(7=0) | MaxSize(6-4: 4=64K,5=256K,6=1M,7=4M) | Reserved(3-0=0)
//! HC : high byte of xxHash32(FLG ‖ BD ‖ ContentSize? ‖ DictID?)
//!
//! Block:
//!   BlockSize:    u32 LE — bit 31 = uncompressed flag, bits 30-0 = length
//!   Data:         BlockSize bytes (raw if flag set, else LZ4-compressed)
//!   BlockChecksum: u32 LE (only if FLG.B.Checksum = 1) — xxHash32(Data)
//!
//! EndMark: BlockSize == 0
//! ContentChecksum: u32 LE (only if FLG.C.Checksum = 1) — xxHash32 of raw content
//! ```
//!
//! The encoder buffers `block_max_size` bytes of input, compresses each
//! block via [`super::block::encode_block`], and emits each block with a
//! 4-byte LZ4-frame block header. If the compressed result is larger than
//! the raw input, the block is emitted uncompressed with the high bit of
//! the size set.
//!
//! ## Linked vs independent blocks
//!
//! When `block_independence = false` (the LZ4 CLI default and ours), the
//! decoder must keep up to 64 KiB of the previously-decoded payload
//! available so the next block's back-references can address it. Our
//! encoder produces such references: it carries a sliding 64 KiB window of
//! the most recently emitted raw output and offers it to the block match
//! finder as a dictionary (see [`block::encode_block_level_dict`]), so a
//! match in one block can reference bytes that were emitted by previous
//! blocks. This is what gives linked mode its ratio edge over independent
//! blocks, whose match window is just the block's own ≤ 64 KiB.
//!
//! When `block_independence = true`, the window is never populated and each
//! block is compressed in isolation, decoding correctly on its own.

use alloc::vec::Vec;

use crate::error::Error;
use crate::traits::{Algorithm, RawDecoder, RawEncoder, RawProgress};

use super::block;

/// Frame magic number, little-endian: `0x184D2204`.
const MAGIC: u32 = 0x184D_2204;

/// High two bits of `FLG`: version (must be `01`).
const FLG_VERSION_MASK: u8 = 0b1100_0000;
const FLG_VERSION_BITS: u8 = 0b0100_0000;
const FLG_BLOCK_INDEP: u8 = 1 << 5;
const FLG_BLOCK_CHECKSUM: u8 = 1 << 4;
const FLG_CONTENT_SIZE: u8 = 1 << 3;
const FLG_CONTENT_CHECKSUM: u8 = 1 << 2;
const FLG_RESERVED: u8 = 1 << 1;
const FLG_DICT_ID: u8 = 1 << 0;

const BD_RESERVED_HIGH: u8 = 1 << 7;
const BD_RESERVED_LOW: u8 = 0b0000_1111;
const BD_BLOCK_MAX_SHIFT: u32 = 4;

/// Sliding-window size for linked-block back-references (64 KiB).
const WINDOW_SIZE: usize = 64 * 1024;

// ─── BlockMaxSize ─────────────────────────────────────────────────────────

/// Maximum uncompressed payload size of a single LZ4 frame block.
///
/// The four legal values (64 KiB, 256 KiB, 1 MiB, 4 MiB) match the
/// canonical `lz4` CLI's `-B4..=-B7`. 64 KiB matches `lz4 -c` with no
/// explicit `-B` flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BlockMaxSize {
    /// 64 KiB (BD value 4). The `lz4 -c` default.
    #[default]
    Max64KB,
    /// 256 KiB (BD value 5).
    Max256KB,
    /// 1 MiB (BD value 6).
    Max1MB,
    /// 4 MiB (BD value 7).
    Max4MB,
}

impl BlockMaxSize {
    /// On-the-wire BD value (4..=7).
    pub const fn bd_value(self) -> u8 {
        match self {
            BlockMaxSize::Max64KB => 4,
            BlockMaxSize::Max256KB => 5,
            BlockMaxSize::Max1MB => 6,
            BlockMaxSize::Max4MB => 7,
        }
    }

    /// Block size in bytes.
    pub const fn bytes(self) -> usize {
        match self {
            BlockMaxSize::Max64KB => 64 * 1024,
            BlockMaxSize::Max256KB => 256 * 1024,
            BlockMaxSize::Max1MB => 1024 * 1024,
            BlockMaxSize::Max4MB => 4 * 1024 * 1024,
        }
    }

    fn from_bd_value(v: u8) -> Result<Self, Error> {
        match v {
            4 => Ok(BlockMaxSize::Max64KB),
            5 => Ok(BlockMaxSize::Max256KB),
            6 => Ok(BlockMaxSize::Max1MB),
            7 => Ok(BlockMaxSize::Max4MB),
            _ => Err(Error::Unsupported),
        }
    }
}

// ─── Algorithm marker ─────────────────────────────────────────────────────

/// Zero-sized marker type implementing [`Algorithm`] for the canonical
/// LZ4 Frame format.
#[derive(Debug, Clone, Copy, Default)]
pub struct LZ4Frame;

/// Encoder configuration. The `Default` impl matches what `lz4 -c`
/// produces with no flags: 64 KiB linked blocks, no per-block checksum,
/// content checksum on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncoderConfig {
    /// Maximum size of one block's raw payload. Default: 64 KiB.
    pub block_max_size: BlockMaxSize,
    /// `true` = each block decodes independently. `false` (default)
    /// allows the decoder to back-reference into the previous block's
    /// data, slightly improving compression ratio at the cost of
    /// non-randomly-seekable output.
    pub block_independence: bool,
    /// `true` = append xxHash32 after each block's payload.
    pub block_checksum: bool,
    /// `true` (default) = append xxHash32 of the raw content at the
    /// frame end. Matches `lz4 -c`.
    pub content_checksum: bool,
    /// Block-compression level forwarded to
    /// [`block::encode_block_level`]. Low levels use the fast greedy parse;
    /// higher levels engage the HC hash-chain match finder with lazy matching
    /// for a better ratio. The emitted bitstream is a valid LZ4 block in every
    /// case. Default `0` (fast path, matching `lz4 -c`'s default speed).
    pub level: u8,
}

impl Default for EncoderConfig {
    fn default() -> Self {
        Self {
            block_max_size: BlockMaxSize::Max64KB,
            block_independence: false,
            block_checksum: false,
            content_checksum: true,
            level: 0,
        }
    }
}

/// Decoder configuration (no tunables yet — every flag is read from the
/// stream).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DecoderConfig;

impl Algorithm for LZ4Frame {
    const NAME: &'static str = "lz4-frame";
    type Encoder = Encoder;
    type Decoder = Decoder;
    type EncoderConfig = EncoderConfig;
    type DecoderConfig = DecoderConfig;

    fn encoder_with(c: EncoderConfig) -> Encoder {
        Encoder::with_config(c)
    }
    fn decoder_with(_: DecoderConfig) -> Decoder {
        Decoder::new()
    }
}

// ─── xxHash32 ─────────────────────────────────────────────────────────────

/// xxHash32 — incremental, seed-0 (the only seed LZ4 Frame uses).
///
/// Reference spec: <https://github.com/Cyan4973/xxHash/blob/dev/doc/xxhash_spec.md>.
#[derive(Clone, Copy)]
struct XxHash32 {
    total_len: u64,
    /// Mixed state — only used once `total_len >= 16`.
    v1: u32,
    v2: u32,
    v3: u32,
    v4: u32,
    /// Buffered tail bytes (length 0..16).
    buf: [u8; 16],
    buf_len: u8,
    /// Whether `v1..v4` have been initialised (i.e. we've seen >= 16 bytes).
    primed: bool,
}

const XXH_PRIME32_1: u32 = 0x9E37_79B1;
const XXH_PRIME32_2: u32 = 0x85EB_CA77;
const XXH_PRIME32_3: u32 = 0xC2B2_AE3D;
const XXH_PRIME32_4: u32 = 0x27D4_EB2F;
const XXH_PRIME32_5: u32 = 0x1656_67B1;

impl XxHash32 {
    fn new() -> Self {
        // Seed = 0 always. v1..v4 stay unused until the first 16 bytes
        // are buffered (or fed straight through).
        Self {
            total_len: 0,
            v1: 0,
            v2: 0,
            v3: 0,
            v4: 0,
            buf: [0; 16],
            buf_len: 0,
            primed: false,
        }
    }

    /// One 16-byte stripe: update the four running accumulators.
    #[inline]
    fn round(acc: u32, lane: u32) -> u32 {
        acc.wrapping_add(lane.wrapping_mul(XXH_PRIME32_2))
            .rotate_left(13)
            .wrapping_mul(XXH_PRIME32_1)
    }

    fn process_stripe(&mut self, s: &[u8; 16]) {
        if !self.primed {
            // Seed = 0; canonical init constants.
            self.v1 = XXH_PRIME32_1.wrapping_add(XXH_PRIME32_2);
            self.v2 = XXH_PRIME32_2;
            self.v3 = 0;
            self.v4 = 0u32.wrapping_sub(XXH_PRIME32_1);
            self.primed = true;
        }
        let lane = |i: usize| u32::from_le_bytes([s[i], s[i + 1], s[i + 2], s[i + 3]]);
        self.v1 = Self::round(self.v1, lane(0));
        self.v2 = Self::round(self.v2, lane(4));
        self.v3 = Self::round(self.v3, lane(8));
        self.v4 = Self::round(self.v4, lane(12));
    }

    fn update(&mut self, mut data: &[u8]) {
        self.total_len = self.total_len.wrapping_add(data.len() as u64);

        // Top up the tail buffer if it has bytes from a previous call.
        if self.buf_len > 0 {
            let need = 16 - self.buf_len as usize;
            let take = data.len().min(need);
            self.buf[self.buf_len as usize..self.buf_len as usize + take]
                .copy_from_slice(&data[..take]);
            self.buf_len += take as u8;
            data = &data[take..];
            if self.buf_len < 16 {
                return;
            }
            let stripe = self.buf;
            self.process_stripe(&stripe);
            self.buf_len = 0;
        }

        // Full 16-byte stripes.
        while data.len() >= 16 {
            let mut stripe = [0u8; 16];
            stripe.copy_from_slice(&data[..16]);
            self.process_stripe(&stripe);
            data = &data[16..];
        }

        // Tail.
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len() as u8;
        }
    }

    fn finish(self) -> u32 {
        let mut h: u32;
        if self.primed {
            h = self
                .v1
                .rotate_left(1)
                .wrapping_add(self.v2.rotate_left(7))
                .wrapping_add(self.v3.rotate_left(12))
                .wrapping_add(self.v4.rotate_left(18));
        } else {
            // Seed = 0; the spec's special case for < 16-byte inputs.
            h = XXH_PRIME32_5;
        }
        // Add total length (low 32 bits).
        h = h.wrapping_add(self.total_len as u32);

        // Consume the tail buffer 4 bytes at a time, then 1 byte at a time.
        let tail = &self.buf[..self.buf_len as usize];
        let mut i = 0;
        while i + 4 <= tail.len() {
            let lane = u32::from_le_bytes([tail[i], tail[i + 1], tail[i + 2], tail[i + 3]]);
            h = h
                .wrapping_add(lane.wrapping_mul(XXH_PRIME32_3))
                .rotate_left(17)
                .wrapping_mul(XXH_PRIME32_4);
            i += 4;
        }
        while i < tail.len() {
            h = h
                .wrapping_add((tail[i] as u32).wrapping_mul(XXH_PRIME32_5))
                .rotate_left(11)
                .wrapping_mul(XXH_PRIME32_1);
            i += 1;
        }

        // Avalanche.
        h ^= h >> 15;
        h = h.wrapping_mul(XXH_PRIME32_2);
        h ^= h >> 13;
        h = h.wrapping_mul(XXH_PRIME32_3);
        h ^= h >> 16;
        h
    }
}

/// One-shot xxHash32(data), seed = 0.
fn xxhash32(data: &[u8]) -> u32 {
    let mut h = XxHash32::new();
    h.update(data);
    h.finish()
}

// ─── Encoder ──────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq)]
enum EncPhase {
    /// Header bytes pending; nothing else has been emitted yet.
    Header,
    /// Accepting raw input into `raw`.
    Buffering,
    /// `staged` holds an encoded block (header + payload + checksum?)
    /// waiting to be drained.
    Flushing,
    /// `staged` holds the EndMark (and, if configured, content checksum).
    Terminating,
    /// All bytes emitted.
    Done,
}

/// Encoder for the canonical LZ4 Frame format.
pub struct Encoder {
    cfg: EncoderConfig,
    block_size: usize,
    raw: Vec<u8>,
    staged: Vec<u8>,
    staged_idx: usize,
    phase: EncPhase,
    /// xxHash32 over the entire raw content. Only used when
    /// `cfg.content_checksum`.
    content_hash: XxHash32,
    /// Sliding 64 KiB window of the most recently emitted *raw* output, used
    /// as a back-reference dictionary for the next block in linked-block mode
    /// (`cfg.block_independence == false`). Empty in independent mode.
    window: Vec<u8>,
}

impl Encoder {
    /// Construct with default config (matches `lz4 -c`).
    pub fn new() -> Self {
        Self::with_config(EncoderConfig::default())
    }

    /// Construct with an explicit config.
    pub fn with_config(cfg: EncoderConfig) -> Self {
        let bs = cfg.block_max_size.bytes();
        let window_cap = if cfg.block_independence {
            0
        } else {
            WINDOW_SIZE
        };
        let mut enc = Self {
            cfg,
            block_size: bs,
            raw: Vec::with_capacity(bs),
            staged: Vec::with_capacity(block::compress_bound(bs) + 16),
            staged_idx: 0,
            phase: EncPhase::Header,
            content_hash: XxHash32::new(),
            window: Vec::with_capacity(window_cap),
        };
        enc.build_header();
        enc
    }

    /// Append `bytes` (a block's raw payload) to the sliding back-reference
    /// window, keeping only the trailing [`WINDOW_SIZE`] bytes. No-op in
    /// independent mode.
    fn push_window(&mut self, bytes: &[u8]) {
        if self.cfg.block_independence {
            return;
        }
        if bytes.len() >= WINDOW_SIZE {
            self.window.clear();
            self.window
                .extend_from_slice(&bytes[bytes.len() - WINDOW_SIZE..]);
            return;
        }
        let combined = self.window.len() + bytes.len();
        if combined > WINDOW_SIZE {
            self.window.drain(..combined - WINDOW_SIZE);
        }
        self.window.extend_from_slice(bytes);
    }

    /// Stage the frame header (magic + FLG + BD + HC) in `staged`.
    fn build_header(&mut self) {
        self.staged.clear();
        self.staged.extend_from_slice(&MAGIC.to_le_bytes());

        let mut flg = FLG_VERSION_BITS;
        if self.cfg.block_independence {
            flg |= FLG_BLOCK_INDEP;
        }
        if self.cfg.block_checksum {
            flg |= FLG_BLOCK_CHECKSUM;
        }
        if self.cfg.content_checksum {
            flg |= FLG_CONTENT_CHECKSUM;
        }
        // FLG.C.Size = 0 (we don't write the content-size field — it
        // requires knowing the total length up front, which is
        // incompatible with streaming).
        // FLG.DictID = 0.
        let bd = self.cfg.block_max_size.bd_value() << BD_BLOCK_MAX_SHIFT;

        // HC = high byte of xxHash32(FLG ‖ BD).
        let descriptor = [flg, bd];
        let hc = (xxhash32(&descriptor) >> 8) as u8;

        self.staged.extend_from_slice(&descriptor);
        self.staged.push(hc);

        self.staged_idx = 0;
    }

    /// Compress whatever is in `raw` and stage the resulting block.
    fn build_block(&mut self) {
        debug_assert!(!self.raw.is_empty());

        // Update the running content checksum with the raw payload.
        if self.cfg.content_checksum {
            self.content_hash.update(&self.raw);
        }

        // Compress into a scratch buffer. In linked-block mode the previous
        // blocks' trailing output (`self.window`, ≤ 64 KiB) is offered as a
        // back-reference dictionary so matches can cross the block boundary.
        let mut compressed = Vec::with_capacity(block::compress_bound(self.raw.len()));
        block::encode_block_level_dict(&self.window, &self.raw, &mut compressed, self.cfg.level);

        // Slide the window forward with this block's raw payload, regardless of
        // whether we end up emitting it compressed or raw — the decoder's
        // window tracks decoded output either way.
        if !self.cfg.block_independence {
            let raw = core::mem::take(&mut self.raw);
            self.push_window(&raw);
            self.raw = raw;
        }

        self.staged.clear();
        // Choose the smaller of compressed / raw. The LZ4 Frame spec
        // says: if compressed >= raw, set the high bit of the size and
        // store the raw payload — saves an unnecessary decode step and
        // ensures the block never grows the output unnecessarily.
        let (payload_is_raw, payload): (bool, &[u8]) = if compressed.len() >= self.raw.len() {
            (true, &self.raw[..])
        } else {
            (false, &compressed[..])
        };

        let mut size_word = payload.len() as u32;
        // Bit 31 = uncompressed flag.
        if payload_is_raw {
            size_word |= 0x8000_0000;
        }
        self.staged.extend_from_slice(&size_word.to_le_bytes());
        self.staged.extend_from_slice(payload);

        if self.cfg.block_checksum {
            let h = xxhash32(payload);
            self.staged.extend_from_slice(&h.to_le_bytes());
        }

        self.raw.clear();
        self.staged_idx = 0;
        self.phase = EncPhase::Flushing;
    }

    /// Stage the EndMark and (optionally) content checksum.
    fn build_trailer(&mut self) {
        self.staged.clear();
        // EndMark: u32 LE 0.
        self.staged.extend_from_slice(&0u32.to_le_bytes());
        if self.cfg.content_checksum {
            // Take the hash by replacing it with a fresh one; we won't
            // need to update it again.
            let h = core::mem::replace(&mut self.content_hash, XxHash32::new()).finish();
            self.staged.extend_from_slice(&h.to_le_bytes());
        }
        self.staged_idx = 0;
        self.phase = EncPhase::Terminating;
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
    }

    fn staged_done(&self) -> bool {
        self.staged_idx == self.staged.len()
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
                    self.drain_staged(output, &mut written);
                    if !self.staged_done() {
                        return Ok(RawProgress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                    self.staged.clear();
                    self.staged_idx = 0;
                    self.phase = EncPhase::Buffering;
                }
                EncPhase::Flushing => {
                    self.drain_staged(output, &mut written);
                    if !self.staged_done() {
                        return Ok(RawProgress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                    self.staged.clear();
                    self.staged_idx = 0;
                    self.phase = EncPhase::Buffering;
                }
                EncPhase::Buffering => {
                    if consumed == input.len() {
                        return Ok(RawProgress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                    let room = self.block_size - self.raw.len();
                    let take = (input.len() - consumed).min(room);
                    self.raw
                        .extend_from_slice(&input[consumed..consumed + take]);
                    consumed += take;
                    if self.raw.len() == self.block_size {
                        self.build_block();
                    }
                }
                // `Terminating` / `Done` are only reachable after `finish`.
                EncPhase::Terminating | EncPhase::Done => {
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
                    self.drain_staged(output, &mut written);
                    if !self.staged_done() {
                        return Ok(RawProgress {
                            consumed: 0,
                            written,
                            done: false,
                        });
                    }
                    self.staged.clear();
                    self.staged_idx = 0;
                    self.phase = EncPhase::Buffering;
                }
                EncPhase::Buffering => {
                    if !self.raw.is_empty() {
                        self.build_block();
                    } else {
                        self.build_trailer();
                    }
                }
                EncPhase::Flushing => {
                    self.drain_staged(output, &mut written);
                    if !self.staged_done() {
                        return Ok(RawProgress {
                            consumed: 0,
                            written,
                            done: false,
                        });
                    }
                    self.staged.clear();
                    self.staged_idx = 0;
                    self.phase = EncPhase::Buffering;
                }
                EncPhase::Terminating => {
                    self.drain_staged(output, &mut written);
                    if !self.staged_done() {
                        return Ok(RawProgress {
                            consumed: 0,
                            written,
                            done: false,
                        });
                    }
                    self.staged.clear();
                    self.staged_idx = 0;
                    self.phase = EncPhase::Done;
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
        self.content_hash = XxHash32::new();
        self.window.clear();
        self.phase = EncPhase::Header;
        self.build_header();
    }
}

// ─── Decoder ──────────────────────────────────────────────────────────────

/// Cap on the raw payload size we accept from any block, regardless of
/// the BD value (which we validate against this too). 4 MiB is the
/// largest legal `BlockMaxSize`.
const MAX_BLOCK_BYTES: usize = 4 * 1024 * 1024;

/// Upper bound on a compressed block's wire length, including the small
/// overhead the LZ4 block format can add (`compress_bound`-style). We
/// reject declared sizes above this before allocating.
fn max_compressed_block(raw_max: usize) -> usize {
    // `compress_bound` covers worst-case literal expansion; the frame
    // format also allows uncompressed blocks with the raw payload, so
    // the on-the-wire length is at most max(compressed_bound, raw_max).
    block::compress_bound(raw_max).max(raw_max)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DecPhase {
    /// Reading the 4-byte magic.
    Magic,
    /// Reading FLG + BD.
    FlgBd,
    /// Reading optional ContentSize (8 bytes) and DictID (4 bytes), in
    /// that order. `desc_remaining` is how many bytes of those optional
    /// fields are still missing.
    DescriptorTail,
    /// Reading the 1-byte HC checksum.
    Hc,
    /// Reading the 4-byte block size word.
    BlockSize,
    /// Reading `expected_len` bytes of block data.
    BlockData,
    /// Reading the 4-byte block xxHash32 trailer (if FLG.B.Checksum=1).
    BlockChecksum,
    /// Decoding (or copying) the buffered block into `decoded`.
    Decode,
    /// Draining `decoded` to the caller's output.
    Draining,
    /// Reading the 4-byte content xxHash32 (if FLG.C.Checksum=1).
    ContentChecksum,
    /// Stream fully consumed.
    Done,
}

/// Decoder for the canonical LZ4 Frame format.
pub struct Decoder {
    phase: DecPhase,
    /// Generic small accumulator for the header fields (magic, FLG+BD,
    /// HC, block size, block checksum, content checksum). `accum_need`
    /// is the next field's target length.
    accum: [u8; 12],
    accum_len: u8,
    accum_need: u8,
    /// Parsed flag bits.
    flg: u8,
    bd: u8,
    /// Parsed optional descriptor fields (consumed but not retained).
    desc_remaining: u8,
    /// Bytes of FLG+BD+ContentSize+DictID, used to recompute HC. Capped
    /// at 14 bytes (2 + 8 + 4).
    descriptor: Vec<u8>,
    block_max: BlockMaxSize,
    block_independent: bool,
    block_checksum: bool,
    content_checksum: bool,
    /// Current block on-the-wire size (after stripping the high bit).
    cur_block_len: u32,
    /// `true` if the current block was emitted uncompressed in the wire.
    cur_block_uncompressed: bool,
    /// Compressed (or uncompressed) buffer for the current block.
    compressed: Vec<u8>,
    /// Decoded payload of the current block.
    decoded: Vec<u8>,
    decoded_idx: usize,
    /// Sliding 64 KiB window of the last decoded bytes, for linked-block
    /// back-references.
    window: Vec<u8>,
    /// Running content checksum (if enabled).
    content_hash: XxHash32,
    /// `true` once a malformed input was seen; further calls error.
    poisoned: bool,
}

impl Decoder {
    /// Construct a fresh decoder. All decode-time options are read from
    /// the stream.
    pub fn new() -> Self {
        Self {
            phase: DecPhase::Magic,
            accum: [0; 12],
            accum_len: 0,
            accum_need: 4,
            flg: 0,
            bd: 0,
            desc_remaining: 0,
            descriptor: Vec::with_capacity(14),
            block_max: BlockMaxSize::Max64KB,
            block_independent: false,
            block_checksum: false,
            content_checksum: false,
            cur_block_len: 0,
            cur_block_uncompressed: false,
            compressed: Vec::new(),
            decoded: Vec::new(),
            decoded_idx: 0,
            window: Vec::with_capacity(WINDOW_SIZE),
            content_hash: XxHash32::new(),
            poisoned: false,
        }
    }

    fn poison<T>(&mut self, e: Error) -> Result<T, Error> {
        self.poisoned = true;
        Err(e)
    }

    /// Read up to `accum_need` bytes from `input` into `accum`. Returns
    /// `true` when the field is fully assembled.
    fn fill_accum(&mut self, input: &[u8], consumed: &mut usize) -> bool {
        while (self.accum_len as usize) < (self.accum_need as usize) && *consumed < input.len() {
            self.accum[self.accum_len as usize] = input[*consumed];
            self.accum_len += 1;
            *consumed += 1;
        }
        self.accum_len == self.accum_need
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
    }

    /// Push `bytes` onto the sliding-back-reference window. Only meaningful
    /// when blocks are linked.
    fn push_window(&mut self, bytes: &[u8]) {
        if self.block_independent {
            return;
        }
        if bytes.len() >= WINDOW_SIZE {
            // The tail of `bytes` is enough on its own.
            self.window.clear();
            self.window
                .extend_from_slice(&bytes[bytes.len() - WINDOW_SIZE..]);
            return;
        }
        let combined = self.window.len() + bytes.len();
        if combined <= WINDOW_SIZE {
            self.window.extend_from_slice(bytes);
        } else {
            // Drop the oldest `combined - WINDOW_SIZE` bytes.
            let drop = combined - WINDOW_SIZE;
            self.window.drain(..drop);
            self.window.extend_from_slice(bytes);
        }
    }

    /// Parse FLG + BD, validate version + reserved bits, capture the
    /// flag set.
    fn parse_flg_bd(&mut self) -> Result<(), Error> {
        let flg = self.accum[0];
        let bd = self.accum[1];
        if (flg & FLG_VERSION_MASK) != FLG_VERSION_BITS {
            return Err(Error::Unsupported);
        }
        if (flg & FLG_RESERVED) != 0 {
            return Err(Error::BadHeader);
        }
        if (bd & BD_RESERVED_HIGH) != 0 || (bd & BD_RESERVED_LOW) != 0 {
            return Err(Error::BadHeader);
        }
        let bd_val = (bd >> BD_BLOCK_MAX_SHIFT) & 0b0111;
        self.block_max = BlockMaxSize::from_bd_value(bd_val)?;
        self.block_independent = (flg & FLG_BLOCK_INDEP) != 0;
        self.block_checksum = (flg & FLG_BLOCK_CHECKSUM) != 0;
        self.content_checksum = (flg & FLG_CONTENT_CHECKSUM) != 0;
        self.flg = flg;
        self.bd = bd;

        self.descriptor.clear();
        self.descriptor.push(flg);
        self.descriptor.push(bd);

        // ContentSize (8 bytes) + DictID (4 bytes), if their flags say so.
        let mut tail = 0u8;
        if (flg & FLG_CONTENT_SIZE) != 0 {
            tail += 8;
        }
        if (flg & FLG_DICT_ID) != 0 {
            tail += 4;
        }
        self.desc_remaining = tail;

        if tail > 0 {
            self.phase = DecPhase::DescriptorTail;
            self.accum_len = 0;
            self.accum_need = tail;
        } else {
            self.phase = DecPhase::Hc;
            self.accum_len = 0;
            self.accum_need = 1;
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
            match self.phase {
                DecPhase::Magic => {
                    if !self.fill_accum(input, &mut consumed) {
                        return Ok(RawProgress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                    let m = u32::from_le_bytes([
                        self.accum[0],
                        self.accum[1],
                        self.accum[2],
                        self.accum[3],
                    ]);
                    if m != MAGIC {
                        return self.poison(Error::BadHeader);
                    }
                    self.phase = DecPhase::FlgBd;
                    self.accum_len = 0;
                    self.accum_need = 2;
                }
                DecPhase::FlgBd => {
                    if !self.fill_accum(input, &mut consumed) {
                        return Ok(RawProgress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                    if let Err(e) = self.parse_flg_bd() {
                        return self.poison(e);
                    }
                }
                DecPhase::DescriptorTail => {
                    if !self.fill_accum(input, &mut consumed) {
                        return Ok(RawProgress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                    // Capture these bytes for the HC computation but
                    // otherwise ignore them — we don't honour DictID
                    // and we don't enforce the ContentSize field.
                    self.descriptor
                        .extend_from_slice(&self.accum[..self.accum_len as usize]);
                    self.phase = DecPhase::Hc;
                    self.accum_len = 0;
                    self.accum_need = 1;
                }
                DecPhase::Hc => {
                    if !self.fill_accum(input, &mut consumed) {
                        return Ok(RawProgress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                    let hc = self.accum[0];
                    let expected = (xxhash32(&self.descriptor) >> 8) as u8;
                    if hc != expected {
                        return self.poison(Error::BadHeader);
                    }
                    self.descriptor.clear();
                    self.phase = DecPhase::BlockSize;
                    self.accum_len = 0;
                    self.accum_need = 4;
                }
                DecPhase::BlockSize => {
                    if !self.fill_accum(input, &mut consumed) {
                        return Ok(RawProgress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                    let raw_word = u32::from_le_bytes([
                        self.accum[0],
                        self.accum[1],
                        self.accum[2],
                        self.accum[3],
                    ]);
                    if raw_word == 0 {
                        // EndMark.
                        if self.content_checksum {
                            self.phase = DecPhase::ContentChecksum;
                            self.accum_len = 0;
                            self.accum_need = 4;
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
                    let uncompressed = (raw_word & 0x8000_0000) != 0;
                    let len = (raw_word & 0x7FFF_FFFF) as usize;
                    let raw_max = self.block_max.bytes();
                    let bound = max_compressed_block(raw_max).min(MAX_BLOCK_BYTES);
                    if len == 0 {
                        // High-bit-only word with zero length is malformed.
                        return self.poison(Error::BadHeader);
                    }
                    if len > bound {
                        return self.poison(Error::Corrupt);
                    }
                    if uncompressed && len > raw_max {
                        return self.poison(Error::Corrupt);
                    }
                    self.cur_block_len = len as u32;
                    self.cur_block_uncompressed = uncompressed;
                    self.compressed.clear();
                    self.compressed.reserve(len);
                    self.phase = DecPhase::BlockData;
                    self.accum_len = 0;
                }
                DecPhase::BlockData => {
                    let need = self.cur_block_len as usize - self.compressed.len();
                    let avail = input.len() - consumed;
                    let take = need.min(avail);
                    if take > 0 {
                        self.compressed
                            .extend_from_slice(&input[consumed..consumed + take]);
                        consumed += take;
                    }
                    if self.compressed.len() < self.cur_block_len as usize {
                        return Ok(RawProgress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                    if self.block_checksum {
                        self.phase = DecPhase::BlockChecksum;
                        self.accum_len = 0;
                        self.accum_need = 4;
                    } else {
                        self.phase = DecPhase::Decode;
                    }
                }
                DecPhase::BlockChecksum => {
                    if !self.fill_accum(input, &mut consumed) {
                        return Ok(RawProgress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                    let expected = u32::from_le_bytes([
                        self.accum[0],
                        self.accum[1],
                        self.accum[2],
                        self.accum[3],
                    ]);
                    let actual = xxhash32(&self.compressed);
                    if actual != expected {
                        return self.poison(Error::ChecksumMismatch);
                    }
                    self.phase = DecPhase::Decode;
                }
                DecPhase::Decode => {
                    self.decoded.clear();
                    if self.cur_block_uncompressed {
                        // Wire payload is the raw block bytes.
                        self.decoded.extend_from_slice(&self.compressed);
                    } else if self.block_independent {
                        let raw_max = self.block_max.bytes();
                        if let Err(e) =
                            block::decode_block(&self.compressed, &mut self.decoded, raw_max)
                        {
                            return self.poison(e);
                        }
                        // Backstop: the per-append cap above already enforces
                        // this, but keep an explicit post-decode check for
                        // parity with the linked-block path and LZ5.
                        if self.decoded.len() > raw_max {
                            return self.poison(Error::Corrupt);
                        }
                    } else {
                        // Linked-block decode: the back-reference search
                        // space is the 64 KiB sliding window plus what
                        // we've decoded in this block so far.
                        if let Err(e) = decode_linked_block(
                            &self.compressed,
                            &self.window,
                            &mut self.decoded,
                            self.block_max.bytes(),
                        ) {
                            return self.poison(e);
                        }
                    }
                    if self.content_checksum {
                        self.content_hash.update(&self.decoded);
                    }
                    // Update the sliding window with this block's output.
                    if !self.block_independent {
                        let bytes = core::mem::take(&mut self.decoded);
                        self.push_window(&bytes);
                        self.decoded = bytes;
                    }
                    self.decoded_idx = 0;
                    self.phase = DecPhase::Draining;
                }
                DecPhase::Draining => {
                    self.drain_decoded(output, &mut written);
                    if self.decoded_idx < self.decoded.len() {
                        return Ok(RawProgress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                    self.decoded.clear();
                    self.decoded_idx = 0;
                    self.phase = DecPhase::BlockSize;
                    self.accum_len = 0;
                    self.accum_need = 4;
                }
                DecPhase::ContentChecksum => {
                    if !self.fill_accum(input, &mut consumed) {
                        return Ok(RawProgress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                    let expected = u32::from_le_bytes([
                        self.accum[0],
                        self.accum[1],
                        self.accum[2],
                        self.accum[3],
                    ]);
                    let actual =
                        core::mem::replace(&mut self.content_hash, XxHash32::new()).finish();
                    if actual != expected {
                        return self.poison(Error::ChecksumMismatch);
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
                        done: false,
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

        // Drain whatever block payload is still staged.
        if self.phase == DecPhase::Draining {
            self.drain_decoded(output, &mut written);
            if self.decoded_idx < self.decoded.len() {
                return Ok(RawProgress {
                    consumed: 0,
                    written,
                    done: false,
                });
            }
            self.decoded.clear();
            self.decoded_idx = 0;
            self.phase = DecPhase::BlockSize;
            self.accum_len = 0;
            self.accum_need = 4;
        }

        match self.phase {
            DecPhase::Done => Ok(RawProgress {
                consumed: 0,
                written,
                done: true,
            }),
            // Caller signalled "no more input" before we ever saw any —
            // legal, just no-op.
            DecPhase::Magic if self.accum_len == 0 => Ok(RawProgress {
                consumed: 0,
                written,
                done: true,
            }),
            _ => Err(Error::UnexpectedEnd),
        }
    }

    fn raw_reset(&mut self) {
        self.phase = DecPhase::Magic;
        self.accum_len = 0;
        self.accum_need = 4;
        self.flg = 0;
        self.bd = 0;
        self.desc_remaining = 0;
        self.descriptor.clear();
        self.block_max = BlockMaxSize::Max64KB;
        self.block_independent = false;
        self.block_checksum = false;
        self.content_checksum = false;
        self.cur_block_len = 0;
        self.cur_block_uncompressed = false;
        self.compressed.clear();
        self.decoded.clear();
        self.decoded_idx = 0;
        self.window.clear();
        self.content_hash = XxHash32::new();
        self.poisoned = false;
    }
}

// ─── Linked-block decoder ────────────────────────────────────────────────
//
// Mostly mirrors `super::block::decode_block` but lets matches reach into
// a prefix buffer (`prefix`) representing the tail of the previously
// decoded content. A back-reference whose offset is greater than the
// number of bytes already written in this block draws from the prefix.

fn decode_linked_block(
    input: &[u8],
    prefix: &[u8],
    out: &mut Vec<u8>,
    raw_max: usize,
) -> Result<(), Error> {
    out.clear();
    if input.is_empty() {
        return Ok(());
    }
    let mut ip = 0usize;
    let n = input.len();

    loop {
        if ip >= n {
            return Err(Error::UnexpectedEnd);
        }
        let token = input[ip];
        ip += 1;

        let mut lit_len = (token >> 4) as usize;
        if lit_len == 15 {
            loop {
                if ip >= n {
                    return Err(Error::UnexpectedEnd);
                }
                let b = input[ip];
                ip += 1;
                lit_len = lit_len.checked_add(b as usize).ok_or(Error::Corrupt)?;
                if b != 255 {
                    break;
                }
            }
        }

        if lit_len > 0 {
            if ip + lit_len > n {
                return Err(Error::UnexpectedEnd);
            }
            if out.len() + lit_len > raw_max {
                return Err(Error::Corrupt);
            }
            out.extend_from_slice(&input[ip..ip + lit_len]);
            ip += lit_len;
        }

        if ip == n {
            return Ok(());
        }
        if ip + 2 > n {
            return Err(Error::UnexpectedEnd);
        }
        let offset = (input[ip] as usize) | ((input[ip + 1] as usize) << 8);
        ip += 2;
        if offset == 0 {
            return Err(Error::InvalidDistance);
        }
        let in_block = out.len();
        let total = in_block + prefix.len();
        if offset > total {
            return Err(Error::InvalidDistance);
        }

        let mut match_excess = (token & 0x0F) as usize;
        if match_excess == 15 {
            loop {
                if ip >= n {
                    return Err(Error::UnexpectedEnd);
                }
                let b = input[ip];
                ip += 1;
                match_excess = match_excess.checked_add(b as usize).ok_or(Error::Corrupt)?;
                if b != 255 {
                    break;
                }
            }
        }
        let match_len = 4 + match_excess;
        if out.len() + match_len > raw_max {
            return Err(Error::Corrupt);
        }

        // Copy bytewise; the match may straddle the prefix/in-block
        // boundary and may overlap itself inside the block.
        for i in 0..match_len {
            // Source position counted backwards from the current write
            // position (= out.len() at the time of *this* copy iteration).
            let cur_len = out.len();
            let src_back = offset; // distance from the current write head
            let b = if src_back <= cur_len {
                // Sits inside what we've written in this block.
                out[cur_len - src_back]
            } else {
                // Reaches into the prefix.
                let into_prefix = src_back - cur_len;
                if into_prefix > prefix.len() {
                    return Err(Error::InvalidDistance);
                }
                prefix[prefix.len() - into_prefix]
            };
            out.push(b);
            let _ = i;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xxhash32_empty() {
        // Reference value for xxHash32("", seed=0).
        assert_eq!(xxhash32(b""), 0x02CC_5D05);
    }

    #[test]
    fn xxhash32_known_short() {
        // "abc" → 0x32D153FF (canonical xxHash test vector).
        assert_eq!(xxhash32(b"abc"), 0x32D1_53FF);
    }

    #[test]
    fn xxhash32_incremental_matches_oneshot() {
        let payload: Vec<u8> = (0..1000u32).map(|i| (i ^ 0x55) as u8).collect();
        let one = xxhash32(&payload);
        let mut h = XxHash32::new();
        // Feed in irregular chunks across the 16-byte stripe boundary.
        let mut i = 0;
        let chunks = [1usize, 3, 7, 16, 5, 31, 13, 19];
        let mut ci = 0;
        while i < payload.len() {
            let take = chunks[ci % chunks.len()].min(payload.len() - i);
            h.update(&payload[i..i + take]);
            i += take;
            ci += 1;
        }
        assert_eq!(h.finish(), one);
    }
}
