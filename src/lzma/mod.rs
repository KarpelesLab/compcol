//! LZMA (Lempel–Ziv–Markov chain Algorithm).
//!
//! This build ships **both an encoder and a decoder** for the legacy `.lzma`
//! (alone) format, and for LZMA entry data in ZIP archives (method 14, see
//! below). The encoder produces a stream that round-trips through
//! our own decoder and decompresses cleanly with external implementations
//! (Python's stdlib `lzma`, XZ Utils, 7-Zip, etc.).
//!
//! Wire format (legacy "alone"):
//! - 1 byte properties (`pp*9*5 + pp*5 + lc`, where `pb`, `lp`, `lc` are the
//!   three LZMA parameters in `0..=4`, `0..=4`, `0..=8`).
//! - 4 bytes little-endian dictionary size.
//! - 8 bytes little-endian uncompressed size; `0xFFFF_FFFF_FFFF_FFFF` means
//!   "unknown" — the stream is terminated by an explicit end-of-stream marker.
//! - The remainder of the input is a range-coded LZMA payload.
//!
//! ZIP method 14 (APPNOTE.TXT §5.8) frames the same payload differently:
//! 2 bytes LZMA SDK version, 2 bytes LE properties size (5), the 5
//! properties bytes (props byte + dictionary size), then the range-coded
//! payload. There is no size field: the uncompressed size is in the ZIP
//! header, and general-purpose flag bit 1 says the stream ends with an
//! end-of-stream marker. [`Decoder::zip`] / [`Decoder::zip_from_gp_flags`]
//! read this form and [`Encoder::zip`] writes it, with or without the
//! marker ([`Encoder::eos_marker`] gives the flag bit to set). Parsing the
//! ZIP headers is out of scope; these work on the entry's stored bytes.
//!
//! ```
//! use compcol::lzma::{Decoder, Encoder, EncoderConfig};
//! use compcol::{Decoder as _, Encoder as _, Status};
//!
//! let data = b"hello hello hello";
//! let mut enc = Encoder::zip(EncoderConfig::default(), false);
//! let gp_flags: u16 = if enc.eos_marker() { 0x0002 } else { 0 };
//! let mut entry = vec![0u8; 256];
//! let (p, _) = enc.encode(data, &mut entry).unwrap();
//! let mut n = p.written;
//! let (p, _) = enc.finish(&mut entry[n..]).unwrap();
//! n += p.written;
//!
//! let mut dec = Decoder::zip_from_gp_flags(gp_flags, Some(data.len() as u64));
//! let mut out = vec![0u8; 64];
//! let (p1, _) = dec.decode(&entry[..n], &mut out).unwrap();
//! let (p2, status) = dec.finish(&mut out[p1.written..]).unwrap();
//! assert_eq!(status, Status::StreamEnd);
//! assert_eq!(&out[..p1.written + p2.written], data);
//! ```
//!
//! References: 7-Zip / lzma-sdk source (well-commented C reference) and
//! `xz-utils` (`liblzma/lz/`, `liblzma/rangecoder/`).
//!
//! Streaming model: the decoder copies compressed input into a small
//! internal `Vec<u8>` a bounded piece at a time. Each call drains as much of
//! the caller's output as possible by attempting LZMA "packets" (a literal
//! or a match). A packet is only started once enough input is buffered for
//! the largest possible packet; otherwise the codec asks for more input on
//! the next call (`finish` lifts that gate). Input the range decoder has not
//! read when the output fills up or the stream ends is left unconsumed, so
//! the buffer stays small whatever the size of the caller's slices.
//!
//! End of stream: `decode` returns `StreamEnd` once the end marker has been
//! read or the declared size has been reached, and consumes nothing after
//! that. A `.lzma` stream with a declared size may still carry an end
//! marker; it is read too. Any other data past the declared size is
//! [`Error::Corrupt`]. Because a packet needs up to 20 bytes of lookahead,
//! a stream whose last bytes arrive without anything following them ends in
//! `finish` rather than in `decode`.
//!
//! Memory: the decoder's one large allocation is the dictionary, whose size
//! the stream's header declares (up to 4 GiB − 1). [`DecoderConfig`] bounds
//! it: a header declaring more than
//! [`max_dict_size`](DecoderConfig::max_dict_size) (64 MiB by default, what
//! `xz --format=lzma -9` writes) is [`Error::Unsupported`]. The dictionary
//! is grown as output is produced, so a stream costs at most the smaller of
//! its declared dictionary and its decoded length.
//!
//! Contiguous output: when the whole result goes into one buffer, the
//! decoder can use that buffer as its history and allocate no dictionary at
//! all — [`Decoder`] implements [`ContiguousDecoder`]
//! (`decode_contiguous` / `finish_contiguous`) for both framings. The same
//! streams are accepted and rejected as with `decode` / `finish`, except
//! that `max_dict_size` is not applied: with no dictionary there is nothing
//! for it to bound. See the notes on that implementation.
//!
//! The encoder lives in the private `encoder` submodule. It accumulates input into a buffer and
//! emits the entire compressed stream on `finish` — LZMA's range coder
//! prevents a true byte-streaming output, and full-buffer encoding is by far
//! the simplest correct strategy.

extern crate alloc;
use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;
use crate::traits::{Algorithm, ContiguousDecoder, Progress, RawDecoder, RawProgress, Status};

mod encoder;
pub use encoder::{Encoder, EncoderConfig};

// ─── algorithm marker ────────────────────────────────────────────────────

/// Zero-sized marker type implementing [`Algorithm`] for legacy `.lzma`.
#[derive(Debug, Clone, Copy, Default)]
pub struct Lzma;

impl Algorithm for Lzma {
    const NAME: &'static str = "lzma";
    type Encoder = Encoder;
    type Decoder = Decoder;
    type EncoderConfig = EncoderConfig;
    type DecoderConfig = DecoderConfig;
    fn encoder_with(c: Self::EncoderConfig) -> Encoder {
        Encoder::with_config(c)
    }
    fn decoder_with(c: DecoderConfig) -> Decoder {
        Decoder::with_config(c)
    }
}

// ─── decoder configuration ───────────────────────────────────────────────

/// Default [`DecoderConfig::max_dict_size`]: 64 MiB, the dictionary
/// `xz --format=lzma -9` writes.
pub const DEFAULT_MAX_DICT_SIZE: u64 = 64 * 1024 * 1024;

/// Largest dictionary a [`DecoderConfig`] can allow: what the header's
/// 32-bit dictionary size field can express (4 GiB − 1), or the largest
/// allocation the target supports if that is smaller (2 GiB − 1 on 32-bit
/// targets). Higher [`DecoderConfig::max_dict_size`] values mean this.
pub const MAX_DICT_SIZE: u64 = if (isize::MAX as u64) < u32::MAX as u64 {
    isize::MAX as u64
} else {
    u32::MAX as u64
};

/// Smallest dictionary the decoder works with; a header (or a limit) asking
/// for less is treated as asking for this, as in the LZMA SDK.
const MIN_DICT_SIZE: u64 = 4096;

/// Decoder tunables, for `.lzma` streams and ZIP method-14 entries alike.
///
/// The dictionary (the sliding window of decoded history) is the decoder's
/// only large allocation, and its size comes from the stream's header, so
/// this limit is the decoder's memory budget. A header declaring a larger
/// dictionary is rejected with [`Error::Unsupported`] as soon as it has been
/// read, before any data is decoded.
///
/// The dictionary is allocated as output is produced, not when the header is
/// read: a stream costs the smaller of its declared dictionary size and the
/// bytes it has decoded to so far, so raising the limit does not by itself
/// make small streams expensive.
///
/// The limit applies to [`decode`](crate::Decoder::decode) /
/// [`finish`](crate::Decoder::finish). Decoding through
/// [`ContiguousDecoder`] allocates no dictionary, so the limit is not
/// applied there.
///
/// ```
/// use compcol::lzma::{Decoder, DecoderConfig};
///
/// // Accept the 1 GiB dictionaries of `xz --format=lzma --lzma1=dict=1GiB`.
/// let dec = Decoder::with_config(DecoderConfig::with_max_dict_size(1 << 30));
/// assert_eq!(dec.max_dict_size(), 1 << 30);
/// // Or keep a memory-constrained ZIP reader to 8 MiB per entry.
/// let dec = Decoder::zip(false, Some(1234)).with_max_dict_size(8 << 20);
/// assert_eq!(dec.max_dict_size(), 8 << 20);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecoderConfig {
    /// Largest dictionary size (in bytes) a stream's header may declare.
    /// Defaults to [`DEFAULT_MAX_DICT_SIZE`] (64 MiB). Values below 4 KiB
    /// are treated as 4 KiB and values above [`MAX_DICT_SIZE`] as
    /// [`MAX_DICT_SIZE`].
    pub max_dict_size: u64,
}

impl DecoderConfig {
    /// The default configuration: a [`DEFAULT_MAX_DICT_SIZE`] limit.
    pub const fn new() -> Self {
        Self {
            max_dict_size: DEFAULT_MAX_DICT_SIZE,
        }
    }

    /// Configuration accepting dictionaries of up to `bytes` bytes.
    pub const fn with_max_dict_size(bytes: u64) -> Self {
        Self {
            max_dict_size: bytes,
        }
    }

    /// The limit actually applied: `max_dict_size` brought into
    /// `4 KiB..=MAX_DICT_SIZE`.
    const fn effective_max_dict_size(self) -> u64 {
        if self.max_dict_size < MIN_DICT_SIZE {
            MIN_DICT_SIZE
        } else if self.max_dict_size > MAX_DICT_SIZE {
            MAX_DICT_SIZE
        } else {
            self.max_dict_size
        }
    }
}

impl Default for DecoderConfig {
    fn default() -> Self {
        Self::new()
    }
}

// ─── LZMA constants ──────────────────────────────────────────────────────

/// Worst-case number of input bytes a single LZMA packet may consume from
/// the range decoder. Matches `LZMA_REQUIRED_INPUT_MAX` in the 7-Zip
/// reference SDK. Used to gate streaming decode attempts: a packet is only
/// started once we have at least this much forward input, otherwise the
/// decoder returns `NeedInput` and waits for the next call.
const REQUIRED_INPUT_MAX: usize = 20;

/// Threshold at which `drain_output` collapses the consumed prefix of
/// `Decoder::buf`. Compacting on every packet would memmove the buffered
/// tail once per packet. Input is absorbed `ABSORB_CHUNK` bytes at a time,
/// so at most that much is moved per `COMPACT_THRESHOLD` bytes consumed and
/// the buffer never holds more than about the sum of the two.
const COMPACT_THRESHOLD: usize = 64 * 1024;

const STATES: usize = 12;
const LIT_STATES: usize = 7;
const POS_STATES_MAX: usize = 1 << 4;

const LEN_LOW_BITS: u32 = 3;
const LEN_LOW_SYMBOLS: usize = 1 << LEN_LOW_BITS;
const LEN_MID_BITS: u32 = 3;
const LEN_MID_SYMBOLS: usize = 1 << LEN_MID_BITS;
const LEN_HIGH_BITS: u32 = 8;
const LEN_HIGH_SYMBOLS: usize = 1 << LEN_HIGH_BITS;

const MATCH_LEN_MIN: u32 = 2;

const DIST_STATES: usize = 4;
const DIST_SLOT_BITS: u32 = 6;
const DIST_SLOTS: usize = 1 << DIST_SLOT_BITS;
const DIST_MODEL_START: u32 = 4;
const DIST_MODEL_END: u32 = 14;
const FULL_DISTANCES_BITS: u32 = DIST_MODEL_END / 2;
const FULL_DISTANCES: usize = 1 << FULL_DISTANCES_BITS;
const ALIGN_BITS: u32 = 4;
const ALIGN_SIZE: usize = 1 << ALIGN_BITS;

const RC_BIT_MODEL_TOTAL_BITS: u32 = 11;
const RC_BIT_MODEL_TOTAL: u32 = 1 << RC_BIT_MODEL_TOTAL_BITS;
const RC_MOVE_BITS: u32 = 5;
const RC_TOP_VALUE: u32 = 0x0100_0000;
const PROB_INIT: u16 = (RC_BIT_MODEL_TOTAL / 2) as u16;

/// Smallest step the lazily grown dictionary buffer is extended by.
const DICT_GROW_MIN: usize = 4096;

// State transitions per LZMA spec: each "packet" advances the state machine
// according to whether the packet was a literal, a new match, a long-rep,
// or a short-rep, with the previous state influencing the destination.

const fn state_after_literal(s: usize) -> usize {
    // 0..=3 → 0; 4..=9 → s-3; 10..=11 → s-6
    if s <= 3 {
        0
    } else if s <= 9 {
        s - 3
    } else {
        s - 6
    }
}

const fn state_after_match(s: usize) -> usize {
    if s < LIT_STATES { 7 } else { 10 }
}

const fn state_after_rep(s: usize) -> usize {
    if s < LIT_STATES { 8 } else { 11 }
}

const fn state_after_short_rep(s: usize) -> usize {
    if s < LIT_STATES { 9 } else { 11 }
}

fn is_literal_state(s: usize) -> bool {
    s < LIT_STATES
}

// ─── range decoder ───────────────────────────────────────────────────────

#[derive(Clone)]
struct RangeDecoder {
    range: u32,
    code: u32,
    /// Position in the buffered input where this decoder reads from.
    pos: usize,
}

impl RangeDecoder {
    fn new() -> Self {
        Self {
            range: 0,
            code: 0,
            pos: 0,
        }
    }

    /// Initialise from the first 5 bytes after the LZMA header. First byte
    /// must be zero per the spec.
    fn init(&mut self, buf: &[u8]) -> Result<bool, Error> {
        if buf.len() < self.pos + 5 {
            return Ok(false);
        }
        if buf[self.pos] != 0 {
            return Err(Error::Corrupt);
        }
        let b1 = buf[self.pos + 1] as u32;
        let b2 = buf[self.pos + 2] as u32;
        let b3 = buf[self.pos + 3] as u32;
        let b4 = buf[self.pos + 4] as u32;
        self.code = (b1 << 24) | (b2 << 16) | (b3 << 8) | b4;
        self.range = 0xFFFF_FFFF;
        self.pos += 5;
        Ok(true)
    }

    /// Try to normalise. Returns `Err(UnexpectedEnd)` if there isn't enough
    /// input — callers above this layer must ensure adequate input has been
    /// buffered (see `REQUIRED_INPUT_MAX`).
    #[inline(always)]
    fn normalize(&mut self, buf: &[u8]) -> Result<(), Error> {
        if self.range < RC_TOP_VALUE {
            if self.pos >= buf.len() {
                return Err(Error::UnexpectedEnd);
            }
            self.range <<= 8;
            self.code = (self.code << 8) | buf[self.pos] as u32;
            self.pos += 1;
        }
        Ok(())
    }

    /// Decode one bit using the probability slot `prob`.
    #[inline(always)]
    fn decode_bit(&mut self, prob: &mut u16, buf: &[u8]) -> Result<u32, Error> {
        self.normalize(buf)?;
        let p = *prob as u32;
        let bound = (self.range >> RC_BIT_MODEL_TOTAL_BITS) * p;
        if self.code < bound {
            self.range = bound;
            *prob = (p + ((RC_BIT_MODEL_TOTAL - p) >> RC_MOVE_BITS)) as u16;
            Ok(0)
        } else {
            self.range -= bound;
            self.code -= bound;
            *prob = (p - (p >> RC_MOVE_BITS)) as u16;
            Ok(1)
        }
    }

    /// End-of-stream check: normalise once more so the stream's
    /// last byte is read, then report whether `code == 0`, as a cleanly
    /// flushed encoder leaves it. `None` means that byte has not arrived.
    fn finish(&mut self, buf: &[u8], at_eof: bool) -> Result<Option<bool>, Error> {
        if self.range < RC_TOP_VALUE {
            if self.pos >= buf.len() {
                return if at_eof {
                    Err(Error::UnexpectedEnd)
                } else {
                    Ok(None)
                };
            }
            self.range <<= 8;
            self.code = (self.code << 8) | buf[self.pos] as u32;
            self.pos += 1;
        }
        Ok(Some(self.code == 0))
    }

    /// Decode `count` direct (uniform) bits in a tight loop and return their
    /// accumulated value, **MSB-first** — the bit decoded on iteration 0
    /// becomes the highest bit of the result; the bit decoded last is bit 0.
    /// This matches liblzma's wire convention (LzmaDec.c uses
    /// `distance = (distance << 1) + ...`, LzmaEnc.c emits via a top-bit
    /// shift loop), so the same compressed stream that liblzma's `xz -d`
    /// decodes is the one this function reconstructs the same value from.
    ///
    /// This is the hot path for slot >= 14 (random / incompressible data):
    /// `count` can be up to 26. By inlining normalisation into the loop we
    /// avoid the per-bit function-call overhead and let the optimiser keep
    /// `range`/`code`/`pos` in registers across iterations.
    #[inline(always)]
    fn decode_direct_bits_msb(&mut self, count: u32, buf: &[u8]) -> Result<u32, Error> {
        let mut range = self.range;
        let mut code = self.code;
        let mut pos = self.pos;
        let buf_len = buf.len();
        let mut result: u32 = 0;
        for _ in 0..count {
            // Normalise inline.
            if range < RC_TOP_VALUE {
                if pos >= buf_len {
                    self.range = range;
                    self.code = code;
                    self.pos = pos;
                    return Err(Error::UnexpectedEnd);
                }
                range <<= 8;
                code = (code << 8) | buf[pos] as u32;
                pos += 1;
            }
            range >>= 1;
            // Branch-free: bit = (code >= range) ? 1 : 0. We need to also
            // subtract `range` from `code` when bit == 1.
            let t = code.wrapping_sub(range);
            let mask = (t as i32 >> 31) as u32; // all-ones when code < range
            // When bit == 1 (mask == 0), keep `t` (i.e. code - range);
            // when bit == 0 (mask == all-ones), keep original `code`.
            code = (code & mask) | (t & !mask);
            // bit = !mask & 1
            let bit = (!mask) & 1;
            // MSB-first: shift accumulator left, place new bit at position 0.
            result = (result << 1) | bit;
        }
        self.range = range;
        self.code = code;
        self.pos = pos;
        Ok(result)
    }
}

// ─── bit-tree helpers ────────────────────────────────────────────────────
//
// The "bittree" decoders are tiny tries of probabilities. Because each
// individual call to `decode_bit` may need more input mid-tree, we cannot
// use plain recursion — we'd have to checkpoint *inside* the tree.
//
// Instead, every bit-tree call here is wrapped by an outer "try the whole
// packet, rollback on starvation" check. As long as the packet doesn't span
// more than the worst-case bytes of compressed input we need, the rollback
// approach is correct.

/// `bits` is `log2(probs.len())`. Decodes `bits` bits MSB-first.
#[inline(always)]
fn bittree_decode(
    rd: &mut RangeDecoder,
    probs: &mut [u16],
    bits: u32,
    buf: &[u8],
) -> Result<u32, Error> {
    let mut idx: u32 = 1;
    for _ in 0..bits {
        let bit = rd.decode_bit(&mut probs[idx as usize], buf)?;
        idx = (idx << 1) | bit;
    }
    Ok(idx - (1 << bits))
}

/// Specialised 4-bit reverse bit-tree for the dist-align table. The hot
/// inner loop unrolls 4 probability lookups onto a fixed-size array, which
/// lets the optimiser elide bounds checks and keep `idx` in a register.
#[inline(always)]
fn dist_align_reverse_decode(
    rd: &mut RangeDecoder,
    probs: &mut [u16; ALIGN_SIZE],
    buf: &[u8],
) -> Result<u32, Error> {
    let mut idx: usize = 1;
    let mut result: u32 = 0;
    // Iteration 0
    let bit = rd.decode_bit(&mut probs[idx], buf)?;
    idx = (idx << 1) | bit as usize;
    result |= bit;
    // Iteration 1
    let bit = rd.decode_bit(&mut probs[idx], buf)?;
    idx = (idx << 1) | bit as usize;
    result |= bit << 1;
    // Iteration 2
    let bit = rd.decode_bit(&mut probs[idx], buf)?;
    idx = (idx << 1) | bit as usize;
    result |= bit << 2;
    // Iteration 3
    let bit = rd.decode_bit(&mut probs[idx], buf)?;
    let _ = idx;
    result |= bit << 3;
    Ok(result)
}

/// The eight bits of a literal, from its 0x300-entry probability set.
/// `match_byte` is the byte at the last match distance when the previous
/// packet was a match ("matched literal" coding), else `None`.
#[inline(always)]
fn literal_bits(
    rd: &mut RangeDecoder,
    probs: &mut [u16],
    match_byte: Option<u8>,
    buf: &[u8],
) -> Result<u8, Error> {
    let mut symbol: u32 = 1;
    match match_byte {
        Some(mb) => {
            let mut match_byte = mb as u32;
            let mut mismatched = false;
            while symbol < 0x100 {
                match_byte <<= 1;
                let match_bit = match_byte & 0x100;
                let idx = (0x100 + match_bit + symbol) as usize;
                let bit = rd.decode_bit(&mut probs[idx], buf)?;
                symbol = (symbol << 1) | bit;
                if match_bit >> 8 != bit {
                    mismatched = true;
                    break;
                }
            }
            if mismatched {
                while symbol < 0x100 {
                    let bit = rd.decode_bit(&mut probs[symbol as usize], buf)?;
                    symbol = (symbol << 1) | bit;
                }
            }
        }
        None => {
            while symbol < 0x100 {
                let bit = rd.decode_bit(&mut probs[symbol as usize], buf)?;
                symbol = (symbol << 1) | bit;
            }
        }
    }
    Ok((symbol - 0x100) as u8)
}

// ─── length decoder ──────────────────────────────────────────────────────

struct LengthCoder {
    choice: u16,
    choice2: u16,
    low: Vec<u16>,  // [POS_STATES_MAX][LEN_LOW_SYMBOLS]
    mid: Vec<u16>,  // [POS_STATES_MAX][LEN_MID_SYMBOLS]
    high: Vec<u16>, // [LEN_HIGH_SYMBOLS]
}

impl LengthCoder {
    fn new() -> Self {
        Self {
            choice: PROB_INIT,
            choice2: PROB_INIT,
            low: vec![PROB_INIT; POS_STATES_MAX * LEN_LOW_SYMBOLS],
            mid: vec![PROB_INIT; POS_STATES_MAX * LEN_MID_SYMBOLS],
            high: vec![PROB_INIT; LEN_HIGH_SYMBOLS],
        }
    }

    fn decode(&mut self, rd: &mut RangeDecoder, pos_state: u32, buf: &[u8]) -> Result<u32, Error> {
        let bit = rd.decode_bit(&mut self.choice, buf)?;
        if bit == 0 {
            let base = (pos_state as usize) * LEN_LOW_SYMBOLS;
            let probs = &mut self.low[base..base + LEN_LOW_SYMBOLS];
            return bittree_decode(rd, probs, LEN_LOW_BITS, buf);
        }
        let bit2 = rd.decode_bit(&mut self.choice2, buf)?;
        if bit2 == 0 {
            let base = (pos_state as usize) * LEN_MID_SYMBOLS;
            let probs = &mut self.mid[base..base + LEN_MID_SYMBOLS];
            let v = bittree_decode(rd, probs, LEN_MID_BITS, buf)?;
            return Ok(LEN_LOW_SYMBOLS as u32 + v);
        }
        let v = bittree_decode(rd, &mut self.high, LEN_HIGH_BITS, buf)?;
        Ok((LEN_LOW_SYMBOLS + LEN_MID_SYMBOLS) as u32 + v)
    }
}

// ─── history sinks ───────────────────────────────────────────────────────
//
// The LZMA logic below is written once, generic over where decoded bytes go
// and where matches read their history from:
//
//   * `WindowSink` — the streaming path: a circular dictionary owned by the
//     decoder, every byte written both to it and to the caller's output;
//   * `ContigSink` — the contiguous path: the caller's buffer holds the whole
//     stream from its first byte, so it is the history and nothing else is
//     kept.
//
// Which distances are valid is *not* the sink's business: `LzmaCore::dict_has`
// decides that from the stream position and the declared dictionary size
// alone, so both paths accept and reject the same streams. The sink methods
// taking a distance require `dict_has(distance)`.

trait Sink {
    /// Whether a decode call stops as soon as the output has no room left
    /// (the streaming path: the caller drains and calls again), or only
    /// once a decoded byte actually has nowhere to go (the contiguous path,
    /// where "full" asks the caller to reallocate: a buffer of exactly the
    /// decoded size must be enough to reach the end of the stream).
    const STOP_WHEN_FULL: bool;
    /// The main loop is about to start, with this (effective) dictionary
    /// size.
    fn begin(&mut self, dict_size: usize);
    /// Bytes that can still be written during this call.
    fn room(&self) -> usize;
    /// The byte `distance + 1` positions back (0 = the last byte written).
    fn get(&self, distance: u32) -> u8;
    /// Append one byte. Requires `room() > 0`.
    fn put(&mut self, b: u8);
    /// Append `n` match bytes that do not overlap their source
    /// (`distance + 1 >= n`). Requires `n <= room()`. Returns how many were
    /// copied, which may be fewer than `n` (the caller's per-byte loop does
    /// the rest).
    fn copy_bulk(&mut self, distance: u32, n: usize) -> usize;
    /// Same for a match that overlaps its source (`distance + 1 < n`, e.g.
    /// an RLE-style run).
    fn copy_overlap(&mut self, distance: u32, n: usize) -> usize;
    /// Bytes this sink has allocated for history.
    fn allocated(&self) -> usize;
}

/// Dictionary / sliding window of the streaming path.
///
/// The buffer is grown lazily, as output is produced, up to the declared
/// window size `dict_size` (see `reserve`), so a stream that merely
/// *declares* a large dictionary commits no memory for it. Invariants
/// (the same as the LZMA2 core's):
///   * `dict_pos < dict.len()` whenever a byte is about to be written
///     (`reserve` runs before every write);
///   * `dict_pos` reaches `dict.len()` — the wrap-around — only once
///     `dict.len() == dict_size`, so a wrapped position implies a fully
///     grown buffer and every wrapped read is modulo `dict_size`;
///   * every read is guarded by `LzmaCore::dict_has`, which admits only
///     distances below the bytes produced so far and below `dict_size`,
///     i.e. bytes already written and still in the buffer.
struct Window {
    dict: Vec<u8>,
    dict_size: usize,
    dict_pos: usize,
}

impl Window {
    const fn new() -> Self {
        Self {
            dict: Vec::new(),
            dict_size: 1,
            dict_pos: 0,
        }
    }

    /// Make room for the next `n` dictionary writes. Must be called before
    /// writing; afterwards up to `n` bytes can be put without `dict_pos`
    /// running into the end of a not yet fully grown buffer.
    #[inline]
    fn reserve(&mut self, n: usize) {
        if self.dict.len() < self.dict_size {
            self.grow(n);
        }
    }

    /// Slow path of [`Self::reserve`]: grow the buffer geometrically
    /// (so the zero-fill and copying stay proportional to the bytes
    /// produced), never past `dict_size`.
    #[cold]
    fn grow(&mut self, n: usize) {
        // One spare byte keeps `dict_pos` strictly below `dict.len()` after
        // the `n` writes, so the wrap-around test (`dict_pos >= dict.len()`)
        // can only fire once the buffer has reached `dict_size`.
        let need = self
            .dict_pos
            .saturating_add(n)
            .saturating_add(1)
            .min(self.dict_size);
        let have = self.dict.len();
        if need <= have {
            return;
        }
        let new_len = need
            .max(have.saturating_mul(2))
            .max(DICT_GROW_MIN)
            .min(self.dict_size);
        self.dict.reserve_exact(new_len - have);
        self.dict.resize(new_len, 0);
    }

    /// Index of the byte `distance + 1` positions behind `dict_pos`.
    #[inline(always)]
    fn src(&self, distance: u32) -> usize {
        let dist1 = distance as usize + 1;
        if self.dict_pos >= dist1 {
            self.dict_pos - dist1
        } else {
            self.dict.len() - (dist1 - self.dict_pos)
        }
    }

    /// Step past `n` bytes just written. Wrapping around is the rare case,
    /// kept out of line so that the common one is a predicted branch
    /// rather than a conditional move on the path to the next read.
    #[inline(always)]
    fn advance(&mut self, n: usize) {
        self.dict_pos += n;
        if self.dict_pos >= self.dict.len() {
            self.wrap();
        }
    }

    #[cold]
    #[inline(never)]
    fn wrap(&mut self) {
        self.dict_pos = 0;
    }
}

/// [`Sink`] of the streaming path: the decoder's [`Window`] (held by value
/// for the duration of a call, so the hot loop reaches the dictionary
/// without an extra indirection) plus the caller's output slice.
struct WindowSink<'a> {
    win: Window,
    output: &'a mut [u8],
    written: usize,
}

impl Sink for WindowSink<'_> {
    const STOP_WHEN_FULL: bool = true;

    fn begin(&mut self, dict_size: usize) {
        self.win = Window::new();
        self.win.dict_size = dict_size.max(1);
    }

    #[inline(always)]
    fn room(&self) -> usize {
        self.output.len() - self.written
    }

    #[inline(always)]
    fn get(&self, distance: u32) -> u8 {
        self.win.dict[self.win.src(distance)]
    }

    #[inline(always)]
    fn put(&mut self, b: u8) {
        let win = &mut self.win;
        win.reserve(1);
        win.dict[win.dict_pos] = b;
        win.advance(1);
        self.output[self.written] = b;
        self.written += 1;
    }

    /// Only the part that wraps neither the source nor the destination
    /// range around the circular dictionary is copied.
    #[inline]
    fn copy_bulk(&mut self, distance: u32, n: usize) -> usize {
        let win = &mut self.win;
        win.reserve(n);
        let src = win.src(distance);
        let src_room = win.dict.len() - src;
        let dst_room = win.dict.len() - win.dict_pos;
        let chunk = n.min(src_room).min(dst_room);
        if chunk == 0 {
            return 0;
        }
        self.output[self.written..self.written + chunk]
            .copy_from_slice(&win.dict[src..src + chunk]);
        win.dict.copy_within(src..src + chunk, win.dict_pos);
        self.written += chunk;
        win.advance(chunk);
        chunk
    }

    /// The `distance + 1`-byte source window behind `dict_pos` is
    /// replicated forward via doubling `copy_within` windows so each read
    /// targets bytes written by an earlier window. Only the contiguous
    /// portion that does not wrap the circular dictionary is handled.
    #[inline]
    fn copy_overlap(&mut self, distance: u32, n: usize) -> usize {
        let win = &mut self.win;
        let dist1 = distance as usize + 1;
        // Source window must not wrap: it starts `dist1` bytes behind dict_pos.
        if win.dict_pos < dist1 {
            return 0;
        }
        win.reserve(n);
        let dst = win.dict_pos;
        let src = dst - dist1;
        let dst_room = win.dict.len() - dst;
        let chunk = n.min(dst_room);
        if chunk == 0 {
            return 0;
        }
        let mut filled = dist1.min(chunk);
        win.dict.copy_within(src..src + filled, dst);
        while filled < chunk {
            let take = filled.min(chunk - filled);
            win.dict.copy_within(dst..dst + take, dst + filled);
            filled += take;
        }
        self.output[self.written..self.written + chunk]
            .copy_from_slice(&win.dict[dst..dst + chunk]);
        self.written += chunk;
        win.advance(chunk);
        chunk
    }

    fn allocated(&self) -> usize {
        self.win.dict.capacity()
    }
}

/// [`Sink`] of the contiguous path: `out` is the caller's buffer from the
/// first byte of the stream and `pos` how much of it is decoded, so
/// `out[..pos]` is the whole history. It is rebuilt from the caller's
/// arguments on every call — nothing here outlives a call, so the buffer
/// may move or grow between calls.
struct ContigSink<'a> {
    out: &'a mut [u8],
    pos: usize,
}

impl Sink for ContigSink<'_> {
    const STOP_WHEN_FULL: bool = false;

    fn begin(&mut self, _dict_size: usize) {}

    #[inline(always)]
    fn room(&self) -> usize {
        self.out.len() - self.pos
    }

    #[inline(always)]
    fn get(&self, distance: u32) -> u8 {
        self.out[self.pos - 1 - distance as usize]
    }

    #[inline(always)]
    fn put(&mut self, b: u8) {
        self.out[self.pos] = b;
        self.pos += 1;
    }

    fn copy_bulk(&mut self, distance: u32, n: usize) -> usize {
        let src = self.pos - 1 - distance as usize;
        self.out.copy_within(src..src + n, self.pos);
        self.pos += n;
        n
    }

    fn copy_overlap(&mut self, distance: u32, n: usize) -> usize {
        let dist1 = distance as usize + 1;
        let dst = self.pos;
        let mut filled = dist1.min(n);
        self.out.copy_within(dst - dist1..dst - dist1 + filled, dst);
        while filled < n {
            let take = filled.min(n - filled);
            self.out.copy_within(dst..dst + take, dst + filled);
            filled += take;
        }
        self.pos += n;
        n
    }

    fn allocated(&self) -> usize {
        0
    }
}

// ─── LZMA decoder core ──────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
struct LzmaCore {
    // Parameters from the header. `lc` is needed at runtime for picking the
    // literal probability set; `pb`/`lp` are baked into the masks below.
    lc: u32,
    pos_mask: u32,
    lit_pos_mask: u32,
    /// Uncompressed length, or `None` for "until EOS marker".
    uncompressed_size: Option<u64>,
    /// The declared size (`.lzma` header field or ZIP entry size), when
    /// known. The stream must end at exactly this many bytes, by the
    /// marker or by reaching the size.
    expected_len: Option<u64>,

    /// The stream's dictionary size (at least `MIN_DICT_SIZE`): how far
    /// back a match may reach, whichever [`Sink`] holds the history.
    dict_size: usize,
    /// Total bytes already produced and successfully delivered to the caller.
    output_pos: u64,

    // Probability tables (Vec for `lit` because it scales with lc/lp).
    is_match: Box<[u16; STATES * POS_STATES_MAX]>,
    is_rep: Box<[u16; STATES]>,
    is_rep0: Box<[u16; STATES]>,
    is_rep1: Box<[u16; STATES]>,
    is_rep2: Box<[u16; STATES]>,
    is_rep0_long: Box<[u16; STATES * POS_STATES_MAX]>,
    dist_slot: Box<[u16; DIST_STATES * DIST_SLOTS]>,
    /// Shared probabilities for slot 4..=13, indexed by the running distance
    /// value during reverse-bittree decoding (see LZMA SDK `SpecPos`).
    dist_special: Box<[u16; FULL_DISTANCES]>,
    dist_align: Box<[u16; ALIGN_SIZE]>,
    lit: Vec<u16>, // sized at runtime by lc/lp

    len_coder: LengthCoder,
    rep_len_coder: LengthCoder,

    // LZ state.
    state: usize,
    rep0: u32,
    rep1: u32,
    rep2: u32,
    rep3: u32,

    range: RangeDecoder,

    /// True once we've reached the EOS marker or uncompressed_size.
    finished: bool,
}

impl LzmaCore {
    fn new(lc: u32, lp: u32, pb: u32, dict_size: usize, uncompressed_size: Option<u64>) -> Self {
        let lit_size = (0x300_usize) << (lc + lp);
        let pos_mask = (1u32 << pb).wrapping_sub(1);
        let lit_pos_mask = (1u32 << lp).wrapping_sub(1);
        Self {
            lc,
            pos_mask,
            lit_pos_mask,
            uncompressed_size,
            expected_len: None,
            dict_size: dict_size.max(1),
            output_pos: 0,
            is_match: Box::new([PROB_INIT; STATES * POS_STATES_MAX]),
            is_rep: Box::new([PROB_INIT; STATES]),
            is_rep0: Box::new([PROB_INIT; STATES]),
            is_rep1: Box::new([PROB_INIT; STATES]),
            is_rep2: Box::new([PROB_INIT; STATES]),
            is_rep0_long: Box::new([PROB_INIT; STATES * POS_STATES_MAX]),
            dist_slot: Box::new([PROB_INIT; DIST_STATES * DIST_SLOTS]),
            dist_special: Box::new([PROB_INIT; FULL_DISTANCES]),
            dist_align: Box::new([PROB_INIT; ALIGN_SIZE]),
            lit: vec![PROB_INIT; lit_size],
            len_coder: LengthCoder::new(),
            rep_len_coder: LengthCoder::new(),
            state: 0,
            rep0: 0,
            rep1: 0,
            rep2: 0,
            rep3: 0,
            range: RangeDecoder::new(),
            finished: false,
        }
    }

    /// Whether a match may read at `distance` (0-based): the byte must
    /// belong to this stream and lie within the dictionary. This is the one
    /// validity rule for both sinks, so the windowed and the contiguous
    /// decoder accept and reject exactly the same streams.
    #[inline(always)]
    fn dict_has(&self, distance: u32) -> bool {
        let d = distance as u64;
        d < self.output_pos && d < self.dict_size as u64
    }

    fn pos_state(&self) -> u32 {
        (self.output_pos as u32) & self.pos_mask
    }

    /// Decode one literal byte. The "prev byte" is fetched from the dict at
    /// distance 0 if available; otherwise 0.
    #[inline(always)]
    fn decode_literal<S: Sink>(&mut self, hist: &S, buf: &[u8]) -> Result<u8, Error> {
        let prev_byte = if self.output_pos > 0 {
            hist.get(0)
        } else {
            0u8
        };

        let is_lit = is_literal_state(self.state);
        let match_byte_init: Option<u8> = if !is_lit {
            if !self.dict_has(self.rep0) {
                return Err(Error::Corrupt);
            }
            Some(hist.get(self.rep0))
        } else {
            None
        };

        let lp_state = ((self.output_pos as u32) & self.lit_pos_mask) << self.lc;
        let prev_high = (prev_byte as u32) >> (8 - self.lc);
        let probs_idx = (lp_state + prev_high) as usize * 0x300;
        let probs = &mut self.lit[probs_idx..probs_idx + 0x300];
        // The bits are decoded on a local copy of the range decoder, written
        // back afterwards (also on error): a local's fields stay in
        // registers across the probability updates, whatever this function
        // ends up inlined into.
        let mut rd = self.range.clone();
        let r = literal_bits(&mut rd, probs, match_byte_init, buf);
        self.range = rd;
        r
    }

    /// Decode the distance value given a length. Returns full distance value
    /// (0-based; 0 = previous byte). May return `0xFFFFFFFF` for the EOS
    /// marker.
    #[inline(always)]
    fn decode_distance(&mut self, length: u32, buf: &[u8]) -> Result<u32, Error> {
        let dist_state_idx =
            (length.min(DIST_STATES as u32 + MATCH_LEN_MIN - 1) - MATCH_LEN_MIN) as usize;
        let slot_base = dist_state_idx * DIST_SLOTS;
        let slot = {
            let probs = &mut self.dist_slot[slot_base..slot_base + DIST_SLOTS];
            bittree_decode(&mut self.range, probs, DIST_SLOT_BITS, buf)?
        };

        if slot < DIST_MODEL_START {
            return Ok(slot);
        }

        let num_direct_bits = (slot >> 1) - 1;
        let mut dist = (2 | (slot & 1)) << num_direct_bits;

        if slot < DIST_MODEL_END {
            // Reverse bit-tree using the shared dist_special table,
            // indexed by the running `dist + 1` value (LZMA SDK SpecPos
            // convention). After `num_direct_bits` iterations, the actual
            // distance bits accumulate inside `idx`; subtract `m` to peel
            // off the bittree's "1" prefix and reveal the final distance.
            let mut idx = dist as usize + 1;
            let mut m: u32 = 1;
            for _ in 0..num_direct_bits {
                let bit = self.range.decode_bit(&mut self.dist_special[idx], buf)?;
                if bit == 0 {
                    idx += m as usize;
                    m += m;
                } else {
                    m += m;
                    idx += m as usize;
                }
            }
            dist = (idx as u32) - m;
        } else {
            // Slot >= 14: the high `num_direct_bits - ALIGN_BITS` bits are
            // uniform (no probability model), and only the low 4 align bits
            // use a tiny probability tree. On random/incompressible data
            // this branch is taken on every match — batch the direct bits
            // through `decode_direct_bits_msb` (one tight loop, normalise
            // inline) and then run a specialised 4-bit align decode.
            let direct_count = num_direct_bits - ALIGN_BITS;
            let direct = self.range.decode_direct_bits_msb(direct_count, buf)?;
            dist |= direct << ALIGN_BITS;
            let v = dist_align_reverse_decode(&mut self.range, &mut self.dist_align, buf)?;
            dist |= v;
        }
        Ok(dist)
    }

    /// Attempt to decode one LZMA "packet" (literal or match).
    ///
    /// `at_eof` is `true` when the caller has signalled end-of-input via
    /// `finish`. In that case we attempt the packet even with less than
    /// `REQUIRED_INPUT_MAX` bytes buffered; an actual short read yields
    /// `Error::UnexpectedEnd`.
    fn step<S: Sink>(
        &mut self,
        hist: &S,
        buf: &[u8],
        at_eof: bool,
    ) -> Result<PacketOutcome, Error> {
        let outcome = self.step_inner(hist, buf, at_eof)?;
        // The stream must end at exactly the declared size: no literal or
        // match may run past it, whether or not a marker is required. (So
        // the size caps on match copies in `drain_output` never bind.)
        if let Some(t) = self.expected_len {
            let bad = match outcome {
                PacketOutcome::Eos => self.output_pos != t,
                PacketOutcome::Literal(_) => self.output_pos >= t,
                PacketOutcome::Match { length } => self.output_pos + length as u64 > t,
                PacketOutcome::NeedInput => false,
            };
            if bad {
                return Err(Error::Corrupt);
            }
        }
        Ok(outcome)
    }

    fn step_inner<S: Sink>(
        &mut self,
        hist: &S,
        buf: &[u8],
        at_eof: bool,
    ) -> Result<PacketOutcome, Error> {
        if self.finished {
            return Ok(PacketOutcome::Eos);
        }
        if matches!(self.uncompressed_size, Some(target) if self.output_pos >= target) {
            // Per spec: if size is known, EOS marker is optional. We mark
            // ourselves finished here.
            self.finished = true;
            return Ok(PacketOutcome::Eos);
        }

        // Streaming gate: a single packet consumes at most REQUIRED_INPUT_MAX
        // bytes; require that much input available, otherwise punt.
        let available = buf.len().saturating_sub(self.range.pos);
        if !at_eof && available < REQUIRED_INPUT_MAX {
            return Ok(PacketOutcome::NeedInput);
        }

        let pos_state = self.pos_state();
        let is_match_idx = self.state * POS_STATES_MAX + pos_state as usize;

        let bit = self
            .range
            .decode_bit(&mut self.is_match[is_match_idx], buf)?;

        if bit == 0 {
            // Literal.
            let lit = self.decode_literal(hist, buf)?;
            self.state = state_after_literal(self.state);
            Ok(PacketOutcome::Literal(lit))
        } else {
            self.decode_match(hist, is_match_idx, pos_state, buf)
        }
    }

    /// The rest of a packet that is not a literal: a match, one of the
    /// repeated-distance forms, or the end marker. Kept out of line so that
    /// the literal path of the main loop stays small; everything a match
    /// needs is inlined here.
    #[inline(never)]
    fn decode_match<S: Sink>(
        &mut self,
        hist: &S,
        is_match_idx: usize,
        pos_state: u32,
        buf: &[u8],
    ) -> Result<PacketOutcome, Error> {
        // Match / rep.
        let rep_bit = self.range.decode_bit(&mut self.is_rep[self.state], buf)?;
        if rep_bit == 1 {
            // Some kind of rep.
            let rep0_bit = self.range.decode_bit(&mut self.is_rep0[self.state], buf)?;
            if rep0_bit == 0 {
                // SHORTREP or LONGREP[0]
                let rep0_long_bit = self
                    .range
                    .decode_bit(&mut self.is_rep0_long[is_match_idx], buf)?;
                if rep0_long_bit == 0 {
                    // SHORTREP: emit 1 byte at distance rep0.
                    if !self.dict_has(self.rep0) {
                        return Err(Error::Corrupt);
                    }
                    let b = hist.get(self.rep0);
                    self.state = state_after_short_rep(self.state);
                    return Ok(PacketOutcome::Literal(b));
                }
                // LONGREP[0]: fall through with rep_idx=0
                return self.finish_rep_match(0, pos_state, buf);
            }
            // rep1/2/3
            let r1 = self.range.decode_bit(&mut self.is_rep1[self.state], buf)?;
            let rep_idx = if r1 == 0 {
                1u32
            } else {
                let r2 = self.range.decode_bit(&mut self.is_rep2[self.state], buf)?;
                if r2 == 0 { 2 } else { 3 }
            };
            self.finish_rep_match(rep_idx, pos_state, buf)
        } else {
            // New match.
            let len = self.len_coder.decode(&mut self.range, pos_state, buf)? + MATCH_LEN_MIN;
            let dist = self.decode_distance(len, buf)?;
            if dist == 0xFFFF_FFFF {
                // End of stream marker.
                self.finished = true;
                return Ok(PacketOutcome::Eos);
            }
            self.rep3 = self.rep2;
            self.rep2 = self.rep1;
            self.rep1 = self.rep0;
            self.rep0 = dist;
            self.state = state_after_match(self.state);
            if !self.dict_has(self.rep0) {
                return Err(Error::Corrupt);
            }
            Ok(PacketOutcome::Match { length: len })
        }
    }

    #[inline(always)]
    fn finish_rep_match(
        &mut self,
        rep_idx: u32,
        pos_state: u32,
        buf: &[u8],
    ) -> Result<PacketOutcome, Error> {
        // Reorder rep registers.
        let dist = match rep_idx {
            0 => self.rep0,
            1 => {
                core::mem::swap(&mut self.rep0, &mut self.rep1);
                self.rep0
            }
            2 => {
                let d = self.rep2;
                self.rep2 = self.rep1;
                self.rep1 = self.rep0;
                self.rep0 = d;
                d
            }
            _ => {
                let d = self.rep3;
                self.rep3 = self.rep2;
                self.rep2 = self.rep1;
                self.rep1 = self.rep0;
                self.rep0 = d;
                d
            }
        };
        let len = self.rep_len_coder.decode(&mut self.range, pos_state, buf)? + MATCH_LEN_MIN;
        self.state = state_after_rep(self.state);
        if !self.dict_has(dist) {
            return Err(Error::Corrupt);
        }
        Ok(PacketOutcome::Match { length: len })
    }
}

enum PacketOutcome {
    Literal(u8),
    /// A match of `length` bytes; the dist is in `rep0`.
    Match {
        length: u32,
    },
    Eos,
    NeedInput,
}

// ─── public streaming decoder ───────────────────────────────────────────

#[derive(Default)]
enum HeaderState {
    #[default]
    Empty,
    /// Header parsed, range coder not yet initialised.
    HeaderParsed {
        lc: u32,
        lp: u32,
        pb: u32,
        dict_size: u32,
        uncompressed_size: u64,
    },
    /// Range coder initialised; main loop active.
    Active(Box<LzmaCore>),
    /// Stream finished cleanly.
    Done,
}

/// Streaming LZMA decoder: legacy `.lzma` (alone) streams by default, or
/// ZIP method-14 entry data with [`Decoder::zip`].
///
/// Copies compressed input into a small internal buffer in bounded pieces
/// and decodes one packet at a time; a packet is only attempted once enough
/// input for the largest possible packet is buffered (or `finish` was
/// called).
///
/// When the stream ends inside a [`decode`](crate::Decoder::decode) call
/// the decoder returns `StreamEnd` and leaves the bytes after the stream
/// unconsumed (except for up to 20 bytes taken by earlier calls when the
/// input arrives in very small pieces). Later `decode` calls consume
/// nothing and return `StreamEnd` again.
pub struct Decoder {
    /// Compressed input buffer. Bounded pieces of the caller's input are
    /// appended here and the front prefix is dropped once the range decoder
    /// has moved well past it.
    buf: Vec<u8>,
    /// Pending-output: a match-copy that we couldn't fully drain into the
    /// caller's output buffer on the previous call.
    pending_match: Option<PendingMatch>,
    pending_literal: Option<u8>,
    header_state: HeaderState,
    /// ZIP method-14 framing, set by [`Decoder::zip`]; `None` for `.lzma`.
    zip: Option<ZipParams>,
    /// Buffered bytes the range decoder had not read when the stream ended.
    leftover: usize,
    /// Largest dictionary size a header may declare (already brought into
    /// `MIN_DICT_SIZE..=MAX_DICT_SIZE`).
    max_dict_size: u64,
    /// The header declared a dictionary over `max_dict_size`: every call
    /// returns [`Error::Unsupported`] until `reset`.
    over_limit: bool,
    /// What the dictionary had grown to when the stream ended (it is freed
    /// then); only read by [`Decoder::dict_allocated`].
    dict_at_end: usize,
    /// Which of the two decode paths this stream is on; fixed by the first
    /// call after a reset.
    mode: Mode,
    /// The dictionary of the streaming path. Never allocated on the
    /// contiguous path.
    window: Window,
    /// Contiguous path: bytes written since the last reset, which is what
    /// the caller's `filled` must be.
    contig_filled: usize,
}

/// The decode path a stream is on.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Not fed yet.
    Unset,
    /// [`decode`](crate::Decoder::decode) / [`finish`](crate::Decoder::finish):
    /// history in the decoder's own window.
    Windowed,
    /// [`ContiguousDecoder`]: history in the caller's buffer.
    Contiguous,
}

/// Out-of-band parameters of a ZIP method-14 entry.
#[derive(Clone, Copy)]
struct ZipParams {
    eos_marker: bool,
    uncompressed_len: Option<u64>,
}

/// ZIP entry header: 2 bytes SDK version, 2 bytes LE properties size (5),
/// then the 5 properties bytes.
const ZIP_HEADER_LEN: usize = 9;

/// Bytes of caller input copied into `buf` per step, so `buf` stays small
/// and the bytes past the end of the stream can be handed back unconsumed.
const ABSORB_CHUNK: usize = 4096;

struct PendingMatch {
    /// 0-based LZ distance for this match (already stored in `rep0`).
    distance: u32,
    /// Bytes still to emit.
    remaining: u32,
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder {
    /// Decoder for a legacy `.lzma` (alone) stream with its 13-byte header,
    /// with the default [`DecoderConfig`]: streams declaring a dictionary
    /// larger than [`DEFAULT_MAX_DICT_SIZE`] (64 MiB) are rejected with
    /// [`Error::Unsupported`].
    pub const fn new() -> Self {
        Self::with_config(DecoderConfig::new())
    }

    /// Decoder for a legacy `.lzma` (alone) stream with an explicit
    /// [`DecoderConfig`] (the dictionary size limit).
    pub const fn with_config(config: DecoderConfig) -> Self {
        Self {
            buf: Vec::new(),
            pending_match: None,
            pending_literal: None,
            header_state: HeaderState::Empty,
            zip: None,
            leftover: 0,
            max_dict_size: config.effective_max_dict_size(),
            over_limit: false,
            dict_at_end: 0,
            mode: Mode::Unset,
            window: Window::new(),
            contig_filled: 0,
        }
    }

    /// Set the largest dictionary size a stream's header may declare, as
    /// [`DecoderConfig::max_dict_size`] does; chainable after any
    /// constructor, e.g. `Decoder::zip(false, len).with_max_dict_size(n)`.
    /// A header declaring more is rejected with [`Error::Unsupported`]
    /// (except when decoding through [`ContiguousDecoder`], which has no
    /// dictionary to limit). `reset` keeps the limit.
    ///
    /// Meant for a decoder that has not been fed yet: it does not
    /// reconsider a header that has already been read.
    pub const fn with_max_dict_size(mut self, bytes: u64) -> Self {
        self.max_dict_size = DecoderConfig::with_max_dict_size(bytes).effective_max_dict_size();
        self
    }

    /// The dictionary size limit in effect, in bytes: the configured
    /// [`DecoderConfig::max_dict_size`] brought into
    /// `4 KiB..=`[`MAX_DICT_SIZE`].
    pub const fn max_dict_size(&self) -> u64 {
        self.max_dict_size
    }

    /// Bytes allocated for the dictionary of the current stream so far (it
    /// only grows; once the stream has ended, what it had grown to).
    /// Always 0 for a stream decoded through [`ContiguousDecoder`]. For
    /// tests of the allocation behaviour; not part of the stable API.
    #[doc(hidden)]
    pub fn dict_allocated(&self) -> usize {
        match &self.header_state {
            HeaderState::Active(_) => self.window.dict.capacity(),
            HeaderState::Done => self.dict_at_end,
            _ => 0,
        }
    }

    /// Decoder for the data of a ZIP entry stored with method 14 (LZMA):
    /// a 4-byte header (SDK version, properties size), the 5 LZMA
    /// properties bytes, then the range-coded stream. ZIP headers are not
    /// parsed here; feed the entry's stored bytes.
    ///
    /// `eos_marker` is general-purpose flag bit 1: the stream ends with an
    /// end-of-stream marker. `uncompressed_len` is the entry's size, when
    /// known.
    ///
    /// - marker and size: decode `uncompressed_len` bytes, then require the
    ///   marker.
    /// - size only: stop after `uncompressed_len` bytes (a marker right
    ///   after them is read too).
    /// - marker only, or neither: decode until the marker.
    ///
    /// A marker before the declared size, or data past it (a literal, or a
    /// match that runs over it), is [`Error::Corrupt`]. When the stream ends inside a
    /// [`decode`](crate::Decoder::decode) call the decoder returns
    /// `StreamEnd` and leaves the bytes after the entry unconsumed (except
    /// for up to 20 bytes taken by earlier calls when the input arrives in
    /// very small pieces). `reset` keeps these settings.
    ///
    /// The dictionary size in the entry's properties is checked against the
    /// default [`DecoderConfig`] limit ([`DEFAULT_MAX_DICT_SIZE`]); use
    /// [`zip_with_config`](Self::zip_with_config) or chain
    /// [`with_max_dict_size`](Self::with_max_dict_size) to change it.
    pub const fn zip(eos_marker: bool, uncompressed_len: Option<u64>) -> Self {
        Self::zip_with_config(eos_marker, uncompressed_len, DecoderConfig::new())
    }

    /// Same as [`Decoder::zip`], with an explicit [`DecoderConfig`] (the
    /// dictionary size limit).
    pub const fn zip_with_config(
        eos_marker: bool,
        uncompressed_len: Option<u64>,
        config: DecoderConfig,
    ) -> Self {
        let mut d = Self::with_config(config);
        d.zip = Some(ZipParams {
            eos_marker,
            uncompressed_len,
        });
        d
    }

    /// Same as [`Decoder::zip`], taking the marker flag from a ZIP entry's
    /// general-purpose bit flag word (bit 1; other bits are ignored).
    pub const fn zip_from_gp_flags(gp_flags: u16, uncompressed_len: Option<u64>) -> Self {
        Self::zip(gp_flags & 0b10 != 0, uncompressed_len)
    }

    /// Drop the prefix of `buf` that the range decoder has already consumed,
    /// keeping its `pos` consistent.
    fn compact_buf(&mut self) {
        if let HeaderState::Active(ref mut core) = self.header_state {
            let pos = core.range.pos;
            if pos > 0 {
                self.buf.drain(0..pos);
                core.range.pos = 0;
            }
        }
    }

    /// Parse the header and initialise the range coder from `buf` as far
    /// as the buffered bytes allow. Returns `true` once the main loop can
    /// run (or the stream is already done).
    fn start<S: Sink>(&mut self, sink: &mut S) -> Result<bool, Error> {
        // ── header parsing ────────────────────────────────────────────
        if matches!(self.header_state, HeaderState::Empty) {
            let header_len = if self.zip.is_some() {
                ZIP_HEADER_LEN
            } else {
                13
            };
            if self.buf.len() < header_len {
                return Ok(false);
            }
            // ZIP: bytes 0..2 are the SDK version (informational), 2..4
            // the properties size, which must be 5.
            let p = if self.zip.is_some() {
                if u16::from_le_bytes([self.buf[2], self.buf[3]]) != 5 {
                    return Err(Error::BadHeader);
                }
                4
            } else {
                0
            };
            let props = self.buf[p];
            if props >= 9 * 5 * 5 {
                return Err(Error::BadHeader);
            }
            let lc = (props as u32) % 9;
            let remainder = (props as u32) / 9;
            let lp = remainder % 5;
            let pb = remainder / 5;
            // Enforce the real LZMA constraint lc + lp <= 4 (matching the
            // LZMA2 path in Lzma2Props::parse). Without this bound a 13-byte
            // header with lc=8,lp=4 would size the literal table at
            // 0x300 << 12 ≈ 6.3 MB, an over-allocation from tiny input.
            if lc + lp > 4 {
                return Err(Error::BadHeader);
            }
            let dict_size = u32::from_le_bytes([
                self.buf[p + 1],
                self.buf[p + 2],
                self.buf[p + 3],
                self.buf[p + 4],
            ]);
            let uncompressed_size = if self.zip.is_some() {
                u64::MAX
            } else {
                u64::from_le_bytes([
                    self.buf[5],
                    self.buf[6],
                    self.buf[7],
                    self.buf[8],
                    self.buf[9],
                    self.buf[10],
                    self.buf[11],
                    self.buf[12],
                ])
            };
            // The dictionary is this decoder's memory budget: refuse a
            // stream that asks for more than the caller allowed, rather
            // than decode it with a smaller window and fail on the first
            // match that reaches further back.
            // (The contiguous path allocates no dictionary, so the limit
            // has nothing to bound there and is not applied.)
            if self.mode != Mode::Contiguous && dict_size as u64 > self.max_dict_size {
                self.over_limit = true;
                self.buf = Vec::new();
                return Err(Error::Unsupported);
            }
            self.buf.drain(0..header_len);
            self.header_state = HeaderState::HeaderParsed {
                lc,
                lp,
                pb,
                dict_size,
                uncompressed_size,
            };
        }

        // ── range decoder init ────────────────────────────────────────
        if let HeaderState::HeaderParsed {
            lc,
            lp,
            pb,
            dict_size,
            uncompressed_size,
        } = self.header_state
        {
            // `unc` caps the output; `expected` is the size the stream
            // must end at (ZIP only).
            let (unc, expected) = match self.zip {
                None if uncompressed_size == u64::MAX => (None, None),
                None => (Some(uncompressed_size), Some(uncompressed_size)),
                Some(z) if z.eos_marker => (None, z.uncompressed_len),
                Some(z) => (z.uncompressed_len, z.uncompressed_len),
            };
            // On the streaming path at most `max_dict_size` (checked when
            // the header was parsed), which is an allocatable size; nothing
            // is allocated for it here, the buffer grows with the output.
            // On the contiguous path any 32-bit value, used only to bound
            // match distances.
            let dict_size_eff = (dict_size as u64).max(MIN_DICT_SIZE) as usize;
            let mut core = Box::new(LzmaCore::new(lc, lp, pb, dict_size_eff, unc));
            core.expected_len = expected;
            // Try to initialise; if not enough bytes yet, stay in HeaderParsed.
            if !core.range.init(&self.buf)? {
                return Ok(false);
            }
            sink.begin(dict_size_eff);
            self.header_state = HeaderState::Active(core);
            self.compact_buf();
        }
        Ok(true)
    }

    /// The decode call of both paths and both framings: copies input in
    /// bounded chunks and hands back the bytes the range decoder did not
    /// read when it stops for a full output buffer or at the end of the
    /// stream. Once the stream has ended nothing more is consumed. Returns
    /// the input bytes consumed and whether the stream has ended; what was
    /// written is in the sink.
    fn absorb_decode<S: Sink>(
        &mut self,
        input: &[u8],
        sink: &mut S,
    ) -> Result<(usize, bool), Error> {
        if self.over_limit {
            return Err(Error::Unsupported);
        }
        if matches!(self.header_state, HeaderState::Done) {
            return Ok((0, true));
        }
        let mut taken = 0usize;
        loop {
            let take = (input.len() - taken).min(ABSORB_CHUNK);
            self.buf.extend_from_slice(&input[taken..taken + take]);
            taken += take;
            if self.start(sink)? {
                self.drain_output(sink, false)?;
            }
            let done = matches!(self.header_state, HeaderState::Done);
            let full = (S::STOP_WHEN_FULL && sink.room() == 0)
                || self.pending_literal.is_some()
                || self.pending_match.is_some();
            if !done && !full && taken < input.len() {
                continue;
            }
            // Hand back what the range decoder did not read (only bytes
            // from this call can be returned).
            let unread = match &self.header_state {
                HeaderState::Done => self.leftover,
                HeaderState::Active(core) if full => self.buf.len() - core.range.pos,
                _ => 0,
            };
            let give = unread.min(taken);
            self.buf.truncate(self.buf.len() - give);
            if done {
                self.leftover -= give;
            }
            return Ok((taken - give, done));
        }
    }

    /// The finish call of both paths. Returns whether the stream has ended;
    /// what was written is in the sink.
    fn finish_into<S: Sink>(&mut self, sink: &mut S) -> Result<bool, Error> {
        if self.over_limit {
            return Err(Error::Unsupported);
        }
        let room = sink.room();
        // Drain whatever we can with at_eof=true so the streaming gate is
        // disabled and any genuine short read errors with UnexpectedEnd.
        self.drain_output(sink, true)?;

        match &self.header_state {
            HeaderState::Done => Ok(true),
            HeaderState::Active(core) => {
                let no_pending = self.pending_match.is_none() && self.pending_literal.is_none();
                let target_met = match core.uncompressed_size {
                    Some(t) => core.output_pos >= t,
                    None => core.finished,
                };
                if target_met && no_pending {
                    self.dict_at_end = sink.allocated();
                    self.header_state = HeaderState::Done;
                    Ok(true)
                } else if no_pending && sink.room() == room && room > 0 {
                    // Genuinely stuck: the output buffer had room, no
                    // packet could be decoded, and we have no buffered
                    // bytes to flush. The stream must be truncated.
                    Err(Error::UnexpectedEnd)
                } else {
                    Ok(false)
                }
            }
            _ => Err(Error::UnexpectedEnd),
        }
    }

    /// Whether the stream is on the other decode path than `mode`.
    fn on_other_path(&self, mode: Mode) -> bool {
        self.mode != Mode::Unset && self.mode != mode
    }

    /// Run `f` with the streaming path's sink over `output`; returns its
    /// result and the bytes written.
    #[inline(always)]
    fn with_window<R>(
        &mut self,
        output: &mut [u8],
        f: impl FnOnce(&mut Self, &mut WindowSink<'_>) -> Result<R, Error>,
    ) -> Result<(R, usize), Error> {
        if self.on_other_path(Mode::Windowed) {
            return Err(Error::Unsupported);
        }
        self.mode = Mode::Windowed;
        // The window moves into the sink for the call (a few words, no
        // allocation) and back afterwards.
        let mut sink = WindowSink {
            win: core::mem::replace(&mut self.window, Window::new()),
            output,
            written: 0,
        };
        let r = f(self, &mut sink);
        let written = sink.written;
        // The dictionary is not needed once the stream has ended.
        if !matches!(self.header_state, HeaderState::Done) {
            self.window = sink.win;
        }
        Ok((r?, written))
    }

    /// Same for the contiguous path, after checking the caller's `filled`.
    #[inline(always)]
    fn with_contiguous<R>(
        &mut self,
        output: &mut [u8],
        filled: usize,
        f: impl FnOnce(&mut Self, &mut ContigSink<'_>) -> Result<R, Error>,
    ) -> Result<(R, usize), Error> {
        if self.on_other_path(Mode::Contiguous)
            || filled > output.len()
            || filled != self.contig_filled
        {
            return Err(Error::Unsupported);
        }
        self.mode = Mode::Contiguous;
        let mut sink = ContigSink {
            out: output,
            pos: filled,
        };
        let r = f(self, &mut sink);
        // Kept in step with the core's position even when the call fails,
        // so a later call can never read history that is not there.
        self.contig_filled = sink.pos;
        Ok((r?, sink.pos - filled))
    }
}

impl RawDecoder for Decoder {
    fn raw_decode(&mut self, input: &[u8], output: &mut [u8]) -> Result<RawProgress, Error> {
        let ((consumed, done), written) =
            self.with_window(output, |d, sink| d.absorb_decode(input, sink))?;
        Ok(RawProgress {
            consumed,
            written,
            done,
        })
    }

    fn raw_finish(&mut self, output: &mut [u8]) -> Result<RawProgress, Error> {
        let (done, written) = self.with_window(output, |d, sink| d.finish_into(sink))?;
        Ok(RawProgress {
            consumed: 0,
            written,
            done,
        })
    }

    fn raw_reset(&mut self) {
        self.buf.clear();
        self.pending_match = None;
        self.pending_literal = None;
        self.header_state = HeaderState::Empty;
        self.leftover = 0;
        self.over_limit = false;
        self.dict_at_end = 0;
        self.mode = Mode::Unset;
        self.window = Window::new();
        self.contig_filled = 0;
    }
}

/// Decoding into one buffer that holds the whole result, with no dictionary
/// of the decoder's own: see [`ContiguousDecoder`] for the contract.
///
/// Both the `.lzma` and the ZIP method-14 decoders work this way, and
/// everything about the input side is the same as for
/// [`decode`](crate::Decoder::decode) / [`finish`](crate::Decoder::finish):
/// what is consumed, when `StreamEnd` is reported, the end-marker and
/// declared-size rules, and which streams are rejected with which error.
/// A match may reach back as far as the dictionary size in the header and
/// no further, even though the bytes before that are still in `output`.
///
/// What differs:
///
/// * **No dictionary is allocated**, whatever the header declares; the
///   decoder keeps only its probability tables (tens of kilobytes) and a
///   small input buffer.
/// * **[`max_dict_size`](DecoderConfig::max_dict_size) is not applied.**
///   The limit is a memory budget for the dictionary, and there is none
///   here: a header declaring a 4 GiB dictionary is decoded like any
///   other, at no extra cost. What bounds memory in this mode is the
///   buffer the caller chooses to provide.
/// * A stream is on one path or the other from its first call until
///   [`reset`](crate::Decoder::reset). Calling `decode`, `finish` or
///   [`discard_output`](crate::Decoder::discard_output) on a stream begun
///   with these methods, or the reverse, is [`Error::Unsupported`], as is
///   a `filled` that exceeds `output.len()` or is not the number of bytes
///   these methods have written since the last reset. Such a call changes
///   nothing; the stream can go on with correct calls.
/// * [`Status::OutputFull`] is returned only when a decoded byte has
///   nowhere to go, not as soon as `output` is full: a buffer of exactly
///   the decoded size reaches `StreamEnd` without being grown.
///
/// ```
/// use compcol::lzma::{Decoder, Encoder};
/// use compcol::{ContiguousDecoder, Encoder as _, Status};
///
/// let data = b"hello hello hello hello";
/// let mut enc = Encoder::new();
/// let mut stream = vec![0u8; 256];
/// let (p, _) = enc.encode(data, &mut stream).unwrap();
/// let mut n = p.written;
/// let (p, _) = enc.finish(&mut stream[n..]).unwrap();
/// n += p.written;
///
/// let mut dec = Decoder::new();
/// let mut out = vec![0u8; 8];
/// let (mut filled, mut pos) = (0, 0);
/// let mut end_of_input = false;
/// loop {
///     let (p, status) = if end_of_input {
///         dec.finish_contiguous(&mut out, filled).unwrap()
///     } else {
///         dec.decode_contiguous(&stream[pos..n], &mut out, filled).unwrap()
///     };
///     pos += p.consumed;
///     filled += p.written;
///     match status {
///         Status::StreamEnd => break,
///         // The buffer may be reallocated: only its contents matter.
///         Status::OutputFull => out.resize(out.len() * 2, 0),
///         Status::InputEmpty => end_of_input = true,
///     }
/// }
/// assert_eq!(&out[..filled], data);
/// ```
impl ContiguousDecoder for Decoder {
    fn decode_contiguous(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        filled: usize,
    ) -> Result<(Progress, Status), Error> {
        let ((consumed, done), written) =
            self.with_contiguous(output, filled, |d, sink| d.absorb_decode(input, sink))?;
        // `OutputFull` only when a decoded byte is waiting for room: a
        // buffer that is merely full may be all the stream needs.
        let status = if done {
            Status::StreamEnd
        } else if self.pending_literal.is_some() || self.pending_match.is_some() {
            Status::OutputFull
        } else {
            debug_assert_eq!(consumed, input.len());
            Status::InputEmpty
        };
        Ok((Progress { consumed, written }, status))
    }

    fn finish_contiguous(
        &mut self,
        output: &mut [u8],
        filled: usize,
    ) -> Result<(Progress, Status), Error> {
        let (done, written) =
            self.with_contiguous(output, filled, |d, sink| d.finish_into(sink))?;
        let status = if done {
            Status::StreamEnd
        } else {
            Status::OutputFull
        };
        Ok((
            Progress {
                consumed: 0,
                written,
            },
            status,
        ))
    }
}

/// Emit up to `*remaining` bytes of a match at `distance`, as far as the
/// sink has room and the declared size allows; `*remaining` is what is
/// still owed afterwards.
#[inline(never)]
fn copy_match<S: Sink>(
    core: &mut LzmaCore,
    sink: &mut S,
    distance: u32,
    remaining: &mut u32,
) -> Result<(), Error> {
    if !core.dict_has(distance) {
        return Err(Error::Corrupt);
    }
    let cap_by_size = match core.uncompressed_size {
        Some(t) => (t - core.output_pos) as usize,
        None => usize::MAX,
    };
    let want = (*remaining as usize).min(sink.room()).min(cap_by_size);
    if want > 0 {
        let did = if (distance as usize + 1) >= want {
            // Fast path: non-overlapping bulk copy.
            sink.copy_bulk(distance, want)
        } else {
            // Overlapping run: replicate the source window forward.
            sink.copy_overlap(distance, want)
        };
        core.output_pos += did as u64;
        *remaining -= did as u32;
        if matches!(core.uncompressed_size, Some(t) if core.output_pos >= t) {
            core.finished = true;
            *remaining = 0;
        }
    }
    while *remaining > 0 && sink.room() > 0 {
        if !core.dict_has(distance) {
            return Err(Error::Corrupt);
        }
        let b = sink.get(distance);
        sink.put(b);
        core.output_pos += 1;
        *remaining -= 1;
        // Respect known uncompressed size.
        if matches!(core.uncompressed_size, Some(t) if core.output_pos >= t) {
            core.finished = true;
            *remaining = 0;
            break;
        }
    }
    Ok(())
}

impl Decoder {
    /// Drive the main decode loop, writing to `sink`. Returns Ok when
    /// either the output is full, the stream is done, or we genuinely need
    /// more input.
    ///
    /// `at_eof` enables the "no input gate" mode: packet attempts proceed
    /// even with `< REQUIRED_INPUT_MAX` bytes buffered. Used by `finish`.
    fn drain_output<S: Sink>(&mut self, sink: &mut S, at_eof: bool) -> Result<(), Error> {
        loop {
            // 1) Drain a pending literal first. If output is full, leave it
            //    parked in `pending_literal` and bail — that's all we can do
            //    in this iteration.
            if let Some(b) = self.pending_literal.take() {
                if sink.room() == 0 {
                    self.pending_literal = Some(b);
                    return Ok(());
                }
                if let HeaderState::Active(ref mut core) = self.header_state {
                    sink.put(b);
                    core.output_pos += 1;
                }
                continue;
            }

            // 2) Drain pending match bytes if any.
            if let Some(mut pm) = self.pending_match.take() {
                if let HeaderState::Active(ref mut core) = self.header_state {
                    copy_match(core, sink, pm.distance, &mut pm.remaining)?;
                    if pm.remaining > 0 {
                        // Output buffer is full, but we still owe bytes.
                        self.pending_match = Some(pm);
                        return Ok(());
                    }
                } else {
                    return Err(Error::Corrupt);
                }
                continue;
            }

            // 3) Try to decode the next packet.
            let HeaderState::Active(ref mut core) = self.header_state else {
                return Ok(());
            };

            // Check finished BEFORE trying to step.
            if matches!(core.uncompressed_size, Some(t) if core.output_pos >= t) {
                core.finished = true;
            }
            if core.finished {
                // Read the stream's last byte and check the coder ended
                // cleanly, so consumption is exact.
                match core.range.finish(&self.buf, at_eof)? {
                    None => return Ok(()),
                    Some(true) => {}
                    Some(false) if core.uncompressed_size.is_some() => {
                        // Size reached but the coder has not ended: an
                        // end marker may follow even though the header
                        // (or ZIP flag) did not say so. Read it (anything
                        // else past the size is an error).
                        core.uncompressed_size = None;
                        core.finished = false;
                        continue;
                    }
                    Some(false) => return Err(Error::Corrupt),
                }
                self.leftover = self.buf.len() - core.range.pos;
                self.dict_at_end = sink.allocated();
                self.header_state = HeaderState::Done;
                return Ok(());
            }

            // Compact buf so range.pos doesn't drift indefinitely — but
            // only when the consumed prefix has grown large enough that
            // the memmove cost is amortised (see `COMPACT_THRESHOLD`).
            if core.range.pos >= COMPACT_THRESHOLD {
                let pos_before = core.range.pos;
                self.buf.drain(0..pos_before);
                core.range.pos = 0;
            }

            let outcome = core.step(&*sink, &self.buf, at_eof)?;
            match outcome {
                PacketOutcome::Literal(b) => {
                    // If output is full, park the literal in pending_literal
                    // and return. We mustn't repeat-decode the packet because
                    // the range coder already advanced past it; pending_literal
                    // exists for exactly this case.
                    if sink.room() == 0 {
                        self.pending_literal = Some(b);
                        return Ok(());
                    }
                    sink.put(b);
                    core.output_pos += 1;
                    if matches!(core.uncompressed_size, Some(t) if core.output_pos >= t) {
                        core.finished = true;
                    }
                }
                PacketOutcome::Match { length } => {
                    let mut remaining = length;
                    let distance = core.rep0;
                    copy_match(core, sink, distance, &mut remaining)?;
                    if remaining > 0 {
                        self.pending_match = Some(PendingMatch {
                            distance,
                            remaining,
                        });
                        return Ok(());
                    }
                }
                PacketOutcome::Eos => {
                    // `core.finished` is set; the check above ends it.
                    continue;
                }
                PacketOutcome::NeedInput => {
                    return Ok(());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::{Decoder as _, Encoder as _};

    fn lcg_bytes(n: usize) -> Vec<u8> {
        let mut x = 0x1234_5678u32;
        (0..n)
            .map(|_| {
                x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                (x >> 24) as u8
            })
            .collect()
    }

    fn encode(data: &[u8]) -> Vec<u8> {
        let mut enc = Encoder::with_config(EncoderConfig { level: 0 });
        let mut out = Vec::new();
        let mut buf = vec![0u8; 1 << 16];
        let mut c = 0;
        while c < data.len() {
            let (p, _) = enc.encode(&data[c..], &mut buf).unwrap();
            c += p.consumed;
            out.extend_from_slice(&buf[..p.written]);
        }
        loop {
            let (p, st) = enc.finish(&mut buf).unwrap();
            out.extend_from_slice(&buf[..p.written]);
            if st == Status::StreamEnd {
                return out;
            }
        }
    }

    /// The input buffer must stay small however the input is sliced, and
    /// must not grow once the stream has ended.
    #[test]
    fn input_buffer_stays_bounded() {
        // Length stays under threshold + chunk + one packet; the capacity
        // may be up to double that from `Vec` growth.
        let bound = 2 * (COMPACT_THRESHOLD + 2 * ABSORB_CHUNK);
        let plain = lcg_bytes(600 * 1024);
        let mut stream = encode(&plain);
        assert!(stream.len() > 500 * 1024, "payload must be incompressible");
        let stream_len = stream.len();
        stream.resize(stream_len + (1 << 20), 0x55);

        // Whole input (stream plus 1 MiB of junk) in one slice.
        let mut dec = Decoder::new();
        let mut out = vec![0u8; 1 << 16];
        let mut got = Vec::new();
        let mut c = 0;
        loop {
            let (p, st) = dec.decode(&stream[c..], &mut out).unwrap();
            c += p.consumed;
            got.extend_from_slice(&out[..p.written]);
            assert!(dec.buf.capacity() <= bound, "{}", dec.buf.capacity());
            if st == Status::StreamEnd {
                break;
            }
            assert!(p.consumed + p.written > 0, "stalled");
        }
        assert_eq!(c, stream_len);
        assert!(got == plain);

        // Junk after the end is not absorbed.
        for _ in 0..64 {
            let (p, st) = dec.decode(&[0x55; 65536], &mut out).unwrap();
            assert_eq!((p.consumed, p.written, st), (0, 0, Status::StreamEnd));
            assert!(dec.buf.capacity() <= bound, "{}", dec.buf.capacity());
        }
    }
}
