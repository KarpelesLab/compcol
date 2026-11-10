//! LZMA payload decoder used inside compressed LZMA2 chunks.
//!
//! The state machine here is a trimmed-down adaptation of the `.lzma`
//! decoder in `src/lzma/mod.rs` (range coder + LZ + probability tables).
//! Two changes are needed to make it fit the LZMA2 framing:
//!
//! 1. There is no 13-byte `.lzma` header. Properties (lc/lp/pb) and dict
//!    size arrive out-of-band — via a per-chunk 1-byte properties field
//!    plus the dict size derived from the xz Block Header's filter
//!    properties.
//! 2. Each chunk carries an explicit *uncompressed length*; decoding
//!    stops at exactly that many output bytes (there is no embedded EOS
//!    marker inside a compressed chunk — chunks are framed externally).
//! 3. State and dictionary may persist across chunks subject to the
//!    LZMA2 reset bits (see [`State::reset_state`] /
//!    [`State::reset_dict`]).
//!
//! Adapted from `src/lzma/mod.rs` in this crate; the math (range coder,
//! state transitions, dist/length probability layout) is unchanged.
//!
//! The kernel is written once, generic over where its output goes and its
//! matches come from (the private `History` trait): the decoder's own
//! sliding window, for the streaming `Decoder` calls, or the caller's
//! contiguous output buffer, for the `ContiguousDecoder` ones — in which
//! case there is no window at all. See [`LzmaCore::decode_partial`] and
//! [`LzmaCore::decode_contiguous`].

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;

// ─── test instrumentation ────────────────────────────────────────────────
//
// Allocation counters for the regression tests guarding against a crafted
// stream making the decoder rebuild or re-zero its dictionary over and over.
// Per thread, so concurrently running tests do not disturb each other.

#[cfg(test)]
pub(crate) mod test_stats {
    extern crate std;

    use core::cell::Cell;

    std::thread_local! {
        /// `LzmaCore`s constructed on this thread.
        static CORES_BUILT: Cell<u64> = const { Cell::new(0) };
        /// Dictionary bytes allocated (and zero-filled) on this thread.
        static DICT_BYTES: Cell<u64> = const { Cell::new(0) };
    }

    pub(crate) fn reset() {
        CORES_BUILT.with(|c| c.set(0));
        DICT_BYTES.with(|c| c.set(0));
    }

    pub(crate) fn cores_built() -> u64 {
        CORES_BUILT.with(|c| c.get())
    }

    pub(crate) fn dict_bytes() -> u64 {
        DICT_BYTES.with(|c| c.get())
    }

    pub(super) fn add_core() {
        CORES_BUILT.with(|c| c.set(c.get() + 1));
    }

    pub(super) fn add_dict_bytes(n: usize) {
        DICT_BYTES.with(|c| c.set(c.get() + n as u64));
    }
}

// ─── LZMA constants (copied from src/lzma/mod.rs) ────────────────────────

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

/// Default limit on the dictionary a stream may declare for the decoders
/// that keep a window ([`crate::xz`], [`crate::lzma2`]): 128 MiB.
pub const DEFAULT_MAX_DICT_SIZE: u64 = 128 * 1024 * 1024;

/// Largest dictionary such a limit can allow: what the LZMA2 dictionary
/// size property can express (4 GiB − 1), or the largest allocation the
/// target supports if that is smaller (2 GiB − 1 on 32-bit targets).
pub const MAX_DICT_SIZE: u64 = if (isize::MAX as u64) < u32::MAX as u64 {
    isize::MAX as u64
} else {
    u32::MAX as u64
};

/// Smallest LZMA2 dictionary; a stream (or a limit) asking for less is
/// treated as asking for this.
pub const MIN_DICT_SIZE: u64 = 4096;

/// A configured dictionary-size limit brought into
/// `MIN_DICT_SIZE..=MAX_DICT_SIZE`.
pub const fn effective_max_dict_size(bytes: u64) -> u64 {
    if bytes < MIN_DICT_SIZE {
        MIN_DICT_SIZE
    } else if bytes > MAX_DICT_SIZE {
        MAX_DICT_SIZE
    } else {
        bytes
    }
}

/// Smallest step the lazily grown dictionary buffer is extended by.
const DICT_GROW_MIN: usize = 4096;

// ─── state transition helpers (copied from src/lzma/mod.rs) ──────────────

const fn state_after_literal(s: usize) -> usize {
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

// ─── range decoder ────────────────────────────────────────────────────────
//
// LZMA's range decoder reads big-endian bytes from a forward buffer.
// `pos` is our cursor inside that buffer. After init we hold the running
// `range`/`code` pair until normalisation needs another byte.

#[derive(Clone)]
struct RangeDecoder {
    range: u32,
    code: u32,
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

    /// Initialise from the first 5 bytes at the current `pos`. First byte
    /// must be zero per the LZMA spec.
    fn init(&mut self, buf: &[u8]) -> Result<(), Error> {
        if buf.len() < self.pos + 5 {
            return Err(Error::UnexpectedEnd);
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
        Ok(())
    }

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

    /// Decode `count` direct (uniform) bits in a tight loop and return their
    /// accumulated value, **MSB-first** — the first decoded bit becomes the
    /// highest position of the result. This matches the MSB-first emission
    /// convention of `src/xz/lzma2_encoder.rs::encode_direct_bits` and the
    /// per-bit accumulation `direct = (direct << 1) | bit` used previously
    /// in this file's `decode_distance`.
    ///
    /// This is the hot path for slot >= 14 on random / incompressible data.
    /// Inlining normalisation into the loop avoids per-bit function-call
    /// overhead and lets the optimiser keep `range`/`code`/`pos` in
    /// registers across iterations.
    #[inline(always)]
    fn decode_direct_bits_msb(&mut self, count: u32, buf: &[u8]) -> Result<u32, Error> {
        let mut range = self.range;
        let mut code = self.code;
        let mut pos = self.pos;
        let buf_len = buf.len();
        let mut result: u32 = 0;
        for _ in 0..count {
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
            let t = code.wrapping_sub(range);
            let mask = (t as i32 >> 31) as u32; // all-ones when code < range
            // bit = 1 if code >= range (mask == 0); subtract `range` from code in that case.
            code = (code & mask) | (t & !mask);
            let bit = (!mask) & 1;
            result = (result << 1) | bit;
        }
        self.range = range;
        self.code = code;
        self.pos = pos;
        Ok(result)
    }
}

// ─── bit-tree helpers ─────────────────────────────────────────────────────

#[inline]
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

/// Specialised 4-bit reverse bit-tree for the dist-align table; the index
/// array is fixed-size so the optimiser can elide bounds checks.
#[inline(always)]
fn dist_align_reverse_decode(
    rd: &mut RangeDecoder,
    probs: &mut [u16; ALIGN_SIZE],
    buf: &[u8],
) -> Result<u32, Error> {
    let mut idx: usize = 1;
    let mut result: u32 = 0;
    let bit = rd.decode_bit(&mut probs[idx], buf)?;
    idx = (idx << 1) | bit as usize;
    result |= bit;
    let bit = rd.decode_bit(&mut probs[idx], buf)?;
    idx = (idx << 1) | bit as usize;
    result |= bit << 1;
    let bit = rd.decode_bit(&mut probs[idx], buf)?;
    idx = (idx << 1) | bit as usize;
    result |= bit << 2;
    let bit = rd.decode_bit(&mut probs[idx], buf)?;
    let _ = idx;
    result |= bit << 3;
    Ok(result)
}

// ─── length decoder ───────────────────────────────────────────────────────

struct LengthCoder {
    choice: u16,
    choice2: u16,
    low: Vec<u16>,
    mid: Vec<u16>,
    high: Vec<u16>,
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

    fn reset(&mut self) {
        self.choice = PROB_INIT;
        self.choice2 = PROB_INIT;
        for p in self.low.iter_mut() {
            *p = PROB_INIT;
        }
        for p in self.mid.iter_mut() {
            *p = PROB_INIT;
        }
        for p in self.high.iter_mut() {
            *p = PROB_INIT;
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

// ─── output convention ────────────────────────────────────────────────────

/// Which of its two output conventions a decoder is being driven with: the
/// streaming one ([`Decoder::decode`](crate::Decoder::decode) /
/// [`finish`](crate::Decoder::finish), the caller takes the bytes away and
/// the decoder keeps a window) or the contiguous one
/// ([`ContiguousDecoder`](crate::ContiguousDecoder), the caller's buffer is
/// the history). A stream is decoded with one of them from start to end;
/// this is what notices a mix, and a `filled` that is not what the decoder
/// wrote.
///
/// Misuse is reported as [`Error::Unsupported`] and changes nothing: the
/// decoder can go on being used correctly.
#[derive(Clone, Copy, Debug, Default)]
pub struct OutputMode {
    contiguous: Option<bool>,
    /// Bytes written by the contiguous calls since the last reset.
    written: usize,
}

impl OutputMode {
    /// A streaming call (`decode`, `finish`) is being made.
    pub fn enter_streaming(&mut self) -> Result<(), Error> {
        if self.contiguous == Some(true) {
            return Err(Error::Unsupported);
        }
        self.contiguous = Some(false);
        Ok(())
    }

    /// A contiguous call is being made with a buffer of `output_len` bytes
    /// of which the caller says `filled` are written.
    pub fn enter_contiguous(&mut self, output_len: usize, filled: usize) -> Result<(), Error> {
        if self.contiguous == Some(false) || filled > output_len || filled != self.written {
            return Err(Error::Unsupported);
        }
        self.contiguous = Some(true);
        Ok(())
    }

    /// Whether the stream is being decoded into a contiguous buffer.
    pub fn is_contiguous(&self) -> bool {
        self.contiguous == Some(true)
    }

    /// A contiguous call wrote `n` more bytes.
    pub fn advance(&mut self, n: usize) {
        self.written += n;
    }
}

// ─── history: where decoded bytes go and matches come from ───────────────

/// What the LZMA kernel needs from the place its output goes: the bytes
/// already decoded (for the literal context, the match byte and match
/// copies) and somewhere to put new ones. Two implementations exist and the
/// kernel is monomorphised over them, so neither pays for the other:
///
/// * [`WindowSink`] — the decoder's own sliding window (a lazily grown ring
///   of at most the dictionary size) plus the chunk's output buffer;
/// * [`ContiguousSink`] — the caller's whole output buffer, which already
///   holds every byte a match may refer to, so no window exists at all.
///
/// Both answer [`History::has`] identically — a distance is valid when it
/// is below both the number of bytes decoded since the last dictionary
/// reset and the dictionary size — so the two modes accept and reject
/// exactly the same streams.
trait History {
    /// Bytes decoded since the last dictionary reset (the low 32 bits: only
    /// the `pb`/`lp` low bits are used).
    fn position(&self) -> u32;
    /// The byte before the next one to be written, `0` right after a
    /// dictionary reset.
    fn prev_byte(&self) -> u8;
    /// Whether a match at `distance` (0 = the previous byte) stays within
    /// the history.
    fn has(&self, distance: u32) -> bool;
    /// The byte `distance + 1` back. Requires `has(distance)`.
    fn get(&self, distance: u32) -> u8;
    /// How many bytes can be written before this call has to stop.
    fn room(&self) -> usize;
    /// How many bytes the chunk being decoded still has to produce (at
    /// least `room()`); a match longer than this is malformed.
    fn chunk_left(&self) -> usize;
    /// Append one byte. Requires `room() > 0`.
    fn put(&mut self, b: u8);
    /// Append `n` bytes of a match at `distance`. Requires `has(distance)`
    /// and `n <= room()`.
    fn copy_match(&mut self, distance: u32, n: usize) -> Result<(), Error>;
}

/// The sliding window of the streaming mode: decoded bytes are written here
/// in wrap-around order so that match back-references can be satisfied
/// after the caller has taken the output away.
///
/// The buffer is grown with the bytes actually produced, up to the
/// declared window size `dict_size` (see `reserve`), so a stream
/// that merely *declares* a large dictionary commits no memory for it.
/// Invariants the indexing below relies on:
///   * `dict_pos < dict.len()` whenever a byte is about to be written
///     (`reserve` runs before every batch of writes);
///   * `dict_pos` reaches `dict.len()` — the wrap-around — only once
///     `dict.len() == dict_size`, so `dict_full` implies a fully grown
///     buffer and every wrapped read is modulo `dict_size`;
///   * only bytes written since the last dictionary reset are ever read:
///     each read is guarded by `has`, which without `dict_full`
///     admits only distances below `dict_pos`. Bytes left over from
///     before a reset (the buffer is neither cleared nor shrunk) are
///     therefore unreachable.
///
/// In contiguous mode (see [`LzmaCore::decode_contiguous`]) `dict` stays
/// empty: only `dict_size` (the distance bound) and `output_pos` (how far
/// back the current dictionary reaches) are used.
struct Window {
    dict: Vec<u8>,
    dict_size: usize,
    dict_pos: usize,
    dict_full: bool,
    /// Bytes decoded since the last dictionary reset.
    output_pos: u64,
}

impl Window {
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
        #[cfg(test)]
        test_stats::add_dict_bytes(new_len - have);
        self.dict.reserve_exact(new_len - have);
        self.dict.resize(new_len, 0);
    }

    #[inline]
    fn get(&self, distance: u32) -> u8 {
        let dist1 = distance as usize + 1;
        let pos = if self.dict_pos >= dist1 {
            self.dict_pos - dist1
        } else {
            self.dict.len() - (dist1 - self.dict_pos)
        };
        self.dict[pos]
    }

    #[inline]
    fn put(&mut self, b: u8) {
        self.dict[self.dict_pos] = b;
        self.dict_pos += 1;
        if self.dict_pos >= self.dict.len() {
            self.dict_pos = 0;
            self.dict_full = true;
        }
        self.output_pos += 1;
    }

    #[inline]
    fn has(&self, distance: u32) -> bool {
        let n = if self.dict_full {
            self.dict.len()
        } else {
            self.dict_pos
        };
        (distance as usize) < n
    }

    /// Bulk-copy up to `n` non-overlapping match bytes (requires
    /// `distance + 1 >= n`) from the dictionary into both `out[*written..]`
    /// and back into the dict. Returns the number of bytes copied; may be
    /// less than `n` when the source or destination range wraps the circular
    /// dict, in which case the caller falls back to the per-byte loop for
    /// the remainder. Caller must guarantee `has(distance)` and that
    /// `out` has at least `n` bytes of room from `*written`.
    #[inline]
    fn copy_match_bulk(
        &mut self,
        distance: u32,
        n: usize,
        out: &mut [u8],
        written: &mut usize,
    ) -> usize {
        let dist1 = distance as usize + 1;
        let src = if self.dict_pos >= dist1 {
            self.dict_pos - dist1
        } else {
            self.dict.len() - (dist1 - self.dict_pos)
        };
        let src_room = self.dict.len() - src;
        let dst_room = self.dict.len() - self.dict_pos;
        let chunk = n.min(src_room).min(dst_room);
        if chunk == 0 {
            return 0;
        }
        out[*written..*written + chunk].copy_from_slice(&self.dict[src..src + chunk]);
        self.dict.copy_within(src..src + chunk, self.dict_pos);
        *written += chunk;
        self.dict_pos += chunk;
        if self.dict_pos >= self.dict.len() {
            self.dict_pos = 0;
            self.dict_full = true;
        }
        self.output_pos += chunk as u64;
        chunk
    }

    /// Bulk-copy up to `n` *overlapping* match bytes (`distance + 1 < n`)
    /// from the dictionary into both `out[*written..]` and the dict. The
    /// source window `[src, dict_pos)` is `dist1` bytes long and is repeated
    /// forward to fill the run; we extend it by `copy_within` in growing
    /// windows so each byte read was already written in a previous window.
    /// Only the contiguous portion that neither wraps the circular dict nor
    /// overruns is handled here; the caller's per-byte loop covers the rest.
    /// Returns the number of bytes copied. Caller must guarantee
    /// `has(distance)` and `out` room for `n` bytes from `*written`.
    #[inline]
    fn copy_match_overlap(
        &mut self,
        distance: u32,
        n: usize,
        out: &mut [u8],
        written: &mut usize,
    ) -> usize {
        let dist1 = distance as usize + 1;
        // Source must not wrap: it begins `dist1` bytes behind dict_pos.
        if self.dict_pos < dist1 {
            return 0;
        }
        let dst = self.dict_pos;
        let src = dst - dist1;
        // Destination must not wrap during the whole run.
        let dst_room = self.dict.len() - dst;
        let chunk = n.min(dst_room);
        if chunk == 0 {
            return 0;
        }
        // Self-overlapping forward fill: copy in doubling windows so each
        // read targets bytes written by an earlier iteration.
        let mut filled = dist1.min(chunk);
        self.dict.copy_within(src..src + filled, dst);
        while filled < chunk {
            let take = filled.min(chunk - filled);
            self.dict.copy_within(dst..dst + take, dst + filled);
            filled += take;
        }
        out[*written..*written + chunk].copy_from_slice(&self.dict[dst..dst + chunk]);
        *written += chunk;
        self.dict_pos += chunk;
        if self.dict_pos >= self.dict.len() {
            self.dict_pos = 0;
            self.dict_full = true;
        }
        self.output_pos += chunk as u64;
        chunk
    }
}

/// [`History`] of the streaming mode: the [`Window`] plus `out`, the whole
/// output of the chunk being decoded, of which `written` bytes are done.
/// Every byte goes to both.
struct WindowSink<'a> {
    win: &'a mut Window,
    out: &'a mut [u8],
    written: usize,
}

impl History for WindowSink<'_> {
    #[inline(always)]
    fn position(&self) -> u32 {
        self.win.output_pos as u32
    }

    #[inline(always)]
    fn prev_byte(&self) -> u8 {
        if self.win.dict_full || self.win.dict_pos > 0 {
            self.win.get(0)
        } else {
            0u8
        }
    }

    #[inline(always)]
    fn has(&self, distance: u32) -> bool {
        self.win.has(distance)
    }

    #[inline(always)]
    fn get(&self, distance: u32) -> u8 {
        self.win.get(distance)
    }

    #[inline(always)]
    fn room(&self) -> usize {
        self.out.len() - self.written
    }

    #[inline(always)]
    fn chunk_left(&self) -> usize {
        self.out.len() - self.written
    }

    #[inline(always)]
    fn put(&mut self, b: u8) {
        self.win.put(b);
        self.out[self.written] = b;
        self.written += 1;
    }

    #[inline(always)]
    fn copy_match(&mut self, distance: u32, n: usize) -> Result<(), Error> {
        let mut remaining = n;
        // Fast path: when the match is non-overlapping
        // (distance + 1 >= remaining) the source bytes already
        // exist contiguously behind `dict_pos`, so we can bulk
        // `copy_from_slice` / `copy_within` instead of stepping
        // byte by byte. `copy_match_bulk` copies as much as
        // it can without crossing the circular dict boundary and
        // returns the count; the per-byte loop handles any
        // wrapped remainder and the overlapping case.
        if distance as usize + 1 >= remaining {
            let did = self
                .win
                .copy_match_bulk(distance, remaining, self.out, &mut self.written);
            remaining -= did;
        } else {
            // Overlapping run (e.g. RLE-style fills): replicate
            // the source window forward in bulk.
            let did = self
                .win
                .copy_match_overlap(distance, remaining, self.out, &mut self.written);
            remaining -= did;
        }
        while remaining > 0 {
            if !self.win.has(distance) {
                return Err(Error::Corrupt);
            }
            let b = self.win.get(distance);
            self.win.put(b);
            self.out[self.written] = b;
            self.written += 1;
            remaining -= 1;
        }
        Ok(())
    }
}

/// [`History`] of the contiguous mode: `out` is the caller's buffer holding
/// the decoded stream from its first byte, `pos` the next byte to write.
/// History is `out[floor..pos]` — `floor` being where the last dictionary
/// reset happened — further limited to the last `dict_size` bytes, exactly
/// what the [`Window`] would still hold.
///
/// Built afresh for every call from absolute positions, so nothing here
/// depends on the buffer being at the same address (or of the same length)
/// as on the previous call.
struct ContiguousSink<'a> {
    out: &'a mut [u8],
    pos: usize,
    /// Absolute position of the last dictionary reset: no match may reach
    /// before it.
    floor: usize,
    dict_size: usize,
    /// Where this call must stop writing: the end of the chunk or of `out`,
    /// whichever comes first.
    limit: usize,
    /// Absolute position at which the chunk being decoded ends.
    chunk_end: usize,
}

impl History for ContiguousSink<'_> {
    #[inline(always)]
    fn position(&self) -> u32 {
        (self.pos - self.floor) as u32
    }

    #[inline(always)]
    fn prev_byte(&self) -> u8 {
        if self.pos > self.floor {
            self.out[self.pos - 1]
        } else {
            0u8
        }
    }

    #[inline(always)]
    fn has(&self, distance: u32) -> bool {
        (distance as usize) < (self.pos - self.floor).min(self.dict_size)
    }

    #[inline(always)]
    fn get(&self, distance: u32) -> u8 {
        self.out[self.pos - 1 - distance as usize]
    }

    #[inline(always)]
    fn room(&self) -> usize {
        self.limit - self.pos
    }

    #[inline(always)]
    fn chunk_left(&self) -> usize {
        self.chunk_end - self.pos
    }

    #[inline(always)]
    fn put(&mut self, b: u8) {
        self.out[self.pos] = b;
        self.pos += 1;
    }

    #[inline(always)]
    fn copy_match(&mut self, distance: u32, n: usize) -> Result<(), Error> {
        let dist1 = distance as usize + 1;
        let dst = self.pos;
        let src = dst - dist1;
        if dist1 >= n {
            // Source and destination do not overlap.
            self.out.copy_within(src..src + n, dst);
        } else {
            // Overlapping run: the `dist1` bytes before `dst` repeat. Copy
            // in doubling windows so each read targets bytes already
            // written.
            let mut filled = dist1;
            self.out.copy_within(src..dst, dst);
            while filled < n {
                let take = filled.min(n - filled);
                self.out.copy_within(dst..dst + take, dst + filled);
                filled += take;
            }
        }
        self.pos += n;
        Ok(())
    }
}

// ─── LZMA core, tuned for LZMA2 framing ──────────────────────────────────

/// Outcome of a single LZMA "packet" (literal, match, rep).
enum PacketOutcome {
    Literal(u8),
    Match { length: u32 },
}

/// Parsed LZMA properties: lc, lp, pb.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lzma2Props {
    pub lc: u32,
    pub lp: u32,
    pub pb: u32,
}

impl Lzma2Props {
    /// Decode a single LZMA2 properties byte into `lc/lp/pb`.
    ///
    /// The byte encodes `(pb * 5 + lp) * 9 + lc` with the constraint
    /// `lc + lp <= 4`.
    pub fn parse(byte: u8) -> Result<Self, Error> {
        if byte >= 9 * 5 * 5 {
            return Err(Error::Corrupt);
        }
        let lc = (byte as u32) % 9;
        let r = (byte as u32) / 9;
        let lp = r % 5;
        let pb = r / 5;
        if lc + lp > 4 {
            return Err(Error::Corrupt);
        }
        Ok(Self { lc, lp, pb })
    }
}

/// The LZMA model: properties, probability tables, LZ state and the range
/// coder — everything but the history, which the decoding methods take as
/// a [`History`].
struct Model {
    lc: u32,
    pos_mask: u32,
    lit_pos_mask: u32,

    // Probability tables.
    is_match: Box<[u16; STATES * POS_STATES_MAX]>,
    is_rep: Box<[u16; STATES]>,
    is_rep0: Box<[u16; STATES]>,
    is_rep1: Box<[u16; STATES]>,
    is_rep2: Box<[u16; STATES]>,
    is_rep0_long: Box<[u16; STATES * POS_STATES_MAX]>,
    dist_slot: Box<[u16; DIST_STATES * DIST_SLOTS]>,
    dist_special: Box<[u16; FULL_DISTANCES]>,
    dist_align: Box<[u16; ALIGN_SIZE]>,
    lit: Vec<u16>,

    len_coder: LengthCoder,
    rep_len_coder: LengthCoder,

    state: usize,
    rep0: u32,
    rep1: u32,
    rep2: u32,
    rep3: u32,

    /// Bytes of the last decoded match (at distance `rep0`) still to be
    /// written: a match cut by the end of the caller's buffer in contiguous
    /// mode, finished first thing on the next call. Always zero in the
    /// streaming mode, whose chunk buffer takes every match whole.
    pending_len: u32,

    range: RangeDecoder,
}

/// LZMA decoder kernel parametrised at construction time by `lc/lp/pb`
/// and a dictionary size; reused across LZMA2 chunks via the various
/// `reset_*` methods.
///
/// It decodes in one of two modes, chosen by which method is called (and
/// not to be mixed between dictionary resets): into its own sliding window
/// ([`Self::decode_partial`], [`Self::append_literals`]) or straight into
/// the caller's contiguous output ([`Self::decode_contiguous`],
/// [`Self::append_contiguous`]), in which case no window is allocated.
pub struct LzmaCore {
    model: Model,
    win: Window,
}

impl LzmaCore {
    pub fn new(props: Lzma2Props, dict_size: usize) -> Self {
        let lit_size = (0x300_usize) << (props.lc + props.lp);
        let pos_mask = (1u32 << props.pb).wrapping_sub(1);
        let lit_pos_mask = (1u32 << props.lp).wrapping_sub(1);
        #[cfg(test)]
        test_stats::add_core();
        Self {
            model: Model {
                lc: props.lc,
                pos_mask,
                lit_pos_mask,
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
                pending_len: 0,
                range: RangeDecoder::new(),
            },
            win: Window {
                dict: Vec::new(),
                dict_size: dict_size.max(1),
                dict_pos: 0,
                dict_full: false,
                output_pos: 0,
            },
        }
    }

    /// Replace the props (lc/lp/pb). Reallocates the literal table if
    /// `lc + lp` changed. Caller must follow with `reset_state` for the
    /// new probability tables to be initialised.
    pub fn replace_props(&mut self, props: Lzma2Props) {
        let m = &mut self.model;
        m.lc = props.lc;
        m.pos_mask = (1u32 << props.pb).wrapping_sub(1);
        m.lit_pos_mask = (1u32 << props.lp).wrapping_sub(1);
        let lit_size = (0x300_usize) << (props.lc + props.lp);
        if m.lit.len() != lit_size {
            m.lit = vec![PROB_INIT; lit_size];
        }
    }

    /// The window size this core was built for (not how much of it is
    /// allocated so far), so the caller can reuse this core for a
    /// dictionary-reset chunk instead of allocating a fresh `LzmaCore`.
    pub fn dict_capacity(&self) -> usize {
        self.win.dict_size
    }

    /// Forget the dictionary contents (an LZMA2 dictionary reset) without
    /// touching the allocation, the properties or the probability state.
    /// Nothing written before the reset can be read afterwards: see the
    /// invariants on [`Window`]. In contiguous mode this is what moves the
    /// history floor up to the current output position.
    pub fn reset_dict(&mut self) {
        self.win.dict_pos = 0;
        self.win.dict_full = false;
        self.win.output_pos = 0;
    }

    /// Give back the sliding window's memory, if any was allocated. For a
    /// caller that, right after a dictionary reset, goes on in contiguous
    /// mode with a core that an earlier part of the stream used with a
    /// window.
    ///
    /// Used by the [`crate::xz`] decoder; dead under an lzma2-only build.
    #[cfg_attr(not(any(feature = "xz", test)), allow(dead_code))]
    pub fn release_window(&mut self) {
        if self.win.dict.capacity() != 0 {
            self.win.dict = Vec::new();
            self.win.dict_pos = 0;
            self.win.dict_full = false;
        }
    }

    /// How many bytes of sliding window are allocated right now.
    #[cfg(test)]
    pub(crate) fn window_allocated(&self) -> usize {
        self.win.dict.capacity()
    }

    /// Perform a "full reset" equivalent to constructing a new `LzmaCore`
    /// with the given props, but reuse the existing dictionary allocation
    /// (and the probability/literal table allocations where their sizes
    /// match). The dictionary contents are cleared and the LZ window
    /// position reset to zero. Caller must follow with `init_range` to
    /// re-bind the range coder to the next chunk's payload.
    pub fn reset_full(&mut self, props: Lzma2Props) {
        self.replace_props(props);
        self.reset_dict();
        self.reset_state();
    }

    /// Reset all probability tables and the LZ state, but keep the
    /// dictionary contents.
    pub fn reset_state(&mut self) {
        let m = &mut self.model;
        for p in m.is_match.iter_mut() {
            *p = PROB_INIT;
        }
        for p in m.is_rep.iter_mut() {
            *p = PROB_INIT;
        }
        for p in m.is_rep0.iter_mut() {
            *p = PROB_INIT;
        }
        for p in m.is_rep1.iter_mut() {
            *p = PROB_INIT;
        }
        for p in m.is_rep2.iter_mut() {
            *p = PROB_INIT;
        }
        for p in m.is_rep0_long.iter_mut() {
            *p = PROB_INIT;
        }
        for p in m.dist_slot.iter_mut() {
            *p = PROB_INIT;
        }
        for p in m.dist_special.iter_mut() {
            *p = PROB_INIT;
        }
        for p in m.dist_align.iter_mut() {
            *p = PROB_INIT;
        }
        for p in m.lit.iter_mut() {
            *p = PROB_INIT;
        }
        m.len_coder.reset();
        m.rep_len_coder.reset();
        m.state = 0;
        m.rep0 = 0;
        m.rep1 = 0;
        m.rep2 = 0;
        m.rep3 = 0;
        m.pending_len = 0;
    }

    /// Re-initialise the range coder against a freshly-buffered chunk.
    /// Expects `buf[0..5]` to be the LZMA range-coder init sequence
    /// (the spec mandates the first byte is `0x00`).
    pub fn init_range(&mut self, buf: &[u8]) -> Result<(), Error> {
        self.model.range = RangeDecoder::new();
        self.model.range.init(buf)
    }

    /// Feed already-known literal bytes (e.g. from an LZMA2 *uncompressed*
    /// chunk) into the LZ window so a later compressed chunk that does not
    /// reset the dictionary can back-reference them. Does not emit output.
    pub fn append_literals(&mut self, bytes: &[u8]) {
        self.win.reserve(bytes.len());
        for &b in bytes {
            self.win.put(b);
        }
    }

    /// The contiguous-mode counterpart of [`Self::append_literals`]: the
    /// caller has written `n` bytes of an uncompressed chunk to the
    /// contiguous output itself, where they now are history like any
    /// decoded byte.
    pub fn append_contiguous(&mut self, n: usize) {
        self.win.output_pos += n as u64;
    }

    /// Decode exactly `uncomp_size` bytes from `buf` (whose first 5 bytes
    /// were already consumed by `init_range`) into `out`. The output buffer
    /// must be sized to hold the chunk's `uncomp_size` bytes.
    ///
    /// `buf` must be the chunk's whole compressed payload: on success the
    /// range coder has been checked to end exactly there (see
    /// [`Self::finish_chunk`]).
    ///
    /// Used by the raw [`crate::lzma2`] decoder; dead under an xz-only build.
    #[cfg_attr(not(any(feature = "lzma2", test)), allow(dead_code))]
    pub fn decode_chunk(&mut self, buf: &[u8], out: &mut [u8]) -> Result<(), Error> {
        let mut written = 0usize;
        self.decode_partial(buf, out, &mut written, 0)?;
        self.finish_chunk(buf)
    }

    /// Check that the range coder ended exactly at the end of the chunk's
    /// compressed payload `buf`, to be called once all of the chunk's
    /// output has been decoded. Returns `Error::Corrupt` otherwise.
    ///
    /// This is liblzma's rule for an LZMA2 chunk: after the last symbol the
    /// decoder normalises once more (the encoder already shifted out the
    /// byte for it), and then `code` must be zero (`rc_is_finished`) and
    /// the chunk's Compressed Size used up to the byte. A range encoder
    /// flushing its 5 final bytes always ends this way; anything else is
    /// either damage or bytes smuggled in behind the LZMA data.
    pub fn finish_chunk(&mut self, buf: &[u8]) -> Result<(), Error> {
        let range = &mut self.model.range;
        if range.range < RC_TOP_VALUE {
            let Some(&b) = buf.get(range.pos) else {
                return Err(Error::Corrupt);
            };
            range.range <<= 8;
            range.code = (range.code << 8) | b as u32;
            range.pos += 1;
        }
        if range.code != 0 || range.pos != buf.len() {
            return Err(Error::Corrupt);
        }
        Ok(())
    }

    /// Continue decoding a chunk whose compressed bytes may not all be in
    /// `buf` yet. `out` is the whole chunk's output, `*written` how much of
    /// it is already decoded. Packets are decoded only while at least
    /// `margin` bytes of `buf` are unread, so with `margin` =
    /// [`IN_REQUIRED`] a packet never runs out of input partway — which
    /// would leave the probabilities and range coder half-updated — and
    /// decoding can resume when more bytes arrive. `margin` 0 decodes to
    /// the end of `out` (the whole chunk is in `buf`, or nothing more will
    /// come: then an `UnexpectedEnd` leaves `*written` covering every
    /// packet that completed, since a packet writes nothing until it has
    /// been fully read).
    pub fn decode_partial(
        &mut self,
        buf: &[u8],
        out: &mut [u8],
        written: &mut usize,
        margin: usize,
    ) -> Result<(), Error> {
        // Everything this call can write to the dictionary.
        self.win.reserve(out.len() - *written);
        let mut sink = WindowSink {
            win: &mut self.win,
            out,
            written: *written,
        };
        let r = self.model.run(buf, &mut sink, margin);
        *written = sink.written;
        r
    }

    /// [`Self::decode_partial`] for the contiguous mode: `output` is the
    /// caller's buffer holding everything decoded so far, `*pos` the
    /// absolute position of the next byte, `chunk_left` how many bytes the
    /// current chunk still has to produce. Decodes until the chunk is
    /// complete, `output` is full, or (see `margin`) the compressed bytes
    /// in `buf` run low; `*pos` is advanced over what was written — also
    /// when an error is returned, as for `decode_partial`.
    ///
    /// No dictionary is allocated: history is read from `output` itself,
    /// from the last dictionary reset on (`reset_dict` / `reset_full` /
    /// a new core, each of which the caller performs at the then current
    /// `*pos`) and at most the dictionary size back — the same bytes the
    /// window of the streaming mode would hold. Every byte written since
    /// that reset must have gone through this method or
    /// [`Self::append_contiguous`].
    ///
    /// A match that does not fit in `output` is written as far as it goes
    /// and completed by the next call, which may pass a different (longer,
    /// moved) buffer with the same contents up to `*pos`.
    pub fn decode_contiguous(
        &mut self,
        buf: &[u8],
        output: &mut [u8],
        pos: &mut usize,
        chunk_left: usize,
        margin: usize,
    ) -> Result<(), Error> {
        let start = *pos;
        // The bytes since the last dictionary reset are all in `output`.
        let floor = usize::try_from(self.win.output_pos)
            .ok()
            .and_then(|n| start.checked_sub(n));
        let (Some(floor), true) = (floor, start <= output.len()) else {
            return Err(Error::Corrupt);
        };
        let chunk_end = start.saturating_add(chunk_left);
        let mut sink = ContiguousSink {
            limit: chunk_end.min(output.len()),
            out: output,
            pos: start,
            floor,
            dict_size: self.win.dict_size,
            chunk_end,
        };
        let r = self.model.run(buf, &mut sink, margin);
        *pos = sink.pos;
        self.win.output_pos += (sink.pos - start) as u64;
        r
    }

    /// Whether [`Self::decode_contiguous`] with this `buf` and `margin`
    /// would decode more if only it had room to write to: a cut match is
    /// waiting, or enough compressed bytes are there for another packet.
    ///
    /// Used by the [`crate::xz`] decoder; dead under an lzma2-only build.
    #[cfg_attr(not(any(feature = "xz", test)), allow(dead_code))]
    pub fn can_continue(&self, buf: &[u8], margin: usize) -> bool {
        self.model.pending_len != 0 || buf.len().saturating_sub(self.model.range.pos) >= margin
    }
}

impl Model {
    #[inline(always)]
    fn decode_literal<H: History>(&mut self, buf: &[u8], h: &H) -> Result<u8, Error> {
        let prev_byte = h.prev_byte();

        let is_lit = is_literal_state(self.state);
        let match_byte_init: Option<u8> = if !is_lit {
            if !h.has(self.rep0) {
                return Err(Error::Corrupt);
            }
            Some(h.get(self.rep0))
        } else {
            None
        };

        let lp_state = (h.position() & self.lit_pos_mask) << self.lc;
        let prev_high = (prev_byte as u32) >> (8 - self.lc);
        let probs_idx = (lp_state + prev_high) as usize * 0x300;
        let probs = &mut self.lit[probs_idx..probs_idx + 0x300];
        let rd = &mut self.range;

        let mut symbol: u32 = 1;
        match match_byte_init {
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
            // Direct (uniform) bits, decoded MSB-first, then a 4-bit align
            // bittree. The MSB-first ordering matches the corresponding
            // encoder in `src/xz/lzma2_encoder.rs` (which differs from the
            // LSB-first ordering used by `src/lzma/`).
            //
            // Hot path on random / incompressible data — batch the direct
            // bits with inlined normalisation and use the specialised
            // 4-bit align decode.
            let direct_count = num_direct_bits - ALIGN_BITS;
            let direct = self.range.decode_direct_bits_msb(direct_count, buf)?;
            dist |= direct << ALIGN_BITS;
            let v = dist_align_reverse_decode(&mut self.range, &mut self.dist_align, buf)?;
            dist |= v;
        }
        Ok(dist)
    }

    /// Decode one packet. EOS markers are not expected inside an LZMA2
    /// compressed chunk (chunks are externally framed by `uncomp_size`);
    /// encountering one yields `Error::Corrupt`.
    #[inline(always)]
    fn step<H: History>(&mut self, buf: &[u8], h: &H) -> Result<PacketOutcome, Error> {
        let pos_state = h.position() & self.pos_mask;
        let is_match_idx = self.state * POS_STATES_MAX + pos_state as usize;

        let bit = self
            .range
            .decode_bit(&mut self.is_match[is_match_idx], buf)?;

        if bit == 0 {
            let lit = self.decode_literal(buf, h)?;
            self.state = state_after_literal(self.state);
            Ok(PacketOutcome::Literal(lit))
        } else {
            let rep_bit = self.range.decode_bit(&mut self.is_rep[self.state], buf)?;
            if rep_bit == 1 {
                let rep0_bit = self.range.decode_bit(&mut self.is_rep0[self.state], buf)?;
                if rep0_bit == 0 {
                    let rep0_long_bit = self
                        .range
                        .decode_bit(&mut self.is_rep0_long[is_match_idx], buf)?;
                    if rep0_long_bit == 0 {
                        if !h.has(self.rep0) {
                            return Err(Error::Corrupt);
                        }
                        let b = h.get(self.rep0);
                        self.state = state_after_short_rep(self.state);
                        return Ok(PacketOutcome::Literal(b));
                    }
                    return self.finish_rep_match(0, pos_state, buf, h);
                }
                let r1 = self.range.decode_bit(&mut self.is_rep1[self.state], buf)?;
                let rep_idx = if r1 == 0 {
                    1u32
                } else {
                    let r2 = self.range.decode_bit(&mut self.is_rep2[self.state], buf)?;
                    if r2 == 0 { 2 } else { 3 }
                };
                self.finish_rep_match(rep_idx, pos_state, buf, h)
            } else {
                let len = self.len_coder.decode(&mut self.range, pos_state, buf)? + MATCH_LEN_MIN;
                let dist = self.decode_distance(len, buf)?;
                if dist == 0xFFFF_FFFF {
                    // EOS markers are illegal inside an LZMA2 compressed chunk.
                    return Err(Error::Corrupt);
                }
                self.rep3 = self.rep2;
                self.rep2 = self.rep1;
                self.rep1 = self.rep0;
                self.rep0 = dist;
                self.state = state_after_match(self.state);
                if !h.has(self.rep0) {
                    return Err(Error::Corrupt);
                }
                Ok(PacketOutcome::Match { length: len })
            }
        }
    }

    fn finish_rep_match<H: History>(
        &mut self,
        rep_idx: u32,
        pos_state: u32,
        buf: &[u8],
        h: &H,
    ) -> Result<PacketOutcome, Error> {
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
        if !h.has(dist) {
            return Err(Error::Corrupt);
        }
        Ok(PacketOutcome::Match { length: len })
    }

    /// The decoding loop shared by both modes: decode packets from `buf`
    /// into `h` until it has no room left or fewer than `margin` compressed
    /// bytes remain unread (see [`LzmaCore::decode_partial`]).
    #[inline(always)]
    fn run<H: History>(&mut self, buf: &[u8], h: &mut H, margin: usize) -> Result<(), Error> {
        if self.pending_len != 0 {
            // Finish the match the previous call had no room to complete.
            let n = (self.pending_len as usize).min(h.room());
            h.copy_match(self.rep0, n)?;
            self.pending_len -= n as u32;
            if self.pending_len != 0 {
                return Ok(());
            }
        }
        while h.room() > 0 && buf.len().saturating_sub(self.range.pos) >= margin {
            match self.step(buf, h)? {
                PacketOutcome::Literal(b) => h.put(b),
                PacketOutcome::Match { length } => {
                    let length = length as usize;
                    let distance = self.rep0;
                    if !h.has(distance) {
                        return Err(Error::Corrupt);
                    }
                    // A match that would write past the chunk's declared
                    // output size is malformed.
                    if length > h.chunk_left() {
                        return Err(Error::Corrupt);
                    }
                    let n = length.min(h.room());
                    h.copy_match(distance, n)?;
                    if n < length {
                        // Out of room mid-match (contiguous mode only):
                        // the rest goes out on the next call.
                        self.pending_len = (length - n) as u32;
                    }
                }
            }
        }
        Ok(())
    }
}

/// Most input bytes one LZMA packet can read (liblzma's
/// `LZMA_IN_REQUIRED`): at most 22 probability-coded bits, each shrinking
/// the range by at most ~6.05 bits, plus 26 direct bits of 1 bit each, so
/// 159 bits; the range coder reads one byte per 8 bits of shrink, plus
/// one.
pub const IN_REQUIRED: usize = 21;

/// Decode the LZMA2 dictionary-size byte from the xz filter properties.
///
/// Spec (xz-file-format.txt §5.3.1): a value `b` in `0..=39` decodes to
/// `(2 | (b & 1)) << (b/2 + 11)`; `b = 40` is the special "max" value
/// `0xFFFFFFFF`. The value is the stream's true dictionary size: the
/// callers check it against their configured limit before allocating a
/// window for it, and never shrink it (a smaller distance bound would make
/// valid far matches look corrupt).
pub fn lzma2_dict_size(b: u8) -> Result<u32, Error> {
    if b > 40 {
        return Err(Error::Corrupt);
    }
    if b == 40 {
        Ok(u32::MAX)
    } else {
        let raw = (2u64 | (b as u64 & 1)) << (b as u64 / 2 + 11);
        Ok(raw as u32)
    }
}
