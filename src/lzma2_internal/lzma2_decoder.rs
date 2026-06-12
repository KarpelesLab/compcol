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

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;

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

/// LZMA decoder kernel parametrised at construction time by `lc/lp/pb`
/// and a dictionary size; reused across LZMA2 chunks via the various
/// `reset_*` methods.
pub struct LzmaCore {
    lc: u32,
    pos_mask: u32,
    lit_pos_mask: u32,

    // Dictionary / sliding window. Decoded bytes are written here in
    // wrap-around order so that we can satisfy match-back-references.
    dict: Vec<u8>,
    dict_pos: usize,
    dict_full: bool,
    output_pos: u64,

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

    range: RangeDecoder,
}

impl LzmaCore {
    pub fn new(props: Lzma2Props, dict_size: usize) -> Self {
        let lit_size = (0x300_usize) << (props.lc + props.lp);
        let pos_mask = (1u32 << props.pb).wrapping_sub(1);
        let lit_pos_mask = (1u32 << props.lp).wrapping_sub(1);
        Self {
            lc: props.lc,
            pos_mask,
            lit_pos_mask,
            dict: vec![0u8; dict_size.max(1)],
            dict_pos: 0,
            dict_full: false,
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
        }
    }

    /// Replace the props (lc/lp/pb). Reallocates the literal table if
    /// `lc + lp` changed. Caller must follow with `reset_state` for the
    /// new probability tables to be initialised.
    pub fn replace_props(&mut self, props: Lzma2Props) {
        self.lc = props.lc;
        self.pos_mask = (1u32 << props.pb).wrapping_sub(1);
        self.lit_pos_mask = (1u32 << props.lp).wrapping_sub(1);
        let lit_size = (0x300_usize) << (props.lc + props.lp);
        if self.lit.len() != lit_size {
            self.lit = vec![PROB_INIT; lit_size];
        }
    }

    /// True iff the current dictionary buffer has the requested size, so
    /// the caller can reuse this core for a full-reset chunk instead of
    /// allocating a fresh `LzmaCore`.
    pub fn dict_capacity(&self) -> usize {
        self.dict.len()
    }

    /// Perform a "full reset" equivalent to constructing a new `LzmaCore`
    /// with the given props, but reuse the existing dictionary allocation
    /// (and the probability/literal table allocations where their sizes
    /// match). The dictionary contents are cleared and the LZ window
    /// position reset to zero. Caller must follow with `init_range` to
    /// re-bind the range coder to the next chunk's payload.
    pub fn reset_full(&mut self, props: Lzma2Props) {
        self.replace_props(props);
        self.dict_pos = 0;
        self.dict_full = false;
        self.output_pos = 0;
        self.reset_state();
    }

    /// Reset all probability tables and the LZ state, but keep the
    /// dictionary contents.
    pub fn reset_state(&mut self) {
        for p in self.is_match.iter_mut() {
            *p = PROB_INIT;
        }
        for p in self.is_rep.iter_mut() {
            *p = PROB_INIT;
        }
        for p in self.is_rep0.iter_mut() {
            *p = PROB_INIT;
        }
        for p in self.is_rep1.iter_mut() {
            *p = PROB_INIT;
        }
        for p in self.is_rep2.iter_mut() {
            *p = PROB_INIT;
        }
        for p in self.is_rep0_long.iter_mut() {
            *p = PROB_INIT;
        }
        for p in self.dist_slot.iter_mut() {
            *p = PROB_INIT;
        }
        for p in self.dist_special.iter_mut() {
            *p = PROB_INIT;
        }
        for p in self.dist_align.iter_mut() {
            *p = PROB_INIT;
        }
        for p in self.lit.iter_mut() {
            *p = PROB_INIT;
        }
        self.len_coder.reset();
        self.rep_len_coder.reset();
        self.state = 0;
        self.rep0 = 0;
        self.rep1 = 0;
        self.rep2 = 0;
        self.rep3 = 0;
    }

    /// Re-initialise the range coder against a freshly-buffered chunk.
    /// Expects `buf[0..5]` to be the LZMA range-coder init sequence
    /// (the spec mandates the first byte is `0x00`).
    pub fn init_range(&mut self, buf: &[u8]) -> Result<(), Error> {
        self.range = RangeDecoder::new();
        self.range.init(buf)
    }

    /// Feed already-known literal bytes (e.g. from an LZMA2 *uncompressed*
    /// chunk) into the LZ window so a later compressed chunk that does not
    /// reset the dictionary can back-reference them. Does not emit output.
    ///
    /// Used by the raw [`crate::lzma2`] decoder; dead under an xz-only build.
    #[cfg_attr(not(any(feature = "lzma2", test)), allow(dead_code))]
    pub fn append_literals(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.dict_put(b);
        }
    }

    fn dict_get(&self, distance: u32) -> u8 {
        let dist1 = distance as usize + 1;
        let pos = if self.dict_pos >= dist1 {
            self.dict_pos - dist1
        } else {
            self.dict.len() - (dist1 - self.dict_pos)
        };
        self.dict[pos]
    }

    fn dict_put(&mut self, b: u8) {
        self.dict[self.dict_pos] = b;
        self.dict_pos += 1;
        if self.dict_pos >= self.dict.len() {
            self.dict_pos = 0;
            self.dict_full = true;
        }
        self.output_pos += 1;
    }

    fn dict_has(&self, distance: u32) -> bool {
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
    /// the remainder. Caller must guarantee `dict_has(distance)` and that
    /// `out` has at least `n` bytes of room from `*written`.
    fn dict_copy_match_bulk(
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
    /// `dict_has(distance)` and `out` room for `n` bytes from `*written`.
    fn dict_copy_match_overlap(
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

    fn pos_state(&self) -> u32 {
        (self.output_pos as u32) & self.pos_mask
    }

    fn decode_literal(&mut self, buf: &[u8]) -> Result<u8, Error> {
        let prev_byte = if self.dict_full || self.dict_pos > 0 {
            self.dict_get(0)
        } else {
            0u8
        };

        let is_lit = is_literal_state(self.state);
        let match_byte_init: Option<u8> = if !is_lit {
            if !self.dict_has(self.rep0) {
                return Err(Error::Corrupt);
            }
            Some(self.dict_get(self.rep0))
        } else {
            None
        };

        let lp_state = ((self.output_pos as u32) & self.lit_pos_mask) << self.lc;
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
    fn step(&mut self, buf: &[u8]) -> Result<PacketOutcome, Error> {
        let pos_state = self.pos_state();
        let is_match_idx = self.state * POS_STATES_MAX + pos_state as usize;

        let bit = self
            .range
            .decode_bit(&mut self.is_match[is_match_idx], buf)?;

        if bit == 0 {
            let lit = self.decode_literal(buf)?;
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
                        if !self.dict_has(self.rep0) {
                            return Err(Error::Corrupt);
                        }
                        let b = self.dict_get(self.rep0);
                        self.state = state_after_short_rep(self.state);
                        return Ok(PacketOutcome::Literal(b));
                    }
                    return self.finish_rep_match(0, pos_state, buf);
                }
                let r1 = self.range.decode_bit(&mut self.is_rep1[self.state], buf)?;
                let rep_idx = if r1 == 0 {
                    1u32
                } else {
                    let r2 = self.range.decode_bit(&mut self.is_rep2[self.state], buf)?;
                    if r2 == 0 { 2 } else { 3 }
                };
                self.finish_rep_match(rep_idx, pos_state, buf)
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
                if !self.dict_has(self.rep0) {
                    return Err(Error::Corrupt);
                }
                Ok(PacketOutcome::Match { length: len })
            }
        }
    }

    fn finish_rep_match(
        &mut self,
        rep_idx: u32,
        pos_state: u32,
        buf: &[u8],
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
        if !self.dict_has(dist) {
            return Err(Error::Corrupt);
        }
        Ok(PacketOutcome::Match { length: len })
    }

    /// Decode exactly `uncomp_size` bytes from `buf` (whose first 5 bytes
    /// were already consumed by `init_range`) into `out`. The output buffer
    /// must be sized to hold the chunk's `uncomp_size` bytes.
    ///
    /// On success the range coder must be in a "clean" terminal state
    /// (range >= TOP and code == 0); we *don't* enforce that here because
    /// the chunk's `comp_size` already bounds how many bytes we read, and
    /// any trailing slack just stays in `buf`.
    pub fn decode_chunk(&mut self, buf: &[u8], out: &mut [u8]) -> Result<(), Error> {
        let target = out.len();
        let mut written = 0usize;
        while written < target {
            match self.step(buf)? {
                PacketOutcome::Literal(b) => {
                    self.dict_put(b);
                    out[written] = b;
                    written += 1;
                }
                PacketOutcome::Match { length } => {
                    let mut remaining = length as usize;
                    let distance = self.rep0;
                    if !self.dict_has(distance) {
                        return Err(Error::Corrupt);
                    }
                    // A match that would write past the chunk's declared
                    // output size is malformed.
                    if remaining > target - written {
                        return Err(Error::Corrupt);
                    }
                    // Fast path: when the match is non-overlapping
                    // (distance + 1 >= remaining) the source bytes already
                    // exist contiguously behind `dict_pos`, so we can bulk
                    // `copy_from_slice` / `copy_within` instead of stepping
                    // byte by byte. `dict_copy_match_bulk` copies as much as
                    // it can without crossing the circular dict boundary and
                    // returns the count; the per-byte loop handles any
                    // wrapped remainder and the overlapping case.
                    if distance as usize + 1 >= remaining {
                        let did = self.dict_copy_match_bulk(distance, remaining, out, &mut written);
                        remaining -= did;
                    } else {
                        // Overlapping run (e.g. RLE-style fills): replicate
                        // the source window forward in bulk.
                        let did =
                            self.dict_copy_match_overlap(distance, remaining, out, &mut written);
                        remaining -= did;
                    }
                    while remaining > 0 {
                        if !self.dict_has(distance) {
                            return Err(Error::Corrupt);
                        }
                        let b = self.dict_get(distance);
                        self.dict_put(b);
                        out[written] = b;
                        written += 1;
                        remaining -= 1;
                    }
                }
            }
        }
        Ok(())
    }
}

/// Decode the LZMA2 dictionary-size byte from the xz filter properties.
///
/// Spec (xz-file-format.txt §5.3.1): a value `b` in `0..=39` decodes to
/// `(2 | (b & 1)) << (b/2 + 11)`; `b = 40` is the special "max" value
/// `0xFFFFFFFF`. We clamp to a sane upper bound when allocating.
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
