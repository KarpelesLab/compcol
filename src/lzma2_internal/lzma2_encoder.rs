//! LZMA payload encoder used inside compressed LZMA2 chunks.
//!
//! Adapted from `src/lzma/encoder.rs`. The two structural changes versus the
//! `.lzma` (alone) encoder are:
//!
//! 1. No 13-byte header. Properties (lc/lp/pb packed into a single byte) and
//!    the LZMA2 dictionary size are emitted by the surrounding LZMA2 chunk
//!    framing, not by this code path.
//! 2. No end-of-stream marker. LZMA2 frames the uncompressed length
//!    explicitly in each chunk header, so the decoder stops at exactly that
//!    many output bytes — emitting an EOS marker would be wrong (the
//!    next chunk's range coder is independent).
//!
//! Output of [`encode_lzma_chunk`] is the raw range-coded body. The range
//! coder is flushed at the end so the last 5 bytes can be parsed by the
//! decoder; the chunk's compressed-size field in the LZMA2 header includes
//! the flush bytes.
//!
//! ## Parse strategy
//!
//! This encoder uses a **cost-based optimal parse** modelled on the LZMA SDK's
//! `GetOptimum`. For each window of input it builds a forward
//! dynamic-programming table over an "optimum" buffer: every reachable
//! position records the minimum range-coder bit price to arrive there and a
//! back-pointer to the decision (literal / match / rep0..rep3 / short-rep)
//! that produced it. Prices come from a snapshot of the live probability
//! model — the same probabilities the range coder is about to use — so the
//! parser optimises the *actual* encoded size rather than a length heuristic.
//!
//! Match finding is a hash-chain finder that returns the full set of
//! candidate (length, distance) pairs at a position (the shortest distance for
//! each achievable length), plus the four repeat-distance matches, so the
//! optimal parser has the complete candidate set it needs.
//!
//! Lower levels fall back to a fast greedy/lazy parse; the optimal parse and
//! its look-ahead window scale up with `level`.

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

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
/// Total number of length symbols (0-based): low ⊕ mid ⊕ high = 8 + 8 + 256.
const LEN_SYMBOLS: usize = LEN_LOW_SYMBOLS + LEN_MID_SYMBOLS + LEN_HIGH_SYMBOLS;

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

// ─── state transition helpers ────────────────────────────────────────────

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

// ─── encoder parameters ──────────────────────────────────────────────────

/// Properties byte = `(pb*5 + lp)*9 + lc` per the LZMA spec; (3, 0, 2) packs
/// to 0x5d — the canonical default that xz-utils emits at its standard
/// presets.
const ENC_LC: u32 = 3;
const ENC_LP: u32 = 0;
const ENC_PB: u32 = 2;
/// Packed LZMA properties byte: lc=3, lp=0, pb=2 → 0x5d.
pub(crate) const LZMA2_PROPS_BYTE: u8 = (ENC_PB * 5 + ENC_LP) as u8 * 9 + ENC_LC as u8;

const MAX_MATCH_LEN: u32 = 273; // 2 + 8 + 8 + 255 (LEN_LOW + LEN_MID + LEN_HIGH)

// Hash chain match finder configuration.
//
// The head table is sized at construction time to the match-finder window
// (≈ `dict_size`, see `HashChain::new`) so that for incompressible input the
// per-bucket chains stay short (load factor ≈ 1). A small *fixed* table would
// make distinct 3-byte prefixes collide into the same bucket as the input
// grows, so every probe walks a chain whose length scales with the input —
// turning the parse O(n²/table) until the `max_chain` cap finally engages.
// liblzma sizes its hash tables to the dictionary for the same reason.
//
// `HASH_MIN_BITS` floors the table for tiny inputs; the upper bound comes from
// the window. `hash3` returns a full 32-bit mix that each probe reduces with
// the runtime `head_mask`.
const HASH_MIN_BITS: u32 = 14;
const NIL: u32 = u32::MAX;

/// Match-finder + optimal-parser tuning expanded from the user-facing `level`
/// byte. Higher levels widen `max_chain` (more hash-chain links walked per
/// probe), raise `nice_match` (the length at which the chain walk gives up and
/// accepts the current match), and enlarge `opt_window` (how far ahead the
/// optimal parser looks before committing a parse). This is the same
/// speed-vs-ratio knob xz-utils exposes — we expose a small subset.
#[derive(Debug, Clone, Copy)]
pub(crate) struct EncoderParams {
    pub max_chain: usize,
    pub nice_match: u32,
    /// Length at which the optimal parser early-commits the current window
    /// (a match this long is almost certainly taken). Keeping this modest
    /// keeps committed segments short and the price snapshot fresh.
    pub nice_len: u32,
    /// Optimal-parser look-ahead window (number of optimum-buffer slots). When
    /// `0` the parser falls back to a fast greedy/lazy parse (used by the
    /// lowest levels so they stay genuinely fast).
    pub opt_window: u32,
}

impl EncoderParams {
    /// Expand a `0..=9` level into match-finder + parser knobs.
    ///
    /// The mapping is monotonic: higher level = deeper chain walk, longer
    /// nice-match cutoff, and a larger optimal-parse window. Values outside
    /// `0..=9` are clamped — we keep the public surface infallible.
    pub fn from_level(level: u8) -> Self {
        let level = level.min(9);
        match level {
            0 => Self {
                max_chain: 4,
                nice_match: 8,
                nice_len: 8,
                opt_window: 0,
            },
            1 => Self {
                max_chain: 8,
                nice_match: 16,
                nice_len: 16,
                opt_window: 0,
            },
            2 => Self {
                max_chain: 16,
                nice_match: 32,
                nice_len: 32,
                opt_window: 0,
            },
            3 => Self {
                max_chain: 32,
                nice_match: 64,
                nice_len: 16,
                opt_window: 512,
            },
            4 => Self {
                max_chain: 64,
                nice_match: 128,
                nice_len: 24,
                opt_window: 1024,
            },
            5 => Self {
                max_chain: 128,
                nice_match: 192,
                nice_len: 32,
                opt_window: 2048,
            },
            6 => Self {
                max_chain: 256,
                nice_match: 273,
                nice_len: 48,
                opt_window: 4096,
            },
            7 => Self {
                max_chain: 512,
                nice_match: 273,
                nice_len: 64,
                opt_window: 4096,
            },
            8 => Self {
                max_chain: 1024,
                nice_match: 273,
                nice_len: 96,
                opt_window: 4096,
            },
            // 9 (and clamp-from-above)
            _ => Self {
                max_chain: 2048,
                nice_match: MAX_MATCH_LEN,
                nice_len: 128,
                opt_window: 4096,
            },
        }
    }
}

/// Full-width 3-byte hash mix. The caller reduces this to a bucket index with
/// the finder's runtime `head_mask`; mixing all three bytes across the high
/// bits keeps distinct prefixes well separated for any mask width.
fn hash3(b0: u8, b1: u8, b2: u8) -> u32 {
    (b0 as u32).wrapping_mul(2654435761)
        ^ (b1 as u32).wrapping_mul(2246822519)
        ^ (b2 as u32).wrapping_mul(3266489917)
}

/// Length of the common prefix of `win[ci..]` and `win[pi..]`, up to `max_len`
/// bytes. Compares eight bytes at a time via little-endian word loads — the
/// first differing byte is the lowest set byte of the XOR, found with
/// `trailing_zeros`. Callers must guarantee `ci < pi`, `pi + max_len <=
/// win.len()` (so both word reads stay in bounds). On highly repetitive input
/// the match-extension loop ran to 273 bytes one-at-a-time and dominated the
/// match finder; the word stride cuts that ~8×.
#[inline]
fn match_len_at(win: &[u8], ci: usize, pi: usize, max_len: usize) -> u32 {
    let mut i = 0usize;
    while i + 8 <= max_len {
        let x = u64::from_le_bytes(win[ci + i..ci + i + 8].try_into().unwrap());
        let y = u64::from_le_bytes(win[pi + i..pi + i + 8].try_into().unwrap());
        let d = x ^ y;
        if d != 0 {
            return (i + (d.trailing_zeros() >> 3) as usize) as u32;
        }
        i += 8;
    }
    while i < max_len && win[ci + i] == win[pi + i] {
        i += 1;
    }
    i as u32
}

// ─── range encoder ───────────────────────────────────────────────────────

struct RangeEncoder {
    low: u64,
    range: u32,
    cache: u8,
    cache_size: u64,
    out: Vec<u8>,
}

impl RangeEncoder {
    fn new() -> Self {
        Self {
            low: 0,
            range: 0xFFFF_FFFF,
            cache: 0,
            cache_size: 1,
            out: Vec::new(),
        }
    }

    fn shift_low(&mut self) {
        let top_bits = (self.low >> 32) as u32;
        if self.low < 0xFF00_0000 || top_bits != 0 {
            let carry = top_bits as u8;
            let mut byte = self.cache.wrapping_add(carry);
            self.out.push(byte);
            byte = if carry == 0 { 0xFF } else { 0x00 };
            while self.cache_size > 1 {
                self.out.push(byte);
                self.cache_size -= 1;
            }
            self.cache = (self.low >> 24) as u8;
            self.cache_size = 1;
        } else {
            self.cache_size += 1;
        }
        self.low = (self.low << 8) & 0xFFFF_FFFFu64;
    }

    fn normalize(&mut self) {
        if self.range < RC_TOP_VALUE {
            self.range <<= 8;
            self.shift_low();
        }
    }

    fn encode_bit(&mut self, prob: &mut u16, bit: u32) {
        let p = *prob as u32;
        let bound = (self.range >> RC_BIT_MODEL_TOTAL_BITS) * p;
        if bit == 0 {
            self.range = bound;
            *prob = (p + ((RC_BIT_MODEL_TOTAL - p) >> RC_MOVE_BITS)) as u16;
        } else {
            self.low = self.low.wrapping_add(bound as u64);
            self.range -= bound;
            *prob = (p - (p >> RC_MOVE_BITS)) as u16;
        }
        self.normalize();
    }

    fn encode_direct_bit(&mut self, bit: u32) {
        self.range >>= 1;
        if bit != 0 {
            self.low = self.low.wrapping_add(self.range as u64);
        }
        self.normalize();
    }

    /// Encode `value` as `bits` direct (uniform) bits.
    ///
    /// The LZMA2 decoder in [`super::lzma2_decoder`] assembles direct bits
    /// MSB-first: each decoded bit shifts the accumulator left, with the
    /// first bit landing in the highest position. To match, we emit
    /// MSB-first — bit `(value >> (bits-1)) & 1` first, bit 0 last.
    ///
    /// Note: this differs from `src/lzma/encoder.rs`, which is paired with
    /// the LSB-first direct-bit assembly used by `src/lzma/` decoder. Both
    /// orderings are internally consistent; we just need the encoder's
    /// emission order to match the decoder it'll be fed to.
    fn encode_direct_bits(&mut self, value: u32, bits: u32) {
        let mut i = bits;
        while i > 0 {
            i -= 1;
            self.encode_direct_bit((value >> i) & 1);
        }
    }

    fn flush(&mut self) {
        for _ in 0..5 {
            self.shift_low();
        }
    }
}

// ─── bit-tree encoders ───────────────────────────────────────────────────

fn bittree_encode(rc: &mut RangeEncoder, probs: &mut [u16], bits: u32, symbol: u32) {
    let mut idx: u32 = 1;
    let mut i = bits;
    while i > 0 {
        i -= 1;
        let bit = (symbol >> i) & 1;
        rc.encode_bit(&mut probs[idx as usize], bit);
        idx = (idx << 1) | bit;
    }
}

fn bittree_reverse_encode(rc: &mut RangeEncoder, probs: &mut [u16], bits: u32, symbol: u32) {
    let mut idx: u32 = 1;
    for i in 0..bits {
        let bit = (symbol >> i) & 1;
        rc.encode_bit(&mut probs[idx as usize], bit);
        idx = (idx << 1) | bit;
    }
}

fn dist_special_encode(
    rc: &mut RangeEncoder,
    probs: &mut [u16],
    base_idx: usize,
    num_direct_bits: u32,
    extra: u32,
) {
    let mut idx = base_idx;
    let mut m: u32 = 1;
    for i in 0..num_direct_bits {
        let bit = (extra >> i) & 1;
        rc.encode_bit(&mut probs[idx], bit);
        if bit == 0 {
            idx += m as usize;
            m += m;
        } else {
            m += m;
            idx += m as usize;
        }
    }
}

// ─── price model ──────────────────────────────────────────────────────────
//
// The optimal parser needs the *bit cost* of encoding a given symbol with the
// current probability model. LZMA prices in 1/16-bit units: the cost of
// coding a bit against probability `p` is a fixed-point `-log2` of the
// matching probability. We replicate the SDK's `ProbPrices` table.

const PRICE_SHIFT_BITS: u32 = 4;
const PRICE_TABLE_SIZE: usize = (RC_BIT_MODEL_TOTAL >> PRICE_SHIFT_BITS) as usize;

/// Precomputed price table: `prices[p >> 4]` is the cost in 1/16-bit units of
/// coding a 0-bit against probability `p`. Generated the same way as the LZMA
/// SDK's price table (a fixed-point `-log2` approximation).
fn build_prob_prices() -> [u32; PRICE_TABLE_SIZE] {
    let mut prices = [0u32; PRICE_TABLE_SIZE];
    // `kCyclesBits` in the SDK: the squaring loop runs exactly this many times
    // (it equals the price shift, 4 — NOT the model-bit count). Getting this
    // wrong makes `bit_count` overflow the subtraction and yields garbage
    // prices.
    let cycles_bits = PRICE_SHIFT_BITS;
    let mut i: usize = (1usize << PRICE_SHIFT_BITS) >> 1;
    while i < (PRICE_TABLE_SIZE << PRICE_SHIFT_BITS) {
        let mut w = i as u32;
        let mut bit_count = 0u32;
        let mut j = 0;
        while j < cycles_bits {
            w = w.wrapping_mul(w);
            bit_count <<= 1;
            while w >= (1u32 << 16) {
                w >>= 1;
                bit_count += 1;
            }
            j += 1;
        }
        let idx = i >> PRICE_SHIFT_BITS;
        prices[idx] = (RC_BIT_MODEL_TOTAL_BITS << PRICE_SHIFT_BITS) - 15 - bit_count;
        i += 1 << PRICE_SHIFT_BITS;
    }
    prices
}

#[inline]
fn price_bit(prices: &[u32; PRICE_TABLE_SIZE], prob: u16, bit: u32) -> u32 {
    let p = if bit == 0 {
        prob as u32
    } else {
        RC_BIT_MODEL_TOTAL - prob as u32
    };
    prices[(p >> PRICE_SHIFT_BITS) as usize]
}

#[inline]
fn price_bit0(prices: &[u32; PRICE_TABLE_SIZE], prob: u16) -> u32 {
    prices[(prob as u32 >> PRICE_SHIFT_BITS) as usize]
}

#[inline]
fn price_bit1(prices: &[u32; PRICE_TABLE_SIZE], prob: u16) -> u32 {
    prices[((RC_BIT_MODEL_TOTAL - prob as u32) >> PRICE_SHIFT_BITS) as usize]
}

fn bittree_price(prices: &[u32; PRICE_TABLE_SIZE], probs: &[u16], bits: u32, symbol: u32) -> u32 {
    let mut total = 0u32;
    let mut idx: u32 = 1;
    let mut i = bits;
    while i > 0 {
        i -= 1;
        let bit = (symbol >> i) & 1;
        total += price_bit(prices, probs[idx as usize], bit);
        idx = (idx << 1) | bit;
    }
    total
}

fn bittree_reverse_price(
    prices: &[u32; PRICE_TABLE_SIZE],
    probs: &[u16],
    bits: u32,
    symbol: u32,
) -> u32 {
    let mut total = 0u32;
    let mut idx: u32 = 1;
    for i in 0..bits {
        let bit = (symbol >> i) & 1;
        total += price_bit(prices, probs[idx as usize], bit);
        idx = (idx << 1) | bit;
    }
    total
}

// ─── length coder ────────────────────────────────────────────────────────

struct LengthCoderEnc {
    choice: u16,
    choice2: u16,
    low: Vec<u16>,
    mid: Vec<u16>,
    high: Vec<u16>,
}

impl LengthCoderEnc {
    fn new() -> Self {
        Self {
            choice: PROB_INIT,
            choice2: PROB_INIT,
            low: vec![PROB_INIT; POS_STATES_MAX * LEN_LOW_SYMBOLS],
            mid: vec![PROB_INIT; POS_STATES_MAX * LEN_MID_SYMBOLS],
            high: vec![PROB_INIT; LEN_HIGH_SYMBOLS],
        }
    }

    fn encode(&mut self, rc: &mut RangeEncoder, pos_state: u32, length: u32) {
        if length < LEN_LOW_SYMBOLS as u32 {
            rc.encode_bit(&mut self.choice, 0);
            let base = (pos_state as usize) * LEN_LOW_SYMBOLS;
            let probs = &mut self.low[base..base + LEN_LOW_SYMBOLS];
            bittree_encode(rc, probs, LEN_LOW_BITS, length);
        } else if length < (LEN_LOW_SYMBOLS + LEN_MID_SYMBOLS) as u32 {
            rc.encode_bit(&mut self.choice, 1);
            rc.encode_bit(&mut self.choice2, 0);
            let base = (pos_state as usize) * LEN_MID_SYMBOLS;
            let probs = &mut self.mid[base..base + LEN_MID_SYMBOLS];
            bittree_encode(rc, probs, LEN_MID_BITS, length - LEN_LOW_SYMBOLS as u32);
        } else {
            rc.encode_bit(&mut self.choice, 1);
            rc.encode_bit(&mut self.choice2, 1);
            bittree_encode(
                rc,
                &mut self.high,
                LEN_HIGH_BITS,
                length - (LEN_LOW_SYMBOLS + LEN_MID_SYMBOLS) as u32,
            );
        }
    }
}

// ─── encoder core ────────────────────────────────────────────────────────

struct LzmaEncCore {
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

    len_coder: LengthCoderEnc,
    rep_len_coder: LengthCoderEnc,

    state: usize,
    rep0: u32,
    rep1: u32,
    rep2: u32,
    rep3: u32,

    pos_mask: u32,
    lit_pos_mask: u32,
    lc: u32,

    rc: RangeEncoder,

    output_pos: u64,
}

impl LzmaEncCore {
    fn new() -> Self {
        let lit_size = 0x300_usize << (ENC_LC + ENC_LP);
        Self {
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
            len_coder: LengthCoderEnc::new(),
            rep_len_coder: LengthCoderEnc::new(),
            state: 0,
            rep0: 0,
            rep1: 0,
            rep2: 0,
            rep3: 0,
            pos_mask: (1u32 << ENC_PB) - 1,
            lit_pos_mask: (1u32 << ENC_LP) - 1,
            lc: ENC_LC,
            rc: RangeEncoder::new(),
            output_pos: 0,
        }
    }

    fn pos_state(&self) -> u32 {
        (self.output_pos as u32) & self.pos_mask
    }

    /// Reset the LZMA *state* for a new continued chunk: re-initialise every
    /// probability table, the LZMA state, the four rep distances, and a fresh
    /// range coder — but deliberately keep `output_pos` running so the
    /// `pos_state` derivation stays continuous across chunks (matching the
    /// decoder, whose `output_pos` only resets on a dictionary reset, not a
    /// state reset). The LZ history (hash chain) is owned outside the core and
    /// is likewise preserved, so matches in this chunk can reference data from
    /// earlier chunks. This is the encoder counterpart of the LZMA2 `0xC0`
    /// "reset state + new props, dictionary continues" control byte.
    fn reset_state_keep_pos(&mut self) {
        self.is_match.fill(PROB_INIT);
        self.is_rep.fill(PROB_INIT);
        self.is_rep0.fill(PROB_INIT);
        self.is_rep1.fill(PROB_INIT);
        self.is_rep2.fill(PROB_INIT);
        self.is_rep0_long.fill(PROB_INIT);
        self.dist_slot.fill(PROB_INIT);
        self.dist_special.fill(PROB_INIT);
        self.dist_align.fill(PROB_INIT);
        self.lit.fill(PROB_INIT);
        self.len_coder = LengthCoderEnc::new();
        self.rep_len_coder = LengthCoderEnc::new();
        self.state = 0;
        self.rep0 = 0;
        self.rep1 = 0;
        self.rep2 = 0;
        self.rep3 = 0;
        self.rc = RangeEncoder::new();
    }

    /// Reset **only** the range coder for a continued chunk (LZMA2 `0x80`):
    /// the probability model, LZMA `state`, and the four rep distances all
    /// carry over, so the adaptive model keeps warming across chunk boundaries
    /// exactly as native `xz` does. Each LZMA2 chunk is still an independently
    /// range-coded blob (its own 5-byte init + flush), so the range coder alone
    /// must start fresh; `output_pos` is likewise left running.
    fn reset_range_coder(&mut self) {
        self.rc = RangeEncoder::new();
    }

    fn encode_literal_full(&mut self, byte: u8, prev_byte: u8, match_byte: Option<u8>) {
        let lp_state = ((self.output_pos as u32) & self.lit_pos_mask) << self.lc;
        let prev_high = (prev_byte as u32) >> (8 - self.lc);
        let probs_idx = (lp_state + prev_high) as usize * 0x300;
        let probs = &mut self.lit[probs_idx..probs_idx + 0x300];

        let mut symbol: u32 = 1;
        let target = byte as u32;
        match match_byte {
            Some(mb) => {
                let mut match_byte_w = mb as u32;
                let mut mismatched = false;
                let mut i: i32 = 8;
                while symbol < 0x100 {
                    i -= 1;
                    let bit = (target >> i) & 1;
                    match_byte_w <<= 1;
                    let match_bit = match_byte_w & 0x100;
                    if !mismatched {
                        let idx = (0x100 + match_bit + symbol) as usize;
                        rc_encode_bit(&mut self.rc, &mut probs[idx], bit);
                        symbol = (symbol << 1) | bit;
                        if (match_bit >> 8) != bit {
                            mismatched = true;
                        }
                    } else {
                        rc_encode_bit(&mut self.rc, &mut probs[symbol as usize], bit);
                        symbol = (symbol << 1) | bit;
                    }
                }
            }
            None => {
                let mut i: i32 = 8;
                while symbol < 0x100 {
                    i -= 1;
                    let bit = (target >> i) & 1;
                    rc_encode_bit(&mut self.rc, &mut probs[symbol as usize], bit);
                    symbol = (symbol << 1) | bit;
                }
            }
        }
    }

    /// Price of coding the literal `byte` at output offset `out_pos` with the
    /// given previous byte, optional match byte (rep0 byte), and literal
    /// state. Reads the live `lit` probabilities (snapshot at call time).
    fn literal_price(
        &self,
        prices: &[u32; PRICE_TABLE_SIZE],
        out_pos: u64,
        byte: u8,
        prev_byte: u8,
        match_byte: Option<u8>,
    ) -> u32 {
        let lp_state = ((out_pos as u32) & self.lit_pos_mask) << self.lc;
        let prev_high = (prev_byte as u32) >> (8 - self.lc);
        let probs_idx = (lp_state + prev_high) as usize * 0x300;
        let probs = &self.lit[probs_idx..probs_idx + 0x300];

        let mut total = 0u32;
        let mut symbol: u32 = 1;
        let target = byte as u32;
        match match_byte {
            Some(mb) => {
                let mut match_byte_w = mb as u32;
                let mut mismatched = false;
                let mut i: i32 = 8;
                while symbol < 0x100 {
                    i -= 1;
                    let bit = (target >> i) & 1;
                    match_byte_w <<= 1;
                    let match_bit = match_byte_w & 0x100;
                    if !mismatched {
                        let idx = (0x100 + match_bit + symbol) as usize;
                        total += price_bit(prices, probs[idx], bit);
                        symbol = (symbol << 1) | bit;
                        if (match_bit >> 8) != bit {
                            mismatched = true;
                        }
                    } else {
                        total += price_bit(prices, probs[symbol as usize], bit);
                        symbol = (symbol << 1) | bit;
                    }
                }
            }
            None => {
                let mut i: i32 = 8;
                while symbol < 0x100 {
                    i -= 1;
                    let bit = (target >> i) & 1;
                    total += price_bit(prices, probs[symbol as usize], bit);
                    symbol = (symbol << 1) | bit;
                }
            }
        }
        total
    }

    fn encode_distance(&mut self, length: u32, distance: u32) {
        let dist_state_idx =
            (length.min(DIST_STATES as u32 + MATCH_LEN_MIN - 1) - MATCH_LEN_MIN) as usize;
        let slot = get_dist_slot(distance);
        let slot_base = dist_state_idx * DIST_SLOTS;
        let probs = &mut self.dist_slot[slot_base..slot_base + DIST_SLOTS];
        bittree_encode(&mut self.rc, probs, DIST_SLOT_BITS, slot);

        if slot < DIST_MODEL_START {
            return;
        }

        let num_direct_bits = (slot >> 1) - 1;
        let base = (2 | (slot & 1)) << num_direct_bits;
        let extra = distance.wrapping_sub(base);

        if slot < DIST_MODEL_END {
            let base_idx = base as usize + 1;
            dist_special_encode(
                &mut self.rc,
                self.dist_special.as_mut_slice(),
                base_idx,
                num_direct_bits,
                extra,
            );
        } else {
            let direct_count = num_direct_bits - ALIGN_BITS;
            let direct = extra >> ALIGN_BITS;
            self.rc.encode_direct_bits(direct, direct_count);
            let align = extra & (ALIGN_SIZE as u32 - 1);
            bittree_reverse_encode(
                &mut self.rc,
                self.dist_align.as_mut_slice(),
                ALIGN_BITS,
                align,
            );
        }
    }

    /// Price of coding a new-match distance `distance` for a match of length
    /// `length`. Reads the live distance probabilities.
    fn distance_price(&self, prices: &[u32; PRICE_TABLE_SIZE], length: u32, distance: u32) -> u32 {
        let dist_state_idx =
            (length.min(DIST_STATES as u32 + MATCH_LEN_MIN - 1) - MATCH_LEN_MIN) as usize;
        let slot = get_dist_slot(distance);
        let slot_base = dist_state_idx * DIST_SLOTS;
        let mut total = bittree_price(
            prices,
            &self.dist_slot[slot_base..slot_base + DIST_SLOTS],
            DIST_SLOT_BITS,
            slot,
        );

        if slot < DIST_MODEL_START {
            return total;
        }

        let num_direct_bits = (slot >> 1) - 1;
        let base = (2 | (slot & 1)) << num_direct_bits;
        let extra = distance.wrapping_sub(base);

        if slot < DIST_MODEL_END {
            let base_idx = base as usize + 1;
            let mut idx = base_idx;
            let mut m: u32 = 1;
            for i in 0..num_direct_bits {
                let bit = (extra >> i) & 1;
                total += price_bit(prices, self.dist_special[idx], bit);
                if bit == 0 {
                    idx += m as usize;
                    m += m;
                } else {
                    m += m;
                    idx += m as usize;
                }
            }
        } else {
            let direct_count = num_direct_bits - ALIGN_BITS;
            // Direct (uniform) bits cost exactly 1 bit each.
            total += direct_count << PRICE_SHIFT_BITS;
            let align = extra & (ALIGN_SIZE as u32 - 1);
            total += bittree_reverse_price(prices, &self.dist_align[..], ALIGN_BITS, align);
        }
        total
    }

    /// Emit the literal at absolute position `pos`, reading bytes from the
    /// sliding window `win` (whose first byte is absolute offset `base`).
    fn emit_literal(&mut self, win: &[u8], base: usize, pos: usize) {
        let pos_state = self.pos_state();
        let idx = self.state * POS_STATES_MAX + pos_state as usize;
        rc_encode_bit(&mut self.rc, &mut self.is_match[idx], 0);

        let i = pos - base;
        let prev_byte = if pos > 0 { win[i - 1] } else { 0 };
        let match_byte = if self.state < LIT_STATES {
            None
        } else {
            let d = self.rep0 as usize + 1;
            if d <= pos { Some(win[i - d]) } else { None }
        };
        self.encode_literal_full(win[i], prev_byte, match_byte);

        self.state = state_after_literal(self.state);
        self.output_pos += 1;
    }

    fn emit_match(&mut self, distance: u32, length: u32) {
        let pos_state = self.pos_state();
        let is_match_idx = self.state * POS_STATES_MAX + pos_state as usize;
        rc_encode_bit(&mut self.rc, &mut self.is_match[is_match_idx], 1);
        rc_encode_bit(&mut self.rc, &mut self.is_rep[self.state], 0);

        let len_sym = length - MATCH_LEN_MIN;
        encode_len(&mut self.len_coder, &mut self.rc, pos_state, len_sym);
        self.encode_distance(length, distance);

        self.rep3 = self.rep2;
        self.rep2 = self.rep1;
        self.rep1 = self.rep0;
        self.rep0 = distance;
        self.state = state_after_match(self.state);
        self.output_pos += length as u64;
    }

    fn emit_short_rep(&mut self) {
        let pos_state = self.pos_state();
        let is_match_idx = self.state * POS_STATES_MAX + pos_state as usize;
        rc_encode_bit(&mut self.rc, &mut self.is_match[is_match_idx], 1);
        rc_encode_bit(&mut self.rc, &mut self.is_rep[self.state], 1);
        rc_encode_bit(&mut self.rc, &mut self.is_rep0[self.state], 0);
        rc_encode_bit(&mut self.rc, &mut self.is_rep0_long[is_match_idx], 0);

        self.state = state_after_short_rep(self.state);
        self.output_pos += 1;
    }

    fn emit_long_rep(&mut self, rep_idx: u32, length: u32) {
        let pos_state = self.pos_state();
        let is_match_idx = self.state * POS_STATES_MAX + pos_state as usize;
        rc_encode_bit(&mut self.rc, &mut self.is_match[is_match_idx], 1);
        rc_encode_bit(&mut self.rc, &mut self.is_rep[self.state], 1);

        match rep_idx {
            0 => {
                rc_encode_bit(&mut self.rc, &mut self.is_rep0[self.state], 0);
                rc_encode_bit(&mut self.rc, &mut self.is_rep0_long[is_match_idx], 1);
            }
            1 => {
                rc_encode_bit(&mut self.rc, &mut self.is_rep0[self.state], 1);
                rc_encode_bit(&mut self.rc, &mut self.is_rep1[self.state], 0);
            }
            2 => {
                rc_encode_bit(&mut self.rc, &mut self.is_rep0[self.state], 1);
                rc_encode_bit(&mut self.rc, &mut self.is_rep1[self.state], 1);
                rc_encode_bit(&mut self.rc, &mut self.is_rep2[self.state], 0);
            }
            _ => {
                rc_encode_bit(&mut self.rc, &mut self.is_rep0[self.state], 1);
                rc_encode_bit(&mut self.rc, &mut self.is_rep1[self.state], 1);
                rc_encode_bit(&mut self.rc, &mut self.is_rep2[self.state], 1);
            }
        }
        let len_sym = length - MATCH_LEN_MIN;
        let pos_state2 = pos_state;
        encode_len(&mut self.rep_len_coder, &mut self.rc, pos_state2, len_sym);

        match rep_idx {
            0 => {}
            1 => core::mem::swap(&mut self.rep0, &mut self.rep1),
            2 => {
                let d = self.rep2;
                self.rep2 = self.rep1;
                self.rep1 = self.rep0;
                self.rep0 = d;
            }
            _ => {
                let d = self.rep3;
                self.rep3 = self.rep2;
                self.rep2 = self.rep1;
                self.rep1 = self.rep0;
                self.rep0 = d;
            }
        }
        self.state = state_after_rep(self.state);
        self.output_pos += length as u64;
    }

    /// Snapshot the cheap per-flag bit prices used by the optimal parser.
    /// Recomputed periodically as the live probabilities drift.
    fn price_snapshot(&self, prices: &[u32; PRICE_TABLE_SIZE]) -> PriceSnapshot {
        let mut is_match = [[0u32; 2]; STATES * POS_STATES_MAX];
        let mut is_rep0_long = [[0u32; 2]; STATES * POS_STATES_MAX];
        for i in 0..STATES * POS_STATES_MAX {
            is_match[i][0] = price_bit0(prices, self.is_match[i]);
            is_match[i][1] = price_bit1(prices, self.is_match[i]);
            is_rep0_long[i][0] = price_bit0(prices, self.is_rep0_long[i]);
            is_rep0_long[i][1] = price_bit1(prices, self.is_rep0_long[i]);
        }
        let mut is_rep = [[0u32; 2]; STATES];
        let mut is_rep0 = [[0u32; 2]; STATES];
        let mut is_rep1 = [[0u32; 2]; STATES];
        let mut is_rep2 = [[0u32; 2]; STATES];
        for s in 0..STATES {
            is_rep[s][0] = price_bit0(prices, self.is_rep[s]);
            is_rep[s][1] = price_bit1(prices, self.is_rep[s]);
            is_rep0[s][0] = price_bit0(prices, self.is_rep0[s]);
            is_rep0[s][1] = price_bit1(prices, self.is_rep0[s]);
            is_rep1[s][0] = price_bit0(prices, self.is_rep1[s]);
            is_rep1[s][1] = price_bit1(prices, self.is_rep1[s]);
            is_rep2[s][0] = price_bit0(prices, self.is_rep2[s]);
            is_rep2[s][1] = price_bit1(prices, self.is_rep2[s]);
        }
        PriceSnapshot {
            is_match,
            is_rep,
            is_rep0,
            is_rep1,
            is_rep2,
            is_rep0_long,
        }
    }
}

/// Cached bit prices for the cheap per-decision flags. Length/distance/literal
/// prices are computed on demand from the core's live tables (which the
/// optimizer holds a reference to) since they have large key spaces.
struct PriceSnapshot {
    is_match: [[u32; 2]; STATES * POS_STATES_MAX],
    is_rep: [[u32; 2]; STATES],
    is_rep0: [[u32; 2]; STATES],
    is_rep1: [[u32; 2]; STATES],
    is_rep2: [[u32; 2]; STATES],
    is_rep0_long: [[u32; 2]; STATES * POS_STATES_MAX],
}

impl PriceSnapshot {
    /// Price of the rep-flag prefix selecting rep index `rep_idx` from `state`
    /// (the `is_rep`=1 bit plus the rep0/rep1/rep2 selector bits, but NOT the
    /// length and NOT the is_rep0_long bit for rep0).
    fn rep_choice_price(&self, state: usize, rep_idx: u32) -> u32 {
        let mut p = self.is_rep[state][1];
        match rep_idx {
            0 => p += self.is_rep0[state][0],
            1 => p += self.is_rep0[state][1] + self.is_rep1[state][0],
            2 => p += self.is_rep0[state][1] + self.is_rep1[state][1] + self.is_rep2[state][0],
            _ => p += self.is_rep0[state][1] + self.is_rep1[state][1] + self.is_rep2[state][1],
        }
        p
    }
}

fn rc_encode_bit(rc: &mut RangeEncoder, prob: &mut u16, bit: u32) {
    rc.encode_bit(prob, bit);
}
fn encode_len(lc: &mut LengthCoderEnc, rc: &mut RangeEncoder, pos_state: u32, len_sym: u32) {
    lc.encode(rc, pos_state, len_sym);
}

fn get_dist_slot(distance: u32) -> u32 {
    if distance < DIST_MODEL_START {
        return distance;
    }
    let n = 31 - distance.leading_zeros();
    2 * n + ((distance >> (n - 1)) & 1)
}

// ─── match finder ────────────────────────────────────────────────────────

/// Sliding-window 3-byte hash-chain match finder.
///
/// Positions stored in `head`/`prev` are **absolute** input offsets, but `prev`
/// is a ring buffer of `prev.len()` slots indexed `pos & prev_mask`. The ring
/// is sized strictly larger than `dict_size + MAX_MATCH_LEN`, so every chain
/// link the finder can legally follow (distance ≤ `dict_size`) is still intact:
/// a slot is only overwritten after `prev.len()` further insertions, by which
/// point that older position is already out of dictionary range and the walk
/// has broken on `dist > max_dist`. This keeps peak memory `O(dict_size)`
/// regardless of total input length while finding exactly the same matches a
/// whole-buffer chain would.
///
/// All byte reads go through the sliding window `win`, whose first byte is the
/// absolute offset `base`; an absolute position `p` reads `win[p - base]`.
struct HashChain {
    head: Vec<u32>,
    head_mask: usize,
    prev: Vec<u32>,
    prev_mask: usize,
}

impl HashChain {
    /// Build a finder whose `prev` ring covers at least `dict_size +
    /// MAX_MATCH_LEN` positions (rounded up to a power of two). `cap_hint`
    /// caps the ring when the total input is known to be smaller, so small
    /// inputs (and the unit tests) don't over-allocate.
    ///
    /// The bucket `head` table is sized to the same window so that the average
    /// chain length stays O(1) as the input grows (load factor ≈ 1); see the
    /// note on `HASH_MIN_BITS`. It is floored at `1 << HASH_MIN_BITS` so tiny
    /// inputs still get a usable spread.
    fn new(dict_size: u32, cap_hint: usize) -> Self {
        let needed = (dict_size as usize)
            .saturating_add(MAX_MATCH_LEN as usize)
            .saturating_add(2);
        let want = needed.min(cap_hint.max(1));
        let cap = want.max(1).next_power_of_two();
        let head_cap = cap.max(1 << HASH_MIN_BITS);
        Self {
            head: vec![NIL; head_cap],
            head_mask: head_cap - 1,
            prev: vec![NIL; cap],
            prev_mask: cap - 1,
        }
    }

    /// Splice absolute position `pos` into the chain. No-op if fewer than three
    /// bytes follow in the window.
    fn insert(&mut self, win: &[u8], base: usize, pos: usize) {
        let i = pos - base;
        if i + 3 > win.len() {
            return;
        }
        let h = hash3(win[i], win[i + 1], win[i + 2]) as usize & self.head_mask;
        self.prev[pos & self.prev_mask] = self.head[h];
        self.head[h] = pos as u32;
    }

    /// Find the single longest match (greedy use). Returns `(len, dist0based)`.
    fn find_longest(
        &self,
        win: &[u8],
        base: usize,
        pos: usize,
        dict_size: u32,
        params: EncoderParams,
    ) -> Option<(u32, u32)> {
        let pi = pos - base;
        if pi + 3 > win.len() {
            return None;
        }
        let h = hash3(win[pi], win[pi + 1], win[pi + 2]) as usize & self.head_mask;
        let max_len = MAX_MATCH_LEN.min((win.len() - pi) as u32);
        let max_dist = (dict_size as usize).min(pos);
        let mut best_len: u32 = 0;
        let mut best_dist: u32 = 0;
        let mut cur = self.head[h];
        let mut steps = 0usize;
        while cur != NIL && steps < params.max_chain {
            let cur_pos = cur as usize;
            if cur_pos >= pos {
                cur = self.prev[cur_pos & self.prev_mask];
                steps += 1;
                continue;
            }
            let dist = pos - cur_pos;
            if dist > max_dist {
                break;
            }
            let ci = cur_pos - base;
            if best_len > 2
                && (best_len as usize) < (win.len() - pi)
                && win[ci + best_len as usize] != win[pi + best_len as usize]
            {
                cur = self.prev[cur_pos & self.prev_mask];
                steps += 1;
                continue;
            }
            let len = match_len_at(win, ci, pi, max_len as usize);
            if len >= MATCH_LEN_MIN && len > best_len {
                best_len = len;
                best_dist = (dist - 1) as u32;
                if len >= params.nice_match {
                    break;
                }
            }
            cur = self.prev[cur_pos & self.prev_mask];
            steps += 1;
        }
        if best_len >= MATCH_LEN_MIN {
            Some((best_len, best_dist))
        } else {
            None
        }
    }

    /// Collect the candidate match set for the optimal parser: for each
    /// achievable length `>= MATCH_LEN_MIN`, the *shortest* distance that
    /// achieves it. `out` is filled with `(len, dist0based)` pairs in
    /// strictly increasing length order. Returns the longest length found.
    fn find_matches(
        &self,
        win: &[u8],
        base: usize,
        pos: usize,
        dict_size: u32,
        params: EncoderParams,
        out: &mut Vec<(u32, u32)>,
    ) -> u32 {
        out.clear();
        let pi = pos - base;
        if pi + 3 > win.len() {
            return 0;
        }
        let h = hash3(win[pi], win[pi + 1], win[pi + 2]) as usize & self.head_mask;
        let max_len = MAX_MATCH_LEN.min((win.len() - pi) as u32);
        let max_dist = (dict_size as usize).min(pos);
        let mut best_len: u32 = MATCH_LEN_MIN - 1;
        let mut cur = self.head[h];
        let mut steps = 0usize;
        while cur != NIL && steps < params.max_chain {
            let cur_pos = cur as usize;
            if cur_pos >= pos {
                cur = self.prev[cur_pos & self.prev_mask];
                steps += 1;
                continue;
            }
            let dist = pos - cur_pos;
            if dist > max_dist {
                break;
            }
            let ci = cur_pos - base;
            if best_len >= MATCH_LEN_MIN
                && (best_len as usize) < (win.len() - pi)
                && win[ci + best_len as usize] != win[pi + best_len as usize]
            {
                cur = self.prev[cur_pos & self.prev_mask];
                steps += 1;
                continue;
            }
            let len = match_len_at(win, ci, pi, max_len as usize);
            if len >= MATCH_LEN_MIN && len > best_len {
                // Chain is walked nearest-first, so this is the shortest
                // distance achieving every length in (best_len, len]. Record
                // one entry at `len`.
                out.push((len, (dist - 1) as u32));
                best_len = len;
                if len >= params.nice_match || len >= max_len {
                    break;
                }
            }
            cur = self.prev[cur_pos & self.prev_mask];
            steps += 1;
        }
        if best_len >= MATCH_LEN_MIN {
            best_len
        } else {
            0
        }
    }
}

// ─── rep-match helpers ───────────────────────────────────────────────────

/// Length of a repeat match at absolute `pos` against 0-based LZ distance
/// `dist`, reading from the sliding window `win` (first byte = absolute `base`).
fn rep_match_len(win: &[u8], base: usize, pos: usize, dist: u32) -> u32 {
    let d = dist as usize + 1;
    if d > pos {
        return 0;
    }
    let pi = pos - base;
    let max_len = MAX_MATCH_LEN.min((win.len() - pi) as u32) as usize;
    match_len_at(win, pi - d, pi, max_len)
}

// ─── parse decision replay ────────────────────────────────────────────────

/// One parser decision, replayed through the real (probability-updating)
/// emit functions after the optimal parse has chosen it.
#[derive(Clone, Copy)]
enum Decision {
    Literal,
    /// New match: `(distance0based, length)`.
    Match(u32, u32),
    /// Long rep: `(rep_index, length)`.
    Rep(u32, u32),
    ShortRep,
}

// ─── optimal parser ────────────────────────────────────────────────────────

/// A node in the optimum DP buffer. `price` is the cheapest known cost (in
/// 1/16-bit units) to reach this input offset; the back-pointer fields encode
/// the decision that produced the cheapest arrival.
#[derive(Clone, Copy)]
struct OptNode {
    price: u32,
    /// Offset of the previous node this arrival came from.
    prev_pos: u32,
    /// Decision taken from `prev_pos` to here.
    decision: Decision,
    /// State after arriving here.
    state: usize,
    /// Rep distances after arriving here.
    reps: [u32; 4],
}

const INFINITY_PRICE: u32 = u32::MAX;

/// Scratch buffers for the optimal parser.
struct Optimizer {
    opt: Vec<OptNode>,
    matches: Vec<(u32, u32)>,
    decisions: Vec<Decision>,
}

impl Optimizer {
    fn new(window: usize) -> Self {
        let cap = window + MAX_MATCH_LEN as usize + 2;
        Self {
            opt: vec![
                OptNode {
                    price: INFINITY_PRICE,
                    prev_pos: 0,
                    decision: Decision::Literal,
                    state: 0,
                    reps: [0; 4],
                };
                cap
            ],
            matches: Vec::with_capacity(64),
            decisions: Vec::with_capacity(window + 1),
        }
    }
}

/// Fill `row[len_sym]` with the price of every length symbol `0..LEN_SYMBOLS`
/// for the given length coder and `pos_state`. Mirrors [`LengthCoderEnc::price`]
/// exactly but amortises the per-symbol choice/bittree work across the whole
/// row — the optimal parser indexes the same `(pos_state, len)` cell many times
/// per window, so one row build replaces hundreds of repeated bittree walks.
fn fill_len_row(
    row: &mut [u32; LEN_SYMBOLS],
    lc: &LengthCoderEnc,
    prices: &[u32; PRICE_TABLE_SIZE],
    pos_state: u32,
) {
    let c0 = price_bit0(prices, lc.choice);
    let c1 = price_bit1(prices, lc.choice);
    let c2_0 = price_bit0(prices, lc.choice2);
    let c2_1 = price_bit1(prices, lc.choice2);

    let low_base = pos_state as usize * LEN_LOW_SYMBOLS;
    let low = &lc.low[low_base..low_base + LEN_LOW_SYMBOLS];
    for (l, cell) in row[..LEN_LOW_SYMBOLS].iter_mut().enumerate() {
        *cell = c0 + bittree_price(prices, low, LEN_LOW_BITS, l as u32);
    }

    let mid_base = pos_state as usize * LEN_MID_SYMBOLS;
    let mid = &lc.mid[mid_base..mid_base + LEN_MID_SYMBOLS];
    let mid_pref = c1 + c2_0;
    for (l, cell) in row[LEN_LOW_SYMBOLS..LEN_LOW_SYMBOLS + LEN_MID_SYMBOLS]
        .iter_mut()
        .enumerate()
    {
        *cell = mid_pref + bittree_price(prices, mid, LEN_MID_BITS, l as u32);
    }

    let hi_pref = c1 + c2_1;
    for (l, cell) in row[LEN_LOW_SYMBOLS + LEN_MID_SYMBOLS..]
        .iter_mut()
        .enumerate()
    {
        *cell = hi_pref + bittree_price(prices, &lc.high, LEN_HIGH_BITS, l as u32);
    }
}

/// Per-window cache of length-symbol prices, one row per `pos_state`, built
/// lazily on first use. Valid only while the live length-coder probabilities
/// are frozen — i.e. within a single `parse_window`, where `core` is borrowed
/// immutably. `reset` invalidates every row at the start of each window.
struct LenPriceCache {
    match_len: Box<[[u32; LEN_SYMBOLS]; POS_STATES_MAX]>,
    rep_len: Box<[[u32; LEN_SYMBOLS]; POS_STATES_MAX]>,
    match_valid: [bool; POS_STATES_MAX],
    rep_valid: [bool; POS_STATES_MAX],
}

impl LenPriceCache {
    fn new() -> Self {
        Self {
            match_len: Box::new([[0u32; LEN_SYMBOLS]; POS_STATES_MAX]),
            rep_len: Box::new([[0u32; LEN_SYMBOLS]; POS_STATES_MAX]),
            match_valid: [false; POS_STATES_MAX],
            rep_valid: [false; POS_STATES_MAX],
        }
    }

    /// Invalidate all rows; call once per `parse_window` before reuse.
    fn reset(&mut self) {
        self.match_valid = [false; POS_STATES_MAX];
        self.rep_valid = [false; POS_STATES_MAX];
    }

    #[inline]
    fn match_price(
        &mut self,
        core: &LzmaEncCore,
        prices: &[u32; PRICE_TABLE_SIZE],
        pos_state: u32,
        len_sym: u32,
    ) -> u32 {
        let ps = pos_state as usize;
        if !self.match_valid[ps] {
            fill_len_row(&mut self.match_len[ps], &core.len_coder, prices, pos_state);
            self.match_valid[ps] = true;
        }
        self.match_len[ps][len_sym as usize]
    }

    #[inline]
    fn rep_price(
        &mut self,
        core: &LzmaEncCore,
        prices: &[u32; PRICE_TABLE_SIZE],
        pos_state: u32,
        len_sym: u32,
    ) -> u32 {
        let ps = pos_state as usize;
        if !self.rep_valid[ps] {
            fill_len_row(
                &mut self.rep_len[ps],
                &core.rep_len_coder,
                prices,
                pos_state,
            );
            self.rep_valid[ps] = true;
        }
        self.rep_len[ps][len_sym as usize]
    }
}

/// Compute the price of a literal at absolute `pos` given the encoder's live
/// state, reading bytes from the sliding window `win` (first byte = `base`).
#[allow(clippy::too_many_arguments)]
fn literal_price_at(
    core: &LzmaEncCore,
    prices: &[u32; PRICE_TABLE_SIZE],
    snap: &PriceSnapshot,
    win: &[u8],
    base: usize,
    pos: usize,
    out_pos: u64,
    state: usize,
    rep0: u32,
) -> u32 {
    let pos_state = (out_pos as u32) & core.pos_mask;
    let im_idx = state * POS_STATES_MAX + pos_state as usize;
    let i = pos - base;
    let prev_byte = if pos > 0 { win[i - 1] } else { 0 };
    let match_byte = if state < LIT_STATES {
        None
    } else {
        let d = rep0 as usize + 1;
        if d <= pos { Some(win[i - d]) } else { None }
    };
    snap.is_match[im_idx][0] + core.literal_price(prices, out_pos, win[i], prev_byte, match_byte)
}

// ─── public chunk encoder ────────────────────────────────────────────────

/// Encode `input` as a single LZMA2 compressed chunk payload (the
/// range-coded body that follows the chunk header).
///
/// The returned byte vector contains the LZMA range-coded packet stream
/// plus the 5-byte range coder flush. There is no `.lzma` header and no
/// LZMA EOS marker — both would be wrong inside an LZMA2 chunk.
///
/// `dict_size` is the LZMA dictionary size to advertise. Match distances
/// are bounded by this value. For LZMA2 the dict size is shared across
/// all chunks of a block; pass a single value consistently.
///
/// `params` is the level-derived match-finder + parser tuning; see
/// [`EncoderParams::from_level`].
///
/// Single-chunk helper retained for the LZMA2 unit tests (which exercise the
/// chunk codec directly); the production encoders use [`Lzma2StreamEncoder`],
/// which keeps one continuous, bounded-memory match-finder across chunks.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn encode_lzma_chunk(input: &[u8], dict_size: u32, params: EncoderParams) -> Vec<u8> {
    if params.opt_window == 0 {
        return encode_chunk_body(input, dict_size, params, false);
    }
    // Run both parses and keep the smaller body. The optimal parse is almost
    // always smaller, but on tiny, highly-repetitive inputs its cold-start
    // price model can momentarily lose to greedy; this guard guarantees a
    // level never regresses below the greedy baseline.
    let opt = encode_chunk_body(input, dict_size, params, true);
    let greedy = encode_chunk_body(input, dict_size, params, false);
    if greedy.len() < opt.len() {
        greedy
    } else {
        opt
    }
}

/// Extra window history retained behind the current parse position, on top of
/// `dict_size`, so an insertion at `pos` never overwrites a still-reachable
/// older ring slot and a match at the very back of the dictionary can still be
/// fully read from the window. `MAX_MATCH_LEN` covers the longest readable
/// match; a small constant covers the `prev_byte`/`match_byte` look-back.
const WINDOW_SLOP: usize = MAX_MATCH_LEN as usize + 16;

/// One framed LZMA2 chunk produced by [`Lzma2StreamEncoder`].
///
/// The caller (xz Block payload or raw LZMA2 stream framing) turns this into
/// the on-wire chunk header + body. `uncomp_len` is the number of input bytes
/// the chunk covers; for a compressed chunk `body` is the range-coded payload,
/// for an uncompressed chunk `body` is empty and the caller copies the
/// `uncomp_len` raw input bytes verbatim.
pub(crate) struct Lzma2Chunk {
    /// Number of uncompressed input bytes this chunk represents.
    pub uncomp_len: usize,
    /// `true` when this is the first chunk of the stream and therefore must
    /// reset the dictionary (`0xE0` compressed / `0x01` uncompressed); `false`
    /// for every later chunk, which continues the dictionary.
    pub reset_dict: bool,
    /// For a compressed chunk (`body.is_some()`): `true` when the LZMA state +
    /// probability model are reset for this chunk (control `0xE0` on the first
    /// chunk, `0xC0` otherwise — both carry a props byte); `false` when the
    /// model is *continued* from the previous chunk (control `0x80`, no props
    /// byte), which is the common case on compressible data and what lets the
    /// adaptive model warm across chunk boundaries. Ignored for uncompressed
    /// chunks (their control is `0x01`/`0x02`, chosen from `reset_dict`).
    pub reset_state: bool,
    /// `Some(range-coded body)` for a compressed chunk; `None` for an
    /// uncompressed-fallback chunk (the caller copies the raw input slice).
    pub body: Option<Vec<u8>>,
}

/// Largest uncompressed payload a single compressed chunk may carry. The
/// compressed-chunk uncompressed-size field is 21 bits (+1 ⇒ 2 MiB), but we
/// cap at 64 KiB so the *compressed* size always fits the 16-bit (+1) comp
/// field and the chunk header shape stays uniform with the uncompressed
/// fallback. The dictionary still spans the whole input regardless of this
/// slice size — only the output framing is chunked.
const STREAM_CHUNK_UNCOMP_MAX: usize = 65_536;

/// Streaming continuous-dictionary LZMA2 chunk encoder with **bounded memory**.
///
/// Keeps a single LZ match-finder and a continuous `output_pos` across all
/// chunks — the first chunk resets the dictionary, every later chunk continues
/// it, so a match in a later chunk references data from any earlier chunk up to
/// `dict_size`. Memory is bounded to `O(dict_size)` regardless of input length:
///
/// - The match finder's `prev` ring is sized `O(dict_size)` (see [`HashChain`]).
/// - Only a sliding window of roughly `dict_size + WINDOW_SLOP` history plus one
///   pending chunk of lookahead is retained in `win`; older bytes are dropped
///   once the parse position has moved `> dict_size + WINDOW_SLOP` past them.
///
/// Feed input with [`push`](Self::push) (which returns any chunks that became
/// fully buffered) and finish with [`finish`](Self::finish). The caller frames
/// each [`Lzma2Chunk`] and is responsible for the `0x00` end marker and any
/// container framing.
pub(crate) struct Lzma2StreamEncoder {
    core: LzmaEncCore,
    hc: HashChain,
    dict_size: u32,
    params: EncoderParams,
    /// Retained window bytes; `win[0]` is absolute offset `win_base`.
    win: Vec<u8>,
    /// Absolute offset of `win[0]`.
    win_base: usize,
    /// Absolute offset of the next byte to encode (== bytes already framed).
    pos: usize,
    /// Absolute count of bytes appended via `push` (encodable extent).
    appended: usize,
    /// `true` until the first chunk is emitted.
    first: bool,
    /// `true` when the next compressed chunk must reset the LZMA state +
    /// probability model rather than continue it. Set on the first chunk and
    /// after any uncompressed-fallback chunk: an uncompressed chunk is not run
    /// through the model on decode, and the discarded compressed attempt has
    /// already mutated our model, so the two would desync unless the next
    /// compressed chunk resets both sides back to a known state.
    need_state_reset: bool,
}

impl Lzma2StreamEncoder {
    pub fn new(dict_size: u32, params: EncoderParams) -> Self {
        // The ring need never exceed what a 32-bit input could address; the
        // dict cap already keeps this `O(dict_size)`.
        let cap_hint = (dict_size as usize)
            .saturating_add(MAX_MATCH_LEN as usize)
            .saturating_add(WINDOW_SLOP + STREAM_CHUNK_UNCOMP_MAX);
        Self {
            core: LzmaEncCore::new(),
            hc: HashChain::new(dict_size, cap_hint),
            dict_size,
            params,
            win: Vec::new(),
            win_base: 0,
            pos: 0,
            appended: 0,
            first: true,
            need_state_reset: true,
        }
    }

    /// Append `data` and emit every chunk that is now fully buffered. A chunk is
    /// only encoded once a whole `STREAM_CHUNK_UNCOMP_MAX` slice (or the rest of
    /// the stream, at `finish`) is available, so the optimal parser always sees
    /// its full forward lookahead within the chunk.
    pub fn push(&mut self, data: &[u8]) -> Vec<Lzma2Chunk> {
        self.win.extend_from_slice(data);
        self.appended += data.len();
        let mut out = Vec::new();
        // Encode while a full chunk's worth of bytes is buffered ahead of `pos`.
        while self.appended - self.pos >= STREAM_CHUNK_UNCOMP_MAX {
            out.push(self.encode_one_chunk(self.pos + STREAM_CHUNK_UNCOMP_MAX));
            self.trim_window();
        }
        out
    }

    /// Flush any remaining buffered bytes as a final chunk (or chunks).
    pub fn finish(&mut self) -> Vec<Lzma2Chunk> {
        let mut out = Vec::new();
        while self.pos < self.appended {
            let end = (self.pos + STREAM_CHUNK_UNCOMP_MAX).min(self.appended);
            out.push(self.encode_one_chunk(end));
            self.trim_window();
        }
        out
    }

    /// Encode the chunk `[self.pos, chunk_end)` and advance `self.pos`.
    fn encode_one_chunk(&mut self, chunk_end: usize) -> Lzma2Chunk {
        let uncomp_len = chunk_end - self.pos;
        // Reset the model on the first chunk and after any uncompressed chunk;
        // otherwise continue it (control `0x80`) so the adaptive model warms
        // across chunk boundaries.
        let reset_state = self.first || self.need_state_reset;
        let body = self.encode_chunk_body(chunk_end, reset_state);
        let use_compressed = !body.is_empty() && body.len() <= 65_536 && body.len() < uncomp_len;
        let chunk = Lzma2Chunk {
            uncomp_len,
            reset_dict: self.first,
            reset_state,
            body: if use_compressed { Some(body) } else { None },
        };
        self.pos = chunk_end;
        self.first = false;
        // A compressed chunk leaves the model in a state the decoder will
        // reproduce, so the next chunk may continue it. An uncompressed
        // fallback does not: the decoder never runs the model over it, and this
        // chunk's discarded compressed attempt already mutated our copy — force
        // the next compressed chunk to reset both sides back into sync.
        self.need_state_reset = !use_compressed;
        chunk
    }

    /// Range-code `[self.pos, chunk_end)` through the shared core/hash chain.
    /// When `reset_state` is set, re-initialise the LZMA state + probability
    /// model first (control `0xC0`/`0xE0` semantics); otherwise keep the model
    /// running and reset only the per-chunk range coder (control `0x80`). Either
    /// way `output_pos` and the LZ history are preserved.
    fn encode_chunk_body(&mut self, chunk_end: usize, reset_state: bool) -> Vec<u8> {
        if reset_state {
            self.core.reset_state_keep_pos();
        } else {
            self.core.reset_range_coder();
        }
        let base = self.win_base;
        let start = self.pos;
        if self.params.opt_window == 0 {
            encode_greedy(
                &mut self.core,
                &mut self.hc,
                &self.win,
                base,
                start,
                chunk_end,
                self.dict_size,
                self.params,
            );
        } else {
            encode_optimal(
                &mut self.core,
                &mut self.hc,
                &self.win,
                base,
                start,
                chunk_end,
                self.dict_size,
                self.params,
            );
        }
        self.core.rc.flush();
        self.core.rc.out.clone()
    }

    /// Drop window history older than `dict_size + WINDOW_SLOP` before `pos`, so
    /// peak `win` memory stays `O(dict_size)`. Never drops bytes a future match
    /// could read (distance ≤ `dict_size`) or the parse look-back needs.
    ///
    /// The front-shift is only performed once the droppable prefix grows past a
    /// whole `dict_size + WINDOW_SLOP` of waste, so the `drain` memmove cost is
    /// amortised `O(1)` per input byte (rather than memmoving `~dict_size` bytes
    /// every chunk, which would be quadratic over a large stream).
    fn trim_window(&mut self) {
        let keep_from = self
            .pos
            .saturating_sub(self.dict_size as usize + WINDOW_SLOP);
        let droppable = keep_from.saturating_sub(self.win_base);
        if droppable >= self.dict_size as usize + WINDOW_SLOP {
            self.win.drain(..droppable);
            self.win_base = keep_from;
        }
    }
}

/// Encode one chunk body (range-coded packets + 5-byte flush, no EOS marker)
/// using the greedy or optimal parse. Only reachable from the test-only
/// [`encode_lzma_chunk`].
#[cfg_attr(not(test), allow(dead_code))]
fn encode_chunk_body(
    input: &[u8],
    dict_size: u32,
    params: EncoderParams,
    optimal: bool,
) -> Vec<u8> {
    let mut core = LzmaEncCore::new();
    let mut hc = HashChain::new(dict_size, input.len().max(1));

    if optimal {
        encode_optimal(
            &mut core,
            &mut hc,
            input,
            0,
            0,
            input.len(),
            dict_size,
            params,
        );
    } else {
        encode_greedy(
            &mut core,
            &mut hc,
            input,
            0,
            0,
            input.len(),
            dict_size,
            params,
        );
    }

    // Flush the range coder. NO EOS marker — LZMA2 frames the uncompressed
    // length externally and decoders read exactly that many bytes.
    core.rc.flush();
    core.rc.out
}

/// Greedy/lazy parse — used by the lowest levels where speed matters most and
/// the optimal-parse overhead isn't worth it.
///
/// Encodes `input[pos_start..pos_end]`. Match finding may reference any earlier
/// position in `input` (the LZ history is the whole buffer up to `pos`), but
/// emitted match/rep lengths are clamped so the parse stops exactly at
/// `pos_end` — this lets a continuous encoder slice the output into chunks
/// without ever crossing a chunk's uncompressed-size boundary.
#[allow(clippy::too_many_arguments)]
fn encode_greedy(
    core: &mut LzmaEncCore,
    hc: &mut HashChain,
    win: &[u8],
    base: usize,
    pos_start: usize,
    pos_end: usize,
    dict_size: u32,
    params: EncoderParams,
) {
    let win_end = base + win.len();
    let mut pos = pos_start;
    while pos < pos_end {
        // Bytes left until this chunk's boundary; emitted lengths never exceed
        // it so the chunk ends exactly at `pos_end`.
        let cap = (pos_end - pos) as u32;
        let rep_lens = [
            rep_match_len(win, base, pos, core.rep0).min(cap),
            rep_match_len(win, base, pos, core.rep1).min(cap),
            rep_match_len(win, base, pos, core.rep2).min(cap),
            rep_match_len(win, base, pos, core.rep3).min(cap),
        ];

        let new_match = hc
            .find_longest(win, base, pos, dict_size, params)
            .map(|(l, d)| (l.min(cap), d));

        let best_rep_len = rep_lens.iter().copied().max().unwrap_or(0);
        let best_rep_idx = rep_lens
            .iter()
            .enumerate()
            .max_by_key(|&(_, &l)| l)
            .map(|(i, _)| i as u32)
            .unwrap_or(0);

        let new_match_len = new_match.map(|(l, _)| l).unwrap_or(0);

        let emit_new = new_match_len > best_rep_len && new_match_len >= MATCH_LEN_MIN;
        let emit_rep_long = !emit_new && best_rep_len >= MATCH_LEN_MIN;
        let emit_short_rep = !emit_new && !emit_rep_long && rep_lens[0] >= 1;

        hc.insert(win, base, pos);

        if emit_new {
            let (len, dist) = new_match.unwrap();
            for j in 1..(len as usize) {
                let p = pos + j;
                if p + 3 <= win_end {
                    hc.insert(win, base, p);
                }
            }
            core.emit_match(dist, len);
            pos += len as usize;
        } else if emit_rep_long {
            for j in 1..(best_rep_len as usize) {
                let p = pos + j;
                if p + 3 <= win_end {
                    hc.insert(win, base, p);
                }
            }
            core.emit_long_rep(best_rep_idx, best_rep_len);
            pos += best_rep_len as usize;
        } else if emit_short_rep {
            core.emit_short_rep();
            pos += 1;
        } else {
            core.emit_literal(win, base, pos);
            pos += 1;
        }
    }
}

/// Cost-based optimal parse: forward DP over a look-ahead window, committing
/// the cheapest path through the optimum buffer, then replaying decisions
/// through the real (probability-updating) emit functions.
///
/// Encodes `input[pos_start..pos_end]`; matches still reference the whole LZ
/// history before `pos`, but the parse never advances past `pos_end`, so the
/// chunk ends exactly there.
#[allow(clippy::too_many_arguments)]
fn encode_optimal(
    core: &mut LzmaEncCore,
    hc: &mut HashChain,
    win: &[u8],
    base: usize,
    pos_start: usize,
    pos_end: usize,
    dict_size: u32,
    params: EncoderParams,
) {
    let prob_prices = build_prob_prices();
    let window = params.opt_window as usize;
    let mut opt = Optimizer::new(window);
    let mut lpc = LenPriceCache::new();

    let mut pos = pos_start;
    // The length-price rows in `lpc` are recomputed from the live model only
    // every `LEN_PRICE_REFRESH` committed *decisions*, not every window:
    // early-commit on long matches makes windows as short as a single (long)
    // match decision, so a per-window rebuild of the 272-entry rows never
    // amortises (it dominated the profile). Counting decisions — as the LZMA SDK
    // counts length encodes — makes the refresh interval span many windows on
    // match-heavy input while staying frequent on literal-heavy input, and
    // leaves prices close enough to the live model that the ratio is unchanged.
    const LEN_PRICE_REFRESH: usize = 128;
    let mut since_refresh = LEN_PRICE_REFRESH; // force a build before the first window
    // Refresh the price snapshot once per committed window. Prices drift as
    // the model adapts; refreshing each window keeps them close to the live
    // model without recomputing per byte.
    while pos < pos_end {
        if since_refresh >= LEN_PRICE_REFRESH {
            lpc.reset();
            since_refresh = 0;
        }
        let snap = core.price_snapshot(&prob_prices);
        let parsed = parse_window(
            core,
            hc,
            win,
            base,
            pos,
            pos_end,
            dict_size,
            params,
            window,
            &prob_prices,
            &snap,
            &mut opt,
            &mut lpc,
        );
        debug_assert!(parsed > 0);
        // Replay the chosen decisions through the real emit path. `pos`
        // advances by exactly `parsed` bytes.
        replay(core, hc, win, base, pos, &opt.decisions);
        pos += parsed;
        since_refresh += opt.decisions.len();
    }
}

/// Parse a single look-ahead window starting at `start`. Fills
/// `opt.decisions` with the cheapest sequence of decisions covering the
/// reachable commit boundary, and returns the number of input bytes the
/// decisions consume. The hash chain is NOT mutated here (read-only match
/// finding); `replay` handles insertion.
#[allow(clippy::too_many_arguments)]
fn parse_window(
    core: &LzmaEncCore,
    hc: &HashChain,
    win: &[u8],
    base: usize,
    start: usize,
    pos_end: usize,
    dict_size: u32,
    params: EncoderParams,
    window: usize,
    prices: &[u32; PRICE_TABLE_SIZE],
    snap: &PriceSnapshot,
    opt: &mut Optimizer,
    lpc: &mut LenPriceCache,
) -> usize {
    // `avail` is bounded by the chunk boundary, not the end of input, so the
    // DP never produces a decision that would carry past `pos_end`.
    let avail = pos_end - start;
    let limit = window.min(avail);

    // Initialize node 0 with the encoder's current live state.
    opt.opt[0] = OptNode {
        price: 0,
        prev_pos: 0,
        decision: Decision::Literal,
        state: core.state,
        reps: [core.rep0, core.rep1, core.rep2, core.rep3],
    };
    for node in opt.opt[1..=limit].iter_mut() {
        node.price = INFINITY_PRICE;
    }

    // Hard commit cap: even without a long match we commit after this many
    // bytes so the price snapshot is refreshed frequently against the live
    // (adapting) model. Without this, a long literal run parsed under a single
    // stale snapshot makes systematically worse rep-vs-match decisions.
    const COMMIT_CAP: usize = 192;

    // `reached` is the furthest offset we've filled a finite price for.
    let mut reached = 0usize;
    // When a long match is found at some position we stop extending the DP and
    // commit up to that match's end, keeping the committed segment short so the
    // price snapshot stays close to the live model. `None` means run to the
    // window limit.
    let mut commit_end: Option<usize> = None;

    let mut cur = 0usize;
    while cur < limit {
        if let Some(ce) = commit_end
            && cur >= ce
        {
            break;
        }
        if commit_end.is_none() && cur >= COMMIT_CAP {
            commit_end = Some(cur);
            break;
        }
        let node = opt.opt[cur];
        if node.price == INFINITY_PRICE {
            cur += 1;
            continue;
        }
        let pos = start + cur;
        let out_pos = core.output_pos + cur as u64;
        let state = node.state;
        let reps = node.reps;
        let pos_state = (out_pos as u32) & core.pos_mask;
        let im_idx = state * POS_STATES_MAX + pos_state as usize;
        // Longest match (rep or new) seen at this position; drives the
        // early-commit decision below.
        let mut best_here: u32 = 0;

        // ── literal transition ──────────────────────────────────────────
        {
            let lp = literal_price_at(core, prices, snap, win, base, pos, out_pos, state, reps[0]);
            let np = node.price.saturating_add(lp);
            let to = cur + 1;
            if to <= limit && np < opt.opt[to].price {
                opt.opt[to] = OptNode {
                    price: np,
                    prev_pos: cur as u32,
                    decision: Decision::Literal,
                    state: state_after_literal(state),
                    reps,
                };
                if to > reached {
                    reached = to;
                }
            }
        }

        // Base price of choosing "match" (is_match=1).
        let match_flag = snap.is_match[im_idx][1];

        // ── rep matches (rep0..rep3) ────────────────────────────────────
        for rep_idx in 0..4u32 {
            let rlen = rep_match_len(win, base, pos, reps[rep_idx as usize]);
            if rlen < 1 {
                continue;
            }
            // Short-rep (length 1, rep0 only).
            if rep_idx == 0 {
                let sp = match_flag
                    + snap.is_rep[state][1]
                    + snap.is_rep0[state][0]
                    + snap.is_rep0_long[im_idx][0];
                let np = node.price.saturating_add(sp);
                let to = cur + 1;
                if to <= limit && np < opt.opt[to].price {
                    opt.opt[to] = OptNode {
                        price: np,
                        prev_pos: cur as u32,
                        decision: Decision::ShortRep,
                        state: state_after_short_rep(state),
                        reps,
                    };
                    if to > reached {
                        reached = to;
                    }
                }
            }
            if rlen < MATCH_LEN_MIN {
                continue;
            }
            if rlen > best_here {
                best_here = rlen;
            }
            let rep_new_reps = reorder_reps(reps, rep_idx);
            let choice = match_flag + snap.rep_choice_price(state, rep_idx);
            let rep0_long = if rep_idx == 0 {
                snap.is_rep0_long[im_idx][1]
            } else {
                0
            };
            let st_after = state_after_rep(state);
            let cap = (limit - cur) as u32;
            let maxr = rlen.min(cap);
            let mut l = MATCH_LEN_MIN;
            while l <= maxr {
                let len_price = lpc.rep_price(core, prices, pos_state, l - MATCH_LEN_MIN);
                let np = node.price.saturating_add(choice + rep0_long + len_price);
                let to = cur + l as usize;
                if np < opt.opt[to].price {
                    opt.opt[to] = OptNode {
                        price: np,
                        prev_pos: cur as u32,
                        decision: Decision::Rep(rep_idx, l),
                        state: st_after,
                        reps: rep_new_reps,
                    };
                    if to > reached {
                        reached = to;
                    }
                }
                l += 1;
            }
        }

        // ── new matches ─────────────────────────────────────────────────
        let longest = {
            let opt_matches = &mut opt.matches;
            hc.find_matches(win, base, pos, dict_size, params, opt_matches)
        };
        if longest >= MATCH_LEN_MIN {
            if longest > best_here {
                best_here = longest;
            }
            let match_choice = match_flag + snap.is_rep[state][0];
            let st_after = state_after_match(state);
            let cap = (limit - cur) as u32;
            let mut prev_len = MATCH_LEN_MIN - 1;
            let nmatches = opt.matches.len();
            for mi in 0..nmatches {
                let (mlen, mdist) = opt.matches[mi];
                let band_end = mlen.min(cap);
                // The distance price depends on length only through the
                // length→dist-state bucket, which is non-decreasing in length and
                // saturates at `DIST_STATES - 1` (every length ≥ `DIST_STATES +
                // MATCH_LEN_MIN - 1` shares one price). Recompute it only when that
                // bucket actually changes — a band starting at length ≥ 5 (the
                // common case) needs a single dist-slot bittree walk instead of
                // one per length. This recompute was ~20% of the realistic-input
                // profile.
                let mut l = (prev_len + 1).max(MATCH_LEN_MIN);
                let mut dist_state = usize::MAX;
                let mut dist_price = 0u32;
                while l <= band_end {
                    let len_price = lpc.match_price(core, prices, pos_state, l - MATCH_LEN_MIN);
                    let ds = ((l - MATCH_LEN_MIN) as usize).min(DIST_STATES - 1);
                    if ds != dist_state {
                        dist_price = core.distance_price(prices, l, mdist);
                        dist_state = ds;
                    }
                    let np = node
                        .price
                        .saturating_add(match_choice + len_price + dist_price);
                    let to = cur + l as usize;
                    if np < opt.opt[to].price {
                        let new_reps = [mdist, reps[0], reps[1], reps[2]];
                        opt.opt[to] = OptNode {
                            price: np,
                            prev_pos: cur as u32,
                            decision: Decision::Match(mdist, l),
                            state: st_after,
                            reps: new_reps,
                        };
                        if to > reached {
                            reached = to;
                        }
                    }
                    l += 1;
                }
                prev_len = mlen;
            }
        }

        // Early-commit: once a long match is reachable from this position, the
        // optimal path almost certainly takes it, and there's little value in
        // extending the DP past it with increasingly stale prices. Commit up
        // to its end. This mirrors the SDK's `nice_len` cut-off in GetOptimum.
        if commit_end.is_none() && best_here >= params.nice_len {
            let bounded = (cur + best_here as usize).min(limit);
            commit_end = Some(bounded);
            // The long match from this node already writes the cheapest known
            // arrival at `bounded` (a single match decision). Stop extending the
            // DP now instead of grinding through every position the match spans
            // — on long-match runs (highly repetitive input) that band would
            // otherwise cost O(nice..273) work per covered byte, turning the
            // parse quadratic. Committing the match here matches the SDK's
            // greedy `nice_len` acceptance and leaves ratio essentially
            // unchanged.
            break;
        }

        cur += 1;
    }

    // Commit boundary. If an early long match capped the DP, commit exactly to
    // its end; otherwise commit the furthest reached offset (always `limit`,
    // since literals reach every offset). `max(1)` guards `limit == 0`.
    let end = match commit_end {
        Some(ce) => ce.max(1).min(reached.max(1)),
        None => reached.max(1),
    }
    .min(avail);
    trace_back(opt, end);
    end
}

/// Reorder rep distances for a long rep referencing index `rep_idx`.
fn reorder_reps(reps: [u32; 4], rep_idx: u32) -> [u32; 4] {
    match rep_idx {
        0 => reps,
        1 => [reps[1], reps[0], reps[2], reps[3]],
        2 => [reps[2], reps[0], reps[1], reps[3]],
        _ => [reps[3], reps[0], reps[1], reps[2]],
    }
}

/// Trace back the cheapest path from offset `end` to 0, filling
/// `opt.decisions` in forward order.
fn trace_back(opt: &mut Optimizer, end: usize) {
    opt.decisions.clear();
    let mut cur = end;
    while cur > 0 {
        let node = opt.opt[cur];
        opt.decisions.push(node.decision);
        cur = node.prev_pos as usize;
    }
    opt.decisions.reverse();
}

/// Replay chosen decisions through the real emit path, updating the hash chain
/// and the live probability model.
fn replay(
    core: &mut LzmaEncCore,
    hc: &mut HashChain,
    win: &[u8],
    base: usize,
    start: usize,
    decisions: &[Decision],
) {
    let win_end = base + win.len();
    let mut pos = start;
    for &d in decisions {
        match d {
            Decision::Literal => {
                hc.insert(win, base, pos);
                core.emit_literal(win, base, pos);
                pos += 1;
            }
            Decision::ShortRep => {
                hc.insert(win, base, pos);
                core.emit_short_rep();
                pos += 1;
            }
            Decision::Match(dist, len) => {
                for j in 0..(len as usize) {
                    let p = pos + j;
                    if p + 3 <= win_end {
                        hc.insert(win, base, p);
                    }
                }
                core.emit_match(dist, len);
                pos += len as usize;
            }
            Decision::Rep(idx, len) => {
                for j in 0..(len as usize) {
                    let p = pos + j;
                    if p + 3 <= win_end {
                        hc.insert(win, base, p);
                    }
                }
                core.emit_long_rep(idx, len);
                pos += len as usize;
            }
        }
    }
}
