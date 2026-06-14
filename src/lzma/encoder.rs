//! Legacy `.lzma` (alone) encoder.
//!
//! Companion to the decoder in `super`. Implements the LZMA range coder,
//! probability model, and a 3-byte hash-chain greedy match finder.
//!
//! Strategy: buffer all input into a `Vec<u8>`, then on `finish` run a single
//! greedy LZMA encode pass producing a byte stream comprising
//!
//! - 13-byte header (`properties`, `dict_size_le`, `uncompressed_size_le`)
//! - range-coded packet stream
//! - end-of-stream marker (match dist=0xFFFFFFFF, len=2)
//! - 5 bytes of range-coder flush.
//!
//! Header choices: `lc=3, lp=0, pb=2` (the standard preset, packed to 0x5d);
//! dictionary size derived from [`EncoderConfig::level`] (clamped to the
//! input length rounded up to a power of two, so a short input never forces
//! the decoder to allocate a huge window); uncompressed size left as
//! `u64::MAX` so the EOS marker terminates the stream — matches what
//! Python's `lzma.compress(..., format=lzma.FORMAT_ALONE)` produces.
//!
//! Quality: a greedy parser with a bounded hash-chain match search. Output is
//! valid LZMA but noticeably weaker than xz at level 6 — there is no lazy
//! matching, no optimal parsing, and no price-based selection of rep slots.
//! The constraints of this task are correctness and decoder-symmetry, not
//! compression ratio.

extern crate alloc;
use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;
use crate::traits::{RawEncoder, RawProgress};

use super::{
    ALIGN_BITS, ALIGN_SIZE, DIST_MODEL_END, DIST_MODEL_START, DIST_SLOT_BITS, DIST_SLOTS,
    DIST_STATES, FULL_DISTANCES, LEN_HIGH_BITS, LEN_HIGH_SYMBOLS, LEN_LOW_BITS, LEN_LOW_SYMBOLS,
    LEN_MID_BITS, LEN_MID_SYMBOLS, LIT_STATES, MATCH_LEN_MIN, POS_STATES_MAX, PROB_INIT,
    RC_BIT_MODEL_TOTAL, RC_BIT_MODEL_TOTAL_BITS, RC_MOVE_BITS, RC_TOP_VALUE, STATES,
    state_after_literal, state_after_match, state_after_rep, state_after_short_rep,
};

// ─── encoder parameters ──────────────────────────────────────────────────

/// Properties byte = `(pb*5 + lp)*9 + lc` per the LZMA spec; (3, 0, 2) packs
/// to 0x5d — the canonical default that Python's `lzma.FORMAT_ALONE` emits.
const ENC_LC: u32 = 3;
const ENC_LP: u32 = 0;
const ENC_PB: u32 = 2;
const ENC_PROPS_BYTE: u8 = (ENC_PB * 5 + ENC_LP) as u8 * 9 + ENC_LC as u8;

const MAX_MATCH_LEN: u32 = 273; // 2 + 8 + 8 + 255 (LEN_LOW + LEN_MID + LEN_HIGH)

// Hash chain match finder configuration.
const HASH_BITS: u32 = 16;
const HASH_SIZE: usize = 1 << HASH_BITS;
const NIL: u32 = u32::MAX;

/// Minimum advertised dictionary size. LZMA's decoder clamps below 4 KiB so
/// the header must carry at least that much.
const MIN_DICT_SIZE: u32 = 1 << 12; // 4 KiB

// ─── compression level ──────────────────────────────────────────────────

/// Tunables for the LZMA encoder.
///
/// `level` controls the speed/ratio trade-off. `0` is fastest and produces
/// the largest output; `9` is slowest and produces the smallest. The default
/// of `6` mirrors xz's default. Values outside `0..=9` are clamped at
/// encoder construction time rather than rejected.
///
/// Internally `level` maps to the advertised dictionary size and the
/// match-finder's chain budget / nice-match cutoff — the same quality knobs
/// the xz reference encoder exposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncoderConfig {
    /// Compression level in `0..=9`.
    pub level: u8,
}

impl Default for EncoderConfig {
    fn default() -> Self {
        Self { level: 6 }
    }
}

/// Per-level match-finder knobs. The table mirrors xz's preset table for the
/// quality dimensions our encoder can vary: dictionary size (advertised in
/// the header and used as `max_dist` in the match finder), how deep the hash
/// chain walks, and when to stop probing.
#[derive(Debug, Clone, Copy)]
struct LevelParams {
    /// Dictionary size advertised in the header (and the cap on `max_dist`
    /// inside the match finder). Capped to 64 MiB so the decoder's
    /// `DIC_SIZE_MAX` clamp doesn't kick in.
    dict_size: u32,
    /// Maximum number of hash-chain links the match finder walks per probe.
    max_chain: usize,
    /// Length at which the match finder stops looking for a longer candidate.
    nice_match: u32,
    /// Length at which the optimal parser early-commits the current window
    /// (a match this long is almost certainly taken, so there's no value in
    /// extending the DP past it with increasingly stale prices). Keeping this
    /// modest keeps committed segments short and prices fresh.
    nice_len: u32,
    /// Optimal-parser look-ahead window (number of optimum-buffer slots). When
    /// `0` the parser falls back to a fast greedy/lazy parse.
    opt_window: u32,
}

impl LevelParams {
    fn from_level(level: u8) -> Self {
        let level = level.min(9);
        // Mirrors xz's preset table for dictionary size, then a graduated
        // chain budget / nice-match cutoff and optimal-parse window that grow
        // with level. The numbers don't have to match xz precisely — what
        // matters is that a higher level walks deeper chains, accepts longer
        // matches, and looks further ahead in the cost-based parse.
        match level {
            0 => Self {
                dict_size: 1 << 16, // 64 KiB
                max_chain: 8,
                nice_match: 8,
                nice_len: 8,
                opt_window: 0,
            },
            1 => Self {
                dict_size: 1 << 20, // 1 MiB
                max_chain: 16,
                nice_match: 16,
                nice_len: 16,
                opt_window: 0,
            },
            2 => Self {
                dict_size: 1 << 21, // 2 MiB
                max_chain: 24,
                nice_match: 32,
                nice_len: 32,
                opt_window: 0,
            },
            3 => Self {
                dict_size: 1 << 22, // 4 MiB
                max_chain: 32,
                nice_match: 64,
                nice_len: 16,
                opt_window: 512,
            },
            4 => Self {
                dict_size: 1 << 22, // 4 MiB
                max_chain: 64,
                nice_match: 128,
                nice_len: 24,
                opt_window: 1024,
            },
            5 => Self {
                dict_size: 1 << 23, // 8 MiB
                max_chain: 128,
                nice_match: 192,
                nice_len: 32,
                opt_window: 2048,
            },
            6 => Self {
                dict_size: 1 << 23, // 8 MiB
                max_chain: 256,
                nice_match: 273,
                nice_len: 48,
                opt_window: 4096,
            },
            7 => Self {
                dict_size: 1 << 24, // 16 MiB
                max_chain: 512,
                nice_match: 273,
                nice_len: 64,
                opt_window: 4096,
            },
            8 => Self {
                dict_size: 1 << 25, // 32 MiB
                max_chain: 1024,
                nice_match: 273,
                nice_len: 96,
                opt_window: 4096,
            },
            _ => Self {
                dict_size: 1 << 26, // 64 MiB (level 9)
                max_chain: 2048,
                nice_match: MAX_MATCH_LEN,
                nice_len: 128,
                opt_window: 4096,
            },
        }
    }

    /// Compute the dict size actually written into the header for an input of
    /// `input_len` bytes. We never claim more than what could possibly be
    /// referenced, so a 1 KiB input doesn't force the decoder to allocate a
    /// 64 MiB window. The advertised size is also clamped to the decoder's
    /// minimum of 4 KiB.
    fn effective_dict_size(&self, input_len: usize) -> u32 {
        // Round `input_len` up to a power of two (clamped at u32::MAX). Empty
        // input gets the minimum dict; `next_power_of_two` would panic on 0.
        let needed = if input_len == 0 {
            MIN_DICT_SIZE
        } else {
            let np2 = (input_len as u64)
                .checked_next_power_of_two()
                .unwrap_or(u32::MAX as u64);
            np2.min(u32::MAX as u64) as u32
        };
        let needed = needed.max(MIN_DICT_SIZE);
        needed.min(self.dict_size)
    }
}

fn hash3(b0: u8, b1: u8, b2: u8) -> u32 {
    // Same rotated-xor shape as the deflate match finder; well-distributed
    // for ASCII and random alike, and trivial to invert in one's head while
    // debugging.
    ((b0 as u32).wrapping_mul(2654435761)
        ^ ((b1 as u32).wrapping_shl(8))
        ^ ((b2 as u32).wrapping_shl(16)))
        & (HASH_SIZE as u32 - 1)
}

// ─── range encoder ───────────────────────────────────────────────────────
//
// Mirror image of `RangeDecoder` in mod.rs. Same state machine: a `range`
// and a `code`-equivalent ("low"), with byte renormalisation after every
// operation that drops `range` below `RC_TOP_VALUE`.
//
// The 7-Zip trick we use here: instead of emitting bytes immediately, we
// keep one byte "cached" and a count of pending 0xFF bytes. When the low
// rolls over (its top bit propagates), we emit `cache + 1` followed by
// `cache_size` zeros; on no rollover, we emit `cache + 0` followed by
// `cache_size` 0xFFs. This correctly handles carry propagation through
// arbitrarily many bytes.

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
        // If the top bits of low are stable (either definitely below 2^32 or
        // definitely carrying), flush the cached byte plus any pending
        // run of 0xFF / 0x00.
        let top_bits = (self.low >> 32) as u32;
        if self.low < 0xFF00_0000 || top_bits != 0 {
            let carry = top_bits as u8; // 0 or 1
            let mut byte = self.cache.wrapping_add(carry);
            self.out.push(byte);
            // `0xFF + carry` style — if carry happened, the queued 0xFFs all
            // wrap to 0x00 and the byte already accounts for the +1.
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
            *prob = (p + ((super::RC_BIT_MODEL_TOTAL - p) >> RC_MOVE_BITS)) as u16;
        } else {
            self.low = self.low.wrapping_add(bound as u64);
            self.range -= bound;
            *prob = (p - (p >> RC_MOVE_BITS)) as u16;
        }
        self.normalize();
    }

    /// Encode a single direct (uniform) bit, MSB-first like the decoder.
    fn encode_direct_bit(&mut self, bit: u32) {
        self.range >>= 1;
        if bit != 0 {
            self.low = self.low.wrapping_add(self.range as u64);
        }
        self.normalize();
    }

    /// Encode `value` as `bits` direct (uniform) bits, **MSB-first**.
    ///
    /// liblzma's reference encoder (LzmaEnc.c) emits direct bits via a
    /// top-bit shift loop, so the bit at position `bits-1` of `value`
    /// goes onto the wire first. To stay interoperable with liblzma's
    /// `xz -d` / Python's stdlib `lzma` decoder, we mirror that order
    /// here: bit `(value >> (bits-1)) & 1` is encoded first, bit 0 last.
    /// The matching decoder is `RangeDecoder::decode_direct_bits_msb` in
    /// `src/lzma/mod.rs`.
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

/// Reverse bit-tree encode against the shared `dist_special` table, indexed
/// by a running `dist + 1` walk. Mirrors the corresponding decode loop.
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

    /// `length` is the symbol value (length - MATCH_LEN_MIN), i.e. 0..272.
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

    /// Price of encoding length symbol `length` (0-based) at `pos_state`.
    fn price(&self, prices: &[u32; PRICE_TABLE_SIZE], pos_state: u32, length: u32) -> u32 {
        if length < LEN_LOW_SYMBOLS as u32 {
            let base = (pos_state as usize) * LEN_LOW_SYMBOLS;
            price_bit0(prices, self.choice)
                + bittree_price(
                    prices,
                    &self.low[base..base + LEN_LOW_SYMBOLS],
                    LEN_LOW_BITS,
                    length,
                )
        } else if length < (LEN_LOW_SYMBOLS + LEN_MID_SYMBOLS) as u32 {
            let base = (pos_state as usize) * LEN_MID_SYMBOLS;
            price_bit1(prices, self.choice)
                + price_bit0(prices, self.choice2)
                + bittree_price(
                    prices,
                    &self.mid[base..base + LEN_MID_SYMBOLS],
                    LEN_MID_BITS,
                    length - LEN_LOW_SYMBOLS as u32,
                )
        } else {
            price_bit1(prices, self.choice)
                + price_bit1(prices, self.choice2)
                + bittree_price(
                    prices,
                    &self.high,
                    LEN_HIGH_BITS,
                    length - (LEN_LOW_SYMBOLS + LEN_MID_SYMBOLS) as u32,
                )
        }
    }
}

// ─── encoder core ────────────────────────────────────────────────────────

struct LzmaEncCore {
    // Mirror of the decoder's probability tables.
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

    /// Total uncompressed bytes encoded so far. Drives pos_state and the
    /// "previous byte" lookup; never exceeds the size of the buffered input.
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

    /// Literal-state encode. The decoder switches between "match-byte
    /// reduced" and "plain" encoding depending on `state`; we mirror that.
    fn encode_literal_full(&mut self, byte: u8, prev_byte: u8, match_byte: Option<u8>) {
        let lp_state = ((self.output_pos as u32) & self.lit_pos_mask) << self.lc;
        let prev_high = (prev_byte as u32) >> (8 - self.lc);
        let probs_idx = (lp_state + prev_high) as usize * 0x300;
        let probs = &mut self.lit[probs_idx..probs_idx + 0x300];

        let mut symbol: u32 = 1;
        // Build the same MSB-first walk the decoder does. We need to feed
        // the *target* bit for each step. We use `symbol`'s own bit count to
        // know how many bits we've encoded so far; the bit we want next is
        // bit `7 - (bits_done)` of `byte`, equivalently `byte >> (7 - bits_done)`.
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

    /// Snapshot the cheap per-flag bit prices used by the optimal parser.
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
        // The "extra" portion stored after the slot is the low num_direct_bits
        // of `distance`; the decoder reconstructs `distance = base | extra`.
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

    /// Emit a literal packet for the byte at index `pos` in the input.
    fn emit_literal(&mut self, input: &[u8], pos: usize) {
        let pos_state = self.pos_state();
        let idx = self.state * POS_STATES_MAX + pos_state as usize;
        rc_encode_bit(&mut self.rc, &mut self.is_match[idx], 0);

        let prev_byte = if pos > 0 { input[pos - 1] } else { 0 };
        let match_byte = if self.state < LIT_STATES {
            None
        } else {
            // The byte at distance rep0; we always have it available in the
            // input buffer because the encoder buffered everything.
            let d = self.rep0 as usize + 1;
            if d <= pos {
                Some(input[pos - d])
            } else {
                // Shouldn't happen at a literal-after-match state, but be
                // safe — fall back to plain literal coding.
                None
            }
        };
        self.encode_literal_full(input[pos], prev_byte, match_byte);

        self.state = state_after_literal(self.state);
        self.output_pos += 1;
    }

    /// Emit a new (non-rep) match packet.
    fn emit_match(&mut self, distance: u32, length: u32) {
        let pos_state = self.pos_state();
        let is_match_idx = self.state * POS_STATES_MAX + pos_state as usize;
        rc_encode_bit(&mut self.rc, &mut self.is_match[is_match_idx], 1);
        rc_encode_bit(&mut self.rc, &mut self.is_rep[self.state], 0);

        let len_sym = length - MATCH_LEN_MIN;
        // Borrow the length coder via a helper to avoid double borrow on self.
        encode_len(&mut self.len_coder, &mut self.rc, pos_state, len_sym);
        self.encode_distance(length, distance);

        self.rep3 = self.rep2;
        self.rep2 = self.rep1;
        self.rep1 = self.rep0;
        self.rep0 = distance;
        self.state = state_after_match(self.state);
        self.output_pos += length as u64;
    }

    /// Emit a SHORTREP packet (1-byte rep[0]).
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

    /// Emit a LONGREP[rep_idx] packet.
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

        // Reorder rep registers — decoder does this *before* decoding length
        // in finish_rep_match; let's match that order conceptually. The
        // mutation is symmetric, so we apply it here.
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

    /// Emit the EOS marker (a new-match packet with distance=0xFFFFFFFF and
    /// length=MATCH_LEN_MIN). The decoder's `decode_distance` returns
    /// 0xFFFFFFFF when slot=63 with maxed-out direct bits; we replicate that
    /// here.
    fn emit_eos_marker(&mut self) {
        let pos_state = self.pos_state();
        let is_match_idx = self.state * POS_STATES_MAX + pos_state as usize;
        rc_encode_bit(&mut self.rc, &mut self.is_match[is_match_idx], 1);
        rc_encode_bit(&mut self.rc, &mut self.is_rep[self.state], 0);
        encode_len(&mut self.len_coder, &mut self.rc, pos_state, 0);

        // Force slot 63 (all-ones). Slot 63 in dist_state 0.
        let slot_base = 0;
        let probs = &mut self.dist_slot[slot_base..slot_base + DIST_SLOTS];
        bittree_encode(&mut self.rc, probs, DIST_SLOT_BITS, (DIST_SLOTS as u32) - 1);
        // num_direct_bits for slot 63: (63 >> 1) - 1 = 30. direct_count =
        // 30 - 4 = 26. The "extra" portion that makes the distance come out
        // 0xFFFFFFFF is all-ones.
        let num_direct_bits = ((DIST_SLOTS as u32 - 1) >> 1) - 1;
        let direct_count = num_direct_bits - ALIGN_BITS;
        // Upper bits = all ones (26 bits), low align bits = all ones (4 bits).
        let upper = (1u32 << direct_count) - 1;
        self.rc.encode_direct_bits(upper, direct_count);
        bittree_reverse_encode(
            &mut self.rc,
            self.dist_align.as_mut_slice(),
            ALIGN_BITS,
            (ALIGN_SIZE as u32) - 1,
        );
    }
}

// Free-function wrappers so we can call them while another field of
// `LzmaEncCore` is borrowed mutably.
fn rc_encode_bit(rc: &mut RangeEncoder, prob: &mut u16, bit: u32) {
    rc.encode_bit(prob, bit);
}
fn encode_len(lc: &mut LengthCoderEnc, rc: &mut RangeEncoder, pos_state: u32, len_sym: u32) {
    lc.encode(rc, pos_state, len_sym);
}

/// Distance-to-slot lookup: for `d < 4` slot is `d`, otherwise it's
/// `2*n + ((d >> (n-1)) & 1)` where `n = floor(log2(d))`. This is the inverse
/// of the decoder's `dist_initial = (2 | (slot & 1)) << ((slot >> 1) - 1)`.
fn get_dist_slot(distance: u32) -> u32 {
    if distance < DIST_MODEL_START {
        return distance;
    }
    let n = 31 - distance.leading_zeros(); // floor(log2(distance))
    2 * n + ((distance >> (n - 1)) & 1)
}

// ─── match finder ────────────────────────────────────────────────────────
//
// 3-byte hash chain over the *entire* buffered input. Because we materialise
// all input before encoding, there's no sliding window to maintain; the head
// array and prev links cover the whole buffer in one shot.

struct HashChain {
    head: Box<[u32; HASH_SIZE]>,
    prev: Vec<u32>,
}

impl HashChain {
    fn new(buf_len: usize) -> Self {
        Self {
            head: Box::new([NIL; HASH_SIZE]),
            prev: vec![NIL; buf_len],
        }
    }

    /// Splice position `pos` into the hash chain. No-op if there aren't
    /// three bytes available.
    fn insert(&mut self, input: &[u8], pos: usize) {
        if pos + 3 > input.len() {
            return;
        }
        let h = hash3(input[pos], input[pos + 1], input[pos + 2]) as usize;
        self.prev[pos] = self.head[h];
        self.head[h] = pos as u32;
    }

    /// Find the longest match for `input[pos..]` against earlier positions,
    /// bounded by `MAX_MATCH_LEN`, the per-level chain budget, and the
    /// per-level "nice match" early-exit.
    fn find_longest(
        &self,
        input: &[u8],
        pos: usize,
        dict_size: u32,
        max_chain: usize,
        nice_match: u32,
    ) -> Option<(u32, u32)> {
        if pos + 3 > input.len() {
            return None;
        }
        let h = hash3(input[pos], input[pos + 1], input[pos + 2]) as usize;
        let max_len = MAX_MATCH_LEN.min((input.len() - pos) as u32);
        let max_dist = (dict_size as usize).min(pos);
        let mut best_len: u32 = 0;
        let mut best_dist: u32 = 0;
        let mut cur = self.head[h];
        let mut steps = 0usize;
        while cur != NIL && steps < max_chain {
            let cur_pos = cur as usize;
            if cur_pos >= pos {
                cur = self.prev[cur_pos];
                steps += 1;
                continue;
            }
            let dist = pos - cur_pos;
            if dist > max_dist {
                break;
            }
            // Cheap rejection by the (best_len)-th byte.
            if best_len > 2
                && (best_len as usize) < (input.len() - pos)
                && input[cur_pos + best_len as usize] != input[pos + best_len as usize]
            {
                cur = self.prev[cur_pos];
                steps += 1;
                continue;
            }
            let mut len = 0u32;
            while len < max_len && input[cur_pos + len as usize] == input[pos + len as usize] {
                len += 1;
            }
            if len >= MATCH_LEN_MIN && len > best_len {
                best_len = len;
                // LZMA distances are 0-based.
                best_dist = (dist - 1) as u32;
                if len >= nice_match {
                    break;
                }
            }
            cur = self.prev[cur_pos];
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
        input: &[u8],
        pos: usize,
        dict_size: u32,
        max_chain: usize,
        nice_match: u32,
        out: &mut Vec<(u32, u32)>,
    ) -> u32 {
        out.clear();
        if pos + 3 > input.len() {
            return 0;
        }
        let h = hash3(input[pos], input[pos + 1], input[pos + 2]) as usize;
        let max_len = MAX_MATCH_LEN.min((input.len() - pos) as u32);
        let max_dist = (dict_size as usize).min(pos);
        let mut best_len: u32 = MATCH_LEN_MIN - 1;
        let mut cur = self.head[h];
        let mut steps = 0usize;
        while cur != NIL && steps < max_chain {
            let cur_pos = cur as usize;
            if cur_pos >= pos {
                cur = self.prev[cur_pos];
                steps += 1;
                continue;
            }
            let dist = pos - cur_pos;
            if dist > max_dist {
                break;
            }
            if best_len >= MATCH_LEN_MIN
                && (best_len as usize) < (input.len() - pos)
                && input[cur_pos + best_len as usize] != input[pos + best_len as usize]
            {
                cur = self.prev[cur_pos];
                steps += 1;
                continue;
            }
            let mut len = 0u32;
            while len < max_len && input[cur_pos + len as usize] == input[pos + len as usize] {
                len += 1;
            }
            if len >= MATCH_LEN_MIN && len > best_len {
                // Chain is walked nearest-first, so this is the shortest
                // distance achieving every length in (best_len, len].
                out.push((len, (dist - 1) as u32));
                best_len = len;
                if len >= nice_match || len >= max_len {
                    break;
                }
            }
            cur = self.prev[cur_pos];
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

/// Try to extend a match starting at `pos` using a 0-based LZ distance
/// `dist`. Returns the match length (0 if not even 1 byte matches), capped
/// at `MAX_MATCH_LEN`. The byte at index `pos - dist - 1` is the first
/// candidate.
fn rep_match_len(input: &[u8], pos: usize, dist: u32) -> u32 {
    let d = dist as usize + 1;
    if d > pos {
        return 0;
    }
    let max_len = MAX_MATCH_LEN.min((input.len() - pos) as u32) as usize;
    let mut len = 0usize;
    while len < max_len && input[pos - d + len] == input[pos + len] {
        len += 1;
    }
    len as u32
}

// ─── price snapshot + optimal-parse scaffolding ───────────────────────────

/// Cached bit prices for the cheap per-decision flags. Length/distance/literal
/// prices are computed on demand from the core's live tables.
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

/// One parser decision, replayed through the real emit functions after the
/// optimal parse has chosen it.
#[derive(Clone, Copy)]
enum Decision {
    Literal,
    /// New match: `(distance0based, length)`.
    Match(u32, u32),
    /// Long rep: `(rep_index, length)`.
    Rep(u32, u32),
    ShortRep,
}

/// A node in the optimum DP buffer.
#[derive(Clone, Copy)]
struct OptNode {
    price: u32,
    prev_pos: u32,
    decision: Decision,
    state: usize,
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

fn reorder_reps(reps: [u32; 4], rep_idx: u32) -> [u32; 4] {
    match rep_idx {
        0 => reps,
        1 => [reps[1], reps[0], reps[2], reps[3]],
        2 => [reps[2], reps[0], reps[1], reps[3]],
        _ => [reps[3], reps[0], reps[1], reps[2]],
    }
}

#[allow(clippy::too_many_arguments)]
fn literal_price_at(
    core: &LzmaEncCore,
    prices: &[u32; PRICE_TABLE_SIZE],
    snap: &PriceSnapshot,
    input: &[u8],
    pos: usize,
    out_pos: u64,
    state: usize,
    rep0: u32,
) -> u32 {
    let pos_state = (out_pos as u32) & core.pos_mask;
    let im_idx = state * POS_STATES_MAX + pos_state as usize;
    let prev_byte = if pos > 0 { input[pos - 1] } else { 0 };
    let match_byte = if state < LIT_STATES {
        None
    } else {
        let d = rep0 as usize + 1;
        if d <= pos { Some(input[pos - d]) } else { None }
    };
    snap.is_match[im_idx][0]
        + core.literal_price(prices, out_pos, input[pos], prev_byte, match_byte)
}

// ─── full encode pass ────────────────────────────────────────────────────

fn encode_all(input: &[u8], params: LevelParams) -> Vec<u8> {
    let dict_size = params.effective_dict_size(input.len());

    // Threshold below which we also run a greedy pass and keep the smaller
    // body. The optimal parser's cold-start price model can briefly lose to
    // greedy on small, highly-repetitive inputs; the absolute loss is bounded
    // by the first few price-refresh segments, so on larger inputs the optimal
    // parse always wins overall and the extra greedy pass is pure waste. We
    // therefore only run the guard pass on small inputs.
    const GUARD_LIMIT: usize = 64 * 1024;

    let body = if params.opt_window == 0 {
        encode_body(input, dict_size, params, false)
    } else if input.len() <= GUARD_LIMIT {
        let opt = encode_body(input, dict_size, params, true);
        let greedy = encode_body(input, dict_size, params, false);
        if greedy.len() < opt.len() {
            greedy
        } else {
            opt
        }
    } else {
        encode_body(input, dict_size, params, true)
    };

    let mut out = Vec::with_capacity(13 + body.len());
    out.push(ENC_PROPS_BYTE);
    out.extend_from_slice(&dict_size.to_le_bytes());
    out.extend_from_slice(&u64::MAX.to_le_bytes());
    out.extend_from_slice(&body);
    out
}

/// Encode the range-coded body (with EOS marker + flush, no 13-byte header)
/// using the greedy or optimal parse. Returns the raw body bytes.
fn encode_body(input: &[u8], dict_size: u32, params: LevelParams, optimal: bool) -> Vec<u8> {
    let mut core = LzmaEncCore::new();
    let mut hc = HashChain::new(input.len());
    if optimal {
        encode_optimal(&mut core, &mut hc, input, dict_size, params);
    } else {
        encode_greedy(&mut core, &mut hc, input, dict_size, params);
    }
    core.emit_eos_marker();
    core.rc.flush();
    core.rc.out
}

/// Greedy/lazy parse — used by the lowest levels.
fn encode_greedy(
    core: &mut LzmaEncCore,
    hc: &mut HashChain,
    input: &[u8],
    dict_size: u32,
    params: LevelParams,
) {
    let mut pos = 0usize;
    while pos < input.len() {
        let rep_lens = [
            rep_match_len(input, pos, core.rep0),
            rep_match_len(input, pos, core.rep1),
            rep_match_len(input, pos, core.rep2),
            rep_match_len(input, pos, core.rep3),
        ];

        let new_match = hc.find_longest(input, pos, dict_size, params.max_chain, params.nice_match);

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

        hc.insert(input, pos);

        if emit_new {
            let (len, dist) = new_match.unwrap();
            for j in 1..(len as usize) {
                let p = pos + j;
                if p + 3 <= input.len() {
                    hc.insert(input, p);
                }
            }
            core.emit_match(dist, len);
            pos += len as usize;
        } else if emit_rep_long {
            for j in 1..(best_rep_len as usize) {
                let p = pos + j;
                if p + 3 <= input.len() {
                    hc.insert(input, p);
                }
            }
            core.emit_long_rep(best_rep_idx, best_rep_len);
            pos += best_rep_len as usize;
        } else if emit_short_rep {
            core.emit_short_rep();
            pos += 1;
        } else {
            core.emit_literal(input, pos);
            pos += 1;
        }
    }
}

/// Cost-based optimal parse over a look-ahead window.
fn encode_optimal(
    core: &mut LzmaEncCore,
    hc: &mut HashChain,
    input: &[u8],
    dict_size: u32,
    params: LevelParams,
) {
    let prob_prices = build_prob_prices();
    let window = params.opt_window as usize;
    let mut opt = Optimizer::new(window);

    let mut pos = 0usize;
    while pos < input.len() {
        let snap = core.price_snapshot(&prob_prices);
        let parsed = parse_window(
            core,
            hc,
            input,
            pos,
            dict_size,
            params,
            window,
            &prob_prices,
            &snap,
            &mut opt,
        );
        debug_assert!(parsed > 0);
        replay(core, hc, input, pos, &opt.decisions);
        pos += parsed;
    }
}

/// Parse one look-ahead window starting at `start`; fills `opt.decisions` and
/// returns the number of input bytes the chosen decisions consume.
#[allow(clippy::too_many_arguments)]
fn parse_window(
    core: &LzmaEncCore,
    hc: &HashChain,
    input: &[u8],
    start: usize,
    dict_size: u32,
    params: LevelParams,
    window: usize,
    prices: &[u32; PRICE_TABLE_SIZE],
    snap: &PriceSnapshot,
    opt: &mut Optimizer,
) -> usize {
    let avail = input.len() - start;
    let limit = window.min(avail);

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

    let mut reached = 0usize;
    let mut commit_end: Option<usize> = None;
    let mut cur = 0usize;
    while cur < limit {
        if let Some(ce) = commit_end
            && cur >= ce
        {
            break;
        }
        // Force a commit boundary once we've extended COMMIT_CAP bytes past the
        // window start with no earlier long-match commit.
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
        let mut best_here: u32 = 0;

        // ── literal ──────────────────────────────────────────────────────
        {
            let lp = literal_price_at(core, prices, snap, input, pos, out_pos, state, reps[0]);
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

        let match_flag = snap.is_match[im_idx][1];

        // ── rep matches ──────────────────────────────────────────────────
        for rep_idx in 0..4u32 {
            let rlen = rep_match_len(input, pos, reps[rep_idx as usize]);
            if rlen < 1 {
                continue;
            }
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
            let maxr = rlen.min((limit - cur) as u32);
            let mut l = MATCH_LEN_MIN;
            while l <= maxr {
                let len_price = core
                    .rep_len_coder
                    .price(prices, pos_state, l - MATCH_LEN_MIN);
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

        // ── new matches ──────────────────────────────────────────────────
        let longest = {
            let opt_matches = &mut opt.matches;
            hc.find_matches(
                input,
                pos,
                dict_size,
                params.max_chain,
                params.nice_match,
                opt_matches,
            )
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
                let mut l = (prev_len + 1).max(MATCH_LEN_MIN);
                while l <= band_end {
                    let len_price = core.len_coder.price(prices, pos_state, l - MATCH_LEN_MIN);
                    let dist_price = core.distance_price(prices, l, mdist);
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

        // Early-commit once a long match is reachable: commit up to its end so
        // the price snapshot stays close to the live model. Mirrors the SDK's
        // `nice_len` cut-off in GetOptimum.
        if commit_end.is_none() && best_here >= params.nice_len {
            commit_end = Some((cur + best_here as usize).min(limit));
        }

        cur += 1;
    }

    let end = match commit_end {
        Some(ce) => ce.max(1).min(reached.max(1)),
        None => reached.max(1),
    }
    .min(avail);
    trace_back(opt, end);
    end
}

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

fn replay(
    core: &mut LzmaEncCore,
    hc: &mut HashChain,
    input: &[u8],
    start: usize,
    decisions: &[Decision],
) {
    let mut pos = start;
    for &d in decisions {
        match d {
            Decision::Literal => {
                hc.insert(input, pos);
                core.emit_literal(input, pos);
                pos += 1;
            }
            Decision::ShortRep => {
                hc.insert(input, pos);
                core.emit_short_rep();
                pos += 1;
            }
            Decision::Match(dist, len) => {
                for j in 0..(len as usize) {
                    let p = pos + j;
                    if p + 3 <= input.len() {
                        hc.insert(input, p);
                    }
                }
                core.emit_match(dist, len);
                pos += len as usize;
            }
            Decision::Rep(idx, len) => {
                for j in 0..(len as usize) {
                    let p = pos + j;
                    if p + 3 <= input.len() {
                        hc.insert(input, p);
                    }
                }
                core.emit_long_rep(idx, len);
                pos += len as usize;
            }
        }
    }
}

// ─── public streaming Encoder ────────────────────────────────────────────

/// Streaming `.lzma` (alone) encoder.
///
/// Implementation note: LZMA's range coder operates on the entire stream, so
/// the simplest correct approach is to accumulate input into a `Vec<u8>` and
/// produce the compressed output in one shot on `finish`. The streaming
/// `encode` calls append to the buffer and never write output; `finish`
/// builds the full output and then drains it across however many calls the
/// caller's output buffer requires.
pub struct Encoder {
    input_buf: Vec<u8>,
    output_buf: Vec<u8>,
    output_pos: usize,
    finished: bool,
    /// Match-finder tuning derived from [`EncoderConfig::level`]. Persisted
    /// across `reset` since configuration is meant to survive resets.
    params: LevelParams,
}

impl Default for Encoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Encoder {
    /// Build an encoder at the default compression level (6).
    pub fn new() -> Self {
        Self::with_config(EncoderConfig::default())
    }

    /// Build an encoder with explicit configuration. `config.level` is
    /// clamped to `0..=9` internally — out-of-range values are snapped to
    /// the nearest valid level rather than rejected.
    pub fn with_config(config: EncoderConfig) -> Self {
        Self {
            input_buf: Vec::new(),
            output_buf: Vec::new(),
            output_pos: 0,
            finished: false,
            params: LevelParams::from_level(config.level),
        }
    }
}

impl RawEncoder for Encoder {
    fn raw_encode(&mut self, input: &[u8], _output: &mut [u8]) -> Result<RawProgress, Error> {
        if self.finished {
            return Err(Error::Corrupt);
        }
        self.input_buf.extend_from_slice(input);
        Ok(RawProgress {
            consumed: input.len(),
            written: 0,
            done: false,
        })
    }

    fn raw_finish(&mut self, output: &mut [u8]) -> Result<RawProgress, Error> {
        if !self.finished {
            // One-shot encode of everything we've buffered.
            self.output_buf = encode_all(&self.input_buf, self.params);
            self.output_pos = 0;
            self.finished = true;
        }
        let remaining = self.output_buf.len() - self.output_pos;
        let n = remaining.min(output.len());
        output[..n].copy_from_slice(&self.output_buf[self.output_pos..self.output_pos + n]);
        self.output_pos += n;
        let done = self.output_pos >= self.output_buf.len();
        Ok(RawProgress {
            consumed: 0,
            written: n,
            done,
        })
    }

    fn raw_reset(&mut self) {
        self.input_buf.clear();
        self.output_buf.clear();
        self.output_pos = 0;
        self.finished = false;
        // Note: params is preserved per the trait contract.
    }
}
