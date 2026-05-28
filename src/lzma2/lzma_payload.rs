//! Raw LZMA payload encoder for use inside LZMA2 compressed chunks.
//!
//! This is a stripped-down sibling of [`crate::lzma::encoder`]: same range
//! coder, same probability tables, same greedy match finder, but it emits
//! only the **range-coded body** — no 13-byte `.lzma` header and no
//! end-of-stream marker. LZMA2 chunks delimit the payload with explicit
//! `compressed_size` / `uncompressed_size` fields, so an EOS marker is both
//! unnecessary and outright wrong for the wire format.
//!
//! ## Why a copy?
//!
//! `src/lzma/encoder.rs` is private to its module and the project rules
//! forbid touching it. Re-exporting its internals would have required
//! cross-cutting edits there; copying the ~600 useful lines of state machine
//! here keeps the LZMA2 work contained to `src/lzma2/`. The constants are
//! all from the public LZMA spec, so this duplication is intrinsic, not
//! stylistic.
//!
//! ## Output contract
//!
//! [`encode_payload`] returns `(props_byte, body)` where:
//!
//! * `props_byte = (pb*5 + lp)*9 + lc` (here `lc=3, lp=0, pb=2`, packing to
//!   `0x5d` — the canonical preset that Python's `lzma.FORMAT_ALONE` and
//!   `xz -6` both emit).
//! * `body` is the range-coded packet stream followed by 5 range-coder flush
//!   bytes. No EOS marker. Feeding `body` to an LZMA decoder primed with
//!   `(props, dict_size, uncompressed_size=input.len())` reproduces `input`
//!   exactly.
//!
//! The single match finder and range coder here are intentionally simple:
//! greedy parsing, 3-byte hash chain bounded at 96 chain steps, no lazy
//! matching, no price-based selection. Plenty good enough for LZMA2-format
//! correctness; not competitive with xz at high presets for ratio.

extern crate alloc;
use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

// ─── LZMA spec constants ─────────────────────────────────────────────────
//
// These mirror the values in `src/lzma/mod.rs`. They're fixed by the LZMA
// spec, so duplicating them across modules is the same kind of duplication
// as constants like `BLOCK_SIZE` in a hash-function implementation.

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

// ─── encoder configuration ───────────────────────────────────────────────

/// Properties byte = `(pb*5 + lp)*9 + lc` per the LZMA spec; (3, 0, 2) packs
/// to 0x5d — the canonical default.
const ENC_LC: u32 = 3;
const ENC_LP: u32 = 0;
const ENC_PB: u32 = 2;
pub(super) const ENC_PROPS_BYTE: u8 = (ENC_PB * 5 + ENC_LP) as u8 * 9 + ENC_LC as u8;

/// Dictionary size used by the match finder. Chunks are capped at 64 KiB of
/// input so any in-chunk back-reference distance fits comfortably below this.
const ENC_DICT_SIZE: u32 = 1 << 16;

const MAX_MATCH_LEN: u32 = 273;

// Hash chain match finder configuration.
const HASH_BITS: u32 = 16;
const HASH_SIZE: usize = 1 << HASH_BITS;
const NIL: u32 = u32::MAX;
const MAX_CHAIN: usize = 96;
const NICE_MATCH: u32 = 192;

fn hash3(b0: u8, b1: u8, b2: u8) -> u32 {
    ((b0 as u32).wrapping_mul(2654435761)
        ^ ((b1 as u32).wrapping_shl(8))
        ^ ((b2 as u32).wrapping_shl(16)))
        & (HASH_SIZE as u32 - 1)
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

    fn encode_direct_bits(&mut self, value: u32, bits: u32) {
        for i in 0..bits {
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

    fn emit_literal(&mut self, input: &[u8], pos: usize) {
        let pos_state = self.pos_state();
        let idx = self.state * POS_STATES_MAX + pos_state as usize;
        rc_encode_bit(&mut self.rc, &mut self.is_match[idx], 0);

        let prev_byte = if pos > 0 { input[pos - 1] } else { 0 };
        let match_byte = if self.state < LIT_STATES {
            None
        } else {
            let d = self.rep0 as usize + 1;
            if d <= pos { Some(input[pos - d]) } else { None }
        };
        self.encode_literal_full(input[pos], prev_byte, match_byte);

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

    fn insert(&mut self, input: &[u8], pos: usize) {
        if pos + 3 > input.len() {
            return;
        }
        let h = hash3(input[pos], input[pos + 1], input[pos + 2]) as usize;
        self.prev[pos] = self.head[h];
        self.head[h] = pos as u32;
    }

    fn find_longest(&self, input: &[u8], pos: usize, dict_size: u32) -> Option<(u32, u32)> {
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
        while cur != NIL && steps < MAX_CHAIN {
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
                best_dist = (dist - 1) as u32;
                if len >= NICE_MATCH {
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
}

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

// ─── full encode pass (no header, no EOS marker) ─────────────────────────

/// Encode `input` as the raw LZMA payload of a single LZMA2 compressed chunk.
///
/// Returns `(props_byte, body)`. `body` contains:
///
/// * The range-coded packet stream for `input`'s data.
/// * 5 range-coder flush bytes (required so the decoder can pick up the last
///   bits of the last symbol; pre-paid here so the decoder side doesn't need
///   any look-ahead beyond what's in the chunk).
///
/// There is **no** end-of-stream marker — the LZMA2 chunk header carries
/// `uncompressed_size`, so the consumer knows when to stop.
///
/// `input` must be in `1..=65_536` bytes (the LZMA2 per-chunk cap); the
/// caller is expected to chunk larger inputs upstream.
pub(super) fn encode_payload(input: &[u8]) -> Vec<u8> {
    debug_assert!((1..=65_536).contains(&input.len()));
    let mut core = LzmaEncCore::new();
    let mut hc = HashChain::new(input.len());

    let mut pos = 0usize;
    while pos < input.len() {
        let rep_lens = [
            rep_match_len(input, pos, core.rep0),
            rep_match_len(input, pos, core.rep1),
            rep_match_len(input, pos, core.rep2),
            rep_match_len(input, pos, core.rep3),
        ];

        let new_match = hc.find_longest(input, pos, ENC_DICT_SIZE);

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

    // No EOS marker — the LZMA2 chunk header bounds the payload by size.
    core.rc.flush();
    core.rc.out
}
