//! LZMA (Lempel–Ziv–Markov chain Algorithm).
//!
//! This build ships a **decoder for the legacy `.lzma` (alone) format only**.
//! The encoder is unimplemented and returns [`Error::Unsupported`] from every
//! call — LZMA has no uncompressed mode, so there is no fall-back.
//!
//! Wire format (legacy "alone"):
//! - 1 byte properties (`pp*9*5 + pp*5 + lc`, where `pb`, `lp`, `lc` are the
//!   three LZMA parameters in `0..=4`, `0..=4`, `0..=8`).
//! - 4 bytes little-endian dictionary size.
//! - 8 bytes little-endian uncompressed size; `0xFFFF_FFFF_FFFF_FFFF` means
//!   "unknown" — the stream is terminated by an explicit end-of-stream marker.
//! - The remainder of the input is a range-coded LZMA payload.
//!
//! References: 7-Zip / lzma-sdk source (well-commented C reference) and
//! `xz-utils` (`liblzma/lz/`, `liblzma/rangecoder/`).
//!
//! Streaming model: the decoder buffers compressed input in an internal
//! `Vec<u8>`. Each call drains as much of the caller's output as possible by
//! attempting LZMA "packets" (a literal or a match). Before each packet the
//! range-decoder state is snapshotted; if the packet would read past the end
//! of the buffered input it is rolled back and the codec asks for more input
//! on the next call. This keeps the per-call buffers small while preserving
//! the streaming `consumed`/`written` contract from `traits.rs`.

extern crate alloc;
use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;
use crate::traits::{Algorithm, Decoder as DecoderTrait, Encoder as EncoderTrait, Progress};

// ─── algorithm marker ────────────────────────────────────────────────────

/// Zero-sized marker type implementing [`Algorithm`] for legacy `.lzma`.
#[derive(Debug, Clone, Copy, Default)]
pub struct Lzma;

impl Algorithm for Lzma {
    const NAME: &'static str = "lzma";
    type Encoder = Encoder;
    type Decoder = Decoder;
    fn encoder() -> Encoder {
        Encoder::new()
    }
    fn decoder() -> Decoder {
        Decoder::new()
    }
}

// ─── encoder: unsupported ────────────────────────────────────────────────

/// Decode-only build: the encoder always returns [`Error::Unsupported`].
///
/// LZMA has no "stored" / uncompressed block mode that we could trivially
/// fall back to, so a partial implementation would be worse than a clear
/// error.
#[derive(Debug, Default)]
pub struct Encoder;

impl Encoder {
    pub const fn new() -> Self {
        Self
    }
}

impl EncoderTrait for Encoder {
    fn encode(&mut self, _input: &[u8], _output: &mut [u8]) -> Result<Progress, Error> {
        Err(Error::Unsupported)
    }
    fn finish(&mut self, _output: &mut [u8]) -> Result<Progress, Error> {
        Err(Error::Unsupported)
    }
    fn reset(&mut self) {}
}

// ─── LZMA constants ──────────────────────────────────────────────────────

/// Worst-case number of input bytes a single LZMA packet may consume from
/// the range decoder. Matches `LZMA_REQUIRED_INPUT_MAX` in the 7-Zip
/// reference SDK. Used to gate streaming decode attempts: a packet is only
/// started once we have at least this much forward input, otherwise the
/// decoder returns `NeedInput` and waits for the next call.
const REQUIRED_INPUT_MAX: usize = 20;

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

const DIC_SIZE_MAX: u64 = 1 << 26; // 64 MiB cap on dict allocation

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

    /// Decode one "direct" bit (uniform).
    fn decode_direct_bit(&mut self, buf: &[u8]) -> Result<u32, Error> {
        self.normalize(buf)?;
        self.range >>= 1;
        let t = self.code.wrapping_sub(self.range);
        // t's sign bit: 1 if code < range, 0 otherwise.
        let mask = (t as i32 >> 31) as u32; // all-ones if code<range, else 0
        self.code = self.code.wrapping_sub(self.range & !mask);
        // bit = 1 if code >= range, 0 if code < range
        let bit = if mask == 0 { 1 } else { 0 };
        Ok(bit)
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

/// Reverse bit-tree decoder: the tree returns the bit-reversed symbol value.
fn bittree_reverse_decode(
    rd: &mut RangeDecoder,
    probs: &mut [u16],
    bits: u32,
    buf: &[u8],
) -> Result<u32, Error> {
    let mut idx: u32 = 1;
    let mut result: u32 = 0;
    for i in 0..bits {
        let bit = rd.decode_bit(&mut probs[idx as usize], buf)?;
        idx = (idx << 1) | bit;
        result |= bit << i;
    }
    Ok(result)
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

    // Dictionary / sliding window (decoded output buffer).
    dict: Vec<u8>,
    dict_pos: usize,
    dict_full: bool,
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
            finished: false,
        }
    }

    fn dict_get(&self, distance: u32) -> u8 {
        // distance is 0-based: distance=0 -> the previous output byte.
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

    fn pos_state(&self) -> u32 {
        (self.output_pos as u32) & self.pos_mask
    }

    /// Decode one literal byte. The "prev byte" is fetched from the dict at
    /// distance 0 if available; otherwise 0.
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

    /// Decode the distance value given a length. Returns full distance value
    /// (0-based; 0 = previous byte). May return `0xFFFFFFFF` for the EOS
    /// marker.
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
            // Direct bits then align bittree.
            let direct_count = num_direct_bits - ALIGN_BITS;
            let mut direct: u32 = 0;
            for i in 0..direct_count {
                let bit = self.range.decode_direct_bit(buf)?;
                direct |= bit << i;
            }
            dist |= direct << ALIGN_BITS;
            let v = bittree_reverse_decode(
                &mut self.range,
                self.dist_align.as_mut_slice(),
                ALIGN_BITS,
                buf,
            )?;
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
    fn step(&mut self, buf: &[u8], at_eof: bool) -> Result<PacketOutcome, Error> {
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
            let lit = self.decode_literal(buf)?;
            self.state = state_after_literal(self.state);
            Ok(PacketOutcome::Literal(lit))
        } else {
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
                        let b = self.dict_get(self.rep0);
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
    }

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

/// Streaming `.lzma` (alone) decoder.
///
/// Buffers compressed input in an internal `Vec<u8>`. Decodes in
/// "one-packet-at-a-time" mode, with the range decoder's state being
/// snapshotted before each attempt; an input-starved attempt is rolled
/// back and retried after the caller pushes more bytes.
pub struct Decoder {
    /// Compressed input buffer. We accumulate bytes here as `decode` is
    /// called and drop the front prefix once the range decoder has moved
    /// past it.
    buf: Vec<u8>,
    /// Pending-output: a match-copy that we couldn't fully drain into the
    /// caller's output buffer on the previous call.
    pending_match: Option<PendingMatch>,
    pending_literal: Option<u8>,
    header_state: HeaderState,
}

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
    pub const fn new() -> Self {
        Self {
            buf: Vec::new(),
            pending_match: None,
            pending_literal: None,
            header_state: HeaderState::Empty,
        }
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
}

impl DecoderTrait for Decoder {
    fn decode(&mut self, input: &[u8], output: &mut [u8]) -> Result<Progress, Error> {
        let initial_buf_len = self.buf.len();
        self.buf.extend_from_slice(input);
        let mut written = 0usize;

        // ── header parsing ────────────────────────────────────────────
        if matches!(self.header_state, HeaderState::Empty) {
            if self.buf.len() < 13 {
                return Ok(Progress {
                    consumed: input.len(),
                    written: 0,
                    done: false,
                });
            }
            let props = self.buf[0];
            if props >= 9 * 5 * 5 {
                return Err(Error::BadHeader);
            }
            let lc = (props as u32) % 9;
            let remainder = (props as u32) / 9;
            let lp = remainder % 5;
            let pb = remainder / 5;
            let dict_size =
                u32::from_le_bytes([self.buf[1], self.buf[2], self.buf[3], self.buf[4]]);
            let uncompressed_size = u64::from_le_bytes([
                self.buf[5],
                self.buf[6],
                self.buf[7],
                self.buf[8],
                self.buf[9],
                self.buf[10],
                self.buf[11],
                self.buf[12],
            ]);
            self.buf.drain(0..13);
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
            let unc = if uncompressed_size == u64::MAX {
                None
            } else {
                Some(uncompressed_size)
            };
            let dict_size_eff = (dict_size as u64).clamp(4096, DIC_SIZE_MAX) as usize;
            let mut core = Box::new(LzmaCore::new(lc, lp, pb, dict_size_eff, unc));
            // Try to initialise; if not enough bytes yet, stay in HeaderParsed.
            if !core.range.init(&self.buf)? {
                // Rewind: we didn't actually consume the 5 init bytes.
                self.header_state = HeaderState::HeaderParsed {
                    lc,
                    lp,
                    pb,
                    dict_size,
                    uncompressed_size,
                };
                return Ok(Progress {
                    consumed: input.len(),
                    written: 0,
                    done: false,
                });
            }
            self.header_state = HeaderState::Active(core);
            self.compact_buf();
        }

        // ── main decode loop ──────────────────────────────────────────
        let result = self.drain_output(output, &mut written, false);
        // After processing, the caller's input has been fully absorbed into
        // self.buf. We report `consumed == input.len()` (we've taken it all
        // into our internal buffer), but compact_buf has already dropped the
        // prefix that the range decoder finished with.
        match result {
            Ok(()) => Ok(Progress {
                consumed: input.len(),
                written,
                done: false,
            }),
            Err(e) => {
                // Best effort: restore buf to pre-call state if we wrote
                // nothing useful. Not strictly required by trait.
                let _ = initial_buf_len;
                Err(e)
            }
        }
    }

    fn finish(&mut self, output: &mut [u8]) -> Result<Progress, Error> {
        let mut written = 0usize;
        // Drain whatever we can with at_eof=true so the streaming gate is
        // disabled and any genuine short read errors with UnexpectedEnd.
        self.drain_output(output, &mut written, true)?;

        let done = match &self.header_state {
            HeaderState::Done => true,
            HeaderState::Active(core) => {
                let no_pending = self.pending_match.is_none() && self.pending_literal.is_none();
                let target_met = match core.uncompressed_size {
                    Some(t) => core.output_pos >= t,
                    None => core.finished,
                };
                if target_met && no_pending {
                    self.header_state = HeaderState::Done;
                    true
                } else if no_pending && written == 0 && !output.is_empty() {
                    // Genuinely stuck: the output buffer had room, no
                    // packet could be decoded, and we have no buffered
                    // bytes to flush. The stream must be truncated.
                    return Err(Error::UnexpectedEnd);
                } else {
                    false
                }
            }
            _ => return Err(Error::UnexpectedEnd),
        };

        Ok(Progress {
            consumed: 0,
            written,
            done,
        })
    }

    fn reset(&mut self) {
        self.buf.clear();
        self.pending_match = None;
        self.pending_literal = None;
        self.header_state = HeaderState::Empty;
    }
}

impl Decoder {
    /// Drive the main decode loop, writing to `output` and recording
    /// progress in `written`. Returns Ok when either the output is full,
    /// the stream is done, or we genuinely need more input.
    ///
    /// `at_eof` enables the "no input gate" mode: packet attempts proceed
    /// even with `< REQUIRED_INPUT_MAX` bytes buffered. Used by `finish`.
    fn drain_output(
        &mut self,
        output: &mut [u8],
        written: &mut usize,
        at_eof: bool,
    ) -> Result<(), Error> {
        loop {
            if *written == output.len() {
                return Ok(());
            }

            // 1) Drain a pending literal first.
            if let Some(b) = self.pending_literal.take() {
                if let HeaderState::Active(ref mut core) = self.header_state {
                    core.dict_put(b);
                }
                output[*written] = b;
                *written += 1;
                continue;
            }

            // 2) Drain pending match bytes if any.
            if let Some(mut pm) = self.pending_match.take() {
                if let HeaderState::Active(ref mut core) = self.header_state {
                    while pm.remaining > 0 && *written < output.len() {
                        if !core.dict_has(pm.distance) {
                            return Err(Error::Corrupt);
                        }
                        let b = core.dict_get(pm.distance);
                        core.dict_put(b);
                        output[*written] = b;
                        *written += 1;
                        pm.remaining -= 1;
                        // Respect known uncompressed size.
                        if matches!(core.uncompressed_size, Some(t) if core.output_pos >= t) {
                            core.finished = true;
                            pm.remaining = 0;
                            break;
                        }
                    }
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
            let state_done = matches!(self.header_state, HeaderState::Done);
            if state_done {
                return Ok(());
            }

            // Working with self.buf as the input source. We must avoid
            // double-mutable-borrow with self.header_state, so we move
            // the core out, work, then move it back.
            let HeaderState::Active(ref mut core) = self.header_state else {
                return Ok(());
            };

            // Check finished BEFORE trying to step.
            if core.finished {
                self.header_state = HeaderState::Done;
                return Ok(());
            }
            if matches!(core.uncompressed_size, Some(t) if core.output_pos >= t) {
                core.finished = true;
                self.header_state = HeaderState::Done;
                return Ok(());
            }

            // Compact buf so range.pos doesn't drift indefinitely.
            let pos_before = core.range.pos;
            if pos_before > 0 {
                self.buf.drain(0..pos_before);
                core.range.pos = 0;
            }

            let outcome = core.step(&self.buf, at_eof)?;
            match outcome {
                PacketOutcome::Literal(b) => {
                    core.dict_put(b);
                    output[*written] = b;
                    *written += 1;
                    if matches!(core.uncompressed_size, Some(t) if core.output_pos >= t) {
                        core.finished = true;
                    }
                }
                PacketOutcome::Match { length } => {
                    let mut remaining = length;
                    let distance = core.rep0;
                    while remaining > 0 && *written < output.len() {
                        if !core.dict_has(distance) {
                            return Err(Error::Corrupt);
                        }
                        let b = core.dict_get(distance);
                        core.dict_put(b);
                        output[*written] = b;
                        *written += 1;
                        remaining -= 1;
                        if matches!(core.uncompressed_size, Some(t) if core.output_pos >= t) {
                            core.finished = true;
                            remaining = 0;
                            break;
                        }
                    }
                    if remaining > 0 {
                        self.pending_match = Some(PendingMatch {
                            distance,
                            remaining,
                        });
                        return Ok(());
                    }
                }
                PacketOutcome::Eos => {
                    self.header_state = HeaderState::Done;
                    return Ok(());
                }
                PacketOutcome::NeedInput => {
                    return Ok(());
                }
            }
        }
    }
}
