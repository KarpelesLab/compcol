//! Finite State Entropy (FSE) primitives for LZFSE v2.
//!
//! Used by the `bvx2` block decoder in [`super::lzfse_v2`].
//!
//! ## What's here
//!
//! Apple's LZFSE uses small fixed FSE tables:
//!   - 1024 states for the literal stream.
//!   - 64 states for the L (literal-run-length) stream.
//!   - 64 states for the M (match-length) stream.
//!   - 256 states for the D (match-distance) stream.
//!
//! Each FSE decode entry stores `(k, symbol_or_base, delta)`. For literals,
//! the symbol is a `u8`; for L/M/D, a base value and a count of extra value
//! bits are stored.
//!
//! ## Table construction (general, k/k-1 split)
//!
//! Table construction matches Apple's `fse_init_decoder_table`: symbols
//! occupy **consecutive** table slots in symbol order (no zstd-style
//! spreading), and a symbol's `f` slots are **not** all assigned the same
//! bit-width. With `n_states = 2^L` (always a power of two) and per-symbol
//! frequency `f` (arbitrary, `1..=n_states`, summing to `n_states`):
//!
//! ```text
//! k  = L - floor(log2(f))          // == clz(f) - clz(n_states)
//! j0 = ((2 * n_states) >> k) - f
//! for i in 0..f (i = the i-th consecutive slot for this symbol):
//!     if i < j0:  entry.k = k;     entry.delta = ((f + i) << k) - n_states
//!     else:       entry.k = k - 1; entry.delta = (i - j0) << (k - 1)
//! ```
//!
//! The first `j0` slots consume `k` bits, the remaining `f - j0` consume
//! `k - 1` bits. When `f` is a power of two `j0 == f` and the table
//! degenerates to a single bit-width per symbol; for general `f` the split
//! is required to tile `[0, n_states)` exactly. This is the algorithm real
//! Apple-produced LZFSE v2 streams rely on.
//!
//! Frequency tables in the v2 block header are encoded with the custom
//! variable-width scheme implemented by [`decode_freq_table`].

use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;
use crate::lzfse::bits::FseBits;

/// One FSE decode entry for the literal stream.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct FseEntry {
    pub(crate) k: u8,
    pub(crate) symbol: u8,
    pub(crate) delta: i16,
}

/// Decode entry for the L/M/D streams. Carries extra "value bits" to pull
/// on top of the base value.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct LmdVEntry {
    pub(crate) total_bits: u8,
    pub(crate) value_bits: u8,
    pub(crate) delta: i16,
    pub(crate) v_base: i32,
}

/// Build an FSE decode table for the literal stream.
pub(crate) fn build_literal_decoder(freq: &[u16], n_states: usize) -> Result<Vec<FseEntry>, Error> {
    if !n_states.is_power_of_two() || n_states == 0 {
        return Err(Error::Corrupt);
    }
    let mut sum = 0usize;
    for &f in freq {
        sum += f as usize;
    }
    if sum != n_states {
        return Err(Error::Corrupt);
    }
    let mut table = vec![FseEntry::default(); n_states];
    let mut t = 0usize;
    let n_states_log2 = n_states.trailing_zeros() as i32;
    for (s, &f) in freq.iter().enumerate() {
        let f = f as usize;
        if f == 0 {
            continue;
        }
        // k = L - floor(log2(f)) = clz(f) - clz(n_states); j0 splits the
        // symbol's slots into a k-bit prefix and a (k-1)-bit suffix.
        let floor_log2 = 31 - (f as u32).leading_zeros() as i32;
        let k = n_states_log2 - floor_log2;
        if k < 0 {
            return Err(Error::Corrupt);
        }
        let k = k as u32;
        let j0 = (((2 * n_states) >> k) as i32) - f as i32;
        for i in 0..f {
            let (ek, delta) = if (i as i32) < j0 {
                (k, ((f as i32 + i as i32) << k) - n_states as i32)
            } else {
                (k - 1, (i as i32 - j0) << (k - 1))
            };
            table[t] = FseEntry {
                k: ek as u8,
                symbol: s as u8,
                delta: delta as i16,
            };
            t += 1;
        }
    }
    Ok(table)
}

/// Build an FSE decode table for the L/M/D streams.
pub(crate) fn build_lmd_decoder(
    freq: &[u16],
    n_states: usize,
    bits_per_symbol: &[u8],
    base_per_symbol: &[i32],
) -> Result<Vec<LmdVEntry>, Error> {
    if !n_states.is_power_of_two() || n_states == 0 {
        return Err(Error::Corrupt);
    }
    let mut sum = 0usize;
    for &f in freq {
        sum += f as usize;
    }
    if sum != n_states {
        return Err(Error::Corrupt);
    }
    if bits_per_symbol.len() != freq.len() || base_per_symbol.len() != freq.len() {
        return Err(Error::Corrupt);
    }
    let mut table = vec![LmdVEntry::default(); n_states];
    let mut t = 0usize;
    let n_states_log2 = n_states.trailing_zeros() as i32;
    for (s, &f) in freq.iter().enumerate() {
        let f = f as usize;
        if f == 0 {
            continue;
        }
        // k = L - floor(log2(f)); j0 splits the symbol's slots into a k-bit
        // prefix and a (k-1)-bit suffix (see module docs).
        let floor_log2 = 31 - (f as u32).leading_zeros() as i32;
        let k = n_states_log2 - floor_log2;
        if k < 0 {
            return Err(Error::Corrupt);
        }
        let k = k as u32;
        let j0 = (((2 * n_states) >> k) as i32) - f as i32;
        for i in 0..f {
            let (ek, delta) = if (i as i32) < j0 {
                (k, ((f as i32 + i as i32) << k) - n_states as i32)
            } else {
                (k - 1, (i as i32 - j0) << (k - 1))
            };
            table[t] = LmdVEntry {
                total_bits: (ek as u8) + bits_per_symbol[s],
                value_bits: bits_per_symbol[s],
                delta: delta as i16,
                v_base: base_per_symbol[s],
            };
            t += 1;
        }
    }
    Ok(table)
}

/// Pull one literal from the FSE stream. Returns `(symbol, next_state)`.
pub(crate) fn fse_decode_literal(
    state: u32,
    table: &[FseEntry],
    bits: &mut FseBits<'_>,
) -> Result<(u8, u32), Error> {
    let e = *table.get(state as usize).ok_or(Error::Corrupt)?;
    let k = e.k as u32;
    bits.refill();
    let pulled = bits.pull(k)? as i32;
    let next = pulled + e.delta as i32;
    if next < 0 || next as usize >= table.len() {
        return Err(Error::Corrupt);
    }
    Ok((e.symbol, next as u32))
}

/// Pull one L/M/D value from the FSE stream. Returns `(value, next_state)`.
pub(crate) fn fse_decode_lmd(
    state: u32,
    table: &[LmdVEntry],
    bits: &mut FseBits<'_>,
) -> Result<(i32, u32), Error> {
    let e = *table.get(state as usize).ok_or(Error::Corrupt)?;
    bits.refill();
    let total = e.total_bits as u32;
    let vb = e.value_bits as u32;
    // Apple's `fse_value_decode`: the state bits are pulled first (the high
    // part of the combined field), the value's extra bits follow (low part).
    let raw = bits.pull(total)?;
    let state_pull = raw >> vb;
    let value_extra = raw & ((1u64 << vb) - 1);
    let value = e.v_base + value_extra as i32;
    let next = state_pull as i32 + e.delta as i32;
    if next < 0 || next as usize >= table.len() {
        return Err(Error::Corrupt);
    }
    Ok((value, next as u32))
}

/// Decode `n_symbols` packed frequencies from `bytes`, returning the
/// frequencies and the number of bits consumed.
///
/// The encoding scheme (from Apple's `lzfse_internal.h` `freq_nbits_table`
/// and `freq_value_table`): the decoder reads up to 14 bits. The low 5
/// bits select a length and base value via two small lookup tables; longer
/// values stash the extra magnitude in the high bits.
pub(crate) fn decode_freq_table(
    bytes: &[u8],
    n_symbols: usize,
) -> Result<(Vec<u16>, usize), Error> {
    const NBITS: [u8; 32] = [
        2, 3, 2, 5, 2, 3, 2, 8, 2, 3, 2, 5, 2, 3, 2, 14, 2, 3, 2, 5, 2, 3, 2, 8, 2, 3, 2, 5, 2, 3,
        2, 14,
    ];
    const VAL: [u8; 32] = [
        0, 2, 1, 4, 0, 3, 1, 8, 0, 2, 1, 5, 0, 3, 1, 0, 0, 2, 1, 6, 0, 3, 1, 8, 0, 2, 1, 7, 0, 3,
        1, 0,
    ];
    let mut pos: usize = 0;
    let total_bits = bytes.len() * 8;
    let mut freqs = vec![0u16; n_symbols];
    for f in freqs.iter_mut() {
        if pos >= total_bits {
            return Err(Error::Corrupt);
        }
        let remaining = total_bits - pos;
        let peek_n = remaining.min(14);
        let mut peek: u32 = 0;
        for i in 0..peek_n {
            let bit_idx = pos + i;
            let b = (bytes[bit_idx / 8] >> (bit_idx % 8)) & 1;
            peek |= (b as u32) << i;
        }
        let lo5 = (peek & 0x1F) as usize;
        let nbits = NBITS[lo5] as usize;
        if nbits > peek_n {
            return Err(Error::Corrupt);
        }
        let val = if nbits == 8 {
            ((peek >> 4) & 0xF) + 8
        } else if nbits == 14 {
            ((peek >> 4) & 0x3FF) + 24
        } else {
            VAL[lo5] as u32
        };
        if val > u16::MAX as u32 {
            return Err(Error::Corrupt);
        }
        *f = val as u16;
        pos += nbits;
    }
    Ok((freqs, pos))
}

// ───────────────────────────── encoder side ─────────────────────────────

/// Normalize a histogram to frequencies summing exactly to `n_states`
/// (a power of two), giving every present symbol at least 1.
///
/// Each count is scaled by `n_states / total` and rounded to nearest; the
/// rounding error is then absorbed by the most frequent symbol, which costs
/// the least (in bits) to perturb. When that symbol cannot absorb an
/// overshoot without dropping to zero — many forced-to-1 singletons — the
/// excess is shaved off the largest entries one at a time. A histogram with
/// no symbols at all yields `freq[0] = n_states` so the table stays valid.
pub(crate) fn normalize_freq(hist: &[u32], n_states: usize, freq: &mut [u16]) {
    debug_assert_eq!(hist.len(), freq.len());
    let total: u64 = hist.iter().map(|&h| h as u64).sum();
    freq.fill(0);
    if total == 0 {
        freq[0] = n_states as u16;
        return;
    }
    let mut assigned: i64 = 0;
    let mut largest = 0usize;
    for (i, &h) in hist.iter().enumerate() {
        if h == 0 {
            continue;
        }
        let scaled = (h as u64 * n_states as u64 + total / 2) / total;
        let f = scaled.clamp(1, n_states as u64);
        freq[i] = f as u16;
        assigned += f as i64;
        if hist[i] > hist[largest] || hist[largest] == 0 {
            largest = i;
        }
    }
    let mut diff = n_states as i64 - assigned;
    if diff == 0 {
        return;
    }
    // Fast path: the most frequent symbol absorbs the whole correction.
    if diff > 0 || (freq[largest] as i64) + diff >= 1 {
        freq[largest] = (freq[largest] as i64 + diff) as u16;
        return;
    }
    // Overshoot the largest cannot absorb: decrement the currently largest
    // entry (> 1) until the sum is right. Bounded by the alphabet size.
    while diff < 0 {
        let (idx, _) = freq
            .iter()
            .enumerate()
            .filter(|&(_, &f)| f > 1)
            .max_by_key(|&(_, &f)| f)
            .expect("an entry > 1 exists while the sum overshoots");
        freq[idx] -= 1;
        diff += 1;
    }
}

/// Encode a frequency value with the LZFSE fixed prefix code (the inverse of
/// [`decode_freq_table`]). Returns `(code, n_bits)`; values above 1047 do not
/// occur (the largest table has 1024 states).
pub(crate) fn encode_freq_value(v: u16) -> (u32, u32) {
    match v {
        0 => (0b00, 2),
        1 => (0b10, 2),
        2 => (0b001, 3),
        3 => (0b101, 3),
        4 => (0b00011, 5),
        5 => (0b01011, 5),
        6 => (0b10011, 5),
        7 => (0b11011, 5),
        8..=23 => (0b0111 | ((v as u32 - 8) << 4), 8),
        _ => {
            debug_assert!(v <= 1047);
            (0b1111 | ((v as u32 - 24) << 4), 14)
        }
    }
}

/// Per-symbol FSE encoder entry: the inverse of the decode table built by
/// [`build_literal_decoder`] / [`build_lmd_decoder`].
///
/// A symbol with frequency `f` owns the `f` consecutive decode slots starting
/// at `offset`. Its first `j0` slots consume `k` bits and their next-state
/// ranges tile `[s0, n_states)`; the remaining slots consume `k - 1` bits and
/// tile `[0, s0)`, where `s0 = (f << k) - n_states`. Encoding a symbol from
/// encoder state `x` (the decoder's *next* state) therefore emits the low
/// `k` (or `k - 1`) bits of `x` and moves to the slot whose range holds `x`.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct FseEncEntry {
    /// States below `s0` use `k - 1` bits.
    s0: i32,
    k: u8,
    /// New state for the `k`-bit branch is `delta0 + (x >> k)`.
    delta0: i32,
    /// New state for the `(k - 1)`-bit branch is `delta1 + (x >> (k - 1))`.
    delta1: i32,
}

/// Build the encoder entries for a normalized frequency table.
pub(crate) fn build_encoder(freq: &[u16], n_states: usize, table: &mut [FseEncEntry]) {
    debug_assert!(n_states.is_power_of_two());
    debug_assert_eq!(freq.len(), table.len());
    let n = n_states as i32;
    let log2 = n_states.trailing_zeros() as i32;
    let mut offset = 0i32;
    for (e, &f) in table.iter_mut().zip(freq) {
        if f == 0 {
            *e = FseEncEntry::default();
            continue;
        }
        let f = f as i32;
        let k = log2 - (31 - (f as u32).leading_zeros() as i32);
        let s0 = (f << k) - n;
        let delta0 = offset - f + (n >> k);
        // With k == 0 (f == n_states) every state takes the k-bit branch.
        let delta1 = if k > 0 {
            offset - f + (n >> (k - 1))
        } else {
            0
        };
        *e = FseEncEntry {
            s0,
            k: k as u8,
            delta0,
            delta1,
        };
        offset += f;
    }
}

/// Encode one symbol from encoder state `x`: returns `(bits, n_bits, new_state)`.
#[inline]
pub(crate) fn fse_encode(e: &FseEncEntry, x: u32) -> (u32, u32, u32) {
    let k = e.k as u32;
    if (x as i32) < e.s0 {
        let nb = k - 1;
        (
            x & ((1 << nb) - 1),
            nb,
            (e.delta1 + (x >> nb) as i32) as u32,
        )
    } else {
        (
            x & ((1u32 << k) - 1),
            k,
            (e.delta0 + (x >> k) as i32) as u32,
        )
    }
}

/// LSB-first bit writer.
///
/// For the FSE payload streams ([`BitWriter::new_fse`]) the writer starts
/// with 8 zero bytes, as Apple's encoder does: the decoder reads the stream
/// backwards in 8-byte loads and may top its accumulator up from below the
/// last real bit. Chunks must be pushed in the reverse of the order the
/// decoder pulls them ([`FseBits`] reads from the top down).
pub(crate) struct BitWriter {
    out: Vec<u8>,
    acc: u64,
    n: u32,
}

impl BitWriter {
    pub(crate) fn new() -> Self {
        Self {
            out: Vec::new(),
            acc: 0,
            n: 0,
        }
    }

    pub(crate) fn new_fse(capacity: usize) -> Self {
        let mut out = Vec::with_capacity(capacity + 16);
        out.extend_from_slice(&[0u8; 8]);
        Self { out, acc: 0, n: 0 }
    }

    /// Append the low `n_bits` (`<= 32`) bits of `value`.
    #[inline]
    pub(crate) fn push(&mut self, value: u32, n_bits: u32) {
        debug_assert!(n_bits <= 32);
        debug_assert!(n_bits == 32 || value >> n_bits == 0);
        self.acc |= (value as u64) << self.n;
        self.n += n_bits;
        while self.n >= 8 {
            self.out.push(self.acc as u8);
            self.acc >>= 8;
            self.n -= 8;
        }
    }

    /// Flush the partial byte. Returns the bytes and the header's 3-bit
    /// "bits" field (`7 -` the number of unused high bits of the last byte).
    pub(crate) fn finish(mut self) -> (Vec<u8>, u32) {
        let mut unused = 0;
        if self.n > 0 {
            self.out.push(self.acc as u8);
            unused = 8 - self.n;
        }
        (self.out, 7 - unused)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Core FSE invariant: for **each symbol** the `f` entries that carry it
    /// must, via their `[delta, delta + 2^k)` next-state ranges, tile
    /// `[0, n_states)` exactly once — that is what lets the encoder transition
    /// to that symbol from any state. This holds **iff** the k/k-1 split is
    /// implemented correctly; a regression to a single bit-width per symbol
    /// breaks the tiling for any non-power-of-two frequency. The check is
    /// independent of any encoder.
    fn assert_literal_table_bijective(freq: &[u16], n_states: usize) {
        let table = build_literal_decoder(freq, n_states).expect("table builds");
        assert_eq!(table.len(), n_states);
        // Per-symbol coverage of the next-state space.
        let mut hits = vec![vec![0u32; n_states]; freq.len()];
        for e in &table {
            let span = 1usize << e.k;
            let base = e.delta as i32;
            for off in 0..span as i32 {
                let next = base + off;
                assert!(
                    (0..n_states as i32).contains(&next),
                    "next {next} out of range for entry {e:?}"
                );
                hits[e.symbol as usize][next as usize] += 1;
            }
        }
        for (sym, &f) in freq.iter().enumerate() {
            if f == 0 {
                assert!(
                    hits[sym].iter().all(|&h| h == 0),
                    "absent symbol {sym} has table entries"
                );
                continue;
            }
            for (s, &h) in hits[sym].iter().enumerate() {
                assert_eq!(
                    h, 1,
                    "symbol {sym}: state {s} reachable {h} times (expected exactly 1)"
                );
            }
        }
    }

    #[test]
    fn literal_table_bijective_non_dyadic() {
        // Deliberately non-power-of-two frequency sets that sum to 1024.
        // A single-`k` table builder cannot tile [0,1024) for any of these.
        assert_literal_table_bijective(&[3, 5, 1000, 16], 1024);
        assert_literal_table_bijective(&[300, 700, 24], 1024);
        // Many singletons + one large symbol (1 is non-dyadic-adjacent edge).
        let mut f = vec![1u16; 24];
        f[0] = 1024 - 23;
        assert_literal_table_bijective(&f, 1024);
        // Skewed but smooth distribution (sums to 1024).
        assert_literal_table_bijective(&[100, 101, 103, 107, 109, 504], 1024);
    }

    #[test]
    fn literal_table_bijective_dyadic_still_ok() {
        // The power-of-two case (j0 == f) must still tile correctly.
        assert_literal_table_bijective(&[512, 256, 256], 1024);
        assert_literal_table_bijective(&[1024], 1024);
    }

    #[test]
    fn lmd_table_built_for_non_dyadic_freqs() {
        // L stream: 64 states, a non-power-of-two split across symbols.
        let mut freq = vec![0u16; 20];
        freq[0] = 30;
        freq[1] = 20;
        freq[2] = 7;
        freq[3] = 5;
        freq[16] = 2; // a symbol carrying extra value bits
        let extra = [0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3, 5, 8];
        let base = [
            0i32, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 20, 28, 60,
        ];
        let table = build_lmd_decoder(&freq, 64, &extra, &base).expect("lmd table builds");
        assert_eq!(table.len(), 64);
        // For each symbol the state-transition portion (total_bits-value_bits)
        // must tile [0,64). Group entries by symbol via v_base, which is
        // unique per symbol in `base`.
        let mut hits: Vec<vec::Vec<u32>> = (0..20).map(|_| vec![0u32; 64]).collect();
        for e in &table {
            let sym = base
                .iter()
                .position(|&b| b == e.v_base)
                .expect("known base");
            let kbits = e.total_bits - e.value_bits;
            let span = 1usize << kbits;
            for off in 0..span as i32 {
                let next = e.delta as i32 + off;
                assert!((0..64).contains(&next));
                hits[sym][next as usize] += 1;
            }
        }
        for (sym, &f) in freq.iter().enumerate() {
            if f == 0 {
                continue;
            }
            assert!(
                hits[sym].iter().all(|&h| h == 1),
                "lmd symbol {sym} not bijective over states"
            );
        }
    }

    #[test]
    fn non_power_of_two_table_size_rejected() {
        // The table SIZE must be 2^L even though per-symbol freqs are general.
        assert!(build_literal_decoder(&[5, 5], 10).is_err());
    }
}
