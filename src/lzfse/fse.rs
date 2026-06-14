//! Finite State Entropy (FSE) primitives for LZFSE v2.
//!
//! ## Build status
//!
//! Currently **unused** — this module exists so that a future round can
//! implement `bvx2` (LZFSE v2 compressed) block decoding without having
//! to re-derive the FSE table construction and pull primitives from
//! scratch. See [`super::lzfse_v2`] for why v2 is gated off in this
//! build.
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
//! Table construction matches Apple's `fse_init_decoder_table`: the `f`
//! slots spread for a symbol are **not** all assigned the same bit-width.
//! With `n_states = 2^L` (always a power of two) and per-symbol frequency
//! `f` (arbitrary, `1..=n_states`, summing to `n_states`):
//!
//! ```text
//! k  = L - floor(log2(f))          // == clz(f) - clz(n_states)
//! j0 = ((2 * n_states) >> k) - f
//! for i in 0..f (i = the i-th slot for this symbol, in spread order):
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

#![allow(dead_code)]

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

/// Spread-table helper: Apple uses a fixed step and walks free slots.
fn spread_step(n_states: usize) -> usize {
    (n_states >> 1) + (n_states >> 3) + 3
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
    let mut occupied = vec![false; n_states];
    let mut t = 0usize;
    let step = spread_step(n_states);
    let mask = n_states - 1;
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
            while occupied[t] {
                t = (t + step) & mask;
            }
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
            occupied[t] = true;
            t = (t + step) & mask;
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
    let mut occupied = vec![false; n_states];
    let mut t = 0usize;
    let step = spread_step(n_states);
    let mask = n_states - 1;
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
            while occupied[t] {
                t = (t + step) & mask;
            }
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
            occupied[t] = true;
            t = (t + step) & mask;
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
    let raw = bits.pull(total)?;
    let kbits = total - vb;
    let state_pull = if kbits == 0 {
        0
    } else {
        raw & ((1u64 << kbits) - 1)
    };
    let value_extra = if kbits == 64 { 0 } else { raw >> kbits };
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
