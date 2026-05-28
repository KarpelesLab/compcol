//! FSE encoder used by the Compressed_Block sequence section.
//!
//! Mirrors the decoder side in [`crate::zstd::fse`]. We rebuild the same
//! `Normalized_Counts → spread → table` pipeline the decoder uses, then add
//! the encoder-only state lookup (`state_table`) and per-symbol delta values
//! (`symbol_tt`) that let us walk the FSE state machine forward (in the
//! reverse-bitstream sense).
//!
//! The reference for this is RFC 8478 §4.1 plus the FSE library's
//! [`FSE_buildCTable`](https://github.com/Cyan4973/FiniteStateEntropy/blob/dev/lib/fse_compress.c).
//! Only the construction we actually need is implemented — we do not generate
//! `FSE_Compressed_Mode` table headers (we only emit Predefined_Mode tables
//! whose normalized counts the decoder already knows).
//!
//! # Encoding pattern (reverse symbol order)
//!
//! FSE encoders run the input sequence backwards so that the decoder (which
//! reads from the start marker downward) recovers the original order:
//!
//! ```text
//! let mut state = enc.init_state(symbols[n - 1]);
//! for i in (0..n - 1).rev() {
//!     state = enc.encode_symbol(state, symbols[i], &mut writer);
//! }
//! enc.write_final_state(state, &mut writer);
//! ```
//!
//! `init_state(symbols[n-1])` arranges things so that the decoder, after
//! reading the final state via [`FseState::init`](crate::zstd::fse::FseState::init),
//! emits `symbols[0]` first. The loop then walks the n-1 transitions the
//! decoder will perform.

use alloc::vec;
use alloc::vec::Vec;

use crate::zstd::encoder_bitwriter::RevBitWriter;

/// Per-symbol encoding metadata used to compute the bit count and next state
/// in [`FseEncoder::encode_symbol`].
#[derive(Clone, Copy, Debug)]
struct SymbolTT {
    /// Encoded as `(maxBitsOut << 16) - (count_rounded_up_to_pow2 << maxBitsOut)`.
    /// `nbBitsOut = (state_in_high_half + delta_nb_bits) >> 16`.
    delta_nb_bits: i32,
    /// Offset into `state_table` to find the next decoder state.
    /// `next_state = state_table[(state >> nbBitsOut) + delta_find_state]`.
    delta_find_state: i32,
}

/// FSE encoder context built from a normalized-count distribution.
pub struct FseEncoder {
    pub accuracy_log: u8,
    /// `state_table[i]` is a *decoder* state in `[0, table_size)`. Indexed in
    /// encoding by `(prev_state_in_high_half >> nb_bits_out) + delta_find_state[sym]`.
    state_table: Vec<u16>,
    /// One entry per symbol, indexed by symbol value.
    symbol_tt: Vec<SymbolTT>,
    /// For symbol `s`, `cumul[s]` is the first state-table slot belonging to
    /// `s` — used to bootstrap [`init_state`].
    cumul: Vec<u32>,
}

impl FseEncoder {
    /// Build the encoder tables from a normalized-count array. Entries may be:
    ///   - `0` — symbol does not appear in the stream.
    ///   - `-1` — "less-than-1" probability (single slot at the table top).
    ///   - `n > 0` — symbol has `n` slots in the table.
    pub fn from_normalized(counts: &[i16], accuracy_log: u8) -> Self {
        assert!(accuracy_log > 0 && accuracy_log <= 9, "bad accuracy_log");
        let table_size = 1usize << accuracy_log;
        let table_mask = table_size - 1;
        let mut high_threshold = table_size as i32 - 1;

        // Stage 1: spread symbols (same algorithm as decoder).
        let mut spread: Vec<i16> = vec![-1; table_size];
        for (sym, &cnt) in counts.iter().enumerate() {
            if cnt == -1 {
                spread[high_threshold as usize] = sym as i16;
                high_threshold -= 1;
            }
        }
        let step = (table_size >> 1) + (table_size >> 3) + 3;
        let mut pos: usize = 0;
        for (sym, &cnt) in counts.iter().enumerate() {
            if cnt <= 0 {
                continue;
            }
            for _ in 0..cnt {
                while spread[pos] != -1 {
                    pos = (pos + step) & table_mask;
                }
                spread[pos] = sym as i16;
                pos = (pos + step) & table_mask;
            }
        }

        // Stage 2: cumulative slot counts per symbol.
        let n_symbols = counts.len();
        let mut cumul: Vec<u32> = vec![0; n_symbols + 1];
        for s in 0..n_symbols {
            let c = counts[s];
            let used = if c == -1 {
                1
            } else if c > 0 {
                c as i32
            } else {
                0
            };
            cumul[s + 1] = cumul[s] + used as u32;
        }

        // Stage 3: state_table — for each spread position, append to that
        // symbol's contiguous region.
        let mut next_per_sym: Vec<u32> = cumul[..n_symbols].to_vec();
        let mut state_table: Vec<u16> = vec![0u16; table_size];
        for (state, &sym_signed) in spread.iter().enumerate() {
            let sym = sym_signed as usize;
            let slot = next_per_sym[sym] as usize;
            next_per_sym[sym] += 1;
            state_table[slot] = state as u16;
        }

        // Stage 4: symbol_tt deltas.
        let mut symbol_tt: Vec<SymbolTT> = vec![
            SymbolTT {
                delta_nb_bits: 0,
                delta_find_state: 0,
            };
            n_symbols
        ];
        for s in 0..n_symbols {
            let c = counts[s];
            if c == 0 {
                // Should never be emitted; set safe defaults.
                symbol_tt[s].delta_nb_bits =
                    ((accuracy_log as i32 + 1) << 16) - (1i32 << accuracy_log);
                symbol_tt[s].delta_find_state = 0;
            } else if c == -1 || c == 1 {
                // Single-slot symbol: always emits `accuracy_log` bits.
                let delta_nb_bits = ((accuracy_log as i32) << 16) - (1i32 << accuracy_log);
                symbol_tt[s].delta_nb_bits = delta_nb_bits;
                symbol_tt[s].delta_find_state = cumul[s] as i32 - 1;
            } else {
                let count = c as u32;
                // max_bits_out = accuracy_log - floor(log2(count - 1))
                let high_bit = 31 - (count - 1).leading_zeros();
                let max_bits_out = accuracy_log as i32 - high_bit as i32;
                let min_state_plus = (count as i32) << max_bits_out;
                let delta_nb_bits = (max_bits_out << 16) - min_state_plus;
                symbol_tt[s].delta_nb_bits = delta_nb_bits;
                symbol_tt[s].delta_find_state = cumul[s] as i32 - count as i32;
            }
        }

        Self {
            accuracy_log,
            state_table,
            symbol_tt,
            cumul,
        }
    }

    /// First state belonging to `symbol`. Used to bootstrap the reverse
    /// encoding loop.
    pub fn init_state(&self, symbol: usize) -> u16 {
        let slot = self.cumul[symbol] as usize;
        self.state_table[slot]
    }

    /// One FSE encoding step. Returns the new state.
    pub fn encode_symbol(&self, state: u16, symbol: usize, writer: &mut RevBitWriter) -> u16 {
        let tt = self.symbol_tt[symbol];
        // Reference algorithm operates on states in [table_size, 2*table_size).
        let s_enc = state as i32 + (1i32 << self.accuracy_log);
        let nb_bits_out = ((s_enc + tt.delta_nb_bits) >> 16) as u32;
        let to_write = if nb_bits_out == 0 {
            0
        } else {
            (s_enc as u64) & ((1u64 << nb_bits_out) - 1)
        };
        writer.write_bits(to_write, nb_bits_out);
        let idx = ((s_enc >> nb_bits_out) + tt.delta_find_state) as usize;
        self.state_table[idx]
    }

    /// Write out the final state as `accuracy_log` bits. The decoder will
    /// read these bits first via `FseState::init`.
    pub fn write_final_state(&self, state: u16, writer: &mut RevBitWriter) {
        writer.write_bits(state as u64, self.accuracy_log as u32);
    }
}

// ─── default (Predefined_Mode) normalised counts ──────────────────────────

/// Normalized counts for the predefined Literal_Lengths_Code FSE table.
pub const DEFAULT_LL_COUNTS: [i16; 36] = [
    4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1, 1, 1,
    -1, -1, -1, -1,
];
pub const DEFAULT_LL_ACCURACY_LOG: u8 = 6;

pub const DEFAULT_ML_COUNTS: [i16; 53] = [
    1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1,
];
pub const DEFAULT_ML_ACCURACY_LOG: u8 = 6;

pub const DEFAULT_OF_COUNTS: [i16; 29] = [
    1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1,
];
pub const DEFAULT_OF_ACCURACY_LOG: u8 = 5;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zstd::bitreader::RevBitReader;
    use crate::zstd::fse::{FseState, FseTable};

    fn fse_round_trip(counts: &[i16], al: u8, syms: &[usize]) {
        let enc = FseEncoder::from_normalized(counts, al);
        let dec_tbl = FseTable::from_normalized(counts, al).unwrap();

        let mut writer = RevBitWriter::new();
        let mut state = enc.init_state(*syms.last().unwrap());
        for i in (0..syms.len() - 1).rev() {
            state = enc.encode_symbol(state, syms[i], &mut writer);
        }
        enc.write_final_state(state, &mut writer);

        let bytes = writer.finish();
        let mut br = RevBitReader::new(&bytes).unwrap();
        let mut s = FseState::init(&dec_tbl, &mut br).unwrap();
        let mut decoded: Vec<usize> = Vec::new();
        for _ in 0..syms.len() {
            decoded.push(s.symbol(&dec_tbl) as usize);
            if decoded.len() < syms.len() {
                s.advance(&dec_tbl, &mut br).unwrap();
            }
        }
        assert_eq!(decoded, syms);
    }

    #[test]
    fn ll_round_trip_predefined() {
        fse_round_trip(
            &DEFAULT_LL_COUNTS,
            DEFAULT_LL_ACCURACY_LOG,
            &[0, 5, 10, 0, 0, 16, 3, 1, 2, 24, 0, 0, 8],
        );
    }

    #[test]
    fn of_round_trip_predefined() {
        fse_round_trip(
            &DEFAULT_OF_COUNTS,
            DEFAULT_OF_ACCURACY_LOG,
            &[3, 5, 0, 8, 12, 2, 1, 4, 6, 0, 10],
        );
    }

    #[test]
    fn ml_round_trip_predefined() {
        fse_round_trip(
            &DEFAULT_ML_COUNTS,
            DEFAULT_ML_ACCURACY_LOG,
            &[0, 1, 2, 3, 10, 20, 0, 0, 30, 5, 15, 8, 0],
        );
    }
}
