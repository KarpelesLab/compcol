//! Finite State Entropy (FSE) decoder for Zstandard.
//!
//! Reference: RFC 8478 §4.1. FSE is a tabular ANS entropy coder. Each table
//! has a fixed power-of-two size `2^accuracy_log` and is built from a
//! `Normalized_Counts[]` array (one entry per symbol giving its assigned
//! probability proportion).
//!
//! Decoding a stream:
//!  1. Read `accuracy_log` bits to initialize each state.
//!  2. Repeatedly: look up `(symbol, num_bits, base_state)` in the table,
//!     emit `symbol`, then state = base_state + read(num_bits).
//!
//! Encoding is not implemented (encoder remains Raw_Block-only).

use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;
use crate::zstd::bitreader::RevBitReader;

/// One decoded entry in the FSE decode table.
///
/// "Decode table" in the spec sense: indexed by *current state*, gives the
/// symbol emitted at that state and the next-state recipe.
#[derive(Clone, Copy, Debug)]
pub struct FseEntry {
    pub symbol: u16,
    pub num_bits: u8,
    pub base_state: u16,
}

/// FSE decode table built from a Normalized_Counts array.
pub struct FseTable {
    pub accuracy_log: u8,
    /// `entries[state]` — table size is `1 << accuracy_log`.
    pub entries: Vec<FseEntry>,
}

impl FseTable {
    pub fn size(&self) -> usize {
        self.entries.len()
    }

    /// Build a decode table from a normalized-count distribution.
    ///
    /// `counts[sym]` is the spec's normalized count. A value of `-1` is the
    /// "less-than-1 probability" marker which gets a dedicated state with
    /// `num_bits = accuracy_log` (so reading that state's bits gives any
    /// valid follow-up state).
    pub fn from_normalized(counts: &[i16], accuracy_log: u8) -> Result<Self, Error> {
        if accuracy_log == 0 || accuracy_log > 9 {
            return Err(Error::Corrupt);
        }
        let table_size = 1usize << accuracy_log;
        let table_mask = (table_size - 1) as u32;
        let high_threshold = table_size as i32 - 1;
        let mut high_threshold = high_threshold;

        // Spread symbols across the table using zstd's spreading algorithm
        // (RFC 8478 §4.1.1): "less-than-1" symbols are placed from the end
        // of the table downward, then the remaining symbols are spread by
        // walking `step = (table_size >> 1) + (table_size >> 3) + 3` with a
        // mod-table_size, skipping already-occupied slots.

        // Position[symbol] of where this symbol is placed (we don't need this
        // separately; we just place entries in `symbol_at[pos] = symbol`).
        let mut symbol_at: Vec<i16> = vec![-1; table_size];

        // Step 1: place less-than-1 ("flow") symbols at the high end of the
        // table.
        for (sym, &cnt) in counts.iter().enumerate() {
            if cnt == -1 {
                symbol_at[high_threshold as usize] = sym as i16;
                high_threshold -= 1;
            }
        }

        // Step 2: spread the rest with the magic step.
        let step = (table_size >> 1) + (table_size >> 3) + 3;
        let mut pos: usize = 0;
        for (sym, &cnt) in counts.iter().enumerate() {
            if cnt <= 0 {
                continue;
            }
            for _ in 0..cnt {
                // skip occupied slots
                while symbol_at[pos] != -1 {
                    pos = (pos + step) & table_mask as usize;
                }
                symbol_at[pos] = sym as i16;
                pos = (pos + step) & table_mask as usize;
            }
        }
        // Note: the spec does NOT require `pos == 0` at the end; the
        // less-than-1 placements at the high end break that invariant.
        // Sanity-check that every slot is filled instead.
        if symbol_at.iter().any(|&s| s < 0) {
            return Err(Error::Corrupt);
        }
        let _ = pos;

        // Now compute next_state[] for each occurrence of each symbol. The
        // spec algorithm: maintain a per-symbol "next" counter starting at
        // `count[sym]` rounded up to the next power-of-two ≥ count. For each
        // occurrence in table order, num_bits = accuracy_log - log2(next),
        // base_state = (next << num_bits) - table_size; then next += 1.
        let n_symbols = counts.len();
        let mut sym_next: Vec<u32> = vec![0; n_symbols];
        for (sym, &cnt) in counts.iter().enumerate() {
            if cnt == -1 {
                // less-than-1 symbol: single occurrence, num_bits = accuracy_log.
                // Its "next" starts at table_size so that
                //   num_bits = accuracy_log - log2(table_size) ... wait, that's 0.
                // Per spec: for these symbols num_bits = accuracy_log,
                // base_state = 0; just set next = table_size+1 so the formula
                // never re-fires (we handle this case in the loop below).
                sym_next[sym] = 1;
            } else if cnt > 0 {
                sym_next[sym] = cnt as u32;
            }
        }

        let mut entries = vec![
            FseEntry {
                symbol: 0,
                num_bits: 0,
                base_state: 0,
            };
            table_size
        ];
        for state in 0..table_size {
            let sym = symbol_at[state];
            if sym < 0 {
                return Err(Error::Corrupt);
            }
            let sym = sym as u16;
            let cnt = counts[sym as usize];
            if cnt == -1 {
                // Special less-than-1 symbol entry.
                entries[state] = FseEntry {
                    symbol: sym,
                    num_bits: accuracy_log,
                    base_state: 0,
                };
            } else {
                let next = sym_next[sym as usize];
                sym_next[sym as usize] = next + 1;
                // num_bits = accuracy_log - log2(next) (rounded down).
                // Using highest-set-bit: log2(next) = 31 - leading_zeros(next).
                let log2 = 31 - next.leading_zeros();
                let num_bits = accuracy_log as i32 - log2 as i32;
                if num_bits < 0 {
                    return Err(Error::Corrupt);
                }
                let num_bits = num_bits as u8;
                let base_state = (next << num_bits) as i32 - table_size as i32;
                if base_state < 0 || base_state >= table_size as i32 {
                    return Err(Error::Corrupt);
                }
                entries[state] = FseEntry {
                    symbol: sym,
                    num_bits,
                    base_state: base_state as u16,
                };
            }
        }

        Ok(Self {
            accuracy_log,
            entries,
        })
    }
}

/// Decode the standard "FSE_Table" preamble that precedes any FSE-compressed
/// data block (§4.1.1).
///
/// Returns `(table, bits_consumed)`. The caller is responsible for byte-aligning
/// any subsequent reads (the spec pads to the next byte after the table).
///
/// `data` is the byte slice starting at the FSE header. The decoder reads
/// forward, MSB-LSB-bitstream style (LSB-first bit accumulator over the bytes).
pub fn decode_fse_table(
    data: &[u8],
    max_accuracy_log: u8,
    max_symbol: u16,
) -> Result<(FseTable, usize), Error> {
    // The FSE header bit stream is LSB-first, byte-by-byte (RFC 8478 §4.1.1).
    // We model it with a tiny forward bit reader local to this function.
    struct FwdBits<'a> {
        data: &'a [u8],
        /// Bit cursor: total bits read so far.
        cursor: usize,
    }
    impl<'a> FwdBits<'a> {
        fn new(d: &'a [u8]) -> Self {
            Self { data: d, cursor: 0 }
        }
        fn peek(&self, n: u32) -> Result<u32, Error> {
            if n == 0 {
                return Ok(0);
            }
            if n > 24 {
                return Err(Error::Corrupt);
            }
            // We need bits [cursor .. cursor+n), LSB-first per byte.
            let byte_idx = self.cursor / 8;
            let bit_idx = self.cursor % 8;
            // Pull up to 4 bytes into a 32-bit accumulator.
            let mut acc: u64 = 0;
            for i in 0..4 {
                if byte_idx + i < self.data.len() {
                    acc |= (self.data[byte_idx + i] as u64) << (i * 8);
                }
            }
            let mask = if n == 32 {
                0xFFFF_FFFFu64
            } else {
                (1u64 << n) - 1
            };
            Ok(((acc >> bit_idx) & mask) as u32)
        }
        fn read(&mut self, n: u32) -> Result<u32, Error> {
            let v = self.peek(n)?;
            self.cursor += n as usize;
            Ok(v)
        }
        fn byte_pos(&self) -> usize {
            self.cursor.div_ceil(8)
        }
    }

    let mut br = FwdBits::new(data);

    // Accuracy_Log = 5 + raw(4 bits)
    let raw_al = br.read(4)? as u8;
    let accuracy_log = raw_al + 5;
    if accuracy_log > max_accuracy_log {
        return Err(Error::Corrupt);
    }
    let table_size = 1u32 << accuracy_log;
    let mut remaining: i32 = table_size as i32 + 1;
    // counts will be sized after we know how far we go; allow up to max_symbol+1
    let mut counts: Vec<i16> = vec![0; (max_symbol as usize) + 1];

    let mut symbol: usize = 0;
    let mut previous_is_zero = false;

    while remaining > 1 && symbol <= max_symbol as usize {
        if previous_is_zero {
            // Read 2-bit run-of-zeros.
            let mut zeros: u32 = 0;
            loop {
                let v = br.read(2)?;
                zeros += v;
                if v != 3 {
                    break;
                }
            }
            // Skip `zeros` symbols (already initialized to 0 in `counts`).
            symbol += zeros as usize;
            if symbol > max_symbol as usize + 1 {
                return Err(Error::Corrupt);
            }
            previous_is_zero = false;
            continue;
        }

        // RFC 8478 §4.1.1: variable-width value.
        //   nbBits   = ceil(log2(remaining + 1))
        //   threshold = (1 << nbBits) - 1 - remaining     (== 2^nbBits - max)
        //   peek `nbBits` bits.
        //   lowBits = peek & ((1 << (nbBits-1)) - 1)
        //   if lowBits < threshold: value = lowBits; consume nbBits-1.
        //   else: value = peek; if value >= (1 << (nbBits-1)) { value -= threshold; }
        //         consume nbBits.
        // `remaining` here is the spec's running counter (>= 2).
        let rem = remaining as u32;
        if rem == 0 {
            return Err(Error::Corrupt);
        }
        // nbBits = ceil(log2(rem + 1)). Since rem >= 1, rem+1 >= 2 so leading_zeros < 32.
        let nb_bits = if rem == 1 {
            1
        } else {
            32 - rem.leading_zeros()
        };
        let threshold = (1u32 << nb_bits) - 1 - rem;
        let peek = br.peek(nb_bits)?;
        let low_mask = (1u32 << (nb_bits - 1)) - 1;
        let low_bits = peek & low_mask;
        let (value, used_bits) = if low_bits < threshold {
            (low_bits, nb_bits - 1)
        } else {
            let mut v = peek;
            if v >= (1u32 << (nb_bits - 1)) {
                v -= threshold;
            }
            (v, nb_bits)
        };
        br.cursor += used_bits as usize;

        let proba = value as i32 - 1;
        if symbol >= counts.len() {
            return Err(Error::Corrupt);
        }
        counts[symbol] = proba as i16;
        if proba == 0 {
            // Zero — next symbol marker.
            previous_is_zero = true;
        } else {
            let used = if proba < 0 { 1 } else { proba };
            if used > remaining - 1 {
                return Err(Error::Corrupt);
            }
            remaining -= used;
        }
        symbol += 1;
    }

    if remaining != 1 {
        return Err(Error::Corrupt);
    }

    // Truncate counts to actually-seen symbols.
    counts.truncate(symbol);

    let table = FseTable::from_normalized(&counts, accuracy_log)?;
    let bytes_consumed = br.byte_pos();
    Ok((table, bytes_consumed))
}

/// Active FSE decoder state. Holds a reference to a table; the bit reader is
/// passed in per call.
pub struct FseState {
    pub state: u16,
}

impl FseState {
    /// Initialize state by reading `accuracy_log` bits from the bit reader.
    pub fn init(table: &FseTable, br: &mut RevBitReader<'_>) -> Result<Self, Error> {
        let s = br.read(table.accuracy_log as u32)? as u16;
        if (s as usize) >= table.size() {
            return Err(Error::Corrupt);
        }
        Ok(Self { state: s })
    }

    /// Return the current symbol (without advancing state).
    pub fn symbol(&self, table: &FseTable) -> u16 {
        table.entries[self.state as usize].symbol
    }

    /// Advance: read `num_bits` from the reader and update state.
    pub fn advance(&mut self, table: &FseTable, br: &mut RevBitReader<'_>) -> Result<(), Error> {
        let e = table.entries[self.state as usize];
        let extra = br.read(e.num_bits as u32)? as u16;
        let next = e.base_state.wrapping_add(extra);
        if (next as usize) >= table.size() {
            return Err(Error::Corrupt);
        }
        self.state = next;
        Ok(())
    }
}

// ─── default tables (RFC 8478 §3.1.1.3.2.2.1) ─────────────────────────────

/// Predefined distributions for literal lengths.
pub fn default_ll_table() -> FseTable {
    let counts: [i16; 36] = [
        4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1,
        1, 1, -1, -1, -1, -1,
    ];
    FseTable::from_normalized(&counts, 6).unwrap()
}

/// Predefined distributions for match lengths.
pub fn default_ml_table() -> FseTable {
    // From zstd reference (ML_defaultNorm, 53 values, sum = 64).
    let counts: [i16; 53] = [
        1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1,
    ];
    FseTable::from_normalized(&counts, 6).unwrap()
}

/// Predefined distributions for offset codes.
pub fn default_of_table() -> FseTable {
    let counts: [i16; 29] = [
        1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1,
    ];
    FseTable::from_normalized(&counts, 5).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_tables_build() {
        let ll = default_ll_table();
        assert_eq!(ll.size(), 64);
        let ml = default_ml_table();
        assert_eq!(ml.size(), 64);
        let of = default_of_table();
        assert_eq!(of.size(), 32);
    }

    #[test]
    fn tiny_normalized_distribution() {
        // accuracy_log=2 → table_size=4. counts must sum to 4.
        let counts = [2i16, 2];
        let t = FseTable::from_normalized(&counts, 2).unwrap();
        assert_eq!(t.size(), 4);
        // every entry's symbol should be 0 or 1
        for e in &t.entries {
            assert!(e.symbol < 2);
        }
    }

    #[test]
    fn less_than_one_symbol() {
        // accuracy_log=2 → table_size=4. counts=[3,-1,1,-1] sums to 3+1=4
        // (-1 contributes 1 nominal slot). Wait — the spec says counts must
        // sum to table_size where -1 counts as 1 slot. So [3, 1] sum=4 works,
        // and [3, -1] would sum to 3 + (-1 → 1) → mismatched. Use [2, -1, -1]
        // → 2 + 1 + 1 = 4.
        let counts = [2i16, -1, -1];
        let t = FseTable::from_normalized(&counts, 2).unwrap();
        assert_eq!(t.size(), 4);
        // exactly two entries should have num_bits = accuracy_log (the
        // less-than-1 symbols)
        let prob1 = t.entries.iter().filter(|e| e.num_bits == 2).count();
        assert_eq!(prob1, 2);
    }
}
