//! Huffman decoder for Zstandard literals (RFC 8478 §4.2).
//!
//! Zstd Huffman codes are canonical, MSB-first, indexed by a *weight* per
//! symbol. The weight array is decoded from a tree description (either direct
//! nibble-packed or FSE-compressed) and then the standard canonical-code
//! construction yields (length, code) for every literal byte symbol (0..256).
//!
//! Streams are read backward MSB-first via [`RevBitReader`]. A lookup table
//! sized to the maximum code length is built to decode one byte per call in
//! O(1) — index the table by the next `max_length` bits, read off the symbol
//! and its actual length.

use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;
use crate::zstd::bitreader::RevBitReader;
use crate::zstd::fse::FseState;

/// Maximum number of bits used by any single Huffman code (per RFC 8478 §4.2).
pub const HUF_MAX_BITS: u8 = 11;

/// Built Huffman table ready for streaming decode.
pub struct HuffTable {
    /// Bit-width used for the lookup index.
    pub max_bits: u8,
    /// For each of the `1 << max_bits` index values: (symbol, length).
    pub lookup: Vec<(u8, u8)>,
}

impl HuffTable {
    /// Decode one symbol from `br`, consuming exactly its bit length.
    ///
    /// Fast path: peek `max_bits` (without consuming), index the lookup table,
    /// then consume only the matched code's actual length. Peeking returns the
    /// next `max_bits` already left-justified, so the index is `raw` directly —
    /// no `read`+`unread` reseed per symbol.
    #[inline]
    pub fn decode(&self, br: &mut RevBitReader<'_>) -> Result<u8, Error> {
        let max = self.max_bits as u32;
        let (raw, avail) = br.peek_bits(max);
        if avail == 0 {
            return Err(Error::Corrupt);
        }
        let idx = raw as usize;
        // `idx` is in `0..(1 << max)` by construction of `peek_bits`, and the
        // lookup table is sized `1 << max`, so the index is always in range.
        debug_assert!(idx < self.lookup.len());
        let (sym, len) = self.lookup[idx];
        if len == 0 || len as u32 > avail {
            return Err(Error::Corrupt);
        }
        br.consume(len as u32);
        Ok(sym)
    }
}

/// Build a `HuffTable` from per-symbol bit lengths using **zstd's canonical
/// code ordering** (RFC 8478 §4.2.1.3): longest codes get the lowest code
/// values. `lengths[sym]==0` means the symbol is not present.
fn table_from_lengths(lengths: &[u8]) -> Result<HuffTable, Error> {
    let mut max_bits = 0u8;
    for &l in lengths {
        if l > HUF_MAX_BITS {
            return Err(Error::Corrupt);
        }
        if l > max_bits {
            max_bits = l;
        }
    }
    if max_bits == 0 {
        return Err(Error::Corrupt);
    }
    let mut counts = [0u32; (HUF_MAX_BITS as usize) + 1];
    for &l in lengths {
        if l > 0 {
            counts[l as usize] += 1;
        }
    }
    // Verify Kraft equality (zstd Huffman codes are complete trees).
    let mut kraft: u64 = 0;
    for l in 1..=max_bits {
        kraft += (counts[l as usize] as u64) << (max_bits - l);
    }
    if kraft != (1u64 << max_bits) {
        return Err(Error::Corrupt);
    }

    // Zstd canonical Huffman: longest codes start at 0, then next-shorter-
    // length resumes after rounding the running code up by `(used+1) >> 1`.
    //
    // Compute `next_code[l]` = starting code value for length-`l` codes.
    // Walking from `l = max_bits` down to `l = 1`:
    //   next_code[max_bits] = 0
    //   next_code[l-1] = (next_code[l] + counts[l]) >> 1
    let mut next_code = [0u32; (HUF_MAX_BITS as usize) + 2];
    next_code[max_bits as usize] = 0;
    for l in (1..max_bits).rev() {
        next_code[l as usize] = (next_code[(l + 1) as usize] + counts[(l + 1) as usize]) >> 1;
    }
    // The recurrence above computes next_code[l] using next_code[l+1].
    // Iterating with `l in (1..max_bits).rev()` gives l = max_bits-1, ..., 1.
    // After this loop, next_code[1..=max_bits] are all populated.

    // Allocate the lookup table.
    let size = 1usize << max_bits;
    let mut lookup = vec![(0u8, 0u8); size];

    // Sort symbols by (length desc, symbol asc) so equal-length symbols
    // keep natural numerical order. We just iterate symbols in ascending
    // order grouped by length.
    for current_len in (1..=max_bits).rev() {
        for (sym, &len) in lengths.iter().enumerate() {
            if len != current_len {
                continue;
            }
            let code = next_code[len as usize];
            next_code[len as usize] += 1;
            // Place this code in the `max_bits`-wide lookup table. The top
            // `len` bits of the index = `code`.
            let shift = max_bits - len;
            let start = (code << shift) as usize;
            let count = 1usize << shift;
            for slot in &mut lookup[start..start + count] {
                *slot = (sym as u8, len);
            }
        }
    }

    Ok(HuffTable { max_bits, lookup })
}

/// Decode the Huffman tree description (RFC 8478 §4.2.1) from `data`.
///
/// Returns `(table, header_bytes_consumed)`.
///
/// `data[0]` is the `Header_Byte` describing how the weights themselves were
/// encoded:
///   - `0..=127`: FSE-compressed weights, header_byte = FSE_byte_count.
///   - `128..=255`: direct, nibble-packed (each weight is 4 bits). Number of
///     symbols described = header_byte - 127. Last weight is implicit.
pub fn decode_huffman_tree(data: &[u8]) -> Result<(HuffTable, usize), Error> {
    if data.is_empty() {
        return Err(Error::Corrupt);
    }
    let hb = data[0];
    let (weights, consumed) = if hb >= 128 {
        // Direct encoding: 4 bits per symbol, count = hb - 127.
        let count = (hb as usize) - 127;
        let bytes_needed = count.div_ceil(2);
        if data.len() < 1 + bytes_needed {
            return Err(Error::Corrupt);
        }
        let mut weights = Vec::with_capacity(count);
        for i in 0..count {
            let b = data[1 + i / 2];
            let nib = if i % 2 == 0 { b >> 4 } else { b & 0x0F };
            weights.push(nib);
        }
        (weights, 1 + bytes_needed)
    } else {
        // FSE-compressed weights. `hb` is the length in bytes of the FSE
        // payload that follows.
        let fse_payload_len = hb as usize;
        if data.len() < 1 + fse_payload_len {
            return Err(Error::Corrupt);
        }
        let fse_bytes = &data[1..1 + fse_payload_len];
        let weights = decode_fse_weights(fse_bytes)?;
        (weights, 1 + fse_payload_len)
    };

    // Reconstruct the canonical Huffman lengths from the weights.
    // Per §4.2.1.3: a weight of 0 means symbol absent; otherwise the symbol's
    // code length is (maxNumBits + 1 - weight), where maxNumBits is the
    // smallest integer s.t. sum(2^weight) <= 2^maxNumBits.
    //
    // Step 1: compute Σ 2^weight for weight > 0.
    let mut sum: u64 = 0;
    for &w in &weights {
        if w > 0 {
            sum += 1u64 << (w - 1);
        }
    }
    if sum == 0 {
        return Err(Error::Corrupt);
    }
    // max_num_bits = ceil(log2(sum)) and the "implicit last weight" closes
    // the tree to 2^max_num_bits.
    // If sum is already a power of two, we set max_num_bits = log2(sum) and
    // emit an implicit "weight 0" (symbol absent) — i.e. no extra symbol.
    let max_num_bits = if sum.is_power_of_two() {
        sum.trailing_zeros() as u8
    } else {
        (64 - sum.leading_zeros()) as u8
    };
    let left_over = (1u64 << max_num_bits) - sum;
    // left_over must be a power of two (or zero, which we already handled).
    let last_weight = if left_over == 0 {
        0
    } else {
        if !left_over.is_power_of_two() {
            return Err(Error::Corrupt);
        }
        (left_over.trailing_zeros() as u8) + 1
    };
    let mut all_weights = weights.clone();
    all_weights.push(last_weight);

    // Convert weights → bit lengths.
    let mut lengths = vec![0u8; 256];
    for (sym, &w) in all_weights.iter().enumerate() {
        if sym >= 256 {
            return Err(Error::Corrupt);
        }
        if w > 0 {
            if w > max_num_bits {
                return Err(Error::Corrupt);
            }
            lengths[sym] = max_num_bits + 1 - w;
        }
    }
    let table = table_from_lengths(&lengths)?;
    Ok((table, consumed))
}

/// Test hook: decode the weights from a Huffman tree description.
pub(crate) fn decode_huffman_tree_weights_for_test(data: &[u8]) -> Result<Vec<u8>, Error> {
    if data.is_empty() {
        return Err(Error::Corrupt);
    }
    let hb = data[0];
    if hb >= 128 {
        let count = (hb as usize) - 127;
        let bytes_needed = count.div_ceil(2);
        if data.len() < 1 + bytes_needed {
            return Err(Error::Corrupt);
        }
        let mut weights = Vec::with_capacity(count);
        for i in 0..count {
            let b = data[1 + i / 2];
            let nib = if i % 2 == 0 { b >> 4 } else { b & 0x0F };
            weights.push(nib);
        }
        Ok(weights)
    } else {
        let fse_payload_len = hb as usize;
        if data.len() < 1 + fse_payload_len {
            return Err(Error::Corrupt);
        }
        decode_fse_weights(&data[1..1 + fse_payload_len])
    }
}

/// Decode the FSE-compressed weight array used when Header_Byte < 128.
///
/// Format (RFC 8478 §4.2.1.2): an FSE table header followed by two
/// interleaved FSE streams reading backwards from the end of the payload.
fn decode_fse_weights(payload: &[u8]) -> Result<Vec<u8>, Error> {
    // Weight alphabet size is fixed at 256; max weight value is HUF_MAX_BITS
    // (11), so max symbol is HUF_MAX_BITS.
    let max_accuracy_log = 6; // RFC §4.2.1.2 caps accuracy_log at 6 for weights
    let max_symbol: u16 = HUF_MAX_BITS as u16;
    let (table, header_bytes) =
        crate::zstd::fse::decode_fse_table(payload, max_accuracy_log, max_symbol)?;
    if header_bytes > payload.len() {
        return Err(Error::Corrupt);
    }
    let bitstream = &payload[header_bytes..];
    if bitstream.is_empty() {
        return Err(Error::Corrupt);
    }
    let mut br = RevBitReader::new(bitstream)?;

    // Initialise two interleaved states.
    let mut s1 = FseState::init(&table, &mut br)?;
    let mut s2 = FseState::init(&table, &mut br)?;

    let mut weights: Vec<u8> = Vec::new();

    // A Huffman weight array describes at most 255 explicit symbols (the 256th
    // — symbol 255 — is the implicit "last weight" closing the tree, computed
    // by the caller). A crafted FSE table whose reachable states all have
    // `num_bits == 0` (e.g. a single-symbol normalized distribution) consumes
    // no bits per advance, so the `br.remaining() < nb` checks below never
    // fire and the loop would push weights forever (hang / OOM). Bound the
    // accumulated weight count and reject once it would exceed the alphabet.
    const MAX_WEIGHTS: usize = 255;

    // Decode in the canonical interleaved FSE pattern:
    //   emit s1.symbol; advance s1 (read num_bits)
    //   emit s2.symbol; advance s2
    // If the advance would have read past the end of the stream we stop;
    // the *other* state's pending symbol is emitted as the final byte.
    loop {
        if weights.len() >= MAX_WEIGHTS {
            return Err(Error::Corrupt);
        }
        let w1 = s1.symbol(&table) as u8;
        weights.push(w1);
        let nb = table.entries[s1.state as usize].num_bits as usize;
        if br.remaining() < nb {
            // Cannot advance s1 — emit s2's pending and stop.
            let w2 = s2.symbol(&table) as u8;
            weights.push(w2);
            break;
        }
        s1.advance(&table, &mut br)?;

        if weights.len() >= MAX_WEIGHTS {
            return Err(Error::Corrupt);
        }
        let w2 = s2.symbol(&table) as u8;
        weights.push(w2);
        let nb = table.entries[s2.state as usize].num_bits as usize;
        if br.remaining() < nb {
            let w1f = s1.symbol(&table) as u8;
            weights.push(w1f);
            break;
        }
        s2.advance(&table, &mut br)?;
    }

    Ok(weights)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_from_simple_lengths() {
        // 4 symbols, all length-2 → complete binary tree.
        let lengths = {
            let mut v = vec![0u8; 256];
            v[0] = 2;
            v[1] = 2;
            v[2] = 2;
            v[3] = 2;
            v
        };
        let t = table_from_lengths(&lengths).unwrap();
        assert_eq!(t.max_bits, 2);
        // lookup size = 4.
        assert_eq!(t.lookup.len(), 4);
        // Codes: sym0=00, sym1=01, sym2=10, sym3=11
        assert_eq!(t.lookup[0], (0, 2));
        assert_eq!(t.lookup[1], (1, 2));
        assert_eq!(t.lookup[2], (2, 2));
        assert_eq!(t.lookup[3], (3, 2));
    }
}
