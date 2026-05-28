//! Brotli prefix-code emission (RFC 7932 §3.4 and §3.5).
//!
//! Two paths:
//!
//! - [`emit_simple_nsym1`] writes a simple prefix code with NSYM=1
//!   (one symbol, zero bits per decode). Used when an alphabet has a
//!   single nonzero-frequency symbol — e.g., a degenerate distance
//!   tree when the encoder emits no back-references in this meta-
//!   block.
//!
//! - [`emit_complex_prefix_code`] writes a complex prefix code given a
//!   per-symbol code-length array. The lengths are RLE-encoded using
//!   the 18-symbol code-length alphabet (literal lengths 0..=15 + the
//!   repeat-previous-nonzero meta-code 16 + the run-of-zeros meta-code
//!   17), itself encoded with a Huffman code over 6 cl-cl symbols
//!   whose lengths are emitted with the fixed cl-cl code values.
//!
//! Codeword bit order follows the decoder: each codeword's MSB is the
//! first stream bit. Since the underlying byte stream is LSB-first,
//! canonical (MSB-first) code values are pre-reversed before passing
//! to the writer.

use alloc::vec;
use alloc::vec::Vec;

use super::BitWriter;

// ─── inlined helpers (cannot depend on the deflate-gated crate-level
//      `bits` and `huffman` modules since the brotli feature can be
//      enabled in isolation) ────────────────────────────────────────────

/// Reverse the lowest `n` bits of `v`. Used to pre-reverse MSB-first
/// canonical codes before LSB-first emission.
pub(crate) const fn reverse_bits(mut v: u32, n: u32) -> u32 {
    let mut out = 0u32;
    let mut i = 0;
    while i < n {
        out = (out << 1) | (v & 1);
        v >>= 1;
        i += 1;
    }
    out
}

/// Pool element used by `length_limited_huffman`.
#[derive(Clone, Copy)]
enum PoolKind {
    Coin(u16),
    Pair(u32, u32),
}
struct PoolElement {
    cost: u64,
    kind: PoolKind,
}

/// Compute optimal code lengths bounded by `max_length` for the given
/// frequency vector via Larmore–Hirschberg package-merge. Mirrors the
/// implementation in `crate::huffman` exactly.
pub(crate) fn length_limited_huffman(freqs: &[u32], max_length: u8) -> Vec<u8> {
    assert!(
        max_length > 0 && max_length <= 15,
        "max_length must be 1..=15"
    );
    let mut out = vec![0u8; freqs.len()];
    let mut coins: Vec<(u32, u16)> = freqs
        .iter()
        .enumerate()
        .filter_map(|(i, &f)| if f > 0 { Some((f, i as u16)) } else { None })
        .collect();
    let n = coins.len();
    if n == 0 {
        return out;
    }
    if n == 1 {
        out[coins[0].1 as usize] = 1;
        return out;
    }
    assert!(n <= 1usize << max_length, "alphabet too big for max_length");
    coins.sort_by_key(|&(f, _)| f);

    let mut pool: Vec<PoolElement> = Vec::with_capacity(n * (max_length as usize) * 2 + 8);
    let mut current: Vec<u32> = Vec::with_capacity(2 * n);
    for &(f, sym) in &coins {
        pool.push(PoolElement {
            cost: f as u64,
            kind: PoolKind::Coin(sym),
        });
        current.push((pool.len() - 1) as u32);
    }

    for _ in 1..max_length {
        let mut packages: Vec<u32> = Vec::with_capacity(current.len() / 2);
        let mut i = 0;
        while i + 1 < current.len() {
            let a = current[i];
            let b = current[i + 1];
            let cost = pool[a as usize].cost + pool[b as usize].cost;
            pool.push(PoolElement {
                cost,
                kind: PoolKind::Pair(a, b),
            });
            packages.push((pool.len() - 1) as u32);
            i += 2;
        }

        let coin_start = pool.len();
        for &(f, sym) in &coins {
            pool.push(PoolElement {
                cost: f as u64,
                kind: PoolKind::Coin(sym),
            });
        }
        let fresh_coins: Vec<u32> = (coin_start..pool.len()).map(|i| i as u32).collect();

        let mut merged: Vec<u32> = Vec::with_capacity(fresh_coins.len() + packages.len());
        let (mut ci, mut pi) = (0usize, 0usize);
        while ci < fresh_coins.len() && pi < packages.len() {
            if pool[fresh_coins[ci] as usize].cost <= pool[packages[pi] as usize].cost {
                merged.push(fresh_coins[ci]);
                ci += 1;
            } else {
                merged.push(packages[pi]);
                pi += 1;
            }
        }
        merged.extend_from_slice(&fresh_coins[ci..]);
        merged.extend_from_slice(&packages[pi..]);
        current = merged;
    }

    let pick = 2 * n - 2;
    let mut stack: Vec<u32> = Vec::with_capacity(32);
    for &root in &current[..pick] {
        stack.clear();
        stack.push(root);
        while let Some(idx) = stack.pop() {
            match pool[idx as usize].kind {
                PoolKind::Coin(sym) => out[sym as usize] += 1,
                PoolKind::Pair(a, b) => {
                    stack.push(a);
                    stack.push(b);
                }
            }
        }
    }

    out
}

/// Compute canonical MSB-first codes per RFC 1951 §3.2.2 (also used
/// in brotli §3.2). Slot `i` holds the code for symbol `i`; the value
/// is meaningless when `lengths[i] == 0`.
pub(crate) fn canonical_codes_from_lengths(lengths: &[u8]) -> Vec<u16> {
    let mut count = [0u32; 16];
    for &len in lengths {
        debug_assert!(len <= 15);
        if len > 0 {
            count[len as usize] += 1;
        }
    }
    let mut next_code = [0u32; 16];
    let mut code: u32 = 0;
    for bits in 1..=15 {
        code = (code + count[bits - 1]) << 1;
        next_code[bits] = code;
    }
    let mut out = vec![0u16; lengths.len()];
    for (i, &len) in lengths.iter().enumerate() {
        if len > 0 {
            out[i] = next_code[len as usize] as u16;
            next_code[len as usize] += 1;
        }
    }
    out
}

/// Minimum bits needed to represent any symbol of an alphabet of the
/// given size. Mirrors the decoder's `alphabet_bits`.
pub(crate) fn alphabet_bits(alphabet_size: u32) -> u32 {
    if alphabet_size <= 1 {
        return 0;
    }
    let mut n = 1u32;
    while (1u32 << n) < alphabet_size {
        n += 1;
    }
    n
}

/// Emit a simple prefix code with NSYM=1 (one symbol, zero bits per
/// decoded use). `alphabet_size` controls how many bits the symbol
/// value field takes.
pub(crate) fn emit_simple_nsym1(
    bw: &mut BitWriter,
    out: &mut Vec<u8>,
    symbol: u32,
    alphabet_size: u32,
) {
    // 2 bits prefix-code-type = 1 (simple)
    bw.write(1, 2, out);
    // 2 bits NSYM-1 = 0
    bw.write(0, 2, out);
    let ab = alphabet_bits(alphabet_size);
    bw.write(symbol, ab, out);
}

/// Emit a simple prefix code with NSYM=2 (two symbols, each 1 bit).
/// Returns the 1-bit code values (LSB-first) for the two listed
/// symbols in input order: `(code_for_symbols[0], code_for_symbols[1])`.
///
/// Per §3.4 the two symbols are emitted in ascending value order and
/// assigned codes "0" and "1" canonically. The wire-format symbol
/// fields are listed in this same ascending order too.
pub(crate) fn emit_simple_nsym2(
    bw: &mut BitWriter,
    out: &mut Vec<u8>,
    symbols: [u32; 2],
    alphabet_size: u32,
) -> [u32; 2] {
    debug_assert!(symbols[0] != symbols[1], "NSYM=2 requires distinct symbols");
    // 2 bits prefix-code-type = 1 (simple)
    bw.write(1, 2, out);
    // 2 bits NSYM-1 = 1 (NSYM = 2)
    bw.write(1, 2, out);
    // Sort symbols ascending — spec requires this so the canonical code
    // assignment matches.
    let (lo, hi) = if symbols[0] < symbols[1] {
        (symbols[0], symbols[1])
    } else {
        (symbols[1], symbols[0])
    };
    let ab = alphabet_bits(alphabet_size);
    bw.write(lo, ab, out);
    bw.write(hi, ab, out);
    // Canonical assignment: lo → "0" (code 0, length 1), hi → "1" (code 1).
    // Bit-reversed (length 1): same values. Map back to input order.
    let lo_code = 0u32;
    let hi_code = 1u32;
    if symbols[0] < symbols[1] {
        [lo_code, hi_code]
    } else {
        [hi_code, lo_code]
    }
}

/// Pre-reversed cl-cl code values indexed by length value 0..=5.
///
/// The decoder builds the cl-cl Huffman tree from the canonical
/// lengths `[(0,2), (1,4), (2,3), (3,2), (4,2), (5,4)]`. The canonical
/// (MSB-first) codes are:
///
///   sym 0 → "00"   (length 2)
///   sym 3 → "01"   (length 2)
///   sym 4 → "10"   (length 2)
///   sym 2 → "110"  (length 3)
///   sym 1 → "1110" (length 4)
///   sym 5 → "1111" (length 4)
///
/// Pre-reversed for LSB-first emission so the first bit emitted is the
/// MSB of the canonical code.
///
/// Tuple is `(bit_count, lsb_first_value)`.
const CL_CL_CODES: [(u32, u32); 6] = [
    (2, 0b00),   // sym 0 ("00")   reversed → 0b00
    (4, 0b0111), // sym 1 ("1110") reversed → 0b0111 = 7
    (3, 0b011),  // sym 2 ("110")  reversed → 0b011  = 3
    (2, 0b10),   // sym 3 ("01")   reversed → 0b10   = 2
    (2, 0b01),   // sym 4 ("10")   reversed → 0b01   = 1
    (4, 0b1111), // sym 5 ("1111") reversed → 0b1111 = 15
];

/// Code-length symbol order from §3.5.
const CODE_LENGTH_ORDER: [usize; 18] =
    [1, 2, 3, 4, 0, 5, 17, 6, 16, 7, 8, 9, 10, 11, 12, 13, 14, 15];

#[derive(Clone, Copy)]
struct RleSymbol {
    sym: u8,
    extra_value: u32,
    extra_bits: u32,
}

/// RLE-encode a code-length sequence per §3.5. Uses code 16 for runs
/// of the same nonzero length and code 17 for runs of zeros, separating
/// repeats with explicit literals so the chain rules (which OVERWRITE
/// the previous count) never fire. This costs a few extra bits but
/// keeps the encoder simple and unambiguous.
fn rle_encode_lengths(lengths: &[u8]) -> Vec<RleSymbol> {
    let mut out: Vec<RleSymbol> = Vec::new();
    let mut i = 0usize;
    while i < lengths.len() {
        let cur = lengths[i];
        // Count consecutive identical entries.
        let mut run = 1usize;
        while i + run < lengths.len() && lengths[i + run] == cur {
            run += 1;
        }

        if cur == 0 {
            // Zero run: use code 17 (3..=10 zeros) for >=3, literal 0 otherwise.
            let mut left = run;
            let mut just_17 = false;
            while left >= 3 {
                if just_17 {
                    // Break the 17-17 chain rule by inserting a literal 0.
                    out.push(RleSymbol {
                        sym: 0,
                        extra_value: 0,
                        extra_bits: 0,
                    });
                    left -= 1;
                    just_17 = false;
                    if left < 3 {
                        break;
                    }
                }
                let chunk = left.min(10);
                out.push(RleSymbol {
                    sym: 17,
                    extra_value: (chunk - 3) as u32,
                    extra_bits: 3,
                });
                left -= chunk;
                just_17 = true;
            }
            let _ = just_17;
            for _ in 0..left {
                out.push(RleSymbol {
                    sym: 0,
                    extra_value: 0,
                    extra_bits: 0,
                });
            }
        } else {
            // First occurrence is a literal length. Subsequent uses 16.
            out.push(RleSymbol {
                sym: cur,
                extra_value: 0,
                extra_bits: 0,
            });
            let mut left = run - 1;
            let mut just_16 = false;
            while left >= 3 {
                if just_16 {
                    // Break the 16-16 chain by inserting a literal `cur`.
                    out.push(RleSymbol {
                        sym: cur,
                        extra_value: 0,
                        extra_bits: 0,
                    });
                    left -= 1;
                    just_16 = false;
                    if left < 3 {
                        break;
                    }
                }
                let chunk = left.min(6);
                out.push(RleSymbol {
                    sym: 16,
                    extra_value: (chunk - 3) as u32,
                    extra_bits: 2,
                });
                left -= chunk;
                just_16 = true;
            }
            let _ = just_16;
            for _ in 0..left {
                out.push(RleSymbol {
                    sym: cur,
                    extra_value: 0,
                    extra_bits: 0,
                });
            }
        }

        i += run;
    }

    // Strip trailing 0 / 17 entries — the last emitted symbol must be in 1..=16.
    while let Some(last) = out.last() {
        if last.sym == 0 || last.sym == 17 {
            out.pop();
        } else {
            break;
        }
    }

    out
}

/// Emit a complex prefix code from a per-symbol code-length list and
/// return the canonical (MSB-first, not bit-reversed) codes the caller
/// uses to emit data symbols.
///
/// Panics in debug mode if `lengths` does not form a valid full prefix
/// code (Kraft equality for ≥ 2 nonzero entries) — caller must ensure
/// this; usually by passing the output of `length_limited_huffman`.
pub(crate) fn emit_complex_prefix_code(
    bw: &mut BitWriter,
    out: &mut Vec<u8>,
    lengths: &[u8],
) -> Vec<u16> {
    // 1. 2-bit prefix-code-type = HSKIP = 0 (i.e. complex code, no skip).
    bw.write(0, 2, out);

    // 2. RLE-encode the target lengths.
    let rle = rle_encode_lengths(lengths);

    // 3. Frequencies of cl-cl symbols, then length-limited Huffman over
    //    the 18-symbol cl-cl alphabet with max length 5.
    let mut cl_freq = [0u32; 18];
    for s in &rle {
        cl_freq[s.sym as usize] += 1;
    }
    let cl_lengths_vec = length_limited_huffman(&cl_freq, 5);

    // Defensive: ensure ≥ 2 distinct nonzero cl-cl lengths so the
    // cl-cl Kraft sum balances to 32. If only one nonzero entry,
    // promote it to length 2 and also assign a "phantom" 16 with
    // length 2 — but no, this changes the meaning. Instead: caller
    // must arrange lengths so this never happens. The RLE always
    // emits at least one literal length plus, for any input with ≥ 1
    // entry, some code-16 or code-17 if there are runs ≥ 3. For
    // single-symbol target alphabets the caller must pick simple-NSYM=1.
    let mut cl_lengths = [0u8; 18];
    for (i, &l) in cl_lengths_vec.iter().enumerate() {
        cl_lengths[i] = l;
    }

    // Verify Kraft equality (debug only). With ≥ 2 distinct cl-cl
    // symbols `length_limited_huffman` guarantees this.
    debug_assert!({
        let mut sum: u32 = 0;
        for &l in cl_lengths.iter() {
            if l > 0 {
                sum += 32u32 >> (l as u32);
            }
        }
        sum == 32
    });

    // 4. Emit cl_lengths in CODE_LENGTH_ORDER, trimming once the Kraft
    //    sum reaches 32 and the last emitted length is nonzero.
    let mut space: i32 = 32;
    let mut last_nonzero_idx: i32 = -1;
    for (idx, &sym_pos) in CODE_LENGTH_ORDER.iter().enumerate() {
        let v = cl_lengths[sym_pos];
        if v != 0 {
            space -= 32 >> (v as i32);
            last_nonzero_idx = idx as i32;
            if space <= 0 {
                break;
            }
        }
    }
    debug_assert!(
        last_nonzero_idx >= 0 && space == 0,
        "cl-cl Kraft sum {} did not reach 32 (lengths={:?})",
        32 - space,
        cl_lengths
    );
    let emit_up_to = (last_nonzero_idx + 1) as usize;
    for &sym_pos in CODE_LENGTH_ORDER.iter().take(emit_up_to) {
        let v = cl_lengths[sym_pos];
        let (n, code) = CL_CL_CODES[v as usize];
        bw.write(code, n, out);
    }

    // 5. Build cl-cl Huffman codes; emit the RLE sequence.
    let cl_codes = canonical_codes_from_lengths(&cl_lengths);
    for s in &rle {
        let len_b = cl_lengths[s.sym as usize] as u32;
        debug_assert!(
            len_b > 0,
            "RLE symbol {} has no cl-cl code (cl_lengths={:?})",
            s.sym,
            cl_lengths
        );
        let code = cl_codes[s.sym as usize];
        let rev = reverse_bits(code as u32, len_b);
        bw.write(rev, len_b, out);
        if s.extra_bits > 0 {
            bw.write(s.extra_value, s.extra_bits, out);
        }
    }

    // 6. Compute canonical (MSB-first) codes for the target alphabet
    //    and return them. Callers bit-reverse before writing data symbols.
    canonical_codes_from_lengths(lengths)
}

/// Build a code-length array of size `alphabet_size` from frequencies
/// (limited to 15 bits per code). Returns all-zero when no symbol has
/// nonzero frequency.
pub(crate) fn build_huffman_lengths(freqs: &[u32], alphabet_size: usize) -> Vec<u8> {
    debug_assert!(freqs.len() <= alphabet_size);
    let lens = length_limited_huffman(freqs, 15);
    let mut out = alloc::vec![0u8; alphabet_size];
    for (i, &l) in lens.iter().enumerate() {
        out[i] = l;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alphabet_bits_known_values() {
        assert_eq!(alphabet_bits(1), 0);
        assert_eq!(alphabet_bits(2), 1);
        assert_eq!(alphabet_bits(16), 4);
        assert_eq!(alphabet_bits(64), 6);
        assert_eq!(alphabet_bits(256), 8);
        assert_eq!(alphabet_bits(704), 10);
    }

    #[test]
    fn rle_drops_trailing_zeros() {
        let lens = [3u8, 4, 0, 0, 0, 0, 0];
        let rle = rle_encode_lengths(&lens);
        let last = rle.last().unwrap();
        assert!(last.sym != 0 && last.sym != 17);
    }

    #[test]
    fn rle_long_zero_run() {
        // 30 zeros → multiple 17s separated by literal 0.
        let lens = [3u8]
            .iter()
            .chain([0u8; 30].iter())
            .copied()
            .collect::<Vec<_>>();
        let rle = rle_encode_lengths(&lens);
        // Trailing zeros stripped.
        assert_eq!(rle.last().unwrap().sym, 3);
    }

    fn kraft_sum(lens: &[u8]) -> u64 {
        let mut s = 0u64;
        for &l in lens {
            if l > 0 {
                s += 32768u64 >> (l as u32);
            }
        }
        s
    }

    #[test]
    fn huffman_three_equal_symbols_balances() {
        // 3 symbols, equal frequency → tree should still be Kraft-balanced.
        let freqs = vec![3u32, 3, 3];
        let lens = length_limited_huffman(&freqs, 15);
        assert_eq!(kraft_sum(&lens), 32768, "lens {:?}", lens);
    }

    #[test]
    fn huffman_four_equal_symbols_balances() {
        let freqs = vec![1u32, 1, 1, 1];
        let lens = length_limited_huffman(&freqs, 15);
        assert_eq!(kraft_sum(&lens), 32768, "lens {:?}", lens);
    }

    #[test]
    fn huffman_skewed_balances() {
        let mut freqs = vec![0u32; 256];
        freqs[0] = 1000;
        freqs[1] = 100;
        freqs[200] = 50;
        freqs[201] = 25;
        let lens = length_limited_huffman(&freqs, 15);
        assert_eq!(
            kraft_sum(&lens),
            32768,
            "lens with kraft={}",
            kraft_sum(&lens)
        );
    }
}
