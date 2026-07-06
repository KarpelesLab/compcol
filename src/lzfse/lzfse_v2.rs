//! LZFSE v2 (`bvx2`) block decoder.
//!
//! ## Status in this build
//!
//! **`bvx2` blocks are now decoded.** This is the core LZFSE block type
//! (LZ77 literal/match commands entropy-coded with Finite State Entropy),
//! so the `lzfse` decoder handles real compressed payloads here rather than
//! only the `bvx-` (uncompressed) and `bvxn` (LZVN) block kinds.
//!
//! ## Validation & interop caveat
//!
//! There is **no Apple `lzfse` reference tool and no captured `bvx2`
//! fixtures available in this build environment**, so correctness is gated
//! by **round-trip against this crate's own spec-conformant v2 encoder**
//! ([`encode_block`], `#[cfg(test)]`): we assert `decode(encode(x)) == x`
//! over empty / small / text / repetitive / random / multi-block inputs,
//! including inputs large enough to force a genuine FSE-coded block. The
//! encoder builds FSE frequency tables from the L/M/D/LIT histograms with the
//! standard quantized (nearest) normalization — producing **general,
//! non-power-of-two frequencies** — FSE-encodes the interleaved literal and
//! LMD streams in reverse, and packs the v2 header exactly per the documented
//! wire layout. Round-trip tests deliberately include skewed, non-dyadic
//! literal distributions and small (singleton) match-count histograms, plus
//! one hand-frozen non-dyadic block decoded independently of the encoder, so
//! a regression to a single bit-width per symbol would fail.
//!
//! The FSE table construction ([`super::fse`]) now matches Apple's general
//! `fse_init_decoder_table` (the **k/k-1 split**: a symbol's `f` spread slots
//! are partitioned into a `k`-bit prefix and a `(k-1)`-bit suffix at the
//! boundary `j0 = (2·n_states >> k) − f`), so arbitrary per-symbol
//! frequencies are handled — not just power-of-two normalizations. The table
//! *size* is always `2^L`; only the per-symbol frequencies are general.
//!
//! Interop with Apple-produced `bvx2` is therefore **best-effort but follows
//! the real table-construction algorithm**: the decoder mirrors the
//! documented format precisely (the same header layout, the same L/M/D
//! base/extra-bit tables, the same frequency-table encoding, the same reverse
//! FSE bit convention, and now the same general FSE table construction). It
//! has still not been cross-checked against an actual Apple-produced stream
//! in this environment, so full Apple-stream interop remains unverified here.
//!
//! ## Wire format reference (v2 header, authoritative)
//!
//! After the 4-byte `bvx2` magic the v2 header is (little-endian,
//! `__packed__`):
//!
//! - `n_raw_bytes: u32` — decoded output size of this block.
//! - `packed_fields[0]: u64`
//!   - `[0..20)`  `n_literals`
//!   - `[20..40)` `n_literal_payload_bytes`
//!   - `[40..60)` `n_matches`
//!   - `[60..63)` `literal_bits` (FSE final-byte stub width for the literal
//!     stream)
//! - `packed_fields[1]: u64`
//!   - `[0..10)`  `literal_state[0]`
//!   - `[10..20)` `literal_state[1]`
//!   - `[20..30)` `literal_state[2]`
//!   - `[30..40)` `literal_state[3]`
//!   - `[40..60)` `n_lmd_payload_bytes`
//!   - `[60..63)` `lmd_bits` (FSE stub width for the LMD stream)
//! - `packed_fields[2]: u64`
//!   - `[0..32)`  `header_size` (bytes, magic..end of freq tables)
//!   - `[32..42)` `l_state`
//!   - `[42..52)` `m_state`
//!   - `[52..62)` `d_state`
//! - then the variable-length frequency tables, bit-contiguous, in order
//!   **L (20 syms), M (20 syms), D (64 syms), LIT (256 syms)**, each packed
//!   with the LZFSE Huffman-style fixed encoding
//!   ([`super::fse::decode_freq_table`]).
//!
//! The two payload streams follow the header: `n_literal_payload_bytes` of
//! literal FSE stream, then `n_lmd_payload_bytes` of LMD FSE stream. Both are
//! decoded **in reverse** (the FSE encoder is LIFO, so the decoder pulls
//! bytes from the end of each stream toward its start).

use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;
use crate::lzfse::bits::FseBits;
use crate::lzfse::fse;

/// Size of the fixed-width portion of the v2 header **after the 4-byte
/// magic**: `n_raw_bytes`(4) + three packed `u64` words (24) = 28 bytes. The
/// variable-length frequency tables follow it. (Apple's `header_size` field
/// additionally counts the 4-byte magic, so `header_size == 4 +
/// V2_HEADER_FIXED_BYTES + freq_table_bytes`.)
pub(crate) const V2_HEADER_FIXED_BYTES: usize = 28;

/// Number of symbols in each stream's alphabet.
const N_L_SYMBOLS: usize = 20;
const N_M_SYMBOLS: usize = 20;
const N_D_SYMBOLS: usize = 64;
const N_LIT_SYMBOLS: usize = 256;

/// FSE state counts (table sizes) for each stream. Fixed by the LZFSE format.
const L_STATES: usize = 64;
const M_STATES: usize = 64;
const D_STATES: usize = 256;
const LIT_STATES: usize = 1024;

/// L/M/D extra-bit widths and base values (Apple's `lzfse_internal.h`).
const L_EXTRA_BITS: [u8; N_L_SYMBOLS] =
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3, 5, 8];
const L_BASE: [i32; N_L_SYMBOLS] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 20, 28, 60,
];
const M_EXTRA_BITS: [u8; N_M_SYMBOLS] =
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 5, 8, 11];
const M_BASE: [i32; N_M_SYMBOLS] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 24, 56, 312,
];
const D_EXTRA_BITS: [u8; N_D_SYMBOLS] = [
    0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 6, 6, 6, 6, 7, 7, 7, 7,
    8, 8, 8, 8, 9, 9, 9, 9, 10, 10, 10, 10, 11, 11, 11, 11, 12, 12, 12, 12, 13, 13, 13, 13, 14, 14,
    14, 14, 15, 15, 15, 15,
];
const D_BASE: [i32; N_D_SYMBOLS] = [
    0, 1, 2, 3, 4, 6, 8, 10, 12, 16, 20, 24, 28, 36, 44, 52, 60, 76, 92, 108, 124, 156, 188, 220,
    252, 316, 380, 444, 508, 636, 764, 892, 1020, 1276, 1532, 1788, 2044, 2556, 3068, 3580, 4092,
    5116, 6140, 7164, 8188, 10236, 12284, 14332, 16380, 20476, 24572, 28668, 32764, 40956, 49148,
    57340, 65532, 81916, 98300, 114684, 131068, 163836, 196604, 229372,
];

/// Parsed v2 header.
struct V2Header {
    n_raw_bytes: u32,
    n_literals: u32,
    n_literal_payload_bytes: u32,
    n_matches: u32,
    literal_bits: u32,
    literal_state: [u32; 4],
    n_lmd_payload_bytes: u32,
    lmd_bits: u32,
    header_size: u32,
    l_state: u32,
    m_state: u32,
    d_state: u32,
    l_freq: Vec<u16>,
    m_freq: Vec<u16>,
    d_freq: Vec<u16>,
    lit_freq: Vec<u16>,
}

/// Extract `width` bits starting at `lo` from a 64-bit packed word.
#[inline]
fn bits64(word: u64, lo: u32, width: u32) -> u64 {
    if width == 0 {
        return 0;
    }
    let mask = if width == 64 {
        u64::MAX
    } else {
        (1u64 << width) - 1
    };
    (word >> lo) & mask
}

/// Total payload size (literal + LMD) declared by a v2 block header. Used by
/// the streaming decoder to know how many payload bytes to buffer. `bytes`
/// is the slice starting **after** the 4-byte magic.
pub(crate) fn parse_payload_size(bytes: &[u8]) -> Result<u32, Error> {
    if bytes.len() < V2_HEADER_FIXED_BYTES {
        return Err(Error::UnexpectedEnd);
    }
    let w0 = u64::from_le_bytes([
        bytes[4], bytes[5], bytes[6], bytes[7], bytes[8], bytes[9], bytes[10], bytes[11],
    ]);
    let w1 = u64::from_le_bytes([
        bytes[12], bytes[13], bytes[14], bytes[15], bytes[16], bytes[17], bytes[18], bytes[19],
    ]);
    let n_literal_payload_bytes = bits64(w0, 20, 20) as u32;
    let n_lmd_payload_bytes = bits64(w1, 40, 20) as u32;
    n_literal_payload_bytes
        .checked_add(n_lmd_payload_bytes)
        .ok_or(Error::Corrupt)
}

/// Total header length (including magic) declared by a v2 block header.
/// `bytes` starts after the magic.
pub(crate) fn parse_header_size(bytes: &[u8]) -> Result<u32, Error> {
    if bytes.len() < V2_HEADER_FIXED_BYTES {
        return Err(Error::UnexpectedEnd);
    }
    let w2 = u64::from_le_bytes([
        bytes[20], bytes[21], bytes[22], bytes[23], bytes[24], bytes[25], bytes[26], bytes[27],
    ]);
    Ok(bits64(w2, 0, 32) as u32)
}

/// Parse the v2 header from `bytes`, which begins **just after** the 4-byte
/// magic.
fn parse_header(bytes: &[u8]) -> Result<V2Header, Error> {
    // The fixed post-magic header is n_raw(4) + three u64 packed words (24) =
    // 28 bytes = V2_HEADER_FIXED_BYTES; the frequency tables follow it.
    let fixed = V2_HEADER_FIXED_BYTES;
    if bytes.len() < fixed {
        return Err(Error::UnexpectedEnd);
    }
    let n_raw_bytes = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let w0 = u64::from_le_bytes([
        bytes[4], bytes[5], bytes[6], bytes[7], bytes[8], bytes[9], bytes[10], bytes[11],
    ]);
    let w1 = u64::from_le_bytes([
        bytes[12], bytes[13], bytes[14], bytes[15], bytes[16], bytes[17], bytes[18], bytes[19],
    ]);
    let w2 = u64::from_le_bytes([
        bytes[20], bytes[21], bytes[22], bytes[23], bytes[24], bytes[25], bytes[26], bytes[27],
    ]);

    let n_literals = bits64(w0, 0, 20) as u32;
    let n_literal_payload_bytes = bits64(w0, 20, 20) as u32;
    let n_matches = bits64(w0, 40, 20) as u32;
    let literal_bits = bits64(w0, 60, 3) as u32;

    let literal_state = [
        bits64(w1, 0, 10) as u32,
        bits64(w1, 10, 10) as u32,
        bits64(w1, 20, 10) as u32,
        bits64(w1, 30, 10) as u32,
    ];
    let n_lmd_payload_bytes = bits64(w1, 40, 20) as u32;
    let lmd_bits = bits64(w1, 60, 3) as u32;

    let header_size = bits64(w2, 0, 32) as u32;
    let l_state = bits64(w2, 32, 10) as u32;
    let m_state = bits64(w2, 42, 10) as u32;
    let d_state = bits64(w2, 52, 10) as u32;

    if literal_bits > 7 || lmd_bits > 7 {
        return Err(Error::Corrupt);
    }

    // `header_size` includes the 4-byte magic, so the minimum valid value is
    // magic(4) + the fixed packed fields.
    if (header_size as usize) < 4 + V2_HEADER_FIXED_BYTES {
        return Err(Error::Corrupt);
    }
    let freq_end = (header_size as usize) - 4; // post-magic offset
    if freq_end < fixed || freq_end > bytes.len() {
        return Err(Error::UnexpectedEnd);
    }
    let freq_bytes = &bytes[fixed..freq_end];

    let (l_freq, m_freq, d_freq, lit_freq) = decode_all_freqs(freq_bytes)?;

    check_freq_sum(&l_freq, L_STATES)?;
    check_freq_sum(&m_freq, M_STATES)?;
    check_freq_sum(&d_freq, D_STATES)?;
    check_freq_sum(&lit_freq, LIT_STATES)?;

    if literal_state.iter().any(|&s| s as usize >= LIT_STATES)
        || l_state as usize >= L_STATES
        || m_state as usize >= M_STATES
        || d_state as usize >= D_STATES
    {
        return Err(Error::Corrupt);
    }

    Ok(V2Header {
        n_raw_bytes,
        n_literals,
        n_literal_payload_bytes,
        n_matches,
        literal_bits,
        literal_state,
        n_lmd_payload_bytes,
        lmd_bits,
        header_size,
        l_state,
        m_state,
        d_state,
        l_freq,
        m_freq,
        d_freq,
        lit_freq,
    })
}

fn check_freq_sum(freq: &[u16], states: usize) -> Result<(), Error> {
    let mut sum = 0usize;
    for &f in freq {
        sum += f as usize;
    }
    if sum != states {
        return Err(Error::Corrupt);
    }
    Ok(())
}

/// The four frequency tables (L, M, D, LIT) decoded from a v2 header.
type FreqTables = (Vec<u16>, Vec<u16>, Vec<u16>, Vec<u16>);

/// Decode the four bit-contiguous frequency tables (L, M, D, LIT).
fn decode_all_freqs(freq_bytes: &[u8]) -> Result<FreqTables, Error> {
    let mut bit_pos = 0usize;
    let l = decode_freq_at(freq_bytes, &mut bit_pos, N_L_SYMBOLS)?;
    let m = decode_freq_at(freq_bytes, &mut bit_pos, N_M_SYMBOLS)?;
    let d = decode_freq_at(freq_bytes, &mut bit_pos, N_D_SYMBOLS)?;
    let lit = decode_freq_at(freq_bytes, &mut bit_pos, N_LIT_SYMBOLS)?;
    Ok((l, m, d, lit))
}

/// Decode one frequency table at bit offset `*bit_pos`, advancing it.
///
/// [`fse::decode_freq_table`] reads LSB-first from bit 0 of the slice it is
/// given. Our tables are bit-packed back-to-back, so a table may begin
/// mid-byte; we shift a temporary view so it starts at bit 0.
fn decode_freq_at(
    freq_bytes: &[u8],
    bit_pos: &mut usize,
    n_symbols: usize,
) -> Result<Vec<u16>, Error> {
    let byte_off = *bit_pos / 8;
    let in_byte = (*bit_pos % 8) as u32;
    if byte_off > freq_bytes.len() {
        return Err(Error::UnexpectedEnd);
    }
    let tail = &freq_bytes[byte_off..];
    if in_byte == 0 {
        let (freqs, consumed_bits) = fse::decode_freq_table(tail, n_symbols)?;
        *bit_pos += consumed_bits;
        Ok(freqs)
    } else {
        // Shift `tail` right by `in_byte` bits so the table begins at bit 0.
        let mut shifted = Vec::with_capacity(tail.len());
        for w in 0..tail.len() {
            let lo = tail[w] >> in_byte;
            let hi = if w + 1 < tail.len() {
                tail[w + 1].checked_shl(8 - in_byte).unwrap_or(0)
            } else {
                0
            };
            shifted.push(lo | hi);
        }
        let (freqs, consumed_bits) = fse::decode_freq_table(&shifted, n_symbols)?;
        *bit_pos += consumed_bits;
        Ok(freqs)
    }
}

/// Decode a full `bvx2` block. `block` is the slice **after** the 4-byte
/// magic and must contain at least `header_size - 4 + payload` bytes.
/// Decoded output is appended to `out`. Returns the number of bytes consumed
/// from `block` (header + payload).
///
/// `out_cap_hint` bounds the up-front output reservation against a hostile
/// `n_raw_bytes`; the real `n_raw_bytes` bound is still enforced exactly.
pub(crate) fn decode_block(
    block: &[u8],
    out: &mut Vec<u8>,
    out_cap_hint: usize,
) -> Result<usize, Error> {
    let hdr = parse_header(block)?;

    let header_len = (hdr.header_size as usize) - 4; // post-magic
    let lit_payload_len = hdr.n_literal_payload_bytes as usize;
    let lmd_payload_len = hdr.n_lmd_payload_bytes as usize;
    let payload_len = lit_payload_len
        .checked_add(lmd_payload_len)
        .ok_or(Error::Corrupt)?;
    let total = header_len.checked_add(payload_len).ok_or(Error::Corrupt)?;
    if block.len() < total {
        return Err(Error::UnexpectedEnd);
    }

    let lit_payload = &block[header_len..header_len + lit_payload_len];
    let lmd_payload = &block[header_len + lit_payload_len..total];

    // ── 1. Decode literals (4-way interleaved FSE, reverse stream) ──
    let lit_table = fse::build_literal_decoder(&hdr.lit_freq, LIT_STATES)?;
    let n_literals = hdr.n_literals as usize;
    // Reject an absurd literal count up-front (DoS guard).
    if n_literals > out_cap_hint.saturating_mul(16).saturating_add(1 << 20) {
        return Err(Error::Corrupt);
    }
    let mut literals = vec![0u8; n_literals];
    {
        let mut bits = FseBits::new_with_stub(lit_payload, hdr.literal_bits)?;
        let mut states = hdr.literal_state;
        let mut i = 0usize;
        while i < n_literals {
            for state in states.iter_mut() {
                if i >= n_literals {
                    break;
                }
                let (sym, next) = fse::fse_decode_literal(*state, &lit_table, &mut bits)?;
                literals[i] = sym;
                *state = next;
                i += 1;
            }
        }
    }

    // ── 2 & 3. Decode L/M/D commands and execute the LZ ──
    let l_table = fse::build_lmd_decoder(&hdr.l_freq, L_STATES, &L_EXTRA_BITS, &L_BASE)?;
    let m_table = fse::build_lmd_decoder(&hdr.m_freq, M_STATES, &M_EXTRA_BITS, &M_BASE)?;
    let d_table = fse::build_lmd_decoder(&hdr.d_freq, D_STATES, &D_EXTRA_BITS, &D_BASE)?;

    let n_raw = hdr.n_raw_bytes as usize;
    let start_len = out.len();
    out.reserve(n_raw.min(out_cap_hint));

    let mut lmd = FseBits::new_with_stub(lmd_payload, hdr.lmd_bits)?;
    let mut l_state = hdr.l_state;
    let mut m_state = hdr.m_state;
    let mut d_state = hdr.d_state;

    let mut lit_pos = 0usize;
    let mut prev_d: i32 = 0;
    let n_matches = hdr.n_matches as usize;

    for _ in 0..n_matches {
        // The encoder pushed streams so the decoder pulls L, then M, then D.
        let (l_val, l_next) = fse::fse_decode_lmd(l_state, &l_table, &mut lmd)?;
        let (m_val, m_next) = fse::fse_decode_lmd(m_state, &m_table, &mut lmd)?;
        let (d_val, d_next) = fse::fse_decode_lmd(d_state, &d_table, &mut lmd)?;
        l_state = l_next;
        m_state = m_next;
        d_state = d_next;

        // D == 0 means "reuse the previous distance".
        let d = if d_val == 0 { prev_d } else { d_val };
        if d_val != 0 {
            prev_d = d_val;
        }
        if l_val < 0 || m_val < 0 || d <= 0 {
            return Err(Error::Corrupt);
        }
        let l = l_val as usize;
        let m = m_val as usize;
        let d = d as usize;

        // Emit L literals.
        if lit_pos + l > n_literals {
            return Err(Error::Corrupt);
        }
        if out.len() + l > start_len + n_raw {
            return Err(Error::Corrupt);
        }
        out.extend_from_slice(&literals[lit_pos..lit_pos + l]);
        lit_pos += l;

        // Copy an M-byte match at distance d (may overlap).
        let cur = out.len() - start_len;
        if d > cur {
            return Err(Error::Corrupt);
        }
        if out.len() + m > start_len + n_raw {
            return Err(Error::Corrupt);
        }
        // Vectorized match copy. The two guards above already bound-check the
        // whole copy. `d == 1` is a byte-splat; otherwise copy in growing
        // chunks: a non-overlapping match (d >= m) collapses to one memcpy, and
        // a self-overlapping one (1 < d < m) runs in O(log(m/d)) memcpys — each
        // chunk `out[src..src+n]` is fully materialized before it is copied, so
        // the emitted bytes are identical to the scalar push loop.
        let src_pos = out.len() - d;
        if d == 1 {
            let b = out[src_pos];
            out.resize(out.len() + m, b);
        } else {
            let mut remaining = m;
            let mut src = src_pos;
            while remaining > 0 {
                let avail = out.len() - src;
                let n = remaining.min(avail);
                out.extend_from_within(src..src + n);
                src += n;
                remaining -= n;
            }
        }
    }

    // Trailing literals after the last match.
    let remaining = n_literals - lit_pos;
    if remaining > 0 {
        if out.len() + remaining > start_len + n_raw {
            return Err(Error::Corrupt);
        }
        out.extend_from_slice(&literals[lit_pos..]);
    }

    if out.len() - start_len != n_raw {
        return Err(Error::Corrupt);
    }

    Ok(total)
}

// ───────────────────────── test-only encoder ─────────────────────────────
//
// A spec-conformant `bvx2` encoder used only to validate the decoder by
// round-trip. It uses a greedy LZ parser, the standard quantized (nearest)
// FSE frequency normalization producing general, non-power-of-two
// frequencies, encode slots that exactly invert the decoder's general k/k-1
// FSE table, and the documented header/payload packing.

#[cfg(test)]
pub(crate) use test_encoder::encode_block;

#[cfg(test)]
mod test_encoder {
    use super::*;

    /// One FSE encode slot for a symbol: covers next-state range `[lo, hi]`,
    /// emits `(next_state - lo)` in `k` bits and moves the encoder's running
    /// state to table index `t`.
    struct EncSlot {
        t: usize,
        k: u8,
        lo: i32,
        hi: i32,
    }

    /// Build per-symbol encode slots that exactly invert
    /// `fse::build_literal_decoder` / `build_lmd_decoder`, including the
    /// general k/k-1 split. Frequencies are arbitrary (`1..=n_states`) and
    /// must sum to `n_states`; the per-symbol slot set tiles `[0, n_states)`.
    ///
    /// Each decode entry maps a current state `t` to a `(next_state, k_bits)`
    /// pull. The encoder inverts this: given the *next* state `cur` it finds
    /// the slot whose `[lo, hi]` next-state range contains `cur`, emits
    /// `cur - lo` in `k` bits and moves the running state to that slot's `t`.
    /// A slot in the `i < j0` region uses `k` bits, otherwise `k - 1` bits —
    /// matching the decode table exactly.
    fn build_enc_slots(freq: &[u16], n_states: usize) -> Vec<Vec<EncSlot>> {
        let mut slots: Vec<Vec<EncSlot>> = (0..freq.len()).map(|_| Vec::new()).collect();
        let mut occ = vec![false; n_states];
        let mut t = 0usize;
        let step = (n_states >> 1) + (n_states >> 3) + 3;
        let mask = n_states - 1;
        let log2 = n_states.trailing_zeros() as i32;
        for (s, &f) in freq.iter().enumerate() {
            let f = f as usize;
            if f == 0 {
                continue;
            }
            let floor_log2 = 31 - (f as u32).leading_zeros() as i32;
            let k = log2 - floor_log2;
            let j0 = (((2 * n_states) >> k) as i32) - f as i32;
            for i in 0..f {
                while occ[t] {
                    t = (t + step) & mask;
                }
                let (ek, delta) = if (i as i32) < j0 {
                    (k, ((f as i32 + i as i32) << k) - n_states as i32)
                } else {
                    (k - 1, (i as i32 - j0) << (k - 1))
                };
                slots[s].push(EncSlot {
                    t,
                    k: ek as u8,
                    lo: delta,
                    hi: delta + (1i32 << ek) - 1,
                });
                occ[t] = true;
                t = (t + step) & mask;
            }
        }
        for sl in slots.iter_mut() {
            sl.sort_by_key(|x| x.lo);
        }
        slots
    }

    /// A bit accumulator producing the reverse FSE stream byte layout that
    /// [`FseBits`] consumes.
    ///
    /// The FSE encoder must walk symbols **in reverse** to chain states
    /// correctly (each symbol's emitted state is determined by the following
    /// symbol in the same lane). The caller therefore [`push`](Self::push)es
    /// `(value, n_bits)` chunks in reverse-of-pull order. [`finish`] reverses
    /// the chunk list back to forward pull order, then packs the resulting
    /// bit string into bytes laid out so [`FseBits`] (which pulls from the end
    /// of the payload backward) reads them back in exactly pull order. One
    /// stub byte always trails so the decoder's init-byte consumption lands on
    /// it.
    struct FseSink {
        /// Each entry is one symbol's `(value, n_bits)`, recorded in
        /// reverse-of-pull order.
        chunks: Vec<(u64, u8)>,
    }

    impl FseSink {
        fn new() -> Self {
            Self { chunks: Vec::new() }
        }

        /// Record `n` bits of `value` for one symbol (reverse-of-pull order).
        fn push(&mut self, value: u64, n: u8) {
            self.chunks.push((value, n));
        }

        /// Serialize to `(payload_bytes, stub_bits)`.
        fn finish(&self) -> (Vec<u8>, u32) {
            // Reverse chunks to forward pull order, then flatten to a bit
            // vector (LSB-first within each chunk).
            let mut bits: Vec<u8> = Vec::new();
            for &(value, n) in self.chunks.iter().rev() {
                for i in 0..n {
                    bits.push(((value >> i) & 1) as u8);
                }
            }
            let total = bits.len();
            let stub = (total % 8) as u32;
            let full = total / 8;
            let plen = full + 1;
            let mut payload = vec![0u8; plen];
            let mut bi = 0usize;
            let mut sb = 0u8;
            for i in 0..stub {
                sb |= bits[bi] << i;
                bi += 1;
            }
            payload[plen - 1] = sb;
            let mut idx = plen as i32 - 2;
            while idx >= 0 {
                let mut b = 0u8;
                for i in 0..8 {
                    if bi < total {
                        b |= bits[bi] << i;
                        bi += 1;
                    }
                }
                payload[idx as usize] = b;
                idx -= 1;
            }
            (payload, stub)
        }
    }

    /// Encode a frequency value with the LZFSE Huffman-style fixed encoding
    /// (inverse of `fse::decode_freq_table`).
    fn encode_freq_value(v: u16) -> (u32, u32) {
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
            24..=1047 => (0b1111 | ((v as u32 - 24) << 4), 14),
            _ => panic!("frequency {v} too large to encode"),
        }
    }

    /// Normalize a histogram to **general** (arbitrary, not power-of-two)
    /// frequencies summing exactly to `n_states`, giving every present symbol
    /// at least 1. This is the standard quantized normalization: scale each
    /// count by `n_states / total`, round to nearest, force present symbols to
    /// 1, then correct the running sum by nudging the largest entry (which can
    /// absorb ±1 changes without dropping a present symbol to 0).
    ///
    /// The resulting per-symbol frequencies are deliberately *not* coerced to
    /// powers of two — the decoder's general k/k-1 table builder handles them
    /// directly. Singletons and skewed (non-dyadic) distributions are
    /// produced as-is so the round-trip exercises the general FSE path.
    pub(super) fn normalize_general(hist: &[u32], n_states: usize) -> Vec<u16> {
        let n = hist.len();
        let total: u64 = hist.iter().map(|&h| h as u64).sum();
        let mut freq = vec![0u16; n];
        if total == 0 {
            freq[0] = n_states as u16;
            return freq;
        }
        // Nearest-rounding scale, with a floor of 1 for every present symbol.
        let mut assigned: i64 = 0;
        for (i, &h) in hist.iter().enumerate() {
            if h == 0 {
                continue;
            }
            let scaled = (h as u64 * n_states as u64 + total / 2) / total;
            let f = scaled.max(1).min(n_states as u64) as i64;
            freq[i] = f as u16;
            assigned += f;
        }
        let target = n_states as i64;
        // Correct the sum. Each step adjusts the symbol that can absorb the
        // change: when overshooting, the largest entry with `f > 1`; when
        // undershooting, simply the largest entry. This converges because the
        // largest entry is at least `n_states / n` which exceeds the total
        // correction magnitude (bounded by `n`).
        while assigned != target {
            if assigned > target {
                let (idx, _) = freq
                    .iter()
                    .enumerate()
                    .filter(|&(_, &f)| f > 1)
                    .max_by_key(|&(_, &f)| f)
                    .expect("an entry > 1 exists while overshooting");
                freq[idx] -= 1;
                assigned -= 1;
            } else {
                let (idx, _) = freq
                    .iter()
                    .enumerate()
                    .max_by_key(|&(_, &f)| f)
                    .expect("non-empty alphabet");
                freq[idx] += 1;
                assigned += 1;
            }
        }
        debug_assert_eq!(assigned, target);
        freq
    }

    /// Map an L/M/D value to `(symbol, extra_value)`.
    fn map_lmd(value: i32, base: &[i32], extra: &[u8]) -> (usize, u32) {
        for s in 0..base.len() {
            if base[s] <= value {
                let hi = base[s] + ((1i64 << extra[s]) - 1) as i32;
                if value <= hi {
                    return (s, (value - base[s]) as u32);
                }
            }
        }
        let s = base.len() - 1;
        (s, (value - base[s]).max(0) as u32)
    }

    struct Cmd {
        l: usize,
        m: usize,
        d: usize,
    }

    /// Greedy LZ parse of `data` via a hash chain over 4-byte prefixes.
    fn lz_parse(data: &[u8]) -> (Vec<u8>, Vec<Cmd>) {
        const MIN_MATCH: usize = 4;
        const MAX_MATCH: usize = 2359; // M max encodable
        const MAX_DIST: usize = 262_139; // D max encodable
        let mut literals = Vec::new();
        let mut cmds = Vec::new();
        let n = data.len();

        let hsize = 1usize << 15;
        let mut head = vec![usize::MAX; hsize];
        let mut prev = vec![usize::MAX; n.max(1)];
        let hash = |d: &[u8], i: usize| -> usize {
            let v = (d[i] as usize)
                | ((d[i + 1] as usize) << 8)
                | ((d[i + 2] as usize) << 16)
                | ((d[i + 3] as usize) << 24);
            (v.wrapping_mul(2654435761) >> 17) & (hsize - 1)
        };

        let mut i = 0usize;
        let mut pending_lit = 0usize;
        while i < n {
            let mut best_len = 0usize;
            let mut best_dist = 0usize;
            if i + MIN_MATCH <= n {
                let h = hash(data, i);
                let mut cand = head[h];
                let mut chain = 0;
                while cand != usize::MAX && chain < 64 {
                    if i - cand <= MAX_DIST {
                        let mut len = 0usize;
                        while i + len < n && len < MAX_MATCH && data[cand + len] == data[i + len] {
                            len += 1;
                        }
                        if len > best_len {
                            best_len = len;
                            best_dist = i - cand;
                        }
                    } else {
                        break;
                    }
                    cand = prev[cand];
                    chain += 1;
                }
            }

            if best_len >= MIN_MATCH {
                let end = i + best_len;
                cmds.push(Cmd {
                    l: pending_lit,
                    m: best_len,
                    d: best_dist,
                });
                pending_lit = 0;
                while i < end {
                    if i + MIN_MATCH <= n {
                        let h = hash(data, i);
                        prev[i] = head[h];
                        head[h] = i;
                    }
                    i += 1;
                }
            } else {
                literals.push(data[i]);
                pending_lit += 1;
                if i + MIN_MATCH <= n {
                    let h = hash(data, i);
                    prev[i] = head[h];
                    head[h] = i;
                }
                i += 1;
            }
        }
        // Remaining `pending_lit` literals are trailing literals (no command);
        // the decoder appends them after the last match.
        let _ = pending_lit;
        (literals, cmds)
    }

    /// Encode `data` as a single `bvx2` block (NOT including the 4-byte
    /// magic, which the caller prepends).
    pub(crate) fn encode_block(data: &[u8]) -> Vec<u8> {
        let (literals, cmds) = lz_parse(data);

        let mut lit_hist = vec![0u32; N_LIT_SYMBOLS];
        for &b in &literals {
            lit_hist[b as usize] += 1;
        }
        let mut l_hist = vec![0u32; N_L_SYMBOLS];
        let mut m_hist = vec![0u32; N_M_SYMBOLS];
        let mut d_hist = vec![0u32; N_D_SYMBOLS];

        struct MappedCmd {
            l_sym: usize,
            l_extra: u32,
            m_sym: usize,
            m_extra: u32,
            d_sym: usize,
            d_extra: u32,
        }
        let mut mapped = Vec::with_capacity(cmds.len());
        for c in &cmds {
            let (l_sym, l_extra) = map_lmd(c.l as i32, &L_BASE, &L_EXTRA_BITS);
            let (m_sym, m_extra) = map_lmd(c.m as i32, &M_BASE, &M_EXTRA_BITS);
            let (d_sym, d_extra) = map_lmd(c.d as i32, &D_BASE, &D_EXTRA_BITS);
            l_hist[l_sym] += 1;
            m_hist[m_sym] += 1;
            d_hist[d_sym] += 1;
            mapped.push(MappedCmd {
                l_sym,
                l_extra,
                m_sym,
                m_extra,
                d_sym,
                d_extra,
            });
        }

        let lit_freq = normalize_general(&lit_hist, LIT_STATES);
        let l_freq = normalize_general(&l_hist, L_STATES);
        let m_freq = normalize_general(&m_hist, M_STATES);
        let d_freq = normalize_general(&d_hist, D_STATES);

        let lit_slots = build_enc_slots(&lit_freq, LIT_STATES);
        let l_slots = build_enc_slots(&l_freq, L_STATES);
        let m_slots = build_enc_slots(&m_freq, M_STATES);
        let d_slots = build_enc_slots(&d_freq, D_STATES);

        // ── Encode literals (reverse, 4-way interleaved) ──
        let n_lit = literals.len();
        let mut lit_sink = FseSink::new();
        let mut lit_states = [0i32; 4];
        for idx in (0..n_lit).rev() {
            let lane = idx % 4;
            let sym = literals[idx] as usize;
            let cur = lit_states[lane];
            let slot = lit_slots[sym]
                .iter()
                .find(|s| cur >= s.lo && cur <= s.hi)
                .expect("literal slot covers state");
            lit_sink.push((cur - slot.lo) as u64, slot.k);
            lit_states[lane] = slot.t as i32;
        }
        let literal_state = [
            lit_states[0] as u32,
            lit_states[1] as u32,
            lit_states[2] as u32,
            lit_states[3] as u32,
        ];
        let (lit_payload, literal_bits) = lit_sink.finish();

        // ── Encode LMD (reverse). Decoder pulls L, M, D per command, so to
        // invert we iterate commands in reverse and push D, then M, then L. ──
        let mut lmd_sink = FseSink::new();
        let mut l_st = 0i32;
        let mut m_st = 0i32;
        let mut d_st = 0i32;
        for mc in mapped.iter().rev() {
            let d_slot = d_slots[mc.d_sym]
                .iter()
                .find(|s| d_st >= s.lo && d_st <= s.hi)
                .expect("d slot");
            let raw = (d_st - d_slot.lo) as u64 | ((mc.d_extra as u64) << d_slot.k);
            lmd_sink.push(raw, d_slot.k + D_EXTRA_BITS[mc.d_sym]);
            d_st = d_slot.t as i32;

            let m_slot = m_slots[mc.m_sym]
                .iter()
                .find(|s| m_st >= s.lo && m_st <= s.hi)
                .expect("m slot");
            let raw = (m_st - m_slot.lo) as u64 | ((mc.m_extra as u64) << m_slot.k);
            lmd_sink.push(raw, m_slot.k + M_EXTRA_BITS[mc.m_sym]);
            m_st = m_slot.t as i32;

            let l_slot = l_slots[mc.l_sym]
                .iter()
                .find(|s| l_st >= s.lo && l_st <= s.hi)
                .expect("l slot");
            let raw = (l_st - l_slot.lo) as u64 | ((mc.l_extra as u64) << l_slot.k);
            lmd_sink.push(raw, l_slot.k + L_EXTRA_BITS[mc.l_sym]);
            l_st = l_slot.t as i32;
        }
        let l_state = l_st as u32;
        let m_state = m_st as u32;
        let d_state = d_st as u32;
        let (lmd_payload, lmd_bits) = lmd_sink.finish();

        // ── Pack frequency tables (L, M, D, LIT, bit-contiguous) ──
        let mut freq_bits: Vec<u8> = Vec::new();
        for table in [&l_freq, &m_freq, &d_freq, &lit_freq] {
            for &f in table.iter() {
                let (code, len) = encode_freq_value(f);
                for i in 0..len {
                    freq_bits.push(((code >> i) & 1) as u8);
                }
            }
        }
        let mut freq_bytes = vec![0u8; freq_bits.len().div_ceil(8)];
        for (i, &b) in freq_bits.iter().enumerate() {
            freq_bytes[i / 8] |= b << (i % 8);
        }

        // ── Assemble the header ──
        // `header_size` is measured from the start of the block, i.e. it
        // includes the 4-byte magic that the caller prepends:
        //   magic(4) + n_raw(4) + 3*u64(24) + freq = 4 + V2_HEADER_FIXED_BYTES + freq.
        let header_size = (4 + V2_HEADER_FIXED_BYTES + freq_bytes.len()) as u32;
        let n_raw_bytes = data.len() as u32;
        let n_literals = n_lit as u32;
        let n_matches = cmds.len() as u32;
        let n_literal_payload_bytes = lit_payload.len() as u32;
        let n_lmd_payload_bytes = lmd_payload.len() as u32;

        let mut w0 = 0u64;
        w0 |= (n_literals as u64) & 0xFFFFF;
        w0 |= ((n_literal_payload_bytes as u64) & 0xFFFFF) << 20;
        w0 |= ((n_matches as u64) & 0xFFFFF) << 40;
        w0 |= ((literal_bits as u64) & 0x7) << 60;

        let mut w1 = 0u64;
        w1 |= (literal_state[0] as u64) & 0x3FF;
        w1 |= ((literal_state[1] as u64) & 0x3FF) << 10;
        w1 |= ((literal_state[2] as u64) & 0x3FF) << 20;
        w1 |= ((literal_state[3] as u64) & 0x3FF) << 30;
        w1 |= ((n_lmd_payload_bytes as u64) & 0xFFFFF) << 40;
        w1 |= ((lmd_bits as u64) & 0x7) << 60;

        let mut w2 = 0u64;
        w2 |= (header_size as u64) & 0xFFFFFFFF;
        w2 |= ((l_state as u64) & 0x3FF) << 32;
        w2 |= ((m_state as u64) & 0x3FF) << 42;
        w2 |= ((d_state as u64) & 0x3FF) << 52;

        let mut out =
            Vec::with_capacity(header_size as usize + lit_payload.len() + lmd_payload.len());
        out.extend_from_slice(&n_raw_bytes.to_le_bytes());
        out.extend_from_slice(&w0.to_le_bytes());
        out.extend_from_slice(&w1.to_le_bytes());
        out.extend_from_slice(&w2.to_le_bytes());
        out.extend_from_slice(&freq_bytes);
        out.extend_from_slice(&lit_payload);
        out.extend_from_slice(&lmd_payload);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lzfse::decoder::Decoder;
    use crate::traits::{RawDecoder, RawProgress};

    /// Wrap a v2-encoded block (post-magic bytes) into a full `bvx2` block.
    fn v2_block(data: &[u8]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(b"bvx2");
        b.extend_from_slice(&encode_block(data));
        b
    }

    /// Block-level round-trip: encode then `decode_block`.
    fn rt_block(data: &[u8]) {
        let block = encode_block(data);
        let mut out = Vec::new();
        let consumed = decode_block(&block, &mut out, 1 << 20)
            .unwrap_or_else(|e| panic!("decode_block failed on len {}: {e:?}", data.len()));
        assert_eq!(consumed, block.len(), "did not consume whole block");
        assert_eq!(out, data, "round-trip mismatch (len {})", data.len());
    }

    /// Full-stream round-trip through the streaming `Decoder`.
    fn rt_stream(blocks: &[&[u8]]) -> Vec<u8> {
        let mut stream = Vec::new();
        for b in blocks {
            stream.extend_from_slice(&v2_block(b));
        }
        stream.extend_from_slice(b"bvx$");

        let mut dec = Decoder::new();
        let mut out = Vec::new();
        let mut buf = vec![0u8; 512];
        let mut pos = 0usize;
        loop {
            let RawProgress {
                consumed,
                written,
                done,
            } = dec.raw_decode(&stream[pos..], &mut buf).unwrap();
            pos += consumed;
            out.extend_from_slice(&buf[..written]);
            if done {
                break;
            }
            if consumed == 0 && written == 0 {
                // Need to finish.
                let RawProgress { written, done, .. } = dec.raw_finish(&mut buf).unwrap();
                out.extend_from_slice(&buf[..written]);
                if done || written == 0 {
                    break;
                }
            }
        }
        out
    }

    #[test]
    fn block_roundtrip_empty() {
        rt_block(b"");
    }

    #[test]
    fn block_roundtrip_small() {
        rt_block(b"a");
        rt_block(b"ab");
        rt_block(b"abc");
        rt_block(b"hello world");
    }

    #[test]
    fn block_roundtrip_text() {
        let text = b"the quick brown fox jumps over the lazy dog. \
                     the quick brown fox jumps over the lazy dog. \
                     pack my box with five dozen liquor jugs.";
        rt_block(text);
    }

    #[test]
    fn block_roundtrip_repetitive() {
        rt_block(&vec![b'A'; 1000]);
        rt_block(&vec![0u8; 5000]);
        let mut v = Vec::new();
        for _ in 0..500 {
            v.extend_from_slice(b"abcd");
        }
        rt_block(&v);
    }

    #[test]
    fn block_roundtrip_random() {
        // Deterministic LCG "random" bytes (incompressible-ish) of varied sizes.
        let mut state = 0x1234_5678u32;
        let mut next = || {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            (state >> 24) as u8
        };
        for &len in &[
            0usize, 1, 7, 15, 16, 17, 63, 64, 100, 255, 256, 1024, 4096, 9001,
        ] {
            let data: Vec<u8> = (0..len).map(|_| next()).collect();
            rt_block(&data);
        }
    }

    #[test]
    fn block_roundtrip_mixed_structure() {
        // Repetitive prefix + random tail + repetitive again exercises both
        // literal-heavy and match-heavy command streams.
        let mut data = vec![b'x'; 300];
        let mut state = 0x9E37_79B9u32;
        for _ in 0..300 {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            data.push((state >> 23) as u8);
        }
        data.extend_from_slice(&vec![b'y'; 400]);
        data.extend_from_slice(b"the the the the the the the the the the the the");
        rt_block(&data);
    }

    #[test]
    fn block_roundtrip_all_byte_values() {
        // Every byte value present forces a full 256-symbol literal table.
        let mut data = Vec::new();
        for _ in 0..8 {
            for b in 0u16..256 {
                data.push(b as u8);
            }
        }
        rt_block(&data);
    }

    #[test]
    fn block_roundtrip_long_match() {
        // A long run produces large match lengths (exercises M extra bits).
        let data = vec![b'Q'; 50_000];
        rt_block(&data);
    }

    #[test]
    fn block_roundtrip_far_distance() {
        // Distinct head, large gap, then a copy of the head — exercises large
        // D extra bits.
        let mut data: Vec<u8> = b"UNIQUEPREFIXHERE0123456789".to_vec();
        data.extend(core::iter::repeat_n(b'.', 70_000));
        data.extend_from_slice(b"UNIQUEPREFIXHERE0123456789");
        rt_block(&data);
    }

    #[test]
    fn stream_roundtrip_single_block() {
        let data = b"the quick brown fox jumps over the lazy dog".repeat(20);
        let out = rt_stream(&[&data]);
        assert_eq!(out, data);
    }

    #[test]
    fn stream_roundtrip_multi_block() {
        let a = b"first block contents, repeated repeated repeated".repeat(10);
        let b = vec![b'Z'; 2000];
        let c = b"third".repeat(100);
        let out = rt_stream(&[&a, &b, &c]);
        let mut want = Vec::new();
        want.extend_from_slice(&a);
        want.extend_from_slice(&b);
        want.extend_from_slice(&c);
        assert_eq!(out, want);
    }

    #[test]
    fn stream_roundtrip_empty_block() {
        let out = rt_stream(&[b""]);
        assert_eq!(out, b"");
    }

    #[test]
    fn corrupt_header_size_rejected() {
        let mut block = encode_block(b"hello world this is a test of corruption");
        // header_size lives in packed_fields[2] low 32 bits, at byte offset
        // 4 + 8 + 8 = 20 within the post-magic block. Set it absurdly large.
        block[20] = 0xFF;
        block[21] = 0xFF;
        block[22] = 0xFF;
        block[23] = 0xFF;
        let mut out = Vec::new();
        assert!(decode_block(&block, &mut out, 1 << 20).is_err());
    }

    #[test]
    fn truncated_payload_rejected() {
        let block = encode_block(&vec![b'k'; 2000]);
        // Drop the last few payload bytes.
        let truncated = &block[..block.len() - 3];
        let mut out = Vec::new();
        assert!(decode_block(truncated, &mut out, 1 << 20).is_err());
    }

    #[test]
    fn garbage_freq_does_not_panic() {
        // A short, mostly-zero block: parse_header should reject (freq sums
        // won't match) rather than panic.
        let mut block = vec![0u8; 64];
        // Give n_raw a small value and a plausible header_size.
        block[0..4].copy_from_slice(&8u32.to_le_bytes());
        // header_size = 32 (magic + fixed, no freq bytes) — freq tables empty
        // → sums won't match the FSE state counts.
        let w2 = 32u64;
        block[20..28].copy_from_slice(&w2.to_le_bytes());
        let mut out = Vec::new();
        let _ = decode_block(&block, &mut out, 1 << 20);
    }

    #[test]
    fn stream_roundtrip_one_byte_at_a_time() {
        // Feed a v2 block + EOS one byte at a time, exercising the streaming
        // decoder's reassembly of the variable-length v2 header and payload.
        let data = b"streaming reassembly test streaming reassembly test".repeat(8);
        let mut stream = v2_block(&data);
        stream.extend_from_slice(b"bvx$");

        let mut dec = Decoder::new();
        let mut out = Vec::new();
        let mut buf = vec![0u8; 64];
        let mut pos = 0usize;
        while pos < stream.len() {
            let end = (pos + 1).min(stream.len());
            let RawProgress {
                consumed,
                written,
                done,
            } = dec.raw_decode(&stream[pos..end], &mut buf).unwrap();
            pos += consumed;
            out.extend_from_slice(&buf[..written]);
            if done {
                break;
            }
        }
        loop {
            let RawProgress { written, done, .. } = dec.raw_finish(&mut buf).unwrap();
            out.extend_from_slice(&buf[..written]);
            if done || written == 0 {
                break;
            }
        }
        assert_eq!(out, data);
    }

    /// A hand-frozen `bvx2` stream, independent of this crate's encoder.
    ///
    /// It is a literals-only block (`n_matches == 0`) whose **literal
    /// frequency table is deliberately non-dyadic**: the high-frequency
    /// literal symbol `0x3d` (`=`) has frequency 1000 and the rare symbol
    /// `0x3e` (`>`) has 24 (sum 1024 = LIT_STATES). Neither is a power of two,
    /// so decoding correctly *requires* the general k/k-1 FSE table
    /// construction — a single-`k` decoder cannot build a table that tiles
    /// `[0,1024)` for these frequencies and mis-decodes the literals.
    ///
    /// The bytes (post-magic header + freq tables + literal FSE payload, then
    /// the `bvx$` EOS) were generated once and frozen here; this test does not
    /// call the encoder, so it guards against the encoder and decoder sharing
    /// the same table-construction bug. The four literals decode to the exact
    /// ASCII string `=>==`.
    const HAND_VECTOR: &[u8] = &[
        0x62, 0x76, 0x78, 0x32, 0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00,
        0x50, 0x48, 0x40, 0x8f, 0x04, 0x12, 0x00, 0x00, 0x00, 0x82, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x8f, 0x02, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x8f, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0xc0, 0x43, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x62, 0x76, 0x78, 0x24,
    ];

    #[test]
    fn hand_vector_non_dyadic_decodes_to_known_string() {
        // Decode the frozen, encoder-independent vector through the public
        // streaming decoder and assert the exact output.
        let mut dec = Decoder::new();
        let mut out = Vec::new();
        let mut buf = vec![0u8; 64];
        let mut pos = 0usize;
        loop {
            let RawProgress {
                consumed,
                written,
                done,
            } = dec.raw_decode(&HAND_VECTOR[pos..], &mut buf).unwrap();
            pos += consumed;
            out.extend_from_slice(&buf[..written]);
            if done {
                break;
            }
            if consumed == 0 && written == 0 {
                let RawProgress { written, done, .. } = dec.raw_finish(&mut buf).unwrap();
                out.extend_from_slice(&buf[..written]);
                if done || written == 0 {
                    break;
                }
            }
        }
        assert_eq!(out, b"=>==", "hand vector decoded to {out:?}");
    }

    #[test]
    fn normalize_general_produces_non_dyadic_freqs() {
        // A skewed histogram must normalize to general (non-power-of-two)
        // frequencies that sum exactly to n_states and give every present
        // symbol at least 1. A regression that snapped to powers of two would
        // be visible here.
        use super::test_encoder::normalize_general;
        let hist = [1000u32, 3, 17, 250, 0, 1];
        let freq = normalize_general(&hist, 1024);
        assert_eq!(freq.iter().map(|&f| f as u32).sum::<u32>(), 1024);
        // Absent symbol stays 0; present symbols are >= 1.
        assert_eq!(freq[4], 0);
        for (i, &h) in hist.iter().enumerate() {
            if h > 0 {
                assert!(freq[i] >= 1, "present symbol {i} dropped to 0");
            }
        }
        // At least one present symbol is genuinely non-power-of-two.
        assert!(
            freq.iter().any(|&f| f > 0 && !f.is_power_of_two()),
            "expected a non-power-of-two frequency, got {freq:?}"
        );
    }

    /// Round-trip a payload whose literal histogram is deliberately skewed so
    /// the normalized FSE frequencies are non-dyadic. A regression to a
    /// single-`k` decode table would corrupt the result.
    fn rt_assert_non_dyadic_lit(data: &[u8]) {
        use super::test_encoder::normalize_general;
        // Recompute the literal histogram the way encode_block does, but only
        // over true literals would require the parser; instead assert on a
        // raw-byte histogram, which upper-bounds the literal alphabet and is a
        // good proxy for "this input yields a non-dyadic literal table".
        let mut hist = vec![0u32; 256];
        for &b in data {
            hist[b as usize] += 1;
        }
        let freq = normalize_general(&hist, LIT_STATES);
        assert!(
            freq.iter().any(|&f| f > 0 && !f.is_power_of_two()),
            "test input does not exercise a non-dyadic table"
        );
        rt_block(data);
    }

    #[test]
    fn block_roundtrip_non_dyadic_literals() {
        // Skewed-but-not-dyadic byte distributions (counts chosen so the
        // 1024-state normalization lands on non-powers-of-two).
        let mut data = Vec::new();
        data.extend(core::iter::repeat_n(b'a', 1000));
        data.extend(core::iter::repeat_n(b'b', 333));
        data.extend(core::iter::repeat_n(b'c', 77));
        data.extend(core::iter::repeat_n(b'd', 7));
        data.push(b'e'); // a singleton
        rt_assert_non_dyadic_lit(&data);

        // A 3-symbol skew (~70/29/1 split).
        let mut d2 = Vec::new();
        d2.extend(core::iter::repeat_n(b'x', 700));
        d2.extend(core::iter::repeat_n(b'y', 290));
        d2.extend(core::iter::repeat_n(b'z', 11));
        rt_assert_non_dyadic_lit(&d2);
    }

    #[test]
    fn block_roundtrip_small_match_counts() {
        // Few, varied matches produce small non-power-of-two L/M/D histograms
        // (e.g. a single match → a singleton frequency in each LMD table).
        // Each must round-trip through the general k/k-1 LMD tables.
        let cases: &[&[u8]] = &[
            b"abcabc",                         // one short match
            b"abcdeabcde_xyzxyz",              // two matches, different lens
            b"AAAABBBBCCCCAAAABBBBCCCC",       // a couple of medium matches
            b"the cat sat on the mat the cat", // overlapping repeats
        ];
        for c in cases {
            rt_block(c);
        }
    }

    #[test]
    fn fuzz_roundtrip_many_sizes() {
        // Broad deterministic fuzz: many sizes, several content shapes. Each
        // must round-trip exactly through decode_block(encode_block(x)).
        let mut state = 0xDEAD_BEEFu32;
        let mut rng = || {
            state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            state
        };
        for len in 0..400usize {
            // Shape 0: random bytes. Shape 1: small alphabet (matches galore).
            // Shape 2: mostly-constant with sparse noise.
            for shape in 0..3 {
                let data: Vec<u8> = (0..len)
                    .map(|_| match shape {
                        0 => (rng() >> 24) as u8,
                        1 => b"abcde"[(rng() as usize) % 5],
                        _ => {
                            if rng() % 16 == 0 {
                                (rng() >> 24) as u8
                            } else {
                                b'='
                            }
                        }
                    })
                    .collect();
                rt_block(&data);
            }
        }
    }
}
