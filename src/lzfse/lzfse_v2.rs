//! LZFSE v2 (`bvx2`) block decoder and encoder.
//!
//! `bvx2` is the core LZFSE block type: LZ77 literal/match commands
//! entropy-coded with Finite State Entropy. [`decode_block`] decodes one;
//! [`encode_block`] encodes a block from commands chosen by the streaming
//! encoder's parser (`super::encoder`).
//!
//! ## Validation & interop
//!
//! The decoder follows Apple's reference decoder (`lzfse_decode_base.c`,
//! `lzfse_fse.h`): FSE decode tables are filled **contiguously** per symbol
//! with the general k/k-1 split (`fse_init_decoder_table`), the payload
//! bit streams are read most-significant-bit first from the end, an L/M/D
//! field is the state bits followed by the value's extra bits, every output
//! literal is emitted by some command's `L` (the literal stream is padded to
//! a multiple of four), and match distances may reach into earlier blocks.
//!
//! `tests/lzfse.rs` decodes multi-block `bvx2` fixtures produced by an
//! independent encoder (`lzfse_rust`, which is validated against Apple's
//! reference library); `tests/lzfse_encoder.rs` cross-checks this encoder
//! and decoder against `lzfse_rust` and, on macOS, Apple's `libcompression`
//! in both directions. The unit tests below round-trip blocks built from an
//! independent test-only parse over empty / small / text / repetitive /
//! random / multi-block inputs with skewed, non-dyadic frequency tables.
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
//!   - `[60..63)` `literal_bits` (`7 -` the number of unused high bits in
//!     the literal stream's last byte)
//! - `packed_fields[1]: u64`
//!   - `[0..10)`  `literal_state[0]`
//!   - `[10..20)` `literal_state[1]`
//!   - `[20..30)` `literal_state[2]`
//!   - `[30..40)` `literal_state[3]`
//!   - `[40..60)` `n_lmd_payload_bytes`
//!   - `[60..63)` `lmd_bits` (same, for the LMD stream)
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

/// Apple's per-block limits (`LZFSE_MATCHES_PER_BLOCK`, `LZFSE_LITERALS_PER_BLOCK`).
/// Its encoder never exceeds them and its decoder holds a block's literals in
/// a fixed `LZFSE_LITERALS_PER_BLOCK` buffer.
const MATCHES_PER_BLOCK: usize = 10_000;
const LITERALS_PER_BLOCK: usize = 4 * MATCHES_PER_BLOCK;

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
    // A block is decoded whole before any of it is drained, so bound it by
    // Apple's per-block limits: at most ~23.6 MiB of output instead of the
    // ~2.4 GiB the 20-bit `n_matches` field could otherwise claim.
    if n_literals as usize > LITERALS_PER_BLOCK || n_matches as usize > MATCHES_PER_BLOCK {
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
/// Bytes already in `out` are the stream's earlier output: as in Apple's
/// decoder, a match distance may reach back into previous blocks.
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
        // A literal-only command (M == 0, e.g. a block's final one) need not
        // carry a usable distance.
        if l_val < 0 || m_val < 0 || (m_val > 0 && d <= 0) {
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

        // Copy an M-byte match at distance d (may overlap). As in Apple's
        // decoder the distance may reach back into earlier blocks' output,
        // which the caller supplies ahead of `start_len`.
        if m == 0 {
            continue;
        }
        if d > out.len() {
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

    // Every output literal is emitted by some command's L. Apple's encoder
    // pads the literal stream to a multiple of four, so literals left past
    // `lit_pos` are padding, not output.
    if out.len() - start_len != n_raw {
        return Err(Error::Corrupt);
    }

    Ok(total)
}

// ─────────────────────────────── encoder ─────────────────────────────────

/// Largest literal run one command's `L` can carry (`L_BASE[19] + 255`).
pub(crate) const MAX_L_VALUE: u32 = 315;
/// Largest match length one command's `M` can carry (`M_BASE[19] + 2047`).
pub(crate) const MAX_M_VALUE: u32 = 2359;
/// Largest match distance a `D` can carry (`D_BASE[63] + 32767`).
pub(crate) const MAX_D_VALUE: u32 = 262_139;
/// Per-block command limit (Apple's `LZFSE_MATCHES_PER_BLOCK`).
pub(crate) const MAX_MATCHES_PER_BLOCK: usize = MATCHES_PER_BLOCK;
/// Per-block literal limit (Apple's `LZFSE_LITERALS_PER_BLOCK`), counting
/// the up-to-3 padding literals the encoder adds.
pub(crate) const MAX_LITERALS_PER_BLOCK: usize = LITERALS_PER_BLOCK;

/// One LZ77 command: `l` literals, then an `m`-byte match at distance `d`.
///
/// A literal-only command has `m == 0`; its `d` is ignored (the encoder
/// substitutes the previous distance so it costs nothing).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Cmd {
    pub(crate) l: u32,
    pub(crate) m: u32,
    pub(crate) d: u32,
}

/// Map an L/M/D value to `(symbol, extra_bits_value)`. The bases are
/// contiguous (`base[s] + 2^extra[s] == base[s + 1]`), so the symbol is the
/// last base not above `value`.
#[inline]
fn map_lmd(value: u32, base: &[i32]) -> (usize, u32) {
    let s = base.partition_point(|&b| b as u32 <= value) - 1;
    (s, value - base[s] as u32)
}

/// Push one L/M/D field: the FSE state bits (high) followed by the value's
/// `vb` extra bits (low), as the decoder pulls them in one go.
#[inline]
fn push_lmd(
    w: &mut fse::BitWriter,
    state: &mut u32,
    enc: &[fse::FseEncEntry],
    vb: u8,
    sym: u8,
    extra: u32,
) {
    let (bits, nb, next) = fse::fse_encode(&enc[sym as usize], *state);
    w.push((bits << vb) | extra, nb + vb as u32);
    *state = next;
}

/// Encode one `bvx2` block (magic included) for the commands `cmds` whose
/// literals, concatenated, are `literals`, appending it to `out`.
///
/// Every command must satisfy `l <= MAX_L_VALUE`,
/// `m <= MAX_M_VALUE`, `1 <= d <= MAX_D_VALUE` when `m > 0`, and the block
/// must respect the per-block limits (`cmds.len() <= MAX_MATCHES_PER_BLOCK`,
/// `literals.len() + 3 <= MAX_LITERALS_PER_BLOCK`). `n_raw` is the decoded
/// size, `sum(l + m)`.
///
/// Layout choices mirror Apple's `lzfse_encode_matches`, which its decoder
/// (and libcompression's) relies on: the literal stream is padded to a
/// multiple of four literals (the decoder decodes them four at a time), a
/// block's first command always carries an explicit distance (a repeat
/// distance `D = 0` is only used from the second command on), and each FSE
/// payload starts with 8 zero bytes.
pub(crate) fn encode_block(literals: &[u8], cmds: &[Cmd], n_raw: u32, out: &mut Vec<u8>) {
    debug_assert!(cmds.len() <= MATCHES_PER_BLOCK);
    debug_assert!(literals.len() + 3 <= LITERALS_PER_BLOCK);

    // ── Literals, padded to a multiple of 4 by repeating the last one ──
    let mut lits: Vec<u8> = Vec::with_capacity(literals.len() + 3);
    lits.extend_from_slice(literals);
    if let Some(&last) = literals.last() {
        while !lits.len().is_multiple_of(4) {
            lits.push(last);
        }
    }

    // ── Map commands to symbols; replace repeated distances by D = 0 ──
    let mut lit_hist = [0u32; N_LIT_SYMBOLS];
    for &b in &lits {
        lit_hist[b as usize] += 1;
    }
    let mut l_hist = [0u32; N_L_SYMBOLS];
    let mut m_hist = [0u32; N_M_SYMBOLS];
    let mut d_hist = [0u32; N_D_SYMBOLS];
    // (symbol, extra) per stream, per command.
    let mut mapped: Vec<[(u8, u32); 3]> = Vec::with_capacity(cmds.len());
    let mut d_prev = 0u32;
    for (i, c) in cmds.iter().enumerate() {
        debug_assert!(c.l <= MAX_L_VALUE && c.m <= MAX_M_VALUE);
        // A literal-only command copies nothing, so any valid distance will
        // do: reuse the previous one (D = 0 below), or 1 for a block's first
        // command.
        let d = if c.m == 0 {
            if i == 0 { 1 } else { d_prev }
        } else {
            c.d
        };
        debug_assert!((1..=MAX_D_VALUE).contains(&d));
        let d_coded = if i > 0 && d == d_prev { 0 } else { d };
        d_prev = d;
        let (ls, le) = map_lmd(c.l, &L_BASE);
        let (ms, me) = map_lmd(c.m, &M_BASE);
        let (ds, de) = map_lmd(d_coded, &D_BASE);
        l_hist[ls] += 1;
        m_hist[ms] += 1;
        d_hist[ds] += 1;
        mapped.push([(ls as u8, le), (ms as u8, me), (ds as u8, de)]);
    }

    let mut lit_freq = [0u16; N_LIT_SYMBOLS];
    let mut l_freq = [0u16; N_L_SYMBOLS];
    let mut m_freq = [0u16; N_M_SYMBOLS];
    let mut d_freq = [0u16; N_D_SYMBOLS];
    fse::normalize_freq(&lit_hist, LIT_STATES, &mut lit_freq);
    fse::normalize_freq(&l_hist, L_STATES, &mut l_freq);
    fse::normalize_freq(&m_hist, M_STATES, &mut m_freq);
    fse::normalize_freq(&d_hist, D_STATES, &mut d_freq);

    let mut lit_enc = [fse::FseEncEntry::default(); N_LIT_SYMBOLS];
    let mut l_enc = [fse::FseEncEntry::default(); N_L_SYMBOLS];
    let mut m_enc = [fse::FseEncEntry::default(); N_M_SYMBOLS];
    let mut d_enc = [fse::FseEncEntry::default(); N_D_SYMBOLS];
    fse::build_encoder(&lit_freq, LIT_STATES, &mut lit_enc);
    fse::build_encoder(&l_freq, L_STATES, &mut l_enc);
    fse::build_encoder(&m_freq, M_STATES, &mut m_enc);
    fse::build_encoder(&d_freq, D_STATES, &mut d_enc);

    // ── Literal stream: four interleaved states, encoded back to front ──
    let mut lit_bits = fse::BitWriter::new_fse(lits.len());
    let mut lit_states = [0u32; 4];
    for (idx, &b) in lits.iter().enumerate().rev() {
        let st = &mut lit_states[idx % 4];
        let (bits, nb, next) = fse::fse_encode(&lit_enc[b as usize], *st);
        lit_bits.push(bits, nb);
        *st = next;
    }
    let (lit_payload, literal_bits) = lit_bits.finish();

    // ── LMD stream: the decoder pulls L, M, D per command, front to back,
    //    so push D, M, L per command, back to front. Each field is the state
    //    bits (high) followed by the value's extra bits (low). ──
    let mut lmd_bits = fse::BitWriter::new_fse(cmds.len() * 6);
    let (mut l_st, mut m_st, mut d_st) = (0u32, 0u32, 0u32);
    for [(ls, le), (ms, me), (ds, de)] in mapped.iter().rev().copied() {
        push_lmd(
            &mut lmd_bits,
            &mut d_st,
            &d_enc,
            D_EXTRA_BITS[ds as usize],
            ds,
            de,
        );
        push_lmd(
            &mut lmd_bits,
            &mut m_st,
            &m_enc,
            M_EXTRA_BITS[ms as usize],
            ms,
            me,
        );
        push_lmd(
            &mut lmd_bits,
            &mut l_st,
            &l_enc,
            L_EXTRA_BITS[ls as usize],
            ls,
            le,
        );
    }
    let (lmd_payload, lmd_bits_field) = lmd_bits.finish();

    // ── Frequency tables: L, M, D, LIT, bit-contiguous ──
    let mut freq_bits = fse::BitWriter::new();
    for table in [&l_freq[..], &m_freq[..], &d_freq[..], &lit_freq[..]] {
        for &f in table {
            let (code, len) = fse::encode_freq_value(f);
            freq_bits.push(code, len);
        }
    }
    let (freq_bytes, _) = freq_bits.finish();

    // ── Header ──
    let header_size = (4 + V2_HEADER_FIXED_BYTES + freq_bytes.len()) as u64;
    let w0 = (lits.len() as u64)
        | ((lit_payload.len() as u64) << 20)
        | ((cmds.len() as u64) << 40)
        | ((literal_bits as u64) << 60);
    let w1 = (lit_states[0] as u64)
        | ((lit_states[1] as u64) << 10)
        | ((lit_states[2] as u64) << 20)
        | ((lit_states[3] as u64) << 30)
        | ((lmd_payload.len() as u64) << 40)
        | ((lmd_bits_field as u64) << 60);
    let w2 = header_size | ((l_st as u64) << 32) | ((m_st as u64) << 42) | ((d_st as u64) << 52);

    out.reserve(header_size as usize + lit_payload.len() + lmd_payload.len());
    out.extend_from_slice(b"bvx2");
    out.extend_from_slice(&n_raw.to_le_bytes());
    out.extend_from_slice(&w0.to_le_bytes());
    out.extend_from_slice(&w1.to_le_bytes());
    out.extend_from_slice(&w2.to_le_bytes());
    out.extend_from_slice(&freq_bytes);
    out.extend_from_slice(&lit_payload);
    out.extend_from_slice(&lmd_payload);
}

// ──────────────────────── test-only parse helper ────────────────────────
//
// An independent greedy parser (hash chain over 4-byte prefixes) feeding
// [`encode_block`], so the block encoder and decoder are exercised on their
// own, separately from the streaming encoder's parser.

#[cfg(test)]
mod test_parse {
    use super::*;

    /// Greedy LZ parse of `data` via a hash chain over 4-byte prefixes.
    pub(crate) fn lz_parse(data: &[u8]) -> (Vec<u8>, Vec<Cmd>) {
        const MIN_MATCH: usize = 4;
        const MAX_MATCH: usize = 2359; // M max encodable
        const MAX_DIST: usize = 262_139; // D max encodable
        const MAX_L: usize = 315; // L max encodable
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
                // L is capped at its largest encodable value; split longer
                // literal runs with literal-only (M == 0) commands.
                while pending_lit > MAX_L {
                    cmds.push(Cmd {
                        l: MAX_L as u32,
                        m: 0,
                        d: 0,
                    });
                    pending_lit -= MAX_L;
                }
                cmds.push(Cmd {
                    l: pending_lit as u32,
                    m: best_len as u32,
                    d: best_dist as u32,
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
        // Every literal is emitted by a command's L, so trailing literals get
        // literal-only (M == 0) commands, like Apple's encoder.
        while pending_lit > 0 {
            let l = pending_lit.min(MAX_L);
            cmds.push(Cmd {
                l: l as u32,
                m: 0,
                d: 0,
            });
            pending_lit -= l;
        }
        (literals, cmds)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lzfse::decoder::Decoder;
    use crate::traits::{RawDecoder, RawProgress};

    /// Encode `data` as one full `bvx2` block (magic included).
    fn v2_block(data: &[u8]) -> Vec<u8> {
        let (literals, cmds) = super::test_parse::lz_parse(data);
        let mut b = Vec::new();
        super::encode_block(&literals, &cmds, data.len() as u32, &mut b);
        b
    }

    /// Encode `data` as one `bvx2` block, without the 4-byte magic (the
    /// shape [`decode_block`] takes).
    fn encode_block(data: &[u8]) -> Vec<u8> {
        v2_block(data)[4..].to_vec()
    }

    fn normalize_general(hist: &[u32], n_states: usize) -> Vec<u16> {
        let mut f = vec![0u16; hist.len()];
        fse::normalize_freq(hist, n_states, &mut f);
        f
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

    /// A ~100-byte block whose single-symbol FSE tables cost zero bits per
    /// command: `n_matches` commands of `L = 0, M = 15, D = 1` expand to
    /// `15 * n_matches` bytes, all materialised before any output drains.
    fn zero_bit_match_block(n_matches: u32) -> Vec<u8> {
        use fse::encode_freq_value;
        let single = |n_symbols: usize, sym: usize, states: u16| {
            let mut f = vec![0u16; n_symbols];
            f[sym] = states;
            f
        };
        let mut freq_bits: Vec<u8> = Vec::new();
        for table in [
            single(N_L_SYMBOLS, 0, L_STATES as u16),
            single(N_M_SYMBOLS, 15, M_STATES as u16),
            single(N_D_SYMBOLS, 1, D_STATES as u16),
            single(N_LIT_SYMBOLS, 0, LIT_STATES as u16),
        ] {
            for f in table {
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
        let header_size = (4 + V2_HEADER_FIXED_BYTES + freq_bytes.len()) as u64;
        let w0 = ((n_matches as u64) << 40) | (7 << 60);
        let w1 = 7u64 << 60;
        let mut b = Vec::new();
        b.extend_from_slice(&(15 * n_matches).to_le_bytes());
        b.extend_from_slice(&w0.to_le_bytes());
        b.extend_from_slice(&w1.to_le_bytes());
        b.extend_from_slice(&header_size.to_le_bytes());
        b.extend_from_slice(&freq_bytes);
        b
    }

    #[test]
    fn match_count_is_capped_per_block() {
        // At Apple's per-block command limit the block still decodes...
        let mut out = vec![0u8];
        let block = zero_bit_match_block(MATCHES_PER_BLOCK as u32);
        assert_eq!(
            decode_block(&block, &mut out, 1 << 16).unwrap(),
            block.len()
        );
        assert_eq!(out.len(), 1 + 15 * MATCHES_PER_BLOCK);
        // ...but a header claiming up to 2^20 - 1 commands no longer lets a
        // ~100-byte block allocate 15 MiB (or, with 11-bit M extras, GiBs)
        // in one go, beyond the reach of `LimitedDecoder`.
        let mut out = vec![0u8];
        let block = zero_bit_match_block((1 << 20) - 1);
        assert_eq!(decode_block(&block, &mut out, 1 << 16), Err(Error::Corrupt));
        assert!(out.len() <= 1, "bomb block produced {} bytes", out.len());
    }

    #[test]
    fn normalize_general_produces_non_dyadic_freqs() {
        // A skewed histogram must normalize to general (non-power-of-two)
        // frequencies that sum exactly to n_states and give every present
        // symbol at least 1. A regression that snapped to powers of two would
        // be visible here.
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
