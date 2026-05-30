//! Static-Huffman LHA methods: -lh4-/-lh5-/-lh6-/-lh7-.
//!
//! These share Okumura's public-domain ar002 block layout. Output is a
//! sequence of blocks; each block carries three canonical-Huffman tables
//! (a small "temp" table that codes the lengths of the main table, the
//! main literal/length table, and the position table) followed by the
//! Huffman-coded LZSS symbol stream.
//!
//! Clean-room implementation from the format description. Constants match
//! the documented method parameters; the per-method ring-buffer sizes and
//! offset-count bit widths follow the de-facto values used by real LHA
//! archives (see [`Params`]).
//!
//! ## Framing
//!
//! The raw method payload has no length field, so — like the other raw
//! method codecs in this crate ([`lzss`](crate::lzss),
//! [`xpress_huffman`](crate::xpress_huffman)) — we prepend a 4-byte
//! little-endian uncompressed length. The decoder stops once that many
//! bytes have been emitted, which makes the stream self-delimiting and
//! bounds output growth for decompression-bomb safety.

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;
use crate::lha::bits::{BitReader, BitWriter};
use crate::lha::huffman::{HuffTable, assign_lengths, lengths_to_codes};

// ─── format constants ──────────────────────────────────────────────────

/// Literal/length alphabet size: 256 literals + 254 length codes.
const NC: usize = 510;
/// Bits used to transmit the C-table symbol count.
const CBIT: u32 = 9;
/// Number of temp-table (code-length) codes.
const NT: usize = 19;
/// Bits used to transmit the temp-table symbol count.
const TBIT: u32 = 5;
/// Minimum match length.
const MIN_MATCH: usize = 3;
/// Maximum match length (so length codes span 0..=253).
const MAX_MATCH: usize = 256;
/// Fast-table width for the main/position decode tables.
const TABLE_BITS: u32 = 12;
/// Fast-table width for the small temp table.
const PT_TABLE_BITS: u32 = 8;
/// Index in the temp table after which a 2-bit "skip up to 3" field
/// appears (Okumura's special case `i == 3`).
const SPECIAL_INDEX: usize = 3;

/// Per-method parameters.
#[derive(Clone, Copy)]
pub struct Params {
    /// Ring-buffer size in bytes (power of two).
    pub ring_size: usize,
    /// Bits used to transmit the position-table symbol count.
    pub pbit: u32,
    /// Number of position codes (offset-bit-count alphabet size).
    pub np: usize,
}

impl Params {
    pub const fn for_method(name: &str) -> Params {
        // Values follow the de-facto LHA decoders (lhasa): lh4 4 KiB,
        // lh5 16 KiB, lh6 64 KiB, lh7 128 KiB. `np` is the number of
        // distinct offset-bit-count symbols (== HISTORY_BITS + 1).
        match name.as_bytes() {
            b"lh4" => Params {
                ring_size: 1 << 12,
                pbit: 4,
                np: 14,
            },
            b"lh6" => Params {
                ring_size: 1 << 16,
                pbit: 5,
                np: 17,
            },
            b"lh7" => Params {
                ring_size: 1 << 17,
                pbit: 5,
                np: 18,
            },
            // lh5 (default).
            _ => Params {
                ring_size: 1 << 14,
                pbit: 4,
                np: 14,
            },
        }
    }
}

// ─── temp-table length read/write ───────────────────────────────────────

/// Decode a "length value": 3 bits, and if all-ones (7) keep reading 1
/// bits, incrementing, until a 0 bit. Caps growth to avoid runaway.
fn read_length_value(br: &mut BitReader<'_>) -> Result<u8, Error> {
    let mut n = br.get_bits(3);
    if n == 7 {
        // Each extra 1-bit adds one. The maximum legal code length is 16,
        // so cap and reject anything past that.
        loop {
            if br.get_bits(1) == 0 {
                break;
            }
            n += 1;
            if n > super::huffman::MAX_BITS {
                return Err(Error::InvalidHuffmanTree);
            }
        }
    }
    Ok(n as u8)
}

fn write_length_value(bw: &mut BitWriter, len: u8) {
    let l = len as u32;
    if l < 7 {
        bw.put_bits(3, l);
    } else {
        bw.put_bits(3, 7);
        let extra = l - 7;
        // `extra` ones followed by a zero.
        for _ in 0..extra {
            bw.put_bits(1, 1);
        }
        bw.put_bits(1, 0);
    }
}

/// Read the temp table (the table that codes C-table lengths).
fn read_temp_table(br: &mut BitReader<'_>) -> Result<HuffTable, Error> {
    let n = br.get_bits(TBIT) as usize;
    if n == 0 {
        let sym = br.get_bits(TBIT) as u16;
        // Single-symbol temp table (validated inside build_single).
        return HuffTable::build_single(NT, sym, PT_TABLE_BITS);
    }
    if n > NT {
        return Err(Error::Corrupt);
    }
    let mut lens = vec![0u8; NT];
    let mut i = 0usize;
    while i < n {
        lens[i] = read_length_value(br)?;
        i += 1;
        if i == SPECIAL_INDEX {
            // Skip a 2-bit count of zero-length entries.
            let skip = br.get_bits(2) as usize;
            for _ in 0..skip {
                if i >= NT {
                    return Err(Error::Corrupt);
                }
                lens[i] = 0;
                i += 1;
            }
        }
    }
    HuffTable::build(&lens, PT_TABLE_BITS)
}

fn write_temp_table(bw: &mut BitWriter, lens: &[u8]) {
    // Determine the count: highest index + 1 with non-zero, but the
    // format transmits the count of leading entries actually written.
    // We always write all NT entries' lengths (n == NT) to keep the
    // encoder simple and unambiguous.
    let n = NT;
    bw.put_bits(TBIT, n as u32);
    let mut i = 0usize;
    while i < n {
        write_length_value(bw, lens[i]);
        i += 1;
        if i == SPECIAL_INDEX {
            // We never use the skip optimisation: write 0.
            bw.put_bits(2, 0);
        }
    }
}

// ─── C-table (literal/length) length read/write ─────────────────────────

fn read_c_lengths(br: &mut BitReader<'_>, temp: &HuffTable) -> Result<Vec<u8>, Error> {
    let n = br.get_bits(CBIT) as usize;
    if n == 0 {
        let sym = br.get_bits(CBIT) as u16;
        if sym as usize >= NC {
            return Err(Error::InvalidHuffmanTree);
        }
        // Single-symbol C-table is represented by a length array that
        // HuffTable::build_single understands; here we return lengths
        // and let the caller build. Encode as a sentinel: all zeros but
        // record the single symbol by giving it length 0 — instead we
        // return a dedicated marker via Err? Simpler: produce a length
        // vec with the single symbol marked length 1-equivalent is
        // wrong. We special-case by returning a vec where only `sym`
        // is set to a reserved 0xFF, decoded by the caller.
        let mut lens = vec![0u8; NC];
        lens[sym as usize] = SINGLE_MARKER;
        return Ok(lens);
    }
    if n > NC {
        return Err(Error::Corrupt);
    }
    let mut lens = vec![0u8; NC];
    let mut i = 0usize;
    while i < n {
        let c = temp.decode(br)?;
        match c {
            0 => {
                // One zero-length entry.
                i += 1;
            }
            1 => {
                // Read 4 bits + 3 zero-length entries.
                let cnt = br.get_bits(4) as usize + 3;
                for _ in 0..cnt {
                    if i >= NC {
                        return Err(Error::Corrupt);
                    }
                    lens[i] = 0;
                    i += 1;
                }
            }
            2 => {
                // Read 9 bits + 20 zero-length entries.
                let cnt = br.get_bits(9) as usize + 20;
                for _ in 0..cnt {
                    if i >= NC {
                        return Err(Error::Corrupt);
                    }
                    lens[i] = 0;
                    i += 1;
                }
            }
            _ => {
                if (c as usize) < 2 {
                    return Err(Error::Corrupt);
                }
                lens[i] = (c - 2) as u8;
                if lens[i] as u32 > super::huffman::MAX_BITS {
                    return Err(Error::InvalidHuffmanTree);
                }
                i += 1;
            }
        }
        if i > NC {
            return Err(Error::Corrupt);
        }
    }
    Ok(lens)
}

/// Reserved length value used internally to flag the single-symbol C-table.
const SINGLE_MARKER: u8 = 0xFF;

/// Encode the C-table lengths using the temp table coding (symbols 0/1/2
/// plus `len+2`). Returns the temp-table frequency histogram needed to
/// build the temp table first; the caller builds the temp table, then we
/// re-encode for real.
fn c_lengths_to_temp_symbols(lens: &[u8]) -> Vec<TempSym> {
    let mut out = Vec::new();
    let mut i = 0usize;
    let n = lens.len();
    while i < n {
        if lens[i] == 0 {
            // Count run of zeros.
            let mut run = 1usize;
            while i + run < n && lens[i + run] == 0 {
                run += 1;
            }
            // Encode runs: prefer the largest applicable code.
            let mut rem = run;
            while rem > 0 {
                if rem >= 20 {
                    let take = rem.min(20 + 511); // 9 bits max extra = 511
                    out.push(TempSym::Run2((take - 20) as u32));
                    rem -= take;
                } else if rem >= 3 {
                    let take = rem.min(3 + 15); // 4 bits max extra = 15
                    out.push(TempSym::Run1((take - 3) as u32));
                    rem -= take;
                } else {
                    out.push(TempSym::Zero);
                    rem -= 1;
                }
            }
            i += run;
        } else {
            out.push(TempSym::Len(lens[i]));
            i += 1;
        }
    }
    out
}

#[derive(Clone, Copy)]
enum TempSym {
    Zero,
    Run1(u32),
    Run2(u32),
    Len(u8),
}

impl TempSym {
    fn symbol(&self) -> usize {
        match self {
            TempSym::Zero => 0,
            TempSym::Run1(_) => 1,
            TempSym::Run2(_) => 2,
            TempSym::Len(l) => *l as usize + 2,
        }
    }
}

// ─── position-table length read/write ───────────────────────────────────

fn read_position_table(br: &mut BitReader<'_>, np: usize, pbit: u32) -> Result<HuffTable, Error> {
    let n = br.get_bits(pbit) as usize;
    if n == 0 {
        let sym = br.get_bits(pbit) as u16;
        if sym as usize >= np {
            return Err(Error::InvalidHuffmanTree);
        }
        return HuffTable::build_single(np, sym, TABLE_BITS);
    }
    if n > np {
        return Err(Error::Corrupt);
    }
    let mut lens = vec![0u8; np];
    let mut i = 0usize;
    while i < n {
        lens[i] = read_length_value(br)?;
        i += 1;
    }
    HuffTable::build(&lens, TABLE_BITS)
}

fn write_position_table(bw: &mut BitWriter, lens: &[u8], np: usize, pbit: u32) {
    let _ = np;
    let n = lens.len();
    bw.put_bits(pbit, n as u32);
    for &l in lens.iter().take(n) {
        write_length_value(bw, l);
    }
}

// ─── offset (position) symbol <-> value ──────────────────────────────────

/// Number of "extra" bits and the symbol for a given match offset
/// (0-based: offset 0 means distance 1). Symbol `s` means: if s<=1 the
/// offset is exactly `s`; otherwise read `s-1` extra bits and the offset
/// is `(1 << (s-1)) + extra`.
fn offset_to_symbol(offset: usize) -> (usize, u32, u32) {
    // offset here is the raw value used by copy_from_history
    // (start = pos - offset - 1), i.e. distance-1.
    if offset == 0 {
        return (0, 0, 0);
    }
    if offset == 1 {
        return (1, 0, 0);
    }
    // Find s such that (1 << (s-1)) <= offset < (1 << s).
    let mut s = 1usize;
    while (1usize << s) <= offset {
        s += 1;
    }
    // Now (1 << (s-1)) <= offset < (1 << s); symbol = s, extra bits = s-1.
    let extra_bits = (s - 1) as u32;
    let extra = (offset - (1usize << (s - 1))) as u32;
    (s, extra_bits, extra)
}

fn read_offset_code(br: &mut BitReader<'_>, table: &HuffTable) -> Result<usize, Error> {
    let sym = table.decode(br)? as usize;
    if sym == 0 {
        Ok(0)
    } else if sym == 1 {
        Ok(1)
    } else {
        let extra = br.get_bits((sym - 1) as u32) as usize;
        Ok((1usize << (sym - 1)) + extra)
    }
}

// ─── decoder ─────────────────────────────────────────────────────────────

/// Decode an lh4/5/6/7 stream (after the 4-byte length header has been
/// stripped) of declared length `expected` into a fresh `Vec<u8>`.
///
/// Bounds output to `expected` bytes (decompression-bomb safe) and never
/// panics on crafted input.
pub fn decode_payload(payload: &[u8], expected: usize, params: Params) -> Result<Vec<u8>, Error> {
    let mut out: Vec<u8> = Vec::with_capacity(expected.min(1 << 20));
    if expected == 0 {
        return Ok(out);
    }
    let ring_size = params.ring_size;
    let mut ring = vec![b' '; ring_size];
    let mut ring_pos = 0usize;

    let mut br = BitReader::new(payload);

    while out.len() < expected {
        // Start a new block.
        let block_codes = br.get_bits(16) as usize;
        if br.overran() {
            return Err(Error::UnexpectedEnd);
        }
        if block_codes == 0 {
            // A zero-length block makes no progress; if we still owe
            // output the stream is malformed.
            return Err(Error::Corrupt);
        }

        let temp = read_temp_table(&mut br)?;
        let c_lens = read_c_lengths(&mut br, &temp)?;
        let c_table = build_c_table(&c_lens)?;
        let p_table = read_position_table(&mut br, params.np, params.pbit)?;

        let mut remaining = block_codes;
        while remaining > 0 && out.len() < expected {
            let code = c_table.decode(&mut br)? as usize;
            if br.overran() {
                return Err(Error::UnexpectedEnd);
            }
            if code < 256 {
                // Literal.
                out.push(code as u8);
                ring[ring_pos] = code as u8;
                ring_pos = (ring_pos + 1) % ring_size;
            } else {
                let count = code - 256 + MIN_MATCH;
                if count > MAX_MATCH {
                    return Err(Error::Corrupt);
                }
                let offset = read_offset_code(&mut br, &p_table)?;
                if br.overran() {
                    return Err(Error::UnexpectedEnd);
                }
                if offset >= ring_size {
                    return Err(Error::InvalidDistance);
                }
                let start = (ring_pos + ring_size - offset - 1) % ring_size;
                for k in 0..count {
                    if out.len() >= expected {
                        break;
                    }
                    let b = ring[(start + k) % ring_size];
                    out.push(b);
                    ring[ring_pos] = b;
                    ring_pos = (ring_pos + 1) % ring_size;
                }
            }
            remaining -= 1;
        }
    }

    Ok(out)
}

/// Build the C-table, honouring the internal single-symbol marker.
fn build_c_table(c_lens: &[u8]) -> Result<HuffTable, Error> {
    // Detect the single-symbol marker produced by `read_c_lengths`.
    let mut single: Option<u16> = None;
    let mut any_normal = false;
    for (s, &l) in c_lens.iter().enumerate() {
        if l == SINGLE_MARKER {
            single = Some(s as u16);
        } else if l != 0 {
            any_normal = true;
        }
    }
    if let Some(sym) = single {
        if any_normal {
            return Err(Error::Corrupt);
        }
        return HuffTable::build_single(NC, sym, TABLE_BITS);
    }
    HuffTable::build(c_lens, TABLE_BITS)
}

// ─── encoder ─────────────────────────────────────────────────────────────

/// One LZSS token: a literal or a (length, offset) match.
enum Token {
    Lit(u8),
    Match { len: usize, offset: usize },
}

/// If exactly one symbol has a non-zero code length, return it. Such a
/// table must be transmitted in the count-0 form (the decoder then
/// consumes zero bits to "decode" that symbol).
fn single_symbol(lens: &[u8]) -> Option<usize> {
    let mut found = None;
    for (s, &l) in lens.iter().enumerate() {
        if l != 0 {
            if found.is_some() {
                return None;
            }
            found = Some(s);
        }
    }
    found
}

/// Encode `data` into an lh5/6/7 payload (no length header — the caller
/// prepends it). Produces a single block holding every token. Uses a
/// greedy hash-chain match finder over the method's window.
pub fn encode_payload(data: &[u8], params: Params) -> Vec<u8> {
    let mut bw = BitWriter::new();
    if data.is_empty() {
        return bw.finish();
    }

    // The largest offset whose position symbol stays within the `np`
    // alphabet is `2^(np-1) - 1` (symbol `np-1` covers offsets
    // `2^(np-2)..2^(np-1)`). Cap match distance accordingly; this is the
    // method's effective dictionary size (e.g. lh5 np=14 → 8 KiB).
    let max_dist = (1usize << (params.np - 1)) - 1;
    let tokens = lz_parse(data, max_dist);

    // Build frequency histograms.
    let mut c_freq = vec![0u32; NC];
    let mut p_freq = vec![0u32; params.np];
    for t in &tokens {
        match t {
            Token::Lit(b) => c_freq[*b as usize] += 1,
            Token::Match { len, offset } => {
                let code = 256 + (len - MIN_MATCH);
                c_freq[code] += 1;
                let (sym, _, _) = offset_to_symbol(*offset);
                p_freq[sym] += 1;
            }
        }
    }

    // Assign canonical code lengths.
    let c_lens = assign_lengths(&c_freq, super::huffman::MAX_BITS);
    let p_lens = assign_lengths(&p_freq, super::huffman::MAX_BITS);
    let c_codes = lengths_to_codes(&c_lens);
    let p_codes = lengths_to_codes(&p_lens);

    // Block header: 16-bit code count.
    bw.put_bits(16, tokens.len() as u32);

    // ── temp + C-table ──────────────────────────────────────────────
    // If the C-table has a single used symbol, the decoder consumes no
    // bits for it (count==0 form), so we must emit that form and NOT a
    // 1-bit code. Otherwise emit the temp table + run-length-coded
    // C-lengths.
    let c_single = single_symbol(&c_lens);
    if let Some(sym) = c_single {
        // Temp table is unused in this branch; emit an empty temp table
        // header (count 0, arbitrary single symbol 0) for symmetry — the
        // decoder still reads it before the C-table header.
        bw.put_bits(TBIT, 0);
        bw.put_bits(TBIT, 0);
        bw.put_bits(CBIT, 0);
        bw.put_bits(CBIT, sym as u32);
    } else {
        let temp_syms = c_lengths_to_temp_symbols(&c_lens);
        let mut t_freq = vec![0u32; NT];
        for ts in &temp_syms {
            t_freq[ts.symbol()] += 1;
        }
        let t_lens = assign_lengths(&t_freq, super::huffman::MAX_BITS);
        let t_codes = lengths_to_codes(&t_lens);
        write_temp_table(&mut bw, &t_lens);
        bw.put_bits(CBIT, NC as u32);
        for ts in &temp_syms {
            let sym = ts.symbol();
            bw.put_bits(t_lens[sym] as u32, t_codes[sym]);
            match ts {
                TempSym::Zero | TempSym::Len(_) => {}
                TempSym::Run1(extra) => bw.put_bits(4, *extra),
                TempSym::Run2(extra) => bw.put_bits(9, *extra),
            }
        }
    }

    // ── position table ──────────────────────────────────────────────
    let p_single = single_symbol(&p_lens);
    if let Some(sym) = p_single {
        bw.put_bits(params.pbit, 0);
        bw.put_bits(params.pbit, sym as u32);
    } else {
        write_position_table(&mut bw, &p_lens, params.np, params.pbit);
    }

    // ── coded token stream ──────────────────────────────────────────
    for t in &tokens {
        match t {
            Token::Lit(b) => {
                let s = *b as usize;
                if c_single.is_none() {
                    bw.put_bits(c_lens[s] as u32, c_codes[s]);
                }
            }
            Token::Match { len, offset } => {
                let code = 256 + (len - MIN_MATCH);
                if c_single.is_none() {
                    bw.put_bits(c_lens[code] as u32, c_codes[code]);
                }
                let (sym, extra_bits, extra) = offset_to_symbol(*offset);
                if p_single.is_none() {
                    bw.put_bits(p_lens[sym] as u32, p_codes[sym]);
                }
                bw.put_bits(extra_bits, extra);
            }
        }
    }

    bw.finish()
}

/// Greedy LZSS parser with a hash-chain match finder. `window` is the
/// maximum back-distance.
fn lz_parse(data: &[u8], window: usize) -> Vec<Token> {
    let n = data.len();
    let mut tokens = Vec::new();

    // Hash chains keyed on 3-byte prefixes.
    const HASH_BITS: u32 = 16;
    const HASH_SIZE: usize = 1 << HASH_BITS;
    let mut head = vec![usize::MAX; HASH_SIZE];
    let mut prev = vec![usize::MAX; n];

    let hash3 = |d: &[u8], i: usize| -> usize {
        let a = d[i] as usize;
        let b = d[i + 1] as usize;
        let c = d[i + 2] as usize;
        ((a << 10) ^ (b << 5) ^ c).wrapping_mul(2654435761) >> (32 - HASH_BITS) & (HASH_SIZE - 1)
    };

    let max_chain = 128usize;
    let mut i = 0usize;
    while i < n {
        let mut best_len = 0usize;
        let mut best_off = 0usize;
        if i + MIN_MATCH <= n {
            let h = hash3(data, i);
            let mut cand = head[h];
            let mut chain = 0usize;
            let max_match = MAX_MATCH.min(n - i);
            let min_pos = i.saturating_sub(window);
            while cand != usize::MAX && cand >= min_pos && chain < max_chain {
                // Compare.
                let mut l = 0usize;
                while l < max_match && data[cand + l] == data[i + l] {
                    l += 1;
                }
                if l > best_len {
                    best_len = l;
                    best_off = i - cand - 1; // distance-1
                    if l >= max_match {
                        break;
                    }
                }
                cand = prev[cand];
                chain += 1;
            }
        }

        if best_len >= MIN_MATCH {
            tokens.push(Token::Match {
                len: best_len,
                offset: best_off,
            });
            // Insert positions covered by the match into the hash chains.
            let end = i + best_len;
            while i < end {
                if i + MIN_MATCH <= n {
                    let h = hash3(data, i);
                    prev[i] = head[h];
                    head[h] = i;
                }
                i += 1;
            }
        } else {
            tokens.push(Token::Lit(data[i]));
            if i + MIN_MATCH <= n {
                let h = hash3(data, i);
                prev[i] = head[h];
                head[h] = i;
            }
            i += 1;
        }
    }

    tokens
}
