//! Sequences_Section decoder + LZ77 reconstruction (RFC 8478 §3.1.1.3.2).
//!
//! After the literals section the remainder of a Compressed_Block holds a
//! sequence of (literal_length, offset, match_length) triples that drive an
//! LZ77-style copy-and-paste into the output. Each component is encoded with
//! its own FSE state plus a base + extra-bits value.
//!
//! Offsets carry the "previous offsets" quirk: values 1, 2, 3 are aliases for
//! the most-recent / second-most / third-most offsets, with special rules
//! when `literal_length == 0`. See [`apply_offset`].

use alloc::vec::Vec;

use crate::error::Error;
use crate::zstd::bitreader::RevBitReader;
use crate::zstd::fse::{
    FseState, FseTable, decode_fse_table, default_ll_table, default_ml_table, default_of_table,
};

/// Tables that may be reused (`Repeat_Mode`) by the next block.
#[derive(Default)]
pub struct SequencesState {
    pub ll_table: Option<FseTable>,
    pub ml_table: Option<FseTable>,
    pub of_table: Option<FseTable>,
    /// Previous offsets — repeat-code aliases for offsets 1..=3 in the
    /// encoded stream. Default per spec: [1, 4, 8].
    pub prev_offsets: [u32; 3],
}

impl SequencesState {
    pub fn new() -> Self {
        Self {
            ll_table: None,
            ml_table: None,
            of_table: None,
            prev_offsets: [1, 4, 8],
        }
    }
}

/// One decoded sequence.
#[derive(Clone, Copy, Debug)]
pub struct Sequence {
    pub literal_length: u32,
    pub match_length: u32,
    pub offset: u32,
}

/// Decode the Sequences_Section starting at `data[0]`.
///
/// Returns the decoded sequences plus the number of literals expected by the
/// reconstruction step (every byte of the literals buffer must be consumed).
pub fn decode_sequences(data: &[u8], state: &mut SequencesState) -> Result<Vec<Sequence>, Error> {
    if data.is_empty() {
        // Per spec: a Sequences_Section with zero sequences may be encoded as
        // a single 0 byte.
        return Err(Error::Corrupt);
    }

    let (n_seq, hdr_after_count) = parse_sequence_count(data)?;
    if n_seq == 0 {
        // Single 0 byte → no sequences; output is pure literals.
        return Ok(Vec::new());
    }

    if data.len() < hdr_after_count + 1 {
        return Err(Error::Corrupt);
    }
    let symbol_modes = data[hdr_after_count];
    let ll_mode = (symbol_modes >> 6) & 0b11;
    let of_mode = (symbol_modes >> 4) & 0b11;
    let ml_mode = (symbol_modes >> 2) & 0b11;
    let reserved = symbol_modes & 0b11;
    if reserved != 0 {
        return Err(Error::Corrupt);
    }

    let mut cur = hdr_after_count + 1;

    // Each `resolve_table` advances `cur` based on the table mode and
    // any embedded length prefixes inside `data`. A maliciously-crafted
    // header can advance `cur` past `data.len()` between calls; use
    // checked slicing to reject rather than panic.
    fn slice_at(data: &[u8], cur: usize) -> Result<&[u8], Error> {
        data.get(cur..).ok_or(Error::Corrupt)
    }

    // Resolve each table.
    let ll_table = resolve_table(
        ll_mode,
        slice_at(data, cur)?,
        &mut cur,
        &mut state.ll_table,
        TableKind::LiteralLength,
    )?;
    let of_table = resolve_table(
        of_mode,
        slice_at(data, cur)?,
        &mut cur,
        &mut state.of_table,
        TableKind::Offset,
    )?;
    let ml_table = resolve_table(
        ml_mode,
        slice_at(data, cur)?,
        &mut cur,
        &mut state.ml_table,
        TableKind::MatchLength,
    )?;

    // What's left is the FSE bit stream (reverse). Its last byte holds the
    // start marker. Bounds-check the slice for the same reason as above.
    let bitstream = data.get(cur..).ok_or(Error::Corrupt)?;
    if bitstream.is_empty() {
        return Err(Error::Corrupt);
    }
    let mut br = RevBitReader::new(bitstream)?;

    // Initialise states in order: LL, OF, ML.
    let mut ll_state = FseState::init(&ll_table, &mut br)?;
    let mut of_state = FseState::init(&of_table, &mut br)?;
    let mut ml_state = FseState::init(&ml_table, &mut br)?;

    // Cap only the capacity HINT so a tiny header advertising a huge sequence
    // count can't force a large reservation before the corresponding sequence
    // data is parsed; the loop below still pushes exactly `n_seq` entries.
    let mut sequences: Vec<Sequence> = Vec::with_capacity((n_seq as usize).min(128 * 1024));

    for i in 0..n_seq {
        // Per RFC §3.1.1.3.2.1.1 decoding order:
        //   1. Read literal_length extra bits.
        //   2. Read offset_code extra bits.
        //   3. Read match_length extra bits.
        // Then advance ll, ml, of states (in that order) by reading their
        // num_bits. Final sequence skips the advance.
        let ll_sym = ll_state.symbol(&ll_table) as u8;
        let ml_sym = ml_state.symbol(&ml_table) as u8;
        let of_sym = of_state.symbol(&of_table) as u8;

        let (ll_base, ll_extra) = ll_base_extra(ll_sym)?;
        let (ml_base, ml_extra) = ml_base_extra(ml_sym)?;

        // Read order is offset first (then match-length, then literal-length)
        // when consuming from the reverse stream. Actually per RFC the order
        // is: 1) Offset_Value extra bits, 2) Match_Length extra bits,
        // 3) Literal_Length extra bits.
        //
        // `of_sym` comes from an FSE-decoded table whose contents are
        // taken from the input — malformed input can yield a symbol
        // ≥ 32, which would overflow the `1u32 << of_sym` shift below.
        // The zstd spec caps offset codes at 31; reject anything past
        // that as corrupt.
        if of_sym >= 32 {
            return Err(Error::Corrupt);
        }
        let offset_value = if of_sym > 0 {
            (1u32 << of_sym) + br.read(of_sym as u32)? as u32
        } else {
            1u32 // of_sym==0 means offset_value=1 (no extra bits)
        };

        let ml_value = ml_base + br.read(ml_extra)? as u32;
        let ll_value = ll_base + br.read(ll_extra)? as u32;

        // Resolve "previous offsets" aliasing.
        let offset = apply_offset(offset_value, ll_value, &mut state.prev_offsets)?;

        sequences.push(Sequence {
            literal_length: ll_value,
            match_length: ml_value,
            offset,
        });

        if i + 1 == n_seq {
            break;
        }

        // Advance states: LL, ML, OF (RFC ordering).
        ll_state.advance(&ll_table, &mut br)?;
        ml_state.advance(&ml_table, &mut br)?;
        of_state.advance(&of_table, &mut br)?;
    }

    // Stash tables for potential Repeat_Mode reuse next block.
    state.ll_table = Some(ll_table);
    state.ml_table = Some(ml_table);
    state.of_table = Some(of_table);

    Ok(sequences)
}

fn parse_sequence_count(data: &[u8]) -> Result<(u32, usize), Error> {
    let b0 = data[0];
    if b0 == 0 {
        return Ok((0, 1));
    }
    if b0 < 128 {
        return Ok((b0 as u32, 1));
    }
    if b0 < 255 {
        // 2-byte form: ((b0-128) << 8) + b1
        if data.len() < 2 {
            return Err(Error::Corrupt);
        }
        let v = (((b0 as u32) - 128) << 8) | (data[1] as u32);
        return Ok((v, 2));
    }
    // 3-byte form: 0xFF, b1, b2 → 0x7F00 + b1 + (b2 << 8)
    if data.len() < 3 {
        return Err(Error::Corrupt);
    }
    let v = (data[1] as u32) | ((data[2] as u32) << 8);
    Ok((v + 0x7F00, 3))
}

enum TableKind {
    LiteralLength,
    Offset,
    MatchLength,
}

fn resolve_table(
    mode: u8,
    rest: &[u8],
    cur: &mut usize,
    repeat_slot: &mut Option<FseTable>,
    kind: TableKind,
) -> Result<FseTable, Error> {
    match mode {
        0b00 => {
            // Predefined_Mode
            Ok(match kind {
                TableKind::LiteralLength => default_ll_table(),
                TableKind::Offset => default_of_table(),
                TableKind::MatchLength => default_ml_table(),
            })
        }
        0b01 => {
            // RLE_Mode: one byte gives the only symbol; accuracy_log = 0
            // can't happen in our FseTable (we require al >= 1). For an RLE
            // table the value is a single state. We synthesise a degenerate
            // 1-entry table with accuracy_log = 1 (size 2) where both entries
            // map to the same symbol with num_bits=0 — that emits the same
            // symbol forever and never consumes extra state bits.
            if rest.is_empty() {
                return Err(Error::Corrupt);
            }
            let sym = rest[0] as u16;
            *cur += 1;
            // Synthesise a "pinned" FSE table: 1 state, always sym, num_bits 0.
            use crate::zstd::fse::FseEntry;
            use alloc::vec;
            // accuracy_log = 0 isn't really used by our consumers; the FseState
            // init reads 0 bits, leaving state=0; advance reads 0 bits, state
            // stays 0; symbol(state=0) = sym. Implement with a table of size 1.
            let t = FseTable {
                accuracy_log: 0,
                entries: vec![FseEntry {
                    symbol: sym,
                    num_bits: 0,
                    base_state: 0,
                }],
            };
            Ok(t)
        }
        0b10 => {
            // FSE_Compressed_Mode: parse header from `rest`.
            let (max_al, max_sym) = match kind {
                TableKind::LiteralLength => (9, 35u16),
                TableKind::Offset => (8, 31u16),
                TableKind::MatchLength => (9, 52u16),
            };
            let (t, consumed) = decode_fse_table(rest, max_al, max_sym)?;
            *cur += consumed;
            Ok(t)
        }
        0b11 => {
            // Repeat_Mode
            match repeat_slot.take() {
                Some(t) => Ok(t),
                None => Err(Error::Corrupt),
            }
        }
        _ => unreachable!(),
    }
}

// ─── code → (base, extra_bits) lookups (RFC §3.1.1.3.2.1) ────────────────

fn ll_base_extra(code: u8) -> Result<(u32, u32), Error> {
    if code > 35 {
        return Err(Error::Corrupt);
    }
    // Spec tables A.4.1 / A.4.2: literal-length codes.
    let bases: [u32; 36] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 18, 20, 22, 24, 28, 32, 40, 48,
        64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536,
    ];
    let extras: [u32; 36] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 3, 3, 4, 6, 7, 8, 9, 10,
        11, 12, 13, 14, 15, 16,
    ];
    Ok((bases[code as usize], extras[code as usize]))
}

fn ml_base_extra(code: u8) -> Result<(u32, u32), Error> {
    if code > 52 {
        return Err(Error::Corrupt);
    }
    let bases: [u32; 53] = [
        3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
        27, 28, 29, 30, 31, 32, 33, 34, 35, 37, 39, 41, 43, 47, 51, 59, 67, 83, 99, 131, 259, 515,
        1027, 2051, 4099, 8195, 16387, 32771, 65539,
    ];
    let extras: [u32; 53] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 1, 1, 1, 1, 2, 2, 3, 3, 4, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
    ];
    Ok((bases[code as usize], extras[code as usize]))
}

/// Translate the `offset_value` produced by the offset FSE+extra-bits sum
/// into the actual back-reference distance, updating `prev_offsets`.
///
/// RFC 8478 §3.1.1.5: the encoded `offset_value` is one of:
///
/// - `1`: "repeat offset 1" (or "repeat offset 2" when literal_length=0).
/// - `2`: "repeat offset 2" (or "repeat offset 3" when LL=0).
/// - `3`: "repeat offset 3" (or "repeat offset 1 - 1" when LL=0).
/// - `>= 4`: normal offset, actual distance = offset_value - 3, then the
///   previous-offsets stack is updated.
fn apply_offset(offset_value: u32, literal_length: u32, prev: &mut [u32; 3]) -> Result<u32, Error> {
    let actual: u32;
    if offset_value > 3 {
        actual = offset_value - 3;
        // Shift prev: [actual, prev[0], prev[1]]
        prev[2] = prev[1];
        prev[1] = prev[0];
        prev[0] = actual;
    } else {
        // Repeat-offset path.
        let idx = offset_value as usize;
        if literal_length == 0 {
            // When LL==0, the "repeat 1" code is actually "repeat 2", etc.
            // Specifically: idx 1 → repeat 2, idx 2 → repeat 3,
            // idx 3 → repeat[0] - 1.
            let candidate = match idx {
                1 => prev[1],
                2 => prev[2],
                3 => prev[0].wrapping_sub(1),
                _ => unreachable!(),
            };
            if candidate == 0 {
                return Err(Error::Corrupt);
            }
            actual = candidate;
            // Update history depending on which slot was used.
            match idx {
                1 => {
                    prev.swap(0, 1);
                }
                2 => {
                    // [prev[2], prev[0], prev[1]]
                    let tmp = prev[2];
                    prev[2] = prev[1];
                    prev[1] = prev[0];
                    prev[0] = tmp;
                }
                3 => {
                    // [prev[0]-1, prev[0], prev[1]]
                    prev[2] = prev[1];
                    prev[1] = prev[0];
                    prev[0] = actual;
                }
                _ => unreachable!(),
            }
        } else {
            // Plain repeat-offset case.
            actual = match idx {
                1 => prev[0],
                2 => prev[1],
                3 => prev[2],
                _ => unreachable!(),
            };
            if actual == 0 {
                return Err(Error::Corrupt);
            }
            // Update history.
            match idx {
                1 => { /* no change */ }
                2 => {
                    prev.swap(0, 1);
                }
                3 => {
                    // [prev[2], prev[0], prev[1]]
                    let tmp = prev[2];
                    prev[2] = prev[1];
                    prev[1] = prev[0];
                    prev[0] = tmp;
                }
                _ => unreachable!(),
            }
        }
    }
    if actual == 0 {
        return Err(Error::Corrupt);
    }
    Ok(actual)
}

/// Apply a decoded sequence stream to a literals buffer + an output history.
///
/// `history` is the previously-decoded output (so back-references can read
/// from it); decoded bytes are appended to `history`.
///
/// `max_block_output` is the per-block decoded-output bound. Per RFC 8478
/// §3.1.1.2 a single Compressed_Block may decode to at most
/// `Block_Maximum_Size = min(Window_Size, 128 KiB)` bytes. Without this cap a
/// malicious block using RLE_Mode FSE tables (e.g. match-length RLE symbol 52,
/// `ml_base = 65539`, consuming no state bits) emits ~65 KiB per cheap
/// sequence, letting a ~128 KiB input block expand `history` to multiple GiB
/// before any output is drained — a decompression-bomb OOM that bypasses the
/// drained-bytes metering in [`crate::limit::LimitedDecoder`]. We track the
/// bytes this block appends (literals **and** match copies, plus the trailing
/// literals) and abort as soon as the running total would exceed the bound.
pub fn execute_sequences(
    sequences: &[Sequence],
    literals: &[u8],
    history: &mut Vec<u8>,
    max_block_output: usize,
) -> Result<(), Error> {
    // Bytes appended to `history` by *this* block so far. `history` itself
    // carries earlier blocks' output, so we meter against this running counter
    // rather than `history.len()`.
    let mut block_output = 0usize;
    let mut lit_pos = 0usize;
    for seq in sequences {
        let ll = seq.literal_length as usize;
        if lit_pos + ll > literals.len() {
            return Err(Error::Corrupt);
        }
        let ml = seq.match_length as usize;
        // Reject before allocating: a literal-run + match-length that would
        // push this block past Block_Maximum_Size is a decompression bomb.
        block_output = block_output
            .checked_add(ll)
            .and_then(|n| n.checked_add(ml))
            .ok_or(Error::Corrupt)?;
        if block_output > max_block_output {
            return Err(Error::Corrupt);
        }
        history.extend_from_slice(&literals[lit_pos..lit_pos + ll]);
        lit_pos += ll;
        let offset = seq.offset as usize;
        if offset == 0 || offset > history.len() {
            return Err(Error::Corrupt);
        }
        let start = history.len() - offset;
        if offset >= ml {
            // Non-overlapping: collapses to memcpy.
            history.extend_from_within(start..start + ml);
        } else if offset == 1 {
            // Byte-splat.
            let b = history[start];
            history.resize(history.len() + ml, b);
        } else {
            // Self-overlapping (RLE-style): replicate byte-by-byte.
            for i in 0..ml {
                let b = history[start + i];
                history.push(b);
            }
        }
    }
    // Trailing literals: leftover bytes copied verbatim. They also count
    // toward the per-block output bound.
    if lit_pos < literals.len() {
        let trailing = literals.len() - lit_pos;
        let total = block_output.checked_add(trailing).ok_or(Error::Corrupt)?;
        if total > max_block_output {
            return Err(Error::Corrupt);
        }
        history.extend_from_slice(&literals[lit_pos..]);
    }
    Ok(())
}
