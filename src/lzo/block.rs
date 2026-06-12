//! LZO1X-1 block-format codec (single-block, in-memory).
//!
//! Reference: <https://docs.kernel.org/staging/lzo.html> — Willy Tarreau's
//! reverse-engineered description of the LZO stream format as understood by
//! the Linux kernel decompressor, which matches Markus Oberhumer's
//! `minilzo` / `lzo1x_decompress_safe` behaviour bit-for-bit.
//!
//! This module operates on a single LZO1X block: the encoder takes a complete
//! input buffer and returns a complete encoded buffer; the decoder does the
//! reverse. The streaming wrapper in [`super`] chunks arbitrarily large
//! inputs into bounded blocks and re-assembles them on decode.
//!
//! ## Wire format recap
//!
//! Each block is a sequence of `(literal_run, copy_instruction)` pairs,
//! terminated by the three-byte sequence `0x11 0x00 0x00` (a copy
//! instruction whose decoded distance equals 16384, which the spec defines
//! as end-of-stream).
//!
//! Bytes describe instructions as follows. The `state` carried between
//! instructions records how many literals were emitted right before; the
//! short-copy forms use it to disambiguate near vs. mid distances.
//!
//! ```text
//! first-byte 0..15        regular instruction (state = 0 ⇒ long-literal)
//! first-byte 16           reserved / invalid as the very first byte
//! first-byte 17           bitstream-version indicator (LZO-RLE v1+); not used
//!                         by this encoder, but the decoder accepts it
//! first-byte 18..21       copy (b−17) literals; state = b−17
//! first-byte 22..255      copy (b−17) literals; state = 4
//!
//! 0000_LLLL  (0..15)      state == 0: long literal copy
//!                           length = 3 + (LLLL or 15 + extension)
//!                         state ∈ {1,2,3}: 2-byte copy from ≤1 KiB
//!                         state == 4: 3-byte copy from 2049..3072
//! 0001_HLLL  (16..31)     long-distance copy ≥16 KiB
//!                           length = 2 + (LLL or 7 + extension)
//!                           +LE16: D14 D14 ... D14 D14 S S
//!                           distance = 16384 + (H<<14) + (D>>2)
//!                           state = S; distance == 16384 ⇒ EOS
//! 001L_LLLL  (32..63)     copy from ≤16 KiB
//!                           length = 2 + (LLLLL or 31 + extension)
//!                           +LE16 D14 ... D14 S S; distance = D + 1
//! 01LD_DDSS  (64..127)    copy 3..4 bytes within 2 KiB
//!                           length = 3 + L; +H byte; dist = (H<<3)+D+1
//! 1LLD_DDSS  (128..255)   copy 5..8 bytes within 2 KiB
//!                           length = 5 + LL; +H byte; dist = (H<<3)+D+1
//! ```
//!
//! After every copy instruction the low two bits select 0..3 trailing
//! literals (the `state` value for the next instruction). If those bits are
//! zero, a longer literal run follows, encoded via the same `LLLL == 0 ⇒ 15
//! + extension` extension scheme.

use alloc::vec::Vec;

use crate::error::Error;

/// Minimum match length we are willing to emit.
///
/// LZO1X copies always cover at least 2 bytes, but the 2-byte form
/// (`0000_DDSS` consumed when the decoder's `state` is in 1..=3) is only
/// reachable after a copy that emitted 1..=3 inline literals — a delicate
/// state dance that our encoder doesn't bother to maintain. We require
/// 3+ byte matches and always emit one of the M2/M3/M4 token forms.
const MIN_MATCH: usize = 3;

/// Distance limit beyond which the long-distance form (16..31) must be used.
const M3_MAX_DISTANCE: usize = 16384;
/// Hard distance limit per the LZO1X-1 format (spec keeps distances ≤49151).
const M4_MAX_DISTANCE: usize = 0xBFFF; // 49151
/// Distance limit for the short M1 copies (64..127 and 128..255).
const M2_MAX_DISTANCE: usize = 0x800; // 2048

/// Hash table size: 13 bits = 8192 entries × 4 bytes = 32 KiB scratch.
const HASH_LOG: u32 = 13;
const HASH_TABLE_SIZE: usize = 1 << HASH_LOG;

/// Sentinel for an empty hash slot.
const HASH_EMPTY: u32 = u32::MAX;

/// Hash 4 bytes down to `HASH_LOG` bits using Knuth's multiplicative hash.
#[inline]
fn hash4(bytes: [u8; 4]) -> usize {
    let v = u32::from_le_bytes(bytes);
    ((v.wrapping_mul(2_654_435_761)) >> (32 - HASH_LOG)) as usize
}

/// Worst-case encoded length for `input_len` bytes of input.
///
/// `LZO_COMPRESS_BOUND` for LZO1X family is `n + n/16 + 64 + 3`.
pub fn compress_bound(input_len: usize) -> usize {
    input_len + (input_len / 16) + 64 + 3
}

// ─── encoder ──────────────────────────────────────────────────────────────

/// Encode `input` as a single LZO1X-1 block into `out` (cleared first).
///
/// The output is self-delimiting: it always ends with the canonical
/// `0x11 0x00 0x00` end-of-stream marker.
pub fn encode_block(input: &[u8], out: &mut Vec<u8>) {
    out.clear();

    if input.is_empty() {
        emit_eos(out);
        return;
    }

    // Inputs too short to find any match: emit as one big literal run + EOS.
    if input.len() < MIN_MATCH + 4 {
        emit_initial_literals(input, out);
        emit_eos(out);
        return;
    }

    let mut table = alloc::vec![HASH_EMPTY; HASH_TABLE_SIZE];

    let mut ip: usize = 0;
    let mut anchor: usize = 0;
    // Index in `out` of the most recently emitted copy-instruction token,
    // or `None` if we haven't emitted any copy yet (so pending literals are
    // an "initial run" rather than a trailing run of a prior copy).
    let mut last_token_idx: Option<usize> = None;
    let in_len = input.len();
    let hash_limit = in_len.saturating_sub(4);

    while ip < hash_limit {
        let h = hash4([input[ip], input[ip + 1], input[ip + 2], input[ip + 3]]);
        let candidate = table[h];
        table[h] = ip as u32;

        let mut found = false;
        let mut match_pos = 0usize;

        if candidate != HASH_EMPTY {
            let cand = candidate as usize;
            if cand < ip {
                let distance = ip - cand;
                if distance <= M4_MAX_DISTANCE
                    && input[cand] == input[ip]
                    && input[cand + 1] == input[ip + 1]
                    && input[cand + 2] == input[ip + 2]
                    && input[cand + 3] == input[ip + 3]
                {
                    found = true;
                    match_pos = cand;
                }
            }
        }

        if !found {
            ip += 1;
            continue;
        }

        // Extend the match forward as far as possible.
        let mut match_len = 4usize;
        while ip + match_len < in_len && input[match_pos + match_len] == input[ip + match_len] {
            match_len += 1;
        }

        let literal_len = ip - anchor;
        let distance = ip - match_pos;

        // Emit pending literals.
        match last_token_idx {
            None => emit_initial_literals(&input[anchor..ip], out),
            Some(_) if literal_len == 0 => {
                // No literals between this and the previous copy.
            }
            Some(tok_idx) if literal_len <= 3 => {
                // Inline 1..3 literals in the previous copy's S bits.
                patch_inline_literal_count(out, tok_idx, literal_len);
                out.extend_from_slice(&input[anchor..ip]);
            }
            Some(_) => {
                // Previous copy keeps S=0; emit a standalone long-literal-run
                // instruction (0000_LLLL form, only valid when decoder
                // state==0, which is exactly what S=0 implies). The decoder
                // will read this as a long-literal-copy and afterwards set
                // state=4 — which is exactly what the next copy we're about
                // to emit expects.
                emit_long_literal_run(&input[anchor..ip], out);
            }
        }

        // Emit this copy. Token index is recorded for future patching.
        let tok = emit_copy(distance, match_len, out);
        last_token_idx = Some(tok);

        ip += match_len;
        anchor = ip;
        // Sample one position close to where we are: this keeps the hash
        // table fresh without spending time on every byte of the match.
        if ip < hash_limit {
            let probe = ip - 1;
            let h2 = hash4([
                input[probe],
                input[probe + 1],
                input[probe + 2],
                input[probe + 3],
            ]);
            table[h2] = probe as u32;
        }
    }

    // Trailing literals from `anchor..in_len`, then EOS.
    let trailing = in_len - anchor;
    match last_token_idx {
        None => emit_initial_literals(&input[anchor..in_len], out),
        Some(_) if trailing == 0 => {
            // No trailing literals; previous copy already has S=0.
        }
        Some(tok_idx) if trailing <= 3 => {
            patch_inline_literal_count(out, tok_idx, trailing);
            out.extend_from_slice(&input[anchor..in_len]);
        }
        Some(_) => emit_long_literal_run(&input[anchor..in_len], out),
    }
    emit_eos(out);
}

/// Encode the very first literal run of a block.
///
/// Rules:
/// - `n = 0`: nothing.
/// - `1 ≤ n ≤ 238`: single byte `n + 17` encodes it.
/// - `n ≥ 239`: regular long-literal coding `0000_LLLL` with `LLLL = 0`,
///   length = 3 + 15 + extension. Same extension format as the body.
fn emit_initial_literals(literals: &[u8], out: &mut Vec<u8>) {
    let n = literals.len();
    if n == 0 {
        return;
    }
    if n <= 238 {
        out.push((n + 17) as u8);
        out.extend_from_slice(literals);
        return;
    }
    // n ≥ 239: use the regular long-literal coding.
    out.push(0x00);
    let mut rem = n - 18; // length − 3 − 15
    while rem > 255 {
        out.push(0);
        rem -= 255;
    }
    out.push(rem as u8);
    out.extend_from_slice(literals);
}

/// Emit a copy instruction with the given `distance` and `length`, leaving
/// the low-2-bit trailing-literal-run-length field at 0 (the caller patches
/// it once the next match position is known).
///
/// Returns the absolute index of the copy's token byte in `out`.
fn emit_copy(distance: usize, length: usize, out: &mut Vec<u8>) -> usize {
    debug_assert!(length >= MIN_MATCH);
    debug_assert!((1..=M4_MAX_DISTANCE).contains(&distance));

    // Pick the smallest instruction form that fits.
    if length <= 8 && distance <= M2_MAX_DISTANCE && length >= 3 {
        let d = distance - 1;
        let d_lo = (d & 0x7) as u8;
        let d_hi = ((d >> 3) & 0xFF) as u8;
        let tok_idx = out.len();
        if length <= 4 {
            // 01LD_DDSS form
            let l = (length - 3) as u8; // 0 or 1
            let token = 0x40 | (l << 5) | (d_lo << 2);
            out.push(token);
            out.push(d_hi);
        } else {
            // 1LLD_DDSS form, length 5..=8
            let l = (length - 5) as u8; // 0..3
            let token = 0x80 | (l << 5) | (d_lo << 2);
            out.push(token);
            out.push(d_hi);
        }
        return tok_idx;
    }

    if distance <= M3_MAX_DISTANCE {
        // 001L_LLLL form with LE16 offset trailing.
        let d = distance - 1;
        debug_assert!(d <= 0x3FFF);
        let tok_idx = out.len();
        if length <= 33 {
            let token = 0x20 | ((length - 2) as u8);
            out.push(token);
        } else {
            out.push(0x20);
            let mut rem = length - 33;
            while rem > 255 {
                out.push(0);
                rem -= 255;
            }
            out.push(rem as u8);
        }
        let off_word = (d as u16) << 2; // S = 0 for now (low 2 bits)
        out.push((off_word & 0xFF) as u8);
        out.push((off_word >> 8) as u8);
        return tok_idx;
    }

    // 0001_HLLL form — long-distance copy ≥16384.
    debug_assert!(distance <= M4_MAX_DISTANCE);
    let d = distance - M3_MAX_DISTANCE;
    let h = ((d >> 14) & 0x1) as u8;
    let d14 = (d & 0x3FFF) as u16;
    let tok_idx = out.len();
    if length <= 9 {
        let token = 0x10 | (h << 3) | ((length - 2) as u8);
        out.push(token);
    } else {
        let token = 0x10 | (h << 3);
        out.push(token);
        let mut rem = length - 9;
        while rem > 255 {
            out.push(0);
            rem -= 255;
        }
        out.push(rem as u8);
    }
    let off_word = d14 << 2; // S = 0 for now (low 2 bits)
    out.push((off_word & 0xFF) as u8);
    out.push((off_word >> 8) as u8);
    tok_idx
}

/// Patch the inline trailing-literal-count (n ∈ 1..=3) of the copy
/// instruction whose token byte is at `tok_idx`.
///
/// For the M2 forms (64..255) the count lives in the token's low 2 bits.
/// For the M3/M4 forms (16..63) it lives in the low 2 bits of the offset
/// word (whose `off_lo` byte is always the second-to-last byte the encoder
/// just wrote).
fn patch_inline_literal_count(out: &mut [u8], tok_idx: usize, n: usize) {
    debug_assert!((1..=3).contains(&n));
    let s = n as u8;
    let token = out[tok_idx];
    if token >= 0x40 {
        out[tok_idx] = (token & !0x03) | s;
    } else {
        let off_lo_idx = out.len() - 2;
        out[off_lo_idx] = (out[off_lo_idx] & !0x03) | s;
    }
}

/// Emit a standalone "long literal run" instruction using the `0000_LLLL`
/// form. Only valid when the decoder's state == 0 (i.e. the previous copy
/// instruction left S = 0, which is the encoder's default).
///
/// After this instruction the decoder's state is set to 4, which is exactly
/// the state the next copy instruction expects.
fn emit_long_literal_run(literals: &[u8], out: &mut Vec<u8>) {
    let n = literals.len();
    debug_assert!(n >= 4);
    if n <= 18 {
        // length = n; LLLL = n - 3 (range 1..=15).
        out.push((n - 3) as u8);
    } else {
        // length ≥ 19: LLLL = 0, then extension bytes encoding n - 18.
        out.push(0x00);
        let mut rem = n - 18;
        while rem > 255 {
            out.push(0);
            rem -= 255;
        }
        out.push(rem as u8);
    }
    out.extend_from_slice(literals);
}

/// Emit the canonical 3-byte end-of-stream marker.
fn emit_eos(out: &mut Vec<u8>) {
    out.extend_from_slice(&[0x11, 0x00, 0x00]);
}

// ─── decoder ──────────────────────────────────────────────────────────────

/// Decode one LZO1X-1 block from `input` into `out`.
///
/// `out` is cleared first. On success it contains the decompressed bytes.
/// Stops when the canonical end-of-stream marker is consumed.
///
/// `raw_max` bounds the decoded output: an LZO match instruction is only a
/// few bytes on the wire but can expand ~255× via length-extension bytes, so
/// without a ceiling a small malicious block could be coaxed into a
/// multi-gigabyte allocation (decompression bomb). Any literal or match
/// append that would push `out.len()` past `raw_max` returns
/// [`Error::Corrupt`]. Pass `usize::MAX` for trusted input.
pub fn decode_block(input: &[u8], out: &mut Vec<u8>, raw_max: usize) -> Result<(), Error> {
    out.clear();
    let n = input.len();
    if n == 0 {
        return Err(Error::UnexpectedEnd);
    }
    let mut ip = 0usize;
    // `state` is the decoder's running record of "literals emitted by the
    // most recent instruction (clipped to 0..=4)".
    let mut state: u8 = 0;

    // ─── first-byte special cases ────────────────────────────────────────
    let b0 = input[ip];
    if b0 == 17 && n >= 5 {
        // Bitstream version indicator (LZO-RLE v1+). Only recognised when
        // there's room for it AND for a body afterward; otherwise b0 == 17
        // is interpreted as the body's first instruction (a regular
        // 0001_HLLL byte). The kernel decoder uses the same heuristic.
        ip += 2;
        state = 0;
    } else if b0 == 16 {
        return Err(Error::Corrupt);
    } else if (18..=255).contains(&b0) {
        let lit_len = (b0 as usize) - 17;
        ip += 1;
        if ip + lit_len > n {
            return Err(Error::UnexpectedEnd);
        }
        if out.len() + lit_len > raw_max {
            return Err(Error::Corrupt);
        }
        out.extend_from_slice(&input[ip..ip + lit_len]);
        ip += lit_len;
        state = if lit_len <= 3 { lit_len as u8 } else { 4 };
    } else {
        // b0 ∈ 0..=15 (or b0 == 17 with n < 5): fall through to the main
        // loop with state == 0.
    }

    // ─── main loop ───────────────────────────────────────────────────────
    loop {
        if ip >= n {
            return Err(Error::UnexpectedEnd);
        }
        let t = input[ip];
        ip += 1;

        if t < 16 {
            if state == 0 {
                // Long literal copy: length = 3 + (LLLL or 15 + ext).
                let mut lit_len = t as usize;
                if lit_len == 0 {
                    lit_len = 15;
                    loop {
                        if ip >= n {
                            return Err(Error::UnexpectedEnd);
                        }
                        let b = input[ip];
                        ip += 1;
                        if b == 0 {
                            lit_len = lit_len.checked_add(255).ok_or(Error::Corrupt)?;
                        } else {
                            lit_len = lit_len.checked_add(b as usize).ok_or(Error::Corrupt)?;
                            break;
                        }
                    }
                }
                lit_len += 3;
                if ip + lit_len > n {
                    return Err(Error::UnexpectedEnd);
                }
                if out.len() + lit_len > raw_max {
                    return Err(Error::Corrupt);
                }
                out.extend_from_slice(&input[ip..ip + lit_len]);
                ip += lit_len;
                state = 4;
                continue;
            } else if state <= 3 {
                // 2-byte copy from ≤ 1 KiB.
                let d_lo = ((t >> 2) & 0x3) as usize;
                let s = (t & 0x3) as usize;
                if ip >= n {
                    return Err(Error::UnexpectedEnd);
                }
                let h = input[ip] as usize;
                ip += 1;
                let distance = (h << 2) + d_lo + 1;
                copy_match(out, distance, 2, raw_max)?;
                handle_trailing_literals(input, &mut ip, out, s, &mut state, n, raw_max)?;
                continue;
            } else {
                // state == 4: 3-byte copy from 2049..3072.
                let d_lo = ((t >> 2) & 0x3) as usize;
                let s = (t & 0x3) as usize;
                if ip >= n {
                    return Err(Error::UnexpectedEnd);
                }
                let h = input[ip] as usize;
                ip += 1;
                let distance = (h << 2) + d_lo + 2049;
                copy_match(out, distance, 3, raw_max)?;
                handle_trailing_literals(input, &mut ip, out, s, &mut state, n, raw_max)?;
                continue;
            }
        } else if t < 32 {
            // 0001_HLLL — long-distance copy.
            let h_bit = ((t >> 3) & 0x1) as usize;
            let mut length = (t & 0x7) as usize;
            if length == 0 {
                length = 7;
                loop {
                    if ip >= n {
                        return Err(Error::UnexpectedEnd);
                    }
                    let b = input[ip];
                    ip += 1;
                    if b == 0 {
                        length = length.checked_add(255).ok_or(Error::Corrupt)?;
                    } else {
                        length = length.checked_add(b as usize).ok_or(Error::Corrupt)?;
                        break;
                    }
                }
            }
            length += 2;
            if ip + 2 > n {
                return Err(Error::UnexpectedEnd);
            }
            let off_word = (input[ip] as usize) | ((input[ip + 1] as usize) << 8);
            ip += 2;
            let s = off_word & 0x3;
            let d = off_word >> 2;
            let distance = 16384 + (h_bit << 14) + d;
            if distance == 16384 {
                return Ok(()); // end of stream
            }
            copy_match(out, distance, length, raw_max)?;
            handle_trailing_literals(input, &mut ip, out, s, &mut state, n, raw_max)?;
            continue;
        } else if t < 64 {
            // 001L_LLLL — copy from ≤16 KiB.
            let mut length = (t & 0x1F) as usize;
            if length == 0 {
                length = 31;
                loop {
                    if ip >= n {
                        return Err(Error::UnexpectedEnd);
                    }
                    let b = input[ip];
                    ip += 1;
                    if b == 0 {
                        length = length.checked_add(255).ok_or(Error::Corrupt)?;
                    } else {
                        length = length.checked_add(b as usize).ok_or(Error::Corrupt)?;
                        break;
                    }
                }
            }
            length += 2;
            if ip + 2 > n {
                return Err(Error::UnexpectedEnd);
            }
            let off_word = (input[ip] as usize) | ((input[ip + 1] as usize) << 8);
            ip += 2;
            let s = off_word & 0x3;
            let d = off_word >> 2;
            let distance = d + 1;
            copy_match(out, distance, length, raw_max)?;
            handle_trailing_literals(input, &mut ip, out, s, &mut state, n, raw_max)?;
            continue;
        } else if t < 128 {
            // 01LD_DDSS — copy 3..4 bytes within 2 KiB.
            let l = ((t >> 5) & 0x1) as usize;
            let d_lo = ((t >> 2) & 0x7) as usize;
            let s = (t & 0x3) as usize;
            let length = 3 + l;
            if ip >= n {
                return Err(Error::UnexpectedEnd);
            }
            let h = input[ip] as usize;
            ip += 1;
            let distance = (h << 3) + d_lo + 1;
            copy_match(out, distance, length, raw_max)?;
            handle_trailing_literals(input, &mut ip, out, s, &mut state, n, raw_max)?;
            continue;
        } else {
            // 1LLD_DDSS — copy 5..8 bytes within 2 KiB.
            let l = ((t >> 5) & 0x3) as usize;
            let d_lo = ((t >> 2) & 0x7) as usize;
            let s = (t & 0x3) as usize;
            let length = 5 + l;
            if ip >= n {
                return Err(Error::UnexpectedEnd);
            }
            let h = input[ip] as usize;
            ip += 1;
            let distance = (h << 3) + d_lo + 1;
            copy_match(out, distance, length, raw_max)?;
            handle_trailing_literals(input, &mut ip, out, s, &mut state, n, raw_max)?;
            continue;
        }
    }
}

/// Copy `length` bytes from `out[out.len()-distance..]` (LZ77
/// overlapping-match semantics) onto the end of `out`.
fn copy_match(
    out: &mut Vec<u8>,
    distance: usize,
    length: usize,
    raw_max: usize,
) -> Result<(), Error> {
    if distance == 0 || distance > out.len() {
        return Err(Error::InvalidDistance);
    }
    // A match instruction is only a few bytes on the wire but can emit a
    // large `length` (extension bytes multiply it ~255×). Reject copies that
    // would push the output past the caller's ceiling before materializing
    // them — otherwise a tiny block can drive a multi-GiB allocation.
    if out.len() + length > raw_max {
        return Err(Error::Corrupt);
    }
    let start = out.len() - distance;
    if distance >= length {
        // Non-overlapping: collapses to memcpy.
        out.extend_from_within(start..start + length);
    } else if distance == 1 {
        // Byte-splat.
        let b = out[start];
        out.resize(out.len() + length, b);
    } else {
        // Self-overlap (LZ77 RLE-style): copy in `distance`-sized chunks. Each
        // round duplicates the tail produced so far, doubling the source
        // region, so the loop runs a logarithmic number of times.
        let mut remaining = length;
        while remaining > 0 {
            let chunk = remaining.min(distance);
            let s = out.len() - distance;
            out.extend_from_within(s..s + chunk);
            remaining -= chunk;
        }
    }
    Ok(())
}

/// Append `s ∈ 0..=3` trailing literals after a copy and update `state`.
fn handle_trailing_literals(
    input: &[u8],
    ip: &mut usize,
    out: &mut Vec<u8>,
    s: usize,
    state: &mut u8,
    n: usize,
    raw_max: usize,
) -> Result<(), Error> {
    if s == 0 {
        *state = 0;
        return Ok(());
    }
    if *ip + s > n {
        return Err(Error::UnexpectedEnd);
    }
    if out.len() + s > raw_max {
        return Err(Error::Corrupt);
    }
    out.extend_from_slice(&input[*ip..*ip + s]);
    *ip += s;
    *state = s as u8;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(data: &[u8]) {
        let mut encoded = Vec::new();
        encode_block(data, &mut encoded);
        let mut decoded = Vec::new();
        decode_block(&encoded, &mut decoded, usize::MAX).expect("decode");
        assert_eq!(decoded, data);
    }

    #[test]
    fn empty() {
        round_trip(&[]);
    }

    #[test]
    fn rejects_output_exceeding_raw_max() {
        // A highly compressible payload decodes to far more than its block
        // size. Decoding with a tight `raw_max` must fail before allocating
        // past it; decoding with a cap >= the real size must still succeed.
        let data = alloc::vec![0xABu8; 4096];
        let mut encoded = Vec::new();
        encode_block(&data, &mut encoded);
        assert!(encoded.len() < data.len(), "should compress");

        let mut decoded = Vec::new();
        let err = decode_block(&encoded, &mut decoded, 1024).unwrap_err();
        assert!(matches!(err, Error::Corrupt));

        let mut ok = Vec::new();
        decode_block(&encoded, &mut ok, data.len()).expect("decode at exact cap");
        assert_eq!(ok, data);
    }

    #[test]
    fn short() {
        round_trip(b"hello");
    }

    #[test]
    fn short_no_match() {
        round_trip(b"abcdefghij");
    }

    #[test]
    fn repeated_pattern() {
        round_trip(b"abcabcabcabcabcabcabcabcabc");
    }

    #[test]
    fn ascii_text() {
        let mut v = Vec::new();
        for _ in 0..100 {
            v.extend_from_slice(b"the quick brown fox jumps over the lazy dog. ");
        }
        round_trip(&v);
    }

    #[test]
    fn run_of_one_byte() {
        let v = alloc::vec![b'Z'; 4096];
        round_trip(&v);
    }

    #[test]
    fn lorem_progression() {
        // Each size catches a different failure mode of the previous
        // implementation (initial run vs first match vs long literal run).
        let lorem = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. ";
        for &sz in &[100usize, 127, 200, 500, 1000, 2000, 4000, 8000, 16384] {
            let mut data = Vec::new();
            while data.len() < sz {
                data.extend_from_slice(lorem);
            }
            data.truncate(sz);
            round_trip(&data);
        }
    }
}
