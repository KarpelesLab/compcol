//! LZ4 block-format codec (single-block, in-memory).
//!
//! Reference: <https://github.com/lz4/lz4/blob/dev/doc/lz4_Block_format.md>.
//!
//! These functions operate on a single LZ4 block: they take a complete input
//! buffer and produce a complete output buffer. The streaming wrapper in
//! [`super`] is responsible for chunking arbitrarily large inputs into blocks
//! of bounded size and re-assembling them on decode.

use alloc::vec::Vec;

use crate::error::Error;

/// Minimum match length encoded by an LZ4 sequence.
const MIN_MATCH: usize = 4;
/// Maximum back-reference distance (16-bit LE offset).
const MAX_DISTANCE: usize = 65_535;
/// Last 5 bytes of every block must be literals.
const LAST_LITERALS: usize = 5;
/// Last match must start at least 12 bytes before the end of the block.
const MFLIMIT: usize = 12;

/// Size of the encoder's hash table (entries are `u32` block offsets).
///
/// 12 bits = 4096 entries × 4 bytes = 16 KiB scratch — small enough to fit
/// comfortably in cache, large enough to find most useful matches in a
/// 64 KiB block.
const HASH_LOG: u32 = 12;
const HASH_TABLE_SIZE: usize = 1 << HASH_LOG;

/// Sentinel for an empty hash slot. `u32::MAX` is safe because block sizes
/// are bounded by the streaming wrapper to fit in a `u32`.
const HASH_EMPTY: u32 = u32::MAX;

/// Hash 4 bytes down to `HASH_LOG` bits.
///
/// Uses the classic LZ4 multiply-and-shift hash. `2654435761` is Knuth's
/// golden-ratio constant — any good odd 32-bit multiplier works here.
#[inline]
fn hash4(bytes: [u8; 4]) -> usize {
    let v = u32::from_le_bytes(bytes);
    ((v.wrapping_mul(2_654_435_761)) >> (32 - HASH_LOG)) as usize
}

/// Worst-case encoded-length bound for `input_len` bytes of input.
///
/// Matches the canonical `LZ4_compressBound` formula. The encoder uses this
/// to right-size its scratch buffer.
pub fn compress_bound(input_len: usize) -> usize {
    input_len + (input_len / 255) + 16
}

/// Encode `input` as a single LZ4 block into `out` (which is cleared first).
///
/// Returns the number of bytes written. Inputs of any length are accepted;
/// inputs shorter than `MFLIMIT + 1` are emitted as a literal-only sequence,
/// as required by the spec.
pub fn encode_block(input: &[u8], out: &mut Vec<u8>) {
    out.clear();
    if input.is_empty() {
        return;
    }

    // Tiny inputs cannot contain a match satisfying the end-of-block rules
    // (last match start >= MFLIMIT before block end, last 5 bytes literals).
    if input.len() < MFLIMIT + 1 {
        emit_last_literals(input, out);
        return;
    }

    let mut table = [HASH_EMPTY; HASH_TABLE_SIZE];

    let mut ip: usize = 0; // current input position
    let mut anchor: usize = 0; // start of the current pending literal run

    // Position of the last byte we are allowed to start a match at. Anything
    // past `match_limit` must be emitted as trailing literals.
    let match_limit = input.len() - MFLIMIT;
    // Position of the last byte we are allowed to *read* a 4-byte hash from.
    let hash_limit = input.len() - MIN_MATCH - LAST_LITERALS;

    // The first byte is never the start of a match in our matcher; insert it
    // into the table so subsequent positions can refer to it.
    let mut next_ip = ip;

    while next_ip <= match_limit {
        ip = next_ip;
        let mut step = 1usize;
        let mut search_match_nb = 1u32 << 6; // skip-step accelerator

        // Hash-table probe loop: walk forward until we find a 4-byte match or
        // run out of room. The probe step grows the further we search without
        // a hit — this is LZ4's "acceleration" trick: it makes the matcher
        // skip faster over incompressible data instead of probing every byte.
        let mut match_pos;
        loop {
            if ip > hash_limit {
                emit_last_literals(&input[anchor..], out);
                return;
            }
            let h = hash4([input[ip], input[ip + 1], input[ip + 2], input[ip + 3]]);
            let candidate = table[h];
            table[h] = ip as u32;

            // Found a candidate within the 64 KiB window with a real 4-byte
            // match? Take it.
            if candidate != HASH_EMPTY {
                let cand = candidate as usize;
                if ip - cand <= MAX_DISTANCE
                    && input[cand] == input[ip]
                    && input[cand + 1] == input[ip + 1]
                    && input[cand + 2] == input[ip + 2]
                    && input[cand + 3] == input[ip + 3]
                {
                    match_pos = cand;
                    break;
                }
            }
            next_ip = ip + step;
            step = (search_match_nb >> 6) as usize;
            search_match_nb += 1;
            ip = next_ip;
        }

        // We have ip and match_pos with a guaranteed 4-byte match. Try to
        // walk the match backward as far as the anchor (catch a longer match
        // when the hash hit fell on a misaligned start).
        while ip > anchor && match_pos > 0 && input[ip - 1] == input[match_pos - 1] {
            ip -= 1;
            match_pos -= 1;
        }

        // Extend the match forward. The forward limit is `input.len() -
        // LAST_LITERALS` because the last 5 bytes must be literals.
        let forward_limit = input.len() - LAST_LITERALS;
        let mut match_len = MIN_MATCH;
        while ip + match_len < forward_limit
            && input[match_pos + match_len] == input[ip + match_len]
        {
            match_len += 1;
        }

        // Emit the sequence: literals from anchor..ip, then offset, then
        // match-length excess.
        let literal_len = ip - anchor;
        let offset = (ip - match_pos) as u16;
        let match_excess = match_len - MIN_MATCH;
        emit_sequence(&input[anchor..ip], literal_len, offset, match_excess, out);

        ip += match_len;
        anchor = ip;

        // Seed the hash table for the byte two before the match end. This
        // helps the *next* probe find a longer back-reference without
        // pointing at the position we're about to probe ourselves (which
        // would yield a zero-distance match).
        if ip >= 2 {
            let seed = ip - 2;
            if seed + MIN_MATCH <= input.len() {
                let h = hash4([
                    input[seed],
                    input[seed + 1],
                    input[seed + 2],
                    input[seed + 3],
                ]);
                table[h] = seed as u32;
            }
        }
        next_ip = ip;
    }

    // Emit anything past the last match as literals.
    emit_last_literals(&input[anchor..], out);
}

/// Write a single sequence (literals + offset + match-length excess).
fn emit_sequence(
    literals: &[u8],
    literal_len: usize,
    offset: u16,
    match_excess: usize,
    out: &mut Vec<u8>,
) {
    let lit_high = if literal_len >= 15 {
        15u8
    } else {
        literal_len as u8
    };
    let match_low = if match_excess >= 15 {
        15u8
    } else {
        match_excess as u8
    };
    let token = (lit_high << 4) | match_low;
    out.push(token);

    if literal_len >= 15 {
        let mut rem = literal_len - 15;
        while rem >= 255 {
            out.push(255);
            rem -= 255;
        }
        out.push(rem as u8);
    }
    out.extend_from_slice(literals);

    out.push((offset & 0xFF) as u8);
    out.push((offset >> 8) as u8);

    if match_excess >= 15 {
        let mut rem = match_excess - 15;
        while rem >= 255 {
            out.push(255);
            rem -= 255;
        }
        out.push(rem as u8);
    }
}

/// Emit the closing literal-only sequence (no offset, no match-length).
fn emit_last_literals(literals: &[u8], out: &mut Vec<u8>) {
    let literal_len = literals.len();
    let lit_high = if literal_len >= 15 {
        15u8
    } else {
        literal_len as u8
    };
    out.push(lit_high << 4);
    if literal_len >= 15 {
        let mut rem = literal_len - 15;
        while rem >= 255 {
            out.push(255);
            rem -= 255;
        }
        out.push(rem as u8);
    }
    out.extend_from_slice(literals);
}

/// Decode one LZ4 block from `input` into `out`.
///
/// `out` is cleared first; on success it contains the decompressed bytes.
pub fn decode_block(input: &[u8], out: &mut Vec<u8>) -> Result<(), Error> {
    out.clear();
    if input.is_empty() {
        return Ok(());
    }
    let mut ip = 0usize;
    let n = input.len();

    loop {
        if ip >= n {
            return Err(Error::UnexpectedEnd);
        }
        let token = input[ip];
        ip += 1;

        // Literal length
        let mut lit_len = (token >> 4) as usize;
        if lit_len == 15 {
            loop {
                if ip >= n {
                    return Err(Error::UnexpectedEnd);
                }
                let b = input[ip];
                ip += 1;
                lit_len = lit_len.checked_add(b as usize).ok_or(Error::Corrupt)?;
                if b != 255 {
                    break;
                }
            }
        }

        if lit_len > 0 {
            if ip + lit_len > n {
                return Err(Error::UnexpectedEnd);
            }
            out.extend_from_slice(&input[ip..ip + lit_len]);
            ip += lit_len;
        }

        // End of block: if no offset bytes follow, this was the closing
        // literal-only sequence.
        if ip == n {
            return Ok(());
        }
        if ip + 2 > n {
            return Err(Error::UnexpectedEnd);
        }
        let offset = (input[ip] as usize) | ((input[ip + 1] as usize) << 8);
        ip += 2;
        if offset == 0 {
            return Err(Error::InvalidDistance);
        }
        if offset > out.len() {
            return Err(Error::InvalidDistance);
        }

        let mut match_excess = (token & 0x0F) as usize;
        if match_excess == 15 {
            loop {
                if ip >= n {
                    return Err(Error::UnexpectedEnd);
                }
                let b = input[ip];
                ip += 1;
                match_excess = match_excess.checked_add(b as usize).ok_or(Error::Corrupt)?;
                if b != 255 {
                    break;
                }
            }
        }
        let match_len = MIN_MATCH + match_excess;

        // Non-overlapping match collapses to memcpy; offset==1 is a byte-splat;
        // otherwise replicate byte-by-byte to handle LZ77 self-overlap.
        let start = out.len() - offset;
        if offset >= match_len {
            out.extend_from_within(start..start + match_len);
        } else if offset == 1 {
            let b = out[start];
            out.resize(out.len() + match_len, b);
        } else {
            for i in 0..match_len {
                let b = out[start + i];
                out.push(b);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(data: &[u8]) {
        let mut encoded = Vec::new();
        encode_block(data, &mut encoded);
        let mut decoded = Vec::new();
        decode_block(&encoded, &mut decoded).expect("decode");
        assert_eq!(decoded, data);
    }

    #[test]
    fn empty() {
        round_trip(&[]);
    }

    #[test]
    fn short() {
        round_trip(b"hello");
    }

    #[test]
    fn run() {
        let v = alloc::vec![b'a'; 1024];
        round_trip(&v);
    }

    #[test]
    fn repeated_text() {
        let mut v = Vec::new();
        for _ in 0..200 {
            v.extend_from_slice(b"the quick brown fox jumps over the lazy dog. ");
        }
        round_trip(&v);
    }
}
