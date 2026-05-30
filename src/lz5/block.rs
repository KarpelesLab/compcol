//! Single-block Lizard decode (compressed-block payload only).
//!
//! The frame-level state machine in [`super`] hands us the bytes of a
//! single compressed block — everything between the 4-byte block-size
//! word and the start of the next block. We parse the block-internal
//! 1-byte `compressionLevel`, then the 1-byte `res` flag, then either
//! the in-block uncompressed payload (when `res == 0x80`) or the
//! five sub-streams (lengths, offset16, offset24, flags, literals).
//!
//! Only the LZ4-codeword sequence loop (levels 10..=19, 30..=39) with
//! all sub-streams stored raw (no Huffman entropy stage) is
//! implemented; everything else returns [`Error::Unsupported`].

use alloc::vec::Vec;

use crate::error::Error;

const LIZARD_MIN_CLEVEL: u8 = 10;
const LIZARD_MAX_CLEVEL: u8 = 49;

const FLAG_LITERALS: u8 = 0x01;
const FLAG_FLAGS: u8 = 0x02;
const FLAG_OFFSET16: u8 = 0x04;
const FLAG_OFFSET24: u8 = 0x08;
const FLAG_LEN: u8 = 0x10;
const FLAG_UNCOMPRESSED: u8 = 0x80;

const MINMATCH: usize = 4;
const RUN_BITS_LZ4: u32 = 4;
const RUN_MASK_LZ4: u8 = (1 << RUN_BITS_LZ4) - 1;
const ML_MASK_LZ4: u8 = (1 << RUN_BITS_LZ4) - 1;

/// Type alias kept exported for callers that want to instantiate the
/// internal LZ4-codeword decoder directly (e.g. for tests). The
/// frame-level [`Decoder`](super::Decoder) is the normal entry point.
pub struct Lz4ModeDecoder;

/// Decode a single Lizard compressed block (everything between the
/// frame's 4-byte block-size word and the start of the next block).
/// `out` is appended to — the caller is expected to clear it first if
/// they want only this block's bytes.
pub fn decode_compressed_block(input: &[u8], out: &mut Vec<u8>) -> Result<(), Error> {
    if input.is_empty() {
        return Err(Error::UnexpectedEnd);
    }
    let mut ip = 0usize;

    // compressionLevel byte.
    let clevel = input[ip];
    ip += 1;
    if !(LIZARD_MIN_CLEVEL..=LIZARD_MAX_CLEVEL).contains(&clevel) {
        return Err(Error::Corrupt);
    }
    // Lizard groups levels by decompression strategy:
    //   10..=19, 30..=39  →  LZ4 codewords (this build supports)
    //   20..=29, 40..=49  →  LIZv1 codewords (not supported)
    let is_lz4_mode = matches!(clevel, 10..=19 | 30..=39);
    if !is_lz4_mode {
        return Err(Error::Unsupported);
    }

    // res flag byte.
    if ip >= input.len() {
        return Err(Error::UnexpectedEnd);
    }
    let res = input[ip];
    ip += 1;

    if res == FLAG_UNCOMPRESSED {
        // In-block uncompressed: 3-byte LE length + raw bytes.
        if ip + 3 > input.len() {
            return Err(Error::UnexpectedEnd);
        }
        let length = read_u24_le(&input[ip..]);
        ip += 3;
        if ip + length > input.len() {
            return Err(Error::UnexpectedEnd);
        }
        out.extend_from_slice(&input[ip..ip + length]);
        return Ok(());
    }

    // LIZARD_FLAG_LEN being set on the block-flag byte is the reference
    // implementation's "reserved / not used" marker; reject so unknown
    // future variants don't decode silently to wrong output.
    if res & FLAG_LEN != 0 {
        return Err(Error::Corrupt);
    }
    // Any Huffman bit set on a sub-stream means we'd need to FSE-Huffman
    // decode that stream. Out of scope.
    let huffman_bits = res & (FLAG_LITERALS | FLAG_FLAGS | FLAG_OFFSET16 | FLAG_OFFSET24);
    if huffman_bits != 0 {
        return Err(Error::Unsupported);
    }

    // Parse five raw streams: lengths, offset16, offset24, flags, literals.
    // Each starts with a 3-byte LE length.
    let lengths = read_raw_stream(input, &mut ip)?;
    let offset16 = read_raw_stream(input, &mut ip)?;
    let offset24 = read_raw_stream(input, &mut ip)?;
    let flags = read_raw_stream(input, &mut ip)?;
    let literals = read_raw_stream(input, &mut ip)?;
    if ip != input.len() {
        return Err(Error::Corrupt);
    }

    // In LZ4 mode the lengths/offset16/offset24 streams must be empty
    // — the encoder packs all length-extensions and offsets inline in
    // the literals stream. Reject any extra bytes there as malformed.
    if !lengths.is_empty() || !offset16.is_empty() || !offset24.is_empty() {
        return Err(Error::Corrupt);
    }

    decode_lz4_sequences(flags, literals, out)
}

/// Read one raw (non-Huffman) sub-stream: 3-byte LE length + bytes.
/// Returns the byte slice and advances `ip` past it.
fn read_raw_stream<'a>(input: &'a [u8], ip: &mut usize) -> Result<&'a [u8], Error> {
    if *ip + 3 > input.len() {
        return Err(Error::UnexpectedEnd);
    }
    let len = read_u24_le(&input[*ip..]);
    *ip += 3;
    if *ip + len > input.len() {
        return Err(Error::UnexpectedEnd);
    }
    let slice = &input[*ip..*ip + len];
    *ip += len;
    Ok(slice)
}

#[inline]
fn read_u24_le(s: &[u8]) -> usize {
    (s[0] as usize) | ((s[1] as usize) << 8) | ((s[2] as usize) << 16)
}

/// LZ4-codeword sequence loop.
///
/// In Lizard's LZ4 mode the `flags` stream contains the sequence
/// tokens (one byte per sequence). The `literals` stream contains, in
/// order, the literal bytes themselves, the 1- or 3-byte literal-length
/// extension bytes, the 2-byte offsets, and the 1- or 3-byte
/// match-length extension bytes. All bytes that the token's literal-run
/// and match-length nibbles refer to are pulled from `literals` via a
/// single cursor that advances through it monotonically.
fn decode_lz4_sequences(flags: &[u8], literals: &[u8], out: &mut Vec<u8>) -> Result<(), Error> {
    let mut lp = 0usize; // literals-stream cursor

    for &token in flags {
        // Literal length: low nibble of the token (LZ4 mode reverses
        // the LZ4-classic ordering — literal length is low, match
        // length excess is high). Sentinel value 15 → one or three
        // extension bytes follow.
        let mut lit_len = (token & RUN_MASK_LZ4) as usize;
        if lit_len == RUN_MASK_LZ4 as usize {
            lit_len = read_length_ext(literals, &mut lp)?;
            lit_len = lit_len
                .checked_add(RUN_MASK_LZ4 as usize)
                .ok_or(Error::Corrupt)?;
        }
        // Copy literals.
        if lit_len > 0 {
            if lp + lit_len > literals.len() {
                return Err(Error::UnexpectedEnd);
            }
            out.extend_from_slice(&literals[lp..lp + lit_len]);
            lp += lit_len;
        }
        // 2-byte LE offset.
        if lp + 2 > literals.len() {
            return Err(Error::UnexpectedEnd);
        }
        let offset = (literals[lp] as usize) | ((literals[lp + 1] as usize) << 8);
        lp += 2;
        if offset == 0 {
            return Err(Error::InvalidDistance);
        }
        if offset > out.len() {
            return Err(Error::InvalidDistance);
        }
        // Match length: high nibble of the token. Sentinel 15 → ext.
        let mut match_excess = ((token >> RUN_BITS_LZ4) & ML_MASK_LZ4) as usize;
        if match_excess == ML_MASK_LZ4 as usize {
            match_excess = read_length_ext(literals, &mut lp)?;
            match_excess = match_excess
                .checked_add(ML_MASK_LZ4 as usize)
                .ok_or(Error::Corrupt)?;
        }
        let match_len = match_excess.checked_add(MINMATCH).ok_or(Error::Corrupt)?;
        copy_match(out, offset, match_len)?;
    }

    // Trailing literals: everything left in the literals stream is
    // copied verbatim after the last token.
    if lp < literals.len() {
        out.extend_from_slice(&literals[lp..]);
    }
    Ok(())
}

/// Read one literal-/match-length extension from the literals stream.
/// Encoding (per `lizard_compress_lz4.h`):
/// - byte < 254 → length = byte
/// - byte == 254 → length = next 2 bytes LE
/// - byte == 255 → length = next 3 bytes LE
fn read_length_ext(literals: &[u8], lp: &mut usize) -> Result<usize, Error> {
    if *lp >= literals.len() {
        return Err(Error::UnexpectedEnd);
    }
    let first = literals[*lp];
    if first < 254 {
        *lp += 1;
        return Ok(first as usize);
    }
    if first == 254 {
        if *lp + 3 > literals.len() {
            return Err(Error::UnexpectedEnd);
        }
        let v = (literals[*lp + 1] as usize) | ((literals[*lp + 2] as usize) << 8);
        *lp += 3;
        return Ok(v);
    }
    // first == 255
    if *lp + 4 > literals.len() {
        return Err(Error::UnexpectedEnd);
    }
    let v = (literals[*lp + 1] as usize)
        | ((literals[*lp + 2] as usize) << 8)
        | ((literals[*lp + 3] as usize) << 16);
    *lp += 4;
    Ok(v)
}

/// Copy `match_len` bytes from `out[start..]` to the end of `out`,
/// where `start = out.len() - offset`. Handles LZ77 self-overlap
/// (offset < match_len) byte-by-byte.
fn copy_match(out: &mut Vec<u8>, offset: usize, match_len: usize) -> Result<(), Error> {
    if offset > out.len() {
        return Err(Error::InvalidDistance);
    }
    let start = out.len() - offset;
    if offset >= match_len {
        // Non-overlapping — bulk copy.
        out.extend_from_within(start..start + match_len);
    } else if offset == 1 {
        // Byte-splat fast path (very common: long runs of one byte).
        let b = out[start];
        out.resize(out.len() + match_len, b);
    } else {
        // Self-overlap — must copy byte-by-byte so back-references read
        // from already-written bytes.
        for i in 0..match_len {
            let b = out[start + i];
            out.push(b);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tiny synthetic block (no sequences, just trailing literals): the
    // simplest possible LZ4-mode block — produces a few bytes of output.
    #[test]
    fn empty_flags_just_literals() {
        // compressionLevel=10, res=0, len streams all empty, flags=0 bytes,
        // literals = "hi" (2 bytes).
        let mut block = alloc::vec![
            10, // clevel
            0,  // res
            0, 0, 0, // lengths len 0
            0, 0, 0, // offset16 len 0
            0, 0, 0, // offset24 len 0
            0, 0, 0, // flags len 0
            2, 0, 0, // literals len 2
        ];
        block.extend_from_slice(b"hi");

        let mut out = Vec::new();
        decode_compressed_block(&block, &mut out).unwrap();
        assert_eq!(out, b"hi");
    }

    #[test]
    fn in_block_uncompressed() {
        let mut block = alloc::vec![
            10,                // clevel
            FLAG_UNCOMPRESSED, // res with uncompressed bit
            5,
            0,
            0, // 3-byte length = 5
        ];
        block.extend_from_slice(b"hello");

        let mut out = Vec::new();
        decode_compressed_block(&block, &mut out).unwrap();
        assert_eq!(out, b"hello");
    }

    #[test]
    fn rejects_lizv1_mode() {
        let block = alloc::vec![20u8, 0u8]; // clevel 20 → LIZv1
        let mut out = Vec::new();
        assert_eq!(
            decode_compressed_block(&block, &mut out),
            Err(Error::Unsupported)
        );
    }

    #[test]
    fn rejects_huffman_flag() {
        let block = alloc::vec![10u8, FLAG_LITERALS]; // Huffman literals stream
        let mut out = Vec::new();
        assert_eq!(
            decode_compressed_block(&block, &mut out),
            Err(Error::Unsupported)
        );
    }

    #[test]
    fn rejects_bad_clevel() {
        let block = alloc::vec![9u8, 0u8];
        let mut out = Vec::new();
        assert_eq!(
            decode_compressed_block(&block, &mut out),
            Err(Error::Corrupt)
        );
    }
}
