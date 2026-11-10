//! Lizard block decode (the payload of one compressed frame block).
//!
//! The frame-level state machine in [`super`] hands us the bytes of one
//! compressed frame block — everything between the 4-byte block-size
//! word and the start of the next block: a 1-byte `compressionLevel`,
//! then one sub-block per 128 KiB of input. A sub-block is a flag byte
//! followed by a stored run (flag `0x80`) or by five sub-streams
//! (lengths, offset16, offset24, tokens, literals), each stored raw or
//! Huffman-coded as its flag bit says.
//!
//! Both sequence formats are decoded: LZ4 codewords (levels 10..=19 and
//! 30..=39) and LIZv1 codewords (20..=29 and 40..=49). The layouts follow
//! `doc/lizard_Block_format.md` of the reference distribution; where that
//! document is silent or ambiguous they were settled against streams
//! written by the reference CLI, which is also what the fixtures in
//! `tests/lz5.rs` come from.

use alloc::vec::Vec;

use crate::error::Error;
use crate::huff0::bitreader::RevBitReader;
use crate::huff0::huffman::{HuffTable, decode_huffman_tree};

const LIZARD_MIN_CLEVEL: u8 = 10;
const LIZARD_MAX_CLEVEL: u8 = 49;

const FLAG_LITERALS: u8 = 0x01;
const FLAG_FLAGS: u8 = 0x02;
const FLAG_OFFSET16: u8 = 0x04;
const FLAG_OFFSET24: u8 = 0x08;
const FLAG_LEN: u8 = 0x10;
const FLAG_UNCOMPRESSED: u8 = 0x80;

const FLAG_ALL_STREAMS: u8 = FLAG_LITERALS | FLAG_FLAGS | FLAG_OFFSET16 | FLAG_OFFSET24 | FLAG_LEN;

/// Ceiling on what one Huffman-coded sub-stream may regenerate. A
/// sub-block covers at most 128 KiB of input, and no stream of it is
/// larger than that by more than a small factor.
const MAX_HUFFMAN_STREAM: usize = 512 * 1024;

/// A LIZv1 token below 32 carries a match of `token + 16` bytes.
const LIZV1_OFF24_MIN_MATCH: usize = 16;
/// The "last offset" a LIZv1 block starts with.
const LIZV1_INITIAL_OFFSET: usize = 0;

const MINMATCH: usize = 4;
const RUN_BITS_LZ4: u32 = 4;
const RUN_MASK_LZ4: u8 = (1 << RUN_BITS_LZ4) - 1;
const ML_MASK_LZ4: u8 = (1 << RUN_BITS_LZ4) - 1;

/// Type alias kept exported for callers that want to instantiate the
/// internal LZ4-codeword decoder directly (e.g. for tests). The
/// frame-level [`Decoder`](super::Decoder) is the normal entry point.
pub struct Lz4ModeDecoder;

/// Decode a single Lizard compressed frame block (everything between the
/// frame's 4-byte block-size word and the start of the next block).
///
/// That payload is one `compressionLevel` byte followed by one or more
/// *sub-blocks*, each covering at most 128 KiB of input ("Division into
/// blocks" in `doc/lizard_Block_format.md`): a flag byte, then either a
/// stored run or the five sub-streams. Sub-blocks share one sliding
/// window, so a match may reach back into the sub-blocks before it. The
/// reference CLI's default frame block is 4 MiB, so any input over
/// 128 KiB yields several sub-blocks per frame block.
///
/// `out` is appended to. What it already holds is history: the output
/// of the earlier blocks of a block-dependent frame, which matches may
/// refer to as well.
///
/// `cap` is the per-frame ceiling on this block's decoded size, not
/// counting that history. Output
/// is checked against it *before* every append (literal run, match copy,
/// in-block-uncompressed payload, trailing literals) so a malformed
/// stream cannot balloon `out` to gigabytes before the size is rejected.
/// A valid block always stays `<= cap`. Overflow is reported as
/// `Error::OutputLimitExceeded`, and as nothing else, so the caller can
/// tell it from other damage: the frame decoder passes the smaller of the
/// frame's block size and the caller's remaining output budget, and turns
/// the error back into `Error::Corrupt` when it was the frame's own block
/// size that was exceeded.
pub fn decode_compressed_block(input: &[u8], out: &mut Vec<u8>, cap: usize) -> Result<(), Error> {
    if input.is_empty() {
        return Err(Error::UnexpectedEnd);
    }
    // From here on `cap` is a ceiling on `out.len()`, history included.
    let cap = out.len().saturating_add(cap);
    let mut ip = 0usize;

    // compressionLevel byte.
    let clevel = input[ip];
    ip += 1;
    if !(LIZARD_MIN_CLEVEL..=LIZARD_MAX_CLEVEL).contains(&clevel) {
        return Err(Error::Corrupt);
    }
    // Lizard groups levels by sequence format:
    //   10..=19, 30..=39  →  LZ4 codewords
    //   20..=29, 40..=49  →  LIZv1 codewords
    // (30 and up are the same two formats with the Huffman stage enabled,
    // but each sub-stream says for itself whether it is Huffman-coded.)
    let lizv1 = matches!(clevel, 20..=29 | 40..=49);

    // At least one sub-block follows the level byte.
    if ip >= input.len() {
        return Err(Error::UnexpectedEnd);
    }
    // The offset a LIZv1 "repeat" token reuses carries over from one
    // sub-block to the next.
    let mut last_offset = LIZV1_INITIAL_OFFSET;
    while ip < input.len() {
        ip = decode_sub_block(input, ip, out, cap, lizv1, &mut last_offset)?;
    }
    Ok(())
}

/// Decode the sub-block starting at `input[ip]` (its flag byte) onto the
/// end of `out`, and return the position just past it.
fn decode_sub_block(
    input: &[u8],
    mut ip: usize,
    out: &mut Vec<u8>,
    cap: usize,
    lizv1: bool,
    last_offset: &mut usize,
) -> Result<usize, Error> {
    let res = input[ip];
    ip += 1;

    if res & FLAG_UNCOMPRESSED != 0 {
        // Stored sub-block: 3-byte LE length + raw bytes.
        if res != FLAG_UNCOMPRESSED {
            return Err(Error::Corrupt);
        }
        if ip + 3 > input.len() {
            return Err(Error::UnexpectedEnd);
        }
        let length = read_u24_le(&input[ip..]);
        ip += 3;
        if length > input.len() - ip {
            return Err(Error::UnexpectedEnd);
        }
        if length > cap - out.len() {
            return Err(Error::OutputLimitExceeded);
        }
        out.extend_from_slice(&input[ip..ip + length]);
        return Ok(ip + length);
    }
    if res & !FLAG_ALL_STREAMS != 0 {
        return Err(Error::Corrupt);
    }

    // Five sub-streams, in this order, each stored raw or Huffman-coded
    // as its flag bit says.
    let lengths = read_stream(input, &mut ip, res & FLAG_LEN != 0)?;
    let offset16 = read_stream(input, &mut ip, res & FLAG_OFFSET16 != 0)?;
    let offset24 = read_stream(input, &mut ip, res & FLAG_OFFSET24 != 0)?;
    let tokens = read_stream(input, &mut ip, res & FLAG_FLAGS != 0)?;
    let literals = read_stream(input, &mut ip, res & FLAG_LITERALS != 0)?;

    if lizv1 {
        decode_lizv1_sequences(
            &Streams {
                lengths: &lengths,
                offset16: &offset16,
                offset24: &offset24,
                tokens: &tokens,
                literals: &literals,
            },
            out,
            cap,
            last_offset,
        )?;
    } else {
        // In LZ4 mode the lengths/offset16/offset24 streams are unused: the
        // encoder packs all length extensions and offsets inline in the
        // literals stream. Reject any bytes there as malformed.
        if !lengths.is_empty() || !offset16.is_empty() || !offset24.is_empty() {
            return Err(Error::Corrupt);
        }
        decode_lz4_sequences(&tokens, &literals, out, cap)?;
    }
    Ok(ip)
}

/// One sub-stream: borrowed from the block when stored raw, owned when
/// it had to be Huffman-decoded.
enum Stream<'a> {
    Raw(&'a [u8]),
    Decoded(Vec<u8>),
}

impl core::ops::Deref for Stream<'_> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match self {
            Stream::Raw(s) => s,
            Stream::Decoded(v) => v,
        }
    }
}

/// Read one sub-stream and advance `ip` past it.
///
/// Raw: a 3-byte LE length, then that many bytes. Huffman-coded: a 3-byte
/// LE regenerated length, a 3-byte LE compressed length, then the
/// compressed bytes.
fn read_stream<'a>(input: &'a [u8], ip: &mut usize, huffman: bool) -> Result<Stream<'a>, Error> {
    if !huffman {
        return read_raw_stream(input, ip).map(Stream::Raw);
    }
    if input.len() - *ip < 6 {
        return Err(Error::UnexpectedEnd);
    }
    let regen = read_u24_le(&input[*ip..]);
    let comp = read_u24_le(&input[*ip + 3..]);
    *ip += 6;
    if comp > input.len() - *ip {
        return Err(Error::UnexpectedEnd);
    }
    let payload = &input[*ip..*ip + comp];
    *ip += comp;
    if regen > MAX_HUFFMAN_STREAM {
        return Err(Error::Corrupt);
    }
    huff0_decompress(payload, regen).map(Stream::Decoded)
}

/// Decode a Huff0 block as the generic `HUF_compress` of Yann Collet's
/// FiniteStateEntropy library writes it: a Huffman tree description (the
/// same one zstd uses for its literals), a 6-byte jump table of three LE
/// u16 stream sizes, then four bitstreams, the first three regenerating
/// `ceil(n / 4)` bytes each and the fourth the rest.
///
/// Which decoding table a decoder builds for it (single- or
/// double-symbol) is its own business and does not change the result.
fn huff0_decompress(src: &[u8], regen: usize) -> Result<Vec<u8>, Error> {
    let (table, used) = decode_huffman_tree(src)?;
    let body = &src[used..];
    if body.len() < 6 {
        return Err(Error::Corrupt);
    }
    let l1 = u16::from_le_bytes([body[0], body[1]]) as usize;
    let l2 = u16::from_le_bytes([body[2], body[3]]) as usize;
    let l3 = u16::from_le_bytes([body[4], body[5]]) as usize;
    let streams = &body[6..];
    let l123 = l1 + l2 + l3;
    if l123 > streams.len() {
        return Err(Error::Corrupt);
    }
    let per = regen.div_ceil(4);
    let last = regen.checked_sub(3 * per).ok_or(Error::Corrupt)?;
    let mut out = Vec::with_capacity(regen);
    decode_huff_stream(&streams[..l1], &table, per, &mut out)?;
    decode_huff_stream(&streams[l1..l1 + l2], &table, per, &mut out)?;
    decode_huff_stream(&streams[l1 + l2..l123], &table, per, &mut out)?;
    decode_huff_stream(&streams[l123..], &table, last, &mut out)?;
    Ok(out)
}

/// Decode exactly `n` symbols from one Huffman bitstream, which must hold
/// those symbols and nothing more.
fn decode_huff_stream(
    data: &[u8],
    table: &HuffTable,
    n: usize,
    out: &mut Vec<u8>,
) -> Result<(), Error> {
    let mut br = RevBitReader::new(data)?;
    for _ in 0..n {
        out.push(table.decode(&mut br)?);
    }
    if br.remaining() != 0 {
        return Err(Error::Corrupt);
    }
    Ok(())
}

/// The five sub-streams of a LIZv1 sub-block.
struct Streams<'a> {
    lengths: &'a [u8],
    offset16: &'a [u8],
    offset24: &'a [u8],
    tokens: &'a [u8],
    literals: &'a [u8],
}

/// LIZv1 sequence loop (levels 20..=29 and 40..=49), as described under
/// "Lizard token decompression" in `doc/lizard_Block_format.md`.
///
/// Each token byte is one of:
///
/// * `0..=31` — no literals; a 24-bit offset from the offset24 stream;
///   match length `token + 16`, and for token 31 a further length from
///   the lengths stream.
/// * `0_MMMM_LLL` with `MMMM >= 4` — `LLL` literals, a 16-bit offset from
///   the offset16 stream, match length `MMMM`.
/// * `1_MMMM_LLL` — `LLL` literals, the last offset again, match length
///   `MMMM` (which may be 0: literals only).
///
/// `LLL == 7` and `MMMM == 15` each add a length from the lengths stream.
/// Whatever is left of the literals stream after the last token ends the
/// sub-block.
fn decode_lizv1_sequences(
    s: &Streams<'_>,
    out: &mut Vec<u8>,
    cap: usize,
    last_offset: &mut usize,
) -> Result<(), Error> {
    let (mut lenp, mut o16p, mut o24p, mut litp) = (0usize, 0usize, 0usize, 0usize);
    // Without a lengths stream the length extensions sit inline in the
    // literals stream, where each is read at the point it is needed.
    let inline_lengths = s.lengths.is_empty();
    macro_rules! length_ext {
        () => {
            if inline_lengths {
                read_length_ext(s.literals, &mut litp)?
            } else {
                read_length_ext(s.lengths, &mut lenp)?
            }
        };
    }

    for &token in s.tokens {
        let match_len = if token < 32 {
            if s.offset24.len() - o24p < 3 {
                return Err(Error::Corrupt);
            }
            *last_offset = read_u24_le(&s.offset24[o24p..]);
            o24p += 3;
            let mut len = token as usize + LIZV1_OFF24_MIN_MATCH;
            if token == 31 {
                len = len.checked_add(length_ext!()).ok_or(Error::Corrupt)?;
            }
            len
        } else {
            let mut lit_len = (token & 7) as usize;
            if lit_len == 7 {
                lit_len += length_ext!();
            }
            if lit_len > s.literals.len() - litp {
                return Err(Error::Corrupt);
            }
            if lit_len > cap - out.len() {
                return Err(Error::OutputLimitExceeded);
            }
            out.extend_from_slice(&s.literals[litp..litp + lit_len]);
            litp += lit_len;

            if token & 0x80 == 0 {
                if s.offset16.len() - o16p < 2 {
                    return Err(Error::Corrupt);
                }
                *last_offset =
                    u16::from_le_bytes([s.offset16[o16p], s.offset16[o16p + 1]]) as usize;
                o16p += 2;
            }
            let mut len = ((token >> 3) & 15) as usize;
            if len == 15 {
                len += length_ext!();
            }
            len
        };
        if match_len > 0 {
            if *last_offset == 0 {
                return Err(Error::InvalidDistance);
            }
            copy_match(out, *last_offset, match_len, cap)?;
        }
    }

    // Every stream but the literals must be used up exactly.
    if lenp != s.lengths.len() || o16p != s.offset16.len() || o24p != s.offset24.len() {
        return Err(Error::Corrupt);
    }
    let tail = &s.literals[litp..];
    if tail.len() > cap - out.len() {
        return Err(Error::OutputLimitExceeded);
    }
    out.extend_from_slice(tail);
    Ok(())
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
fn decode_lz4_sequences(
    flags: &[u8],
    literals: &[u8],
    out: &mut Vec<u8>,
    cap: usize,
) -> Result<(), Error> {
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
            if out.len() + lit_len > cap {
                return Err(Error::OutputLimitExceeded);
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
        copy_match(out, offset, match_len, cap)?;
    }

    // Trailing literals: everything left in the literals stream is
    // copied verbatim after the last token.
    if lp < literals.len() {
        let tail = literals.len() - lp;
        if out.len() + tail > cap {
            return Err(Error::OutputLimitExceeded);
        }
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
/// (offset < match_len) byte-by-byte. Rejects (`Error::Corrupt`) any
/// match that would grow `out` past `cap` before copying a single byte.
fn copy_match(out: &mut Vec<u8>, offset: usize, match_len: usize, cap: usize) -> Result<(), Error> {
    if offset > out.len() {
        return Err(Error::InvalidDistance);
    }
    if out.len() + match_len > cap {
        return Err(Error::OutputLimitExceeded);
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
        // Self-overlap — copy in `offset`-sized chunks. Each round duplicates
        // the tail produced so far, doubling the source region, so the loop
        // runs a logarithmic number of times instead of once per byte.
        let mut remaining = match_len;
        while remaining > 0 {
            let chunk = remaining.min(offset);
            let s = out.len() - offset;
            out.extend_from_within(s..s + chunk);
            remaining -= chunk;
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
        decode_compressed_block(&block, &mut out, usize::MAX).unwrap();
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
        decode_compressed_block(&block, &mut out, usize::MAX).unwrap();
        assert_eq!(out, b"hello");
    }

    /// A LIZv1 sub-block built by hand: every token kind, with the
    /// length extensions inline in the literals stream.
    #[test]
    fn lizv1_tokens() {
        // tokens:
        //   0x2f = 0_0101_111: 7+ literals (ext 1 -> 8), offset16, match 5
        //   0xf9 = 1_1111_001: 1 literal, last offset, match 15+ (ext 3 -> 18)
        //   0x81 = 1_0000_001: 1 literal, no match
        //   0x00: offset24, match 16
        let literals = b"\x01abcdefgh!\x03?tail";
        let mut block = alloc::vec![20u8, 0];
        block.extend_from_slice(&[0, 0, 0]); // lengths
        block.extend_from_slice(&[2, 0, 0, 8, 0]); // offset16: 8
        block.extend_from_slice(&[3, 0, 0, 27, 0, 0]); // offset24: 27
        block.extend_from_slice(&[4, 0, 0, 0x2f, 0xf9, 0x81, 0x00]);
        block.extend_from_slice(&[literals.len() as u8, 0, 0]);
        block.extend_from_slice(literals);

        let mut want = b"abcdefgh".to_vec();
        want.extend_from_slice(b"abcde"); // match 5 at 8
        want.push(b'!');
        for _ in 0..18 {
            want.push(want[want.len() - 8]); // match 18 at 8
        }
        want.push(b'?');
        for _ in 0..16 {
            want.push(want[want.len() - 27]); // match 16 at 27
        }
        want.extend_from_slice(b"tail");

        let mut out = Vec::new();
        decode_compressed_block(&block, &mut out, usize::MAX).unwrap();
        assert_eq!(out, want);

        // The same sequences with a separate lengths stream.
        let literals = b"abcdefgh!?tail";
        let mut block = alloc::vec![20u8, 0];
        block.extend_from_slice(&[2, 0, 0, 1, 3]); // lengths
        block.extend_from_slice(&[2, 0, 0, 8, 0]);
        block.extend_from_slice(&[3, 0, 0, 27, 0, 0]);
        block.extend_from_slice(&[4, 0, 0, 0x2f, 0xf9, 0x81, 0x00]);
        block.extend_from_slice(&[literals.len() as u8, 0, 0]);
        block.extend_from_slice(literals);
        let mut out = Vec::new();
        decode_compressed_block(&block, &mut out, usize::MAX).unwrap();
        assert_eq!(out, want);
    }

    #[test]
    fn lizv1_rejects_bad_sequences() {
        let build = |off16: &[u8], off24: &[u8], tokens: &[u8], literals: &[u8]| {
            let mut b = alloc::vec![20u8, 0, 0, 0, 0];
            for s in [off16, off24, tokens, literals] {
                b.extend_from_slice(&[s.len() as u8, 0, 0]);
                b.extend_from_slice(s);
            }
            b
        };
        let run = |b: &[u8]| {
            let mut out = Vec::new();
            decode_compressed_block(b, &mut out, 1 << 16)
        };
        // A repeat match before any offset was set.
        assert_eq!(
            run(&build(&[], &[], &[0xa1], b"x")),
            Err(Error::InvalidDistance)
        );
        // An offset reaching before the start of the output.
        assert_eq!(
            run(&build(&[2, 0], &[], &[0x21], b"x")),
            Err(Error::InvalidDistance)
        );
        // A token with no offset left to read.
        assert_eq!(run(&build(&[], &[], &[0x21], b"x")), Err(Error::Corrupt));
        assert_eq!(run(&build(&[], &[1, 0], &[0x00], b"")), Err(Error::Corrupt));
        // Offsets nobody used.
        assert_eq!(
            run(&build(&[1, 0, 1, 0], &[], &[0x21], b"x")),
            Err(Error::Corrupt)
        );
        // A match longer than the block may hold: reported as the cap
        // being hit, which the frame decoder turns back into `Corrupt`
        // when the cap was the frame's block size (see tests/lz5.rs,
        // `block_larger_than_the_frame_block_size_is_still_corrupt`).
        assert_eq!(
            run(&build(&[1, 0], &[], &[0x79], b"x\xff\xff\xff\xff")),
            Err(Error::OutputLimitExceeded)
        );
    }

    #[test]
    fn rejects_truncated_huffman_stream() {
        // Huffman-coded literals stream whose header is cut short, then
        // one whose payload is not a Huffman block.
        let mut out = Vec::new();
        assert_eq!(
            decode_compressed_block(&[10u8, FLAG_LITERALS], &mut out, usize::MAX),
            Err(Error::UnexpectedEnd)
        );
        let mut block = alloc::vec![10u8, FLAG_LITERALS, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        block.extend_from_slice(&[4, 0, 0, 3, 0, 0, 0xff, 0xff, 0xff]);
        assert!(decode_compressed_block(&block, &mut out, usize::MAX).is_err());
        // A regenerated size beyond what a sub-block can need.
        let mut block = alloc::vec![10u8, FLAG_LITERALS, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        block.extend_from_slice(&[0xff, 0xff, 0xff, 1, 0, 0, 0]);
        assert_eq!(
            decode_compressed_block(&block, &mut out, usize::MAX),
            Err(Error::Corrupt)
        );
    }

    #[test]
    fn rejects_bad_clevel() {
        let block = alloc::vec![9u8, 0u8];
        let mut out = Vec::new();
        assert_eq!(
            decode_compressed_block(&block, &mut out, usize::MAX),
            Err(Error::Corrupt)
        );
    }
}
