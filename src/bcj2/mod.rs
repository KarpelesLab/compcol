//! BCJ2 — the 4-stream x86 branch-conversion filter (7-Zip filter id
//! `0303011B`), from the public-domain LZMA SDK.
//!
//! BCJ2 is the version-2 x86 branch converter. Like the single-stream
//! [`crate::bcj`] x86 filter it rewrites the relative operands of `CALL`
//! (`E8`), `JMP` (`E9`), and the two-byte conditional jumps (`0F 80`..`0F 8F`)
//! into absolute form for better compression — but instead of one in-place
//! stream it splits the data across **four** streams:
//!
//! * **main** — every byte of the original input *except* the 4-byte operands
//!   of the branches that were converted;
//! * **call** — the 4-byte big-endian absolute targets of converted `E8`
//!   calls;
//! * **jump** — the 4-byte big-endian absolute targets of converted `E9` /
//!   `0F 8x` jumps;
//! * **rc** — an LZMA-style range-coded control stream carrying one bit per
//!   branch *candidate* (an `E8`/`E9`/`0F 8x` opcode) that says whether that
//!   candidate was converted.
//!
//! In a 7z archive the main/call/jump streams are usually each LZMA-coded
//! and the rc stream stored raw; this module operates on the already-
//! decompressed four streams.
//!
//! ## API shape
//!
//! The 4-input shape does not fit the single-input
//! [`Decoder`](crate::Decoder) trait, so BCJ2 is exposed as a dedicated
//! function: [`decode`] takes the four input slices plus the known output
//! length and returns the recombined bytes. [`encode`] performs the inverse
//! split (used for round-trip testing and by callers that want to produce
//! BCJ2 streams).
//!
//! ## Algorithm
//!
//! Decode walks `main` byte by byte, copying to the output and tracking the
//! running output position `ip`. When it reaches a branch candidate it
//! decodes one range-coded bit (using a probability model selected by the
//! opcode kind: `E8`→`2 + prev_byte`, `E9`→`1`, `0F 8x`→`0`). If the bit is
//! set, the operand was converted: the 4-byte big-endian absolute target is
//! read from `call` (for `E8`) or `jump` (for `E9`/`0F 8x`), turned back
//! into a relative `dest = abs - (ip + 4)`, and written little-endian to the
//! output. Otherwise the operand bytes follow literally in `main`.
//!
//! All address arithmetic is modular (`wrapping_*`) — overflow of the 32-bit
//! operand field is the format's defined behaviour, so `encode`∘`decode` is
//! the exact identity.

#![cfg_attr(docsrs, doc(cfg(feature = "bcj2")))]

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;

// ─── range coder constants (LZMA-style, shared by BCJ2's rc stream) ─────────

const NUM_MODEL_BITS: u32 = 11;
const BIT_MODEL_TOTAL: u32 = 1 << NUM_MODEL_BITS;
const TOP_VALUE: u32 = 1 << 24;
const NUM_MOVE_BITS: u32 = 5;
const PROB_INIT: u16 = (BIT_MODEL_TOTAL / 2) as u16;

/// Number of probability models: index 0 = `0F 8x`, index 1 = `E9`,
/// indices `2..=257` = `E8` keyed by the previous byte.
const NUM_PROBS: usize = 2 + 256;

/// True if `b` is `0xE8` (CALL) or `0xE9` (JMP).
#[inline]
fn is_e8_e9(b: u8) -> bool {
    b == 0xE8 || b == 0xE9
}

/// True if `(prev, b)` form a `0F 80`..`0F 8F` two-byte conditional jump.
#[inline]
fn is_jcc(prev: u8, b: u8) -> bool {
    prev == 0x0F && (b & 0xF0) == 0x80
}

// ─── range decoder over the rc stream ───────────────────────────────────────

struct RangeDec<'a> {
    rc: &'a [u8],
    pos: usize,
    range: u32,
    code: u32,
}

impl<'a> RangeDec<'a> {
    /// Initialise from 5 leading bytes of the rc stream (first must be 0).
    fn new(rc: &'a [u8]) -> Result<Self, Error> {
        if rc.len() < 5 {
            return Err(Error::UnexpectedEnd);
        }
        if rc[0] != 0 {
            return Err(Error::Corrupt);
        }
        let code = ((rc[1] as u32) << 24)
            | ((rc[2] as u32) << 16)
            | ((rc[3] as u32) << 8)
            | (rc[4] as u32);
        Ok(Self {
            rc,
            pos: 5,
            range: 0xFFFF_FFFF,
            code,
        })
    }

    #[inline]
    fn normalize(&mut self) -> Result<(), Error> {
        if self.range < TOP_VALUE {
            if self.pos >= self.rc.len() {
                return Err(Error::UnexpectedEnd);
            }
            self.range <<= 8;
            self.code = (self.code << 8) | self.rc[self.pos] as u32;
            self.pos += 1;
        }
        Ok(())
    }

    #[inline]
    fn decode_bit(&mut self, prob: &mut u16) -> Result<u32, Error> {
        self.normalize()?;
        let ttt = *prob as u32;
        let bound = (self.range >> NUM_MODEL_BITS) * ttt;
        if self.code < bound {
            self.range = bound;
            *prob = (ttt + ((BIT_MODEL_TOTAL - ttt) >> NUM_MOVE_BITS)) as u16;
            Ok(0)
        } else {
            self.range -= bound;
            self.code -= bound;
            *prob = (ttt - (ttt >> NUM_MOVE_BITS)) as u16;
            Ok(1)
        }
    }
}

/// Select the probability-model index for a branch candidate.
#[inline]
fn prob_index(b: u8, prev: u8) -> usize {
    if b == 0xE8 {
        2 + prev as usize
    } else if b == 0xE9 {
        1
    } else {
        // 0F 8x conditional jump.
        0
    }
}

/// Decode a BCJ2-filtered payload from its four streams.
///
/// * `main` — the main stream (bulk bytes, converted operands removed).
/// * `call` — big-endian absolute targets of converted `E8` calls.
/// * `jump` — big-endian absolute targets of converted `E9` / `0F 8x` jumps.
/// * `rc` — the range-coded control stream.
/// * `out_len` — the exact length of the recombined output (known from the
///   7z coder's unpack size).
///
/// Returns the recombined, un-filtered bytes. On any malformed / truncated
/// stream returns [`Error::Corrupt`] or [`Error::UnexpectedEnd`]; never
/// panics.
pub fn decode(
    main: &[u8],
    call: &[u8],
    jump: &[u8],
    rc: &[u8],
    out_len: usize,
) -> Result<Vec<u8>, Error> {
    let mut out = vec![0u8; out_len];
    let mut probs = [PROB_INIT; NUM_PROBS];
    let mut rd = RangeDec::new(rc)?;

    let mut mp = 0usize; // main cursor
    let mut cp = 0usize; // call cursor
    let mut jp = 0usize; // jump cursor
    let mut op = 0usize; // output cursor (== ip)
    let mut prev: u8 = 0;

    while op < out_len {
        // Copy the next main byte.
        if mp >= main.len() {
            return Err(Error::UnexpectedEnd);
        }
        let b = main[mp];
        mp += 1;
        out[op] = b;
        op += 1;

        // Is this a branch candidate? `prev` is still the byte before `b`.
        let candidate = is_e8_e9(b) || is_jcc(prev, b);
        let prev_before = prev;
        prev = b;
        if !candidate {
            continue;
        }
        let pidx = prob_index(b, prev_before);
        let bit = rd.decode_bit(&mut probs[pidx])?;
        if bit == 0 {
            // Not converted: operand bytes (if any) are literal in `main`.
            continue;
        }
        // Converted branch: its 4-byte operand must fit in the output.
        if out_len - op < 4 {
            return Err(Error::Corrupt);
        }

        // Converted: read 4-byte big-endian absolute from the right stream.
        let (src, sp) = if b == 0xE8 {
            (call, &mut cp)
        } else {
            (jump, &mut jp)
        };
        if *sp + 4 > src.len() {
            return Err(Error::UnexpectedEnd);
        }
        let abs = ((src[*sp] as u32) << 24)
            | ((src[*sp + 1] as u32) << 16)
            | ((src[*sp + 2] as u32) << 8)
            | (src[*sp + 3] as u32);
        *sp += 4;

        // dest = abs - (ip + 4), where ip is the output position of the
        // operand's first byte (== current `op`).
        let ip4 = (op as u32).wrapping_add(4);
        let dest = abs.wrapping_sub(ip4);

        out[op] = dest as u8;
        out[op + 1] = (dest >> 8) as u8;
        out[op + 2] = (dest >> 16) as u8;
        out[op + 3] = (dest >> 24) as u8;
        op += 4;
        prev = (dest >> 24) as u8;
    }

    Ok(out)
}

/// Encode (split) a raw payload into the four BCJ2 streams.
///
/// Returns `(main, call, jump, rc)`. This is the inverse of [`decode`]:
/// `decode(&main, &call, &jump, &rc, input.len())` reproduces `input`.
///
/// The conversion policy matches the reference: every `E8` / `E9` /
/// `0F 8x` whose 4-byte operand fits within the input is converted.
pub fn encode(input: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut main = Vec::with_capacity(input.len());
    let mut call = Vec::new();
    let mut jump = Vec::new();
    let mut probs = [PROB_INIT; NUM_PROBS];
    let mut rc = RangeEnc::new();

    let mut i = 0usize;
    let mut prev: u8 = 0;
    while i < input.len() {
        let b = input[i];
        main.push(b);
        // `prev` is still the byte before `b` here.
        let candidate = is_e8_e9(b) || is_jcc(prev, b);
        let pidx = prob_index(b, prev);
        prev = b;
        i += 1;
        if !candidate {
            continue;
        }
        // Operand would occupy input[i..i+4] (i already past `b`).
        if i + 4 > input.len() {
            // No room for an operand → cannot convert; emit a 0 bit so the
            // decoder's range coder stays in sync.
            rc.encode_bit(&mut probs[pidx], 0);
            continue;
        }
        // Convert: compute absolute target from the little-endian relative.
        let rel = (input[i] as u32)
            | ((input[i + 1] as u32) << 8)
            | ((input[i + 2] as u32) << 16)
            | ((input[i + 3] as u32) << 24);
        // dest at decode = abs - (operand_pos + 4); operand_pos == i here.
        let ip4 = (i as u32).wrapping_add(4);
        let abs = rel.wrapping_add(ip4);
        rc.encode_bit(&mut probs[pidx], 1);
        let stream = if b == 0xE8 { &mut call } else { &mut jump };
        stream.push((abs >> 24) as u8);
        stream.push((abs >> 16) as u8);
        stream.push((abs >> 8) as u8);
        stream.push(abs as u8);
        // The 4 operand bytes are NOT copied to main.
        i += 4;
        prev = (rel >> 24) as u8;
    }

    let rc = rc.finish();
    (main, call, jump, rc)
}

// ─── range encoder for the rc stream ────────────────────────────────────────

struct RangeEnc {
    low: u64,
    range: u32,
    cache: u8,
    cache_size: u64,
    out: Vec<u8>,
}

impl RangeEnc {
    fn new() -> Self {
        Self {
            low: 0,
            range: 0xFFFF_FFFF,
            cache: 0,
            cache_size: 1,
            out: Vec::new(),
        }
    }

    fn shift_low(&mut self) {
        if self.low < 0xFF00_0000 || self.low > 0xFFFF_FFFF {
            let mut temp = self.cache;
            loop {
                self.out
                    .push((temp as u64).wrapping_add(self.low >> 32) as u8);
                temp = 0xFF;
                self.cache_size -= 1;
                if self.cache_size == 0 {
                    break;
                }
            }
            self.cache = (self.low >> 24) as u8;
        }
        self.cache_size += 1;
        self.low = (self.low << 8) & 0xFFFF_FFFF;
    }

    fn encode_bit(&mut self, prob: &mut u16, bit: u32) {
        let ttt = *prob as u32;
        let bound = (self.range >> NUM_MODEL_BITS) * ttt;
        if bit == 0 {
            self.range = bound;
            *prob = (ttt + ((BIT_MODEL_TOTAL - ttt) >> NUM_MOVE_BITS)) as u16;
        } else {
            self.low += bound as u64;
            self.range -= bound;
            *prob = (ttt - (ttt >> NUM_MOVE_BITS)) as u16;
        }
        while self.range < TOP_VALUE {
            self.range <<= 8;
            self.shift_low();
        }
    }

    fn finish(mut self) -> Vec<u8> {
        for _ in 0..5 {
            self.shift_low();
        }
        self.out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(input: &[u8]) {
        let (main, call, jump, rc) = encode(input);
        let got = decode(&main, &call, &jump, &rc, input.len()).expect("decode");
        assert_eq!(got, input, "BCJ2 round-trip mismatch");
    }

    #[test]
    fn empty() {
        roundtrip(&[]);
    }

    #[test]
    fn no_branches() {
        roundtrip(b"the quick brown fox jumps over the lazy dog");
        roundtrip(&[0u8; 64]);
        let ramp: Vec<u8> = (0..200u32)
            .map(|x| x as u8)
            .filter(|&b| b != 0xE8 && b != 0xE9)
            .collect();
        roundtrip(&ramp);
    }

    #[test]
    fn single_call() {
        // E8 + 4-byte rel operand, then trailing bytes.
        let mut v = vec![0x90u8, 0x90, 0xE8, 0x10, 0x20, 0x30, 0x00, 0xCC, 0xCC];
        v.extend_from_slice(&[0u8; 8]);
        roundtrip(&v);
    }

    #[test]
    fn single_jmp() {
        let v = vec![0xE9u8, 0xFF, 0xFF, 0xFF, 0xFF, 0x90, 0x90, 0x90, 0x90, 0x90];
        roundtrip(&v);
    }

    #[test]
    fn conditional_jump() {
        // 0F 84 (je) + operand.
        let v = vec![0x0Fu8, 0x84, 0x01, 0x02, 0x03, 0x04, 0x55, 0x55, 0x55, 0x55];
        roundtrip(&v);
    }

    #[test]
    fn mixed_branches() {
        let mut v = Vec::new();
        for k in 0..50u32 {
            v.push(0x55);
            v.push(0xE8);
            v.extend_from_slice(&(k.wrapping_mul(7)).to_le_bytes());
            v.push(0xE9);
            v.extend_from_slice(&(0x1000u32.wrapping_sub(k)).to_le_bytes());
            v.push(0x0F);
            v.push(0x8C);
            v.extend_from_slice(&k.to_le_bytes());
        }
        v.extend_from_slice(&[0u8; 8]); // tail so last operands fit
        roundtrip(&v);
    }

    #[test]
    fn branch_opcode_at_tail_no_room() {
        // E8 with fewer than 4 bytes after it: must not convert, round-trips.
        roundtrip(&[0x90, 0x90, 0xE8, 0x01, 0x02]); // only 2 bytes after E8
        roundtrip(&[0xE9]); // bare opcode at end
        roundtrip(&[0x0F, 0x80]); // bare jcc at end
    }

    #[test]
    fn e8_prev_byte_models() {
        // Many E8s with different preceding bytes exercise the per-prev
        // probability models (indices 2..258).
        let mut v = Vec::new();
        for p in 0..256u32 {
            v.push(p as u8);
            v.push(0xE8);
            v.extend_from_slice(&p.to_le_bytes());
        }
        v.extend_from_slice(&[0u8; 8]);
        roundtrip(&v);
    }

    #[test]
    fn truncated_rc_errors() {
        // rc stream shorter than 5 bytes → UnexpectedEnd.
        assert_eq!(
            decode(&[0x90], &[], &[], &[0, 0], 1),
            Err(Error::UnexpectedEnd)
        );
    }

    #[test]
    fn bad_rc_first_byte() {
        assert_eq!(
            decode(&[0x90], &[], &[], &[1, 0, 0, 0, 0], 1),
            Err(Error::Corrupt)
        );
    }

    #[test]
    fn truncated_main_errors() {
        // out_len exceeds what main + conversions can supply.
        let (main, call, jump, rc) = encode(b"abc");
        assert_eq!(
            decode(&main, &call, &jump, &rc, 100),
            Err(Error::UnexpectedEnd)
        );
    }
}
