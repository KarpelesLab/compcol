//! Integration tests for the RAR 2.x decoder.
//!
//! RAR2 is a 1997-2002 format with effectively no surviving public fixture
//! corpus, so these tests stand up *synthetic* RAR2 bitstreams from scratch
//! using a small in-test encoder helper. The helper emits the exact byte
//! sequence the real RAR 2.x archiver would have written for a given block
//! shape, then feeds it through the production decoder.
//!
//! The non-audio path with literals + repeat-match symbols is the primary
//! integration target. Audio-block, short-match, and long-match coverage are
//! handled in unit tests inside `src/rar2/` because building a valid audio
//! block by hand is verbose enough that putting it here would obscure the
//! integration intent.
//!
//! Canonical v0.3 port: every call returns `(Progress, Status)` and the
//! loop dispatches on `Status` rather than inferring from byte counts.

#![cfg(feature = "rar2")]

use compcol::rar2::{Decoder, Encoder, Rar2};
use compcol::{Algorithm, Decoder as _, Encoder as _, Error, Status};

// ---------------------------------------------------------------------------
// Minimal MSB-first bit-writer for building synthetic RAR2 streams in tests.
// ---------------------------------------------------------------------------

struct BitWriter {
    out: Vec<u8>,
    cur: u32,
    nbits: u32,
}

impl BitWriter {
    fn new() -> Self {
        Self {
            out: Vec::new(),
            cur: 0,
            nbits: 0,
        }
    }
    /// Write the low `n` bits of `value`, MSB-first.
    fn write(&mut self, value: u32, n: u32) {
        assert!(n <= 24);
        // Shift current accumulator left to make room.
        self.cur = (self.cur << n) | (value & ((1 << n) - 1));
        self.nbits += n;
        while self.nbits >= 8 {
            let shift = self.nbits - 8;
            self.out.push(((self.cur >> shift) & 0xFF) as u8);
            self.cur &= (1 << shift) - 1;
            self.nbits -= 8;
        }
    }
    fn finish(mut self) -> Vec<u8> {
        if self.nbits > 0 {
            let pad = 8 - self.nbits;
            self.cur <<= pad;
            self.out.push(self.cur as u8);
        }
        self.out
    }
}

// ---------------------------------------------------------------------------
// Canonical Huffman code builder (matches RAR2's `shortestCodeIsZeros:YES`
// flavour: codes start at 0 for length 1, walk MSB-first).
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct Code {
    bits: u32,
    len: u32,
}

fn build_codes(lengths: &[u8]) -> Vec<Option<Code>> {
    let mut codes = vec![None; lengths.len()];
    let mut code: u32 = 0;
    let max_len: u32 = *lengths.iter().max().unwrap_or(&0) as u32;
    for length in 1..=max_len {
        for (i, &l) in lengths.iter().enumerate() {
            if l as u32 == length {
                codes[i] = Some(Code {
                    bits: code,
                    len: length,
                });
                code += 1;
            }
        }
        code <<= 1;
    }
    codes
}

// ---------------------------------------------------------------------------
// Helpers: write the pretree, then the length-table entries it encodes.
// ---------------------------------------------------------------------------

const PRETREE_SIZE: usize = 19;
const MAIN_TREE_SIZE: usize = 298;
const OFFSET_TREE_SIZE: usize = 48;
const LENGTH_TREE_SIZE: usize = 28;
const NON_AUDIO_LENGTHS: usize = MAIN_TREE_SIZE + OFFSET_TREE_SIZE + LENGTH_TREE_SIZE;

fn write_block_header(w: &mut BitWriter, audio: bool, keep_lengths: bool) {
    w.write(if audio { 1 } else { 0 }, 1);
    w.write(if keep_lengths { 1 } else { 0 }, 1);
}

/// Write a synthetic non-audio block whose main tree assigns a 1-bit code to
/// `literal_sym` and empty offset/length trees (we won't be hitting them in
/// the all-literals test).
///
/// Returns the assembled compressed bytes.
fn build_literals_only_block(literal_byte: u8, count: usize) -> Vec<u8> {
    // We need a *valid* main tree. The simplest configuration that lets us
    // emit literals only: a single length-1 main symbol — Rar2Huffman accepts
    // under-full trees with a single length-1 entry.
    let mut main_lens = vec![0u8; MAIN_TREE_SIZE];
    main_lens[literal_byte as usize] = 1;
    // Empty offset and length trees (all zeros) — we won't decode from them.
    let offset_lens = vec![0u8; OFFSET_TREE_SIZE];
    let length_lens = vec![0u8; LENGTH_TREE_SIZE];

    // Concatenate the three runs into the full length table.
    let mut full = Vec::with_capacity(NON_AUDIO_LENGTHS);
    full.extend(main_lens);
    full.extend(offset_lens);
    full.extend(length_lens);

    // Build a pretree that can encode this run of lengths.
    //   sym 0  ("delta 0") → length 1   (code "0")
    //   sym 1  ("delta 1") → length 2   (code "10")
    //   sym 18 ("run of zeros, 7 bits + 11") → length 2 (code "11")
    let mut pre_lens = [0u8; PRETREE_SIZE];
    pre_lens[0] = 1;
    pre_lens[1] = 2;
    pre_lens[18] = 2;
    let pre_codes = build_codes(&pre_lens);

    // Build a writer and emit:
    //   block header: audio=0, keep_lengths=0
    //   19 × 4-bit pretree lengths
    //   the encoded length table
    let mut w = BitWriter::new();
    write_block_header(&mut w, false, false);
    for &l in pre_lens.iter() {
        w.write(l as u32, 4);
    }

    // Now encode the 374 length-table entries.
    let mut i = 0usize;
    while i < NON_AUDIO_LENGTHS {
        if i == literal_byte as usize {
            let c = pre_codes[1].as_ref().unwrap();
            w.write(c.bits, c.len);
            i += 1;
        } else {
            // Count how many zero entries follow.
            let mut zero_run = 0usize;
            while i + zero_run < NON_AUDIO_LENGTHS
                && (i + zero_run) != literal_byte as usize
                && zero_run < 11 + 127
            {
                zero_run += 1;
            }
            if zero_run >= 11 {
                let c = pre_codes[18].as_ref().unwrap();
                w.write(c.bits, c.len);
                let n = (zero_run.min(138)) - 11;
                w.write(n as u32, 7);
                i += 11 + n;
            } else {
                let c = pre_codes[0].as_ref().unwrap();
                for _ in 0..zero_run {
                    w.write(c.bits, c.len);
                }
                i += zero_run;
            }
        }
    }

    // Main loop: write `count` copies of the literal symbol (1-bit code "0").
    for _ in 0..count {
        w.write(0, 1);
    }

    w.finish()
}

/// Build a non-audio block that supports literals + one short-match symbol.
///
/// Main tree:
///   - literal_byte: length 1 ("0")
///   - 261 (short match): length 1 ("1")
fn build_short_match_block(literal_byte: u8, short_extra: u32, sequence: &[u8]) -> Vec<u8> {
    let mut main_lens = vec![0u8; MAIN_TREE_SIZE];
    main_lens[literal_byte as usize] = 1;
    main_lens[261] = 1;
    let offset_lens = vec![0u8; OFFSET_TREE_SIZE];
    let length_lens = vec![0u8; LENGTH_TREE_SIZE];

    let mut full = Vec::with_capacity(NON_AUDIO_LENGTHS);
    full.extend(main_lens);
    full.extend(offset_lens);
    full.extend(length_lens);

    let mut pre_lens = [0u8; PRETREE_SIZE];
    pre_lens[0] = 1;
    pre_lens[1] = 2;
    pre_lens[18] = 2;
    let pre_codes = build_codes(&pre_lens);

    let mut w = BitWriter::new();
    write_block_header(&mut w, false, false);
    for &l in pre_lens.iter() {
        w.write(l as u32, 4);
    }

    let mut targets = [literal_byte as usize, 261usize];
    targets.sort();
    let mut cursor = 0usize;
    for &t in &targets {
        let gap = t - cursor;
        if gap > 0 {
            if gap >= 11 {
                let c = pre_codes[18].as_ref().unwrap();
                let n = gap.min(138) - 11;
                w.write(c.bits, c.len);
                w.write(n as u32, 7);
                cursor += 11 + n;
                while cursor < t {
                    let c0 = pre_codes[0].as_ref().unwrap();
                    w.write(c0.bits, c0.len);
                    cursor += 1;
                }
            } else {
                let c0 = pre_codes[0].as_ref().unwrap();
                for _ in 0..gap {
                    w.write(c0.bits, c0.len);
                }
                cursor += gap;
            }
        }
        let c1 = pre_codes[1].as_ref().unwrap();
        w.write(c1.bits, c1.len);
        cursor += 1;
    }
    let remaining = NON_AUDIO_LENGTHS - cursor;
    if remaining > 0 {
        let mut left = remaining;
        while left >= 11 {
            let c = pre_codes[18].as_ref().unwrap();
            let chunk = left.min(138);
            let n = chunk - 11;
            w.write(c.bits, c.len);
            w.write(n as u32, 7);
            left -= chunk;
        }
        let c0 = pre_codes[0].as_ref().unwrap();
        for _ in 0..left {
            w.write(c0.bits, c0.len);
        }
    }

    let (lit_code, match_code) = if (literal_byte as usize) < 261 {
        (0u32, 1u32)
    } else {
        unreachable!()
    };
    for &which in sequence {
        if which == 0 {
            w.write(lit_code, 1);
        } else {
            w.write(match_code, 1);
            // Symbol 261 needs 2 extra bits for the short offset.
            w.write(short_extra, 2);
        }
    }

    w.finish()
}

// ─── algorithm metadata ──────────────────────────────────────────────────

#[test]
fn algorithm_name_is_rar2() {
    assert_eq!(<Rar2 as Algorithm>::NAME, "rar2");
}

#[test]
fn rar2_algorithm_factory_produces_codec() {
    let _enc = <Rar2 as Algorithm>::encoder();
    let _dec = <Rar2 as Algorithm>::decoder();
}

// ─── encoder is permanently unsupported ──────────────────────────────────

#[test]
fn encoder_encode_is_unsupported() {
    let mut enc = Encoder::new();
    let mut out = [0u8; 16];
    assert_eq!(
        enc.encode(b"hello", &mut out).unwrap_err(),
        Error::Unsupported
    );
}

#[test]
fn encoder_finish_is_unsupported() {
    let mut enc = Encoder::new();
    let mut out = [0u8; 16];
    assert_eq!(enc.finish(&mut out).unwrap_err(), Error::Unsupported);
}

#[test]
fn encoder_reset_is_a_no_op() {
    // Encoder is stateless; reset must not panic.
    let mut enc = Encoder::new();
    enc.reset();
    let mut out = [0u8; 4];
    assert_eq!(enc.encode(b"x", &mut out).unwrap_err(), Error::Unsupported);
}

#[test]
fn algorithm_encoder_factory_is_unsupported() {
    let mut enc = <Rar2 as Algorithm>::encoder();
    let mut out = [0u8; 4];
    assert_eq!(enc.encode(b"x", &mut out).unwrap_err(), Error::Unsupported);
}

// ─── trivial / empty streams ─────────────────────────────────────────────

#[test]
fn decoder_zero_unpack_size_is_immediately_done() {
    let mut dec = Decoder::with_unpack_size(0);
    let mut out = [0u8; 1];
    let (p, status) = dec.finish(&mut out).expect("finish");
    assert!(matches!(status, Status::StreamEnd));
    assert_eq!(p.written, 0);
}

#[test]
fn decoder_default_constructor_is_zero_stream() {
    // `new()` without with_unpack_size behaves as a zero-length stream.
    let mut dec = <Rar2 as Algorithm>::decoder();
    let mut out = [0u8; 4];
    let (p, status) = dec.finish(&mut out).unwrap();
    assert!(matches!(status, Status::StreamEnd));
    assert_eq!(p.written, 0);
}

// ─── literals-only roundtrip ──────────────────────────────────────────────

#[test]
fn literals_only_block_roundtrip() {
    // Synthesize a block whose only main-tree symbol is the literal byte
    // `0x41` (== 'A') with a 1-bit code; the decoder should emit `count`
    // 'A' bytes.
    let count = 7;
    let bytes = build_literals_only_block(b'A', count);
    let mut dec = Decoder::with_unpack_size(count as u64);
    let (p, status) = dec.decode(&bytes, &mut []).unwrap();
    assert_eq!(p.consumed, bytes.len());
    // `decode` only buffers; `finish` runs the actual decode. With all input
    // consumed, the status should be InputEmpty.
    assert!(matches!(status, Status::InputEmpty));

    let mut out = vec![0u8; count];
    let (p, status) = dec.finish(&mut out).unwrap();
    assert!(matches!(status, Status::StreamEnd));
    assert_eq!(p.written, count);
    assert_eq!(out, vec![b'A'; count]);
}

#[test]
fn literals_only_block_split_finish_calls() {
    // Drive `finish` with a small buffer so it has to be called multiple
    // times to drain the output.
    let count = 20;
    let bytes = build_literals_only_block(b'X', count);
    let mut dec = Decoder::with_unpack_size(count as u64);
    let (_p, _s) = dec.decode(&bytes, &mut []).unwrap();

    let mut collected = Vec::new();
    let mut buf = [0u8; 3];
    loop {
        let (p, status) = dec.finish(&mut buf).unwrap();
        collected.extend_from_slice(&buf[..p.written]);
        if matches!(status, Status::StreamEnd) {
            break;
        }
        if p.written == 0 {
            panic!("decoder stalled");
        }
    }
    assert_eq!(collected.len(), count);
    assert!(collected.iter().all(|&b| b == b'X'));
}

// ─── short-match coverage ─────────────────────────────────────────────────

#[test]
fn short_match_repeats_prior_byte() {
    // Emit "A" then a short match of length 2 with offset 1 (extra_bits = 0,
    // so SHORT_BASE[0] + 1 = 1). That copies the just-written "A" twice.
    // Sequence: literal, match → "AAA" (length 3 output).
    let bytes = build_short_match_block(b'A', 0, &[0, 1]);
    let mut dec = Decoder::with_unpack_size(3);
    let (_p, _s) = dec.decode(&bytes, &mut []).unwrap();
    let mut out = vec![0u8; 3];
    let (p, status) = dec.finish(&mut out).unwrap();
    assert!(matches!(status, Status::StreamEnd));
    assert_eq!(p.written, 3);
    assert_eq!(&out, b"AAA");
}

#[test]
fn short_match_with_larger_offset() {
    // Emit four literals, then a match with offset 4 length 2.
    // With extra_bits = 3, the offset is SHORT_BASE[0] + 1 + 3 = 4. Because
    // the literal symbol is a single byte, the result is the same byte
    // repeated six times — still exercises the offset-4 LRU path.
    let bytes = build_short_match_block(b'Q', 3, &[0, 0, 0, 0, 1]);
    let mut dec = Decoder::with_unpack_size(6);
    let (_p, _s) = dec.decode(&bytes, &mut []).unwrap();
    let mut out = vec![0u8; 6];
    let (_p, status) = dec.finish(&mut out).unwrap();
    assert!(matches!(status, Status::StreamEnd));
    assert_eq!(&out, b"QQQQQQ");
}

// ─── malformed input ──────────────────────────────────────────────────────

#[test]
fn decode_then_extra_input_errors() {
    // After finish triggers the decode, feeding more input is illegal.
    let bytes = build_literals_only_block(b'Z', 3);
    let mut dec = Decoder::with_unpack_size(3);
    let (_p, _s) = dec.decode(&bytes, &mut []).unwrap();
    let mut out = [0u8; 8];
    let _ = dec.finish(&mut out).unwrap();
    let err = dec.decode(&[0u8], &mut []).unwrap_err();
    assert_eq!(err, Error::Corrupt);
}

#[test]
fn truncated_input_errors() {
    // No input fed but a nonzero unpack size requested — finish must error
    // rather than silently produce zeros.
    let mut dec = Decoder::with_unpack_size(8);
    let mut out = [0u8; 8];
    let result = dec.finish(&mut out);
    assert!(result.is_err());
}

#[test]
fn poisoned_after_error_stays_poisoned() {
    // Drive a corrupt stream into the decoder; further calls must error
    // until reset().
    let mut dec = Decoder::with_unpack_size(8);
    let mut out = [0u8; 8];
    let _ = dec.finish(&mut out).expect_err("truncation should error");
    // Subsequent finish must continue to return Err until reset.
    assert!(dec.finish(&mut out).is_err());
    assert!(dec.decode(&[0u8], &mut out).is_err());
}

// ─── real-world fixtures: produced by historical rar 2.60 ─────────────────

/// Compressed payload from a real RAR 2.6 archive produced by the historical
/// `rar` binary version 2.60 (Oct 1999). The archive contains a single
/// 105-byte text file `hello.txt`; this is the body of the data block (no
/// RAR file header bytes; those have been stripped out).
///
/// Source: `rar a -m3 hello.rar hello.txt` with rar 2.60 statically-linked
/// Linux binary downloaded from snapshot.debian.org.
static REAL_RAR2_HELLO: &[u8] = &[
    0x0d, 0x55, 0x54, 0x89, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd2, 0xf7, 0x45, 0x79, 0xbf, 0x23, 0x41,
    0x63, 0x59, 0x8d, 0x2d, 0x0d, 0x44, 0x74, 0x0b, 0x30, 0xfb, 0x02, 0x41, 0x3e, 0xc0, 0x24, 0x5d,
    0xf9, 0x94, 0x66, 0x24, 0x68, 0x46, 0x97, 0x46, 0x72, 0xbe, 0xf7, 0x4d, 0x73, 0x9a, 0x3e, 0xf2,
    0x73, 0x8f, 0xd0, 0x52, 0x54, 0x81, 0xb1, 0xc1, 0xcb, 0xae, 0xac, 0x58, 0xd8, 0x8a, 0x32, 0x12,
    0x28, 0xc8, 0x1e, 0x7c, 0x6c, 0x2e, 0xf1, 0x08, 0xb3, 0x70, 0xb2, 0xf8, 0x7f, 0xf8, 0x59, 0x56,
    0x0d, 0x79, 0x52, 0x30, 0x2e, 0x1d, 0x9b, 0xf8, 0x22, 0x7a, 0x4c, 0xce, 0xea, 0x52, 0xfa, 0xd3,
    0x7d, 0xa1, 0x3e, 0xee, 0xf1, 0xcb, 0x80,
];

const REAL_RAR2_HELLO_PLAIN: &[u8] = b"Hello, RAR2 world!\nThis is a test of the RAR 2.x decoder.\nLine three with some repetition: ABCABCABCABC.\n";

#[test]
fn real_rar2_hello_archive_decodes() {
    // Smoke test against a real, historical-archiver-produced RAR 2.x stream.
    let mut dec = Decoder::with_unpack_size(REAL_RAR2_HELLO_PLAIN.len() as u64);
    let (p, _s) = dec.decode(REAL_RAR2_HELLO, &mut []).unwrap();
    assert_eq!(p.consumed, REAL_RAR2_HELLO.len());

    let mut out = vec![0u8; REAL_RAR2_HELLO_PLAIN.len()];
    let (p, status) = dec
        .finish(&mut out)
        .expect("real rar2 hello fixture should decode");
    assert!(matches!(status, Status::StreamEnd));
    assert_eq!(p.written, REAL_RAR2_HELLO_PLAIN.len());
    assert_eq!(out, REAL_RAR2_HELLO_PLAIN);
}

/// Compressed payload of `binary.bin` — a 250-byte file containing 30 copies
/// of "ABC", followed by 100 random bytes, followed by 20 copies of "XYZ".
/// Hits the long-match path on the leading and trailing runs and the literal
/// path through the random middle, exercising more of the wire format than
/// the all-text "hello" sample.
static REAL_RAR2_BINARY_COMP: &[u8] = &[
    0x09, 0x40, 0x01, 0x4c, 0x80, 0x00, 0x00, 0x00, 0x14, 0x97, 0xe0, 0x1a, 0x28, 0x2b, 0x0d, 0xdc,
    0xa6, 0x31, 0x8c, 0x08, 0xf8, 0x06, 0x6e, 0x04, 0xde, 0x23, 0xa1, 0xa7, 0x94, 0x54, 0xd0, 0x6a,
    0xc1, 0x11, 0x6a, 0xa2, 0xdd, 0x82, 0x09, 0xb4, 0x74, 0x36, 0x3b, 0x1d, 0x5d, 0x8c, 0x61, 0x82,
    0x20, 0xcd, 0x04, 0x70, 0xd7, 0xa8, 0xb0, 0x64, 0xe0, 0x50, 0x46, 0x0d, 0x11, 0x7a, 0x0f, 0xc0,
    0x3f, 0x14, 0xcf, 0x87, 0x3e, 0x8b, 0x9f, 0x0d, 0xcb, 0x1e, 0x82, 0x27, 0xff, 0x3b, 0x8a, 0x6e,
    0x94, 0x5d, 0x1d, 0x44, 0x5d, 0x8f, 0x3b, 0x98, 0x8a, 0xc3, 0x3f, 0x88, 0x2a, 0xe0, 0x26, 0x19,
    0x77, 0xe4, 0xa4, 0xc0, 0x93, 0x39, 0xa5, 0xa9, 0xdb, 0xd7, 0x4a, 0x60, 0x2e, 0x0f, 0x90, 0x7c,
    0x75, 0xd2, 0xce, 0x45, 0xb1, 0x1a, 0xcf, 0xc7, 0xa2, 0x5c, 0xb3, 0x84, 0xab, 0xca, 0x7a, 0xe1,
    0x20, 0xc0, 0xbb, 0x00, 0xfb, 0x15, 0x43, 0x2f, 0x99, 0xa4, 0xb7, 0xd3, 0x3e, 0xc7, 0xe3, 0x77,
    0xd1, 0x5e, 0xa7, 0xb0, 0x5e, 0x5d, 0x0c, 0x70, 0xed, 0x19, 0xb5, 0xa2, 0xdf, 0x9a, 0xc5, 0x9b,
    0x5f, 0x7c,
];

static REAL_RAR2_BINARY_PLAIN: &[u8] = &[
    0x41, 0x42, 0x43, 0x41, 0x42, 0x43, 0x41, 0x42, 0x43, 0x41, 0x42, 0x43, 0x41, 0x42, 0x43, 0x41,
    0x42, 0x43, 0x41, 0x42, 0x43, 0x41, 0x42, 0x43, 0x41, 0x42, 0x43, 0x41, 0x42, 0x43, 0x41, 0x42,
    0x43, 0x41, 0x42, 0x43, 0x41, 0x42, 0x43, 0x41, 0x42, 0x43, 0x41, 0x42, 0x43, 0x41, 0x42, 0x43,
    0x41, 0x42, 0x43, 0x41, 0x42, 0x43, 0x41, 0x42, 0x43, 0x41, 0x42, 0x43, 0x41, 0x42, 0x43, 0x41,
    0x42, 0x43, 0x41, 0x42, 0x43, 0x41, 0x42, 0x43, 0x41, 0x42, 0x43, 0x41, 0x42, 0x43, 0x41, 0x42,
    0x43, 0x41, 0x42, 0x43, 0x41, 0x42, 0x43, 0x41, 0x42, 0x43, 0xa5, 0x4d, 0xca, 0x18, 0x25, 0x30,
    0xbb, 0x1d, 0x6d, 0x13, 0x2c, 0xde, 0xd6, 0x23, 0x7b, 0x2e, 0xd9, 0x1e, 0x3f, 0x72, 0x1f, 0xcb,
    0x19, 0x71, 0x17, 0x44, 0x94, 0xd6, 0x49, 0x3c, 0x9d, 0x5c, 0x34, 0x60, 0xbe, 0x31, 0x20, 0x1e,
    0x69, 0xfe, 0xda, 0xa0, 0xee, 0xe8, 0xb9, 0x99, 0x7f, 0x5c, 0x7c, 0x29, 0x99, 0xfd, 0xaf, 0xe5,
    0x93, 0x25, 0x3c, 0xd6, 0x54, 0xaf, 0x4d, 0xfa, 0xd7, 0x14, 0x27, 0xa0, 0xae, 0xb3, 0xfe, 0xe9,
    0x23, 0x2f, 0x8a, 0xf2, 0x21, 0x1f, 0x9e, 0xe4, 0x91, 0xc5, 0xb1, 0x0b, 0xec, 0xb5, 0x56, 0x3b,
    0xfc, 0x1e, 0x6f, 0x93, 0x42, 0x7e, 0xcb, 0xc8, 0xfe, 0x29, 0x55, 0xe5, 0xcd, 0x8e, 0x58, 0x59,
    0x5a, 0x58, 0x59, 0x5a, 0x58, 0x59, 0x5a, 0x58, 0x59, 0x5a, 0x58, 0x59, 0x5a, 0x58, 0x59, 0x5a,
    0x58, 0x59, 0x5a, 0x58, 0x59, 0x5a, 0x58, 0x59, 0x5a, 0x58, 0x59, 0x5a, 0x58, 0x59, 0x5a, 0x58,
    0x59, 0x5a, 0x58, 0x59, 0x5a, 0x58, 0x59, 0x5a, 0x58, 0x59, 0x5a, 0x58, 0x59, 0x5a, 0x58, 0x59,
    0x5a, 0x58, 0x59, 0x5a, 0x58, 0x59, 0x5a, 0x58, 0x59, 0x5a,
];

#[test]
fn real_rar2_binary_archive_decodes() {
    let mut dec = Decoder::with_unpack_size(REAL_RAR2_BINARY_PLAIN.len() as u64);
    let (p, _s) = dec.decode(REAL_RAR2_BINARY_COMP, &mut []).unwrap();
    assert_eq!(p.consumed, REAL_RAR2_BINARY_COMP.len());

    let mut out = vec![0u8; REAL_RAR2_BINARY_PLAIN.len()];
    let (p, status) = dec.finish(&mut out).expect("real rar2 binary decode");
    assert!(matches!(status, Status::StreamEnd));
    assert_eq!(p.written, REAL_RAR2_BINARY_PLAIN.len());
    assert_eq!(out, REAL_RAR2_BINARY_PLAIN);
}

// ─── reset behaviour ──────────────────────────────────────────────────────

#[test]
fn reset_clears_state() {
    let bytes = build_literals_only_block(b'Q', 2);
    let mut dec = Decoder::with_unpack_size(2);
    let (_p, _s) = dec.decode(&bytes, &mut []).unwrap();
    let mut out = [0u8; 4];
    let (p, status) = dec.finish(&mut out).unwrap();
    assert_eq!(p.written, 2);
    assert!(matches!(status, Status::StreamEnd));

    dec.reset();
    // `reset` preserves unpack_size; feeding the same stream should give the
    // same output.
    let (_p, _s) = dec.decode(&bytes, &mut []).unwrap();
    let (p, status) = dec.finish(&mut out).unwrap();
    assert_eq!(p.written, 2);
    assert!(matches!(status, Status::StreamEnd));
    assert_eq!(&out[..2], b"QQ");
}

#[test]
fn reset_after_error_recovers() {
    let mut dec = Decoder::with_unpack_size(8);
    let mut out = [0u8; 8];
    // Truncation: nothing fed, nonzero unpack — finish errors.
    let _ = dec.finish(&mut out).expect_err("expected error");
    // Subsequent calls remain poisoned.
    assert!(dec.finish(&mut out).is_err());
    // reset clears the poison; we can now drive a valid stream.
    dec.reset();
    // unpack_size is preserved; switch to a value that matches our fixture.
    dec.set_unpack_size(2);
    let bytes = build_literals_only_block(b'R', 2);
    let (_p, _s) = dec.decode(&bytes, &mut []).unwrap();
    let (p, status) = dec.finish(&mut out).unwrap();
    assert_eq!(p.written, 2);
    assert!(matches!(status, Status::StreamEnd));
    assert_eq!(&out[..2], b"RR");
}

// ─── factory (only if the feature is enabled) ─────────────────────────────

#[cfg(feature = "factory")]
mod factory {
    use compcol::Error;
    use compcol::factory;

    #[test]
    fn lookup_rar2_encoder_and_decoder() {
        assert!(factory::encoder_by_name("rar2").is_some());
        assert!(factory::decoder_by_name("rar2").is_some());
    }

    #[test]
    fn lookup_unknown() {
        assert!(factory::encoder_by_name("not-a-real-rar2").is_none());
        assert!(factory::decoder_by_name("not-a-real-rar2").is_none());
    }

    #[test]
    fn names_contains_rar2() {
        assert!(factory::names().contains(&"rar2"));
    }

    #[test]
    fn boxed_encoder_is_unsupported() {
        let mut enc = factory::encoder_by_name("rar2").unwrap();
        let mut out = [0u8; 16];
        assert_eq!(
            enc.encode(b"hello", &mut out).unwrap_err(),
            Error::Unsupported
        );
    }
}
