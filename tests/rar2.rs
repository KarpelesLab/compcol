//! Integration tests for the RAR 2.x decoder.
//!
//! RAR2 is a 1997-2002 format with effectively no surviving public fixture
//! corpus, so these tests stand up *synthetic* RAR2 bitstreams from scratch
//! using a small in-test encoder helper. The helper emits the exact byte
//! sequence the real RAR 2.x archiver would have written for a given block
//! shape, then feeds it through the production decoder.
//!
//! The hand-rolled block builders near the top cover literals and short
//! matches; the `StreamBuilder` further down emits every LZ token kind next
//! to a reference model (so expected output does not come from the decoder)
//! and audio blocks (pinned against the decoder's earlier output, as there
//! is no independent audio model here).
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
    // With no room for output `decode` only queues the input. With all of
    // it consumed, the status should be InputEmpty.
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

/// Regression: main symbol 256 ("repeat last match") must push its distance
/// into the old-offset ring like every other RAR 2.x match (unrar's
/// `CopyString20`). Hand-built RAR 2.0 stream: literals `ABBA`, short match
/// at offset 4, short match at offset 1, symbol 256, literal `A`, then
/// symbol 258 (second-most-recent offset). Expected output taken from
/// `unrar p` on the same stream wrapped in a RAR container; without the
/// push, 258 picked offset 4 instead of 1 and produced `...ABB`.
#[test]
fn repeat_last_match_updates_old_offsets() {
    const STREAM: [u8; 107] = [
        0x08, 0x88, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0xA0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x03, 0x30, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x2E, 0x31, 0xC0,
    ];
    const WANT: &[u8] = b"ABBAABBBBBAAA";
    let mut dec = Decoder::with_unpack_size(WANT.len() as u64);
    dec.decode(&STREAM, &mut []).unwrap();
    let mut out = [0u8; 32];
    let (p, status) = dec.finish(&mut out).unwrap();
    assert!(matches!(status, Status::StreamEnd));
    assert_eq!(&out[..p.written], WANT);
}

/// Regression: a hostile declared unpack size (64 TiB here) used to be
/// reserved up front with `reserve_exact`, aborting the process with an
/// allocation failure before a single input byte was read. It must now fail
/// cleanly on the short input instead.
#[test]
fn huge_declared_unpack_size_does_not_preallocate() {
    let mut dec = Decoder::with_unpack_size(1 << 46);
    dec.decode(&[0u8; 8], &mut []).unwrap();
    let mut out = [0u8; 16];
    assert!(dec.finish(&mut out).is_err());
}

// ─── streaming: synthetic stream builder with a reference model ───────────

const LENGTH_BASE: [u32; 28] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 14, 16, 20, 24, 28, 32, 40, 48, 56, 64, 80, 96, 112, 128,
    160, 192, 224,
];
const LENGTH_EXTRA: [u32; 28] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5,
];
const OFFSET_BASE: [u32; 48] = [
    0, 1, 2, 3, 4, 6, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512, 768, 1024, 1536,
    2048, 3072, 4096, 6144, 8192, 12288, 16384, 24576, 32768, 49152, 65536, 98304, 131072, 196608,
    262144, 327680, 393216, 458752, 524288, 589824, 655360, 720896, 786432, 851968, 917504, 983040,
];
const OFFSET_EXTRA: [u32; 48] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13, 14, 14, 15, 15, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
];
const SHORT_BASE: [u32; 8] = [0, 4, 8, 16, 32, 64, 128, 192];
const SHORT_EXTRA: [u32; 8] = [2, 2, 3, 4, 5, 6, 6, 6];
const AUDIO_TREE_SIZE: usize = 257;
const WINDOW_SIZE: usize = 1 << 20;

/// Tiny deterministic PRNG (xorshift64*), so the synthetic streams are
/// identical on every run.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u32 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        (self.0.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 32) as u32
    }
    fn below(&mut self, n: u32) -> u32 {
        self.next() % n
    }
}

/// Index of the last table entry whose base is `<= v`.
fn bucket(bases: &[u32], v: u32) -> usize {
    bases.iter().rposition(|&b| b <= v).unwrap()
}

/// Flat LZ length table: every main symbol 9 bits, offsets 6, lengths 5.
fn lz_table_a() -> Vec<u8> {
    let mut t = vec![9u8; MAIN_TREE_SIZE];
    t.extend(vec![6u8; OFFSET_TREE_SIZE]);
    t.extend(vec![5u8; LENGTH_TREE_SIZE]);
    t
}

/// Uneven LZ length table whose main codes reach 10 bits (past the
/// decoder's 9-bit primary lookup, so the slow path is exercised too).
fn lz_table_b() -> Vec<u8> {
    let mut t = vec![8u8; 128];
    t.extend(vec![10u8; MAIN_TREE_SIZE - 128]);
    t.extend(vec![6u8; OFFSET_TREE_SIZE]);
    t.extend(vec![4u8; 4]);
    t.extend(vec![5u8; LENGTH_TREE_SIZE - 4]);
    t
}

/// Builds RAR 2.x LZ streams token by token and applies the same tokens to
/// a plain `Vec<u8>` model, so the expected output does not come from the
/// decoder under test.
struct StreamBuilder {
    w: BitWriter,
    /// Decoder-side cumulative length table (1028 entries).
    lens: Vec<u8>,
    main: Vec<Option<Code>>,
    offset: Vec<Option<Code>>,
    length: Vec<Option<Code>>,
    audio: Vec<Vec<Option<Code>>>,
    /// Reference output (LZ tokens only; audio samples are not modelled).
    out: Vec<u8>,
    old: [u32; 4],
    old_idx: usize,
    last_off: u32,
    last_len: u32,
}

impl StreamBuilder {
    fn new() -> Self {
        Self {
            w: BitWriter::new(),
            lens: vec![0u8; 4 * AUDIO_TREE_SIZE],
            main: Vec::new(),
            offset: Vec::new(),
            length: Vec::new(),
            audio: Vec::new(),
            out: Vec::new(),
            old: [0; 4],
            old_idx: 0,
            last_off: 0,
            last_len: 0,
        }
    }

    fn put(&mut self, c: &Option<Code>) {
        let c = c.as_ref().expect("symbol has a code");
        self.w.write(c.bits, c.len);
    }

    /// Block header with a flat pretree: the 16 delta symbols all get 4-bit
    /// codes (so delta `d` is written as the nibble `d`), no run symbols.
    fn header(&mut self, channels: Option<u32>, keep: bool, new_lens: &[u8]) {
        self.w.write(channels.is_some() as u32, 1);
        self.w.write(keep as u32, 1);
        if let Some(ch) = channels {
            self.w.write(ch - 1, 2);
        }
        if !keep {
            self.lens.fill(0);
        }
        for i in 0..PRETREE_SIZE {
            self.w.write(if i < 16 { 4 } else { 0 }, 4);
        }
        for (i, &l) in new_lens.iter().enumerate() {
            self.w.write((l.wrapping_sub(self.lens[i]) & 15) as u32, 4);
            self.lens[i] = l;
        }
    }

    fn lz_block(&mut self, keep: bool, table: &[u8]) {
        assert_eq!(table.len(), NON_AUDIO_LENGTHS);
        self.header(None, keep, table);
        self.main = build_codes(&table[..MAIN_TREE_SIZE]);
        self.offset = build_codes(&table[MAIN_TREE_SIZE..MAIN_TREE_SIZE + OFFSET_TREE_SIZE]);
        self.length = build_codes(&table[MAIN_TREE_SIZE + OFFSET_TREE_SIZE..]);
    }

    fn audio_block(&mut self, channels: u32, keep: bool) {
        let table = vec![9u8; channels as usize * AUDIO_TREE_SIZE];
        self.header(Some(channels), keep, &table);
        self.audio = (0..channels)
            .map(|_| build_codes(&[9u8; AUDIO_TREE_SIZE]))
            .collect();
    }

    fn main_sym(&mut self, sym: usize) {
        let c = self.main[sym].clone();
        self.put(&c);
    }

    fn audio_sym(&mut self, channel: usize, sym: usize) {
        let c = self.audio[channel][sym].clone();
        self.put(&c);
    }

    fn copy(&mut self, off: u32, len: u32) {
        for _ in 0..len {
            let b = match self.out.len().checked_sub(off as usize) {
                Some(i) => self.out[i],
                // Before the start of the stream the window reads as zeros.
                None => 0,
            };
            self.out.push(b);
        }
    }

    fn commit(&mut self, off: u32) {
        self.old[self.old_idx & 3] = off;
        self.old_idx += 1;
        self.last_off = off;
    }

    fn literal(&mut self, b: u8) {
        self.main_sym(b as usize);
        self.out.push(b);
    }

    /// Main symbols 270..=297. `len` is the final match length.
    fn long_match(&mut self, off: u32, len: u32) {
        let adj = (off >= 0x2000) as u32 + (off >= 0x40000) as u32;
        let base = len - 3 - adj;
        let li = bucket(&LENGTH_BASE, base);
        self.main_sym(270 + li);
        self.w.write(base - LENGTH_BASE[li], LENGTH_EXTRA[li]);
        let oi = bucket(&OFFSET_BASE, off - 1);
        let c = self.offset[oi].clone();
        self.put(&c);
        self.w.write(off - 1 - OFFSET_BASE[oi], OFFSET_EXTRA[oi]);
        self.commit(off);
        self.last_len = len;
        self.copy(off, len);
    }

    /// Main symbols 261..=268: length 2, offset 1..=256.
    fn short_match(&mut self, off: u32) {
        let si = bucket(&SHORT_BASE, off - 1);
        self.main_sym(261 + si);
        self.w.write(off - 1 - SHORT_BASE[si], SHORT_EXTRA[si]);
        self.commit(off);
        self.last_len = 2;
        self.copy(off, 2);
    }

    /// Main symbol 256.
    fn repeat_last(&mut self) {
        self.main_sym(256);
        self.commit(self.last_off);
        self.copy(self.last_off, self.last_len);
    }

    /// Offset the `k`-th most recent match used (`k` in 1..=4).
    fn old_offset_value(&self, k: usize) -> u32 {
        self.old[self.old_idx.wrapping_sub(k) & 3]
    }

    /// Main symbols 257..=260. `base` is the length-tree value (0..=255).
    fn old_offset_match(&mut self, k: usize, base: u32) {
        let off = self.old_offset_value(k);
        let li = bucket(&LENGTH_BASE, base);
        self.main_sym(256 + k);
        let c = self.length[li].clone();
        self.put(&c);
        self.w.write(base - LENGTH_BASE[li], LENGTH_EXTRA[li]);
        let len =
            base + 2 + (off >= 0x101) as u32 + (off >= 0x2000) as u32 + (off >= 0x40000) as u32;
        self.commit(off);
        self.last_len = len;
        self.copy(off, len);
    }

    /// Append random LZ tokens until the model holds at least `until` bytes.
    fn random_lz(&mut self, rng: &mut Rng, until: usize, max_off: u32) {
        while self.out.len() < until {
            match rng.below(16) {
                0..=4 => self.literal(b'a' + rng.below(20) as u8),
                5..=9 => {
                    let off = 1 + rng.below(max_off);
                    let adj = (off >= 0x2000) as u32 + (off >= 0x40000) as u32;
                    self.long_match(off, 3 + adj + rng.below(256));
                }
                10 | 11 => self.short_match(1 + rng.below(256)),
                12 if self.last_len > 0 => self.repeat_last(),
                13 | 14 => {
                    let k = 1 + rng.below(4) as usize;
                    if self.old_offset_value(k) != 0 {
                        self.old_offset_match(k, rng.below(256));
                    }
                }
                15 if rng.below(64) == 0 => {
                    // "Re-read trees", alternating tables, with and without
                    // delta-coding against the previous block's lengths.
                    self.main_sym(269);
                    let table = if rng.below(2) == 0 {
                        lz_table_a()
                    } else {
                        lz_table_b()
                    };
                    self.lz_block(rng.below(2) == 0, &table);
                }
                _ => {}
            }
        }
    }

    fn finish(self) -> (Vec<u8>, Vec<u8>) {
        (self.w.finish(), self.out)
    }
}

/// ~1.3 MiB of output (past the 1 MiB window, so the ring wraps) from every
/// LZ token kind, plus the model's expected bytes.
fn build_big_lz_stream() -> (Vec<u8>, Vec<u8>) {
    let mut b = StreamBuilder::new();
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    b.lz_block(false, &lz_table_a());
    b.random_lz(&mut rng, WINDOW_SIZE + 300_000, WINDOW_SIZE as u32);
    b.finish()
}

/// A few KiB with short offsets only: cheap enough to push through the
/// decoder one byte at a time.
fn build_small_lz_stream() -> (Vec<u8>, Vec<u8>) {
    let mut b = StreamBuilder::new();
    let mut rng = Rng(0x0123_4567_89AB_CDEF);
    b.lz_block(false, &lz_table_b());
    b.random_lz(&mut rng, 6000, 3000);
    b.finish()
}

/// Audio (multimedia) block → LZ block that copies out of the audio bytes →
/// audio block with a different channel count. Returns the stream and the
/// number of bytes it decodes to.
fn build_audio_stream() -> (Vec<u8>, usize) {
    let mut b = StreamBuilder::new();
    let mut rng = Rng(0xA5A5_5A5A_1234_5678);
    let mut total = 0usize;

    b.audio_block(2, false);
    let mut ch = 0usize;
    for _ in 0..3001 {
        // Mostly small deltas, like real PCM, plus the odd jump.
        let d = if rng.below(8) == 0 {
            rng.below(256)
        } else {
            (rng.below(9) as i32 - 4) as u8 as u32
        };
        b.audio_sym(ch, d as usize);
        ch = (ch + 1) % 2;
        total += 1;
    }
    // Symbol 256 on the current channel: new tables follow.
    b.audio_sym(ch, 256);
    b.lz_block(false, &lz_table_a());
    for _ in 0..40 {
        let off = 1 + rng.below(3000);
        let len = 3 + rng.below(200);
        b.long_match(off, len);
        b.literal(rng.below(256) as u8);
        total += len as usize + 1;
    }
    b.main_sym(269);
    b.audio_block(3, false);
    // The decoder keeps its channel cursor across blocks (reset only when
    // it is out of range for the new channel count); `ch` is 1 here.
    for _ in 0..1000 {
        b.audio_sym(ch, rng.below(256) as usize);
        ch = (ch + 1) % 3;
        total += 1;
    }
    (b.w.finish(), total)
}

/// Drive `dec` over `input` in `in_chunk`-byte pieces with an
/// `out_chunk`-byte output buffer, through `decode` and then `finish`.
fn drive(
    mut dec: impl compcol::Decoder,
    input: &[u8],
    in_chunk: usize,
    out_chunk: usize,
) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    let mut buf = vec![0u8; out_chunk];
    let mut pos = 0usize;
    while pos < input.len() {
        let end = pos.saturating_add(in_chunk).min(input.len());
        let (p, status) = dec.decode(&input[pos..end], &mut buf)?;
        out.extend_from_slice(&buf[..p.written]);
        pos += p.consumed;
        if matches!(status, Status::StreamEnd) {
            return Ok(out);
        }
        assert!(p.consumed > 0 || p.written > 0, "decode made no progress");
    }
    loop {
        let (p, status) = dec.finish(&mut buf)?;
        out.extend_from_slice(&buf[..p.written]);
        if matches!(status, Status::StreamEnd) {
            return Ok(out);
        }
        assert!(p.written > 0, "finish made no progress");
    }
}

fn fnv1a(data: &[u8]) -> u64 {
    data.iter().fold(0xcbf2_9ce4_8422_2325u64, |h, &b| {
        (h ^ b as u64).wrapping_mul(0x0000_0100_0000_01b3)
    })
}

/// Output of [`build_audio_stream`] as decoded by the pre-streaming
/// (decode-everything-in-`finish`) decoder: pins the audio predictor and the
/// audio↔LZ block switches across the streaming rewrite.
const AUDIO_STREAM_FNV1A: u64 = 0x304c_2501_dbf0_5ded;

#[test]
fn synthetic_lz_stream_matches_model() {
    let (stream, want) = build_big_lz_stream();
    assert!(want.len() > WINDOW_SIZE);
    let got = drive(
        Decoder::with_unpack_size(want.len() as u64),
        &stream,
        usize::MAX,
        want.len(),
    )
    .unwrap();
    assert!(got == want, "one-shot output differs from the model");
    // Odd-sized chunks on both sides, so symbols and matches straddle calls.
    let got = drive(
        Decoder::with_unpack_size(want.len() as u64),
        &stream,
        4099,
        7919,
    )
    .unwrap();
    assert!(got == want, "chunked output differs from the model");
}

#[test]
fn audio_and_lz_blocks_decode_to_pinned_output() {
    let (stream, total) = build_audio_stream();
    let got = drive(
        Decoder::with_unpack_size(total as u64),
        &stream,
        usize::MAX,
        total,
    )
    .unwrap();
    assert_eq!(got.len(), total);
    assert_eq!(fnv1a(&got), AUDIO_STREAM_FNV1A, "{:#x}", fnv1a(&got));
}

/// Chunking differential: one-shot, 1-byte input, 1-byte output and both at
/// once must agree on every fixture.
#[test]
fn chunking_does_not_change_output() {
    let (small_lz, small_want) = build_small_lz_stream();
    let (audio, audio_len) = build_audio_stream();
    let audio_want = drive(
        Decoder::with_unpack_size(audio_len as u64),
        &audio,
        usize::MAX,
        audio_len,
    )
    .unwrap();
    let fixtures: Vec<(&str, Vec<u8>, Vec<u8>)> = vec![
        (
            "real hello",
            REAL_RAR2_HELLO.to_vec(),
            REAL_RAR2_HELLO_PLAIN.to_vec(),
        ),
        (
            "real binary",
            REAL_RAR2_BINARY_COMP.to_vec(),
            REAL_RAR2_BINARY_PLAIN.to_vec(),
        ),
        (
            "literals",
            build_literals_only_block(b'A', 300),
            vec![b'A'; 300],
        ),
        (
            "short match",
            build_short_match_block(b'Q', 3, &[0, 0, 0, 0, 1]),
            b"QQQQQQ".to_vec(),
        ),
        ("synthetic lz", small_lz, small_want),
        ("audio", audio, audio_want),
    ];
    for (name, stream, want) in &fixtures {
        for (in_chunk, out_chunk) in [
            (usize::MAX, want.len().max(1)),
            (1, want.len().max(1)),
            (usize::MAX, 1),
            (1, 1),
            (3, 5),
        ] {
            let dec = Decoder::with_unpack_size(want.len() as u64);
            let got = drive(dec, stream, in_chunk, out_chunk)
                .unwrap_or_else(|e| panic!("{name} in={in_chunk} out={out_chunk}: {e:?}"));
            assert!(
                got == *want,
                "{name}: output differs with in={in_chunk} out={out_chunk}"
            );
        }
    }
}

/// Upper bound on what the decoder may hold of its own output: the 64 KiB
/// high-water mark plus one maximal match.
const MAX_BUFFERED_OUTPUT: usize = 64 * 1024 + 260;

/// Regression: the decoder used to buffer all input and, on the first
/// `finish`, build the whole member in memory before handing out a byte, so
/// a hostile declared size made it produce everything the payload could
/// expand to no matter how little the caller took. Output must now come out
/// of `decode` as it is produced, with only a bounded amount held back.
#[test]
fn output_is_streamed_and_bounded() {
    // One input bit per output byte: 128 KiB of payload → 1 MiB of 'A's.
    let count = 8 * 128 * 1024;
    let stream = build_literals_only_block(b'A', count);
    let mut dec = Decoder::with_unpack_size(1 << 40);
    let mut buf = [0u8; 1024];

    // The very first `decode` call already yields output.
    let (p, status) = dec.decode(&stream, &mut buf).unwrap();
    assert_eq!(p.consumed, stream.len());
    assert_eq!(p.written, buf.len());
    assert!(matches!(status, Status::OutputFull));
    assert!(dec.buffered_output_len() <= MAX_BUFFERED_OUTPUT);

    let mut total = p.written;
    loop {
        let (p, status) = dec.decode(&[], &mut buf).unwrap();
        assert!(buf[..p.written].iter().all(|&b| b == b'A'));
        total += p.written;
        assert!(
            dec.buffered_output_len() <= MAX_BUFFERED_OUTPUT,
            "{} bytes buffered after {total} drained",
            dec.buffered_output_len()
        );
        if p.written == 0 {
            assert!(matches!(status, Status::InputEmpty));
            break;
        }
    }
    // Everything the payload encodes came out (the zero padding of the last
    // byte reads as up to 7 more one-bit literals).
    assert!((count..count + 8).contains(&total), "{total}");
    assert_eq!(dec.buffered_output_len(), 0);
    // Input the decoder has moved past is released, not kept.
    assert!(dec.buffered_input_len() <= 4096);
    // The declared size was a lie: the stream is truncated.
    assert_eq!(dec.finish(&mut buf).unwrap_err(), Error::UnexpectedEnd);
}

/// The audit scenario: hostile declared size under a 1 KiB `LimitedDecoder`.
/// The limit must trip having decoded only a bounded amount.
#[test]
fn output_limit_trips_without_building_the_declared_size() {
    use compcol::limit::LimitedDecoder;

    let stream = build_literals_only_block(b'A', 8 * 256 * 1024);
    let mut dec = LimitedDecoder::new(Decoder::with_unpack_size(u64::MAX), 1024);
    let mut buf = [0u8; 4096];
    let (p, _) = dec.decode(&stream, &mut buf).unwrap();
    assert_eq!(p.written, 1024);
    assert!(dec.get_ref().buffered_output_len() <= MAX_BUFFERED_OUTPUT);
    assert_eq!(
        dec.decode(&[], &mut buf).unwrap_err(),
        Error::OutputLimitExceeded
    );
    assert!(dec.get_ref().buffered_output_len() <= MAX_BUFFERED_OUTPUT);
}

/// `decode` with an empty output slice only queues input; `finish` with an
/// empty slice still reports the end of an empty member and still surfaces
/// truncation instead of asking to be called again forever.
#[test]
fn empty_output_slices_do_not_stall() {
    let bytes = build_literals_only_block(b'A', 4);
    let mut dec = Decoder::with_unpack_size(4);
    let (p, status) = dec.decode(&bytes, &mut []).unwrap();
    assert_eq!((p.consumed, p.written), (bytes.len(), 0));
    assert!(matches!(status, Status::InputEmpty));
    let (p, status) = dec.finish(&mut []).unwrap();
    assert_eq!(p.written, 0);
    assert!(matches!(status, Status::OutputFull));
    let mut out = [0u8; 8];
    let (p, status) = dec.finish(&mut out).unwrap();
    assert_eq!(&out[..p.written], b"AAAA");
    assert!(matches!(status, Status::StreamEnd));

    let mut dec = Decoder::with_unpack_size(4);
    dec.decode(&bytes[..10], &mut []).unwrap();
    assert_eq!(dec.finish(&mut []).unwrap_err(), Error::UnexpectedEnd);
}

/// A member whose declared size ends in the middle of the stream (here in
/// the middle of a match) stops exactly there, and `decode` reports the end
/// itself without taking what follows.
#[test]
fn stops_exactly_at_the_declared_size() {
    let (stream, want) = build_small_lz_stream();
    for n in [0usize, 1, 1000, 2999, want.len() - 1] {
        for (in_chunk, out_chunk) in [(usize::MAX, 8192), (1, 1), (5, 3)] {
            let dec = Decoder::with_unpack_size(n as u64);
            let got = drive(dec, &stream, in_chunk, out_chunk).unwrap();
            assert!(got == want[..n], "n={n} in={in_chunk} out={out_chunk}");
        }
    }

    let mut dec = Decoder::with_unpack_size(1000);
    let mut out = vec![0u8; 4096];
    let (p, status) = dec.decode(&stream, &mut out).unwrap();
    assert_eq!(p.written, 1000);
    assert!(matches!(status, Status::StreamEnd));
    // Terminal: trailing bytes are left alone.
    let (p, status) = dec.decode(b"next header", &mut out).unwrap();
    assert_eq!((p.consumed, p.written), (0, 0));
    assert!(matches!(status, Status::StreamEnd));
    let (p, status) = dec.finish(&mut out).unwrap();
    assert_eq!(p.written, 0);
    assert!(matches!(status, Status::StreamEnd));
}

/// A truncated stream yields the bytes decoded before the cut and then the
/// error, identically however the calls are chunked.
#[test]
fn truncation_yields_the_same_prefix_then_errors() {
    fn run(input: &[u8], size: u64, in_chunk: usize, out_chunk: usize) -> (Vec<u8>, Error) {
        let mut dec = Decoder::with_unpack_size(size);
        let mut out = Vec::new();
        let mut buf = vec![0u8; out_chunk];
        for chunk in input.chunks(in_chunk) {
            let mut chunk = chunk;
            loop {
                let (p, _) = dec.decode(chunk, &mut buf).unwrap();
                out.extend_from_slice(&buf[..p.written]);
                chunk = &chunk[p.consumed..];
                if chunk.is_empty() && p.written == 0 {
                    break;
                }
            }
        }
        loop {
            match dec.finish(&mut buf) {
                Ok((p, status)) => {
                    assert!(!matches!(status, Status::StreamEnd));
                    assert!(p.written > 0, "finish stalled");
                    out.extend_from_slice(&buf[..p.written]);
                }
                Err(e) => {
                    // Sticky from here on.
                    assert!(dec.finish(&mut buf).is_err());
                    return (out, e);
                }
            }
        }
    }

    let (stream, want) = build_small_lz_stream();
    let cut = &stream[..stream.len() * 3 / 4];
    let (prefix, err) = run(cut, want.len() as u64, usize::MAX, 8192);
    assert_eq!(err, Error::UnexpectedEnd);
    assert!(
        prefix.len() > 1000 && prefix.len() < want.len(),
        "{} of {} ({} stream bytes)",
        prefix.len(),
        want.len(),
        stream.len()
    );
    assert!(prefix == want[..prefix.len()]);
    for (in_chunk, out_chunk) in [(1, 1), (1, 8192), (usize::MAX, 1), (7, 11)] {
        let (got, err) = run(cut, want.len() as u64, in_chunk, out_chunk);
        assert_eq!(err, Error::UnexpectedEnd);
        assert!(got == prefix, "in={in_chunk} out={out_chunk}");
    }
}

/// `reset` mid-stream discards the window, the queued input and the pending
/// output: the next stream decodes as on a fresh decoder.
#[test]
fn reset_mid_stream_starts_clean() {
    let (stream, want) = build_small_lz_stream();
    let mut dec = Decoder::with_unpack_size(want.len() as u64);
    let mut buf = [0u8; 100];
    dec.decode(&stream[..stream.len() / 2], &mut buf).unwrap();
    assert!(dec.buffered_output_len() > 0);
    dec.reset();
    assert_eq!(dec.buffered_output_len(), 0);
    assert_eq!(dec.buffered_input_len(), 0);
    let mut out = vec![0u8; want.len()];
    let (p, status) = dec.decode(&stream, &mut out).unwrap();
    assert!(matches!(status, Status::StreamEnd));
    assert!(out[..p.written] == want[..]);
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
