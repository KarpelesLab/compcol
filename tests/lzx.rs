//! Streaming round-trip + decoder-fixture tests for LZX.
//!
//! The encoder in this build only emits uncompressed BLOCKTYPE=3 blocks, so
//! the round-trip tests exercise:
//!   - The 5-byte standalone stream header (window_bits + LE length).
//!   - The LZX 16-bit-LE-MSB-first bit reader on uncompressed-block headers.
//!   - The R0/R1/R2 dump and word-aligned raw payload path on the decoder
//!     side.
//!
//! Fixture-based decoder tests use bytes hand-built to exercise the verbatim
//! and aligned-offset code paths that the encoder never produces.
//!
//! v0.3 port: every codec call returns `(Progress, Status)` and the loop
//! dispatches on `Status` rather than inferring from byte counts.

#![cfg(feature = "lzx")]

use compcol::lzx::{Decoder, Encoder, Lzx};
use compcol::{Algorithm, Decoder as _, Encoder as _, Error, Status};

// ─── small chunked-IO helpers ────────────────────────────────────────────

fn encode_chunked(input: &[u8], in_chunk: usize, out_chunk: usize) -> Vec<u8> {
    let mut enc = Encoder::new();
    let mut encoded = Vec::new();
    let mut buf = vec![0u8; out_chunk.max(1)];
    let mut i = 0;

    while i < input.len() {
        let end = (i + in_chunk).min(input.len());
        let chunk = &input[i..end];
        let mut consumed = 0;
        while consumed < chunk.len() {
            let (p, status) = enc.encode(&chunk[consumed..], &mut buf).unwrap();
            encoded.extend_from_slice(&buf[..p.written]);
            consumed += p.consumed;
            match status {
                Status::InputEmpty | Status::StreamEnd => break,
                Status::OutputFull => continue,
            }
        }
        i = end;
    }

    loop {
        let (p, status) = enc.finish(&mut buf).unwrap();
        encoded.extend_from_slice(&buf[..p.written]);
        match status {
            Status::StreamEnd => break,
            Status::OutputFull | Status::InputEmpty => {
                if p.written == 0 {
                    panic!("encoder finish stalled");
                }
            }
        }
    }
    encoded
}

fn decode_chunked(encoded: &[u8], in_chunk: usize, out_chunk: usize) -> Vec<u8> {
    let mut dec = Decoder::new();
    let mut decoded = Vec::new();
    let mut buf = vec![0u8; out_chunk.max(1)];
    let mut i = 0;

    while i < encoded.len() {
        let end = (i + in_chunk).min(encoded.len());
        let chunk = &encoded[i..end];
        let mut consumed = 0;
        while consumed < chunk.len() {
            let (p, status) = dec.decode(&chunk[consumed..], &mut buf).unwrap();
            decoded.extend_from_slice(&buf[..p.written]);
            consumed += p.consumed;
            match status {
                Status::InputEmpty | Status::StreamEnd => break,
                Status::OutputFull => continue,
            }
        }
        i = end;
    }

    loop {
        let (p, status) = dec.finish(&mut buf).unwrap();
        decoded.extend_from_slice(&buf[..p.written]);
        match status {
            Status::StreamEnd => break,
            Status::OutputFull | Status::InputEmpty => {
                if p.written == 0 {
                    panic!("decoder finish stalled (decoded {} so far)", decoded.len());
                }
            }
        }
    }
    decoded
}

fn round_trip(input: &[u8]) {
    let encoded = encode_chunked(input, input.len().max(1), input.len().max(64) * 2 + 64);
    let decoded = decode_chunked(&encoded, encoded.len().max(1), input.len().max(1));
    assert_eq!(decoded, input, "round-trip mismatch");
}

// ─── identity ────────────────────────────────────────────────────────────

#[test]
fn name_is_lzx() {
    assert_eq!(<Lzx as Algorithm>::NAME, "lzx");
}

// ─── empty + small inputs ────────────────────────────────────────────────

#[test]
fn empty_input() {
    round_trip(&[]);
}

#[test]
fn hello_world() {
    round_trip(b"hello, world!");
}

#[test]
fn single_byte() {
    round_trip(&[0x42]);
}

#[test]
fn two_bytes() {
    round_trip(&[0xAA, 0xBB]);
}

// ─── larger payloads ─────────────────────────────────────────────────────

fn lorem(target_bytes: usize) -> Vec<u8> {
    let base: &[u8] = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit, \
        sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. ";
    let mut out = Vec::with_capacity(target_bytes + base.len());
    while out.len() < target_bytes {
        out.extend_from_slice(base);
    }
    out.truncate(target_bytes);
    out
}

#[test]
fn lorem_4kib() {
    round_trip(&lorem(4 * 1024));
}

#[test]
fn lorem_16kib() {
    round_trip(&lorem(16 * 1024));
}

#[test]
fn lorem_40kib_crosses_chunk() {
    // 40 KiB crosses a CHUNK_BYTES = 32 KiB block boundary in the encoder.
    round_trip(&lorem(40 * 1024));
}

#[test]
fn pseudo_random_8kib() {
    let mut data = Vec::with_capacity(8 * 1024);
    let mut x: u32 = 0xCAFE_BABE;
    while data.len() < 8 * 1024 {
        x = x.wrapping_mul(1103515245).wrapping_add(12345);
        data.push((x >> 16) as u8);
    }
    round_trip(&data);
}

#[test]
fn one_byte_streaming_round_trip() {
    // Feed/encode/decode 1 byte at a time on both sides.
    let input = b"streaming, one byte at a time, both directions.".to_vec();
    let encoded = encode_chunked(&input, 1, 1);
    let decoded = decode_chunked(&encoded, 1, 1);
    assert_eq!(decoded, input);
}

// ─── error rejection ─────────────────────────────────────────────────────

#[test]
fn invalid_window_bits_in_header() {
    // window_bits = 9 is below the supported range.
    let bad: &[u8] = &[9, 0, 0, 0, 0];
    let mut dec = Decoder::new();
    let mut out = [0u8; 16];
    let err = dec.decode(bad, &mut out).unwrap_err();
    assert_eq!(err, Error::Unsupported);
}

#[test]
fn truncated_stream_after_header() {
    // Valid header declaring 10 uncompressed bytes, but no actual data follows.
    // The decoder's finish() must reject this.
    let header: &[u8] = &[15, 10, 0, 0, 0]; // window=15, total=10
    let mut dec = Decoder::new();
    let mut out = [0u8; 16];
    let (p, _status) = dec.decode(header, &mut out).unwrap();
    assert_eq!(p.consumed, 5);
    assert_eq!(p.written, 0);
    let err = dec.finish(&mut out).unwrap_err();
    assert_eq!(err, Error::UnexpectedEnd);
}

#[test]
fn invalid_block_type_zero() {
    // Build a stream: framing header (window=15, total=10), then the LZX
    // stream-level flag bit (0), then a block with BLOCKTYPE=000 which our
    // decoder doesn't recognize. BLOCKTYPE values 1..=3 are legal; the spec
    // leaves BLOCKTYPE=0 unspecified.
    //
    // The MSB-first bit stream is: [flag=0][btype=000][block_size=10 (24 bits)]
    // = 28 bits. Pad 4 zeros to reach 32 bits = two 16-bit MSB-first words.
    let block_size: u32 = 10;
    let header28: u32 = ((block_size >> 8) & 0xFFFF) << 8 | (block_size & 0xFF);
    // flag=0 in bit 27, btype=0 in bits 24..26, block_size in bits 0..23. With
    // btype=0 the whole 28-bit MSB-first value is just block_size.
    let padded32 = header28 << 4;
    let w0 = ((padded32 >> 16) & 0xFFFF) as u16;
    let w1 = (padded32 & 0xFFFF) as u16;
    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend_from_slice(&[15, 10, 0, 0, 0]);
    bytes.push((w0 & 0xFF) as u8);
    bytes.push((w0 >> 8) as u8);
    bytes.push((w1 & 0xFF) as u8);
    bytes.push((w1 >> 8) as u8);

    let mut dec = Decoder::new();
    let mut out = [0u8; 32];
    let res = dec.decode(&bytes, &mut out);
    assert_eq!(res, Err(Error::InvalidBlockType));
}

// ─── decoder fixture: hand-built uncompressed-block stream ──────────────
//
// Decoding fixtures generated by an external LZX tool would be ideal but
// would tie the test suite to a libmspack / cabextract installation. We
// instead use bytes produced by *our own encoder*, then independently
// dismantle them to verify the bit layout matches what the spec requires.

#[test]
fn fixture_uncompressed_block_layout() {
    // Encode "hi" and verify the byte stream matches the documented layout:
    //   [15] [02 00 00 00]                  ← framing header
    //   then the LZX bitstream:
    //     1 bit  flag = 0 (no intel translation)
    //     3 bits BLOCKTYPE = 011 (uncompressed)
    //     24 bits BLOCK_SIZE = 2 (16 hi || 8 lo)
    //     4 bits zero pad to reach a 16-bit-word boundary
    //   = two 16-bit MSB-first words: 0x3000, 0x0020
    //   then 12 R-bytes = 01 00 00 00 01 00 00 00 01 00 00 00
    //   then payload "hi" = 0x68 0x69
    let encoded = encode_chunked(b"hi", 2, 64);
    let expected: &[u8] = &[
        15, 0x02, 0, 0, 0, // framing header
        0x00, 0x30, // first LZX word (0x3000) on wire as LE
        0x20, 0x00, // second LZX word (0x0020)
        0x01, 0x00, 0x00, 0x00, // R0
        0x01, 0x00, 0x00, 0x00, // R1
        0x01, 0x00, 0x00, 0x00, // R2
        0x68, 0x69, // payload "hi"
    ];
    assert_eq!(encoded, expected);
}

#[test]
fn fixture_round_trip_decoder_only() {
    // Test the decoder against the hand-built fixture, independent of the
    // encoder's correctness.
    let fixture: &[u8] = &[
        15, 0x02, 0, 0, 0, // framing header (total = 2 bytes)
        0x00, 0x30, 0x20, 0x00, // flag=0 + block header (BLOCKTYPE=3, BLOCK_SIZE=2)
        0x01, 0x00, 0x00, 0x00, // R0
        0x01, 0x00, 0x00, 0x00, // R1
        0x01, 0x00, 0x00, 0x00, // R2
        b'h', b'i',
    ];
    let out = decode_chunked(fixture, 4, 4);
    assert_eq!(out, b"hi");
}

#[test]
fn fixture_multi_block() {
    // Encode 80 KiB so we get at least 3 uncompressed blocks (each ≤ 32 KiB).
    let n = 80 * 1024;
    let data = lorem(n);
    let encoded = encode_chunked(&data, n, n * 2 + 1024);
    // Sanity: framing overhead ≈ 5 + 3 * (4 + 12) = 53 bytes.
    assert!(encoded.len() >= data.len() + 53);
    assert!(encoded.len() <= data.len() + 256);
    let decoded = decode_chunked(&encoded, encoded.len() / 7 + 1, 4096);
    assert_eq!(decoded, data);
}

// ─── reset ───────────────────────────────────────────────────────────────

#[test]
fn encoder_reset_round_trip() {
    let mut enc = Encoder::new();
    let mut buf = vec![0u8; 1024];

    for input in [b"abc".as_ref(), b"defgh".as_ref(), b"".as_ref()] {
        enc.reset();
        let mut encoded = Vec::new();
        // Feed all at once.
        let (p, _status) = enc.encode(input, &mut buf).unwrap();
        encoded.extend_from_slice(&buf[..p.written]);
        assert_eq!(p.consumed, input.len());
        loop {
            let (p, status) = enc.finish(&mut buf).unwrap();
            encoded.extend_from_slice(&buf[..p.written]);
            if matches!(status, Status::StreamEnd) {
                break;
            }
        }
        let decoded = decode_chunked(&encoded, encoded.len().max(1), 1024);
        assert_eq!(decoded, input);
    }
}

#[test]
fn decoder_reset_round_trip() {
    let mut dec = Decoder::new();
    for input in [b"abc".as_ref(), b"longer message here".as_ref()] {
        let encoded = encode_chunked(input, input.len().max(1), 1024);
        dec.reset();
        let mut decoded = Vec::new();
        let mut buf = vec![0u8; 1024];
        let mut i = 0;
        while i < encoded.len() {
            let (p, status) = dec.decode(&encoded[i..], &mut buf).unwrap();
            decoded.extend_from_slice(&buf[..p.written]);
            i += p.consumed;
            match status {
                Status::InputEmpty | Status::StreamEnd => break,
                Status::OutputFull => continue,
            }
        }
        loop {
            let (p, status) = dec.finish(&mut buf).unwrap();
            decoded.extend_from_slice(&buf[..p.written]);
            if matches!(status, Status::StreamEnd) {
                break;
            }
        }
        assert_eq!(decoded, input);
    }
}

// ─── CAB conformance: hand-built bitstreams checked against libmspack ──
//
// Each stream below was wrapped in a CAB folder and decoded with
// `cabextract` (libmspack) while writing these tests; the expected outputs
// are what it produced.

/// LZX bit writer: 16-bit little-endian words, bits MSB-first.
struct BitW {
    out: Vec<u8>,
    acc: u32,
    n: u32,
}

impl BitW {
    fn new() -> Self {
        Self {
            out: Vec::new(),
            acc: 0,
            n: 0,
        }
    }

    fn put(&mut self, bits: u32, v: u32) {
        for i in (0..bits).rev() {
            self.acc = (self.acc << 1) | ((v >> i) & 1);
            self.n += 1;
            if self.n == 16 {
                self.out.push(self.acc as u8);
                self.out.push((self.acc >> 8) as u8);
                self.acc = 0;
                self.n = 0;
            }
        }
    }

    fn raw(&mut self, b: &[u8]) {
        assert_eq!(self.n, 0, "raw bytes must start on a word boundary");
        self.out.extend_from_slice(b);
    }

    /// The standalone framing: window_bits + LE total length + bitstream.
    fn framed(&self, window_bits: u8, total: usize) -> Vec<u8> {
        let mut s = vec![window_bits];
        s.extend_from_slice(&(total as u32).to_le_bytes());
        s.extend_from_slice(&self.out);
        s
    }
}

/// Uncompressed block, padded the way MS-CAB / libmspack expect: 1..=16
/// bits to the next word boundary, R0..R2, the data, a pad byte if odd.
fn put_uncompressed_block(w: &mut BitW, data: &[u8]) {
    w.put(3, 3);
    w.put(24, data.len() as u32);
    let pad = if w.n == 0 { 16 } else { 16 - w.n };
    w.put(pad, 0);
    for _ in 0..3 {
        w.raw(&1u32.to_le_bytes());
    }
    w.raw(data);
    if data.len() % 2 == 1 {
        w.raw(&[0]);
    }
}

fn decode_all_ways(stream: &[u8]) -> Vec<u8> {
    let whole = decode_chunked(stream, stream.len(), 1 << 20);
    for (i, o) in [(1, 1), (3, 7), (4096, 1000)] {
        assert_eq!(decode_chunked(stream, i, o), whole, "chunking {i}/{o}");
    }
    whole
}

/// libmspack's E8 decode over one frame: `curpos` is the absolute output
/// position of the 0xE8 byte.
fn e8_reference(frame: &mut [u8], frame_start: i64, filesize: i64) {
    if frame.len() <= 10 {
        return;
    }
    let mut i = 0;
    while i < frame.len() - 10 {
        if frame[i] != 0xE8 {
            i += 1;
            continue;
        }
        let curpos = frame_start + i as i64;
        let abs = i32::from_le_bytes(frame[i + 1..i + 5].try_into().unwrap()) as i64;
        if -curpos <= abs && abs < filesize {
            let rel = if abs >= 0 {
                abs - curpos
            } else {
                abs + filesize
            };
            frame[i + 1..i + 5].copy_from_slice(&(rel as i32).to_le_bytes());
        }
        i += 5;
    }
}

/// The E8 call-translation filter measures `curpos` at the 0xE8 byte, and
/// it runs over whole 32 KiB frames. It used to be off by one, and with
/// small input chunks it drained partial frames before translating them.
#[test]
fn cab_e8_translation_matches_libmspack() {
    const FILESIZE: u32 = 0x0010_0000;
    let mut data = vec![0x90u8; 1000];
    let sites: [(usize, i32); 6] = [
        (0, 5),
        (17, -3),
        (100, 1000),
        (300, 50_000),
        (500, -200),
        (989, 7),
    ];
    for (i, v) in sites {
        data[i] = 0xE8;
        data[i + 1..i + 5].copy_from_slice(&v.to_le_bytes());
    }
    let mut w = BitW::new();
    w.put(1, 1);
    w.put(32, FILESIZE);
    put_uncompressed_block(&mut w, &data);
    let out = decode_all_ways(&w.framed(16, data.len()));
    // Values cabextract produced for this stream.
    let want = [5, 1_048_573, 900, 49_700, 1_048_376, -982];
    for ((i, _), want) in sites.iter().zip(want) {
        assert_eq!(
            i32::from_le_bytes(out[i + 1..i + 5].try_into().unwrap()),
            want,
            "@{i}"
        );
    }

    // Several frames, E8 sites everywhere (including frame tails, which are
    // left alone), fed in small chunks.
    let mut data: Vec<u8> = (0..80_000u32).map(|i| (i * 31 % 251) as u8).collect();
    let mut i = 3;
    while i + 5 < data.len() {
        data[i] = 0xE8;
        i += 97 + (i % 13);
    }
    let mut w = BitW::new();
    w.put(1, 1);
    w.put(32, FILESIZE);
    for block in data.chunks(30_000) {
        put_uncompressed_block(&mut w, block);
    }
    let mut want = data.clone();
    for (k, frame) in want.chunks_mut(32_768).enumerate() {
        e8_reference(frame, (k * 32_768) as i64, FILESIZE as i64);
    }
    assert_eq!(decode_all_ways(&w.framed(16, data.len())), want);
}

/// Verbatim block coding `data` as literals only: every byte value gets an
/// 8-bit code (so a literal's code is the byte itself), no matches. The
/// pretree codes "length 8" (delta symbol 9) and "length 0" (symbol 0) in
/// one bit each. With `realign`, the bitstream is padded to a word boundary
/// after each 32 KiB frame, as MS-CAB compressors do.
fn put_verbatim_literals(w: &mut BitW, window_bits: u8, data: &[u8], realign: bool) {
    let slots = [30u32, 32, 34, 36, 38, 42, 50][(window_bits - 15) as usize];
    w.put(3, 1);
    w.put(24, data.len() as u32);
    let pretree = |w: &mut BitW| {
        for sym in 0..20 {
            w.put(4, u32::from(sym == 0 || sym == 9));
        }
    };
    pretree(w);
    for _ in 0..256 {
        w.put(1, 1); // main lens 0..256: 0 -> 8
    }
    pretree(w);
    for _ in 0..slots * 8 {
        w.put(1, 0); // no match symbols
    }
    pretree(w);
    for _ in 0..249 {
        w.put(1, 0); // empty length tree
    }
    for (i, &b) in data.iter().enumerate() {
        if realign && i > 0 && i % 32_768 == 0 && w.n != 0 {
            w.put(16 - w.n, 0);
        }
        w.put(8, u32::from(b));
    }
}

/// The bitstream is realigned to 16 bits at every 32 KiB frame boundary
/// (cabextract decodes this stream; without the padding it does not). The
/// decoder used to read straight through, mis-decoding everything after
/// the first frame.
#[test]
fn cab_frame_boundary_realigns_bitstream() {
    let data: Vec<u8> = (0..80_000u32).map(|i| (i % 251) as u8).collect();
    let mut w = BitW::new();
    w.put(1, 0);
    put_verbatim_literals(&mut w, 16, &data, true);
    // The frame-1 symbols end mid-word, so the padding is really there.
    assert_ne!((1 + 27 + 3 * 80 + 256 + 256 + 249 + 8 * 32_768) % 16, 0);
    assert_eq!(decode_all_ways(&w.framed(16, data.len())), data);
}

/// An uncompressed block whose 27-bit header ends exactly on a word
/// boundary is followed by a whole 16-bit padding word (the rule is 1..=16
/// bits, not 0..=15). The decoder used to treat the padding as R0.
#[test]
fn cab_word_aligned_uncompressed_header_skips_full_pad_word() {
    let data: Vec<u8> = (0..110u32).map(|i| (i * 13) as u8).collect();
    let mut w = BitW::new();
    w.put(1, 0);
    put_verbatim_literals(&mut w, 16, &data[..100], false);
    assert_eq!((w.n + 27) % 16, 0, "next header must end word-aligned");
    put_uncompressed_block(&mut w, &data[100..]);
    assert_eq!(decode_all_ways(&w.framed(16, data.len())), data);
}

/// Odd-sized uncompressed blocks carry one pad byte, and a following block
/// must decode normally. The decoder used to reject the pad with
/// `Unsupported`, so any stream with an odd uncompressed block before its
/// last one failed.
#[test]
fn cab_odd_uncompressed_block_followed_by_more() {
    let data: Vec<u8> = (0..1001u32).map(|i| (i * 7) as u8).collect();
    let mut w = BitW::new();
    w.put(1, 0);
    put_uncompressed_block(&mut w, &data[..501]);
    put_uncompressed_block(&mut w, &data[501..]);
    assert_eq!(decode_all_ways(&w.framed(16, data.len())), data);
}

/// A frame boundary can fall on an odd byte inside an uncompressed block
/// (here the block starts at frame offset 32767). The decoder used to put
/// both bytes of that word in the old frame, making it 32769 bytes long
/// and shifting E8 translation for everything after it.
#[test]
fn cab_frame_boundary_inside_uncompressed_word() {
    const FILESIZE: u32 = 0x0010_0000;
    let mut head: Vec<u8> = (0..32_767u32).map(|i| (i % 200) as u8).collect();
    // Frame 1 ends at 32768: an E8 at 32758 is inside its last 10 bytes and
    // must stay untranslated, which only holds if the frame ends there.
    head[32_758..32_763].copy_from_slice(&[0xE8, 5, 0, 0, 0]);
    let mut tail: Vec<u8> = (0..3_000u32).map(|i| (i % 200) as u8).collect();
    for i in [0usize, 7, 20, 300, 2_980] {
        tail[i] = 0xE8;
    }
    let mut w = BitW::new();
    w.put(1, 1);
    w.put(32, FILESIZE);
    put_verbatim_literals(&mut w, 16, &head, true);
    put_uncompressed_block(&mut w, &tail);
    let mut want = head.clone();
    want.extend_from_slice(&tail);
    for (k, frame) in want.chunks_mut(32_768).enumerate() {
        e8_reference(frame, (k * 32_768) as i64, FILESIZE as i64);
    }
    let total = want.len();
    assert_eq!(decode_all_ways(&w.framed(16, total)), want);
}

/// Verbatim block coding `data` as literals with the given literal code
/// lengths (first block, so every pretree delta is taken from 0). Pretree:
/// delta symbol 0 at 1 bit, symbols 1..=16 at 5 bits.
fn put_verbatim_with_lens(w: &mut BitW, window_bits: u8, lens: &[u8; 256], data: &[u8]) {
    let slots = [30u32, 32, 34, 36, 38, 42, 50][(window_bits - 15) as usize];
    w.put(3, 1);
    w.put(24, data.len() as u32);
    let pretree = |w: &mut BitW| {
        for sym in 0..20 {
            w.put(
                4,
                [1, 5][usize::from((1..=16).contains(&sym))] * u32::from(sym <= 16),
            );
        }
    };
    // Canonical pretree codes: sym 0 = "0", sym k (1..=16) = "1" + (k-1) in 4 bits.
    let delta = |w: &mut BitW, len: u8| {
        let sym = (17 - u32::from(len)) % 17;
        if sym == 0 {
            w.put(1, 0);
        } else {
            w.put(5, 0b10000 | (sym - 1));
        }
    };
    pretree(w);
    for &l in lens {
        delta(w, l);
    }
    pretree(w);
    for _ in 0..slots * 8 {
        delta(w, 0);
    }
    pretree(w);
    for _ in 0..249 {
        delta(w, 0);
    }
    // Canonical literal codes.
    let mut count = [0u32; 17];
    for &l in lens {
        count[usize::from(l)] += 1;
    }
    count[0] = 0;
    let mut next = [0u32; 17];
    let mut code = 0;
    for l in 1..17 {
        code = (code + count[l - 1]) << 1;
        next[l] = code;
    }
    let mut codes = [0u32; 256];
    for (s, &l) in lens.iter().enumerate() {
        if l > 0 {
            codes[s] = next[usize::from(l)];
            next[usize::from(l)] += 1;
        }
    }
    for &b in data {
        w.put(u32::from(lens[usize::from(b)]), codes[usize::from(b)]);
    }
}

/// A tree's longest code can exceed the bits left in the stream: the final
/// symbols here are 1-bit codes but the tree's max length is 16, so near the
/// end fewer than 16 bits remain. The decoder used to wait for bits that
/// never come and `finish` failed with `UnexpectedEnd`; libmspack pads the
/// end of input with zeros, as the decoder now does on `finish`.
#[test]
fn cab_long_max_code_near_end_of_stream() {
    let mut lens = [0u8; 256];
    for (k, l) in lens.iter_mut().enumerate().take(16) {
        *l = k as u8 + 1;
    }
    lens[16] = 16;
    for n in [1usize, 5, 11, 100, 1003] {
        let data: Vec<u8> = (0..n).map(|i| if i % 7 == 3 { 5 } else { 0 }).collect();
        let mut w = BitW::new();
        w.put(1, 0);
        put_verbatim_with_lens(&mut w, 16, &lens, &data);
        if w.n != 0 {
            w.put(16 - w.n, 0);
        }
        assert_eq!(decode_all_ways(&w.framed(16, n)), data, "n={n}");
    }
}

/// A match that ends exactly on a 32 KiB frame boundary, followed by more
/// symbols in the same block. The decoder used to read the next symbol
/// before closing the frame, so it skipped the frame-end realignment (and
/// the E8 pass), mis-decoding the rest of the stream. Found by comparing
/// random valid streams against cabextract.
#[test]
fn cab_match_ending_on_frame_boundary() {
    // First block, window 16: main alphabet 256 + 32 * 8. Symbols: 'a' (1
    // bit), 'b' (2 bits) and match symbol 256 = slot 0 (R0 = 1), length 2
    // (2 bits). Empty length tree. Pretree deltas from 0: "0" = keep 0,
    // "1" + 4 bits = delta symbol k in 1..=16.
    let main_len = 256 + 32 * 8;
    let mut lens = vec![0u8; main_len];
    lens[usize::from(b'a')] = 1;
    lens[usize::from(b'b')] = 2;
    lens[256] = 2;
    // Canonical codes: 'a' = 0, 'b' = 10, match = 11.
    let mut w = BitW::new();
    w.put(1, 0);
    let n_a = 32_766usize;
    let n_b = 100usize;
    w.put(3, 1);
    w.put(24, (n_a + 2 + n_b) as u32);
    let deltas = |w: &mut BitW, lens: &[u8]| {
        for sym in 0..20 {
            w.put(
                4,
                [1, 5][usize::from((1..=16).contains(&sym))] * u32::from(sym <= 16),
            );
        }
        for &l in lens {
            let sym = (17 - u32::from(l)) % 17;
            if sym == 0 {
                w.put(1, 0);
            } else {
                w.put(5, 0b10000 | (sym - 1));
            }
        }
    };
    deltas(&mut w, &lens[..256]);
    deltas(&mut w, &lens[256..]);
    deltas(&mut w, &[0u8; 249]);
    for _ in 0..n_a {
        w.put(1, 0);
    }
    w.put(2, 0b11); // match: 2 bytes at distance 1 → output reaches 32768
    assert_ne!(w.n, 0, "frame end must be mid-word for the test to bite");
    w.put(16 - w.n, 0); // frame-end realignment
    for _ in 0..n_b {
        w.put(2, 0b10);
    }
    if w.n != 0 {
        w.put(16 - w.n, 0);
    }
    let mut want = vec![b'a'; n_a + 2];
    want.extend_from_slice(&[b'b'; 100]);
    assert_eq!(decode_all_ways(&w.framed(16, want.len())), want);
}

// ─── audit regressions: end of input, declared total, finish ────────────

/// Like `decode_chunked`, but returns the decoder's error instead of
/// panicking on it.
fn try_decode(stream: &[u8], in_chunk: usize, out_chunk: usize) -> Result<Vec<u8>, Error> {
    let mut dec = Decoder::new();
    let mut decoded = Vec::new();
    let mut buf = vec![0u8; out_chunk.max(1)];
    for chunk in stream.chunks(in_chunk.max(1)) {
        let mut consumed = 0;
        while consumed < chunk.len() {
            let (p, status) = dec.decode(&chunk[consumed..], &mut buf)?;
            decoded.extend_from_slice(&buf[..p.written]);
            consumed += p.consumed;
            match status {
                Status::StreamEnd => return Ok(decoded),
                Status::InputEmpty => break,
                Status::OutputFull => {}
            }
        }
    }
    loop {
        let (p, status) = dec.finish(&mut buf)?;
        decoded.extend_from_slice(&buf[..p.written]);
        if status == Status::StreamEnd {
            return Ok(decoded);
        }
        assert_ne!(p.written, 0, "finish stalled after {} bytes", decoded.len());
    }
}

/// Every chunking must agree on the result, error or not.
fn try_decode_all_ways(stream: &[u8]) -> Result<Vec<u8>, Error> {
    let whole = try_decode(stream, stream.len(), 1 << 20);
    for (i, o) in [(1, 1), (1, 4096), (3, 7), (4096, 1)] {
        let got = try_decode(stream, i, o);
        match (&whole, &got) {
            (Ok(a), Ok(b)) => assert_eq!(a, b, "chunking {i}/{o}"),
            (Err(_), Err(_)) => {}
            _ => panic!("chunking {i}/{o}: {got:?} vs one-shot {whole:?}"),
        }
    }
    whole
}

/// No proper prefix of `stream` may decode successfully to anything but
/// `want` (a prefix that only loses tolerated trailing padding may still
/// decode in full). Returns how many prefixes decoded.
fn check_prefixes(stream: &[u8], want: &[u8]) -> usize {
    let mut ok = 0;
    // From 1: zero bytes of input is, by design, the empty stream.
    for cut in 1..stream.len() {
        if let Ok(got) = try_decode_all_ways(&stream[..cut]) {
            assert_eq!(got, want, "prefix of {cut}/{} bytes", stream.len());
            ok += 1;
        }
    }
    ok
}

/// `finish` pads the input with one zero word for Huffman lookahead. A
/// stream missing its last word used to have that padding decoded as data:
/// two zero bytes in an uncompressed block, up to 16 bits of symbols in a
/// Huffman block.
#[test]
fn stream_missing_last_word_is_rejected() {
    let data = b"hello world, this is the LZX tail!";
    let enc = encode_chunked(data, data.len(), 256);
    assert_eq!(try_decode_all_ways(&enc).unwrap(), data);
    assert_eq!(
        try_decode_all_ways(&enc[..enc.len() - 2]),
        Err(Error::UnexpectedEnd)
    );
    assert_eq!(check_prefixes(&enc, data), 0);

    // Verbatim block of 8-bit literals; the last word holds real symbols.
    let data: Vec<u8> = (0..23u32).map(|i| (i * 37 + 1) as u8).collect();
    let mut w = BitW::new();
    w.put(1, 0);
    put_verbatim_literals(&mut w, 16, &data, false);
    let tail_bits = if w.n == 0 { 16 } else { w.n };
    if w.n != 0 {
        w.put(16 - w.n, 0);
    }
    let s = w.framed(16, data.len());
    assert_eq!(try_decode_all_ways(&s).unwrap(), data);
    assert_eq!(
        try_decode_all_ways(&s[..s.len() - 2]),
        Err(Error::UnexpectedEnd)
    );
    assert_eq!(check_prefixes(&s, &data), 0, "tail bits {tail_bits}");

    // Zero literals coded as a 1-bit zero code look exactly like the pad.
    let mut lens = [0u8; 256];
    lens[0] = 1;
    lens[1] = 1;
    for n in [16usize, 17, 31, 40] {
        let mut w = BitW::new();
        w.put(1, 0);
        put_verbatim_with_lens(&mut w, 16, &lens, &vec![0u8; n]);
        if w.n != 0 {
            w.put(16 - w.n, 0);
        }
        let s = w.framed(16, n);
        assert_eq!(try_decode_all_ways(&s).unwrap(), vec![0u8; n]);
        assert_eq!(
            try_decode_all_ways(&s[..s.len() - 2]),
            Err(Error::UnexpectedEnd),
            "n={n}"
        );
    }
}

/// An odd-sized final uncompressed block does not need its pad byte: there
/// is nothing after it to align (libmspack only skips the pad when another
/// block follows). Dropping that byte must keep decoding; dropping a data
/// byte must not.
#[test]
fn odd_final_uncompressed_block_without_pad_byte() {
    let data: Vec<u8> = (0..41u32).map(|i| (i * 11 + 3) as u8).collect();
    let mut w = BitW::new();
    w.put(1, 0);
    put_uncompressed_block(&mut w, &data);
    let s = w.framed(16, data.len());
    assert_eq!(try_decode_all_ways(&s).unwrap(), data);
    assert_eq!(try_decode_all_ways(&s[..s.len() - 1]).unwrap(), data);
    assert_eq!(
        try_decode_all_ways(&s[..s.len() - 2]),
        Err(Error::UnexpectedEnd)
    );
    assert_eq!(check_prefixes(&s, &data), 1);
}

/// Pretree with all 20 lengths = 5 (so code == symbol), then one 5-bit
/// delta per code length (first block: the previous lengths are all 0).
fn put_lens_fixed5(w: &mut BitW, lens: &[u8]) {
    for _ in 0..20 {
        w.put(4, 5);
    }
    for &l in lens {
        w.put(5, (17 - u32::from(l)) % 17);
    }
}

/// Header of a verbatim block (window 15) whose main tree is: literal 0 =
/// "0" and `sym10` = "10"; "11" is not a code. No length tree.
fn put_overshoot_header(w: &mut BitW, block_size: u32, sym10: usize) {
    w.put(1, 0);
    w.put(3, 1);
    w.put(24, block_size);
    let mut main = vec![0u8; 256 + 30 * 8];
    main[0] = 1;
    main[sym10] = 2;
    put_lens_fixed5(w, &main[..256]);
    put_lens_fixed5(w, &main[256..]);
    put_lens_fixed5(w, &[0u8; 249]);
}

/// The declared total ends the stream, even inside a block whose
/// BLOCK_SIZE runs past it. The symbol loop used to keep decoding as long
/// as bits were buffered, so garbage after the last byte was an error when
/// it arrived in the same `decode` call and ignored when it did not.
#[test]
fn total_reached_mid_block_ignores_what_follows() {
    // How many bits are left in the current word after the header.
    let mut probe = BitW::new();
    put_overshoot_header(&mut probe, 5, 1);
    let fill = 16 - probe.n;
    // `k` zero literals then a lone "1": a word boundary, and a decoder that
    // reads on is one bit short of a symbol.
    let k = if fill > 1 { fill - 1 } else { 16 };
    let mut w = BitW::new();
    put_overshoot_header(&mut w, k + 5, 1);
    for _ in 0..k {
        w.put(1, 0);
    }
    w.put(1, 1);
    assert_eq!(w.n, 0);
    w.raw(&[0xFF; 8]); // "11" is not a code
    let s = w.framed(15, k as usize);
    assert_eq!(try_decode_all_ways(&s), Ok(vec![0u8; k as usize]));
}

/// Same, with the total falling inside a match: the match's surplus byte
/// is dropped and nothing after it is read.
#[test]
fn total_reached_mid_match_ignores_what_follows() {
    // Symbol 256: match, position slot 0 (R0 = 1), length 2.
    let mut probe = BitW::new();
    put_overshoot_header(&mut probe, 5, 256);
    let fill = 16 - probe.n;
    let k = if fill > 3 { fill - 3 } else { fill + 13 };
    let mut w = BitW::new();
    put_overshoot_header(&mut w, k + 7, 256);
    for _ in 0..k {
        w.put(1, 0);
    }
    w.put(2, 0b10); // 2 bytes at distance 1; the second is past the total
    w.put(1, 1);
    assert_eq!(w.n, 0);
    w.raw(&[0xFF; 8]);
    let s = w.framed(15, k as usize + 1);
    assert_eq!(try_decode_all_ways(&s), Ok(vec![0u8; k as usize + 1]));
}

/// `finish` with no room for output is not an error while bytes are still
/// owed: it used to report `UnexpectedEnd` and poison a healthy decoder.
/// On a stream that really is truncated it must still fail, not stall.
#[test]
fn finish_with_empty_output_on_a_healthy_stream() {
    let data: Vec<u8> = (0..100u32).map(|i| (i * 5 + 1) as u8).collect();
    let enc = encode_chunked(&data, data.len(), 256);
    for out_chunk in [1usize, 7, 4096] {
        let mut dec = Decoder::new();
        let mut got = Vec::new();
        let mut buf = vec![0u8; out_chunk];
        let mut pos = 0;
        while pos < enc.len() {
            let (p, _) = dec.decode(&enc[pos..], &mut buf).unwrap();
            pos += p.consumed;
            got.extend_from_slice(&buf[..p.written]);
        }
        let mut ended = false;
        for _ in 0..3 {
            let (p, status) = dec.finish(&mut []).unwrap();
            assert_eq!(p.written, 0);
            ended = status == Status::StreamEnd;
        }
        while !ended {
            let (p, status) = dec.finish(&mut buf).unwrap();
            got.extend_from_slice(&buf[..p.written]);
            ended = status == Status::StreamEnd;
            assert!(ended || p.written > 0, "finish stalled");
        }
        assert_eq!(got, data, "out_chunk {out_chunk}");
    }

    // Truncated: whatever is still owed can be drained, then it is an error.
    let mut dec = Decoder::new();
    let mut buf = [0u8; 4096];
    let cut = &enc[..enc.len() - 2];
    let (p, _) = dec.decode(cut, &mut buf).unwrap();
    assert_eq!(p.consumed, cut.len());
    assert_eq!(dec.finish(&mut []).unwrap_err(), Error::UnexpectedEnd);
}

// ─── factory ─────────────────────────────────────────────────────────────

#[cfg(feature = "factory")]
mod factory {
    use compcol::Status;
    use compcol::factory;

    #[test]
    fn lookup_known() {
        assert!(factory::encoder_by_name("lzx").is_some());
        assert!(factory::decoder_by_name("lzx").is_some());
    }

    #[test]
    fn lookup_unknown() {
        assert!(factory::encoder_by_name("does-not-exist").is_none());
        assert!(factory::decoder_by_name("does-not-exist").is_none());
    }

    #[test]
    fn names_contains_lzx() {
        assert!(factory::names().contains(&"lzx"));
    }

    #[test]
    fn boxed_round_trip() {
        // The fallback encoder emits uncompressed blocks; round-trip via the
        // boxed trait objects to confirm the factory hooks up correctly.
        let mut enc = factory::encoder_by_name("lzx").unwrap();
        let mut dec = factory::decoder_by_name("lzx").unwrap();
        let input = b"hello hello hello";
        let mut buf = vec![0u8; 256];
        let mut encoded = Vec::new();
        let (p, _) = enc.encode(input, &mut buf).unwrap();
        encoded.extend_from_slice(&buf[..p.written]);
        assert_eq!(p.consumed, input.len());
        loop {
            let (pf, status) = enc.finish(&mut buf).unwrap();
            encoded.extend_from_slice(&buf[..pf.written]);
            if matches!(status, Status::StreamEnd) {
                break;
            }
        }

        let mut decoded = Vec::new();
        let mut i = 0;
        while i < encoded.len() {
            let (pd, status) = dec.decode(&encoded[i..], &mut buf).unwrap();
            decoded.extend_from_slice(&buf[..pd.written]);
            i += pd.consumed;
            match status {
                Status::InputEmpty | Status::StreamEnd => break,
                Status::OutputFull => continue,
            }
        }
        loop {
            let (pdf, status) = dec.finish(&mut buf).unwrap();
            decoded.extend_from_slice(&buf[..pdf.written]);
            if matches!(status, Status::StreamEnd) {
                break;
            }
        }
        assert_eq!(decoded, input);
    }
}
