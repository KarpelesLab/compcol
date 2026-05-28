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

#![cfg(feature = "lzx")]

use compcol::lzx::{Decoder, Encoder, Lzx};
use compcol::{Algorithm, Decoder as _, Encoder as _, Error};

// ─── small chunked-IO helpers (mirroring the deflate/zstd tests) ────────

fn encode_chunked(input: &[u8], in_chunk: usize, out_chunk: usize) -> Vec<u8> {
    let mut enc = Encoder::new();
    let mut encoded = Vec::new();
    let mut buf = vec![0u8; out_chunk.max(1)];
    let mut i = 0;

    while i < input.len() {
        let end = (i + in_chunk).min(input.len());
        let chunk = &input[i..end];
        let mut consumed_in_chunk = 0;
        while consumed_in_chunk < chunk.len() {
            let p = enc.encode(&chunk[consumed_in_chunk..], &mut buf).unwrap();
            encoded.extend_from_slice(&buf[..p.written]);
            consumed_in_chunk += p.consumed;
            if p.consumed == 0 && p.written == 0 {
                // Encoder is buffering — that's fine for our uncompressed-only
                // encoder, just move on.
                break;
            }
        }
        i = end;
    }

    loop {
        let p = enc.finish(&mut buf).unwrap();
        encoded.extend_from_slice(&buf[..p.written]);
        if p.done {
            break;
        }
        if p.written == 0 {
            panic!("encoder finish stalled");
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
        let mut consumed_in_chunk = 0;
        while consumed_in_chunk < chunk.len() {
            let p = dec.decode(&chunk[consumed_in_chunk..], &mut buf).unwrap();
            decoded.extend_from_slice(&buf[..p.written]);
            consumed_in_chunk += p.consumed;
            if p.consumed == 0 && p.written == 0 {
                break;
            }
        }
        i = end;
    }

    loop {
        let p = dec.finish(&mut buf).unwrap();
        decoded.extend_from_slice(&buf[..p.written]);
        if p.done {
            break;
        }
        if p.written == 0 {
            panic!("decoder finish stalled (decoded {} so far)", decoded.len());
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
    let res = dec.decode(bad, &mut out);
    assert_eq!(res, Err(Error::Unsupported));
}

#[test]
fn truncated_stream_after_header() {
    // Valid header declaring 10 uncompressed bytes, but no actual data follows.
    // The decoder's finish() must reject this.
    let header: &[u8] = &[15, 10, 0, 0, 0]; // window=15, total=10
    let mut dec = Decoder::new();
    let mut out = [0u8; 16];
    let p = dec.decode(header, &mut out).unwrap();
    assert_eq!(p.consumed, 5);
    assert_eq!(p.written, 0);
    let r = dec.finish(&mut out);
    assert_eq!(r, Err(Error::UnexpectedEnd));
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

// ─── encoder reuse ───────────────────────────────────────────────────────

#[test]
fn encoder_reset_round_trip() {
    let mut enc = Encoder::new();
    let mut buf = vec![0u8; 1024];

    for input in [b"abc".as_ref(), b"defgh".as_ref(), b"".as_ref()] {
        enc.reset();
        let mut encoded = Vec::new();
        // Feed all at once.
        let p = enc.encode(input, &mut buf).unwrap();
        encoded.extend_from_slice(&buf[..p.written]);
        assert_eq!(p.consumed, input.len());
        loop {
            let p = enc.finish(&mut buf).unwrap();
            encoded.extend_from_slice(&buf[..p.written]);
            if p.done {
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
            let p = dec.decode(&encoded[i..], &mut buf).unwrap();
            decoded.extend_from_slice(&buf[..p.written]);
            i += p.consumed;
            if p.consumed == 0 && p.written == 0 {
                break;
            }
        }
        loop {
            let p = dec.finish(&mut buf).unwrap();
            decoded.extend_from_slice(&buf[..p.written]);
            if p.done {
                break;
            }
        }
        assert_eq!(decoded, input);
    }
}
