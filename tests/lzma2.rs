//! Streaming round-trip tests for the LZMA2 algorithm.
//!
//! The crate currently ships a stored-only LZMA2 encoder (type-0x01 chunks)
//! and an uncompressed-only decoder. These tests exercise both ends of that
//! contract; the compressed-chunk path is checked only insofar as the decoder
//! must reject it cleanly without panicking.

#![cfg(feature = "lzma2")]

use compcol::lzma2::{Decoder, Encoder, Lzma2};
use compcol::{Algorithm, Decoder as _, Encoder as _, Error};

/// Encode `input` using fixed chunk sizes on both sides, returning the
/// resulting LZMA2 byte stream.
fn encode_chunked(input: &[u8], in_chunk: usize, out_chunk: usize) -> Vec<u8> {
    let mut enc = Encoder::new();
    let mut encoded = Vec::new();
    let mut buf = vec![0u8; out_chunk.max(1)];
    let mut i = 0usize;

    while i < input.len() {
        let end = (i + in_chunk).min(input.len());
        let chunk = &input[i..end];
        let mut consumed_in_chunk = 0usize;
        while consumed_in_chunk < chunk.len() {
            let p = enc.encode(&chunk[consumed_in_chunk..], &mut buf).unwrap();
            encoded.extend_from_slice(&buf[..p.written]);
            consumed_in_chunk += p.consumed;
            if p.consumed == 0 && p.written == 0 {
                panic!("encoder stalled mid-input");
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
    let mut i = 0usize;

    while i < encoded.len() {
        let end = (i + in_chunk).min(encoded.len());
        let chunk = &encoded[i..end];
        let mut consumed_in_chunk = 0usize;
        while consumed_in_chunk < chunk.len() {
            let p = dec.decode(&chunk[consumed_in_chunk..], &mut buf).unwrap();
            decoded.extend_from_slice(&buf[..p.written]);
            consumed_in_chunk += p.consumed;
            if p.consumed == 0 && p.written == 0 {
                // Decoder accepted the bytes already; loop on next chunk.
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
            panic!("decoder finish stalled");
        }
    }

    decoded
}

fn round_trip_chunked(input: &[u8], in_chunk: usize, out_chunk: usize) {
    let encoded = encode_chunked(input, in_chunk, out_chunk);
    let decoded = decode_chunked(&encoded, in_chunk, out_chunk);
    assert_eq!(decoded.len(), input.len(), "decoded length mismatch");
    assert_eq!(decoded, input, "round-trip mismatch");
}

fn round_trip(input: &[u8]) {
    // Large buffers on both sides — exercises the fast path.
    let big_in = input.len().max(1);
    let big_out = (input.len() + 32).max(64);
    round_trip_chunked(input, big_in, big_out);
}

#[test]
fn name_is_lzma2() {
    assert_eq!(<Lzma2 as Algorithm>::NAME, "lzma2");
}

#[test]
fn empty_input() {
    // The encoder for empty input should just emit a 0x00 end-of-stream marker.
    let mut enc = Encoder::new();
    let mut out = [0u8; 16];
    let p = enc.encode(&[], &mut out).unwrap();
    assert_eq!(p.consumed, 0);
    assert_eq!(p.written, 0);
    let mut total = Vec::new();
    loop {
        let pf = enc.finish(&mut out).unwrap();
        total.extend_from_slice(&out[..pf.written]);
        if pf.done {
            break;
        }
        if pf.written == 0 {
            panic!("encoder finish stalled on empty input");
        }
    }
    assert_eq!(total, vec![0x00]);

    // Decoder over `[0x00]` should decode to nothing and finish cleanly.
    let mut dec = Decoder::new();
    let mut buf = [0u8; 4];
    let p = dec.decode(&total, &mut buf).unwrap();
    assert_eq!(p.consumed, 1);
    assert_eq!(p.written, 0);
    let pf = dec.finish(&mut buf).unwrap();
    assert!(pf.done);
    assert_eq!(pf.written, 0);
}

#[test]
fn single_byte() {
    round_trip(&[0x42]);
}

#[test]
fn header_layout_for_single_byte_chunk() {
    // Spot-check the wire format for the smallest possible chunk: control=0x01,
    // big-endian size-minus-1 = 0x0000, then the single payload byte, then the
    // 0x00 end-of-stream marker.
    let encoded = encode_chunked(&[0xAB], 1, 16);
    assert_eq!(encoded, vec![0x01, 0x00, 0x00, 0xAB, 0x00]);
}

#[test]
fn short_input() {
    round_trip(b"hello, lzma2 world");
}

#[test]
fn pseudo_random_input() {
    // Tiny LCG, fixed seed — keeps the test dependency-free and deterministic.
    let mut state: u32 = 0xDEADBEEFu32;
    let mut input = Vec::with_capacity(8192);
    for _ in 0..8192 {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        input.push((state >> 16) as u8);
    }
    round_trip(&input);
}

#[test]
fn long_input_forces_multiple_chunks() {
    // 200_000 bytes — must be carried by at least 4 type-0x01 chunks
    // (each capped at 65_536 uncompressed bytes by the encoder).
    let mut input = Vec::with_capacity(200_000);
    for i in 0..200_000usize {
        input.push((i as u8).wrapping_mul(31));
    }
    let encoded = encode_chunked(&input, input.len(), 4096);

    // Count the chunk headers we expect to see: 200_000 = 65_536 + 65_536 +
    // 65_536 + 3_392, so 4 chunks. Each starts with 0x01 plus 2 size bytes.
    // We just verify chunk count by walking the stream.
    let mut chunks = 0;
    let mut i = 0;
    while i < encoded.len() {
        match encoded[i] {
            0x00 => {
                assert_eq!(i, encoded.len() - 1, "EOS marker should be last byte");
                break;
            }
            0x01 => {
                let size = ((encoded[i + 1] as u32) << 8 | encoded[i + 2] as u32) + 1;
                chunks += 1;
                i += 3 + size as usize;
            }
            other => panic!("unexpected control byte 0x{other:02X} at offset {i}"),
        }
    }
    assert_eq!(chunks, 4, "expected 4 chunks for 200_000 bytes");

    let decoded = decode_chunked(&encoded, encoded.len(), 4096);
    assert_eq!(decoded, input);
}

#[test]
fn streaming_one_byte_buffers_round_trip() {
    // The acid test: 1-byte input and output buffers on both sides.
    let input: Vec<u8> = (0..1024u32).map(|i| (i % 251) as u8).collect();
    let encoded = encode_chunked(&input, 1, 1);
    let decoded = decode_chunked(&encoded, 1, 1);
    assert_eq!(decoded, input);
}

#[test]
fn streaming_just_over_64k_with_tiny_buffers() {
    // Force the encoder to commit to a 65_536-byte chunk and then a 1-byte
    // chunk, with cramped buffers on both sides.
    let mut input = Vec::with_capacity(65_537);
    let mut state: u32 = 0x12345678u32;
    for _ in 0..65_537usize {
        state = state.wrapping_mul(1_103_515_245).wrapping_add(12345);
        input.push((state >> 24) as u8);
    }
    let encoded = encode_chunked(&input, 7, 13);
    let decoded = decode_chunked(&encoded, 11, 17);
    assert_eq!(decoded.len(), input.len());
    assert_eq!(decoded, input);
}

#[test]
fn decoder_rejects_compressed_chunk_as_unsupported() {
    // A compressed-LZMA chunk control byte (any of 0x80..=0xFF) must surface
    // as Error::Unsupported, not panic, not Corrupt.
    let mut dec = Decoder::new();
    let mut out = [0u8; 4];
    let err = dec
        .decode(&[0xE0, 0x00, 0x00, 0x00, 0x00, 0x5D], &mut out)
        .unwrap_err();
    assert_eq!(err, Error::Unsupported);
}

#[test]
fn decoder_rejects_invalid_control_byte() {
    // 0x03..=0x7F are unassigned — those must hit the Corrupt path.
    let mut dec = Decoder::new();
    let mut out = [0u8; 4];
    let err = dec.decode(&[0x03], &mut out).unwrap_err();
    assert_eq!(err, Error::Corrupt);

    let mut dec = Decoder::new();
    let err = dec.decode(&[0x7F], &mut out).unwrap_err();
    assert_eq!(err, Error::Corrupt);
}

#[test]
fn decoder_truncated_uncompressed_chunk_is_unexpected_end() {
    // 0x01 header + size-minus-1 = 0x0003 (so 4 payload bytes), but we only
    // give the decoder 2 of those bytes before calling finish().
    let mut dec = Decoder::new();
    let mut out = [0u8; 16];
    let p = dec
        .decode(&[0x01, 0x00, 0x03, 0xAA, 0xBB], &mut out)
        .unwrap();
    // Two payload bytes are streamed out; the decoder is mid-chunk.
    assert_eq!(p.consumed, 5);
    assert_eq!(p.written, 2);
    let err = dec.finish(&mut out).unwrap_err();
    assert_eq!(err, Error::UnexpectedEnd);
}

#[test]
fn decoder_missing_eos_marker_is_unexpected_end() {
    // Single chunk delivered fully but no 0x00 marker at the end.
    let mut dec = Decoder::new();
    let mut out = [0u8; 16];
    let p = dec.decode(&[0x01, 0x00, 0x00, 0x42], &mut out).unwrap();
    assert_eq!(p.consumed, 4);
    assert_eq!(p.written, 1);
    let err = dec.finish(&mut out).unwrap_err();
    assert_eq!(err, Error::UnexpectedEnd);
}

#[test]
fn decoder_type_2_chunk_decodes_without_reset() {
    // Hand-craft a stream with a 0x01 chunk (1 byte 0xAA) followed by a 0x02
    // chunk (1 byte 0xBB) followed by the 0x00 EOS marker.
    let stream = [0x01, 0x00, 0x00, 0xAA, 0x02, 0x00, 0x00, 0xBB, 0x00];
    let decoded = decode_chunked(&stream, stream.len(), 4);
    assert_eq!(decoded, vec![0xAA, 0xBB]);
}

#[test]
fn encoder_reset_recycles_state() {
    let mut enc = Encoder::new();
    let mut out = [0u8; 32];

    // Partially encode then reset.
    let _ = enc.encode(b"abcd", &mut out).unwrap();
    enc.reset();

    // After reset, a fresh round-trip should work and produce *only* the new
    // input's bytes — no leftovers from before the reset.
    let _ = enc.encode(b"xy", &mut out).unwrap();
    let mut total = Vec::new();
    total.extend_from_slice(&out[..5]); // header(3) + payload(2)
    let pf = enc.finish(&mut out).unwrap();
    total.extend_from_slice(&out[..pf.written]);
    assert!(pf.done);
    assert_eq!(total, vec![0x01, 0x00, 0x01, b'x', b'y', 0x00]);
}

#[test]
fn decoder_reset_recycles_state() {
    let mut dec = Decoder::new();
    let mut out = [0u8; 16];

    // Drive it into a poisoned-looking mid-state, then reset.
    let p = dec.decode(&[0x01, 0x00, 0x02, 0xAA], &mut out).unwrap();
    assert_eq!(p.consumed, 4);
    assert_eq!(p.written, 1);
    dec.reset();

    // Fresh stream after reset.
    let p = dec
        .decode(&[0x01, 0x00, 0x00, 0xCD, 0x00], &mut out)
        .unwrap();
    assert_eq!(p.consumed, 5);
    assert_eq!(p.written, 1);
    assert_eq!(out[0], 0xCD);
    let pf = dec.finish(&mut out).unwrap();
    assert!(pf.done);
}
