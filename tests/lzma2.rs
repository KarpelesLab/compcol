//! Streaming round-trip tests for the LZMA2 algorithm.
//!
//! The crate currently ships a stored-only LZMA2 encoder (type-0x01 chunks)
//! and a decoder that accepts uncompressed chunks **and** compressed chunks
//! whose control byte requests a dictionary reset (`0xE0..=0xFF`). The
//! compressed-chunk fixtures below were produced by the system `xz` CLI in
//! raw mode:
//!
//! ```sh
//! printf '...' | xz --format=raw --lzma2=preset=6 -c | xxd -p
//! ```
//!
//! The control byte `0xE0` (state reset + new properties + dict reset) is
//! the only compressed variant xz-utils actually emits in normal output,
//! which is why we focus on it here.

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
    // 200_000 bytes — must be carried by at least 4 chunks
    // (each capped at 65_536 uncompressed bytes by the encoder).
    let mut input = Vec::with_capacity(200_000);
    for i in 0..200_000usize {
        input.push((i as u8).wrapping_mul(31));
    }
    let encoded = encode_chunked(&input, input.len(), 4096);

    // Count the chunk headers we expect to see: 200_000 = 65_536 + 65_536 +
    // 65_536 + 3_392, so 4 chunks. Each chunk is either a stored `0x01`
    // (3-byte header + raw payload) or a compressed `0xE0..=0xFF` (5-byte
    // header + LZMA payload). Walk the stream and count, recognising both.
    let mut chunks = 0;
    let mut i = 0;
    while i < encoded.len() {
        match encoded[i] {
            0x00 => {
                assert_eq!(i, encoded.len() - 1, "EOS marker should be last byte");
                break;
            }
            0x01 | 0x02 => {
                let size = ((encoded[i + 1] as u32) << 8 | encoded[i + 2] as u32) + 1;
                chunks += 1;
                i += 3 + size as usize;
            }
            0xE0..=0xFF => {
                // unc top5 in bits 0..4 of ctrl, then 16 bits of unc-low,
                // then 16 bits of cmp-size-1, then props.
                let unc_top5 = (encoded[i] as u32) & 0x1F;
                let unc_low = ((encoded[i + 1] as u32) << 8) | (encoded[i + 2] as u32);
                let _unc = (unc_top5 << 16 | unc_low) + 1;
                let cmp = ((encoded[i + 3] as u32) << 8 | encoded[i + 4] as u32) + 1;
                chunks += 1;
                // header(6) + payload(cmp).
                i += 6 + cmp as usize;
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
fn decoder_rejects_non_dict_reset_compressed_chunk_as_unsupported() {
    // Compressed chunks without a dictionary reset (0x80..=0xDF) still
    // require a persistent inner LZMA state, which we don't carry across
    // chunks in this build. Each of the three sub-ranges must surface
    // cleanly as Error::Unsupported.
    for ctrl in [0x80u8, 0xA0, 0xC0] {
        let mut dec = Decoder::new();
        let mut out = [0u8; 4];
        let err = dec
            .decode(&[ctrl, 0x00, 0x00, 0x00, 0x00, 0x5D], &mut out)
            .unwrap_err();
        assert_eq!(err, Error::Unsupported, "ctrl=0x{ctrl:02X}");
    }
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

    // Partially encode then reset. The current encoder buffers input until a
    // chunk is sealed, so `encode` here writes nothing — `reset` simply
    // discards the buffered "abcd".
    let _ = enc.encode(b"abcd", &mut out).unwrap();
    enc.reset();

    // After reset, a fresh round-trip should work and produce *only* the new
    // input's bytes — no leftovers from before the reset. Two bytes pay too
    // much range-coder overhead to actually compress, so the encoder's
    // size-fallback kicks in and emits a stored `0x01` chunk.
    let mut total = Vec::new();
    loop {
        let p = enc.encode(b"xy", &mut out).unwrap();
        total.extend_from_slice(&out[..p.written]);
        if p.consumed == 2 || (p.consumed == 0 && p.written == 0) {
            break;
        }
    }
    loop {
        let pf = enc.finish(&mut out).unwrap();
        total.extend_from_slice(&out[..pf.written]);
        if pf.done {
            break;
        }
        if pf.written == 0 {
            panic!("encoder finish stalled");
        }
    }
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

// ─── compressed-chunk fixtures (produced by xz-utils raw mode) ──────────────

/// `'hello world '.repeat(50)` (600 bytes) — fits in a single 0xE0 chunk.
///
/// Generated with:
/// ```sh
/// python3 -c "import sys; sys.stdout.buffer.write(b'hello world ' * 50)" \
///   | xz --format=raw --lzma2=preset=6 -c | xxd -p
/// ```
const HELLO_REPEATED_LZMA2: &[u8] = &[
    0xe0, 0x02, 0x57, 0x00, 0x16, 0x5d, 0x00, 0x34, 0x19, 0x49, 0xee, 0x8d, 0xe9, 0x17, 0x89, 0x3a,
    0x33, 0x5f, 0xfd, 0x82, 0x7c, 0x64, 0xd3, 0x9c, 0xa1, 0xcb, 0x89, 0xa0, 0x00, 0x00,
];

/// `b'A' * 4096` — same 0xE0 chunk family, exercises a tight back-reference
/// pattern (every byte after the first is a match).
const REPEATING_4K_LZMA2: &[u8] = &[
    0xe0, 0x0f, 0xff, 0x00, 0x19, 0x5d, 0x00, 0x20, 0xef, 0xfb, 0xbf, 0xfe, 0xa3, 0xb1, 0x5e, 0xe5,
    0xf8, 0x3f, 0xb2, 0xaa, 0x26, 0x55, 0xf8, 0x68, 0x70, 0x41, 0x70, 0x15, 0x0e, 0x24, 0x18, 0xcf,
    0x00,
];

/// 16 KiB of `"The quick brown fox jumps over the lazy dog. "`, generated
/// via `xz --format=raw --lzma2=preset=6` over the first 16 384 bytes of
/// that pangram repeated. Exercises long-distance back-references because
/// the pangram length (45 bytes) doesn't evenly divide 16 384, so xz
/// builds a mixture of fresh literals and matches across the whole window.
const FOX_16K_LZMA2: &[u8] = &[
    0xe0, 0x3f, 0xff, 0x00, 0x63, 0x5d, 0x00, 0x2a, 0x1a, 0x08, 0xa2, 0x03, 0x25, 0x66, 0xf1, 0x4b,
    0x78, 0xc5, 0xa2, 0x05, 0xff, 0x2e, 0xe6, 0xd9, 0xd2, 0x20, 0x1a, 0xad, 0x34, 0xf8, 0xe2, 0x1d,
    0xe8, 0x41, 0x36, 0xfa, 0xdc, 0x06, 0x69, 0xbb, 0x3c, 0xe4, 0x10, 0x34, 0x27, 0x09, 0xeb, 0xb3,
    0x66, 0xe3, 0xed, 0x37, 0x98, 0xed, 0x92, 0xad, 0xd5, 0x27, 0x45, 0x08, 0x30, 0x5e, 0x5d, 0x9a,
    0x3c, 0x41, 0xc4, 0x18, 0x4a, 0x53, 0xf6, 0x6a, 0xd9, 0xfd, 0xd0, 0x04, 0xac, 0x83, 0x78, 0x9d,
    0x17, 0x17, 0x82, 0x3e, 0x6c, 0x38, 0xb1, 0xde, 0xcc, 0x3f, 0xba, 0xe5, 0x03, 0xb1, 0x5b, 0x44,
    0xb8, 0x9d, 0x9c, 0x3d, 0x06, 0x69, 0x4b, 0x3a, 0x2c, 0x00, 0x00,
];

/// Reconstruct the payload that `FOX_16K_LZMA2` should decompress to.
fn fox_text() -> Vec<u8> {
    let unit = "The quick brown fox jumps over the lazy dog. ";
    let repeated = unit.repeat(400);
    repeated.as_bytes()[..16_384].to_vec()
}

/// Drive `dec` to completion against `encoded` using a fixed-size output
/// buffer; mirrors `decode_chunked` above but is simpler since we never
/// need to deliver input in slices for these tests.
fn decode_all(dec: &mut Decoder, encoded: &[u8]) -> Vec<u8> {
    let mut decoded = Vec::new();
    let mut buf = [0u8; 4096];
    let mut i = 0;
    while i < encoded.len() {
        let p = dec.decode(&encoded[i..], &mut buf).unwrap();
        decoded.extend_from_slice(&buf[..p.written]);
        i += p.consumed;
        if p.consumed == 0 && p.written == 0 {
            // Decoder accepted everything from the current slice; advance
            // by 0 means we'll bail out via the while-condition if we'd
            // looped — that only happens if encoded contains garbage,
            // which these tests don't.
            break;
        }
    }
    loop {
        let pf = dec.finish(&mut buf).unwrap();
        decoded.extend_from_slice(&buf[..pf.written]);
        if pf.done {
            break;
        }
        if pf.written == 0 {
            panic!("decoder finish stalled");
        }
    }
    decoded
}

#[test]
fn compressed_empty_stream_is_just_eos_marker() {
    // `xz --format=raw --lzma2=... -c` over zero-length input emits a single
    // 0x00 EOS marker, no chunks at all.
    let mut dec = Decoder::new();
    let decoded = decode_all(&mut dec, &[0x00]);
    assert!(decoded.is_empty());
}

#[test]
fn compressed_hello_world_repeated_round_trip() {
    let expected: Vec<u8> = "hello world "
        .as_bytes()
        .iter()
        .cycle()
        .take(600)
        .copied()
        .collect();
    let mut dec = Decoder::new();
    let decoded = decode_all(&mut dec, HELLO_REPEATED_LZMA2);
    assert_eq!(decoded.len(), 600);
    assert_eq!(decoded, expected);
}

#[test]
fn compressed_4k_repeating_round_trip() {
    let expected = vec![b'A'; 4096];
    let mut dec = Decoder::new();
    let decoded = decode_all(&mut dec, REPEATING_4K_LZMA2);
    assert_eq!(decoded.len(), 4096);
    assert_eq!(decoded, expected);
}

#[test]
fn compressed_16k_fox_round_trip() {
    let expected = fox_text();
    let mut dec = Decoder::new();
    let decoded = decode_all(&mut dec, FOX_16K_LZMA2);
    assert_eq!(decoded.len(), 16_384);
    assert_eq!(decoded, expected);
}

#[test]
fn compressed_chunk_one_byte_input_buffers() {
    // Feed the encoded stream one byte at a time and pull output through a
    // small buffer. Stresses the streaming-header parser and the
    // pump-the-inner-decoder loop in CompData.
    let expected = fox_text();
    let mut dec = Decoder::new();
    let mut decoded = Vec::with_capacity(expected.len());
    let mut buf = [0u8; 7];

    let mut i = 0;
    while i < FOX_16K_LZMA2.len() {
        let one = &FOX_16K_LZMA2[i..i + 1];
        let p = dec.decode(one, &mut buf).unwrap();
        decoded.extend_from_slice(&buf[..p.written]);
        i += p.consumed;
        // After consuming the single byte, drain any pending output by
        // calling decode again with an empty input until written == 0.
        if p.consumed == 1 {
            loop {
                let p2 = dec.decode(&[], &mut buf).unwrap();
                decoded.extend_from_slice(&buf[..p2.written]);
                if p2.written == 0 {
                    break;
                }
            }
        }
    }
    loop {
        let pf = dec.finish(&mut buf).unwrap();
        decoded.extend_from_slice(&buf[..pf.written]);
        if pf.done {
            break;
        }
        if pf.written == 0 {
            panic!("finish stalled");
        }
    }
    assert_eq!(decoded.len(), expected.len());
    assert_eq!(decoded, expected);
}

#[test]
fn compressed_then_uncompressed_chunk_concat() {
    // Hand-glue a compressed chunk (`'A' * 4096`) followed by an
    // uncompressed `0x01` chunk carrying the single byte 0xCD, then EOS.
    // The decoder must clean-finish each chunk before consuming the next
    // control byte. The compressed fixture below ends with the EOS marker
    // `0x00`, so we have to strip that to splice.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&REPEATING_4K_LZMA2[..REPEATING_4K_LZMA2.len() - 1]);
    bytes.extend_from_slice(&[0x01, 0x00, 0x00, 0xCD]);
    bytes.push(0x00); // overall EOS marker

    let mut dec = Decoder::new();
    let decoded = decode_all(&mut dec, &bytes);
    assert_eq!(decoded.len(), 4097);
    assert!(decoded[..4096].iter().all(|&b| b == b'A'));
    assert_eq!(decoded[4096], 0xCD);
}

#[test]
fn compressed_chunk_corrupt_payload_surfaces_error() {
    // Take the 4K repeating fixture, scramble a byte in the LZMA payload,
    // and expect Error::Corrupt (or some non-panic error). The fixture's
    // LZMA payload is at offset 6 (control + 4 size + 1 props).
    let mut bytes = REPEATING_4K_LZMA2.to_vec();
    bytes[10] ^= 0xFF;

    let mut dec = Decoder::new();
    let mut buf = [0u8; 4096];
    // Either the decode call or the finish call should surface an error.
    let mut err = None;
    let mut i = 0;
    while i < bytes.len() {
        match dec.decode(&bytes[i..], &mut buf) {
            Ok(p) => {
                i += p.consumed;
                if p.consumed == 0 && p.written == 0 {
                    break;
                }
            }
            Err(e) => {
                err = Some(e);
                break;
            }
        }
    }
    if err.is_none() {
        err = dec.finish(&mut buf).err();
    }
    let err = err.expect("expected an error on corrupt payload");
    assert!(
        matches!(err, Error::Corrupt | Error::UnexpectedEnd),
        "got {err:?}"
    );
}

#[test]
fn compressed_chunk_invalid_properties_is_bad_header() {
    // Hand-craft a 0xE0 chunk header but with a properties byte beyond the
    // LZMA range (>= 9*5*5 = 225). The decoder should surface BadHeader
    // before touching the payload.
    let bad_props: u8 = 230;
    let stream = [
        0xE0, // ctrl: state reset + props + dict reset, unc top5 = 0
        0x00, 0x00, // uncompressed size = 1
        0x00, 0x00,      // compressed size = 1
        bad_props, // props byte (invalid)
        0x00,      // 1 byte of (unreachable) payload
        0x00,      // EOS marker
    ];
    let mut dec = Decoder::new();
    let mut buf = [0u8; 16];
    let err = dec.decode(&stream, &mut buf).unwrap_err();
    assert_eq!(err, Error::BadHeader);
}

#[test]
fn compressed_chunk_then_reset_recycles_inner_state() {
    // Decode one compressed chunk, reset the decoder, then decode another.
    // The inner LZMA decoder must come back fresh.
    let mut dec = Decoder::new();
    let decoded1 = decode_all(&mut dec, REPEATING_4K_LZMA2);
    assert_eq!(decoded1.len(), 4096);
    dec.reset();
    let decoded2 = decode_all(&mut dec, HELLO_REPEATED_LZMA2);
    assert_eq!(decoded2.len(), 600);
    assert!(decoded2.starts_with(b"hello world "));
}

// ─── encoder: compressed-chunk path ───────────────────────────────────────

/// Walk an LZMA2 stream and count, by chunk type, what kinds of chunks the
/// encoder produced. Returns `(compressed_chunks, uncompressed_chunks)`.
fn classify_chunks(encoded: &[u8]) -> (usize, usize) {
    let mut comp = 0usize;
    let mut uncomp = 0usize;
    let mut i = 0;
    while i < encoded.len() {
        match encoded[i] {
            0x00 => break,
            0x01 | 0x02 => {
                let size = ((encoded[i + 1] as u32) << 8 | encoded[i + 2] as u32) + 1;
                uncomp += 1;
                i += 3 + size as usize;
            }
            0xE0..=0xFF => {
                let cmp = ((encoded[i + 3] as u32) << 8 | encoded[i + 4] as u32) + 1;
                comp += 1;
                i += 6 + cmp as usize;
            }
            other => panic!("unexpected control byte 0x{other:02X} at offset {i}"),
        }
    }
    (comp, uncomp)
}

#[test]
fn encoder_emits_compressed_chunk_for_repetitive_input() {
    // Same payload as the imported hello-world fixture. The encoder should
    // produce one compressed chunk (control byte in 0xE0..=0xFF) and the
    // round-trip must succeed.
    let input: Vec<u8> = "hello world "
        .as_bytes()
        .iter()
        .cycle()
        .take(600)
        .copied()
        .collect();
    let encoded = encode_chunked(&input, input.len(), 4096);
    let (comp, uncomp) = classify_chunks(&encoded);
    assert_eq!(comp, 1, "expected exactly one compressed chunk");
    assert_eq!(uncomp, 0, "expected no uncompressed chunks");
    assert!(
        encoded.len() < input.len(),
        "compressed stream should be smaller than raw input"
    );
    let decoded = decode_chunked(&encoded, encoded.len(), 4096);
    assert_eq!(decoded, input);
}

#[test]
fn encoder_emits_compressed_chunk_for_4k_repeating_a() {
    // 4 KiB of 'A' — a single-byte alphabet should compress to a few dozen
    // bytes of LZMA after the initial literal.
    let input = vec![b'A'; 4096];
    let encoded = encode_chunked(&input, input.len(), 4096);
    let (comp, uncomp) = classify_chunks(&encoded);
    assert_eq!(comp, 1);
    assert_eq!(uncomp, 0);
    assert!(encoded.len() < 200, "expected very tight compression");
    let decoded = decode_chunked(&encoded, encoded.len(), 4096);
    assert_eq!(decoded, input);
}

#[test]
fn encoder_falls_back_to_uncompressed_for_incompressible_input() {
    // Pseudo-random bytes — LZMA's overhead won't pay off, so the encoder's
    // compressed-vs-uncompressed picker should fall back to type-0x01
    // chunks. Either way the round-trip must succeed.
    let mut state: u32 = 0xC0FFEE42u32;
    let mut input = Vec::with_capacity(2048);
    for _ in 0..2048usize {
        state = state.wrapping_mul(1_103_515_245).wrapping_add(12345);
        input.push((state >> 16) as u8);
    }
    let encoded = encode_chunked(&input, input.len(), 256);
    let (_comp, uncomp) = classify_chunks(&encoded);
    // The pseudo-random input is genuinely incompressible at greedy LZMA, so
    // we expect the fallback to kick in for at least one chunk.
    assert!(
        uncomp >= 1,
        "expected at least one uncompressed fallback chunk for random data"
    );
    let decoded = decode_chunked(&encoded, encoded.len(), 256);
    assert_eq!(decoded, input);
}

#[test]
fn encoder_multi_chunk_compressed_round_trip() {
    // Input larger than a single 64 KiB chunk, all compressible (lots of
    // repetition). The encoder should split into multiple compressed chunks
    // and the round-trip must reconstruct the exact input.
    let unit = b"The quick brown fox jumps over the lazy dog. ";
    let mut input = Vec::with_capacity(200_000);
    while input.len() < 200_000 {
        input.extend_from_slice(unit);
    }
    input.truncate(200_000);

    let encoded = encode_chunked(&input, input.len(), 8192);
    let (comp, _uncomp) = classify_chunks(&encoded);
    assert!(
        comp >= 4,
        "expected at least 4 compressed chunks, got {comp}"
    );
    let decoded = decode_chunked(&encoded, encoded.len(), 8192);
    assert_eq!(decoded.len(), input.len());
    assert_eq!(decoded, input);
}

#[test]
fn encoder_streaming_one_byte_buffers_compressed_round_trip() {
    // 1-byte-on-both-sides streaming over compressible input. Forces the
    // encoder to buffer up to a full chunk and then drain it through a
    // tiny output buffer, and the decoder to reassemble through tiny
    // buffers on its side too.
    let mut input = Vec::with_capacity(4096);
    let unit = b"abcdefghij";
    while input.len() < 4096 {
        input.extend_from_slice(unit);
    }
    input.truncate(4096);

    let encoded = encode_chunked(&input, 1, 1);
    // Should compress meaningfully — the round-trip is the load-bearing check.
    assert!(
        encoded.len() < input.len(),
        "expected compression; encoded {} bytes, input {} bytes",
        encoded.len(),
        input.len()
    );
    let decoded = decode_chunked(&encoded, 1, 1);
    assert_eq!(decoded, input);
}

#[test]
fn encoder_just_over_64k_emits_two_chunks() {
    // 65_537 bytes of compressible data: exactly one full 64 KiB chunk
    // followed by a 1-byte tail chunk.
    let mut input = Vec::with_capacity(65_537);
    let unit = b"compressible payload! ";
    while input.len() < 65_537 {
        input.extend_from_slice(unit);
    }
    input.truncate(65_537);

    let encoded = encode_chunked(&input, input.len(), 1024);
    let (comp, uncomp) = classify_chunks(&encoded);
    assert_eq!(comp + uncomp, 2, "expected exactly two chunks");
    let decoded = decode_chunked(&encoded, encoded.len(), 1024);
    assert_eq!(decoded, input);
}

// ─── xz-utils cross-validation ────────────────────────────────────────────
//
// These tests pipe our encoder output through `xz --format=raw
// --lzma2=preset=6 -d` and check that xz reproduces the original input.
// Gated on Unix + tool availability so the test suite still passes in
// minimal environments.

#[cfg(unix)]
fn xz_available() -> bool {
    use std::process::Command;
    Command::new("xz")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[cfg(unix)]
fn xz_decode(encoded: &[u8]) -> Result<Vec<u8>, String> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let mut child = Command::new("xz")
        .args(["--format=raw", "--lzma2=preset=6", "-d", "-c"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn xz: {e}"))?;
    {
        let stdin = child.stdin.as_mut().ok_or("no stdin")?;
        stdin
            .write_all(encoded)
            .map_err(|e| format!("write stdin: {e}"))?;
    }
    let out = child.wait_with_output().map_err(|e| format!("wait: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "xz exit {:?}: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(out.stdout)
}

#[cfg(unix)]
#[test]
fn xz_decodes_our_compressed_output_hello_world() {
    if !xz_available() {
        eprintln!("xz not available; skipping");
        return;
    }
    let input: Vec<u8> = "hello world "
        .as_bytes()
        .iter()
        .cycle()
        .take(600)
        .copied()
        .collect();
    let encoded = encode_chunked(&input, input.len(), 4096);
    let xz_decoded = xz_decode(&encoded).expect("xz must accept our output");
    assert_eq!(xz_decoded, input, "xz output differs from input");
}

#[cfg(unix)]
#[test]
fn xz_decodes_our_compressed_output_4k_repeating() {
    if !xz_available() {
        eprintln!("xz not available; skipping");
        return;
    }
    let input = vec![b'A'; 4096];
    let encoded = encode_chunked(&input, input.len(), 4096);
    let xz_decoded = xz_decode(&encoded).expect("xz must accept our output");
    assert_eq!(xz_decoded, input);
}

#[cfg(unix)]
#[test]
fn xz_decodes_our_multi_chunk_output() {
    // Force multiple compressed chunks (input > 64 KiB) and verify xz
    // recombines them losslessly. Reads the trickiest path: chunk boundaries
    // plus state-reset on every chunk.
    if !xz_available() {
        eprintln!("xz not available; skipping");
        return;
    }
    let unit = b"The quick brown fox jumps over the lazy dog. ";
    let mut input = Vec::with_capacity(150_000);
    while input.len() < 150_000 {
        input.extend_from_slice(unit);
    }
    input.truncate(150_000);
    let encoded = encode_chunked(&input, input.len(), 8192);
    let xz_decoded = xz_decode(&encoded).expect("xz must accept our output");
    assert_eq!(xz_decoded.len(), input.len());
    assert_eq!(xz_decoded, input);
}

#[cfg(unix)]
#[test]
fn xz_decodes_our_incompressible_fallback() {
    // Verify xz also accepts streams where the encoder falls back to
    // uncompressed (0x01) chunks for random data — those chunks share the
    // wire format with what xz itself emits for incompressible regions, so
    // this just exercises the mixed-chunk case from xz's side.
    if !xz_available() {
        eprintln!("xz not available; skipping");
        return;
    }
    let mut state: u32 = 0xFEEDFACEu32;
    let mut input = Vec::with_capacity(2048);
    for _ in 0..2048usize {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        input.push((state >> 24) as u8);
    }
    let encoded = encode_chunked(&input, input.len(), 256);
    let xz_decoded = xz_decode(&encoded).expect("xz must accept our output");
    assert_eq!(xz_decoded, input);
}

#[cfg(unix)]
#[test]
fn xz_decodes_our_empty_output() {
    if !xz_available() {
        eprintln!("xz not available; skipping");
        return;
    }
    let encoded = encode_chunked(&[], 1, 16);
    assert_eq!(encoded, vec![0x00]);
    let xz_decoded = xz_decode(&encoded).expect("xz must accept our output");
    assert!(xz_decoded.is_empty());
}
