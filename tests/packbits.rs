//! Streaming round-trip tests for the PackBits codec.
//!
//! PackBits has no header or trailer: the encoded length is the framing.
//! Tests therefore mirror that — the decoder takes the encoded slice
//! and finish() is the explicit "input is over" signal.

#![cfg(feature = "packbits")]

use compcol::packbits::{Decoder, Encoder, PackBits};
use compcol::{Algorithm, Decoder as _, Encoder as _, Error, Status};

fn encode_chunked(enc: &mut Encoder, input: &[u8], in_chunk: usize, out_chunk: usize) -> Vec<u8> {
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
                    panic!("packbits encoder finish stalled");
                }
            }
        }
    }
    encoded
}

fn decode_chunked(encoded: &[u8], in_chunk: usize, out_chunk: usize) -> Result<Vec<u8>, Error> {
    let mut dec = Decoder::new();
    decode_chunked_with(&mut dec, encoded, in_chunk, out_chunk)
}

fn decode_chunked_with(
    dec: &mut Decoder,
    encoded: &[u8],
    in_chunk: usize,
    out_chunk: usize,
) -> Result<Vec<u8>, Error> {
    let mut decoded = Vec::new();
    let mut buf = vec![0u8; out_chunk.max(1)];
    let mut i = 0;
    while i < encoded.len() {
        let end = (i + in_chunk).min(encoded.len());
        let chunk = &encoded[i..end];
        let mut consumed = 0;
        while consumed < chunk.len() {
            let (p, status) = dec.decode(&chunk[consumed..], &mut buf)?;
            decoded.extend_from_slice(&buf[..p.written]);
            consumed += p.consumed;
            match status {
                Status::StreamEnd => break,
                Status::InputEmpty => break,
                Status::OutputFull => continue,
            }
        }
        i = end;
    }
    loop {
        let (p, status) = dec.finish(&mut buf)?;
        decoded.extend_from_slice(&buf[..p.written]);
        match status {
            Status::StreamEnd => break,
            Status::OutputFull | Status::InputEmpty => {
                if p.written == 0 {
                    panic!("packbits decoder finish stalled");
                }
            }
        }
    }
    Ok(decoded)
}

fn encode_all(input: &[u8]) -> Vec<u8> {
    let mut enc = Encoder::new();
    encode_chunked(&mut enc, input, input.len().max(1), 4096)
}

fn round_trip(input: &[u8]) {
    let encoded = encode_all(input);
    let decoded = decode_chunked(&encoded, 4096, 4096).unwrap();
    assert_eq!(decoded, input, "round-trip mismatch len {}", input.len());
}

// ─── algorithm metadata ────────────────────────────────────────────────

#[test]
fn name_is_packbits() {
    assert_eq!(<PackBits as Algorithm>::NAME, "packbits");
}

// ─── round-trip tests ──────────────────────────────────────────────────

#[test]
fn round_trip_empty() {
    let encoded = encode_all(b"");
    assert!(encoded.is_empty(), "no input → no output");
    let decoded = decode_chunked(&encoded, 4096, 4096).unwrap();
    assert!(decoded.is_empty());
}

#[test]
fn round_trip_single_byte() {
    round_trip(b"X");
    // Single byte must fit into one literal-header pair.
    let encoded = encode_all(b"X");
    assert_eq!(encoded, vec![0x00, b'X']);
}

#[test]
fn round_trip_hello_world() {
    round_trip(b"hello world");
}

#[test]
fn round_trip_repeated_short_run() {
    // Three identical bytes is the threshold for a replicate.
    let input = b"AAA";
    let encoded = encode_all(input);
    assert_eq!(encoded, vec![0xFE, b'A']); // -2 (signed) = three A's
    round_trip(input);
}

#[test]
fn round_trip_two_byte_repeat_is_literal() {
    // Two identical bytes: should fall through to a literal pair.
    let input = b"AA";
    let encoded = encode_all(input);
    assert_eq!(encoded, vec![0x01, b'A', b'A']);
    round_trip(input);
}

#[test]
fn round_trip_64kib_repeating_pattern() {
    // 64 KiB of a 4-byte cycle — neither pure run nor pure literal.
    let mut input = Vec::with_capacity(64 * 1024);
    while input.len() < 64 * 1024 {
        input.extend_from_slice(b"abcd");
    }
    round_trip(&input);
}

#[test]
fn round_trip_64kib_pure_run() {
    let input = vec![0xABu8; 64 * 1024];
    let encoded = encode_all(&input);
    // 64 KiB / 128-byte runs = 512 replicate pairs.
    assert_eq!(encoded.len(), 512 * 2);
    round_trip(&input);
}

#[test]
fn round_trip_mixed_corpus() {
    // Phrases + zero-padding + pseudo-random bytes.
    let mut state: u32 = 0xC0FFEE_u32;
    let mut input = Vec::with_capacity(16 * 1024);
    let phrases: &[&[u8]] = &[
        b"the quick brown fox jumps over the lazy dog ",
        b"compcol streaming packbits round-trip test ",
        b"AAAAAAAAAAAAAAAA", // exercise runs mid-stream
    ];
    let mut p = 0;
    while input.len() < 8 * 1024 {
        for _ in 0..32 {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            input.push((state >> 16) as u8);
        }
        input.extend_from_slice(phrases[p % phrases.len()]);
        p += 1;
    }
    round_trip(&input);
}

// ─── streaming chunk sizes ─────────────────────────────────────────────

#[test]
fn round_trip_streaming_one_byte() {
    let input = b"streaming one byte at a time AAAAAAAA done";
    let mut enc = Encoder::new();
    let encoded = encode_chunked(&mut enc, input, 1, 1);
    let decoded = decode_chunked(&encoded, 1, 1).unwrap();
    assert_eq!(decoded, input);
}

#[test]
fn round_trip_tiny_output_buffer() {
    // 1-byte output forces the encoder/decoder to suspend after every byte.
    let input = b"the quick brown fox AAAAAAAA";
    let mut enc = Encoder::new();
    let encoded = encode_chunked(&mut enc, input, 8, 1);
    let decoded = decode_chunked(&encoded, 8, 1).unwrap();
    assert_eq!(decoded, input);
}

// ─── reset / reuse ─────────────────────────────────────────────────────

#[test]
fn encoder_reset_allows_reuse() {
    let mut enc = Encoder::new();
    let encoded_a = encode_chunked(&mut enc, b"alpha alpha alpha", 4096, 4096);
    enc.reset();
    let encoded_b = encode_chunked(&mut enc, b"bravo bravo bravo", 4096, 4096);
    assert_eq!(
        decode_chunked(&encoded_a, 4096, 4096).unwrap(),
        b"alpha alpha alpha"
    );
    assert_eq!(
        decode_chunked(&encoded_b, 4096, 4096).unwrap(),
        b"bravo bravo bravo"
    );
}

#[test]
fn decoder_reset_allows_reuse() {
    let encoded_a = encode_all(b"hello");
    let encoded_b = encode_all(b"world");
    let mut dec = Decoder::new();
    assert_eq!(
        decode_chunked_with(&mut dec, &encoded_a, 4096, 4096).unwrap(),
        b"hello"
    );
    dec.reset();
    assert_eq!(
        decode_chunked_with(&mut dec, &encoded_b, 4096, 4096).unwrap(),
        b"world"
    );
}

// ─── decode reference fixtures (from PIL TIFF PackBits) ────────────────
//
// Generated offline by passing each input through PIL's
// `Image.save(..., compression='packbits')` on a 1×N L-mode image and
// extracting the strip bytes. Verified against the Apple TN1023
// reference decoder shape.

#[test]
fn decode_reference_hello_world() {
    // input  = b"hello world"
    // encoded: 0a 68 65 6c 6c 6f 20 77 6f 72 6c 64 (one 11-byte literal pair)
    let encoded: &[u8] = &[
        0x0A, 0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x77, 0x6F, 0x72, 0x6C, 0x64,
    ];
    let decoded = decode_chunked(encoded, 1024, 1024).unwrap();
    assert_eq!(decoded, b"hello world");
}

#[test]
fn decode_reference_pure_literals() {
    // input = b"abcdef"
    let encoded: &[u8] = &[0x05, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66];
    let decoded = decode_chunked(encoded, 1024, 1024).unwrap();
    assert_eq!(decoded, b"abcdef");
}

#[test]
fn decode_reference_32_run() {
    // input = b"A" * 32, encoded as one replicate header (-31 = 0xE1) + 'A'.
    let encoded: &[u8] = &[0xE1, b'A'];
    let decoded = decode_chunked(encoded, 1024, 1024).unwrap();
    assert_eq!(decoded, vec![b'A'; 32]);
}

#[test]
fn decode_reference_300_run_split_into_three() {
    // input = b"B" * 300, encoded by PIL as: 81 42 81 42 d5 42
    // (two 128-byte runs and one 44-byte run, headers 0x81=-127, 0xd5=-43).
    let encoded: &[u8] = &[0x81, b'B', 0x81, b'B', 0xD5, b'B'];
    let decoded = decode_chunked(encoded, 1024, 1024).unwrap();
    assert_eq!(decoded, vec![b'B'; 300]);
}

#[test]
fn decode_reference_mixed_literal_then_run_then_literal() {
    // input  = b"abc" + b"X" * 10 + b"defgh"
    // encoded: 02 61 62 63 f7 58 04 64 65 66 67 68
    //          ^^                 ^^                 (literal headers)
    //                ^^                              (run header -9)
    let encoded: &[u8] = &[
        0x02, 0x61, 0x62, 0x63, 0xF7, 0x58, 0x04, 0x64, 0x65, 0x66, 0x67, 0x68,
    ];
    let decoded = decode_chunked(encoded, 1024, 1024).unwrap();
    let mut expected = Vec::new();
    expected.extend_from_slice(b"abc");
    expected.extend(core::iter::repeat_n(b'X', 10));
    expected.extend_from_slice(b"defgh");
    assert_eq!(decoded, expected);
}

#[test]
fn decode_reference_full_byte_range() {
    // 256 bytes 0x00..=0xff: PIL splits into two 128-byte literal blocks
    // (header 0x7F = 127, meaning 128 bytes follow).
    let mut expected: Vec<u8> = Vec::with_capacity(256);
    expected.extend(0..=255u8);
    let mut encoded: Vec<u8> = Vec::with_capacity(258);
    encoded.push(0x7F);
    encoded.extend_from_slice(&expected[0..128]);
    encoded.push(0x7F);
    encoded.extend_from_slice(&expected[128..256]);
    let decoded = decode_chunked(&encoded, 1024, 1024).unwrap();
    assert_eq!(decoded, expected);
}

#[test]
fn decode_apple_tn1023_example() {
    // Apple TN1023 worked example. The packed sequence
    //   FE AA 02 80 00 2A FD AA 03 80 00 2A 22 F7 AA
    // decodes to 24 bytes:
    //   3×AA  |  80 00 2A  |  4×AA  |  80 00 2A 22  |  10×AA
    let encoded: &[u8] = &[
        0xFE, 0xAA, 0x02, 0x80, 0x00, 0x2A, 0xFD, 0xAA, 0x03, 0x80, 0x00, 0x2A, 0x22, 0xF7, 0xAA,
    ];
    let expected: &[u8] = &[
        0xAA, 0xAA, 0xAA, 0x80, 0x00, 0x2A, 0xAA, 0xAA, 0xAA, 0xAA, 0x80, 0x00, 0x2A, 0x22, 0xAA,
        0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    ];
    let decoded = decode_chunked(encoded, 1024, 1024).unwrap();
    assert_eq!(decoded, expected);
}

#[test]
fn decode_noop_header_is_skipped() {
    // 0x80 by itself is a no-op header; the decoder should drop it
    // and continue with the following symbol.
    let encoded: &[u8] = &[0x80, 0x02, b'a', b'b', b'c'];
    let decoded = decode_chunked(encoded, 1024, 1024).unwrap();
    assert_eq!(decoded, b"abc");
}

// ─── decoder error rejection ───────────────────────────────────────────

#[test]
fn truncated_after_literal_header() {
    // 0x02 promises 3 literal bytes; we supply only 1. finish() must
    // report UnexpectedEnd.
    let encoded: &[u8] = &[0x02, b'a'];
    let err = decode_chunked(encoded, 1024, 1024).unwrap_err();
    assert_eq!(err, Error::UnexpectedEnd);
}

#[test]
fn truncated_before_run_byte() {
    // 0xFE promises a 3-byte replicate but we never give it the byte.
    let encoded: &[u8] = &[0xFE];
    let err = decode_chunked(encoded, 1024, 1024).unwrap_err();
    assert_eq!(err, Error::UnexpectedEnd);
}

#[test]
fn decode_empty_stream_is_clean_end() {
    // Empty input is well-formed PackBits: no headers, no bytes.
    let decoded = decode_chunked(&[], 1024, 1024).unwrap();
    assert!(decoded.is_empty());
}

#[test]
fn decode_all_noops_yields_empty() {
    let encoded: &[u8] = &[0x80, 0x80, 0x80, 0x80];
    let decoded = decode_chunked(encoded, 1024, 1024).unwrap();
    assert!(decoded.is_empty());
}

// ─── Algorithm-trait entry points ──────────────────────────────────────

#[test]
fn algorithm_encoder_decoder_round_trip() {
    let mut enc = <PackBits as Algorithm>::encoder();
    let mut dec = <PackBits as Algorithm>::decoder();
    let input = b"compcol Algorithm trait roundtrip!";

    let mut encoded = Vec::new();
    let mut buf = vec![0u8; 256];
    let mut consumed = 0;
    while consumed < input.len() {
        let (p, status) = enc.encode(&input[consumed..], &mut buf).unwrap();
        encoded.extend_from_slice(&buf[..p.written]);
        consumed += p.consumed;
        if matches!(status, Status::InputEmpty) {
            break;
        }
    }
    loop {
        let (p, status) = enc.finish(&mut buf).unwrap();
        encoded.extend_from_slice(&buf[..p.written]);
        if matches!(status, Status::StreamEnd) {
            break;
        }
        if p.written == 0 {
            panic!("finish stalled");
        }
    }

    let mut decoded = Vec::new();
    let mut consumed = 0;
    loop {
        let (p, status) = dec.decode(&encoded[consumed..], &mut buf).unwrap();
        decoded.extend_from_slice(&buf[..p.written]);
        consumed += p.consumed;
        if matches!(status, Status::StreamEnd | Status::InputEmpty) {
            break;
        }
    }
    let (_, status) = dec.finish(&mut buf).unwrap();
    assert!(matches!(status, Status::StreamEnd));
    assert_eq!(decoded, input);
}

// ─── factory lookup ────────────────────────────────────────────────────

#[cfg(feature = "factory")]
mod factory {
    use compcol::Status;
    use compcol::factory;

    #[test]
    fn lookup_known() {
        assert!(factory::encoder_by_name("packbits").is_some());
        assert!(factory::decoder_by_name("packbits").is_some());
    }

    #[test]
    fn names_contains_packbits() {
        assert!(factory::names().contains(&"packbits"));
    }

    #[test]
    fn extension_is_packbits() {
        assert_eq!(factory::extension("packbits"), Some("packbits"));
    }

    #[test]
    fn boxed_round_trip() {
        let mut enc = factory::encoder_by_name("packbits").unwrap();
        let mut dec = factory::decoder_by_name("packbits").unwrap();
        let input = b"factory boxed PackBits round-trip XXXXXXXXXXXXXXXX";

        let mut encoded = Vec::new();
        let mut buf = vec![0u8; 256];
        let mut consumed = 0;
        while consumed < input.len() {
            let (p, status) = enc.encode(&input[consumed..], &mut buf).unwrap();
            encoded.extend_from_slice(&buf[..p.written]);
            consumed += p.consumed;
            if matches!(status, Status::InputEmpty) {
                break;
            }
        }
        loop {
            let (p, status) = enc.finish(&mut buf).unwrap();
            encoded.extend_from_slice(&buf[..p.written]);
            if matches!(status, Status::StreamEnd) {
                break;
            }
            if p.written == 0 {
                panic!("finish stalled");
            }
        }

        let mut decoded = Vec::new();
        let mut consumed = 0;
        loop {
            let (p, status) = dec.decode(&encoded[consumed..], &mut buf).unwrap();
            decoded.extend_from_slice(&buf[..p.written]);
            consumed += p.consumed;
            if matches!(status, Status::StreamEnd | Status::InputEmpty) {
                break;
            }
        }
        let (_, status) = dec.finish(&mut buf).unwrap();
        assert!(matches!(status, Status::StreamEnd));
        assert_eq!(&decoded[..], input);
    }
}
