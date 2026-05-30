//! Streaming round-trip tests for the LZSS codec (Okumura layout).
//!
//! Decoder fixtures are hard-coded byte arrays generated offline by an
//! external Python port of Okumura's reference `lzss.c` (public domain).
//! See the comment on each fixture for the input it was generated from.

#![cfg(feature = "lzss")]

use compcol::lzss::{Decoder, Encoder, Lzss};
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
                    panic!("lzss encoder finish stalled");
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

    // Drain anything still pending without further input.
    loop {
        let (p, _status) = dec.decode(&[], &mut buf)?;
        decoded.extend_from_slice(&buf[..p.written]);
        if p.written == 0 {
            break;
        }
    }

    let (p, status) = dec.finish(&mut buf)?;
    decoded.extend_from_slice(&buf[..p.written]);
    assert!(matches!(status, Status::StreamEnd));

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

// ─── algorithm metadata ─────────────────────────────────────────────────

#[test]
fn name_is_lzss() {
    assert_eq!(<Lzss as Algorithm>::NAME, "lzss");
}

// ─── round-trip tests ──────────────────────────────────────────────────

#[test]
fn round_trip_empty() {
    let encoded = encode_all(b"");
    assert_eq!(encoded, &[0u8; 4]); // 4-byte LE length = 0, no payload.
    let decoded = decode_chunked(&encoded, 4096, 4096).unwrap();
    assert_eq!(decoded, b"");
}

#[test]
fn round_trip_single_byte() {
    round_trip(b"X");
}

#[test]
fn round_trip_hello_world() {
    round_trip(b"hello world");
}

#[test]
fn round_trip_short_repetition() {
    round_trip(b"abcabcabcabcabcabc");
}

#[test]
fn round_trip_long_run() {
    round_trip(&vec![b'a'; 1024]);
}

#[test]
fn round_trip_64kib_repeating() {
    let phrase = b"the quick brown fox jumps over the lazy dog ";
    let mut input = Vec::with_capacity(64 * 1024);
    while input.len() < 64 * 1024 {
        input.extend_from_slice(phrase);
    }
    input.truncate(64 * 1024);
    round_trip(&input);
}

#[test]
fn round_trip_mixed_corpus() {
    let mut input = Vec::new();
    input.extend_from_slice(b"lorem ipsum dolor sit amet ");
    input.extend(core::iter::repeat_n(b'A', 50));
    input.extend_from_slice(b"consectetur adipiscing elit ");
    input.extend(core::iter::repeat_n(b'\x00', 100));
    input.extend_from_slice(b"sed do eiusmod tempor incididunt");
    round_trip(&input);
}

#[test]
fn round_trip_all_byte_values() {
    let input: Vec<u8> = (0..=255u8).collect();
    round_trip(&input);
}

// ─── streaming chunk sizes ─────────────────────────────────────────────

#[test]
fn round_trip_streaming_one_byte() {
    let input = b"streaming one byte at a time test".to_vec();
    let mut enc = Encoder::new();
    let encoded = encode_chunked(&mut enc, &input, 1, 1);
    let decoded = decode_chunked(&encoded, 1, 1).unwrap();
    assert_eq!(decoded, input);
}

#[test]
fn round_trip_streaming_small_buffers() {
    // Inner buffer smaller than F=18 forces the decoder's "output full
    // mid-match" path to fire.
    let mut input = Vec::new();
    for i in 0..1024 {
        input.push((i & 0xFF) as u8);
    }
    input.extend(core::iter::repeat_n(b'Z', 200));
    let mut enc = Encoder::new();
    let encoded = encode_chunked(&mut enc, &input, 7, 5);
    let decoded = decode_chunked(&encoded, 11, 3).unwrap();
    assert_eq!(decoded, input);
}

// ─── reset / reuse ─────────────────────────────────────────────────────

#[test]
fn reset_preserves_config_and_allows_reuse() {
    let input_a = b"alpha alpha alpha".as_slice();
    let input_b = b"bravo bravo bravo".as_slice();

    let mut enc = Encoder::new();
    let encoded_a = encode_chunked(&mut enc, input_a, 4096, 4096);
    enc.reset();
    let encoded_b = encode_chunked(&mut enc, input_b, 4096, 4096);

    assert_eq!(decode_chunked(&encoded_a, 4096, 4096).unwrap(), input_a);
    assert_eq!(decode_chunked(&encoded_b, 4096, 4096).unwrap(), input_b);
}

#[test]
fn decoder_reset_allows_reuse() {
    let mut enc = Encoder::new();
    let encoded_a = encode_chunked(&mut enc, b"hello", 4096, 4096);
    enc.reset();
    let encoded_b = encode_chunked(&mut enc, b"world", 4096, 4096);

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

// ─── decoder fixtures (hard-coded byte arrays from Python reference) ───
//
// Reference encoder lives in `docs/lzss-ref.py` (a port of Okumura's
// public-domain `lzss.c`). The bytes below were generated as
// `python3 docs/lzss-ref.py encode < input.bin`.

/// `encode("hello world")` per the Okumura reference.
const HELLO_WORLD_ENCODED: &[u8] = &[
    0x0b, 0x00, 0x00, 0x00, 0xff, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x07, 0x72, 0x6c,
    0x64,
];

/// `encode("abcdefgabcdefgabcdefgabcdefg")` per the Okumura reference.
const REPEATED_ENCODED: &[u8] = &[
    0x1c, 0x00, 0x00, 0x00, 0x7f, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0xee, 0xff, 0x00, 0x00,
    0x00,
];

/// `encode("X")` per the Okumura reference.
const SINGLE_BYTE_ENCODED: &[u8] = &[0x01, 0x00, 0x00, 0x00, 0x01, 0x58];

/// `encode(bytes(range(256)))` per the Okumura reference.
const ALL_BYTES_ENCODED: &[u8] = &[
    0x00, 0x01, 0x00, 0x00, 0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0xff, 0x08, 0x09,
    0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0xff,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0xff, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26,
    0x27, 0xff, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0xff, 0x30, 0x31, 0x32, 0x33, 0x34,
    0x35, 0x36, 0x37, 0xff, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0xff, 0x40, 0x41, 0x42,
    0x43, 0x44, 0x45, 0x46, 0x47, 0xff, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0xff, 0x50,
    0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0xff, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
    0xff, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0xff, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d,
    0x6e, 0x6f, 0xff, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0xff, 0x78, 0x79, 0x7a, 0x7b,
    0x7c, 0x7d, 0x7e, 0x7f, 0xff, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0xff, 0x88, 0x89,
    0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0xff, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0xff,
    0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xff, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6,
    0xa7, 0xff, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xff, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4,
    0xb5, 0xb6, 0xb7, 0xff, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xff, 0xc0, 0xc1, 0xc2,
    0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xff, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xff, 0xd0,
    0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xff, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
    0xff, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xff, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed,
    0xee, 0xef, 0xff, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xff, 0xf8, 0xf9, 0xfa, 0xfb,
    0xfc, 0xfd, 0xfe, 0xff,
];

#[test]
fn decode_reference_hello_world() {
    let decoded = decode_chunked(HELLO_WORLD_ENCODED, 1024, 1024).unwrap();
    assert_eq!(decoded, b"hello world");
}

#[test]
fn decode_reference_repeated() {
    let decoded = decode_chunked(REPEATED_ENCODED, 1024, 1024).unwrap();
    assert_eq!(decoded, b"abcdefgabcdefgabcdefgabcdefg");
}

#[test]
fn decode_reference_single_byte() {
    let decoded = decode_chunked(SINGLE_BYTE_ENCODED, 1024, 1024).unwrap();
    assert_eq!(decoded, b"X");
}

#[test]
fn decode_reference_all_bytes() {
    let decoded = decode_chunked(ALL_BYTES_ENCODED, 1024, 1024).unwrap();
    let expected: Vec<u8> = (0..=255u8).collect();
    assert_eq!(decoded, expected);
}

// ─── decoder error rejection ───────────────────────────────────────────

#[test]
fn truncated_header_rejected() {
    let stream = &[0x42, 0x00]; // 2 of the 4 header bytes
    let mut dec = Decoder::new();
    let mut buf = [0u8; 64];
    let (_p, status) = dec.decode(stream, &mut buf).unwrap();
    // After consuming the partial header, the decoder still wants more input.
    assert!(matches!(status, Status::InputEmpty));
    let err = dec.finish(&mut buf).unwrap_err();
    assert_eq!(err, Error::UnexpectedEnd);
}

#[test]
fn truncated_payload_rejected() {
    // Declare 64 bytes uncompressed but supply no payload.
    let stream: &[u8] = &[0x40, 0x00, 0x00, 0x00];
    let mut dec = Decoder::new();
    let mut buf = [0u8; 256];
    let (_p, _status) = dec.decode(stream, &mut buf).unwrap();
    let err = dec.finish(&mut buf).unwrap_err();
    assert_eq!(err, Error::UnexpectedEnd);
}

#[test]
fn truncated_match_token_rejected() {
    // 4-byte header + flag byte 0x00 (one match token coming) + only
    // the first byte of the 2-byte match body. Decoder consumes those
    // bytes happily but `finish` must reject.
    let stream: &[u8] = &[0x05, 0x00, 0x00, 0x00, 0x00, 0xAB];
    let mut dec = Decoder::new();
    let mut buf = [0u8; 64];
    let _ = dec.decode(stream, &mut buf).unwrap();
    let err = dec.finish(&mut buf).unwrap_err();
    assert_eq!(err, Error::UnexpectedEnd);
}

#[test]
fn header_with_zero_length_decodes_empty() {
    let stream: &[u8] = &[0x00, 0x00, 0x00, 0x00];
    let decoded = decode_chunked(stream, 4096, 4096).unwrap();
    assert!(decoded.is_empty());
}

// ─── Algorithm-trait entry points ──────────────────────────────────────

#[test]
fn algorithm_encoder_decoder_round_trip() {
    let mut enc = <Lzss as Algorithm>::encoder();
    let mut dec = <Lzss as Algorithm>::decoder();
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
        assert!(factory::encoder_by_name("lzss").is_some());
        assert!(factory::decoder_by_name("lzss").is_some());
    }

    #[test]
    fn names_contains_lzss() {
        assert!(factory::names().contains(&"lzss"));
    }

    #[test]
    fn extension_is_lzss() {
        assert_eq!(factory::extension("lzss"), Some("lzss"));
    }

    #[test]
    fn boxed_round_trip() {
        let mut enc = factory::encoder_by_name("lzss").unwrap();
        let mut dec = factory::decoder_by_name("lzss").unwrap();
        let input = b"factory boxed round-trip";

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
