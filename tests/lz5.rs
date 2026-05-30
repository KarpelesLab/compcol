//! Streaming round-trip + reference-fixture tests for the LZ5 / Lizard
//! frame-format codec.
//!
//! The encoder shipped in this build is intentionally a store-only
//! encoder (every block carries the frame-uncompressed flag) so its
//! output round-trips through both this crate's decoder and the
//! reference Lizard CLI. The decoder additionally accepts compressed
//! blocks emitted by `lizard -10 --no-frame-crc` whose sub-streams are
//! stored raw (no Huffman) — that's the most common shape at level 10.

#![cfg(feature = "lz5")]

use compcol::lz5::{Decoder, Encoder, Lz5};
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
                    panic!("lz5 encoder finish stalled");
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
    // Drain any decoder-internal buffer with empty-input nudges.
    loop {
        let (p, _) = dec.decode(&[], &mut buf)?;
        decoded.extend_from_slice(&buf[..p.written]);
        if p.written == 0 {
            break;
        }
    }
    loop {
        let (p, status) = dec.finish(&mut buf)?;
        decoded.extend_from_slice(&buf[..p.written]);
        match status {
            Status::StreamEnd => break,
            Status::OutputFull | Status::InputEmpty => {
                if p.written == 0 {
                    panic!("lz5 decoder finish stalled");
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
    // Sanity-check: every encoded stream starts with the Lizard magic.
    assert!(encoded.len() >= 11, "encoded too short: {}", encoded.len());
    assert_eq!(&encoded[..4], &[0x06, 0x22, 0x4D, 0x18], "magic mismatch");
    let decoded = decode_chunked(&encoded, 4096, 4096).unwrap();
    assert_eq!(decoded, input, "round-trip mismatch len {}", input.len());
}

// ─── algorithm metadata ─────────────────────────────────────────────────

#[test]
fn name_is_lz5() {
    assert_eq!(<Lz5 as Algorithm>::NAME, "lz5");
}

// ─── round-trip tests (store-only encoder) ────────────────────────────

#[test]
fn round_trip_empty() {
    let encoded = encode_all(b"");
    // Empty input: header + endmark only, no blocks.
    assert_eq!(encoded.len(), 11);
    let decoded = decode_chunked(&encoded, 4096, 4096).unwrap();
    assert!(decoded.is_empty());
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
fn round_trip_repeated_bytes() {
    let input = vec![b'a'; 1024];
    round_trip(&input);
}

#[test]
fn round_trip_64kib_repeating() {
    let mut input = Vec::with_capacity(64 * 1024);
    while input.len() < 64 * 1024 {
        input.extend_from_slice(b"abcdefgh");
    }
    round_trip(&input);
}

#[test]
fn round_trip_mixed_corpus() {
    let mut input = Vec::new();
    let phrase = b"the quick brown fox jumps over the lazy dog. ";
    for _ in 0..50 {
        input.extend_from_slice(phrase);
    }
    for _ in 0..5 {
        for b in 0..=255u8 {
            input.push(b);
        }
    }
    round_trip(&input);
}

// ─── streaming chunk sizes ─────────────────────────────────────────────

#[test]
fn round_trip_streaming_one_byte() {
    let input = b"streaming bytes one at a time".to_vec();
    let mut enc = Encoder::new();
    let encoded = encode_chunked(&mut enc, &input, 1, 1);
    let decoded = decode_chunked(&encoded, 1, 1).unwrap();
    assert_eq!(decoded, input);
}

// ─── reset / reuse ─────────────────────────────────────────────────────

#[test]
fn encoder_reset_allows_reuse() {
    let mut enc = Encoder::new();
    let encoded_a = encode_chunked(&mut enc, b"alpha", 4096, 4096);
    enc.reset();
    let encoded_b = encode_chunked(&mut enc, b"bravo", 4096, 4096);
    assert_eq!(decode_chunked(&encoded_a, 4096, 4096).unwrap(), b"alpha");
    assert_eq!(decode_chunked(&encoded_b, 4096, 4096).unwrap(), b"bravo");
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

// ─── multi-block ────────────────────────────────────────────────────────

#[test]
fn round_trip_multi_block_400kib() {
    // 128 KiB per block × 3 + change → at least 3 blocks.
    let mut state: u32 = 0xC0FFEE;
    let mut input = Vec::with_capacity(400 * 1024);
    for _ in 0..(400 * 1024) {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        input.push((state >> 16) as u8);
    }
    round_trip(&input);
}

// ─── reference fixtures emitted by `lizard -10 --no-frame-crc` ────────

// All fixtures below were generated with Lizard CLI 2.1.0 built from
// inikep/lizard@lizard:
//
//     lizard -10 --no-frame-crc -f <input> <output>.liz
//
// They cover (a) the empty-frame edge case, (b) the in-block uncompressed
// flag path, (c) several compressed blocks with raw sub-streams, and (d)
// a frame-level uncompressed block (high-bit on block-size word) used
// by the CLI for incompressible inputs.

#[test]
fn decode_reference_empty() {
    // Empty input: header + endmark only.
    let encoded: &[u8] = &[
        0x06, 0x22, 0x4d, 0x18, 0x60, 0x10, 0x8e, 0x00, 0x00, 0x00, 0x00,
    ];
    let decoded = decode_chunked(encoded, 1024, 1024).unwrap();
    assert!(decoded.is_empty());
}

#[test]
fn decode_reference_single_byte() {
    // Input: "A".  Encoded as a single uncompressed block (high-bit flag).
    let encoded: &[u8] = &[
        0x06, 0x22, 0x4d, 0x18, 0x60, 0x10, 0x8e, 0x01, 0x00, 0x00, 0x80, 0x41, 0x00, 0x00, 0x00,
        0x00,
    ];
    let decoded = decode_chunked(encoded, 1024, 1024).unwrap();
    assert_eq!(decoded, b"A");
}

#[test]
fn decode_reference_hello_world() {
    // Input: "hello world".  Encoded as a single frame-uncompressed block.
    let encoded: &[u8] = &[
        0x06, 0x22, 0x4d, 0x18, 0x60, 0x10, 0x8e, 0x0b, 0x00, 0x00, 0x80, 0x68, 0x65, 0x6c, 0x6c,
        0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x00, 0x00, 0x00, 0x00,
    ];
    let decoded = decode_chunked(encoded, 1024, 1024).unwrap();
    assert_eq!(decoded, b"hello world");
}

#[test]
fn decode_reference_incompressible_64b() {
    // Input: 64 random bytes — Lizard's level-10 encoder chose to emit
    // them as a frame-level uncompressed block (high-bit on block-size
    // word).  The exact 64 bytes are derived from /dev/urandom; we
    // verify the decoder reproduces them.
    let encoded: &[u8] = &[
        0x06, 0x22, 0x4d, 0x18, 0x60, 0x10, 0x8e, 0x40, 0x00, 0x00, 0x80, 0x53, 0x66, 0x8a, 0x99,
        0xbf, 0x66, 0xb8, 0x20, 0x07, 0xaa, 0x35, 0x63, 0xd8, 0x58, 0x00, 0x27, 0x69, 0x13, 0x5e,
        0x0a, 0xc8, 0x04, 0x16, 0x14, 0xef, 0xc3, 0x42, 0x68, 0x76, 0xb6, 0x13, 0x6e, 0x3e, 0x9b,
        0x08, 0xf1, 0xf4, 0x7e, 0xf5, 0x36, 0x58, 0x5b, 0xfb, 0x1c, 0xc9, 0xc2, 0xcc, 0x90, 0x81,
        0x90, 0xb0, 0x36, 0x8d, 0xfd, 0xd9, 0x79, 0x27, 0x4b, 0xcb, 0x3d, 0x7a, 0x3c, 0xcd, 0x97,
        0x00, 0x00, 0x00, 0x00,
    ];
    let expected: &[u8] = &[
        0x53, 0x66, 0x8a, 0x99, 0xbf, 0x66, 0xb8, 0x20, 0x07, 0xaa, 0x35, 0x63, 0xd8, 0x58, 0x00,
        0x27, 0x69, 0x13, 0x5e, 0x0a, 0xc8, 0x04, 0x16, 0x14, 0xef, 0xc3, 0x42, 0x68, 0x76, 0xb6,
        0x13, 0x6e, 0x3e, 0x9b, 0x08, 0xf1, 0xf4, 0x7e, 0xf5, 0x36, 0x58, 0x5b, 0xfb, 0x1c, 0xc9,
        0xc2, 0xcc, 0x90, 0x81, 0x90, 0xb0, 0x36, 0x8d, 0xfd, 0xd9, 0x79, 0x27, 0x4b, 0xcb, 0x3d,
        0x7a, 0x3c, 0xcd, 0x97,
    ];
    let decoded = decode_chunked(encoded, 1024, 1024).unwrap();
    assert_eq!(decoded, expected);
}

#[test]
fn decode_reference_compressed_repeating_text() {
    // Input: "the quick brown fox jumps over the lazy dog. " × 500.
    // The encoder picked a real LZ4-codeword block: 2 sequences (tokens
    // 0x1f, 0xf0) followed by 16 trailing literals. This exercises the
    // sequence loop with literal length extension, offset, and a
    // large-extension match length (the 0xfe 254-marker path).
    let encoded: &[u8] = &[
        0x06, 0x22, 0x4d, 0x18, 0x60, 0x10, 0x8e, 0x57, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x1f, 0xf0, 0x44, 0x00, 0x00,
        0x1d, 0x74, 0x68, 0x65, 0x20, 0x71, 0x75, 0x69, 0x63, 0x6b, 0x20, 0x62, 0x72, 0x6f, 0x77,
        0x6e, 0x20, 0x66, 0x6f, 0x78, 0x20, 0x6a, 0x75, 0x6d, 0x70, 0x73, 0x20, 0x6f, 0x76, 0x65,
        0x72, 0x20, 0x74, 0x68, 0x65, 0x20, 0x6c, 0x61, 0x7a, 0x79, 0x20, 0x64, 0x6f, 0x67, 0x2e,
        0x0e, 0x00, 0x2d, 0x00, 0xfe, 0x90, 0x57, 0x72, 0x20, 0x74, 0x68, 0x65, 0x20, 0x6c, 0x61,
        0x7a, 0x79, 0x20, 0x64, 0x6f, 0x67, 0x2e, 0x20, 0x00, 0x00, 0x00, 0x00,
    ];
    let mut expected = Vec::new();
    let phrase = b"the quick brown fox jumps over the lazy dog. ";
    for _ in 0..500 {
        expected.extend_from_slice(phrase);
    }
    let decoded = decode_chunked(encoded, 1024, 1024).unwrap();
    assert_eq!(decoded.len(), expected.len());
    assert_eq!(decoded, expected);
}

// ─── decoder error rejection ───────────────────────────────────────────

#[test]
fn truncated_stream_rejected() {
    // Truncate the bigtext fixture before its endmark: decoder must
    // report UnexpectedEnd or Corrupt rather than silently succeeding.
    let encoded: &[u8] = &[
        0x06, 0x22, 0x4d, 0x18, 0x60, 0x10, 0x8e, 0x57, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x1f, 0xf0, 0x44, 0x00, 0x00,
        0x1d, 0x74, 0x68, 0x65, 0x20,
    ];
    let err = decode_chunked(encoded, 4096, 4096).unwrap_err();
    assert!(
        matches!(err, Error::UnexpectedEnd | Error::Corrupt),
        "unexpected error: {:?}",
        err
    );
}

#[test]
fn bad_magic_rejected() {
    // First 4 bytes are not the Lizard magic.
    let encoded: &[u8] = &[0xFF, 0xFF, 0xFF, 0xFF, 0x60, 0x10, 0x8e];
    let mut dec = Decoder::new();
    let mut buf = [0u8; 16];
    let err = dec.decode(encoded, &mut buf).unwrap_err();
    assert_eq!(err, Error::BadHeader);
}

#[test]
fn bad_version_bits_rejected() {
    // Magic OK but FLG version bits (top 2) are 00, not 01.
    let encoded: &[u8] = &[0x06, 0x22, 0x4d, 0x18, 0x00, 0x10, 0x8e];
    let mut dec = Decoder::new();
    let mut buf = [0u8; 16];
    let err = dec.decode(encoded, &mut buf).unwrap_err();
    assert_eq!(err, Error::BadHeader);
}

#[test]
fn bad_header_checksum_rejected() {
    // Magic + FLG + BD correct but HC byte flipped.
    let encoded: &[u8] = &[
        0x06, 0x22, 0x4d, 0x18, 0x60, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let mut dec = Decoder::new();
    let mut buf = [0u8; 16];
    let err = dec.decode(encoded, &mut buf).unwrap_err();
    assert_eq!(err, Error::ChecksumMismatch);
}

#[test]
fn invalid_clevel_rejected() {
    // Frame OK; first block claims compressionLevel = 5 (< MIN).
    let encoded: &[u8] = &[
        0x06, 0x22, 0x4d, 0x18, 0x60, 0x10, 0x8e, // header
        0x05, 0x00, 0x00, 0x00, // block size = 5 (compressed)
        0x05, 0x00, 0x00, 0x00, 0x00, // clevel=5, res=0, lengths_len=0(first 3 bytes)
    ];
    let err = decode_chunked(encoded, 1024, 1024).unwrap_err();
    assert!(
        matches!(err, Error::Corrupt | Error::UnexpectedEnd),
        "unexpected error: {:?}",
        err
    );
}

#[test]
fn rejects_lizv1_mode() {
    // Frame OK; block compressionLevel = 20 (LIZv1 mode) — Unsupported.
    let encoded: &[u8] = &[
        0x06, 0x22, 0x4d, 0x18, 0x60, 0x10, 0x8e, // header
        0x02, 0x00, 0x00, 0x00, // block size = 2 (compressed)
        0x14, 0x00, // clevel=20, res=0 (need at least 2 bytes to enter the LIZv1 check)
    ];
    let err = decode_chunked(encoded, 1024, 1024).unwrap_err();
    assert_eq!(err, Error::Unsupported);
}

// ─── cross-validate with reference `lizard -d` (if available) ─────────

#[cfg(feature = "std")]
#[test]
fn cross_validate_with_reference_lizard() {
    use std::io::Write;
    use std::process::{Command, Stdio};

    // Skip cleanly if the reference CLI isn't on $PATH.
    if Command::new("lizard").arg("-V").output().is_err() {
        eprintln!("`lizard` CLI not available; skipping cross-validation");
        return;
    }

    let phrase = b"the quick brown fox jumps over the lazy dog. ";
    let mut input = Vec::with_capacity(100 * phrase.len());
    for _ in 0..100 {
        input.extend_from_slice(phrase);
    }
    let encoded = encode_all(&input);

    let mut child = Command::new("lizard")
        .arg("-d")
        .arg("-c")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn lizard");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(&encoded)
        .expect("write to lizard stdin");
    let out = child.wait_with_output().expect("wait lizard");
    assert!(
        out.status.success(),
        "reference `lizard -d` rejected our stream: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout, input);
}

// ─── Algorithm-trait entry points ──────────────────────────────────────

#[test]
fn algorithm_encoder_decoder_round_trip() {
    let mut enc = <Lz5 as Algorithm>::encoder();
    let mut dec = <Lz5 as Algorithm>::decoder();
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
    use compcol::factory;
    use compcol::{Encoder as _, Status};

    #[test]
    fn lookup_known() {
        assert!(factory::encoder_by_name("lz5").is_some());
        assert!(factory::decoder_by_name("lz5").is_some());
    }

    #[test]
    fn names_contains_lz5() {
        assert!(factory::names().contains(&"lz5"));
    }

    #[test]
    fn extension_is_liz() {
        assert_eq!(factory::extension("lz5"), Some("liz"));
    }

    #[test]
    fn boxed_round_trip() {
        let mut enc = factory::encoder_by_name("lz5").unwrap();
        let mut dec = factory::decoder_by_name("lz5").unwrap();
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
        assert_eq!(decoded, input);
    }
}
