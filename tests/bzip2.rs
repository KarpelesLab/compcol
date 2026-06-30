//! Streaming round-trip tests for the bzip2 codec.
//!
//! Canonical v0.4 (Progress, Status) driver. Encoder and decoder are
//! exercised at the chunk-level and via the runtime factory.

#![cfg(feature = "bzip2")]

use compcol::bzip2::{Bzip2, Decoder, Encoder, EncoderConfig};
use compcol::{Algorithm, Decoder as _, Encoder as _, Error, Status};

/// Drive an encoder to completion, feeding `input` in `in_chunk`-sized
/// slices and draining via an `out_chunk`-sized buffer.
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
                    panic!("bzip2 encoder finish stalled");
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

    // After all input is fed, drain any remaining output the decoder
    // can produce with an empty input slice.
    loop {
        let (p, _status) = dec.decode(&[], &mut buf)?;
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
                    panic!("bzip2 decoder finish stalled");
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
    // Sanity-check the bzip2 framing.
    assert!(encoded.len() >= 14, "encoded too short: {}", encoded.len());
    assert_eq!(&encoded[..3], b"BZh", "stream header magic");
    let decoded = decode_chunked(&encoded, 4096, 4096).unwrap();
    assert_eq!(decoded, input, "round-trip mismatch len {}", input.len());
}

// ─── algorithm metadata ─────────────────────────────────────────────────

#[test]
fn name_is_bzip2() {
    assert_eq!(<Bzip2 as Algorithm>::NAME, "bzip2");
}

#[test]
fn default_config_is_level_6() {
    assert_eq!(EncoderConfig::default().level, 6);
}

// ─── round-trip tests ──────────────────────────────────────────────────

#[test]
fn round_trip_empty() {
    // Empty input: still produces a valid stream (header + footer; no
    // block). Decode must yield empty.
    let encoded = encode_all(b"");
    assert_eq!(&encoded[..3], b"BZh");
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
fn round_trip_repeated_bytes() {
    // RLE-1 should kick in: long run of identical bytes.
    let input = vec![b'a'; 1024];
    round_trip(&input);
}

#[test]
fn round_trip_mixed_short_runs() {
    let mut input = Vec::new();
    input.extend(core::iter::repeat_n(b'a', 10));
    input.extend(core::iter::repeat_n(b'b', 3));
    input.extend(core::iter::repeat_n(b'c', 7));
    input.extend(b"and a quick fox jumps over");
    input.extend(core::iter::repeat_n(b'z', 200));
    round_trip(&input);
}

#[test]
fn round_trip_lorem_8kib() {
    // Lorem-ipsum-like 8 KiB corpus: many recurring short phrases.
    // This exercises the Huffman path because the alphabet is small
    // and the symbol distribution is skewed.
    let phrase = b"lorem ipsum dolor sit amet consectetur adipiscing elit ";
    let mut input = Vec::new();
    while input.len() < 8 * 1024 {
        input.extend_from_slice(phrase);
    }
    round_trip(&input);
}

#[test]
fn round_trip_pseudo_random_64kib() {
    // 64 KiB of LCG output: low compressibility, exercises the worst
    // case of the Huffman tables.
    let mut state: u32 = 0xC0FFEE_u32;
    let mut input = Vec::with_capacity(64 * 1024);
    for _ in 0..(64 * 1024) {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        input.push((state >> 16) as u8);
    }
    round_trip(&input);
}

#[test]
fn round_trip_mixed_corpus() {
    // Phrase repetition mixed with pseudo-random padding — similar to
    // the gzip test corpus but smaller (this codec is slow at >64 KB
    // because we use a naive O(n² log n) suffix-array build for the
    // BWT).
    let mut state: u32 = 0xDEADBEEFu32;
    let mut input = Vec::with_capacity(32 * 1024);
    let phrases: &[&[u8]] = &[
        b"the_quick_brown_fox_jumps_over_the_lazy_dog ",
        b"compcol streaming codec test corpus aaaa ",
        b"bzip2 round trip mixed ",
    ];
    let mut p = 0;
    while input.len() < 16 * 1024 {
        for _ in 0..32 {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            input.push((state >> 16) as u8);
        }
        input.extend_from_slice(phrases[p % phrases.len()]);
        p += 1;
    }
    round_trip(&input);
}

#[test]
fn round_trip_large_compressible_multiblock() {
    // 1.5 MB of zeros. Post-RLE-1 this is tiny, but it exercises the
    // RLE-1-size-based block fill in the encoder (reference bzip2 sizes
    // blocks by post-RLE-1 length, not raw input). Round-trips through
    // the library decoder regardless of how compressible the data is.
    let input = vec![0u8; 1_500_000];
    let encoded = encode_all(&input);
    let decoded = decode_chunked(&encoded, 4096, 4096).unwrap();
    assert_eq!(decoded.len(), input.len());
    assert_eq!(decoded, input);
}

#[test]
fn round_trip_low_level_forces_multiple_blocks() {
    // At level 1 (≈100 KB post-RLE-1 cap) a ~250 KB low-redundancy
    // payload spans several blocks, exercising the multi-table Huffman
    // optimisation and selector encoding across block boundaries.
    let mut state: u32 = 0x1234_5678;
    let mut input = Vec::with_capacity(250_000);
    while input.len() < 250_000 {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        input.push((state >> 16) as u8);
        input.push((state >> 8) as u8);
        // Inject some structure so the BWT/MTF/Huffman path is non-trivial.
        if input.len() % 64 == 0 {
            input.extend_from_slice(b"compcol-bzip2-multiblock ");
        }
    }
    let mut enc = Encoder::with_config(EncoderConfig { level: 1 });
    let encoded = encode_chunked(&mut enc, &input, 7919, 4096);
    let decoded = decode_chunked(&encoded, 4096, 4096).unwrap();
    assert_eq!(decoded, input);
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

/// Decode following the *exact* streaming loop documented on the `Decoder`
/// trait — no defensive "drain after InputEmpty" workaround like
/// [`decode_chunked`] has. A naive caller breaks out of the decode loop on
/// `InputEmpty` and then calls `finish`. This is the pattern that regressed:
/// the decoder buffers a whole block internally, so when the small `output`
/// fills mid-block it used to report `InputEmpty` (instead of `OutputFull`),
/// the loop stopped with the block half-drained, and `finish` then failed with
/// `UnexpectedEnd`.
fn decode_documented_loop(encoded: &[u8], out_chunk: usize) -> Result<Vec<u8>, Error> {
    let mut dec = Decoder::new();
    let mut buf = vec![0u8; out_chunk];
    let mut out = Vec::new();
    let mut consumed = 0;
    loop {
        let (p, status) = dec.decode(&encoded[consumed..], &mut buf)?;
        out.extend_from_slice(&buf[..p.written]);
        consumed += p.consumed;
        match status {
            Status::OutputFull => continue,
            Status::InputEmpty => break,
            Status::StreamEnd => return Ok(out),
        }
    }
    loop {
        let (p, status) = dec.finish(&mut buf)?;
        out.extend_from_slice(&buf[..p.written]);
        if matches!(status, Status::StreamEnd) {
            break;
        }
    }
    Ok(out)
}

#[test]
fn round_trip_small_output_buffer_naive_loop() {
    // Inputs larger than the output buffer force the decoder to drain a single
    // decoded block across several `decode` calls. Before the fix this failed
    // with `UnexpectedEnd` for any block bigger than `out_chunk`.
    for &n in &[100_000usize, 600_000, 1_000_000] {
        let input: Vec<u8> = (0..n)
            .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
            .collect();
        let encoded = encode_all(&input);
        for &out_chunk in &[1usize, 64, 4096, 65536] {
            let decoded = decode_documented_loop(&encoded, out_chunk)
                .unwrap_or_else(|e| panic!("n={n} out_chunk={out_chunk}: {e:?}"));
            assert_eq!(decoded, input, "n={n} out_chunk={out_chunk}");
        }
    }
}

// ─── reset / reuse ─────────────────────────────────────────────────────

#[test]
fn reset_preserves_level_and_allows_reuse() {
    let input_a = b"alpha alpha alpha alpha alpha".as_slice();
    let input_b = b"bravo bravo bravo bravo bravo".as_slice();

    let mut enc = Encoder::with_config(EncoderConfig { level: 6 });
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

// ─── multi-block ────────────────────────────────────────────────────────

#[test]
fn round_trip_multi_block_200kib() {
    // 200 KiB at the default level (100 KB blocks) forces at least
    // two blocks. We use a lower level to keep the suffix-sort cost
    // bounded (~100 KB per block × 2 ≈ a few hundred ms).
    let mut state: u32 = 0xCAFEFACEu32;
    let mut input = Vec::with_capacity(200 * 1024);
    for _ in 0..(200 * 1024) {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        input.push((state >> 16) as u8);
    }
    let mut enc = Encoder::with_config(EncoderConfig { level: 1 });
    let encoded = encode_chunked(&mut enc, &input, 4096, 4096);
    assert_eq!(&encoded[..3], b"BZh");
    assert_eq!(encoded[3], b'1', "level 1 → 'BZh1'");
    let decoded = decode_chunked(&encoded, 4096, 4096).unwrap();
    assert_eq!(decoded, input);
}

// ─── decode real bzip2 fixtures ────────────────────────────────────────

#[test]
fn decode_reference_hello_bzip2() {
    // `echo -n 'hello bzip2' | bzip2 -c` at the default level.
    let encoded: &[u8] = &[
        0x42, 0x5a, 0x68, 0x39, 0x31, 0x41, 0x59, 0x26, 0x53, 0x59, 0x55, 0x5a, 0x44, 0xf7, 0x00,
        0x00, 0x02, 0x19, 0x80, 0x40, 0x00, 0x10, 0x00, 0x12, 0x64, 0xc0, 0x10, 0x20, 0x00, 0x22,
        0x00, 0x69, 0xea, 0x10, 0x03, 0x05, 0xd3, 0xb6, 0x21, 0x83, 0xc5, 0xdc, 0x91, 0x4e, 0x14,
        0x24, 0x15, 0x56, 0x91, 0x3d, 0xc0,
    ];
    let decoded = decode_chunked(encoded, 1024, 1024).unwrap();
    assert_eq!(decoded, b"hello bzip2");
}

#[test]
fn decode_reference_full_byte_range() {
    // 256 bytes of 0..=255 piped through `bzip2 -c`.
    let encoded: &[u8] = &[
        0x42, 0x5a, 0x68, 0x39, 0x31, 0x41, 0x59, 0x26, 0x53, 0x59, 0xb6, 0xb5, 0xee, 0x95, 0x00,
        0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xb0, 0x00, 0xc5, 0x52, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x30, 0x09, 0x80,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4c, 0x00, 0x04, 0xc0, 0x04,
        0x98, 0x00, 0x26, 0x00, 0x02, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x02, 0x4c, 0x00, 0x13, 0x00, 0x01, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xf0, 0x08, 0x0c, 0x10, 0x14, 0x18, 0x1c,
        0x20, 0x24, 0x28, 0x2c, 0x30, 0x34, 0x38, 0x3c, 0x40, 0x44, 0x48, 0x4c, 0x50, 0x54, 0x58,
        0x5c, 0x60, 0x64, 0x68, 0x6c, 0x70, 0x74, 0x78, 0x7c, 0x80, 0x84, 0x88, 0x8c, 0x90, 0x94,
        0x98, 0x9c, 0xa0, 0xa4, 0xa8, 0xac, 0xb0, 0xb4, 0xb8, 0xbc, 0xc0, 0xc4, 0xc8, 0xcc, 0xd0,
        0xd4, 0xd8, 0xdc, 0xe0, 0xe4, 0xe8, 0xec, 0xf0, 0xf4, 0xf8, 0xfd, 0x01, 0x05, 0x09, 0x0d,
        0x11, 0x15, 0x19, 0x1d, 0x21, 0x25, 0x29, 0x2d, 0x31, 0x35, 0x39, 0x3d, 0x41, 0x45, 0x49,
        0x4d, 0x51, 0x55, 0x59, 0x5d, 0x61, 0x65, 0x69, 0x6d, 0x71, 0x75, 0x79, 0x7d, 0x81, 0x85,
        0x89, 0x8d, 0x91, 0x85, 0x89, 0x8d, 0x91, 0x95, 0x99, 0x9d, 0xa1, 0xa5, 0xa9, 0xad, 0xb1,
        0xb5, 0xb9, 0xbd, 0xc1, 0xc5, 0xc9, 0xcd, 0xd1, 0xd5, 0xd9, 0xdd, 0xe1, 0xe5, 0xe9, 0xed,
        0xf1, 0xf5, 0xf9, 0xfe, 0x02, 0x06, 0x0a, 0x0e, 0x12, 0x16, 0x1a, 0x1e, 0x22, 0x26, 0x2a,
        0x2e, 0x32, 0x36, 0x3a, 0x3e, 0x42, 0x46, 0x4a, 0x56, 0x5a, 0x5e, 0x62, 0x66, 0x6a, 0x6e,
        0x72, 0x76, 0x7a, 0x7e, 0x82, 0x86, 0x8a, 0x8e, 0x92, 0x96, 0x9a, 0x9e, 0xa2, 0xa6, 0xaa,
        0xae, 0xb2, 0xb6, 0xba, 0xbe, 0xc2, 0xc6, 0xca, 0xce, 0xd2, 0xd6, 0xda, 0xde, 0xe2, 0xe6,
        0xea, 0xee, 0xf2, 0xf6, 0xfa, 0xff, 0x03, 0x07, 0x0b, 0x0f, 0x13, 0x17, 0x1b, 0x17, 0x1b,
        0x1f, 0x23, 0x27, 0x2b, 0x2f, 0x33, 0x37, 0x3b, 0x3f, 0x43, 0x47, 0x4b, 0x4f, 0x53, 0x57,
        0x5b, 0x5f, 0x63, 0x67, 0x6b, 0x6f, 0x73, 0x77, 0x7b, 0x7f, 0x83, 0x87, 0x8b, 0x8f, 0x93,
        0x97, 0x9b, 0x9f, 0xa3, 0xa7, 0xab, 0xaf, 0xb3, 0xb7, 0xbb, 0xbf, 0xc3, 0xc7, 0xcb, 0xcf,
        0xd3, 0xd7, 0xdb, 0xdf, 0xe3, 0xe7, 0xeb, 0xef, 0xf3, 0xf4, 0x5d, 0xc9, 0x14, 0xe1, 0x42,
        0x42, 0xda, 0xd7, 0xba, 0x54,
    ];
    let decoded = decode_chunked(encoded, 1024, 1024).unwrap();
    let expected: Vec<u8> = (0..=255u8).collect();
    assert_eq!(decoded, expected);
}

// ─── cross-validate with system `bunzip2` (if available) ───────────────

#[cfg(feature = "std")]
#[test]
fn cross_validate_with_system_bunzip2() {
    use std::io::Write;
    use std::process::{Command, Stdio};

    // Skip cleanly if `bunzip2` isn't on $PATH.
    if Command::new("bunzip2").arg("--version").output().is_err() {
        eprintln!("bunzip2 not available; skipping cross-validation");
        return;
    }

    let input = b"the quick brown fox jumps over the lazy dog 1234567890";
    let encoded = encode_all(input);

    let mut child = Command::new("bunzip2")
        .arg("-c")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn bunzip2");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(&encoded)
        .expect("write to bunzip2 stdin");
    let out = child.wait_with_output().expect("wait bunzip2");
    assert!(
        out.status.success(),
        "bunzip2 rejected our stream: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout, input);
}

// ─── decoder error rejection ───────────────────────────────────────────

#[test]
fn truncated_stream_rejected() {
    // Encode something, then truncate before the trailer.
    let encoded = encode_all(b"some payload bytes that produce a few output bytes");
    let truncated = &encoded[..encoded.len() / 2];
    let err = decode_chunked(truncated, 4096, 4096).unwrap_err();
    assert!(
        matches!(err, Error::UnexpectedEnd | Error::Corrupt),
        "unexpected error: {:?}",
        err
    );
}

#[test]
fn bad_header_rejected() {
    let stream = b"XYh6garbage data";
    let mut dec = Decoder::new();
    let mut buf = [0u8; 16];
    let err = dec.decode(stream, &mut buf).unwrap_err();
    assert_eq!(err, Error::BadHeader);
}

#[test]
fn flipped_block_crc_rejected() {
    let mut encoded = encode_all(b"the encoded crc lives at a fixed-ish offset");
    // The block CRC is the 32 bits right after the 4-byte header + 48
    // bits of block magic = bytes 4..=9 hold the magic; bytes 10..=13
    // hold the CRC. Flip a bit there.
    encoded[12] ^= 0xFF;
    let err = decode_chunked(&encoded, 4096, 4096).unwrap_err();
    assert!(
        matches!(err, Error::ChecksumMismatch | Error::Corrupt),
        "expected ChecksumMismatch or Corrupt, got {:?}",
        err
    );
}

// ─── Algorithm-trait entry points ──────────────────────────────────────

#[test]
fn algorithm_encoder_decoder_round_trip() {
    let mut enc = <Bzip2 as Algorithm>::encoder();
    let mut dec = <Bzip2 as Algorithm>::decoder();
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
        assert!(factory::encoder_by_name("bzip2").is_some());
        assert!(factory::decoder_by_name("bzip2").is_some());
    }

    #[test]
    fn names_contains_bzip2() {
        assert!(factory::names().contains(&"bzip2"));
    }

    #[test]
    fn extension_is_bz2() {
        assert_eq!(factory::extension("bzip2"), Some("bz2"));
    }

    #[test]
    fn boxed_round_trip() {
        let mut enc = factory::encoder_by_name("bzip2").unwrap();
        let mut dec = factory::decoder_by_name("bzip2").unwrap();
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
