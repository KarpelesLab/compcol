//! Streaming round-trip tests for the bzip2 codec.
//!
//! Canonical v0.4 (Progress, Status) driver. Encoder and decoder are
//! exercised at the chunk-level and via the runtime factory.

#![cfg(feature = "bzip2")]

use compcol::bzip2::{Bzip2, Decoder, DecoderConfig, Encoder, EncoderConfig};
use compcol::{Algorithm, Decoder as _, Encoder as _, Error, Flush, Status};

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

// ─── decoded block larger than the caller's buffer ─────────────────────
//
// bzip2 decodes a whole block (up to 900 kB) at once. When a single
// `decode` call hands it all remaining input, it can consume every byte
// while still holding far more decoded output than the caller's buffer
// takes. Fixtures generated with the reference `bzip2` CLI as a black box:
//
//   python3 tests/fixtures/gen_words.py 200000 | bzip2 -9 > words200k_9.bz2
//   python3 tests/fixtures/gen_words.py 250000 | bzip2 -1 > words250k_1.bz2
//
// (one 200 kB block, and three blocks at the 100 kB level-1 block size).

static WORDS200K_9: &[u8] = include_bytes!("fixtures/bzip2/words200k_9.bz2");
static WORDS250K_1: &[u8] = include_bytes!("fixtures/bzip2/words250k_1.bz2");

/// Same bytes as `tests/fixtures/gen_words.py`.
fn gen_words(n: usize) -> Vec<u8> {
    const WORDS: [&[u8]; 8] = [
        b"alpha ",
        b"beta ",
        b"gamma ",
        b"delta ",
        b"epsilon ",
        b"zeta ",
        b"eta ",
        b"theta ",
    ];
    let mut x: u32 = 1;
    let mut out = Vec::with_capacity(n + 8);
    while out.len() < n {
        x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        out.extend_from_slice(WORDS[((x >> 16) & 7) as usize]);
    }
    out.truncate(n);
    out
}

#[test]
fn vec_helpers_decode_blocks_larger_than_scratch() {
    // `vec::decompress_to_vec*` stage output through a 64 KiB buffer; both
    // fixtures decode to blocks larger than that. They used to fail with
    // `UnexpectedEnd`.
    for (enc, n) in [(WORDS200K_9, 200_000), (WORDS250K_1, 250_000)] {
        let expected = gen_words(n);
        assert_eq!(
            compcol::vec::decompress_to_vec::<Bzip2>(enc).unwrap(),
            expected
        );
        assert_eq!(
            compcol::vec::decompress_to_vec_capped::<Bzip2>(enc, 1 << 20).unwrap(),
            expected
        );
    }
}

#[test]
fn finish_drains_pending_block_output() {
    // Feed the whole stream in one `decode` call with a small output buffer,
    // then rely solely on `finish` to deliver the rest. Per the `Decoder`
    // contract `finish` is called repeatedly until `StreamEnd`; it used to
    // report `UnexpectedEnd` as soon as a decoded block was still pending.
    for (enc, n) in [(WORDS200K_9, 200_000), (WORDS250K_1, 250_000)] {
        let expected = gen_words(n);
        let mut dec = Decoder::new();
        let mut buf = vec![0u8; 4096];
        let mut out = Vec::new();
        let mut consumed = 0;
        while consumed < enc.len() {
            let (p, _) = dec.decode(&enc[consumed..], &mut buf).unwrap();
            out.extend_from_slice(&buf[..p.written]);
            consumed += p.consumed;
        }
        loop {
            let (p, status) = dec.finish(&mut buf).unwrap();
            out.extend_from_slice(&buf[..p.written]);
            if status == Status::StreamEnd {
                break;
            }
            assert!(p.written > 0, "finish stalled");
        }
        assert_eq!(out, expected);
    }
}

#[test]
fn finish_still_reports_truncation() {
    // Draining must not mask a genuinely truncated stream.
    let truncated = &WORDS250K_1[..WORDS250K_1.len() - 200];
    let mut dec = Decoder::new();
    let mut buf = vec![0u8; 4096];
    let (_p, _) = dec.decode(truncated, &mut buf).unwrap();
    let err = loop {
        match dec.finish(&mut buf) {
            Ok((p, status)) => {
                assert_ne!(status, Status::StreamEnd);
                assert!(p.written > 0, "finish stalled");
            }
            Err(e) => break e,
        }
    };
    assert_eq!(err, Error::UnexpectedEnd);
    assert_eq!(
        compcol::vec::decompress_to_vec::<Bzip2>(truncated),
        Err(Error::UnexpectedEnd)
    );
}

/// `cat a.bz2 b.bz2` (and pbzip2/lbzip2 output) is a valid multi-stream
/// file that `bzip2 -d` decodes in full. The decoder used to stop at the
/// first stream's trailer and silently drop the rest — while reporting the
/// whole input as consumed.
#[test]
fn concatenated_streams_decode_in_full() {
    let a = encode_all(b"hello ");
    let mut enc = Encoder::with_config(EncoderConfig { level: 1 });
    let b = encode_chunked(&mut enc, &[b'w'; 300_000], 300_000, 4096);
    let c = encode_all(b"");
    let mut cat = a.clone();
    cat.extend_from_slice(&b);
    cat.extend_from_slice(&c);
    cat.extend_from_slice(&a);
    let mut want = b"hello ".to_vec();
    want.extend_from_slice(&[b'w'; 300_000]);
    want.extend_from_slice(b"hello ");
    for (in_chunk, out_chunk) in [(cat.len(), 65536), (1, 7), (3, 1), (4096, 1)] {
        assert_eq!(
            decode_chunked(&cat, in_chunk, out_chunk).unwrap(),
            want,
            "{in_chunk}/{out_chunk}"
        );
        assert_eq!(decode_documented_loop(&cat, out_chunk).unwrap(), want);
    }
    assert_eq!(
        compcol::vec::decompress_to_vec::<Bzip2>(&cat).unwrap(),
        want
    );

    // A corrupt second stream is reported, not ignored.
    let mut bad = a.clone();
    bad.extend_from_slice(&a[..a.len() - 2]);
    assert!(compcol::vec::decompress_to_vec::<Bzip2>(&bad).is_err());
}

/// Bytes after the final trailer that don't start a new `BZh` stream are
/// trailing garbage; `bzip2 -d` ignores them (with a warning) and so do we.
#[test]
fn trailing_garbage_after_stream_is_ignored() {
    let a = encode_all(b"payload");
    for tail in [&b"\0\0\0\0"[..], b"B", b"BZ", b"BZh", b"BZhX", b"junk data"] {
        let mut s = a.clone();
        s.extend_from_slice(tail);
        assert_eq!(decode_chunked(&s, 1, 1).unwrap(), b"payload", "{tail:?}");
        assert_eq!(
            compcol::vec::decompress_to_vec::<Bzip2>(&s).unwrap(),
            b"payload",
            "{tail:?}"
        );
    }
}

/// Feeding a large block one byte at a time used to re-parse the whole
/// buffered block on every byte (quadratic: ~150 s for a 200 KB block in
/// release, far longer in debug). Retries are now spaced geometrically.
#[test]
fn one_byte_input_on_large_block_is_not_quadratic() {
    let mut s = 0x9E37_79B9_7F4A_7C15u64;
    let input: Vec<u8> = (0..200_000)
        .map(|_| {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s as u8
        })
        .collect();
    let encoded = encode_all(&input);
    let start = std::time::Instant::now();
    assert_eq!(decode_chunked(&encoded, 1, 65536).unwrap(), input);
    // Generous bound for slow debug CI; the quadratic path took minutes.
    assert!(start.elapsed().as_secs() < 60, "{:?}", start.elapsed());
}

// ─── byte-identity with libbzip2 ───────────────────────────────────────

fn encode_level(input: &[u8], level: u8) -> Vec<u8> {
    let mut enc = Encoder::with_config(EncoderConfig { level });
    encode_chunked(&mut enc, input, input.len().max(1), 4096)
}

/// 510 zero bytes RLE-1 to a block of period 5, whose two equal
/// rotations make the origin a matter of sort order: libbzip2 reports 0,
/// and so must we (we used to say 1). Reference: `bzip2 -9`.
#[test]
fn periodic_block_origin_matches_libbzip2() {
    const REF: [u8; 41] = [
        0x42, 0x5a, 0x68, 0x39, 0x31, 0x41, 0x59, 0x26, 0x53, 0x59, 0x8f, 0x19, 0xb0, 0x35, 0x00,
        0x00, 0x00, 0x40, 0x00, 0xc0, 0x00, 0x00, 0x08, 0x20, 0x00, 0x30, 0x80, 0x2a, 0x69, 0x21,
        0xc5, 0xdc, 0x91, 0x4e, 0x14, 0x24, 0x23, 0xc6, 0x6c, 0x0d, 0x40,
    ];
    assert_eq!(encode_level(&[0u8; 510], 9), REF);
}

/// Inputs that put a run on a block boundary (libbzip2 closes a block
/// without the run in progress, which then starts the next block),
/// periodic blocks either side of the 10 000-byte switch to the main
/// sort and past its work budget, and plain text, at several levels.
/// Compared with the system `bzip2` when there is one.
#[cfg(feature = "std")]
#[test]
fn output_matches_system_bzip2() {
    use std::io::Write;
    use std::process::{Command, Stdio};

    if Command::new("bzip2").arg("--help").output().is_err() {
        eprintln!("bzip2 not available; skipping");
        return;
    }
    let mut s = 0x2545_F491_4F6C_DD1Du64;
    let mut rnd = move || {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        s
    };
    // Runs of 1..=8 and some long ones: over 1 MB at level 1 this ends
    // many blocks inside a run.
    let mut runs = Vec::new();
    while runs.len() < 1_200_000 {
        let r = rnd();
        let len = if r % 16 == 0 {
            (r >> 8) % 300
        } else {
            (r >> 8) % 8 + 1
        };
        runs.extend(std::iter::repeat_n(
            b'a' + (r >> 20) as u8 % 3,
            len as usize,
        ));
    }
    let cases: Vec<(Vec<u8>, u8)> = vec![
        (runs.clone(), 1),
        (runs, 2),
        (b"ab".repeat(4_000), 9),
        (b"abcde".repeat(30_000), 9),
        (b"hello world, periodic ".repeat(60_000), 1),
        (vec![7u8; 3_000_000], 1),
        (gen_words(250_000), 1),
    ];
    for (input, level) in &cases {
        let mut child = Command::new("bzip2")
            .arg(format!("-{level}"))
            .arg("-c")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn bzip2");
        let mut stdin = child.stdin.take().unwrap();
        let data = input.clone();
        let writer = std::thread::spawn(move || stdin.write_all(&data));
        let out = child.wait_with_output().expect("wait bzip2");
        writer.join().unwrap().unwrap();
        let ours = encode_level(input, *level);
        assert!(
            ours == out.stdout,
            "differs from bzip2 -{level} on {} bytes: {} vs {}",
            input.len(),
            ours.len(),
            out.stdout.len()
        );
    }
}

/// `flush` is libbzip2's `BZ_FLUSH`: it closes the block and hands out
/// the bytes libbzip2 would — all but the bits of the last write, which
/// a bzip2 stream has no way to pad. Reference: libbzip2 with BZ_RUN /
/// BZ_FLUSH / BZ_FINISH at level 1, flushing at offsets 0, 6 and 6 of
/// "hello hello hello world" (3, 31 and 31 bytes out after each flush).
#[test]
fn flush_matches_libbzip2() {
    const REF: [u8; 78] = [
        0x42, 0x5a, 0x68, 0x31, 0x31, 0x41, 0x59, 0x26, 0x53, 0x59, 0x76, 0x69, 0xe0, 0xd4, 0x00,
        0x00, 0x01, 0x11, 0x00, 0x40, 0x00, 0x02, 0x44, 0xa0, 0x00, 0x30, 0xcd, 0x00, 0xc3, 0x46,
        0x29, 0x97, 0x31, 0x41, 0x59, 0x26, 0x53, 0x59, 0xde, 0x9d, 0x45, 0x08, 0x00, 0x00, 0x02,
        0x91, 0x80, 0x40, 0x00, 0x06, 0x44, 0x90, 0x80, 0x20, 0x00, 0x31, 0x0c, 0x08, 0x12, 0x81,
        0xea, 0x08, 0xa6, 0x66, 0xe8, 0x87, 0x73, 0xe2, 0xee, 0x48, 0xa7, 0x0a, 0x12, 0x06, 0x49,
        0xd0, 0x94, 0x00,
    ];
    let input = b"hello hello hello world";
    for out_chunk in [1, 5, 4096] {
        let mut enc = Encoder::with_config(EncoderConfig { level: 1 });
        let mut buf = vec![0u8; out_chunk];
        let mut out = Vec::new();
        let mut after_flush = Vec::new();
        let mut fed = 0;
        for split in [0, 6, 6, input.len()] {
            while fed < split {
                let (p, _) = enc.encode(&input[fed..split], &mut buf).unwrap();
                out.extend_from_slice(&buf[..p.written]);
                fed += p.consumed;
            }
            if split == input.len() {
                break;
            }
            loop {
                let (p, status) = enc.flush(&mut buf, Flush::Sync).unwrap();
                out.extend_from_slice(&buf[..p.written]);
                if status == Status::InputEmpty {
                    break;
                }
            }
            after_flush.push(out.len());
        }
        loop {
            let (p, status) = enc.finish(&mut buf).unwrap();
            out.extend_from_slice(&buf[..p.written]);
            if status == Status::StreamEnd {
                break;
            }
        }
        assert_eq!(after_flush, [3, 31, 31], "out_chunk {out_chunk}");
        assert_eq!(out, REF, "out_chunk {out_chunk}");
    }
}

// ─── decoder: where the stream ends ────────────────────────────────────

/// With `multi_stream` off, `decode` stops at the trailer and never
/// reports the bytes after it consumed, however the input is chunked.
#[test]
fn single_stream_decode_leaves_bytes_after_the_stream() {
    let plain = gen_words(150_000);
    let stream = encode_level(&plain, 1);
    let mut input = stream.clone();
    input.extend_from_slice(b"BZh9 and more trailing bytes");
    let config = DecoderConfig::default().with_multi_stream(false);

    for (in_chunk, out_chunk) in [
        (input.len(), 1 << 20),
        (input.len(), 1000),
        (1, 1 << 20),
        (7, 3),
    ] {
        let mut dec = Bzip2::decoder_with(config);
        let mut buf = vec![0u8; out_chunk];
        let mut got = Vec::new();
        let mut pos = 0;
        loop {
            let end = (pos + in_chunk).min(input.len());
            let (p, status) = dec.decode(&input[pos..end], &mut buf).unwrap();
            got.extend_from_slice(&buf[..p.written]);
            pos += p.consumed;
            if status == Status::StreamEnd {
                break;
            }
            assert!(pos < input.len(), "ran out of input before StreamEnd");
        }
        assert!(got == plain, "{in_chunk}/{out_chunk}");
        assert_eq!(pos, stream.len(), "{in_chunk}/{out_chunk}");
        let (p, status) = dec.decode(&input[pos..], &mut buf).unwrap();
        assert_eq!((p.consumed, p.written, status), (0, 0, Status::StreamEnd));
        assert_eq!(dec.finish(&mut buf).unwrap().1, Status::StreamEnd);
    }
}

/// In the default multi-stream mode, the call that finds the end hands
/// back the trailing bytes it was given.
#[test]
fn multi_stream_decode_hands_back_trailing_garbage() {
    let a = encode_all(b"first ");
    let b = encode_all(b"second");
    let mut input = a.clone();
    input.extend_from_slice(&b);
    input.extend_from_slice(b"garbage");
    let mut dec = Decoder::new();
    let mut out = vec![0u8; 100];
    let (p, status) = dec.decode(&input, &mut out).unwrap();
    assert_eq!(status, Status::StreamEnd);
    assert_eq!(&out[..p.written], b"first second");
    assert_eq!(p.consumed, a.len() + b.len());
}

/// A full output buffer leaves the input past the decoded block for the
/// next call instead of swallowing it.
#[test]
fn decode_with_full_output_does_not_take_unparsed_input() {
    let plain = gen_words(250_000);
    let stream = encode_level(&plain, 1);
    let mut input = stream.clone();
    input.extend_from_slice(b"tail");
    let mut dec = Decoder::with_config(DecoderConfig::default().with_multi_stream(false));
    let mut buf = [0u8; 4096];
    let (p, status) = dec.decode(&input, &mut buf).unwrap();
    assert_eq!(status, Status::OutputFull);
    assert!(
        p.consumed < stream.len(),
        "{} of {}",
        p.consumed,
        stream.len()
    );
    let mut got = buf[..p.written].to_vec();
    let mut pos = p.consumed;
    loop {
        let (p, status) = dec.decode(&input[pos..], &mut buf).unwrap();
        got.extend_from_slice(&buf[..p.written]);
        pos += p.consumed;
        if status == Status::StreamEnd {
            break;
        }
    }
    assert!(got == plain);
    assert_eq!(&input[pos..], b"tail");
}

// ─── decoder: what libbzip2 accepts ────────────────────────────────────

/// Blocks with the "randomised" bit set, as bzip2 0.9.0/0.9.5 wrote for
/// repetitive data. The fixtures were made by randomising blocks the way
/// those versions did and checked with libbzip2 1.0.8 (`bunzip2 -t`);
/// the second has several blocks at level 1.
#[test]
fn decodes_randomised_blocks() {
    let mut small = Vec::new();
    let mut x: u32 = 12345;
    while small.len() < 6000 {
        x = x.wrapping_mul(1_103_515_245).wrapping_add(12345) & 0x7fff_ffff;
        let byte = b'a' + ((x >> 16) % 6) as u8;
        let n = if (x >> 4).is_multiple_of(7) {
            1 + (x >> 8) % 6
        } else {
            1
        };
        small.extend(std::iter::repeat_n(byte, n as usize));
    }
    small.truncate(6000);
    let mut big = b"abcd".repeat(30_000);
    big.extend((0..=255u8).cycle().take(128_000));
    big.resize(300_000, 0);

    for (stream, want) in [
        (
            &include_bytes!("fixtures/bzip2/randomised_small.bz2")[..],
            small,
        ),
        (
            &include_bytes!("fixtures/bzip2/randomised_multiblock.bz2")[..],
            big,
        ),
    ] {
        assert!(decode_chunked(stream, stream.len(), 1 << 20).unwrap() == want);
        assert!(decode_chunked(stream, 1, 777).unwrap() == want);
    }
}

/// MSB-first bit writer for hand-built streams.
#[derive(Default)]
struct Bits {
    out: Vec<u8>,
    acc: u64,
    n: u32,
}

impl Bits {
    fn put(&mut self, n: u32, v: u64) {
        for i in (0..n).rev() {
            self.acc = (self.acc << 1) | ((v >> i) & 1);
            self.n += 1;
            if self.n == 8 {
                self.out.push(self.acc as u8);
                self.acc = 0;
                self.n = 0;
            }
        }
    }
    fn finish(mut self) -> Vec<u8> {
        if self.n > 0 {
            self.put(8 - self.n, 0);
        }
        self.out
    }
}

fn crc32_mpeg2(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc ^= (b as u32) << 24;
        for _ in 0..8 {
            crc = if crc & 0x8000_0000 != 0 {
                (crc << 1) ^ 0x04C1_1DB7
            } else {
                crc << 1
            };
        }
    }
    !crc
}

/// A one-block stream of the single byte "a" (MTF symbols: RUNA, EOB;
/// alphabet RUNA/RUNB/EOB) with the given code lengths for both tables,
/// `num_selectors` selectors, and the symbols' codes given as bit
/// strings.
fn hand_built_stream(lengths: [u32; 3], num_selectors: u32, codes: &[(u32, u64)]) -> Vec<u8> {
    let crc = crc32_mpeg2(b"a");
    let mut w = Bits::default();
    for &b in b"BZh1" {
        w.put(8, b as u64);
    }
    w.put(48, 0x3141_5926_5359);
    w.put(32, crc as u64);
    w.put(1, 0); // not randomised
    w.put(24, 0); // origin
    w.put(16, 1 << (15 - 6)); // stripe 0x60..0x6F
    w.put(16, 1 << (15 - 1)); // 'a' = 0x61
    w.put(3, 2); // two tables
    w.put(15, num_selectors as u64);
    for _ in 0..num_selectors {
        w.put(1, 0); // table 0
    }
    for _ in 0..2 {
        let mut cur = lengths[0];
        w.put(5, cur as u64);
        for &l in &lengths {
            while cur < l {
                w.put(2, 0b10);
                cur += 1;
            }
            while cur > l {
                w.put(2, 0b11);
                cur -= 1;
            }
            w.put(1, 0);
        }
    }
    for &(n, v) in codes {
        w.put(n, v);
    }
    w.put(48, 0x1772_4538_5090);
    w.put(32, crc as u64);
    w.finish()
}

/// libbzip2 builds its decode tables from any code lengths in 1..=20
/// without checking they form a complete prefix code; only a code that
/// the stream uses has to decode. We used to reject such tables.
#[test]
fn accepts_incomplete_and_oversubscribed_code_tables() {
    let cases = [
        // Incomplete (Kraft sum 3/4): RUNA = 00, RUNB = 01, EOB = 10.
        hand_built_stream([2, 2, 2], 1, &[(2, 0b00), (2, 0b10)]),
        // Over-subscribed: RUNA = 0, EOB = 1, and RUNB (length 2) gets
        // a code that cannot exist.
        hand_built_stream([1, 2, 1], 1, &[(1, 0), (1, 1)]),
        // A complete code, but 20 000 selectors: libbzip2 reads and
        // ignores those past the 18 002 that can ever be used.
        hand_built_stream([1, 2, 2], 20_000, &[(1, 0), (2, 0b11)]),
    ];
    for stream in &cases {
        assert_eq!(decode_chunked(stream, stream.len(), 64).unwrap(), b"a");
        assert_eq!(decode_chunked(stream, 1, 1).unwrap(), b"a");
    }
    // An unused code in an incomplete table is still an error when the
    // stream contains it (11 is nobody's code).
    let bad = hand_built_stream([2, 2, 2], 1, &[(2, 0b00), (2, 0b11)]);
    assert!(decode_chunked(&bad, bad.len(), 64).is_err());

    #[cfg(feature = "std")]
    if std::process::Command::new("bunzip2")
        .arg("--help")
        .output()
        .is_ok()
    {
        use std::io::Write;
        for stream in &cases {
            let mut child = std::process::Command::new("bunzip2")
                .arg("-c")
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            child.stdin.as_mut().unwrap().write_all(stream).unwrap();
            let out = child.wait_with_output().unwrap();
            assert!(out.status.success(), "libbzip2 rejects a case: {:?}", out);
            assert_eq!(out.stdout, b"a");
        }
    }
}

/// `finish` on a truncated stream hands over every decoded byte before
/// reporting `UnexpectedEnd`. The call that drained the last few bytes
/// used to fail instead (its buffer was not full), dropping them.
#[test]
fn finish_hands_over_all_decoded_bytes_before_truncation() {
    let plain = gen_words(250_000);
    let stream = encode_level(&plain, 1);
    // The first block is complete; the second is cut short.
    let cut = &stream[..stream.len() - 200];
    let mut lengths = Vec::new();
    // Buffers smaller than a block: the one `decode` call below fills
    // its buffer and leaves the rest of the first block pending.
    for out_chunk in [1usize, 7, 4096] {
        let mut dec = Decoder::new();
        let mut buf = vec![0u8; out_chunk];
        // One `decode` call, then `finish`, which must drain the first
        // block in full before reporting the truncation.
        let (p, _) = dec.decode(cut, &mut buf).unwrap();
        let mut got = buf[..p.written].to_vec();
        let err = loop {
            match dec.finish(&mut buf) {
                Ok((p, status)) => {
                    assert_ne!(status, Status::StreamEnd);
                    assert!(p.written > 0, "finish stalled");
                    got.extend_from_slice(&buf[..p.written]);
                }
                Err(e) => break e,
            }
        };
        assert_eq!(err, Error::UnexpectedEnd);
        assert!(
            !got.is_empty() && plain.starts_with(&got),
            "out_chunk {out_chunk}"
        );
        lengths.push(got.len());
    }
    // The first block, all of it, for every buffer size.
    assert!(lengths.iter().all(|&l| l == lengths[0]), "{lengths:?}");
    assert_eq!(lengths[0], 99_981);
}
