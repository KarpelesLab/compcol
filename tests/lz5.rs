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

// ─── content checksum ──────────────────────────────────────────────────

/// Header of a frame with the content-checksum flag set (FLG = 0x64,
/// BD = 0x10). The header checksum byte is found by asking the decoder,
/// which rejects every wrong value.
fn checksummed_frame_header() -> Vec<u8> {
    let mut header = vec![0x06, 0x22, 0x4d, 0x18, 0x64, 0x10, 0x00];
    for hc in 0..=255u8 {
        header[6] = hc;
        let mut dec = Decoder::new();
        if dec.decode(&header, &mut [0u8; 16]).is_ok() {
            return header;
        }
    }
    panic!("no header checksum accepted");
}

/// `header ‖ one uncompressed block per chunk ‖ EndMark ‖ checksum`.
fn checksummed_frame(blocks: &[&[u8]], checksum: u32) -> Vec<u8> {
    let mut frame = checksummed_frame_header();
    for block in blocks {
        frame.extend_from_slice(&(block.len() as u32 | 0x8000_0000).to_le_bytes());
        frame.extend_from_slice(block);
    }
    frame.extend_from_slice(&[0, 0, 0, 0]);
    frame.extend_from_slice(&checksum.to_le_bytes());
    frame
}

/// XXH32("hello", seed 0) — the frame format's content checksum.
const XXH32_HELLO: u32 = 0xFB00_77F9;
/// XXH32("hello world", seed 0).
const XXH32_HELLO_WORLD: u32 = 0xCEBB_6622;

#[test]
fn content_checksum_verified() {
    let frame = checksummed_frame(&[b"hello"], XXH32_HELLO);
    assert_eq!(decode_chunked(&frame, 1024, 1024).unwrap(), b"hello");
    // The checksum covers the whole content across blocks, and survives
    // the trailer being split across `decode` calls.
    let frame = checksummed_frame(&[b"hello", b" ", b"world"], XXH32_HELLO_WORLD);
    assert_eq!(decode_chunked(&frame, 1024, 1024).unwrap(), b"hello world");
    assert_eq!(decode_chunked(&frame, 1, 1).unwrap(), b"hello world");
}

#[test]
fn content_checksum_mismatch_rejected() {
    // FLG promises a content checksum; the trailer carries a wrong one.
    // This used to decode to "hello" without complaint.
    let frame = checksummed_frame(&[b"hello"], 0xEFBE_ADDE);
    assert_eq!(
        decode_chunked(&frame, 1024, 1024).unwrap_err(),
        Error::ChecksumMismatch
    );
    assert_eq!(
        decode_chunked(&frame, 1, 1).unwrap_err(),
        Error::ChecksumMismatch
    );
    // Right checksum, corrupted payload.
    let mut frame = checksummed_frame(&[b"hello"], XXH32_HELLO);
    let payload_at = frame.len() - 4 - 4 - 5;
    frame[payload_at] ^= 0x20;
    assert_eq!(
        decode_chunked(&frame, 1024, 1024).unwrap_err(),
        Error::ChecksumMismatch
    );
    // A checksum for different content of the same frame shape.
    let frame = checksummed_frame(&[b"hello", b" ", b"world"], XXH32_HELLO);
    assert_eq!(
        decode_chunked(&frame, 1024, 1024).unwrap_err(),
        Error::ChecksumMismatch
    );
}

#[test]
fn content_checksum_trailer_truncated_rejected() {
    let frame = checksummed_frame(&[b"hello"], XXH32_HELLO);
    for cut in 1..=4 {
        let truncated = &frame[..frame.len() - cut];
        assert_eq!(
            decode_chunked(truncated, 1024, 1024).unwrap_err(),
            Error::UnexpectedEnd,
            "cut {cut}"
        );
    }
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
fn truncated_lizv1_block_rejected() {
    // Frame OK; block compressionLevel = 20 (LIZv1), one sub-block flag
    // byte and then nothing: its sub-streams are missing.
    let encoded: &[u8] = &[
        0x06, 0x22, 0x4d, 0x18, 0x60, 0x10, 0x8e, // header
        0x02, 0x00, 0x00, 0x00, // block size = 2 (compressed)
        0x14, 0x00, // clevel=20, sub-block flags=0
    ];
    let err = decode_chunked(encoded, 1024, 1024).unwrap_err();
    assert_eq!(err, Error::UnexpectedEnd);
}

// ─── reference fixtures larger than one 128 KiB sub-block ─────────────

// Generated with Lizard CLI 2.1.0 (inikep/lizard) from `records_input()`:
//
//     lizard -10 <input> records_l10_multi_subblock.liz
//     lizard -15 -B1 -BD <input> records_l15_b1_dependent.liz
//
// Both carry the content checksum the CLI writes by default, so decoding
// them also checks this crate's reading of that field (xxh32, seed 0, of
// the decoded content) against the reference.

/// 300 000 bytes of repetitive records: more than two 128 KiB sub-blocks.
fn records_input() -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0u64;
    while out.len() < 300_000 {
        out.extend_from_slice(
            format!(
                "record {}: the quick brown fox jumps over the lazy dog, batch {}\n",
                i % 37,
                (i * i) % 11
            )
            .as_bytes(),
        );
        i += 1;
    }
    out.truncate(300_000);
    out
}

fn assert_decodes_to_records(encoded: &[u8]) {
    let want = records_input();
    for (in_chunk, out_chunk) in [(encoded.len(), 1 << 20), (1, 4096), (4096, 1), (777, 333)] {
        let got = decode_chunked(encoded, in_chunk, out_chunk).unwrap();
        assert!(got == want, "mismatch with chunks {in_chunk}/{out_chunk}");
    }
}

/// One frame block holding three sub-blocks that share a window. The decoder used to stop after the first sub-block and
/// call the rest of the block corrupt, so no file written with the CLI's
/// default settings and larger than 128 KiB decoded.
#[test]
fn decode_reference_multiple_sub_blocks() {
    let encoded = include_bytes!("fixtures/lz5/records_l10_multi_subblock.liz");
    // FLG: version 01, independent blocks, content checksum.
    assert_eq!(encoded[4], 0x64);
    assert_decodes_to_records(encoded);
}

/// `-BD`: 128 KiB frame blocks whose matches reach back into the blocks
/// before them. The decoder used to treat every block as independent.
#[test]
fn decode_reference_dependent_blocks() {
    let encoded = include_bytes!("fixtures/lz5/records_l15_b1_dependent.liz");
    // FLG: version 01, block-independence bit clear, content checksum.
    assert_eq!(encoded[4], 0x44);
    assert_decodes_to_records(encoded);
}

/// The reference's own checksum trailer is what gets verified: flip one
/// bit of it and the frame fails, after its content has been handed out.
#[test]
fn reference_content_checksum_is_checked() {
    for fixture in [
        &include_bytes!("fixtures/lz5/records_l10_multi_subblock.liz")[..],
        &include_bytes!("fixtures/lz5/records_l15_b1_dependent.liz")[..],
    ] {
        let mut bad = fixture.to_vec();
        *bad.last_mut().unwrap() ^= 0x01;
        assert_eq!(
            decode_chunked(&bad, bad.len(), 1 << 20),
            Err(Error::ChecksumMismatch)
        );
    }
}

/// A match in a dependent block may not reach before the history kept.
#[test]
fn dependent_block_cannot_reach_before_the_frame() {
    // FLG 0x40: version 01, dependent blocks, no checksums. BD 0x10.
    let mut frame = vec![0x06, 0x22, 0x4d, 0x18, 0x40, 0x10];
    let hc = (0..=255u8)
        .find(|&hc| {
            let mut f = frame.clone();
            f.push(hc);
            f.extend_from_slice(&[0, 0, 0, 0]);
            decode_chunked(&f, f.len(), 64).is_ok()
        })
        .expect("some header checksum byte is right");
    frame.push(hc);
    // First block, stored: "abcd". Second block, compressed (level 10):
    // one token, no literals, a 4-byte match at offset 5 — one byte
    // before the start of the frame.
    frame.extend_from_slice(&(4u32 | 0x8000_0000).to_le_bytes());
    frame.extend_from_slice(b"abcd");
    let block = [
        10, 0, // level, sub-block flags
        0, 0, 0, 0, 0, 0, 0, 0, 0, // lengths, offset16, offset24: empty
        1, 0, 0, 0x00, // flags: one token
        2, 0, 0, 5, 0, // literals: the offset
    ];
    frame.extend_from_slice(&(block.len() as u32).to_le_bytes());
    frame.extend_from_slice(&block);
    frame.extend_from_slice(&[0, 0, 0, 0]);
    assert_eq!(
        decode_chunked(&frame, frame.len(), 64),
        Err(Error::InvalidDistance)
    );
    // The same match at offset 4 is the first block again.
    let at = frame.len() - 4 - 2;
    frame[at] = 4;
    assert_eq!(
        decode_chunked(&frame, frame.len(), 64).unwrap(),
        b"abcdabcd"
    );
}

// ─── reference fixtures for LIZv1 codewords and Huffman sub-streams ───

// Generated with Lizard CLI 2.1.0 (inikep/lizard) from `words_input()`:
//
//     lizard -24 <input> words_l24_lizv1.liz
//     lizard -39 <input> words_l39_lz4_huffman.liz
//     lizard -45 -B1 -BD <input> words_l45_b1_dependent.liz

/// 150 000 bytes of skewed pseudo-random words, with the first 20 000
/// bytes repeated 100 000 bytes later: far enough for a 24-bit offset,
/// and skewed enough for the Huffman stage to be worth it.
fn words_input() -> Vec<u8> {
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let mut vocab: Vec<Vec<u8>> = Vec::new();
    for _ in 0..64 {
        let n = 2 + next() % 7;
        vocab.push((0..n).map(|_| b'a' + (next() % 26) as u8).collect());
    }
    let mut out = Vec::new();
    let mut fill = |out: &mut Vec<u8>, target: usize| {
        while out.len() < target {
            let (a, b) = (next() % 64, next() % 64);
            out.extend_from_slice(&vocab[a.min(b) as usize]);
            out.push(b' ');
        }
        out.truncate(target);
    };
    fill(&mut out, 100_000);
    out.extend_from_within(..20_000);
    fill(&mut out, 150_000);
    out
}

fn assert_decodes_to_words(encoded: &[u8], level: u8) {
    // First block: 4-byte size word after the 7-byte header, then the
    // compression level byte.
    assert_eq!(encoded[11], level);
    let want = words_input();
    for (in_chunk, out_chunk) in [(encoded.len(), 1 << 20), (1, 4096), (4096, 1), (777, 333)] {
        let got = decode_chunked(encoded, in_chunk, out_chunk).unwrap();
        assert!(got == want, "mismatch with chunks {in_chunk}/{out_chunk}");
    }
}

/// LIZv1 codewords with every sub-stream stored raw, including a match
/// through the 24-bit offset stream.
#[test]
fn decode_reference_lizv1() {
    let encoded = include_bytes!("fixtures/lz5/words_l24_lizv1.liz");
    assert_eq!(encoded[12], 0x00, "no Huffman-coded sub-stream");
    assert_decodes_to_words(encoded, 24);
}

/// LZ4 codewords with a Huffman-coded sub-stream.
#[test]
fn decode_reference_lz4_codewords_with_huffman() {
    let encoded = include_bytes!("fixtures/lz5/words_l39_lz4_huffman.liz");
    assert_ne!(encoded[12] & 0x1f, 0, "a Huffman-coded sub-stream");
    assert_decodes_to_words(encoded, 39);
}

/// LIZv1 codewords with Huffman-coded sub-streams, in a block-dependent
/// frame of 128 KiB blocks: the far match of the second block reaches
/// 100 000 bytes back into the first.
#[test]
fn decode_reference_lizv1_huffman_dependent() {
    let encoded = include_bytes!("fixtures/lz5/words_l45_b1_dependent.liz");
    assert_eq!(encoded[4] & 0x20, 0, "block-dependent frame");
    assert_ne!(encoded[12] & 0x1f, 0, "a Huffman-coded sub-stream");
    assert_decodes_to_words(encoded, 45);
}

/// Every proper prefix of a reference stream is an error or a short
/// result, never a panic or wrong bytes; and no single corrupted byte
/// makes the decoder panic or hand out wrong bytes as a clean result.
#[test]
fn reference_fixtures_survive_truncation_and_corruption() {
    let want = words_input();
    for fixture in [
        &include_bytes!("fixtures/lz5/words_l24_lizv1.liz")[..],
        &include_bytes!("fixtures/lz5/words_l39_lz4_huffman.liz")[..],
        &include_bytes!("fixtures/lz5/words_l45_b1_dependent.liz")[..],
    ] {
        for cut in (0..fixture.len()).step_by(997) {
            if let Ok(got) = decode_chunked(&fixture[..cut], 4096, 4096) {
                assert!(want.starts_with(&got), "wrong bytes at cut {cut}");
            }
        }
        for at in (7..fixture.len()).step_by(211) {
            let mut bad = fixture.to_vec();
            bad[at] ^= 0x55;
            // The content checksum catches whatever the block decoder lets
            // through, so a corrupted frame that still decodes can only be
            // one whose content came out the same (a match offset moved
            // to another copy of the same bytes).
            if let Ok(got) = decode_chunked(&bad, bad.len(), 1 << 16) {
                assert!(got == want, "wrong bytes accepted with byte {at} corrupted");
            }
        }
    }
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

// ─── output limit ────────────────────────────────────────────────────────

/// A 7-byte frame header for `flg`/`bd`. The header checksum byte is
/// found by asking the decoder, which rejects every wrong value.
fn frame_header(flg: u8, bd: u8) -> Vec<u8> {
    let mut header = vec![0x06, 0x22, 0x4d, 0x18, flg, bd, 0x00];
    for hc in 0..=255u8 {
        header[6] = hc;
        if Decoder::new().decode(&header, &mut [0u8; 16]).is_ok() {
            return header;
        }
    }
    panic!("no header checksum accepted");
}

/// The v0.7.8 audit's bomb: a frame whose one block is 15 maximum-length
/// matches at offset 1, decoding to hundreds of MiB (138 bytes with a
/// BD code 7 header). A frame block is decoded whole before any of it is
/// handed out, so only a decoder that knows the caller's limit can refuse
/// it in time. `bd` is the frame's BD byte.
fn bomb_frame(bd: u8) -> Vec<u8> {
    let mut f = frame_header(0x60, bd);
    f.extend_from_slice(&[0x7b, 0, 0, 0]);
    // Level 10, all five streams raw; lengths/offset16/offset24 empty.
    f.extend_from_slice(&[0x0a, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    // Tokens.
    f.extend_from_slice(&[0x0f, 0, 0, 0xf1]);
    f.extend_from_slice(&[0xf0; 14]);
    // Literals: one byte, then offset 1 and a maximal length, 15 times.
    f.extend_from_slice(&[0x5b, 0, 0, 0x41, 0x01, 0x00, 0xff, 0xff, 0xff, 0xff]);
    for _ in 0..14 {
        f.extend_from_slice(&[0x01, 0x00, 0xff, 0xff, 0xff, 0xff]);
    }
    f.extend_from_slice(&[0, 0, 0, 0]);
    assert_eq!(f.len(), 138);
    f
}

#[test]
fn output_limit_refuses_a_block_bomb_before_decoding_it() {
    let frame = bomb_frame(0x70);
    assert_eq!(frame[6], 0x73);
    let mut buf = vec![0u8; 4096];

    let mut dec = Decoder::new();
    dec.set_output_limit(1024);
    assert_eq!(
        dec.decode(&frame, &mut buf),
        Err(Error::OutputLimitExceeded)
    );

    // The limit is configuration: it survives a reset.
    dec.reset();
    assert_eq!(
        dec.decode(&frame, &mut buf),
        Err(Error::OutputLimitExceeded)
    );
}

#[test]
fn limited_decoder_refuses_a_block_bomb() {
    use compcol::limit::LimitedDecoder;
    use compcol::vec::decompress_to_vec_capped;

    let frame = bomb_frame(0x70);
    let mut dec = LimitedDecoder::new(Decoder::new(), 1024);
    let mut buf = vec![0u8; 4096];
    assert_eq!(
        dec.decode(&frame, &mut buf),
        Err(Error::OutputLimitExceeded)
    );
    assert_eq!(dec.bytes_written(), 0);
    assert_eq!(
        decompress_to_vec_capped::<Lz5>(&frame, 1024),
        Err(Error::OutputLimitExceeded)
    );
}

/// The limit is a bound on the whole frame: exactly the content length
/// decodes, one byte less does not, for compressed blocks (independent
/// and dependent) and for stored ones.
#[test]
fn output_exactly_at_the_limit_decodes() {
    use compcol::vec::decompress_to_vec_capped;

    let records = records_input();
    let stored_input: Vec<u8> = (0..300_000u32).map(|i| (i * 7 + i / 251) as u8).collect();
    let stored = encode_all(&stored_input);
    let cases: [(&[u8], &[u8]); 3] = [
        (
            include_bytes!("fixtures/lz5/records_l10_multi_subblock.liz"),
            &records,
        ),
        (
            include_bytes!("fixtures/lz5/records_l15_b1_dependent.liz"),
            &records,
        ),
        (&stored, &stored_input),
    ];
    for (i, (encoded, want)) in cases.into_iter().enumerate() {
        let n = want.len() as u64;
        for (in_chunk, out_chunk) in [(encoded.len(), 1 << 16), (777, 333)] {
            let mut dec = Decoder::new();
            dec.set_output_limit(n);
            let got = decode_chunked_with(&mut dec, encoded, in_chunk, out_chunk).unwrap();
            assert!(got == want, "case {i}: mismatch at the limit");

            let mut dec = Decoder::new();
            dec.set_output_limit(n - 1);
            assert_eq!(
                decode_chunked_with(&mut dec, encoded, in_chunk, out_chunk),
                Err(Error::OutputLimitExceeded),
                "case {i}"
            );
        }
        assert!(decompress_to_vec_capped::<Lz5>(encoded, n).unwrap() == want);
        assert_eq!(
            decompress_to_vec_capped::<Lz5>(encoded, n - 1),
            Err(Error::OutputLimitExceeded),
            "case {i}"
        );
    }
}

/// A block that outgrows the frame's own block size is still a corrupt
/// frame, not a limit error, unless the limit is what it hit first.
#[test]
fn block_larger_than_the_frame_block_size_is_still_corrupt() {
    // The bomb again, in a 128 KiB-block frame (BD code 1).
    let frame = bomb_frame(0x10);
    let mut buf = vec![0u8; 4096];
    assert_eq!(Decoder::new().decode(&frame, &mut buf), Err(Error::Corrupt));
    let mut dec = Decoder::new();
    dec.set_output_limit(1 << 20);
    assert_eq!(dec.decode(&frame, &mut buf), Err(Error::Corrupt));
    let mut dec = Decoder::new();
    dec.set_output_limit(1024);
    assert_eq!(
        dec.decode(&frame, &mut buf),
        Err(Error::OutputLimitExceeded)
    );
}

// ─── block-size cap ──────────────────────────────────────────────────────

/// The frame header's BD code sets how large a block the decoder will
/// build. A configured cap refuses a larger one when the header is read,
/// before any block data is looked at.
#[test]
fn max_block_size_rejects_larger_frames_at_the_header() {
    use compcol::lz5::{DecoderConfig, MAX_BLOCK_SIZE};

    assert_eq!(DecoderConfig::default().max_block_size, MAX_BLOCK_SIZE);
    assert_eq!(MAX_BLOCK_SIZE, 256 << 20);

    // BD codes 1..=7 and the block size each names.
    let sizes: [usize; 7] = [
        128 << 10,
        256 << 10,
        1 << 20,
        4 << 20,
        16 << 20,
        64 << 20,
        256 << 20,
    ];
    let mut buf = [0u8; 16];
    for (i, &size) in sizes.iter().enumerate() {
        let header = frame_header(0x60, ((i + 1) as u8) << 4);

        // The default accepts every code.
        assert!(Lz5::decoder().decode(&header, &mut buf).is_ok());

        // A cap of exactly the block size accepts it...
        let config = DecoderConfig::default().with_max_block_size(size);
        let mut dec = Lz5::decoder_with(config);
        let (p, _) = dec.decode(&header, &mut buf).unwrap();
        assert_eq!(p.consumed, header.len());

        // ...and one byte less refuses it on the header alone.
        let config = DecoderConfig::default().with_max_block_size(size - 1);
        let mut dec = Decoder::with_config(config);
        assert_eq!(dec.decode(&header, &mut buf), Err(Error::Unsupported));

        // The cap is configuration: it survives a reset.
        dec.reset();
        assert_eq!(dec.decode(&header, &mut buf), Err(Error::Unsupported));
    }
}

#[test]
fn max_block_size_refuses_the_block_bomb_and_keeps_small_frames() {
    use compcol::lz5::DecoderConfig;
    use compcol::vec::decompress_to_vec_capped_with;

    let config = DecoderConfig::default().with_max_block_size(4 << 20);

    // The 256 MiB-block bomb never gets past its header.
    let mut buf = vec![0u8; 4096];
    assert_eq!(
        Decoder::with_config(config).decode(&bomb_frame(0x70), &mut buf),
        Err(Error::Unsupported)
    );

    // Frames within the cap decode as before: the encoder's own 128 KiB
    // blocks and a reference-CLI frame declaring 1 MiB ones.
    let input: Vec<u8> = (0..300_000u32).map(|i| (i * 7 + i / 251) as u8).collect();
    let encoded = encode_all(&input);
    let mut dec = Decoder::with_config(config);
    let got = decode_chunked_with(&mut dec, &encoded, 777, 333).unwrap();
    assert!(got == input);

    let reference = include_bytes!("fixtures/lz5/records_l10_multi_subblock.liz");
    assert_eq!(reference[5] >> 4, 3, "fixture declares 1 MiB blocks");
    let records = records_input();
    assert!(decompress_to_vec_capped_with::<Lz5>(reference, config, 1 << 20).unwrap() == records);
    let tight = DecoderConfig::default().with_max_block_size(256 << 10);
    assert_eq!(
        decompress_to_vec_capped_with::<Lz5>(reference, tight, 1 << 20),
        Err(Error::Unsupported)
    );
}

/// A header that is malformed is still reported as such, whatever the cap.
#[test]
fn max_block_size_does_not_mask_a_bad_header() {
    use compcol::lz5::DecoderConfig;

    let mut header = frame_header(0x60, 0x70);
    header[6] ^= 0x55;
    let config = DecoderConfig::default().with_max_block_size(128 << 10);
    assert_eq!(
        Decoder::with_config(config).decode(&header, &mut [0u8; 16]),
        Err(Error::ChecksumMismatch)
    );
}
