//! Streaming round-trip + decode-only tests for the Zstd algorithm.
//!
//! Canonical v0.3 port: every call returns `(Progress, Status)` and the
//! loop dispatches on `Status` rather than inferring from byte counts.
//!
//! See `src/zstd/mod.rs` for the supported subset (Raw_Block, RLE_Block, and
//! Compressed_Block on both halves; no Content_Checksum_Flag, no Skippable
//! frames, no Dictionary_ID).

#![cfg(feature = "zstd")]

use compcol::zstd::{Decoder, Encoder, EncoderConfig, Zstd};
use compcol::{Algorithm, Decoder as _, Encoder as _, Error, Flush, Status};

// ─── helpers ─────────────────────────────────────────────────────────────

/// Drive an encoder to completion, feeding `input` in `in_chunk`-sized
/// slices and draining via an `out_chunk`-sized buffer. Returns the
/// fully-encoded byte stream.
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
                    panic!("encoder finish stalled");
                }
            }
        }
    }

    encoded
}

/// Inverse of `encode_chunked`. Accepts any valid streaming chunking on either
/// side.
fn decode_chunked(encoded: &[u8], in_chunk: usize, out_chunk: usize) -> Result<Vec<u8>, Error> {
    let mut dec = Decoder::new();
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

    // The decoder may have produced output it couldn't drain on the last
    // pass (RleEmit / CompressedEmit phases). Keep calling decode with an
    // empty slice until it stops making progress.
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
                    panic!("decoder finish stalled");
                }
            }
        }
    }

    Ok(decoded)
}

fn round_trip(input: &[u8]) {
    let mut enc = Encoder::new();
    let encoded = encode_chunked(&mut enc, input, 4096, 4096);
    let decoded = decode_chunked(&encoded, 4096, 4096).unwrap();
    assert_eq!(
        decoded,
        input,
        "round-trip mismatch (input len {})",
        input.len()
    );
}

// ─── algorithm metadata ─────────────────────────────────────────────────

#[test]
fn name_is_zstd() {
    assert_eq!(<Zstd as Algorithm>::NAME, "zstd");
}

#[test]
fn default_config_is_level_3() {
    assert_eq!(EncoderConfig::default().level, 3);
}

// ─── round-trip tests at the default level ──────────────────────────────

#[test]
fn round_trip_empty() {
    round_trip(b"");
}

#[test]
fn round_trip_single_byte() {
    round_trip(b"x");
}

#[test]
fn round_trip_hello_world() {
    round_trip(b"hello world");
}

#[test]
fn round_trip_medium_pseudo_random() {
    let input: Vec<u8> = (0u32..4096).map(|i| ((i * 31) ^ (i >> 3)) as u8).collect();
    round_trip(&input);
}

#[test]
fn round_trip_64_kib_pseudo_random() {
    let input = lcg_bytes(0x1234_5678, 64 * 1024);
    round_trip(&input);
}

#[test]
fn round_trip_streaming_one_byte() {
    let input: Vec<u8> = (0..512u32).map(|i| (i % 7) as u8).collect();
    let mut enc = Encoder::new();
    let encoded = encode_chunked(&mut enc, &input, 1, 1);
    let decoded = decode_chunked(&encoded, 1, 1).unwrap();
    assert_eq!(decoded, input);
}

/// Build a ≥64 KiB mixed corpus that genuinely separates compression levels.
///
/// The corpus is constructed so that:
///   1. The match finder fires often (lots of recurring 3- and 4-grams),
///      keeping the chain-walking path exercised.
///   2. Long-but-distant matches exist that level 1's tiny chain budget
///      (`max_chain=4`) walks past — only higher levels will find them.
///
/// We pick a short alphabet so 4-byte hashes collide often (driving up chain
/// length) and mix in long repeated phrases at scattered offsets so deep
/// walks have something to find that shallow walks miss.
fn mixed_corpus() -> Vec<u8> {
    let mut state: u32 = 0xC0FFEE_u32;
    let mut out = Vec::with_capacity(80 * 1024);
    // Short alphabet → 4-gram hash buckets fill up fast.
    let alphabet = b"abcdef";
    let phrases: &[&[u8]] = &[
        b"the_quick_brown_fox_jumps_over_the_lazy_dog_xxxxxxxxxxxxxxxxxxxxxxxx",
        b"lorem_ipsum_dolor_sit_amet_consectetur_adipiscing_elit_yyyyyyyyyyyyyy",
        b"compcol_streaming_codec_test_corpus_for_level_differentiation_zzzzz",
    ];
    let mut phrase_idx = 0usize;
    while out.len() < 64 * 1024 {
        for _ in 0..64 {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            out.push(alphabet[(state as usize) % alphabet.len()]);
        }
        out.extend_from_slice(phrases[phrase_idx % phrases.len()]);
        phrase_idx += 1;
    }
    out
}

#[test]
fn round_trip_mixed_corpus_default_level() {
    let input = mixed_corpus();
    assert!(input.len() >= 64 * 1024);
    round_trip(&input);
}

// ─── level-specific tests ───────────────────────────────────────────────

fn encode_at_level(input: &[u8], level: u8) -> Vec<u8> {
    let mut enc = Encoder::with_config(EncoderConfig { level });
    encode_chunked(&mut enc, input, 4096, 4096)
}

#[test]
fn round_trip_level_1() {
    for input in [
        &b""[..],
        b"hello world",
        &b"abcabcabcabcabc".repeat(100)[..],
    ] {
        let mut enc = Encoder::with_config(EncoderConfig { level: 1 });
        let encoded = encode_chunked(&mut enc, input, 4096, 4096);
        let decoded = decode_chunked(&encoded, 4096, 4096).unwrap();
        assert_eq!(decoded, input);
    }
}

#[test]
fn round_trip_level_9() {
    for input in [
        &b""[..],
        b"hello world",
        &b"abcabcabcabcabc".repeat(100)[..],
    ] {
        let mut enc = Encoder::with_config(EncoderConfig { level: 9 });
        let encoded = encode_chunked(&mut enc, input, 4096, 4096);
        let decoded = decode_chunked(&encoded, 4096, 4096).unwrap();
        assert_eq!(decoded, input);
    }
}

#[test]
fn round_trip_level_22() {
    // The top of zstd's range. Our encoder uses a hash-chain matcher rather
    // than zstd's btultra strategy, but it still must produce a valid
    // round-tripping frame.
    for input in [
        &b""[..],
        b"hello world",
        &b"abcabcabcabcabc".repeat(100)[..],
    ] {
        let mut enc = Encoder::with_config(EncoderConfig { level: 22 });
        let encoded = encode_chunked(&mut enc, input, 4096, 4096);
        let decoded = decode_chunked(&encoded, 4096, 4096).unwrap();
        assert_eq!(decoded, input);
    }
}

#[test]
fn level_9_no_worse_than_level_1_on_compressible_corpus() {
    // The whole point of having levels: max-effort must produce output at
    // least as small as min-effort on a realistic corpus.
    let input = mixed_corpus();
    let lo = encode_at_level(&input, 1);
    let hi = encode_at_level(&input, 9);
    assert!(
        hi.len() <= lo.len(),
        "level 9 ({} bytes) was bigger than level 1 ({} bytes)",
        hi.len(),
        lo.len(),
    );
    assert_eq!(decode_chunked(&lo, 4096, 4096).unwrap(), input);
    assert_eq!(decode_chunked(&hi, 4096, 4096).unwrap(), input);
}

#[test]
fn level_1_does_less_work_than_level_9() {
    // Indirect "level 1 is faster than 9" signal: on a corpus designed to
    // defeat low chain budgets, level 1's output must be strictly larger
    // than level 9's. (Direct wall-clock timing is too flaky for CI.)
    let input = mixed_corpus();
    let lo = encode_at_level(&input, 1);
    let hi = encode_at_level(&input, 9);
    assert!(
        lo.len() > hi.len(),
        "level 1 did not produce a measurably larger output: lo={} hi={}",
        lo.len(),
        hi.len(),
    );
    assert_eq!(decode_chunked(&lo, 4096, 4096).unwrap(), input);
    assert_eq!(decode_chunked(&hi, 4096, 4096).unwrap(), input);
}

#[test]
fn out_of_range_level_is_clamped() {
    // Level 0 and level 250 should both produce valid streams (clamped to
    // 1 and 22 respectively) — we don't expose a fallible constructor.
    let input = b"the rain in spain falls mainly on the plain";
    let mut enc_lo = Encoder::with_config(EncoderConfig { level: 0 });
    let enc_lo_out = encode_chunked(&mut enc_lo, input, 4096, 4096);
    assert_eq!(decode_chunked(&enc_lo_out, 4096, 4096).unwrap(), input);
    let mut enc_hi = Encoder::with_config(EncoderConfig { level: 250 });
    let enc_hi_out = encode_chunked(&mut enc_hi, input, 4096, 4096);
    assert_eq!(decode_chunked(&enc_hi_out, 4096, 4096).unwrap(), input);
}

// ─── reset / reuse ──────────────────────────────────────────────────────

#[test]
fn reset_preserves_level_and_allows_reuse() {
    let input_a = b"alpha alpha alpha alpha alpha".as_slice();
    let input_b = b"bravo bravo bravo bravo bravo".as_slice();

    let mut enc = Encoder::with_config(EncoderConfig { level: 9 });
    let encoded_a = encode_chunked(&mut enc, input_a, 4096, 4096);
    enc.reset();
    let encoded_b = encode_chunked(&mut enc, input_b, 4096, 4096);

    assert_eq!(decode_chunked(&encoded_a, 4096, 4096).unwrap(), input_a);
    assert_eq!(decode_chunked(&encoded_b, 4096, 4096).unwrap(), input_b);

    // After reset, an encoder configured at level 9 should still be at
    // level 9. Compare with a fresh level-9 encoder on the same input.
    let mut fresh = Encoder::with_config(EncoderConfig { level: 9 });
    let fresh_b = encode_chunked(&mut fresh, input_b, 4096, 4096);
    assert_eq!(encoded_b, fresh_b, "reset must preserve compression level");
}

#[test]
fn decoder_reset_allows_reuse() {
    let mut enc = Encoder::new();
    let encoded_a = encode_chunked(&mut enc, b"hello", 4096, 4096);
    enc.reset();
    let encoded_b = encode_chunked(&mut enc, b"world", 4096, 4096);

    let mut dec = Decoder::new();
    assert_eq!(decode_chunked_with(&mut dec, &encoded_a).unwrap(), b"hello");
    dec.reset();
    assert_eq!(decode_chunked_with(&mut dec, &encoded_b).unwrap(), b"world");
}

/// Variant of `decode_chunked` that drives the given decoder once with the
/// full input — used by `decoder_reset_allows_reuse` to keep the same
/// decoder across two streams.
fn decode_chunked_with(dec: &mut Decoder, encoded: &[u8]) -> Result<Vec<u8>, Error> {
    let mut decoded = Vec::new();
    let mut buf = vec![0u8; 4096];
    let mut consumed = 0;
    while consumed < encoded.len() {
        let (p, status) = dec.decode(&encoded[consumed..], &mut buf)?;
        decoded.extend_from_slice(&buf[..p.written]);
        consumed += p.consumed;
        match status {
            Status::StreamEnd => break,
            Status::InputEmpty => break,
            Status::OutputFull => continue,
        }
    }
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
        if matches!(status, Status::StreamEnd) {
            break;
        }
        if p.written == 0 {
            panic!("decoder finish stalled");
        }
    }
    Ok(decoded)
}

// ─── decoder: hand-built fixtures ────────────────────────────────────────

/// Construct a minimal valid Zstd frame with a single Last_Block Raw_Block.
fn build_raw_frame(payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&[0x28, 0xB5, 0x2F, 0xFD]); // magic
    f.push(0x00); // FHD: no FCS, SS=0, no checksum, no dict
    f.push(0x50); // WD: Exp=10, Mant=0 → 1 KiB window
    let bh: u32 = 1 | ((payload.len() as u32) << 3);
    f.push((bh & 0xFF) as u8);
    f.push(((bh >> 8) & 0xFF) as u8);
    f.push(((bh >> 16) & 0xFF) as u8);
    f.extend_from_slice(payload);
    f
}

/// Construct a minimal valid Zstd frame with a single Last_Block RLE_Block.
fn build_rle_frame(value: u8, count: u32) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&[0x28, 0xB5, 0x2F, 0xFD]);
    f.push(0x00);
    f.push(0x50);
    let bh: u32 = 1 | (1u32 << 1) | (count << 3);
    f.push((bh & 0xFF) as u8);
    f.push(((bh >> 8) & 0xFF) as u8);
    f.push(((bh >> 16) & 0xFF) as u8);
    f.push(value);
    f
}

#[test]
fn decode_hand_built_raw_block() {
    let frame = build_raw_frame(b"hello world");
    let decoded = decode_chunked(&frame, 1024, 1024).unwrap();
    assert_eq!(decoded, b"hello world");
}

#[test]
fn decode_hand_built_rle_block() {
    let frame = build_rle_frame(b'x', 17);
    let decoded = decode_chunked(&frame, 1024, 1024).unwrap();
    assert_eq!(decoded, vec![b'x'; 17]);
}

#[test]
fn decode_hand_built_rle_block_streaming_output() {
    // RLE expansion drives the output buffer; verify it streams correctly
    // when the output is much smaller than the run length.
    let frame = build_rle_frame(b'q', 500);
    let decoded = decode_chunked(&frame, 1024, 32).unwrap();
    assert_eq!(decoded, vec![b'q'; 500]);
}

#[test]
fn decode_rejects_bad_magic() {
    let mut bad = build_raw_frame(b"x");
    bad[0] = 0; // corrupt magic
    let mut dec = Decoder::new();
    let mut out = [0u8; 16];
    let err = dec.decode(&bad, &mut out).unwrap_err();
    assert_eq!(err, Error::BadHeader);
}

/// A minimal valid frame carrying `Content_Checksum_Flag`: magic, FHD with the
/// checksum bit set, a Window_Descriptor, one Last Raw_Block of `payload`, then
/// the 4-byte trailer (caller supplies it so tests can corrupt it).
fn checksummed_raw_frame(payload: &[u8], trailer: [u8; 4]) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&[0x28, 0xB5, 0x2F, 0xFD]);
    f.push(0x04); // FHD: Content_Checksum_Flag = 1, SS = 0, no dict, no FCS
    f.push(0x00); // Window_Descriptor (minimal)
    // Block_Header: Last_Block = 1, Block_Type = 0 (Raw), Block_Size = len.
    let bh: u32 = 1 | ((payload.len() as u32) << 3);
    f.push((bh & 0xFF) as u8);
    f.push(((bh >> 8) & 0xFF) as u8);
    f.push(((bh >> 16) & 0xFF) as u8);
    f.extend_from_slice(payload);
    f.extend_from_slice(&trailer);
    f
}

#[test]
fn decode_validates_correct_checksum() {
    // Trailer = low 32 bits of XXH64("hello", seed 0), little-endian.
    let frame = checksummed_raw_frame(b"hello", [0xA3, 0x6D, 0x9F, 0x88]);
    let mut dec = Decoder::new();
    let mut out = [0u8; 16];
    let (p, _st) = dec.decode(&frame, &mut out).unwrap();
    let (pf, _stf) = dec.finish(&mut out[p.written..]).unwrap();
    assert_eq!(&out[..p.written + pf.written], b"hello");
}

#[test]
fn decode_rejects_bad_checksum() {
    // Same frame with the trailer corrupted: must be rejected, not ignored.
    let frame = checksummed_raw_frame(b"hello", [0xA3, 0x6D, 0x9F, 0x00]);
    let mut dec = Decoder::new();
    let mut out = [0u8; 16];
    // The mismatch surfaces once the trailer is read (here, in one shot).
    let err = dec
        .decode(&frame, &mut out)
        .and_then(|p| dec.finish(&mut out[p.0.written..]))
        .unwrap_err();
    assert_eq!(err, Error::ChecksumMismatch);
}

#[test]
fn decode_rejects_reserved_fhd_bit() {
    // FHD bit 3 (Reserved) must be zero.
    let mut f = Vec::new();
    f.extend_from_slice(&[0x28, 0xB5, 0x2F, 0xFD]);
    f.push(0x08); // FHD: Reserved bit set
    let mut dec = Decoder::new();
    let mut out = [0u8; 16];
    let err = dec.decode(&f, &mut out).unwrap_err();
    assert_eq!(err, Error::Corrupt);
}

#[test]
fn decode_rejects_reserved_block_type() {
    // Block_Type field of 3 (Reserved). Decoder should bail at block-header parse.
    let mut f = Vec::new();
    f.extend_from_slice(&[0x28, 0xB5, 0x2F, 0xFD]);
    f.push(0x00); // FHD
    f.push(0x50); // WD
    let bh: u32 = 1 | (3u32 << 1); // Last=1, Type=3 (reserved), Size=0
    f.push((bh & 0xFF) as u8);
    f.push(((bh >> 8) & 0xFF) as u8);
    f.push(((bh >> 16) & 0xFF) as u8);
    let mut dec = Decoder::new();
    let mut out = [0u8; 16];
    let err = dec.decode(&f, &mut out).unwrap_err();
    assert_eq!(err, Error::Corrupt);
}

#[test]
fn decode_truncated_frame_unexpected_end() {
    // Magic + FHD only, then nothing — decoder should return UnexpectedEnd
    // when the caller signals end-of-input via `finish`.
    let f = vec![0x28, 0xB5, 0x2F, 0xFD, 0x00];
    let mut dec = Decoder::new();
    let mut out = [0u8; 16];
    let (p, status) = dec.decode(&f, &mut out).unwrap();
    assert_eq!(p.consumed, 5);
    assert_eq!(p.written, 0);
    assert!(matches!(status, Status::InputEmpty));
    let err = dec.finish(&mut out).unwrap_err();
    assert_eq!(err, Error::UnexpectedEnd);
}

#[test]
fn decode_known_good_zstd_fixture_no_checksum_raw_block() {
    // Captured from `printf hello | zstd --no-check -c`:
    //   28 B5 2F FD 00 58 29 00 00 68 65 6C 6C 6F
    let fixture: &[u8] = &[
        0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x58, 0x29, 0x00, 0x00, 0x68, 0x65, 0x6C, 0x6C, 0x6F,
    ];
    let decoded = decode_chunked(fixture, 1024, 1024).unwrap();
    assert_eq!(decoded, b"hello");
}

// ─── encoder: frame shape sanity ─────────────────────────────────────────

#[test]
fn encoder_emits_valid_frame_header() {
    let mut enc = Encoder::new();
    let encoded = encode_chunked(&mut enc, b"x", 16, 16);
    // First 4 bytes are the magic.
    assert_eq!(&encoded[..4], &[0x28, 0xB5, 0x2F, 0xFD]);
    // Single-block frame: FHD = Single_Segment_Flag, FCS_Flag 0 (1-byte FCS).
    assert_eq!(encoded[4], 0x20);
    // Frame_Content_Size = 1.
    assert_eq!(encoded[5], 0x01);
    // Block_Header bytes 6..9 should encode Last=1, Type=0 (Raw), Size=1.
    let bh = (encoded[6] as u32) | ((encoded[7] as u32) << 8) | ((encoded[8] as u32) << 16);
    let last = bh & 1;
    let btype = (bh >> 1) & 0b11;
    let bsize = (bh >> 3) & 0x1F_FFFF;
    assert_eq!(last, 1);
    assert_eq!(btype, 0);
    assert_eq!(bsize, 1);
    assert_eq!(encoded[9], b'x');
    assert_eq!(encoded.len(), 10);
}

#[test]
fn empty_encode_emits_empty_last_block() {
    let mut enc = Encoder::new();
    let encoded = encode_chunked(&mut enc, &[], 16, 16);
    assert_eq!(&encoded[..4], &[0x28, 0xB5, 0x2F, 0xFD]);
    // Single_Segment, 1-byte Frame_Content_Size = 0.
    assert_eq!(encoded[4], 0x20);
    assert_eq!(encoded[5], 0x00);
    // 3-byte block header: Last=1, Type=0, Size=0 → 01 00 00.
    assert_eq!(&encoded[6..9], &[0x01, 0x00, 0x00]);
    assert_eq!(encoded.len(), 9);
}

#[test]
fn encoder_rle_block_for_long_run() {
    // 5000 identical bytes — the encoder picks RLE_Block.
    let mut enc = Encoder::new();
    let input = vec![b'a'; 5000];
    let encoded = encode_chunked(&mut enc, &input, 4096, 4096);
    // Frame: magic(4) + FHD(1) + FCS(2) + BH(3) + payload(1).
    assert_eq!(encoded.len(), 11);
    // Single_Segment + 2-byte Frame_Content_Size (stored as size - 256).
    assert_eq!(encoded[4], 0x60);
    assert_eq!(
        u16::from_le_bytes([encoded[5], encoded[6]]) as usize + 256,
        input.len()
    );
    let bh = (encoded[7] as u32) | ((encoded[8] as u32) << 8) | ((encoded[9] as u32) << 16);
    let btype = (bh >> 1) & 0b11;
    let bsize = (bh >> 3) & 0x1F_FFFF;
    assert_eq!(btype, 1, "expected RLE_Block");
    assert_eq!(bsize, input.len() as u32);
    assert_eq!(encoded[10], b'a');
    // Round-trips back through our decoder.
    let decoded = decode_chunked(&encoded, 1024, 1024).unwrap();
    assert_eq!(decoded, input);
}

#[test]
fn encoder_compressed_block_round_trip() {
    // 4 KiB of repeated text — the encoder should pick a Compressed_Block.
    let snippet = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. ";
    let mut input = Vec::with_capacity(4096);
    while input.len() < 4096 {
        input.extend_from_slice(snippet);
    }
    input.truncate(4096);

    let mut enc = Encoder::new();
    let encoded = encode_chunked(&mut enc, &input, 4096, 4096);
    // Sanity: should compress.
    assert!(
        encoded.len() < input.len(),
        "encoder produced larger output than input: {} -> {}",
        input.len(),
        encoded.len()
    );
    // magic(4) + FHD(1) + 2-byte FCS, then the block header.
    let bh = (encoded[7] as u32) | ((encoded[8] as u32) << 8) | ((encoded[9] as u32) << 16);
    let btype = (bh >> 1) & 0b11;
    assert_eq!(btype, 2, "expected Compressed_Block for repeated text");

    let decoded = decode_chunked(&encoded, 4096, 4096).unwrap();
    assert_eq!(decoded, input);
}

// ─── algorithm-trait entry points ───────────────────────────────────────

#[test]
fn algorithm_encoder_decoder_round_trip() {
    let mut enc = <Zstd as Algorithm>::encoder();
    let mut dec = <Zstd as Algorithm>::decoder();
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

#[test]
fn algorithm_encoder_with_uses_config() {
    let input = mixed_corpus();
    let mut enc_lo = <Zstd as Algorithm>::encoder_with(EncoderConfig { level: 1 });
    let mut enc_hi = <Zstd as Algorithm>::encoder_with(EncoderConfig { level: 9 });
    let lo = encode_chunked(&mut enc_lo, &input, 4096, 4096);
    let hi = encode_chunked(&mut enc_hi, &input, 4096, 4096);
    assert!(
        hi.len() <= lo.len(),
        "encoder_with(level=9) was bigger than encoder_with(level=1): {} > {}",
        hi.len(),
        lo.len(),
    );
    assert_eq!(decode_chunked(&lo, 4096, 4096).unwrap(), input);
    assert_eq!(decode_chunked(&hi, 4096, 4096).unwrap(), input);
}

// ─── pseudo-random helper ────────────────────────────────────────────────

fn lcg_bytes(seed: u32, len: usize) -> Vec<u8> {
    let mut state = seed;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        out.push((state >> 16) as u8);
    }
    out
}

// ─── factory lookup ─────────────────────────────────────────────────────

#[cfg(feature = "factory")]
mod factory {
    use compcol::Status;
    use compcol::factory;

    #[test]
    fn lookup_known() {
        assert!(factory::encoder_by_name("zstd").is_some());
        assert!(factory::decoder_by_name("zstd").is_some());
    }

    #[test]
    fn names_contains_zstd() {
        assert!(factory::names().contains(&"zstd"));
    }

    #[test]
    fn boxed_round_trip() {
        let mut enc = factory::encoder_by_name("zstd").unwrap();
        let mut dec = factory::decoder_by_name("zstd").unwrap();
        let input = b"hello hello hello world world world!";

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

// ─── reference-tool fixtures: Huffman implicit last weight ──────────────
//
// Generated with the reference `zstd` CLI as a black box (frames carry
// Frame_Content_Size and a Content_Checksum):
//
//   python3 -c "import random; r=random.Random(12345); \
//     open('ab.raw','wb').write(bytes(r.choice(b'ab') for _ in range(4000)))"
//   zstd -19 ab.raw -o ab_19.zst
//   python3 -c "import random; r=random.Random(99); \
//     open('dlast.raw','wb').write(bytes(r.choices(b'abcd',weights=[4,2,2,8])[0] \
//     for _ in range(6000)))"
//   zstd -19 dlast.raw -o dlast_19.zst
//
// Both use Huffman-coded literals whose explicitly listed weights sum
// (Σ 2^(W-1)) to an exact power of two. RFC 8878 §4.2.1.3: the last present
// symbol always has a non-zero weight, obtained by completing the sum to the
// *next* power of two — so Max_Number_of_Bits is one more than log2(sum). The
// decoder used to treat such a sum as an already-complete tree, dropping the
// last symbol: `ab_19` failed with `Corrupt`, `dlast_19` decoded to wrong
// bytes caught only by the content checksum. Real-world frames from
// `zstd -15..-22` hit this regularly.

static AB_RAW: &[u8] = include_bytes!("fixtures/zstd/ab.raw");
static AB_19: &[u8] = include_bytes!("fixtures/zstd/ab_19.zst");
static DLAST_RAW: &[u8] = include_bytes!("fixtures/zstd/dlast.raw");
static DLAST_19: &[u8] = include_bytes!("fixtures/zstd/dlast_19.zst");

#[test]
fn reference_two_symbol_huffman_literals() {
    // Two literal symbols → a single explicit weight of 1 (sum = 1 = 2^0).
    assert_eq!(decode_chunked(AB_19, 4096, 4096).unwrap(), AB_RAW);
    assert_eq!(decode_chunked(AB_19, 1, 7).unwrap(), AB_RAW);
    assert_eq!(
        compcol::vec::decompress_to_vec::<Zstd>(AB_19).unwrap(),
        AB_RAW
    );
}

#[test]
fn reference_power_of_two_weight_sum_last_symbol_most_frequent() {
    // Weights a=2, b=1, c=1 (sum 4) — the implicit last symbol `d` takes the
    // other half of the 8-leaf tree (a 1-bit code).
    assert_eq!(decode_chunked(DLAST_19, 4096, 4096).unwrap(), DLAST_RAW);
    assert_eq!(
        compcol::vec::decompress_to_vec::<Zstd>(DLAST_19).unwrap(),
        DLAST_RAW
    );
}

// ─── window handling ────────────────────────────────────────────────────

/// Deterministic word salad; `tests/fixtures/gen_words.py` produces the same
/// bytes for the fixtures below.
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

/// `python3 tests/fixtures/gen_words.py 300000 > w.raw;
///  zstd -19 --zstd=wlog=10 w.raw -o words300k_wlog10.zst` — a 1 KiB window
/// (Window_Descriptor 0x00) over 300 KB of output, so the decoder must slide
/// its retained history many times while back-references stay valid.
static WORDS300K_WLOG10: &[u8] = include_bytes!("fixtures/zstd/words300k_wlog10.zst");

#[test]
fn reference_small_window_long_stream() {
    let expected = gen_words(300_000);
    assert_eq!(
        decode_chunked(WORDS300K_WLOG10, 4096, 4096).unwrap(),
        expected
    );
    assert_eq!(
        compcol::vec::decompress_to_vec::<Zstd>(WORDS300K_WLOG10).unwrap(),
        expected
    );
    // A 1 KiB window is within even the tightest configurable limit.
    let mut dec = Decoder::with_config(compcol::zstd::DecoderConfig {
        max_window_size: 1024,
    });
    assert_eq!(
        decode_chunked_with(&mut dec, WORDS300K_WLOG10).unwrap(),
        expected
    );
}

/// Frame header with the given Window_Descriptor, then one empty last
/// Raw_Block.
fn frame_with_window_descriptor(wd: u8) -> Vec<u8> {
    vec![0x28, 0xB5, 0x2F, 0xFD, 0x00, wd, 0x01, 0x00, 0x00]
}

#[test]
fn window_size_limit_is_enforced_and_configurable() {
    use compcol::zstd::{DEFAULT_MAX_WINDOW_SIZE, DecoderConfig, RECOMMENDED_WINDOW_SIZE};
    assert_eq!(DEFAULT_MAX_WINDOW_SIZE, 128 << 20);
    assert_eq!(RECOMMENDED_WINDOW_SIZE, 8 << 20);

    // Exponent 17 → 128 MiB: accepted by default.
    let w128m = frame_with_window_descriptor(17 << 3);
    assert_eq!(decode_chunked(&w128m, 64, 64).unwrap(), b"");
    // 128 MiB + 1/8 (Mantissa 1): over the default cap.
    let over = frame_with_window_descriptor((17 << 3) | 1);
    assert_eq!(decode_chunked(&over, 64, 64), Err(Error::Unsupported));
    // Largest expressible window (3.75 TB): rejected, no overflow / alloc.
    let huge = frame_with_window_descriptor(0xFF);
    assert_eq!(decode_chunked(&huge, 64, 64), Err(Error::Unsupported));

    // A tighter limit (the RFC 8878 recommended 8 MiB) rejects 16 MiB...
    let cfg = DecoderConfig {
        max_window_size: RECOMMENDED_WINDOW_SIZE,
    };
    let w16m = frame_with_window_descriptor(14 << 3);
    let mut dec = Decoder::with_config(cfg);
    assert_eq!(
        decode_chunked_with(&mut dec, &w16m),
        Err(Error::Unsupported)
    );
    // ...and the limit survives `reset`.
    dec.reset();
    assert_eq!(
        decode_chunked_with(&mut dec, &w16m),
        Err(Error::Unsupported)
    );
    let w8m = frame_with_window_descriptor(13 << 3);
    dec.reset();
    assert_eq!(decode_chunked_with(&mut dec, &w8m).unwrap(), b"");

    // Single-segment frames: Window_Size = Frame_Content_Size, same cap.
    // FHD 0xE0 = FCS_Flag 3 (8 bytes) + Single_Segment.
    let mut ss = vec![0x28, 0xB5, 0x2F, 0xFD, 0xE0];
    ss.extend_from_slice(&(RECOMMENDED_WINDOW_SIZE + 1).to_le_bytes());
    ss.extend_from_slice(&[0x01, 0x00, 0x00]);
    let mut dec = Decoder::with_config(cfg);
    assert_eq!(decode_chunked_with(&mut dec, &ss), Err(Error::Unsupported));
}

/// Hand-assembled frame: Window_Descriptor `wd`, two 1000-byte Raw_Blocks,
/// then a last Compressed_Block holding one sequence (no literals,
/// match_length 3, offset 1621) coded with RLE_Mode tables:
///
/// - literals: `00` (Raw_Literals_Block, Regenerated_Size 0)
/// - sequences: count `01`, modes `54` (LL/OF/ML all RLE_Mode), RLE symbols
///   LL=0, OF=10, ML=0
/// - bitstream `58 06`: start marker + the 10 offset extra bits (600), so
///   Offset_Value = (1 << 10) + 600 = 1624 → offset 1621.
fn far_offset_frame(wd: u8) -> Vec<u8> {
    let mut f = vec![0x28, 0xB5, 0x2F, 0xFD, 0x00, wd];
    for _ in 0..2 {
        let bh: u32 = 1000 << 3; // Raw_Block, not last
        f.extend_from_slice(&bh.to_le_bytes()[..3]);
        f.extend((0..1000u32).map(|i| (i % 251) as u8));
    }
    let body = [0x00, 0x01, 0x54, 0x00, 0x0A, 0x00, 0x58, 0x06];
    let bh: u32 = ((body.len() as u32) << 3) | (2 << 1) | 1;
    f.extend_from_slice(&bh.to_le_bytes()[..3]);
    f.extend_from_slice(&body);
    f
}

#[test]
fn offset_beyond_window_is_rejected() {
    // 2 KiB window (Exponent 1): offset 1621 is legal.
    let ok = decode_chunked(&far_offset_frame(1 << 3), 4096, 4096).unwrap();
    assert_eq!(ok.len(), 2003);
    assert_eq!(&ok[2000..], &[128, 129, 130]);
    // 1 KiB window: RFC 8878 §3.1.1.4 forbids reaching back 1621 bytes, even
    // though that much output exists.
    assert_eq!(
        decode_chunked(&far_offset_frame(0x00), 4096, 4096),
        Err(Error::Corrupt)
    );
}

// ─── encoder: Frame_Content_Size ────────────────────────────────────────

#[test]
fn encoder_writes_frame_content_size_for_single_block_inputs() {
    for n in [0usize, 1, 255, 256, 257, 65_791, 65_792, 100_000, 131_071] {
        let input = gen_words(n);
        let encoded = compcol::vec::compress_to_vec::<Zstd>(&input).unwrap();
        let fhd = encoded[4];
        assert_eq!(fhd & 0x20, 0x20, "n={n}: Single_Segment_Flag");
        let fcs = match fhd >> 6 {
            0 => encoded[5] as u64,
            1 => u16::from_le_bytes([encoded[5], encoded[6]]) as u64 + 256,
            2 => u32::from_le_bytes(encoded[5..9].try_into().unwrap()) as u64,
            _ => u64::from_le_bytes(encoded[5..13].try_into().unwrap()),
        };
        assert_eq!(fcs, n as u64, "n={n}");
        assert_eq!(
            compcol::vec::decompress_to_vec::<Zstd>(&encoded).unwrap(),
            input
        );
    }
    // Multi-block inputs: size unknown when the first block is emitted, so
    // the encoder keeps the windowed header (no FCS).
    let input = gen_words(300_000);
    let encoded = compcol::vec::compress_to_vec::<Zstd>(&input).unwrap();
    assert_eq!(&encoded[4..6], &[0x00, 0x70]);
    assert_eq!(
        compcol::vec::decompress_to_vec::<Zstd>(&encoded).unwrap(),
        input
    );
}

/// Skippable_Frame magics (`0x184D2A50..=0x184D2A5F`, little-endian on the
/// wire) are reported as `Unsupported`, not as a bad header.
#[test]
fn skippable_frame_magic_is_unsupported() {
    for lo in 0x50u8..=0x5F {
        let frame = [lo, 0x2A, 0x4D, 0x18, 0, 0, 0, 0];
        let mut dec = Zstd::decoder();
        let mut out = [0u8; 16];
        assert_eq!(
            dec.decode(&frame, &mut out).unwrap_err(),
            Error::Unsupported,
            "magic low byte {lo:#x}"
        );
    }
}

// ─── flush ──────────────────────────────────────────────────────────────

/// Feed all of `input` through `enc.encode`, draining via `out_chunk`-byte
/// buffers, and append what it emits to `wire`.
fn flush_test_encode(enc: &mut Encoder, input: &[u8], out_chunk: usize, wire: &mut Vec<u8>) {
    let mut buf = vec![0u8; out_chunk];
    let mut consumed = 0;
    loop {
        let (p, status) = enc.encode(&input[consumed..], &mut buf).unwrap();
        wire.extend_from_slice(&buf[..p.written]);
        consumed += p.consumed;
        match status {
            Status::InputEmpty if consumed == input.len() => break,
            Status::InputEmpty | Status::OutputFull => {}
            Status::StreamEnd => panic!("encode returned StreamEnd"),
        }
    }
}

/// Drive `enc.flush(mode)` until it reports `InputEmpty`, re-calling on
/// `OutputFull` as the trait requires.
fn flush_test_flush(enc: &mut Encoder, mode: Flush, out_chunk: usize, wire: &mut Vec<u8>) {
    let mut buf = vec![0u8; out_chunk];
    for _ in 0..10_000_000 {
        let (p, status) = enc.flush(&mut buf, mode).unwrap();
        wire.extend_from_slice(&buf[..p.written]);
        match status {
            Status::InputEmpty => return,
            Status::OutputFull => {}
            Status::StreamEnd => panic!("flush returned StreamEnd"),
        }
    }
    panic!("flush never completed");
}

fn flush_test_finish(enc: &mut Encoder, out_chunk: usize, wire: &mut Vec<u8>) {
    let mut buf = vec![0u8; out_chunk];
    loop {
        let (p, status) = enc.finish(&mut buf).unwrap();
        wire.extend_from_slice(&buf[..p.written]);
        if status == Status::StreamEnd {
            return;
        }
    }
}

/// Decode a stream cut short at a flush point: `decode` only, never
/// `finish` (the stream is deliberately unterminated).
fn decode_prefix(wire: &[u8]) -> Vec<u8> {
    let mut dec = Decoder::new();
    let mut out = Vec::new();
    let mut buf = vec![0u8; 1 << 16];
    let mut consumed = 0;
    loop {
        let (p, _) = dec.decode(&wire[consumed..], &mut buf).unwrap();
        out.extend_from_slice(&buf[..p.written]);
        consumed += p.consumed;
        if p.consumed == 0 && p.written == 0 {
            return out;
        }
    }
}

/// Encode `flush_segments()` with a `mode` flush after each, checking after
/// every flush that the bytes emitted so far decode to everything given so
/// far. Returns the finished stream and the concatenated input.
fn flush_after_each_segment(mode: Flush, out_chunk: usize) -> (Vec<u8>, Vec<u8>) {
    let mut enc = Encoder::new();
    let mut wire = Vec::new();
    let mut given = Vec::new();
    for seg in flush_segments() {
        flush_test_encode(&mut enc, &seg, out_chunk, &mut wire);
        given.extend_from_slice(&seg);
        flush_test_flush(&mut enc, mode, out_chunk, &mut wire);
        let got = decode_prefix(&wire);
        assert!(
            got == given,
            "{mode:?} flush after {} bytes: decoded {} bytes from the prefix",
            given.len(),
            got.len()
        );
        // A second flush with nothing new pending emits nothing.
        let before = wire.len();
        flush_test_flush(&mut enc, mode, out_chunk, &mut wire);
        assert_eq!(wire.len(), before, "empty {mode:?} flush emitted bytes");
    }
    flush_test_finish(&mut enc, out_chunk, &mut wire);
    assert_eq!(decode_chunked(&wire, 4096, 4096).unwrap(), given);
    (wire, given)
}

#[test]
fn sync_flush_makes_everything_given_decodable() {
    flush_after_each_segment(Flush::Sync, 4096);
}

#[test]
fn full_flush_makes_everything_given_decodable() {
    flush_after_each_segment(Flush::Full, 4096);
}

#[test]
fn flush_with_one_byte_output_buffer() {
    flush_after_each_segment(Flush::Sync, 1);
    flush_after_each_segment(Flush::Full, 1);
}

/// After a `Sync` flush, repeated data back-references the pre-flush bytes
/// and costs almost nothing; after a `Full` flush it must be encoded from
/// scratch.
#[test]
fn full_flush_drops_history_sync_keeps_it() {
    let text = flush_text(20_000);
    let tail_size = |mode: Flush| {
        let mut enc = Encoder::new();
        let mut wire = Vec::new();
        flush_test_encode(&mut enc, &text, 4096, &mut wire);
        flush_test_flush(&mut enc, mode, 4096, &mut wire);
        let mark = wire.len();
        flush_test_encode(&mut enc, &text, 4096, &mut wire);
        flush_test_flush(&mut enc, Flush::Sync, 4096, &mut wire);
        let tail = wire.len() - mark;
        flush_test_finish(&mut enc, 4096, &mut wire);
        let mut expect = text.clone();
        expect.extend_from_slice(&text);
        assert_eq!(decode_chunked(&wire, 4096, 4096).unwrap(), expect);
        tail
    };
    let sync_tail = tail_size(Flush::Sync);
    let full_tail = tail_size(Flush::Full);
    assert!(sync_tail < 100, "sync tail {sync_tail} bytes");
    assert!(
        full_tail > 10 * sync_tail,
        "full tail {full_tail} bytes vs sync tail {sync_tail}"
    );
}

/// The bytes emitted up to each flush point, closed off with an empty
/// `Last_Block` (`01 00 00`), form a complete frame that `zstd -d` decodes
/// to everything given before that flush; the finished stream decodes
/// cleanly.
///
/// The cut stream is terminated rather than fed to `zstd -dc` as-is because
/// the CLI's error path on a truncated frame drops up to one 128 KiB output
/// buffer of already-decoded data. It does that for streams `zstd` itself
/// wrote too, so it would test the CLI rather than the flush.
fn check_flushes_with_system_tool(cmd: &str, mode: Flush) {
    let mut enc = Encoder::new();
    let mut wire = Vec::new();
    let mut given = Vec::new();
    for seg in flush_segments() {
        flush_test_encode(&mut enc, &seg, 4096, &mut wire);
        given.extend_from_slice(&seg);
        flush_test_flush(&mut enc, mode, 4096, &mut wire);
        let mut cut = wire.clone();
        cut.extend_from_slice(&[0x01, 0x00, 0x00]);
        let out = run_tool(cmd, &["-d", "-c"], &cut);
        assert!(
            out.status.success() && out.stdout == given,
            "{cmd} -d on a stream cut at a {mode:?} flush after {} bytes wrote {} bytes",
            given.len(),
            out.stdout.len()
        );
    }
    flush_test_finish(&mut enc, 4096, &mut wire);
    let out = run_tool(cmd, &["-d", "-c"], &wire);
    assert!(
        out.status.success(),
        "{cmd} -d rejected the {mode:?}-flushed stream"
    );
    assert!(
        out.stdout == given,
        "{cmd} -d decoded the {mode:?}-flushed stream wrong"
    );
}

/// Run `cmd args` with `stdin_data` on stdin; returns its output whatever
/// the exit status.
fn run_tool(cmd: &str, args: &[&str], stdin_data: &[u8]) -> std::process::Output {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let mut child = Command::new(cmd)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let data = stdin_data.to_vec();
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(&data);
    });
    let out = child.wait_with_output().unwrap();
    let _ = writer.join();
    out
}

/// Segments fed between flushes: tiny, compressible, incompressible, and
/// one larger than a 128 KiB block so a flush lands mid-way through the
/// second block.
fn flush_segments() -> Vec<Vec<u8>> {
    vec![
        b"x".to_vec(),
        gen_words(100),
        gen_words(5_000),
        lcg_bytes(7, 3_000),
        gen_words(200_000),
        b"tail".to_vec(),
        gen_words(70_000),
    ]
}

/// Incompressible on its own, so a second copy is cheap only when it can
/// back-reference the first.
fn flush_text(n: usize) -> Vec<u8> {
    lcg_bytes(11, n)
}

/// A flush on a frame shorter than one block must not produce a
/// known-size Single_Segment header: more data follows the flushed block.
#[test]
fn flushed_frame_uses_windowed_header() {
    let mut enc = Encoder::new();
    let mut wire = Vec::new();
    flush_test_encode(&mut enc, b"hello", 64, &mut wire);
    flush_test_flush(&mut enc, Flush::Sync, 64, &mut wire);
    assert_eq!(&wire[4..6], &[0x00, 0x70]);
    flush_test_encode(&mut enc, b" world", 64, &mut wire);
    flush_test_finish(&mut enc, 64, &mut wire);
    assert_eq!(decode_chunked(&wire, 4096, 4096).unwrap(), b"hello world");
}

#[test]
fn flushes_interoperate_with_system_zstd() {
    let available = std::process::Command::new("zstd")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success());
    if !available {
        println!("skipping: zstd not installed");
        return;
    }
    check_flushes_with_system_tool("zstd", Flush::Sync);
    check_flushes_with_system_tool("zstd", Flush::Full);
}
