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
use compcol::{Algorithm, Decoder as _, Encoder as _, Error, Status};

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

#[test]
fn decode_rejects_checksum_flag() {
    // Build a frame with Content_Checksum_Flag set (bit 2). We can't actually
    // verify the checksum (no XXH64), so the decoder must refuse.
    let mut f = Vec::new();
    f.extend_from_slice(&[0x28, 0xB5, 0x2F, 0xFD]);
    f.push(0x04); // FHD: Content_Checksum_Flag = 1
    f.push(0x50);
    let mut dec = Decoder::new();
    let mut out = [0u8; 16];
    let err = dec.decode(&f, &mut out).unwrap_err();
    assert_eq!(err, Error::Unsupported);
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
    // FHD should be 0x00.
    assert_eq!(encoded[4], 0x00);
    // WD = 0x70 (Exp=14, Mant=0).
    assert_eq!(encoded[5], 0x70);
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
    assert_eq!(encoded[4], 0x00);
    assert_eq!(encoded[5], 0x70);
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
    // Frame: magic(4) + FHD(1) + WD(1) + BH(3) + payload(1).
    assert_eq!(encoded.len(), 10);
    let bh = (encoded[6] as u32) | ((encoded[7] as u32) << 8) | ((encoded[8] as u32) << 16);
    let btype = (bh >> 1) & 0b11;
    let bsize = (bh >> 3) & 0x1F_FFFF;
    assert_eq!(btype, 1, "expected RLE_Block");
    assert_eq!(bsize, input.len() as u32);
    assert_eq!(encoded[9], b'a');
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
    let bh = (encoded[6] as u32) | ((encoded[7] as u32) << 8) | ((encoded[8] as u32) << 16);
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
