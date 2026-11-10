//! Streaming round-trip + decode-only tests for the Zstd algorithm.
//!
//! Canonical v0.3 port: every call returns `(Progress, Status)` and the
//! loop dispatches on `Status` rather than inferring from byte counts.
//!
//! See `src/zstd/mod.rs` for the supported subset (Raw_Block, RLE_Block, and
//! Compressed_Block on both halves; no Content_Checksum_Flag, no Skippable
//! frames, no Dictionary_ID).

#![cfg(feature = "zstd")]

use compcol::zstd::{DEFAULT_LEVEL, Decoder, Encoder, EncoderConfig, MIN_LEVEL, Zstd};
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

fn encode_at_level(input: &[u8], level: i32) -> Vec<u8> {
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
    // Levels beyond either end should produce valid streams (clamped to
    // MIN_LEVEL and 22 respectively) — we don't expose a fallible constructor.
    let input = b"the rain in spain falls mainly on the plain";
    for level in [i32::MIN, MIN_LEVEL - 1, 250, i32::MAX] {
        let mut enc = Encoder::with_config(EncoderConfig { level });
        let out = encode_chunked(&mut enc, input, 4096, 4096);
        assert_eq!(decode_chunked(&out, 4096, 4096).unwrap(), input);
    }
    let corpus = mixed_corpus();
    assert_eq!(
        encode_at_level(&corpus, i32::MIN),
        encode_at_level(&corpus, MIN_LEVEL)
    );
    assert_eq!(encode_at_level(&corpus, 250), encode_at_level(&corpus, 22));
}

#[test]
fn level_0_means_default() {
    // As in libzstd, 0 selects the default level rather than clamping to 1.
    let input = mixed_corpus();
    assert_eq!(EncoderConfig::default().level, DEFAULT_LEVEL);
    assert_eq!(
        encode_at_level(&input, 0),
        encode_at_level(&input, DEFAULT_LEVEL)
    );
}

// ─── negative ("fast") levels ───────────────────────────────────────────

/// Fast levels exercised by the tests below, from libzstd's `--fast=1` down
/// to `ZSTD_minCLevel()`.
const FAST_LEVELS: [i32; 6] = [-1, -3, -7, -50, -1000, MIN_LEVEL];

#[test]
fn negative_levels_round_trip() {
    let inputs = [
        Vec::new(),
        b"hello world".to_vec(),
        b"abcabcabcabcabc".repeat(100),
        mixed_corpus(),
        gen_words(200_000),
        lcg_bytes(3, 150_000),
    ];
    for level in FAST_LEVELS {
        for input in &inputs {
            let encoded = encode_at_level(input, level);
            assert_eq!(
                &decode_chunked(&encoded, 4096, 4096).unwrap(),
                input,
                "level {level}, {} bytes",
                input.len()
            );
        }
    }
}

#[test]
fn negative_levels_trade_ratio_monotonically() {
    // Each more negative level strides further past misses, so it can only
    // find fewer matches: output grows (non-strictly) as the level drops,
    // and a strongly negative level must be measurably worse than level 1.
    let input = gen_words(100_000);
    let mut text = Vec::new();
    for i in 0..3_000 {
        text.extend_from_slice(format!("line {i}: the quick brown fox {}\n", i % 97).as_bytes());
    }
    for input in [input, mixed_corpus(), text] {
        let l1 = encode_at_level(&input, 1).len();
        let mut prev = l1;
        for level in FAST_LEVELS {
            let n = encode_at_level(&input, level).len();
            assert!(
                n >= prev,
                "level {level} ({n} bytes) beat a higher level ({prev} bytes)"
            );
            prev = n;
        }
        let fast = encode_at_level(&input, -50).len();
        assert!(
            fast > l1,
            "level -50 ({fast} bytes) no larger than level 1 ({l1} bytes)"
        );
    }
}

#[test]
fn negative_levels_interoperate_with_system_zstd() {
    let available = std::process::Command::new("zstd")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success());
    if !available {
        println!("skipping: zstd not installed");
        return;
    }
    let mut input = gen_words(150_000);
    input.extend_from_slice(&lcg_bytes(5, 20_000));
    input.extend_from_slice(&mixed_corpus());
    for level in FAST_LEVELS {
        let encoded = encode_at_level(&input, level);
        let out = run_tool("zstd", &["-d", "-c"], &encoded);
        assert!(
            out.status.success(),
            "zstd -d rejected level {level}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(out.stdout == input, "zstd -d decoded level {level} wrong");
    }
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

// ─── decoder: Frame_Content_Size validation ─────────────────────────────

/// Frame = magic + `header` (FHD onwards) + `blocks`.
fn frame_from_parts(header: &[u8], blocks: &[u8]) -> Vec<u8> {
    let mut f = vec![0x28, 0xB5, 0x2F, 0xFD];
    f.extend_from_slice(header);
    f.extend_from_slice(blocks);
    f
}

/// Decode with several input/output chunkings; all must agree.
fn decode_all_chunkings(frame: &[u8]) -> Result<Vec<u8>, Error> {
    let first = decode_chunked(frame, 4096, 4096);
    for (i, o) in [(1, 1), (1, 4096), (4096, 1), (3, 2)] {
        assert_eq!(decode_chunked(frame, i, o), first, "chunking {i}/{o}");
    }
    first
}

/// A frame whose header declares a `Frame_Content_Size` must decode to
/// exactly that many bytes (reference zstd: "Data corruption detected").
#[test]
fn frame_content_size_is_enforced() {
    // Single_Segment, 1-byte FCS, one last Raw_Block "abc".
    let raw_abc = [0x19, 0x00, 0x00, b'a', b'b', b'c'];
    assert_eq!(
        decode_all_chunkings(&frame_from_parts(&[0x20, 3], &raw_abc)).unwrap(),
        b"abc"
    );
    // Declared 5, content 3: short.
    assert_eq!(
        decode_all_chunkings(&frame_from_parts(&[0x20, 5], &raw_abc)),
        Err(Error::Corrupt)
    );
    // Declared 1, content 3: long.
    assert_eq!(
        decode_all_chunkings(&frame_from_parts(&[0x20, 1], &raw_abc)),
        Err(Error::Corrupt)
    );

    // Windowed header (1 KiB) with a 4-byte FCS, so block sizes are not
    // limited by the content size. Blocks: Raw "abc" (not last), RLE 'x' * 4
    // (not last), Raw "de" (last) = 9 bytes.
    let blocks = [
        0x18, 0x00, 0x00, b'a', b'b', b'c', // Raw, 3 bytes
        0x22, 0x00, 0x00, b'x', // RLE, 4 bytes
        0x11, 0x00, 0x00, b'd', b'e', // Raw, 2 bytes, last
    ];
    let with_fcs = |n: u32| {
        let mut h = vec![0x80, 0x00];
        h.extend_from_slice(&n.to_le_bytes());
        frame_from_parts(&h, &blocks)
    };
    assert_eq!(decode_all_chunkings(&with_fcs(9)).unwrap(), b"abcxxxxde");
    // 2 and 5 are exceeded by a non-last block, 8 by the last one; 10 and
    // 1000 are never reached.
    for n in [0, 2, 5, 8, 10, 1000] {
        assert_eq!(
            decode_all_chunkings(&with_fcs(n)),
            Err(Error::Corrupt),
            "FCS={n}"
        );
    }

    // Compressed_Block regenerating "abcdddd" (7 bytes).
    let comp = [
        0x55, 0x00, 0x00, 0x20, b'a', b'b', b'c', b'd', 0x01, 0x00, 0x00, 0x8E, 0x08,
    ];
    let with_fcs = |n: u32| {
        let mut h = vec![0x80, 0x00];
        h.extend_from_slice(&n.to_le_bytes());
        frame_from_parts(&h, &comp)
    };
    assert_eq!(decode_all_chunkings(&with_fcs(7)).unwrap(), b"abcdddd");
    for n in [0, 6, 8] {
        assert_eq!(
            decode_all_chunkings(&with_fcs(n)),
            Err(Error::Corrupt),
            "FCS={n}"
        );
    }
}

/// Nothing past the declared size is ever handed to the caller.
#[test]
fn frame_content_size_overrun_emits_nothing_past_it() {
    // FCS = 2, then a Raw_Block "ab" (not last) and an RLE_Block of 1000.
    let frame = frame_from_parts(
        &[0x80, 0x00, 2, 0, 0, 0],
        &[0x10, 0x00, 0x00, b'a', b'b', 0x43, 0x1F, 0x00, b'z'],
    );
    let mut dec = Decoder::new();
    let mut out = vec![0u8; 4096];
    let mut total = 0;
    let mut pos = 0;
    let err = loop {
        match dec.decode(&frame[pos..], &mut out[total..]) {
            Ok((p, status)) => {
                pos += p.consumed;
                total += p.written;
                assert_ne!(status, Status::StreamEnd, "frame accepted");
                assert!(p.consumed + p.written > 0, "decoder stalled");
            }
            Err(e) => break e,
        }
    };
    assert_eq!(err, Error::Corrupt);
    assert!(total <= 2, "emitted {total} bytes for a 2-byte frame");
}

// ─── decoder: Block_Maximum_Size ────────────────────────────────────────

/// 3-byte Block_Header.
fn block_header(last: bool, block_type: u32, size: u32) -> [u8; 3] {
    let bh = (size << 3) | (block_type << 1) | last as u32;
    [bh as u8, (bh >> 8) as u8, (bh >> 16) as u8]
}

/// Windowed frame (`wd` = Window_Descriptor) holding one last RLE_Block.
fn rle_frame_in_window(wd: u8, count: u32) -> Vec<u8> {
    let mut f = vec![0x28, 0xB5, 0x2F, 0xFD, 0x00, wd];
    f.extend_from_slice(&block_header(true, 1, count));
    f.push(b'z');
    f
}

/// Windowed frame holding one last Raw_Block of `count` bytes.
fn raw_frame_in_window(wd: u8, count: u32) -> Vec<u8> {
    let mut f = vec![0x28, 0xB5, 0x2F, 0xFD, 0x00, wd];
    f.extend_from_slice(&block_header(true, 0, count));
    f.extend((0..count).map(|i| (i % 251) as u8));
    f
}

/// RFC 8878 §3.1.1.2.4: no block may be larger, nor regenerate more, than
/// `Block_Maximum_Size = min(Window_Size, 128 KiB)`. The RLE case used to
/// have no bound at all: 10 input bytes produced 2 MiB in a 1 KiB window.
#[test]
fn block_size_is_capped_at_block_maximum_size() {
    const WD_1K: u8 = 0x00;
    const WD_128K: u8 = 0x38;
    const WD_256K: u8 = 0x40;
    const KIB128: u32 = 128 * 1024;

    // The audit's reproducer: `28 B5 2F FD 00 00 FB FF FF 7A`.
    let bomb = rle_frame_in_window(WD_1K, 0x1F_FFFF);
    assert_eq!(bomb, [0x28, 0xB5, 0x2F, 0xFD, 0, 0, 0xFB, 0xFF, 0xFF, 0x7A]);
    // (Lengths only: a failure must not dump megabytes of output.)
    let len = |frame: &[u8], chunk: usize| decode_chunked(frame, chunk, chunk).map(|v| v.len());
    assert_eq!(len(&bomb, 4096), Err(Error::Corrupt));
    assert_eq!(len(&bomb, 1), Err(Error::Corrupt));

    for (wd, max) in [(WD_1K, 1024), (WD_128K, KIB128), (WD_256K, KIB128)] {
        // Exactly Block_Maximum_Size is fine...
        let ok = decode_chunked(&rle_frame_in_window(wd, max), 4096, 4096).unwrap();
        assert!(
            ok.len() == max as usize && ok.iter().all(|&b| b == b'z'),
            "RLE wd={wd:#x}"
        );
        assert_eq!(
            len(&raw_frame_in_window(wd, max), 4096),
            Ok(max as usize),
            "Raw wd={wd:#x}"
        );
        // ...one byte more is not.
        assert_eq!(
            len(&rle_frame_in_window(wd, max + 1), 4096),
            Err(Error::Corrupt),
            "RLE wd={wd:#x}"
        );
        assert_eq!(
            len(&raw_frame_in_window(wd, max + 1), 4096),
            Err(Error::Corrupt),
            "Raw wd={wd:#x}"
        );
    }

    // Compressed_Block whose Block_Size exceeds a 1 KiB window: a
    // Raw_Literals_Block of 1021 bytes (3-byte header) + a zero sequence
    // count is 1025 bytes on the wire. In a 2 KiB window it is legal.
    let mut body = vec![0xDC, 0x3F, 0x00]; // Raw literals, 20-bit size 1021
    body.extend((0..1021u32).map(|i| (i % 251) as u8));
    body.push(0x00);
    assert_eq!(body.len(), 1025);
    let comp_frame = |wd: u8| {
        let mut f = vec![0x28, 0xB5, 0x2F, 0xFD, 0x00, wd];
        f.extend_from_slice(&block_header(true, 2, body.len() as u32));
        f.extend_from_slice(&body);
        f
    };
    assert_eq!(len(&comp_frame(0x08), 4096), Ok(1021));
    assert_eq!(len(&comp_frame(WD_1K), 4096), Err(Error::Corrupt));

    // Compressed_Block that is small on the wire but regenerates 1025 bytes
    // (RLE_Literals_Block) in a 1 KiB window.
    let rle_lit_frame = |wd: u8, n: u32| {
        let mut f = vec![0x28, 0xB5, 0x2F, 0xFD, 0x00, wd];
        f.extend_from_slice(&block_header(true, 2, 4));
        // RLE literals, Size_Format 01 (12-bit size), byte 'q', 0 sequences.
        f.extend_from_slice(&[0x05 | ((n & 0xF) << 4) as u8, (n >> 4) as u8, b'q', 0x00]);
        f
    };
    assert_eq!(len(&rle_lit_frame(WD_1K, 1024), 4096), Ok(1024));
    assert_eq!(len(&rle_lit_frame(WD_1K, 1025), 4096), Err(Error::Corrupt));
}

/// In a Single_Segment frame `Window_Size` is the Frame_Content_Size, so
/// Block_Maximum_Size shrinks with it (reference: `blockSizeMax =
/// MIN(windowSize, ZSTD_BLOCKSIZE_MAX)` with `windowSize = frameContentSize`).
#[test]
fn single_segment_block_maximum_size_is_the_content_size() {
    let ss = |fcs: u8, blocks: &[u8]| frame_from_parts(&[0x20, fcs], blocks);
    // Compressed_Block of 3 bytes (RLE literal 'z' * n, no sequences).
    let comp = |n: u8| [0x1D, 0x00, 0x00, (n << 3) | 1, b'z', 0x00];

    // Raw and RLE blocks of exactly the content size are fine.
    assert_eq!(
        decode_all_chunkings(&ss(1, &[0x09, 0x00, 0x00, b'z'])).unwrap(),
        b"z"
    );
    assert_eq!(
        decode_all_chunkings(&ss(3, &[0x1B, 0x00, 0x00, b'z'])).unwrap(),
        b"zzz"
    );
    // A 3-byte Compressed_Block fits a 3-byte frame, not a 1- or 2-byte one.
    assert_eq!(decode_all_chunkings(&ss(3, &comp(3))).unwrap(), b"zzz");
    assert_eq!(decode_all_chunkings(&ss(2, &comp(2))), Err(Error::Corrupt));
    assert_eq!(decode_all_chunkings(&ss(1, &comp(1))), Err(Error::Corrupt));
    // An empty frame can only hold empty Raw_Blocks.
    assert_eq!(
        decode_all_chunkings(&ss(0, &[0x01, 0x00, 0x00])).unwrap(),
        b""
    );
    assert_eq!(
        decode_all_chunkings(&ss(0, &[0x15, 0x00, 0x00, 0x00, 0x00])),
        Err(Error::Corrupt)
    );
    // The same empty Compressed_Block is legal in a windowed frame.
    assert_eq!(
        decode_all_chunkings(&frame_from_parts(
            &[0x00, 0x00],
            &[0x15, 0x00, 0x00, 0x00, 0x00]
        ))
        .unwrap(),
        b""
    );
    // Several blocks: the bound is the frame's size, not what is left of it.
    let mut blocks = vec![0x18, 0x00, 0x00, b'a', b'b', b'c'];
    blocks.extend_from_slice(&comp(1));
    assert_eq!(decode_all_chunkings(&ss(4, &blocks)).unwrap(), b"abcz");
}

// ─── decoder: entropy bitstreams must be consumed exactly ───────────────

/// Windowed (1 KiB) frame holding one last Compressed_Block with `body`.
fn compressed_block_frame(body: &[u8]) -> Vec<u8> {
    let mut f = vec![0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x00];
    f.extend_from_slice(&block_header(true, 2, body.len() as u32));
    f.extend_from_slice(body);
    f
}

/// The sequence bitstream must be used up exactly once the last sequence is
/// decoded (reference: `BIT_endOfDStream` check, "corruption_detected").
#[test]
fn sequence_bitstream_must_be_fully_consumed() {
    // Raw literals "abcd", one sequence (predefined tables): LL=4, ML=3,
    // offset 1 → "abcd" + "ddd". Bitstream `00 8E 08`.
    let exact =
        compressed_block_frame(&[0x20, b'a', b'b', b'c', b'd', 0x01, 0x00, 0x00, 0x8E, 0x08]);
    assert_eq!(
        exact,
        [
            0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x00, 0x55, 0x00, 0x00, 0x20, 0x61, 0x62, 0x63, 0x64,
            0x01, 0x00, 0x00, 0x8E, 0x08
        ]
    );
    assert_eq!(decode_all_chunkings(&exact).unwrap(), b"abcdddd");

    // The audit's reproducer: one extra zero byte at the (unread) low end of
    // the bitstream.
    let padded = compressed_block_frame(&[
        0x20, b'a', b'b', b'c', b'd', 0x01, 0x00, 0x00, 0x00, 0x8E, 0x08,
    ]);
    assert_eq!(
        padded,
        [
            0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x00, 0x5D, 0x00, 0x00, 0x20, 0x61, 0x62, 0x63, 0x64,
            0x01, 0x00, 0x00, 0x00, 0x8E, 0x08
        ]
    );
    assert_eq!(decode_all_chunkings(&padded), Err(Error::Corrupt));

    // Two extra bytes.
    let padded2 = compressed_block_frame(&[
        0x20, b'a', b'b', b'c', b'd', 0x01, 0x00, 0x00, 0x00, 0x00, 0x8E, 0x08,
    ]);
    assert_eq!(decode_all_chunkings(&padded2), Err(Error::Corrupt));
}

/// Every Huffman-coded literal stream must end exactly on its last symbol
/// (reference: `BIT_endOfDStream` per stream in huf_decompress.c).
///
/// The tree `80 10` gives symbols 0x00 and 0x01 one-bit codes (0 and 1), so
/// a stream is just its symbols' bits below the start marker.
#[test]
fn huffman_literal_streams_must_be_fully_consumed() {
    // ── 1 stream, 5 literals 0,1,1,0,1 → bits 01101 → `2D`.
    let exact = compressed_block_frame(&[0x52, 0xC0, 0x00, 0x80, 0x10, 0x2D, 0x00]);
    assert_eq!(decode_all_chunkings(&exact).unwrap(), [0, 1, 1, 0, 1]);
    // One spare bit in the same byte (`5A` = marker + 011010).
    let spare_bit = compressed_block_frame(&[0x52, 0xC0, 0x00, 0x80, 0x10, 0x5A, 0x00]);
    assert_eq!(decode_all_chunkings(&spare_bit), Err(Error::Corrupt));
    // A spare zero byte below the stream.
    let spare_byte = compressed_block_frame(&[0x52, 0x00, 0x01, 0x80, 0x10, 0x00, 0x2D, 0x00]);
    assert_eq!(decode_all_chunkings(&spare_byte), Err(Error::Corrupt));
    // One bit short was always rejected.
    let short = compressed_block_frame(&[0x52, 0xC0, 0x00, 0x80, 0x10, 0x16, 0x00]);
    assert_eq!(decode_all_chunkings(&short), Err(Error::Corrupt));

    // ── 4 streams, 8 literals 0,1 | 1,0 | 1,1 | 0,0 → `05`, `06`, `07`, `04`.
    let four = |streams: [&[u8]; 4]| {
        let total: usize = streams.iter().map(|s| s.len()).sum();
        let comp = 2 + 6 + total; // tree + jump table + streams
        let mut body = vec![0x86, ((comp & 3) << 6) as u8, (comp >> 2) as u8, 0x80, 0x10];
        for s in &streams[..3] {
            body.extend_from_slice(&(s.len() as u16).to_le_bytes());
        }
        for s in streams {
            body.extend_from_slice(s);
        }
        body.push(0x00); // no sequences
        compressed_block_frame(&body)
    };
    let good: [&[u8]; 4] = [&[0x05], &[0x06], &[0x07], &[0x04]];
    assert_eq!(
        four(good),
        [
            0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x00, 0x85, 0x00, 0x00, 0x86, 0x00, 0x03, 0x80, 0x10,
            0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x05, 0x06, 0x07, 0x04, 0x00
        ]
    );
    assert_eq!(
        decode_all_chunkings(&four(good)).unwrap(),
        [0, 1, 1, 0, 1, 1, 0, 0]
    );
    // Each stream in turn with one spare bit, then with a spare zero byte.
    let spare_bit: [&[u8]; 4] = [&[0x0A], &[0x0C], &[0x0E], &[0x08]];
    let spare_byte: [&[u8]; 4] = [&[0x00, 0x05], &[0x00, 0x06], &[0x00, 0x07], &[0x00, 0x04]];
    for i in 0..4 {
        let mut s = good;
        s[i] = spare_bit[i];
        assert_eq!(
            decode_all_chunkings(&four(s)),
            Err(Error::Corrupt),
            "stream {i}: spare bit"
        );
        let mut s = good;
        s[i] = spare_byte[i];
        assert_eq!(
            decode_all_chunkings(&four(s)),
            Err(Error::Corrupt),
            "stream {i}: spare byte"
        );
    }

    // ── 4 streams, 6 literals: the streams hold 2, 2, 2 and 0 symbols. The
    // empty fourth stream must still be a well-formed, empty bitstream (a
    // bare start marker), not arbitrary bytes.
    let six = |s4: u8| {
        compressed_block_frame(&[
            0x66, 0x00, 0x03, 0x80, 0x10, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x05, 0x06, 0x07, s4,
            0x00,
        ])
    };
    assert_eq!(
        decode_all_chunkings(&six(0x01)).unwrap(),
        [0, 1, 1, 0, 1, 1]
    );
    assert_eq!(decode_all_chunkings(&six(0x04)), Err(Error::Corrupt));
    assert_eq!(decode_all_chunkings(&six(0x00)), Err(Error::Corrupt));
}

/// 4-stream Huffman literals need a Regenerated_Size of at least 6
/// (reference `MIN_LITERALS_FOR_4_STREAMS`: "Header of Literals' block
/// doesn't respect format specification"). Four literals, one per stream,
/// used to be accepted; six (see the test above) is the smallest legal size.
#[test]
fn four_stream_literals_need_six_bytes() {
    // Same tree as above; streams `02 03 02 03` = symbols 0, 1, 0, 1.
    let four = compressed_block_frame(&[
        0x46, 0x00, 0x03, 0x80, 0x10, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0x03, 0x02, 0x03,
        0x00,
    ]);
    assert_eq!(decode_all_chunkings(&four), Err(Error::Corrupt));
}

/// The exact-consumption checks must never reject what the crate's own
/// encoder writes: many small inputs of different shapes (so 1- and 4-stream
/// Huffman literals, FSE-compressed / RLE / predefined / repeat sequence
/// tables all occur) at assorted levels, with and without flushes.
#[test]
fn exact_bitstream_checks_accept_encoder_output() {
    const LEVELS: [i32; 9] = [MIN_LEVEL, -50, -3, -1, 1, 3, 7, 15, 22];
    for case in 0..240u32 {
        let len = (case as usize * 131) % 6000;
        let input: Vec<u8> = match case % 4 {
            0 => gen_words(len),
            // Skewed small alphabet: Huffman literals, few matches.
            1 => lcg_bytes(case, len)
                .into_iter()
                .map(|b| b"aaaabbbcdeefghij"[(b & 15) as usize])
                .collect(),
            // Words interleaved with noise.
            2 => gen_words(len)
                .into_iter()
                .zip(lcg_bytes(case, len))
                .map(|(w, n)| if n < 40 { n } else { w })
                .collect(),
            // Short period with occasional breaks.
            _ => lcg_bytes(case, len)
                .into_iter()
                .enumerate()
                .map(|(i, n)| if n < 8 { n } else { (i % 7) as u8 })
                .collect(),
        };
        let level = LEVELS[case as usize % LEVELS.len()];
        let mut enc = Encoder::with_config(EncoderConfig { level });
        let mut wire = Vec::new();
        if case % 3 == 0 && len > 2 {
            // Two flushed segments, then the rest: several blocks in one
            // frame, so repeat tables / treeless literals get a chance.
            let (a, rest) = input.split_at(len / 3);
            let (b, c) = rest.split_at(len / 3);
            flush_test_encode(&mut enc, a, 4096, &mut wire);
            flush_test_flush(&mut enc, Flush::Sync, 4096, &mut wire);
            flush_test_encode(&mut enc, b, 4096, &mut wire);
            flush_test_flush(&mut enc, Flush::Full, 4096, &mut wire);
            flush_test_encode(&mut enc, c, 4096, &mut wire);
            flush_test_finish(&mut enc, 4096, &mut wire);
        } else {
            wire = encode_chunked(&mut enc, &input, 4096, 4096);
        }
        let decoded = decode_chunked(&wire, 4096, 4096);
        assert!(
            decoded.as_deref() == Ok(&input[..]),
            "case {case}: len {len}, level {level}: {:?}",
            decoded.map(|v| v.len())
        );
    }
}
