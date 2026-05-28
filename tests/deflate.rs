//! Streaming round-trip tests for the deflate algorithm.
//!
//! Canonical v0.3 port: every call returns `(Progress, Status)` and the
//! loop dispatches on `Status` rather than inferring from byte counts.

#![cfg(feature = "deflate")]

use compcol::deflate::{Decoder, Deflate, Encoder, EncoderConfig};
use compcol::{Algorithm, Decoder as _, Encoder as _, Error, Status};

/// Parse a hex string into a byte vector — used by the decoder fixtures
/// produced from python3 zlib.
fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

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

/// Drive a decoder to completion. After feeding each input chunk we drain
/// the decoder; once all chunks are fed we also keep calling `decode` with
/// an empty input slice to flush any output the decoder can still produce
/// from bits already buffered internally, before calling `finish`.
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

    // The decoder can hold up to 7+ compressed bytes internally in its bit
    // reader. Drain any output those buffered bits can still produce by
    // calling decode with an empty slice until it stops making progress.
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
fn name_is_deflate() {
    assert_eq!(<Deflate as Algorithm>::NAME, "deflate");
}

#[test]
fn default_config_is_level_6() {
    assert_eq!(EncoderConfig::default().level, 6);
}

// ─── decoder fixtures (reference outputs from python3 zlib) ─────────────

#[test]
fn decode_handcrafted_stored_block() {
    // Hand-constructed stored deflate block carrying "hello":
    //   header byte:  BFINAL=1 | BTYPE=00 | 5 bits of byte-alignment padding = 0x01
    //   LEN  = 5 (little-endian)              -> 0x05 0x00
    //   NLEN = ~5 = 0xFFFA (little-endian)    -> 0xFA 0xFF
    //   data = "hello"                        -> 68 65 6C 6C 6F
    let stream = [0x01, 0x05, 0x00, 0xFA, 0xFF, b'h', b'e', b'l', b'l', b'o'];
    let decoded = decode_chunked(&stream, 1024, 1024).unwrap();
    assert_eq!(decoded, b"hello");
}

#[test]
fn decode_two_stored_blocks() {
    // Block 1 (not final): BFINAL=0, BTYPE=00. Header byte 0x00.
    //   LEN=3, NLEN=~3   -> 03 00 FC FF, data "abc"
    // Block 2 (final):    Header byte 0x01.
    //   LEN=2, NLEN=~2   -> 02 00 FD FF, data "de"
    let stream = [
        0x00, 0x03, 0x00, 0xFC, 0xFF, b'a', b'b', b'c', //
        0x01, 0x02, 0x00, 0xFD, 0xFF, b'd', b'e',
    ];
    let decoded = decode_chunked(&stream, 1024, 1024).unwrap();
    assert_eq!(decoded, b"abcde");
}

#[test]
fn decode_stored_block_streaming_one_byte_at_a_time() {
    let stream = [0x01, 0x05, 0x00, 0xFA, 0xFF, b'h', b'e', b'l', b'l', b'o'];
    let decoded = decode_chunked(&stream, 1, 1).unwrap();
    assert_eq!(decoded, b"hello");
}

#[test]
fn decode_fixed_huffman_hello() {
    // "hello" at zlib level 6 picks a fixed-Huffman block.
    let stream = hex("cb48cdc9c90700");
    let decoded = decode_chunked(&stream, 1024, 1024).unwrap();
    assert_eq!(decoded, b"hello");
}

#[test]
fn decode_fixed_huffman_long_run() {
    // 300 zero bytes — exercises the run-overlap copy (distance=1, length>1).
    let stream = hex("63601805c40200");
    let decoded = decode_chunked(&stream, 1024, 1024).unwrap();
    assert_eq!(decoded.len(), 300);
    assert!(decoded.iter().all(|&b| b == 0));
}

#[test]
fn decode_fixed_huffman_two_runs() {
    // 256x 'A' followed by 256x 'B' — exercises long matches across distance.
    let stream = hex("73741cd9c069840300");
    let decoded = decode_chunked(&stream, 1024, 1024).unwrap();
    let mut expected = vec![b'A'; 256];
    expected.extend(vec![b'B'; 256]);
    assert_eq!(decoded, expected);
}

#[test]
fn decode_lorem_fixed_huffman() {
    // 896-byte Lorem ipsum compressed at level 6 — fixed Huffman block.
    let stream =
        hex("f3c92f4acd55c82c282ecd5548c9cfc92f5228ce2c5148cc4d2dd151f019951b951b95a3a91c00");
    let decoded = decode_chunked(&stream, 1024, 1024).unwrap();
    let expected = b"Lorem ipsum dolor sit amet, ".repeat(32);
    assert_eq!(decoded, expected);
}

#[test]
fn decode_dynamic_huffman_quick_brown_fox() {
    // 4500-byte "The quick brown fox..." compressed at level 6 — dynamic Huffman.
    let stream = hex(
        "edca470180301045412b5f016a628092d0d910084d3d88e0f8ce33aef35a735f8faa929d8b825d1af21c37d9e193f68fa7f2b9d5585bc891c96432994c2693c96432994c2693ffc82f",
    );
    let decoded = decode_chunked(&stream, 1024, 1024).unwrap();
    let expected = b"The quick brown fox jumps over the lazy dog. ".repeat(100);
    assert_eq!(decoded, expected);
}

#[test]
fn decode_dynamic_huffman_streaming_one_byte() {
    // Same dynamic-Huffman fixture, fed 1 byte at a time, drained 1 byte at a time.
    let stream = hex(
        "edca470180301045412b5f016a628092d0d910084d3d88e0f8ce33aef35a735f8faa929d8b825d1af21c37d9e193f68fa7f2b9d5585bc891c96432994c2693c96432994c2693ffc82f",
    );
    let decoded = decode_chunked(&stream, 1, 1).unwrap();
    let expected = b"The quick brown fox jumps over the lazy dog. ".repeat(100);
    assert_eq!(decoded, expected);
}

// ─── encoder round-trip tests at the default level ──────────────────────

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
fn round_trip_repeated_string() {
    // Should compress well with LZ77 references.
    round_trip(b"abcabcabcabcabcabcabcabcabc");
}

#[test]
fn round_trip_long_zeros() {
    let input = vec![0u8; 4096];
    let mut enc = Encoder::new();
    let encoded = encode_chunked(&mut enc, &input, 4096, 4096);
    assert!(
        encoded.len() < input.len() / 10,
        "zeros didn't compress: {} -> {}",
        input.len(),
        encoded.len()
    );
    let decoded = decode_chunked(&encoded, 4096, 4096).unwrap();
    assert_eq!(decoded, input);
}

#[test]
fn round_trip_lorem_ipsum() {
    let input = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. ".repeat(20);
    let mut enc = Encoder::new();
    let encoded = encode_chunked(&mut enc, &input, 4096, 4096);
    assert!(
        encoded.len() < input.len() / 2,
        "text didn't compress: {} -> {}",
        input.len(),
        encoded.len()
    );
    let decoded = decode_chunked(&encoded, 4096, 4096).unwrap();
    assert_eq!(decoded, input);
}

#[test]
fn round_trip_streaming_one_byte() {
    let input = b"Hello, world! ".repeat(50);
    let mut enc = Encoder::new();
    let encoded = encode_chunked(&mut enc, &input, 1, 1);
    let decoded = decode_chunked(&encoded, 1, 1).unwrap();
    assert_eq!(decoded, input);
}

#[test]
fn round_trip_cross_block_matches() {
    // Construct an input where the second 16 KiB block contains a long
    // verbatim copy of the first 16 KiB block. With cross-block matching
    // this should compress to a tiny output (mostly back-references into
    // the previous block).
    let unique = b"The quick brown fox jumps over the lazy dog. ".repeat(370); // ~16.6 KiB
    let mut input = Vec::new();
    input.extend_from_slice(&unique);
    input.extend_from_slice(&unique); // exact repeat → should be one big match
    let mut enc = Encoder::new();
    let encoded = encode_chunked(&mut enc, &input, 4096, 4096);
    assert!(
        encoded.len() < 2048,
        "cross-block matching not effective: {} -> {}",
        input.len(),
        encoded.len()
    );
    let decoded = decode_chunked(&encoded, 4096, 4096).unwrap();
    assert_eq!(decoded, input);
}

/// Build a ≥64 KiB corpus that genuinely separates compression levels.
///
/// The corpus is constructed so that:
///   1. The match finder fires often (lots of recurring 3-grams), keeping
///      the encoder's lazy-matching and chain-walking paths exercised.
///   2. Long-but-distant matches exist that level 1's tiny chain budget
///      (`max_chain=4`) walks past — only level 9's larger budget will
///      find them. This is what makes level 9 measurably smaller than
///      level 1 on the same input.
///
/// We pick a short alphabet so 3-byte hashes collide often (driving up
/// chain length) and we mix in long repeated phrases at scattered offsets
/// so high-budget walks have something to find that low-budget walks miss.
fn mixed_corpus() -> Vec<u8> {
    let mut state: u32 = 0xC0FFEE_u32;
    let mut out = Vec::with_capacity(80 * 1024);
    // Short alphabet → 3-gram hash buckets fill up fast.
    let alphabet = b"abcdef";
    // Long phrases placed periodically so back-references must walk
    // through many chained 3-grams before reaching them.
    let phrases: &[&[u8]] = &[
        b"the_quick_brown_fox_jumps_over_the_lazy_dog_xxxxxxxxxxxxxxxxxxxxxxxx",
        b"lorem_ipsum_dolor_sit_amet_consectetur_adipiscing_elit_yyyyyyyyyyyyyy",
        b"compcol_streaming_codec_test_corpus_for_level_differentiation_zzzzz",
    ];
    let mut phrase_idx = 0usize;
    while out.len() < 64 * 1024 {
        // ~64 bytes drawn from the short alphabet — lots of recurring 3-grams.
        for _ in 0..64 {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            out.push(alphabet[(state as usize) % alphabet.len()]);
        }
        // A long phrase — when it recurs, only a deep chain walk finds it
        // because the short-alphabet noise floods the hash buckets.
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
    // Empty, tiny, and a compressible block — all must roundtrip at the
    // fastest level.
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
fn level_9_no_worse_than_level_1_on_compressible_corpus() {
    // The whole point of having levels: max-effort must produce output
    // at least as small as min-effort on a realistic corpus.
    let input = mixed_corpus();
    let lo = encode_at_level(&input, 1);
    let hi = encode_at_level(&input, 9);
    assert!(
        hi.len() <= lo.len(),
        "level 9 ({} bytes) was bigger than level 1 ({} bytes)",
        hi.len(),
        lo.len(),
    );
    // Sanity: both must roundtrip.
    assert_eq!(decode_chunked(&lo, 4096, 4096).unwrap(), input);
    assert_eq!(decode_chunked(&hi, 4096, 4096).unwrap(), input);
}

#[test]
fn out_of_range_level_is_clamped() {
    // Level 0 and level 250 should both produce valid streams (clamped to
    // 1 and 9 respectively) — we don't expose a fallible constructor.
    let input = b"the rain in spain falls mainly on the plain";
    let mut enc_lo = Encoder::with_config(EncoderConfig { level: 0 });
    let enc_lo_out = encode_chunked(&mut enc_lo, input, 4096, 4096);
    assert_eq!(decode_chunked(&enc_lo_out, 4096, 4096).unwrap(), input);
    let mut enc_hi = Encoder::with_config(EncoderConfig { level: 250 });
    let enc_hi_out = encode_chunked(&mut enc_hi, input, 4096, 4096);
    assert_eq!(decode_chunked(&enc_hi_out, 4096, 4096).unwrap(), input);
}

#[test]
fn level_1_does_less_work_than_level_9() {
    // We don't directly time the encoders (flaky in CI). The level-1 vs
    // level-9 separation is twofold:
    //   - level 1 walks at most 4 hash-chain links per probe; level 9
    //     walks up to 4096. On a hash-collision-heavy corpus, the level-1
    //     encoder misses long matches the level-9 encoder finds.
    //   - level 1 disables lazy matching entirely (greedy parsing); level
    //     9 enables it.
    // The user-visible signal is encoded size: on `mixed_corpus`, which is
    // designed to defeat low chain budgets, level 1 must be strictly
    // larger than level 9.
    let input = mixed_corpus();
    let lo = encode_at_level(&input, 1);
    let hi = encode_at_level(&input, 9);
    assert!(
        lo.len() > hi.len(),
        "level 1 did not produce a measurably larger output: lo={} hi={}",
        lo.len(),
        hi.len(),
    );
    // And both roundtrip.
    assert_eq!(decode_chunked(&lo, 4096, 4096).unwrap(), input);
    assert_eq!(decode_chunked(&hi, 4096, 4096).unwrap(), input);
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
    // Drain output the decoder can still produce from internally-buffered bits.
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

// ─── algorithm-trait entry points ───────────────────────────────────────

#[test]
fn algorithm_encoder_decoder_round_trip() {
    let mut enc = <Deflate as Algorithm>::encoder();
    let mut dec = <Deflate as Algorithm>::decoder();
    let input = b"compcol Algorithm trait roundtrip!";

    // Encode.
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
    }

    // Decode.
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
    let input = b"abcabcabcabcabcabc".repeat(100);
    let mut enc_lo = <Deflate as Algorithm>::encoder_with(EncoderConfig { level: 1 });
    let mut enc_hi = <Deflate as Algorithm>::encoder_with(EncoderConfig { level: 9 });
    let lo = encode_chunked(&mut enc_lo, &input, 4096, 4096);
    let hi = encode_chunked(&mut enc_hi, &input, 4096, 4096);
    assert!(
        hi.len() <= lo.len(),
        "encoder_with(level=9) was bigger than encoder_with(level=1)"
    );
    assert_eq!(decode_chunked(&lo, 4096, 4096).unwrap(), input);
    assert_eq!(decode_chunked(&hi, 4096, 4096).unwrap(), input);
}

// ─── factory lookup ─────────────────────────────────────────────────────

#[cfg(feature = "factory")]
mod factory {
    use compcol::Status;
    use compcol::factory;

    #[test]
    fn lookup_known() {
        assert!(factory::encoder_by_name("deflate").is_some());
        assert!(factory::decoder_by_name("deflate").is_some());
    }

    #[test]
    fn names_contains_deflate() {
        assert!(factory::names().contains(&"deflate"));
    }

    #[test]
    fn boxed_round_trip() {
        let mut enc = factory::encoder_by_name("deflate").unwrap();
        let mut dec = factory::decoder_by_name("deflate").unwrap();
        let input = b"hello hello hello world world world!";

        // Encode the whole input.
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
        }

        // Decode and compare.
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
