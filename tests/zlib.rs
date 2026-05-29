//! Streaming round-trip tests for the zlib codec.
//!
//! Canonical v0.3 port: every call returns `(Progress, Status)` and the
//! loop dispatches on `Status` rather than inferring from byte counts.

#![cfg(feature = "zlib")]

use compcol::zlib::{Decoder, Encoder, EncoderConfig, Zlib};
use compcol::{Algorithm, Decoder as _, Encoder as _, Error, Status};

/// Parse a hex string into a byte vector — used by the decoder fixture
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
                    panic!("zlib encoder finish stalled");
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

    // Drain any output the decoder can still produce from internally-buffered bits.
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
    // First byte should be 0x78 (the standard zlib CMF byte at CINFO=7).
    assert_eq!(encoded[0], 0x78);
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
fn name_is_zlib() {
    assert_eq!(<Zlib as Algorithm>::NAME, "zlib");
}

#[test]
fn default_config_is_level_6() {
    assert_eq!(EncoderConfig::default().level, 6);
}

// ─── decoder fixture ────────────────────────────────────────────────────

#[test]
fn decode_python_zlib_reference() {
    // Output of: python3 -c "import zlib; print(zlib.compress(b'hello world', 6).hex())"
    let stream = hex("789ccb48cdc9c95728cf2fca4901001a0b045d");
    let decoded = decode_chunked(&stream, 1024, 1024).unwrap();
    assert_eq!(decoded, b"hello world");
}

// ─── encoder round-trip tests at the default level ──────────────────────

#[test]
fn round_trip_empty() {
    round_trip(b"");
}

#[test]
fn round_trip_hello_world() {
    round_trip(b"hello world");
}

#[test]
fn round_trip_repeated() {
    round_trip(&b"foo bar baz ".repeat(100));
}

#[test]
fn round_trip_long_zeros() {
    let input = vec![0u8; 4096];
    let mut enc = Encoder::new();
    let encoded = encode_chunked(&mut enc, &input, 4096, 4096);
    // Should compress well: 4096 bytes -> << 100 with the header/trailer overhead.
    assert!(
        encoded.len() < 100,
        "zeros didn't compress: {}",
        encoded.len()
    );
    let decoded = decode_chunked(&encoded, 4096, 4096).unwrap();
    assert_eq!(decoded, input);
}

#[test]
fn round_trip_streaming_one_byte() {
    let input = b"streaming bytes one at a time".to_vec();
    let mut enc = Encoder::new();
    let encoded = encode_chunked(&mut enc, &input, 1, 1);
    let decoded = decode_chunked(&encoded, 1, 1).unwrap();
    assert_eq!(decoded, input);
}

/// Build a ≥64 KiB corpus that genuinely separates compression levels.
/// Mirrors the corpus from `tests/deflate.rs` — short alphabet keeps the
/// 3-gram hash buckets full so the chain-walk depth becomes the limiting
/// factor; long phrases at scattered offsets give the deep-walking levels
/// something to find that the shallow walkers miss.
fn mixed_corpus() -> Vec<u8> {
    let mut state: u32 = 0xC0FFEE_u32;
    let mut out = Vec::with_capacity(80 * 1024);
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
fn level_9_no_worse_than_level_1_on_compressible_corpus() {
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
fn level_1_flevel_bits_set_correctly() {
    // Per RFC 1950 §2.2 the FLEVEL bits (FLG bits 6-7) advertise the
    // compression effort: 0=fastest, 1=fast, 2=default, 3=maximum.
    // Level 1 → FLEVEL = 0.
    let mut enc = Encoder::with_config(EncoderConfig { level: 1 });
    let encoded = encode_chunked(&mut enc, b"hi", 4096, 4096);
    let flg = encoded[1];
    assert_eq!(flg & 0xC0, 0 << 6, "level 1 should set FLEVEL=0");
    let total = ((encoded[0] as u32) << 8) | (flg as u32);
    assert_eq!(
        total % 31,
        0,
        "FCHECK must make CMF*256+FLG divisible by 31"
    );
}

#[test]
fn level_3_flevel_bits_set_correctly() {
    // Levels 2..=5 → FLEVEL = 1.
    let mut enc = Encoder::with_config(EncoderConfig { level: 3 });
    let encoded = encode_chunked(&mut enc, b"hi", 4096, 4096);
    let flg = encoded[1];
    assert_eq!(flg & 0xC0, 1 << 6, "level 3 should set FLEVEL=1");
    let total = ((encoded[0] as u32) << 8) | (flg as u32);
    assert_eq!(total % 31, 0);
}

#[test]
fn level_6_flevel_bits_set_correctly() {
    // Level 6 → FLEVEL = 2 (default).
    let mut enc = Encoder::with_config(EncoderConfig { level: 6 });
    let encoded = encode_chunked(&mut enc, b"hi", 4096, 4096);
    assert_eq!(encoded[0], 0x78);
    assert_eq!(
        encoded[1], 0x9C,
        "level 6 should produce the canonical 0x78 0x9C header"
    );
    let total = ((encoded[0] as u32) << 8) | (encoded[1] as u32);
    assert_eq!(total % 31, 0);
}

#[test]
fn level_9_flevel_bits_set_correctly() {
    // Levels 7..=9 → FLEVEL = 3 (maximum).
    let mut enc = Encoder::with_config(EncoderConfig { level: 9 });
    let encoded = encode_chunked(&mut enc, b"hi", 4096, 4096);
    let flg = encoded[1];
    assert_eq!(flg & 0xC0, 3 << 6, "level 9 should set FLEVEL=3");
    let total = ((encoded[0] as u32) << 8) | (flg as u32);
    assert_eq!(total % 31, 0);
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

// ─── adler-32 trailer + malformed-header validation ─────────────────────

#[test]
fn corrupted_adler_rejected() {
    let input = b"some payload bytes";
    let mut enc = Encoder::new();
    let mut encoded = encode_chunked(&mut enc, input, 4096, 4096);
    // Flip a bit in the trailer (last 4 bytes).
    let last = encoded.len() - 1;
    encoded[last] ^= 0x01;
    let err = decode_chunked(&encoded, 4096, 4096).unwrap_err();
    assert_eq!(err, Error::ChecksumMismatch);
}

#[test]
fn corrupt_header_unsupported_cm_rejected() {
    // CMF=0x77 (CM=7, not deflate)
    let stream = hex("77deadbeef");
    let mut dec = Decoder::new();
    let mut buf = [0u8; 16];
    let err = dec.decode(&stream, &mut buf).unwrap_err();
    assert_eq!(err, Error::Unsupported);
}

#[test]
fn corrupt_header_bad_check_rejected() {
    // CMF=0x78, FLG with FCHECK that violates divisibility by 31.
    let stream = hex("7800deadbeef");
    let mut dec = Decoder::new();
    let mut buf = [0u8; 16];
    let err = dec.decode(&stream, &mut buf).unwrap_err();
    assert_eq!(err, Error::BadHeader);
}

#[test]
fn fdict_header_rejected() {
    // CMF=0x78, FLG=0xBB → bit 5 (FDICT) set; check 0x78BB % 31 = 0:
    //   0x78BB = 30907; 30907 / 31 = 997; remainder 0 ✓
    // We don't carry a preset dictionary so this must be rejected.
    let stream = hex("78bbdeadbeef");
    let mut dec = Decoder::new();
    let mut buf = [0u8; 16];
    let err = dec.decode(&stream, &mut buf).unwrap_err();
    assert_eq!(err, Error::Unsupported);
}

// ─── algorithm-trait entry points ───────────────────────────────────────

#[test]
fn algorithm_encoder_decoder_round_trip() {
    let mut enc = <Zlib as Algorithm>::encoder();
    let mut dec = <Zlib as Algorithm>::decoder();
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
    let mut enc_lo = <Zlib as Algorithm>::encoder_with(EncoderConfig { level: 1 });
    let mut enc_hi = <Zlib as Algorithm>::encoder_with(EncoderConfig { level: 9 });
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
        assert!(factory::encoder_by_name("zlib").is_some());
        assert!(factory::decoder_by_name("zlib").is_some());
    }

    #[test]
    fn names_contains_zlib() {
        assert!(factory::names().contains(&"zlib"));
    }

    #[test]
    fn boxed_round_trip() {
        let mut enc = factory::encoder_by_name("zlib").unwrap();
        let mut dec = factory::decoder_by_name("zlib").unwrap();
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

// ─── FDICT / preset dictionary (#22) ──────────────────────────────────────

use compcol::zlib::DecoderConfig;

fn drain_full(mut dec: Decoder, encoded: &[u8]) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    let mut buf = vec![0u8; 4096];
    let mut consumed = 0;
    loop {
        let (p, status) = dec.decode(&encoded[consumed..], &mut buf)?;
        out.extend_from_slice(&buf[..p.written]);
        consumed += p.consumed;
        if matches!(status, Status::StreamEnd) {
            return Ok(out);
        }
        if matches!(status, Status::InputEmpty) {
            break;
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

/// Real FDICT-set zlib stream produced by Python's `zlib.compressobj(zdict=DICT)`.
/// CMF=0x78, FLG=0xF9 (FDICT=1, FCHECK chosen so `(CMF*256 + FLG) % 31 == 0`).
/// DICTID = Adler-32 of the dictionary, big-endian: `0x81AC1048`.
const FDICT_DICTIONARY: &[u8] = b"the quick brown fox jumps over the lazy dog. ";
const FDICT_PAYLOAD: &[u8] = b"the quick brown fox is quicker than the lazy dog!";

/// FDICT=1 stream with a configured matching dictionary decodes cleanly.
#[test]
fn zlib_decoder_fdict_decodes_with_matching_dictionary() {
    let encoded = hex("78f981ac10482bc1a238b3182204569c9887a2431100c4ce11cb");

    let dec = Decoder::with_config(DecoderConfig {
        dictionary: FDICT_DICTIONARY.to_vec(),
    });
    let out = drain_full(dec, &encoded).unwrap();
    assert_eq!(out, FDICT_PAYLOAD);

    // Same via the type-associated config path.
    let dec: Decoder = Zlib::decoder_with(DecoderConfig {
        dictionary: FDICT_DICTIONARY.to_vec(),
    });
    let out = drain_full(dec, &encoded).unwrap();
    assert_eq!(out, FDICT_PAYLOAD);
}

/// FDICT=1 stream with NO configured dictionary errors as Unsupported.
/// Preserves the pre-#22 behaviour: streams the decoder was always
/// unable to handle still surface the same way.
#[test]
fn zlib_decoder_fdict_without_dictionary_is_unsupported() {
    let encoded = hex("78f981ac10482bc1a238b3182204569c9887a2431100c4ce11cb");

    let dec = Decoder::new();
    let err = drain_full(dec, &encoded).unwrap_err();
    assert!(matches!(err, Error::Unsupported), "got {err:?}");
}

/// FDICT=1 stream with the WRONG dictionary errors as ChecksumMismatch
/// (the on-wire DICTID is the dictionary's Adler-32, so any non-matching
/// dict surfaces as a checksum failure before we touch the deflate body).
#[test]
fn zlib_decoder_fdict_with_wrong_dictionary_errors_checksum_mismatch() {
    let encoded = hex("78f981ac10482bc1a238b3182204569c9887a2431100c4ce11cb");

    let dec = Decoder::with_config(DecoderConfig {
        dictionary: b"definitely not the right dictionary".to_vec(),
    });
    let err = drain_full(dec, &encoded).unwrap_err();
    assert!(matches!(err, Error::ChecksumMismatch), "got {err:?}");
}

/// FDICT=0 streams still decode normally even when a dictionary is
/// configured — the dictionary is held but only consulted when the
/// stream's FDICT bit is set.
#[test]
fn zlib_decoder_fdict0_ignores_configured_dictionary() {
    // Build a normal FDICT=0 stream by encoding "hello zlib" with our own
    // encoder.
    let plaintext = b"hello zlib, preset dict should be ignored when FDICT is 0";
    let mut enc = Encoder::new();
    let mut buf = vec![0u8; 256];
    let mut encoded = Vec::new();
    let mut consumed = 0;
    while consumed < plaintext.len() {
        let (p, _status) = enc.encode(&plaintext[consumed..], &mut buf).unwrap();
        encoded.extend_from_slice(&buf[..p.written]);
        consumed += p.consumed;
    }
    loop {
        let (p, status) = enc.finish(&mut buf).unwrap();
        encoded.extend_from_slice(&buf[..p.written]);
        if matches!(status, Status::StreamEnd) {
            break;
        }
    }

    // Decode with a (wrong) dictionary configured — should still succeed.
    let dec = Decoder::with_config(DecoderConfig {
        dictionary: b"unrelated bytes".to_vec(),
    });
    let out = drain_full(dec, &encoded).unwrap();
    assert_eq!(&out[..], plaintext);
}
