//! Streaming round-trip tests for the Brotli (RFC 7932) codec.
//!
//! Canonical v0.3 port: every call returns `(Progress, Status)` and the
//! loop dispatches on `Status` rather than inferring from byte counts.

#![cfg(feature = "brotli")]

use compcol::brotli::{Brotli, Decoder, Encoder, EncoderConfig};
use compcol::{Algorithm, Decoder as _, Encoder as _, Error, Status};

/// Parse a hex string into a byte vector.
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
/// the decoder; once all chunks are fed we keep calling `decode` with
/// an empty input slice to flush any output the decoder can still
/// produce from bits already buffered internally before calling `finish`.
fn decode_chunked(encoded: &[u8], in_chunk: usize, out_chunk: usize) -> Result<Vec<u8>, Error> {
    let mut dec = Decoder::new();
    decode_chunked_with(&mut dec, encoded, in_chunk, out_chunk)
}

/// Variant that drives a caller-supplied decoder — used by reset tests.
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

    // Drain any output the decoder can still produce from internally-
    // buffered bits.
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
fn name_is_brotli() {
    assert_eq!(<Brotli as Algorithm>::NAME, "brotli");
}

#[test]
fn default_config_is_quality_6() {
    assert_eq!(EncoderConfig::default().quality, 6);
}

// ─── decoder fixtures (reference outputs from the brotli CLI) ───────────

#[test]
fn decode_handcrafted_hello_uncompressed() {
    // Hand-built brotli stream containing a single uncompressed meta-block
    // carrying "hello", followed by the empty-last terminator.
    //
    // Bits in emission order (LSB-first within each byte):
    //
    //   WBITS=16        : 0
    //   ISLAST=0        : 0
    //   MNIBBLES=4 nib  : 0 0
    //   MLEN-1 = 4      : 0 0 1 0   0 0 0 0   0 0 0 0   0 0 0 0   (16 bits)
    //   ISUNCOMPRESSED  : 1
    //   pad to byte     : 0 0 0      (3 zero bits)
    //   payload         : "hello"
    //   ISLAST=1        : 1
    //   ISLASTEMPTY=1   : 1
    //   pad to byte     : 0 0 0 0 0 0
    let stream = hex("40001068656c6c6f03");
    let decoded = decode_chunked(&stream, 1024, 1024).unwrap();
    assert_eq!(decoded, b"hello");
}

#[test]
fn decode_rejects_unsupported_large_window_flag() {
    // The "large window" flag uses WBITS preamble: first bit = 1, next
    // 3 bits = 0, next 3 bits = 1. Packed LSB-first as bits 1,0,0,0,1,0,0
    // -> 0b00010001 = 0x11. Decoder must reject as Unsupported.
    let stream = [0x11u8];
    let mut dec = Decoder::new();
    let mut buf = [0u8; 32];
    let err = dec.decode(&stream, &mut buf).unwrap_err();
    assert_eq!(err, Error::Unsupported);
}

#[test]
fn decode_rejects_truncated_stream() {
    // Valid prefix: just WBITS + ISLAST=0 + half of MLEN. finish() should
    // report UnexpectedEnd.
    let stream = [0x00];
    let mut dec = Decoder::new();
    let mut buf = [0u8; 32];
    let _ = dec.decode(&stream, &mut buf).unwrap();
    let err = dec.finish(&mut buf).unwrap_err();
    assert_eq!(err, Error::UnexpectedEnd);
}

/// Bench of hand-picked reference streams generated with the brotli
/// CLI at default settings. Verifies the decoder copes with the full
/// range of features exercised by realistic input — complex prefix
/// codes, dictionary references with transforms, ring-buffer reuse,
/// and back-references.
#[test]
fn decode_fixed_reference_streams() {
    let cases: &[(&str, &[u8])] = &[
        // Eight 'a's, compressed (uses NSYM=1 literal+IC+dist trees).
        ("1f0700f825c242840000", b"aaaaaaaa"),
        // 14 'a's, also NSYM=1.
        ("1f0d00f825c2e2850000", b"aaaaaaaaaaaaaa"),
        // 40 'a's — block of repeated literals via back-refs.
        (
            "1f2700f825c2a28c00c0",
            b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ),
        // Phrase whose words "the", "time", "has", "come" all live in
        // the static dictionary — exercises the dictionary path with
        // transforms applied.
        (
            "1f1000f8a541c2d0e69428c0d429203d343906",
            b"the time has come",
        ),
        // Short phrase mixing literal and dict references.
        ("1f0d00f825004a9042ea16999e2200", b"this is a test"),
        // 43 chars: complex prefix codes for literal/IC trees + dict.
        (
            "1f2a00889c09364ea87737bc2433a34b9033bc427b4b90b23998c881435ba0f7dea7150ee90b4789ea0c1be0563506",
            b"the quick brown fox jumps over the lazy dog",
        ),
    ];
    for (hex_s, expected) in cases {
        let stream = hex(hex_s);
        let got = decode_chunked(&stream, 1024, 1024).unwrap();
        assert_eq!(
            got,
            *expected,
            "mismatch for stream {hex_s}: got {:?}",
            String::from_utf8_lossy(&got)
        );
    }
}

// ─── encoder round-trip tests at the default quality ────────────────────

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
fn round_trip_alphabet() {
    let input: Vec<u8> = (0..=255u8).collect();
    round_trip(&input);
}

#[test]
fn round_trip_streaming_one_byte() {
    let input = b"Hello, world! ".repeat(50);
    let mut enc = Encoder::new();
    let encoded = encode_chunked(&mut enc, &input, 1, 1);
    let decoded = decode_chunked(&encoded, 1, 1).unwrap();
    assert_eq!(decoded, input);
}

/// Build a ≤64 KiB corpus that genuinely separates quality levels.
///
/// The corpus is constructed so that:
///   1. The match finder fires often (lots of recurring 4-grams), keeping
///      the encoder's chain-walking path exercised. (Brotli's hash uses
///      4-byte keys.)
///   2. Long-but-distant matches exist that quality 1's tiny chain
///      budget walks past — only quality 11 finds them.
///
/// The corpus is deliberately capped just under 64 KiB so it fits in one
/// brotli meta-block — keeps the level-1 vs level-11 comparison clean of
/// chunk-boundary effects.
fn mixed_corpus() -> Vec<u8> {
    let mut state: u32 = 0xC0FFEE_u32;
    let mut out = Vec::with_capacity(64 * 1024);
    // Short alphabet → 4-gram hash buckets fill up fast.
    let alphabet = b"abcdef";
    // Long phrases placed periodically so back-references must walk
    // through many chained 4-grams before reaching them.
    let phrases: &[&[u8]] = &[
        b"the_quick_brown_fox_jumps_over_the_lazy_dog_xxxxxxxxxxxxxxxxxxxxxxxx",
        b"lorem_ipsum_dolor_sit_amet_consectetur_adipiscing_elit_yyyyyyyyyyyyyy",
        b"compcol_streaming_codec_test_corpus_for_level_differentiation_zzzzz",
    ];
    let mut phrase_idx = 0usize;
    while out.len() < 60 * 1024 {
        for _ in 0..64 {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            out.push(alphabet[(state as usize) % alphabet.len()]);
        }
        out.extend_from_slice(phrases[phrase_idx % phrases.len()]);
        phrase_idx += 1;
    }
    out.truncate(60 * 1024);
    out
}

#[test]
fn round_trip_mixed_corpus_default_quality() {
    let input = mixed_corpus();
    assert!(input.len() <= 64 * 1024);
    round_trip(&input);
}

// ─── quality-specific tests ─────────────────────────────────────────────

fn encode_at_quality(input: &[u8], quality: u8) -> Vec<u8> {
    let mut enc = Encoder::with_config(EncoderConfig { quality });
    encode_chunked(&mut enc, input, 4096, 4096)
}

#[test]
fn round_trip_quality_1() {
    // Empty, tiny, and a compressible block — all must roundtrip at the
    // fastest level.
    for input in [
        &b""[..],
        b"hello world",
        &b"abcabcabcabcabc".repeat(100)[..],
    ] {
        let mut enc = Encoder::with_config(EncoderConfig { quality: 1 });
        let encoded = encode_chunked(&mut enc, input, 4096, 4096);
        let decoded = decode_chunked(&encoded, 4096, 4096).unwrap();
        assert_eq!(decoded, input);
    }
}

#[test]
fn round_trip_quality_11() {
    for input in [
        &b""[..],
        b"hello world",
        &b"abcabcabcabcabc".repeat(100)[..],
    ] {
        let mut enc = Encoder::with_config(EncoderConfig { quality: 11 });
        let encoded = encode_chunked(&mut enc, input, 4096, 4096);
        let decoded = decode_chunked(&encoded, 4096, 4096).unwrap();
        assert_eq!(decoded, input);
    }
}

#[test]
fn quality_11_no_worse_than_quality_1_on_compressible_corpus() {
    // The whole point of having levels: max-effort must produce output
    // at least as small as min-effort on a realistic corpus.
    let input = mixed_corpus();
    let lo = encode_at_quality(&input, 1);
    let hi = encode_at_quality(&input, 11);
    assert!(
        hi.len() <= lo.len(),
        "quality 11 ({} bytes) was bigger than quality 1 ({} bytes)",
        hi.len(),
        lo.len(),
    );
    // Sanity: both must roundtrip.
    assert_eq!(decode_chunked(&lo, 4096, 4096).unwrap(), input);
    assert_eq!(decode_chunked(&hi, 4096, 4096).unwrap(), input);
}

#[test]
fn quality_1_does_less_work_than_quality_11() {
    // On a corpus designed to defeat low chain budgets, quality 1 must
    // be strictly larger than quality 11 — same idea as deflate's
    // level_1_does_less_work_than_level_9 test.
    let input = mixed_corpus();
    let lo = encode_at_quality(&input, 1);
    let hi = encode_at_quality(&input, 11);
    assert!(
        lo.len() > hi.len(),
        "quality 1 did not produce a measurably larger output: lo={} hi={}",
        lo.len(),
        hi.len(),
    );
    // And both roundtrip.
    assert_eq!(decode_chunked(&lo, 4096, 4096).unwrap(), input);
    assert_eq!(decode_chunked(&hi, 4096, 4096).unwrap(), input);
}

#[test]
fn out_of_range_quality_is_clamped() {
    // Quality 250 should be clamped to 11 and still produce a valid
    // stream — we don't expose a fallible constructor.
    let input = b"the rain in spain falls mainly on the plain";
    let mut enc_lo = Encoder::with_config(EncoderConfig { quality: 0 });
    let enc_lo_out = encode_chunked(&mut enc_lo, input, 4096, 4096);
    assert_eq!(decode_chunked(&enc_lo_out, 4096, 4096).unwrap(), input);
    let mut enc_hi = Encoder::with_config(EncoderConfig { quality: 250 });
    let enc_hi_out = encode_chunked(&mut enc_hi, input, 4096, 4096);
    assert_eq!(decode_chunked(&enc_hi_out, 4096, 4096).unwrap(), input);
}

// ─── reset / reuse ──────────────────────────────────────────────────────

#[test]
fn reset_preserves_quality_and_allows_reuse() {
    let input_a = b"alpha alpha alpha alpha alpha".as_slice();
    let input_b = b"bravo bravo bravo bravo bravo".as_slice();

    let mut enc = Encoder::with_config(EncoderConfig { quality: 11 });
    let encoded_a = encode_chunked(&mut enc, input_a, 4096, 4096);
    enc.reset();
    let encoded_b = encode_chunked(&mut enc, input_b, 4096, 4096);

    assert_eq!(decode_chunked(&encoded_a, 4096, 4096).unwrap(), input_a);
    assert_eq!(decode_chunked(&encoded_b, 4096, 4096).unwrap(), input_b);

    // After reset, an encoder configured at quality 11 should still be
    // at quality 11. Compare with a fresh quality-11 encoder.
    let mut fresh = Encoder::with_config(EncoderConfig { quality: 11 });
    let fresh_b = encode_chunked(&mut fresh, input_b, 4096, 4096);
    assert_eq!(encoded_b, fresh_b, "reset must preserve quality");
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

// ─── algorithm-trait entry points ───────────────────────────────────────

#[test]
fn algorithm_encoder_decoder_round_trip() {
    let mut enc = <Brotli as Algorithm>::encoder();
    let mut dec = <Brotli as Algorithm>::decoder();
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
    let input = mixed_corpus();
    let mut enc_lo = <Brotli as Algorithm>::encoder_with(EncoderConfig { quality: 1 });
    let mut enc_hi = <Brotli as Algorithm>::encoder_with(EncoderConfig { quality: 11 });
    let lo = encode_chunked(&mut enc_lo, &input, 4096, 4096);
    let hi = encode_chunked(&mut enc_hi, &input, 4096, 4096);
    assert!(
        hi.len() <= lo.len(),
        "encoder_with(quality=11) was bigger than encoder_with(quality=1)"
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
        assert!(factory::encoder_by_name("brotli").is_some());
        assert!(factory::decoder_by_name("brotli").is_some());
    }

    #[test]
    fn names_contains_brotli() {
        assert!(factory::names().contains(&"brotli"));
    }

    #[test]
    fn boxed_round_trip() {
        let mut enc = factory::encoder_by_name("brotli").unwrap();
        let mut dec = factory::decoder_by_name("brotli").unwrap();
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

// ─── large-input round-trip regression ────────────────────────────────
//
// Locks in the fix for the long-standing "fails above 128 KiB" report.
// The actual bug turned out to live in the *decoder*'s `raw_finish`:
// when the caller's output buffer filled mid-stream, `raw_decode`
// returned early with meta-blocks still pending in `self.raw`, and
// `raw_finish` then gave up immediately instead of draining and
// processing them. Now finish loops the drain-and-process pair until
// either the stream ends or output fills again.

#[test]
fn encoder_above_128kib() {
    // 131 072 bytes — one byte past the 128 KiB threshold called out in
    // the original report. Used to fail; must round-trip now.
    let input: Vec<u8> = (0..131_072).map(|i| (i % 251) as u8).collect();
    let mut enc = Encoder::new();
    let encoded = encode_chunked(&mut enc, &input, 4096, 4096);
    let decoded = decode_chunked(&encoded, 4096, 4096).unwrap();
    assert_eq!(decoded, input);
}

#[test]
fn roundtrip_above_old_buggy_size_with_full_buffer() {
    // Regression for the >256 KiB decoder bug: when the caller's output
    // buffer fills mid-stream, raw_decode returns early with bytes still
    // pending in self.raw. The driver naturally calls finish next; finish
    // used to give up immediately if state != Done, leaving every pending
    // meta-block undecoded. Now finish processes pending meta-blocks
    // until either the stream ends or the caller's buffer fills.
    use compcol::brotli;
    use compcol::{Decoder as _, Encoder as _, Status};

    for &n in &[262_145usize, 1_000_000, 4 * 1024 * 1024] {
        let input: Vec<u8> = (0..n)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 8) as u8)
            .collect();
        let mut enc = brotli::Encoder::new();
        let mut compressed = Vec::new();
        let mut buf = vec![0u8; 1 << 18];
        let mut consumed = 0;
        while consumed < input.len() {
            let (p, _) = enc.encode(&input[consumed..], &mut buf).unwrap();
            compressed.extend_from_slice(&buf[..p.written]);
            consumed += p.consumed;
            if p.consumed == 0 && p.written == 0 {
                break;
            }
        }
        loop {
            let (p, s) = enc.finish(&mut buf).unwrap();
            compressed.extend_from_slice(&buf[..p.written]);
            if matches!(s, Status::StreamEnd) {
                break;
            }
        }
        let mut dec = brotli::Decoder::new();
        let mut out = Vec::new();
        let mut c2 = 0;
        loop {
            let (p, s) = dec.decode(&compressed[c2..], &mut buf).unwrap();
            out.extend_from_slice(&buf[..p.written]);
            c2 += p.consumed;
            if matches!(s, Status::StreamEnd) {
                break;
            }
            if matches!(s, Status::InputEmpty) && c2 == compressed.len() {
                break;
            }
            if p.consumed == 0 && p.written == 0 {
                break;
            }
        }
        loop {
            let (p, s) = dec.finish(&mut buf).unwrap();
            out.extend_from_slice(&buf[..p.written]);
            if matches!(s, Status::StreamEnd) {
                break;
            }
        }
        assert_eq!(out.len(), input.len(), "n={n}");
        assert_eq!(out, input, "n={n}");
    }
}
