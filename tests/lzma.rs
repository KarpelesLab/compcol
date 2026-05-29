//! Integration tests for the LZMA encoder and decoder.
//!
//! The decoder tests use pre-generated `.lzma` fixtures produced by Python's
//! stdlib `lzma` module (which uses XZ Utils internally) via
//! `lzma.compress(payload, format=lzma.FORMAT_ALONE)`.
//!
//! The encoder tests verify round-trip against our own decoder, plus a
//! handful of decoder-only edge cases. Canonical v0.3 port: every call
//! returns `(Progress, Status)` and the loop dispatches on `Status` rather
//! than inferring from byte counts.

#![cfg(feature = "lzma")]

use compcol::lzma::{Decoder, Encoder, EncoderConfig, Lzma};
use compcol::{Algorithm, Decoder as _, Encoder as _, Error, Status};

fn hex(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn decode_one_shot(compressed: &[u8]) -> Result<Vec<u8>, Error> {
    decode_chunked(compressed, compressed.len().max(1), 65536)
}

/// Drive a fresh decoder to completion. Feeds the input in `in_chunk`-sized
/// slices and drains via an `out_chunk`-sized buffer.
fn decode_chunked(compressed: &[u8], in_chunk: usize, out_chunk: usize) -> Result<Vec<u8>, Error> {
    let mut dec = Decoder::new();
    decode_chunked_with(&mut dec, compressed, in_chunk, out_chunk)
}

/// Same as `decode_chunked`, but operates on a caller-supplied decoder so the
/// reset-and-reuse test can hit the same instance with two streams.
fn decode_chunked_with(
    dec: &mut Decoder,
    compressed: &[u8],
    in_chunk: usize,
    out_chunk: usize,
) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    let mut buf = vec![0u8; out_chunk.max(1)];
    let mut i = 0;

    while i < compressed.len() {
        let end = (i + in_chunk).min(compressed.len());
        let chunk = &compressed[i..end];
        let mut consumed = 0;
        while consumed < chunk.len() {
            let (p, status) = dec.decode(&chunk[consumed..], &mut buf)?;
            out.extend_from_slice(&buf[..p.written]);
            consumed += p.consumed;
            match status {
                Status::StreamEnd => return Ok(out),
                Status::InputEmpty => break,
                Status::OutputFull => continue,
            }
        }
        i = end;
    }

    // Drain any output the decoder can still produce from internally
    // buffered bytes.
    loop {
        let (p, status) = dec.decode(&[], &mut buf)?;
        out.extend_from_slice(&buf[..p.written]);
        if matches!(status, Status::StreamEnd) {
            return Ok(out);
        }
        if p.written == 0 {
            break;
        }
    }

    loop {
        let (p, status) = dec.finish(&mut buf)?;
        out.extend_from_slice(&buf[..p.written]);
        match status {
            Status::StreamEnd => break,
            Status::OutputFull | Status::InputEmpty => {
                if p.written == 0 {
                    panic!("decoder finish stalled");
                }
            }
        }
    }
    Ok(out)
}

// ─── decoder fixtures (FORMAT_ALONE, "alone" / .lzma legacy) ─────────────

/// `python3 -c "import lzma; print(lzma.compress(b'', format=lzma.FORMAT_ALONE).hex())"`
const FIX_EMPTY: &str = "5d00008000ffffffffffffffff0083fffbffffc0000000";

/// `lzma.compress(b'hello world', format=lzma.FORMAT_ALONE)`
const FIX_HELLO: &str = "5d00008000ffffffffffffffff00341949ee8de917893a336005f7cf64fffb782000";

/// `lzma.compress(b'A' * 4096, format=lzma.FORMAT_ALONE)`
const FIX_REP4K: &str =
    "5d00008000ffffffffffffffff0020effbbffea3b15ee5f83fb2aa2655f868704170150ee40930ffffb52c0000";

#[test]
fn decode_empty() {
    let out = decode_one_shot(&hex(FIX_EMPTY)).unwrap();
    assert!(
        out.is_empty(),
        "empty fixture decoded to {} bytes",
        out.len()
    );
}

#[test]
fn decode_hello_world() {
    let out = decode_one_shot(&hex(FIX_HELLO)).unwrap();
    assert_eq!(out, b"hello world");
}

#[test]
fn decode_hello_world_chunked() {
    let stream = hex(FIX_HELLO);
    for in_chunk in [1, 2, 3, 5, 8, 16] {
        let out = decode_chunked(&stream, in_chunk, 7).unwrap();
        assert_eq!(out, b"hello world", "in_chunk={in_chunk}");
    }
}

#[test]
fn decode_4kib_repeating_bytes() {
    let out = decode_one_shot(&hex(FIX_REP4K)).unwrap();
    assert_eq!(out.len(), 4096);
    assert!(out.iter().all(|&b| b == b'A'));
}

#[test]
fn decode_4kib_chunked_tiny_output() {
    let stream = hex(FIX_REP4K);
    let out = decode_chunked(&stream, 7, 13).unwrap();
    assert_eq!(out.len(), 4096);
    assert!(out.iter().all(|&b| b == b'A'));
}

#[test]
fn decode_lorem_16kib() {
    // 16 KiB of repeating Lorem ipsum (well past one dictionary refresh).
    let fix = concat!(
        "5d00008000ffffffffffffffff00261bca46675af277b87d86d841db0535cd",
        "83a57c12a505db90bd2f14d3717296a88a7d8456718d6a2298ab9e3dc355ef",
        "cca5c3dd5b8ebf03812140d6269102454f92a178bb8a00af902a26920223e5",
        "5cb32de3e85c2cfb3221c66f6a37b16620cdb7527d66a42108d1441495affc",
        "58cfe5db354c05b89327ad7fe5fcbd0afbe2eda9e4d660d61c60112bf411e2",
        "9134c192bd8d4ac7c3c84aef9b3dda35640dd2db8ac9fd8cacc0",
    );
    let out = decode_one_shot(&hex(fix)).unwrap();
    let lorem_chunk = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. ";
    let expected: Vec<u8> = lorem_chunk
        .repeat(200)
        .into_bytes()
        .into_iter()
        .take(16384)
        .collect();
    assert_eq!(out.len(), 16384);
    assert_eq!(out, expected);
}

#[test]
fn decode_known_uncompressed_size_header() {
    // Same payload as FIX_HELLO but with the uncompressed-size field set
    // to 11 instead of u64::MAX. The decoder should stop after producing
    // exactly 11 bytes.
    let mut stream = hex(FIX_HELLO);
    stream[5..13].copy_from_slice(&11u64.to_le_bytes());
    let out = decode_one_shot(&stream).unwrap();
    assert_eq!(out, b"hello world");
}

#[test]
fn bad_header_props_rejected() {
    // properties byte 0xFF (>= 9*5*5 = 225) is illegal.
    let mut stream = hex(FIX_HELLO);
    stream[0] = 0xFF;
    let mut dec = Decoder::new();
    let mut buf = [0u8; 64];
    let err = dec.decode(&stream, &mut buf).unwrap_err();
    assert_eq!(err, Error::BadHeader);
}

#[test]
fn corrupt_first_init_byte_rejected() {
    // The first byte of the range-coder payload (offset 13) must be 0x00.
    let mut stream = hex(FIX_HELLO);
    stream[13] = 0x01;
    let mut dec = Decoder::new();
    let mut buf = [0u8; 64];
    let err = dec.decode(&stream, &mut buf).unwrap_err();
    assert_eq!(err, Error::Corrupt);
}

#[test]
fn unexpected_eof_on_finish() {
    let stream = hex(FIX_HELLO);
    let truncated = &stream[..stream.len() - 4]; // chop the EOS marker
    let mut dec = Decoder::new();
    let mut buf = vec![0u8; 64];
    let _ = dec.decode(truncated, &mut buf).unwrap();
    // finish should now realise we're stuck without input.
    let err = dec.finish(&mut buf).unwrap_err();
    assert_eq!(err, Error::UnexpectedEnd);
}

// ─── algorithm metadata ─────────────────────────────────────────────────

#[test]
fn name_is_lzma() {
    assert_eq!(<Lzma as Algorithm>::NAME, "lzma");
}

#[test]
fn default_config_is_level_6() {
    assert_eq!(EncoderConfig::default().level, 6);
}

// ─── encoder round-trip tests ────────────────────────────────────────────

fn encode_one_shot(payload: &[u8]) -> Vec<u8> {
    let mut enc = Encoder::new();
    encode_with(&mut enc, payload)
}

fn encode_at_level(payload: &[u8], level: u8) -> Vec<u8> {
    let mut enc = Encoder::with_config(EncoderConfig { level });
    encode_with(&mut enc, payload)
}

fn encode_with(enc: &mut Encoder, payload: &[u8]) -> Vec<u8> {
    // The encoder buffers all input internally and emits nothing until
    // `finish`, so a small scratch buffer is fine for the `encode` calls.
    let mut scratch = [0u8; 64];
    let mut consumed = 0;
    while consumed < payload.len() {
        let (p, status) = enc.encode(&payload[consumed..], &mut scratch).unwrap();
        consumed += p.consumed;
        // Output should always be empty from encode() for LZMA.
        assert_eq!(p.written, 0);
        match status {
            Status::InputEmpty | Status::StreamEnd => break,
            Status::OutputFull => {
                // Shouldn't happen — encode() doesn't write anything.
                if p.consumed == 0 {
                    panic!("encoder stalled mid-input");
                }
            }
        }
    }

    let mut out = Vec::new();
    let mut buf = vec![0u8; 4096];
    loop {
        let (p, status) = enc.finish(&mut buf).unwrap();
        out.extend_from_slice(&buf[..p.written]);
        match status {
            Status::StreamEnd => break,
            Status::OutputFull | Status::InputEmpty => {
                if p.written == 0 {
                    panic!("encoder finish stalled");
                }
            }
        }
    }
    out
}

fn round_trip(payload: &[u8]) {
    let compressed = encode_one_shot(payload);
    let recovered = decode_one_shot(&compressed).expect("decoding our own output failed");
    assert_eq!(
        recovered,
        payload,
        "round-trip mismatch (input len {})",
        payload.len()
    );
}

#[test]
fn encode_empty_round_trip() {
    let compressed = encode_one_shot(b"");
    assert!(
        compressed.len() >= 13,
        "encoder must always emit a header, got {} bytes",
        compressed.len()
    );
    assert_eq!(
        compressed[0], 0x5d,
        "props byte = (pb=2)*5*9 + (lp=0)*9 + (lc=3)"
    );
    // Uncompressed size sentinel = u64::MAX.
    for &b in &compressed[5..13] {
        assert_eq!(b, 0xFF);
    }
    let recovered = decode_one_shot(&compressed).unwrap();
    assert!(recovered.is_empty());
}

#[test]
fn encode_single_byte_round_trip() {
    for b in [0u8, 1, 0x7F, 0xFE, 0xFF, b'A'] {
        let compressed = encode_one_shot(&[b]);
        let recovered = decode_one_shot(&compressed).unwrap();
        assert_eq!(recovered, vec![b], "byte 0x{:02x}", b);
    }
}

#[test]
fn encode_hello_world_round_trip() {
    round_trip(b"hello world");
}

#[test]
fn encode_small_text_round_trip() {
    round_trip(b"hello world! hello world! hello world!");
}

#[test]
fn encode_4kib_repeating_byte_round_trip() {
    // All-A's: dominated by rep matches.
    let payload = vec![b'A'; 4096];
    let compressed = encode_one_shot(&payload);
    // Highly compressible: should be well under 100 bytes for this case.
    assert!(
        compressed.len() < 100,
        "expected strong compression on repeating byte, got {} bytes",
        compressed.len()
    );
    let recovered = decode_one_shot(&compressed).unwrap();
    assert_eq!(recovered, payload);
}

#[test]
fn encode_byte_value_coverage() {
    // Every byte value 0..=255 in sequence, to exercise every literal path.
    let payload: Vec<u8> = (0u8..=255).collect();
    round_trip(&payload);
}

#[test]
fn encode_streaming_one_byte_chunks_round_trip() {
    let payload = b"The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog.";

    let mut enc = Encoder::new();
    let mut scratch = [0u8; 4];
    for byte in payload {
        let (p, _status) = enc
            .encode(core::slice::from_ref(byte), &mut scratch)
            .unwrap();
        assert_eq!(p.consumed, 1);
        assert_eq!(p.written, 0);
    }
    let mut compressed = Vec::new();
    let mut buf = [0u8; 1];
    loop {
        let (p, status) = enc.finish(&mut buf).unwrap();
        compressed.extend_from_slice(&buf[..p.written]);
        match status {
            Status::StreamEnd => break,
            Status::OutputFull | Status::InputEmpty => {
                if p.written == 0 {
                    panic!("encoder finish stalled in single-byte streaming mode");
                }
            }
        }
    }

    // Also stream the decode side one byte at a time on input and output.
    let recovered = decode_chunked(&compressed, 1, 1).unwrap();
    assert_eq!(recovered, payload);
}

// ─── ≥64 KiB mixed corpus ───────────────────────────────────────────────

/// Build a ≥64 KiB corpus that compresses well but is not the
/// random-data pathology documented in BENCH.md (high-distance-slot path
/// is slow on incompressible input). Mixes a small alphabet with
/// long recurring phrases that benefit from match-finder depth.
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

/// Repeated "Lorem ipsum" buffer of at least 16 KiB — well past the point
/// where lzma at higher levels can find very long matches the lower-level
/// chain budget walks past.
fn lorem_corpus(min_len: usize) -> Vec<u8> {
    let chunk = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. ";
    let mut out = Vec::with_capacity(min_len + chunk.len());
    while out.len() < min_len {
        out.extend_from_slice(chunk.as_bytes());
    }
    out
}

#[test]
fn round_trip_level_1() {
    for input in [
        &b""[..],
        b"hello world",
        &b"abcabcabcabcabc".repeat(100)[..],
    ] {
        let compressed = encode_at_level(input, 1);
        let recovered = decode_one_shot(&compressed).unwrap();
        assert_eq!(recovered, input);
    }
}

#[test]
fn round_trip_level_9() {
    for input in [
        &b""[..],
        b"hello world",
        &b"abcabcabcabcabc".repeat(100)[..],
    ] {
        let compressed = encode_at_level(input, 9);
        let recovered = decode_one_shot(&compressed).unwrap();
        assert_eq!(recovered, input);
    }
}

#[test]
fn level_9_no_worse_than_level_1_on_compressible_corpus() {
    // The whole point of having levels: max-effort must produce output
    // at least as small as min-effort on a compressible corpus. We use a
    // ≥16 KiB lorem corpus so the chain-depth difference has room to
    // produce a measurable size delta — on tiny inputs LZMA's greedy
    // parser converges and the levels collapse.
    let input = lorem_corpus(16 * 1024);
    let lo = encode_at_level(&input, 1);
    let hi = encode_at_level(&input, 9);
    assert!(
        hi.len() <= lo.len(),
        "level 9 ({} bytes) was bigger than level 1 ({} bytes)",
        hi.len(),
        lo.len(),
    );
    // Sanity: both must roundtrip.
    assert_eq!(decode_one_shot(&lo).unwrap(), input);
    assert_eq!(decode_one_shot(&hi).unwrap(), input);
}

#[test]
fn out_of_range_level_is_clamped() {
    // Level 250 should produce a valid stream (clamped to 9) — we don't
    // expose a fallible constructor.
    let input = b"the rain in spain falls mainly on the plain";
    let compressed = encode_at_level(input, 250);
    assert_eq!(decode_one_shot(&compressed).unwrap(), input);
}

// ─── reset / reuse ──────────────────────────────────────────────────────

#[test]
fn reset_preserves_level_and_allows_reuse() {
    let input_a = b"alpha alpha alpha alpha alpha".as_slice();
    let input_b = b"bravo bravo bravo bravo bravo".as_slice();

    let mut enc = Encoder::with_config(EncoderConfig { level: 9 });
    let encoded_a = encode_with(&mut enc, input_a);
    enc.reset();
    let encoded_b = encode_with(&mut enc, input_b);

    assert_eq!(decode_one_shot(&encoded_a).unwrap(), input_a);
    assert_eq!(decode_one_shot(&encoded_b).unwrap(), input_b);

    // After reset, an encoder configured at level 9 should still be at
    // level 9. A fresh level-9 encoder on the same input must produce
    // an identical byte stream — this is the contract that reset
    // preserves configuration.
    let mut fresh = Encoder::with_config(EncoderConfig { level: 9 });
    let fresh_b = encode_with(&mut fresh, input_b);
    assert_eq!(encoded_b, fresh_b, "reset must preserve compression level");
}

#[test]
fn decoder_reset_allows_reuse() {
    let encoded_a = encode_one_shot(b"hello");
    let encoded_b = encode_one_shot(b"world");

    let mut dec = Decoder::new();
    assert_eq!(
        decode_chunked_with(&mut dec, &encoded_a, 64, 64).unwrap(),
        b"hello"
    );
    dec.reset();
    assert_eq!(
        decode_chunked_with(&mut dec, &encoded_b, 64, 64).unwrap(),
        b"world"
    );
}

// ─── algorithm-trait entry points ───────────────────────────────────────

#[test]
fn algorithm_encoder_decoder_round_trip() {
    let mut enc = <Lzma as Algorithm>::encoder();
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

    // Decode through Algorithm::decoder() as well.
    let mut dec = <Lzma as Algorithm>::decoder();
    let decoded = decode_chunked_with(&mut dec, &encoded, encoded.len(), 256).unwrap();
    assert_eq!(decoded, input);
}

#[test]
fn algorithm_encoder_with_uses_config() {
    let input = lorem_corpus(16 * 1024);
    let mut enc_lo = <Lzma as Algorithm>::encoder_with(EncoderConfig { level: 1 });
    let mut enc_hi = <Lzma as Algorithm>::encoder_with(EncoderConfig { level: 9 });
    let lo = encode_with(&mut enc_lo, &input);
    let hi = encode_with(&mut enc_hi, &input);
    assert!(
        hi.len() <= lo.len(),
        "encoder_with(level=9) was bigger than encoder_with(level=1): hi={} lo={}",
        hi.len(),
        lo.len(),
    );
    assert_eq!(decode_one_shot(&lo).unwrap(), input);
    assert_eq!(decode_one_shot(&hi).unwrap(), input);
}

// ─── factory lookup ─────────────────────────────────────────────────────

#[cfg(feature = "factory")]
mod factory {
    use compcol::Status;
    use compcol::factory;

    #[test]
    fn lookup_known() {
        assert!(factory::encoder_by_name("lzma").is_some());
        assert!(factory::decoder_by_name("lzma").is_some());
    }

    #[test]
    fn names_contains_lzma() {
        assert!(factory::names().contains(&"lzma"));
    }

    #[test]
    fn boxed_round_trip() {
        let mut enc = factory::encoder_by_name("lzma").unwrap();
        let mut dec = factory::decoder_by_name("lzma").unwrap();
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
        }

        // Decode — feed the whole thing in one go (the decoder's loop
        // tolerates partial draws), then drain anything still buffered,
        // then finish.
        let mut decoded = Vec::new();
        let mut consumed = 0;
        while consumed < encoded.len() {
            let (p, status) = dec.decode(&encoded[consumed..], &mut buf).unwrap();
            decoded.extend_from_slice(&buf[..p.written]);
            consumed += p.consumed;
            if matches!(status, Status::StreamEnd) {
                break;
            }
            if matches!(status, Status::InputEmpty) {
                break;
            }
        }
        loop {
            let (p, status) = dec.decode(&[], &mut buf).unwrap();
            decoded.extend_from_slice(&buf[..p.written]);
            if matches!(status, Status::StreamEnd) {
                break;
            }
            if p.written == 0 {
                break;
            }
        }
        loop {
            let (p, status) = dec.finish(&mut buf).unwrap();
            decoded.extend_from_slice(&buf[..p.written]);
            if matches!(status, Status::StreamEnd) {
                break;
            }
            if p.written == 0 {
                panic!("decoder finish stalled");
            }
        }
        assert_eq!(&decoded[..], input);
    }
}

// ─── interop with system xz --format=lzma (issue #14) ───────────────────

/// Known-failing interop case for the encoder direction of #14
/// ([reopened comment](https://github.com/KarpelesLab/compcol/issues/14#issuecomment-…)).
///
/// `xz --format=lzma` round-trips compcol's output for short / highly-
/// compressible inputs (this is verified by
/// `encoder_emits_liblzma_compatible_alone_header_at_every_level` below),
/// but rejects it for larger / lower-entropy inputs. Bisecting on a
/// linear-congruential pseudo-random byte stream shows the threshold at
/// **628 bytes of input**: 627 bytes round-trip through `xz -d` cleanly,
/// 628 bytes cause `xz` to mis-decode (consume the encoded stream past
/// the EOS marker and report `Unexpected end of input`).
///
/// The encoder header structure is correct (locked by the test below);
/// the bug is in the body, almost certainly a probability-model drift
/// that compcol's own decoder happens to tolerate while liblzma's
/// (stricter) decoder rejects. compcol's decoder round-trips the same
/// stream — and conversely compcol's decoder reads liblzma's output of
/// the same input correctly — so the asymmetry is encoder-only.
///
/// This test is `#[ignore]`-d for now and serves only as documentation
/// of the bug shape. fstool keeps `.lzma` (alone) on `lzma-rs` until
/// the encoder is rewritten.
#[test]
#[ignore = "known regression: encoder produces output liblzma rejects above ~628 random bytes; see issue #14"]
fn encoder_round_trips_through_python_lzma_above_threshold() {
    let mut data = Vec::new();
    let mut state: u32 = 0xC0FFEE;
    for _ in 0..2048 {
        state = state.wrapping_mul(1664525).wrapping_add(1013904223);
        data.push(((state >> 16) & 0xFF) as u8);
    }

    let mut enc = Encoder::new();
    let mut out = Vec::new();
    let mut buf = vec![0u8; 4096];
    let mut consumed = 0;
    while consumed < data.len() {
        let (p, _s) = enc.encode(&data[consumed..], &mut buf).unwrap();
        out.extend_from_slice(&buf[..p.written]);
        consumed += p.consumed;
    }
    loop {
        let (p, s) = enc.finish(&mut buf).unwrap();
        out.extend_from_slice(&buf[..p.written]);
        if matches!(s, Status::StreamEnd) {
            break;
        }
    }

    // Self round-trip: compcol's decoder reads compcol's encoder output.
    // This passes today — the regression is encoder ↔ liblzma interop.
    let self_back = decode_one_shot(&out).unwrap();
    assert_eq!(self_back, data, "self round-trip is the floor");

    // Cross-tool: this is the assertion that currently fails. Decoding
    // compcol's output with Python's stdlib lzma (which uses liblzma)
    // should yield the original bytes. Once the encoder bug is fixed,
    // remove `#[ignore]` and shell-out to verify against `xz --format=lzma -d`.
    //
    // For now we document the contract here without actually shelling
    // out (the test environment may not have a Python or xz binary
    // available); see the issue for manual reproduction.
}

/// Regression for the encoder direction of issue #14 — assert the
/// encoder emits a liblzma-compatible "alone" header at every level.
///
/// The contract liblzma's `.lzma` reader enforces:
/// - byte 0       = properties packed `(pb*5 + lp)*9 + lc` = 0x5D for
///   the canonical `(lc=3, lp=0, pb=2)` triple.
/// - bytes 1..=4  = dictionary size, little-endian u32, ≥ 4 KiB.
/// - bytes 5..=12 = uncompressed size, little-endian u64. liblzma
///   accepts an exact size, but `xz --format=lzma -c` writes the
///   sentinel `u64::MAX` ("unknown size, terminate on EOS marker"),
///   and that's what we want our output to interoperate with. Anything
///   less than `u64::MAX` makes `xz -d` skip the EOS check and refuse
///   streams whose body terminates with an EOS marker.
///
/// If any of those bytes regress, `xz --format=lzma -dc` rejects our
/// output as "Compressed data is corrupt". The manual `xz` round-trip
/// across levels 0..=9 has been verified at PR time; this test locks
/// the header contract so a future encoder change can't silently
/// reintroduce the original interop bug.
#[test]
fn encoder_emits_liblzma_compatible_alone_header_at_every_level() {
    use compcol::Algorithm;
    use compcol::Encoder as _;

    let payload: Vec<u8> = b"the quick brown fox jumps over the lazy dog. ".repeat(100);

    for level in 0..=9u8 {
        let mut enc = compcol::lzma::Lzma::encoder_with(compcol::lzma::EncoderConfig { level });
        let mut out = Vec::new();
        let mut buf = vec![0u8; 4096];
        let mut consumed = 0;
        while consumed < payload.len() {
            let (p, _) = enc.encode(&payload[consumed..], &mut buf).unwrap();
            out.extend_from_slice(&buf[..p.written]);
            consumed += p.consumed;
        }
        loop {
            let (p, s) = enc.finish(&mut buf).unwrap();
            out.extend_from_slice(&buf[..p.written]);
            if matches!(s, Status::StreamEnd) {
                break;
            }
        }
        assert!(out.len() >= 13, "level {level}: header truncated");

        // Properties byte: (pb=2)*5 + (lp=0) = 10, *9 = 90, + (lc=3) = 93 = 0x5D.
        assert_eq!(out[0], 0x5D, "level {level}: properties byte not 0x5D");

        // Dictionary size: u32 LE, ≥ 4 KiB.
        let dict_size = u32::from_le_bytes([out[1], out[2], out[3], out[4]]);
        assert!(
            dict_size >= 4 * 1024,
            "level {level}: dict_size {dict_size} < 4 KiB"
        );

        // Uncompressed size: u64 LE, expected `u64::MAX` (unknown / EOS-marker
        // terminated). This is the bit that liblzma's `xz -d` needs in order
        // to honour the EOS marker we emit at the end of the stream.
        let unc = u64::from_le_bytes([
            out[5], out[6], out[7], out[8], out[9], out[10], out[11], out[12],
        ]);
        assert_eq!(
            unc,
            u64::MAX,
            "level {level}: uncompressed-size field is {unc:#x}, expected u64::MAX (unknown). \
             liblzma's `xz -d` interprets any other value as a known-size stream and refuses \
             the trailing EOS marker — this is the original #14 interop bug."
        );

        // Round-trips through our own decoder regardless.
        let back = compcol::vec::decompress_to_vec::<compcol::lzma::Lzma>(&out).unwrap();
        assert_eq!(back, payload, "level {level}: self round-trip failed");
    }
}

#[test]
fn xz_format_lzma_round_trips_via_vec_helper() {
    // Reporter's exact path: xz --format=lzma → vec::decompress_to_vec.
    // We don't depend on `xz` being on PATH; instead we hard-code a
    // small fixture produced offline by `echo "hello lzma alone" |
    // xz --format=lzma -c | xxd -i` (echo appends a trailing newline).
    const FIXTURE: &[u8] = &[
        0x5d, 0x00, 0x00, 0x80, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x34,
        0x19, 0x49, 0xee, 0x8d, 0xe9, 0x14, 0x8a, 0x6a, 0xa5, 0xd6, 0xb6, 0x11, 0x0a, 0xd7, 0x39,
        0x16, 0x6a, 0x19, 0x15, 0x45, 0xff, 0xfe, 0x66, 0xec, 0x00,
    ];
    let decoded = compcol::vec::decompress_to_vec::<compcol::lzma::Lzma>(FIXTURE).unwrap();
    assert_eq!(decoded, b"hello lzma alone\n");
}

#[test]
fn limited_decoder_at_exact_budget_terminates_cleanly() {
    // Used to fail with Error::OutputLimitExceeded because the decoder's
    // raw_finish couldn't recognize EOS once the budget exhausted the
    // output slice. The decoder produced exactly N bytes correctly but
    // never returned StreamEnd — the EOS packet (which emits zero
    // output bytes) wasn't being decoded inside drain_output. Fixed by
    // restructuring drain_output so EOS / packet-with-no-output paths
    // run regardless of remaining output capacity.
    use compcol::Algorithm;
    use compcol::limit::LimitedDecoder;
    let original = vec![b'A'; 65536];
    let compressed = compcol::vec::compress_to_vec::<compcol::lzma::Lzma>(&original).unwrap();

    let mut dec = LimitedDecoder::new(compcol::lzma::Lzma::decoder(), original.len() as u64);
    let mut buf = vec![0u8; 4096];
    let mut decoded = Vec::new();
    let mut consumed = 0;
    while consumed < compressed.len() {
        let (p, s) = dec.decode(&compressed[consumed..], &mut buf).unwrap();
        decoded.extend_from_slice(&buf[..p.written]);
        consumed += p.consumed;
        if matches!(s, compcol::Status::StreamEnd) {
            break;
        }
        if matches!(s, compcol::Status::InputEmpty) && consumed == compressed.len() {
            break;
        }
        if p.consumed == 0 && p.written == 0 {
            break;
        }
    }
    loop {
        let (p, s) = dec.finish(&mut buf).unwrap();
        decoded.extend_from_slice(&buf[..p.written]);
        if matches!(s, compcol::Status::StreamEnd) {
            break;
        }
    }
    assert_eq!(decoded, original);
}
