//! Streaming round-trip tests for the gzip codec.
//!
//! Canonical v0.3 port: every call returns `(Progress, Status)` and the
//! loop dispatches on `Status` rather than inferring from byte counts.

#![cfg(feature = "gzip")]

use compcol::gzip::{Decoder, Encoder, EncoderConfig, Gzip};
use compcol::{Algorithm, Decoder as _, Encoder as _, Error, Status};

/// Parse a hex string into a byte vector — used by the decoder fixtures
/// produced from python3 gzip / hand-built reference streams.
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
                    panic!("gzip encoder finish stalled");
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

    // The inner deflate decoder can hold up to 7+ compressed bytes in its
    // bit reader. Drain any output those buffered bits can still produce
    // by calling decode with an empty slice until it stops making progress.
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
                    panic!("gzip decoder finish stalled");
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
    // Sanity-check the gzip framing.
    assert!(encoded.len() >= 18, "encoded too short: {}", encoded.len());
    assert_eq!(encoded[0], 0x1F, "ID1");
    assert_eq!(encoded[1], 0x8B, "ID2");
    assert_eq!(encoded[2], 0x08, "CM=deflate");
    let decoded = decode_chunked(&encoded, 4096, 4096).unwrap();
    assert_eq!(decoded, input, "round-trip mismatch len {}", input.len());
}

// ─── algorithm metadata ─────────────────────────────────────────────────

#[test]
fn name_is_gzip() {
    assert_eq!(<Gzip as Algorithm>::NAME, "gzip");
}

#[test]
fn default_config_is_level_6() {
    assert_eq!(EncoderConfig::default().level, 6);
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
fn round_trip_short() {
    round_trip(b"Hello, gzip!");
}

#[test]
fn round_trip_repeated() {
    round_trip(&b"foo bar baz ".repeat(100));
}

#[test]
fn round_trip_long_zeros() {
    let input = vec![0u8; 8192];
    let encoded = encode_all(&input);
    assert!(
        encoded.len() < 200,
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

/// Build a ≥64 KiB mixed-content corpus: pseudo-random short-alphabet bytes
/// interleaved with long recurring phrases, the same shape `deflate`'s
/// canonical test uses. Compresses well at higher levels, ensuring the
/// CRC-32 path is exercised on bulk data.
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
    // Same as deflate's canonical level-discrimination test: mixed_corpus
    // is constructed to defeat level 1's tiny chain budget so the encoded
    // size must be strictly larger than at level 9.
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
fn xfl_byte_reflects_level() {
    // RFC 1952 §2.3.1: XFL=2 means "max compression", XFL=4 means "fastest",
    // anything else (including the default level 6) is XFL=0.
    let lvl1 = encode_at_level(b"abc", 1);
    let lvl6 = encode_at_level(b"abc", 6);
    let lvl9 = encode_at_level(b"abc", 9);
    // XFL is byte offset 8 in the fixed header.
    assert_eq!(lvl1[8], 4, "level 1 should set XFL=4");
    assert_eq!(lvl6[8], 0, "level 6 should set XFL=0");
    assert_eq!(lvl9[8], 2, "level 9 should set XFL=2");
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

    // After reset, the encoder should still be at level 9. Compare with a
    // fresh level-9 encoder on the same input — byte-for-byte equal.
    let mut fresh = Encoder::with_config(EncoderConfig { level: 9 });
    let fresh_b = encode_chunked(&mut fresh, input_b, 4096, 4096);
    assert_eq!(encoded_b, fresh_b, "reset must preserve compression level");
    // Sanity: the XFL byte after reset still reflects level 9.
    assert_eq!(encoded_b[8], 2);
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

// ─── decoder fixtures: optional header fields ───────────────────────────

#[test]
fn decode_reference_minimal_stream() {
    // `python3 -c "import gzip; print(gzip.compress(b'hello', compresslevel=6, mtime=0).hex())"`
    // FLG=0, OS=0xff (unknown), deflate "cb48cdc9c907", CRC=0x3610a686, ISIZE=5.
    let stream = hex("1f8b08000000000000ffcb48cdc9c9070086a6103605000000");
    let decoded = decode_chunked(&stream, 1024, 1024).unwrap();
    assert_eq!(decoded, b"hello");
}

#[test]
fn decode_with_fname_field() {
    // gzip stream of "hello" with FNAME = "test.txt" (FLG = 0x08).
    // CRC32 of "hello" = 0x3610a686 (LE = 86 a6 10 36)
    // ISIZE = 5 (LE = 05 00 00 00)
    let mut stream = vec![0x1F, 0x8B, 0x08, 0x08, 0, 0, 0, 0, 0, 0x03];
    stream.extend_from_slice(b"test.txt\0");
    stream.extend_from_slice(&hex("cb48cdc9c90700"));
    stream.extend_from_slice(&[0x86, 0xa6, 0x10, 0x36, 0x05, 0x00, 0x00, 0x00]);
    let decoded = decode_chunked(&stream, 1024, 1024).unwrap();
    assert_eq!(decoded, b"hello");
}

#[test]
fn decode_with_fextra_field() {
    // gzip stream of "hello" with an FEXTRA field of 4 bytes (FLG = 0x04).
    // XLEN = 4 (LE) followed by 4 bytes of arbitrary extra data, then deflate
    // + trailer for "hello".
    let mut stream = vec![0x1F, 0x8B, 0x08, 0x04, 0, 0, 0, 0, 0, 0x03];
    stream.extend_from_slice(&[0x04, 0x00]); // XLEN = 4
    stream.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]); // arbitrary extra data
    stream.extend_from_slice(&hex("cb48cdc9c90700"));
    stream.extend_from_slice(&[0x86, 0xa6, 0x10, 0x36, 0x05, 0x00, 0x00, 0x00]);
    let decoded = decode_chunked(&stream, 1024, 1024).unwrap();
    assert_eq!(decoded, b"hello");
}

#[test]
fn decode_with_fcomment_field() {
    // gzip stream of "hello" with FCOMMENT = "a comment" (FLG = 0x10).
    let mut stream = vec![0x1F, 0x8B, 0x08, 0x10, 0, 0, 0, 0, 0, 0x03];
    stream.extend_from_slice(b"a comment\0");
    stream.extend_from_slice(&hex("cb48cdc9c90700"));
    stream.extend_from_slice(&[0x86, 0xa6, 0x10, 0x36, 0x05, 0x00, 0x00, 0x00]);
    let decoded = decode_chunked(&stream, 1024, 1024).unwrap();
    assert_eq!(decoded, b"hello");
}

#[test]
fn decode_with_all_optional_fields() {
    // FEXTRA + FNAME + FCOMMENT all together (FLG = 0x1C).
    let mut stream = vec![0x1F, 0x8B, 0x08, 0x1C, 0, 0, 0, 0, 0, 0x03];
    stream.extend_from_slice(&[0x03, 0x00]); // XLEN = 3
    stream.extend_from_slice(&[1, 2, 3]);
    stream.extend_from_slice(b"name.txt\0");
    stream.extend_from_slice(b"some comment\0");
    stream.extend_from_slice(&hex("cb48cdc9c90700"));
    stream.extend_from_slice(&[0x86, 0xa6, 0x10, 0x36, 0x05, 0x00, 0x00, 0x00]);
    let decoded = decode_chunked(&stream, 1024, 1024).unwrap();
    assert_eq!(decoded, b"hello");
}

// ─── malformed-header rejection ─────────────────────────────────────────

#[test]
fn bad_magic_rejected() {
    let stream = hex("1f8c0800000000000003"); // ID2=0x8c instead of 0x8b
    let mut dec = Decoder::new();
    let mut buf = [0u8; 16];
    let err = dec.decode(&stream, &mut buf).unwrap_err();
    assert_eq!(err, Error::BadHeader);
}

#[test]
fn unsupported_method_rejected() {
    // CM=9 instead of 8 (deflate)
    let stream = hex("1f8b0900000000000003");
    let mut dec = Decoder::new();
    let mut buf = [0u8; 16];
    let err = dec.decode(&stream, &mut buf).unwrap_err();
    assert_eq!(err, Error::Unsupported);
}

#[test]
fn reserved_flag_rejected() {
    // Top bit of FLG (0x80) is reserved; setting it must be rejected.
    let stream = hex("1f8b0880000000000003");
    let mut dec = Decoder::new();
    let mut buf = [0u8; 16];
    let err = dec.decode(&stream, &mut buf).unwrap_err();
    assert_eq!(err, Error::Unsupported);
}

#[test]
fn corrupted_crc_rejected() {
    let input = b"some payload bytes";
    let mut encoded = encode_all(input);
    // Flip a bit in the CRC (4 bytes before ISIZE).
    let crc_offset = encoded.len() - 8;
    encoded[crc_offset] ^= 0x01;
    let err = decode_chunked(&encoded, 4096, 4096).unwrap_err();
    assert_eq!(err, Error::ChecksumMismatch);
}

#[test]
fn corrupted_isize_rejected() {
    let input = b"some payload bytes";
    let mut encoded = encode_all(input);
    // Flip a bit in ISIZE (last 4 bytes).
    let last = encoded.len() - 1;
    encoded[last] ^= 0x80;
    let err = decode_chunked(&encoded, 4096, 4096).unwrap_err();
    assert_eq!(err, Error::TrailerMismatch);
}

#[test]
fn truncated_stream_rejected() {
    // Truncate the encoded "hello" before the trailer arrives.
    let encoded = encode_all(b"hello world");
    let truncated = &encoded[..encoded.len() - 4];
    let err = decode_chunked(truncated, 4096, 4096).unwrap_err();
    assert_eq!(err, Error::UnexpectedEnd);
}

// ─── algorithm-trait entry points ───────────────────────────────────────

#[test]
fn algorithm_encoder_decoder_round_trip() {
    let mut enc = <Gzip as Algorithm>::encoder();
    let mut dec = <Gzip as Algorithm>::decoder();
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
    let input = b"abcabcabcabcabcabc".repeat(100);
    let mut enc_lo = <Gzip as Algorithm>::encoder_with(EncoderConfig { level: 1 });
    let mut enc_hi = <Gzip as Algorithm>::encoder_with(EncoderConfig { level: 9 });
    let lo = encode_chunked(&mut enc_lo, &input, 4096, 4096);
    let hi = encode_chunked(&mut enc_hi, &input, 4096, 4096);
    assert!(
        hi.len() <= lo.len(),
        "encoder_with(level=9) was bigger than encoder_with(level=1)"
    );
    assert_eq!(decode_chunked(&lo, 4096, 4096).unwrap(), input);
    assert_eq!(decode_chunked(&hi, 4096, 4096).unwrap(), input);
    // XFL still reflects the levels.
    assert_eq!(lo[8], 4);
    assert_eq!(hi[8], 2);
}

// ─── factory lookup ─────────────────────────────────────────────────────

#[cfg(feature = "factory")]
mod factory {
    use compcol::Status;
    use compcol::factory;

    #[test]
    fn lookup_known() {
        assert!(factory::encoder_by_name("gzip").is_some());
        assert!(factory::decoder_by_name("gzip").is_some());
    }

    #[test]
    fn names_contains_gzip() {
        assert!(factory::names().contains(&"gzip"));
    }

    #[test]
    fn boxed_round_trip() {
        let mut enc = factory::encoder_by_name("gzip").unwrap();
        let mut dec = factory::decoder_by_name("gzip").unwrap();
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

// ─── multi-member streams (RFC 1952 §2.2) ───────────────────────────────

#[test]
fn multi_member_stream_decodes_concatenated_members() {
    // Encode two separate payloads, concatenate, decode as one stream.
    let mut enc1 = Encoder::new();
    let a = encode_chunked(&mut enc1, b"hello, ", 32, 32);
    let mut enc2 = Encoder::new();
    let b = encode_chunked(&mut enc2, b"world!\n", 32, 32);

    let mut combined = Vec::new();
    combined.extend_from_slice(&a);
    combined.extend_from_slice(&b);

    let decoded = decode_chunked(&combined, 32, 32).unwrap();
    assert_eq!(decoded, b"hello, world!\n");
}

#[test]
fn multi_member_stream_with_three_members() {
    let mut all = Vec::new();
    let mut expected = Vec::new();
    for (i, payload) in [
        b"alpha\n".as_slice(),
        b"beta beta beta\n".as_slice(),
        b"gamma! and the rest...".as_slice(),
    ]
    .iter()
    .enumerate()
    {
        let mut enc = Encoder::new();
        let chunk_in = 16 + i * 7; // jitter chunking
        let chunk_out = 16 + i * 5;
        let bytes = encode_chunked(&mut enc, payload, chunk_in, chunk_out);
        all.extend_from_slice(&bytes);
        expected.extend_from_slice(payload);
    }
    let decoded = decode_chunked(&all, 64, 64).unwrap();
    assert_eq!(decoded, expected);
}

#[test]
fn single_member_stream_still_works() {
    // The multi-member code path must not regress the common case.
    let payload = b"single member, no concatenation";
    let mut enc = Encoder::new();
    let encoded = encode_chunked(&mut enc, payload, 64, 64);
    let decoded = decode_chunked(&encoded, 64, 64).unwrap();
    assert_eq!(decoded, payload);
}

#[test]
fn trailing_garbage_after_last_member_is_ignored() {
    // gzip(1) ignores trailing non-magic bytes after the final trailer.
    // Our decoder enters Done when it sees a non-0x1F next byte and
    // leaves the garbage unconsumed for the caller.
    let payload = b"clean payload";
    let mut enc = Encoder::new();
    let mut encoded = encode_chunked(&mut enc, payload, 64, 64);
    encoded.extend_from_slice(b"xx garbage tail");
    let decoded = decode_chunked(&encoded, 64, 64).unwrap();
    assert_eq!(decoded, payload);
}

#[test]
fn second_member_with_corrupted_crc_errors() {
    let mut enc1 = Encoder::new();
    let a = encode_chunked(&mut enc1, b"ok\n", 32, 32);
    let mut enc2 = Encoder::new();
    let mut b = encode_chunked(&mut enc2, b"bad\n", 32, 32);
    // Flip a CRC byte in member 2 (CRC sits at b.len() - 8 .. b.len() - 4).
    let last = b.len() - 5;
    b[last] ^= 0xFF;
    let mut combined = a;
    combined.extend_from_slice(&b);
    let err = decode_chunked(&combined, 64, 64).unwrap_err();
    assert_eq!(err, Error::ChecksumMismatch);
}
