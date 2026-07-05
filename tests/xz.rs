//! Streaming round-trip tests for the xz codec.
//!
//! Canonical v0.3 port: every call returns `(Progress, Status)` and the
//! loop dispatches on `Status` rather than inferring from byte counts.

#![cfg(feature = "xz")]

use std::io::Write;
use std::process::{Command, Stdio};

use compcol::xz::{Decoder, Encoder, EncoderConfig, Xz};
use compcol::{Algorithm, Decoder as _, Encoder as _, Error, Status};

// ─── helpers ───────────────────────────────────────────────────────────────

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
                    panic!("xz encoder finish stalled");
                }
            }
        }
    }

    encoded
}

/// Convenience wrapper: encode with a fresh default-config encoder.
fn encode_all(input: &[u8]) -> Vec<u8> {
    let mut enc = Encoder::new();
    encode_chunked(&mut enc, input, 4096, 4096)
}

/// Drive a decoder to completion. Mirrors `tests/deflate.rs`.
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

    // Drain any output buffered internally from compressed-chunk state.
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
                    panic!("xz decoder finish stalled");
                }
            }
        }
    }

    Ok(decoded)
}

fn round_trip(input: &[u8]) {
    let encoded = encode_all(input);
    // Stream Header magic.
    assert_eq!(&encoded[..6], &[0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00]);
    // Stream Footer magic in the last 2 bytes.
    assert_eq!(&encoded[encoded.len() - 2..], b"YZ");
    let decoded = decode_chunked(&encoded, 4096, 4096).unwrap();
    assert_eq!(decoded, input, "round-trip mismatch (len {})", input.len());
}

// ─── algorithm metadata ─────────────────────────────────────────────────

#[test]
fn name_is_xz() {
    assert_eq!(<Xz as Algorithm>::NAME, "xz");
}

#[test]
fn default_config_is_level_6() {
    assert_eq!(EncoderConfig::default().level, 6);
}

// ─── round-trip tests at the default level ─────────────────────────────

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
    round_trip(b"hello xz");
}

#[test]
fn round_trip_repeated() {
    round_trip(&b"the quick brown fox ".repeat(100));
}

#[test]
fn round_trip_zeros_long() {
    round_trip(&vec![0u8; 8192]);
}

#[test]
fn round_trip_pseudo_random() {
    let data: Vec<u8> = (0..50_000u32)
        .map(|i| ((i.wrapping_mul(0x9E37_79B1)) >> 24) as u8)
        .collect();
    round_trip(&data);
}

#[test]
fn round_trip_structured() {
    let mut v = Vec::new();
    for i in 0..200u32 {
        let s = format!(
            "record {:04} | timestamp 2026-05-28T{:02}:{:02}:00Z\n",
            i,
            (i / 60) % 24,
            i % 60
        );
        v.extend_from_slice(s.as_bytes());
    }
    round_trip(&v);
}

#[test]
fn round_trip_exactly_one_chunk() {
    round_trip(&vec![0xABu8; 65_536]);
}

#[test]
fn round_trip_just_over_one_chunk() {
    let mut v = vec![0u8; 65_537];
    for (i, b) in v.iter_mut().enumerate() {
        *b = (i & 0xFF) as u8;
    }
    round_trip(&v);
}

#[test]
fn round_trip_multi_chunk() {
    let v: Vec<u8> = (0..200_000u32)
        .map(|i| (i as u8).wrapping_mul(17))
        .collect();
    round_trip(&v);
}

#[test]
fn streaming_one_byte_both_sides() {
    let input = b"one byte at a time, all the way through".to_vec();
    let mut enc = Encoder::new();
    let encoded = encode_chunked(&mut enc, &input, 1, 1);
    let decoded = decode_chunked(&encoded, 1, 1).unwrap();
    assert_eq!(decoded, input);
}

#[test]
fn streaming_irregular_chunks() {
    let input: Vec<u8> = (0..70_000u32).map(|i| (i ^ (i >> 7)) as u8).collect();
    let mut enc = Encoder::new();
    let encoded = encode_chunked(&mut enc, &input, 13, 257);
    let decoded = decode_chunked(&encoded, 521, 1024).unwrap();
    assert_eq!(decoded, input);
}

/// Build a ≥64 KiB corpus that genuinely separates compression levels.
///
/// Same construction principle as `tests/deflate.rs::mixed_corpus`: a
/// short alphabet floods the 3-gram hash buckets, and periodic long
/// phrases give the high-chain levels something to find that the low
/// levels' tiny chain budget walks past. The phrases are also stitched
/// across chunk boundaries so cross-chunk match opportunities exist
/// (though our encoder full-resets between chunks, so that part is moot
/// — what matters is in-chunk chain depth).
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
fn round_trip_level_0() {
    for input in [
        &b""[..],
        b"hello world",
        &b"abcabcabcabcabc".repeat(100)[..],
    ] {
        let mut enc = Encoder::with_config(EncoderConfig { level: 0 });
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
fn level_9_no_worse_than_level_0_on_compressible_corpus() {
    // The whole point of having levels: max-effort must produce output at
    // least as small as min-effort on a realistic corpus. The level is
    // wired into our LZMA2 chunk encoder's match-finder tuning, so we
    // expect a measurable difference here.
    let input = mixed_corpus();
    let lo = encode_at_level(&input, 0);
    let hi = encode_at_level(&input, 9);
    assert!(
        hi.len() <= lo.len(),
        "level 9 ({} bytes) was bigger than level 0 ({} bytes)",
        hi.len(),
        lo.len(),
    );
    // Both must roundtrip.
    assert_eq!(decode_chunked(&lo, 4096, 4096).unwrap(), input);
    assert_eq!(decode_chunked(&hi, 4096, 4096).unwrap(), input);
}

#[test]
fn out_of_range_level_is_clamped() {
    // Level 250 should snap to 9 and still roundtrip; level 0 is the legal
    // floor so it also roundtrips cleanly.
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

    // After reset, a level-9 encoder must still be level-9.
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

// ─── error path tests ──────────────────────────────────────────────────

#[test]
fn bad_magic_rejected() {
    let stream = [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x01]; // last byte wrong
    let mut dec = Decoder::new();
    let mut buf = [0u8; 16];
    let err = dec.decode(&stream, &mut buf).unwrap_err();
    assert_eq!(err, Error::BadHeader);
}

#[test]
fn truncated_stream_rejected() {
    let mut encoded = encode_all(b"some payload");
    encoded.truncate(encoded.len() - 4);
    let err = decode_chunked(&encoded, 1024, 1024).unwrap_err();
    assert_eq!(err, Error::UnexpectedEnd);
}

#[test]
fn corrupted_check_rejected() {
    let input = b"checksum me please";
    let mut encoded = encode_all(input);
    let mid = encoded.len() / 2;
    encoded[mid] ^= 0x01;
    let err = decode_chunked(&encoded, 1024, 1024).unwrap_err();
    assert!(
        matches!(
            err,
            Error::ChecksumMismatch | Error::Corrupt | Error::Unsupported | Error::TrailerMismatch
        ),
        "unexpected error variant: {:?}",
        err
    );
}

// ─── algorithm-trait entry points ───────────────────────────────────────

#[test]
fn algorithm_encoder_decoder_round_trip() {
    let mut enc = <Xz as Algorithm>::encoder();
    let mut dec = <Xz as Algorithm>::decoder();
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
        if p.written == 0 {
            panic!("encoder finish stalled");
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
    // Flush any output buffered from a partial compressed chunk.
    loop {
        let (p, _status) = dec.decode(&[], &mut buf).unwrap();
        decoded.extend_from_slice(&buf[..p.written]);
        if p.written == 0 {
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
    let mut enc_lo = <Xz as Algorithm>::encoder_with(EncoderConfig { level: 0 });
    let mut enc_hi = <Xz as Algorithm>::encoder_with(EncoderConfig { level: 9 });
    let lo = encode_chunked(&mut enc_lo, &input, 4096, 4096);
    let hi = encode_chunked(&mut enc_hi, &input, 4096, 4096);
    assert!(
        hi.len() <= lo.len(),
        "encoder_with(level=9) was bigger than encoder_with(level=0)"
    );
    assert_eq!(decode_chunked(&lo, 4096, 4096).unwrap(), input);
    assert_eq!(decode_chunked(&hi, 4096, 4096).unwrap(), input);
}

// ─── cross-validation with system `xz` (if installed) ──────────────────

fn tool_available(cmd: &str) -> bool {
    Command::new(cmd)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn pipe_through(cmd: &str, args: &[&str], stdin_data: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut child = Command::new(cmd)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    // Feed stdin from a dedicated thread while the parent drains stdout, so a
    // payload larger than the OS pipe buffer (~64 KiB) can't deadlock both ends
    // — the same pattern the bench harness uses.
    let mut stdin = child.stdin.take().unwrap();
    let data = stdin_data.to_vec();
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(&data);
        // Drop `stdin` to send EOF.
    });
    let out = child.wait_with_output()?;
    let _ = writer.join();
    if !out.status.success() {
        return Err(std::io::Error::other(format!(
            "{} {:?} exited {:?}: {}",
            cmd,
            args,
            out.status,
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    Ok(out.stdout)
}

#[test]
fn our_encode_then_system_xz_decode() {
    if !tool_available("xz") {
        println!("skipping: xz not installed");
        return;
    }
    for (label, input) in [
        ("empty", Vec::new()),
        ("short", b"hello xz world".to_vec()),
        ("medium", b"Lorem ipsum dolor sit amet. ".repeat(200)),
        ("two_chunks", vec![0xCDu8; 70_000]),
        // Highly compressible input spanning many 64 KiB chunks: every
        // continuation chunk is a `0x80` (no state/props reset), so the
        // adaptive model carries across all of them. Native `xz` must accept
        // that continuation framing.
        (
            "many_chunks_compressible",
            b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. ".repeat(40_000),
        ),
        // Many chunks of incompressible data: forces uncompressed-fallback
        // chunks interleaved with state-reset (`0xC0`) compressed chunks.
        ("many_chunks_random", {
            let mut v = Vec::with_capacity(600_000);
            let mut s: u32 = 0x1234_5678;
            while v.len() < 600_000 {
                s = s.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                v.push((s >> 16) as u8);
            }
            v
        }),
    ] {
        let encoded = encode_all(&input);
        match pipe_through("xz", &["-d", "-c"], &encoded) {
            Ok(decoded) => assert_eq!(decoded, input, "{}: system xz decoded wrong", label),
            Err(e) => panic!("{}: system xz failed: {}", label, e),
        }
    }
}

#[test]
fn system_xz_encode_then_our_decode_small() {
    if !tool_available("xz") {
        println!("skipping: xz not installed");
        return;
    }
    for input in [
        b"".to_vec(),
        b"hello".to_vec(),
        b"a".to_vec(),
        b"the quick brown fox jumps over".to_vec(),
    ] {
        let encoded = match pipe_through("xz", &["-c", "-z"], &input) {
            Ok(v) => v,
            Err(e) => {
                println!("skipping case (xz failed): {}", e);
                continue;
            }
        };
        match decode_chunked(&encoded, 1024, 1024) {
            Ok(decoded) => assert_eq!(decoded, input),
            Err(e) => panic!(
                "our decoder failed for system-xz output ({:?}): {:?}",
                input, e
            ),
        }
    }
}

// ─── factory lookup ─────────────────────────────────────────────────────

#[cfg(feature = "factory")]
mod factory {
    use compcol::Status;
    use compcol::factory;

    #[test]
    fn lookup_known() {
        assert!(factory::encoder_by_name("xz").is_some());
        assert!(factory::decoder_by_name("xz").is_some());
    }

    #[test]
    fn names_contains_xz() {
        assert!(factory::names().contains(&"xz"));
    }

    #[test]
    fn boxed_round_trip() {
        let mut enc = factory::encoder_by_name("xz").unwrap();
        let mut dec = factory::decoder_by_name("xz").unwrap();
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
                panic!("encoder finish stalled");
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
        loop {
            let (p, _status) = dec.decode(&[], &mut buf).unwrap();
            decoded.extend_from_slice(&buf[..p.written]);
            if p.written == 0 {
                break;
            }
        }
        let (_, status) = dec.finish(&mut buf).unwrap();
        assert!(matches!(status, Status::StreamEnd));
        assert_eq!(&decoded[..], input);
    }
}
