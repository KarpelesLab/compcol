//! Streaming round-trip tests for the Microsoft Xpress (Plain LZ77) codec.
//!
//! Canonical v0.4 (Progress, Status) driver. Encoder and decoder are
//! exercised at the chunk-level and via the runtime factory.

#![cfg(feature = "xpress")]

use compcol::xpress::{Decoder, Encoder, Xpress};
use compcol::{Algorithm, Decoder as _, Encoder as _, Error, Status};

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
                    panic!("xpress encoder finish stalled");
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

    // Drain anything remaining the decoder can produce with empty input.
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
                    panic!("xpress decoder finish stalled");
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
    let decoded = decode_chunked(&encoded, 4096, 4096).unwrap();
    assert_eq!(decoded, input, "round-trip mismatch len {}", input.len());
}

// ─── algorithm metadata ─────────────────────────────────────────────────

#[test]
fn name_is_xpress() {
    assert_eq!(<Xpress as Algorithm>::NAME, "xpress");
}

// ─── round-trip tests ──────────────────────────────────────────────────

#[test]
fn round_trip_empty() {
    let encoded = encode_all(b"");
    // 8-byte header + zero payload bytes.
    assert_eq!(encoded.len(), 8);
    assert_eq!(&encoded[..8], &0u64.to_le_bytes());
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
fn round_trip_short_match() {
    // 3 bytes ("abc") repeated immediately — exercises the smallest
    // match the encoder can emit (tier 1, lc=0 → length 3).
    round_trip(b"abcabcabc");
}

#[test]
fn round_trip_distance_one() {
    // Triggers a distance-1 "byte splat" match.
    round_trip(b"aaaaaaaa");
}

#[test]
fn round_trip_tier2_length() {
    // Length 10..24 forces the half-byte length tier.
    let mut input = Vec::new();
    input.extend_from_slice(b"abcdefghij");
    input.extend_from_slice(b"abcdefghijabcdefghij");
    round_trip(&input);
}

#[test]
fn round_trip_tier3_length() {
    // Length 25..279 forces the byte-extension tier.
    let phrase = b"the quick brown fox jumps over the lazy dog ";
    let mut input = Vec::new();
    for _ in 0..8 {
        input.extend_from_slice(phrase);
    }
    round_trip(&input);
}

#[test]
fn round_trip_tier4_length() {
    // Length > 279 forces the 16-bit tier.
    let input = vec![b'a'; 4096];
    round_trip(&input);
}

#[test]
fn round_trip_long_repeating_64kib() {
    // 64 KiB run-length-encodeable input. Exercises long matches and
    // the 8 KiB window cap.
    let input = vec![b'Z'; 64 * 1024];
    round_trip(&input);
}

#[test]
fn round_trip_mixed_short_runs() {
    let mut input = Vec::new();
    input.extend(core::iter::repeat_n(b'a', 10));
    input.extend(core::iter::repeat_n(b'b', 3));
    input.extend(core::iter::repeat_n(b'c', 7));
    input.extend_from_slice(b"and a quick fox jumps over");
    input.extend(core::iter::repeat_n(b'z', 200));
    round_trip(&input);
}

#[test]
fn round_trip_mixed_corpus() {
    // Mix repetition with pseudo-random padding so the encoder has to
    // intermix literal and match symbols.
    let mut state: u32 = 0xC0FFEE_u32;
    let mut input = Vec::with_capacity(16 * 1024);
    let phrases: &[&[u8]] = &[
        b"the_quick_brown_fox_jumps_over_the_lazy_dog ",
        b"compcol streaming codec test corpus aaaa ",
        b"xpress round trip mixed ",
    ];
    let mut p = 0;
    while input.len() < 8 * 1024 {
        for _ in 0..32 {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            input.push((state >> 16) as u8);
        }
        input.extend_from_slice(phrases[p % phrases.len()]);
        p += 1;
    }
    round_trip(&input);
}

#[test]
fn round_trip_pseudo_random_64kib() {
    // 64 KiB of LCG output: low compressibility. The encoder will be
    // forced to emit mostly literals; this exercises the "every flag
    // bit is 0" path.
    let mut state: u32 = 0xC0FFEE_u32;
    let mut input = Vec::with_capacity(64 * 1024);
    for _ in 0..(64 * 1024) {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        input.push((state >> 16) as u8);
    }
    round_trip(&input);
}

#[test]
fn round_trip_full_byte_alphabet() {
    let input: Vec<u8> = (0..=255u8).collect();
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

#[test]
fn decoder_output_buffer_size_one() {
    // Tiny output buffer forces every match-copy to be a pending-match
    // across multiple decode calls.
    let input = b"the_the_the_the_the_the_the_the_the_the_the_the_the_".to_vec();
    let encoded = encode_all(&input);
    let decoded = decode_chunked(&encoded, 4096, 1).unwrap();
    assert_eq!(decoded, input);
}

#[test]
fn decoder_input_buffer_size_one() {
    let input = b"the_the_the_the_the_the_the_the_the_the_the_the_the_".to_vec();
    let encoded = encode_all(&input);
    let decoded = decode_chunked(&encoded, 1, 4096).unwrap();
    assert_eq!(decoded, input);
}

// ─── reset / reuse ─────────────────────────────────────────────────────

#[test]
fn encoder_reset_allows_reuse() {
    let input_a = b"alpha alpha alpha alpha alpha".as_slice();
    let input_b = b"bravo bravo bravo bravo bravo".as_slice();

    let mut enc = Encoder::new();
    let encoded_a = encode_chunked(&mut enc, input_a, 4096, 4096);
    enc.reset();
    let encoded_b = encode_chunked(&mut enc, input_b, 4096, 4096);

    assert_eq!(decode_chunked(&encoded_a, 4096, 4096).unwrap(), input_a);
    assert_eq!(decode_chunked(&encoded_b, 4096, 4096).unwrap(), input_b);
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

// ─── decoder error rejection ───────────────────────────────────────────

#[test]
fn truncated_header_rejected() {
    // Less than 8 bytes ⇒ finish must error.
    let encoded = vec![0u8; 4];
    let mut dec = Decoder::new();
    let mut buf = [0u8; 32];
    let (_p, _s) = dec.decode(&encoded, &mut buf).unwrap();
    let err = dec.finish(&mut buf).unwrap_err();
    assert_eq!(err, Error::UnexpectedEnd);
}

#[test]
fn truncated_payload_rejected() {
    // Claim 100 decompressed bytes but provide only the header.
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&100u64.to_le_bytes());
    let err = decode_chunked(&encoded, 4096, 4096).unwrap_err();
    assert_eq!(err, Error::UnexpectedEnd);
}

#[test]
fn distance_out_of_history_rejected() {
    // Craft a minimal payload: header says 4 bytes uncompressed; the
    // flag DWORD's first bit is `1` (match), but no prior bytes have
    // been produced — distance must be invalid.
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&4u64.to_le_bytes());
    // Flag word with bit 31 set: 0x8000_0000.
    encoded.extend_from_slice(&0x8000_0000u32.to_le_bytes());
    // 16-bit sym: distance 1, length code 0 → length 3.
    // sym = ((1 - 1) << 3) | 0 = 0. But distance 1 with no produced
    // bytes is still invalid.
    encoded.extend_from_slice(&0u16.to_le_bytes());
    let err = decode_chunked(&encoded, 4096, 4096).unwrap_err();
    assert_eq!(err, Error::InvalidDistance);
}

#[test]
fn invalid_long_length_rejected() {
    // Header claims 10000 decoded bytes; payload uses tier-4 16-bit
    // length encoded as `w = 10` (< 22). Decoder must reject.
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&10_000u64.to_le_bytes());
    // First emit one literal so a back-reference has history.
    // Flag word: bit31=0 (literal), bit30=1 (match), then 30 padding 1s.
    let flag: u32 = 0b0100_0000_0000_0000_0000_0000_0000_0000 | 0x3FFF_FFFF;
    encoded.extend_from_slice(&flag.to_le_bytes());
    // Literal 'A'.
    encoded.push(b'A');
    // Sym: distance 1, lc = 7 (tier-2 trigger).
    let sym: u16 = 7; // (distance-1) << 3 == 0, low 3 bits = 7
    encoded.extend_from_slice(&sym.to_le_bytes());
    // Half-byte: low nibble 0xF (tier-3 trigger).
    encoded.push(0x0F);
    // Tier-3 byte: 0xFF (tier-4 trigger).
    encoded.push(0xFF);
    // Tier-4 word: 10 — out-of-range (< 22).
    encoded.extend_from_slice(&10u16.to_le_bytes());
    let err = decode_chunked(&encoded, 4096, 4096).unwrap_err();
    assert_eq!(err, Error::Corrupt);
}

// ─── Algorithm-trait entry points ──────────────────────────────────────

#[test]
fn algorithm_encoder_decoder_round_trip() {
    let mut enc = <Xpress as Algorithm>::encoder();
    let mut dec = <Xpress as Algorithm>::decoder();
    let input = b"compcol xpress Algorithm trait roundtrip!";

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

// ─── known-fixture decode ───────────────────────────────────────────────
//
// MS-XCA §2.5 worked example: the 26-byte ASCII alphabet
// "abcdefghijklmnopqrstuvwxyz" compresses to the byte string
// `3F 00 00 00 61 62 63 ... 7A` — a single flag DWORD of `0x0000003F`
// (26 literal flags, then 6 trailing 1s) followed by the alphabet.
//
// Our framing prepends an 8-byte length header to the raw MS-XCA
// payload (the spec's bytes); the decoder strips that header and then
// runs the plain-LZ77 stream verbatim.

#[test]
fn decode_ms_xca_alphabet_fixture() {
    let mut encoded = Vec::new();
    // Header: 26 decoded bytes.
    encoded.extend_from_slice(&26u64.to_le_bytes());
    // Spec's flag word + 26 literal bytes.
    encoded.extend_from_slice(&[
        0x3F, 0x00, 0x00, 0x00, // flag DWORD
        b'a', b'b', b'c', b'd', b'e', b'f', b'g', b'h', b'i', b'j', b'k', b'l', b'm', b'n', b'o',
        b'p', b'q', b'r', b's', b't', b'u', b'v', b'w', b'x', b'y', b'z',
    ]);
    let decoded = decode_chunked(&encoded, 4096, 4096).unwrap();
    assert_eq!(decoded, b"abcdefghijklmnopqrstuvwxyz");
}

// The following decoder fixtures were generated offline by running this
// crate's encoder over the listed inputs, then cross-checked through
// Python's `dissect.util.compression.lzxpress.decompress` to confirm
// they are valid MS-XCA Plain LZ77 streams. We hard-code the resulting
// bytes so the test suite needs no external tools at run time.

#[test]
fn decode_short_match_fixture() {
    // Cross-validated payload for `b"abcabc"`. Bytes after the 8-byte
    // header come from a hand-crafted flag word + literals + sym.
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&6u64.to_le_bytes());
    encoded.extend_from_slice(&[
        0xff, 0xff, 0xff, 0x1f, // flag = 0x1fffffff: 3 literal bits + 29 ones
        b'a', b'b', b'c', // literals
        0x10, 0x00, // sym: distance=3, lc=0 → length 3
    ]);
    let decoded = decode_chunked(&encoded, 4096, 4096).unwrap();
    assert_eq!(decoded, b"abcabc");
}

#[test]
fn decode_long_run_fixture() {
    // Cross-validated payload for `b"a" * 128`. Single literal `a`
    // followed by one big match (distance 1, length 127).
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&128u64.to_le_bytes());
    encoded.extend_from_slice(&[
        0xff, 0xff, 0xff, 0x7f, // flag: 1 literal, 1 match, 30 trailing ones
        b'a', // literal
        0x07, 0x00, // sym: distance=1, lc=7 → tier 2
        0x0f, // half-byte 0xF (tier 3 trigger), high nibble unused
        0x66, // tier-3 byte = 102 → length = 102+25 = 127
    ]);
    let decoded = decode_chunked(&encoded, 4096, 4096).unwrap();
    assert_eq!(decoded, vec![b'a'; 128]);
}

#[test]
fn decode_tier4_length_fixture() {
    // Cross-validated payload for `b"a" * 65536`. Single literal `a`
    // followed by one big match (distance 1, length 65535) via tier-4.
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&65_536u64.to_le_bytes());
    encoded.extend_from_slice(&[
        0xff, 0xff, 0xff, 0x7f, // flag: 1 literal, 1 match, 30 trailing ones
        b'a', // literal
        0x07, 0x00, // sym: distance=1, lc=7 → tier 2
        0x0f, // half-byte 0xF (tier 3 trigger)
        0xff, // tier-3 byte = 255 → tier 4 trigger
        0xfc, 0xff, // tier-4 16-bit = 0xFFFC = 65532 → length = 65532+3 = 65535
    ]);
    let decoded = decode_chunked(&encoded, 4096, 4096).unwrap();
    assert_eq!(decoded, vec![b'a'; 65536]);
}

// ─── cross-validate with Python's dissect.util (if available) ──────────

#[cfg(feature = "std")]
#[test]
fn cross_validate_with_python_dissect() {
    use std::io::Write;
    use std::process::{Command, Stdio};

    // Skip cleanly if Python (or the `dissect` module) isn't available.
    let probe = Command::new("python3")
        .arg("-c")
        .arg("import dissect.util.compression.lzxpress")
        .output();
    if !matches!(probe, Ok(o) if o.status.success()) {
        eprintln!("python3 / dissect.util not available; skipping cross-validation");
        return;
    }

    let input = b"the quick brown fox jumps over the lazy dog 1234567890";
    let encoded = encode_all(input);
    // Strip our framing's 8-byte length prefix — dissect operates on the
    // raw MS-XCA bytes.
    let payload = &encoded[8..];

    let mut child = Command::new("python3")
        .arg("-c")
        .arg("import sys; from dissect.util.compression import lzxpress; sys.stdout.buffer.write(lzxpress.decompress(sys.stdin.buffer.read()))")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn python3");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(payload)
        .expect("write to python stdin");
    let out = child.wait_with_output().expect("wait python");
    assert!(
        out.status.success(),
        "python decoder rejected our stream: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout, input);
}

// ─── factory lookup ────────────────────────────────────────────────────

#[cfg(feature = "factory")]
mod factory {
    use compcol::Status;
    use compcol::factory;

    #[test]
    fn lookup_known() {
        assert!(factory::encoder_by_name("xpress").is_some());
        assert!(factory::decoder_by_name("xpress").is_some());
    }

    #[test]
    fn names_contains_xpress() {
        assert!(factory::names().contains(&"xpress"));
    }

    #[test]
    fn extension_is_xpress() {
        assert_eq!(factory::extension("xpress"), Some("xpress"));
    }

    #[test]
    fn boxed_round_trip() {
        let mut enc = factory::encoder_by_name("xpress").unwrap();
        let mut dec = factory::decoder_by_name("xpress").unwrap();
        let input = b"factory boxed round-trip via xpress";

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
