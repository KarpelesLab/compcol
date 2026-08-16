//! Streaming round-trip tests for the ADC (Apple Data Compression) algorithm.
//!
//! Canonical v0.3 port: every call returns `(Progress, Status)` and the
//! loop dispatches on `Status` rather than inferring from byte counts.
//!
//! ADC is a whole-buffer codec on the encoder side (no header/trailer means
//! a streaming encoder would have to commit greedily and lose match
//! opportunities at chunk boundaries) — every `encode` call reports
//! `Status::InputEmpty`, and `finish` reports `OutputFull` while draining
//! the encoded token stream then `StreamEnd` at the end. The decoder is
//! a strict byte-by-byte state machine.

#![cfg(feature = "adc")]

use compcol::adc::{Adc, Decoder, Encoder};
use compcol::{Algorithm, Decoder as _, Encoder as _, Status};

fn encode_chunked(input: &[u8], in_chunk: usize, out_chunk: usize) -> Vec<u8> {
    let mut enc = Encoder::new();
    let mut encoded = Vec::new();
    let mut buf = vec![0u8; out_chunk.max(1)];
    let mut i = 0;

    while i < input.len() {
        let end = (i + in_chunk.max(1)).min(input.len());
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

fn decode_chunked(encoded: &[u8], in_chunk: usize, out_chunk: usize) -> Vec<u8> {
    let mut dec = Decoder::new();
    let mut decoded = Vec::new();
    let mut buf = vec![0u8; out_chunk.max(1)];
    let mut i = 0;

    while i < encoded.len() {
        let end = (i + in_chunk.max(1)).min(encoded.len());
        let chunk = &encoded[i..end];
        let mut consumed = 0;
        while consumed < chunk.len() {
            let (p, status) = dec.decode(&chunk[consumed..], &mut buf).unwrap();
            decoded.extend_from_slice(&buf[..p.written]);
            consumed += p.consumed;
            match status {
                Status::InputEmpty | Status::StreamEnd => break,
                Status::OutputFull => continue,
            }
        }
        i = end;
    }

    loop {
        let (p, status) = dec.finish(&mut buf).unwrap();
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

    decoded
}

fn round_trip(input: &[u8]) {
    let big = input.len().saturating_mul(2).max(1024);
    let encoded = encode_chunked(input, big, big);
    let decoded = decode_chunked(&encoded, big, big);
    assert_eq!(decoded.len(), input.len(), "round-trip length mismatch");
    assert!(decoded == input, "round-trip content mismatch");
}

#[test]
fn name_is_adc() {
    assert_eq!(<Adc as Algorithm>::NAME, "adc");
}

#[test]
fn default_constructors() {
    let _enc: Encoder = <Adc as Algorithm>::encoder();
    let _dec: Decoder = <Adc as Algorithm>::decoder();
    let _enc2 = Encoder::default();
    let _dec2 = Decoder::default();
}

#[test]
fn empty_input() {
    round_trip(&[]);
}

#[test]
fn single_byte() {
    round_trip(&[0x42]);
}

#[test]
fn hello_world() {
    round_trip(b"hello world");
}

#[test]
fn zeros_1k() {
    round_trip(&[0u8; 1024]);
}

#[test]
fn ascending_4k() {
    let input: Vec<u8> = (0..4096u32).map(|i| i as u8).collect();
    round_trip(&input);
}

#[test]
fn mixed_corpus_over_64_kib() {
    // ≥ 64 KiB mix: repetitive prefix + LCG noise + repetitive tail.
    let mut input = Vec::with_capacity(80 * 1024);
    let phrase = b"The quick brown fox jumps over the lazy dog. ";
    while input.len() < 24 * 1024 {
        input.extend_from_slice(phrase);
    }
    let mut state: u32 = 0xC0FFEEu32;
    for _ in 0..24 * 1024 {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        input.push((state >> 16) as u8);
    }
    while input.len() < 70 * 1024 {
        input.extend_from_slice(phrase);
    }
    assert!(input.len() >= 64 * 1024);
    round_trip(&input);
}

// ─── token-shape exercises ────────────────────────────────────────────────

#[test]
fn raw_only_pseudo_random() {
    // LCG noise — virtually nothing should match, so the encoder must emit
    // a sequence of raw literal runs and the decoder must accept them.
    let mut state: u32 = 0xDECAFBADu32;
    let mut input = Vec::with_capacity(2048);
    for _ in 0..2048 {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        input.push((state >> 16) as u8);
    }
    let encoded = encode_chunked(&input, input.len(), input.len() * 2);
    // First token byte must be a raw-literal tag (0x80..=0xFF).
    assert!(
        !encoded.is_empty() && encoded[0] >= 0x80,
        "expected raw-literal tag, got {:#04x}",
        encoded[0]
    );
    let decoded = decode_chunked(&encoded, encoded.len(), encoded.len() * 4);
    assert_eq!(decoded, input);
}

#[test]
fn short_match_form_exercised() {
    // A short match — length 3..=18, offset ≤ 1024 — is the most compact
    // encoding for a small back-reference. Use 5 bytes of one byte: the
    // encoder emits 1 byte literal then a 4-byte short match (length 4,
    // distance 1). With length ≤ 18, the encoder prefers the short form.
    let input = vec![0xABu8; 5];
    let encoded = encode_chunked(&input, input.len(), input.len() * 2);
    // Expect: 0x80 (literal len 1), 0xAB, then a short-match tag (< 0x40).
    assert!(encoded.len() >= 4);
    assert_eq!(encoded[0], 0x80, "first byte should be raw-literal tag");
    assert_eq!(encoded[1], 0xAB, "literal byte");
    let tag_after_lit = encoded[2];
    assert!(
        tag_after_lit < 0x40,
        "expected short-match tag after literal, got {:#04x}",
        tag_after_lit
    );
    let decoded = decode_chunked(&encoded, encoded.len(), encoded.len() * 2);
    assert_eq!(decoded, input);
}

#[test]
fn long_match_form_exercised() {
    // Build input so the back-distance for the second copy exceeds 1024,
    // forcing the encoder to choose the long-match form. Strategy: write
    // 1500 bytes of pattern A, then 1500 bytes of pattern A again. The
    // matcher should find a back-reference at distance 1500 (> 1024).
    let phrase: &[u8] = b"compcol-adc-distinct-1500byte-block-pattern-XYZ";
    let mut input = Vec::with_capacity(3200);
    while input.len() < 1500 {
        input.extend_from_slice(phrase);
    }
    let first_half_len = input.len();
    let first_half: Vec<u8> = input.clone();
    input.extend_from_slice(&first_half);
    let encoded = encode_chunked(&input, input.len(), input.len() * 2);

    // Confirm at least one long-match tag (0x40..=0x7F) appears.
    let any_long = encoded.iter().any(|&b| (0x40..=0x7F).contains(&b));
    assert!(
        any_long,
        "expected at least one long-match token in encoded stream"
    );

    let decoded = decode_chunked(&encoded, encoded.len(), encoded.len() * 2);
    assert_eq!(decoded.len(), input.len());
    assert_eq!(&decoded[..first_half_len], &first_half[..]);
    assert_eq!(decoded, input);
}

// ─── boundary conditions ──────────────────────────────────────────────────

#[test]
fn max_raw_run_128() {
    // Force a 128-byte literal run by feeding 128 distinct bytes the matcher
    // can't compress. Using a pseudo-random LCG over exactly 128 outputs.
    let mut state: u32 = 0x1234_5678u32;
    let mut input = Vec::with_capacity(128);
    for _ in 0..128 {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        input.push((state >> 16) as u8);
    }
    let encoded = encode_chunked(&input, 128, 1024);
    // Whole thing should fit in exactly one literal-run token + 128 bytes
    // — encoded length 129 — or be split into two tokens if hash collisions
    // happened to spawn a false-positive match attempt. Decode must match
    // either way.
    let decoded = decode_chunked(&encoded, encoded.len(), encoded.len() * 2);
    assert_eq!(decoded, input);
}

#[test]
fn max_short_match_length_18() {
    // A run of 21 of the same byte → after one literal byte, the matcher
    // should emit a 18-byte short match followed by a 2-byte tail literal.
    let input = vec![0x5Au8; 21];
    let encoded = encode_chunked(&input, input.len(), input.len() * 2);
    let decoded = decode_chunked(&encoded, encoded.len(), encoded.len() * 2);
    assert_eq!(decoded, input);
}

#[test]
fn max_long_match_length_67() {
    // A 100-byte run with distance > 1024 → long match capped at 67.
    let mut input = Vec::with_capacity(2000);
    // 1024 bytes of unique LCG noise (no matches), then a 100-byte run of
    // 0xCC that will need to find a back-reference to itself.
    let mut state: u32 = 0xFADE_FACEu32;
    for _ in 0..1024 {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        input.push((state >> 16) as u8);
    }
    input.extend(core::iter::repeat_n(0xCCu8, 200));
    // After encoding, decode and check exact bytes.
    let encoded = encode_chunked(&input, input.len(), input.len() * 2);
    let decoded = decode_chunked(&encoded, encoded.len(), encoded.len() * 2);
    assert_eq!(decoded, input);
}

#[test]
fn max_short_offset_1024() {
    // Build input where the only viable back-reference for the trailing
    // section is at exactly distance 1024.
    let mut input = Vec::with_capacity(2048);
    // 1024 bytes of LCG noise.
    let mut state: u32 = 0xBEEF_F00Du32;
    let mut prefix = Vec::with_capacity(1024);
    for _ in 0..1024 {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        prefix.push((state >> 16) as u8);
    }
    input.extend_from_slice(&prefix);
    // Copy the first 8 bytes of the prefix back at the end — distance = 1024.
    input.extend_from_slice(&prefix[..8]);
    let encoded = encode_chunked(&input, input.len(), input.len() * 2);
    let decoded = decode_chunked(&encoded, encoded.len(), encoded.len() * 2);
    assert_eq!(decoded, input);
}

#[test]
fn max_long_offset_65536() {
    // Build input where a back-reference at the maximum supported distance
    // of 65 536 round-trips correctly. Mode: 65 536 bytes of LCG noise +
    // 16-byte block, then "1 byte filler" + the 16-byte block again, so the
    // copy distance for the repeated 16-byte block becomes exactly 65 536.
    let mut prefix = Vec::with_capacity(65_536);
    let mut state: u32 = 0xCAFED00Du32;
    for _ in 0..65_536 {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        prefix.push((state >> 16) as u8);
    }
    let mut input = prefix.clone();
    input.push(0xAA);
    // Re-append the first 16 bytes of the prefix.
    input.extend_from_slice(&prefix[..16]);
    let encoded = encode_chunked(&input, input.len(), input.len() * 2);
    let decoded = decode_chunked(&encoded, encoded.len(), encoded.len() * 2);
    assert_eq!(decoded.len(), input.len());
    assert!(decoded == input);
}

// ─── streaming-shape tests ────────────────────────────────────────────────

#[test]
fn chunked_one_byte_at_a_time() {
    // 1-byte input chunks and 1-byte output buffers on both sides.
    let input: Vec<u8> = (0..512u32).map(|i| (i % 7) as u8).collect();
    let encoded = encode_chunked(&input, 1, 1);
    let decoded = decode_chunked(&encoded, 1, 1);
    assert_eq!(decoded, input);
}

#[test]
fn chunked_one_byte_at_a_time_repetitive() {
    // 1-byte buffers for a compressible payload — exercises mid-token
    // buffer fragmentation in the decoder.
    let mut input = Vec::with_capacity(2048);
    for _ in 0..256 {
        input.extend_from_slice(b"abcdefgh");
    }
    let encoded = encode_chunked(&input, 1, 1);
    let decoded = decode_chunked(&encoded, 1, 1);
    assert_eq!(decoded, input);
}

#[test]
fn encode_reports_input_empty() {
    // ADC buffers the whole input internally during `encode`, so every
    // encode call must report InputEmpty and emit zero output bytes.
    let mut enc = Encoder::new();
    let mut out = [0u8; 32];
    let (p, status) = enc.encode(b"hello", &mut out).unwrap();
    assert_eq!(p.consumed, 5);
    assert_eq!(p.written, 0);
    assert!(matches!(status, Status::InputEmpty));
}

#[test]
fn finish_streams_end_marker() {
    let mut enc = Encoder::new();
    let mut out = [0u8; 64];
    let _ = enc.encode(b"hello world", &mut out).unwrap();
    let (_p, status) = enc.finish(&mut out).unwrap();
    assert!(matches!(status, Status::StreamEnd));
    // Subsequent finish must be a no-op.
    let (p2, status2) = enc.finish(&mut out).unwrap();
    assert_eq!(p2.written, 0);
    assert!(matches!(status2, Status::StreamEnd));
}

#[test]
fn finish_drains_across_calls() {
    // 1-byte output buffer forces `finish` to make many calls.
    let phrase = b"hello hello hello hello hello hello hello hello";
    let mut enc = Encoder::new();
    let mut tiny = [0u8; 1];
    let (p, status) = enc.encode(phrase, &mut tiny).unwrap();
    assert_eq!(p.consumed, phrase.len());
    assert!(matches!(status, Status::InputEmpty));
    let mut produced = Vec::new();
    loop {
        let (p, status) = enc.finish(&mut tiny).unwrap();
        produced.extend_from_slice(&tiny[..p.written]);
        match status {
            Status::StreamEnd => break,
            Status::OutputFull | Status::InputEmpty => {
                if p.written == 0 {
                    panic!("encoder finish stalled");
                }
            }
        }
    }
    let decoded = decode_chunked(&produced, 1, 1);
    assert_eq!(&decoded, phrase);
}

#[test]
fn reset_clears_encoder_state() {
    let mut enc = Encoder::new();
    let mut out = [0u8; 256];
    let _ = enc
        .encode(b"first run, will be discarded", &mut out)
        .unwrap();
    enc.reset();

    let _ = enc.encode(b"second run", &mut out).unwrap();
    let mut produced = Vec::new();
    loop {
        let (p, status) = enc.finish(&mut out).unwrap();
        produced.extend_from_slice(&out[..p.written]);
        match status {
            Status::StreamEnd => break,
            Status::OutputFull | Status::InputEmpty => {
                if p.written == 0 {
                    panic!("encoder finish stalled");
                }
            }
        }
    }

    let decoded = decode_chunked(&produced, produced.len(), 256);
    assert_eq!(&decoded, b"second run");
}

#[test]
fn reset_clears_decoder_state() {
    // After reset(), the decoder must forget its previous (already-decoded)
    // window and decode the next stream from scratch.
    let encoded_hello = encode_chunked(b"hello", 32, 32);
    let encoded_world = encode_chunked(b"world", 32, 32);

    let mut dec = Decoder::new();
    let mut buf = [0u8; 64];
    let mut consumed = 0;
    let mut decoded = Vec::new();
    while consumed < encoded_hello.len() {
        let (p, _) = dec.decode(&encoded_hello[consumed..], &mut buf).unwrap();
        decoded.extend_from_slice(&buf[..p.written]);
        consumed += p.consumed;
        if p.consumed == 0 && p.written == 0 {
            break;
        }
    }
    loop {
        let (p, status) = dec.finish(&mut buf).unwrap();
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
    assert_eq!(&decoded, b"hello");

    dec.reset();

    let mut decoded2 = Vec::new();
    let mut consumed = 0;
    while consumed < encoded_world.len() {
        let (p, _) = dec.decode(&encoded_world[consumed..], &mut buf).unwrap();
        decoded2.extend_from_slice(&buf[..p.written]);
        consumed += p.consumed;
        if p.consumed == 0 && p.written == 0 {
            break;
        }
    }
    loop {
        let (p, status) = dec.finish(&mut buf).unwrap();
        decoded2.extend_from_slice(&buf[..p.written]);
        match status {
            Status::StreamEnd => break,
            Status::OutputFull | Status::InputEmpty => {
                if p.written == 0 {
                    panic!("decoder finish stalled");
                }
            }
        }
    }
    assert_eq!(&decoded2, b"world");
}

#[test]
fn decoder_rejects_truncated_long_match() {
    // Build: a single raw-literal token "AB", then a long-match tag that
    // promises 2 offset bytes but we cut input off before them.
    // Raw literal: tag 0x81 (length 2), then "AB".
    // Long match: tag 0x40 (length 4), then offset hi/lo — truncated.
    let encoded = [0x81u8, b'A', b'B', 0x40];
    let mut dec = Decoder::new();
    let mut out = [0u8; 16];
    let _ = dec.decode(&encoded, &mut out).unwrap();
    let err = dec.finish(&mut out).unwrap_err();
    assert_eq!(err, compcol::Error::UnexpectedEnd);
}

#[test]
fn decoder_rejects_truncated_short_match() {
    // Raw literal "AB" then a short-match tag missing its offset byte.
    let encoded = [0x81u8, b'A', b'B', 0x00];
    let mut dec = Decoder::new();
    let mut out = [0u8; 16];
    let _ = dec.decode(&encoded, &mut out).unwrap();
    let err = dec.finish(&mut out).unwrap_err();
    assert_eq!(err, compcol::Error::UnexpectedEnd);
}

#[test]
fn decoder_rejects_truncated_literal() {
    // Raw literal tag promising 5 bytes but only 2 follow.
    let encoded = [0x84u8, b'A', b'B'];
    let mut dec = Decoder::new();
    let mut out = [0u8; 16];
    let _ = dec.decode(&encoded, &mut out).unwrap();
    let err = dec.finish(&mut out).unwrap_err();
    assert_eq!(err, compcol::Error::UnexpectedEnd);
}

#[test]
fn decoder_rejects_oversize_distance() {
    // Long match referencing 1 byte back, but no bytes have been emitted.
    // Tag 0x40 → length 4, offset bytes 0x00 0x00 → distance 1; no history
    // → should fail with InvalidDistance.
    let encoded = [0x40u8, 0x00, 0x00];
    let mut dec = Decoder::new();
    let mut out = [0u8; 16];
    let res = dec.decode(&encoded, &mut out);
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert_eq!(err, compcol::Error::InvalidDistance);
}

#[test]
fn decoder_self_overlapping_copy() {
    // Encode a single literal 'X' followed by a short-match referencing 1
    // byte back, length 18 — should generate 18 'X's via self-overlap.
    let encoded = [
        0x80u8,
        b'X',              // literal: length 1, 'X'
        ((18u8 - 3) << 2), // short-match tag: length 18, off_hi = 0
        0x00,              // off_lo = 0 → distance 1
    ];
    let mut dec = Decoder::new();
    let mut out = [0u8; 64];
    let (p, _) = dec.decode(&encoded, &mut out).unwrap();
    assert_eq!(p.written, 19);
    assert_eq!(&out[..19], &[b'X'; 19]);
    let (_pf, status) = dec.finish(&mut out).unwrap();
    assert!(matches!(status, Status::StreamEnd));
}

#[cfg(feature = "factory")]
mod factory {
    use compcol::Status;
    use compcol::factory;

    #[test]
    fn lookup_known() {
        assert!(factory::encoder_by_name("adc").is_some());
        assert!(factory::decoder_by_name("adc").is_some());
    }

    #[test]
    fn lookup_unknown() {
        assert!(factory::encoder_by_name("does-not-exist").is_none());
        assert!(factory::decoder_by_name("does-not-exist").is_none());
    }

    #[test]
    fn names_contains_adc() {
        assert!(factory::names().contains(&"adc"));
    }

    #[test]
    fn extension_is_adc() {
        assert_eq!(factory::extension("adc"), Some("adc"));
    }

    #[test]
    fn boxed_round_trip() {
        let mut enc = factory::encoder_by_name("adc").unwrap();
        let mut dec = factory::decoder_by_name("adc").unwrap();
        let input = b"hello hello hello hello hello hello";
        let mut scratch = vec![0u8; 256];
        let (_p, status) = enc.encode(input, &mut scratch).unwrap();
        assert!(matches!(status, Status::InputEmpty));

        let mut encoded = Vec::new();
        loop {
            let (pf, status) = enc.finish(&mut scratch).unwrap();
            encoded.extend_from_slice(&scratch[..pf.written]);
            match status {
                Status::StreamEnd => break,
                Status::OutputFull | Status::InputEmpty => {
                    if pf.written == 0 {
                        panic!("encoder finish stalled");
                    }
                }
            }
        }

        let mut decoded = Vec::new();
        let (pd, _) = dec.decode(&encoded, &mut scratch).unwrap();
        decoded.extend_from_slice(&scratch[..pd.written]);
        loop {
            let (pf, status) = dec.finish(&mut scratch).unwrap();
            decoded.extend_from_slice(&scratch[..pf.written]);
            match status {
                Status::StreamEnd => break,
                Status::OutputFull | Status::InputEmpty => {
                    if pf.written == 0 {
                        panic!("decoder finish stalled");
                    }
                }
            }
        }
        assert_eq!(&decoded, input);
    }
}
