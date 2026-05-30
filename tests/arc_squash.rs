//! Streaming round-trip and error-path tests for ARC Squashed (method 9:
//! fixed 13-bit LZW, PKARC/PKPAK variant).

#![cfg(feature = "arc_squash")]

use compcol::arc_squash::{ArcSquash, Decoder, Encoder};
use compcol::{Algorithm, Decoder as _, Encoder as _, Error, Status};

fn encode_chunked(input: &[u8], in_chunk: usize, out_chunk: usize) -> Vec<u8> {
    let mut enc = Encoder::new();
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
                Status::OutputFull => {
                    if p.consumed == 0 && p.written == 0 {
                        panic!("encoder stalled mid-input");
                    }
                }
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
        let end = (i + in_chunk).min(encoded.len());
        let chunk = &encoded[i..end];
        let mut consumed = 0;
        while consumed < chunk.len() {
            let (p, status) = dec.decode(&chunk[consumed..], &mut buf).unwrap();
            decoded.extend_from_slice(&buf[..p.written]);
            consumed += p.consumed;
            match status {
                Status::InputEmpty | Status::StreamEnd => break,
                Status::OutputFull => {
                    if p.consumed == 0 && p.written == 0 {
                        panic!("decoder stalled mid-input");
                    }
                }
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
    let encoded = encode_chunked(input, input.len().max(1), input.len().max(64) * 2 + 16);
    let decoded = decode_chunked(&encoded, encoded.len().max(1), input.len().max(1));
    assert_eq!(decoded.len(), input.len(), "round-trip length mismatch");
    assert_eq!(decoded, input, "round-trip data mismatch");
}

#[test]
fn name_is_squashed() {
    assert_eq!(<ArcSquash as Algorithm>::NAME, "squashed");
}

#[test]
fn empty_input_round_trip() {
    round_trip(&[]);
}

#[test]
fn single_byte_round_trip() {
    round_trip(&[0x42]);
}

#[test]
fn hello_world_round_trip() {
    round_trip(b"hello world");
}

#[test]
fn long_run_of_one_byte() {
    let input = vec![b'Z'; 10 * 1024];
    round_trip(&input);
}

#[test]
fn ascii_text_forces_dictionary_clear() {
    // Enough text to fill the 8192-entry dictionary and force >= 1 CLEAR.
    let line = b"The quick brown fox jumps over the lazy dog.\n";
    let mut input = Vec::with_capacity(80 * 1024);
    while input.len() < 80 * 1024 {
        input.extend_from_slice(line);
    }
    round_trip(&input);
}

#[test]
fn mixed_corpus() {
    let mut input = Vec::with_capacity(64 * 1024);
    let line = b"compcol squashes bytes; arc method 9 is fixed 13-bit lzw.\n";
    while input.len() < 24 * 1024 {
        input.extend_from_slice(line);
    }
    let mut state: u32 = 0xC0FFEE;
    while input.len() < 48 * 1024 {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        input.push((state >> 16) as u8);
    }
    input.extend(core::iter::repeat_n(b'X', 16 * 1024));
    round_trip(&input);
}

#[test]
fn pseudo_random_data() {
    let mut state: u32 = 0xDEADBEEF;
    let mut input = Vec::with_capacity(8 * 1024);
    for _ in 0..8 * 1024 {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        input.push((state >> 16) as u8);
    }
    round_trip(&input);
}

#[test]
fn one_byte_at_a_time_round_trip() {
    let input: Vec<u8> = (0..2048u32).map(|i| ((i * 31) % 251) as u8).collect();
    let encoded = encode_chunked(&input, 1, 1);
    let decoded = decode_chunked(&encoded, 1, 1);
    assert_eq!(decoded, input);
}

#[test]
fn kwkwk_round_trip() {
    // Pattern that triggers immediate reuse of a newly-added code (KwKwK).
    let mut input = Vec::with_capacity(4096);
    for _ in 0..256 {
        input.extend_from_slice(b"abcabcabcabcabcd");
    }
    round_trip(&input);
}

#[test]
fn all_byte_values_round_trip() {
    let mut input = Vec::new();
    for rep in 0..40u32 {
        for b in 0..=255u32 {
            input.push(((b + rep) % 256) as u8);
        }
    }
    round_trip(&input);
}

#[test]
fn dictionary_clear_forcing_input() {
    // > 8192 distinct codes drive at least one CLEAR/reset cycle. Use a long
    // walk over all 256 byte values that keeps producing fresh phrases.
    let mut input = Vec::with_capacity(64 * 1024);
    let mut state: u32 = 0x12345678;
    for _ in 0..48 * 1024 {
        state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        input.push((state >> 24) as u8);
    }
    round_trip(&input);
}

// ── error paths: crafted streams must not panic ──

/// Pack a sequence of fixed 13-bit codes LSB-first into a byte vector.
fn pack_codes(codes: &[u32]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut acc: u64 = 0;
    let mut cnt: u8 = 0;
    for &code in codes {
        acc |= (code as u64) << cnt;
        cnt += 13;
        while cnt >= 8 {
            out.push(acc as u8);
            acc >>= 8;
            cnt -= 8;
        }
    }
    if cnt > 0 {
        out.push(acc as u8);
    }
    out
}

#[test]
fn code_out_of_range_is_corrupt() {
    // First code a literal ('A' = 65), then a wildly out-of-range code (500,
    // far past next_code which is 257) → Corrupt, never a panic.
    let stream = pack_codes(&[65, 500]);
    let mut dec = Decoder::new();
    let mut buf = [0u8; 64];
    let saw_err = dec.decode(&stream, &mut buf).is_err() || dec.finish(&mut buf).is_err();
    assert!(saw_err, "expected Corrupt from out-of-range code");
}

#[test]
fn first_code_non_literal_is_corrupt() {
    // First 13-bit code = 300 (>= 256, not a literal) → Corrupt.
    let stream = pack_codes(&[300]);
    let mut dec = Decoder::new();
    let mut buf = [0u8; 64];
    let r1 = dec.decode(&stream, &mut buf);
    let r2 = dec.finish(&mut buf);
    assert!(r1 == Err(Error::Corrupt) || r2 == Err(Error::Corrupt));
}

#[test]
fn reset_clears_state() {
    let mut enc = Encoder::new();
    let mut out = [0u8; 64];
    let _ = enc.encode(b"hello", &mut out).unwrap();
    enc.reset();

    // After reset, encoding "AB" must produce the same stream a fresh encoder
    // would, and that stream must decode back to "AB".
    let mut produced = Vec::new();
    let (p, _) = enc.encode(b"AB", &mut out).unwrap();
    produced.extend_from_slice(&out[..p.written]);
    loop {
        let (p, s) = enc.finish(&mut out).unwrap();
        produced.extend_from_slice(&out[..p.written]);
        if matches!(s, Status::StreamEnd) {
            break;
        }
    }

    let fresh = encode_chunked(b"AB", 2, 64);
    assert_eq!(produced, fresh);
    assert_eq!(decode_chunked(&produced, produced.len(), 64), b"AB");
}

#[cfg(feature = "factory")]
mod factory {
    use compcol::factory;

    #[test]
    fn lookup_known() {
        assert!(factory::encoder_by_name("squashed").is_some());
        assert!(factory::decoder_by_name("squashed").is_some());
    }

    #[test]
    fn names_contains_squashed() {
        assert!(factory::names().contains(&"squashed"));
    }
}
