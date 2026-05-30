//! Streaming round-trip and error-path tests for ARC Crunch (method 8 LZW).

#![cfg(feature = "arc_crunch")]

use compcol::arc_crunch::{ArcCrunch, Decoder, Encoder};
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
fn name_is_crunch() {
    assert_eq!(<ArcCrunch as Algorithm>::NAME, "crunch");
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
    // > 64 KiB drives nbits to 12 and at least one CLEAR.
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
    let line = b"compcol crunches bytes; arc method 8 is dynamic lzw.\n";
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

// ── error paths: crafted streams must not panic ──

#[test]
fn bad_maxbits_header_rejected() {
    // maxbits = 8 is below the minimum (9).
    let mut dec = Decoder::new();
    let mut buf = [0u8; 64];
    let r = dec.decode(&[8u8, 0x00, 0x01], &mut buf);
    assert_eq!(r, Err(Error::Unsupported));
}

#[test]
fn code_out_of_range_is_corrupt() {
    // maxbits=12 header, then a first code that is a literal (ok), then a
    // wildly out-of-range code. Construct a stream where the second 9-bit
    // code is 500 (>> next_code which would be 257) → Corrupt, no panic.
    // bytes after header: pack two 9-bit codes LSB-first: 65 ('A'), 500.
    let mut bits = Vec::new();
    let mut acc: u32 = 0;
    let mut cnt = 0u8;
    let push = |code: u32, n: u8, out: &mut Vec<u8>, acc: &mut u32, cnt: &mut u8| {
        *acc |= code << *cnt;
        *cnt += n;
        while *cnt >= 8 {
            out.push(*acc as u8);
            *acc >>= 8;
            *cnt -= 8;
        }
    };
    push(65, 9, &mut bits, &mut acc, &mut cnt);
    push(500, 9, &mut bits, &mut acc, &mut cnt);
    if cnt > 0 {
        bits.push(acc as u8);
    }
    let mut stream = vec![12u8];
    stream.extend_from_slice(&bits);

    let mut dec = Decoder::new();
    let mut buf = [0u8; 64];
    // Either the decode or the finish should surface an error; never panic.
    let saw_err = dec.decode(&stream, &mut buf).is_err() || dec.finish(&mut buf).is_err();
    assert!(saw_err, "expected Corrupt from out-of-range code");
}

#[test]
fn first_code_non_literal_is_corrupt() {
    // maxbits=12, first 9-bit code = 300 (>=256, not a literal) → Corrupt.
    let mut bits = Vec::new();
    let mut acc: u32 = 300;
    let mut cnt = 9u8;
    while cnt >= 8 {
        bits.push(acc as u8);
        acc >>= 8;
        cnt -= 8;
    }
    if cnt > 0 {
        bits.push(acc as u8);
    }
    let mut stream = vec![12u8];
    stream.extend_from_slice(&bits);
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
        assert!(factory::encoder_by_name("crunch").is_some());
        assert!(factory::decoder_by_name("crunch").is_some());
    }

    #[test]
    fn names_contains_crunch() {
        assert!(factory::names().contains(&"crunch"));
    }
}
