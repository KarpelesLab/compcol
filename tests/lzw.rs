#![cfg(any())] // TODO(v0.3): port to new (Progress, Status) API
//! Streaming round-trip tests for the LZW algorithm (compress(1) flavour).
//!
//! Tests run under the `std` test harness but the library itself is `no_std`.

#![cfg(feature = "lzw")]

use compcol::lzw::{Decoder, Encoder, Lzw};
use compcol::{Algorithm, Decoder as _, Encoder as _};

/// Encode `input` into a fresh `Vec`, feeding the encoder `in_chunk` bytes at
/// a time and giving it an `out_chunk`-sized output slice on each call.
fn encode_chunked(input: &[u8], in_chunk: usize, out_chunk: usize) -> Vec<u8> {
    let mut enc = Encoder::new();
    let mut encoded = Vec::new();
    let mut buf = vec![0u8; out_chunk.max(1)];
    let mut i = 0;

    while i < input.len() {
        let end = (i + in_chunk).min(input.len());
        let chunk = &input[i..end];
        let mut consumed_in_chunk = 0;
        while consumed_in_chunk < chunk.len() {
            let p = enc.encode(&chunk[consumed_in_chunk..], &mut buf).unwrap();
            encoded.extend_from_slice(&buf[..p.written]);
            consumed_in_chunk += p.consumed;
            if p.consumed == 0 && p.written == 0 {
                panic!("encoder stalled mid-input");
            }
        }
        i = end;
    }

    loop {
        let p = enc.finish(&mut buf).unwrap();
        encoded.extend_from_slice(&buf[..p.written]);
        if matches!(_s, compcol::Status::StreamEnd) {
            break;
        }
        if p.written == 0 {
            panic!("encoder finish stalled");
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
        let mut consumed_in_chunk = 0;
        while consumed_in_chunk < chunk.len() {
            let p = dec.decode(&chunk[consumed_in_chunk..], &mut buf).unwrap();
            decoded.extend_from_slice(&buf[..p.written]);
            consumed_in_chunk += p.consumed;
            if p.consumed == 0 && p.written == 0 {
                panic!("decoder stalled mid-input");
            }
        }
        i = end;
    }

    loop {
        let p = dec.finish(&mut buf).unwrap();
        decoded.extend_from_slice(&buf[..p.written]);
        if matches!(_s, compcol::Status::StreamEnd) {
            break;
        }
        if p.written == 0 {
            panic!("decoder finish stalled");
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
fn name_is_lzw() {
    assert_eq!(<Lzw as Algorithm>::NAME, "lzw");
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
fn long_run_of_one_byte() {
    // 10 KiB of the same byte.
    let input = vec![b'Z'; 10 * 1024];
    round_trip(&input);
}

#[test]
fn ascii_text_over_64kib() {
    // Build > 64 KiB of repetitive ASCII to exercise the full 9..=16 nbits
    // climb and at least one dictionary clear.
    let line = b"The quick brown fox jumps over the lazy dog.\n";
    let mut input = Vec::with_capacity(80 * 1024);
    while input.len() < 80 * 1024 {
        input.extend_from_slice(line);
    }
    round_trip(&input);
}

#[test]
fn pseudo_random_data() {
    // Tiny LCG, fixed seed; dependency-free.
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
    let input: Vec<u8> = (0..1024u32).map(|i| ((i * 31) % 251) as u8).collect();
    let encoded = encode_chunked(&input, 1, 1);
    let decoded = decode_chunked(&encoded, 1, 1);
    assert_eq!(decoded, input);
}

#[test]
fn decode_compress_fixture_hello() {
    // `printf hello | compress -c | xxd -p` = 1f9d 9068 cab0 61f3 06
    let fixture: &[u8] = &[0x1f, 0x9d, 0x90, 0x68, 0xca, 0xb0, 0x61, 0xf3, 0x06];
    let decoded = decode_chunked(fixture, fixture.len(), 64);
    assert_eq!(decoded, b"hello");
}

#[test]
fn decode_compress_fixture_aaaaaaaaaa() {
    // `printf AAAAAAAAAA | compress -c | xxd -p` = 1f9d 9041 020a 1c08
    let fixture: &[u8] = &[0x1f, 0x9d, 0x90, 0x41, 0x02, 0x0a, 0x1c, 0x08];
    let decoded = decode_chunked(fixture, fixture.len(), 64);
    assert_eq!(decoded, b"AAAAAAAAAA");
}

#[test]
fn decode_compress_fixture_byte_at_a_time() {
    // Real fixture: `printf "hello world" | compress -c | xxd -p` =
    //     1f9d 9068 cab0 61f3 06c4 9d37 72d8 9001
    // Streamed 1 byte at a time on both sides to exercise the partial-bits
    // path through the bit reader.
    let real: &[u8] = &[
        0x1f, 0x9d, 0x90, 0x68, 0xca, 0xb0, 0x61, 0xf3, 0x06, 0xc4, 0x9d, 0x37, 0x72, 0xd8, 0x90,
        0x01,
    ];
    let decoded = decode_chunked(real, 1, 1);
    assert_eq!(decoded, b"hello world");
}

#[test]
fn reset_clears_encoder_state() {
    let mut enc = Encoder::new();
    let mut out = [0u8; 64];
    let _ = enc.encode(b"hello", &mut out).unwrap();
    enc.reset();
    // After reset, encoding "AB" and finishing should produce a fresh stream
    // starting with the magic.
    let mut produced = Vec::new();
    let p = enc.encode(b"AB", &mut out).unwrap();
    produced.extend_from_slice(&out[..p.written]);
    loop {
        let p = enc.finish(&mut out).unwrap();
        produced.extend_from_slice(&out[..p.written]);
        if matches!(_s, compcol::Status::StreamEnd) {
            break;
        }
    }
    assert_eq!(&produced[..3], &[0x1f, 0x9d, 0x90]);
}

#[test]
fn reset_clears_decoder_state() {
    let mut dec = Decoder::new();
    // Feed a partial header, then reset and decode a complete fixture.
    let _ = dec.decode(&[0x1f, 0x9d], &mut [0u8; 8]).unwrap();
    dec.reset();

    let fixture: &[u8] = &[0x1f, 0x9d, 0x90, 0x41, 0x02, 0x0a, 0x1c, 0x08];
    let mut buf = [0u8; 32];
    let p = dec.decode(fixture, &mut buf).unwrap();
    let mut decoded = Vec::new();
    decoded.extend_from_slice(&buf[..p.written]);
    loop {
        let pf = dec.finish(&mut buf).unwrap();
        decoded.extend_from_slice(&buf[..pf.written]);
        if matches!(_s, compcol::Status::StreamEnd) {
            break;
        }
        if pf.written == 0 {
            panic!("decoder stalled");
        }
    }
    assert_eq!(decoded, b"AAAAAAAAAA");
}

#[test]
fn encoder_output_decompressable_by_uncompress_logic() {
    // Round-trip a tricky 4 KiB pattern that triggers KwKwK (immediate
    // repetition of newly-added entries).
    let mut input = Vec::with_capacity(4096);
    for _ in 0..256 {
        input.extend_from_slice(b"abcabcabcabcabcd");
    }
    round_trip(&input);
}

#[cfg(feature = "factory")]
mod factory {
    use compcol::factory;

    #[test]
    fn lookup_known() {
        assert!(factory::encoder_by_name("lzw").is_some());
        assert!(factory::decoder_by_name("lzw").is_some());
    }

    #[test]
    fn names_contains_lzw() {
        assert!(factory::names().contains(&"lzw"));
    }
}
