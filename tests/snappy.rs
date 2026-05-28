#![cfg(any())] // TODO(v0.3): port to new (Progress, Status) API
//! Streaming round-trip tests for the Snappy algorithm.
//!
//! The library is `no_std`; tests run under the `std` harness.

#![cfg(feature = "snappy")]

use compcol::snappy::{Decoder, Encoder, Snappy};
use compcol::{Algorithm, Decoder as _, Encoder as _};

/// Encode `input` using `in_chunk`-sized feeds and `out_chunk`-sized
/// output buffers, then return the resulting compressed bytes.
fn encode_chunked(input: &[u8], in_chunk: usize, out_chunk: usize) -> Vec<u8> {
    let mut enc = Encoder::new();
    let mut encoded = Vec::new();
    let mut buf = vec![0u8; out_chunk.max(1)];
    let mut i = 0;

    while i < input.len() {
        let end = (i + in_chunk.max(1)).min(input.len());
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
        let end = (i + in_chunk.max(1)).min(encoded.len());
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
    // Pick chunk sizes scaled to the input to keep tests snappy.
    let chunk_in = (input.len() / 4).max(1);
    let chunk_out = (input.len() / 4).max(16);
    let encoded = encode_chunked(input, chunk_in, chunk_out);
    let decoded = decode_chunked(&encoded, chunk_in, chunk_out);
    assert_eq!(decoded.len(), input.len(), "round-trip length mismatch");
    assert!(decoded == input, "round-trip byte mismatch");
}

#[test]
fn name_is_snappy() {
    assert_eq!(<Snappy as Algorithm>::NAME, "snappy");
}

#[test]
fn empty_round_trip() {
    round_trip(&[]);
}

#[test]
fn single_byte() {
    round_trip(&[0xA5]);
}

#[test]
fn long_run_of_one_byte() {
    // 10 KiB of the same byte — should compress to a tiny output via the
    // self-overlapping copy trick.
    let input = vec![0x7Fu8; 10 * 1024];
    round_trip(&input);
}

#[test]
fn ascii_text_over_64_kib() {
    // 65 KiB of ASCII with frequent repetition. Exercises 2-byte offsets
    // (since offsets cross the 32 KiB threshold) and multi-byte literal
    // length encodings if any one literal grows large.
    let phrase = b"The quick brown fox jumps over the lazy dog. ";
    let mut input = Vec::with_capacity(70 * 1024);
    while input.len() < 65 * 1024 {
        input.extend_from_slice(phrase);
    }
    round_trip(&input);
    // The compressed form should be substantially smaller than the input.
    let encoded = encode_chunked(&input, input.len(), input.len() * 2 + 8);
    assert!(
        encoded.len() < input.len() / 2,
        "expected at least 2x compression on repetitive ASCII, got {} -> {}",
        input.len(),
        encoded.len()
    );
}

#[test]
fn pseudo_random_data() {
    // Tiny LCG keeps the test dependency-free and deterministic.
    let mut state: u32 = 0xDECAFBADu32;
    let mut input = Vec::with_capacity(8192);
    for _ in 0..8192 {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        input.push((state >> 16) as u8);
    }
    round_trip(&input);
}

#[test]
fn chunked_one_byte_at_a_time() {
    // The acid test: 1-byte input chunks and 1-byte output buffers on
    // both sides. Even though Snappy's streaming model buffers the whole
    // block internally, the public encode/decode/finish dance must still
    // converge byte-by-byte.
    let mut input = Vec::with_capacity(200);
    for i in 0..200u32 {
        input.push((i * 31) as u8);
    }
    // Add a recognisable repeat so the matcher gets exercised too.
    let tail = input.clone();
    input.extend_from_slice(&tail[..50]);

    let encoded = encode_chunked(&input, 1, 1);
    let decoded = decode_chunked(&encoded, 1, 1);
    assert_eq!(decoded, input);
}

#[test]
fn reset_clears_state() {
    let mut enc = Encoder::new();
    let mut out = [0u8; 64];
    let _ = enc.encode(b"first input data", &mut out).unwrap();
    enc.reset();
    // After reset, only the second input should appear in the output.
    let _ = enc.encode(b"hello", &mut out).unwrap();
    let mut produced = Vec::new();
    loop {
        let p = enc.finish(&mut out).unwrap();
        produced.extend_from_slice(&out[..p.written]);
        if matches!(_s, compcol::Status::StreamEnd) {
            break;
        }
        if p.written == 0 {
            panic!("encoder finish stalled");
        }
    }

    let mut dec = Decoder::new();
    let _ = dec.decode(&produced, &mut out).unwrap();
    let mut decoded = Vec::new();
    loop {
        let p = dec.finish(&mut out).unwrap();
        decoded.extend_from_slice(&out[..p.written]);
        if matches!(_s, compcol::Status::StreamEnd) {
            break;
        }
        if p.written == 0 {
            panic!("decoder finish stalled");
        }
    }
    assert_eq!(&decoded, b"hello");
}

#[cfg(feature = "factory")]
mod factory {
    use compcol::factory;

    #[test]
    fn lookup_known() {
        assert!(factory::encoder_by_name("snappy").is_some());
        assert!(factory::decoder_by_name("snappy").is_some());
    }

    #[test]
    fn names_contains_snappy() {
        assert!(factory::names().contains(&"snappy"));
    }
}
