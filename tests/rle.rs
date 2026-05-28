//! Streaming round-trip tests for the RLE algorithm.
//!
//! Tests run under the `std` test harness but the library itself is `no_std`.

#![cfg(feature = "rle")]

use compcol::rle::{Decoder, Encoder, Rle};
use compcol::{Algorithm, Decoder as _, Encoder as _, Error};

/// Encode `input` into `dst` using the supplied output-chunk size, then
/// return the encoded bytes.
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
        if p.done {
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
        if p.done {
            break;
        }
        if p.written == 0 {
            panic!("decoder finish stalled");
        }
    }

    decoded
}

fn round_trip(input: &[u8]) {
    let encoded = encode_chunked(input, input.len().max(1), input.len() * 2 + 2);
    let decoded = decode_chunked(&encoded, encoded.len().max(1), input.len().max(1));
    assert_eq!(decoded, input, "round-trip mismatch");
}

#[test]
fn name_is_rle() {
    assert_eq!(<Rle as Algorithm>::NAME, "rle");
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
fn run_of_one() {
    round_trip(b"abcdef");
}

#[test]
fn long_run_forces_split() {
    // 600 zero bytes — three pairs of (255,0), (255,0), (90,0).
    let input = vec![0u8; 600];
    round_trip(&input);
}

#[test]
fn mixed_runs() {
    let mut input = Vec::new();
    input.extend(core::iter::repeat_n(b'a', 10));
    input.extend(core::iter::repeat_n(b'b', 1));
    input.extend(core::iter::repeat_n(b'c', 300));
    input.extend(core::iter::repeat_n(b'd', 255));
    input.extend(core::iter::repeat_n(b'd', 1)); // forces a 255+1 split
    round_trip(&input);
}

#[test]
fn pseudo_random_input() {
    // Tiny LCG, fixed seed; keeps the test dependency-free.
    let mut state: u32 = 0xC0FFEEu32;
    let mut input = Vec::with_capacity(2048);
    for _ in 0..2048 {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        input.push((state >> 16) as u8);
    }
    round_trip(&input);
}

#[test]
fn chunked_one_byte_at_a_time() {
    // The acid test: 1-byte buffers on both input and output, on both sides.
    let input: Vec<u8> = (0..512u32).map(|i| (i % 7) as u8).collect();
    let encoded = encode_chunked(&input, 1, 1);
    let decoded = decode_chunked(&encoded, 1, 1);
    assert_eq!(decoded, input);
}

#[test]
fn corrupt_zero_count_rejected() {
    let mut dec = Decoder::new();
    let mut out = [0u8; 4];
    let err = dec.decode(&[0x00, 0x42], &mut out).unwrap_err();
    assert_eq!(err, Error::Corrupt);
}

#[test]
fn truncated_pair_rejected() {
    let mut dec = Decoder::new();
    let mut out = [0u8; 4];
    let p = dec.decode(&[0x03], &mut out).unwrap(); // count only
    assert_eq!(p.consumed, 1);
    assert_eq!(p.written, 0);
    let err = dec.finish(&mut out).unwrap_err();
    assert_eq!(err, Error::UnexpectedEnd);
}

#[test]
fn reset_clears_state() {
    let mut enc = Encoder::new();
    let mut out = [0u8; 16];
    let _ = enc.encode(b"aaaa", &mut out).unwrap();
    enc.reset();
    // After reset, encoding new input followed by finish should produce just
    // that input's encoding, with no leftover state from before.
    let mut produced = Vec::new();
    let p = enc.encode(b"bbb", &mut out).unwrap();
    produced.extend_from_slice(&out[..p.written]);
    let p = enc.finish(&mut out).unwrap();
    produced.extend_from_slice(&out[..p.written]);
    assert!(p.done);
    assert_eq!(produced, vec![3, b'b']);
}

#[cfg(feature = "factory")]
mod factory {
    use compcol::factory;

    #[test]
    fn lookup_known() {
        assert!(factory::encoder_by_name("rle").is_some());
        assert!(factory::decoder_by_name("rle").is_some());
    }

    #[test]
    fn lookup_unknown() {
        assert!(factory::encoder_by_name("does-not-exist").is_none());
        assert!(factory::decoder_by_name("does-not-exist").is_none());
    }

    #[test]
    fn names_contains_rle() {
        assert!(factory::names().contains(&"rle"));
    }

    #[test]
    fn boxed_round_trip() {
        let mut enc = factory::encoder_by_name("rle").unwrap();
        let mut dec = factory::decoder_by_name("rle").unwrap();
        let input = b"hello hello hello";
        let mut encoded = vec![0u8; 64];
        let p = enc.encode(input, &mut encoded).unwrap();
        let consumed = p.consumed;
        assert_eq!(consumed, input.len());
        let mut tail = vec![0u8; 16];
        let pf = enc.finish(&mut tail).unwrap();
        assert!(pf.done);
        let mut all = Vec::new();
        all.extend_from_slice(&encoded[..p.written]);
        all.extend_from_slice(&tail[..pf.written]);

        let mut out = vec![0u8; input.len()];
        let pd = dec.decode(&all, &mut out).unwrap();
        let pdf = dec.finish(&mut out[pd.written..]).unwrap();
        assert!(pdf.done);
        assert_eq!(&out[..pd.written + pdf.written], input);
    }
}
