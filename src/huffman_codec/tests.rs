//! Round-trip and malformed-input tests for the standalone Huffman codec.

use super::*;
use crate::traits::{Decoder as _, Encoder as _, Status};
use alloc::vec;
use alloc::vec::Vec;

/// Encode `input` through the streaming encoder, draining into a Vec.
fn encode(input: &[u8]) -> Vec<u8> {
    let mut enc = Encoder::new();
    let mut out = Vec::new();
    let mut scratch = [0u8; 7]; // deliberately tiny to exercise drain loops
    let mut consumed = 0;
    while consumed < input.len() {
        let (p, st) = enc.encode(&input[consumed..], &mut scratch).unwrap();
        out.extend_from_slice(&scratch[..p.written]);
        consumed += p.consumed;
        match st {
            Status::InputEmpty => break,
            Status::OutputFull => continue,
            Status::StreamEnd => break,
        }
    }
    loop {
        let (p, st) = enc.finish(&mut scratch).unwrap();
        out.extend_from_slice(&scratch[..p.written]);
        if matches!(st, Status::StreamEnd) {
            break;
        }
        assert!(p.written > 0, "finish stalled");
    }
    out
}

/// Decode `stream` through the streaming decoder, draining into a Vec.
fn decode(stream: &[u8]) -> Result<Vec<u8>, Error> {
    let mut dec = Decoder::new();
    let mut out = Vec::new();
    let mut scratch = [0u8; 5]; // tiny to exercise drain loops
    // Feed all input first (decoder buffers until finish).
    let mut consumed = 0;
    while consumed < stream.len() {
        let (p, _st) = dec.decode(&stream[consumed..], &mut scratch)?;
        out.extend_from_slice(&scratch[..p.written]);
        consumed += p.consumed;
        if p.consumed == 0 && p.written == 0 {
            break;
        }
    }
    loop {
        let (p, st) = dec.finish(&mut scratch)?;
        out.extend_from_slice(&scratch[..p.written]);
        if matches!(st, Status::StreamEnd) {
            break;
        }
        assert!(p.written > 0, "finish stalled");
    }
    Ok(out)
}

fn roundtrip(input: &[u8]) -> Vec<u8> {
    let enc = encode(input);
    let dec = decode(&enc).expect("decode should succeed");
    assert_eq!(dec, input, "round-trip mismatch");
    enc
}

#[test]
fn empty_input() {
    let enc = roundtrip(&[]);
    // Empty stream is just the varint 0.
    assert_eq!(enc, vec![0x00]);
}

#[test]
fn single_byte() {
    roundtrip(&[0x42]);
}

#[test]
fn single_symbol_repeated() {
    let input = vec![0xABu8; 10_000];
    let enc = roundtrip(&input);
    // 1-bit code → ~ceil(10000/8) payload + small header. Must be a big shrink.
    assert!(
        enc.len() < input.len() / 4,
        "single-symbol input should shrink ~8x, got {} from {}",
        enc.len(),
        input.len()
    );
}

#[test]
fn english_text() {
    let text = b"the quick brown fox jumps over the lazy dog. \
                 the quick brown fox jumps over the lazy dog. \
                 pack my box with five dozen liquor jugs. \
                 how vexingly quick daft zebras jump!";
    let mut input = Vec::new();
    for _ in 0..50 {
        input.extend_from_slice(text);
    }
    let enc = roundtrip(&input);
    assert!(
        enc.len() < input.len(),
        "english text must shrink: {} -> {}",
        input.len(),
        enc.len()
    );
}

#[test]
fn all_byte_values_once() {
    let input: Vec<u8> = (0..=255u16).map(|b| b as u8).collect();
    roundtrip(&input);
}

#[test]
fn all_byte_values_many() {
    // Each value present, varied frequencies.
    let mut input = Vec::new();
    for b in 0..=255u16 {
        for _ in 0..(1 + (b % 7)) {
            input.push(b as u8);
        }
    }
    roundtrip(&input);
}

#[test]
fn highly_skewed() {
    // One symbol dominates; a few rare others.
    let mut input = vec![0u8; 5000];
    input.extend_from_slice(&[1, 2, 3, 4, 5, 1, 2, 1]);
    input.extend(vec![0u8; 5000]);
    let enc = roundtrip(&input);
    assert!(
        enc.len() < input.len() / 4,
        "skewed input should shrink hard"
    );
}

#[test]
fn pseudo_random() {
    // A simple xorshift PRNG — high entropy, should round-trip exactly even
    // if it doesn't shrink.
    let mut state: u32 = 0x1234_5678;
    let mut input = Vec::with_capacity(4096);
    for _ in 0..4096 {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        input.push((state & 0xFF) as u8);
    }
    roundtrip(&input);
}

#[test]
fn two_symbols() {
    let mut input = Vec::new();
    for i in 0..1000 {
        input.push(if i % 3 == 0 { b'A' } else { b'B' });
    }
    roundtrip(&input);
}

#[test]
fn one_shot_vec_helpers() {
    let input = b"compression makes things smaller, sometimes, when there is redundancy";
    let enc = crate::vec::compress_to_vec::<Huffman>(input).unwrap();
    let dec = crate::vec::decompress_to_vec::<Huffman>(&enc).unwrap();
    assert_eq!(dec, input);
}

// ─── code-length table RLE unit tests ─────────────────────────────────────

#[test]
fn length_table_roundtrip_various() {
    let cases: &[[u8; 256]] = &[
        [0u8; 256],
        {
            let mut a = [0u8; 256];
            a[65] = 1; // single symbol, 1-bit
            a
        },
        {
            let mut a = [3u8; 256]; // all length 3 (not valid Kraft, but RLE only)
            a[0] = 15;
            a[255] = 1;
            a
        },
    ];
    for case in cases {
        let mut buf = Vec::new();
        encode_lengths(case, &mut buf);
        let (decoded, consumed) = decode_lengths(&buf).unwrap();
        assert_eq!(consumed, buf.len());
        assert_eq!(&decoded, case);
    }
}

// ─── malformed-input rejection (no panic, Error::Corrupt) ─────────────────

#[test]
fn truncated_varint_is_corrupt() {
    // A varint with continuation bit set but no following byte.
    assert_eq!(decode(&[0x80]).unwrap_err(), Error::Corrupt);
}

#[test]
fn truncated_table_is_corrupt() {
    // Nonzero length but the table commands run out before 256 entries.
    let stream = [0x05u8, 0x01]; // len=5, then one literal-length command, then EOF
    let err = decode(&stream).unwrap_err();
    assert_eq!(err, Error::Corrupt);
}

#[test]
fn oversubscribed_tree_is_corrupt() {
    // Build a table that over-fills the Kraft budget: many short codes.
    // 256 symbols all with length 1 → kraft = 256 * 2^14 ≫ 2^15.
    let mut stream = Vec::new();
    write_varint(&mut stream, 4); // claim 4 output bytes
    let lengths = [1u8; 256];
    encode_lengths(&lengths, &mut stream);
    // Append some payload bytes so we don't fail on EOF first.
    stream.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);
    let err = decode(&stream).unwrap_err();
    assert_eq!(err, Error::Corrupt);
}

#[test]
fn incomplete_tree_is_corrupt() {
    // Two symbols each with length 2: kraft = 2 * 2^13 = 2^14 < 2^15.
    // Incomplete (not single-symbol) → rejected.
    let mut stream = Vec::new();
    write_varint(&mut stream, 2);
    let mut lengths = [0u8; 256];
    lengths[10] = 2;
    lengths[20] = 2;
    encode_lengths(&lengths, &mut stream);
    stream.extend_from_slice(&[0x00, 0x00]);
    let err = decode(&stream).unwrap_err();
    assert_eq!(err, Error::Corrupt);
}

#[test]
fn length_over_15_is_corrupt() {
    // Hand-craft a stream whose F1 command declares a length of 16.
    let mut stream = Vec::new();
    write_varint(&mut stream, 1);
    stream.push(0xF1);
    stream.push(16); // illegal length
    stream.push(0); // k=0 → 19 repeats
    let err = decode(&stream).unwrap_err();
    assert_eq!(err, Error::Corrupt);
}

#[test]
fn reset_reuses_encoder_and_decoder() {
    let mut enc = Encoder::new();
    let mut scratch = [0u8; 64];
    enc.encode(b"first", &mut scratch).unwrap();
    let mut first = Vec::new();
    loop {
        let (p, st) = enc.finish(&mut scratch).unwrap();
        first.extend_from_slice(&scratch[..p.written]);
        if matches!(st, Status::StreamEnd) {
            break;
        }
    }
    enc.reset();
    // After reset, encoder produces a fresh stream for new input.
    let again = encode(b"second");
    assert_eq!(decode(&again).unwrap(), b"second");
    assert_eq!(decode(&first).unwrap(), b"first");
}

#[test]
fn truncated_payload_is_unexpected_end() {
    // Valid header but payload too short to decode the claimed length.
    let full = encode(b"abracadabra");
    // Drop the final payload byte.
    let truncated = &full[..full.len() - 1];
    let err = decode(truncated).unwrap_err();
    // Either UnexpectedEnd (ran out of bits) — must not panic.
    assert!(matches!(err, Error::UnexpectedEnd | Error::Corrupt));
}
