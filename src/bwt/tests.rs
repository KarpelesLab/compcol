//! Round-trip and robustness tests for the BWT block codec.

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use super::{Bwt, Decoder, Encoder, EncoderConfig};
use crate::error::Error;
use crate::traits::{Algorithm, Decoder as _, Encoder as _, Status};

/// Drive an `Encoder` to completion over `input`, returning the encoded bytes.
/// Uses a deliberately small output buffer to exercise the drain loop.
fn encode_all(mut enc: Encoder, input: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = [0u8; 17];
    let mut consumed = 0;
    while consumed < input.len() {
        let (p, status) = enc.encode(&input[consumed..], &mut buf).unwrap();
        out.extend_from_slice(&buf[..p.written]);
        consumed += p.consumed;
        if matches!(status, Status::InputEmpty) {
            break;
        }
    }
    loop {
        let (p, status) = enc.finish(&mut buf).unwrap();
        out.extend_from_slice(&buf[..p.written]);
        if matches!(status, Status::StreamEnd) {
            break;
        }
    }
    out
}

/// Drive a `Decoder` to completion over `encoded`, returning the decoded bytes.
fn decode_all(mut dec: Decoder, encoded: &[u8]) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    let mut buf = [0u8; 19];
    let mut consumed = 0;
    while consumed < encoded.len() {
        let (p, status) = dec.decode(&encoded[consumed..], &mut buf)?;
        out.extend_from_slice(&buf[..p.written]);
        consumed += p.consumed;
        if matches!(status, Status::StreamEnd) {
            return Ok(out);
        }
        if matches!(status, Status::InputEmpty) {
            break;
        }
    }
    loop {
        let (p, status) = dec.finish(&mut buf)?;
        out.extend_from_slice(&buf[..p.written]);
        if matches!(status, Status::StreamEnd) {
            break;
        }
    }
    Ok(out)
}

fn roundtrip_with(block_size: usize, input: &[u8]) {
    let enc = Bwt::encoder_with(EncoderConfig::default().with_block_size(block_size));
    let encoded = encode_all(enc, input);
    let dec = Bwt::decoder();
    let decoded = decode_all(dec, &encoded).expect("decode failed");
    assert_eq!(
        decoded, input,
        "roundtrip mismatch (block_size={block_size})"
    );
}

fn roundtrip(input: &[u8]) {
    // Default block size, plus a couple of small sizes to force multi-block.
    roundtrip_with(super::DEFAULT_BLOCK_SIZE, input);
    roundtrip_with(64, input);
    roundtrip_with(1, input);
    roundtrip_with(7, input);
}

#[test]
fn empty_input_produces_empty_stream() {
    let enc = Bwt::encoder();
    let encoded = encode_all(enc, b"");
    assert!(encoded.is_empty(), "empty input must emit zero blocks");
    let decoded = decode_all(Bwt::decoder(), &encoded).unwrap();
    assert!(decoded.is_empty());
}

#[test]
fn one_byte() {
    roundtrip(b"X");
}

#[test]
fn repetitive_banana() {
    roundtrip(b"banana");
    roundtrip(b"bananabananabanana");
    roundtrip(b"mississippi");
}

#[test]
fn english_text_multiblock() {
    let text = b"The Burrows-Wheeler transform rearranges a character string into \
                 runs of similar characters. This is useful for compression, since \
                 it tends to be easy to compress a string that has runs of repeated \
                 characters by techniques such as move-to-front transform and \
                 run-length encoding. More importantly, the transformation is \
                 reversible, without needing to store any additional data except \
                 the position of the first original character.";
    roundtrip(text);
}

#[test]
fn all_byte_values() {
    let block: Vec<u8> = (0..=255u8).collect();
    roundtrip(&block);
    // Repeated a few times so multiple blocks at small sizes have full alphabet.
    let mut big = Vec::new();
    for _ in 0..4 {
        big.extend_from_slice(&block);
    }
    roundtrip(&big);
}

#[test]
fn all_same_byte() {
    roundtrip(&[0u8; 100]);
    roundtrip(&[0xAB; 257]);
}

#[test]
fn pseudo_random() {
    // Simple xorshift PRNG — deterministic, no deps.
    let mut state = 0x1234_5678_9abc_def0u64;
    let mut data = Vec::with_capacity(5000);
    for _ in 0..5000 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        data.push((state & 0xff) as u8);
    }
    roundtrip(&data);
}

#[test]
fn multi_block_larger_than_block_size() {
    // Input strictly larger than the block size forces >1 block.
    let mut data = Vec::new();
    let mut state = 0xdead_beefu32;
    for _ in 0..1000 {
        state = state.wrapping_mul(1664525).wrapping_add(1013904223);
        data.push((state >> 16) as u8);
    }
    roundtrip_with(100, &data); // 10 full blocks
    roundtrip_with(333, &data); // 3 blocks + remainder
}

#[test]
fn default_block_size_is_256k() {
    assert_eq!(super::DEFAULT_BLOCK_SIZE, 256 * 1024);
    assert_eq!(EncoderConfig::default().block_size, 256 * 1024);
}

#[test]
fn block_size_clamped() {
    // Zero clamps up to MIN, absurdly large clamps down to MAX.
    let enc = Encoder::new(0);
    assert_eq!(enc.block_size, super::MIN_BLOCK_SIZE);
    let enc = Encoder::new(usize::MAX);
    assert_eq!(enc.block_size, super::MAX_BLOCK_SIZE);
}

// ─── malformed-input rejection (no panics) ───────────────────────────────

#[test]
fn rejects_truncated_header() {
    // Fewer than 8 header bytes.
    for len in 1..8 {
        let bad = vec![0u8; len];
        let err = decode_all(Bwt::decoder(), &bad).unwrap_err();
        assert_eq!(err, Error::UnexpectedEnd);
    }
}

#[test]
fn rejects_zero_length_block() {
    // len=0, primary=0, no payload.
    let mut bad = Vec::new();
    bad.extend_from_slice(&0u32.to_le_bytes());
    bad.extend_from_slice(&0u32.to_le_bytes());
    let err = decode_all(Bwt::decoder(), &bad).unwrap_err();
    assert_eq!(err, Error::Corrupt);
}

#[test]
fn rejects_primary_out_of_range() {
    // len=3, primary=3 (== len, invalid), 3 payload bytes.
    let mut bad = Vec::new();
    bad.extend_from_slice(&3u32.to_le_bytes());
    bad.extend_from_slice(&3u32.to_le_bytes());
    bad.extend_from_slice(b"abc");
    let err = decode_all(Bwt::decoder(), &bad).unwrap_err();
    assert_eq!(err, Error::Corrupt);
}

#[test]
fn rejects_truncated_payload() {
    // len=10 but only 4 payload bytes present.
    let mut bad = Vec::new();
    bad.extend_from_slice(&10u32.to_le_bytes());
    bad.extend_from_slice(&0u32.to_le_bytes());
    bad.extend_from_slice(b"abcd");
    let err = decode_all(Bwt::decoder(), &bad).unwrap_err();
    assert_eq!(err, Error::UnexpectedEnd);
}

#[test]
fn arbitrary_garbage_never_panics() {
    // Feed a variety of random-ish byte strings; decode must return a result
    // (Ok or Err) and never panic.
    let mut state = 0xabcd_1234u32;
    for _ in 0..200 {
        let mut data = Vec::new();
        state = state.wrapping_mul(1103515245).wrapping_add(12345);
        let n = (state >> 24) as usize % 40;
        for _ in 0..n {
            state = state.wrapping_mul(1103515245).wrapping_add(12345);
            data.push((state >> 16) as u8);
        }
        let _ = decode_all(Bwt::decoder(), &data);
    }
}

// ─── classic clustering property ─────────────────────────────────────────

#[test]
fn clusters_runs_on_repetitive_text() {
    // BWT of repetitive text should produce more/longer runs than the input.
    // We check that the last column of a single block has strictly fewer
    // "transitions" (adjacent differing bytes) than the original for a highly
    // structured input — the property that makes BWT useful.
    let input = b"abcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabc";
    let enc = Bwt::encoder_with(EncoderConfig::default().with_block_size(input.len()));
    let encoded = encode_all(enc, input);
    // Skip the 8-byte header to get the last column.
    let last_col = &encoded[8..];
    let transitions = |s: &[u8]| s.windows(2).filter(|w| w[0] != w[1]).count();
    assert!(
        transitions(last_col) < transitions(input),
        "BWT should cluster runs: input transitions {}, L transitions {}",
        transitions(input),
        transitions(last_col)
    );
}

#[test]
fn reset_reuses_encoder_and_decoder() {
    let mut enc = Bwt::encoder();
    let _ = encode_all_inplace(&mut enc, b"first stream");
    enc.reset();
    let encoded = encode_all_inplace(&mut enc, b"second stream");
    let decoded = decode_all(Bwt::decoder(), &encoded).unwrap();
    assert_eq!(decoded, b"second stream");
}

fn encode_all_inplace(enc: &mut Encoder, input: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = [0u8; 32];
    let mut consumed = 0;
    while consumed < input.len() {
        let (p, status) = enc.encode(&input[consumed..], &mut buf).unwrap();
        out.extend_from_slice(&buf[..p.written]);
        consumed += p.consumed;
        if matches!(status, Status::InputEmpty) {
            break;
        }
    }
    loop {
        let (p, status) = enc.finish(&mut buf).unwrap();
        out.extend_from_slice(&buf[..p.written]);
        if matches!(status, Status::StreamEnd) {
            break;
        }
    }
    out
}
