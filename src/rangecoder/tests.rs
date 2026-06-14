//! Round-trip, compression, and robustness tests for the adaptive order-0
//! range coder. All tests drive the public streaming [`Encoder`] /
//! [`Decoder`] traits exactly as a downstream caller would.

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use super::RangeCoder;
use crate::error::Error;
use crate::traits::{Algorithm, Decoder, Encoder, Status};

/// Encode `input` to a single owned buffer, driving the streaming loop with
/// modestly-sized output chunks so the drain paths get exercised.
fn encode(input: &[u8]) -> Vec<u8> {
    let mut enc = RangeCoder::encoder();
    let mut out = Vec::new();
    let mut buf = [0u8; 64];
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

/// Decode `input`, returning the produced bytes or the decoder error.
fn decode(input: &[u8]) -> Result<Vec<u8>, Error> {
    let mut dec = RangeCoder::decoder();
    let mut out = Vec::new();
    let mut buf = [0u8; 64];
    let mut consumed = 0;
    while consumed < input.len() {
        let (p, status) = dec.decode(&input[consumed..], &mut buf)?;
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

fn round_trip(input: &[u8]) {
    let enc = encode(input);
    let dec = decode(&enc).expect("decode should succeed on our own output");
    assert_eq!(dec, input, "round-trip mismatch (len {})", input.len());
}

// ─── round-trip correctness ───────────────────────────────────────────────

#[test]
fn empty_round_trips() {
    round_trip(&[]);
    // Empty input: 8-byte header, no payload.
    assert_eq!(encode(&[]).len(), 8);
}

#[test]
fn single_byte_round_trips() {
    for b in 0u16..=255 {
        round_trip(&[b as u8]);
    }
}

#[test]
fn two_bytes_round_trip() {
    round_trip(&[0x00, 0xFF]);
    round_trip(&[0xFF, 0x00]);
    round_trip(&[0xAA, 0x55]);
}

#[test]
fn all_byte_values_round_trip() {
    let data: Vec<u8> = (0..=255u16).map(|b| b as u8).collect();
    round_trip(&data);
    // Repeated, so the model gets to adapt across the full alphabet.
    let mut big = Vec::new();
    for _ in 0..16 {
        big.extend((0..=255u16).map(|b| b as u8));
    }
    round_trip(&big);
}

#[test]
fn zeros_round_trip() {
    round_trip(&[0u8; 1]);
    round_trip(&vec![0u8; 1000]);
    round_trip(&vec![0u8; 64 * 1024]);
}

#[test]
fn english_text_round_trips() {
    let text = b"The quick brown fox jumps over the lazy dog. \
        Pack my box with five dozen liquor jugs. \
        How vexingly quick daft zebras jump! \
        Sphinx of black quartz, judge my vow.";
    let mut data = Vec::new();
    for _ in 0..64 {
        data.extend_from_slice(text);
    }
    round_trip(&data);
}

#[test]
fn carry_heavy_round_trips() {
    // Bytes that drive `low` toward the 0xFF.. carry-propagation path.
    let data: Vec<u8> = (0..5000u32)
        .map(|i| (i.wrapping_mul(131) >> 3) as u8)
        .collect();
    round_trip(&data);
    round_trip(&vec![0xFFu8; 4096]);
}

#[test]
fn pseudo_random_round_trips() {
    // A simple LCG — deterministic, no deps. "Incompressible"-ish.
    let mut state: u32 = 0x1234_5678;
    let mut data = Vec::with_capacity(8192);
    for _ in 0..8192 {
        state = state.wrapping_mul(1_103_515_245).wrapping_add(12345);
        data.push((state >> 16) as u8);
    }
    round_trip(&data);
}

#[test]
fn many_sizes_round_trip() {
    let mut state: u32 = 0xDEAD_BEEF;
    for len in 0..300usize {
        let data: Vec<u8> = (0..len)
            .map(|_| {
                state = state.wrapping_mul(1_103_515_245).wrapping_add(12345);
                (state >> 16) as u8
            })
            .collect();
        round_trip(&data);
    }
}

// ─── compression effectiveness ────────────────────────────────────────────

#[test]
fn compresses_zeros_hugely() {
    let data = vec![0u8; 64 * 1024];
    let enc = encode(&data);
    // 64 KiB of a single symbol collapses dramatically. The order-0
    // adaptive counter floors at ~0.02 bits/symbol per bit-tree level
    // (move-shift 5), so the payload settles around 1.5 KiB — a >40x
    // ratio. Assert a comfortable < input/30 to prove genuine, large
    // compression without being brittle about the exact floor.
    assert!(
        enc.len() < data.len() / 30,
        "64 KiB of zeros should shrink >30x, got {} bytes ({}x)",
        enc.len(),
        data.len() / enc.len().max(1)
    );
}

#[test]
fn compresses_skewed_input() {
    // 95% zeros, 5% spread — low entropy, must compress well below input.
    let mut state: u32 = 0xABCD_1234;
    let mut data = Vec::with_capacity(32 * 1024);
    for _ in 0..32 * 1024 {
        state = state.wrapping_mul(1_103_515_245).wrapping_add(12345);
        if (state >> 24).is_multiple_of(20) {
            data.push((state >> 8) as u8);
        } else {
            data.push(0);
        }
    }
    let enc = encode(&data);
    assert!(
        enc.len() < data.len() / 2,
        "skewed input ({} bytes) should compress to <50%, got {}",
        data.len(),
        enc.len()
    );
}

#[test]
fn compresses_english_text() {
    let text = b"the quick brown fox jumps over the lazy dog ";
    let mut data = Vec::new();
    for _ in 0..512 {
        data.extend_from_slice(text);
    }
    let enc = encode(&data);
    assert!(
        enc.len() < data.len(),
        "English text ({} bytes) should compress, got {}",
        data.len(),
        enc.len()
    );
}

#[test]
fn incompressible_overhead_is_bounded() {
    // Random data may not shrink, but must not blow up: at most a small
    // fraction larger than the original plus the 8-byte header.
    let mut state: u32 = 0x0BAD_F00D;
    let mut data = Vec::with_capacity(16 * 1024);
    for _ in 0..16 * 1024 {
        state = state.wrapping_mul(1_103_515_245).wrapping_add(12345);
        data.push((state >> 16) as u8);
    }
    let enc = encode(&data);
    assert!(
        enc.len() <= data.len() + data.len() / 16 + 16,
        "incompressible expansion too large: {} -> {}",
        data.len(),
        enc.len()
    );
}

// ─── robustness: never panic on bad input ─────────────────────────────────

#[test]
fn truncated_header_errors() {
    for n in 0..8 {
        let bytes = vec![0u8; n];
        let err = decode(&bytes).unwrap_err();
        assert_eq!(err, Error::UnexpectedEnd, "n={n}");
    }
}

#[test]
fn truncated_payload_errors() {
    // Encode something non-trivial, then lop off the tail of the payload.
    let data = vec![7u8; 4096];
    let enc = encode(&data);
    assert!(enc.len() > 13);
    // Drop the final flush bytes — decoder must over-read and error.
    for cut in 1..=6 {
        let truncated = &enc[..enc.len() - cut];
        let r = decode(truncated);
        assert!(
            r.is_err(),
            "truncating {cut} bytes should error, got {:?}",
            r.map(|v| v.len())
        );
    }
}

#[test]
fn garbage_does_not_panic() {
    // A header claiming a small length, with random payload bytes: must
    // either decode to *something* of that length or error — never panic.
    let mut state: u32 = 0xFACE_CAFE;
    for _ in 0..200 {
        let mut bytes = Vec::new();
        state = state.wrapping_mul(1_103_515_245).wrapping_add(12345);
        let declared = (state >> 24) as u64 % 64; // 0..63
        bytes.extend_from_slice(&declared.to_le_bytes());
        let payload_len = (state >> 8) as usize % 40;
        for _ in 0..payload_len {
            state = state.wrapping_mul(1_103_515_245).wrapping_add(12345);
            bytes.push((state >> 16) as u8);
        }
        // Just must not panic; result is don't-care.
        let _ = decode(&bytes);
    }
}

#[test]
fn absurd_length_header_errors() {
    // Header claims u64::MAX bytes with a tiny payload — reject as corrupt
    // rather than attempting a gigantic allocation.
    let mut bytes = u64::MAX.to_le_bytes().to_vec();
    bytes.extend_from_slice(&[0u8; 5]);
    assert_eq!(decode(&bytes).unwrap_err(), Error::Corrupt);
}

#[test]
fn zero_length_with_payload_is_corrupt() {
    let mut bytes = 0u64.to_le_bytes().to_vec();
    bytes.push(0xAB); // length says 0, but there are extra bytes
    assert_eq!(decode(&bytes).unwrap_err(), Error::Corrupt);
}

// ─── reset reuse ──────────────────────────────────────────────────────────

#[test]
fn encoder_and_decoder_reset() {
    let mut enc = RangeCoder::encoder();
    let mut buf = [0u8; 256];

    // First stream.
    let _ = enc.encode(b"first stream payload", &mut buf).unwrap();
    let mut s1 = Vec::new();
    loop {
        let (p, st) = enc.finish(&mut buf).unwrap();
        s1.extend_from_slice(&buf[..p.written]);
        if matches!(st, Status::StreamEnd) {
            break;
        }
    }

    enc.reset();

    // Second stream after reset must be independent and correct.
    let _ = enc.encode(b"second!", &mut buf).unwrap();
    let mut s2 = Vec::new();
    loop {
        let (p, st) = enc.finish(&mut buf).unwrap();
        s2.extend_from_slice(&buf[..p.written]);
        if matches!(st, Status::StreamEnd) {
            break;
        }
    }

    assert_eq!(decode(&s1).unwrap(), b"first stream payload");
    assert_eq!(decode(&s2).unwrap(), b"second!");
}
