//! Streaming round-trip tests for the LZ4 block-format algorithm.
//!
//! Canonical v0.3 port: every call returns `(Progress, Status)` and the
//! loop dispatches on `Status` rather than inferring from byte counts.
//!
//! Tests run under the `std` test harness but the library itself is `no_std`.

#![cfg(feature = "lz4")]

use compcol::lz4::{Decoder, Encoder, Lz4};
use compcol::{Algorithm, Decoder as _, Encoder as _, Status};

/// Encode `input` through the streaming trait using the supplied chunk sizes.
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
        let end = (i + in_chunk).min(encoded.len());
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

fn round_trip_with_chunks(input: &[u8], in_chunk: usize, out_chunk: usize) {
    let encoded = encode_chunked(input, in_chunk, out_chunk);
    let decoded = decode_chunked(&encoded, in_chunk.max(1), out_chunk.max(1));
    assert_eq!(decoded.len(), input.len(), "round-trip length mismatch");
    assert_eq!(decoded, input, "round-trip content mismatch");
}

fn round_trip(input: &[u8]) {
    // Single-shot: large enough buffers that everything fits in one call.
    let big = input.len().saturating_mul(2).max(1024);
    round_trip_with_chunks(input, big, big);
}

#[test]
fn name_is_lz4() {
    assert_eq!(<Lz4 as Algorithm>::NAME, "lz4");
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
fn short_input() {
    round_trip(b"hello, world");
}

#[test]
fn hello_world() {
    round_trip(b"hello world");
}

#[test]
fn just_under_mflimit() {
    // 11 bytes — below LZ4's MFLIMIT of 12, so the encoder takes the
    // last-literals fast path.
    round_trip(b"hello world");
}

#[test]
fn just_above_mflimit() {
    // 13 bytes — above MFLIMIT. Forces the matcher to run even though there
    // is nothing to match.
    round_trip(b"hello world!!");
}

#[test]
fn long_run_of_one_byte() {
    // 10 KiB of one byte exercises the LZ77 overlapping-match case (the
    // copy length exceeds the offset).
    let input = vec![b'Z'; 10 * 1024];
    round_trip(&input);
}

#[test]
fn ascii_text_exceeding_64kib() {
    // Repeat a sentence until well past the canonical 64 KiB block size, so
    // the streaming wrapper has to split the input across multiple blocks.
    let sentence = b"the quick brown fox jumps over the lazy dog. ";
    let mut input = Vec::with_capacity(80 * 1024);
    while input.len() < 80 * 1024 {
        input.extend_from_slice(sentence);
    }
    round_trip(&input);

    // Sanity: the encoded form must be meaningfully smaller than the input
    // for this corpus — if it isn't, the matcher silently fell back to the
    // all-literals path.
    let encoded = encode_chunked(&input, input.len(), input.len() * 2);
    assert!(
        encoded.len() < input.len() / 2,
        "encoded size {} not less than half the input size {}",
        encoded.len(),
        input.len()
    );
}

#[test]
fn pseudo_random_input() {
    // Tiny LCG, fixed seed; keeps the test dependency-free.
    let mut state: u32 = 0xC0FFEEu32;
    let mut input = Vec::with_capacity(8192);
    for _ in 0..8192 {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        input.push((state >> 16) as u8);
    }
    round_trip(&input);
}

#[test]
fn large_mixed_input() {
    // 64 KiB+ mix of pseudo-random and repetitive runs — covers both the
    // multi-block path and the matcher's two extremes in one shot.
    let mut input = Vec::with_capacity(96 * 1024);
    let mut state: u32 = 0xDEADBEEFu32;
    while input.len() < 96 * 1024 {
        // 1 KiB pseudo-random.
        for _ in 0..1024 {
            state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            input.push((state >> 16) as u8);
        }
        // 1 KiB highly compressible.
        let sentence = b"the quick brown fox jumps over the lazy dog. ";
        let mut remaining = 1024usize;
        while remaining > 0 {
            let take = sentence.len().min(remaining);
            input.extend_from_slice(&sentence[..take]);
            remaining -= take;
        }
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
fn chunked_one_byte_at_a_time_repetitive() {
    // 1-byte-on-both-sides for a payload that actually compresses, ensuring
    // mid-block matches survive the worst-case buffer fragmentation.
    let mut input = Vec::with_capacity(2048);
    for _ in 0..256 {
        input.extend_from_slice(b"abcdefgh");
    }
    let encoded = encode_chunked(&input, 1, 1);
    let decoded = decode_chunked(&encoded, 1, 1);
    assert_eq!(decoded, input);
}

#[test]
fn chunked_at_block_boundary() {
    // 128 KiB so it crosses two 64 KiB block boundaries. Feed the encoder
    // and decoder in chunks that don't align with the boundary.
    let mut input = Vec::with_capacity(128 * 1024);
    let sentence = b"compcol streaming test payload - repeat me. ";
    while input.len() < 128 * 1024 {
        input.extend_from_slice(sentence);
    }
    let encoded = encode_chunked(&input, 7919, 8191);
    let decoded = decode_chunked(&encoded, 7919, 8191);
    assert_eq!(decoded.len(), input.len());
    assert_eq!(decoded, input);
}

#[test]
fn reset_clears_state() {
    let mut enc = Encoder::new();
    let mut out = [0u8; 256];
    let _ = enc
        .encode(b"first run, will be discarded", &mut out)
        .unwrap();
    enc.reset();

    // After reset, a fresh round-trip should succeed.
    let mut produced = Vec::new();
    let (p, _) = enc.encode(b"second run", &mut out).unwrap();
    produced.extend_from_slice(&out[..p.written]);
    loop {
        let (p, status) = enc.finish(&mut out).unwrap();
        produced.extend_from_slice(&out[..p.written]);
        match status {
            Status::StreamEnd => break,
            Status::OutputFull | Status::InputEmpty => {
                if p.written == 0 {
                    panic!("finish stalled");
                }
            }
        }
    }

    let mut dec = Decoder::new();
    let mut decoded = Vec::new();
    let (pd, _) = dec.decode(&produced, &mut out).unwrap();
    decoded.extend_from_slice(&out[..pd.written]);
    let (pf, status) = dec.finish(&mut out).unwrap();
    decoded.extend_from_slice(&out[..pf.written]);
    assert!(matches!(status, Status::StreamEnd));
    assert_eq!(decoded, b"second run");
}

#[test]
fn decoder_rejects_zero_offset() {
    // Construct a tiny invalid block by hand: literal length 0, match
    // length excess 0 (token 0x00), offset 0 — invalid.
    // Wrap it in our framing: u32_le(3) || [0x00, 0x00, 0x00] || u32_le(0)
    let framed: [u8; 11] = [
        3, 0, 0, 0,    // block length
        0x00, // token: 0 literals, match excess 0 (i.e. 4 bytes)
        0x00, 0x00, // offset = 0
        0, 0, 0, 0, // terminator (won't be reached)
    ];
    let mut dec = Decoder::new();
    let mut out = [0u8; 32];
    let err = dec.decode(&framed, &mut out).unwrap_err();
    assert_eq!(err, compcol::Error::InvalidDistance);
}

#[cfg(feature = "factory")]
mod factory {
    use compcol::Status;
    use compcol::factory;

    #[test]
    fn lookup_known() {
        assert!(factory::encoder_by_name("lz4").is_some());
        assert!(factory::decoder_by_name("lz4").is_some());
    }

    #[test]
    fn names_contains_lz4() {
        assert!(factory::names().contains(&"lz4"));
    }

    #[test]
    fn boxed_round_trip() {
        let mut enc = factory::encoder_by_name("lz4").unwrap();
        let mut dec = factory::decoder_by_name("lz4").unwrap();
        let input = b"hello hello hello hello hello hello hello hello";
        let mut encoded = vec![0u8; 256];
        let (p, _) = enc.encode(input, &mut encoded).unwrap();
        assert_eq!(p.consumed, input.len());
        let mut tail = vec![0u8; 256];
        let (pf, status) = enc.finish(&mut tail).unwrap();
        assert!(matches!(status, Status::StreamEnd));
        let mut all = Vec::new();
        all.extend_from_slice(&encoded[..p.written]);
        all.extend_from_slice(&tail[..pf.written]);

        let mut out = vec![0u8; input.len()];
        let (pd, _) = dec.decode(&all, &mut out).unwrap();
        let (pdf, status) = dec.finish(&mut out[pd.written..]).unwrap();
        assert!(matches!(status, Status::StreamEnd));
        assert_eq!(&out[..pd.written + pdf.written], input);
    }
}
