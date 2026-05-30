//! Streaming round-trip and error-path tests for ARC Squeeze (method 4 / SQ).

#![cfg(feature = "arc_squeeze")]

use compcol::arc_squeeze::{ArcSqueeze, Decoder, Encoder};
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
    let encoded = encode_chunked(input, input.len().max(1), input.len().max(64) * 2 + 64);
    let decoded = decode_chunked(&encoded, encoded.len().max(1), input.len().max(1));
    assert_eq!(decoded.len(), input.len(), "round-trip length mismatch");
    assert_eq!(decoded, input, "round-trip data mismatch");
}

#[test]
fn name_is_squeeze() {
    assert_eq!(<ArcSqueeze as Algorithm>::NAME, "squeeze");
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
fn two_distinct_bytes() {
    round_trip(b"AB");
}

#[test]
fn hello_world_round_trip() {
    round_trip(b"hello world");
}

#[test]
fn long_run_exercises_rle() {
    // Long runs of one byte exercise the 0x90 RLE pre-pass.
    let input = vec![b'Z'; 4096];
    round_trip(&input);
}

#[test]
fn literal_flag_byte_round_trip() {
    // 0x90 itself must round-trip (encoded as 0x90 0x00 in the RLE stage).
    let input = vec![0x90u8; 100];
    round_trip(&input);
    round_trip(&[0x90, 0x41, 0x90, 0x90, 0x42, 0x90]);
}

#[test]
fn mixed_runs_and_literals() {
    let mut input = Vec::new();
    input.extend(core::iter::repeat_n(b'a', 300)); // run > 255 boundary
    input.extend_from_slice(b"xyz");
    input.extend(core::iter::repeat_n(0x90u8, 10));
    input.extend(core::iter::repeat_n(b'q', 5));
    input.extend_from_slice(b"the end");
    round_trip(&input);
}

#[test]
fn ascii_text_round_trip() {
    let line = b"The quick brown fox jumps over the lazy dog.\n";
    let mut input = Vec::with_capacity(8 * 1024);
    while input.len() < 8 * 1024 {
        input.extend_from_slice(line);
    }
    round_trip(&input);
}

#[test]
fn pseudo_random_data() {
    let mut state: u32 = 0xDEADBEEF;
    let mut input = Vec::with_capacity(4 * 1024);
    for _ in 0..4 * 1024 {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        input.push((state >> 16) as u8);
    }
    round_trip(&input);
}

#[test]
fn all_byte_values_round_trip() {
    let mut input = Vec::new();
    for rep in 0..10u32 {
        for b in 0..=255u32 {
            input.push(((b + rep) % 256) as u8);
        }
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

// ── error paths ──

#[test]
fn oversized_node_count_rejected() {
    // numnodes far beyond MAX_NODES (2*257) → InvalidHuffmanTree.
    let stream = [0xFFu8, 0xFF]; // numnodes = 0xFFFF
    let mut dec = Decoder::new();
    let mut buf = [0u8; 64];
    let r = dec.decode(&stream, &mut buf);
    assert_eq!(r, Err(Error::InvalidHuffmanTree));
}

#[test]
fn child_index_out_of_range_rejected() {
    // numnodes = 1, single node whose left child points at node index 5
    // (out of range) → InvalidHuffmanTree.
    let mut stream = vec![1u8, 0]; // numnodes = 1
    // node 0: left = 5 (i16 LE), right = -1 (leaf for value 0)
    stream.extend_from_slice(&5i16.to_le_bytes());
    stream.extend_from_slice(&(-1i16).to_le_bytes());
    let mut dec = Decoder::new();
    let mut buf = [0u8; 64];
    let r = dec.decode(&stream, &mut buf);
    assert_eq!(r, Err(Error::InvalidHuffmanTree));
}

#[test]
fn truncated_bitstream_is_unexpected_end() {
    // Valid header (1 node, both children leaves) but no bitstream reaching
    // SPEOF. Build a tree: node 0 -> left leaf 'A'(0?) right leaf SPEOF.
    // value v encoded as -(v)-1. Use left = leaf for byte 0x41, right =
    // leaf for SPEOF(256).
    let left = -(0x41i32) - 1; // -66
    let right = -(256i32) - 1; // -257
    let mut stream = vec![1u8, 0];
    stream.extend_from_slice(&(left as i16).to_le_bytes());
    stream.extend_from_slice(&(right as i16).to_le_bytes());
    // No bitstream bytes at all → decoder can't reach a leaf → UnexpectedEnd
    // at finish.
    let mut dec = Decoder::new();
    let mut buf = [0u8; 64];
    let _ = dec.decode(&stream, &mut buf).unwrap();
    let r = dec.finish(&mut buf);
    assert_eq!(r, Err(Error::UnexpectedEnd));
}

#[test]
fn reset_clears_state() {
    let a = encode_chunked(b"hello", 5, 64);
    let mut enc = Encoder::new();
    let mut out = [0u8; 64];
    let _ = enc.encode(b"garbage", &mut out).unwrap();
    enc.reset();
    let mut produced = Vec::new();
    let (p, _) = enc.encode(b"hello", &mut out).unwrap();
    produced.extend_from_slice(&out[..p.written]);
    loop {
        let (p, s) = enc.finish(&mut out).unwrap();
        produced.extend_from_slice(&out[..p.written]);
        if matches!(s, Status::StreamEnd) {
            break;
        }
    }
    assert_eq!(a, produced);
    assert_eq!(decode_chunked(&produced, produced.len(), 64), b"hello");
}

#[cfg(feature = "factory")]
mod factory {
    use compcol::factory;

    #[test]
    fn lookup_known() {
        assert!(factory::encoder_by_name("squeeze").is_some());
        assert!(factory::decoder_by_name("squeeze").is_some());
    }

    #[test]
    fn names_contains_squeeze() {
        assert!(factory::names().contains(&"squeeze"));
    }
}
