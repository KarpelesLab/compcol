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

/// Input whose byte frequencies follow the Fibonacci sequence over `n`
/// symbols — the worst case for Huffman depth (an unlimited tree is about
/// `n` levels deep). No byte repeats back to back, so the RLE stage leaves
/// the frequencies alone.
fn fib_input(n: usize) -> Vec<u8> {
    let mut w = vec![1u64; n];
    w[1] = 2;
    for i in 2..n {
        w[i] = w[i - 1] + w[i - 2];
    }
    let total: u64 = w.iter().sum();
    let (mut out, mut prev) = (Vec::new(), None);
    for _ in 0..total {
        let mut best: Option<usize> = None;
        for i in 0..n {
            if w[i] > 0 && Some(i) != prev && best.is_none_or(|b| w[i] > w[b]) {
                best = Some(i);
            }
        }
        let b = best.or(prev).unwrap();
        w[b] -= 1;
        out.push(b as u8);
        prev = Some(b);
    }
    out
}

/// Depth of the deepest leaf in an encoded stream's node table.
fn max_code_len(encoded: &[u8]) -> usize {
    let n = u16::from_le_bytes([encoded[0], encoded[1]]) as usize;
    let child = |node: usize, right: usize| {
        let at = 2 + 4 * node + 2 * right;
        i16::from_le_bytes([encoded[at], encoded[at + 1]])
    };
    let mut deepest = 0;
    let mut stack = vec![(0usize, 0usize)];
    while let Some((node, depth)) = stack.pop() {
        assert!(node < n && depth < n, "malformed node table");
        for right in 0..2 {
            let c = child(node, right);
            if c < 0 {
                deepest = deepest.max(depth + 1);
            } else {
                stack.push((c as usize, depth + 1));
            }
        }
    }
    deepest
}

/// Skewed frequencies used to produce Huffman codes of unbounded length;
/// past 25 bits the encoder's bit accumulator truncated them and the
/// stream no longer decoded to the input. Codes are now limited to 16
/// bits, as in the original SQ.
#[test]
fn skewed_frequencies_are_length_limited() {
    for n in [16, 20, 23] {
        let input = fib_input(n);
        let encoded = encode_chunked(&input, input.len(), 1 << 16);
        let depth = max_code_len(&encoded);
        assert!(depth <= 16, "n = {n}: {depth}-bit code");
        let decoded = decode_chunked(&encoded, 4096, 1 << 16);
        assert!(decoded == input, "n = {n}: round-trip mismatch");
    }
}

/// The multi-megabyte inputs that hit the truncation: `n = 28` failed to
/// decode (`UnexpectedEnd`), `n = 30` decoded to the wrong bytes.
#[test]
#[ignore = "multi-megabyte input, slow in debug builds"]
fn skewed_frequencies_round_trip_large() {
    for n in [28, 30] {
        let input = fib_input(n);
        let encoded = encode_chunked(&input, input.len(), 1 << 16);
        assert!(max_code_len(&encoded) <= 16);
        let decoded = decode_chunked(&encoded, 1 << 16, 1 << 16);
        assert!(decoded == input, "n = {n}: round-trip mismatch");
    }
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

// `finish` used to report `UnexpectedEnd` whenever its output slice filled
// exactly as the internal emit buffer ran dry while symbols were still
// undecoded — i.e. depending only on the caller's buffer size.
#[test]
fn finish_drains_with_tiny_output_buffers() {
    let input: Vec<u8> = (0..20_000u32)
        .map(|i| b"squeeze me, arc!"[(i % 16) as usize] ^ (i / 97) as u8)
        .collect();
    let encoded = encode_chunked(&input, input.len(), 1 << 16);
    for out_len in [1usize, 2, 3, 7] {
        let mut dec = Decoder::new();
        let mut buf = vec![0u8; out_len];
        let mut out = Vec::new();
        // Hand over all input, then drain only through `finish`.
        let mut consumed = 0;
        while consumed < encoded.len() {
            let (p, _) = dec.decode(&encoded[consumed..], &mut buf).unwrap();
            out.extend_from_slice(&buf[..p.written]);
            consumed += p.consumed;
        }
        loop {
            let (p, status) = dec.finish(&mut buf).unwrap();
            out.extend_from_slice(&buf[..p.written]);
            if status == Status::StreamEnd {
                break;
            }
            assert!(p.written > 0, "finish stalled");
        }
        assert_eq!(out, input, "out_len {out_len}");
    }
}

/// Decode `stream` the way a streaming caller does — `in_chunk` bytes per
/// `decode` call, an `out_chunk`-byte output buffer, then `finish` until it
/// ends — and return the verdict together with every byte handed out.
fn decode_outcome(
    stream: &[u8],
    in_chunk: usize,
    out_chunk: usize,
) -> (Result<(), Error>, Vec<u8>) {
    let mut dec = Decoder::new();
    let mut out = Vec::new();
    let mut buf = vec![0u8; out_chunk];
    let mut pos = 0;
    let mut steps = 0usize;
    while pos < stream.len() {
        steps += 1;
        assert!(steps < 1 << 20, "decode did not terminate");
        let end = pos.saturating_add(in_chunk).min(stream.len());
        match dec.decode(&stream[pos..end], &mut buf) {
            Ok((p, status)) => {
                out.extend_from_slice(&buf[..p.written]);
                pos += p.consumed;
                if status == Status::StreamEnd {
                    return (Ok(()), out);
                }
            }
            Err(e) => return (Err(e), out),
        }
    }
    loop {
        steps += 1;
        assert!(steps < 1 << 20, "finish did not terminate");
        match dec.finish(&mut buf) {
            Ok((p, status)) => {
                out.extend_from_slice(&buf[..p.written]);
                if status == Status::StreamEnd {
                    return (Ok(()), out);
                }
            }
            Err(e) => return (Err(e), out),
        }
    }
}

// Found by the `chunked_vs_oneshot` fuzz target. The last symbol before the
// end-of-stream symbol is a bare 0x90 run flag with no count byte, which is
// malformed. `decode` used to report `StreamEnd` for it whenever the end
// symbol was reached and the output drained within a `decode` call (a large
// output buffer), while a small output buffer left the verdict to `finish`,
// which rejected it: the result depended on the caller's buffer size.
#[test]
fn dangling_run_flag_is_rejected_for_every_chunking() {
    let stream: [u8; 27] = [
        0x04, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x00, 0xff, 0x87, 0xff, 0x6f, 0xff, 0x2d,
        0xff, 0xff, 0xfe, 0x6d, 0x23, 0x6d, 0xdb, 0x70, 0x61, 0x72, 0x63, 0xb6,
    ];
    let reference = decode_outcome(&stream, usize::MAX, 1 << 16);
    assert_eq!(reference.0, Err(Error::UnexpectedEnd));
    // Everything decoded ahead of the bad flag is still delivered.
    assert_eq!(reference.1.len(), 1101);
    for in_chunk in [1usize, 2, 3, 5, 8, 26, 27, usize::MAX] {
        for out_chunk in [
            1usize,
            2,
            3,
            7,
            61,
            255,
            256,
            1099,
            1100,
            1101,
            4096,
            1 << 16,
        ] {
            let got = decode_outcome(&stream, in_chunk, out_chunk);
            let at = format!("in_chunk {in_chunk}, out_chunk {out_chunk}");
            assert_eq!(
                (&got.0, got.1.len()),
                (&reference.0, reference.1.len()),
                "{at}"
            );
            assert!(got.1 == reference.1, "{at}: delivered bytes differ");
        }
    }
}

// The same must hold for a stream that simply stops short of its
// end-of-stream symbol: same verdict and same delivered bytes however the
// caller slices it.
#[test]
fn truncated_stream_agrees_for_every_chunking() {
    let input: Vec<u8> = (0..3000u32)
        .map(|i| b"squeeze me, arc!"[(i % 16) as usize] ^ (i / 97) as u8)
        .collect();
    let encoded = encode_chunked(&input, input.len(), 1 << 16);
    let cut = &encoded[..encoded.len() - 40];
    let reference = decode_outcome(cut, usize::MAX, 1 << 16);
    assert_eq!(reference.0, Err(Error::UnexpectedEnd));
    assert!(!reference.1.is_empty() && input.starts_with(&reference.1));
    for in_chunk in [1usize, 7, 256, usize::MAX] {
        for out_chunk in [1usize, 3, 255, 4096] {
            let got = decode_outcome(cut, in_chunk, out_chunk);
            let at = format!("in_chunk {in_chunk}, out_chunk {out_chunk}");
            assert_eq!(
                (&got.0, got.1.len()),
                (&reference.0, reference.1.len()),
                "{at}"
            );
            assert!(got.1 == reference.1, "{at}: delivered bytes differ");
        }
    }
}
