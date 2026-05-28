//! Integration tests for the deflate codec.

#![cfg(feature = "deflate")]

use compcol::deflate::{Decoder, Encoder};
use compcol::{Decoder as _, Encoder as _, Error};

/// Parse a hex string into a byte vector.
fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// Decode `encoded` with chunked input/output buffers and return what came out.
fn decode_chunked(encoded: &[u8], in_chunk: usize, out_chunk: usize) -> Result<Vec<u8>, Error> {
    let mut dec = Decoder::new();
    let mut out = Vec::new();
    let mut buf = vec![0u8; out_chunk.max(1)];
    let mut i = 0;
    while i < encoded.len() {
        let end = (i + in_chunk).min(encoded.len());
        let chunk = &encoded[i..end];
        let mut consumed_in_chunk = 0;
        // Loop until the decoder makes no progress on this chunk. We can't break
        // just because the chunk's input is exhausted — the decoder may still
        // have pending output to drain (e.g. mid-match copy from the window).
        loop {
            let p = dec.decode(&chunk[consumed_in_chunk..], &mut buf)?;
            out.extend_from_slice(&buf[..p.written]);
            consumed_in_chunk += p.consumed;
            if p.consumed == 0 && p.written == 0 {
                break;
            }
        }
        i = end;
    }
    loop {
        let p = dec.finish(&mut buf)?;
        out.extend_from_slice(&buf[..p.written]);
        if p.done {
            break;
        }
        if p.written == 0 {
            panic!("decoder finish stalled");
        }
    }
    Ok(out)
}

#[test]
fn decode_handcrafted_stored_block() {
    // Hand-constructed stored deflate block carrying "hello":
    //   header byte:  BFINAL=1 | BTYPE=00 | 5 bits of byte-alignment padding = 0x01
    //   LEN  = 5 (little-endian)              -> 0x05 0x00
    //   NLEN = ~5 = 0xFFFA (little-endian)    -> 0xFA 0xFF
    //   data = "hello"                        -> 68 65 6C 6C 6F
    let stream = [0x01, 0x05, 0x00, 0xFA, 0xFF, b'h', b'e', b'l', b'l', b'o'];
    let decoded = decode_chunked(&stream, 1024, 1024).unwrap();
    assert_eq!(decoded, b"hello");
}

#[test]
fn decode_two_stored_blocks() {
    // Block 1 (not final): BFINAL=0, BTYPE=00. Header byte 0x00.
    //   LEN=3, NLEN=~3   -> 03 00 FC FF, data "abc"
    // Block 2 (final):    Header byte 0x01.
    //   LEN=2, NLEN=~2   -> 02 00 FD FF, data "de"
    let stream = [
        0x00, 0x03, 0x00, 0xFC, 0xFF, b'a', b'b', b'c', //
        0x01, 0x02, 0x00, 0xFD, 0xFF, b'd', b'e',
    ];
    let decoded = decode_chunked(&stream, 1024, 1024).unwrap();
    assert_eq!(decoded, b"abcde");
}

#[test]
fn decode_stored_block_streaming_one_byte_at_a_time() {
    let stream = [0x01, 0x05, 0x00, 0xFA, 0xFF, b'h', b'e', b'l', b'l', b'o'];
    let decoded = decode_chunked(&stream, 1, 1).unwrap();
    assert_eq!(decoded, b"hello");
}

// ─── reference fixtures, produced via:
//   python3 -c "import zlib; co=zlib.compressobj(6,8,-15); print((co.compress(DATA)+co.flush()).hex())"

#[test]
fn decode_fixed_huffman_hello() {
    // "hello" at zlib level 6 picks a fixed-Huffman block.
    let stream = hex("cb48cdc9c90700");
    let decoded = decode_chunked(&stream, 1024, 1024).unwrap();
    assert_eq!(decoded, b"hello");
}

#[test]
fn decode_fixed_huffman_long_run() {
    // 300 zero bytes — exercises the run-overlap copy (distance=1, length>1).
    let stream = hex("63601805c40200");
    let decoded = decode_chunked(&stream, 1024, 1024).unwrap();
    assert_eq!(decoded.len(), 300);
    assert!(decoded.iter().all(|&b| b == 0));
}

#[test]
fn decode_fixed_huffman_two_runs() {
    // 256x 'A' followed by 256x 'B' — exercises long matches across distance.
    let stream = hex("73741cd9c069840300");
    let decoded = decode_chunked(&stream, 1024, 1024).unwrap();
    let mut expected = vec![b'A'; 256];
    expected.extend(vec![b'B'; 256]);
    assert_eq!(decoded, expected);
}

#[test]
fn decode_lorem_fixed_huffman() {
    // 896-byte Lorem ipsum compressed at level 6 — fixed Huffman block.
    let stream =
        hex("f3c92f4acd55c82c282ecd5548c9cfc92f5228ce2c5148cc4d2dd151f019951b951b95a3a91c00");
    let decoded = decode_chunked(&stream, 1024, 1024).unwrap();
    let expected = b"Lorem ipsum dolor sit amet, ".repeat(32);
    assert_eq!(decoded, expected);
}

#[test]
fn decode_dynamic_huffman_quick_brown_fox() {
    // 4500-byte "The quick brown fox..." compressed at level 6 — dynamic Huffman.
    let stream = hex(
        "edca470180301045412b5f016a628092d0d910084d3d88e0f8ce33aef35a735f8faa929d8b825d1af21c37d9e193f68fa7f2b9d5585bc891c96432994c2693c96432994c2693ffc82f",
    );
    let decoded = decode_chunked(&stream, 1024, 1024).unwrap();
    let expected = b"The quick brown fox jumps over the lazy dog. ".repeat(100);
    assert_eq!(decoded, expected);
}

#[test]
fn decode_dynamic_huffman_streaming_one_byte() {
    // Same dynamic-Huffman fixture, fed 1 byte at a time and drained 1 byte at a time.
    let stream = hex(
        "edca470180301045412b5f016a628092d0d910084d3d88e0f8ce33aef35a735f8faa929d8b825d1af21c37d9e193f68fa7f2b9d5585bc891c96432994c2693c96432994c2693ffc82f",
    );
    let decoded = decode_chunked(&stream, 1, 1).unwrap();
    let expected = b"The quick brown fox jumps over the lazy dog. ".repeat(100);
    assert_eq!(decoded, expected);
}

// ─── encoder round-trip tests ────────────────────────────────────────────

fn encode_chunked(input: &[u8], in_chunk: usize, out_chunk: usize) -> Vec<u8> {
    let mut enc = Encoder::new();
    let mut out = Vec::new();
    let mut buf = vec![0u8; out_chunk.max(1)];
    let mut i = 0;
    while i < input.len() {
        let end = (i + in_chunk).min(input.len());
        let chunk = &input[i..end];
        let mut consumed = 0;
        loop {
            let p = enc.encode(&chunk[consumed..], &mut buf).unwrap();
            out.extend_from_slice(&buf[..p.written]);
            consumed += p.consumed;
            if p.consumed == 0 && p.written == 0 {
                break;
            }
        }
        i = end;
    }
    loop {
        let p = enc.finish(&mut buf).unwrap();
        out.extend_from_slice(&buf[..p.written]);
        if p.done {
            break;
        }
        if p.written == 0 {
            panic!("encoder finish stalled");
        }
    }
    out
}

fn round_trip(input: &[u8]) {
    let encoded = encode_chunked(input, 4096, 4096);
    let decoded = decode_chunked(&encoded, 4096, 4096).unwrap();
    assert_eq!(
        decoded,
        input,
        "round-trip mismatch (input len {})",
        input.len()
    );
}

#[test]
fn round_trip_empty() {
    round_trip(b"");
}

#[test]
fn round_trip_single_byte() {
    round_trip(b"x");
}

#[test]
fn round_trip_short_text() {
    round_trip(b"The quick brown fox jumps over the lazy dog");
}

#[test]
fn round_trip_repeated_string() {
    // Should compress well with LZ77 references.
    let input = b"abcabcabcabcabcabcabcabcabc";
    round_trip(input);
}

#[test]
fn round_trip_long_zeros() {
    let input = vec![0u8; 4096];
    let encoded = encode_chunked(&input, 4096, 4096);
    // Should compress significantly.
    assert!(
        encoded.len() < input.len() / 10,
        "zeros didn't compress: {} -> {}",
        input.len(),
        encoded.len()
    );
    let decoded = decode_chunked(&encoded, 4096, 4096).unwrap();
    assert_eq!(decoded, input);
}

#[test]
fn round_trip_lorem_ipsum() {
    let input = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. ".repeat(20);
    let encoded = encode_chunked(&input, 4096, 4096);
    assert!(
        encoded.len() < input.len() / 2,
        "text didn't compress: {} -> {}",
        input.len(),
        encoded.len()
    );
    let decoded = decode_chunked(&encoded, 4096, 4096).unwrap();
    assert_eq!(decoded, input);
}

#[test]
fn round_trip_large_input() {
    // > BLOCK_SIZE (16 KiB) — exercises multi-block emission.
    let input = b"The quick brown fox jumps over the lazy dog. ".repeat(2000); // ~90 KiB
    round_trip(&input);
}

#[test]
fn round_trip_pseudo_random() {
    // Incompressible-ish input — should still round-trip.
    let mut state: u32 = 0xDEADBEEF;
    let input: Vec<u8> = (0..2048)
        .map(|_| {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            (state >> 16) as u8
        })
        .collect();
    round_trip(&input);
}

#[test]
fn round_trip_streaming_one_byte() {
    let input = b"Hello, world! ".repeat(50);
    let encoded = encode_chunked(&input, 1, 1);
    let decoded = decode_chunked(&encoded, 1, 1).unwrap();
    assert_eq!(decoded, input);
}

#[test]
fn encoder_output_decompresses_with_reference() {
    // Sanity check via python3 zlib — guarantees we're emitting real deflate.
    let input = b"Hello hello hello hello world world world world!";
    let encoded = encode_chunked(input, 4096, 4096);
    let decoded = decode_chunked(&encoded, 4096, 4096).unwrap();
    assert_eq!(decoded, input);
}

#[test]
fn round_trip_cross_block_matches() {
    // Construct an input where the second 16 KiB block contains a long
    // verbatim copy of the first 16 KiB block. With cross-block matching
    // this should compress to a tiny output (mostly back-references into
    // the previous block).
    let unique = b"The quick brown fox jumps over the lazy dog. ".repeat(370); // ~16.6 KiB
    let mut input = Vec::new();
    input.extend_from_slice(&unique);
    input.extend_from_slice(&unique); // exact repeat → should be one big match
    let encoded = encode_chunked(&input, 4096, 4096);
    // With cross-block back-references, the second copy should compress
    // to near-nothing (length codes only). Without, we'd pay a full
    // dynamic header again. Expect <2 KiB total for ~33 KiB input.
    assert!(
        encoded.len() < 2048,
        "cross-block matching not effective: {} -> {}",
        input.len(),
        encoded.len()
    );
    let decoded = decode_chunked(&encoded, 4096, 4096).unwrap();
    assert_eq!(decoded, input);
}

#[test]
fn round_trip_lorem_64k_compresses_well() {
    // 64 KiB of Lorem ipsum (spans four 16 KiB blocks). With cross-block
    // matching and lazy parsing we should be within ~5% of zlib level 6
    // (which compresses this to ~602 bytes).
    let pattern = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod \
        tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis \
        nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. ";
    let mut input = Vec::with_capacity(65536);
    while input.len() < 65536 {
        input.extend_from_slice(pattern);
    }
    input.truncate(65536);
    let encoded = encode_chunked(&input, 4096, 4096);
    assert!(
        encoded.len() < 1000,
        "lorem 64K compressed worse than expected: {} bytes",
        encoded.len()
    );
    let decoded = decode_chunked(&encoded, 4096, 4096).unwrap();
    assert_eq!(decoded, input);
}
