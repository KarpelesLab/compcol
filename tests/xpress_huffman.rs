//! Streaming round-trip tests for the XPress Huffman codec.
//!
//! Canonical (Progress, Status) driver. Encoder and decoder are
//! exercised at chunk granularity and via the runtime factory.

#![cfg(feature = "xpress_huffman")]

use compcol::xpress_huffman::{Decoder, Encoder, EncoderConfig, XpressHuffman};
use compcol::{Algorithm, Decoder as _, Encoder as _, Error, Status};

fn encode_chunked(enc: &mut Encoder, input: &[u8], in_chunk: usize, out_chunk: usize) -> Vec<u8> {
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
                    panic!("xpress huffman encoder finish stalled");
                }
            }
        }
    }
    encoded
}

fn decode_chunked(encoded: &[u8], in_chunk: usize, out_chunk: usize) -> Result<Vec<u8>, Error> {
    let mut dec = Decoder::new();
    decode_chunked_with(&mut dec, encoded, in_chunk, out_chunk)
}

fn decode_chunked_with(
    dec: &mut Decoder,
    encoded: &[u8],
    in_chunk: usize,
    out_chunk: usize,
) -> Result<Vec<u8>, Error> {
    let mut decoded = Vec::new();
    let mut buf = vec![0u8; out_chunk.max(1)];
    let mut i = 0;
    while i < encoded.len() {
        let end = (i + in_chunk).min(encoded.len());
        let chunk = &encoded[i..end];
        let mut consumed = 0;
        while consumed < chunk.len() {
            let (p, status) = dec.decode(&chunk[consumed..], &mut buf)?;
            decoded.extend_from_slice(&buf[..p.written]);
            consumed += p.consumed;
            match status {
                Status::StreamEnd => break,
                Status::InputEmpty => break,
                Status::OutputFull => continue,
            }
        }
        i = end;
    }
    loop {
        let (p, _status) = dec.decode(&[], &mut buf)?;
        decoded.extend_from_slice(&buf[..p.written]);
        if p.written == 0 {
            break;
        }
    }
    loop {
        let (p, status) = dec.finish(&mut buf)?;
        decoded.extend_from_slice(&buf[..p.written]);
        match status {
            Status::StreamEnd => break,
            Status::OutputFull | Status::InputEmpty => {
                if p.written == 0 {
                    panic!("xpress huffman decoder finish stalled");
                }
            }
        }
    }
    Ok(decoded)
}

fn encode_all(input: &[u8]) -> Vec<u8> {
    let mut enc = Encoder::new();
    encode_chunked(&mut enc, input, input.len().max(1), 4096)
}

fn round_trip(input: &[u8]) {
    let encoded = encode_all(input);
    let decoded = decode_chunked(&encoded, 4096, 4096).unwrap();
    assert_eq!(decoded, input, "round-trip mismatch len {}", input.len());
}

// ─── algorithm metadata ─────────────────────────────────────────────────

#[test]
fn name_is_xpress_huffman() {
    assert_eq!(<XpressHuffman as Algorithm>::NAME, "xpress-huffman");
}

#[test]
fn default_config_level_is_zero() {
    assert_eq!(EncoderConfig::default().level, 0);
}

// ─── round-trip tests ──────────────────────────────────────────────────

#[test]
fn round_trip_empty() {
    let encoded = encode_all(b"");
    // 4-byte length header + no block payload.
    assert_eq!(encoded.len(), 4);
    assert_eq!(&encoded[..4], &[0, 0, 0, 0]);
    let decoded = decode_chunked(&encoded, 4096, 4096).unwrap();
    assert_eq!(decoded, b"");
}

#[test]
fn round_trip_single_byte() {
    round_trip(b"X");
}

#[test]
fn round_trip_hello_world() {
    round_trip(b"hello world");
}

#[test]
fn round_trip_repeating_short() {
    round_trip(b"abcabcabcabcabcabc");
}

#[test]
fn round_trip_repeating_64kib() {
    // Exactly one full 64 KiB block of repeating phrase.
    let phrase = b"the quick brown fox jumps over the lazy dog ";
    let mut input = Vec::new();
    while input.len() < 64 * 1024 {
        input.extend_from_slice(phrase);
    }
    input.truncate(64 * 1024);
    round_trip(&input);
}

#[test]
fn round_trip_mixed_corpus() {
    let mut input = Vec::new();
    input.extend(core::iter::repeat_n(b'a', 10));
    input.extend(b"and a quick fox jumps over");
    input.extend(core::iter::repeat_n(b'z', 200));
    input.extend(b"final tail");
    round_trip(&input);
}

#[test]
fn round_trip_pseudo_random_8kib() {
    // 8 KiB of LCG output: low compressibility. Verifies that the
    // encoder's match search and Huffman table handle skewed/uneven
    // distributions correctly.
    let mut state: u32 = 0xC0FFEEu32;
    let mut input = Vec::with_capacity(8 * 1024);
    for _ in 0..(8 * 1024) {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        input.push((state >> 16) as u8);
    }
    round_trip(&input);
}

#[test]
fn round_trip_long_match_escape() {
    // A run of 1000 'a' bytes after a single 'a' literal exercises the
    // long-match escape path (length - 3 > 14 triggers length_class=15).
    let mut input = Vec::new();
    input.push(b'a');
    input.extend(core::iter::repeat_n(b'a', 1000));
    round_trip(&input);
}

#[test]
fn round_trip_multi_block() {
    // 130 KiB → 2 full blocks + a tail. Verifies the inter-block
    // boundary on both sides.
    let mut state: u32 = 0xDEAD_BEEFu32;
    let mut input = Vec::with_capacity(130 * 1024);
    let phrases: &[&[u8]] = &[
        b"alpha alpha alpha ",
        b"bravo bravo bravo ",
        b"charlie delta echo ",
    ];
    let mut p = 0;
    while input.len() < 130 * 1024 {
        for _ in 0..16 {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            input.push((state >> 16) as u8);
        }
        input.extend_from_slice(phrases[p % phrases.len()]);
        p += 1;
    }
    input.truncate(130 * 1024);
    round_trip(&input);
}

// ─── cross-drain back-reference regression ─────────────────────────────

/// Regression for the cross-block / cross-drain back-reference underflow
/// (DoS panic). The decoder's `decoded` buffer is cleared every time it
/// is fully drained to the caller; back-references that reach across such
/// a drain boundary must read from the retained history, not the cleared
/// buffer. Decoding a multi-block, highly back-referential stream through
/// a 1-byte output buffer forces a drain after essentially every emitted
/// byte, so any match looking further back than the (cleared) `decoded`
/// length would previously underflow `decoded.len() - match_offset` and
/// panic. With the fix it must decode correctly.
#[test]
fn cross_drain_back_reference_does_not_panic() {
    // ~3 full 64 KiB blocks of a repeating phrase: matches routinely
    // reach back across drain and block boundaries.
    let phrase = b"the quick brown fox jumps over the lazy dog 0123456789 ";
    let mut input = Vec::new();
    while input.len() < 3 * 64 * 1024 + 1234 {
        input.extend_from_slice(phrase);
    }
    let encoded = encode_all(&input);

    // out_chunk == 1 forces a drain (and `decoded.clear()`) on every byte.
    let decoded = decode_chunked(&encoded, 4096, 1).expect("must not panic/error");
    assert_eq!(decoded, input, "cross-drain round-trip mismatch");
}

/// Regression for the `decode_loop` output back-pressure bound (H5 OOM).
/// Feeding the *entire* multi-block compressed stream in a single `decode`
/// call previously let `decode_loop` decode every buffered block into the
/// internal `decoded` buffer before a single byte was drained (a tiny input
/// could balloon to gigabytes resident). Draining through a 1-byte output
/// buffer means the decoder must bound its backlog and resume across many
/// calls; the round-trip must still be byte-exact.
#[test]
fn whole_stream_one_byte_output_is_bounded_and_correct() {
    let phrase = b"the quick brown fox jumps over the lazy dog 0123456789 ";
    let mut input = Vec::new();
    while input.len() < 4 * 64 * 1024 + 777 {
        input.extend_from_slice(phrase);
    }
    let encoded = encode_all(&input);

    // in_chunk == whole stream: all blocks are buffered before decoding.
    // out_chunk == 1: forces the back-pressure return path every byte.
    let decoded = decode_chunked(&encoded, encoded.len(), 1).expect("must decode");
    assert_eq!(decoded, input, "whole-stream/1-byte round-trip mismatch");
}

// ─── streaming chunk sizes ─────────────────────────────────────────────

#[test]
fn round_trip_streaming_one_byte() {
    let input = b"streaming bytes one at a time".to_vec();
    let mut enc = Encoder::new();
    let encoded = encode_chunked(&mut enc, &input, 1, 1);
    let decoded = decode_chunked(&encoded, 1, 1).unwrap();
    assert_eq!(decoded, input);
}

// ─── reset / reuse ─────────────────────────────────────────────────────

#[test]
fn reset_preserves_config_and_allows_reuse() {
    let input_a = b"alpha alpha alpha alpha".as_slice();
    let input_b = b"bravo bravo bravo bravo".as_slice();

    let mut enc = Encoder::with_config(EncoderConfig { level: 0 });
    let encoded_a = encode_chunked(&mut enc, input_a, 4096, 4096);
    enc.reset();
    let encoded_b = encode_chunked(&mut enc, input_b, 4096, 4096);

    assert_eq!(decode_chunked(&encoded_a, 4096, 4096).unwrap(), input_a);
    assert_eq!(decode_chunked(&encoded_b, 4096, 4096).unwrap(), input_b);
}

#[test]
fn decoder_reset_allows_reuse() {
    let mut enc = Encoder::new();
    let encoded_a = encode_chunked(&mut enc, b"hello", 4096, 4096);
    enc.reset();
    let encoded_b = encode_chunked(&mut enc, b"world", 4096, 4096);
    let mut dec = Decoder::new();
    assert_eq!(
        decode_chunked_with(&mut dec, &encoded_a, 4096, 4096).unwrap(),
        b"hello"
    );
    dec.reset();
    assert_eq!(
        decode_chunked_with(&mut dec, &encoded_b, 4096, 4096).unwrap(),
        b"world"
    );
}

// ─── decoder error cases ───────────────────────────────────────────────

#[test]
fn decoder_truncated_header() {
    // Less than 4 bytes for the length header: decoder waits for more
    // (no error).
    let mut dec = Decoder::new();
    let mut buf = vec![0u8; 64];
    let (p, status) = dec.decode(&[0x10, 0x00], &mut buf).unwrap();
    assert_eq!(p.written, 0);
    assert_eq!(status, Status::InputEmpty);
}

#[test]
fn decoder_truncated_table_after_header() {
    // Header says 10 bytes expected, but no block payload follows.
    // `finish` should report UnexpectedEnd.
    let mut dec = Decoder::new();
    let mut buf = vec![0u8; 64];
    let _ = dec.decode(&[10, 0, 0, 0], &mut buf).unwrap();
    let res = dec.finish(&mut buf);
    assert!(matches!(res, Err(Error::UnexpectedEnd)));
}

#[test]
fn decoder_bad_huffman_table() {
    // 4-byte length header (1 byte expected) followed by a 256-byte
    // zero table (no symbols → invalid). The decoder must reject.
    let mut input = vec![1u8, 0, 0, 0];
    input.extend(core::iter::repeat_n(0u8, 256));
    input.extend(core::iter::repeat_n(0u8, 4)); // bogus prefill bytes
    let mut dec = Decoder::new();
    let mut buf = vec![0u8; 64];
    let res = dec.decode(&input, &mut buf);
    assert!(matches!(res, Err(Error::InvalidHuffmanTree)));
}

// ─── ms-xca spec fixtures ──────────────────────────────────────────────

/// The MS-XCA §2.1.5 worked example: `abcdefghijklmnopqrstuvwxyz`
/// compressed to 264 bytes. We strip off the 4-byte length-prefix
/// because the spec example is raw MS-XCA without any framing — to
/// run it through our decoder we prepend our framing header.
#[test]
fn decode_ms_xca_alphabet_example() {
    // 256-byte length table followed by 8 bytes of bit-stream from the spec.
    let spec_blob: &[u8] = &[
        // 256-byte packed length table (most zeros)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x50, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x45,
        0x44, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, // 8-byte payload encoding the alphabet + EOF.
        0xd8, 0x52, 0x3e, 0xd7, 0x94, 0x11, 0x5b, 0xe9, 0x19, 0x5f, 0xf9, 0xd6, 0x7c, 0xdf, 0x8d,
        0x04, 0x00, 0x00, 0x00, 0x00,
    ];
    // Prepend 4-byte length header (26 = 0x1A).
    let mut framed = Vec::with_capacity(4 + spec_blob.len());
    framed.extend_from_slice(&26u32.to_le_bytes());
    framed.extend_from_slice(spec_blob);
    let decoded = decode_chunked(&framed, 4096, 4096).unwrap();
    assert_eq!(decoded, b"abcdefghijklmnopqrstuvwxyz");
}

#[test]
fn decode_ms_xca_long_match_example() {
    // Spec §2.1.6 worked example: `abc` repeated 100 times = 300 bytes.
    let spec_blob: &[u8] = &[
        // 256-byte packed length table
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x30, 0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, // Payload: abc[match 3..297][EOF]
        0xa8, 0xdc, 0x00, 0x00, 0xff, 0x26, 0x01,
    ];
    let mut framed = Vec::with_capacity(4 + spec_blob.len());
    framed.extend_from_slice(&300u32.to_le_bytes());
    framed.extend_from_slice(spec_blob);
    let decoded = decode_chunked(&framed, 4096, 4096).unwrap();
    let mut expected = Vec::new();
    for _ in 0..100 {
        expected.extend_from_slice(b"abc");
    }
    assert_eq!(decoded, expected);
}

// ─── factory wiring ────────────────────────────────────────────────────

#[cfg(feature = "factory")]
mod factory {
    use super::*;
    use compcol::factory::{decoder_by_name, encoder_by_name, extension, names};

    #[test]
    fn encoder_decoder_by_name() {
        let mut enc = encoder_by_name("xpress-huffman").expect("encoder");
        let mut dec = decoder_by_name("xpress-huffman").expect("decoder");
        let input = b"factory round trip test";
        let mut out = vec![0u8; 1024];
        let (p, _) = enc.encode(input, &mut out).unwrap();
        let written = p.written;
        let mut tail = vec![0u8; 1024];
        let (p2, _) = enc.finish(&mut tail).unwrap();
        let mut encoded = Vec::new();
        encoded.extend_from_slice(&out[..written]);
        encoded.extend_from_slice(&tail[..p2.written]);

        let mut decoded = Vec::new();
        let mut buf = vec![0u8; 1024];
        let (p3, _) = dec.decode(&encoded, &mut buf).unwrap();
        decoded.extend_from_slice(&buf[..p3.written]);
        loop {
            let (p4, status) = dec.finish(&mut buf).unwrap();
            decoded.extend_from_slice(&buf[..p4.written]);
            if matches!(status, Status::StreamEnd) {
                break;
            }
            if p4.written == 0 {
                break;
            }
        }
        assert_eq!(decoded, input);
    }

    #[test]
    fn extension_is_xph() {
        assert_eq!(extension("xpress-huffman"), Some("xph"));
    }

    #[test]
    fn name_appears_in_list() {
        assert!(names().contains(&"xpress-huffman"));
    }
}
