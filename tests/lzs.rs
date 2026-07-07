//! Streaming round-trip tests for the LZS (RFC 1974) codec.
//!
//! Canonical v0.4 (Progress, Status) driver. Encoder and decoder are
//! exercised at the chunk level and via the runtime factory.

#![cfg(feature = "lzs")]

use compcol::lzs::{Decoder, Encoder, Lzs};
use compcol::{Algorithm, Decoder as _, Encoder as _, Error, Status};

/// Drive an encoder to completion, feeding `input` in `in_chunk`-sized
/// slices and draining via an `out_chunk`-sized buffer.
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
                    panic!("lzs encoder finish stalled");
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

    // After all input is fed, drain whatever the decoder can still
    // produce with an empty input slice.
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
                    panic!("lzs decoder finish stalled");
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
fn name_is_lzs() {
    assert_eq!(<Lzs as Algorithm>::NAME, "lzs");
}

// ─── round-trip tests ──────────────────────────────────────────────────

#[test]
fn round_trip_empty() {
    let encoded = encode_all(b"");
    // 8-byte length header (zero) + at least one byte for the
    // end-of-stream marker + padding.
    assert!(encoded.len() >= 9);
    assert_eq!(&encoded[..8], &0u64.to_le_bytes());
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
fn round_trip_repeated_bytes() {
    // Long run of identical bytes — exercises the chained 1111 length
    // extension code.
    let input = vec![b'a'; 1024];
    round_trip(&input);
}

#[test]
fn round_trip_repeated_64kib() {
    // 64 KiB of a recurring phrase — well beyond the 2 KiB window.
    let phrase = b"the quick brown fox jumps over the lazy dog ";
    let mut input = Vec::new();
    while input.len() < 64 * 1024 {
        input.extend_from_slice(phrase);
    }
    round_trip(&input);
}

#[test]
fn round_trip_match_exceeding_16mib_guard() {
    // Regression: a single back-reference longer than the old fixed 16 MiB
    // (1<<24) "sanity" cap must still decode. ~20 MiB of a short repeating
    // phrase collapses to one very long match; the decoder previously rejected
    // it as a suspected decompression bomb (Error::Corrupt).
    let phrase = b"the quick brown fox jumps over the lazy dog. ";
    let mut input = Vec::with_capacity(20 << 20);
    while input.len() < (20 << 20) {
        input.extend_from_slice(phrase);
    }
    round_trip(&input);
}

#[test]
fn round_trip_mixed_short_runs() {
    let mut input = Vec::new();
    input.extend(core::iter::repeat_n(b'a', 10));
    input.extend(core::iter::repeat_n(b'b', 3));
    input.extend(core::iter::repeat_n(b'c', 7));
    input.extend(b"and a quick fox jumps over");
    input.extend(core::iter::repeat_n(b'z', 200));
    round_trip(&input);
}

#[test]
fn round_trip_pseudo_random_8kib() {
    // 8 KiB of LCG output: incompressible. Encoder must still
    // round-trip — most tokens will be literals.
    let mut state: u32 = 0xC0FFEE_u32;
    let mut input = Vec::with_capacity(8 * 1024);
    for _ in 0..(8 * 1024) {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        input.push((state >> 16) as u8);
    }
    round_trip(&input);
}

#[test]
fn round_trip_full_byte_range() {
    // 0..=255: small enough to be all literals, exercises every byte
    // value through the bit packer.
    let input: Vec<u8> = (0..=255u8).collect();
    round_trip(&input);
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

#[test]
fn round_trip_streaming_tiny_buffers() {
    let input = b"the quick brown fox jumps over the lazy dog\
                  the quick brown fox jumps over the lazy dog\
                  the quick brown fox jumps over the lazy dog"
        .to_vec();
    let mut enc = Encoder::new();
    let encoded = encode_chunked(&mut enc, &input, 3, 4);
    let decoded = decode_chunked(&encoded, 3, 4).unwrap();
    assert_eq!(decoded, input);
}

// ─── reset / reuse ─────────────────────────────────────────────────────

#[test]
fn encoder_reset_allows_reuse() {
    let input_a = b"alpha alpha alpha alpha alpha".as_slice();
    let input_b = b"bravo bravo bravo bravo bravo".as_slice();

    let mut enc = Encoder::new();
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

// ─── hand-crafted RFC 1974 fixtures ───────────────────────────────────
//
// We construct the bit stream by hand from the spec so the fixture is
// independent of our encoder's match-finder choices and exercises the
// exact bit patterns defined in RFC 1974 § 2.5.5.
//
// Within each fixture, bits are listed left-to-right (MSB-first within
// each byte) and the fixture comment shows the exact decomposition.

#[test]
fn decode_fixture_three_literals() {
    // Input "abc" → 3 literals + end marker, padded.
    //
    //   bits:   0 01100001 0 01100010 0 01100011 1 1 0000000 1...1
    //           |---- 'a' --|---- 'b' --|---- 'c' --|-- EOS --|pad
    //
    // 9*3 + 9 = 36 bits, padded to 40 bits = 5 bytes.
    //
    //   00110 0001  00110 0010  00110 0011  11000 0000  pad 1111
    //   = 0x30 0xC4 0x60 0xE2 (?) -- recompute carefully below.
    //
    // Bit-by-bit, MSB-first byte stream:
    //   bit  0..7 : 0 0110 0001 0 0       (last 2 bits start 'b')
    //   ... let's just build it from raw bits:
    let bits = [
        // literal 'a' (0x61 = 0110_0001)
        0u8, 0, 1, 1, 0, 0, 0, 0, 1, // literal 'b' (0x62 = 0110_0010)
        0, 0, 1, 1, 0, 0, 0, 1, 0, // literal 'c' (0x63 = 0110_0011)
        0, 0, 1, 1, 0, 0, 0, 1, 1, // EOS: 1 1 0000000
        1, 1, 0, 0, 0, 0, 0, 0, 0,
    ];
    let payload = pack_msb(&bits);

    // Frame: 8-byte little-endian length + payload.
    let mut framed = Vec::new();
    framed.extend_from_slice(&3u64.to_le_bytes());
    framed.extend_from_slice(&payload);

    let decoded = decode_chunked(&framed, 4096, 4096).unwrap();
    assert_eq!(decoded, b"abc");
}

#[test]
fn decode_fixture_match_short_offset_len2() {
    // Input "ababab" — first 2 bytes are literals, then a short
    // back-reference of length 6 at distance 2.
    //
    //   bits:
    //     0 'a'_8         (literal 'a')
    //     0 'b'_8         (literal 'b')
    //     1 1 0000010     (match, short offset, distance 2)
    //     1101            (length 6)
    //     1 1 0000000     (EOS)
    //     pad with 1s
    let bits = [
        // literal 'a' (0x61 = 0110_0001)
        0u8, 0, 1, 1, 0, 0, 0, 0, 1, // literal 'b' (0x62 = 0110_0010)
        0, 0, 1, 1, 0, 0, 0, 1, 0, // match: tag=1, short=1, offset=2 (0000010)
        1, 1, 0, 0, 0, 0, 0, 1, 0, // length 6 = 1101
        1, 1, 0, 1, // EOS: 110000000
        1, 1, 0, 0, 0, 0, 0, 0, 0,
    ];
    let payload = pack_msb(&bits);
    let mut framed = Vec::new();
    framed.extend_from_slice(&8u64.to_le_bytes());
    framed.extend_from_slice(&payload);

    let decoded = decode_chunked(&framed, 4096, 4096).unwrap();
    assert_eq!(decoded, b"abababab");
}

#[test]
fn decode_fixture_long_offset() {
    // Input is 256 distinct literals followed by a back-reference at
    // distance 200. That distance fits in the long-offset 11-bit field.
    //
    // Build: 256 literal bytes (values 0..=255), then match tag with
    // long offset 200, length 4, then EOS + pad.
    let mut bits: Vec<u8> = Vec::new();
    for i in 0u16..256 {
        let b = i as u8;
        bits.push(0); // literal flag
        for shift in (0..8).rev() {
            bits.push((b >> shift) & 1);
        }
    }
    // match: tag=1, long=0, 11-bit offset = 200 = 00011001000
    bits.push(1);
    bits.push(0);
    let off: u16 = 200;
    for shift in (0..11).rev() {
        bits.push(((off >> shift) & 1) as u8);
    }
    // length 4 = `10`
    bits.push(1);
    bits.push(0);
    // EOS
    bits.extend_from_slice(&[1, 1, 0, 0, 0, 0, 0, 0, 0]);

    let payload = pack_msb(&bits);
    let mut framed = Vec::new();
    framed.extend_from_slice(&260u64.to_le_bytes());
    framed.extend_from_slice(&payload);

    let decoded = decode_chunked(&framed, 4096, 4096).unwrap();
    let mut expected: Vec<u8> = (0..=255u8).collect();
    // Tail: 4 bytes copied from distance 200 → indices 56..=59.
    for _ in 0..4 {
        expected.push(expected[expected.len() - 200]);
    }
    assert_eq!(decoded, expected);
}

#[test]
fn decode_fixture_extended_length() {
    // Long run of identical bytes triggering the 1111-chained length
    // code. Use length 23 — encoded as `1111 1111 0000`.
    //
    //   bits:
    //     0 'a'_8       (literal 'a')
    //     1 1 0000001   (match short offset, distance 1)
    //     1111 1111 0000  (length 23)
    //     EOS + pad
    let mut bits: Vec<u8> = Vec::new();
    // literal 'a' (0x61)
    bits.push(0);
    for shift in (0..8).rev() {
        bits.push((0x61u8 >> shift) & 1);
    }
    // match tag, short offset 1
    bits.push(1);
    bits.push(1);
    let off: u8 = 1;
    for shift in (0..7).rev() {
        bits.push((off >> shift) & 1);
    }
    // length 23: 1111 1111 0000
    bits.extend_from_slice(&[1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0]);
    // EOS
    bits.extend_from_slice(&[1, 1, 0, 0, 0, 0, 0, 0, 0]);

    let payload = pack_msb(&bits);
    let mut framed = Vec::new();
    framed.extend_from_slice(&24u64.to_le_bytes());
    framed.extend_from_slice(&payload);

    let decoded = decode_chunked(&framed, 4096, 4096).unwrap();
    assert_eq!(decoded, vec![b'a'; 24]);
}

// Pack a slice of 0/1 bits MSB-first into bytes, padding the final
// partial byte with `1` bits (RFC 1974 §2 convention).
fn pack_msb(bits: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bits.len().div_ceil(8));
    let mut cur: u8 = 0;
    let mut n: u8 = 0;
    for &b in bits {
        debug_assert!(b <= 1);
        cur = (cur << 1) | (b & 1);
        n += 1;
        if n == 8 {
            out.push(cur);
            cur = 0;
            n = 0;
        }
    }
    if n != 0 {
        while n < 8 {
            cur = (cur << 1) | 1;
            n += 1;
        }
        out.push(cur);
    }
    out
}

// ─── decoder error rejection ───────────────────────────────────────────

#[test]
fn truncated_header_rejected() {
    // Less than 8 bytes of header.
    let stream = [0u8, 0, 0];
    let mut dec = Decoder::new();
    let mut buf = [0u8; 16];
    // Feeding the partial header alone must not be an error yet —
    // the decoder is still waiting for more bytes.
    let (_, _) = dec.decode(&stream, &mut buf).unwrap();
    // Calling `finish` now should report the truncation.
    let err = dec.finish(&mut buf).unwrap_err();
    assert!(
        matches!(err, Error::UnexpectedEnd | Error::Corrupt),
        "unexpected error: {:?}",
        err
    );
}

#[test]
fn truncated_payload_rejected() {
    // Header says "10 bytes" but no payload follows.
    let mut framed = Vec::new();
    framed.extend_from_slice(&10u64.to_le_bytes());
    let err = decode_chunked(&framed, 4096, 4096).unwrap_err();
    assert!(
        matches!(err, Error::UnexpectedEnd | Error::Corrupt),
        "unexpected error: {:?}",
        err
    );
}

#[test]
fn match_before_any_output_rejected() {
    // First token is a match — but there's no history yet. Must be
    // rejected as InvalidDistance.
    //
    //   bits: 1 1 0000001 00  (match short offset 1, length 2, no history)
    //
    // Then EOS + pad.
    let bits = [
        1u8, 1, 0, 0, 0, 0, 0, 0, 1, // match: short offset 1
        0, 0, // length 2
        1, 1, 0, 0, 0, 0, 0, 0,
        0, // EOS (unreachable; included so any continued read terminates cleanly)
    ];
    let payload = pack_msb(&bits);
    let mut framed = Vec::new();
    framed.extend_from_slice(&8u64.to_le_bytes());
    framed.extend_from_slice(&payload);

    let err = decode_chunked(&framed, 4096, 4096).unwrap_err();
    assert_eq!(err, Error::InvalidDistance);
}

#[test]
fn length_mismatch_rejected() {
    // Header claims more bytes than the payload actually decodes to.
    //
    //   bits: 0 'X'_8  EOS pad
    let mut bits: Vec<u8> = Vec::new();
    bits.push(0);
    for shift in (0..8).rev() {
        bits.push((b'X' >> shift) & 1);
    }
    bits.extend_from_slice(&[1, 1, 0, 0, 0, 0, 0, 0, 0]);
    let payload = pack_msb(&bits);
    let mut framed = Vec::new();
    framed.extend_from_slice(&99u64.to_le_bytes()); // lie
    framed.extend_from_slice(&payload);

    let err = decode_chunked(&framed, 4096, 4096).unwrap_err();
    assert!(
        matches!(
            err,
            Error::TrailerMismatch | Error::UnexpectedEnd | Error::Corrupt
        ),
        "unexpected error: {:?}",
        err
    );
}

// ─── Algorithm-trait entry points ──────────────────────────────────────

#[test]
fn algorithm_encoder_decoder_round_trip() {
    let mut enc = <Lzs as Algorithm>::encoder();
    let mut dec = <Lzs as Algorithm>::decoder();
    let input = b"compcol Algorithm trait roundtrip for lzs!";

    let mut encoded = Vec::new();
    let mut buf = vec![0u8; 256];
    let mut consumed = 0;
    while consumed < input.len() {
        let (p, status) = enc.encode(&input[consumed..], &mut buf).unwrap();
        encoded.extend_from_slice(&buf[..p.written]);
        consumed += p.consumed;
        if matches!(status, Status::InputEmpty) {
            break;
        }
    }
    loop {
        let (p, status) = enc.finish(&mut buf).unwrap();
        encoded.extend_from_slice(&buf[..p.written]);
        if matches!(status, Status::StreamEnd) {
            break;
        }
        if p.written == 0 {
            panic!("finish stalled");
        }
    }

    let mut decoded = Vec::new();
    let mut consumed = 0;
    loop {
        let (p, status) = dec.decode(&encoded[consumed..], &mut buf).unwrap();
        decoded.extend_from_slice(&buf[..p.written]);
        consumed += p.consumed;
        if matches!(status, Status::StreamEnd | Status::InputEmpty) {
            break;
        }
    }
    let (_, status) = dec.finish(&mut buf).unwrap();
    assert!(matches!(status, Status::StreamEnd));
    assert_eq!(decoded, input);
}

// ─── factory lookup ────────────────────────────────────────────────────

#[cfg(feature = "factory")]
mod factory {
    use compcol::Status;
    use compcol::factory;

    #[test]
    fn lookup_known() {
        assert!(factory::encoder_by_name("lzs").is_some());
        assert!(factory::decoder_by_name("lzs").is_some());
    }

    #[test]
    fn names_contains_lzs() {
        assert!(factory::names().contains(&"lzs"));
    }

    #[test]
    fn extension_is_lzs() {
        assert_eq!(factory::extension("lzs"), Some("lzs"));
    }

    #[test]
    fn boxed_round_trip() {
        let mut enc = factory::encoder_by_name("lzs").unwrap();
        let mut dec = factory::decoder_by_name("lzs").unwrap();
        let input = b"factory boxed round-trip for lzs";

        let mut encoded = Vec::new();
        let mut buf = vec![0u8; 256];
        let mut consumed = 0;
        while consumed < input.len() {
            let (p, status) = enc.encode(&input[consumed..], &mut buf).unwrap();
            encoded.extend_from_slice(&buf[..p.written]);
            consumed += p.consumed;
            if matches!(status, Status::InputEmpty) {
                break;
            }
        }
        loop {
            let (p, status) = enc.finish(&mut buf).unwrap();
            encoded.extend_from_slice(&buf[..p.written]);
            if matches!(status, Status::StreamEnd) {
                break;
            }
            if p.written == 0 {
                panic!("finish stalled");
            }
        }

        let mut decoded = Vec::new();
        let mut consumed = 0;
        loop {
            let (p, status) = dec.decode(&encoded[consumed..], &mut buf).unwrap();
            decoded.extend_from_slice(&buf[..p.written]);
            consumed += p.consumed;
            if matches!(status, Status::StreamEnd | Status::InputEmpty) {
                break;
            }
        }
        let (_, status) = dec.finish(&mut buf).unwrap();
        assert!(matches!(status, Status::StreamEnd));
        assert_eq!(&decoded[..], input);
    }
}
