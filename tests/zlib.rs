//! Integration tests for the zlib codec.

#![cfg(feature = "zlib")]

use compcol::zlib::{Decoder, Encoder};
use compcol::{Decoder as _, Encoder as _, Error};

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn encode_all(input: &[u8]) -> Vec<u8> {
    let mut enc = Encoder::new();
    let mut out = Vec::new();
    let mut buf = vec![0u8; 4096];
    loop {
        let p = enc.encode(input, &mut buf).unwrap();
        out.extend_from_slice(&buf[..p.written]);
        if p.consumed == input.len() {
            break;
        }
    }
    loop {
        let p = enc.finish(&mut buf).unwrap();
        out.extend_from_slice(&buf[..p.written]);
        if p.done {
            break;
        }
        if p.written == 0 {
            panic!("zlib encoder finish stalled");
        }
    }
    out
}

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

fn decode_chunked(encoded: &[u8], in_chunk: usize, out_chunk: usize) -> Result<Vec<u8>, Error> {
    let mut dec = Decoder::new();
    let mut out = Vec::new();
    let mut buf = vec![0u8; out_chunk.max(1)];
    let mut i = 0;
    while i < encoded.len() {
        let end = (i + in_chunk).min(encoded.len());
        let chunk = &encoded[i..end];
        let mut consumed = 0;
        loop {
            let p = dec.decode(&chunk[consumed..], &mut buf)?;
            out.extend_from_slice(&buf[..p.written]);
            consumed += p.consumed;
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

fn round_trip(input: &[u8]) {
    let encoded = encode_all(input);
    // First byte should be 0x78 (the standard zlib CMF byte).
    assert_eq!(encoded[0], 0x78);
    let decoded = decode_chunked(&encoded, 4096, 4096).unwrap();
    assert_eq!(decoded, input, "round-trip mismatch len {}", input.len());
}

#[test]
fn round_trip_empty() {
    round_trip(b"");
}

#[test]
fn round_trip_short() {
    round_trip(b"Hello, world!");
}

#[test]
fn round_trip_repeated() {
    round_trip(&b"foo bar baz ".repeat(100));
}

#[test]
fn round_trip_long_zeros() {
    let input = vec![0u8; 4096];
    let encoded = encode_all(&input);
    // Should compress well: 4096 bytes -> << 100 with the header/trailer overhead.
    assert!(encoded.len() < 100, "zeros didn't compress: {}", encoded.len());
    let decoded = decode_chunked(&encoded, 4096, 4096).unwrap();
    assert_eq!(decoded, input);
}

#[test]
fn round_trip_streaming_one_byte() {
    let input = b"streaming bytes one at a time".to_vec();
    let encoded = encode_chunked(&input, 1, 1);
    let decoded = decode_chunked(&encoded, 1, 1).unwrap();
    assert_eq!(decoded, input);
}

#[test]
fn decode_python_zlib_reference() {
    // Output of: python3 -c "import zlib; print(zlib.compress(b'hello world', 6).hex())"
    // = "789c cb48 cdc9 c957 28cf 2fca 4901 0019 9b04 1c"
    let stream = hex("789ccb48cdc9c95728cf2fca4901001a0b045d");
    let decoded = decode_chunked(&stream, 1024, 1024).unwrap();
    assert_eq!(decoded, b"hello world");
}

#[test]
fn corrupt_header_rejected() {
    // CMF=0x77 (CM=7, not deflate)
    let stream = hex("77deadbeef");
    let mut dec = Decoder::new();
    let mut buf = [0u8; 16];
    let err = dec.decode(&stream, &mut buf).unwrap_err();
    assert_eq!(err, Error::Unsupported);
}

#[test]
fn bad_check_rejected() {
    // CMF=0x78, FLG with FCHECK that violates divisibility by 31.
    let stream = hex("7800deadbeef");
    let mut dec = Decoder::new();
    let mut buf = [0u8; 16];
    let err = dec.decode(&stream, &mut buf).unwrap_err();
    assert_eq!(err, Error::BadHeader);
}

#[test]
fn corrupted_adler_rejected() {
    let input = b"some payload bytes";
    let mut encoded = encode_all(input);
    // Flip a bit in the trailer (last 4 bytes).
    let last = encoded.len() - 1;
    encoded[last] ^= 0x01;
    let err = decode_chunked(&encoded, 4096, 4096).unwrap_err();
    assert_eq!(err, Error::ChecksumMismatch);
}
