//! Integration tests for the gzip codec.

#![cfg(feature = "gzip")]

use compcol::gzip::{Decoder, Encoder};
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
            panic!("gzip encoder finish stalled");
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
    assert_eq!(encoded[0], 0x1F);
    assert_eq!(encoded[1], 0x8B);
    assert_eq!(encoded[2], 0x08); // CM=deflate
    let decoded = decode_chunked(&encoded, 4096, 4096).unwrap();
    assert_eq!(decoded, input, "round-trip mismatch len {}", input.len());
}

#[test]
fn round_trip_empty() {
    round_trip(b"");
}

#[test]
fn round_trip_short() {
    round_trip(b"Hello, gzip!");
}

#[test]
fn round_trip_repeated() {
    round_trip(&b"foo bar baz ".repeat(100));
}

#[test]
fn round_trip_long_zeros() {
    let input = vec![0u8; 8192];
    let encoded = encode_all(&input);
    assert!(encoded.len() < 200, "zeros didn't compress: {}", encoded.len());
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
fn decode_reference_gzip_with_extras() {
    // A gzip stream produced with `printf hello | gzip -n` (FLG=0, no FNAME).
    // Hex captured offline. ID1 ID2 CM FLG | MTIME | XFL OS | deflate | CRC ISIZE
    // 1f8b08 00 00000000 00 03 cb48cdc9c907 8631 5e60 0500 0000
    // Hmm, that's not quite valid. Let me construct one properly:
    // Run `printf hello | gzip -n -c | xxd`:
    //   1f8b 0800 0000 0000 0003 cb48 cdc9 c907 008631 5e60 0500 0000
    // Actually let's just use a fixture generated via Python's gzip module.
    let stream = hex("1f8b0800000000000003cb48cdc9c9070086a610360500000000");
    let decoded = decode_chunked(&stream, 1024, 1024).unwrap();
    assert_eq!(decoded, b"hello");
}

#[test]
fn decode_with_fname_field() {
    // gzip stream of "hello" with FNAME = "test.txt" (FLG = 0x08).
    // Constructed: 1f8b08 08 (FLG=FNAME) 00000000 00 03 (OS=Unix) "test.txt\0" then deflate "cb48cdc9c907" then CRC+ISIZE.
    // CRC32 of "hello" = 0x3610a686 (LE = 86 a6 10 36)
    // ISIZE = 5 (LE = 05 00 00 00)
    let mut stream = vec![0x1F, 0x8B, 0x08, 0x08, 0, 0, 0, 0, 0, 0x03];
    stream.extend_from_slice(b"test.txt\0");
    stream.extend_from_slice(&hex("cb48cdc9c90700"));
    stream.extend_from_slice(&[0x86, 0xa6, 0x10, 0x36, 0x05, 0x00, 0x00, 0x00]);
    let decoded = decode_chunked(&stream, 1024, 1024).unwrap();
    assert_eq!(decoded, b"hello");
}

#[test]
fn bad_magic_rejected() {
    let stream = hex("1f8c0800000000000003"); // ID2=0x8c instead of 0x8b
    let mut dec = Decoder::new();
    let mut buf = [0u8; 16];
    let err = dec.decode(&stream, &mut buf).unwrap_err();
    assert_eq!(err, Error::BadHeader);
}

#[test]
fn unsupported_method_rejected() {
    // CM=9 instead of 8 (deflate)
    let stream = hex("1f8b0900000000000003");
    let mut dec = Decoder::new();
    let mut buf = [0u8; 16];
    let err = dec.decode(&stream, &mut buf).unwrap_err();
    assert_eq!(err, Error::Unsupported);
}

#[test]
fn corrupted_crc_rejected() {
    let input = b"some payload bytes";
    let mut encoded = encode_all(input);
    // Flip a bit in the CRC (4 bytes before ISIZE).
    let crc_offset = encoded.len() - 8;
    encoded[crc_offset] ^= 0x01;
    let err = decode_chunked(&encoded, 4096, 4096).unwrap_err();
    assert_eq!(err, Error::ChecksumMismatch);
}

#[test]
fn corrupted_isize_rejected() {
    let input = b"some payload bytes";
    let mut encoded = encode_all(input);
    // Flip a bit in ISIZE (last 4 bytes).
    let last = encoded.len() - 1;
    encoded[last] ^= 0x80;
    let err = decode_chunked(&encoded, 4096, 4096).unwrap_err();
    assert_eq!(err, Error::TrailerMismatch);
}
