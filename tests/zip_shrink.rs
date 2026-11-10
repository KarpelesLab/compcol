//! Streaming decode tests for the ZIP Shrink (method 1) codec.
//!
//! Decoder-only — the encoder permanently returns `Error::Unsupported`.
//! Fixtures were produced by a reference Shrink encoder, then verified by
//! decompressing the surrounding `.zip` with Info-ZIP `unzip -p`. The byte
//! arrays below are the raw method-1 payloads (no local file header) with
//! a 4-byte LE uncompressed-length prefix as documented in
//! `src/zip_shrink/mod.rs`.
//!
//! Each fixture carries:
//!  * `name`       — descriptive label
//!  * `expected`   — the uncompressed bytes
//!  * `payload`    — the raw Shrink method-1 byte stream
//!
//! The test framing prepends `expected.len() as u32 LE` and feeds the
//! result to the decoder. The `raw_*` tests feed the same payloads,
//! without the header, to `Decoder::raw(len)`.

#![cfg(feature = "zip_shrink")]

use compcol::zip_shrink::{Decoder, Encoder, ZipShrink};
use compcol::{Algorithm, Decoder as _, Encoder as _, Error, Status};

fn framed(payload: &[u8], len: u32) -> Vec<u8> {
    let mut v = Vec::with_capacity(payload.len() + 4);
    v.extend_from_slice(&len.to_le_bytes());
    v.extend_from_slice(payload);
    v
}

fn decode_chunked(framed: &[u8], in_chunk: usize, out_chunk: usize) -> Result<Vec<u8>, Error> {
    let mut dec = Decoder::new();
    decode_chunked_with(&mut dec, framed, in_chunk, out_chunk)
}

fn decode_chunked_with(
    dec: &mut Decoder,
    framed: &[u8],
    in_chunk: usize,
    out_chunk: usize,
) -> Result<Vec<u8>, Error> {
    let mut decoded = Vec::new();
    let mut buf = vec![0u8; out_chunk.max(1)];
    let mut i = 0;
    while i < framed.len() {
        let end = (i + in_chunk).min(framed.len());
        let chunk = &framed[i..end];
        let mut consumed = 0;
        while consumed < chunk.len() {
            let (p, status) = dec.decode(&chunk[consumed..], &mut buf)?;
            decoded.extend_from_slice(&buf[..p.written]);
            consumed += p.consumed;
            match status {
                Status::StreamEnd | Status::InputEmpty => break,
                Status::OutputFull => continue,
            }
        }
        i = end;
    }
    // Drain after feeding everything.
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
                    panic!("decoder finish stalled");
                }
            }
        }
    }
    Ok(decoded)
}

// ─── algorithm metadata ─────────────────────────────────────────────────

#[test]
fn name_is_zip_shrink() {
    assert_eq!(<ZipShrink as Algorithm>::NAME, "zip-shrink");
}

// ─── encoder is Unsupported ─────────────────────────────────────────────

#[test]
fn encoder_returns_unsupported() {
    let mut enc = Encoder::new();
    let mut out = [0u8; 16];
    assert_eq!(enc.encode(b"abc", &mut out).err(), Some(Error::Unsupported));
    assert_eq!(enc.finish(&mut out).err(), Some(Error::Unsupported));
}

// Payloads shared by the framed and raw tests.
const LOREM: &[u8] = &[
    0x6c, 0xde, 0xc8, 0x29, 0xd3, 0x06, 0x44, 0x1a, 0x38, 0x73, 0xea, 0x14, 0x24, 0xf3, 0x26, 0xa0,
    0x1c, 0x10, 0x73, 0xd2, 0xd0, 0x01, 0x11, 0xa6, 0x4d, 0x99, 0x89, 0x0e, 0x09, 0x1a, 0x44, 0xa8,
    0x10, 0x04, 0x43, 0x87, 0x10, 0x25, 0x52, 0xb4, 0x88, 0x51, 0xa0, 0xc6, 0x83, 0x09, 0x17, 0x36,
    0x14, 0x18, 0x72, 0x62, 0xc5, 0x8b, 0x20, 0x32, 0x16, 0x44, 0xd9, 0xf1, 0x23, 0xcb, 0x88, 0x2e,
    0x49, 0x82, 0x00,
];

const MIXED: &[u8] = &[
    0x74, 0xd0, 0x94, 0x01, 0x11, 0xa7, 0x4e, 0x9a, 0x31, 0x6b, 0x40, 0x88, 0x91, 0xf3, 0xe6, 0x8e,
    0x1b, 0x10, 0x66, 0xde, 0xe0, 0x01, 0xa1, 0xa6, 0x4e, 0x1b, 0x38, 0x73, 0x40, 0xbc, 0xb1, 0x53,
    0x46, 0x0e, 0x88, 0x80, 0x03, 0xd9, 0x84, 0xd1, 0x93, 0x07, 0x04, 0x99, 0x37, 0x67, 0x14, 0x80,
    0x24, 0x68, 0x10, 0xa1, 0x42, 0x86, 0x0e, 0x21, 0x4a, 0xa4, 0x68, 0x11, 0xa3, 0x46, 0x8e, 0x1e,
    0x57, 0x8a, 0x24, 0x69, 0x12, 0xa5, 0x4a, 0x81, 0x2c, 0x0f, 0x26, 0x5c, 0xd8, 0xf0, 0x61, 0xc4,
    0x89, 0x15, 0x2f, 0x66, 0xdc, 0xd8, 0xf1, 0x23, 0xd0, 0x9d, 0x25, 0x4f, 0xa6, 0x5c, 0x59, 0x50,
    0xe8, 0xcb, 0xa2, 0x32, 0x91, 0xd6, 0x5c, 0x8a, 0xd3, 0x69, 0xc8, 0x91, 0x51, 0x7d, 0x52, 0x6d,
    0x39, 0x14, 0xa6, 0xd1, 0x99, 0x49, 0x6d, 0x32, 0xcd, 0xf9, 0x14, 0x6c, 0xcf, 0xa9, 0x40, 0xab,
    0xba, 0x24, 0x1a, 0xf3, 0x28, 0x4d, 0xa5, 0x37, 0x9b, 0xea, 0x74, 0x2b, 0xf5, 0xe7, 0x40, 0xb9,
    0x65, 0xb1, 0xda, 0x4d, 0xcb, 0x55, 0x6f, 0x5b, 0x9e, 0x7d, 0xc7, 0x5a, 0xa5, 0x7b, 0x56, 0x2b,
    0xde, 0xb5, 0x5e, 0x41, 0x40, 0x7d, 0xab, 0x60, 0xcc, 0x9b, 0x8b, 0x96, 0xd9, 0x80, 0xd0, 0x93,
    0x06, 0xce, 0x97, 0x39, 0x68, 0xe4, 0xa4, 0x71, 0x93, 0xd0, 0x4c, 0x1a, 0x3c, 0x74, 0xea, 0xc8,
    0x19, 0x68, 0x59, 0x0e, 0x9c, 0x3a, 0x19, 0x63, 0xc8, 0x98, 0x41, 0xa3, 0x06, 0x08, 0x1b, 0x37,
    0x70, 0xe4, 0x80, 0x51, 0xf9, 0x32, 0x9c, 0xcc, 0x9b, 0x3b, 0x7f, 0x0e, 0x3d, 0xba, 0xf4, 0xe9,
    0xd4, 0xab, 0x41, 0xb4, 0x7e, 0x1d, 0x7b, 0x76, 0xed, 0xdb, 0xb9, 0x77, 0xf7, 0xc6, 0xfc, 0x46,
    0x33, 0x67, 0xcf, 0xa0, 0x45, 0x93, 0x86, 0x78, 0x5c, 0x35, 0xeb, 0x37, 0xae, 0x61, 0x83, 0x90,
    0x4d, 0xdb, 0x36, 0x6e, 0xdd, 0xbc, 0x2d, 0x53, 0xb7, 0x2e, 0x3c, 0x7b, 0x71, 0xee, 0xa8, 0xbd,
    0x2b, 0x07, 0xcf, 0x7c, 0xbc, 0x73, 0xf3, 0xd1, 0x79, 0x03,
];

const ABC: &[u8] = &[
    0x41, 0x84, 0x0c, 0x09, 0x38, 0x50, 0x20, 0xc1, 0x83, 0x06, 0x13, 0x16, 0x5c, 0x88, 0x90, 0xa1,
    0xc2, 0x86, 0x10, 0x1f, 0x4a, 0x74, 0x48, 0x31, 0x62, 0xc5, 0x89, 0x16, 0x33, 0x62, 0xdc, 0x78,
    0xb1, 0xa3, 0x46, 0x8f, 0x1c, 0x3f, 0x8a, 0x0c, 0x49, 0x12, 0xa4, 0xc9, 0x91, 0x27, 0x4b, 0xa2,
    0x5c, 0xa9, 0xb2, 0x65, 0xca, 0x97, 0x2c, 0x61, 0xba, 0x8c, 0x49, 0x73, 0xa6, 0x4d, 0x99, 0x38,
    0x6b, 0xe6, 0xbc, 0xa9, 0xb3, 0x27, 0xcf, 0x9f, 0x3b, 0x83, 0xfa, 0x14, 0x0a, 0x74, 0xa8, 0xd1,
    0xa2, 0x48, 0x89, 0x2a, 0x3d, 0xba, 0x34, 0x29, 0xd3, 0xa7, 0x4e, 0xa3, 0x36, 0x9d, 0x0a, 0x95,
    0xaa, 0xd4, 0xaa, 0x58, 0xaf, 0x6a, 0xb5, 0xca, 0x35, 0x6b, 0xd7, 0xad, 0x5e, 0xc3, 0x82, 0x1d,
    0xfb, 0xb5, 0xac, 0x58, 0xb3, 0x64, 0xcf, 0xaa, 0x4d, 0xcb, 0x16, 0xad, 0xdb, 0xb5, 0x6f, 0xdb,
    0xc2, 0x9d, 0x2b, 0xb7, 0x6e, 0xdc, 0xbb, 0x74, 0xf1, 0xda, 0xcd, 0xcb, 0x77, 0xaf, 0x5f, 0xbd,
    0x80, 0xfb, 0x06, 0xfe, 0x2b, 0xb8, 0x30, 0xe1, 0xc3, 0x83, 0x13, 0x1b, 0x56, 0x8c, 0x78, 0xb1,
    0xe3, 0xc6, 0x90, 0x19, 0x4b, 0x7e, 0x3c, 0x39, 0x32, 0xe5, 0xcb, 0x96, 0x33, 0x57, 0xde, 0x8c,
    0x99, 0xb3, 0xe6, 0xce, 0xa0, 0x3f, 0x8b, 0xf6, 0x4c, 0x3a, 0x74, 0xe9, 0xd1, 0xa6, 0x53, 0xa3,
    0x5e, 0x7d, 0xba, 0xb5, 0x6a, 0xd7, 0xac, 0x5f, 0xcb, 0x8e, 0x4d, 0x1b, 0xb6, 0xed, 0xd9, 0xb7,
    0x6b, 0xe3, 0xde, 0xad, 0xbb, 0x37, 0x57,
];

fn mixed_expected() -> Vec<u8> {
    let mut expected = Vec::new();
    for _ in 0..8 {
        expected.extend_from_slice(b"the quick brown fox jumps over the lazy dog\n");
    }
    for _ in 0..4 {
        expected.extend_from_slice(b"compcol zip_shrink fixture corpus 12345 67890\n");
    }
    expected
}

// ─── reference fixtures ─────────────────────────────────────────────────
//
// Each payload below was produced by a reference Shrink encoder that
// matches PKZIP 1.x semantics (LSB-first bit packing, 256,1 widen,
// 256,2 partial clear, HSIZE = 8192). The resulting ZIP archives were
// cross-decompressed by Info-ZIP `unzip 6.00` to confirm the byte
// streams are valid.

#[test]
fn decode_single_byte() {
    // Source: b"X"
    let payload: &[u8] = &[0x58, 0x00];
    let framed = framed(payload, 1);
    let out = decode_chunked(&framed, framed.len(), 64).unwrap();
    assert_eq!(out, b"X");
}

#[test]
fn decode_hello_world() {
    // Source: b"hello world"
    let payload: &[u8] = &[
        0x68, 0xca, 0xb0, 0x61, 0xf3, 0x06, 0xc4, 0x9d, 0x37, 0x72, 0xd8, 0x90, 0x01,
    ];
    let framed = framed(payload, 11);
    let out = decode_chunked(&framed, framed.len(), 64).unwrap();
    assert_eq!(out, b"hello world");
}

#[test]
fn decode_repeated_a() {
    // Source: b"aaaaaaaa" — exercises the KwKwK path on a tight loop of
    // identical bytes.
    let payload: &[u8] = &[0x61, 0x02, 0x0a, 0x0c, 0x08];
    let framed = framed(payload, 8);
    let out = decode_chunked(&framed, framed.len(), 64).unwrap();
    assert_eq!(out, b"aaaaaaaa");
}

#[test]
fn decode_lorem_4x() {
    // Source: b"lorem ipsum dolor sit amet " * 4 = 108 bytes.
    let expected = b"lorem ipsum dolor sit amet ".repeat(4);
    let framed = framed(LOREM, expected.len() as u32);
    let out = decode_chunked(&framed, framed.len(), 64).unwrap();
    assert_eq!(out, expected);
}

#[test]
fn decode_mixed_corpus() {
    // Source: 8 copies of "the quick brown fox jumps over the lazy dog\n"
    // followed by 4 copies of "compcol zip_shrink fixture corpus 12345
    // 67890\n" = 536 bytes. Exercises a 9→10→11→12 width walk and a
    // healthy dictionary fill across two phrases.
    let expected = mixed_expected();
    assert_eq!(expected.len(), 536);
    let framed = framed(MIXED, expected.len() as u32);
    let out = decode_chunked(&framed, framed.len(), 64).unwrap();
    assert_eq!(out, expected);
}

#[test]
fn decode_long_repetitive() {
    // Source: b"ABCABCABCABC" * 512 = 6144 bytes. Encoder output is only
    // 215 bytes — heavy KwKwK and width walk from 9 up to 13 bits.
    let expected = b"ABCABCABCABC".repeat(512);
    assert_eq!(expected.len(), 6144);
    let framed = framed(ABC, expected.len() as u32);
    let out = decode_chunked(&framed, framed.len(), 1024).unwrap();
    assert_eq!(out, expected);
}

// ─── streaming chunk sizes ─────────────────────────────────────────────

#[test]
fn decode_byte_at_a_time() {
    let payload: &[u8] = &[
        0x68, 0xca, 0xb0, 0x61, 0xf3, 0x06, 0xc4, 0x9d, 0x37, 0x72, 0xd8, 0x90, 0x01,
    ];
    let framed = framed(payload, 11);
    let out = decode_chunked(&framed, 1, 1).unwrap();
    assert_eq!(out, b"hello world");
}

#[test]
fn decode_tiny_output_buffer() {
    let payload: &[u8] = &[0x61, 0x02, 0x0a, 0x0c, 0x08];
    let framed = framed(payload, 8);
    let out = decode_chunked(&framed, framed.len(), 1).unwrap();
    assert_eq!(out, b"aaaaaaaa");
}

// ─── reset / reuse ─────────────────────────────────────────────────────

#[test]
fn decoder_reset_allows_reuse() {
    let mut dec = Decoder::new();

    let p1: &[u8] = &[0x58, 0x00];
    let f1 = framed(p1, 1);
    assert_eq!(
        decode_chunked_with(&mut dec, &f1, f1.len(), 32).unwrap(),
        b"X"
    );
    dec.reset();

    let p2: &[u8] = &[
        0x68, 0xca, 0xb0, 0x61, 0xf3, 0x06, 0xc4, 0x9d, 0x37, 0x72, 0xd8, 0x90, 0x01,
    ];
    let f2 = framed(p2, 11);
    assert_eq!(
        decode_chunked_with(&mut dec, &f2, f2.len(), 32).unwrap(),
        b"hello world"
    );
}

// ─── error cases ───────────────────────────────────────────────────────

#[test]
fn truncated_header_errors_on_finish() {
    let mut dec = Decoder::new();
    let mut buf = [0u8; 16];
    // Three bytes of the four-byte length header.
    let (_, _) = dec.decode(&[0x05, 0x00, 0x00], &mut buf).unwrap();
    let err = dec.finish(&mut buf).err().unwrap();
    assert_eq!(err, Error::UnexpectedEnd);
}

#[test]
fn truncated_payload_errors_on_finish() {
    let mut dec = Decoder::new();
    let mut buf = [0u8; 16];
    // Declare 11 bytes but feed only the first compressed byte after the
    // header.
    let framed = [
        0x0b, 0x00, 0x00, 0x00, // length = 11
        0x68, // first compressed byte
    ];
    let _ = dec.decode(&framed, &mut buf);
    let err = dec.finish(&mut buf).err().unwrap();
    assert_eq!(err, Error::UnexpectedEnd);
}

#[test]
fn invalid_control_byte_errors() {
    // Construct a tiny stream that ends with `256, 99` — an unknown
    // control sub-command. Bit packing is LSB-first at 9 bits per code.
    // Codes in order: literal 'A' (0x41 = 65), 256 (BOGUS), 99.
    // 9-bit packing:
    //   bit stream low→high: 0|0100_0001 | 1|0000_0000 | 0|0110_0011
    // = 0b011_00011_0_0000_0000_1_0100_0001
    // Easier to compute via Python; we hard-code the bytes:
    let mut stream = Vec::new();
    let mut acc: u32 = 0;
    let mut cnt: u8 = 0;
    fn push(stream: &mut Vec<u8>, acc: &mut u32, cnt: &mut u8, code: u32, n: u8) {
        *acc |= code << *cnt;
        *cnt += n;
        while *cnt >= 8 {
            stream.push(*acc as u8);
            *acc >>= 8;
            *cnt -= 8;
        }
    }
    push(&mut stream, &mut acc, &mut cnt, 0x41, 9);
    push(&mut stream, &mut acc, &mut cnt, 256, 9);
    push(&mut stream, &mut acc, &mut cnt, 99, 9);
    if cnt > 0 {
        stream.push(acc as u8);
    }
    let f = framed(&stream, 32); // any non-zero target; we error before reaching it
    let mut dec = Decoder::new();
    let mut out = vec![0u8; 64];
    // Feed once and finish; the bad-control error should surface on one
    // of the calls.
    let err1 = dec.decode(&f, &mut out);
    let err2 = dec.finish(&mut out);
    assert!(
        err1.is_err() || err2.is_err(),
        "expected an error from invalid control"
    );
    let err = err1.err().or(err2.err()).unwrap();
    assert_eq!(err, Error::Corrupt);
}

#[test]
fn empty_declared_length_yields_empty() {
    // length = 0; no payload bytes needed.
    let framed = [0u8; 4];
    let mut dec = Decoder::new();
    let mut buf = [0u8; 16];
    let (_, status) = dec.decode(&framed, &mut buf).unwrap();
    let _ = status; // may report StreamEnd via finish.
    let (p, status) = dec.finish(&mut buf).unwrap();
    assert_eq!(p.written, 0);
    assert!(matches!(status, Status::StreamEnd));
}

// ─── raw (headerless) entry point ──────────────────────────────────────
//
// `Decoder::raw(len)` takes the size from the ZIP header and consumes the
// bare payload. It must decode exactly what the framed path decodes.

const HELLO: &[u8] = &[
    0x68, 0xca, 0xb0, 0x61, 0xf3, 0x06, 0xc4, 0x9d, 0x37, 0x72, 0xd8, 0x90, 0x01,
];
const AAAA: &[u8] = &[0x61, 0x02, 0x0a, 0x0c, 0x08];

/// Every reference fixture above as (payload, expected).
fn all_raw_cases() -> Vec<(Vec<u8>, Vec<u8>)> {
    vec![
        (vec![0x58, 0x00], b"X".to_vec()),
        (HELLO.to_vec(), b"hello world".to_vec()),
        (AAAA.to_vec(), b"aaaaaaaa".to_vec()),
        (LOREM.to_vec(), b"lorem ipsum dolor sit amet ".repeat(4)),
        (MIXED.to_vec(), mixed_expected()),
        (ABC.to_vec(), b"ABCABCABCABC".repeat(512)),
    ]
}

#[test]
fn raw_matches_framed_all_chunkings() {
    for (payload, expected) in all_raw_cases() {
        let f = framed(&payload, expected.len() as u32);
        let framed_out = decode_chunked(&f, f.len(), 64).unwrap();
        assert_eq!(framed_out, expected);
        for &(ic, oc) in &[(1, 1), (1, 3), (2, 7), (5, 1), (16, 16), (usize::MAX, 64)] {
            let mut dec = Decoder::raw(expected.len() as u64);
            let ic = ic.min(payload.len().max(1));
            let out = decode_chunked_with(&mut dec, &payload, ic, oc).unwrap();
            assert_eq!(out, expected, "in_chunk={ic} out_chunk={oc}");
        }
    }
}

#[test]
fn raw_reports_stream_end_like_framed() {
    // Single call with a big enough output: both paths must report the
    // same status and byte counts (minus the 4 header bytes).
    let f = framed(HELLO, 11);
    let mut a = Decoder::new();
    let mut b = Decoder::raw(11);
    let mut oa = [0u8; 64];
    let mut ob = [0u8; 64];
    let (pa, sa) = a.decode(&f, &mut oa).unwrap();
    let (pb, sb) = b.decode(HELLO, &mut ob).unwrap();
    assert_eq!(sa, sb);
    assert_eq!(pa.written, pb.written);
    assert_eq!(pa.consumed, pb.consumed + 4);
    let (fa, ta) = a.finish(&mut oa[pa.written..]).unwrap();
    let (fb, tb) = b.finish(&mut ob[pb.written..]).unwrap();
    assert_eq!((fa.written, ta), (fb.written, tb));
    assert_eq!(tb, Status::StreamEnd);
    assert_eq!(&ob[..pb.written + fb.written], b"hello world");
}

#[test]
fn raw_trailing_bytes_like_framed() {
    // Extra bytes after the entry are handled the same way on both paths.
    let mut payload = HELLO.to_vec();
    payload.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    let f = framed(&payload, 11);
    let framed_res = decode_chunked(&f, f.len(), 64);
    let raw_res = decode_chunked_with(&mut Decoder::raw(11), &payload, payload.len(), 64);
    assert_eq!(framed_res, raw_res);
    let framed_res = decode_chunked(&f, 1, 1);
    let raw_res = decode_chunked_with(&mut Decoder::raw(11), &payload, 1, 1);
    assert_eq!(framed_res, raw_res);
}

#[test]
fn raw_shorter_declared_len_truncates_like_framed() {
    let f = framed(HELLO, 5);
    let framed_out = decode_chunked(&f, 1, 1).unwrap();
    let raw_out = decode_chunked_with(&mut Decoder::raw(5), HELLO, 1, 1).unwrap();
    assert_eq!(framed_out, b"hello");
    assert_eq!(raw_out, framed_out);
}

#[test]
fn raw_truncated_payload_errors_on_finish() {
    for (payload, expected) in all_raw_cases() {
        for cut in [0, payload.len() / 2, payload.len() - 1] {
            let f = framed(&payload[..cut], expected.len() as u32);
            let framed_res = decode_chunked(&f, 1, 1);
            let raw_res = decode_chunked_with(
                &mut Decoder::raw(expected.len() as u64),
                &payload[..cut],
                1,
                1,
            );
            assert_eq!(raw_res, Err(Error::UnexpectedEnd), "cut={cut}");
            assert_eq!(framed_res, raw_res, "cut={cut}");
        }
    }
}

#[test]
fn raw_overstated_len_errors() {
    // Declared size larger than the payload decodes to.
    let res = decode_chunked_with(&mut Decoder::raw(12), HELLO, HELLO.len(), 64);
    assert_eq!(res, Err(Error::UnexpectedEnd));
    let f = framed(HELLO, 12);
    assert_eq!(decode_chunked(&f, f.len(), 64), res);
}

#[test]
fn raw_reset_keeps_raw_mode() {
    let mut dec = Decoder::raw(11);
    assert_eq!(
        decode_chunked_with(&mut dec, HELLO, 3, 2).unwrap(),
        b"hello world"
    );
    dec.reset();
    // Same length, no header expected after reset.
    assert_eq!(
        decode_chunked_with(&mut dec, HELLO, 1, 1).unwrap(),
        b"hello world"
    );
    // Reset mid-stream too.
    dec.reset();
    let mut buf = [0u8; 4];
    let _ = dec.decode(&HELLO[..4], &mut buf).unwrap();
    dec.reset();
    assert_eq!(
        decode_chunked_with(&mut dec, HELLO, HELLO.len(), 64).unwrap(),
        b"hello world"
    );
}

#[test]
fn framed_reset_keeps_framed_mode() {
    let mut dec = Decoder::new();
    let f = framed(HELLO, 11);
    assert_eq!(
        decode_chunked_with(&mut dec, &f, 4, 4).unwrap(),
        b"hello world"
    );
    dec.reset();
    assert_eq!(
        decode_chunked_with(&mut dec, &f, 1, 1).unwrap(),
        b"hello world"
    );
}

#[test]
fn raw_zero_len_yields_empty() {
    // finish() with no input at all.
    let mut dec = Decoder::raw(0);
    let mut buf = [0u8; 16];
    let (p, status) = dec.finish(&mut buf).unwrap();
    assert_eq!(p.written, 0);
    assert_eq!(status, Status::StreamEnd);

    // decode() of an empty slice, then finish.
    let mut dec = Decoder::raw(0);
    let (p, status) = dec.decode(&[], &mut buf).unwrap();
    assert_eq!(p.written, 0);
    assert_eq!(status, Status::StreamEnd);
    let (p, status) = dec.finish(&mut buf).unwrap();
    assert_eq!(p.written, 0);
    assert_eq!(status, Status::StreamEnd);

    // Same as the framed zero-length stream.
    assert_eq!(
        decode_chunked_with(&mut Decoder::raw(0), &[], 1, 1).unwrap(),
        decode_chunked(&[0u8; 4], 1, 1).unwrap()
    );
}

#[test]
fn raw_accepts_sizes_above_u32() {
    // A ZIP64-sized declaration must not be truncated: decoding the small
    // payload then running out of input is a truncation error, not a
    // successful 11-byte (or wrapped) result.
    let len = (1u64 << 32) + 11;
    let res = decode_chunked_with(&mut Decoder::raw(len), HELLO, HELLO.len(), 64);
    assert_eq!(res, Err(Error::UnexpectedEnd));
}

// ─── large streams (more than one internal 16 KiB decode burst) ────────
//
// The decoder buffers decoded bytes internally in bursts of about 16 KiB.
// A stream that decodes to more than that used to stall: `decode` took all
// the input, handed back the first burst, said `InputEmpty`, and `finish`
// then reported `UnexpectedEnd` with the rest of the input still undecoded.

fn xorshift_bytes(n: usize, mut s: u64) -> Vec<u8> {
    (0..n)
        .map(|_| {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s as u8
        })
        .collect()
}

/// LSB-first code writer for the test encoders below.
struct CodeWriter {
    out: Vec<u8>,
    acc: u32,
    cnt: u32,
}

impl CodeWriter {
    fn new() -> Self {
        Self {
            out: Vec::new(),
            acc: 0,
            cnt: 0,
        }
    }
    fn push(&mut self, code: u32, bits: u32) {
        self.acc |= code << self.cnt;
        self.cnt += bits;
        while self.cnt >= 8 {
            self.out.push(self.acc as u8);
            self.acc >>= 8;
            self.cnt -= 8;
        }
    }
    fn finish(mut self) -> Vec<u8> {
        if self.cnt > 0 {
            self.out.push(self.acc as u8);
        }
        self.out
    }
}

/// Encode `data` as 9-bit literal codes, with a partial clear every 7000
/// bytes so the dictionary (which only ever holds leaves here) never fills.
fn shrink_literals(data: &[u8]) -> Vec<u8> {
    let mut w = CodeWriter::new();
    for (i, &b) in data.iter().enumerate() {
        if i > 0 && i % 7000 == 0 {
            w.push(256, 9);
            w.push(2, 9);
        }
        w.push(b as u32, 9);
    }
    w.finish()
}

/// A small real Shrink encoder for tests: greedy LZW that widens codes with
/// `256,1` and issues `256,2` (partial clear) when the dictionary is full.
/// It keeps the same dictionary bookkeeping as Info-ZIP's `unshrink.c`
/// (lowest free slot above the last one used; partial clear frees leaves up
/// to the last slot used), so its streams use string codes, KwKwK codes,
/// every code width and many partial clears.
fn shrink_lzw(data: &[u8]) -> Vec<u8> {
    use std::collections::HashMap;
    const HSIZE: usize = 8192;
    const FREE: u16 = 0xFFFF;
    const LITERAL: u16 = 0xFFFE;

    fn next_free(parent: &[u16], from: usize) -> Option<usize> {
        (from + 1..HSIZE).find(|&s| parent[s] == FREE)
    }

    let mut parent = vec![FREE; HSIZE];
    for p in parent.iter_mut().take(257) {
        *p = LITERAL;
    }
    // (parent code, next byte) -> code, for entries the encoder may use.
    let mut child: HashMap<(u16, u8), u16> = HashMap::new();
    let mut last_free = 256usize;
    let mut bits = 9u32;
    let mut w = CodeWriter::new();
    let mut prev: Option<u16> = None;
    let mut i = 0usize;
    while i < data.len() {
        // The decoder adds (prev, first byte of this string) on receiving
        // this code. Mirror that first, clearing if no slot is left.
        if let Some(p) = prev {
            let mut slot = next_free(&parent, last_free);
            if slot.is_none() {
                w.push(256, bits);
                w.push(2, bits);
                let mut has_child = vec![false; HSIZE];
                for &par in &parent[257..=last_free] {
                    if par != FREE && par != LITERAL && par > 256 {
                        has_child[par as usize] = true;
                    }
                }
                for (par, &kept) in parent[257..=last_free]
                    .iter_mut()
                    .zip(&has_child[257..=last_free])
                {
                    if !kept {
                        *par = FREE;
                    }
                }
                last_free = 256;
                child.retain(|_, c| parent[*c as usize] != FREE);
                slot = next_free(&parent, last_free);
            }
            let slot = slot.expect("partial clear freed nothing");
            // Usable only if its prefix survived the clear; otherwise the
            // slot is occupied but the encoder never refers to it.
            let usable = parent[p as usize] != FREE && slot != p as usize;
            parent[slot] = p;
            last_free = slot;
            if usable {
                child.insert((p, data[i]), slot as u16);
            }
        }
        let mut code = data[i] as u16;
        let mut len = 1;
        while i + len < data.len() {
            match child.get(&(code, data[i + len])) {
                Some(&c) => {
                    code = c;
                    len += 1;
                }
                None => break,
            }
        }
        while (code as u32) >= (1 << bits) {
            w.push(256, bits);
            w.push(1, bits);
            bits += 1;
        }
        w.push(code as u32, bits);
        prev = Some(code);
        i += len;
    }
    w.finish()
}

/// Compressible data with enough variety to fill the dictionary many times.
fn wordy(n: usize) -> Vec<u8> {
    let noise = xorshift_bytes(n, 0x0bad_5eed_1234_5678);
    let mut out = Vec::with_capacity(n + 64);
    let mut k = 0usize;
    while out.len() < n {
        let r = noise[k % noise.len()] as usize;
        k += 1;
        match r % 5 {
            0 => out.extend_from_slice(b"the quick brown fox "),
            1 => out.extend_from_slice(b"jumps over "),
            2 => out.extend_from_slice(&noise[k % (n - 8)..][..(r % 7) + 1]),
            3 => out.extend_from_slice(b"ABCABCABCABC"),
            _ => out.extend_from_slice(b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        }
    }
    out.truncate(n);
    out
}

/// The decode loop from the `compcol::Decoder` docs: feed until the input
/// is taken, then `finish` until `StreamEnd`. No extra `decode(&[])` calls.
fn decode_documented(dec: &mut Decoder, input: &[u8], out_chunk: usize) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    let mut buf = vec![0u8; out_chunk];
    let mut consumed = 0;
    loop {
        let (p, status) = dec.decode(&input[consumed..], &mut buf)?;
        out.extend_from_slice(&buf[..p.written]);
        consumed += p.consumed;
        match status {
            Status::OutputFull => continue,
            Status::InputEmpty | Status::StreamEnd => break,
        }
    }
    loop {
        let (p, status) = dec.finish(&mut buf)?;
        out.extend_from_slice(&buf[..p.written]);
        if status == Status::StreamEnd {
            break;
        }
        assert!(p.written > 0, "finish stalled");
    }
    Ok(out)
}

#[test]
fn large_literal_stream_framed_one_shot() {
    let data = xorshift_bytes(200_000, 0x1234_5678_9abc_def0);
    let f = framed(&shrink_literals(&data), data.len() as u32);
    let r = compcol::vec::decompress_to_vec_capped::<ZipShrink>(&f, 1 << 30);
    assert!(
        r.as_deref() == Ok(&data[..]),
        "got {:?}",
        r.map(|v| v.len())
    );
}

#[test]
fn large_stream_documented_loop_framed_and_raw() {
    let lit = xorshift_bytes(200_000, 0x1234_5678_9abc_def0);
    let words = wordy(300_000);
    let cases = [(shrink_literals(&lit), lit), (shrink_lzw(&words), words)];
    for (payload, data) in &cases {
        let f = framed(payload, data.len() as u32);
        // Output buffers smaller than, equal to and larger than the
        // decoder's internal burst, and larger than the whole output.
        for out_chunk in [1000, 16 * 1024, 64 * 1024, 1 << 20] {
            let got = decode_documented(&mut Decoder::new(), &f, out_chunk);
            assert!(
                got.as_ref() == Ok(data),
                "framed, out_chunk={out_chunk}: {:?}",
                got.map(|v| v.len())
            );
            let mut raw = Decoder::raw(data.len() as u64);
            let got = decode_documented(&mut raw, payload, out_chunk);
            assert!(
                got.as_ref() == Ok(data),
                "raw, out_chunk={out_chunk}: {:?}",
                got.map(|v| v.len())
            );
        }
    }
}

#[test]
fn large_stream_all_input_in_decode_then_finish_drains() {
    // One `decode` with a small output buffer, then only `finish`: finish
    // has to keep decoding the buffered input, not just drain one burst.
    let data = wordy(300_000);
    let payload = shrink_lzw(&data);
    assert!(
        payload.len() < data.len() / 2,
        "test encoder should compress"
    );
    let mut dec = Decoder::raw(data.len() as u64);
    let mut buf = vec![0u8; 4096];
    let (p, status) = dec.decode(&payload, &mut buf).unwrap();
    assert_eq!(p.consumed, payload.len());
    assert_eq!(status, Status::OutputFull);
    let mut out = buf[..p.written].to_vec();
    loop {
        let (p, status) = dec.finish(&mut buf).unwrap();
        out.extend_from_slice(&buf[..p.written]);
        if status == Status::StreamEnd {
            break;
        }
        assert!(p.written > 0, "finish stalled");
    }
    assert!(out == data);
}

#[test]
fn large_stream_chunked_input_matches() {
    let data = wordy(250_000);
    let payload = shrink_lzw(&data);
    let f = framed(&payload, data.len() as u32);
    for (ic, oc) in [(1, 100_000), (7, 3), (4096, 4096), (100_000, 1 << 20)] {
        let got = decode_chunked(&f, ic, oc).unwrap();
        assert!(got == data, "in_chunk={ic} out_chunk={oc}");
    }
}

#[test]
fn large_stream_truncated_still_errors() {
    let data = wordy(250_000);
    let payload = shrink_lzw(&data);
    for cut in [payload.len() - 1, payload.len() / 2, 20_000] {
        let mut dec = Decoder::raw(data.len() as u64);
        let r = decode_documented(&mut dec, &payload[..cut], 64 * 1024);
        assert_eq!(r.err(), Some(Error::UnexpectedEnd), "cut={cut}");
    }
}

// ─── factory lookup ────────────────────────────────────────────────────

#[cfg(feature = "factory")]
mod factory {
    use compcol::factory;

    #[test]
    fn lookup_known() {
        assert!(factory::encoder_by_name("zip-shrink").is_some());
        assert!(factory::decoder_by_name("zip-shrink").is_some());
    }

    #[test]
    fn names_contains_zip_shrink() {
        assert!(factory::names().contains(&"zip-shrink"));
    }

    #[test]
    fn extension_is_shrunk() {
        assert_eq!(factory::extension("zip-shrink"), Some("shrunk"));
    }
}

// ─── declared length reached with codes still buffered ──────────────────

/// Decode with `in_chunk` input bytes per `decode` call and an
/// `out_chunk`-byte output buffer, then `finish` until it ends; returns the
/// verdict together with every byte handed out.
fn decode_outcome(
    dec: &mut Decoder,
    stream: &[u8],
    in_chunk: usize,
    out_chunk: usize,
) -> (Result<(), Error>, Vec<u8>) {
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

// Found by the `chunked_vs_oneshot` fuzz target. The stream declares one
// byte, and its first code is that byte; the bytes after it do not form
// valid codes. The decoder ends once the declared length has been
// produced, so those bytes are never codes at all — but it used to go on
// decoding whatever input happened to be buffered already, and so rejected
// the stream as `Corrupt` when given all of it at once while accepting it
// one byte at a time.
#[test]
fn codes_after_declared_length_are_not_decoded() {
    let stream: [u8; 8] = [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd3, 0x07];
    let expected = (Ok(()), vec![0u8]);
    for in_chunk in [1usize, 2, 3, 4, 5, 6, 7, 8, 9, usize::MAX] {
        for out_chunk in [1usize, 2, 7, 64, 1 << 16] {
            let got = decode_outcome(&mut Decoder::new(), &stream, in_chunk, out_chunk);
            assert_eq!(
                got, expected,
                "framed in_chunk {in_chunk}, out_chunk {out_chunk}"
            );
            let got = decode_outcome(&mut Decoder::raw(1), &stream[4..], in_chunk, out_chunk);
            assert_eq!(
                got, expected,
                "raw in_chunk {in_chunk}, out_chunk {out_chunk}"
            );
        }
    }
}

// Same property on a real stream: garbage after the last code needed for
// the declared length never changes the result, including when the
// declared length ends in the middle of a code's string.
#[test]
fn trailing_garbage_agrees_for_every_chunking() {
    let data = wordy(6000);
    let mut payload = shrink_lzw(&data);
    payload.extend_from_slice(&[0xff; 64]);
    for len in [1usize, 2, 1000, 5999, 6000] {
        let expected = (Ok(()), data[..len].to_vec());
        for in_chunk in [1usize, 3, 4, 61, 4096, usize::MAX] {
            for out_chunk in [1usize, 255, 1 << 16] {
                let got =
                    decode_outcome(&mut Decoder::raw(len as u64), &payload, in_chunk, out_chunk);
                let at = format!("len {len}, in_chunk {in_chunk}, out_chunk {out_chunk}");
                assert_eq!((&got.0, got.1.len()), (&expected.0, len), "{at}");
                assert!(got.1 == expected.1, "{at}: delivered bytes differ");
            }
        }
    }
}
