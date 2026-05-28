//! Integration tests for the LZMA decoder.
//!
//! The encoder is intentionally unimplemented in this build — the tests
//! exercise the decoder against pre-generated `.lzma` fixtures produced by
//! Python's stdlib `lzma` module (which uses XZ Utils internally) via
//! `lzma.compress(payload, format=lzma.FORMAT_ALONE)`.

#![cfg(feature = "lzma")]

use compcol::lzma::{Decoder, Encoder};
use compcol::{Decoder as _, Encoder as _, Error};

fn hex(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn decode_one_shot(compressed: &[u8]) -> Result<Vec<u8>, Error> {
    decode_chunked(compressed, compressed.len().max(1), 65536)
}

fn decode_chunked(compressed: &[u8], in_chunk: usize, out_chunk: usize) -> Result<Vec<u8>, Error> {
    let mut dec = Decoder::new();
    let mut out = Vec::new();
    let mut buf = vec![0u8; out_chunk.max(1)];
    let mut i = 0;
    while i < compressed.len() {
        let end = (i + in_chunk).min(compressed.len());
        let chunk = &compressed[i..end];
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

// ─── decoder fixtures (FORMAT_ALONE, "alone" / .lzma legacy) ─────────────

/// `python3 -c "import lzma; print(lzma.compress(b'', format=lzma.FORMAT_ALONE).hex())"`
const FIX_EMPTY: &str = "5d00008000ffffffffffffffff0083fffbffffc0000000";

/// `lzma.compress(b'hello world', format=lzma.FORMAT_ALONE)`
const FIX_HELLO: &str = "5d00008000ffffffffffffffff00341949ee8de917893a336005f7cf64fffb782000";

/// `lzma.compress(b'A' * 4096, format=lzma.FORMAT_ALONE)`
const FIX_REP4K: &str =
    "5d00008000ffffffffffffffff0020effbbffea3b15ee5f83fb2aa2655f868704170150ee40930ffffb52c0000";

#[test]
fn decode_empty() {
    let out = decode_one_shot(&hex(FIX_EMPTY)).unwrap();
    assert!(
        out.is_empty(),
        "empty fixture decoded to {} bytes",
        out.len()
    );
}

#[test]
fn decode_hello_world() {
    let out = decode_one_shot(&hex(FIX_HELLO)).unwrap();
    assert_eq!(out, b"hello world");
}

#[test]
fn decode_hello_world_chunked() {
    let stream = hex(FIX_HELLO);
    for in_chunk in [1, 2, 3, 5, 8, 16] {
        let out = decode_chunked(&stream, in_chunk, 7).unwrap();
        assert_eq!(out, b"hello world", "in_chunk={in_chunk}");
    }
}

#[test]
fn decode_4kib_repeating_bytes() {
    let out = decode_one_shot(&hex(FIX_REP4K)).unwrap();
    assert_eq!(out.len(), 4096);
    assert!(out.iter().all(|&b| b == b'A'));
}

#[test]
fn decode_4kib_chunked_tiny_output() {
    let stream = hex(FIX_REP4K);
    let out = decode_chunked(&stream, 7, 13).unwrap();
    assert_eq!(out.len(), 4096);
    assert!(out.iter().all(|&b| b == b'A'));
}

#[test]
fn decode_lorem_16kib() {
    // 16 KiB of repeating Lorem ipsum (well past one dictionary refresh).
    // Generated with:
    //   data = ('Lorem ipsum dolor sit amet, consectetur adipiscing elit, '
    //           'sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. ' * 200)[:16384]
    //   lzma.compress(data.encode('ascii'), format=lzma.FORMAT_ALONE)
    let fix = concat!(
        "5d00008000ffffffffffffffff00261bca46675af277b87d86d841db0535cd",
        "83a57c12a505db90bd2f14d3717296a88a7d8456718d6a2298ab9e3dc355ef",
        "cca5c3dd5b8ebf03812140d6269102454f92a178bb8a00af902a26920223e5",
        "5cb32de3e85c2cfb3221c66f6a37b16620cdb7527d66a42108d1441495affc",
        "58cfe5db354c05b89327ad7fe5fcbd0afbe2eda9e4d660d61c60112bf411e2",
        "9134c192bd8d4ac7c3c84aef9b3dda35640dd2db8ac9fd8cacc0",
    );
    let out = decode_one_shot(&hex(fix)).unwrap();
    let lorem_chunk = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. ";
    let expected: Vec<u8> = lorem_chunk
        .repeat(200)
        .into_bytes()
        .into_iter()
        .take(16384)
        .collect();
    assert_eq!(out.len(), 16384);
    assert_eq!(out, expected);
}

#[test]
fn decode_64kib_pattern_exercises_high_distance_slots() {
    // 64 KiB of a 64-byte repeating pattern. The 64 KiB output forces the
    // encoder to emit at least some matches with distance > 4 KiB, which
    // means dist_slot >= 14 — the "direct bits + align bittree" code path.
    let fix = concat!(
        "5d00008000ffffffffffffffff0020908476ba8a75cfb40db2e89f1387f82434",
        "06665269475cb0abef7542320240670c71179b6077f0d35f7ba7b4353d652aaf",
        "794911d88e6fdb4f561ee45f7411acad969598429b5f0b9dc161fa118e806330",
        "f7486ed3aeae90b6d8cffffee7b000",
    );
    let stream = hex(fix);
    let out = decode_one_shot(&stream).unwrap();
    assert_eq!(out.len(), 65536);
    let pattern = b"ABCDEFGHIJKLMNOPABCDEFGHIJKLMNOPABCDEFGHIJKLMNOPABCDEFGHIJKLMNOP";
    for (i, chunk) in out.chunks(64).enumerate() {
        assert_eq!(chunk, pattern, "mismatch in chunk {i}");
    }
}

#[test]
fn decode_lorem_16kib_byte_streamed() {
    // Hand the decoder one input byte at a time and one output byte at a
    // time. This stresses both the input-starvation rollback and the
    // mid-match-copy pending state.
    let fix = concat!(
        "5d00008000ffffffffffffffff00261bca46675af277b87d86d841db0535cd",
        "83a57c12a505db90bd2f14d3717296a88a7d8456718d6a2298ab9e3dc355ef",
        "cca5c3dd5b8ebf03812140d6269102454f92a178bb8a00af902a26920223e5",
        "5cb32de3e85c2cfb3221c66f6a37b16620cdb7527d66a42108d1441495affc",
        "58cfe5db354c05b89327ad7fe5fcbd0afbe2eda9e4d660d61c60112bf411e2",
        "9134c192bd8d4ac7c3c84aef9b3dda35640dd2db8ac9fd8cacc0",
    );
    let stream = hex(fix);
    let out = decode_chunked(&stream, 1, 1).unwrap();
    assert_eq!(out.len(), 16384);
    let lorem_chunk = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. ";
    let expected: Vec<u8> = lorem_chunk
        .repeat(200)
        .into_bytes()
        .into_iter()
        .take(16384)
        .collect();
    assert_eq!(out, expected);
}

#[test]
fn decode_known_uncompressed_size_header() {
    // Same payload as FIX_HELLO but with the uncompressed-size field set
    // to 11 instead of u64::MAX. The decoder should stop after producing
    // exactly 11 bytes; the still-present EOS marker is harmless because
    // size is checked first.
    let mut stream = hex(FIX_HELLO);
    // Bytes 5..13 are uncompressed-size LE.
    stream[5..13].copy_from_slice(&11u64.to_le_bytes());
    let out = decode_one_shot(&stream).unwrap();
    assert_eq!(out, b"hello world");
}

#[test]
fn bad_header_props_rejected() {
    // properties byte 0xFF (>= 9*5*5 = 225) is illegal.
    let mut stream = hex(FIX_HELLO);
    stream[0] = 0xFF;
    let mut dec = Decoder::new();
    let mut buf = [0u8; 64];
    let err = dec.decode(&stream, &mut buf).unwrap_err();
    assert_eq!(err, Error::BadHeader);
}

#[test]
fn corrupt_first_init_byte_rejected() {
    // The first byte of the range-coder payload (offset 13) must be 0x00.
    let mut stream = hex(FIX_HELLO);
    stream[13] = 0x01;
    let mut dec = Decoder::new();
    let mut buf = [0u8; 64];
    let err = dec.decode(&stream, &mut buf).unwrap_err();
    assert_eq!(err, Error::Corrupt);
}

#[test]
fn unexpected_eof_on_finish() {
    let stream = hex(FIX_HELLO);
    let truncated = &stream[..stream.len() - 4]; // chop the EOS marker
    let mut dec = Decoder::new();
    let mut buf = vec![0u8; 64];
    let _ = dec.decode(truncated, &mut buf).unwrap();
    // finish should now realise we're stuck without input.
    let err = dec.finish(&mut buf).unwrap_err();
    assert_eq!(err, Error::UnexpectedEnd);
}

// ─── encoder is documented as unsupported ────────────────────────────────

#[test]
fn encoder_returns_unsupported() {
    let mut enc = Encoder::new();
    let mut out = [0u8; 16];
    let err = enc.encode(b"hi", &mut out).unwrap_err();
    assert_eq!(err, Error::Unsupported);
    let err = enc.finish(&mut out).unwrap_err();
    assert_eq!(err, Error::Unsupported);
}

#[test]
fn reset_allows_reuse() {
    let stream = hex(FIX_HELLO);
    let mut dec = Decoder::new();
    let mut buf = vec![0u8; 64];

    let mut consumed = 0;
    let mut written = 0;
    let p = dec.decode(&stream[..6], &mut buf).unwrap();
    consumed += p.consumed;
    written += p.written;
    assert!(written < 11);

    dec.reset();

    // Now decode the full stream fresh.
    let out = decode_one_shot(&stream).unwrap();
    assert_eq!(out, b"hello world");
    let _ = consumed;
}
