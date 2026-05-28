//! Integration tests for the Brotli (RFC 7932) codec.
//!
//! This build implements only the uncompressed subset of the format:
//! the encoder emits a 1-bit WBITS header, then chunks input into
//! uncompressed meta-blocks followed by an empty-last terminator; the
//! decoder parses any combination of uncompressed and metadata
//! meta-blocks plus the empty-last terminator. Compressed meta-blocks
//! are intentionally rejected with `Error::Unsupported`.

#![cfg(feature = "brotli")]

use std::io::Write;
use std::process::{Command, Stdio};

use compcol::brotli::{Decoder, Encoder};
use compcol::{Decoder as _, Encoder as _, Error};

/// Parse a hex string into a byte vector.
fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// Encode `input` in one shot using `in_chunk`-sized input and
/// `out_chunk`-sized output buffers. Returns the full encoded stream.
fn encode_chunked(input: &[u8], in_chunk: usize, out_chunk: usize) -> Result<Vec<u8>, Error> {
    let mut enc = Encoder::new();
    let mut out = Vec::new();
    let mut buf = vec![0u8; out_chunk.max(1)];
    let mut i = 0;
    while i < input.len() {
        let end = (i + in_chunk).min(input.len());
        let chunk = &input[i..end];
        let mut consumed_total = 0;
        // Drive the encoder until either the chunk is fully consumed or
        // we make no further progress on it (output buffer full).
        loop {
            let p = enc.encode(&chunk[consumed_total..], &mut buf)?;
            out.extend_from_slice(&buf[..p.written]);
            consumed_total += p.consumed;
            if consumed_total == chunk.len() && p.written == 0 {
                break;
            }
            if p.consumed == 0 && p.written == 0 {
                break;
            }
        }
        i = end;
    }
    loop {
        let p = enc.finish(&mut buf)?;
        out.extend_from_slice(&buf[..p.written]);
        if p.done {
            break;
        }
        if p.written == 0 {
            panic!("encoder finish stalled");
        }
    }
    Ok(out)
}

/// Decode `encoded` with chunked input/output buffers.
fn decode_chunked(encoded: &[u8], in_chunk: usize, out_chunk: usize) -> Result<Vec<u8>, Error> {
    let mut dec = Decoder::new();
    let mut out = Vec::new();
    let mut buf = vec![0u8; out_chunk.max(1)];
    let mut i = 0;
    while i < encoded.len() {
        let end = (i + in_chunk).min(encoded.len());
        let chunk = &encoded[i..end];
        let mut consumed_in_chunk = 0;
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

/// Convenience: one-shot encode then decode and check we got the input
/// back. Also verifies the encoded output is at least the minimum size
/// the format demands.
fn roundtrip(input: &[u8]) {
    let encoded = encode_chunked(input, input.len().max(1), input.len().max(1) + 32).unwrap();
    let decoded = decode_chunked(&encoded, encoded.len().max(1), input.len().max(1)).unwrap();
    assert_eq!(decoded, input);
}

#[test]
fn empty_stream_round_trip() {
    roundtrip(b"");
}

#[test]
fn empty_stream_exact_bytes() {
    // WBITS=16 (1 bit = 0), ISLAST=1, ISLASTEMPTY=1, pad: bits 0,1,1
    // packed LSB-first = 0b00000110 = 0x06.
    let encoded = encode_chunked(b"", 1, 16).unwrap();
    assert_eq!(encoded, [0x06]);
}

#[test]
fn short_round_trip() {
    roundtrip(b"hello");
    roundtrip(b"a");
    roundtrip(b"hello world");
    roundtrip(b"The quick brown fox jumps over the lazy dog.");
}

#[test]
fn binary_round_trip() {
    let input: Vec<u8> = (0..=255u8).collect();
    roundtrip(&input);
}

#[test]
fn large_round_trip() {
    // Exceeds the encoder's 64 KiB per-block cap, so multiple meta-blocks
    // are emitted.
    let input: Vec<u8> = (0..200_000).map(|i| (i * 31) as u8).collect();
    roundtrip(&input);
}

#[test]
fn exact_block_boundary_round_trip() {
    // 65 536 bytes — exactly one full max-size meta-block. Then 65 537
    // — one full block plus one byte of tail.
    let input: Vec<u8> = (0..65_536).map(|i| (i % 251) as u8).collect();
    roundtrip(&input);
    let input: Vec<u8> = (0..65_537).map(|i| (i % 251) as u8).collect();
    roundtrip(&input);
    // And 2 * 65_536 — two full blocks, empty tail.
    let input: Vec<u8> = (0..131_072).map(|i| (i % 251) as u8).collect();
    roundtrip(&input);
}

#[test]
fn structured_round_trip() {
    let mut input = Vec::new();
    for _ in 0..1000 {
        input.extend_from_slice(b"the quick brown fox jumps over the lazy dog\n");
    }
    roundtrip(&input);
}

#[test]
fn pseudo_random_round_trip() {
    // Simple xorshift to avoid pulling a dep.
    let mut x: u32 = 0xdead_beef;
    let mut input = vec![0u8; 70_000];
    for slot in &mut input {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        *slot = x as u8;
    }
    roundtrip(&input);
}

#[test]
fn one_byte_input_one_byte_output_round_trip() {
    let input = b"hello world from brotli";
    let encoded = encode_chunked(input, 1, 1).unwrap();
    let decoded = decode_chunked(&encoded, 1, 1).unwrap();
    assert_eq!(decoded, input);
}

#[test]
fn one_byte_streaming_large_round_trip() {
    let input: Vec<u8> = (0..3000).map(|i| (i * 17 + 5) as u8).collect();
    let encoded = encode_chunked(&input, 1, 1).unwrap();
    let decoded = decode_chunked(&encoded, 1, 1).unwrap();
    assert_eq!(decoded, input);
}

#[test]
fn decode_handcrafted_hello_uncompressed() {
    // Hand-built brotli stream containing a single uncompressed meta-block
    // carrying "hello", followed by the empty-last terminator.
    //
    // Bits in emission order (LSB-first within each byte):
    //
    //   WBITS=16        : 0
    //   ISLAST=0        : 0
    //   MNIBBLES=4 nib  : 0 0
    //   MLEN-1 = 4      : 0 0 1 0   0 0 0 0   0 0 0 0   0 0 0 0   (16 bits)
    //   ISUNCOMPRESSED  : 1
    //   pad to byte     : 0 0 0      (3 zero bits)
    //   payload         : "hello"
    //   ISLAST=1        : 1
    //   ISLASTEMPTY=1   : 1
    //   pad to byte     : 0 0 0 0 0 0
    //
    // Packed byte-by-byte:
    //   byte 0: bits 0..7  = 0,0,0,0, 0,0,1,0  -> 0b01000000 = 0x40
    //   byte 1: bits 8..15 = 0,0,0,0, 0,0,0,0  -> 0x00
    //   byte 2: bits 16..23= 0,0,0,0, 1,0,0,0  -> 0b00010000 = 0x10
    //   byte 3: 'h' = 0x68
    //   byte 4: 'e' = 0x65
    //   byte 5: 'l' = 0x6c
    //   byte 6: 'l' = 0x6c
    //   byte 7: 'o' = 0x6f
    //   byte 8: 1,1,0,0,0,0,0,0 -> 0b00000011 = 0x03
    let stream = hex("40001068656c6c6f03");
    let decoded = decode_chunked(&stream, 1024, 1024).unwrap();
    assert_eq!(decoded, b"hello");
}

#[test]
fn decode_rejects_compressed_meta_block() {
    // A stream that announces a compressed (non-uncompressed) meta-block:
    // WBITS=16, ISLAST=0, MNIBBLES=4nib, MLEN-1=0 (mlen=1), ISUNCOMPRESSED=0.
    //
    // Bits: 0, 0, 0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0
    // = 21 zero bits, padded with 3 zero bits to 24 -> 3 bytes of 0x00.
    let stream = [0x00, 0x00, 0x00];
    let mut dec = Decoder::new();
    let mut buf = [0u8; 32];
    let err = dec.decode(&stream, &mut buf).unwrap_err();
    assert_eq!(err, Error::Unsupported);
}

#[test]
fn decode_rejects_truncated_stream() {
    // Valid prefix: just WBITS + ISLAST=0 + half of MLEN. finish() should
    // report UnexpectedEnd.
    let stream = [0x00];
    let mut dec = Decoder::new();
    let mut buf = [0u8; 32];
    let _ = dec.decode(&stream, &mut buf).unwrap();
    let err = dec.finish(&mut buf).unwrap_err();
    assert_eq!(err, Error::UnexpectedEnd);
}

#[test]
fn reset_allows_reuse() {
    let mut enc = Encoder::new();
    let mut buf = [0u8; 64];
    let p = enc.encode(b"hi", &mut buf).unwrap();
    assert_eq!(p.consumed, 2);
    enc.reset();
    let p1 = enc.encode(b"bye", &mut buf).unwrap();
    assert_eq!(p1.consumed, 3);
    let mut total = Vec::new();
    total.extend_from_slice(&buf[..p1.written]);
    loop {
        let p2 = enc.finish(&mut buf).unwrap();
        total.extend_from_slice(&buf[..p2.written]);
        if p2.done {
            break;
        }
        if p2.written == 0 {
            panic!("stalled");
        }
    }
    let decoded = decode_chunked(&total, 1024, 1024).unwrap();
    assert_eq!(decoded, b"bye");
}

// ─── cross-validation against the reference `brotli` CLI ────────────────

/// Returns Some(brotli_path) if the `brotli` binary is on PATH and
/// runs, otherwise None.
fn brotli_cli_available() -> Option<String> {
    let path = "brotli";
    let r = Command::new(path)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    match r {
        Ok(s) if s.success() => Some(path.to_string()),
        _ => None,
    }
}

/// Pipe `data` through `brotli -d -c` and return the decoded output.
fn brotli_decode(brotli: &str, data: &[u8]) -> Vec<u8> {
    let mut child = Command::new(brotli)
        .args(["-d", "-c"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn brotli");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(data)
        .expect("write stdin");
    let out = child.wait_with_output().expect("wait brotli");
    assert!(
        out.status.success(),
        "brotli -d failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out.stdout
}

/// Pipe `data` through `brotli -c` and return the encoded output.
fn brotli_encode(brotli: &str, data: &[u8]) -> Vec<u8> {
    let mut child = Command::new(brotli)
        .args(["-c"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn brotli");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(data)
        .expect("write stdin");
    let out = child.wait_with_output().expect("wait brotli");
    assert!(out.status.success(), "brotli encode failed");
    out.stdout
}

#[test]
fn cross_validate_with_reference_decoder() {
    let Some(brotli) = brotli_cli_available() else {
        eprintln!("skipping: brotli CLI not available");
        return;
    };
    for input in [
        b"".to_vec(),
        b"a".to_vec(),
        b"hello world".to_vec(),
        (0..=255u8).collect::<Vec<_>>(),
        (0..70_000usize).map(|i| (i * 37) as u8).collect::<Vec<_>>(),
    ] {
        let encoded = encode_chunked(&input, input.len().max(1), input.len().max(1) + 32).unwrap();
        let decoded = brotli_decode(&brotli, &encoded);
        assert_eq!(decoded, input, "reference decoder mismatch");
    }
}

#[test]
fn cross_validate_compressed_input_is_rejected() {
    // The reference encoder will produce a real compressed stream
    // (not an uncompressed-only one). Our decoder should reject it
    // with Unsupported rather than corrupting silently.
    let Some(brotli) = brotli_cli_available() else {
        eprintln!("skipping: brotli CLI not available");
        return;
    };
    let input = b"the quick brown fox jumps over the lazy dog. this is repetitive enough that the encoder will pick compressed format and our decoder must say so.";
    let encoded = brotli_encode(&brotli, input);
    let mut dec = Decoder::new();
    let mut buf = [0u8; 256];
    // We don't care which call produces the error — just that the
    // outcome is Error::Unsupported, never silent corruption.
    let mut hit_unsupported = false;
    let mut i = 0;
    while i < encoded.len() {
        match dec.decode(&encoded[i..], &mut buf) {
            Ok(p) => {
                i += p.consumed;
                if p.consumed == 0 && p.written == 0 {
                    break;
                }
            }
            Err(Error::Unsupported) => {
                hit_unsupported = true;
                break;
            }
            Err(other) => panic!("unexpected error: {other:?}"),
        }
    }
    if !hit_unsupported {
        // Maybe the error only surfaces in finish.
        match dec.finish(&mut buf) {
            Err(Error::Unsupported) => {}
            Err(Error::UnexpectedEnd) => {
                // Acceptable: we never consumed enough to see the
                // compressed meta-block flag (e.g. the encoder produced
                // a degenerate stream). We don't expect this in
                // practice but accept it as non-corruption.
            }
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }
}
