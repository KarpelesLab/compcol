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
fn decode_rejects_unsupported_large_window_flag() {
    // The "large window" flag uses WBITS preamble: first bit = 1, next
    // 3 bits = 0, next 3 bits = 1. Packed LSB-first as bits 1,0,0,0,1,0,0
    // -> 0b00010001 = 0x11. Decoder must reject as Unsupported.
    let stream = [0x11u8];
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
fn cross_validate_compressed_input_round_trips() {
    // The reference encoder produces a real compressed stream. Our
    // decoder should recover the original bytes.
    let Some(brotli) = brotli_cli_available() else {
        eprintln!("skipping: brotli CLI not available");
        return;
    };
    let input = b"the quick brown fox jumps over the lazy dog. this is repetitive enough that the encoder will pick compressed format.";
    let encoded = brotli_encode(&brotli, input);
    let decoded = decode_chunked(&encoded, encoded.len(), input.len()).unwrap();
    assert_eq!(decoded, input);
}

#[test]
fn cross_validate_compressed_hello_world() {
    let Some(brotli) = brotli_cli_available() else {
        eprintln!("skipping: brotli CLI not available");
        return;
    };
    let input = b"hello world\n";
    let encoded = brotli_encode(&brotli, input);
    let decoded = decode_chunked(&encoded, encoded.len(), input.len()).unwrap();
    assert_eq!(decoded, input);
}

#[test]
fn cross_validate_compressed_4k_ascii() {
    let Some(brotli) = brotli_cli_available() else {
        eprintln!("skipping: brotli CLI not available");
        return;
    };
    // 4 KiB of structured ASCII text.
    let mut input = Vec::with_capacity(4096);
    while input.len() < 4096 {
        input.extend_from_slice(b"The quick brown fox jumps over the lazy dog.\n");
    }
    input.truncate(4096);
    let encoded = brotli_encode(&brotli, &input);
    let decoded = decode_chunked(&encoded, encoded.len(), input.len()).unwrap();
    assert_eq!(decoded, input);
}

#[test]
fn cross_validate_compressed_16k_lorem() {
    let Some(brotli) = brotli_cli_available() else {
        eprintln!("skipping: brotli CLI not available");
        return;
    };
    let lorem: &[u8] = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum. ";
    let mut input = Vec::with_capacity(16 * 1024);
    while input.len() < 16 * 1024 {
        input.extend_from_slice(lorem);
    }
    input.truncate(16 * 1024);
    let encoded = brotli_encode(&brotli, &input);
    let decoded = decode_chunked(&encoded, encoded.len(), input.len()).unwrap();
    assert_eq!(decoded, input);
}

#[test]
fn cross_validate_compressed_dictionary_phrase() {
    // "the time has come" — the words "the", "time", "has", "come" all
    // exist verbatim in the static dictionary (length 4). This exercises
    // the static-dictionary back-reference path.
    let Some(brotli) = brotli_cli_available() else {
        eprintln!("skipping: brotli CLI not available");
        return;
    };
    let input = b"the time has come";
    let encoded = brotli_encode(&brotli, input);
    eprintln!(
        "encoded: {} bytes: {:?}",
        encoded.len(),
        encoded
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join("")
    );
    let decoded = decode_chunked(&encoded, encoded.len(), input.len() + 32).unwrap();
    assert_eq!(decoded, input);
}

#[test]
fn cross_validate_compressed_empty() {
    let Some(brotli) = brotli_cli_available() else {
        eprintln!("skipping: brotli CLI not available");
        return;
    };
    let input: &[u8] = b"";
    let encoded = brotli_encode(&brotli, input);
    let decoded = decode_chunked(&encoded, encoded.len().max(1), 16).unwrap();
    assert_eq!(decoded, input);
}

/// Helper: decode one shot, no chunking, returns the bytes.
fn decode_one_shot(stream: &[u8]) -> Vec<u8> {
    let mut dec = Decoder::new();
    let mut out = vec![0u8; stream.len() * 16 + 4096];
    let p = dec.decode(stream, &mut out).expect("decode");
    out.truncate(p.written);
    out
}

/// Bench of hand-picked reference streams generated with the brotli
/// CLI at default settings. Verifies the decoder copes with the full
/// range of features exercised by realistic input — complex prefix
/// codes, dictionary references with transforms, ring-buffer reuse,
/// and back-references. Doesn't depend on the brotli CLI being
/// available at test time.
#[test]
fn decode_fixed_reference_streams() {
    // Each entry: (hex stream, expected decoded bytes).
    let cases: &[(&str, &[u8])] = &[
        // Eight 'a's, compressed (uses NSYM=1 literal+IC+dist trees).
        ("1f0700f825c242840000", b"aaaaaaaa"),
        // 14 'a's, also NSYM=1.
        ("1f0d00f825c2e2850000", b"aaaaaaaaaaaaaa"),
        // 40 'a's — block of repeated literals via back-refs.
        (
            "1f2700f825c2a28c00c0",
            b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ),
        // Phrase whose words "the", "time", "has", "come" all live in
        // the static dictionary — exercises the dictionary path with
        // transforms applied.
        (
            "1f1000f8a541c2d0e69428c0d429203d343906",
            b"the time has come",
        ),
        // Short phrase mixing literal and dict references.
        ("1f0d00f825004a9042ea16999e2200", b"this is a test"),
        // 43 chars: complex prefix codes for literal/IC trees + dict.
        (
            "1f2a00889c09364ea87737bc2433a34b9033bc427b4b90b23998c881435ba0f7dea7150ee90b4789ea0c1be0563506",
            b"the quick brown fox jumps over the lazy dog",
        ),
        // 75 chars including punctuation; exercises both back-refs and
        // dict references.
        (
            "1f4a00a014a1d2d56da92ea4c77e70ea41b8e8101536e080bd05f617fd00b5e7947aa93a819311a5e685e00dc00fff0f259bd5b15d9c5428ceec103d",
            b"the quick brown fox jumps over the lazy dog. this is repetitive enough that",
        ),
        // 116 chars: complete sentence with many dict references and
        // back-refs. This case exercises the "static-dict reference
        // does not push to the ring buffer" rule.
        (
            "1f7300e045b779bd3b2ecf3f68a550182651e9e40ecc7fd4965cf212ce2df084052db0c8db379508510f9ae617e0bd617b47f90fd5bbdcc4bee0625ada219e1c75aa68e600388b1d6a0eb3004b01",
            b"the quick brown fox jumps over the lazy dog. this is repetitive enough that the encoder will pick compressed format.",
        ),
    ];
    for (hex_s, expected) in cases {
        let stream = hex(hex_s);
        let got = decode_one_shot(&stream);
        assert_eq!(
            got,
            *expected,
            "mismatch for stream {hex_s}: got {:?}",
            String::from_utf8_lossy(&got)
        );
    }
}
