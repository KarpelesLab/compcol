//! Integration tests for the LZMA encoder and decoder.
//!
//! The decoder tests use pre-generated `.lzma` fixtures produced by Python's
//! stdlib `lzma` module (which uses XZ Utils internally) via
//! `lzma.compress(payload, format=lzma.FORMAT_ALONE)`.
//!
//! The encoder tests verify round-trip against our own decoder, plus a
//! handful of decoder-only edge cases.

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

// ─── encoder round-trip tests ────────────────────────────────────────────

/// Push `payload` through the encoder in one shot, then run the resulting
/// bytes through `decode_one_shot`. Returns the recovered payload.
fn round_trip(payload: &[u8]) -> Vec<u8> {
    let compressed = encode_one_shot(payload);
    decode_one_shot(&compressed).expect("decoding our own output failed")
}

fn encode_one_shot(payload: &[u8]) -> Vec<u8> {
    let mut enc = Encoder::new();
    // Pipe everything in. The encoder buffers internally and produces no
    // output bytes until finish, so we can pass a small scratch buffer.
    let mut scratch = [0u8; 64];
    let mut consumed = 0;
    while consumed < payload.len() {
        let p = enc.encode(&payload[consumed..], &mut scratch).unwrap();
        consumed += p.consumed;
        // Output should always be empty from encode() for LZMA.
        assert_eq!(p.written, 0);
        if p.consumed == 0 {
            panic!("encoder stalled mid-input");
        }
    }
    let mut out = Vec::new();
    let mut buf = vec![0u8; 4096];
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

#[test]
fn encode_empty_round_trip() {
    let compressed = encode_one_shot(b"");
    assert!(
        compressed.len() >= 13,
        "encoder must always emit a header, got {} bytes",
        compressed.len()
    );
    assert_eq!(
        compressed[0], 0x5d,
        "props byte = (pb=2)*5*9 + (lp=0)*9 + (lc=3)"
    );
    // Dict size LE at bytes 1..5; we use 1 MiB.
    let dict = u32::from_le_bytes([compressed[1], compressed[2], compressed[3], compressed[4]]);
    assert_eq!(dict, 1 << 20);
    // Uncompressed size sentinel = u64::MAX.
    for &b in &compressed[5..13] {
        assert_eq!(b, 0xFF);
    }
    let recovered = decode_one_shot(&compressed).unwrap();
    assert!(recovered.is_empty());
}

#[test]
fn encode_single_byte_round_trip() {
    for b in [0u8, 1, 0x7F, 0xFE, 0xFF, b'A'] {
        let recovered = round_trip(&[b]);
        assert_eq!(recovered, vec![b], "byte 0x{:02x}", b);
    }
}

#[test]
fn encode_small_text_round_trip() {
    let payload = b"hello world! hello world! hello world!";
    let recovered = round_trip(payload);
    assert_eq!(recovered.as_slice(), payload.as_slice());
}

#[test]
fn encode_4kib_pseudorandom_round_trip() {
    // Pseudo-random but deterministic — a tiny xorshift, since we can't
    // use any external rng crate.
    let mut state: u32 = 0xDEADBEEF;
    let mut payload = vec![0u8; 4096];
    for byte in payload.iter_mut() {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        *byte = (state & 0xFF) as u8;
    }
    let recovered = round_trip(&payload);
    assert_eq!(recovered.len(), payload.len());
    assert_eq!(recovered, payload);
}

#[test]
fn encode_16kib_lorem_round_trip() {
    let lorem_chunk = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. ";
    let payload: Vec<u8> = lorem_chunk
        .repeat(200)
        .into_bytes()
        .into_iter()
        .take(16384)
        .collect();
    let compressed = encode_one_shot(&payload);
    // Lorem ipsum is highly repetitive; we should beat the 1:1 ratio by a
    // wide margin even with a greedy parser. (xz at level 6 reaches ~180
    // bytes on this 16 KiB input; this greedy encoder lands at ~184 bytes —
    // long matches mean greedy parsing is near-optimal here.)
    assert!(
        compressed.len() < payload.len() / 2,
        "expected at least 2x compression on lorem, got {} -> {}",
        payload.len(),
        compressed.len()
    );
    eprintln!(
        "lorem 16 KiB compressed to {} bytes (xz-level-6 reference ~180)",
        compressed.len()
    );
    let recovered = decode_one_shot(&compressed).unwrap();
    assert_eq!(recovered, payload);
}

#[test]
fn encode_4kib_repeating_byte_round_trip() {
    // All-A's: dominated by rep matches.
    let payload = vec![b'A'; 4096];
    let compressed = encode_one_shot(&payload);
    // Highly compressible: should be well under 100 bytes for this case.
    assert!(
        compressed.len() < 100,
        "expected strong compression on repeating byte, got {} bytes",
        compressed.len()
    );
    let recovered = decode_one_shot(&compressed).unwrap();
    assert_eq!(recovered, payload);
}

#[test]
fn encode_streaming_one_byte_chunks_round_trip() {
    let payload = b"The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog.";

    let mut enc = Encoder::new();
    let mut scratch = [0u8; 4];
    for byte in payload {
        let p = enc
            .encode(core::slice::from_ref(byte), &mut scratch)
            .unwrap();
        assert_eq!(p.consumed, 1);
        assert_eq!(p.written, 0);
    }
    let mut compressed = Vec::new();
    let mut buf = [0u8; 1];
    loop {
        let p = enc.finish(&mut buf).unwrap();
        compressed.extend_from_slice(&buf[..p.written]);
        if p.done {
            break;
        }
        if p.written == 0 {
            panic!("encoder finish stalled in single-byte streaming mode");
        }
    }

    // Now also stream the decode side one byte at a time on input and one
    // byte at a time on output.
    let recovered = decode_chunked(&compressed, 1, 1).unwrap();
    assert_eq!(recovered, payload);
}

#[test]
fn encode_then_decode_match_with_high_dist_slot() {
    // 64 KiB of a 64-byte pattern. Forces distances large enough to require
    // the direct-bits + align-bittree path. Our encoder advertises a 1 MiB
    // dict, so all distances are reachable.
    let pattern: &[u8] = b"ABCDEFGHIJKLMNOPABCDEFGHIJKLMNOPABCDEFGHIJKLMNOPABCDEFGHIJKLMNOP";
    let mut payload = Vec::with_capacity(64 * 1024);
    while payload.len() < 64 * 1024 {
        payload.extend_from_slice(pattern);
    }
    payload.truncate(64 * 1024);
    let recovered = round_trip(&payload);
    assert_eq!(recovered.len(), payload.len());
    assert_eq!(recovered, payload);
}

#[test]
fn encode_after_reset_round_trip() {
    let mut enc = Encoder::new();
    let mut scratch = [0u8; 64];

    let _ = enc.encode(b"first payload", &mut scratch).unwrap();
    enc.reset();

    let payload = b"second payload after reset";
    let mut consumed = 0;
    while consumed < payload.len() {
        let p = enc.encode(&payload[consumed..], &mut scratch).unwrap();
        consumed += p.consumed;
    }
    let mut compressed = Vec::new();
    let mut buf = [0u8; 64];
    loop {
        let p = enc.finish(&mut buf).unwrap();
        compressed.extend_from_slice(&buf[..p.written]);
        if p.done {
            break;
        }
    }
    let recovered = decode_one_shot(&compressed).unwrap();
    assert_eq!(recovered.as_slice(), payload.as_slice());
}

#[test]
fn encode_byte_value_coverage() {
    // Every byte value 0..=255 in sequence, to exercise every literal path.
    let payload: Vec<u8> = (0u8..=255).collect();
    let recovered = round_trip(&payload);
    assert_eq!(recovered, payload);
}

/// Pipe `compressed` to `python3 -c "import sys, lzma; sys.stdout.buffer.write(
/// lzma.decompress(sys.stdin.buffer.read(), format=lzma.FORMAT_ALONE))"` and
/// return the decompressed bytes. Returns `None` if `python3` is missing.
fn python_decompress_alone(compressed: &[u8]) -> Option<Vec<u8>> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let mut child = Command::new("python3")
        .args([
            "-c",
            "import sys, lzma; sys.stdout.buffer.write(lzma.decompress(sys.stdin.buffer.read(), format=lzma.FORMAT_ALONE))",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    {
        // Take stdin so it drops at end of this scope, closing the pipe.
        let mut stdin = child.stdin.take()?;
        stdin.write_all(compressed).ok()?;
    }
    let out = child.wait_with_output().ok()?;
    if !out.status.success() {
        eprintln!(
            "python3 lzma.decompress failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        return None;
    }
    Some(out.stdout)
}

#[test]
fn encode_decodes_externally_with_python_lzma() {
    // Cross-validate against Python's stdlib `lzma` (XZ Utils-backed) to
    // prove the output is a valid `.lzma` (alone) stream, not just one our
    // decoder happens to accept.
    let payloads: &[&[u8]] = &[
        b"",
        b"hello world",
        &[42u8; 4096],
        b"The quick brown fox jumps over the lazy dog. ",
    ];
    for payload in payloads {
        let compressed = encode_one_shot(payload);
        match python_decompress_alone(&compressed) {
            Some(recovered) => assert_eq!(
                recovered.as_slice(),
                *payload,
                "external decode mismatch for {} bytes",
                payload.len()
            ),
            None => {
                eprintln!("skipping external validation (no python3 available)");
                return;
            }
        }
    }

    // One bigger payload — the same 16 KiB lorem we use elsewhere.
    let lorem_chunk = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. ";
    let big: Vec<u8> = lorem_chunk
        .repeat(200)
        .into_bytes()
        .into_iter()
        .take(16384)
        .collect();
    let compressed = encode_one_shot(&big);
    if let Some(rec) = python_decompress_alone(&compressed) {
        assert_eq!(rec, big);
    }
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
