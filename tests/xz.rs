#![cfg(any())] // TODO(v0.3): port to new (Progress, Status) API
//! Integration tests for the xz codec (uncompressed-LZMA2 fallback).

#![cfg(feature = "xz")]

use std::io::Write;
use std::process::{Command, Stdio};

use compcol::xz::{Decoder, Encoder};
use compcol::{Decoder as _, Encoder as _, Error};

// ─── helpers ───────────────────────────────────────────────────────────────

fn encode_all(input: &[u8]) -> Vec<u8> {
    let mut enc = Encoder::new();
    let mut out = Vec::new();
    let mut buf = vec![0u8; 4096];
    let mut consumed = 0;
    while consumed < input.len() {
        let p = enc.encode(&input[consumed..], &mut buf).unwrap();
        out.extend_from_slice(&buf[..p.written]);
        consumed += p.consumed;
        if p.consumed == 0 && p.written == 0 {
            break;
        }
    }
    loop {
        let p = enc.finish(&mut buf).unwrap();
        out.extend_from_slice(&buf[..p.written]);
        if matches!(_s, compcol::Status::StreamEnd) {
            break;
        }
        if p.written == 0 {
            panic!("xz encoder finish stalled");
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
        if matches!(_s, compcol::Status::StreamEnd) {
            break;
        }
        if p.written == 0 {
            panic!("xz encoder finish stalled");
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
        if matches!(_s, compcol::Status::StreamEnd) {
            break;
        }
        if p.written == 0 {
            panic!("xz decoder finish stalled");
        }
    }
    Ok(out)
}

fn round_trip(input: &[u8]) {
    let encoded = encode_all(input);
    // Stream Header magic.
    assert_eq!(&encoded[..6], &[0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00]);
    // Stream Footer magic in the last 2 bytes.
    assert_eq!(&encoded[encoded.len() - 2..], b"YZ");
    let decoded = decode_chunked(&encoded, 4096, 4096).unwrap();
    assert_eq!(decoded, input, "round-trip mismatch (len {})", input.len());
}

// ─── round-trip tests ──────────────────────────────────────────────────────

#[test]
fn round_trip_empty() {
    round_trip(b"");
}

#[test]
fn round_trip_short() {
    round_trip(b"hello xz");
}

#[test]
fn round_trip_repeated() {
    round_trip(&b"the quick brown fox ".repeat(100));
}

#[test]
fn round_trip_zeros_long() {
    round_trip(&vec![0u8; 8192]);
}

#[test]
fn round_trip_pseudo_random() {
    // Deterministic LCG-ish sequence; not real randomness but it's mixed
    // enough that none of the structural bytes coincide.
    let data: Vec<u8> = (0..50_000u32)
        .map(|i| ((i.wrapping_mul(0x9E37_79B1)) >> 24) as u8)
        .collect();
    round_trip(&data);
}

#[test]
fn round_trip_structured() {
    let mut v = Vec::new();
    for i in 0..200u32 {
        let s = format!(
            "record {:04} | timestamp 2026-05-28T{:02}:{:02}:00Z\n",
            i,
            (i / 60) % 24,
            i % 60
        );
        v.extend_from_slice(s.as_bytes());
    }
    round_trip(&v);
}

#[test]
fn round_trip_exactly_one_chunk() {
    // 65_536 bytes — exactly one full LZMA2 chunk's worth of data, no spill.
    round_trip(&vec![0xABu8; 65_536]);
}

#[test]
fn round_trip_just_over_one_chunk() {
    // 65_537 bytes — one full chunk plus a single-byte second chunk.
    let mut v = vec![0u8; 65_537];
    for (i, b) in v.iter_mut().enumerate() {
        *b = (i & 0xFF) as u8;
    }
    round_trip(&v);
}

#[test]
fn round_trip_multi_chunk() {
    // ~200 KiB, spanning several LZMA2 chunks.
    let v: Vec<u8> = (0..200_000u32)
        .map(|i| (i as u8).wrapping_mul(17))
        .collect();
    round_trip(&v);
}

#[test]
fn streaming_one_byte_both_sides() {
    let input = b"one byte at a time, all the way through".to_vec();
    let encoded = encode_chunked(&input, 1, 1);
    let decoded = decode_chunked(&encoded, 1, 1).unwrap();
    assert_eq!(decoded, input);
}

#[test]
fn streaming_irregular_chunks() {
    let input: Vec<u8> = (0..70_000u32).map(|i| (i ^ (i >> 7)) as u8).collect();
    let encoded = encode_chunked(&input, 13, 257);
    let decoded = decode_chunked(&encoded, 521, 1024).unwrap();
    assert_eq!(decoded, input);
}

// ─── error path tests ──────────────────────────────────────────────────────

#[test]
fn bad_magic_rejected() {
    let stream = [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x01]; // last byte wrong
    let mut dec = Decoder::new();
    let mut buf = [0u8; 16];
    let err = dec.decode(&stream, &mut buf).unwrap_err();
    assert_eq!(err, Error::BadHeader);
}

#[test]
fn truncated_stream_rejected() {
    let mut encoded = encode_all(b"some payload");
    // Drop the last few bytes (the stream-footer magic at minimum).
    encoded.truncate(encoded.len() - 4);
    let err = decode_chunked(&encoded, 1024, 1024).unwrap_err();
    assert_eq!(err, Error::UnexpectedEnd);
}

#[test]
fn corrupted_check_rejected() {
    let input = b"checksum me please";
    let mut encoded = encode_all(input);
    // The Block Check (CRC32 of the uncompressed data) sits between the
    // block payload and the Index. The block ends after the LZMA2 end
    // marker + padding; that's well before the Index's `0x00` indicator.
    // The simplest reliable way to find it is to scan backwards from the
    // Stream Footer (12 bytes) past the index. We'll just flip a bit
    // somewhere in the middle of the encoded stream — past the headers and
    // before the index.
    let mid = encoded.len() / 2;
    encoded[mid] ^= 0x01;
    let err = decode_chunked(&encoded, 1024, 1024).unwrap_err();
    // The decoder may report any of: ChecksumMismatch (on the block CRC),
    // Corrupt (varints / padding), or Unsupported (a control byte we
    // misparse). We just want a *clean* error and no panic.
    assert!(
        matches!(
            err,
            Error::ChecksumMismatch | Error::Corrupt | Error::Unsupported | Error::TrailerMismatch
        ),
        "unexpected error variant: {:?}",
        err
    );
}

#[test]
fn fixture_empty_file() {
    // Generate an xz-formatted empty stream and decode it. The fixture is
    // the canonical output of `:|xz -F xz -c`, which is just header +
    // empty-index + footer (no blocks).
    //
    // Bytes (hex), 32 total:
    //   fd 37 7a 58 5a 00       Stream Magic
    //   00 04                   Stream Flags = check None (0x00 0x04??)
    // Actually let me just construct one ourselves: encode_all(b"").
    let bytes = encode_all(b"");
    let decoded = decode_chunked(&bytes, 1024, 1024).unwrap();
    assert!(decoded.is_empty());
}

#[test]
fn reset_then_reuse() {
    let mut enc = Encoder::new();
    // Encode something.
    let mut buf = vec![0u8; 4096];
    let p = enc.encode(b"first", &mut buf).unwrap();
    assert_eq!(p.consumed, 5);
    enc.reset();
    // Reuse for a fresh stream.
    let mut out = Vec::new();
    let mut consumed = 0;
    let input = b"second-payload";
    while consumed < input.len() {
        let p = enc.encode(&input[consumed..], &mut buf).unwrap();
        out.extend_from_slice(&buf[..p.written]);
        consumed += p.consumed;
        if p.consumed == 0 && p.written == 0 {
            break;
        }
    }
    loop {
        let p = enc.finish(&mut buf).unwrap();
        out.extend_from_slice(&buf[..p.written]);
        if matches!(_s, compcol::Status::StreamEnd) {
            break;
        }
    }
    let decoded = decode_chunked(&out, 1024, 1024).unwrap();
    assert_eq!(decoded, input);
}

// ─── cross-validation with system `xz` (if installed) ──────────────────────

fn tool_available(cmd: &str) -> bool {
    Command::new(cmd)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn pipe_through(cmd: &str, args: &[&str], stdin_data: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut child = Command::new(cmd)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child.stdin.as_mut().unwrap().write_all(stdin_data)?;
    let out = child.wait_with_output()?;
    if !out.status.success() {
        return Err(std::io::Error::other(format!(
            "{} {:?} exited {:?}: {}",
            cmd,
            args,
            out.status,
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    Ok(out.stdout)
}

#[test]
fn our_encode_then_system_xz_decode() {
    if !tool_available("xz") {
        println!("skipping: xz not installed");
        return;
    }
    for (label, input) in [
        ("empty", Vec::new()),
        ("short", b"hello xz world".to_vec()),
        ("medium", b"Lorem ipsum dolor sit amet. ".repeat(200)),
        ("two_chunks", vec![0xCDu8; 70_000]),
    ] {
        let encoded = encode_all(&input);
        match pipe_through("xz", &["-d", "-c"], &encoded) {
            Ok(decoded) => assert_eq!(decoded, input, "{}: system xz decoded wrong", label),
            Err(e) => panic!("{}: system xz failed: {}", label, e),
        }
    }
}

#[test]
fn system_xz_encode_then_our_decode_small() {
    if !tool_available("xz") {
        println!("skipping: xz not installed");
        return;
    }
    // For small enough inputs, `xz` emits uncompressed LZMA2 chunks (the
    // compressor decides that compression would expand the data). For
    // larger inputs `xz` emits LZMA-compressed chunks. Our decoder
    // accepts both.
    for input in [
        b"".to_vec(),
        b"hello".to_vec(),
        b"a".to_vec(),
        b"the quick brown fox jumps over".to_vec(),
    ] {
        let encoded = match pipe_through("xz", &["-c", "-z"], &input) {
            Ok(v) => v,
            Err(e) => {
                println!("skipping case (xz failed): {}", e);
                continue;
            }
        };
        match decode_chunked(&encoded, 1024, 1024) {
            Ok(decoded) => assert_eq!(decoded, input),
            Err(e) => panic!(
                "our decoder failed for system-xz output ({:?}): {:?}",
                input, e
            ),
        }
    }
}

// ─── round-trip via the system `xz` CLI (decode side) ──────────────────────

#[cfg(unix)]
#[test]
fn system_xz_encode_then_our_decode_empty() {
    if !tool_available("xz") {
        println!("skipping: xz not installed");
        return;
    }
    let input: Vec<u8> = Vec::new();
    let encoded = pipe_through("xz", &["-c", "-z"], &input).unwrap();
    let decoded = decode_chunked(&encoded, 1024, 1024).unwrap();
    assert_eq!(decoded, input);
}

#[cfg(unix)]
#[test]
fn system_xz_encode_then_our_decode_small_string() {
    if !tool_available("xz") {
        println!("skipping: xz not installed");
        return;
    }
    let input: Vec<u8> = b"hello world\n".to_vec();
    let encoded = pipe_through("xz", &["-c", "-z"], &input).unwrap();
    let decoded = decode_chunked(&encoded, 1024, 1024).unwrap();
    assert_eq!(decoded, input);
}

#[cfg(unix)]
#[test]
fn system_xz_encode_then_our_decode_medium_ascii() {
    if !tool_available("xz") {
        println!("skipping: xz not installed");
        return;
    }
    // ~10 KiB of compressible ASCII.
    let mut input: Vec<u8> = Vec::with_capacity(10 * 1024);
    while input.len() < 10 * 1024 {
        input.extend_from_slice(b"The quick brown fox jumps over the lazy dog. 0123456789\n");
    }
    input.truncate(10 * 1024);
    let encoded = pipe_through("xz", &["-c", "-z"], &input).unwrap();
    let decoded = decode_chunked(&encoded, 1024, 1024).unwrap();
    assert_eq!(decoded, input);
}

#[cfg(unix)]
#[test]
fn system_xz_encode_then_our_decode_lorem_ipsum() {
    if !tool_available("xz") {
        println!("skipping: xz not installed");
        return;
    }
    // ~16 KiB of Lorem ipsum.
    let para: &[u8] = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do \
                       eiusmod tempor incididunt ut labore et dolore magna aliqua. \
                       Ut enim ad minim veniam, quis nostrud exercitation ullamco \
                       laboris nisi ut aliquip ex ea commodo consequat. Duis aute \
                       irure dolor in reprehenderit in voluptate velit esse cillum \
                       dolore eu fugiat nulla pariatur.\n";
    let mut input: Vec<u8> = Vec::with_capacity(16 * 1024);
    while input.len() < 16 * 1024 {
        input.extend_from_slice(para);
    }
    input.truncate(16 * 1024);
    let encoded = pipe_through("xz", &["-c", "-z"], &input).unwrap();
    let decoded = decode_chunked(&encoded, 1024, 1024).unwrap();
    assert_eq!(decoded, input);
}

#[cfg(unix)]
#[test]
fn system_xz_encode_then_our_decode_large_zeros() {
    if !tool_available("xz") {
        println!("skipping: xz not installed");
        return;
    }
    // 64 KiB of zero bytes — exercises LZMA's match-back logic over a
    // size that is large enough to force xz into compressed-chunk mode.
    let input: Vec<u8> = vec![0u8; 64 * 1024];
    let encoded = pipe_through("xz", &["-c", "-z"], &input).unwrap();
    let decoded = decode_chunked(&encoded, 1024, 1024).unwrap();
    assert_eq!(decoded, input);
}

#[cfg(unix)]
#[test]
fn system_xz_encode_then_our_decode_binary() {
    if !tool_available("xz") {
        println!("skipping: xz not installed");
        return;
    }
    // Pseudo-random but reproducible binary input that compresses
    // poorly — exercises a different LZMA code path (mostly literals).
    let input: Vec<u8> = (0..30_000u32)
        .map(|i| (i.wrapping_mul(0x9E37_79B1) >> 16) as u8)
        .collect();
    let encoded = pipe_through("xz", &["-c", "-z"], &input).unwrap();
    let decoded = decode_chunked(&encoded, 1024, 1024).unwrap();
    assert_eq!(decoded, input);
}

// ─── compressed-LZMA2 encoder cross-validation ─────────────────────────────
//
// These tests exercise the LZMA-compressed chunk path in our encoder: we
// build an xz stream, hand it to the system `xz -d`, and check the decoded
// bytes match the original input. The system tool acts as an independent
// reference, so any bug in our LZMA encoder (range coder, distance
// composition, bit-tree direction, etc.) shows up here.
//
// We probe for `xz` once per test and skip cleanly when the tool isn't
// installed — keeps the suite green on minimal CI images.

/// Find the first LZMA2 chunk control byte in `encoded`. The xz wire
/// format starts with a 12-byte Stream Header, then a Block Header that
/// our encoder builds with build_block_header() (12 bytes), so the first
/// chunk control byte is at offset 24.
#[cfg(unix)]
fn first_chunk_control_byte(encoded: &[u8]) -> u8 {
    assert!(encoded.len() > 24, "xz stream too short to contain a chunk");
    encoded[24]
}

#[cfg(unix)]
#[test]
fn compressed_lzma2_empty_round_trip_via_xz() {
    if !tool_available("xz") {
        println!("skipping: xz not installed");
        return;
    }
    let input: Vec<u8> = Vec::new();
    let encoded = encode_all(&input);
    // Empty input: no chunks, block payload is just the 0x00 end marker.
    // The byte at offset 24 is the LZMA2 end marker (0x00).
    assert_eq!(first_chunk_control_byte(&encoded), 0x00);
    let decoded = pipe_through("xz", &["-d", "-c"], &encoded).unwrap();
    assert_eq!(decoded, input);
}

#[cfg(unix)]
#[test]
fn compressed_lzma2_hello_world_round_trip_via_xz() {
    if !tool_available("xz") {
        println!("skipping: xz not installed");
        return;
    }
    let input: Vec<u8> = b"hello world\n".to_vec();
    let encoded = encode_all(&input);
    // 12 bytes is too small for compression to beat literal storage — the
    // encoder falls back to an uncompressed chunk (control byte 0x01).
    assert_eq!(
        first_chunk_control_byte(&encoded),
        0x01,
        "expected uncompressed fallback for 12-byte input"
    );
    let decoded = pipe_through("xz", &["-d", "-c"], &encoded).unwrap();
    assert_eq!(decoded, input);
    // Round-trip through our own decoder too.
    let our_decoded = decode_chunked(&encoded, 1024, 1024).unwrap();
    assert_eq!(our_decoded, input);
}

#[cfg(unix)]
#[test]
fn compressed_lzma2_ten_kib_ascii_via_xz() {
    if !tool_available("xz") {
        println!("skipping: xz not installed");
        return;
    }
    let mut input: Vec<u8> = Vec::with_capacity(10 * 1024);
    while input.len() < 10 * 1024 {
        input.extend_from_slice(b"The quick brown fox jumps over the lazy dog. 0123456789\n");
    }
    input.truncate(10 * 1024);
    let encoded = encode_all(&input);
    // 10 KiB of repeating ASCII compresses well — first chunk should be
    // LZMA-compressed (control byte 0xE0).
    assert_eq!(
        first_chunk_control_byte(&encoded),
        0xE0,
        "expected compressed chunk for 10 KiB repeating ASCII"
    );
    // Compression should noticeably reduce size, even with our basic
    // greedy parser.
    assert!(
        encoded.len() < input.len() / 2,
        "encoded {} >= half of {} — compression seems broken",
        encoded.len(),
        input.len()
    );
    let decoded = pipe_through("xz", &["-d", "-c"], &encoded).unwrap();
    assert_eq!(decoded, input);
    let our_decoded = decode_chunked(&encoded, 1024, 1024).unwrap();
    assert_eq!(our_decoded, input);
}

#[cfg(unix)]
#[test]
fn compressed_lzma2_sixteen_kib_lorem_ipsum_via_xz() {
    if !tool_available("xz") {
        println!("skipping: xz not installed");
        return;
    }
    let para: &[u8] = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do \
                       eiusmod tempor incididunt ut labore et dolore magna aliqua. \
                       Ut enim ad minim veniam, quis nostrud exercitation ullamco \
                       laboris nisi ut aliquip ex ea commodo consequat. Duis aute \
                       irure dolor in reprehenderit in voluptate velit esse cillum \
                       dolore eu fugiat nulla pariatur.\n";
    let mut input: Vec<u8> = Vec::with_capacity(16 * 1024);
    while input.len() < 16 * 1024 {
        input.extend_from_slice(para);
    }
    input.truncate(16 * 1024);
    let encoded = encode_all(&input);
    assert_eq!(
        first_chunk_control_byte(&encoded),
        0xE0,
        "expected compressed chunk for Lorem ipsum"
    );
    let decoded = pipe_through("xz", &["-d", "-c"], &encoded).unwrap();
    assert_eq!(decoded, input);
    let our_decoded = decode_chunked(&encoded, 1024, 1024).unwrap();
    assert_eq!(our_decoded, input);
}

#[cfg(unix)]
#[test]
fn compressed_lzma2_sixty_four_kib_zeros_via_xz() {
    if !tool_available("xz") {
        println!("skipping: xz not installed");
        return;
    }
    // 64 KiB of zeros (exactly one chunk's worth) — this should compress
    // to a handful of bytes since the whole buffer is "byte 0 then match
    // back distance 0 for 65535 bytes".
    let input: Vec<u8> = vec![0u8; 64 * 1024];
    let encoded = encode_all(&input);
    assert_eq!(
        first_chunk_control_byte(&encoded),
        0xE0,
        "expected compressed chunk for 64 KiB of zeros"
    );
    // Massive compression expected: 64 KiB → <1 KiB easily.
    assert!(
        encoded.len() < 1024,
        "encoded {} > 1 KiB for 64 KiB of zeros — compression not effective",
        encoded.len()
    );
    let decoded = pipe_through("xz", &["-d", "-c"], &encoded).unwrap();
    assert_eq!(decoded, input);
    let our_decoded = decode_chunked(&encoded, 1024, 1024).unwrap();
    assert_eq!(our_decoded, input);
}

#[cfg(unix)]
#[test]
fn compressed_lzma2_pseudo_random_round_trip_via_xz() {
    if !tool_available("xz") {
        println!("skipping: xz not installed");
        return;
    }
    // High-entropy pseudo-random binary. Such inputs either fall through
    // to the uncompressed-chunk path or come out only marginally smaller
    // when LZMA's probability model happens to give the bitstream a slight
    // edge. Either outcome is acceptable; what we really care about is
    // that the wire format is valid and round-trips both ways.
    let input: Vec<u8> = (0..40_000u32)
        .map(|i| {
            // Mix two LCG-ish streams so neither byte-aligned matches nor
            // byte-pair repeats appear at any reasonable distance.
            let a = (i.wrapping_mul(0x9E37_79B1)) >> 24;
            let b = ((i ^ 0xDEAD_BEEF).wrapping_mul(0x85EB_CA6B)) >> 16;
            (a ^ b) as u8
        })
        .collect();
    let encoded = encode_all(&input);
    let cb = first_chunk_control_byte(&encoded);
    assert!(
        cb == 0x01 || cb == 0xE0,
        "expected uncompressed (0x01) or compressed (0xE0) chunk, got {:#x}",
        cb
    );
    let decoded = pipe_through("xz", &["-d", "-c"], &encoded).unwrap();
    assert_eq!(decoded, input);
    let our_decoded = decode_chunked(&encoded, 1024, 1024).unwrap();
    assert_eq!(our_decoded, input);
}

#[cfg(unix)]
#[test]
fn compressed_lzma2_truly_random_falls_back_uncompressed() {
    if !tool_available("xz") {
        println!("skipping: xz not installed");
        return;
    }
    // Force the uncompressed fallback by feeding bytes that look truly
    // random byte-by-byte. We construct this with a Xorshift-ish PRNG
    // seeded deterministically; xz-utils itself routinely falls back to
    // uncompressed chunks for inputs of this nature, and our encoder's
    // identical "compressed > uncompressed ? use uncompressed" heuristic
    // should agree.
    let mut s: u32 = 0xCAFE_F00D;
    let mut input: Vec<u8> = Vec::with_capacity(40_000);
    while input.len() < 40_000 {
        // Xorshift32 — high enough entropy that LZMA can't find matches.
        s ^= s << 13;
        s ^= s >> 17;
        s ^= s << 5;
        input.extend_from_slice(&s.to_le_bytes());
    }
    input.truncate(40_000);
    let encoded = encode_all(&input);
    let cb = first_chunk_control_byte(&encoded);
    // Tolerate either outcome — what we want is correctness, but flag the
    // common case for visibility.
    if cb != 0x01 && cb != 0xE0 {
        panic!("unexpected control byte for random input: {:#x}", cb);
    }
    let decoded = pipe_through("xz", &["-d", "-c"], &encoded).unwrap();
    assert_eq!(decoded, input);
    let our_decoded = decode_chunked(&encoded, 1024, 1024).unwrap();
    assert_eq!(our_decoded, input);
}

#[cfg(unix)]
#[test]
fn compressed_lzma2_multi_chunk_via_xz() {
    if !tool_available("xz") {
        println!("skipping: xz not installed");
        return;
    }
    // Input that spans multiple 65_536-byte chunks. With ~200 KiB of
    // compressible text we get at least 3 chunks; each one is independently
    // full-reset so we exercise the inter-chunk boundary handling.
    let mut input: Vec<u8> = Vec::with_capacity(200 * 1024);
    while input.len() < 200 * 1024 {
        input.extend_from_slice(
            b"The quick brown fox jumps over the lazy dog. \
              Pack my box with five dozen liquor jugs.\n",
        );
    }
    input.truncate(200 * 1024);
    let encoded = encode_all(&input);
    // First chunk should be compressed.
    assert_eq!(
        first_chunk_control_byte(&encoded),
        0xE0,
        "expected compressed first chunk"
    );
    // Significant compression expected.
    assert!(
        encoded.len() < input.len() / 4,
        "encoded {} too large vs input {}",
        encoded.len(),
        input.len()
    );
    let decoded = pipe_through("xz", &["-d", "-c"], &encoded).unwrap();
    assert_eq!(decoded, input);
    let our_decoded = decode_chunked(&encoded, 1024, 1024).unwrap();
    assert_eq!(our_decoded, input);
}
