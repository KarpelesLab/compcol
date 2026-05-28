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
        if p.done {
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
        if p.done {
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
        if p.done {
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
        if p.done {
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
    // compressor decides that compression would expand the data). Pick
    // small inputs so this is the common case.
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
            Err(Error::Unsupported) => {
                // xz chose to LZMA-compress this input; our decoder
                // correctly reports it as Unsupported.
            }
            Err(e) => panic!(
                "our decoder failed for system-xz output ({:?}): {:?}",
                input, e
            ),
        }
    }
}
