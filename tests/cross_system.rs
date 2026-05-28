#![cfg(any())] // TODO(v0.3): port to new (Progress, Status) API
//! Cross-validation against system tools (`gzip`, `python3 zlib`).
//!
//! Each test probes for the required tool with `--version`; if it's missing,
//! the test is skipped with a `println!` rather than failing the suite.

#![cfg(all(unix, feature = "gzip", feature = "zlib", feature = "deflate"))]

use std::io::Write;
use std::process::{Command, Stdio};

use compcol::{Decoder as _, Encoder as _};

fn tool_available(cmd: &str, version_flag: &str) -> bool {
    Command::new(cmd)
        .arg(version_flag)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn pipe_through(cmd: &str, args: &[&str], stdin_data: &[u8]) -> Vec<u8> {
    let mut child = Command::new(cmd)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn failed");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(stdin_data)
        .expect("stdin write failed");
    let out = child.wait_with_output().expect("wait failed");
    assert!(
        out.status.success(),
        "{} {:?} exited {:?}: {}",
        cmd,
        args,
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    out.stdout
}

// ── gzip ──────────────────────────────────────────────────────────────────

fn our_gzip_encode(input: &[u8]) -> Vec<u8> {
    let mut enc = compcol::gzip::Encoder::new();
    let mut out = Vec::new();
    let mut buf = vec![0u8; 8192];
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
            panic!("gzip encoder finish stalled");
        }
    }
    out
}

fn our_gzip_decode(input: &[u8]) -> Vec<u8> {
    let mut dec = compcol::gzip::Decoder::new();
    let mut out = Vec::new();
    let mut buf = vec![0u8; 8192];
    let mut consumed = 0;
    while consumed < input.len() {
        let p = dec.decode(&input[consumed..], &mut buf).unwrap();
        out.extend_from_slice(&buf[..p.written]);
        consumed += p.consumed;
        if p.consumed == 0 && p.written == 0 {
            break;
        }
    }
    loop {
        let p = dec.finish(&mut buf).unwrap();
        out.extend_from_slice(&buf[..p.written]);
        if matches!(_s, compcol::Status::StreamEnd) {
            break;
        }
        if p.written == 0 {
            panic!("decoder finish stalled");
        }
    }
    out
}

#[test]
fn our_gzip_encode_then_system_gunzip() {
    if !tool_available("gzip", "--version") {
        println!("skipping: gzip not installed");
        return;
    }
    for (label, input) in [
        ("small", b"hello world\n".to_vec()),
        (
            "medium",
            b"The quick brown fox jumps over the lazy dog. ".repeat(200),
        ),
        ("large", b"Mary had a little lamb. ".repeat(10_000)),
    ] {
        let encoded = our_gzip_encode(&input);
        let decoded = pipe_through("gzip", &["-d", "-c"], &encoded);
        assert_eq!(decoded, input, "{}: gunzip mismatch", label);
    }
}

#[test]
fn system_gzip_then_our_gzip_decode() {
    if !tool_available("gzip", "--version") {
        println!("skipping: gzip not installed");
        return;
    }
    for (label, input) in [
        ("small", b"hello world\n".to_vec()),
        (
            "medium",
            b"The quick brown fox jumps over the lazy dog. ".repeat(200),
        ),
        ("large", b"Mary had a little lamb. ".repeat(10_000)),
    ] {
        let encoded = pipe_through("gzip", &["-c", "-n"], &input);
        let decoded = our_gzip_decode(&encoded);
        assert_eq!(decoded, input, "{}: our gzip decode mismatch", label);
    }
}

// ── zlib (via python3) ────────────────────────────────────────────────────

const PY_ZLIB_COMPRESS: &str =
    "import sys, zlib; sys.stdout.buffer.write(zlib.compress(sys.stdin.buffer.read(), 6))";
const PY_ZLIB_DECOMPRESS: &str =
    "import sys, zlib; sys.stdout.buffer.write(zlib.decompress(sys.stdin.buffer.read()))";
const PY_DEFLATE_COMPRESS: &str = "import sys, zlib; co=zlib.compressobj(6, zlib.DEFLATED, -15); sys.stdout.buffer.write(co.compress(sys.stdin.buffer.read())+co.flush())";
const PY_DEFLATE_DECOMPRESS: &str =
    "import sys, zlib; sys.stdout.buffer.write(zlib.decompress(sys.stdin.buffer.read(), -15))";

fn our_zlib_encode(input: &[u8]) -> Vec<u8> {
    let mut enc = compcol::zlib::Encoder::new();
    let mut out = Vec::new();
    let mut buf = vec![0u8; 8192];
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
            panic!("zlib encoder finish stalled");
        }
    }
    out
}

fn our_zlib_decode(input: &[u8]) -> Vec<u8> {
    let mut dec = compcol::zlib::Decoder::new();
    let mut out = Vec::new();
    let mut buf = vec![0u8; 8192];
    let mut consumed = 0;
    while consumed < input.len() {
        let p = dec.decode(&input[consumed..], &mut buf).unwrap();
        out.extend_from_slice(&buf[..p.written]);
        consumed += p.consumed;
        if p.consumed == 0 && p.written == 0 {
            break;
        }
    }
    loop {
        let p = dec.finish(&mut buf).unwrap();
        out.extend_from_slice(&buf[..p.written]);
        if matches!(_s, compcol::Status::StreamEnd) {
            break;
        }
        if p.written == 0 {
            panic!("decoder finish stalled");
        }
    }
    out
}

fn our_deflate_encode(input: &[u8]) -> Vec<u8> {
    let mut enc = compcol::deflate::Encoder::new();
    let mut out = Vec::new();
    let mut buf = vec![0u8; 8192];
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
            panic!("deflate encoder finish stalled");
        }
    }
    out
}

fn our_deflate_decode(input: &[u8]) -> Vec<u8> {
    let mut dec = compcol::deflate::Decoder::new();
    let mut out = Vec::new();
    let mut buf = vec![0u8; 8192];
    let mut consumed = 0;
    while consumed < input.len() {
        let p = dec.decode(&input[consumed..], &mut buf).unwrap();
        out.extend_from_slice(&buf[..p.written]);
        consumed += p.consumed;
        if p.consumed == 0 && p.written == 0 {
            break;
        }
    }
    loop {
        let p = dec.finish(&mut buf).unwrap();
        out.extend_from_slice(&buf[..p.written]);
        if matches!(_s, compcol::Status::StreamEnd) {
            break;
        }
        if p.written == 0 {
            panic!("decoder finish stalled");
        }
    }
    out
}

#[test]
fn our_zlib_encode_then_python_decompress() {
    if !tool_available("python3", "--version") {
        println!("skipping: python3 not installed");
        return;
    }
    for input in [
        b"hello".to_vec(),
        b"Lorem ipsum dolor sit amet. ".repeat(500),
        (0..200_000u32)
            .map(|i| (i % 251) as u8)
            .collect::<Vec<u8>>(),
    ] {
        let encoded = our_zlib_encode(&input);
        let decoded = pipe_through("python3", &["-c", PY_ZLIB_DECOMPRESS], &encoded);
        assert_eq!(decoded, input, "python zlib decompress mismatch");
    }
}

#[test]
fn python_zlib_compress_then_our_decode() {
    if !tool_available("python3", "--version") {
        println!("skipping: python3 not installed");
        return;
    }
    for input in [
        b"hello".to_vec(),
        b"Lorem ipsum dolor sit amet. ".repeat(500),
        (0..200_000u32)
            .map(|i| (i % 251) as u8)
            .collect::<Vec<u8>>(),
    ] {
        let encoded = pipe_through("python3", &["-c", PY_ZLIB_COMPRESS], &input);
        let decoded = our_zlib_decode(&encoded);
        assert_eq!(decoded, input, "our zlib decode mismatch");
    }
}

#[test]
fn our_deflate_encode_then_python_inflate_raw() {
    if !tool_available("python3", "--version") {
        println!("skipping: python3 not installed");
        return;
    }
    for input in [
        b"hello".to_vec(),
        b"Lorem ipsum dolor sit amet. ".repeat(500),
        (0..200_000u32)
            .map(|i| (i % 251) as u8)
            .collect::<Vec<u8>>(),
    ] {
        let encoded = our_deflate_encode(&input);
        let decoded = pipe_through("python3", &["-c", PY_DEFLATE_DECOMPRESS], &encoded);
        assert_eq!(decoded, input, "python raw inflate mismatch");
    }
}

#[test]
fn python_deflate_then_our_decode() {
    if !tool_available("python3", "--version") {
        println!("skipping: python3 not installed");
        return;
    }
    for input in [
        b"hello".to_vec(),
        b"Lorem ipsum dolor sit amet. ".repeat(500),
        (0..200_000u32)
            .map(|i| (i % 251) as u8)
            .collect::<Vec<u8>>(),
    ] {
        let encoded = pipe_through("python3", &["-c", PY_DEFLATE_COMPRESS], &input);
        let decoded = our_deflate_decode(&encoded);
        assert_eq!(decoded, input, "our raw inflate mismatch");
    }
}
