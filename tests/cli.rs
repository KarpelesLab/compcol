//! End-to-end tests for the `compcol` binary.
//!
//! Spawns the binary built by Cargo (via the `CARGO_BIN_EXE_compcol`
//! environment variable Cargo sets for integration tests) and drives it
//! via stdin/stdout/file I/O. Tests use unique scratch paths inside
//! `std::env::temp_dir()` so they run in parallel without colliding.

#![cfg(feature = "factory")]

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

const BIN: &str = env!("CARGO_BIN_EXE_compcol");

/// Unique tempdir per test invocation. Removed at Drop.
struct Scratch {
    path: PathBuf,
}

impl Scratch {
    fn new(label: &str) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let path = std::env::temp_dir().join(format!("compcol-test-{pid}-{n}-{label}"));
        fs::create_dir_all(&path).expect("create scratch");
        Self { path }
    }
    fn file(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// Spawn the binary with the given args and stdin payload; return stdout +
/// the exit status code.
fn run_with_stdin(args: &[&str], stdin: &[u8]) -> (Vec<u8>, Vec<u8>, i32) {
    let mut child = Command::new(BIN)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn compcol");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(stdin)
        .expect("write stdin");
    drop(child.stdin.take());
    let mut out = Vec::new();
    let mut err = Vec::new();
    child.stdout.as_mut().unwrap().read_to_end(&mut out).unwrap();
    child.stderr.as_mut().unwrap().read_to_end(&mut err).unwrap();
    let status = child.wait().expect("wait");
    let code = status.code().unwrap_or(-1);
    (out, err, code)
}

/// Spawn the binary with no stdin redirected (e.g. file mode).
fn run(args: &[&str]) -> (Vec<u8>, Vec<u8>, i32) {
    let child = Command::new(BIN)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn compcol");
    let out = child.wait_with_output().expect("wait");
    (
        out.stdout,
        out.stderr,
        out.status.code().unwrap_or(-1),
    )
}

fn file_contents(p: &Path) -> Vec<u8> {
    fs::read(p).expect("read")
}

// ─── help / list / version ───────────────────────────────────────────────

#[test]
fn help_prints_usage_and_exits_zero() {
    let (out, _err, code) = run(&["--help"]);
    assert_eq!(code, 0);
    let s = String::from_utf8_lossy(&out);
    assert!(s.contains("Usage:"), "{}", s);
    assert!(s.contains("--decompress"), "{}", s);
}

#[test]
fn version_prints_pkg_version() {
    let (out, _err, code) = run(&["--version"]);
    assert_eq!(code, 0);
    assert!(String::from_utf8_lossy(&out).starts_with("compcol "));
}

#[test]
fn list_includes_compiled_algorithms() {
    let (out, _err, code) = run(&["--list"]);
    assert_eq!(code, 0);
    let s = String::from_utf8(out).unwrap();
    for name in ["rle", "deflate", "zlib", "gzip"] {
        assert!(s.contains(name), "expected '{name}' in list output:\n{s}");
    }
}

#[test]
fn missing_type_is_usage_error() {
    let (_out, err, code) = run_with_stdin(&[], b"hello");
    assert_eq!(code, 2);
    assert!(String::from_utf8_lossy(&err).contains("-t ALGO is required"));
}

#[test]
fn unknown_type_is_usage_error() {
    let (_out, err, code) = run_with_stdin(&["-t", "bogus", "-c"], b"hello");
    assert_eq!(code, 2);
    assert!(
        String::from_utf8_lossy(&err).contains("unknown algorithm"),
        "{}",
        String::from_utf8_lossy(&err)
    );
}

#[test]
fn unknown_flag_is_usage_error() {
    let (_out, err, code) = run_with_stdin(&["--banana"], b"");
    assert_eq!(code, 2);
    assert!(String::from_utf8_lossy(&err).contains("unknown option"));
}

// ─── pipe mode round-trips ───────────────────────────────────────────────

#[test]
fn pipe_round_trip_gzip() {
    let input = b"The quick brown fox jumps over the lazy dog. ".repeat(20);
    let (encoded, _err, code) = run_with_stdin(&["-t", "gzip"], &input);
    assert_eq!(code, 0);
    // Magic bytes confirm we really emitted gzip.
    assert_eq!(&encoded[..2], &[0x1F, 0x8B]);
    let (decoded, _err, code) = run_with_stdin(&["-t", "gzip", "-d"], &encoded);
    assert_eq!(code, 0);
    assert_eq!(decoded, input);
}

#[test]
fn pipe_round_trip_zlib() {
    let input = b"compress me through zlib".to_vec();
    let (encoded, _err, code) = run_with_stdin(&["-t", "zlib"], &input);
    assert_eq!(code, 0);
    assert_eq!(encoded[0], 0x78); // standard zlib CMF byte
    let (decoded, _err, code) = run_with_stdin(&["-t", "zlib", "-d"], &encoded);
    assert_eq!(code, 0);
    assert_eq!(decoded, input);
}

#[test]
fn pipe_round_trip_deflate() {
    let input = b"raw deflate stream payload bytes".to_vec();
    let (encoded, _err, code) = run_with_stdin(&["-t", "deflate"], &input);
    assert_eq!(code, 0);
    let (decoded, _err, code) = run_with_stdin(&["-t", "deflate", "-d"], &encoded);
    assert_eq!(code, 0);
    assert_eq!(decoded, input);
}

#[test]
fn pipe_round_trip_rle() {
    let input = b"aaabbbcccdddeeee".to_vec();
    let (encoded, _err, code) = run_with_stdin(&["-t", "rle"], &input);
    assert_eq!(code, 0);
    let (decoded, _err, code) = run_with_stdin(&["-t", "rle", "-d"], &encoded);
    assert_eq!(code, 0);
    assert_eq!(decoded, input);
}

// ─── file modes ─────────────────────────────────────────────────────────

#[test]
fn in_place_compress_removes_input() {
    let s = Scratch::new("inplace_compress");
    let input = s.file("data.txt");
    fs::write(&input, b"hello in place world\n").unwrap();

    let (_out, err, code) = run(&["-t", "gzip", input.to_str().unwrap()]);
    assert_eq!(code, 0, "stderr: {}", String::from_utf8_lossy(&err));
    assert!(!input.exists(), "input should have been removed");
    let gz = s.file("data.txt.gz");
    assert!(gz.exists(), "output {} not created", gz.display());

    // Round-trip via decompress.
    let (_out, err, code) = run(&["-t", "gzip", "-d", gz.to_str().unwrap()]);
    assert_eq!(code, 0, "stderr: {}", String::from_utf8_lossy(&err));
    assert!(!gz.exists(), "compressed input should have been removed");
    assert_eq!(file_contents(&input), b"hello in place world\n");
}

#[test]
fn keep_preserves_input() {
    let s = Scratch::new("keep");
    let input = s.file("kept.txt");
    fs::write(&input, b"keep me").unwrap();

    let (_out, err, code) = run(&["-t", "gzip", "-k", input.to_str().unwrap()]);
    assert_eq!(code, 0, "stderr: {}", String::from_utf8_lossy(&err));
    assert!(input.exists(), "-k should have preserved input");
    assert!(s.file("kept.txt.gz").exists());
}

#[test]
fn stdout_flag_keeps_input_and_writes_to_stdout() {
    let s = Scratch::new("stdout_flag");
    let input = s.file("a.txt");
    fs::write(&input, b"stdout please").unwrap();
    let (out, err, code) = run(&["-t", "gzip", "-c", input.to_str().unwrap()]);
    assert_eq!(code, 0, "stderr: {}", String::from_utf8_lossy(&err));
    assert!(input.exists(), "-c must not remove input");
    assert_eq!(&out[..2], &[0x1F, 0x8B]);
}

#[test]
fn output_flag_writes_to_specified_path() {
    let s = Scratch::new("oflag");
    let input = s.file("src.txt");
    let dst = s.file("out/elsewhere.bin");
    fs::create_dir_all(s.file("out")).unwrap();
    fs::write(&input, b"to elsewhere").unwrap();

    let (_out, err, code) = run(&[
        "-t",
        "gzip",
        "-o",
        dst.to_str().unwrap(),
        input.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "stderr: {}", String::from_utf8_lossy(&err));
    assert!(input.exists(), "-o must not remove input");
    assert!(dst.exists(), "-o destination missing");
    assert_eq!(&file_contents(&dst)[..2], &[0x1F, 0x8B]);
}

#[test]
fn refuses_to_overwrite_existing_output() {
    let s = Scratch::new("overwrite_no_f");
    let input = s.file("z.txt");
    fs::write(&input, b"data").unwrap();
    fs::write(s.file("z.txt.gz"), b"pre-existing").unwrap();

    let (_out, err, code) = run(&["-t", "gzip", input.to_str().unwrap()]);
    assert_eq!(code, 2);
    assert!(
        String::from_utf8_lossy(&err).contains("output exists"),
        "{}",
        String::from_utf8_lossy(&err)
    );
    // Original output unchanged, input still present.
    assert_eq!(file_contents(&s.file("z.txt.gz")), b"pre-existing");
    assert!(input.exists());
}

#[test]
fn force_overwrites_existing_output() {
    let s = Scratch::new("overwrite_force");
    let input = s.file("z.txt");
    fs::write(&input, b"new data").unwrap();
    fs::write(s.file("z.txt.gz"), b"old").unwrap();

    let (_out, err, code) = run(&["-t", "gzip", "-f", input.to_str().unwrap()]);
    assert_eq!(code, 0, "stderr: {}", String::from_utf8_lossy(&err));
    let new = file_contents(&s.file("z.txt.gz"));
    assert_eq!(&new[..2], &[0x1F, 0x8B]);
    assert!(!input.exists());
}

#[test]
fn decompress_requires_matching_extension_in_inplace_mode() {
    let s = Scratch::new("dec_ext");
    let bogus = s.file("data.txt"); // wrong extension for gzip
    fs::write(&bogus, b"\x1f\x8b\x08\x00").unwrap(); // gzip-like prefix
    let (_out, err, code) = run(&["-t", "gzip", "-d", bogus.to_str().unwrap()]);
    assert_eq!(code, 2);
    assert!(
        String::from_utf8_lossy(&err).contains("doesn't end with"),
        "{}",
        String::from_utf8_lossy(&err)
    );
}

#[test]
fn long_options_with_equals() {
    let input = b"hello".repeat(100);
    let (encoded, _err, code) = run_with_stdin(&["--type=gzip"], &input);
    assert_eq!(code, 0);
    let (decoded, _err, code) = run_with_stdin(&["--type=gzip", "--decompress"], &encoded);
    assert_eq!(code, 0);
    assert_eq!(decoded, input);
}

#[test]
fn short_t_with_attached_value() {
    let input = b"hi";
    let (encoded, _err, code) = run_with_stdin(&["-tgzip"], input);
    assert_eq!(code, 0);
    assert_eq!(&encoded[..2], &[0x1F, 0x8B]);
}

// ─── cross-tool sanity: our binary's output decompresses with system gunzip ──

#[test]
fn output_decompresses_with_system_gunzip() {
    if Command::new("gunzip")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| !s.success())
        .unwrap_or(true)
    {
        println!("skipping: gunzip not available");
        return;
    }
    let input = b"Mary had a little lamb. ".repeat(200);
    let (encoded, _err, code) = run_with_stdin(&["-t", "gzip"], &input);
    assert_eq!(code, 0);
    let mut child = Command::new("gunzip")
        .arg("-c")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.as_mut().unwrap().write_all(&encoded).unwrap();
    drop(child.stdin.take());
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    assert_eq!(out.stdout, input);
}
