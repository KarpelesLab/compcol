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
    // Feed stdin from another thread: the child writes stdout as it goes,
    // and once that pipe is full (a 64 KiB of output, which an `embed`
    // build's weaker ratio reaches on the larger inputs here) it blocks
    // until we read — which we must not wait to do until stdin is written.
    //
    // The child can exit before we finish writing stdin (e.g. usage
    // errors that fail fast without consuming input). The kernel then
    // returns EPIPE; treat that as "child ate what it wanted, move on."
    let mut stdin_pipe = child.stdin.take().unwrap();
    let stdin = stdin.to_vec();
    let feeder = std::thread::spawn(move || {
        if let Err(e) = stdin_pipe.write_all(&stdin)
            && e.kind() != std::io::ErrorKind::BrokenPipe
        {
            panic!("write stdin: {e:?}");
        }
    });
    let mut out = Vec::new();
    let mut err = Vec::new();
    child
        .stdout
        .as_mut()
        .unwrap()
        .read_to_end(&mut out)
        .unwrap();
    child
        .stderr
        .as_mut()
        .unwrap()
        .read_to_end(&mut err)
        .unwrap();
    feeder.join().expect("stdin feeder");
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
    (out.stdout, out.stderr, out.status.code().unwrap_or(-1))
}

fn file_contents(p: &Path) -> Vec<u8> {
    fs::read(p).expect("read")
}

/// Sorted names of the entries in `dir` — to check nothing extra (such as a
/// temporary file) was left behind.
fn names_in(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .expect("read_dir")
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
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
#[cfg(all(
    feature = "bzip2",
    feature = "gzip",
    feature = "xz",
    feature = "zstd",
    feature = "lzma",
    feature = "lz4",
    feature = "brotli"
))]
fn pipe_decode_drains_internal_block_buffer() {
    // Regression: a highly-compressible large input decodes to far more than
    // one output-buffer's worth. Block-buffering decoders (notably bzip2)
    // decode an entire block internally; the CLI must drain that buffer after
    // the compressed input is consumed instead of stopping at the first
    // buffer-full (which previously truncated bzip2 output at 64 KiB).
    let input = b"the quick brown fox jumps over the lazy dog 0123456789\n".repeat(100_000);
    for codec in ["bzip2", "gzip", "xz", "zstd", "lzma", "lz4", "brotli"] {
        let (encoded, _err, code) = run_with_stdin(&["-t", codec], &input);
        assert_eq!(code, 0, "{codec} encode failed");
        let (decoded, err, code) = run_with_stdin(&["-t", codec, "-d"], &encoded);
        assert_eq!(
            code,
            0,
            "{codec} decode failed: {}",
            String::from_utf8_lossy(&err)
        );
        assert_eq!(
            decoded.len(),
            input.len(),
            "{codec} decode truncated: got {} of {} bytes",
            decoded.len(),
            input.len()
        );
        assert_eq!(decoded, input, "{codec} decode mismatch");
    }
}

#[test]
fn auto_detect_decompress_gzip_via_pipe() {
    // Compress with an explicit -t, then decompress with NO -t: the binary
    // must auto-detect gzip from the 1F 8B magic.
    let input = b"auto-detect me, please, from my magic bytes".repeat(8);
    let (encoded, _err, code) = run_with_stdin(&["-t", "gzip"], &input);
    assert_eq!(code, 0);
    assert_eq!(&encoded[..2], &[0x1F, 0x8B]);

    // No -t on the decompress side.
    let (decoded, err, code) = run_with_stdin(&["-d"], &encoded);
    assert_eq!(code, 0, "stderr: {}", String::from_utf8_lossy(&err));
    assert_eq!(decoded, input);
}

#[test]
fn auto_detect_unknown_format_is_usage_error() {
    // Plain text has no recognizable magic; -d with no -t must fail clearly.
    let (_out, err, code) = run_with_stdin(&["-d"], b"this is not a compressed stream at all");
    assert_eq!(code, 2);
    let s = String::from_utf8_lossy(&err);
    assert!(s.contains("could not detect format"), "stderr: {s}");
}

#[test]
fn auto_detect_failure_names_the_real_flag() {
    // The hint must name a flag that exists: the option is `--type` / `-t`
    // (there is no `--algo`).
    let (_out, err, code) = run_with_stdin(&["-d"], b"this is not a compressed stream at all");
    assert_eq!(code, 2);
    let s = String::from_utf8_lossy(&err);
    assert!(s.contains("--type"), "stderr: {s}");
    assert!(!s.contains("--algo"), "stderr: {s}");
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
fn force_target_not_deleted_when_codec_errors_midstream() {
    // Regression for L12: a mid-stream codec error on an existing
    // --force target must not delete the user's pre-existing file. We
    // feed corrupt gzip so stream_decode fails after the output was
    // opened. The file must still exist afterwards — and, since --force
    // writes to a temporary file that only replaces the target on success,
    // with its content intact (it used to be left truncated).
    let s = Scratch::new("force_no_delete");
    let bad = s.file("bad.gz");
    // Valid gzip magic + method/flags + zeroed mtime, then garbage that
    // is not a valid deflate stream — decode starts then errors.
    fs::write(
        &bad,
        b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03\xff\xff\xff\xff",
    )
    .unwrap();

    let out = s.file("preexisting.out");
    fs::write(&out, b"precious user data").unwrap();

    let (_o, _err, code) = run(&[
        "-t",
        "gzip",
        "-d",
        "-f",
        "-o",
        out.to_str().unwrap(),
        bad.to_str().unwrap(),
    ]);
    assert_ne!(code, 0, "expected the corrupt input to fail");
    // The pre-existing target must survive the error. Before the first fix
    // it was unconditionally deleted; before the second, truncated.
    assert!(
        out.exists(),
        "pre-existing --force target was deleted on codec error"
    );
    assert_eq!(
        file_contents(&out),
        b"precious user data",
        "pre-existing --force target was modified by a failed run"
    );
    assert_eq!(names_in(&s.path), ["bad.gz", "preexisting.out"]);
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

// ─── --level / -l flag ──────────────────────────────────────────────────

#[test]
fn level_flag_round_trips_through_compression() {
    // Pick a reasonably-compressible payload (highly compressible data
    // collapses to the same few bytes at every level on small inputs).
    let payload: Vec<u8> = (0..16usize * 1024)
        .map(|i| (i.wrapping_mul(2654435761) >> 8) as u8)
        .collect();
    let (out, _err, code) = run_with_stdin(&["-t", "gzip", "-l", "9", "-c"], &payload);
    assert_eq!(code, 0);
    assert!(!out.is_empty());
    // And the resulting bytes decompress back.
    let (back, _err, code) = run_with_stdin(&["-t", "gzip", "-d", "-c"], &out);
    assert_eq!(code, 0);
    assert_eq!(back, payload);
}

#[test]
#[cfg(feature = "zstd")]
fn level_equals_form_is_accepted() {
    let (out, _err, code) = run_with_stdin(&["-t", "zstd", "--level=19", "-c"], b"hello\n");
    assert_eq!(code, 0);
    // zstd magic.
    assert_eq!(&out[..4], &[0x28, 0xB5, 0x2F, 0xFD]);
}

#[test]
fn short_l_attached_value() {
    let (out, _err, code) = run_with_stdin(&["-t", "gzip", "-l5", "-c"], b"hi\n");
    assert_eq!(code, 0);
    // gzip magic.
    assert_eq!(&out[..2], &[0x1F, 0x8B]);
}

#[test]
fn level_with_non_integer_is_usage_error() {
    let (_out, err, code) = run_with_stdin(&["-t", "gzip", "-l", "abc", "-c"], b"data");
    assert_eq!(code, 2);
    assert!(
        String::from_utf8_lossy(&err).contains("--level"),
        "stderr was {}",
        String::from_utf8_lossy(&err)
    );
}

#[test]
fn level_with_decompress_is_usage_error() {
    let (_out, err, code) = run_with_stdin(&["-t", "gzip", "-d", "-l", "5", "-c"], b"data");
    assert_eq!(code, 2);
    assert!(
        String::from_utf8_lossy(&err).contains("--level"),
        "stderr was {}",
        String::from_utf8_lossy(&err)
    );
}

#[test]
fn level_ignored_on_algorithms_without_a_level_knob() {
    // rle has no level. --level is a no-op rather than an error.
    let (out, _err, code) = run_with_stdin(&["-t", "rle", "-l", "5", "-c"], b"aaaa");
    assert_eq!(code, 0);
    let (back, _err, code) = run_with_stdin(&["-t", "rle", "-d", "-c"], &out);
    assert_eq!(code, 0);
    assert_eq!(back, b"aaaa");
}

// ─── output-file safety ─────────────────────────────────────────────────

#[test]
fn unknown_algorithm_does_not_truncate_force_target() {
    // The algorithm must be validated before the output is opened: with -f
    // an unknown -t used to truncate the existing target and then bail out.
    for mode in [&[][..], &["-d"][..]] {
        let s = Scratch::new("unknown_algo_force");
        let input = s.file("in.txt");
        let keep = s.file("keep.txt");
        fs::write(&input, b"input data").unwrap();
        fs::write(&keep, b"precious user data").unwrap();

        let mut args = vec!["-t", "nosuch", "-f", "-o", keep.to_str().unwrap()];
        args.extend_from_slice(mode);
        args.push(input.to_str().unwrap());
        let (_out, err, code) = run(&args);
        assert_eq!(code, 2, "stderr: {}", String::from_utf8_lossy(&err));
        assert!(
            String::from_utf8_lossy(&err).contains("unknown algorithm"),
            "{}",
            String::from_utf8_lossy(&err)
        );
        assert_eq!(file_contents(&keep), b"precious user data");
        assert_eq!(file_contents(&input), b"input data");
    }
}

#[test]
fn unknown_algorithm_does_not_create_output() {
    for mode in [&[][..], &["-d"][..]] {
        let s = Scratch::new("unknown_algo_new");
        let input = s.file("in.txt");
        let out = s.file("new.out");
        fs::write(&input, b"input data").unwrap();

        let mut args = vec!["-t", "nosuch", "-o", out.to_str().unwrap()];
        args.extend_from_slice(mode);
        args.push(input.to_str().unwrap());
        let (_out, err, code) = run(&args);
        assert_eq!(code, 2, "stderr: {}", String::from_utf8_lossy(&err));
        assert!(!out.exists(), "an empty output file was left behind");
        assert!(input.exists());
    }
}

#[test]
fn force_refuses_output_that_is_the_input() {
    // `-f -o X X` used to truncate X before reading it, "successfully"
    // replacing the input with a compressed empty stream.
    let s = Scratch::new("same_file");
    let same = s.file("same.txt");
    fs::write(&same, b"precious\n").unwrap();
    // Same file through a different spelling of the path.
    let respelled = s.path.join(".").join("same.txt");

    for out in [&same, &respelled] {
        let (_out, err, code) = run(&[
            "-t",
            "gzip",
            "-f",
            "-o",
            out.to_str().unwrap(),
            same.to_str().unwrap(),
        ]);
        assert_ne!(code, 0, "must refuse to overwrite the input with itself");
        assert!(
            String::from_utf8_lossy(&err).contains("same file"),
            "{}",
            String::from_utf8_lossy(&err)
        );
        assert_eq!(file_contents(&same), b"precious\n");
    }
}

#[cfg(unix)]
#[test]
fn in_place_decompress_keeps_non_utf8_name_bytes() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    // Stripping the extension went through a lossy UTF-8 conversion, so
    // `f\xFF.gz` decompressed to `f` + U+FFFD (and distinct inputs could
    // collide on that one mangled name) before the input was removed.
    let (gz, _err, code) = run_with_stdin(&["-t", "gzip"], b"non-utf8 name payload");
    assert_eq!(code, 0);

    let s = Scratch::new("non_utf8");
    let input = s.path.join(OsString::from_vec(b"f\xff.gz".to_vec()));
    let expected = s.path.join(OsString::from_vec(b"f\xff".to_vec()));
    if fs::write(&input, &gz).is_err() {
        // Some filesystems (APFS, for one) reject names that aren't UTF-8.
        println!("skipping: filesystem rejects non-UTF-8 file names");
        return;
    }

    let out = Command::new(BIN)
        .arg("-d")
        .arg(&input)
        .stdin(Stdio::null())
        .output()
        .expect("spawn compcol");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!input.exists(), "input should have been removed");
    assert!(
        !s.file("f\u{FFFD}").exists(),
        "output name was mangled to U+FFFD"
    );
    assert_eq!(file_contents(&expected), b"non-utf8 name payload");
}

/// Permission bits of `p`.
#[cfg(unix)]
fn mode_of(p: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(p).expect("stat").permissions().mode() & 0o777
}

#[cfg(unix)]
fn set_mode(p: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(p, fs::Permissions::from_mode(mode)).expect("chmod");
}

#[cfg(unix)]
#[test]
fn output_inherits_input_permissions() {
    // The output used to be created with the default mode (0666 & !umask),
    // so compressing a 0600 file produced a world-readable copy of it — and
    // in-place mode then removed the protected original.
    for mode in [0o600, 0o640] {
        let s = Scratch::new("perms");
        let secret = s.file("secret");
        fs::write(&secret, b"s3cret\n").unwrap();
        set_mode(&secret, mode);

        // In-place compress.
        let (_out, err, code) = run(&["-t", "gzip", secret.to_str().unwrap()]);
        assert_eq!(code, 0, "stderr: {}", String::from_utf8_lossy(&err));
        let gz = s.file("secret.gz");
        assert_eq!(mode_of(&gz), mode, "compressed output mode");

        // In-place decompress.
        let (_out, err, code) = run(&["-d", gz.to_str().unwrap()]);
        assert_eq!(code, 0, "stderr: {}", String::from_utf8_lossy(&err));
        assert_eq!(mode_of(&secret), mode, "decompressed output mode");
        assert_eq!(file_contents(&secret), b"s3cret\n");

        // Explicit -o, onto an existing more permissive file with --force.
        let other = s.file("other.gz");
        fs::write(&other, b"old").unwrap();
        set_mode(&other, 0o666);
        let (_out, err, code) = run(&[
            "-t",
            "gzip",
            "-f",
            "-o",
            other.to_str().unwrap(),
            secret.to_str().unwrap(),
        ]);
        assert_eq!(code, 0, "stderr: {}", String::from_utf8_lossy(&err));
        assert_eq!(mode_of(&other), mode, "--force output mode");
    }
}

#[cfg(unix)]
#[test]
fn output_from_stdin_keeps_default_permissions() {
    // With no input file there is no mode to copy: the output gets whatever
    // a plainly created file gets under the current umask.
    let s = Scratch::new("perms_stdin");
    let reference = s.file("reference");
    fs::write(&reference, b"x").unwrap();
    let out = s.file("out.gz");

    let (_out, err, code) = run_with_stdin(&["-t", "gzip", "-o", out.to_str().unwrap()], b"data");
    assert_eq!(code, 0, "stderr: {}", String::from_utf8_lossy(&err));
    assert_eq!(mode_of(&out), mode_of(&reference));
}

#[cfg(unix)]
#[test]
fn force_refuses_output_hard_linked_to_the_input() {
    // Two names, one inode: path comparison can't see it, dev/ino can.
    let s = Scratch::new("same_inode");
    let input = s.file("data.txt");
    let link = s.file("alias.txt");
    fs::write(&input, b"precious\n").unwrap();
    fs::hard_link(&input, &link).unwrap();

    let (_out, err, code) = run(&[
        "-t",
        "gzip",
        "-f",
        "-o",
        link.to_str().unwrap(),
        input.to_str().unwrap(),
    ]);
    assert_ne!(code, 0, "must refuse to overwrite the input with itself");
    assert!(
        String::from_utf8_lossy(&err).contains("same file"),
        "{}",
        String::from_utf8_lossy(&err)
    );
    assert_eq!(file_contents(&input), b"precious\n");
}

// ─── --max-output ───────────────────────────────────────────────────────

/// A small compressed stream that expands to `len` zero bytes.
fn bomb(codec: &str, len: usize) -> Vec<u8> {
    let (encoded, err, code) = run_with_stdin(&["-t", codec], &vec![0u8; len]);
    assert_eq!(code, 0, "{codec}: {}", String::from_utf8_lossy(&err));
    encoded
}

#[test]
fn max_output_aborts_a_decompression_bomb() {
    // Without --max-output the CLI had no way to bound what a tiny hostile
    // stream expands to; the library's LimitedDecoder was unreachable.
    const LEN: usize = 4 * 1024 * 1024;
    let mut codecs = vec!["gzip"];
    if cfg!(feature = "zstd") {
        codecs.push("zstd");
    }
    if cfg!(feature = "xz") {
        codecs.push("xz");
    }
    if cfg!(feature = "bzip2") {
        codecs.push("bzip2");
    }
    for codec in codecs {
        let encoded = bomb(codec, LEN);
        for limit in ["1048576", "1M", "1024k", "64K", "0"] {
            let (out, err, code) =
                run_with_stdin(&["-d", "-t", codec, "--max-output", limit], &encoded);
            let err = String::from_utf8_lossy(&err);
            assert_eq!(code, 1, "{codec} limit {limit}: {err}");
            assert!(err.contains("--max-output"), "{codec} limit {limit}: {err}");
            assert!(
                out.len() <= 1024 * 1024,
                "{codec} limit {limit}: {} bytes got out",
                out.len()
            );
        }
    }
}

#[test]
fn max_output_allows_output_up_to_the_limit() {
    const LEN: usize = 300 * 1024;
    let encoded = bomb("gzip", LEN);
    // Exactly the limit, the `=` spelling, and each suffix.
    for limit in [
        "--max-output=307200",
        "--max-output=300K",
        "--max-output=300KiB",
        "--max-output=1M",
    ] {
        let (out, err, code) = run_with_stdin(&["-d", "-t", "gzip", limit], &encoded);
        assert_eq!(code, 0, "{limit}: {}", String::from_utf8_lossy(&err));
        assert_eq!(out.len(), LEN, "{limit}");
    }
    let (out, err, code) = run_with_stdin(&["-d", "--max-output", "1G"], &encoded);
    assert_eq!(code, 0, "{}", String::from_utf8_lossy(&err));
    assert_eq!(out.len(), LEN);
    // One byte short is over the limit.
    let (_out, _err, code) = run_with_stdin(&["-d", "--max-output=307199"], &encoded);
    assert_eq!(code, 1);
}

#[test]
fn max_output_failure_removes_output_and_keeps_input() {
    let s = Scratch::new("max_output_file");
    let input = s.file("bomb.gz");
    let encoded = bomb("gzip", 1024 * 1024);
    fs::write(&input, &encoded).unwrap();

    let (_out, err, code) = run(&["-d", "--max-output", "64K", input.to_str().unwrap()]);
    let err = String::from_utf8_lossy(&err);
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("--max-output"), "{err}");
    assert!(err.contains("65536"), "limit not named in: {err}");
    assert!(!s.file("bomb").exists(), "partial output left behind");
    assert_eq!(file_contents(&input), encoded, "input must be kept");
}

#[test]
fn max_output_is_rejected_when_compressing() {
    let (_out, err, code) = run_with_stdin(&["-t", "gzip", "--max-output", "1M"], b"data");
    assert_eq!(code, 2);
    assert!(
        String::from_utf8_lossy(&err).contains("--max-output"),
        "{}",
        String::from_utf8_lossy(&err)
    );
}

#[test]
fn max_output_rejects_malformed_values() {
    for bad in [
        "",
        "abc",
        "-1",
        "+1",
        "1X",
        "K",
        "1.5M",
        "1 M",
        "1KB",
        "99999999999999999999",
        "17179869184G",
    ] {
        let arg = format!("--max-output={bad}");
        let (_out, err, code) = run_with_stdin(&["-d", "-t", "gzip", &arg], b"");
        assert_eq!(code, 2, "'{bad}' was accepted");
        assert!(
            String::from_utf8_lossy(&err).contains("--max-output"),
            "'{bad}': {}",
            String::from_utf8_lossy(&err)
        );
    }
    let (_out, err, code) = run_with_stdin(&["-d", "--max-output"], b"");
    assert_eq!(code, 2);
    assert!(String::from_utf8_lossy(&err).contains("requires an argument"));
}

// ─── trailing data after the stream ─────────────────────────────────────

const TRAILING_MSG: &str = "trailing data after the end of the compressed stream";

#[test]
fn trailing_data_fails_in_place_decompress_and_keeps_input() {
    // `cp a.gz g.gz; echo garbage >> g.gz; compcol -d g.gz` used to exit 0,
    // silently drop the extra bytes and delete g.gz.
    let (gz, _err, code) = run_with_stdin(&["-t", "gzip"], b"payload before the garbage\n");
    assert_eq!(code, 0);
    // A short tail, and one far larger than any buffer the CLI reads with.
    for tail in [b"garbage\n".to_vec(), vec![0x55u8; 300 * 1024]] {
        let s = Scratch::new("trailing");
        let input = s.file("g.gz");
        let mut bytes = gz.clone();
        bytes.extend_from_slice(&tail);
        fs::write(&input, &bytes).unwrap();

        let (_out, err, code) = run(&["-d", input.to_str().unwrap()]);
        let err = String::from_utf8_lossy(&err);
        assert_eq!(code, 1, "{err}");
        assert!(err.contains(TRAILING_MSG), "{err}");
        assert!(!s.file("g").exists(), "output must be removed");
        assert_eq!(file_contents(&input), bytes, "input must be kept");
    }
}

#[test]
fn trailing_data_fails_in_stdout_and_pipe_modes_too() {
    let (gz, _err, code) = run_with_stdin(&["-t", "gzip"], b"payload before the garbage\n");
    assert_eq!(code, 0);
    let mut bytes = gz.clone();
    bytes.extend_from_slice(b"garbage\n");

    // stdin → stdout.
    let (_out, err, code) = run_with_stdin(&["-d"], &bytes);
    assert_eq!(code, 1);
    assert!(String::from_utf8_lossy(&err).contains(TRAILING_MSG));

    // file → stdout (-c) and file → -o: the input is kept either way.
    let s = Scratch::new("trailing_c");
    let input = s.file("g.gz");
    fs::write(&input, &bytes).unwrap();
    let (_out, err, code) = run(&["-d", "-c", input.to_str().unwrap()]);
    assert_eq!(code, 1);
    assert!(String::from_utf8_lossy(&err).contains(TRAILING_MSG));
    let out = s.file("out");
    let (_out, err, code) = run(&["-d", "-o", out.to_str().unwrap(), input.to_str().unwrap()]);
    assert_eq!(code, 1);
    assert!(String::from_utf8_lossy(&err).contains(TRAILING_MSG));
    assert!(!out.exists(), "output must be removed");
    assert_eq!(file_contents(&input), bytes);
}

#[test]
fn ignore_trailing_restores_the_lenient_behaviour_with_a_warning() {
    let payload = b"payload before the garbage\n";
    let (gz, _err, code) = run_with_stdin(&["-t", "gzip"], payload);
    assert_eq!(code, 0);
    for tail in [b"garbage\n".to_vec(), vec![0x55u8; 300 * 1024]] {
        let mut bytes = gz.clone();
        bytes.extend_from_slice(&tail);

        let (out, err, code) = run_with_stdin(&["-d", "--ignore-trailing"], &bytes);
        let err = String::from_utf8_lossy(&err);
        assert_eq!(code, 0, "{err}");
        assert_eq!(out, payload);
        assert!(err.contains("warning"), "{err}");
        assert!(err.contains("trailing data"), "{err}");

        let s = Scratch::new("ignore_trailing");
        let input = s.file("g.gz");
        fs::write(&input, &bytes).unwrap();
        let (_out, err, code) = run(&["-d", "--ignore-trailing", input.to_str().unwrap()]);
        let err = String::from_utf8_lossy(&err);
        assert_eq!(code, 0, "{err}");
        assert!(err.contains("warning"), "{err}");
        assert_eq!(file_contents(&s.file("g")), payload);
        assert!(!input.exists(), "input is removed as on any success");
    }
}

#[test]
fn ignore_trailing_is_silent_without_trailing_data() {
    let (gz, _err, code) = run_with_stdin(&["-t", "gzip"], b"clean");
    assert_eq!(code, 0);
    let (out, err, code) = run_with_stdin(&["-d", "--ignore-trailing"], &gz);
    assert_eq!(code, 0);
    assert_eq!(out, b"clean");
    assert!(err.is_empty(), "{}", String::from_utf8_lossy(&err));
}

#[test]
fn ignore_trailing_is_rejected_when_compressing() {
    let (_out, err, code) = run_with_stdin(&["-t", "gzip", "--ignore-trailing"], b"data");
    assert_eq!(code, 2);
    assert!(
        String::from_utf8_lossy(&err).contains("only meaningful on decompression"),
        "{}",
        String::from_utf8_lossy(&err)
    );
}

#[test]
fn concatenated_members_are_not_trailing_data() {
    // Formats whose decoder continues into a following member/stream must
    // keep doing so: that is more stream, not trailing data.
    let a = b"first member\n".repeat(50);
    let b = b"second member, different text\n".repeat(5000);
    let mut codecs = vec!["gzip"];
    if cfg!(feature = "xz") {
        codecs.push("xz");
    }
    if cfg!(feature = "bzip2") {
        codecs.push("bzip2");
    }
    for codec in codecs {
        let (mut joined, _err, code) = run_with_stdin(&["-t", codec], &a);
        assert_eq!(code, 0);
        let (second, _err, code) = run_with_stdin(&["-t", codec], &b);
        assert_eq!(code, 0);
        joined.extend_from_slice(&second);

        let (out, err, code) = run_with_stdin(&["-d", "-t", codec], &joined);
        assert_eq!(code, 0, "{codec}: {}", String::from_utf8_lossy(&err));
        assert_eq!(out, [&a[..], &b[..]].concat(), "{codec}");
    }
}

#[test]
fn round_trips_never_report_trailing_data() {
    // Every codec that can both encode and decode through the CLI must come
    // back clean: an end-of-stream that leaves the encoder's own padding or
    // trailer unconsumed would now be an error.
    let (list, _err, code) = run(&["--list"]);
    assert_eq!(code, 0);
    let list = String::from_utf8(list).unwrap();
    let payloads: [Vec<u8>; 3] = [
        b"x".to_vec(),
        b"The quick brown fox jumps over the lazy dog. ".repeat(40),
        (0..200_000usize)
            .map(|i| (i.wrapping_mul(2654435761) >> 11) as u8)
            .collect(),
    ];
    for codec in list.lines() {
        for payload in &payloads {
            let (encoded, _err, code) = run_with_stdin(&["-t", codec], payload);
            if code != 0 {
                continue; // decode-only codec
            }
            let (_out, err, _code) = run_with_stdin(&["-d", "-t", codec], &encoded);
            let err = String::from_utf8_lossy(&err);
            assert!(
                !err.contains("trailing data"),
                "{codec} ({} bytes): {err}",
                payload.len()
            );
        }
    }
}

// ─── --force writes through a temporary file ────────────────────────────

#[test]
fn force_leaves_no_temporary_files() {
    let s = Scratch::new("force_tmp");
    let input = s.file("in.txt");
    let out = s.file("out.gz");
    fs::write(&input, b"new data").unwrap();

    // Onto a path that doesn't exist yet, then onto the file just written.
    for _ in 0..2 {
        let (_out, err, code) = run(&[
            "-t",
            "gzip",
            "-f",
            "-o",
            out.to_str().unwrap(),
            input.to_str().unwrap(),
        ]);
        assert_eq!(code, 0, "stderr: {}", String::from_utf8_lossy(&err));
        assert_eq!(names_in(&s.path), ["in.txt", "out.gz"]);
        let (back, _err, code) = run(&["-d", "-c", out.to_str().unwrap()]);
        assert_eq!(code, 0);
        assert_eq!(back, b"new data");
    }

    // A failing run onto a path that doesn't exist creates nothing.
    let bad = s.file("bad.gz");
    fs::write(
        &bad,
        b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03\xff\xff\xff\xff",
    )
    .unwrap();
    let fresh = s.file("fresh");
    let (_out, _err, code) = run(&[
        "-d",
        "-f",
        "-o",
        fresh.to_str().unwrap(),
        bad.to_str().unwrap(),
    ]);
    assert_ne!(code, 0);
    assert_eq!(names_in(&s.path), ["bad.gz", "in.txt", "out.gz"]);
}

#[test]
fn force_in_a_relative_directory() {
    // The temporary file goes next to the output; a bare file name has an
    // empty parent, which must mean the current directory.
    let s = Scratch::new("force_rel");
    fs::write(s.file("in.txt"), b"relative").unwrap();
    fs::write(s.file("in.txt.gz"), b"old").unwrap();
    let out = Command::new(BIN)
        .args(["-t", "gzip", "-f", "in.txt"])
        .current_dir(&s.path)
        .stdin(Stdio::null())
        .output()
        .expect("spawn compcol");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(names_in(&s.path), ["in.txt.gz"]);
    assert_eq!(&file_contents(&s.file("in.txt.gz"))[..2], &[0x1F, 0x8B]);
}

#[test]
fn force_onto_a_directory_fails_cleanly() {
    let s = Scratch::new("force_dir");
    let input = s.file("in.txt");
    let dir = s.file("dir");
    fs::write(&input, b"data").unwrap();
    fs::create_dir(&dir).unwrap();
    fs::write(dir.join("inside"), b"kept").unwrap();

    let (_out, err, code) = run(&[
        "-t",
        "gzip",
        "-f",
        "-o",
        dir.to_str().unwrap(),
        input.to_str().unwrap(),
    ]);
    assert_eq!(code, 1, "stderr: {}", String::from_utf8_lossy(&err));
    assert_eq!(names_in(&s.path), ["dir", "in.txt"]);
    assert_eq!(names_in(&dir), ["inside"]);
}

#[cfg(unix)]
#[test]
fn force_replaces_a_symlink_instead_of_writing_through_it() {
    // `ln -s tgt link.gz; compcol -t gzip -f link` used to follow the
    // symlink and overwrite `tgt`. Like gzip -f, replace the link itself.
    let s = Scratch::new("force_symlink");
    let tgt = s.file("tgt");
    let link = s.file("link.gz");
    let input = s.file("link");
    fs::write(&tgt, b"the symlink's target").unwrap();
    std::os::unix::fs::symlink(&tgt, &link).unwrap();
    fs::write(&input, b"input data").unwrap();

    let (_out, err, code) = run(&["-t", "gzip", "-f", input.to_str().unwrap()]);
    assert_eq!(code, 0, "stderr: {}", String::from_utf8_lossy(&err));
    assert_eq!(file_contents(&tgt), b"the symlink's target");
    assert!(
        fs::symlink_metadata(&link).unwrap().file_type().is_file(),
        "the symlink should have been replaced by the output file"
    );
    assert_eq!(&file_contents(&link)[..2], &[0x1F, 0x8B]);
    assert_eq!(names_in(&s.path), ["link.gz", "tgt"]);

    // The same for a dangling symlink: nothing is created at its target.
    let dangling = s.file("dangling.gz");
    std::os::unix::fs::symlink(s.file("nowhere"), &dangling).unwrap();
    let (_out, err, code) = run(&[
        "-d",
        "-k",
        "-f",
        "-o",
        dangling.to_str().unwrap(),
        link.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "stderr: {}", String::from_utf8_lossy(&err));
    assert!(!s.file("nowhere").exists());
    assert_eq!(file_contents(&dangling), b"input data");
}

#[cfg(unix)]
#[test]
fn force_replaces_the_file_rather_than_rewriting_it() {
    // The destination is swapped by rename: another hard link to the old
    // file keeps the old content instead of seeing a truncate-and-rewrite.
    let s = Scratch::new("force_inode");
    let input = s.file("in.txt");
    let out = s.file("out.gz");
    let other = s.file("other-name");
    fs::write(&input, b"new").unwrap();
    fs::write(&out, b"old content").unwrap();
    fs::hard_link(&out, &other).unwrap();

    let (_out, err, code) = run(&[
        "-t",
        "gzip",
        "-f",
        "-o",
        out.to_str().unwrap(),
        input.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "stderr: {}", String::from_utf8_lossy(&err));
    assert_eq!(file_contents(&other), b"old content");
    assert_eq!(&file_contents(&out)[..2], &[0x1F, 0x8B]);
}

#[cfg(unix)]
#[test]
fn force_writes_straight_to_a_device() {
    use std::os::unix::fs::FileTypeExt;

    // A device (or FIFO, socket) can't be replaced by rename and holds
    // nothing to protect: `-f -o /dev/null` must keep writing into it —
    // also when it is reached through a symlink.
    let s = Scratch::new("force_dev");
    let input = s.file("in.txt");
    let sink = s.file("sink");
    fs::write(&input, b"discard me").unwrap();
    std::os::unix::fs::symlink("/dev/null", &sink).unwrap();

    for out in [Path::new("/dev/null"), &sink] {
        let (_out, err, code) = run(&[
            "-t",
            "gzip",
            "-f",
            "-o",
            out.to_str().unwrap(),
            input.to_str().unwrap(),
        ]);
        assert_eq!(code, 0, "stderr: {}", String::from_utf8_lossy(&err));
    }
    assert!(
        fs::metadata("/dev/null")
            .unwrap()
            .file_type()
            .is_char_device()
    );
    assert!(
        fs::symlink_metadata(&sink)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(names_in(&s.path), ["in.txt", "sink"]);
}

#[cfg(unix)]
#[test]
fn force_from_stdin_keeps_the_replaced_files_permissions() {
    // With no input file there is no mode to copy. Overwriting in place
    // used to leave the existing file's mode alone; replacing it must not
    // quietly widen a private file to the umask default.
    let s = Scratch::new("force_stdin_mode");
    let out = s.file("out.gz");
    fs::write(&out, b"old").unwrap();
    set_mode(&out, 0o600);

    let (_out, err, code) =
        run_with_stdin(&["-t", "gzip", "-f", "-o", out.to_str().unwrap()], b"data");
    assert_eq!(code, 0, "stderr: {}", String::from_utf8_lossy(&err));
    assert_eq!(mode_of(&out), 0o600);
    assert_eq!(&file_contents(&out)[..2], &[0x1F, 0x8B]);

    // And a new file gets the plain default, as without --force.
    let reference = s.file("reference");
    fs::write(&reference, b"x").unwrap();
    let fresh = s.file("fresh.gz");
    let (_out, err, code) = run_with_stdin(
        &["-t", "gzip", "-f", "-o", fresh.to_str().unwrap()],
        b"data",
    );
    assert_eq!(code, 0, "stderr: {}", String::from_utf8_lossy(&err));
    assert_eq!(mode_of(&fresh), mode_of(&reference));
}

// ─── auto-detection vs. archive containers ──────────────────────────────

#[test]
fn auto_detect_refuses_archive_containers() {
    // `factory::detect` answers RAR and StuffIt magics with the name of a
    // member codec, as a hint. The CLI used to take the hint literally and
    // feed the whole archive — headers, directory and all — to that codec.
    let mut sit_classic = b"SIT!\x00\x01\x00\x00\x10\x00rLau\x01\x00".to_vec();
    sit_classic.extend_from_slice(&[0u8; 64]);
    let cases: [(&[u8], &str); 4] = [
        (b"Rar!\x1a\x07\x01\x00 rar5 archive body ...", "RAR"),
        (b"Rar!\x1a\x07\x00 rar4 archive body .......", "RAR"),
        (&sit_classic, "StuffIt"),
        (b"StuffIt (c)1997-2002 Aladdin Systems, Inc.", "StuffIt"),
    ];
    for (bytes, kind) in cases {
        let (out, err, code) = run_with_stdin(&["-d"], bytes);
        let err = String::from_utf8_lossy(&err);
        assert_eq!(code, 2, "{kind}: {err}");
        assert!(
            err.contains(&format!("looks like a {kind} archive")),
            "{kind}: {err}"
        );
        assert!(err.contains("pass -t to force"), "{kind}: {err}");
        assert!(out.is_empty());

        // An explicit -t is taken at its word: the codec runs (and gets to
        // report whatever it makes of the bytes), without the archive hint.
        let (_out, err, _code) = run_with_stdin(&["-d", "-t", "gzip"], bytes);
        let err = String::from_utf8_lossy(&err);
        assert!(!err.contains("archive"), "{kind} with -t: {err}");
    }
}

#[test]
fn auto_detect_archive_refusal_touches_no_files() {
    let s = Scratch::new("archive_detect");
    let input = s.file("stuff.rar");
    let bytes = b"Rar!\x1a\x07\x01\x00 not really an archive, but it claims to be";
    fs::write(&input, bytes).unwrap();

    let (_out, err, code) = run(&["-d", input.to_str().unwrap()]);
    assert_eq!(code, 2, "{}", String::from_utf8_lossy(&err));
    assert!(String::from_utf8_lossy(&err).contains("RAR archive"));
    assert_eq!(names_in(&s.path), ["stuff.rar"]);
    assert_eq!(file_contents(&input), bytes);
}
