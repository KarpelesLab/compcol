//! `compcol` — pure-Rust streaming compression / decompression CLI.
//!
//! Selects an algorithm with `-t ALGO` (required), compresses by default,
//! decompresses with `-d`. Reads stdin or an input file, writes stdout or
//! an `<input>.<ext>` derived path. See `compcol --help`.
//!
//! With the `mmap` Cargo feature, `-d` into a file the CLI creates decodes
//! straight into a memory mapping of that file when the format has a
//! [`compcol::ContiguousDecoder`]: the output then doubles as the decoder's
//! history, so no dictionary-sized window is held in memory. See the
//! `mapped` module.

// The library forbids `unsafe`. This binary denies it, with one exception:
// the function that maps the output file (`mapped::map_file`).
#![deny(unsafe_code)]

use std::env;
use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use compcol::factory;
use compcol::limit::LimitedDecoder;
use compcol::{Decoder, Encoder};

const VERSION: &str = env!("CARGO_PKG_VERSION");

const USAGE: &str = "\
Usage: compcol -t ALGO [OPTIONS] [INPUT]

Pure-Rust streaming compression / decompression.

Required:
    -t, --type ALGO         Algorithm (use --list to see what's compiled in).
                            Optional on -d: if omitted, the format is
                            auto-detected from the input's magic bytes.
                            Archives (RAR, StuffIt) are recognised but not
                            unpacked: -t is needed to run a codec on one.

Mode:
    -d, --decompress        Decompress instead of compress

Output (mutually exclusive):
    -c, --stdout            Write to stdout, keep input file
    -o, --output PATH       Write to PATH
    (default, INPUT given)  Write to <INPUT>.<ext> on compress, or strip
                            <ext> on decompress; remove INPUT on success
    (default, no INPUT)     Read stdin, write stdout

Compression tuning:
    -l, --level N           Compression level for the encoder
                            (ignored on decompress and on algorithms
                            without a level knob):
                              deflate/zlib/gzip: 0..=9, default 6 (0 = stored)
                              lzma/xz:           0..=9, default 6
                              zstd:              1..=22, default 3
                              brotli quality:    0..=11, default 6
                            Out-of-range values are clamped per algorithm.

Decompression safety:
        --max-output SIZE   Fail (and remove the partial output) rather than
                            write more than SIZE decompressed bytes — the
                            defence against decompression bombs. SIZE is a
                            byte count, optionally with a K, M, G or T
                            suffix (powers of 1024: 64M, 2G). Default: no
                            limit. Only valid with -d.
        --ignore-trailing   Input left over after the end of the compressed
                            stream is an error by default (the output is
                            removed, the input kept). With this flag it is
                            ignored with a warning. Only valid with -d.

Decompression output:
        --no-mmap           Always decode through ordinary buffered writes.
                            By default, a build with the `mmap` feature
                            memory-maps the output of -d when it is a file
                            that compcol itself creates and the format
                            allows it (xz, lzma, lzma2, zstd), and decodes
                            straight into it. The file then serves as the
                            dictionary too, so a stream with a 1 GiB
                            dictionary does not take 1 GiB of memory.
                            Caveats: the result is synced to disk before
                            compcol exits; and should the disk fill up in
                            a way that reserving space ahead of the
                            decoder does not catch (copy-on-write and
                            network file systems), the process is killed
                            (SIGBUS on unix) and leaves a partial output
                            behind instead of failing cleanly. Pass
                            --no-mmap if that matters. Only valid with -d;
                            accepted and without effect in other builds.

Misc:
    -k, --keep              Keep input file even in in-place mode
    -f, --force             Replace an existing output file. The output is
                            written to a temporary file next to it and
                            renamed over it once complete, so a failed run
                            leaves the old file as it was, and a symlink
                            is replaced rather than followed.
    -L, --list              List available algorithms and exit
    -V, --version           Print version and exit
    -h, --help              Print this help and exit

Examples:
    cat file.txt | compcol -t gzip > file.txt.gz
    compcol -t gzip file.txt              # → file.txt.gz, removes file.txt
    compcol -t gzip -k file.txt           # → file.txt.gz, keeps file.txt
    compcol -t gzip -c file.txt > out.gz  # explicit stdout
    compcol -t gzip -d file.txt.gz        # → file.txt, removes file.txt.gz
    compcol -t zstd -l 19 file.bin        # high-ratio zstd encode
";

// ─── argument parsing ────────────────────────────────────────────────────

#[derive(Debug, Default)]
struct Args {
    algorithm: Option<String>,
    decompress: bool,
    stdout: bool,
    output: Option<PathBuf>,
    keep: bool,
    force: bool,
    list: bool,
    version: bool,
    help: bool,
    /// When `Some`, compression level passed to the encoder via
    /// `factory::encoder_by_name_with_level`. Ignored on decompress.
    level: Option<u8>,
    /// When `Some`, the most decompressed bytes `-d` may produce before the
    /// run is aborted (see [`LimitedDecoder`]).
    max_output: Option<u64>,
    /// Accept (with a warning) input left over after the end of the
    /// compressed stream instead of failing.
    ignore_trailing: bool,
    /// Never decode into a memory-mapped output file. Accepted, and without
    /// effect, in builds without the `mmap` feature.
    no_mmap: bool,
    input: Option<PathBuf>,
}

#[derive(Debug)]
enum ParseError {
    MissingValue(&'static str),
    UnknownFlag(String),
    ExtraPositional(String),
    BadLevel(String),
    BadSize(String),
}

impl core::fmt::Display for ParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MissingValue(flag) => write!(f, "{flag} requires an argument"),
            Self::UnknownFlag(s) => write!(f, "unknown option: {s}"),
            Self::ExtraPositional(s) => write!(f, "unexpected extra argument: {s}"),
            Self::BadLevel(s) => write!(f, "--level expects an integer in 0..=255, got '{s}'"),
            Self::BadSize(s) => write!(
                f,
                "--max-output expects a byte count with an optional K/M/G/T suffix, got '{s}'"
            ),
        }
    }
}

/// Parse `argv` (excluding the program name).
fn parse_args<I>(argv: I) -> Result<Args, ParseError>
where
    I: IntoIterator<Item = OsString>,
{
    let mut args = Args::default();
    let mut iter = argv.into_iter();
    let mut positional_only = false;

    while let Some(raw) = iter.next() {
        let raw_str = raw.to_string_lossy().into_owned();
        if positional_only {
            set_positional(&mut args, raw)?;
            continue;
        }
        if raw_str == "--" {
            positional_only = true;
            continue;
        }
        match raw_str.as_str() {
            "-h" | "--help" => args.help = true,
            "-V" | "--version" => args.version = true,
            "-L" | "--list" => args.list = true,
            "-d" | "--decompress" => args.decompress = true,
            "-c" | "--stdout" => args.stdout = true,
            "-k" | "--keep" => args.keep = true,
            "-f" | "--force" => args.force = true,
            "--ignore-trailing" => args.ignore_trailing = true,
            "--no-mmap" => args.no_mmap = true,
            "-t" | "--type" => {
                let v = iter.next().ok_or(ParseError::MissingValue("-t"))?;
                args.algorithm = Some(v.to_string_lossy().into_owned());
            }
            "-o" | "--output" => {
                let v = iter.next().ok_or(ParseError::MissingValue("-o"))?;
                args.output = Some(PathBuf::from(v));
            }
            "-l" | "--level" => {
                let v = iter
                    .next()
                    .ok_or(ParseError::MissingValue("-l"))?
                    .to_string_lossy()
                    .into_owned();
                args.level = Some(v.parse().map_err(|_| ParseError::BadLevel(v))?);
            }
            "--max-output" => {
                let v = iter
                    .next()
                    .ok_or(ParseError::MissingValue("--max-output"))?
                    .to_string_lossy()
                    .into_owned();
                args.max_output = Some(parse_size(&v).ok_or(ParseError::BadSize(v))?);
            }
            s if s.starts_with("--max-output=") => {
                let v = &s["--max-output=".len()..];
                args.max_output =
                    Some(parse_size(v).ok_or_else(|| ParseError::BadSize(v.to_string()))?);
            }
            s if s.starts_with("--type=") => {
                args.algorithm = Some(s["--type=".len()..].to_string());
            }
            s if s.starts_with("--output=") => {
                args.output = Some(PathBuf::from(&s["--output=".len()..]));
            }
            s if s.starts_with("--level=") => {
                let v = &s["--level=".len()..];
                args.level = Some(v.parse().map_err(|_| ParseError::BadLevel(v.to_string()))?);
            }
            s if s.starts_with("-t") && s.len() > 2 => {
                args.algorithm = Some(s[2..].to_string());
            }
            s if s.starts_with("-o") && s.len() > 2 => {
                args.output = Some(PathBuf::from(&s[2..]));
            }
            s if s.starts_with("-l") && s.len() > 2 => {
                let v = &s[2..];
                args.level = Some(v.parse().map_err(|_| ParseError::BadLevel(v.to_string()))?);
            }
            s if s.starts_with('-') && s != "-" => {
                return Err(ParseError::UnknownFlag(s.to_string()));
            }
            _ => set_positional(&mut args, raw)?,
        }
    }
    Ok(args)
}

/// Parse a byte count: a decimal integer, optionally followed by a binary
/// multiplier — `K`, `M`, `G` or `T` (case-insensitive, optionally spelled
/// `KiB` etc.), each a power of 1024. `None` if malformed or beyond `u64`.
fn parse_size(s: &str) -> Option<u64> {
    let digits = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (number, suffix) = s.split_at(digits);
    let number: u64 = number.parse().ok()?;
    let shift = match suffix.to_ascii_lowercase().as_str() {
        "" => 0,
        "k" | "kib" => 10,
        "m" | "mib" => 20,
        "g" | "gib" => 30,
        "t" | "tib" => 40,
        _ => return None,
    };
    number.checked_mul(1u64 << shift)
}

fn set_positional(args: &mut Args, raw: OsString) -> Result<(), ParseError> {
    if args.input.is_some() {
        return Err(ParseError::ExtraPositional(
            raw.to_string_lossy().into_owned(),
        ));
    }
    args.input = Some(PathBuf::from(raw));
    Ok(())
}

// ─── streaming ───────────────────────────────────────────────────────────

const BUF_SIZE: usize = 64 * 1024;

fn stream_encode(
    mut enc: Box<dyn Encoder>,
    reader: &mut dyn Read,
    writer: &mut dyn Write,
) -> io::Result<()> {
    use compcol::Status;
    let mut in_buf = [0u8; BUF_SIZE];
    let mut out_buf = [0u8; BUF_SIZE];

    loop {
        let n = reader.read(&mut in_buf)?;
        if n == 0 {
            break;
        }
        let mut consumed = 0;
        while consumed < n {
            let (p, status) = enc
                .encode(&in_buf[consumed..n], &mut out_buf)
                .map_err(codec_err)?;
            writer.write_all(&out_buf[..p.written])?;
            consumed += p.consumed;
            match status {
                Status::InputEmpty => break,
                // "Drain and call again" — unless nothing moved, in which
                // case calling again would spin on unchanged state forever.
                Status::OutputFull => {
                    if p.consumed == 0 && p.written == 0 {
                        return Err(io::Error::other("encoder stalled with input pending"));
                    }
                }
                Status::StreamEnd => break,
            }
        }
    }

    loop {
        let (p, status) = enc.finish(&mut out_buf).map_err(codec_err)?;
        writer.write_all(&out_buf[..p.written])?;
        match status {
            Status::StreamEnd => break,
            Status::OutputFull | Status::InputEmpty => {
                if p.written == 0 {
                    return Err(io::Error::other("encoder stalled in finish"));
                }
            }
        }
    }

    Ok(())
}

/// Decode `reader` into `writer`.
///
/// Returns whether input was left over once the decoder reported the end of
/// the stream — bytes that belong to no stream this decoder understands. The
/// caller decides whether that is an error. Nothing past the read that
/// carried the end of the stream is consumed beyond a single probing byte.
fn stream_decode(
    mut dec: Box<dyn Decoder>,
    reader: &mut dyn Read,
    writer: &mut dyn Write,
) -> io::Result<bool> {
    use compcol::Status;
    let mut in_buf = [0u8; BUF_SIZE];
    let mut out_buf = [0u8; BUF_SIZE];
    let mut trailing = false;

    'input: loop {
        let n = reader.read(&mut in_buf)?;
        if n == 0 {
            break;
        }
        let mut consumed = 0;
        while consumed < n {
            let (p, status) = dec
                .decode(&in_buf[consumed..n], &mut out_buf)
                .map_err(codec_err)?;
            writer.write_all(&out_buf[..p.written])?;
            consumed += p.consumed;
            match status {
                Status::InputEmpty => break,
                // "Drain and call again" — unless nothing moved, in which
                // case calling again would spin on unchanged state forever.
                Status::OutputFull => {
                    if p.consumed == 0 && p.written == 0 {
                        return Err(io::Error::other("decoder stalled with input pending"));
                    }
                }
                // The stream is over. Whatever input remains — the rest of
                // this buffer, or anything still unread — is trailing data.
                // (Formats that allow concatenated members, like gzip, are
                // handled inside the decoder and don't end here.) Stop
                // reading: the decoder would not take any of it.
                Status::StreamEnd => {
                    trailing = consumed < n || has_more_input(reader)?;
                    break 'input;
                }
            }
        }
    }

    // Drain any decoded output the decoder still holds internally before
    // declaring end-of-input. Some codecs (notably bzip2) decode a whole block
    // into an internal buffer that can exceed the caller's output buffer; once
    // the compressed input is fully consumed, the decode loop above stops
    // (its `consumed < n` guard is false) with that buffer still pending. Pull
    // the rest out with empty-input `decode` calls until nothing more is
    // produced — mirroring the streaming contract the library exercises.
    loop {
        let (p, _status) = dec.decode(&[], &mut out_buf).map_err(codec_err)?;
        writer.write_all(&out_buf[..p.written])?;
        if p.written == 0 {
            break;
        }
    }

    loop {
        let (p, status) = dec.finish(&mut out_buf).map_err(codec_err)?;
        writer.write_all(&out_buf[..p.written])?;
        match status {
            Status::StreamEnd => break,
            Status::OutputFull | Status::InputEmpty => {
                if p.written == 0 {
                    return Err(io::Error::other("decoder stalled in finish"));
                }
            }
        }
    }

    Ok(trailing)
}

/// Whether `reader` has at least one more byte. Reads (and drops) that one
/// byte: enough to know, without buffering what follows.
fn has_more_input(reader: &mut dyn Read) -> io::Result<bool> {
    let mut probe = [0u8; 1];
    loop {
        match reader.read(&mut probe) {
            Ok(n) => return Ok(n > 0),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
}

/// A codec error carried inside an `io::Error`. The library's `Error` is
/// only a `std::error::Error` with its `std` feature on, which this binary
/// does not require.
#[derive(Debug)]
struct CodecError(compcol::Error);

impl std::fmt::Display for CodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for CodecError {}

/// Wrap a codec error, keeping the typed value so `run` can tell which one
/// it was (the `Display` output is the codec error's own).
fn codec_err(e: compcol::Error) -> io::Error {
    io::Error::other(CodecError(e))
}

/// Whether `e` is the codec error `kind`, as wrapped by [`codec_err`].
fn is_codec_err(e: &io::Error, kind: compcol::Error) -> bool {
    e.get_ref()
        .and_then(|inner| inner.downcast_ref::<CodecError>())
        .is_some_and(|inner| inner.0 == kind)
}

/// Read up to `n` bytes from `reader`, returning what was available (possibly
/// fewer than `n` near EOF, or empty). Used to buffer a prefix for format
/// auto-detection without losing those bytes — the caller chains them back in
/// front of the stream.
fn read_up_to(reader: &mut dyn Read, n: usize) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    let mut filled = 0;
    while filled < n {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(got) => filled += got,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    buf.truncate(filled);
    Ok(buf)
}

// ─── output-path derivation ──────────────────────────────────────────────

enum Output {
    Stdout,
    File(PathBuf),
}

fn derive_output(args: &Args, algo: &str) -> Result<Output, String> {
    if args.stdout {
        return Ok(Output::Stdout);
    }
    if let Some(p) = &args.output {
        return Ok(Output::File(p.clone()));
    }
    let input = match &args.input {
        Some(p) => p,
        None => return Ok(Output::Stdout),
    };

    let ext = factory::extension(algo).ok_or_else(|| {
        format!("no default extension for algorithm '{algo}'; use -c or -o to pick output")
    })?;

    if args.decompress {
        match strip_extension(input, ext)? {
            Some(stripped) => Ok(Output::File(stripped)),
            None => Err(format!(
                "input {} doesn't end with '.{ext}'; use -o PATH",
                input.display()
            )),
        }
    } else {
        // Append `.<ext>` to the input path.
        let mut new_name = input.clone().into_os_string();
        new_name.push(".");
        new_name.push(ext);
        Ok(Output::File(PathBuf::from(new_name)))
    }
}

/// Strip a trailing `.<ext>` from `input`, returning `Ok(None)` when the
/// path doesn't end with it.
///
/// The path is never round-tripped through a lossy string conversion: a name
/// that isn't valid Unicode must keep its exact bytes, or the output would
/// land under a different (mangled, possibly colliding) name while the input
/// is removed.
#[cfg(unix)]
fn strip_extension(input: &Path, ext: &str) -> Result<Option<PathBuf>, String> {
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    let suffix = format!(".{ext}");
    Ok(input
        .as_os_str()
        .as_bytes()
        .strip_suffix(suffix.as_bytes())
        .map(|stem| PathBuf::from(OsString::from_vec(stem.to_vec()))))
}

/// Non-unix fallback: without a safe way to slice the platform's native
/// encoding, only valid-Unicode paths are handled; anything else is refused
/// rather than written under a mangled name.
#[cfg(not(unix))]
fn strip_extension(input: &Path, ext: &str) -> Result<Option<PathBuf>, String> {
    let Some(s) = input.to_str() else {
        return Err(format!(
            "input {} is not valid Unicode, so the output name can't be derived; use -o PATH",
            input.display()
        ));
    };
    let suffix = format!(".{ext}");
    Ok(s.strip_suffix(&suffix).map(PathBuf::from))
}

/// Permission bits of `f` if it is a regular file, for copying onto the
/// output. `None` for pipes, devices and the like — and always on platforms
/// without unix permission bits, where the output keeps its default ACL.
fn regular_file_mode(f: &File) -> Option<u32> {
    f.metadata()
        .ok()
        .filter(|m| m.is_file())
        .and_then(|m| mode_bits(&m))
}

/// An output file being written.
struct FileOutput {
    file: File,
    /// The path the data is going to, removed if the run fails: the
    /// destination itself (created exclusively, so it is ours), or the
    /// temporary file of a `--force` run. `None` when writing into something
    /// that isn't a regular file (`-f -o /dev/null`), which is never removed.
    written_at: Option<PathBuf>,
    /// For a `--force` run: the destination `written_at` is renamed onto
    /// once it is complete.
    rename_to: Option<PathBuf>,
    /// Permission bits to give the finished file (unix).
    final_mode: Option<u32>,
}

impl FileOutput {
    /// Undo a failed run: remove what was written, leaving any existing
    /// destination of a `--force` run as it was.
    fn discard(self) {
        // Close first, so the removal is immediate on every platform.
        drop(self.file);
        if let Some(p) = &self.written_at {
            let _ = std::fs::remove_file(p);
        }
    }

    /// Finish a successful run: set the final permission bits and, for a
    /// `--force` run, move the completed file onto its destination.
    fn commit(self) -> io::Result<()> {
        let Self {
            file,
            written_at,
            rename_to,
            final_mode,
        } = self;
        // Failing to set the mode leaves the file no more accessible than
        // intended (a file we created is still owner-only), so warn rather
        // than fail the whole run.
        if let Some(mode) = final_mode
            && let Err(e) = set_mode(&file, mode)
            && let Some(shown) = rename_to.as_ref().or(written_at.as_ref())
        {
            eprintln!(
                "compcol: warning: could not set permissions on {}: {e}",
                shown.display()
            );
        }
        // Close before renaming: not every platform lets an open file be
        // moved over another.
        drop(file);
        if let (Some(temp), Some(dest)) = (&written_at, &rename_to)
            && let Err(e) = std::fs::rename(temp, dest)
        {
            let _ = std::fs::remove_file(temp);
            return Err(io::Error::new(
                e.kind(),
                format!("replace {}: {e}", dest.display()),
            ));
        }
        Ok(())
    }
}

/// Create the output file for `dest`.
///
/// Without `force` the destination is created exclusively (`O_EXCL`) and
/// written in place. That is already race-free — there is no gap between an
/// existence check and the open — and never follows a symlink, dangling or
/// not; nothing else can exist under that name, so there is nothing to
/// preserve if the run fails, and the partial file is simply removed. (A
/// temporary file put in place with a no-replace `hard_link` would give the
/// same guarantee, but hard links don't exist on FAT/exFAT and some network
/// file systems, where it would turn every plain run into an error.)
///
/// With `force` an existing destination must survive a failed run, and a
/// symlink there must not be written through. So the data goes to a new,
/// exclusively created file in the same directory, which [`run`] renames
/// over the destination only once the stream is complete: the old file stays
/// untouched until then, and `rename` replaces a symlink rather than
/// following it. The existence of the destination is never consulted, so
/// there is no check-then-open race either.
///
/// The exception is a `force` destination that exists but is neither a
/// regular file nor a directory — a device, FIFO or socket, directly or
/// through a symlink (`-f -o /dev/null`, `/dev/stdout`). It can't sensibly
/// be replaced by a rename and holds no data to protect, so it is opened and
/// written directly.
///
/// `input_mode` is the input's permission bits when it is a regular file.
/// The output then starts out owner-only (0600 on unix) rather than
/// `0666 & !umask`, so the data is never exposed more widely than the input
/// was while it is being written, and gets `input_mode` once complete. With
/// no input mode (stdin), a `force` run that replaces a regular file keeps
/// that file's mode, as overwriting it in place used to.
fn open_file_output(
    dest: &Path,
    force: bool,
    input_mode: Option<u32>,
) -> Result<FileOutput, RunError> {
    let create_err = |e: io::Error| {
        RunError::Io(io::Error::new(
            e.kind(),
            format!("create {}: {e}", dest.display()),
        ))
    };

    if !force {
        let file = new_file_options(input_mode.is_some())
            .open(dest)
            .map_err(|e| {
                if e.kind() == io::ErrorKind::AlreadyExists {
                    RunError::Usage(format!(
                        "output exists: {} (use -f to overwrite)",
                        dest.display()
                    ))
                } else {
                    create_err(e)
                }
            })?;
        return Ok(FileOutput {
            file,
            written_at: Some(dest.to_path_buf()),
            rename_to: None,
            final_mode: input_mode,
        });
    }

    // What the destination resolves to (following symlinks), if anything.
    if let Ok(target) = std::fs::metadata(dest) {
        if target.is_dir() {
            return Err(create_err(io::Error::new(
                io::ErrorKind::IsADirectory,
                "is a directory",
            )));
        }
        if !target.is_file() {
            let file = OpenOptions::new()
                .write(true)
                .open(dest)
                .map_err(create_err)?;
            // Opened without create or truncate, so if the path was swapped
            // for a regular file in the meantime nothing has been lost yet:
            // refuse rather than overwrite it in place.
            if file.metadata().map_err(create_err)?.is_file() {
                return Err(create_err(io::Error::other(
                    "changed while it was being opened",
                )));
            }
            return Ok(FileOutput {
                file,
                written_at: None,
                rename_to: None,
                final_mode: None,
            });
        }
    }

    // The mode of the regular file being replaced. A symlink is replaced
    // itself, so whatever it points to doesn't lend its mode.
    let replaced_mode = std::fs::symlink_metadata(dest)
        .ok()
        .filter(|m| m.is_file())
        .and_then(|m| mode_bits(&m));
    let final_mode = input_mode.or(replaced_mode);

    let dir = match dest.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    let (file, temp) = create_temp_file(dir, final_mode.is_some()).map_err(|e| {
        RunError::Io(io::Error::new(
            e.kind(),
            format!(
                "create temporary file in {} for {}: {e}",
                dir.display(),
                dest.display()
            ),
        ))
    })?;
    Ok(FileOutput {
        file,
        written_at: Some(temp),
        rename_to: Some(dest.to_path_buf()),
        final_mode,
    })
}

/// Options that create a new file exclusively — failing if anything, even a
/// dangling symlink, already has the name — owner-only on unix if asked.
fn new_file_options(owner_only: bool) -> OpenOptions {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    // A shared writable mapping of the file needs it open for reading too.
    #[cfg(feature = "mmap")]
    opts.read(true);
    #[cfg(unix)]
    if owner_only {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    #[cfg(not(unix))]
    let _ = owner_only;
    opts
}

/// Create a new, uniquely named file in `dir`.
///
/// The name combines the process id with a value from the standard
/// library's randomly seeded hasher, so it can't be guessed ahead of time;
/// and since the file is created exclusively, a name that does already exist
/// (as a file or a planted symlink) is never opened — another one is tried.
fn create_temp_file(dir: &Path, owner_only: bool) -> io::Result<(File, PathBuf)> {
    use std::hash::{BuildHasher, Hasher};

    let pid = std::process::id();
    for attempt in 0u32..64 {
        let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
        hasher.write_u32(attempt);
        let path = dir.join(format!(".compcol-{pid}-{:016x}.tmp", hasher.finish()));
        match new_file_options(owner_only).open(&path) {
            Ok(file) => return Ok((file, path)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "no unused temporary file name found",
    ))
}

/// Permission bits from `m`; `None` on platforms without unix permissions.
fn mode_bits(m: &std::fs::Metadata) -> Option<u32> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Some(m.mode() & 0o777)
    }
    #[cfg(not(unix))]
    {
        let _ = m;
        None
    }
}

/// Set the permission bits of the open output file to `mode`. Only regular
/// files are touched (`-f -o /dev/null` must not chmod the device); a no-op
/// on platforms without unix permission bits.
fn set_mode(f: &File, mode: u32) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if f.metadata()?.is_file() {
            f.set_permissions(std::fs::Permissions::from_mode(mode))?;
        }
    }
    #[cfg(not(unix))]
    let _ = (f, mode);
    Ok(())
}

/// Whether `input` and `output` name the same existing file.
///
/// On unix the device/inode pair is compared, which also catches hard links
/// and bind mounts; everywhere, the canonicalized paths are compared, which
/// catches different spellings and symlinks. A path that doesn't exist (the
/// usual case for the output) can't be the input, so any lookup failure
/// means "not the same".
fn is_same_file(input: &Path, output: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let (Ok(a), Ok(b)) = (std::fs::metadata(input), std::fs::metadata(output))
            && a.dev() == b.dev()
            && a.ino() == b.ino()
        {
            return true;
        }
    }
    match (std::fs::canonicalize(input), std::fs::canonicalize(output)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

// ─── memory-mapped output ────────────────────────────────────────────────

/// Decoding straight into a memory mapping of the output file.
///
/// A [`ContiguousDecoder`] reads its history from the output it has already
/// produced, so when that output is one mapping of the destination file the
/// decoder keeps no window: the page cache backs the dictionary, and the
/// kernel can write it out and drop it under memory pressure.
///
/// The size of the output is not known beforehand, so the file is grown
/// geometrically and mapped again whenever the decoder runs out of room, and
/// trimmed to the decoded length at the end.
///
/// Only files this process has itself just created are ever mapped — see
/// [`open`] and the safety comment on `map_file`.
#[cfg(feature = "mmap")]
mod mapped {
    use std::fs::File;
    use std::io::{self, Read, Seek, SeekFrom, Write};

    use compcol::{ContiguousDecoder, Status};
    use memmap2::{MmapMut, MmapOptions};

    use super::{BUF_SIZE, FileOutput, codec_err, has_more_input};

    /// How the mapped file grows.
    #[derive(Clone, Copy, Debug)]
    pub(super) struct Sizing {
        /// Length the file is first given.
        pub(super) initial: u64,
        /// The file at most doubles on each growth, by no more than this.
        pub(super) max_step: u64,
        /// Whether the blocks of the file are reserved, by writing zeros
        /// through the file handle, before the decoder is allowed to write
        /// to them through the mapping. Growing a file with `set_len` alone
        /// leaves it sparse on most unix file systems; a write through a
        /// mapping that then finds the disk full is not an error return but
        /// a SIGBUS. An ordinary `write` reports it as `ENOSPC` instead.
        /// (Windows allocates on `set_len`, so it is not done there.)
        pub(super) reserve: bool,
        /// Blocks are reserved ahead of the decoder this much at a time: as
        /// much again as is already reserved, clamped to these bounds. Small
        /// enough that little is written for a small output and that the
        /// zeroed pages are still in the page cache — not yet written out —
        /// when the decoder overwrites them.
        pub(super) reserve_min: u64,
        pub(super) reserve_max: u64,
        /// A decoder that asks for more room without having consumed or
        /// written anything, while it already has this much to write into,
        /// is taken to be stuck rather than short of space.
        pub(super) stall_room: u64,
    }

    impl Sizing {
        /// The sizing for a real run. `input_len` is the size of the
        /// compressed input when it is a regular file.
        pub(super) fn for_input(input_len: Option<u64>) -> Self {
            // A multiple of the page size (and of the Windows allocation
            // granularity) everywhere.
            const UNIT: u64 = 64 * 1024;
            const MIB: u64 = 1024 * 1024;
            let guess = input_len
                .unwrap_or(0)
                .saturating_mul(4)
                .clamp(4 * MIB, 1024 * MIB);
            Self {
                initial: guess.next_multiple_of(UNIT),
                max_step: 1024 * MIB,
                reserve: cfg!(not(windows)),
                reserve_min: 256 * 1024,
                reserve_max: 16 * MIB,
                stall_room: 256 * MIB,
            }
        }
    }

    /// The output file, mapped from its first byte.
    pub(super) struct MappedOutput {
        /// A handle of our own on the output file (the caller keeps its).
        file: File,
        /// The mapping, `len` bytes long. `None` only while the file is
        /// being resized.
        map: Option<MmapMut>,
        /// Current length of the file and of the mapping. Never 0: an empty
        /// file cannot be mapped.
        len: usize,
        /// The decoder is given `map[..ready]`: the part whose blocks are
        /// reserved. Equal to `len` when nothing is reserved ahead.
        ready: usize,
        /// `len` never exceeds this: one byte more than the output limit
        /// (see [`MappedOutput::new`]), and what a mapping can address.
        cap: usize,
        /// The `--max-output` limit.
        limit: Option<u64>,
        sizing: Sizing,
    }

    impl MappedOutput {
        /// Give the empty `file` its first length and map it.
        pub(super) fn new(file: File, sizing: Sizing, limit: Option<u64>) -> io::Result<Self> {
            // One byte past the limit, so that a decoder which has produced
            // exactly `limit` bytes and reports `OutputFull` can be told
            // apart from one that has more to write: given a single spare
            // byte, the first leaves it alone (and goes on to read the
            // stream's trailer), the second uses it and is stopped. The
            // file never holds more than that one byte beyond the limit,
            // and a file over the limit is removed.
            let addressable = isize::MAX as usize;
            let cap = match limit {
                Some(limit) => usize::try_from(limit.saturating_add(1))
                    .unwrap_or(addressable)
                    .min(addressable),
                None => addressable,
            };
            let len = usize::try_from(sizing.initial).unwrap_or(cap).clamp(1, cap);
            file.set_len(len as u64)?;
            let map = map_file(&file, len)?;
            let mut out = Self {
                file,
                map: Some(map),
                len,
                ready: 0,
                cap,
                limit,
                sizing,
            };
            out.reserve_more()?;
            Ok(out)
        }

        /// The buffer the decoder writes into: the file from its first
        /// byte, as far as it may be written.
        fn buffer(&mut self) -> &mut [u8] {
            match &mut self.map {
                Some(map) => &mut map[..self.ready],
                // Unreachable: `grow` either restores the mapping or fails,
                // and a failure ends the run.
                None => &mut [],
            }
        }

        /// Account for `written` more decoded bytes after `filled`.
        fn advance(&self, filled: usize, written: usize) -> io::Result<usize> {
            let filled = filled
                .checked_add(written)
                .filter(|&n| n <= self.ready)
                .ok_or_else(|| {
                    io::Error::other("decoder reported more output than it had room for")
                })?;
            if self.limit.is_some_and(|limit| filled as u64 > limit) {
                return Err(codec_err(compcol::Error::OutputLimitExceeded));
            }
            Ok(filled)
        }

        /// The decoder reported `OutputFull` with `filled` bytes decoded;
        /// `progressed` says whether that call consumed or wrote anything.
        fn make_room(&mut self, filled: usize, progressed: bool) -> io::Result<()> {
            let room = self.ready - filled;
            if progressed && room > 0 {
                // Not actually full: call it again as it is.
                return Ok(());
            }
            if !progressed && room as u64 >= self.sizing.stall_room {
                return Err(io::Error::other("decoder stalled with room to write"));
            }
            self.grow()
        }

        /// Make `buffer()` longer, keeping its contents.
        fn grow(&mut self) -> io::Result<()> {
            if self.ready < self.len {
                return self.reserve_more();
            }
            if self.len >= self.cap {
                return Err(match self.limit {
                    Some(limit) if self.len as u64 > limit => {
                        codec_err(compcol::Error::OutputLimitExceeded)
                    }
                    _ => too_large(),
                });
            }
            let mut step = usize::try_from(self.sizing.max_step)
                .unwrap_or(usize::MAX)
                .min(self.len)
                .min(self.cap - self.len);
            // The mapping has to go before the file is resized (Windows
            // refuses otherwise), and it is replaced anyway.
            self.map = None;
            // Where growing a file allocates it right away, a large step
            // can fail on a disk that would have held the output: settle
            // for less before giving up.
            const SMALLEST_STEP: usize = 64 * 1024;
            loop {
                match self.file.set_len((self.len + step) as u64) {
                    Ok(()) => break,
                    Err(_) if step > SMALLEST_STEP => step /= 2,
                    Err(e) => return Err(e),
                }
            }
            self.len += step;
            self.map = Some(map_file(&self.file, self.len).map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!("map {} bytes of output: {e} (pass --no-mmap)", self.len),
                )
            })?);
            self.reserve_more()
        }

        /// Extend `ready` towards `len`, reserving the blocks in between.
        fn reserve_more(&mut self) -> io::Result<()> {
            if !self.sizing.reserve {
                self.ready = self.len;
                return Ok(());
            }
            let chunk = (self.ready as u64).clamp(
                self.sizing.reserve_min.max(1),
                self.sizing.reserve_max.max(1),
            );
            let end = usize::try_from(chunk)
                .ok()
                .and_then(|chunk| self.ready.checked_add(chunk))
                .map_or(self.len, |end| end.min(self.len));
            // Nothing has been decoded into this range yet (it lies past
            // `ready`), so zeros are all there is to keep.
            self.file.seek(SeekFrom::Start(self.ready as u64))?;
            static ZEROS: [u8; BUF_SIZE] = [0; BUF_SIZE];
            let mut left = end - self.ready;
            while left > 0 {
                let n = left.min(ZEROS.len());
                self.file.write_all(&ZEROS[..n])?;
                left -= n;
            }
            self.ready = end;
            Ok(())
        }

        /// The stream is complete at `filled` bytes: write the mapping out
        /// and cut the file to that length.
        fn finish(mut self, filled: usize) -> io::Result<()> {
            if let Some(map) = self.map.take() {
                // Wait for the decoded pages to be written out. An I/O error
                // doing that has nowhere else to be reported: without this
                // it would be lost, and in-place mode would go on to remove
                // the input. (What lies past `filled` is about to be cut
                // off.) This is the one thing the streaming path does not
                // pay for: it leaves its output in the page cache.
                if filled > 0 {
                    map.flush_range(0, filled)?;
                }
                // Unmapped before truncating: Windows refuses to shorten a
                // file that is mapped.
                drop(map);
            }
            self.file.set_len(filled as u64)
        }

        /// Give up on mapping `file` before anything was decoded: make it
        /// the empty file, written from the start, that it was.
        pub(super) fn undo(mut file: &File) -> io::Result<()> {
            file.set_len(0)?;
            file.seek(SeekFrom::Start(0))?;
            Ok(())
        }
    }

    fn too_large() -> io::Error {
        io::Error::other("output too large to map into memory (pass --no-mmap)")
    }

    /// Map the first `len` bytes of `file`, shared and writable.
    ///
    /// The only `unsafe` in the binary.
    #[allow(unsafe_code)]
    fn map_file(file: &File, len: usize) -> io::Result<MmapMut> {
        if len == 0 {
            // Mapping nothing is an error on some platforms and a trap on
            // others; no caller asks for it.
            return Err(io::Error::other("cannot map an empty file"));
        }
        // SAFETY: a file mapping is shared memory, and the `&mut [u8]` it
        // is handed out as promises nothing else changes those bytes — a
        // promise the operating system does not keep for us. If another
        // process wrote to the file while it is mapped, the decoder would
        // read history that changed under it (garbage output, and formally
        // undefined behaviour); if another process truncated it, touching
        // the pages past the new end would kill this process with SIGBUS
        // (an access violation on Windows). So does running out of disk
        // space under a page that has no block yet, which is what
        // `Sizing::reserve` is for.
        //
        // What makes this acceptable is where `file` comes from. `open` is
        // the only source outside the tests, and it maps nothing but a
        // regular file that this process created exclusively moments ago
        // (`create_new`: the destination itself, or the randomly named
        // temporary file of a `--force` run), that is still empty, and — on
        // unix, where the mode says so — that no other user may write to:
        // it is created 0600 whenever the input is a regular file, and a
        // file left group- or world-writable by the umask is not mapped.
        // (On Windows the new file has the ACL of its directory, as any
        // file the CLI writes.) It never maps a pre-existing destination,
        // a device, a FIFO or stdout. Interfering therefore takes a process
        // of the same user that goes looking for the file while it is being
        // written — one that could just as well kill or debug us. This
        // narrows the hazard; it does not remove it, which is why
        // `--no-mmap` exists. `len` is non-zero and no larger than the file,
        // which was given that length before this call; the file is only
        // ever shortened after the mapping is dropped.
        unsafe { MmapOptions::new().len(len).map_mut(file) }
    }

    /// Map the output file `out` if it can be: a regular file the CLI has
    /// just created, still empty, writable by no one else.
    ///
    /// `Ok(None)` means "use the streaming path": the file is as it was.
    /// An error means it could not be put back that way.
    pub(super) fn open(
        out: &FileOutput,
        input_len: Option<u64>,
        limit: Option<u64>,
    ) -> io::Result<Option<MappedOutput>> {
        // No path to remove on failure means the output is not ours: a
        // device or FIFO opened in place by `--force`.
        if out.written_at.is_none() {
            return Ok(None);
        }
        let Ok(meta) = out.file.metadata() else {
            return Ok(None);
        };
        if !meta.is_file() || meta.len() != 0 {
            return Ok(None);
        }
        // With a regular input file the output is created owner-only. From
        // stdin it is created with the default mode, which the umask may
        // leave writable by the group or by everyone: not to be mapped.
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if meta.mode() & 0o022 != 0 {
                return Ok(None);
            }
        }
        let Ok(file) = out.file.try_clone() else {
            return Ok(None);
        };
        match MappedOutput::new(file, Sizing::for_input(input_len), limit) {
            Ok(map) => Ok(Some(map)),
            // An unsupported file system, no address space, not even room
            // for the first blocks: nothing has been decoded, so the
            // streaming path can still take over. (`new` has dropped the
            // mapping and its handle; the caller's shares its position.)
            Err(_) => MappedOutput::undo(&out.file).map(|()| None),
        }
    }

    /// Decode `reader` into `out`, leaving the file with exactly the decoded
    /// bytes. The counterpart of [`stream_decode`](super::stream_decode),
    /// with the same result: whether input was left over after the end of
    /// the stream.
    ///
    /// On an error the file is left in an unspecified state for the caller
    /// to remove; the mapping and this function's handle on the file are
    /// gone by the time it returns.
    pub(super) fn decode(
        mut dec: Box<dyn ContiguousDecoder>,
        reader: &mut dyn Read,
        mut out: MappedOutput,
    ) -> io::Result<bool> {
        let mut in_buf = [0u8; BUF_SIZE];
        let mut filled = 0usize;
        let mut trailing = false;

        'input: loop {
            let n = reader.read(&mut in_buf)?;
            if n == 0 {
                break;
            }
            let mut consumed = 0;
            while consumed < n {
                let (p, status) = dec
                    .decode_contiguous(&in_buf[consumed..n], out.buffer(), filled)
                    .map_err(codec_err)?;
                consumed += p.consumed;
                filled = out.advance(filled, p.written)?;
                match status {
                    Status::InputEmpty => break,
                    Status::OutputFull => {
                        out.make_room(filled, p.consumed != 0 || p.written != 0)?;
                    }
                    // As in `stream_decode`: what remains is trailing data.
                    Status::StreamEnd => {
                        trailing = consumed < n || has_more_input(reader)?;
                        break 'input;
                    }
                }
            }
        }

        // The same two steps as `stream_decode`: pull out what the decoder
        // still holds, then declare the end of the input.
        loop {
            let (p, status) = dec
                .decode_contiguous(&[], out.buffer(), filled)
                .map_err(codec_err)?;
            filled = out.advance(filled, p.written)?;
            if status == Status::OutputFull && (p.written != 0 || out.ready == filled) {
                out.make_room(filled, p.written != 0)?;
            } else if p.written == 0 {
                break;
            }
        }

        loop {
            let (p, status) = dec
                .finish_contiguous(out.buffer(), filled)
                .map_err(codec_err)?;
            filled = out.advance(filled, p.written)?;
            match status {
                Status::StreamEnd => break,
                Status::OutputFull => out.make_room(filled, p.written != 0)?,
                Status::InputEmpty => {
                    if p.written == 0 {
                        return Err(io::Error::other("decoder stalled in finish"));
                    }
                }
            }
        }

        out.finish(filled)?;
        Ok(trailing)
    }
}

// ─── main ────────────────────────────────────────────────────────────────

fn main() -> ExitCode {
    let argv: Vec<OsString> = env::args_os().skip(1).collect();
    let args = match parse_args(argv) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("compcol: {e}");
            eprintln!("Try 'compcol --help' for more information.");
            return ExitCode::from(2);
        }
    };

    if args.help {
        print!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    if args.version {
        println!("compcol {VERSION}");
        return ExitCode::SUCCESS;
    }
    if args.list {
        for name in factory::names() {
            println!("{name}");
        }
        return ExitCode::SUCCESS;
    }
    // `-t ALGO` is required for compression, and for decompression unless the
    // format can be auto-detected from the input's leading magic bytes (see
    // `run`). Only reject "no algorithm" outright on compress; on decompress
    // we defer to detection.
    if args.algorithm.is_none() && !args.decompress {
        eprintln!("compcol: -t ALGO is required (or pass --list / --help)");
        return ExitCode::from(2);
    }

    if args.stdout && args.output.is_some() {
        eprintln!("compcol: -c and -o are mutually exclusive");
        return ExitCode::from(2);
    }

    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(RunError::Usage(msg)) => {
            eprintln!("compcol: {msg}");
            ExitCode::from(2)
        }
        Err(RunError::Io(e)) => {
            eprintln!("compcol: {e}");
            ExitCode::FAILURE
        }
    }
}

enum RunError {
    Usage(String),
    Io(io::Error),
}

impl From<io::Error> for RunError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// The codec selected for this run, resolved before any output is opened.
enum Codec {
    Encoder(Box<dyn Encoder>),
    Decoder(Box<dyn Decoder>),
}

/// Number of leading bytes buffered for format auto-detection. The longest
/// magic we examine is the StuffIt-classic check, which reaches byte 13, so a
/// 16-byte window is comfortably sufficient.
const PEEK_LEN: usize = 16;

/// The archive format `prefix` belongs to, if it starts with the magic of a
/// multi-member container rather than of a single compressed stream.
///
/// These are the magics [`factory::detect`] answers with a container *hint*
/// — the name of a codec used for members inside such an archive (`rar1`,
/// `rar2`, `rar3`, `rar5` for RAR; `arsenic` for StuffIt), not of something
/// that can decode the file. They are matched here directly so the answer
/// doesn't depend on which of those codecs are compiled in; `detected` is
/// checked as well, so a hint that `detect` derives some other way is still
/// never auto-dispatched.
fn archive_kind(prefix: &[u8], detected: Option<&str>) -> Option<&'static str> {
    // RAR 1.5–4.x ("Rar!\x1A\x07\x00") and RAR 5 ("Rar!\x1A\x07\x01\x00").
    if prefix.starts_with(b"Rar!\x1A\x07") {
        return Some("RAR");
    }
    // StuffIt classic ("SIT!" with the "rLau" signature at offset 10) and
    // StuffIt 5 ("StuffIt (c)...").
    if (prefix.len() >= 14 && prefix.starts_with(b"SIT!") && &prefix[10..14] == b"rLau")
        || prefix.starts_with(b"StuffIt")
    {
        return Some("StuffIt");
    }
    match detected {
        Some("rar1" | "rar2" | "rar3" | "rar5") => Some("RAR"),
        Some("arsenic") => Some("StuffIt"),
        _ => None,
    }
}

const TRAILING_DATA: &str = "trailing data after the end of the compressed stream";

fn run(args: &Args) -> Result<(), RunError> {
    if args.decompress && args.level.is_some() {
        // Decompressors don't have a level — flag it rather than silently
        // ignore so users notice the mistake. Checked up front, before any
        // output file is created.
        return Err(RunError::Usage(
            "--level is only meaningful on compression (no -d)".into(),
        ));
    }
    if !args.decompress && args.max_output.is_some() {
        return Err(RunError::Usage(
            "--max-output is only meaningful on decompression (-d)".into(),
        ));
    }
    if !args.decompress && args.ignore_trailing {
        return Err(RunError::Usage(
            "--ignore-trailing is only meaningful on decompression (-d)".into(),
        ));
    }
    if !args.decompress && args.no_mmap {
        return Err(RunError::Usage(
            "--no-mmap is only meaningful on decompression (-d)".into(),
        ));
    }

    // For in-place mode (input file + no -c/-o), we also remove the input on
    // success unless -k. Capture that decision up front.
    let in_place = args.input.is_some() && !args.stdout && args.output.is_none();
    let should_remove_input = in_place && !args.keep;

    // Reader. When the input is a regular file, remember its permission bits
    // so a file output can be given the same ones (see `open_file_output`).
    let mut input_mode: Option<u32> = None;
    // Its size, when it is a regular file: the basis for a first guess at
    // how large a mapped output has to be.
    #[cfg(feature = "mmap")]
    let mut input_len: Option<u64> = None;
    let mut reader: Box<dyn Read> = if let Some(p) = &args.input {
        let f = File::open(p).map_err(|e| {
            RunError::Io(io::Error::new(
                e.kind(),
                format!("open {}: {e}", p.display()),
            ))
        })?;
        input_mode = regular_file_mode(&f);
        #[cfg(feature = "mmap")]
        {
            input_len = f.metadata().ok().filter(|m| m.is_file()).map(|m| m.len());
        }
        Box::new(BufReader::new(f))
    } else {
        Box::new(BufReader::new(io::stdin()))
    };

    // Resolve the algorithm. If the user passed `-t`, use it verbatim. On
    // decompress with no `-t`, peek the leading bytes (without consuming them
    // from the logical stream — they're buffered and chained back in below)
    // and auto-detect the format from its magic bytes.
    let mut peeked: Vec<u8> = Vec::new();
    let algo: String = if let Some(a) = &args.algorithm {
        a.clone()
    } else {
        // Only reachable on decompress: main() rejects a missing -t on
        // compress before calling run().
        peeked = read_up_to(&mut reader, PEEK_LEN)?;
        let detected = factory::detect(&peeked);
        // For archive magics `detect` returns a member codec's name purely
        // as a format hint. Dispatching on it would feed the archive's own
        // headers and directory to a decoder for one member's raw stream.
        if let Some(kind) = archive_kind(&peeked, detected) {
            return Err(RunError::Usage(format!(
                "looks like a {kind} archive; compcol decodes single compressed \
                 streams, not archives — pass -t to force"
            )));
        }
        match detected {
            Some(name) => name.to_string(),
            None => {
                return Err(RunError::Usage(
                    "could not detect format; specify with --type (e.g. -t gzip)".into(),
                ));
            }
        }
    };
    // Re-prepend any bytes consumed for detection so the decoder sees the
    // whole stream.
    let mut reader: Box<dyn Read> = if peeked.is_empty() {
        reader
    } else {
        Box::new(io::Cursor::new(peeked).chain(reader))
    };

    // Resolve the codec BEFORE touching the output: an unknown algorithm must
    // not create an empty output file, nor (with --force) truncate an
    // existing one.
    let unknown = || RunError::Usage(format!("unknown algorithm: '{algo}' (use --list)"));
    let codec = if args.decompress {
        let dec = factory::decoder_by_name(&algo).ok_or_else(unknown)?;
        // --max-output: bound the decoded size. The wrapper also hands the
        // budget to the decoder itself, so codecs that build output
        // internally refuse early instead of allocating it first.
        Codec::Decoder(match args.max_output {
            Some(limit) => Box::new(LimitedDecoder::new(dec, limit)),
            None => dec,
        })
    } else {
        Codec::Encoder(
            match args.level {
                Some(level) => factory::encoder_by_name_with_level(&algo, level),
                None => factory::encoder_by_name(&algo),
            }
            .ok_or_else(unknown)?,
        )
    };

    let output = derive_output(args, &algo).map_err(RunError::Usage)?;

    // Writer, plus what is needed to finish or undo a file output.
    let stdout = io::stdout();
    let mut file_output: Option<FileOutput> = None;
    // Set when the output file is memory-mapped and decoded into directly
    // rather than written through `writer` (see the `mapped` module).
    #[cfg(feature = "mmap")]
    let mut mapped_output: Option<(Box<dyn compcol::ContiguousDecoder>, mapped::MappedOutput)> =
        None;
    let mut writer: Box<dyn Write> = match &output {
        Output::Stdout => Box::new(BufWriter::new(stdout.lock())),
        Output::File(p) => {
            // Refuse to write over the file we are reading. --force no
            // longer truncates its target up front, but replacing the input
            // under its own name with its (de)compressed form is never what
            // was asked for.
            if let Some(input) = &args.input
                && is_same_file(input, p)
            {
                return Err(RunError::Usage(format!(
                    "input and output are the same file: {}",
                    p.display()
                )));
            }
            let out = open_file_output(p, args.force, input_mode)?;
            // Decompressing into a file we have just created: map it and
            // let the decoder use it as its history, if this format has a
            // decoder that can. Whatever prevents the mapping from being
            // set up leaves the still-empty file to the streaming path.
            #[cfg(feature = "mmap")]
            if args.decompress
                && !args.no_mmap
                && let Some(mut contiguous) = factory::contiguous_decoder_by_name(&algo)
            {
                match mapped::open(&out, input_len, args.max_output) {
                    Ok(Some(map)) => {
                        // The mapping never grows past the limit (see
                        // `mapped::decode`); this lets a decoder that can
                        // tell earlier refuse earlier.
                        if let Some(limit) = args.max_output {
                            contiguous.set_output_limit(limit);
                        }
                        mapped_output = Some((contiguous, map));
                    }
                    Ok(None) => {}
                    Err(e) => {
                        out.discard();
                        return Err(RunError::Io(io::Error::new(
                            e.kind(),
                            format!("create {}: {e}", p.display()),
                        )));
                    }
                }
            }
            // The writer gets a second handle; the first stays in `out` so
            // the permission bits can be applied to this very file (not to
            // whatever the path names by then) once it is complete.
            let handle = match out.file.try_clone() {
                Ok(handle) => handle,
                Err(e) => {
                    out.discard();
                    return Err(RunError::Io(io::Error::new(
                        e.kind(),
                        format!("create {}: {e}", p.display()),
                    )));
                }
            };
            file_output = Some(out);
            Box::new(BufWriter::new(handle))
        }
    };

    // Undocumented diagnostic, for the test suite: say which of the two ways
    // the output is being written.
    if env::var_os("COMPCOL_DEBUG_IO").is_some() {
        #[cfg(feature = "mmap")]
        let via_mmap = mapped_output.is_some();
        #[cfg(not(feature = "mmap"))]
        let via_mmap = false;
        eprintln!("io: {}", if via_mmap { "mmap" } else { "stream" });
    }

    // From here on the output (or its temporary file) exists: every failure
    // — including the final flush — must go through the cleanup below rather
    // than an early `?`.
    let result = match codec {
        Codec::Decoder(dec) => {
            // Either way of decoding answers the same question — was input
            // left over? — and everything that follows from it is shared.
            #[cfg(feature = "mmap")]
            let decoded = match mapped_output.take() {
                Some((contiguous, map)) => {
                    drop(dec);
                    mapped::decode(contiguous, &mut *reader, map)
                }
                None => stream_decode(dec, &mut *reader, &mut *writer),
            };
            #[cfg(not(feature = "mmap"))]
            let decoded = stream_decode(dec, &mut *reader, &mut *writer);
            decoded.and_then(|trailing| {
                if !trailing {
                    return Ok(());
                }
                // Input left over after the end of the stream: the file is
                // not (just) what it claims to be — appended garbage, a
                // second stream in a format that has no notion of one, or a
                // truncated copy of something else. Succeeding would, in
                // in-place mode, delete an input whose content was only
                // partly accounted for. The rule is the same for every
                // output mode so that the exit status means the same thing
                // whether or not -c / -o is used.
                if args.ignore_trailing {
                    eprintln!("compcol: warning: {TRAILING_DATA} ignored");
                    // Keep reading to the end as the CLI always did, so a
                    // process piping into us isn't killed by a closed pipe.
                    let _ = io::copy(&mut *reader, &mut io::sink());
                    Ok(())
                } else {
                    Err(io::Error::other(format!(
                        "{TRAILING_DATA} (pass --ignore-trailing to accept it)"
                    )))
                }
            })
        }
        Codec::Encoder(enc) => stream_encode(enc, &mut *reader, &mut *writer),
    }
    .and_then(|()| writer.flush());

    // Release the file handle before removing or reporting anything.
    drop(writer);
    if let Err(e) = result {
        // Best-effort: remove the partial output, leave the input — and a
        // --force destination that already existed — intact.
        if let Some(out) = file_output {
            out.discard();
        }
        // Name the flag and the limit rather than the library's generic
        // "configured limit" wording.
        if let Some(limit) = args.max_output
            && is_codec_err(&e, compcol::Error::OutputLimitExceeded)
        {
            return Err(RunError::Io(io::Error::other(format!(
                "decompressed output exceeds the --max-output limit of {limit} bytes"
            ))));
        }
        return Err(RunError::Io(e));
    }

    // The output is complete: give it its final permissions and name. The
    // input is only removed once that has worked.
    if let Some(out) = file_output {
        out.commit()?;
    }

    if should_remove_input
        && let Some(p) = &args.input
        && let Err(e) = std::fs::remove_file(p)
    {
        return Err(RunError::Io(io::Error::new(
            e.kind(),
            format!("removing input {}: {e}", p.display()),
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use compcol::{Error, Progress, Status};

    /// A codec that reports `OutputFull` forever without consuming or
    /// producing anything. No real codec does this; the streaming loops must
    /// still terminate. To keep a regression from hanging the suite, the mock
    /// panics once it has been called far more often than a sane driver
    /// would.
    #[derive(Default)]
    struct Stalling {
        calls: u32,
    }

    impl Stalling {
        fn step(&mut self) -> Result<(Progress, Status), Error> {
            self.calls += 1;
            assert!(self.calls < 1000, "streaming loop spins on a stalled codec");
            Ok((Progress::default(), Status::OutputFull))
        }
    }

    impl Encoder for Stalling {
        fn encode(&mut self, _: &[u8], _: &mut [u8]) -> Result<(Progress, Status), Error> {
            self.step()
        }
        fn finish(&mut self, _: &mut [u8]) -> Result<(Progress, Status), Error> {
            Ok((Progress::default(), Status::StreamEnd))
        }
        fn reset(&mut self) {}
    }

    impl Decoder for Stalling {
        fn decode(&mut self, _: &[u8], _: &mut [u8]) -> Result<(Progress, Status), Error> {
            self.step()
        }
        fn finish(&mut self, _: &mut [u8]) -> Result<(Progress, Status), Error> {
            Ok((Progress::default(), Status::StreamEnd))
        }
        fn reset(&mut self) {}
        fn discard_output(&mut self, _: &[u8], _: usize) -> Result<(Progress, Status), Error> {
            self.step()
        }
    }

    #[test]
    fn stream_encode_errors_on_a_stalled_encoder() {
        let mut out = Vec::new();
        let err = stream_encode(
            Box::new(Stalling::default()),
            &mut &b"pending input"[..],
            &mut out,
        )
        .unwrap_err();
        assert!(err.to_string().contains("stalled"), "{err}");
    }

    #[test]
    fn stream_decode_errors_on_a_stalled_decoder() {
        let mut out = Vec::new();
        let err = stream_decode(
            Box::new(Stalling::default()),
            &mut &b"pending input"[..],
            &mut out,
        )
        .unwrap_err();
        assert!(err.to_string().contains("stalled"), "{err}");
    }

    /// A decoder whose stream is exactly `left` bytes long, copied verbatim.
    struct FixedLen {
        left: usize,
    }

    impl Decoder for FixedLen {
        fn decode(&mut self, input: &[u8], out: &mut [u8]) -> Result<(Progress, Status), Error> {
            let n = input.len().min(out.len()).min(self.left);
            out[..n].copy_from_slice(&input[..n]);
            self.left -= n;
            let status = if self.left == 0 {
                Status::StreamEnd
            } else {
                Status::InputEmpty
            };
            Ok((
                Progress {
                    consumed: n,
                    written: n,
                },
                status,
            ))
        }
        fn finish(&mut self, _: &mut [u8]) -> Result<(Progress, Status), Error> {
            if self.left == 0 {
                Ok((Progress::default(), Status::StreamEnd))
            } else {
                Err(Error::UnexpectedEnd)
            }
        }
        fn reset(&mut self) {}
        fn discard_output(&mut self, _: &[u8], _: usize) -> Result<(Progress, Status), Error> {
            unreachable!("the CLI never skips output")
        }
    }

    /// Hands out its chunks one per `read` (never joining two) and counts
    /// the bytes read.
    struct Chunked<'a> {
        chunks: std::collections::VecDeque<&'a [u8]>,
        bytes_read: usize,
    }

    impl Read for Chunked<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let Some(first) = self.chunks.front_mut() else {
                return Ok(0);
            };
            let n = first.len().min(buf.len());
            buf[..n].copy_from_slice(&first[..n]);
            *first = &first[n..];
            if first.is_empty() {
                self.chunks.pop_front();
            }
            self.bytes_read += n;
            Ok(n)
        }
    }

    fn decode_chunks(stream_len: usize, chunks: &[&[u8]]) -> (Vec<u8>, bool, usize) {
        let mut reader = Chunked {
            chunks: chunks.iter().copied().collect(),
            bytes_read: 0,
        };
        let mut out = Vec::new();
        let trailing = stream_decode(
            Box::new(FixedLen { left: stream_len }),
            &mut reader,
            &mut out,
        )
        .unwrap();
        (out, trailing, reader.bytes_read)
    }

    #[test]
    fn stream_decode_reports_no_trailing_data_on_a_clean_end() {
        let (out, trailing, _) = decode_chunks(6, &[b"abc", b"def"]);
        assert_eq!(out, b"abcdef");
        assert!(!trailing);
    }

    #[test]
    fn stream_decode_reports_trailing_data_in_the_same_read() {
        let (out, trailing, _) = decode_chunks(4, &[b"abcdXY"]);
        assert_eq!(out, b"abcd");
        assert!(trailing);
    }

    #[test]
    fn stream_decode_reports_trailing_data_in_a_later_read() {
        // The stream ends exactly at a read boundary: the leftover is only
        // visible by reading on.
        let (out, trailing, _) = decode_chunks(4, &[b"abcd", b"XY"]);
        assert_eq!(out, b"abcd");
        assert!(trailing);
    }

    #[test]
    fn stream_decode_does_not_read_through_trailing_data() {
        // One probing byte is enough to know; the megabytes behind it must
        // not be pulled in.
        let big = vec![0u8; 4096];
        let chunks: Vec<&[u8]> = [&b"abcd"[..], b"X"]
            .into_iter()
            .chain(std::iter::repeat_n(&big[..], 64))
            .collect();
        let (out, trailing, bytes_read) = decode_chunks(4, &chunks);
        assert_eq!(out, b"abcd");
        assert!(trailing);
        assert_eq!(bytes_read, 5);
    }

    /// The memory-mapped output path, driven by a mock decoder: no real
    /// codec is needed to check how the file is grown, re-mapped, limited,
    /// trimmed and cleaned up.
    #[cfg(feature = "mmap")]
    mod mapped_output {
        use super::super::mapped::{self, MappedOutput, Sizing};
        use super::super::*;
        use super::{Chunked, Stalling};
        use compcol::{ContiguousDecoder, Error, Progress, Status};
        use std::sync::atomic::{AtomicU64, Ordering};

        // Token bytes of the mock decoder's format.
        const LIT: u8 = b'L'; // LIT byte: that byte
        const COPY: u8 = b'C'; // COPY dist:u16le len:u16le: a match
        const HOLD: u8 = b'H'; // HOLD len:u16le: `len` × b'h', only at finish
        const END: u8 = b'E'; // end of stream
        const BAD: u8 = b'X'; // a corrupt stream

        /// What the decoder is in the middle of writing.
        enum Pending {
            Copy { dist: usize, left: usize },
            Held { left: usize },
        }

        /// A decoder for the toy format above that follows the
        /// [`ContiguousDecoder`] contract — matches are copied out of
        /// `output[..filled]` itself — and checks that its caller does: on
        /// every call `output[..filled]` must be exactly what it wrote.
        #[derive(Default)]
        struct Script {
            written: Vec<u8>,
            pending: Option<Pending>,
            held: usize,
            ended: bool,
        }

        impl Script {
            fn check(&self, output: &[u8], filled: usize) {
                assert_eq!(filled, self.written.len(), "wrong `filled`");
                assert!(
                    output[..filled] == self.written[..],
                    "output[..filled] is not what was decoded"
                );
            }

            /// Write as much of the pending operation as fits; whether it
            /// is done.
            fn emit(&mut self, output: &mut [u8], pos: &mut usize) -> bool {
                match &mut self.pending {
                    None => {}
                    Some(Pending::Copy { dist, left }) => {
                        while *left > 0 && *pos < output.len() {
                            output[*pos] = output[*pos - *dist];
                            self.written.push(output[*pos]);
                            *pos += 1;
                            *left -= 1;
                        }
                        if *left > 0 {
                            return false;
                        }
                    }
                    Some(Pending::Held { left }) => {
                        while *left > 0 && *pos < output.len() {
                            output[*pos] = b'h';
                            self.written.push(b'h');
                            *pos += 1;
                            *left -= 1;
                        }
                        if *left > 0 {
                            return false;
                        }
                    }
                }
                self.pending = None;
                true
            }
        }

        fn u16_at(input: &[u8], at: usize) -> Result<usize, Error> {
            match input.get(at..at + 2) {
                Some(b) => Ok(usize::from(u16::from_le_bytes([b[0], b[1]]))),
                None => Err(Error::UnexpectedEnd),
            }
        }

        impl Decoder for Script {
            fn decode(&mut self, _: &[u8], _: &mut [u8]) -> Result<(Progress, Status), Error> {
                unreachable!("only driven through the contiguous methods")
            }
            fn finish(&mut self, _: &mut [u8]) -> Result<(Progress, Status), Error> {
                unreachable!("only driven through the contiguous methods")
            }
            fn reset(&mut self) {}
            fn discard_output(&mut self, _: &[u8], _: usize) -> Result<(Progress, Status), Error> {
                unreachable!("the CLI never skips output")
            }
        }

        impl ContiguousDecoder for Script {
            fn decode_contiguous(
                &mut self,
                input: &[u8],
                output: &mut [u8],
                filled: usize,
            ) -> Result<(Progress, Status), Error> {
                self.check(output, filled);
                let mut pos = filled;
                let mut consumed = 0;
                let status = loop {
                    if !self.emit(output, &mut pos) {
                        break Status::OutputFull;
                    }
                    if self.ended {
                        break Status::StreamEnd;
                    }
                    let Some(&token) = input.get(consumed) else {
                        break Status::InputEmpty;
                    };
                    match token {
                        LIT => {
                            if pos == output.len() {
                                break Status::OutputFull;
                            }
                            let byte = *input.get(consumed + 1).ok_or(Error::UnexpectedEnd)?;
                            output[pos] = byte;
                            self.written.push(byte);
                            pos += 1;
                            consumed += 2;
                        }
                        COPY => {
                            let dist = u16_at(input, consumed + 1)?;
                            let left = u16_at(input, consumed + 3)?;
                            if dist == 0 || dist > pos {
                                return Err(Error::InvalidDistance);
                            }
                            self.pending = Some(Pending::Copy { dist, left });
                            consumed += 5;
                        }
                        HOLD => {
                            self.held += u16_at(input, consumed + 1)?;
                            consumed += 3;
                        }
                        END => {
                            self.ended = true;
                            consumed += 1;
                        }
                        _ => return Err(Error::Corrupt),
                    }
                };
                Ok((
                    Progress {
                        consumed,
                        written: pos - filled,
                    },
                    status,
                ))
            }

            fn finish_contiguous(
                &mut self,
                output: &mut [u8],
                filled: usize,
            ) -> Result<(Progress, Status), Error> {
                self.check(output, filled);
                let mut pos = filled;
                if self.pending.is_none() && self.held > 0 {
                    self.pending = Some(Pending::Held {
                        left: core::mem::take(&mut self.held),
                    });
                }
                let status = if self.emit(output, &mut pos) {
                    Status::StreamEnd
                } else {
                    Status::OutputFull
                };
                Ok((
                    Progress {
                        consumed: 0,
                        written: pos - filled,
                    },
                    status,
                ))
            }
        }

        impl ContiguousDecoder for Stalling {
            fn decode_contiguous(
                &mut self,
                _: &[u8],
                _: &mut [u8],
                _: usize,
            ) -> Result<(Progress, Status), Error> {
                self.step()
            }
            fn finish_contiguous(
                &mut self,
                _: &mut [u8],
                _: usize,
            ) -> Result<(Progress, Status), Error> {
                Ok((Progress::default(), Status::StreamEnd))
            }
        }

        /// Builds a stream for [`Script`] along with what it decodes to.
        #[derive(Default)]
        struct Stream {
            bytes: Vec<u8>,
            expect: Vec<u8>,
            held: usize,
        }

        impl Stream {
            fn lit(mut self, text: &[u8]) -> Self {
                for &b in text {
                    self.bytes.extend_from_slice(&[LIT, b]);
                    self.expect.push(b);
                }
                self
            }
            fn copy(mut self, dist: u16, len: u16) -> Self {
                self.bytes.push(COPY);
                self.bytes.extend_from_slice(&dist.to_le_bytes());
                self.bytes.extend_from_slice(&len.to_le_bytes());
                for _ in 0..len {
                    self.expect
                        .push(self.expect[self.expect.len() - usize::from(dist)]);
                }
                self
            }
            fn hold(mut self, len: u16) -> Self {
                self.bytes.push(HOLD);
                self.bytes.extend_from_slice(&len.to_le_bytes());
                self.held += usize::from(len);
                self
            }
            fn end(mut self) -> Self {
                self.bytes.push(END);
                self
            }
            fn raw(mut self, bytes: &[u8]) -> Self {
                self.bytes.extend_from_slice(bytes);
                self
            }
            /// The stream and its decoded form.
            fn build(mut self) -> (Vec<u8>, Vec<u8>) {
                self.expect.extend(std::iter::repeat_n(b'h', self.held));
                (self.bytes, self.expect)
            }
        }

        /// A directory of its own for one test, removed afterwards.
        struct Scratch(PathBuf);

        impl Scratch {
            fn new() -> Self {
                static COUNTER: AtomicU64 = AtomicU64::new(0);
                let path = env::temp_dir().join(format!(
                    "compcol-mapped-{}-{}",
                    std::process::id(),
                    COUNTER.fetch_add(1, Ordering::Relaxed)
                ));
                std::fs::create_dir_all(&path).unwrap();
                Self(path)
            }
            fn file(&self, name: &str) -> PathBuf {
                self.0.join(name)
            }
            fn names(&self) -> Vec<String> {
                let mut names: Vec<String> = std::fs::read_dir(&self.0)
                    .unwrap()
                    .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                    .collect();
                names.sort();
                names
            }
        }

        impl Drop for Scratch {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }

        /// A sizing small enough that a few kilobytes of output take many
        /// growth steps, with and without reserving blocks ahead.
        fn tiny(reserve: bool) -> Sizing {
            Sizing {
                initial: 8,
                max_step: 96,
                reserve,
                reserve_min: 4,
                reserve_max: 40,
                stall_room: 4096,
            }
        }

        /// Decode `stream` into a new file with `sizing` and `limit`;
        /// the result and what the file holds afterwards.
        fn decode_with(
            stream: &[u8],
            sizing: Sizing,
            limit: Option<u64>,
        ) -> (io::Result<bool>, Vec<u8>) {
            let scratch = Scratch::new();
            let path = scratch.file("out");
            let file = new_file_options(true).open(&path).unwrap();
            let out = MappedOutput::new(file, sizing, limit).unwrap();
            let result = mapped::decode(Box::new(Script::default()), &mut &stream[..], out);
            // The mapping and the handle are gone: the file can be read
            // (and, by `Scratch`, removed) on every platform.
            (result, std::fs::read(&path).unwrap())
        }

        fn decode_ok(stream: &[u8], sizing: Sizing, limit: Option<u64>) -> (bool, Vec<u8>) {
            let (result, contents) = decode_with(stream, sizing, limit);
            (result.unwrap(), contents)
        }

        #[test]
        fn matches_reach_back_across_many_remaps() {
            // Far more output than the first mapping holds, built from
            // matches whose source was written several mappings ago — some
            // overlapping their own output, one reaching back to byte 0.
            let (stream, expect) = Stream::default()
                .lit(b"abc")
                .copy(3, 500)
                .lit(b"defgh")
                .copy(1, 300)
                .copy(700, 3000)
                .lit(b"!")
                .copy(3809, 3809)
                .end()
                .build();
            assert_eq!(expect.len(), 7618);
            for reserve in [false, true] {
                let (trailing, contents) = decode_ok(&stream, tiny(reserve), None);
                assert!(!trailing);
                // Exactly the decoded bytes: the over-allocation is gone.
                assert_eq!(contents.len(), expect.len(), "reserve={reserve}");
                assert!(contents == expect, "reserve={reserve}");
            }
        }

        #[test]
        fn real_sizing_decodes_and_trims() {
            let (stream, expect) = Stream::default()
                .lit(b"xyz")
                .copy(2, 60000)
                .copy(60000, 60000)
                .end()
                .build();
            let (trailing, contents) = decode_ok(&stream, Sizing::for_input(Some(64)), None);
            assert!(!trailing);
            assert!(contents == expect);
        }

        #[test]
        fn empty_output_leaves_an_empty_file() {
            for reserve in [false, true] {
                // An explicit end of stream, and no stream at all.
                for stream in [&[END][..], &[]] {
                    let (trailing, contents) = decode_ok(stream, tiny(reserve), None);
                    assert!(!trailing);
                    assert!(contents.is_empty());
                }
            }
            let (_, contents) = decode_ok(&[END], Sizing::for_input(None), None);
            assert!(contents.is_empty());
        }

        #[test]
        fn output_held_back_until_finish_grows_the_file_too() {
            let (stream, expect) = Stream::default().lit(b"ab").hold(5000).build();
            for reserve in [false, true] {
                let (trailing, contents) = decode_ok(&stream, tiny(reserve), None);
                assert!(!trailing);
                assert!(contents == expect);
            }
        }

        #[test]
        fn output_limit_is_enforced_by_the_size_of_the_mapping() {
            let (stream, expect) = Stream::default().lit(b"ab").copy(2, 998).end().build();
            assert_eq!(expect.len(), 1000);
            for reserve in [false, true] {
                // Up to and including the limit is fine …
                for limit in [1000, 1001, 5000, u64::MAX] {
                    let (_, contents) = decode_ok(&stream, tiny(reserve), Some(limit));
                    assert!(contents == expect, "limit {limit}");
                }
                // … one byte less is not, whether the decoder is cut off in
                // the middle of a match or right at its end.
                for limit in [999, 500, 2, 1, 0] {
                    let (result, contents) = decode_with(&stream, tiny(reserve), Some(limit));
                    let err = result.unwrap_err();
                    assert!(
                        is_codec_err(&err, Error::OutputLimitExceeded),
                        "limit {limit}: {err}"
                    );
                    // The file was never made larger than the limit plus
                    // the one byte that tells "full" from "over".
                    assert!(contents.len() as u64 <= limit + 1, "limit {limit}");
                }
                // The same from `finish`.
                let (held, _) = Stream::default().hold(1000).build();
                let (result, _) = decode_with(&held, tiny(reserve), Some(999));
                assert!(is_codec_err(
                    &result.unwrap_err(),
                    Error::OutputLimitExceeded
                ));
                let (_, contents) = decode_ok(&held, tiny(reserve), Some(1000));
                assert_eq!(contents.len(), 1000);
                // An empty output fits a limit of zero.
                let (_, contents) = decode_ok(&[END], tiny(reserve), Some(0));
                assert!(contents.is_empty());
            }
        }

        #[test]
        fn trailing_data_is_reported_like_the_streaming_path_does() {
            let (clean, expect) = Stream::default().lit(b"ab").copy(1, 200).end().build();
            let (trailing, contents) = decode_ok(&clean, tiny(true), None);
            assert!(!trailing);
            assert!(contents == expect);

            // In the same read as the end of the stream.
            let (dirty, _) = Stream::default()
                .lit(b"ab")
                .copy(1, 200)
                .end()
                .raw(b"junk")
                .build();
            let (trailing, contents) = decode_ok(&dirty, tiny(true), None);
            assert!(trailing);
            assert!(contents == expect);

            // In a later read, of which a single byte is looked at.
            let scratch = Scratch::new();
            let path = scratch.file("out");
            let file = new_file_options(true).open(&path).unwrap();
            let out = MappedOutput::new(file, tiny(true), None).unwrap();
            let big = vec![0u8; 4096];
            let mut reader = Chunked {
                chunks: [&clean[..], b"X", &big, &big].into_iter().collect(),
                bytes_read: 0,
            };
            let trailing = mapped::decode(Box::new(Script::default()), &mut reader, out).unwrap();
            assert!(trailing);
            assert_eq!(reader.bytes_read, clean.len() + 1);
            assert!(std::fs::read(&path).unwrap() == expect);
        }

        #[test]
        fn a_stalled_decoder_is_an_error_not_an_endless_file() {
            let scratch = Scratch::new();
            for reserve in [false, true] {
                let path = scratch.file(if reserve { "reserved" } else { "sparse" });
                let file = new_file_options(true).open(&path).unwrap();
                let sizing = tiny(reserve);
                let out = MappedOutput::new(file, sizing, None).unwrap();
                let err = mapped::decode(Box::new(Stalling::default()), &mut &b"input"[..], out)
                    .unwrap_err();
                assert!(err.to_string().contains("stalled"), "{err}");
                // It was given room to make progress in, and no more.
                let len = std::fs::metadata(&path).unwrap().len();
                assert!(len >= sizing.stall_room && len <= 4 * sizing.stall_room);
            }
        }

        /// The stream that fails after producing a good deal of output.
        fn failing_stream() -> Vec<u8> {
            Stream::default()
                .lit(b"ab")
                .copy(2, 60000)
                .raw(&[BAD])
                .build()
                .0
        }

        #[test]
        fn a_failed_decode_leaves_nothing_behind() {
            // Through the same `FileOutput` the CLI uses: a destination
            // created exclusively is removed again.
            let scratch = Scratch::new();
            let dest = scratch.file("out");
            let out = open_file_output(&dest, false, Some(0o600))
                .ok()
                .expect("create");
            let map = mapped::open(&out, None, None)
                .unwrap()
                .expect("a new regular file is mapped");
            let err = mapped::decode(Box::new(Script::default()), &mut &failing_stream()[..], map)
                .unwrap_err();
            assert!(is_codec_err(&err, Error::Corrupt), "{err}");
            assert!(std::fs::metadata(&dest).unwrap().len() > 0);
            out.discard();
            assert!(scratch.names().is_empty(), "{:?}", scratch.names());
        }

        #[test]
        fn a_failed_forced_decode_keeps_the_old_destination() {
            let scratch = Scratch::new();
            let dest = scratch.file("out");
            std::fs::write(&dest, b"old contents").unwrap();
            let out = open_file_output(&dest, true, Some(0o600))
                .ok()
                .expect("create");
            let map = mapped::open(&out, None, None)
                .unwrap()
                .expect("the temporary file is mapped");
            mapped::decode(Box::new(Script::default()), &mut &failing_stream()[..], map)
                .unwrap_err();
            out.discard();
            assert_eq!(scratch.names(), ["out"]);
            assert_eq!(std::fs::read(&dest).unwrap(), b"old contents");
        }

        #[test]
        fn a_successful_decode_commits_like_any_other_output() {
            let (stream, expect) = Stream::default().lit(b"ab").copy(2, 60000).end().build();
            for force in [false, true] {
                let scratch = Scratch::new();
                let dest = scratch.file("out");
                if force {
                    std::fs::write(&dest, b"old contents").unwrap();
                }
                let out = open_file_output(&dest, force, Some(0o640))
                    .ok()
                    .expect("create");
                let map = mapped::open(&out, Some(stream.len() as u64), Some(1 << 20))
                    .unwrap()
                    .expect("mapped");
                let trailing =
                    mapped::decode(Box::new(Script::default()), &mut &stream[..], map).unwrap();
                assert!(!trailing);
                out.commit().unwrap();
                assert_eq!(scratch.names(), ["out"], "force={force}");
                assert!(std::fs::read(&dest).unwrap() == expect, "force={force}");
                #[cfg(unix)]
                {
                    let mode = mode_bits(&std::fs::metadata(&dest).unwrap());
                    assert_eq!(mode, Some(0o640), "force={force}");
                }
            }
        }

        #[test]
        fn only_a_new_empty_regular_file_of_ours_is_mapped() {
            let scratch = Scratch::new();
            let output_on = |file: File, ours: bool| FileOutput {
                file,
                written_at: ours.then(|| scratch.file("unused")),
                rename_to: None,
                final_mode: None,
            };

            // Not ours to remove — the way a device opened by `--force`
            // is represented.
            let file = new_file_options(true).open(scratch.file("a")).unwrap();
            assert!(
                mapped::open(&output_on(file, false), None, None)
                    .unwrap()
                    .is_none()
            );

            // Already holds data.
            let mut file = new_file_options(true).open(scratch.file("b")).unwrap();
            file.write_all(b"data").unwrap();
            assert!(
                mapped::open(&output_on(file, true), None, None)
                    .unwrap()
                    .is_none()
            );
            assert_eq!(std::fs::read(scratch.file("b")).unwrap(), b"data");

            // Writable by others (unix): whoever can write it can truncate
            // it under the mapping.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let file = new_file_options(true).open(scratch.file("c")).unwrap();
                file.set_permissions(std::fs::Permissions::from_mode(0o620))
                    .unwrap();
                assert!(
                    mapped::open(&output_on(file, true), None, None)
                        .unwrap()
                        .is_none()
                );
                assert_eq!(std::fs::metadata(scratch.file("c")).unwrap().len(), 0);
            }
        }

        #[test]
        fn giving_up_on_a_mapping_restores_the_empty_file() {
            // What `open` does when the mapping cannot be set up: the
            // streaming path must find an empty file positioned at 0.
            let scratch = Scratch::new();
            let path = scratch.file("out");
            let mut file = new_file_options(true).open(&path).unwrap();
            drop(MappedOutput::new(file.try_clone().unwrap(), tiny(true), None).unwrap());
            assert!(file.metadata().unwrap().len() > 0);
            MappedOutput::undo(&file).unwrap();
            file.write_all(b"streamed").unwrap();
            drop(file);
            assert_eq!(std::fs::read(&path).unwrap(), b"streamed");
        }
    }
}
