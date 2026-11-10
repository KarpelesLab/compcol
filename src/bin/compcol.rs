//! `compcol` — pure-Rust streaming compression / decompression CLI.
//!
//! Selects an algorithm with `-t ALGO` (required), compresses by default,
//! decompresses with `-d`. Reads stdin or an input file, writes stdout or
//! an `<input>.<ext>` derived path. See `compcol --help`.

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

Misc:
    -k, --keep              Keep input file even in in-place mode
    -f, --force             Overwrite an existing output file
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

/// Wrap a codec error, keeping the typed value so `run` can tell which one
/// it was (the `Display` output is the codec error's own).
fn codec_err(e: compcol::Error) -> io::Error {
    io::Error::other(e)
}

/// Whether `e` is the codec error `kind`, as wrapped by [`codec_err`].
fn is_codec_err(e: &io::Error, kind: compcol::Error) -> bool {
    e.get_ref()
        .and_then(|inner| inner.downcast_ref::<compcol::Error>())
        == Some(&kind)
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
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        f.metadata()
            .ok()
            .filter(|m| m.is_file())
            .map(|m| m.mode() & 0o777)
    }
    #[cfg(not(unix))]
    {
        let _ = f;
        None
    }
}

/// Open the output file: exclusively (`O_EXCL`) unless `force`, which
/// truncates an existing file instead.
///
/// With `owner_only` (unix; set when the input is a regular file whose mode
/// will be copied over afterwards) a newly created file starts out as 0600
/// rather than `0666 & !umask`, so the data is never exposed more widely
/// than the input was while it is being written. An existing `--force`
/// target keeps its mode until then.
fn open_output(path: &Path, force: bool, owner_only: bool) -> io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.write(true);
    if force {
        opts.create(true).truncate(true);
    } else {
        opts.create_new(true);
    }
    #[cfg(unix)]
    if owner_only {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    #[cfg(not(unix))]
    let _ = owner_only;
    opts.open(path)
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

    // For in-place mode (input file + no -c/-o), we also remove the input on
    // success unless -k. Capture that decision up front.
    let in_place = args.input.is_some() && !args.stdout && args.output.is_none();
    let should_remove_input = in_place && !args.keep;

    // Reader. When the input is a regular file, remember its permission bits
    // so a file output can be given the same ones (see `open_output`).
    let mut input_mode: Option<u32> = None;
    let mut reader: Box<dyn Read> = if let Some(p) = &args.input {
        let f = File::open(p).map_err(|e| {
            RunError::Io(io::Error::new(
                e.kind(),
                format!("open {}: {e}", p.display()),
            ))
        })?;
        input_mode = regular_file_mode(&f);
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
        match factory::detect(&peeked) {
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

    // Writer + the path we'd remove on cleanup if anything goes wrong.
    let stdout = io::stdout();
    let mut final_mode: Option<(File, u32, PathBuf)> = None;
    let (mut writer, output_path): (Box<dyn Write>, Option<PathBuf>) = match &output {
        Output::Stdout => (Box::new(BufWriter::new(stdout.lock())), None),
        Output::File(p) => {
            // Refuse to write over the file we are about to read: opening it
            // for writing (--force truncates) would destroy the input before
            // a single byte of it had been consumed.
            if let Some(input) = &args.input
                && is_same_file(input, p)
            {
                return Err(RunError::Usage(format!(
                    "input and output are the same file: {}",
                    p.display()
                )));
            }
            // Without --force, create the output atomically with O_EXCL
            // (create_new). This eliminates the TOCTOU between an existence
            // check and the open, and refuses to follow a pre-existing or
            // dangling symlink into an attacker-controlled target. With
            // --force we keep the documented overwrite (truncate) behavior.
            //
            // For the --force path, remember whether the target already
            // existed: if a later codec error triggers cleanup we must NOT
            // delete a file the user already had (data loss). Only output we
            // newly created is ours to remove on failure. (The non-force path
            // uses create_new, so a successful open there always created the
            // file — it is always safe to clean up.)
            let preexisting = args.force && p.exists();
            let f = open_output(p, args.force, input_mode.is_some()).map_err(|e| {
                if !args.force && e.kind() == io::ErrorKind::AlreadyExists {
                    RunError::Usage(format!(
                        "output exists: {} (use -f to overwrite)",
                        p.display()
                    ))
                } else {
                    RunError::Io(io::Error::new(
                        e.kind(),
                        format!("create {}: {e}", p.display()),
                    ))
                }
            })?;
            // Cleanup only files we created. A pre-existing --force target is
            // left in place (already truncated) rather than deleted out from
            // under the user.
            let cleanup = if preexisting { None } else { Some(p.clone()) };
            // Keep a second handle so the input's permission bits can be
            // applied to this very file (not to whatever the path names by
            // then) once it is completely written. If the handle can't be
            // duplicated the output simply stays owner-only.
            if let Some(mode) = input_mode
                && let Ok(handle) = f.try_clone()
            {
                final_mode = Some((handle, mode, p.clone()));
            }
            (Box::new(BufWriter::new(f)), cleanup)
        }
    };

    // From here on the output exists: every failure — including the final
    // flush — must go through the cleanup below rather than an early `?`.
    let result = match codec {
        Codec::Decoder(dec) => {
            stream_decode(dec, &mut *reader, &mut *writer).and_then(|trailing| {
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
        // Best-effort: remove the partial output, leave the input intact.
        if let Some(p) = output_path {
            let _ = std::fs::remove_file(&p);
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

    // The output is complete: hand it the input's permission bits. Failing
    // to do so leaves it no more accessible than intended (a file we created
    // is still owner-only), so warn rather than fail the whole run.
    if let Some((handle, mode, path)) = final_mode
        && let Err(e) = set_mode(&handle, mode)
    {
        eprintln!(
            "compcol: warning: could not set permissions on {}: {e}",
            path.display()
        );
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
}
