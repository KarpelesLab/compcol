//! `compcol` — pure-Rust streaming compression / decompression CLI.
//!
//! Selects an algorithm with `-t ALGO` (required), compresses by default,
//! decompresses with `-d`. Reads stdin or an input file, writes stdout or
//! an `<input>.<ext>` derived path. See `compcol --help`.

use std::env;
use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use compcol::factory;
use compcol::{Decoder, Encoder};

const VERSION: &str = env!("CARGO_PKG_VERSION");

const USAGE: &str = "\
Usage: compcol -t ALGO [OPTIONS] [INPUT]

Pure-Rust streaming compression / decompression.

Required:
    -t, --type ALGO         Algorithm (use --list to see what's compiled in)

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
                              deflate/zlib/gzip: 1..=9, default 6
                              lzma/xz:           0..=9, default 6
                              zstd:              1..=22, default 3
                              brotli quality:    0..=11, default 6
                            Out-of-range values are clamped per algorithm.

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
    input: Option<PathBuf>,
}

#[derive(Debug)]
enum ParseError {
    MissingValue(&'static str),
    UnknownFlag(String),
    ExtraPositional(String),
    BadLevel(String),
}

impl core::fmt::Display for ParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MissingValue(flag) => write!(f, "{flag} requires an argument"),
            Self::UnknownFlag(s) => write!(f, "unknown option: {s}"),
            Self::ExtraPositional(s) => write!(f, "unexpected extra argument: {s}"),
            Self::BadLevel(s) => write!(f, "--level expects an integer in 0..=255, got '{s}'"),
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
                Status::OutputFull => continue,
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

fn stream_decode(
    mut dec: Box<dyn Decoder>,
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
            let (p, status) = dec
                .decode(&in_buf[consumed..n], &mut out_buf)
                .map_err(codec_err)?;
            writer.write_all(&out_buf[..p.written])?;
            consumed += p.consumed;
            match status {
                Status::InputEmpty => break,
                Status::OutputFull => continue,
                Status::StreamEnd => break,
            }
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

    Ok(())
}

fn codec_err(e: compcol::Error) -> io::Error {
    io::Error::other(format!("{e}"))
}

// ─── output-path derivation ──────────────────────────────────────────────

enum Output {
    Stdout,
    File(PathBuf),
}

fn derive_output(args: &Args) -> Result<Output, String> {
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

    let algo = args.algorithm.as_deref().unwrap_or_default();
    let ext = factory::extension(algo).ok_or_else(|| {
        format!("no default extension for algorithm '{algo}'; use -c or -o to pick output")
    })?;

    if args.decompress {
        let s = input.to_string_lossy();
        let suffix = format!(".{ext}");
        if !s.ends_with(&suffix) {
            return Err(format!(
                "input {} doesn't end with '.{ext}'; use -o PATH",
                input.display()
            ));
        }
        Ok(Output::File(PathBuf::from(&s[..s.len() - suffix.len()])))
    } else {
        // Append `.<ext>` to the input path.
        let mut new_name = input.clone().into_os_string();
        new_name.push(".");
        new_name.push(ext);
        Ok(Output::File(PathBuf::from(new_name)))
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
    let algo = match &args.algorithm {
        Some(a) => a.clone(),
        None => {
            eprintln!("compcol: -t ALGO is required (or pass --list / --help)");
            return ExitCode::from(2);
        }
    };

    if args.stdout && args.output.is_some() {
        eprintln!("compcol: -c and -o are mutually exclusive");
        return ExitCode::from(2);
    }

    match run(&args, &algo) {
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

fn run(args: &Args, algo: &str) -> Result<(), RunError> {
    let output = derive_output(args).map_err(RunError::Usage)?;

    // For in-place mode (input file + no -c/-o), we also remove the input on
    // success unless -k. Capture that decision up front.
    let in_place = args.input.is_some() && !args.stdout && args.output.is_none();
    let should_remove_input = in_place && !args.keep;

    // Reader.
    let mut reader: Box<dyn Read> = if let Some(p) = &args.input {
        let f = File::open(p).map_err(|e| {
            RunError::Io(io::Error::new(
                e.kind(),
                format!("open {}: {e}", p.display()),
            ))
        })?;
        Box::new(BufReader::new(f))
    } else {
        Box::new(BufReader::new(io::stdin()))
    };

    // Writer + the path we'd remove on cleanup if anything goes wrong.
    let stdout = io::stdout();
    let (mut writer, output_path): (Box<dyn Write>, Option<PathBuf>) = match &output {
        Output::Stdout => (Box::new(BufWriter::new(stdout.lock())), None),
        Output::File(p) => {
            if !args.force && p.exists() {
                return Err(RunError::Usage(format!(
                    "output exists: {} (use -f to overwrite)",
                    p.display()
                )));
            }
            let f = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(p)
                .map_err(|e| {
                    RunError::Io(io::Error::new(
                        e.kind(),
                        format!("create {}: {e}", p.display()),
                    ))
                })?;
            (Box::new(BufWriter::new(f)), Some(p.clone()))
        }
    };

    let result = if args.decompress {
        if args.level.is_some() {
            // Decompressors don't have a level — flag it rather than
            // silently ignore so users notice the mistake.
            return Err(RunError::Usage(
                "--level is only meaningful on compression (no -d)".into(),
            ));
        }
        let dec = factory::decoder_by_name(algo)
            .ok_or_else(|| RunError::Usage(format!("unknown algorithm: '{algo}' (use --list)")))?;
        stream_decode(dec, &mut *reader, &mut *writer)
    } else {
        let enc = match args.level {
            Some(level) => factory::encoder_by_name_with_level(algo, level),
            None => factory::encoder_by_name(algo),
        }
        .ok_or_else(|| RunError::Usage(format!("unknown algorithm: '{algo}' (use --list)")))?;
        stream_encode(enc, &mut *reader, &mut *writer)
    };

    if let Err(e) = result {
        // Best-effort: drop the writer (releases the file handle), remove the
        // partial output, leave the input intact.
        drop(writer);
        if let Some(p) = output_path {
            let _ = std::fs::remove_file(&p);
        }
        return Err(RunError::Io(e));
    }
    writer.flush()?;
    drop(writer);

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
