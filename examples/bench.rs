//! `compcol` benchmark harness.
//!
//! Runs each compiled-in algorithm against a small fixed corpus, measuring
//! our encoder + decoder throughput and compression ratio, and compares
//! against the system reference implementation when one is available.
//!
//! Run with:
//!
//! ```sh
//! cargo run --release --all-features --example bench
//! ```
//!
//! No `criterion` dependency: we use `std::time::Instant`, run each
//! measurement after 1 warmup pass, and report the median of 2 timed
//! runs. Reference timings include subprocess startup overhead (a few
//! ms); for small inputs that dominates, so treat those numbers as a
//! "format works" sanity check rather than a serious speed comparison.

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use compcol::factory;

// ─── corpus ─────────────────────────────────────────────────────────────

/// A short Lorem ipsum block, repeated to fill the requested size.
const LOREM: &[u8] = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit, \
sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim \
ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip \
ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate \
velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat \
cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id \
est laborum. ";

struct Input {
    name: &'static str,
    data: Vec<u8>,
}

fn build_corpus() -> Vec<Input> {
    // Sizes kept modest so even the slower encoders (lzma-family on random
    // input, brotli, zstd) finish in a reasonable wall-clock time. Bump
    // these for one-off deeper measurements; the medians stay representative.
    vec![
        text_input("Lorem 4 KiB", 4 * 1024),
        text_input("Lorem 64 KiB", 64 * 1024),
        zeros_input("Zeros 64 KiB", 64 * 1024),
        random_input("Random 16 KiB", 16 * 1024, 0xDEAD_BEEF),
    ]
}

fn text_input(name: &'static str, target_size: usize) -> Input {
    let mut data = Vec::with_capacity(target_size);
    while data.len() < target_size {
        let take = LOREM.len().min(target_size - data.len());
        data.extend_from_slice(&LOREM[..take]);
    }
    Input { name, data }
}

fn zeros_input(name: &'static str, size: usize) -> Input {
    Input {
        name,
        data: vec![0u8; size],
    }
}

fn random_input(name: &'static str, size: usize, seed: u32) -> Input {
    let mut data = Vec::with_capacity(size);
    let mut state = seed;
    while data.len() < size {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        data.push((state >> 16) as u8);
    }
    Input { name, data }
}

// ─── timing ─────────────────────────────────────────────────────────────

const WARMUP_RUNS: usize = 1;
const TIMED_RUNS: usize = 2;

fn median_of<F: FnMut()>(mut f: F) -> Duration {
    for _ in 0..WARMUP_RUNS {
        f();
    }
    let mut samples: Vec<Duration> = (0..TIMED_RUNS)
        .map(|_| {
            let t = Instant::now();
            f();
            t.elapsed()
        })
        .collect();
    samples.sort();
    samples[samples.len() / 2]
}

fn throughput_mb_s(bytes: usize, t: Duration) -> f64 {
    let s = t.as_secs_f64();
    if s == 0.0 {
        f64::INFINITY
    } else {
        (bytes as f64) / s / 1e6
    }
}

// ─── compcol round-trip ─────────────────────────────────────────────────

fn our_encode(algo: &str, input: &[u8]) -> Result<Vec<u8>, String> {
    let mut enc = factory::encoder_by_name(algo).ok_or_else(|| format!("unknown algo {algo}"))?;
    let mut out = Vec::with_capacity(input.len());
    let mut buf = vec![0u8; 64 * 1024];
    let mut consumed = 0;
    while consumed < input.len() {
        let p = enc
            .encode(&input[consumed..], &mut buf)
            .map_err(|e| format!("{e}"))?;
        out.extend_from_slice(&buf[..p.written]);
        consumed += p.consumed;
        if p.consumed == 0 && p.written == 0 {
            break;
        }
    }
    loop {
        let p = enc.finish(&mut buf).map_err(|e| format!("{e}"))?;
        out.extend_from_slice(&buf[..p.written]);
        if p.done {
            break;
        }
        if p.written == 0 {
            return Err(format!("{algo}: encoder finish stalled"));
        }
    }
    Ok(out)
}

fn our_decode(algo: &str, encoded: &[u8]) -> Result<Vec<u8>, String> {
    let mut dec = factory::decoder_by_name(algo).ok_or_else(|| format!("unknown algo {algo}"))?;
    let mut out = Vec::with_capacity(encoded.len() * 4);
    let mut buf = vec![0u8; 64 * 1024];
    let mut consumed = 0;
    while consumed < encoded.len() {
        let p = dec
            .decode(&encoded[consumed..], &mut buf)
            .map_err(|e| format!("{e}"))?;
        out.extend_from_slice(&buf[..p.written]);
        consumed += p.consumed;
        if p.consumed == 0 && p.written == 0 {
            break;
        }
    }
    loop {
        let p = dec.finish(&mut buf).map_err(|e| format!("{e}"))?;
        out.extend_from_slice(&buf[..p.written]);
        if p.done {
            break;
        }
        if p.written == 0 {
            return Err(format!("{algo}: decoder finish stalled"));
        }
    }
    Ok(out)
}

// ─── system references ──────────────────────────────────────────────────

struct Reference {
    name: &'static str,
    encode: Vec<String>,
    decode: Vec<String>,
}

fn reference_for(algo: &str) -> Option<Reference> {
    fn r(name: &'static str, encode: &[&str], decode: &[&str]) -> Reference {
        Reference {
            name,
            encode: encode.iter().map(|s| s.to_string()).collect(),
            decode: decode.iter().map(|s| s.to_string()).collect(),
        }
    }
    Some(match algo {
        "gzip" => r("gzip", &["gzip", "-c"], &["gzip", "-dc"]),
        "xz" => r("xz", &["xz", "-c"], &["xz", "-dc"]),
        "zstd" => r("zstd", &["zstd", "-c", "--no-check"], &["zstd", "-dc"]),
        "brotli" => r("brotli", &["brotli", "-c"], &["brotli", "-dc"]),
        "lz4" => r("lz4", &["lz4", "-cz"], &["lz4", "-dc"]),
        "lzw" => r("compress", &["compress", "-c"], &["uncompress", "-c"]),
        "zlib" => r(
            "py-zlib",
            &["python3", "-c", PY_ZLIB_ENC],
            &["python3", "-c", PY_ZLIB_DEC],
        ),
        "deflate" => r(
            "py-deflate",
            &["python3", "-c", PY_DEFLATE_ENC],
            &["python3", "-c", PY_DEFLATE_DEC],
        ),
        "lzma" => r(
            "py-lzma",
            &["python3", "-c", PY_LZMA_ENC],
            &["python3", "-c", PY_LZMA_DEC],
        ),
        "lzma2" => r(
            "xz-raw",
            &["xz", "--format=raw", "--lzma2=preset=6", "-c"],
            &["xz", "--format=raw", "--lzma2=preset=6", "-dc"],
        ),
        "snappy" => r(
            "py-snappy",
            &["python3", "-c", PY_SNAPPY_ENC],
            &["python3", "-c", PY_SNAPPY_DEC],
        ),
        _ => return None,
    })
}

const PY_ZLIB_ENC: &str =
    "import sys,zlib; sys.stdout.buffer.write(zlib.compress(sys.stdin.buffer.read()))";
const PY_ZLIB_DEC: &str =
    "import sys,zlib; sys.stdout.buffer.write(zlib.decompress(sys.stdin.buffer.read()))";
const PY_DEFLATE_ENC: &str = "import sys,zlib; co=zlib.compressobj(6,8,-15); \
sys.stdout.buffer.write(co.compress(sys.stdin.buffer.read())+co.flush())";
const PY_DEFLATE_DEC: &str =
    "import sys,zlib; sys.stdout.buffer.write(zlib.decompress(sys.stdin.buffer.read(), -15))";
const PY_LZMA_ENC: &str = "import sys,lzma; \
sys.stdout.buffer.write(lzma.compress(sys.stdin.buffer.read(), format=lzma.FORMAT_ALONE))";
const PY_LZMA_DEC: &str = "import sys,lzma; \
sys.stdout.buffer.write(lzma.decompress(sys.stdin.buffer.read(), format=lzma.FORMAT_ALONE))";
const PY_SNAPPY_ENC: &str =
    "import sys,snappy; sys.stdout.buffer.write(snappy.compress(sys.stdin.buffer.read()))";
const PY_SNAPPY_DEC: &str =
    "import sys,snappy; sys.stdout.buffer.write(snappy.uncompress(sys.stdin.buffer.read()))";

/// Run the reference command end-to-end once and return its output. Used
/// both for warmup (probing tool availability) and for timed runs.
fn pipe_through(cmd: &[String], input: &[u8]) -> Result<Vec<u8>, String> {
    let mut child = Command::new(&cmd[0])
        .args(&cmd[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn {}: {e}", cmd[0]))?;
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(input)
        .map_err(|e| format!("write stdin: {e}"))?;
    drop(child.stdin.take());
    let out = child.wait_with_output().map_err(|e| format!("wait: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "{} failed: {}",
            cmd[0],
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(out.stdout)
}

// ─── per-row measurement ───────────────────────────────────────────────

#[derive(Clone, Copy)]
enum Cell {
    Value(f64),
    Bytes(usize),
    Missing,
}

impl core::fmt::Display for Cell {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Cell::Value(v) if *v == f64::INFINITY => f.write_str("∞"),
            Cell::Value(v) if *v >= 1000.0 => write!(f, "{v:.0}"),
            Cell::Value(v) if *v >= 10.0 => write!(f, "{v:.1}"),
            Cell::Value(v) => write!(f, "{v:.2}"),
            Cell::Bytes(b) => write!(f, "{b}"),
            Cell::Missing => f.write_str("—"),
        }
    }
}

struct Row {
    algo: String,
    input_name: String,
    input_bytes: usize,
    our_size: Cell,
    our_ratio: Cell,
    our_enc_mb_s: Cell,
    our_dec_mb_s: Cell,
    reference: String,
    ref_ratio: Cell,
    ref_enc_mb_s: Cell,
    ref_dec_mb_s: Cell,
}

fn bench_one(algo: &str, input: &Input) -> Row {
    let mut row = Row {
        algo: algo.to_string(),
        input_name: input.name.to_string(),
        input_bytes: input.data.len(),
        our_size: Cell::Missing,
        our_ratio: Cell::Missing,
        our_enc_mb_s: Cell::Missing,
        our_dec_mb_s: Cell::Missing,
        reference: "—".to_string(),
        ref_ratio: Cell::Missing,
        ref_enc_mb_s: Cell::Missing,
        ref_dec_mb_s: Cell::Missing,
    };

    // Our encoder
    let our_encoded = match our_encode(algo, &input.data) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("warning: {algo}/{} encode: {e}", input.name);
            return row;
        }
    };
    let our_decoded = match our_decode(algo, &our_encoded) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("warning: {algo}/{} decode: {e}", input.name);
            return row;
        }
    };
    if our_decoded != input.data {
        eprintln!("warning: {algo}/{} round-trip mismatch", input.name);
        return row;
    }
    row.our_size = Cell::Bytes(our_encoded.len());
    row.our_ratio = Cell::Value((our_encoded.len() as f64) / (input.data.len() as f64));
    let enc_t = median_of(|| {
        let _ = our_encode(algo, &input.data).unwrap();
    });
    row.our_enc_mb_s = Cell::Value(throughput_mb_s(input.data.len(), enc_t));
    let dec_t = median_of(|| {
        let _ = our_decode(algo, &our_encoded).unwrap();
    });
    row.our_dec_mb_s = Cell::Value(throughput_mb_s(input.data.len(), dec_t));

    // Reference
    if let Some(r) = reference_for(algo) {
        match pipe_through(&r.encode, &input.data) {
            Ok(ref_encoded) => match pipe_through(&r.decode, &ref_encoded) {
                Ok(ref_decoded) if ref_decoded == input.data => {
                    row.reference = r.name.to_string();
                    row.ref_ratio =
                        Cell::Value((ref_encoded.len() as f64) / (input.data.len() as f64));
                    let renc_t = median_of(|| {
                        let _ = pipe_through(&r.encode, &input.data);
                    });
                    row.ref_enc_mb_s = Cell::Value(throughput_mb_s(input.data.len(), renc_t));
                    let rdec_t = median_of(|| {
                        let _ = pipe_through(&r.decode, &ref_encoded);
                    });
                    row.ref_dec_mb_s = Cell::Value(throughput_mb_s(input.data.len(), rdec_t));
                }
                Ok(_) => {
                    eprintln!(
                        "warning: {algo}/{} reference round-trip mismatch",
                        input.name
                    );
                }
                Err(e) => {
                    eprintln!("warning: {algo}/{} reference decode: {e}", input.name);
                }
            },
            Err(_) => {
                // Tool missing or python module unavailable — leave as "—".
            }
        }
    }
    row
}

// ─── output ────────────────────────────────────────────────────────────

fn main() {
    let corpus = build_corpus();
    let mut algos: Vec<&str> = factory::names().to_vec();
    algos.sort();

    println!("# compcol benchmark");
    println!();
    println!(
        "Throughput in MB/s (decimal). Median of {TIMED_RUNS} timed runs after {WARMUP_RUNS} \
         warmup. Reference timings include subprocess startup overhead (~ms); for small inputs \
         that dominates, so treat those as a sanity check, not a serious speed comparison."
    );
    println!();
    println!(
        "| Algorithm | Input | Bytes | Ours: out | Ours: ratio | Ours: enc | Ours: dec | Reference \
         | Ref: ratio | Ref: enc | Ref: dec |"
    );
    println!("|---|---|---|---|---|---|---|---|---|---|---|");

    for algo in &algos {
        for input in &corpus {
            let row = bench_one(algo, input);
            println!(
                "| `{}` | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |",
                row.algo,
                row.input_name,
                row.input_bytes,
                row.our_size,
                row.our_ratio,
                row.our_enc_mb_s,
                row.our_dec_mb_s,
                row.reference,
                row.ref_ratio,
                row.ref_enc_mb_s,
                row.ref_dec_mb_s,
            );
        }
    }
}
