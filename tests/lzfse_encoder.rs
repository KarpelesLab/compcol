//! LZFSE encoder tests.
//!
//! - round-trip through this crate's decoder over a corpus (empty, one
//!   byte, text, random, runs, structured binary, long-distance repeats,
//!   sizes around the 4 KiB LZVN threshold, multi-MiB inputs), with input
//!   and output fed in assorted chunk sizes;
//! - the block kinds chosen (`bvxn` / `bvx-` / `bvx2`) and the ratio;
//! - `flush` (sync and full), `reset`;
//! - cross-checks against independent implementations: the `lzfse_rust`
//!   crate decodes every stream (all platforms), and on macOS Apple's own
//!   `libcompression` (`COMPRESSION_LZFSE`, reached through Python's
//!   `ctypes`) decodes every stream and encodes inputs this crate must
//!   decode. That part skips with a message when `python3` is missing.

#![cfg(feature = "lzfse")]

use compcol::lzfse::{Encoder, Lzfse};
use compcol::vec::decompress_to_vec;
use compcol::{Encoder as _, Flush, Status};

// ─── corpus ──────────────────────────────────────────────────────────────

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| (self.next() >> 24) as u8).collect()
    }
}

/// Text-like data: words from a small vocabulary with punctuation.
fn text(n: usize, seed: u64) -> Vec<u8> {
    const WORDS: &[&str] = &[
        "the",
        "quick",
        "brown",
        "fox",
        "jumps",
        "over",
        "lazy",
        "dog",
        "lorem",
        "ipsum",
        "dolor",
        "sit",
        "amet",
        "compression",
        "finite",
        "state",
        "entropy",
        "apple",
        "block",
        "stream",
        "of",
        "and",
        "a",
        "to",
        "in",
        "is",
        "that",
        "it",
        "with",
        "for",
        "zebra",
        "quantum",
        "xylophone",
        "jukebox",
        "wizard",
    ];
    let mut r = Rng(seed);
    let mut v = Vec::with_capacity(n + 16);
    while v.len() < n {
        let w = WORDS[(r.next() % WORDS.len() as u64) as usize];
        v.extend_from_slice(w.as_bytes());
        v.push(match r.next() % 16 {
            0 => b'.',
            1 => b',',
            2 => b'\n',
            _ => b' ',
        });
    }
    v.truncate(n);
    v
}

/// Back-references reaching up to `max_d` bytes back, so matches cross
/// block boundaries.
fn far_repeats(n: usize, max_d: usize) -> Vec<u8> {
    let mut r = Rng(0x9E37_79B9_7F4A_7C15);
    let mut v: Vec<u8> = Vec::with_capacity(n);
    while v.len() < n {
        let s = r.next();
        if v.len() > 1000 && s.is_multiple_of(4) {
            let d = 1 + ((s >> 8) as usize) % v.len().min(max_d);
            let l = 4 + ((s >> 40) as usize) % 200;
            let st = v.len() - d;
            for i in 0..l {
                let b = v[st + i % d];
                v.push(b);
            }
        } else {
            v.push(b"abcdefghijklmnop"[(s >> 33) as usize % 16]);
        }
    }
    v.truncate(n);
    v
}

/// Little-endian counters and small structs: typical disk-image content.
fn structured(n: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(n + 16);
    let mut i = 0u32;
    while v.len() < n {
        v.extend_from_slice(&i.to_le_bytes());
        v.extend_from_slice(&(i.wrapping_mul(2_654_435_761) >> 20).to_le_bytes());
        v.extend_from_slice(b"\0\0\x01\x80");
        i += 1;
    }
    v.truncate(n);
    v
}

fn corpus() -> Vec<(String, Vec<u8>)> {
    let mut r = Rng(42);
    let mut c: Vec<(String, Vec<u8>)> = vec![
        ("empty".into(), vec![]),
        ("one byte".into(), vec![0x5a]),
        ("hello".into(), b"hello, world".to_vec()),
        ("aaaa".into(), vec![b'a'; 4]),
        ("text 3000".into(), text(3000, 1)),
        ("text 4095".into(), text(4095, 2)),
        ("text 4096".into(), text(4096, 3)),
        ("text 4097".into(), text(4097, 4)),
        ("random 1000".into(), r.bytes(1000)),
        ("random 300k".into(), r.bytes(300_000)),
        ("zeros 2 MiB".into(), vec![0u8; 2 << 20]),
        ("abcd x 25k".into(), b"abcd".repeat(25_000)),
        ("structured 600k".into(), structured(600_000)),
        ("far repeats 700k".into(), far_repeats(700_000, 260_000)),
        ("text 1.5 MiB".into(), text(1_500_000, 5)),
    ];
    // Text, then incompressible bytes, then zeros, then text again: blocks
    // of every kind in one stream, with matches reaching over stored ones.
    let mut mixed = text(50_000, 6);
    mixed.extend(r.bytes(120_000));
    mixed.extend(vec![0u8; 70_000]);
    mixed.extend(text(50_000, 6));
    c.push(("mixed".into(), mixed));
    // Sizes around the parse segment (256 KiB) and lookahead boundaries.
    for n in [(1 << 18) - 1, (1 << 18) + 4096, (1 << 18) + 4097] {
        c.push((format!("text {n}"), text(n, n as u64)));
    }
    c
}

// ─── helpers ─────────────────────────────────────────────────────────────

/// Compress with input fed `in_chunk` bytes and output drained through an
/// `out_chunk`-byte buffer.
fn compress_chunked(data: &[u8], in_chunk: usize, out_chunk: usize) -> Vec<u8> {
    let mut enc = Encoder::new();
    let mut out = Vec::new();
    let mut buf = vec![0u8; out_chunk];
    for piece in data.chunks(in_chunk.max(1)) {
        let mut pos = 0;
        loop {
            let (p, s) = enc.encode(&piece[pos..], &mut buf).unwrap();
            pos += p.consumed;
            out.extend_from_slice(&buf[..p.written]);
            if s == Status::InputEmpty {
                assert_eq!(pos, piece.len());
                break;
            }
            assert_eq!(s, Status::OutputFull);
        }
    }
    loop {
        let (p, s) = enc.finish(&mut buf).unwrap();
        out.extend_from_slice(&buf[..p.written]);
        if s == Status::StreamEnd {
            break;
        }
    }
    out
}

fn compress(data: &[u8]) -> Vec<u8> {
    compcol::vec::compress_to_vec::<Lzfse>(data).unwrap()
}

/// Block magics of a stream, in order.
fn block_kinds(stream: &[u8]) -> Vec<&'static str> {
    let mut kinds = Vec::new();
    let mut p = 0;
    let u32_at = |p: usize| u32::from_le_bytes(stream[p..p + 4].try_into().unwrap()) as usize;
    loop {
        match &stream[p..p + 4] {
            b"bvx$" => {
                kinds.push("bvx$");
                assert_eq!(p + 4, stream.len(), "bytes after bvx$");
                return kinds;
            }
            b"bvx-" => {
                kinds.push("bvx-");
                p += 8 + u32_at(p + 4);
            }
            b"bvxn" => {
                kinds.push("bvxn");
                p += 12 + u32_at(p + 8);
            }
            b"bvx2" => {
                kinds.push("bvx2");
                let w0 = u64::from_le_bytes(stream[p + 8..p + 16].try_into().unwrap());
                let w1 = u64::from_le_bytes(stream[p + 16..p + 24].try_into().unwrap());
                let w2 = u64::from_le_bytes(stream[p + 24..p + 32].try_into().unwrap());
                let header = (w2 & 0xFFFF_FFFF) as usize;
                let lit = ((w0 >> 20) & 0xF_FFFF) as usize;
                let lmd = ((w1 >> 40) & 0xF_FFFF) as usize;
                p += header + lit + lmd;
            }
            m => panic!("unknown block magic {m:?} at {p}"),
        }
    }
}

// ─── round trips ─────────────────────────────────────────────────────────

#[test]
fn round_trip_corpus() {
    for (name, data) in corpus() {
        let packed = compress(&data);
        let back = decompress_to_vec::<Lzfse>(&packed).unwrap();
        assert!(back == data, "{name}: round-trip mismatch");
        block_kinds(&packed);
    }
}

#[test]
fn round_trip_chunked_io() {
    let data = far_repeats(600_000, 200_000);
    let whole = compress(&data);
    for (inc, outc) in [
        (1, 1 << 16),
        (7, 13),
        (4096, 1),
        (65_537, 999),
        (1 << 20, 64),
    ] {
        let packed = compress_chunked(&data, inc, outc);
        // Chunking changes nothing: the encoder's parse is independent of
        // how input arrives.
        assert!(
            packed == whole,
            "chunking ({inc}, {outc}) changed the stream"
        );
    }
    assert_eq!(decompress_to_vec::<Lzfse>(&whole).unwrap(), data);
}

#[test]
fn round_trip_many_sizes_and_shapes() {
    let mut r = Rng(7);
    for len in (0..600usize).chain([4095, 4096, 4097, 40_000, 40_003, 65_536]) {
        for shape in 0..4 {
            let data: Vec<u8> = (0..len)
                .map(|i| match shape {
                    0 => (r.next() >> 24) as u8,
                    1 => b"abcde"[(r.next() % 5) as usize],
                    2 => {
                        if r.next().is_multiple_of(16) {
                            (r.next() >> 24) as u8
                        } else {
                            b'='
                        }
                    }
                    _ => (i / 7) as u8,
                })
                .collect();
            let packed = compress(&data);
            assert!(
                decompress_to_vec::<Lzfse>(&packed).unwrap() == data,
                "len {len} shape {shape}"
            );
        }
    }
}

#[test]
fn reset_reuses_the_encoder() {
    let a = text(10_000, 9);
    let b = b"second stream".repeat(50);
    let mut enc = Encoder::new();
    let mut buf = vec![0u8; 1 << 16];
    let (p, _) = enc.encode(&a, &mut buf).unwrap();
    assert_eq!(p.consumed, a.len());
    enc.reset();
    let mut out = Vec::new();
    let (p, _) = enc.encode(&b, &mut buf).unwrap();
    out.extend_from_slice(&buf[..p.written]);
    loop {
        let (p, s) = enc.finish(&mut buf).unwrap();
        out.extend_from_slice(&buf[..p.written]);
        if s == Status::StreamEnd {
            break;
        }
    }
    assert_eq!(out, compress(&b));
    assert_eq!(decompress_to_vec::<Lzfse>(&out).unwrap(), b);
}

// ─── stream shape and ratio ──────────────────────────────────────────────

#[test]
fn block_kinds_follow_the_reference() {
    // Empty input: just the end-of-stream marker.
    assert_eq!(compress(b""), b"bvx$");
    // Under 4 KiB: a single LZVN block, or stored when LZVN can't help.
    assert_eq!(block_kinds(&compress(&text(3000, 1))), ["bvxn", "bvx$"]);
    assert_eq!(block_kinds(&compress(b"x")), ["bvx-", "bvx$"]);
    assert_eq!(
        block_kinds(&compress(&Rng(1).bytes(2000))),
        ["bvx-", "bvx$"]
    );
    // From 4 KiB on: FSE blocks.
    assert_eq!(block_kinds(&compress(&text(4096, 3))), ["bvx2", "bvx$"]);
    // Incompressible input is stored rather than expanded by FSE.
    let random = compress(&Rng(2).bytes(100_000));
    assert!(block_kinds(&random).iter().all(|k| *k != "bvx2"));
    assert!(random.len() <= 100_000 + 100_000 / 1000 + 64);
}

#[test]
fn compression_ratio_is_reasonable() {
    let t = text(1 << 20, 11);
    let packed = compress(&t);
    // Words drawn at random from a small vocabulary: ~26% for this encoder
    // and libcompression alike; a literal-only coder would land near 55%.
    assert!(
        packed.len() * 10 < t.len() * 3,
        "text: {} -> {}",
        t.len(),
        packed.len()
    );
    let z = compress(&vec![0u8; 1 << 20]);
    assert!(z.len() < 1024, "1 MiB of zeros -> {}", z.len());
    let s = structured(1 << 20);
    let packed = compress(&s);
    assert!(packed.len() * 3 < s.len(), "structured -> {}", packed.len());
}

// ─── flush ───────────────────────────────────────────────────────────────

fn encode_all(enc: &mut Encoder, data: &[u8], out: &mut Vec<u8>) {
    let mut buf = vec![0u8; 4096];
    let mut pos = 0;
    loop {
        let (p, s) = enc.encode(&data[pos..], &mut buf).unwrap();
        pos += p.consumed;
        out.extend_from_slice(&buf[..p.written]);
        if s == Status::InputEmpty {
            return;
        }
    }
}

fn flush_all(enc: &mut Encoder, mode: Flush, out: &mut Vec<u8>) {
    let mut buf = vec![0u8; 100];
    loop {
        let (p, s) = enc.flush(&mut buf, mode).unwrap();
        out.extend_from_slice(&buf[..p.written]);
        if s == Status::InputEmpty {
            return;
        }
    }
}

#[test]
fn flush_makes_everything_so_far_decodable() {
    for mode in [Flush::Sync, Flush::Full] {
        let a = text(70_000, 12);
        let b = text(5_000, 12); // repeats `a`'s start: matches reach back
        let mut enc = Encoder::new();
        let mut out = Vec::new();
        encode_all(&mut enc, &a, &mut out);
        flush_all(&mut enc, mode, &mut out);

        // The bytes so far decode to `a` (no end marker yet).
        let mut dec = compcol::lzfse::Decoder::new();
        let mut got = vec![0u8; a.len() + 10];
        let (p, s) = compcol::Decoder::decode(&mut dec, &out, &mut got).unwrap();
        assert_eq!(s, Status::InputEmpty);
        assert_eq!(p.consumed, out.len());
        assert!(got[..p.written] == a[..], "{mode:?}");

        // Flushing again with nothing new emits nothing.
        let before = out.len();
        flush_all(&mut enc, mode, &mut out);
        assert_eq!(out.len(), before);

        encode_all(&mut enc, &b, &mut out);
        let mut buf = vec![0u8; 512];
        loop {
            let (p, s) = enc.finish(&mut buf).unwrap();
            out.extend_from_slice(&buf[..p.written]);
            if s == Status::StreamEnd {
                break;
            }
        }
        let mut want = a.clone();
        want.extend_from_slice(&b);
        assert!(decompress_to_vec::<Lzfse>(&out).unwrap() == want);
        let mut theirs = Vec::new();
        lzfse_rust::decode_bytes(&out, &mut theirs).unwrap();
        assert!(theirs == want, "{mode:?}: lzfse_rust disagrees");
    }
}

// ─── lzfse_rust cross-checks ─────────────────────────────────────────────

#[test]
fn lzfse_rust_decodes_our_streams() {
    for (name, data) in corpus() {
        let packed = compress(&data);
        let mut out = Vec::new();
        lzfse_rust::decode_bytes(&packed, &mut out)
            .unwrap_or_else(|e| panic!("{name}: lzfse_rust rejected our stream: {e:?}"));
        assert!(out == data, "{name}: lzfse_rust decoded different bytes");
    }
}

#[test]
fn we_decode_lzfse_rust_streams() {
    for (name, data) in corpus() {
        let mut packed = Vec::new();
        lzfse_rust::encode_bytes(&data, &mut packed).unwrap();
        let back = decompress_to_vec::<Lzfse>(&packed)
            .unwrap_or_else(|e| panic!("{name}: rejected lzfse_rust stream: {e:?}"));
        assert!(back == data, "{name}: mismatch");
    }
}

#[test]
fn ratio_is_in_line_with_lzfse_rust() {
    for (name, data) in corpus() {
        if data.len() < 100_000 {
            continue;
        }
        let ours = compress(&data).len();
        let mut theirs = Vec::new();
        lzfse_rust::encode_bytes(&data, &mut theirs).unwrap();
        // Allow 5% slack (plus a little for near-empty outputs).
        assert!(
            ours * 100 <= theirs.len() * 105 + 2000,
            "{name}: ours {ours} vs lzfse_rust {}",
            theirs.len()
        );
    }
}

// ─── Apple libcompression cross-checks (macOS) ───────────────────────────

#[cfg(target_os = "macos")]
mod libcompression {
    use super::*;
    use std::io::Write;
    use std::process::{Command, Stdio};

    /// `compression_{encode,decode}_buffer` with `COMPRESSION_LZFSE` (0x801)
    /// over stdin/stdout. `decode CAP` decodes into a `CAP + 1`-byte buffer
    /// and prints what it produced; `encode` prints the encoded stream.
    const HELPER: &str = r#"
import ctypes, sys
lib = ctypes.CDLL("/usr/lib/libcompression.dylib")
for f in (lib.compression_encode_buffer, lib.compression_decode_buffer):
    f.restype = ctypes.c_size_t
    f.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p,
                  ctypes.c_size_t, ctypes.c_void_p, ctypes.c_int]
data = sys.stdin.buffer.read()
if sys.argv[1] == "decode":
    cap = int(sys.argv[2]) + 1
    fn = lib.compression_decode_buffer
else:
    cap = 2 * len(data) + 4096
    fn = lib.compression_encode_buffer
dst = ctypes.create_string_buffer(cap)
n = fn(dst, cap, data, len(data), None, 0x801)
sys.stdout.buffer.write(dst.raw[:n])
"#;

    fn available() -> bool {
        let ok = Command::new("python3")
            .args([
                "-c",
                "import ctypes; ctypes.CDLL('/usr/lib/libcompression.dylib')",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok {
            println!("skipping: python3 with ctypes + libcompression unavailable");
        }
        ok
    }

    fn run(args: &[&str], input: &[u8]) -> Vec<u8> {
        let mut child = Command::new("python3")
            .args(["-c", HELPER])
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn python3");
        let mut stdin = child.stdin.take().unwrap();
        let input = input.to_vec();
        let writer = std::thread::spawn(move || stdin.write_all(&input));
        let out = child.wait_with_output().expect("python3 helper");
        writer.join().unwrap().expect("write to helper");
        assert!(
            out.status.success(),
            "helper failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        out.stdout
    }

    #[test]
    fn libcompression_decodes_our_streams() {
        if !available() {
            return;
        }
        for (name, data) in corpus() {
            let packed = compress(&data);
            let n = data.len().to_string();
            let back = run(&["decode", &n], &packed);
            assert!(
                back == data,
                "{name}: libcompression decoded {} bytes, want {}",
                back.len(),
                data.len()
            );
        }
    }

    #[test]
    fn libcompression_decodes_flushed_streams() {
        if !available() {
            return;
        }
        let a = text(9_000, 21);
        let b = text(300_000, 21);
        let mut enc = Encoder::new();
        let mut out = Vec::new();
        encode_all(&mut enc, &a, &mut out);
        flush_all(&mut enc, Flush::Sync, &mut out);
        encode_all(&mut enc, &b, &mut out);
        flush_all(&mut enc, Flush::Full, &mut out);
        encode_all(&mut enc, &a, &mut out);
        let mut buf = vec![0u8; 4096];
        loop {
            let (p, s) = enc.finish(&mut buf).unwrap();
            out.extend_from_slice(&buf[..p.written]);
            if s == Status::StreamEnd {
                break;
            }
        }
        let mut want = a.clone();
        want.extend_from_slice(&b);
        want.extend_from_slice(&a);
        let back = run(&["decode", &want.len().to_string()], &out);
        assert!(back == want);
    }

    #[test]
    fn we_decode_libcompression_streams() {
        if !available() {
            return;
        }
        for (name, data) in corpus() {
            let packed = run(&["encode"], &data);
            assert!(!packed.is_empty(), "{name}: libcompression encode failed");
            let back = decompress_to_vec::<Lzfse>(&packed)
                .unwrap_or_else(|e| panic!("{name}: rejected libcompression stream: {e:?}"));
            assert!(back == data, "{name}: mismatch");
        }
    }

    #[test]
    fn ratio_is_in_line_with_libcompression() {
        if !available() {
            return;
        }
        for (name, data) in corpus() {
            if data.len() < 100_000 {
                continue;
            }
            let ours = compress(&data).len();
            let apple = run(&["encode"], &data).len();
            println!(
                "{name}: {} -> ours {ours}, libcompression {apple}",
                data.len()
            );
            assert!(
                ours * 100 <= apple * 105 + 2000,
                "{name}: ours {ours} vs libcompression {apple}"
            );
        }
    }
}
