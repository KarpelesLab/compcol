//! zlib-style encoder knobs for deflate / zlib / gzip: level 0, strategies,
//! memory level, window bits, preset dictionary, partial / block flush and
//! `set_params`.
//!
//! Every stream is produced with a 1-byte output buffer and chunked input,
//! decoded by our decoders and, when `python3` is available, by Python's
//! zlib. A small inflate-style parser checks which block types and matches
//! each mode puts in the stream.

#![cfg(all(
    feature = "deflate",
    feature = "zlib",
    feature = "gzip",
    not(feature = "embed")
))]

use std::io::Write;
use std::process::{Command, Stdio};

use compcol::deflate::{EncoderConfig, Strategy};
use compcol::{Encoder as _, Error, Flush, Progress, Status};
use compcol::{deflate, gzip, zlib};

// ─── test data ──────────────────────────────────────────────────────────

struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u32 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (self.0 >> 33) as u32
    }
    fn below(&mut self, n: u32) -> u32 {
        self.next() % n
    }
}

/// Text-like words, byte runs, random stretches and far-back copies, so
/// every strategy and window size has something to do.
fn corpus(seed: u64, len: usize) -> Vec<u8> {
    const WORDS: &[&str] = &[
        "alpha ",
        "bravo ",
        "charlie ",
        "delta ",
        "echo ",
        "foxtrot ",
        "golf ",
        "hotel ",
        "india ",
        "juliet ",
        "kilo ",
        "lima ",
        "mike ",
        "november ",
        "oscar ",
        "papa ",
        "quebec ",
        "romeo ",
        "sierra ",
        "tango ",
        "\n",
        ", ",
        "the ",
        "of ",
    ];
    let mut r = Lcg(seed);
    let mut v = Vec::with_capacity(len + 4096);
    while v.len() < len {
        match r.below(20) {
            0 => {
                let b = r.below(256) as u8;
                let n = 4 + r.below(300) as usize;
                v.extend(std::iter::repeat_n(b, n));
            }
            1 => {
                let n = 16 + r.below(600) as usize;
                for _ in 0..n {
                    v.push(r.below(256) as u8);
                }
            }
            2 if v.len() > 40_000 => {
                let back = 300 + r.below(32_000) as usize;
                let n = 8 + r.below(200) as usize;
                let start = v.len() - back;
                for i in 0..n {
                    v.push(v[start + i]);
                }
            }
            _ => {
                for _ in 0..1 + r.below(12) {
                    v.extend_from_slice(WORDS[r.below(WORDS.len() as u32) as usize].as_bytes());
                }
            }
        }
    }
    v.truncate(len);
    v
}

// ─── encoder driving ────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum F {
    None,
    Sync,
    Full,
    Partial,
    Block,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Raw,
    Zlib,
    Gzip,
}

const KINDS: [Kind; 3] = [Kind::Raw, Kind::Zlib, Kind::Gzip];

trait Enc: compcol::Encoder {
    fn partial(&mut self, out: &mut [u8]) -> Result<(Progress, Status), Error>;
    fn block(&mut self, out: &mut [u8]) -> Result<(Progress, Status), Error>;
    fn params(&mut self, level: u8, strategy: Strategy);
}

macro_rules! impl_enc {
    ($($t:ty),*) => {$(
        impl Enc for $t {
            fn partial(&mut self, out: &mut [u8]) -> Result<(Progress, Status), Error> {
                self.flush_partial(out)
            }
            fn block(&mut self, out: &mut [u8]) -> Result<(Progress, Status), Error> {
                self.flush_block(out)
            }
            fn params(&mut self, level: u8, strategy: Strategy) {
                self.set_params(level, strategy)
            }
        }
    )*};
}
impl_enc!(deflate::Encoder, zlib::Encoder, gzip::Encoder);

/// Feed `data` with a 1-byte output buffer.
fn feed<E: Enc>(e: &mut E, data: &[u8], out: &mut Vec<u8>) {
    let mut buf = [0u8; 1];
    let mut off = 0;
    loop {
        let (p, s) = e.encode(&data[off..], &mut buf).unwrap();
        out.extend_from_slice(&buf[..p.written]);
        off += p.consumed;
        if s == Status::InputEmpty {
            assert_eq!(off, data.len());
            return;
        }
    }
}

fn flush<E: Enc>(e: &mut E, mode: F, out: &mut Vec<u8>) {
    let mut buf = [0u8; 1];
    for _ in 0..10_000_000 {
        let (p, s) = match mode {
            F::None => return,
            F::Sync => e.flush(&mut buf, Flush::Sync),
            F::Full => e.flush(&mut buf, Flush::Full),
            F::Partial => e.partial(&mut buf),
            F::Block => e.block(&mut buf),
        }
        .unwrap();
        out.extend_from_slice(&buf[..p.written]);
        match s {
            Status::InputEmpty => return,
            Status::OutputFull => {}
            Status::StreamEnd => panic!("flush ended the stream"),
        }
    }
    panic!("flush stalled");
}

fn finish<E: Enc>(e: &mut E, out: &mut Vec<u8>) {
    let mut buf = [0u8; 1];
    for _ in 0..10_000_000 {
        let (p, s) = e.finish(&mut buf).unwrap();
        out.extend_from_slice(&buf[..p.written]);
        if s == Status::StreamEnd {
            return;
        }
    }
    panic!("finish stalled");
}

/// Encode in `chunk`-sized pieces, flushing with `mode` after each piece
/// but the last. Returns the stream and the `(compressed_len, input_len)`
/// at each flush.
fn run<E: Enc>(e: &mut E, data: &[u8], chunk: usize, mode: F) -> (Vec<u8>, Vec<(usize, usize)>) {
    let mut out = Vec::new();
    let mut points = Vec::new();
    let mut done = 0;
    for c in data.chunks(chunk) {
        feed(e, c, &mut out);
        done += c.len();
        if mode != F::None && done < data.len() {
            flush(e, mode, &mut out);
            points.push((out.len(), done));
        }
    }
    finish(e, &mut out);
    (out, points)
}

fn make_raw(cfg: EncoderConfig, dict: &[u8]) -> deflate::Encoder {
    let e = deflate::Encoder::with_config(cfg);
    if dict.is_empty() {
        e
    } else {
        e.with_dictionary(dict)
    }
}

fn make_zlib(cfg: EncoderConfig, dict: &[u8]) -> zlib::Encoder {
    let e = zlib::Encoder::with_deflate_config(cfg);
    if dict.is_empty() {
        e
    } else {
        e.with_dictionary(dict)
    }
}

fn encode(
    kind: Kind,
    cfg: EncoderConfig,
    dict: &[u8],
    data: &[u8],
    chunk: usize,
    mode: F,
) -> (Vec<u8>, Vec<(usize, usize)>) {
    match kind {
        Kind::Raw => run(&mut make_raw(cfg, dict), data, chunk, mode),
        Kind::Zlib => run(&mut make_zlib(cfg, dict), data, chunk, mode),
        Kind::Gzip => {
            assert!(dict.is_empty());
            run(
                &mut gzip::Encoder::with_deflate_config(cfg),
                data,
                chunk,
                mode,
            )
        }
    }
}

// ─── decoding ───────────────────────────────────────────────────────────

fn decode_with<D: compcol::Decoder>(mut d: D, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = [0u8; 7];
    let mut pos = 0;
    let mut idle = 0;
    while pos < data.len() {
        let end = (pos + 1000).min(data.len());
        let (p, s) = d.decode(&data[pos..end], &mut buf).unwrap();
        out.extend_from_slice(&buf[..p.written]);
        pos += p.consumed;
        if s == Status::StreamEnd {
            break;
        }
        if p.consumed == 0 && p.written == 0 {
            idle += 1;
            assert!(idle < 1000, "decoder stalled");
        } else {
            idle = 0;
        }
    }
    for _ in 0..10_000_000 {
        let (p, s) = d.finish(&mut buf).unwrap();
        out.extend_from_slice(&buf[..p.written]);
        if s == Status::StreamEnd {
            return out;
        }
    }
    panic!("decoder finish stalled");
}

fn decode_ours(kind: Kind, data: &[u8], dict: &[u8]) -> Vec<u8> {
    match kind {
        Kind::Raw => decode_with(
            deflate::Decoder::with_config(
                deflate::DecoderConfig::new().with_dictionary(dict.to_vec()),
            ),
            data,
        ),
        Kind::Zlib => decode_with(
            zlib::Decoder::with_config(zlib::DecoderConfig {
                dictionary: dict.to_vec(),
            }),
            data,
        ),
        Kind::Gzip => decode_with(gzip::Decoder::new(), data),
    }
}

/// Feeds the stream to `zlib.decompressobj` 1000 bytes at a time and checks
/// that all input up to each flush point is out by then. Input on stdin:
/// u32 LE dictionary length, dictionary, stream.
const PY_INFLATE: &str = r#"
import sys, zlib
wbits = int(sys.argv[1])
points = [tuple(map(int, p.split(':'))) for p in sys.argv[2].split(',') if p]
raw = sys.stdin.buffer.read()
n = int.from_bytes(raw[:4], 'little')
zd = raw[4:4 + n]
data = raw[4 + n:]
d = zlib.decompressobj(wbits=wbits, zdict=zd) if n else zlib.decompressobj(wbits=wbits)
out = bytearray()
pos = 0
def feed(upto):
    global pos
    while pos < upto:
        k = min(1000, upto - pos)
        out.extend(d.decompress(data[pos:pos + k]))
        pos += k
for off, plain in points:
    feed(off)
    if len(out) != plain:
        sys.stderr.write("flush at %d: have %d bytes, want %d\n" % (off, len(out), plain))
        sys.exit(2)
feed(len(data))
out.extend(d.flush())
if not d.eof:
    sys.stderr.write("stream not finished\n")
    sys.exit(3)
sys.stdout.buffer.write(out)
"#;

/// Decode with Python's zlib. `None` when python3 isn't available.
fn decode_python(
    wbits: i32,
    data: &[u8],
    dict: &[u8],
    points: &[(usize, usize)],
) -> Option<Vec<u8>> {
    let pts: Vec<String> = points.iter().map(|(a, b)| format!("{a}:{b}")).collect();
    let child = Command::new("python3")
        .args(["-I", "-c", PY_INFLATE, &wbits.to_string(), &pts.join(",")])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();
    let Ok(mut child) = child else {
        eprintln!("python3 not available; skipping");
        return None;
    };
    let mut stdin = child.stdin.take().unwrap();
    let mut payload = (dict.len() as u32).to_le_bytes().to_vec();
    payload.extend_from_slice(dict);
    payload.extend_from_slice(data);
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(&payload);
    });
    let out = child.wait_with_output().unwrap();
    writer.join().unwrap();
    assert!(
        out.status.success(),
        "python zlib rejected the stream (wbits {wbits}): {}",
        String::from_utf8_lossy(&out.stderr)
    );
    Some(out.stdout)
}

fn py_wbits(kind: Kind, bits: i32) -> i32 {
    match kind {
        Kind::Raw => -bits,
        Kind::Zlib => bits,
        Kind::Gzip => 16 + bits,
    }
}

/// Decode with ours and Python and compare both with `data`.
fn check_both(
    kind: Kind,
    bits: i32,
    stream: &[u8],
    dict: &[u8],
    points: &[(usize, usize)],
    data: &[u8],
    what: &str,
) {
    assert!(
        decode_ours(kind, stream, dict) == data,
        "{what}: our decoder"
    );
    if let Some(py) = decode_python(py_wbits(kind, bits), stream, dict, points) {
        assert!(py == data, "{what}: python zlib output differs");
    }
}

// ─── block parser ───────────────────────────────────────────────────────

#[derive(Debug)]
struct Block {
    btype: u32,
    /// Output position where the block starts.
    start: usize,
    /// Decoded bytes in the block.
    len: usize,
    /// `(length, distance)` of every match.
    matches: Vec<(u32, u32)>,
}

struct Bits<'a> {
    d: &'a [u8],
    pos: usize,
    acc: u64,
    n: u32,
}

impl Bits<'_> {
    fn bits(&mut self, k: u32) -> u32 {
        while self.n < k {
            self.acc |= (self.d[self.pos] as u64) << self.n;
            self.pos += 1;
            self.n += 8;
        }
        let v = (self.acc & ((1u64 << k) - 1)) as u32;
        self.acc >>= k;
        self.n -= k;
        v
    }
}

struct Huff {
    count: [i32; 16],
    sym: Vec<u16>,
}

fn huff(lengths: &[u8]) -> Huff {
    let mut count = [0i32; 16];
    for &l in lengths {
        count[l as usize] += 1;
    }
    count[0] = 0;
    let mut offs = [0usize; 16];
    for l in 1..16 {
        offs[l] = offs[l - 1] + count[l - 1] as usize;
    }
    let mut sym = vec![0u16; lengths.len()];
    for (s, &l) in lengths.iter().enumerate() {
        if l != 0 {
            sym[offs[l as usize]] = s as u16;
            offs[l as usize] += 1;
        }
    }
    Huff { count, sym }
}

fn decode_sym(b: &mut Bits, h: &Huff) -> u16 {
    let (mut code, mut first, mut index) = (0i32, 0i32, 0i32);
    for len in 1..16 {
        code |= b.bits(1) as i32;
        let count = h.count[len];
        if code - count < first {
            return h.sym[(index + (code - first)) as usize];
        }
        index += count;
        first += count;
        first <<= 1;
        code <<= 1;
    }
    panic!("bad huffman code");
}

const LBASE: [u32; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
const LEXT: [u32; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
const DBASE: [u32; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DEXT: [u32; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];

/// Walk a raw deflate stream up to its final block.
fn parse_blocks(d: &[u8]) -> Vec<Block> {
    let mut b = Bits {
        d,
        pos: 0,
        acc: 0,
        n: 0,
    };
    let mut blocks = Vec::new();
    let mut out = 0usize;
    loop {
        let last = b.bits(1);
        let btype = b.bits(2);
        let mut blk = Block {
            btype,
            start: out,
            len: 0,
            matches: Vec::new(),
        };
        match btype {
            0 => {
                b.acc = 0;
                b.n = 0;
                let len = u16::from_le_bytes([d[b.pos], d[b.pos + 1]]);
                let nlen = u16::from_le_bytes([d[b.pos + 2], d[b.pos + 3]]);
                assert_eq!(len, !nlen, "stored LEN/NLEN mismatch");
                b.pos += 4 + len as usize;
                blk.len = len as usize;
            }
            1 | 2 => {
                let (lit, dist) = if btype == 1 {
                    let mut l = [0u8; 288];
                    l[..144].fill(8);
                    l[144..256].fill(9);
                    l[256..280].fill(7);
                    l[280..].fill(8);
                    (huff(&l), huff(&[5u8; 30]))
                } else {
                    let hlit = b.bits(5) as usize + 257;
                    let hdist = b.bits(5) as usize + 1;
                    let hclen = b.bits(4) as usize + 4;
                    const ORDER: [usize; 19] = [
                        16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
                    ];
                    let mut cl = [0u8; 19];
                    for &i in ORDER.iter().take(hclen) {
                        cl[i] = b.bits(3) as u8;
                    }
                    let clh = huff(&cl);
                    let mut lens = Vec::new();
                    while lens.len() < hlit + hdist {
                        let s = decode_sym(&mut b, &clh);
                        match s {
                            0..=15 => lens.push(s as u8),
                            16 => {
                                let p = *lens.last().unwrap();
                                for _ in 0..3 + b.bits(2) {
                                    lens.push(p);
                                }
                            }
                            17 => lens.extend(std::iter::repeat_n(0, 3 + b.bits(3) as usize)),
                            _ => lens.extend(std::iter::repeat_n(0, 11 + b.bits(7) as usize)),
                        }
                    }
                    (huff(&lens[..hlit]), huff(&lens[hlit..]))
                };
                loop {
                    let s = decode_sym(&mut b, &lit) as usize;
                    if s < 256 {
                        blk.len += 1;
                    } else if s == 256 {
                        break;
                    } else {
                        let li = s - 257;
                        let len = LBASE[li] + b.bits(LEXT[li]);
                        let di = decode_sym(&mut b, &dist) as usize;
                        let dist = DBASE[di] + b.bits(DEXT[di]);
                        blk.matches.push((len, dist));
                        blk.len += len as usize;
                    }
                }
            }
            _ => panic!("reserved block type"),
        }
        out += blk.len;
        blocks.push(blk);
        if last == 1 {
            return blocks;
        }
    }
}

/// The raw deflate data inside a stream of `kind`.
fn deflate_body(kind: Kind, s: &[u8]) -> &[u8] {
    match kind {
        Kind::Raw => s,
        Kind::Zlib => {
            if s[1] & 0x20 != 0 {
                &s[6..]
            } else {
                &s[2..]
            }
        }
        Kind::Gzip => &s[10..],
    }
}

fn adler32(d: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for &x in d {
        a = (a + x as u32) % 65521;
        b = (b + a) % 65521;
    }
    (b << 16) | a
}

// ─── level 0 ────────────────────────────────────────────────────────────

#[test]
fn level_0_writes_only_stored_blocks() {
    let data = corpus(1, 150_000);
    let cfg = EncoderConfig::default().with_level(0);
    for kind in KINDS {
        for (mode, chunk) in [(F::None, 4099), (F::Sync, 30_001), (F::Full, 9_000)] {
            let (s, points) = encode(kind, cfg, &[], &data, chunk, mode);
            let blocks = parse_blocks(deflate_body(kind, &s));
            for b in &blocks {
                assert_eq!(b.btype, 0, "{kind:?} {mode:?}: non-stored block");
                assert!(b.len <= 65535);
            }
            // Uncompressed size plus a few bytes per block.
            assert!(s.len() > data.len());
            check_both(
                kind,
                15,
                &s,
                &[],
                &points,
                &data,
                &format!("{kind:?} level 0 {mode:?}"),
            );
        }
    }
    // zlib FLEVEL 0, gzip XFL 4 ("fastest").
    let (z, _) = encode(Kind::Zlib, cfg, &[], b"x", 1, F::None);
    assert_eq!(z[1] >> 6, 0);
    let (g, _) = encode(Kind::Gzip, cfg, &[], b"x", 1, F::None);
    assert_eq!(g[8], 4);
    // Empty input: one empty final stored block.
    let (e, _) = encode(Kind::Raw, cfg, &[], b"", 1, F::None);
    assert_eq!(e, [0x01, 0x00, 0x00, 0xff, 0xff]);
}

#[test]
fn level_0_via_plain_configs() {
    let data = corpus(2, 40_000);
    let mut z = zlib::Encoder::with_config(zlib::EncoderConfig { level: 0 });
    let (zs, _) = run(&mut z, &data, 5000, F::None);
    assert!(parse_blocks(&zs[2..]).iter().all(|b| b.btype == 0));
    check_both(Kind::Zlib, 15, &zs, &[], &[], &data, "zlib level 0");
    let mut g = gzip::Encoder::with_config(gzip::EncoderConfig { level: 0 });
    let (gs, _) = run(&mut g, &data, 5000, F::None);
    assert!(parse_blocks(&gs[10..]).iter().all(|b| b.btype == 0));
    check_both(Kind::Gzip, 15, &gs, &[], &[], &data, "gzip level 0");
}

// ─── strategies ─────────────────────────────────────────────────────────

fn check_strategy(strategy: Strategy, blocks: &[Block], what: &str) {
    for b in blocks {
        match strategy {
            Strategy::HuffmanOnly => assert!(b.matches.is_empty(), "{what}: match found"),
            Strategy::Rle => {
                assert!(
                    b.matches.iter().all(|&(_, d)| d == 1),
                    "{what}: distance > 1"
                )
            }
            Strategy::Fixed => assert_eq!(b.btype, 1, "{what}: non-fixed block"),
            Strategy::Filtered => {
                assert!(
                    b.matches.iter().all(|&(l, _)| l >= 6),
                    "{what}: short match"
                )
            }
            _ => {}
        }
    }
}

const STRATEGIES: [Strategy; 5] = [
    Strategy::Default,
    Strategy::Filtered,
    Strategy::HuffmanOnly,
    Strategy::Rle,
    Strategy::Fixed,
];

#[test]
fn strategies_keep_their_limits() {
    let data = corpus(3, 120_000);
    for strategy in STRATEGIES {
        for level in [1u8, 4, 6, 9] {
            let cfg = EncoderConfig::default()
                .with_level(level)
                .with_strategy(strategy);
            let what = format!("{strategy:?} level {level}");
            let (s, _) = encode(Kind::Raw, cfg, &[], &data, 7001, F::None);
            let blocks = parse_blocks(&s);
            assert_eq!(blocks.iter().map(|b| b.len).sum::<usize>(), data.len());
            check_strategy(strategy, &blocks, &what);
            if strategy == Strategy::Rle {
                assert!(
                    blocks.iter().any(|b| !b.matches.is_empty()),
                    "{what}: no runs"
                );
            }
            check_both(Kind::Raw, 15, &s, &[], &[], &data, &what);
        }
        // Containers, and the header fields zlib derives from the strategy.
        let cfg = EncoderConfig::default().with_strategy(strategy);
        let fast = matches!(
            strategy,
            Strategy::HuffmanOnly | Strategy::Rle | Strategy::Fixed
        );
        for kind in [Kind::Zlib, Kind::Gzip] {
            let (s, _) = encode(kind, cfg, &[], &data, 7001, F::None);
            check_strategy(strategy, &parse_blocks(deflate_body(kind, &s)), "container");
            check_both(
                kind,
                15,
                &s,
                &[],
                &[],
                &data,
                &format!("{kind:?} {strategy:?}"),
            );
            match kind {
                Kind::Zlib => assert_eq!(s[1] >> 6, if fast { 0 } else { 2 }),
                _ => assert_eq!(s[8], if fast { 4 } else { 0 }),
            }
        }
    }
}

#[test]
fn rle_does_not_reach_across_a_full_flush() {
    // A run that spans the flush point: after a full flush the data must
    // decode on its own.
    let data = vec![b'a'; 20_000];
    for strategy in [Strategy::Rle, Strategy::Default] {
        let cfg = EncoderConfig::default().with_strategy(strategy);
        let (s, points) = encode(Kind::Raw, cfg, &[], &data, 10_000, F::Full);
        let (off, plain) = points[0];
        assert_eq!(decode_ours(Kind::Raw, &s[off..], &[]), &data[plain..]);
        check_both(Kind::Raw, 15, &s, &[], &points, &data, "rle full flush");
    }
}

// ─── memory level ───────────────────────────────────────────────────────

#[test]
fn mem_levels_round_trip() {
    let data = corpus(4, 100_000);
    let default = encode(
        Kind::Raw,
        EncoderConfig::default(),
        &[],
        &data,
        9000,
        F::None,
    )
    .0;
    for mem in 0..=10u8 {
        let cfg = EncoderConfig::default().with_mem_level(mem);
        let (s, _) = encode(Kind::Raw, cfg, &[], &data, 9000, F::None);
        if mem == 8 {
            assert_eq!(s, default, "mem level 8 is the default");
        }
        check_both(
            Kind::Raw,
            15,
            &s,
            &[],
            &[],
            &data,
            &format!("mem level {mem}"),
        );
    }
    for kind in [Kind::Zlib, Kind::Gzip] {
        let cfg = EncoderConfig::default().with_mem_level(1).with_level(9);
        let (s, _) = encode(kind, cfg, &[], &data, 9000, F::None);
        check_both(kind, 15, &s, &[], &[], &data, "mem level 1 container");
    }
}

// ─── window bits ────────────────────────────────────────────────────────

#[test]
fn window_bits_limit_distance_and_set_cinfo() {
    let data = corpus(5, 120_000);
    for bits in 8..=15u8 {
        let eff = bits.max(9) as i32;
        let cfg = EncoderConfig::default()
            .with_level(9)
            .with_window_bits(bits);
        for kind in KINDS {
            let (s, _) = encode(kind, cfg, &[], &data, 6000, F::None);
            let max = parse_blocks(deflate_body(kind, &s))
                .iter()
                .flat_map(|b| b.matches.iter().map(|&(_, d)| d))
                .max()
                .unwrap();
            assert!(max <= 1 << eff, "{kind:?} bits {bits}: distance {max}");
            if bits == 15 {
                assert!(max > 1 << 14, "corpus should use the whole window");
            }
            if kind == Kind::Zlib {
                assert_eq!(s[0], (((eff - 8) as u8) << 4) | 8, "CINFO for {bits}");
                assert_eq!(((s[0] as u32) << 8 | s[1] as u32) % 31, 0);
            }
            check_both(
                kind,
                eff,
                &s,
                &[],
                &[],
                &data,
                &format!("{kind:?} bits {bits}"),
            );
        }
    }
    // A small max_distance still gets the 512-byte minimum CINFO.
    let cfg = EncoderConfig::default().with_max_distance(100);
    let (s, _) = encode(Kind::Zlib, cfg, &[], &data, 6000, F::None);
    assert_eq!(s[0], 0x18);
    check_both(Kind::Zlib, 9, &s, &[], &[], &data, "zlib max_distance 100");
}

// ─── preset dictionary ──────────────────────────────────────────────────

#[test]
fn preset_dictionary_raw_and_zlib() {
    let dict = corpus(6, 40_000);
    // Starts with text from deep inside the dictionary.
    let mut data = dict[10_000..14_000].to_vec();
    data.extend_from_slice(&corpus(7, 30_000));
    for kind in [Kind::Raw, Kind::Zlib] {
        for level in [1u8, 6, 9] {
            let cfg = EncoderConfig::default().with_level(level);
            let (s, _) = encode(kind, cfg, &dict, &data, 3000, F::None);
            let (plain, _) = encode(kind, cfg, &[], &data, 3000, F::None);
            assert!(s.len() < plain.len(), "dictionary should help");
            let first = &parse_blocks(deflate_body(kind, &s))[0];
            assert!(
                first.matches.iter().any(|&(_, d)| d > 20_000),
                "no match into the dictionary"
            );
            if kind == Kind::Zlib {
                assert_ne!(s[1] & 0x20, 0, "FDICT");
                assert_eq!(s[2..6], adler32(&dict).to_be_bytes(), "DICTID");
                assert_eq!(((s[0] as u32) << 8 | s[1] as u32) % 31, 0);
            }
            check_both(
                kind,
                15,
                &s,
                &dict,
                &[],
                &data,
                &format!("{kind:?} dict L{level}"),
            );
        }
    }
    // Kept across reset.
    let mut e = make_zlib(EncoderConfig::default(), &dict);
    let (a, _) = run(&mut e, &data, 3000, F::None);
    e.reset();
    let (b, _) = run(&mut e, &data, 3000, F::None);
    assert_eq!(a, b);
    // An empty dictionary is no dictionary.
    let e = zlib::Encoder::new().with_dictionary(&[]);
    let (s, _) = run(&mut { e }, b"abc", 1, F::None);
    assert_eq!(s[1] & 0x20, 0);
    // Short dictionaries (shorter than a hash key) work too.
    for d in [&b"a"[..], b"ab", b"abc"] {
        let (s, _) = encode(
            Kind::Zlib,
            EncoderConfig::default(),
            d,
            b"abcabcabc",
            2,
            F::None,
        );
        check_both(Kind::Zlib, 15, &s, d, &[], b"abcabcabc", "short dict");
    }
}

#[test]
fn preset_dictionary_with_strategies() {
    let dict = corpus(8, 5_000);
    let data = [&dict[1000..3000], &corpus(9, 20_000)[..]].concat();
    for strategy in STRATEGIES {
        let cfg = EncoderConfig::default().with_strategy(strategy);
        let (s, _) = encode(Kind::Raw, cfg, &dict, &data, 999, F::None);
        check_strategy(strategy, &parse_blocks(&s), "dict");
        check_both(
            Kind::Raw,
            15,
            &s,
            &dict,
            &[],
            &data,
            &format!("dict {strategy:?}"),
        );
    }
}

// ─── flush modes ────────────────────────────────────────────────────────

#[test]
fn flush_modes_with_tiny_output_buffers() {
    let data = corpus(10, 60_000);
    for kind in KINDS {
        for mode in [F::Sync, F::Full, F::Partial, F::Block] {
            for level in [0u8, 1, 6] {
                let cfg = EncoderConfig::default().with_level(level);
                let (s, points) = encode(kind, cfg, &[], &data, 4099, mode);
                let blocks = parse_blocks(deflate_body(kind, &s));
                let empty_fixed = blocks.iter().filter(|b| b.btype == 1 && b.len == 0).count();
                let empty_stored = blocks.iter().filter(|b| b.btype == 0 && b.len == 0).count();
                match mode {
                    F::Partial => assert!(empty_fixed >= points.len()),
                    F::Block => assert_eq!(empty_stored, 0, "Z_BLOCK adds no marker"),
                    _ => assert!(empty_stored >= points.len()),
                }
                // Z_BLOCK may hold back up to 7 bits, so only the other
                // modes promise everything is decodable at the flush.
                let pts = if mode == F::Block {
                    &[][..]
                } else {
                    &points[..]
                };
                let what = format!("{kind:?} {mode:?} level {level}");
                check_both(kind, 15, &s, &[], pts, &data, &what);
            }
        }
    }
}

#[test]
fn repeated_flushes() {
    let data = corpus(11, 5_000);
    for mode in [F::Partial, F::Block, F::Sync] {
        let mut e = zlib::Encoder::new();
        let mut out = Vec::new();
        flush(&mut e, mode, &mut out);
        feed(&mut e, &data, &mut out);
        flush(&mut e, mode, &mut out);
        flush(&mut e, mode, &mut out);
        finish(&mut e, &mut out);
        check_both(
            Kind::Zlib,
            15,
            &out,
            &[],
            &[],
            &data,
            &format!("{mode:?} twice"),
        );
    }
}

// ─── set_params ─────────────────────────────────────────────────────────

#[test]
fn set_params_mid_stream() {
    let data = corpus(12, 80_000);
    let half = 40_000;
    for kind in KINDS {
        for (level, strategy) in [
            (0u8, Strategy::Default),
            (6, Strategy::HuffmanOnly),
            (9, Strategy::Rle),
            (1, Strategy::Fixed),
        ] {
            let mut out = Vec::new();
            let check = |out: &[u8]| {
                for b in parse_blocks(deflate_body(kind, out)) {
                    if b.start >= half {
                        if level == 0 {
                            assert_eq!(b.btype, 0);
                        } else {
                            check_strategy(strategy, std::slice::from_ref(&b), "after switch");
                        }
                    }
                }
                check_both(
                    kind,
                    15,
                    out,
                    &[],
                    &[],
                    &data,
                    &format!("{kind:?} -> {level}"),
                );
            };
            macro_rules! go {
                ($e:expr) => {{
                    let mut e = $e;
                    feed(&mut e, &data[..half], &mut out);
                    flush(&mut e, F::Block, &mut out);
                    e.params(level, strategy);
                    feed(&mut e, &data[half..], &mut out);
                    finish(&mut e, &mut out);
                }};
            }
            match kind {
                Kind::Raw => go!(deflate::Encoder::new()),
                Kind::Zlib => go!(zlib::Encoder::new()),
                Kind::Gzip => go!(gzip::Encoder::new()),
            }
            check(&out);
        }
    }
    // Before the header is out, the header follows the new level.
    let mut z = zlib::Encoder::new();
    z.set_params(9, Strategy::Default);
    let (s, _) = run(&mut z, b"hello", 5, F::None);
    assert_eq!(s[1] >> 6, 3);
    let mut g = gzip::Encoder::new();
    g.set_params(1, Strategy::Default);
    let (s, _) = run(&mut g, b"hello", 5, F::None);
    assert_eq!(s[8], 4);
}
