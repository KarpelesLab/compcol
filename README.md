# compcol

A collection of compression algorithms in pure Rust.

`compcol` puts every supported algorithm — RLE, deflate, Deflate64,
zlib, gzip, LZMA, xz, Zstandard, Brotli, LZ4, Snappy, LZW, LZO, LZX,
Amiga LZX, Quantum, LZFSE, ADC, bzip2, Microsoft Xpress / Xpress
Huffman, LZNT1, plus decoders for RAR 1/2/3/5 and PPMd — behind one
uniform streaming trait, with each algorithm gated by its own Cargo
feature so downstream crates only pay for what they pull in. A runtime
by-name factory makes algorithms selectable from configuration or a CLI
flag, and a `compcol` binary turns the library into a Unix-style filter.

## Design principles

- **Pure Rust.** No `bindgen`, no FFI, no C dependencies. The crate has
  **zero runtime dependencies** — nothing in `[dependencies]`.
- **100% safe.** `unsafe_code = "forbid"` is set crate-wide; the library
  never opts out.
- **`no_std`.** The library is `#![no_std]`. `alloc` is used by
  everything except the bare-bones `rle` algorithm; algorithms that need
  large windows or work buffers pull in `alloc` automatically.
- **Streaming.** The caller owns both buffers; the codec preserves its
  state across calls. Works in a 1-byte-on-both-sides streaming loop.
- **Per-algorithm features.** `default = ["alloc", "rle", "deflate",
  "zlib", "gzip", "factory"]`. Everything else is opt-in.
- **`all` meta-feature.** `features = ["all"]` is a single name that
  enables every algorithm — useful for downstream crates and the CLI
  install command instead of a 20-item feature list.

## Supported algorithms

| Algorithm | Feature | Extension | Encoder | Decoder | Cross-validation |
|---|---|---|---|---|---|
| RLE | `rle` | `.rle` | full | full | — |
| Deflate (RFC 1951) | `deflate` | `.deflate` | full (lazy LZ77 + dynamic / fixed / stored Huffman; cross-block matching) | full | `python3 -c "import zlib"` |
| Deflate64 (PKWARE method 9) | `deflate64` | `.deflate64` | full (LZ77 + 64 KiB window + extended length/distance codes) | full | `7z a -tzip -mm=deflate64` |
| Zlib (RFC 1950) | `zlib` | `.zz` | full | full | `python3 -c "import zlib"` |
| Gzip (RFC 1952) | `gzip` | `.gz` | full | full | `gzip(1)` |
| LZ4 block format | `lz4` | `.lz4` | LZ77 hash matcher | full | — |
| Snappy | `snappy` | `.sz` | LZ77 hash matcher (raw block format) | full | — |
| LZW (`compress(1)` `.Z`) | `lzw` | `.lzw` | full | full | `compress(1)` / `uncompress(1)` |
| LZMA (legacy `.lzma`) | `lzma` | `.lzma` | full | full | `python3 -m lzma` (FORMAT_ALONE) |
| xz | `xz` | `.xz` | compressed-LZMA2 chunks + uncompressed fallback | full envelope + all reset variants | `xz(1)` both directions |
| Raw LZMA2 (7z coder 21) | `lzma2` | `.lzma2` | `Unsupported` (decode-only) | full (raw LZMA2 chunk stream; reuses the xz LZMA2 engine) | round-trip vs the xz LZMA2 encoder |
| Zstandard (RFC 8478) | `zstd` | `.zst` | LZ77 + Huffman literals + FSE_Compressed_Mode sequences + repeat offsets + RLE blocks | full Compressed_Block | `zstd(1)` both directions |
| Brotli (RFC 7932) | `brotli` | `.br` | LZ77 + length-limited Huffman + 704-symbol IC alphabet + static-dictionary refs | full (with 122 KiB static dictionary) | `brotli(1)` both directions |
| LZO (LZO1X-1) | `lzo` | `.lzo` | LZ77 hash matcher | full | `python3 -c "import lzo"` |
| LZX (Microsoft CAB / WIM) | `lzx` | `.lzx` | uncompressed blocks only | full (verbatim + aligned-offset + uncompressed; E8 filter) | — |
| Amiga LZX (original 1995 Forbes) | `amiga_lzx` | — (`.lzx` claimed by MS LZX) | uncompressed blocks only | full (verbatim + aligned + uncompressed; fixed 64 KiB window, no chunk reset, no E8 filter) | — |
| Quantum (Stac, old CAB) | `quantum` | `.q` | `Unsupported` (no public encoder exists) | full (libmspack-equivalent) | libmspack regression fixtures |
| LZFSE (Apple) | `lzfse` | `.lzfse` | `Unsupported` (decoder-only) | `bvx-` raw + `bvxn` (LZVN); `bvx2` returns `Unsupported` | hand-built fixtures (no Apple toolchain bundled) |
| ADC (Apple DMG) | `adc` | `.adc` | LZSS-style greedy match-finder | full | hand-built fixtures |
| bzip2 | `bzip2` | `.bz2` | full (RLE-1 + SA-IS BWT + MTF + RLE-2 + dynamic Huffman) | full | `bzip2(1)` both directions |
| PPMd (Shkarin's PPMII variant H) | `ppmd` | `.ppmd` | `Unsupported` (decoder-only; PPM model is intricate) | full (used in 7z / RAR3+ / ZIP method 98) | `python3 ppmd-cffi` |
| Microsoft Xpress (plain LZ77) | `xpress` | `.xpress` | full | full (per [MS-XCA] §2.2) | hand-built fixtures |
| Microsoft Xpress Huffman | `xpress_huffman` | `.xph` | full (LZ77 + canonical Huffman) | full (per [MS-XCA] §2.1; used in WIM / CompactOS NTFS) | hand-built fixtures |
| LZNT1 (NTFS native compression) | `lznt1` | `.lznt1` | full | full (per [MS-XCA] §2.5; 4 KiB-chunked LZ77, no entropy coding) | hand-built fixtures |
| LHA / LZH (`-lh1-`/`-lh4-`/`-lh5-`/`-lh6-`/`-lh7-`) | `lha` | `.lzh` | full (lh1 adaptive Huffman; lh4/5/6/7 static Huffman) | full (clean-room from Okumura LZHUF / ar002) | own round-trip (no reference fixture) |
| BCJ branch filters (x86, ARM, ARMT, ARM64, PPC, SPARC, IA-64, RISC-V) | `bcj` | `bcj-<arch>` | full (reversible filter) | full | round-trip identity (public-domain LZMA SDK transform) |
| BCJ2 (7z 4-stream x86 filter) | `bcj2` | — | `bcj2::encode` (fn API) | `bcj2::decode` (fn API) | round-trip identity (LZMA SDK algorithm) |
| Delta filter (distance 1..=256) | `delta` | `delta` | full (reversible filter) | full | round-trip identity |
| ARC Crunch (method 8) | `arc_crunch` | `.arc` | full (12-bit dynamic LZW) | full | own round-trip (no reference fixture) |
| ARC Squeeze (method 4) | `arc_squeeze` | `.sqz` | full (RLE + static Huffman) | full | own round-trip (no reference fixture) |
| ARC Squashed (method 9) | `arc_squash` | `.arc` | full (13-bit LZW) | full | own round-trip (no reference fixture) |
| RLE90 (ARC method 3 / StuffIt method 1) | `rle90` | `.rle90` | full | full | round-trip (`0x90`/DLE scheme) |
| StuffIt method 5 (LZAH) | `lzah` | `.sit` | `Unsupported` (decode-only) | full (LZSS + 314-symbol adaptive Huffman, 4 KiB window) | **real StuffIt `.sit` fixtures (per-fork CRC-16)** |
| StuffIt method 13 (LZ+Huffman) | `sit13` | `.sit` | `Unsupported` (decode-only) | full (LZSS + dual 321-symbol Huffman, 64 KiB window, LSB-first) | **real StuffIt `.sit` fixtures (per-fork CRC-16)** |
| StuffIt 5 Arsenic (method 15) | `arsenic` | `.sit` | `Unsupported` (decode-only) | full (range coder + inverse BWT + MTF/RLE + de-randomization) | **real StuffIt 5 fixtures (in-stream CRC-32 + SHA vs `unar`)** |
| RAR 1.x | `rar1` | `.rar` | `Unsupported` (license) | building blocks only (Huffman tables not license-clean) | — |
| RAR 2.x | `rar2` | `.rar` | `Unsupported` (license) | full LZ77+Huffman + audio predictor | real rar-2.60 fixtures |
| RAR 3.x | `rar3` | `.rar` | `Unsupported` (license) | full LZ77+Huffman + E8 filter; PPMd & VM filters refused | libarchive RAR3 fixtures |
| RAR 5.x | `rar5` | `.rar` | `Unsupported` (license) | full LZ77+Huffman + x86 filter; Delta/ARM refused | RARLAB-CLI fixtures |

The RAR encoders are permanently `Unsupported` per RARLAB's unRAR
license terms (every clean-room RAR reader — libarchive, The
Unarchiver, 7-Zip — ships decoder-only for the same reason).

Most other algorithms decode real-world output from their reference
toolchain and produce output that the same reference toolchain accepts.
Some encoders (zstd, brotli) lag the reference's compression ratio
because they skip features like FSE-compressed Huffman weight tables
(zstd) or encoder-side static-dictionary lookups for non-English text
(brotli); the wire format is always conformant.

The exceptions, where no reference toolchain or fixtures were available,
are noted in the table above:

- **LHA (`lha`)** and **ARC Crunch/Squeeze (`arc_crunch`/`arc_squeeze`)**
  are clean-room implementations from public format descriptions,
  validated by their own encoder↔decoder round-trip rather than against
  reference-tool output. They are expected to be wire-compatible but this
  has not been cross-checked against the original tools.
- **BCJ (`bcj`)** and **Delta (`delta`)** are reversible *filters* (from
  the public-domain LZMA SDK lineage); correctness is the
  forward∘inverse identity, verified exhaustively.
The StuffIt codecs **`lzah` (method 5)** and **`sit13` (method 13)** are, by
contrast, validated to the highest bar in the table: they were implemented
clean-room from facts-only functional specifications and decode **real
`.sit` archives bit-exactly**, verified against the stored per-fork CRC-16.
Their few fixed interoperability tables (the offset code, the method-13
meta-code and predefined code-length sets) are functional data required for
interop, supplied as a separately-licensed adjunct kept out of the clean-room
spec material.

## Library usage

```toml
# Cargo.toml
[dependencies]
compcol = { version = "0.4", features = ["gzip", "factory"] }
```

### The trait

```rust
use compcol::{Algorithm, Encoder, Decoder, Progress, Error};

pub struct Progress {
    pub consumed: usize,  // bytes read from input
    pub written:  usize,  // bytes written to output
    pub done:     bool,   // true once finish() has fully drained
}

pub trait Encoder {
    fn encode(&mut self, input: &[u8], output: &mut [u8]) -> Result<Progress, Error>;
    fn finish(&mut self, output: &mut [u8]) -> Result<Progress, Error>;
    fn reset(&mut self);
}

pub trait Decoder {
    fn decode(&mut self, input: &[u8], output: &mut [u8]) -> Result<Progress, Error>;
    fn finish(&mut self, output: &mut [u8]) -> Result<Progress, Error>;
    fn reset(&mut self);

    /// Advance the decompressed stream by up to `n` bytes without
    /// emitting them. Default impl reads-and-discards through a small
    /// scratch buffer; algorithms can override for cheaper skipping.
    fn skip(&mut self, input: &[u8], n: usize) -> Result<Progress, Error>;
}

pub trait Algorithm {
    const NAME: &'static str;
    type Encoder: Encoder;
    type Decoder: Decoder;
    fn encoder() -> Self::Encoder;
    fn decoder() -> Self::Decoder;
}
```

### One-shot helpers (`compcol::vec`)

For callers that already have the whole payload in memory:

```rust
use compcol::gzip::Gzip;
use compcol::vec::{compress_to_vec, decompress_to_vec, compress_to_vec_with};

let plain = b"hello world hello world hello world";

let compressed = compress_to_vec::<Gzip>(plain)?;
let decoded    = decompress_to_vec::<Gzip>(&compressed)?;
assert_eq!(decoded, plain);

// With explicit config:
let small = compress_to_vec_with::<Gzip>(
    plain, compcol::gzip::EncoderConfig { level: 9 },
)?;
# Ok::<(), compcol::Error>(())
```

`compress_to_vec_with` / `decompress_to_vec_with` accept the
algorithm's `EncoderConfig` / `DecoderConfig` for tuning (level,
quality, etc.). Available under the `alloc` feature — no `std`
required.

### Streaming through `std::io` (`compcol::io`)

For files, sockets, or any `Read`/`Write` source. All four
directions are covered; pick by which side you control and which
direction the bytes flow.

```rust
use std::io::{Read, Write};
use compcol::{Algorithm, gzip::Gzip};
use compcol::io::{EncoderWriter, DecoderReader};

// Write plaintext, get a compressed file.
let file = std::fs::File::create("hello.txt.gz")?;
let mut w = EncoderWriter::new(file, Gzip::encoder());
w.write_all(b"hello, gzip\n")?;
let _file = w.finish()?;                  // returns the inner File

// Read a compressed file as if it were plain text.
let file = std::fs::File::open("hello.txt.gz")?;
let mut r = DecoderReader::new(file, Gzip::decoder());
let mut decoded = String::new();
r.read_to_string(&mut decoded)?;
# Ok::<(), std::io::Error>(())
```

`EncoderReader` (compressed source out of a plain reader) and
`DecoderWriter` (plain output out of a compressed writer) round out
the set. Writers call `finish` on `Drop` best-effort — call
`finish()` explicitly to catch errors. Requires the `std` feature.

### Driving the trait directly

```rust
use compcol::gzip::{Encoder, Decoder};
use compcol::{Encoder as _, Decoder as _, Status};

let input = b"hello world hello world hello world";

// Encode.
let mut enc = Encoder::new();
let mut buf = [0u8; 256];
let mut encoded = Vec::new();
let mut consumed = 0;
while consumed < input.len() {
    let (p, status) = enc.encode(&input[consumed..], &mut buf).unwrap();
    encoded.extend_from_slice(&buf[..p.written]);
    consumed += p.consumed;
    if matches!(status, Status::InputEmpty) { break; }
}
loop {
    let (p, status) = enc.finish(&mut buf).unwrap();
    encoded.extend_from_slice(&buf[..p.written]);
    if matches!(status, Status::StreamEnd) { break; }
}

// Decode.
let mut dec = Decoder::new();
let mut decoded = Vec::new();
let mut c2 = 0;
while c2 < encoded.len() {
    let (p, status) = dec.decode(&encoded[c2..], &mut buf).unwrap();
    decoded.extend_from_slice(&buf[..p.written]);
    c2 += p.consumed;
    if matches!(status, Status::StreamEnd | Status::InputEmpty) { break; }
}
loop {
    let (p, status) = dec.finish(&mut buf).unwrap();
    decoded.extend_from_slice(&buf[..p.written]);
    if matches!(status, Status::StreamEnd) { break; }
}
assert_eq!(decoded, input);
```

### Runtime selection via the factory

```rust
use compcol::{factory, Encoder as _, Decoder as _};

let mut enc = factory::encoder_by_name("gzip")
    .expect("gzip not compiled in");

let mut out = [0u8; 1024];
let p = enc.encode(b"hello", &mut out).unwrap();
// ...

println!("available algorithms: {:?}", factory::names());
```

`factory::extension(name)` returns the conventional file extension for
each algorithm (e.g. `"gz"` for gzip, `"zst"` for zstd).

`factory::detect(prefix)` sniffs the leading bytes of a compressed stream
and returns the algorithm name of the most likely codec (gzip, zlib, xz,
zstd, bzip2, lz4-frame, and the rar/StuffIt container hints), or `None` for
short/unrecognized input. It is conservative — it prefers `None` over a wrong
guess — and only ever names codecs compiled into the current build. Formats
without a magic number (notably brotli, and raw `.lzma`) are intentionally
not detected.

```rust
use compcol::factory;

assert_eq!(factory::detect(&[0x1F, 0x8B, 0x08]), Some("gzip"));
assert_eq!(factory::detect(b"not compressed"), None);
```

### Skipping decompressed bytes

Useful for tar-style archive browsing — read a header, skip past the
file body, read the next header:

```rust
use compcol::gzip::Decoder;
use compcol::Decoder as _;

let mut dec = Decoder::new();
// Skip past the first 100 decompressed bytes…
let p = dec.skip(&compressed[..], 100).unwrap();
// …then decode the next 50:
let mut out = [0u8; 50];
let p = dec.decode(&compressed[p.consumed..], &mut out).unwrap();
```

The default `skip` implementation just reads-and-discards through a
small scratch buffer, so it works for every algorithm. Individual
decoders are free to override with a smarter implementation when the
format allows it (e.g. fast-forwarding through stored deflate blocks
without LZ77 expansion).

## CLI usage

The `compcol` binary ships with the crate. Install with:

```sh
cargo install --path . --features all
```

…or pick a subset:

```sh
cargo install --path . --features "gzip,zstd,brotli,lz4,factory"
```

```text
Usage: compcol -t ALGO [OPTIONS] [INPUT]

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

Misc:
    -k, --keep              Keep input file even in in-place mode
    -f, --force             Overwrite an existing output file
    -L, --list              List available algorithms and exit
    -V, --version           Print version and exit
    -h, --help              Print this help and exit
```

### Examples

```sh
# Pipe-style use (gzip via stdin → stdout)
cat README.md | compcol -t gzip > README.md.gz

# In-place compression (mirrors gzip(1) semantics: removes the original)
compcol -t gzip README.md            # → README.md.gz, removes README.md

# Keep the original
compcol -t gzip -k README.md         # → README.md.gz, keeps README.md

# Decompress
compcol -t gzip -d README.md.gz      # → README.md, removes README.md.gz

# Decompress with format auto-detection (no -t needed)
cat README.md.gz | compcol -d > README.md

# Force overwrite of an existing output file
compcol -t gzip -f README.md

# Round-trip into a pager
compcol -t xz -d archive.xz -c | less

# Mix algorithms
compcol -t zstd payload.bin          # → payload.bin.zst
compcol -t brotli payload.bin        # → payload.bin.br

# List what's compiled in
compcol --list
```

Exit codes: `0` success, `1` runtime / I/O error, `2` usage / argument
error.

## Cargo feature topology

```toml
[features]
default = ["alloc", "rle", "deflate", "zlib", "gzip", "factory"]
# Meta-feature: pulls in every algorithm. Equivalent to `--all-features`.
all     = ["alloc", "factory",
           "rle", "deflate", "zlib", "gzip",
           "lzma", "xz",
           "zstd", "brotli", "lz4", "snappy", "lzw",
           "lzo", "lzx", "quantum", "lzfse", "adc",
           "rar1", "rar2", "rar3", "rar5"]
alloc   = []
std     = ["alloc"]            # std::io::{Read,Write} adapters in compcol::io
factory = ["alloc"]            # by-name lookup, returns Box<dyn …>
rle     = []                   # no_std clean (alloc not required)
deflate = ["alloc"]
zlib    = ["deflate"]
gzip    = ["deflate"]
lzma    = ["alloc"]
xz      = ["lzma"]
zstd    = ["alloc"]
brotli  = ["alloc"]
lz4     = ["alloc"]
snappy  = ["alloc"]
lzw     = ["alloc"]
lzo     = ["alloc"]
lzx     = ["alloc"]
quantum = ["alloc"]
lzfse   = ["alloc"]            # decoder-only, bvx2 returns Unsupported
adc     = ["alloc"]
rar1    = ["alloc"]
rar2    = ["alloc"]
rar3    = ["alloc"]
rar5    = ["alloc"]
```

A bare `--no-default-features` build produces a library with just the
trait surface — useful for the most constrained embedded targets.
Adding `rle` gives an algorithm that doesn't need `alloc`. Adding any
other algorithm feature pulls in `alloc` and the codec.

The `alloc` feature also enables `compcol::vec` (one-shot
`compress_to_vec` / `decompress_to_vec` helpers). The `std` feature
adds `compcol::io` (the `Read`/`Write` adapters) plus
`From<Error> for std::io::Error` so adapter code can use `?`
freely.

`features = ["all"]` enables every algorithm and is the most ergonomic
choice when you don't know in advance which formats you'll see.

The `compcol` binary is gated on `features = ["factory"]` so a
`--no-default-features` library build doesn't try to compile it.

## Errors

`compcol::Error` is a single crate-wide enum so trait objects work
without GATs:

```rust
pub enum Error {
    Corrupt,             // generic malformed input
    UnexpectedEnd,       // finish() called mid-stream
    OutputTooSmall,      // codec has a minimum atomic output size
    BadHeader,           // container header malformed
    InvalidBlockType,    // deflate BTYPE=3, etc.
    InvalidHuffmanTree,  // code lengths violate Kraft inequality
    InvalidDistance,     // LZ77 back-reference out of range
    ChecksumMismatch,    // Adler-32 / CRC-32 mismatch
    TrailerMismatch,     // gzip ISIZE doesn't match output length
    Unsupported,         // option / mode this build doesn't implement
}
```

## Development

```sh
cargo build                                                      # builds lib + bin (default features)
cargo build --no-default-features                                # bare no_std lib
cargo build --no-default-features --features rle                 # narrowest alloc-free build
cargo build --no-default-features --features all                 # every algorithm, still no_std

cargo test --all-features                                        # full test suite
cargo clippy --all-features --all-targets -- -D warnings         # lint clean
cargo fmt --all --check                                          # format clean
```

The crate currently ships with **~566 tests across 23 test binaries**,
including round-trip tests for every algorithm with an encoder,
cross-validation against system `gzip` / `xz` / `zstd` / `brotli` /
`compress` / `lz4` / `python3 lzo` / `python3 lzma`, and hand-crafted
hex fixtures for every decoder-only format (RAR 2/3/5, Quantum, LZX).

A simple benchmark harness lives at `examples/bench.rs`. Run it with:

```sh
cargo run --release --features all --example bench
```

It measures each compiled-in algorithm's encoder/decoder throughput
and compression ratio on a small fixed corpus and compares against
the system reference when one is installed. A snapshot of the output
is kept in [`BENCH.md`](./BENCH.md).

## License

MIT. © 2026 Karpeles Lab Inc. See [`LICENSE`](./LICENSE). The MIT terms
cover this crate's own source code; they grant no rights in any
third-party trademark or compressed-format specification.

### A note on RAR

`RAR`, `WinRAR`, and `unRAR` are trademarks of Alexander Roshal / RARLAB.
This project is **not** affiliated with or endorsed by RARLAB.

The `rar2` / `rar3` / `rar5` decoders are **clean-room** reimplementations
written from public format descriptions and other clean-room readers
(libarchive, The Unarchiver). **No source code or data tables from
RARLAB's `unRAR` distribution were used.** RARLAB's unRAR license forbids
using its source to recreate the RAR *compression* algorithm, so every RAR
**encoder** in this crate is permanently `Unsupported` by design — the same
decoder-only posture taken by libarchive, The Unarchiver, and 7-Zip.

`rar1` is `Unsupported` even for decoding: a working RAR1 decoder needs
static Huffman code-length tables that RAR1 does not transmit, and no
license-clean published form of those tables is available to reproduce
here (the building blocks ship, but the tables do not). See the module
docs in `src/rar1/`, `src/rar2/`, `src/rar3/`, and `src/rar5/` for details.
