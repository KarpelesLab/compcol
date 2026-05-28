# compcol

A collection of compression algorithms in pure Rust.

`compcol` puts every supported algorithm — RLE, deflate, zlib, gzip,
LZMA, xz, Zstandard, Brotli, LZ4, Snappy, LZW, LZO, LZX, Quantum, plus
decoders for RAR 1/2/3/5 — behind one uniform streaming trait, with
each algorithm gated by its own Cargo feature so downstream crates
only pay for what they pull in. A runtime by-name factory makes
algorithms selectable from configuration or a CLI flag, and a
`compcol` binary turns the library into a Unix-style filter.

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
| Zlib (RFC 1950) | `zlib` | `.zz` | full | full | `python3 -c "import zlib"` |
| Gzip (RFC 1952) | `gzip` | `.gz` | full | full | `gzip(1)` |
| LZ4 block format | `lz4` | `.lz4` | LZ77 hash matcher | full | — |
| Snappy | `snappy` | `.sz` | LZ77 hash matcher (raw block format) | full | — |
| LZW (`compress(1)` `.Z`) | `lzw` | `.lzw` | full | full | `compress(1)` / `uncompress(1)` |
| LZMA (legacy `.lzma`) | `lzma` | `.lzma` | full | full | `python3 -m lzma` (FORMAT_ALONE) |
| xz | `xz` | `.xz` | compressed-LZMA2 chunks + uncompressed fallback | full envelope + all reset variants | `xz(1)` both directions |
| Zstandard (RFC 8478) | `zstd` | `.zst` | LZ77 + Huffman literals + FSE_Compressed_Mode sequences + repeat offsets + RLE blocks | full Compressed_Block | `zstd(1)` both directions |
| Brotli (RFC 7932) | `brotli` | `.br` | LZ77 + length-limited Huffman + 704-symbol IC alphabet + static-dictionary refs | full (with 122 KiB static dictionary) | `brotli(1)` both directions |
| LZO (LZO1X-1) | `lzo` | `.lzo` | LZ77 hash matcher | full | `python3 -c "import lzo"` |
| LZX (Microsoft CAB / WIM) | `lzx` | `.lzx` | uncompressed blocks only | full (verbatim + aligned-offset + uncompressed; E8 filter) | — |
| Quantum (Stac, old CAB) | `quantum` | `.q` | `Unsupported` (no public encoder exists) | full (libmspack-equivalent) | libmspack regression fixtures |
| LZFSE (Apple) | `lzfse` | `.lzfse` | `Unsupported` (decoder-only) | `bvx-` raw + `bvxn` (LZVN); `bvx2` returns `Unsupported` | hand-built fixtures (no Apple toolchain bundled) |
| ADC (Apple DMG) | `adc` | `.adc` | LZSS-style greedy match-finder | full | hand-built fixtures |
| RAR 1.x | `rar1` | `.rar` | `Unsupported` (license) | building blocks only (Huffman tables not license-clean) | — |
| RAR 2.x | `rar2` | `.rar` | `Unsupported` (license) | full LZ77+Huffman + audio predictor | real rar-2.60 fixtures |
| RAR 3.x | `rar3` | `.rar` | `Unsupported` (license) | full LZ77+Huffman + E8 filter; PPMd & VM filters refused | libarchive RAR3 fixtures |
| RAR 5.x | `rar5` | `.rar` | `Unsupported` (license) | full LZ77+Huffman + x86 filter; Delta/ARM refused | RARLAB-CLI fixtures |

The RAR encoders are permanently `Unsupported` per RARLAB's unRAR
license terms (every clean-room RAR reader — libarchive, The
Unarchiver, 7-Zip — ships decoder-only for the same reason).

Every other algorithm decodes real-world output from its reference
toolchain and produces output that the same reference toolchain
accepts. Some encoders (zstd, brotli) lag the reference's compression
ratio because they skip features like FSE-compressed Huffman weight
tables (zstd) or encoder-side static-dictionary lookups for non-English
text (brotli); the wire format is always conformant.

## Library usage

```toml
# Cargo.toml
[dependencies]
compcol = { version = "0.1", features = ["gzip", "factory"] }
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

### Streaming a round-trip

```rust
use compcol::gzip::{Encoder, Decoder};
use compcol::{Encoder as _, Decoder as _};

let input = b"hello world hello world hello world";

// Encode.
let mut enc = Encoder::new();
let mut buf = [0u8; 256];
let mut encoded = Vec::new();

let p = enc.encode(input, &mut buf).unwrap();
encoded.extend_from_slice(&buf[..p.written]);
loop {
    let p = enc.finish(&mut buf).unwrap();
    encoded.extend_from_slice(&buf[..p.written]);
    if p.done { break; }
}

// Decode.
let mut dec = Decoder::new();
let mut decoded = Vec::new();
let p = dec.decode(&encoded, &mut buf).unwrap();
decoded.extend_from_slice(&buf[..p.written]);
let p = dec.finish(&mut buf).unwrap();
decoded.extend_from_slice(&buf[..p.written]);
assert!(p.done);
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
    -t, --type ALGO         Algorithm (use --list to see what's compiled in)

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

MIT. © 2026 Karpeles Lab Inc.
