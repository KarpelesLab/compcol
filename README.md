# compcol

[![crates.io](https://img.shields.io/crates/v/compcol.svg)](https://crates.io/crates/compcol)
[![docs.rs](https://img.shields.io/docsrs/compcol)](https://docs.rs/compcol)
[![CI](https://github.com/KarpelesLab/compcol/actions/workflows/ci.yml/badge.svg)](https://github.com/KarpelesLab/compcol/actions/workflows/ci.yml)
[![license](https://img.shields.io/crates/l/compcol.svg)](./LICENSE)

A collection of compression algorithms in pure Rust.

`compcol` puts every supported algorithm — RLE, deflate, Deflate64,
zlib, gzip, LZMA, LZMA2, xz, Zstandard, Brotli, LZ4, LZ5/Lizard, Snappy,
LZW, LZSS, LZO, LZX, Amiga LZX, Quantum, LZFSE, ADC, bzip2, Microsoft
Xpress / Xpress Huffman, LZNT1, Stac LZS, PackBits, LHA, the legacy
ARC / PKZIP / StuffIt methods, BCJ/Delta filters, plus decoders for
RAR 2/3/5 and PPMd — behind one uniform streaming trait, with each
algorithm gated by its own Cargo feature so downstream crates only pay
for what they pull in. A runtime
by-name factory makes algorithms selectable from configuration or a CLI
flag, and a `compcol` binary turns the library into a Unix-style filter.

## Design principles

- **Pure Rust.** No `bindgen`, no FFI, no C dependencies. The crate has
  **zero runtime dependencies** by default — the only entry in
  `[dependencies]` is an optional `tokio` (trait definitions only),
  pulled in solely by the opt-in `tokio` feature.
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
  install command instead of a 60-item feature list.

## Supported algorithms

The *Name* column is the string the runtime factory and the CLI's `-t`
flag accept; *Ext* is what `factory::extension(name)` returns.

| Algorithm | Feature | Name | Ext | Encoder | Decoder | Cross-validation |
|---|---|---|---|---|---|---|
| RLE | `rle` | `rle` | `.rle` | full | full | — |
| Deflate (RFC 1951) | `deflate` | `deflate` | `.deflate` | full (lazy LZ77 + dynamic / fixed / stored Huffman; cross-block matching) | full | `python3 -c "import zlib"` |
| Deflate64 (PKWARE method 9) | `deflate64` | `deflate64` | `.deflate64` | full (LZ77 + 64 KiB window + extended length/distance codes) | full | `7z a -tzip -mm=deflate64` |
| Zlib (RFC 1950) | `zlib` | `zlib` | `.zz` | full | full | `python3 -c "import zlib"` |
| Gzip (RFC 1952) | `gzip` | `gzip` | `.gz` | full | full | `gzip(1)` |
| LZ4 frame format | `lz4` | `lz4-frame` | `.lz4` | full (greedy or HC hash-chain + lazy / optimal parse; linked blocks) | full (block + content checksums) | `lz4(1)` both directions |
| LZ4 block format | `lz4` | `lz4` | `.lz4` | same matcher, wrapped in a minimal length-prefixed block framing | full | — |
| LZ5 / Lizard (frame) | `lz5` | `lz5` | `.liz` | store-only frames (valid, no compression) | LZ4-codeword path with raw sub-streams (levels 10..=19); LIZv1 / Huffman sub-streams `Unsupported` | `lizard(1)` 2.1.0 fixtures + CLI cross-decode |
| Snappy | `snappy` | `snappy` | `.sz` | LZ77 hash matcher (raw block format) | full | — |
| LZW (`compress(1)` `.Z`) | `lzw` | `lzw` | `.lzw` | full | full | `compress(1)` / `uncompress(1)` |
| LZSS (Okumura `lzss.c` layout) | `lzss` | `lzss` | `.lzss` | hash-chain match finder | full (4-byte length header + raw payload) | fixtures from a port of Okumura's `lzss.c` (`docs/lzss-ref.py`) |
| LZMA (legacy `.lzma`) | `lzma` | `lzma` | `.lzma` | full | full | `python3 -m lzma` (FORMAT_ALONE) |
| xz | `xz` | `xz` | `.xz` | compressed-LZMA2 chunks + uncompressed fallback | full envelope + all reset variants | `xz(1)` both directions |
| Raw LZMA2 (7z coder 21) | `lzma2` | `lzma2` | `.lzma2` | full (raw LZMA2 chunk stream; reuses the xz LZMA2 engine) | full (raw LZMA2 chunk stream; reuses the xz LZMA2 engine) | round-trip + cross-decode via the shared xz LZMA2 codec |
| Zstandard (RFC 8478) | `zstd` | `zstd` | `.zst` | LZ77 + Huffman literals + FSE_Compressed_Mode sequences + repeat offsets + RLE blocks; optimal parse at high levels | full Compressed_Block + XXH64 content checksum | `zstd(1)` both directions |
| Brotli (RFC 7932) | `brotli` | `brotli` | `.br` | LZ77 + length-limited Huffman + 704-symbol IC alphabet + static-dictionary refs; context modeling + optimal parse at q9+ | full (with 122 KiB static dictionary) | `brotli(1)` both directions |
| LZO (LZO1X-1) | `lzo` | `lzo` | `.lzo` | LZ77 hash matcher | full | `python3 -c "import lzo"` |
| LZX (Microsoft CAB / WIM) | `lzx` | `lzx` | `.lzx` | uncompressed blocks only | full (verbatim + aligned-offset + uncompressed; E8 filter) | — |
| Amiga LZX (original 1995 Forbes) | `amiga_lzx` | `amiga_lzx` | — | uncompressed blocks only | full (verbatim + aligned + uncompressed; fixed 64 KiB window, no chunk reset, no E8 filter) | — |
| Quantum (Stac, old CAB) | `quantum` | `quantum` | `.q` | `Unsupported` (no public encoder exists) | full (libmspack-equivalent) | libmspack regression fixtures |
| LZFSE (Apple) | `lzfse` | `lzfse` | `.lzfse` | `Unsupported` (decoder-only) | `bvx-` raw + `bvxn` (LZVN) + `bvx2` (LZ77 + FSE); `bvx1` returns `Unsupported` | round-trip (bvx2 vs own FSE encoder; no Apple toolchain bundled) |
| ADC (Apple DMG) | `adc` | `adc` | `.adc` | LZSS-style greedy match-finder | full | hand-built fixtures |
| PackBits (Apple / TIFF / PSD) | `packbits` | `packbits` | `.packbits` | full (libtiff-equivalent greedy) | full | PIL TIFF PackBits fixtures |
| bzip2 | `bzip2` | `bzip2` | `.bz2` | full (RLE-1 + SA-IS BWT + MTF + RLE-2 + dynamic Huffman) | full | `bzip2(1)` both directions |
| PPMd (Shkarin's PPMII variant H) | `ppmd` | `ppmd` | `.ppmd` | `Unsupported` (decoder-only; PPM model is intricate) | full (used in 7z / RAR3+ / ZIP method 98) | `python3 ppmd-cffi` |
| Microsoft Xpress (plain LZ77) | `xpress` | `xpress` | `.xpress` | full | full (per [MS-XCA] §2.2) | hand-built fixtures |
| Microsoft Xpress Huffman | `xpress_huffman` | `xpress-huffman` | `.xph` | full (LZ77 + canonical Huffman) | full (per [MS-XCA] §2.1; used in WIM / CompactOS NTFS) | hand-built fixtures |
| LZNT1 (NTFS native compression) | `lznt1` | `lznt1` | `.lznt1` | full | full (per [MS-XCA] §2.5; 4 KiB-chunked LZ77, no entropy coding) | hand-built fixtures |
| Stac LZS (RFC 1974) | `lzs` | `lzs` | `.lzs` | full (2 KiB window, MSB-first) | full | hand-crafted RFC 1974 fixtures |
| LZHAM | `lzham` | `lzham` | `.lzham` | `Unsupported` | `LZH0` container header only; payload `Unsupported` (undocumented bitstream) | — |
| PKZIP Shrink (ZIP method 1) | `zip_shrink` | `zip-shrink` | `.shrunk` | `Unsupported` (decode-only) | full (dynamic LZW + partial clear; 4-byte length header) | reference-encoder fixtures, validated with Info-ZIP `unzip` |
| PKZIP Reduce (ZIP methods 2–5) | `zip_reduce` | `zip-reduce` | `.reduce` | `Unsupported` (decode-only) | full (all four factors; 5-byte factor + length header) | hwzip reference fixtures |
| PKZIP Implode (ZIP method 6) | `zip_implode` | `zip-implode` | `.implode` | `Unsupported` (decode-only) | full (4/8 KiB window × 2/3 Shannon–Fano trees; 5-byte flag + length header) | in-test fixture builder + golden fixture |
| LHA / LZH (`-lh1-`/`-lh2-`/`-lh4-`/`-lh5-`/`-lh6-`/`-lh7-`) | `lha` | `lh1` … `lh7` | `.lzh` | full (lh1/lh2 adaptive Huffman; lh4/5/6/7 static Huffman) | full (clean-room from Okumura LZHUF / ar002) | own round-trip (no reference fixture) |
| BCJ branch filters (x86, ARM, ARMT, ARM64, PPC, SPARC, IA-64, RISC-V) | `bcj` | `bcj-<arch>` | `bcj-<arch>` | full (reversible filter) | full | round-trip identity (public-domain LZMA SDK transform) |
| BCJ2 (7z 4-stream x86 filter) | `bcj2` | — | — | `bcj2::encode` (fn API) | `bcj2::decode` (fn API) | round-trip identity (LZMA SDK algorithm) |
| Delta filter (distance 1..=256) | `delta` | `delta` | `delta` | full (reversible filter) | full | round-trip identity |
| ARC Crunch (method 8) | `arc_crunch` | `crunch` | `.arc` | full (12-bit dynamic LZW) | full | own round-trip (no reference fixture) |
| ARC Squeeze (method 4) | `arc_squeeze` | `squeeze` | `.sqz` | full (RLE + static Huffman) | full | own round-trip (no reference fixture) |
| ARC Squashed (method 9) | `arc_squash` | `squashed` | `.arc` | full (13-bit LZW) | full | own round-trip (no reference fixture) |
| RLE90 (ARC method 3 / StuffIt method 1) | `rle90` | `rle90` | `.rle90` | full | full | round-trip (`0x90`/DLE scheme) |
| StuffIt method 5 (LZAH) | `lzah` | `lzah` | `.lzah` | `Unsupported` (decode-only) | full (LZSS + 314-symbol adaptive Huffman, 4 KiB window) | **real StuffIt `.sit` fixtures (per-fork CRC-16)** |
| StuffIt method 13 (LZ+Huffman) | `sit13` | `sit13` | `.sit13` | `Unsupported` (decode-only) | full (LZSS + dual 321-symbol Huffman, 64 KiB window, LSB-first) | **real StuffIt `.sit` fixtures (per-fork CRC-16)** |
| StuffIt 5 Arsenic (method 15) | `arsenic` | `arsenic` | `.arsenic` | `Unsupported` (decode-only) | full (range coder + inverse BWT + MTF/RLE + de-randomization) | **real StuffIt 5 fixtures (in-stream CRC-32 + SHA vs `unar`)** |
| RAR 1.x | `rar1` | `rar1` | `.rar` | `Unsupported` (license) | building blocks only (Huffman tables not license-clean) | — |
| RAR 2.x | `rar2` | `rar2` | `.rar` | `Unsupported` (license) | full LZ77+Huffman + audio predictor | real rar-2.60 fixtures |
| RAR 3.x / 4.x (v29) | `rar3` | `rar3` | `.rar` | `Unsupported` (license) | full LZ77+Huffman + PPMd-II variant H + standard filters (Delta, x86 E8/E8E9), incl. solid groups; non-standard VM programs refused | libarchive RAR3 fixtures + **real rar-6.24 archives (differential vs UnRAR 7.23)** |
| RAR 5.x | `rar5` | `rar5` | `.rar` | `Unsupported` (license) | full LZ77+Huffman + Delta/x86 filters (incl. solid groups); ARM refused | RARLAB-CLI fixtures + **real WinRAR 7.23 archives (differential vs UnRAR 7.23)** |
| HTTP/2 HPACK (RFC 7541) | `hpack` | `h2-huffman` (string codec) | — | full (header codec + `h2-huffman` string codec) | full (static+dynamic tables, integer/string coding) | RFC 7541 Appendix C vectors |
| HTTP/3 QPACK (RFC 9204) | `qpack` | — | — | full (static + dynamic-table encoder driving the encoder stream; eviction-safe) | full (static+dynamic tables via encoder stream, all field representations) | RFC 9204 Appendix B vectors |
| Canonical Huffman (standalone) | `huffman` | `huffman` | `.huff` | full (length-limited, self-delimiting) | full | own round-trip |
| Range coder (adaptive order-0) | `rangecoder` | `range` | `.range` | full | full | own round-trip |
| Move-To-Front transform | `mtf` | `mtf` | `mtf` | full (reversible filter) | full | round-trip identity |
| Burrows-Wheeler Transform (standalone) | `bwt` | `bwt` | `bwt` | full (block BWT + primary index) | full | round-trip identity |

HPACK and QPACK are HTTP header-compression codecs, not byte-stream codecs:
they operate on `(name, value)` header lists with per-connection dynamic-table
state, so they live behind their own `compcol::hpack` / `compcol::qpack` APIs.
The §5.2 string Huffman primitive is also exposed as the `Http2Huffman` codec
(name `h2-huffman`) through the uniform trait surface; QPACK reuses it. The
`huffman` / `rangecoder` / `mtf` / `bwt` features expose standalone
building-block codecs (entropy coding and reversible transforms) that can be
composed into a custom pipeline.

The RAR encoders are permanently `Unsupported` per RARLAB's unRAR
license terms (every clean-room RAR reader — libarchive, The
Unarchiver, 7-Zip — ships decoder-only for the same reason).

Most other algorithms decode real-world output from their reference
toolchain and produce output that the same reference toolchain accepts.
Some encoders lag the reference's compression ratio because they skip
optional features — e.g. brotli's encoder-side static-dictionary lookups
for non-English text, or the store-only / uncompressed-block encoders
for LZ5, LZX and Amiga LZX; the wire format is always conformant.

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
- **LZ5 (`lz5`)** ships a store-only encoder and a decoder for the most
  common reference-CLI block shape; **LZHAM (`lzham`)** parses only the
  `LZH0` container header. Both return `Unsupported` for what they don't
  cover rather than guessing at an undocumented bitstream.
- The **ZIP method** codecs (`zip-shrink`, `zip-reduce`, `zip-implode`),
  **LZSS**, **`lzah`** and **`sit13`** carry parameters that their host
  container normally stores out of band (uncompressed length, flags);
  each module documents the small header or `DecoderConfig` it expects.

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
compcol = { version = "0.6", features = ["gzip", "factory"] }
```

### The trait

```rust
use compcol::{Algorithm, Encoder, Decoder, Progress, Status, Flush, Error};

pub struct Progress {
    pub consumed: usize,  // bytes read from input
    pub written:  usize,  // bytes written to output
}

pub enum Status {
    InputEmpty,  // all input consumed; feed more (or call finish)
    OutputFull,  // output buffer full; drain it and call again
    StreamEnd,   // the stream is complete
}

pub enum Flush { Sync, Full }

pub trait Encoder {
    fn encode(&mut self, input: &[u8], output: &mut [u8]) -> Result<(Progress, Status), Error>;
    fn finish(&mut self, output: &mut [u8]) -> Result<(Progress, Status), Error>;
    fn reset(&mut self);

    /// Emit a sync point without ending the stream. No-op by default;
    /// deflate / zlib / gzip (and others with an in-band marker) override.
    fn flush(&mut self, output: &mut [u8], mode: Flush) -> Result<(Progress, Status), Error>;
}

pub trait Decoder {
    fn decode(&mut self, input: &[u8], output: &mut [u8]) -> Result<(Progress, Status), Error>;
    fn finish(&mut self, output: &mut [u8]) -> Result<(Progress, Status), Error>;
    fn reset(&mut self);

    /// Advance the decompressed stream by up to `n` bytes without
    /// emitting them.
    fn discard_output(&mut self, input: &[u8], n: usize) -> Result<(Progress, Status), Error>;
}

pub trait Algorithm {
    const NAME: &'static str;
    type Encoder: Encoder;
    type Decoder: Decoder;
    type EncoderConfig: Clone + Default;
    type DecoderConfig: Clone + Default;

    fn encoder() -> Self::Encoder;                              // default config
    fn encoder_with(config: Self::EncoderConfig) -> Self::Encoder;
    fn decoder() -> Self::Decoder;
    fn decoder_with(config: Self::DecoderConfig) -> Self::Decoder;
}
```

`reset` preserves the configuration passed at construction, and is also
the way to recover an encoder/decoder after it returns an `Err`.

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

`decompress_to_vec` trusts its input. For untrusted data use
`decompress_to_vec_capped::<A>(input, max_output)` (or `…_capped_with`),
which fails with `Error::OutputLimitExceeded` instead of growing without
bound — see [decompression bombs](#bounding-decompressed-output) below.

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

### Async adapters (`compcol::tokio_io`)

The `tokio` feature adds `compcol::tokio_io`, mirroring the four
adapters above over `tokio::io::{AsyncRead, AsyncWrite}` (same
constructors and accessors; writers are finished with
`shutdown_into_inner().await`). It is the only feature that adds a
dependency.

### Bounding decompressed output

`compcol::limit::LimitedDecoder` wraps any `Decoder` — including a boxed
one from the factory — and aborts with `Error::OutputLimitExceeded` once
decoded output would exceed a byte budget. It is `no_std` and needs no
feature flag.

```rust
use compcol::{Algorithm, gzip::Gzip};
use compcol::limit::LimitedDecoder;

// Refuse anything larger than 16 MiB of decoded output.
let dec = LimitedDecoder::new(Gzip::decoder(), 16 * 1024 * 1024);
let r = compcol::io::DecoderReader::new(std::io::empty(), dec);
```

### Sync / full flush

`Encoder::flush(output, Flush::Sync)` makes everything written so far
decodable by the peer without ending the stream (deflate's empty stored
block, for example); `Flush::Full` additionally drops the match history
so the next chunk decodes independently. Formats without an in-band
sync marker treat it as a no-op. Call it until it returns
`Status::InputEmpty`.

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
let (p, status) = enc.encode(b"hello", &mut out).unwrap();
// ...

// Leveled algorithms take a level; others ignore it.
let enc = factory::encoder_by_name_with_level("zstd", 19).unwrap();
let dec = factory::decoder_by_name("zstd").unwrap();

println!("available algorithms: {:?}", factory::names());
```

`factory::extension(name)` returns the conventional file extension for
each algorithm (e.g. `"gz"` for gzip, `"zst"` for zstd). Both
`names()` and `extension()` are `const fn`.

`encoder_by_name_with_level` plumbs a level into the algorithms that
have one, clamping to each range: deflate / deflate64 / zlib / gzip
`1..=9` (default 6), lzma / xz `0..=9` (default 6), zstd `1..=22`
(default 3), brotli quality `0..=11` (default 6), bzip2 block size
`1..=9` (default 6), lz4 / lz4-frame `0` = fast greedy, higher = HC
match finder.

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

### Discarding decompressed bytes

Useful for tar-style archive browsing — read a header, skip past the
file body, read the next header:

```rust
use compcol::gzip::Decoder;
use compcol::Decoder as _;

let mut dec = Decoder::new();
// Skip past the first 100 decompressed bytes…
let (p, _) = dec.discard_output(&compressed[..], 100).unwrap();
// …then decode the next 50:
let mut out = [0u8; 50];
let (p2, _) = dec.decode(&compressed[p.consumed..], &mut out).unwrap();
```

The default `discard_output` implementation just reads-and-discards through a
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
compcol -t zstd -l 19 payload.bin    # high-ratio zstd

# List what's compiled in
compcol --list
```

Exit codes: `0` success, `1` runtime / I/O error, `2` usage / argument
error (including `-l` combined with `-d`).

## Cargo feature topology

Every algorithm in the [table above](#supported-algorithms) has its own
feature (the *Feature* column); `Cargo.toml` documents each one. The
non-algorithm features are:

```toml
[features]
default  = ["alloc", "rle", "deflate", "zlib", "gzip", "factory"]
all      = [ …every algorithm…, "alloc", "std", "tokio", "factory", "checksum"]
alloc    = []                  # heap-backed codecs + compcol::vec
std      = ["alloc"]           # compcol::io Read/Write adapters, std::error::Error
tokio    = ["std", "dep:tokio"] # compcol::tokio_io async adapters
factory  = ["alloc"]           # by-name lookup, returns Box<dyn …>
checksum = []                  # publish compcol::checksum::{Crc32, Adler32}
```

Dependencies between algorithm features are resolved for you: `zlib` and
`gzip` pull `deflate`, `xz` and `lzma2` pull `lzma`, `rar3` pulls `ppmd`,
`qpack` pulls `hpack`, and every codec except `rle`, `checksum` and the
deflate family pulls `alloc`. The deflate family needs `alloc` in its
standard build (enable `alloc` or `std` alongside, as the defaults do; a
build with neither fails with a message saying so) and nothing at all in
its `embed` build, below.

A bare `--no-default-features` build produces a library with just the
trait surface (plus `compcol::limit`) — useful for the most constrained
embedded targets. Adding `rle` gives an algorithm that doesn't need
`alloc`; `checksum` is likewise allocation-free.

### Embedded targets: the `embed` feature

```toml
compcol = { version = "0.6", default-features = false, features = ["embed", "gzip"] }
```

`embed` is a mode rather than an algorithm: with it on, the algorithms
that have a small variant are built as that variant **under their usual
names** — `compcol::gzip::Gzip`, `compcol::zlib::Encoder`,
`compcol::deflate::Decoder` keep their paths and their `Encoder` /
`Decoder` contracts, so the same code compiles either way — with no heap,
little stack and little code. Today that is the deflate family: a decoder
in the manner of zlib's `puff` and a greedy fixed-Huffman encoder, both
written straight against the crate's traits. Everything else is unchanged
by `embed`; the `alloc`-backed codecs stay available if you enable `alloc`.

When the data is in memory, the one-shot functions need nothing but a
little stack: `decompress` uses the output slice as its history window,
and `compress` takes a hash table of yours, of any size.

```rust
use compcol::gzip;

let len = gzip::decompress(packed, &mut out)?;            // ~1.3 KiB of stack, no window
let len = gzip::decompressed_len(packed, 1 << 20)?;      // no output at all
let len = gzip::compress(data, &mut [0u16; 1024], &mut out)?;
```

The streaming codecs own all their memory and are `const`-constructible
with an all-zero state, so they can live in a `static` in `.bss`. Their
sizes are picked at build time: `gzip::Decoder` holds a 32 KiB window
(≈ 34 KB in all), and `gzip::WindowedDecoder::<4096>` a 4 KiB one, enough
for streams whose encoder kept within it; `gzip::Encoder` compresses 4 KiB
blocks with a 1024-entry table (≈ 6 KB), and `gzip::BlockEncoder::<B, T>`
any other sizes, larger ones for a better ratio.

```rust
use compcol::{gzip, Decoder, Status};

static DECODER: Mutex<gzip::Decoder> = Mutex::new(gzip::Decoder::new()); // your platform's Mutex

fn unpack(packed: &[u8], out: &mut [u8]) -> Result<usize, compcol::Error> {
    let mut dec = DECODER.lock();
    dec.reset();
    let mut done = 0;
    let (p, status) = dec.decode(packed, out)?;
    done += p.written;
    if status != Status::StreamEnd {
        done += dec.finish(&mut out[done..])?.0.written;
    }
    Ok(done)
}
```

`compcol::embed::flate` goes one level lower, with the API of the retired
`minizlib` crate: the memory is all the caller's, the input and output
whatever the caller plugs in. It decodes into the caller's buffer, or
through a window of the caller's of any size, pulls its input through a
callback or an iterator or has it pushed, and compresses a chunk at a time
with the caller's table, all with no state but a little stack.

```rust
use compcol::embed::flate::{gunzip, Error, Reader, Stream};

let mut scratch = [0; 64];
let input = Reader::new(&mut scratch, |buf| uart.read(buf).map_err(|_| Error::Io));
let output = Stream::new(&mut window, max_len, |data| flash.write(data).map_err(|_| Error::Io));
let len = gunzip(input, output)?;                         // ~1.5 KiB of stack
```

What the `embed` deflate family gives up: ratio (fixed Huffman codes,
matches within a block: with the default sizes roughly 40–45 % on text
where `gzip -6` gets 20 %; `level` is accepted and ignored), speed (tens of
MB/s), sync flush (`Error::Unsupported`) and preset dictionaries.
`compcol::embed` documents the details and the sizes CI holds the build
to on a Cortex-M4 (`thumbv7em-none-eabi`, `opt-level = "z"`, LTO):

| configuration                   | code      | stack     |
|---------------------------------|----------:|----------:|
| gzip / zlib streaming decode    | ≤ 4.0 KB  | ≤ 352 B   |
| raw deflate streaming decode    | ≤ 3.4 KB  | ≤ 352 B   |
| gzip / zlib streaming encode    | ≤ 1.85 KB | ≤ 256 B   |
| raw deflate streaming encode    | ≤ 1.5 KB  | ≤ 224 B   |
| gzip encode + decode            | ≤ 6.2 KB  | ≤ 416 B   |
| gzip / zlib `decompress`        | ≤ 2.4 KB  | ≤ 1.4 KB  |
| raw deflate `decompress`        | ≤ 2.0 KB  | ≤ 1.4 KB  |
| gzip / zlib `compress`          | ≤ 1.0 KB  | ≤ 160 B   |
| raw deflate `compress`          | ≤ 0.8 KB  | ≤ 160 B   |
| `flate`: `gunzip`, buffer out   | ≤ 2.55 KB | ≤ 1.45 KB |
| `flate`: `gunzip`, streams      | ≤ 2.9 KB  | ≤ 1.6 KB  |
| `flate`: `Decompressor`         | ≤ 3.65 KB | ≤ 1.5 KB  |
| `flate`: `gzip`, buffer out     | ≤ 1.1 KB  | ≤ 192 B   |
| `flate`: `Compressor`, streams  | ≤ 1.5 KB  | ≤ 840 B   |

No panic machinery is linked, and no static RAM is needed beyond the codec
struct itself. `tools/footprint/check.sh` reproduces the measurement;
`tools/embed-crosscheck.sh` checks the embed and standard builds read each
other's streams. Because Cargo features unify, enabling `embed` anywhere in
a dependency graph switches every user of that graph to the small variants:
it is meant for firmware, not for libraries.

The `alloc` feature also enables `compcol::vec` (one-shot
`compress_to_vec` / `decompress_to_vec` helpers and their `_capped`
variants). The `std` feature adds `compcol::io` (the `Read`/`Write`
adapters) plus `From<Error> for std::io::Error` so adapter code can use
`?` freely.

`features = ["all"]` enables every algorithm and is the most ergonomic
choice when you don't know in advance which formats you'll see. Note
that it includes `tokio`; list features explicitly if you need a
dependency-free build. It does not include `embed`, which is a mode, so
`--all-features` (which does) builds the embedded deflate family instead
of the standard one.

The `compcol` binary is gated on `features = ["factory"]` so a
`--no-default-features` library build doesn't try to compile it.

### Checksums

With the `checksum` feature, the CRC-32 (IEEE, as used by gzip/zip) and
Adler-32 (RFC 1950) implementations the deflate family uses internally
are public:

```rust
use compcol::checksum::Crc32;

let mut crc = Crc32::new();
crc.update(b"hello");
assert_eq!(crc.finalize(), 0x3610_A686);
```

## Errors

`compcol::Error` is a single crate-wide enum so trait objects work
without GATs:

```rust
#[non_exhaustive]
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
    OutputLimitExceeded, // LimitedDecoder / *_capped budget exceeded
}
```

## Development

```sh
cargo build                                                      # builds lib + bin (default features)
cargo build --no-default-features                                # bare no_std lib
cargo build --no-default-features --features rle                 # narrowest alloc-free build
cargo build --no-default-features --features all                 # every algorithm, still no_std
cargo build --no-default-features --features embed,gzip          # small gzip, no alloc

cargo test --features all                                        # full test suite
cargo test --all-features                                        # the same with `embed` on
cargo clippy --features all --all-targets -- -D warnings         # lint clean
cargo fmt --all --check                                          # format clean
tools/footprint/check.sh                                         # embed sizes on Cortex-M (needs the thumbv7em-none-eabi target + llvm-tools)
tools/embed-crosscheck.sh                                        # embed vs standard deflate family through the CLI
```

The crate currently ships with **1,700+ tests** (unit tests plus 59
integration-test binaries), including round-trip tests for every
algorithm with an encoder, cross-validation against system tools
(`gzip`, `xz`, `bzip2`, `lz4`, `lizard`, `python3` modules) where
installed, and reference fixtures for every decoder-only format (RAR
2/3/5, StuffIt, Quantum, LZX, PKZIP methods, PPMd, …).

`fuzz/` holds a `cargo fuzz` harness with a decoder target per codec
plus a `roundtrip` target for the encoders:

```sh
cargo +nightly fuzz run decoder_gzip
```

A simple benchmark harness lives at `examples/bench.rs`. Run it with:

```sh
cargo run --release --features all --example bench
```

It measures each compiled-in algorithm's encoder/decoder throughput
and compression ratio on a small fixed corpus and compares against
the system reference when one is installed. A snapshot of the output
is kept in [`BENCH.md`](./BENCH.md).

Two more harnesses live alongside it: `examples/micro.rs` (focused
micro-benchmarks for hot paths) and `examples/stress.rs` (multi-GiB
streaming round-trips to catch large-file bugs).

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
