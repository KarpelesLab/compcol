# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.3](https://github.com/KarpelesLab/compcol/compare/v0.4.2...v0.4.3) - 2026-05-29

### Other

- deflate, zlib: preset-dictionary support + reset_keep_window (closes #22) ([#24](https://github.com/KarpelesLab/compcol/pull/24))
- Add Amiga LZX codec (original 1995 Forbes variant, distinct from MS-CAB LZX) ([#23](https://github.com/KarpelesLab/compcol/pull/23))

## [0.4.2](https://github.com/KarpelesLab/compcol/compare/v0.4.1...v0.4.2) - 2026-05-29

### Other

- DecoderReader drains pending output before falling back to finish (closes #17) ([#21](https://github.com/KarpelesLab/compcol/pull/21))
- Add canonical LZ4 Frame format encoder + decoder (closes #10) ([#20](https://github.com/KarpelesLab/compcol/pull/20))
- Add Encoder::flush(Sync|Full) for per-packet sync boundaries (closes #11) ([#19](https://github.com/KarpelesLab/compcol/pull/19))
- Expose raw single-block LZ4/LZO codecs (closes #9) ([#15](https://github.com/KarpelesLab/compcol/pull/15))
- recognise EOS marker even with zero-capacity output (closes #14) ([#16](https://github.com/KarpelesLab/compcol/pull/16))

## [0.4.1](https://github.com/KarpelesLab/compcol/compare/v0.4.0...v0.4.1) - 2026-05-29

### Other

- Optimization pass: 6 algorithms, including 120× lzma decoder fix and SA-IS bzip2 BWT ([#13](https://github.com/KarpelesLab/compcol/pull/13))
- Fix repository URL in Cargo.toml ([#12](https://github.com/KarpelesLab/compcol/pull/12))
- Add bzip2 (encoder + decoder) ([#8](https://github.com/KarpelesLab/compcol/pull/8))
- use RELEASE_PLZ_TOKEN on the release-pr job ([#6](https://github.com/KarpelesLab/compcol/pull/6))

## [0.4.0](https://github.com/KarpelesLab/compcol/compare/v0.3.1...v0.4.0) - 2026-05-29

### Other

- Mark Error enum #[non_exhaustive] ([#5](https://github.com/KarpelesLab/compcol/pull/5))
- Polish + extend: Box trait impls, CLI levels, multi-member gzip, bomb defense, fuzz harness, async tokio adapters ([#4](https://github.com/KarpelesLab/compcol/pull/4))
- fix doc warnings, narrow-feature clippy, and cli BrokenPipe race
- Revert "CHANGELOG: document compcol::vec + compcol::io helpers under Unreleased"
- document compcol::vec + compcol::io helpers under Unreleased
- Add compcol::vec (one-shot helpers) and compcol::io (std::io adapters)

## [0.3.1](https://github.com/KarpelesLab/compcol/compare/v0.3.0...v0.3.1) - 2026-05-28

### Other

- Remove stray src/brotli/mod.rs.orig (patch leftover)
- fix "fails above 128 KiB" decoder bug
- README + CHANGELOG: document new lzfse + adc features
- Add LZFSE (Apple) decoder + LZVN sub-format
- Add ADC (Apple Data Compression) algorithm

### Added

- **LZFSE** (Apple's LZ77 + Finite State Entropy). Decoder-only; encoder
  permanently returns `Error::Unsupported` (matches lzx/quantum/rar*
  pattern). Handles `bvx-` (raw) and `bvxn` (LZVN) block types. `bvx2`
  (LZFSE v2) block type currently returns `Error::Unsupported`; the FSE
  primitives and v2 bit reader scaffolding are in place for a future
  round to wire up. Feature: `lzfse`.
- **ADC** (Apple Data Compression — DMG / HFS+ compressed-resource
  format). Full encoder + decoder. Simple LZSS-style 3-token format
  (raw run, short match, long match) with a 64 KiB sliding window.
  Greedy match-finder on the encode side. Feature: `adc`.
- Both algorithms wired into the `factory` module (by-name lookup,
  extension table, names list) and the `all` meta-feature.

## [0.3.0](https://github.com/KarpelesLab/compcol/compare/v0.2.0...v0.3.0) - 2026-05-29

### Trait redesign (breaking)

- `Encoder::encode`, `Encoder::finish`, `Decoder::decode`, `Decoder::finish`
  now return `Result<(Progress, Status), Error>` instead of
  `Result<Progress, Error>`. `Status` is an explicit enum
  (`InputEmpty`, `OutputFull`, `StreamEnd`) so callers no longer have to
  infer end-of-stream from byte counts.
- `Progress` no longer carries a `done` field — `Status::StreamEnd`
  replaces it.
- `Decoder::skip` renamed to `Decoder::discard_output` to better describe
  what it does (advance past decompressed bytes without writing them).
- `Algorithm` gains two associated config types:
  `type EncoderConfig: Clone + Default` and
  `type DecoderConfig: Clone + Default`, plus two new constructors:
  `encoder_with(config) -> Encoder` and `decoder_with(config) -> Decoder`.
  The existing `encoder()`/`decoder()` continue to work via the
  `Default` impl.
- New post-error contract documented on `Encoder`/`Decoder`: after any
  `Err(_)` return, the codec is poisoned; further calls are
  unspecified until `reset()`.
- Private `RawEncoder` / `RawDecoder` traits bridge each algorithm's
  byte-counts-only impl to the new public surface — algorithms don't
  have to think about `Status` themselves; the blanket impl computes
  it from `consumed == input.len()` etc.

### Compression level configuration

Levelled algorithms now expose a `pub struct EncoderConfig` with a
`level` (or `quality` for brotli) field:

| Algorithm | Range  | Default |
|-----------|--------|---------|
| deflate   | 1..=9  | 6       |
| zlib      | 1..=9  | 6       |
| gzip      | 1..=9  | 6       |
| lzma      | 0..=9  | 6       |
| xz        | 0..=9  | 6       |
| zstd      | 1..=22 | 3       |
| brotli    | 0..=11 | 6       |

Out-of-range values are clamped, not rejected. `level=1` should be
measurably faster than the max level, and the max level produces
≥ the compression ratio of `level=1` on a realistic corpus. The
plumbing into match-finder depth / nice-match cutoff / strategy is
honest end-to-end — see each `tests/<algo>.rs` for the size-relation
assertions.

Algorithms without a level (rle, lz4, snappy, lzw, lzo, lzx,
quantum, rar1/2/3/5) use `type EncoderConfig = ();`.

### Other

- 17 algorithms ported under the new trait API across 4 parallel-agent
  rounds, ~640 tests total (was ~178 on v0.2.0).
- `tests/<algo>.rs` files rewritten in the canonical
  `(Progress, Status)` pattern; `tests/rle.rs` is the reference example.

## [0.2.0](https://github.com/KarpelesLab/compcol/compare/v0.1.0...v0.2.0) - 2026-05-28

### Other

- Fix Windows CI: gate first_chunk_control_byte() helper with #[cfg(unix)]
- Add 'all' meta-feature; update README; fix two latent CI regressions
- Implement RAR1/RAR2/RAR3/RAR5 decoders via parallel agents
- Scaffold rar1/rar2/rar3/rar5 — decoder-only, encoders permanently Unsupported
- Add LZO / LZX / Quantum — three more algorithms via parallel agents
- Scaffold lzo / lzx / quantum + Cargo wiring
- Remove standalone lzma2 module; xz already wraps the same LZMA2 codec
- Round 4: improve deflate, zstd, brotli encoder compression ratio
- Add benchmark harness (examples/bench.rs) + snapshot results (BENCH.md)
