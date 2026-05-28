# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
