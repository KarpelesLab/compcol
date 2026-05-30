# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **StuffIt 5 Arsenic codec** (`arsenic`, compression method 15): BWT-based —
  a carry-less range/arithmetic decoder (9 adaptive models) → selector-driven
  un-MTF/un-RLE → inverse BWT → optional de-randomization → final RLE →
  CRC-32. Decode-only, self-terminating (in-band end-of-blocks + CRC trailer).
  Clean-room from a facts-only spec, with the fixed interop tables (9 model
  parameters + 256-entry randomization table) supplied as a separately-licensed
  adjunct. Validated bit-exactly against real StuffIt 5 archives — 46 method-15
  forks across 5 fixtures verify (in-stream CRC-32 + declared size), and all 11
  data forks SHA-256 match the reference `unar` output.

- **StuffIt classic LZAH codec** (`lzah`, compression method 5): LZSS sliding
  window (4 KiB, MSB-first) + a single 314-symbol adaptive Huffman tree,
  decode-only. Clean-room from a facts-only functional spec; the raw fork
  payload is decoded with the uncompressed size supplied out of band via
  `DecoderConfig::with_len` (StuffIt has no in-band end marker). Validated
  bit-exactly against real classic `SIT!` archives — 17 method-5 forks across
  5 fixtures pass the stored per-fork CRC-16.

- **LHA / LZH codecs** (`lha`): `-lh1-` (adaptive Huffman) and
  `-lh4-/-lh5-/-lh6-/-lh7-` (static Huffman) LZSS methods, encoder + decoder.
  Clean-room from Okumura's public-domain LZHUF / ar002 descriptions.
- **BCJ branch-converter filters** (`bcj`): reversible x86, ARM, ARM-Thumb,
  ARM64, PowerPC, SPARC, IA-64, and RISC-V filters (public-domain LZMA SDK
  lineage), encoder + decoder.
- **Delta filter** (`delta`): reversible byte-wise delta with a configurable
  distance (1..=256), encoder + decoder.
- **ARC Crunch** (`arc_crunch`, method 8, 12-bit dynamic LZW) and **ARC
  Squeeze** (`arc_squeeze`, method 4, RLE + static Huffman), encoder + decoder.
- **StuffIt method 13 decoder** (`sit13`, "LZ+Huffman"): LZSS (64 KiB window,
  LSB-first) + two per-stream 321-symbol Huffman codes switched per token,
  obtained via the fixed meta-code or one of five predefined code-length sets;
  explicit end-of-stream symbol. Decode-only. Clean-room from a facts-only
  spec, with the fixed interop tables supplied as a separately-licensed
  adjunct. Validated bit-exactly against real classic `SIT!` archives —
  28 method-13 forks pass the stored per-fork CRC-16, covering all five
  control modes. (Upgrades the earlier building-blocks-only `Unsupported`
  stub.)

  Note: `lha` and `arc_*` are clean-room from public specs and validated by
  their own encoder↔decoder round-trip, not against reference-tool output.

## [0.5.0](https://github.com/KarpelesLab/compcol/compare/v0.4.7...v0.5.0) - 2026-05-30

### Other

- bound block decode output with raw_max to prevent OOM (parity with lz4) ([#62](https://github.com/KarpelesLab/compcol/pull/62))
- add RAR trademark + clean-room licensing note to README ([#61](https://github.com/KarpelesLab/compcol/pull/61))
- Security hardening: DoS fixes across decoders (panics, OOM, decompression bombs) ([#59](https://github.com/KarpelesLab/compcol/pull/59))

### Security

Decoder hardening against malicious/untrusted compressed input (DoS):

- zstd: bound the FSE Huffman-weight decode loop (a `num_bits == 0` table
  could spin forever / OOM); cap `window_size` and literal `Regenerated_Size`
  at 128 MiB to bound decompression-bomb frames.
- xz: drop the unbounded `Vec::reserve` driven by the Index `NumRecords`
  varint (could panic with capacity-overflow or OOM-abort).
- lz4 / lzo: bound raw block-decode output (`block::decode_block` now takes a
  `raw_max` ceiling) on the public block API and the streaming paths,
  preventing ~255× match-copy decompression bombs.
- lzfse/LZVN: reject match copies that exceed the block's declared size
  before materializing them.
- xpress_huffman: bound `decode_loop` output backlog so a multi-block stream
  can't accumulate unbounded internal memory before draining.
- zip_reduce: decode through a bounded sliding output window instead of
  retaining the entire (header-declared) output in memory.
- brotli: avoid a panic when a single-block-type length counter is exhausted.
- bzip2: enforce the Kraft–McMillan check on Huffman tables.
- quantum: end frames on overshooting matches (signed `frame_todo`).
- lzx: track the intel-translation filesize read with a flag, not a
  `0xFFFFFFFF` sentinel that a real filesize could collide with.
- ppmd: cap the order-0 arena allocation to what is actually used rather than
  the advertised (attacker-controlled, up to 255 MiB) memory size.
- rar5: split wide high-distance bit reads to respect the 16-bit reader
  contract (debug-build panic); propagate filter-apply failures instead of
  emitting raw bytes.
- lzs: stop emitting once the declared output length is reached.
- limit: clamp the budget in `u64` to avoid a 32-bit truncation that could
  stall the decode loop.
- io/tokio_io: surface truncated streams as an error instead of a silent EOF.
- vec: add `decompress_to_vec_capped{,_with}` bounded one-shot helpers;
  documented that the unbounded variants must not be used on untrusted input.
- cli: don't delete a pre-existing `--force` output target if the codec
  errors mid-stream (data loss); the non-`--force` `create_new` symlink/TOCTOU
  protection is retained.

### Changed

- **Breaking:** `compcol::lz4::block::decode_block` and
  `compcol::lzo::block::decode_block` now take a third `raw_max: usize`
  argument bounding the decoded output. Pass `usize::MAX` to preserve the
  previous unbounded behavior for trusted input.

## [0.4.7](https://github.com/KarpelesLab/compcol/compare/v0.4.6...v0.4.7) - 2026-05-30

### Other

- Security fixes 2026 05 30 ([#58](https://github.com/KarpelesLab/compcol/pull/58))
- Add LZ5 / Lizard codec ([#56](https://github.com/KarpelesLab/compcol/pull/56))
- Add lzham (LZH0 framing parser; payload Unsupported) ([#55](https://github.com/KarpelesLab/compcol/pull/55))
- Add LZSS codec (Storer-Szymanski / Okumura variant) ([#54](https://github.com/KarpelesLab/compcol/pull/54))
- Add LZS codec (Lempel-Ziv-Stac, RFC 1974) ([#53](https://github.com/KarpelesLab/compcol/pull/53))
- Add ZIP method 6 (Implode) decoder ([#52](https://github.com/KarpelesLab/compcol/pull/52))
- Add PKZip Reduce (methods 2-5, decoder-only) ([#51](https://github.com/KarpelesLab/compcol/pull/51))
- Add ZIP method 1 (Shrink) decoder ([#50](https://github.com/KarpelesLab/compcol/pull/50))
- Add PackBits codec (Apple TN1023 RLE, encoder + decoder) ([#49](https://github.com/KarpelesLab/compcol/pull/49))

## [0.4.6](https://github.com/KarpelesLab/compcol/compare/v0.4.5...v0.4.6) - 2026-05-30

### Other

- add deflate64, amiga_lzx, bzip2, PPMd, Xpress, Xpress Huffman, LZNT1 ([#47](https://github.com/KarpelesLab/compcol/pull/47))
- Add Microsoft Xpress (Plain LZ77) codec ([#45](https://github.com/KarpelesLab/compcol/pull/45))
- Add lznt1 (encoder + decoder) ([#44](https://github.com/KarpelesLab/compcol/pull/44))
- Add xpress_huffman (encoder + decoder) ([#43](https://github.com/KarpelesLab/compcol/pull/43))
- Add ppmd (PPMd / PPMII variant H, decoder-only) ([#42](https://github.com/KarpelesLab/compcol/pull/42))
- Add deflate64 (encoder + decoder) ([#41](https://github.com/KarpelesLab/compcol/pull/41))

## [0.4.5](https://github.com/KarpelesLab/compcol/compare/v0.4.4...v0.4.5) - 2026-05-29

### Other

- emit direct (uniform) distance bits MSB-first to match liblzma (closes #14) ([#39](https://github.com/KarpelesLab/compcol/pull/39))

## [0.4.4](https://github.com/KarpelesLab/compcol/compare/v0.4.3...v0.4.4) - 2026-05-29

### Other

- *(brotli-u64-bitreader)* brotli: u64 accumulator + refill in BitSource ([#37](https://github.com/KarpelesLab/compcol/pull/37))
- compute block cost from frequency histograms ([#36](https://github.com/KarpelesLab/compcol/pull/36))
- u64 accumulator in RevBitReader to eliminate per-bit byte loop ([#35](https://github.com/KarpelesLab/compcol/pull/35))
- byte-indexed table for forward CRC-32/MPEG-2 update ([#34](https://github.com/KarpelesLab/compcol/pull/34))
- reuse decoder LzmaCore across full-reset chunks ([#33](https://github.com/KarpelesLab/compcol/pull/33))
- *(pow2-mask)* Power-of-two window mask in 3 algorithms (amiga_lzx, rar3, rar5) ([#32](https://github.com/KarpelesLab/compcol/pull/32))
- *(bulk-match-copy)* Bulk match copy via extend_from_within / copy_within across 14 algorithms ([#31](https://github.com/KarpelesLab/compcol/pull/31))
- *(huffman-lut)* Huffman primary LUT for O(1) symbol decode across 7 algorithms ([#30](https://github.com/KarpelesLab/compcol/pull/30))
- lock the .lzma "alone" encoder header contract against #14 regression ([#29](https://github.com/KarpelesLab/compcol/pull/29))
- probe inner at the exact-budget boundary so trailer steps complete (closes #26) ([#27](https://github.com/KarpelesLab/compcol/pull/27))

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
