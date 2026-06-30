# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- *(decoder bridge)* a decoder that buffers a whole block internally (notably
  `bzip2`) could fail a naive decode loop with `UnexpectedEnd`. When the
  caller's `output` buffer filled mid-block, the `RawDecoder`→`Decoder` bridge
  reported `InputEmpty` (because the decoder had already absorbed all the input)
  instead of `OutputFull`; a loop that stops on `InputEmpty` then called
  `finish` on a half-drained stream and got `UnexpectedEnd`. The bridge now
  returns `OutputFull` whenever the output buffer is full, which is always the
  correct "drain and call again" signal. Affected `bzip2` round-trips whenever a
  decoded block was larger than the output buffer.
- *(lzma2/xz)* eliminated quadratic encode time on incompressible/low-match
  input. The match finder's hash head table was a fixed 64 Ki buckets, so as the
  input grew the per-bucket chains lengthened and every probe walked work that
  scaled with the input — `xz` encode of 4 MiB of random data took ~6.7 s and
  kept worsening. The head table is now sized to the match-finder window (like
  liblzma sizes its hash to the dictionary), so chains stay O(1) and encode is
  linear. Output is byte-for-byte unchanged.

### Changed

- *(lzma2/xz)* faster optimal-parse encoder, output unchanged: length-symbol
  prices are cached per `pos_state` and refreshed periodically (instead of an
  8-bit bittree walk per length per position), the new-match distance price is
  computed once per dist-state band rather than per length, and match-length
  comparison runs eight bytes at a time. Net: ~3× fewer instructions on
  natural-language text, ~4× on long-run data, ~1.6× on mixed source code, with
  identical compressed output.

## [0.6.6](https://github.com/KarpelesLab/compcol/compare/v0.6.5...v0.6.6) - 2026-06-27

### Added

- *(qpack)* dynamic-table encoder driving the encoder stream

### Added

- *(qpack)* dynamic-table encoder: `QpackEncoder::with_dynamic_table` + `encode`
  drive the encoder stream (Set Dynamic Table Capacity, Insert with
  Name Reference against static/dynamic names, Insert with Literal Name) and
  emit field sections with dynamic indexed / name-reference representations and
  a non-zero Required Insert Count. Entries referenced by a field section are
  never evicted by inserts in the same batch; sensitive fields stay out of the
  table (never-indexed). The previous static-only `encode_field_section` path is
  unchanged. QPACK is now fully bidirectional (encode + decode, static +
  dynamic), matching HPACK.

## [0.6.5](https://github.com/KarpelesLab/compcol/compare/v0.6.4...v0.6.5) - 2026-06-15

### Fixed

- docs.rs build + add docs.rs-config CI job

### Other

- changelog for bounded-memory LZMA encoders; demote private doc link
- early-commit long matches in the optimal parser
- bounded-memory sliding-window streaming encoders

## [0.6.4](https://github.com/KarpelesLab/compcol/compare/v0.6.3...v0.6.4) - 2026-06-15

### Fixed

- *(cli)* drain decoder's internal block buffer before finish

### Other

- changelog for CLI decode-drain fix
- changelog for iterative optimal brotli parse
- *(enc)* enable optimal parse at q9 (2 passes)
- *(enc)* cargo fmt encoder_optimal
- *(enc)* price ring-reuse short codes for explicit DP matches
- *(enc)* iterative zopfli-style optimal parse at q10/q11
- changelog for round-2 ratio + speed work
- *(enc)* cross-block matching + two-pass statistics-driven optimal parse
- *(enc)* single-pass scan-and-shift move-to-front
- tighten encode/decode hot loops
- *(enc)* replace prefix-doubling rotation sort with SA-IS
- test linked-block cross-boundary references and cross-tool decode
- implement frame linked-block mode (cross-block match window)
- emit continue-dict chunks; feed uncompressed chunks to the dict
- continuous cross-chunk dictionary in the shared chunk encoder

### Fixed

- **docs.rs build**: add the crate-root `#![cfg_attr(docsrs, feature(doc_cfg))]`
  that the crate's per-module `#[cfg_attr(docsrs, doc(cfg(...)))]` labels
  require. Without it the docs.rs build (nightly + `--cfg docsrs`) failed with
  E0658, even though the plain stable `cargo doc` CI job — where `docsrs` is
  unset and the attributes are inert — passed. A new CI job (`docsrs`) now
  builds the docs the way docs.rs does (nightly + `--cfg docsrs`, warnings
  denied) so this gap is caught before publishing.

### Fixed

- *(cli)* `compcol -d` no longer truncates highly-compressible large inputs.
  The streaming decode loop stopped once the compressed input was consumed,
  leaving output a block-buffering decoder (notably bzip2) still held
  internally — `finish` does not flush it, so `compcol -t bzip2 -d` cut output
  at 64 KiB. A drain loop now pulls the decoder's buffered output before
  finishing. (Library decoders were already correct; this was CLI-only.)

### Added

- *(brotli enc)* iterative, statistics-driven optimal LZ77 parse
  (zopfli-style forward DP) at quality 9–11. The cost model is rebuilt from
  the previous pass's command/literal/distance histograms each round;
  candidate matches are precomputed once and shared across passes. Improves
  the max-quality ratio on the 2.9 MB corpus from 707558 to 669632 bytes
  (1.473 → 1.394 vs `brotli -q 11`) and q9 from 709198 to 680156, with
  reference cross-decode verified.

### Performance

- **Round 2 of encoder ratio + codec speed work** (encoder-only for ratio;
  decoders unchanged and every format still decodes byte-for-byte with its
  reference tool). Ratios on a 2.9 MB real-source corpus, our max level vs the
  reference's max (`ours/ref`, lower is better):
  - **xz / lzma2**: 1.51 → **1.10** — the LZMA2 chunk encoder now keeps the LZ
    dictionary **continuous across chunks** (emits `0xC0` continue-dict control
    bytes after the first `0xE0`, with a single match-finder spanning the whole
    input) instead of resetting every 64 KiB. Closes nearly all of the gap to
    the `.lzma` path (1.07). Also fixes the raw-LZMA2 decoder to feed
    uncompressed (stored) chunks into the dictionary.
  - **zstd**: 1.40 → **1.04 vs `zstd -19`** at max level (now beats `zstd -12`)
    — cross-block matching over a retained sliding window (≤8 MiB, within the
    advertised window) plus a two-pass, statistics-driven optimal parse
    (btultra2-style repricing) and repeat-offset-aware DP pricing.
  - **lz4**: 1.18 → **1.02** (frame, `-l 12` beats `lz4 -9`) — implemented LZ4
    frame **block-linked** mode so matches reference up to 64 KiB of prior
    blocks' output, not just the current block.
- **Standalone-codec encode throughput** (output byte-identical):
  - **bwt** encode ~3× faster — replaced the prefix-doubling rotation sort with
    linear-time SA-IS suffix-array construction.
  - **mtf** encode ~2.3× faster (single-pass scan-and-shift); **rangecoder**
    encode/decode ~+15% (tightened hot loops).
- **Bounded-memory LZMA encoders.** The `xz`, raw `lzma2`, and `.lzma`
  encoders now stream with a sliding window whose match finder, history, and
  hash chains are all `O(dict_size)` (default 4 MiB) instead of buffering the
  whole input — peak memory is now independent of input length (≈45 MB RSS
  encoding a 600 MB file; previously O(input) and OOM-prone). The continuous
  dictionary, and therefore the ratio, is unchanged (matches already could not
  reach past `dict_size`): `xz`/`.lzma` on the 2.9 MB corpus stay within 0.03%.
  Output continues to decode byte-for-byte with system `xz`. (`zstd` already
  streamed within its bounded window.)

## [0.6.3](https://github.com/KarpelesLab/compcol/compare/v0.6.2...v0.6.3) - 2026-06-15

### Added

- add QPACK (RFC 9204) + standalone Huffman / range-coder / MTF / BWT codecs

### Fixed

- *(lzma2)* restore Debug/Clone on Encoder; document the stub→struct break

### Other

- changelog for encoder compression-ratio improvements
- *(enc)* literal context modeling + cost-aware match selection
- enable optimal parse from level 13
- price-based optimal parse at high levels (btopt-style)
- distance-aware repeat-offset preference in match selection
- FSE-compressed Huffman weights for >128-symbol literal alphabets
- skip redundant greedy guard pass on large inputs
- cost-based optimal parse for compression ratio
- price-based optimal parse for top levels + fix EOB conformance
- HC hash-chain match finder + lazy parse, wire level knob
- size blocks by post-RLE-1 length, like reference bzip2
- multi-table Huffman optimization (sendMTFValues)
- port reference BZ2_hbMakeCodeLengths (depth-aware, 17-bit cap)
- README + CHANGELOG for lzma2 encoder, lzfse bvx2, lz5 rationale
- document why Huff0 sub-streams stay Unsupported (no functional change)
- general FSE table construction (k/k-1 split) for bvx2
- implement bvx2 (LZFSE v2) block decoder
- implement raw LZMA2 encoder (replace Unsupported stub)

### Performance

- **Encoder compression-ratio improvements** across the high-effort formats
  (encoder-only; decoders unchanged, and every format's output still decodes
  byte-for-byte with its reference tool — `xz`/`lzma`/`zstd`/`brotli`/`bzip2`/
  `lz4 -d`). Measured on a 2.9 MB real-source corpus, our max level vs the
  reference's max level (`ours/ref`, lower is better):
  - **bzip2**: 1.07 → **1.00** — the encoder was building a single Huffman
    table and pinning all selectors to 0; now does the reference's up-to-6
    tables with 4 refinement passes (`sendMTFValues`) + depth-aware code
    lengths + post-RLE1 block sizing. Output is byte-identical to `bzip2 -9`.
  - **lzma**: 1.57 → **1.07** — cost-based optimal parse (LZMA-SDK-style
    price model + DP over literals/matches/rep-matches) replacing the greedy
    parse. `.lzma` is now near parity with `xz -9`.
  - **lz4**: 1.53 → **1.18** — new HC (hash-chain + lazy) and price-based
    optimal parse tiers wired to the level knob (`-l 9` does HC, `-l 12`
    optimal); the fast low levels are unchanged. Also fixed a latent
    conformance bug where a match could start in the final 12 bytes of a block
    (rejected by strict `lz4 -d`).
  - **zstd**: 1.49 → **1.40** — literals were always falling back to a raw
    (un-entropy-coded) block because the Huffman-weight writer capped at 128
    symbols; added FSE-compressed weights, plus a price-based optimal parse and
    repeat-offset preference at high levels.
  - **xz / lzma2**: 1.60 → **1.51** — benefits from the shared LZMA optimal
    parse; the remaining gap is the 64 KiB per-chunk dictionary/model reset
    framing, not the parse.
  - **brotli**: 1.50 → **1.48** — literal context modeling (multi-tree context
    map), cost-aware match selection, and repeat-distance preference.
  - **deflate/zlib/gzip** (≈1.01 vs `gzip -9`) and **lzw** were already at
    parity and are unchanged.

### Added

- **Raw LZMA2 encoder** (`lzma2`): `compcol::lzma2::Lzma2` now encodes as well
  as decodes — it emits the raw 7-Zip LZMA2 chunk stream (full dict/props/state
  reset per chunk, uncompressed-chunk fallback when compression would expand,
  `0x00` end marker), reusing the xz LZMA2 chunk codec. The dictionary size is
  out of band (the 7z coder property); the encoder uses the 4 MiB default so a
  default-config decoder round-trips. Validated by round-trip and by decoding
  the output through the shared xz LZMA2 codec.
- **LZFSE `bvx2` decoding** (`lzfse`): the core LZFSE v2 block type (LZ77 +
  Finite State Entropy) now decodes — full v2 header parse, 4-way interleaved
  literal FSE, three interleaved L/M/D FSE streams (reverse bitstreams), and LZ
  reconstruction. The FSE table construction matches Apple's general
  `fse_init_decoder_table` (the `k`/`k-1` split), so arbitrary frequency tables
  are handled, not just power-of-two ones. Validated by round-trip against an
  in-crate v2 encoder plus a frozen hand-written non-dyadic vector; there is no
  Apple `lzfse` tool in the build environment, so real-stream interop is
  best-effort but follows the documented format precisely. `bvx1` (v1) remains
  `Unsupported`.

### Changed

- **Breaking:** `compcol::lzma2::Encoder` is now a normal (stateful) struct
  instead of the former permanently-`Unsupported` unit-struct stub, because the
  working encoder buffers chunk state. As a result it **no longer implements
  `Copy`** and can no longer be constructed via a unit-struct literal; construct
  it through `Lzma2::encoder()` as with every other codec. It still derives
  `Debug` + `Clone`. (No effect on the decoder or any other codec.)
- **lz5 (Lizard) Huffman sub-streams** stay `Unsupported`, now with a precise
  rationale in the module docs: the Huff0 entropy stage selects X1/X2 from
  `(regenSize, comprLen)` at runtime and there is no reference encoder or
  fixture available to validate a decoder bit-exactly, so — consistent with the
  crate's `lzham`/`sit13` policy — it is left honest rather than shipped blind.
  The docs record the concrete reuse path (zstd's X1 Huff0 decoder + an X2
  decoder + the `HUF_selectDecoder` heuristic) for a future round with fixtures.


### Added

- **HTTP/3 QPACK header compression** (RFC 9204) behind the new `qpack`
  feature. `compcol::qpack::{QpackEncoder, QpackDecoder}` — full decoder
  (static table, dynamic table built from the encoder-stream instructions, and
  all field-line representations) validated byte-for-byte against the RFC 9204
  Appendix B examples; the encoder uses the static table + literals (Required
  Insert Count = 0). Reuses the HPACK string Huffman code and `HeaderField`.
- **Standalone primitives / transforms**, each a first-class codec reachable
  through the factory:
  - `huffman` — a self-delimiting canonical (length-limited, order-0) Huffman
    codec, `compcol::huffman_codec::Huffman` (name `"huffman"`).
  - `rangecoder` — an adaptive order-0 binary range coder,
    `compcol::rangecoder::RangeCoder` (name `"range"`).
  - `mtf` — the Move-To-Front reversible transform, `compcol::mtf::Mtf`
    (name `"mtf"`), a streaming length-preserving filter.
  - `bwt` — a standalone block Burrows-Wheeler Transform, `compcol::bwt::Bwt`
    (name `"bwt"`), with a per-block primary index. Pairs with `mtf` + an
    entropy coder to build a bzip2-style pipeline from parts.

## [0.6.2](https://github.com/KarpelesLab/compcol/compare/v0.6.1...v0.6.2) - 2026-06-12

### Other

- changelog entry for codec throughput optimizations
- bulk match-copy in decode loops
- bulk LZ77 match-copy in decode window loops
- bulk match-copy in static-Huffman decode hot loop
- vectorizable filter loop via direct predecessor indexing
- single-write LZW string assembly + literal fast path
- single-write LZW string assembly + literal fast path
- byte-wide FSA Huffman decoder
- bulk copy_within for non-overlapping match copies
- amortize decoder history trim (O(n²) → O(n))
- recurse SA-IS reduced problem in place (drop per-level copy)
- cut SA-IS allocations and inline induced-sort hot paths
- *(snappy)* skip-step accelerator in encoder match search
- *(lzo)* skip-step accelerator in encoder match search
- *(lzw)* single-pass string emit, drop scratch stack
- *(decoders)* bulk overlapping match copy in lz4/lz5/lzo/snappy
- fetch each FSE entry once per sequence (symbol + advance share load)
- hoist LL/ML base+extra tables to module-level const
- inline RevBitReader::read fast path, split wide reads out of line
- skip zero-bit reads and inline FSE state transitions
- faster Huffman literal decode via peek/consume
- widen Huffman fast-path LUT from 9 to 11 bits
- skip literal context lookup when there is a single tree
- keep bit accumulator across Huffman LUT hits
- bulk overlapping match-copy in decoder drain loops (.lzma decode)
- bulk overlapping match-copy in decode_chunk (xz/lzma2 decode)
- bulk match-copy in decode_chunk (xz/lzma2 decode)
- vectorize decoder match-copy incl. overlapping runs
- replace per-literal modulo with a wrap branch in emit_byte
- vectorize decoder match-copy incl. overlapping runs
- bulk-copy literal runs in decoder (~1268 -> ~4600 MB/s, 3.5x)
- CRC-32 slice-by-8 (642 -> 2525 MB/s, 3.9x)

### Performance

- **Throughput optimizations across the codec suite**, all preserving
  byte-identical decoder output (validated by the existing round-trip and
  reference-fixture tests) — no `unsafe`, no new dependencies. Highlights:
  - **deflate / deflate64** decode: vectorized match-copy (contiguous spans +
    doubling `copy_within` for overlapping runs) — deflate Random decode
    ~3.5×, deflate64 long-match decode several×; zlib/gzip inherit the gains.
  - **LZMA / xz** decode: bulk (and overlapping) dictionary match-copy —
    RLE-heavy `.lzma` decode up to ~6×.
  - **zstd** decode: inlined backward bit-reader fast path, single-load FSE
    state transitions, hoisted LL/ML tables — ~1.5× on Huffman/FSE-heavy input.
  - **brotli** decode: wider Huffman fast LUT, single-tree literal fast path,
    bit-accumulator kept across LUT hits — literal-heavy decode ~2.3×.
  - **lz4 / lz5 / lzo / snappy** decode: bulk overlapping match-copy
    (multi-GB/s); **lzo / snappy** encoder skip-step match search (~6× on
    incompressible input). **lzw** single-pass string emit.
  - **xpress-huffman** decode: fixed an O(n²) history-trim to O(n) (orders of
    magnitude on large inputs); **lznt1** bulk match-copy.
  - **lha / rar1–5 / zip-implode·reduce·shrink / arc-crunch·squash**: bulk
    LZSS/LZW window copy; **delta** filter encode ~15× (auto-vectorized);
    **hpack** byte-wide Huffman decode.
  - **bzip2** encode: reduced SA-IS suffix-array allocations and in-place
    recursion (+14–31% on the BWT build, the dominant encode cost).
  - **checksum**: CRC-32 slice-by-8 (~4×); **rle90** bulk literal copy (~3.5×).

## [0.6.1](https://github.com/KarpelesLab/compcol/compare/v0.6.0...v0.6.1) - 2026-06-12

### Other

- Security hardening: fix decompression bombs, OOB panic, and overflow in decoders ([#88](https://github.com/KarpelesLab/compcol/pull/88))
- Add HTTP/2 HPACK (RFC 7541) and LHA -lh2- codecs ([#89](https://github.com/KarpelesLab/compcol/pull/89))
- replace two decoder-path unwrap/expect with error returns ([#86](https://github.com/KarpelesLab/compcol/pull/86))

### Added

- **HTTP/2 HPACK header compression** (RFC 7541) behind the new `hpack`
  feature. `compcol::hpack::{HpackEncoder, HpackDecoder}` implement the full
  header codec — static + dynamic indexing tables, N-bit-prefix integers,
  string literals, and all field representations (indexed, literal
  with/without indexing, never-indexed, dynamic-table size update). Validated
  byte-for-byte against the RFC 7541 Appendix C worked examples. The §5.2
  string Huffman primitive is also exposed as the `Http2Huffman` codec
  (name `h2-huffman`) through the uniform `Encoder`/`Decoder` traits.
- **LHA `-lh2-`** added to the `lha` feature: 8 KiB-window LZSS with adaptive
  (dynamic) Huffman for both literals/lengths and match positions. Like `lh1`
  it is continuous and size-terminated, so its decoder takes the uncompressed
  length via `DecoderConfig::with_len`. Clean-room, round-trip validated.

## [0.6.0](https://github.com/KarpelesLab/compcol/compare/v0.5.1...v0.6.0) - 2026-06-03

### Other

- make EncoderConfig/DecoderConfig non_exhaustive + add builders ([#85](https://github.com/KarpelesLab/compcol/pull/85))
- configurable window — encoder max_distance + decoder window_size ([#84](https://github.com/KarpelesLab/compcol/pull/84))
- magic-byte format auto-detection + CLI auto-detect on -d ([#82](https://github.com/KarpelesLab/compcol/pull/82))
- add decode targets for 10 recently-added codecs ([#81](https://github.com/KarpelesLab/compcol/pull/81))
- add README badges, SECURITY.md, and CONTRIBUTING.md ([#80](https://github.com/KarpelesLab/compcol/pull/80))

### Added

- **Configurable deflate window** for small-window interop and memory-limited
  decoding:
  - `deflate::EncoderConfig::max_distance` caps the LZ77 back-reference
    distance (clamped to `1..=32768`), so the encoder can target a decoder
    with a smaller sliding window — e.g. qemu/qcow2 inflates clusters with a
    4 KiB window (`inflateInit2(-12)`) and rejects farther references.
  - `deflate::DecoderConfig::window_size` sizes the decoder's history ring
    (clamped to `1..=32768`, default 32 KiB): it allocates only that much and
    rejects any back-reference beyond it with `Error::InvalidDistance` — both
    a memory knob for constrained systems and a way to validate that an
    encoded stream stays within a given window.

  Both configs gained `with_*` builders (`EncoderConfig::default().with_level(9)
  .with_max_distance(4096)`, `DecoderConfig::default().with_window_size(4096)`).

### Changed

- **Breaking:** `deflate::EncoderConfig` and `deflate::DecoderConfig` are now
  `#[non_exhaustive]`. Construct them via `default()` + the `with_*` builders
  instead of a struct literal; in return, future tuning knobs can be added
  without breaking downstream code.

- **Format auto-detection** (`factory::detect`): sniff a stream's leading
  bytes and return the matching codec name by magic signature (gzip, zlib,
  xz, zstd, bzip2, lz4-frame, RAR, StuffIt/StuffIt 5), feature-gated so only
  compiled-in codecs are reported and conservative enough to prefer `None`
  over a wrong guess. The CLI now auto-detects the format on `-d` when no
  `-t` is given.

## [0.5.1](https://github.com/KarpelesLab/compcol/compare/v0.5.0...v0.5.1) - 2026-05-30

### Other

- raw LZMA2 decoder + BCJ2 4-stream filter ([#74](https://github.com/KarpelesLab/compcol/pull/74)) ([#79](https://github.com/KarpelesLab/compcol/pull/79))
- Add RLE90 ([#75](https://github.com/KarpelesLab/compcol/pull/75)) and ARC Squashed / method 9 ([#76](https://github.com/KarpelesLab/compcol/pull/76)) codecs ([#78](https://github.com/KarpelesLab/compcol/pull/78))
- StuffIt 5 Arsenic (method 15) decoder, validated against real archives ([#73](https://github.com/KarpelesLab/compcol/pull/73))
- real StuffIt method-13 (LZ+Huffman) decoder, validated against real archives ([#72](https://github.com/KarpelesLab/compcol/pull/72))
- StuffIt classic method-5 (LZAH) decoder, validated against real archives ([#71](https://github.com/KarpelesLab/compcol/pull/71))
- decode the raw method payload (no invented length prefix) ([#70](https://github.com/KarpelesLab/compcol/pull/70))
- *(release-plz)* create the GitHub Release with RELEASE_PLZ_TOKEN ([#63](https://github.com/KarpelesLab/compcol/pull/63))
- Add LHA, BCJ/Delta filters, ARC Crunch/Squeeze, and StuffIt-13 building blocks ([#68](https://github.com/KarpelesLab/compcol/pull/68))

### Added

- **Raw LZMA2 decoder** (`lzma2`): decodes the raw 7-Zip LZMA2 chunk stream
  (codec id 21) — control-byte-framed chunks, self-terminating — distinct from
  the `.xz` container. The 1-byte 7z dict-size coder property is passed via
  `DecoderConfig::with_dict_prop`. Reuses the existing xz LZMA2 engine (the
  shared codec was relocated to a crate-internal `lzma2_internal` module; `xz`
  behavior unchanged). Decode-only.
- **BCJ2 filter** (`bcj2`): the 7-Zip 4-stream x86 branch filter
  (`0303011B`), encode + decode via a dedicated `compcol::bcj2::{encode,decode}`
  function API (the 4-input shape doesn't fit the single-stream `Decoder`
  trait). Public-domain LZMA SDK algorithm; round-trip validated.
- **RLE90 codec** (`rle90`): the `0x90`/DLE run-length variant shared by ARC
  method 3 ("packed") and classic StuffIt method 1, encoder + decoder.
  Byte-compatible with the `arc_squeeze` internal RLE90 pre-pass.
- **ARC Squashed codec** (`arc_squash`, method 9): fixed 13-bit LZW
  (PKARC/PKPAK variant, no RLE), encoder + decoder.

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
