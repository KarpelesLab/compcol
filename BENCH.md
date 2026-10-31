# Benchmark snapshot

Output of `cargo run --release --features all --example bench` on
2026-07-04 (Linux 6.12, Intel Core i9-14900K). Reproduce via:

```sh
cargo run --release --features all --example bench
```

For a single codec + input without the reference subprocess overhead,
`examples/micro.rs` gives cleaner before/after numbers:

```sh
cargo run --release --features all --example micro -- lz4 lorem 1048576 20 enc
```

## Quick "which algorithm should I use?" guide

Numbers below are for **1 MiB Lorem ipsum** input on this host —
roughly representative of natural-language text. Higher MB/s is
faster; lower output ratio (B/B) is smaller.

| Goal | Algorithm | Ratio | Our enc MB/s | Our dec MB/s |
|---|---|---|---|---|
| **Fastest encode + decode** | `lz4` | 0.010 | 14856 | 13592 |
| **Fastest, tiny LZ output** | `lzo` | 0.013 | 13515 | 10942 |
| **Best ratio (English text)** | `lzma` | 0.001 | 22.6 | 3761 |
| **Best ratio + decent speed** | `zstd` | 0.000 | 449 | 2011 |
| **Most universal (Unix tooling)** | `gzip` | 0.005 | 533 | 1820 |
| **Best ratio with structured-text bias** | `brotli` | 0.005 | 161 | 1156 |

## How to read this

- **Bytes** — input size.
- **Ours: out** — output size from our encoder.
- **Ours: ratio** — `out / input` (lower is better).
- **Ours: enc ms / dec ms** — median wall-clock time for the full
  streaming codec round-trip with 64 KiB caller-side buffers.
- **Ours: enc MB/s / dec MB/s** — throughput. **`bytes / 1e6 / sec`**
  i.e. decimal MB/s.
- **Reference** — system tool we shelled out to.
- **Ref: enc / dec MB/s** — throughput of the reference, **including
  subprocess fork+exec startup** (~1–3 ms on Linux). Inputs are
  1 MiB+ so the overhead is <5% of the work for slow codecs and
  5–20% for very fast ones (`lz4`, `snappy`, `lzo`).
- **Δ enc / Δ dec** — `ours / ref` MB/s. **`1.0` means equal,
  `>1` means ours is faster, `<1` means ours is slower.**

## Detailed results

Throughput in MB/s (decimal). Time in ms. Median of 3 timed runs
after 1 warmup.

| Algorithm | Input | Bytes | Ours: out | Ours: ratio | Ours: enc ms | Ours: enc MB/s | Ours: dec ms | Ours: dec MB/s | Reference | Ref: ratio | Ref: enc ms | Ref: enc MB/s | Ref: dec ms | Ref: dec MB/s | Δ enc | Δ dec |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `adc` | Lorem 1 MiB | 1048576 | 103789 | 0.10 | 1.13 | 927.8 | 0.37 | 2811 | — | — | — | — | — | — | — | — |
| `adc` | Zeros 1 MiB | 1048576 | 46955 | 0.04 | 0.85 | 1234 | 0.79 | 1325 | — | — | — | — | — | — | — | — |
| `adc` | Random 1 MiB | 1048576 | 1056742 | 1.01 | 2.42 | 434.0 | 0.09 | 11551 | — | — | — | — | — | — | — | — |
| `brotli` | Lorem 1 MiB | 1048576 | 5643 | 0.01 | 6.51 | 161.1 | 0.91 | 1156 | brotli | 0.00 | 11.9 | 87.7 | 3.04 | 344.7 | 1.84 | 3.35 |
| `brotli` | Zeros 1 MiB | 1048576 | 961 | 0.00 | 1.19 | 880.1 | 0.09 | 12087 | brotli | 0.00 | 16.5 | 63.6 | 2.46 | 426.2 | 13.8 | 28.4 |
| `brotli` | Random 1 MiB | 1048576 | 1058731 | 1.01 | 388.1 | 2.70 | 10.4 | 100.7 | brotli | 1.00 | 203.6 | 5.15 | 2.74 | 382.7 | 0.52 | 0.26 |
| `bzip2` | Lorem 1 MiB | 1048576 | 1849 | 0.00 | 46.5 | 22.5 | 10.3 | 101.4 | — | — | — | — | — | — | — | — |
| `bzip2` | Zeros 1 MiB | 1048576 | 45 | 0.00 | 3.45 | 303.9 | 2.11 | 497.6 | — | — | — | — | — | — | — | — |
| `bzip2` | Random 1 MiB | 1048576 | 1050728 | 1.00 | 114.0 | 9.20 | 25.3 | 41.5 | — | — | — | — | — | — | — | — |
| `deflate` | Lorem 1 MiB | 1048576 | 5711 | 0.01 | 1.67 | 629.0 | 0.19 | 5463 | py-deflate | 0.00 | 15.8 | 66.5 | 9.91 | 105.9 | 9.46 | 51.6 |
| `deflate` | Zeros 1 MiB | 1048576 | 1812 | 0.00 | 1.54 | 678.8 | 2.38 | 440.8 | py-deflate | 0.00 | 10.6 | 98.9 | 9.98 | 105.0 | 6.87 | 4.20 |
| `deflate` | Random 1 MiB | 1048576 | 1048898 | 1.00 | 17.5 | 59.8 | 0.89 | 1180 | py-deflate | 1.00 | 23.2 | 45.2 | 9.88 | 106.1 | 1.32 | 11.1 |
| `gzip` | Lorem 1 MiB | 1048576 | 5729 | 0.01 | 1.97 | 533.0 | 0.58 | 1820 | gzip | 0.00 | 2.70 | 389.0 | 0.91 | 1149 | 1.37 | 1.58 |
| `gzip` | Zeros 1 MiB | 1048576 | 1830 | 0.00 | 2.96 | 354.5 | 2.87 | 365.2 | gzip | 0.00 | 2.28 | 459.3 | 1.92 | 545.2 | 0.77 | 0.67 |
| `gzip` | Random 1 MiB | 1048576 | 1048916 | 1.00 | 18.8 | 55.8 | 1.31 | 799.8 | gzip | 1.00 | 18.8 | 55.8 | 2.21 | 474.1 | 1.00 | 1.69 |
| `lz4` | Lorem 1 MiB | 1048576 | 10997 | 0.01 | 0.07 | 14856 | 0.08 | 13592 | lz4 | 0.00 | 2.13 | 493.1 | 1.63 | 643.2 | 30.1 | 21.1 |
| `lz4` | Zeros 1 MiB | 1048576 | 4340 | 0.00 | 0.13 | 8113 | 0.11 | 9220 | lz4 | 0.00 | 1.59 | 660.6 | 1.71 | 612.9 | 12.3 | 15.0 |
| `lz4` | Random 1 MiB | 1048576 | 1052772 | 1.00 | 0.33 | 3146 | 0.11 | 9180 | lz4 | 1.00 | 2.30 | 455.9 | 2.57 | 408.4 | 6.90 | 22.5 |
| `lzfse` | Lorem 1 MiB | 1048576 | — | — | — | — | — | — | — | — | — | — | — | — | — | — |
| `lzfse` | Zeros 1 MiB | 1048576 | — | — | — | — | — | — | — | — | — | — | — | — | — | — |
| `lzfse` | Random 1 MiB | 1048576 | — | — | — | — | — | — | — | — | — | — | — | — | — | — |
| `lzma` | Lorem 1 MiB | 1048576 | 564 | 0.00 | 46.4 | 22.6 | 0.28 | 3761 | py-lzma | 0.00 | 29.6 | 35.4 | 13.4 | 78.3 | 0.64 | 48.0 |
| `lzma` | Zeros 1 MiB | 1048576 | 255 | 0.00 | 63.3 | 16.6 | 0.34 | 3074 | py-lzma | 0.00 | 24.9 | 42.0 | 12.8 | 81.6 | 0.39 | 37.7 |
| `lzma` | Random 1 MiB | 1048576 | 1062929 | 1.01 | 195.9 | 5.35 | 43.6 | 24.0 | py-lzma | 1.01 | 136.7 | 7.67 | 29.3 | 35.8 | 0.70 | 0.67 |
| `lzo` | Lorem 1 MiB | 1048576 | 13325 | 0.01 | 0.08 | 13515 | 0.10 | 10942 | — | — | — | — | — | — | — | — |
| `lzo` | Zeros 1 MiB | 1048576 | 4386 | 0.00 | 0.05 | 19554 | 0.06 | 17979 | — | — | — | — | — | — | — | — |
| `lzo` | Random 1 MiB | 1048576 | 1052874 | 1.00 | 0.22 | 4784 | 0.07 | 14932 | — | — | — | — | — | — | — | — |
| `lzw` | Lorem 1 MiB | 1048576 | 52217 | 0.05 | 11.2 | 93.6 | 2.12 | 494.7 | compress | 0.05 | 9.07 | 115.5 | 3.65 | 287.5 | 0.81 | 1.72 |
| `lzw` | Zeros 1 MiB | 1048576 | 1866 | 0.00 | 5.57 | 188.4 | 1.07 | 982.4 | compress | 0.00 | 2.82 | 371.4 | 1.66 | 631.2 | 0.51 | 1.56 |
| `lzw` | Random 1 MiB | 1048576 | 1299379 | 1.24 | 11.5 | 91.1 | 5.77 | 181.8 | — | — | — | — | — | — | — | — |
| `lzx` | Lorem 1 MiB | 1048576 | 1049093 | 1.00 | 0.16 | 6744 | 2.27 | 461.7 | — | — | — | — | — | — | — | — |
| `lzx` | Zeros 1 MiB | 1048576 | 1049093 | 1.00 | 0.15 | 7024 | 2.43 | 430.8 | — | — | — | — | — | — | — | — |
| `lzx` | Random 1 MiB | 1048576 | 1049093 | 1.00 | 0.16 | 6457 | 2.26 | 464.6 | — | — | — | — | — | — | — | — |
| `quantum` | Lorem 1 MiB | 1048576 | — | — | — | — | — | — | — | — | — | — | — | — | — | — |
| `quantum` | Zeros 1 MiB | 1048576 | — | — | — | — | — | — | — | — | — | — | — | — | — | — |
| `quantum` | Random 1 MiB | 1048576 | — | — | — | — | — | — | — | — | — | — | — | — | — | — |
| `rar1` | Lorem 1 MiB | 1048576 | — | — | — | — | — | — | — | — | — | — | — | — | — | — |
| `rar1` | Zeros 1 MiB | 1048576 | — | — | — | — | — | — | — | — | — | — | — | — | — | — |
| `rar1` | Random 1 MiB | 1048576 | — | — | — | — | — | — | — | — | — | — | — | — | — | — |
| `rar2` | Lorem 1 MiB | 1048576 | — | — | — | — | — | — | — | — | — | — | — | — | — | — |
| `rar2` | Zeros 1 MiB | 1048576 | — | — | — | — | — | — | — | — | — | — | — | — | — | — |
| `rar2` | Random 1 MiB | 1048576 | — | — | — | — | — | — | — | — | — | — | — | — | — | — |
| `rar3` | Lorem 1 MiB | 1048576 | — | — | — | — | — | — | — | — | — | — | — | — | — | — |
| `rar3` | Zeros 1 MiB | 1048576 | — | — | — | — | — | — | — | — | — | — | — | — | — | — |
| `rar3` | Random 1 MiB | 1048576 | — | — | — | — | — | — | — | — | — | — | — | — | — | — |
| `rar5` | Lorem 1 MiB | 1048576 | — | — | — | — | — | — | — | — | — | — | — | — | — | — |
| `rar5` | Zeros 1 MiB | 1048576 | — | — | — | — | — | — | — | — | — | — | — | — | — | — |
| `rar5` | Random 1 MiB | 1048576 | — | — | — | — | — | — | — | — | — | — | — | — | — | — |
| `rle` | Lorem 1 MiB | 1048576 | 2059536 | 1.96 | 1.35 | 774.8 | 3.26 | 321.2 | — | — | — | — | — | — | — | — |
| `rle` | Zeros 1 MiB | 1048576 | 8226 | 0.01 | 0.45 | 2348 | 0.06 | 17932 | — | — | — | — | — | — | — | — |
| `rle` | Random 1 MiB | 1048576 | 2088794 | 1.99 | 1.24 | 848.9 | 3.29 | 318.4 | — | — | — | — | — | — | — | — |
| `snappy` | Lorem 1 MiB | 1048576 | 49552 | 0.05 | 0.10 | 10217 | 0.12 | 9115 | — | — | — | — | — | — | — | — |
| `snappy` | Zeros 1 MiB | 1048576 | 49157 | 0.05 | 0.10 | 10513 | 0.11 | 9619 | — | — | — | — | — | — | — | — |
| `snappy` | Random 1 MiB | 1048576 | 1048583 | 1.00 | 0.15 | 7077 | 0.10 | 10573 | — | — | — | — | — | — | — | — |
| `xz` | Lorem 1 MiB | 1048576 | 588 | 0.00 | 28.8 | 36.4 | 1.85 | 566.1 | xz | 0.00 | 21.6 | 48.4 | 1.90 | 553.0 | 0.75 | 1.02 |
| `xz` | Zeros 1 MiB | 1048576 | 280 | 0.00 | 30.9 | 33.9 | 1.97 | 533.5 | xz | 0.00 | 13.3 | 78.9 | 2.33 | 449.7 | 0.43 | 1.19 |
| `xz` | Random 1 MiB | 1048576 | 1048680 | 1.00 | 228.4 | 4.59 | 2.49 | 421.4 | xz | 1.00 | 144.1 | 7.27 | 1.59 | 660.5 | 0.63 | 0.64 |
| `zlib` | Lorem 1 MiB | 1048576 | 5717 | 0.01 | 1.89 | 555.5 | 0.40 | 2612 | py-zlib | 0.00 | 10.8 | 97.5 | 11.0 | 95.7 | 5.70 | 27.3 |
| `zlib` | Zeros 1 MiB | 1048576 | 1818 | 0.00 | 1.73 | 606.0 | 2.57 | 407.3 | py-zlib | 0.00 | 11.1 | 94.4 | 9.98 | 105.0 | 6.42 | 3.88 |
| `zlib` | Random 1 MiB | 1048576 | 1048904 | 1.00 | 16.8 | 62.4 | 1.09 | 961.9 | py-zlib | 1.00 | 26.1 | 40.1 | 12.1 | 86.5 | 1.56 | 11.1 |
| `zstd` | Lorem 1 MiB | 1048576 | 400 | 0.00 | 2.34 | 448.7 | 0.52 | 2011 | zstd | 0.00 | 2.56 | 409.7 | 1.23 | 852.9 | 1.10 | 2.36 |
| `zstd` | Zeros 1 MiB | 1048576 | 41 | 0.00 | 0.39 | 2677 | 0.50 | 2091 | zstd | 0.00 | 2.55 | 411.1 | 1.50 | 700.6 | 6.51 | 2.98 |
| `zstd` | Random 1 MiB | 1048576 | 1048609 | 1.00 | 23.4 | 44.7 | 0.09 | 12173 | zstd | 1.00 | 3.55 | 295.4 | 1.98 | 530.5 | 0.15 | 22.9 |

## What the numbers say

**vs reference (Δ MB/s = ours / ref)**, on Lorem 1 MiB unless noted:

- `lz4` enc: **30× ref**, **14.9 GB/s** on Lorem and **3.1 GB/s** on
  incompressible Random (near memcpy). The 2026-07 word-at-a-time
  match extender took Lorem encode from ~1.8 GB/s to ~14.9 GB/s with
  byte-identical output.
- `lzo` / `snappy`: no reference in-bench, but the same match-extender
  change lifted `lzo` Lorem encode ~3× (to 13.5 GB/s) and `snappy`
  ~1.7× (to 10.2 GB/s).
- `gzip` enc: **1.37× ref**, dec **1.58× ref** — we now edge out the
  system `gzip` on this input.
- `deflate` vs py-deflate: **9× enc / 52× dec** — Python pays CPython
  startup + GIL, so treat as a smoke test, not a real gap.
- `zstd` enc: **1.10× ref**, dec **2.36× ref** on Lorem; **0.15× /
  23× on Random** (our encoder is slower on incompressible input, our
  decoder much faster). Lorem output is **400 B** (ratio 0.0004) —
  the smallest of any codec here on this input.
- `brotli` enc: **1.84× ref** on Lorem, dec **28× ref** on Zeros.
  Random encode stays slow (**2.7 MB/s**) — the dictionary match
  search dominates on incompressible input; see Known issues.
- `lzma` / `xz`: encode is now **~0.65× ref** (≈23–40 MB/s), a
  deliberate tradeoff — the encoders were rewritten to bounded-memory
  sliding-window streaming, which costs raw encode speed. Decode is
  strong: `lzma` **48× ref** on Lorem, and Random decode is **24 MB/s**
  (`lzma`) / **485 MB/s** (`xz`). Two 2026-07 fixes closed the
  compressible-ratio gap vs native `xz`: (1) chunk-model-carry
  (continuation control `0x80`, model warms across chunks), and (2)
  packing up to 1 MiB per chunk (vs 64 KiB) so per-chunk framing +
  flush overhead is amortised. Together they shrank `xz` Lorem output
  **1708 → 588 B** and Zeros **1368 → 280 B**, and 16 MiB Lorem
  **~21.8 KB → ~3.0 KB** — now **~1.03× native `xz`**, down from ~7.5×.
- `bzip2`: encode **22.5 MB/s** Lorem — the SA-IS BWT is the right
  algorithm class; it is bound by the suffix sort and the table
  refinement, not the bit I/O.

**Ratio gaps vs reference**:
- `lz4`, `zstd` match (or beat) the reference's ratio on text.
- `gzip` / `zlib` / `deflate` are ~1× the reference.
- `lzw` Random: **1.24** — bit-for-bit identical to system
  `compress -cf`; 1.24 is the `.Z` format floor on incompressible
  input (no uncompressed-block escape).
- `lzma` is **1.01×** on Random — the greedy/optimal parser emits
  marginally larger output than the reference on incompressible data.

## Deflate encoder vs in-process zlib (2026-10)

The snapshot above times the system tools as subprocesses. This table
compares the raw deflate encoder against zlib called **in-process**
(Python's `zlib.compressobj(level, DEFLATED, -15)`, system zlib 1.2.12),
on a different host: Apple M5 Max, macOS. Each row is the best of 5
runs over a 4 MB input (words: `/usr/share/dict/words`, 2.5 MB; rust:
this crate's `src/**/*.rs` concatenated; mixed: `/bin/zsh`,
`/usr/bin/ssh` and `/bin/bash` concatenated; lorem: one 120-byte
sentence repeated; random: `/dev/urandom`). Our encoder streams into a
64 KiB output buffer. "Before" is the encoder as of v0.7.7 plus the
level-0/strategy work, before the speed pass.

| Input | Level | Before: size | Before: MB/s | After: size | After: MB/s | zlib: size | zlib: MB/s | After / zlib speed |
|---|---|---|---|---|---|---|---|---|
| words | 1 | 794984 | 148.7 | 793690 | 264.0 | 901742 | 190.0 | 1.39× |
| words | 6 | 759754 | 30.9 | 759623 | 43.0 | 754211 | 33.3 | 1.29× |
| words | 9 | 759666 | 14.2 | 759666 | 15.7 | 754271 | 14.3 | 1.10× |
| rust | 1 | 1121787 | 141.9 | 1092160 | 303.8 | 1166315 | 222.9 | 1.36× |
| rust | 6 | 948438 | 55.5 | 948378 | 89.4 | 943056 | 70.1 | 1.28× |
| rust | 9 | 942202 | 17.9 | 942202 | 21.3 | 934739 | 18.0 | 1.18× |
| mixed | 1 | 1975095 | 88.4 | 1958677 | 177.9 | 2008434 | 123.3 | 1.44× |
| mixed | 6 | 1880291 | 33.8 | 1879457 | 59.0 | 1894491 | 38.0 | 1.55× |
| mixed | 9 | 1870112 | 12.6 | 1870110 | 16.4 | 1883868 | 14.1 | 1.16× |
| lorem | 1 | 16914 | 814.2 | 16914 | 1958 | 27300 | 1559 | 1.26× |
| lorem | 6 | 16914 | 817.2 | 16914 | 1910 | 13680 | 701.8 | 2.72× |
| lorem | 9 | 16914 | 820.6 | 16914 | 1962 | 13680 | 704.9 | 2.78× |
| random | 1 | 4001225 | 83.7 | 4001225 | 117.6 | 4001220 | 88.9 | 1.32× |
| random | 6 | 4001225 | 82.2 | 4001225 | 116.3 | 4001225 | 88.0 | 1.32× |
| random | 9 | 4001225 | 80.5 | 4001225 | 115.1 | 4001225 | 87.8 | 1.31× |

Output sizes moved by at most +0.1% at any level 1–9 on these inputs
(most shrank; level 1 by up to 2.6%). The zlib and gzip wrappers add
the trailer checksums: Adler-32 now runs at ~7.7 GB/s and CRC-32 at
~4.3 GB/s on this host, so e.g. rust level 6 encodes at ~88 MB/s in
all three containers.

What changed: a multiplicative 3-byte hash (fewer collisions, shorter
chains); a chain walk that starts from the head returned by the insert,
rejects candidates on the four bytes ending at the current best length,
and only looks for matches longer than the pending lazy one; zlib's
`max_lazy` cut-off at levels 6–7; literal/length and distance
histograms tallied during the LZ77 pass (no second pass, no per-block
copy of the block bytes for the stored fallback); an in-place
Moffat–Katajainen Huffman builder (package-merge only when a code would
exceed 15 bits); and a branch-free 64-bit bit writer over a pre-sized
buffer, with length/distance codes and extra bits merged into one write.

## Known issues surfaced by the bench

1. **`brotli` random-input encode is ~2.7 MB/s.** The quality-6
   encoder runs its static-dictionary match search at every position,
   and the empty-prefix transforms re-hash and re-walk the same bucket
   dozens of times per position. It only hurts incompressible input
   (you would not brotli random data), so it is left as-is.
2. **`lzma` / `xz` encode is ~10× slower than the 2026-05 snapshot.**
   Not a regression to fix but a design change: the encoders moved to
   bounded-memory sliding-window streaming. Ratio and decode are
   unaffected.
3. **~~`lzma` decoder ~50× slower than reference on random data.~~**
   *Fixed earlier.* Batching the high-distance-slot direct-bit read
   and inlining range-coder normalisation brought Random decode from
   0.30 MB/s to tens of MB/s; `xz` inherits the fix.
4. **~~`lzw` Random ratio = 1.38.~~** *Fixed earlier.* `compress(1)`-
   style CLEAR-on-ratio-degradation lands Random at 1.24, identical to
   system `compress -cf`.

## Deflate / zlib / gzip decoding vs zlib

The `deflate` / `zlib` / `gzip` decode rows in the table above predate
the 2026-10 table-driven inflate (fast loop, decoding straight into the
caller's buffer) and the faster Adler-32 / CRC-32. Measured on
2026-10-31 on an Apple M5 Max (macOS 26) against the system zlib 1.2.12
through Python's `zlib.decompress` on the same inputs, each compressed by
zlib at the given level. Decimal MB/s of decompressed output, best of 15,
whole stream decoded into one buffer:

| Input (size) | Format | Level | Before | Now | zlib | Now / zlib |
|---|---|---|---|---|---|---|
| `/usr/share/dict/words` (2.5 MB) | raw deflate | 1 | 197 | 923 | 1007 | 0.92 |
| | raw deflate | 6 | 223 | 898 | 878 | 1.02 |
| | raw deflate | 9 | 224 | 902 | 885 | 1.02 |
| Rust sources (3.8 MB) | raw deflate | 1 | 249 | 1235 | 1536 | 0.80 |
| | raw deflate | 6 | 313 | 1534 | 1685 | 0.91 |
| | raw deflate | 9 | 328 | 1559 | 1691 | 0.92 |
| Mach-O binaries (4.3 MB) | raw deflate | 1 | 226 | 862 | 931 | 0.93 |
| | raw deflate | 6 | 242 | 975 | 1029 | 0.95 |
| | raw deflate | 9 | 248 | 1003 | 1037 | 0.97 |
| Runs (4 MB) | raw deflate | 1 | 964 | 4663 | 5061 | 0.92 |
| | raw deflate | 6 | 6888 | 25196 | 22668 | 1.11 |
| | raw deflate | 9 | 15607 | 37122 | 27706 | 1.34 |
| words | zlib (Adler-32) | 6 | 218 | 866 | 857 | 1.01 |
| Rust sources | zlib | 6 | 291 | 1392 | 1574 | 0.88 |
| binaries | zlib | 6 | 232 | 908 | 985 | 0.92 |
| runs | zlib | 6 | 2513 | 12844 | 11392 | 1.13 |
| words | gzip (CRC-32) | 6 | 211 | 793 | 848 | 0.94 |
| Rust sources | gzip | 6 | 276 | 1214 | 1627 | 0.75 |
| binaries | gzip | 6 | 221 | 817 | 1027 | 0.80 |
| runs | gzip | 6 | 1863 | 5259 | 15404 | 0.34 |

With 64 KiB output buffers (the usual streaming loop) ours runs 5–10%
below the whole-buffer numbers (zlib through Python's `decompressobj`,
which adds interpreter overhead, drops 13–40%). The remaining gzip gap
is CRC-32: the system zlib uses the ARMv8 CRC instructions, which safe
Rust cannot reach, so ours is a four-way interleaved slice-by-8 at
~7 GB/s (Adler-32 vectorises to ~20 GB/s).

## Caveats

- All numbers outside the deflate-vs-zlib section reflect a **single
  host** (Linux 6.12 / Intel Core i9-14900K). Throughputs scale with the host's L1/L2 sizes and DRAM
  bandwidth; the **Δ ratios** are more portable than the absolute
  MB/s numbers.
- Reference timings are **single-shot subprocesses**: each median
  run pays one fork+exec. For very fast codecs (lz4 at <1 ms encode
  / decode) the subprocess overhead is a meaningful fraction of the
  measured time, so the reference looks artificially slow there.
  Read those `Δ` cells as "ours including no startup vs reference
  including ~2 ms startup" and adjust mentally.
- A more rigorous comparison would link against the reference
  libraries directly (in-process). That requires FFI dependencies
  (`libdeflate-sys`, `zstd-sys`, etc.) which compcol's zero-dep
  policy forbids.
