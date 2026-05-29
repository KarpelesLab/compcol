# Benchmark snapshot

Output of `cargo run --release --features all --example bench` on
2026-05-29 (Linux 6.12, AMD64). Reproduce via:

```sh
cargo run --release --features all --example bench
```

## Quick "which algorithm should I use?" guide

Numbers below are for **1 MiB Lorem ipsum** input on this host —
roughly representative of natural-language text. Higher MB/s is
faster; lower output ratio (B/B) is smaller.

| Goal | Algorithm | Ratio | Our enc MB/s | Our dec MB/s |
|---|---|---|---|---|
| **Fastest encode** | `lzo` | 0.013 | 2768 | 2296 |
| **Fastest decode** | `lz4` | 0.010 | 1776 | 1462 |
| **Best ratio (English text)** | `lzma` | 0.001 | 322 | 899 |
| **Best ratio + decent speed** | `zstd` | 0.002 | 1058 | 2037 |
| **Most universal (Unix tooling)** | `gzip` | 0.005 | 345 | 477 |
| **Best ratio with structured-text bias** | `brotli` | 0.005 | 320 | 1106 |

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

`—` means the reference tool wasn't installed (or there's no
widely-available reference — there's no canonical `rle`, `lzo`, or
`snappy` CLI on this host), or the row's encoder is a permanent
`Unsupported` (the four `rar*` decoders and `quantum`).

## Detailed results

Throughput in MB/s (decimal). Time in ms. Median of 3 timed runs
after 1 warmup.

| Algorithm | Input | Bytes | Ours: out | Ours: ratio | Ours: enc ms | Ours: enc MB/s | Ours: dec ms | Ours: dec MB/s | Reference | Ref: ratio | Ref: enc ms | Ref: enc MB/s | Ref: dec ms | Ref: dec MB/s | Δ enc | Δ dec |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `adc` | Lorem 1 MiB | 1048576 | 103789 | 0.10 | 1.52 | 691.0 | 0.72 | 1465 | — | — | — | — | — | — | — | — |
| `adc` | Zeros 1 MiB | 1048576 | 46955 | 0.04 | 1.29 | 814.9 | 0.64 | 1643 | — | — | — | — | — | — | — | — |
| `adc` | Random 1 MiB | 1048576 | 1056742 | 1.01 | 2.22 | 472.3 | 0.88 | 1194 | — | — | — | — | — | — | — | — |
| `brotli` | Lorem 1 MiB | 1048576 | 5643 | 0.01 | 3.28 | 319.9 | 0.95 | 1106 | brotli | 0.00 | 12.5 | 83.7 | 2.28 | 459.1 | 3.82 | 2.41 |
| `brotli` | Zeros 1 MiB | 1048576 | 961 | 0.00 | 1.06 | 985.4 | 1.00 | 1053 | brotli | 0.00 | 15.2 | 68.9 | 2.59 | 405.2 | 14.3 | 2.60 |
| `brotli` | Random 1 MiB | 1048576 | 1049091 | 1.00 | 243.2 | 4.31 | 10.8 | 96.7 | brotli | 1.00 | 174.6 | 6.00 | 2.55 | 410.7 | 0.72 | 0.24 |
| `bzip2` | Lorem 1 MiB | 1048576 | 1901 | 0.00 | 45.9 | 22.9 | 10.2 | 102.7 | — | — | — | — | — | — | — | — |
| `bzip2` | Zeros 1 MiB | 1048576 | 83 | 0.00 | 2.48 | 422.2 | 2.23 | 471.1 | — | — | — | — | — | — | — | — |
| `bzip2` | Random 1 MiB | 1048576 | 1050833 | 1.00 | 109.0 | 9.62 | 23.7 | 44.3 | — | — | — | — | — | — | — | — |
| `deflate` | Lorem 1 MiB | 1048576 | 5711 | 0.01 | 1.97 | 533.6 | 1.43 | 735.7 | py-deflate | 0.00 | 11.7 | 89.8 | 11.3 | 92.6 | 5.95 | 7.95 |
| `deflate` | Zeros 1 MiB | 1048576 | 1812 | 0.00 | 1.51 | 694.3 | 1.03 | 1016 | py-deflate | 0.00 | 15.2 | 69.2 | 10.2 | 103.1 | 10.0 | 9.85 |
| `deflate` | Random 1 MiB | 1048576 | 1048898 | 1.00 | 17.0 | 61.6 | 0.62 | 1694 | py-deflate | 1.00 | 23.8 | 44.1 | 11.5 | 91.4 | 1.40 | 18.5 |
| `gzip` | Lorem 1 MiB | 1048576 | 5729 | 0.01 | 3.04 | 344.6 | 2.20 | 477.0 | gzip | 0.00 | 2.06 | 507.9 | 0.91 | 1158 | 0.68 | 0.41 |
| `gzip` | Zeros 1 MiB | 1048576 | 1830 | 0.00 | 3.07 | 341.1 | 2.44 | 429.7 | gzip | 0.00 | 2.05 | 510.4 | 2.05 | 512.0 | 0.67 | 0.84 |
| `gzip` | Random 1 MiB | 1048576 | 1048916 | 1.00 | 18.4 | 57.1 | 2.04 | 514.1 | gzip | 1.00 | 18.2 | 57.6 | 2.49 | 420.9 | 0.99 | 1.22 |
| `lz4` | Lorem 1 MiB | 1048576 | 10997 | 0.01 | 0.59 | 1776 | 0.72 | 1462 | lz4 | 0.00 | 1.52 | 692.1 | 1.48 | 710.1 | 2.57 | 2.06 |
| `lz4` | Zeros 1 MiB | 1048576 | 4340 | 0.00 | 0.58 | 1822 | 0.98 | 1067 | lz4 | 0.00 | 1.64 | 637.5 | 1.89 | 555.7 | 2.86 | 1.92 |
| `lz4` | Random 1 MiB | 1048576 | 1052772 | 1.00 | 0.29 | 3674 | 0.12 | 9063 | lz4 | 1.00 | 2.62 | 400.4 | 2.61 | 402.4 | 9.18 | 22.5 |
| `lzfse` | Lorem 1 MiB | 1048576 | — | — | — | — | — | — | — | — | — | — | — | — | — | — |
| `lzfse` | Zeros 1 MiB | 1048576 | — | — | — | — | — | — | — | — | — | — | — | — | — | — |
| `lzfse` | Random 1 MiB | 1048576 | — | — | — | — | — | — | — | — | — | — | — | — | — | — |
| `lzma` | Lorem 1 MiB | 1048576 | 566 | 0.00 | 3.25 | 322.4 | 1.17 | 898.9 | py-lzma | 0.00 | 28.9 | 36.3 | 13.7 | 76.7 | 8.87 | 11.7 |
| `lzma` | Zeros 1 MiB | 1048576 | 241 | 0.00 | 2.86 | 367.0 | 1.30 | 807.3 | py-lzma | 0.00 | 25.9 | 40.5 | 12.8 | 81.7 | 9.06 | 9.88 |
| `lzma` | Random 1 MiB | 1048576 | 1155677 | 1.10 | 80.8 | 13.0 | 28.2 | 37.2 | py-lzma | 1.01 | 113.6 | 9.23 | 31.3 | 33.5 | 1.41 | 1.11 |
| `lzo` | Lorem 1 MiB | 1048576 | 13309 | 0.01 | 0.38 | 2768 | 0.46 | 2296 | — | — | — | — | — | — | — | — |
| `lzo` | Zeros 1 MiB | 1048576 | 4386 | 0.00 | 0.30 | 3553 | 1.00 | 1054 | — | — | — | — | — | — | — | — |
| `lzo` | Random 1 MiB | 1048576 | 1052874 | 1.00 | 1.99 | 525.8 | 0.07 | 15181 | — | — | — | — | — | — | — | — |
| `lzw` | Lorem 1 MiB | 1048576 | 52217 | 0.05 | 10.4 | 101.1 | 2.31 | 453.3 | compress | 0.05 | 8.30 | 126.3 | 3.84 | 273.1 | 0.80 | 1.66 |
| `lzw` | Zeros 1 MiB | 1048576 | 1866 | 0.00 | 5.43 | 192.9 | 1.42 | 737.4 | compress | 0.00 | 2.64 | 397.6 | 1.65 | 634.2 | 0.49 | 1.16 |
| `lzw` | Random 1 MiB | 1048576 | 1299379 | 1.24 | 10.8 | 96.8 | 5.24 | 200.1 | — | — | — | — | — | — | — | — |
| `lzx` | Lorem 1 MiB | 1048576 | 1049093 | 1.00 | 0.16 | 6483 | 2.16 | 486.3 | — | — | — | — | — | — | — | — |
| `lzx` | Zeros 1 MiB | 1048576 | 1049093 | 1.00 | 0.16 | 6704 | 2.13 | 492.7 | — | — | — | — | — | — | — | — |
| `lzx` | Random 1 MiB | 1048576 | 1049093 | 1.00 | 0.17 | 6154 | 2.13 | 492.1 | — | — | — | — | — | — | — | — |
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
| `rle` | Lorem 1 MiB | 1048576 | 2059536 | 1.96 | 1.22 | 859.2 | 3.08 | 340.9 | — | — | — | — | — | — | — | — |
| `rle` | Zeros 1 MiB | 1048576 | 8226 | 0.01 | 0.41 | 2568 | 0.05 | 19650 | — | — | — | — | — | — | — | — |
| `rle` | Random 1 MiB | 1048576 | 2088794 | 1.99 | 1.14 | 917.5 | 3.02 | 346.8 | — | — | — | — | — | — | — | — |
| `snappy` | Lorem 1 MiB | 1048576 | 49542 | 0.05 | 0.39 | 2669 | 0.51 | 2046 | — | — | — | — | — | — | — | — |
| `snappy` | Zeros 1 MiB | 1048576 | 49157 | 0.05 | 0.38 | 2740 | 1.16 | 905.7 | — | — | — | — | — | — | — | — |
| `snappy` | Random 1 MiB | 1048576 | 1048583 | 1.00 | 1.28 | 821.1 | 0.11 | 9882 | — | — | — | — | — | — | — | — |
| `xz` | Lorem 1 MiB | 1048576 | 6652 | 0.01 | 3.38 | 309.8 | 3.79 | 276.7 | xz | 0.00 | 13.3 | 78.8 | 2.29 | 458.8 | 3.93 | 0.60 |
| `xz` | Zeros 1 MiB | 1048576 | 1320 | 0.00 | 4.25 | 246.6 | 3.69 | 283.8 | xz | 0.00 | 12.3 | 85.3 | 2.93 | 358.1 | 2.89 | 0.79 |
| `xz` | Random 1 MiB | 1048576 | 1048680 | 1.00 | 45.8 | 22.9 | 1.47 | 713.7 | xz | 1.00 | 115.1 | 9.11 | 1.64 | 637.5 | 2.52 | 1.12 |
| `zlib` | Lorem 1 MiB | 1048576 | 5717 | 0.01 | 1.74 | 601.1 | 0.90 | 1160 | py-zlib | 0.00 | 11.1 | 94.1 | 9.60 | 109.2 | 6.39 | 10.6 |
| `zlib` | Zeros 1 MiB | 1048576 | 1818 | 0.00 | 1.72 | 609.7 | 1.16 | 904.0 | py-zlib | 0.00 | 12.6 | 83.1 | 11.3 | 92.4 | 7.34 | 9.78 |
| `zlib` | Random 1 MiB | 1048576 | 1048904 | 1.00 | 17.2 | 61.0 | 0.79 | 1327 | py-zlib | 1.00 | 24.3 | 43.2 | 11.0 | 95.7 | 1.41 | 13.9 |
| `zstd` | Lorem 1 MiB | 1048576 | 2093 | 0.00 | 0.99 | 1058 | 0.51 | 2037 | zstd | 0.00 | 2.45 | 428.1 | 1.17 | 894.8 | 2.47 | 2.28 |
| `zstd` | Zeros 1 MiB | 1048576 | 41 | 0.00 | 0.52 | 2000 | 0.62 | 1700 | zstd | 0.00 | 2.93 | 358.4 | 1.53 | 685.3 | 5.58 | 2.48 |
| `zstd` | Random 1 MiB | 1048576 | 1048609 | 1.00 | 19.8 | 53.0 | 0.09 | 11525 | zstd | 1.00 | 3.13 | 335.5 | 1.87 | 561.4 | 0.16 | 20.5 |

## What the numbers say

**Headlines vs reference (Δ MB/s = ours / ref)**, on Lorem 1 MiB:

- `gzip` enc: **0.68× ref** — system `gzip` is the optimised C zlib,
  so closing the gap is mostly LLVM-vs-handwritten-asm territory.
  Up from 0.50× before this round's deflate-encoder micro-opts.
- `gzip` dec: **0.41× ref** — same gap.
- `deflate` vs py-deflate: **6× / 8× faster** — but Python's
  `zlib.compress` pays CPython startup + GIL, so the comparison
  flatters us.
- `lz4` enc: **2.6× ref**, **3.7 GB/s** on incompressible Random
  (essentially memcpy speed).
- `lzma` enc: **8.9× ref**. **Random decode now 37 MB/s** —
  120× faster than before, no longer pathological. The
  high-distance-slot path's per-bit normalisation got batched in
  this round.
- `xz` enc: **3.9× ref**, dec: **714 MB/s on Random** — was
  63 MB/s before (also benefiting from the lzma decoder fix).
- `zstd` enc: **2.5× ref**, dec: **2.3× ref** on Lorem, **0.16× /
  21× on Random**. Lorem ratio **0.002** (was 0.0025) — 22% smaller
  output after this round's lazy-parsing + 3-slot repeat-offset
  probe.
- `brotli` enc: **3.8× ref** on Lorem (up from 3.1×), **14× ref**
  on Zeros (was 5.9×) — the per-iteration hash-chain micro-opts and
  buffer recycling paid off.
- `bzip2`: now functional in the bench at all (was timing out before
  on the naive O(n² log n) BWT). SA-IS landed encoder at **23 MB/s**
  Lorem — slow vs reference but the right algorithm class. SA-IS in
  pure-safe-Rust is the canonical algorithm; further wins require
  unsafe or SIMD.

**Ratio gaps vs reference**:
- `lz4`, `xz`, `zstd` match the reference's ratio on text.
- `lzw` Random: **1.24** (was 1.38) — matches reference
  `compress -cf` byte-for-byte. The wire format has no
  uncompressed-block escape so 1.24 is the format floor on
  incompressible input.
- `gzip`/`zlib`/`deflate` are ~1× the reference.
- `lzma` is 1.10× on random — our greedy parser produces slightly
  larger output.

## Known issues surfaced by the bench

1. **~~`brotli` encoder fails on inputs > 128 KiB.~~** *Fixed
   in v0.4.* The actual bug was in the decoder's `raw_finish`, not
   the encoder.
2. **~~`lzma` decoder is ~50× slower than the reference on random
   data.~~** *Fixed in this round.* The high-distance-slot decode
   path was reading direct bits one at a time through a function
   call; batching the read and inlining range-coder normalisation
   brought Random decode from 0.30 MB/s up to **37 MB/s** (about
   120× faster). xz inherits the fix.
3. **~~`lzw` Random ratio = 1.38.~~** *Fixed in this round.*
   Implemented `compress(1)`-style CLEAR-on-ratio-degradation. Random
   ratio is now 1.24 — bit-for-bit identical to system
   `compress -cf` output. 1.24 is the format's theoretical floor on
   incompressible data (no uncompressed-block escape in `.Z`).

## Caveats

- All numbers reflect a **single host** (this Linux 6.12 / AMD64
  desktop). Throughputs scale with the host's L1/L2 sizes and DRAM
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
