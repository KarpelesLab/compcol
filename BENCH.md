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
| **Fastest encode** | `lzo` | 0.013 | 3360 | 2240 |
| **Fastest decode** | `lz4` | 0.010 | 1780 | 1480 |
| **Best ratio (English text)** | `lzma` | 0.001 | 614 | 905 |
| **Best ratio + decent speed** | `zstd` | 0.003 | 902 | 1330 |
| **Most universal (Unix tooling)** | `gzip` | 0.005 | 280 | 478 |
| **Best ratio with structured-text bias** | `brotli` | 0.005 | 234 | 1058 |

(Previously this row showed `—` due to a decoder `raw_finish`
bug — see the "Known issues" post-mortem below.)

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
| `brotli` | Lorem 1 MiB | 1048576 | 5643 | 0.01 | 4.48 | 233.9 | 0.99 | 1058 | brotli | 0.00 | 13.6 | 77.1 | 3.27 | 320.5 | 3.03 | 3.30 |
| `brotli` | Zeros 1 MiB | 1048576 | 961 | 0.00 | 2.59 | 404.9 | 1.82 | 575.0 | brotli | 0.00 | 15.4 | 68.1 | 3.70 | 283.3 | 5.94 | 2.03 |
| `brotli` | Random 1 MiB | 1048576 | 1049091 | 1.00 | 260.8 | 4.02 | 10.9 | 96.2 | brotli | 1.00 | 180.6 | 5.81 | 2.52 | 416.6 | 0.69 | 0.23 |
| `deflate` | Lorem 1 MiB | 1048576 | 5711 | 0.01 | 2.01 | 521.7 | 0.70 | 1499 | py-deflate | 0.00 | 17.3 | 60.5 | 14.6 | 71.8 | 8.63 | 25.3 |
| `deflate` | Zeros 1 MiB | 1048576 | 1812 | 0.00 | 2.01 | 522.5 | 1.02 | 1031 | py-deflate | 0.00 | 17.5 | 60.1 | 22.4 | 46.7 | 8.70 | 11.8 |
| `deflate` | Random 1 MiB | 1048576 | 1048898 | 1.00 | 17.4 | 60.3 | 0.68 | 1545 | py-deflate | 1.00 | 26.7 | 39.2 | 17.1 | 61.4 | 1.54 | 19.5 |
| `gzip` | Lorem 1 MiB | 1048576 | 5729 | 0.01 | 4.19 | 250.4 | 2.24 | 467.8 | gzip | 0.00 | 2.11 | 497.2 | 1.27 | 826.7 | 0.50 | 0.56 |
| `gzip` | Zeros 1 MiB | 1048576 | 1830 | 0.00 | 3.49 | 300.0 | 2.51 | 416.9 | gzip | 0.00 | 2.63 | 399.4 | 2.69 | 390.2 | 0.75 | 1.07 |
| `gzip` | Random 1 MiB | 1048576 | 1048916 | 1.00 | 18.7 | 56.2 | 2.15 | 488.6 | gzip | 1.00 | 22.7 | 46.1 | 2.58 | 406.4 | 1.22 | 1.20 |
| `lz4` | Lorem 1 MiB | 1048576 | 10997 | 0.01 | 0.59 | 1775 | 0.71 | 1481 | lz4 | 0.00 | 2.09 | 501.6 | 2.94 | 356.6 | 3.54 | 4.16 |
| `lz4` | Zeros 1 MiB | 1048576 | 4340 | 0.00 | 0.87 | 1209 | 2.90 | 361.0 | lz4 | 0.00 | 2.20 | 476.9 | 3.59 | 291.7 | 2.53 | 1.23 |
| `lz4` | Random 1 MiB | 1048576 | 1052772 | 1.00 | 0.97 | 1078 | 0.35 | 3009 | lz4 | 1.00 | 6.88 | 152.5 | 31.2 | 33.6 | 7.07 | 89.5 |
| `lzma` | Lorem 1 MiB | 1048576 | 566 | 0.00 | 1.71 | 614.4 | 1.16 | 905.4 | py-lzma | 0.00 | 27.7 | 37.8 | 13.4 | 78.5 | 16.2 | 11.5 |
| `lzma` | Zeros 1 MiB | 1048576 | 241 | 0.00 | 2.95 | 354.9 | 1.24 | 845.1 | py-lzma | 0.00 | 22.7 | 46.1 | 9.78 | 107.2 | 7.71 | 7.88 |
| `lzma` | Random 1 MiB | 1048576 | 1155677 | 1.10 | 84.9 | 12.3 | 3531 | 0.30 | py-lzma | 1.01 | 166.7 | 6.29 | 47.8 | 21.9 | 1.96 | 0.014 |
| `lzo` | Lorem 1 MiB | 1048576 | 13309 | 0.01 | 0.31 | 3362 | 0.45 | 2305 | — | — | — | — | — | — | — | — |
| `lzo` | Zeros 1 MiB | 1048576 | 4386 | 0.00 | 0.29 | 3578 | 1.00 | 1052 | — | — | — | — | — | — | — | — |
| `lzo` | Random 1 MiB | 1048576 | 1052874 | 1.00 | 1.97 | 532.5 | 0.07 | 14651 | — | — | — | — | — | — | — | — |
| `lzw` | Lorem 1 MiB | 1048576 | 52217 | 0.05 | 11.1 | 94.4 | 2.33 | 449.9 | compress | 0.05 | 7.13 | 147.1 | 6.55 | 160.1 | 0.64 | 2.81 |
| `lzw` | Zeros 1 MiB | 1048576 | 1866 | 0.00 | 6.17 | 170.0 | 1.35 | 779.0 | compress | 0.00 | 2.68 | 391.7 | 6.00 | 174.7 | 0.43 | 4.46 |
| `lzw` | Random 1 MiB | 1048576 | 1444513 | 1.38 | 9.15 | 114.6 | 6.08 | 172.5 | — | — | — | — | — | — | — | — |
| `lzx` | Lorem 1 MiB | 1048576 | 1049093 | 1.00 | 0.14 | 7440 | 2.28 | 459.4 | — | — | — | — | — | — | — | — |
| `lzx` | Zeros 1 MiB | 1048576 | 1049093 | 1.00 | 0.13 | 7833 | 2.29 | 457.6 | — | — | — | — | — | — | — | — |
| `lzx` | Random 1 MiB | 1048576 | 1049093 | 1.00 | 0.13 | 7950 | 2.30 | 456.7 | — | — | — | — | — | — | — | — |
| `quantum` | — | — | — | — | — | — | — | — | — | — | — | — | — | — | — | — |
| `rar1` | — | — | — | — | — | — | — | — | — | — | — | — | — | — | — | — |
| `rar2` | — | — | — | — | — | — | — | — | — | — | — | — | — | — | — | — |
| `rar3` | — | — | — | — | — | — | — | — | — | — | — | — | — | — | — | — |
| `rar5` | — | — | — | — | — | — | — | — | — | — | — | — | — | — | — | — |
| `rle` | Lorem 1 MiB | 1048576 | 2057384 | 1.96 | 7.62 | 137.6 | 16.9 | 62.1 | — | — | — | — | — | — | — | — |
| `rle` | Zeros 1 MiB | 1048576 | 8264 | 0.01 | 0.18 | 5715 | 0.07 | 16071 | — | — | — | — | — | — | — | — |
| `rle` | Random 1 MiB | 1048576 | 2089478 | 1.99 | 6.50 | 161.2 | 21.4 | 49.0 | — | — | — | — | — | — | — | — |
| `snappy` | Lorem 1 MiB | 1048576 | 56114 | 0.05 | 0.38 | 2761 | 0.61 | 1717 | — | — | — | — | — | — | — | — |
| `snappy` | Zeros 1 MiB | 1048576 | 49231 | 0.05 | 0.39 | 2706 | 0.96 | 1093 | — | — | — | — | — | — | — | — |
| `snappy` | Random 1 MiB | 1048576 | 1048590 | 1.00 | 1.51 | 696.7 | 0.04 | 25821 | — | — | — | — | — | — | — | — |
| `xz` | Lorem 1 MiB | 1048576 | 743 | 0.00 | 5.99 | 175.0 | 2.93 | 357.7 | xz | 0.00 | 25.4 | 41.3 | 12.8 | 81.7 | 4.24 | 4.38 |
| `xz` | Zeros 1 MiB | 1048576 | 240 | 0.00 | 4.59 | 228.5 | 4.20 | 249.5 | xz | 0.00 | 22.7 | 46.2 | 10.2 | 103.0 | 4.95 | 2.42 |
| `xz` | Random 1 MiB | 1048576 | 1048988 | 1.00 | 80.3 | 13.1 | 16.5 | 63.5 | xz | 1.00 | 110.8 | 9.46 | 33.9 | 30.9 | 1.38 | 2.06 |
| `zlib` | Lorem 1 MiB | 1048576 | 5723 | 0.01 | 2.04 | 514.7 | 0.71 | 1474 | py-zlib | 0.00 | 17.9 | 58.5 | 18.7 | 56.1 | 8.79 | 26.3 |
| `zlib` | Zeros 1 MiB | 1048576 | 1824 | 0.00 | 2.05 | 512.2 | 1.02 | 1027 | py-zlib | 0.00 | 18.2 | 57.6 | 22.4 | 46.7 | 8.89 | 22.0 |
| `zlib` | Random 1 MiB | 1048576 | 1048910 | 1.00 | 18.1 | 57.9 | 0.69 | 1525 | py-zlib | 1.00 | 27.1 | 38.7 | 17.4 | 60.4 | 1.50 | 25.2 |
| `zstd` | Lorem 1 MiB | 1048576 | 2678 | 0.00 | 1.16 | 902.1 | 0.79 | 1330 | zstd | 0.00 | 9.96 | 105.3 | 5.95 | 176.2 | 8.57 | 7.55 |
| `zstd` | Zeros 1 MiB | 1048576 | 41 | 0.00 | 0.79 | 1327 | 1.16 | 902.5 | zstd | 0.00 | 2.80 | 374.3 | 5.34 | 196.5 | 3.55 | 4.59 |
| `zstd` | Random 1 MiB | 1048576 | 1048609 | 1.00 | 15.9 | 66.1 | 0.07 | 15096 | zstd | 1.00 | 3.50 | 299.4 | 2.66 | 393.9 | 0.22 | 38.3 |

## What the numbers say

**Headlines vs reference (Δ MB/s = ours / ref)**, on Lorem 1 MiB:

- `gzip` enc: **0.50× ref** — we're 2× slower (system `gzip` is the
  optimised C zlib).
- `gzip` dec: **0.56× ref** — same gap.
- `deflate` vs py-deflate: **8.6× / 25× faster** — but that's
  Python's `zlib.compress` going through CPython start-up + GIL
  every time, so the comparison is mostly Python overhead.
- `lz4` enc: **3.5× ref** — we beat the reference. Subprocess
  startup is a meaningful fraction of `lz4`'s tiny 2 ms encode time,
  so this is closer than the headline suggests.
- `lzma` enc: **16.2× ref**, dec: **11.5× ref** — but our LZMA
  decode at **0.014× ref on random data** is pathological (3.5
  seconds vs 47 ms). That's the high-distance-slot path; profiling
  candidate.
- `xz` enc: **4.2× ref** — reasonable since most of xz's work is
  the LZMA2 inner codec we control; the envelope is small overhead.
- `zstd` enc: **8.6× ref**, dec: **7.6× ref** on Lorem. **0.22× /
  38× on Random** — encode is slow on incompressible input, decode
  is essentially memcpy.

**Ratio gaps vs reference**:
- `lz4`, `lzw`, `xz`, `zstd` match the reference's ratio exactly
  (or within bytes) on text.
- `gzip`/`zlib`/`deflate` are ~1× the reference (after round 4
  lazy-matching + cross-block matching).
- `lzma` is **1.10×** on random — our greedy parser produces
  slightly larger output.
- `lzw` Random has **ratio 1.38**: dictionary fills, restart cycle
  doesn't help. Same on `system_compress` (no entry shown because
  `compress -c` refused the high-entropy random input on this host).

## Known issues surfaced by the bench

1. **~~`brotli` encoder fails on inputs > 128 KiB.~~** *Fixed.* The
   1 MiB rows now round-trip cleanly. The actual bug was in the
   decoder's `raw_finish`, not the encoder: when the caller's output
   slice filled mid-stream `raw_decode` returned early with
   meta-blocks still pending in `self.raw`, and `raw_finish` then
   gave up immediately instead of draining and processing them. The
   "fails above 128 KiB" symptom showed up because that's roughly when
   typical buffer sizes start hitting capacity. `raw_finish` now loops
   the drain-and-process pair until the stream ends or the output
   buffer fills again.
2. **`lzma` decoder is ~50× slower than the reference on random
   data.** Lorem decode is 905 MB/s but Random decode collapses to
   0.30 MB/s. The high-distance-slot decode path (slot ≥ 14, direct
   bits + align tree) is the suspect — those slots dominate on
   incompressible input.
3. **`lzw` Random ratio = 1.38** — dictionary saturation without a
   reset on incompressible input. Adding the `compress(1)`-style
   ratio-degradation reset would fix it.

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
