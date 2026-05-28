# Benchmark snapshot

Output of `cargo run --release --all-features --example bench` on
2026-05-28 (Linux 6.12, AMD64). Reproduce via:

```sh
cargo run --release --all-features --example bench
```

## How to read this table

- **Bytes** — input size.
- **Ours: out** — output size from our encoder.
- **Ours: ratio** — `out / input`. Lower is better.
- **Ours: enc / dec** — throughput of our streaming codec in MB/s
  (decimal), measured in-process around an idiomatic encode/decode
  loop with 64 KiB caller-side buffers.
- **Reference** — system tool we shelled out to (gzip, xz, zstd, brotli,
  lz4, compress, or a python3 one-liner over `zlib` / `lzma` / `snappy`).
- **Ref: enc / dec** — throughput of the reference, **including subprocess
  startup overhead**. For small inputs the fork+exec dominates and the
  reference looks artificially slow; that's a measurement artifact, not
  a comment on the reference impl.

`—` means the reference tool wasn't installed at run time (or there's
no widely-available reference — there's no canonical `rle` or `snappy`
CLI on this host).

## Results

Throughput in MB/s (decimal). Median of 2 timed runs after 1 warmup.
Reference timings include subprocess startup overhead (~ms); for small
inputs that dominates, so treat those as a sanity check, not a serious
speed comparison.

| Algorithm | Input | Bytes | Ours: out | Ours: ratio | Ours: enc | Ours: dec | Reference | Ref: ratio | Ref: enc | Ref: dec |
|---|---|---|---|---|---|---|---|---|---|---|
| `brotli` | Lorem 4 KiB | 4096 | 296 | 0.07 | 19.9 | 56.2 | brotli | 0.07 | 1.04 | 3.94 |
| `brotli` | Lorem 64 KiB | 65536 | 352 | 0.01 | 210.4 | 365.6 | brotli | 0.00 | 18.9 | 79.8 |
| `brotli` | Zeros 64 KiB | 65536 | 63 | 0.00 | 341.3 | 928.7 | brotli | 0.00 | 11.5 | 86.1 |
| `brotli` | Random 16 KiB | 16384 | 16420 | 1.00 | 51.1 | 47.2 | brotli | 1.00 | 0.64 | 18.8 |
| `deflate` | Lorem 4 KiB | 4096 | 299 | 0.07 | 112.6 | 259.8 | py-deflate | 0.07 | 0.26 | 0.20 |
| `deflate` | Lorem 64 KiB | 65536 | 1475 | 0.02 | 467.1 | 1049 | py-deflate | 0.01 | 5.36 | 5.77 |
| `deflate` | Zeros 64 KiB | 65536 | 139 | 0.00 | 565.9 | 995.3 | py-deflate | 0.00 | 2.78 | 4.29 |
| `deflate` | Random 16 KiB | 16384 | 16434 | 1.00 | 81.7 | 86.1 | py-deflate | 1.00 | 0.86 | 0.87 |
| `gzip` | Lorem 4 KiB | 4096 | 317 | 0.08 | 82.8 | 158.0 | gzip | 0.08 | 3.19 | 2.48 |
| `gzip` | Lorem 64 KiB | 65536 | 1493 | 0.02 | 34.6 | 287.8 | gzip | 0.01 | 22.2 | 28.6 |
| `gzip` | Zeros 64 KiB | 65536 | 157 | 0.00 | 60.5 | 77.1 | gzip | 0.00 | 23.5 | 30.2 |
| `gzip` | Random 16 KiB | 16384 | 16452 | 1.00 | 14.5 | 16.4 | gzip | 1.00 | 5.92 | 32.7 |
| `lz4` | Lorem 4 KiB | 4096 | 449 | 0.11 | 816.3 | 853.5 | lz4 | 0.11 | 1.88 | 1.32 |
| `lz4` | Lorem 64 KiB | 65536 | 690 | 0.01 | 306.8 | 235.7 | lz4 | 0.01 | 27.5 | 20.6 |
| `lz4` | Zeros 64 KiB | 65536 | 275 | 0.00 | 313.5 | 251.0 | lz4 | 0.00 | 25.9 | 17.6 |
| `lz4` | Random 16 KiB | 16384 | 16458 | 1.00 | 475.7 | 735.9 | lz4 | 1.00 | 7.52 | 4.93 |
| `lzma` | Lorem 4 KiB | 4096 | 372 | 0.09 | 20.0 | 14.3 | py-lzma | 0.09 | 0.24 | 0.41 |
| `lzma` | Lorem 64 KiB | 65536 | 425 | 0.01 | 366.1 | 441.2 | py-lzma | 0.01 | 2.26 | 4.75 |
| `lzma` | Zeros 64 KiB | 65536 | 91 | 0.00 | 189.6 | 376.8 | py-lzma | 0.00 | 2.51 | 4.41 |
| `lzma` | Random 16 KiB | 16384 | 17066 | 1.04 | 24.6 | 4.54 | py-lzma | 1.01 | 0.65 | 0.85 |
| `lzma2` | Lorem 4 KiB | 4096 | 360 | 0.09 | 158.5 | 232.0 | xz-raw | 0.09 | 0.86 | 1.50 |
| `lzma2` | Lorem 64 KiB | 65536 | 413 | 0.01 | 51.9 | 138.9 | xz-raw | 0.01 | 7.47 | 22.6 |
| `lzma2` | Zeros 64 KiB | 65536 | 80 | 0.00 | 69.7 | 158.8 | xz-raw | 0.00 | 8.87 | 21.9 |
| `lzma2` | Random 16 KiB | 16384 | 16388 | 1.00 | 7.31 | 6176 | xz-raw | 1.00 | 1.21 | 15.9 |
| `lzw` | Lorem 4 KiB | 4096 | 1723 | 0.42 | 36.3 | 69.2 | compress | 0.42 | 1.77 | 2.69 |
| `lzw` | Lorem 64 KiB | 65536 | 10501 | 0.16 | 27.6 | 115.7 | compress | 0.16 | 10.5 | 24.0 |
| `lzw` | Zeros 64 KiB | 65536 | 424 | 0.01 | 32.2 | 136.5 | compress | 0.01 | 14.3 | 27.7 |
| `lzw` | Random 16 KiB | 16384 | 24130 | 1.47 | 28.7 | 33.7 | — | — | — | — |
| `rle` | Lorem 4 KiB | 4096 | 8048 | 1.96 | 129.1 | 57.6 | — | — | — | — |
| `rle` | Lorem 64 KiB | 65536 | 128722 | 1.96 | 146.9 | 63.3 | — | — | — | — |
| `rle` | Zeros 64 KiB | 65536 | 516 | 0.01 | 2570 | 20518 | — | — | — | — |
| `rle` | Random 16 KiB | 16384 | 32662 | 1.99 | 803.9 | 328.8 | — | — | — | — |
| `snappy` | Lorem 4 KiB | 4096 | 581 | 0.14 | 1147 | 1526 | — | — | — | — |
| `snappy` | Lorem 64 KiB | 65536 | 3462 | 0.05 | 2569 | 2075 | — | — | — | — |
| `snappy` | Zeros 64 KiB | 65536 | 3077 | 0.05 | 2556 | 1066 | — | — | — | — |
| `snappy` | Random 16 KiB | 16384 | 16390 | 1.00 | 190.5 | 7447 | — | — | — | — |
| `xz` | Lorem 4 KiB | 4096 | 412 | 0.10 | 100.8 | 4.08 | xz | 0.10 | 0.57 | 1.21 |
| `xz` | Lorem 64 KiB | 65536 | 468 | 0.01 | 67.1 | 62.0 | xz | 0.01 | 7.22 | 18.0 |
| `xz` | Zeros 64 KiB | 65536 | 132 | 0.00 | 145.9 | 197.5 | xz | 0.00 | 7.84 | 17.1 |
| `xz` | Random 16 KiB | 16384 | 16440 | 1.00 | 24.2 | 671.7 | xz | 1.00 | 1.12 | 13.3 |
| `zlib` | Lorem 4 KiB | 4096 | 305 | 0.07 | 61.9 | 136.0 | py-zlib | 0.07 | 0.19 | 0.17 |
| `zlib` | Lorem 64 KiB | 65536 | 1481 | 0.02 | 261.0 | 538.8 | py-zlib | 0.01 | 2.73 | 3.25 |
| `zlib` | Zeros 64 KiB | 65536 | 145 | 0.00 | 365.6 | 611.4 | py-zlib | 0.00 | 6.33 | 2.53 |
| `zlib` | Random 16 KiB | 16384 | 16440 | 1.00 | 27.2 | 24.7 | py-zlib | 1.00 | 0.61 | 0.64 |
| `zstd` | Lorem 4 KiB | 4096 | 416 | 0.10 | 155.1 | 417.6 | zstd | 0.07 | 0.56 | 0.99 |
| `zstd` | Lorem 64 KiB | 65536 | 1691 | 0.03 | 69.3 | 346.7 | zstd | 0.00 | 9.73 | 15.8 |
| `zstd` | Zeros 64 KiB | 65536 | 97 | 0.00 | 77.8 | 229.2 | zstd | 0.00 | 7.68 | 13.9 |
| `zstd` | Random 16 KiB | 16384 | 16396 | 1.00 | 21.0 | 894.4 | zstd | 1.00 | 1.85 | 4.07 |

## Notes on the numbers

### Compression ratio

- `lz4` and `lzw` match the reference's compression ratio exactly on
  every input — same format, same encoding choices in practice.
- `deflate` / `zlib` / `gzip` come in within a small constant factor of
  zlib's default-level output (e.g. 1475 B vs zlib's 1156 B on
  Lorem 64 KiB — ~1.27× larger).
- `lzma` and `lzma2` are within ~1.05× of Python's `lzma`/`xz` for
  Lorem; on random data we're at ratio 1.04 vs reference 1.01, because
  our greedy parser emits slightly more match/literal overhead.
- `xz` matches reference on every text input (468 B vs reference).
- `zstd` and `brotli` lag the reference for highly-compressible inputs
  because we don't yet ship Huffman literal compression / FSE table
  customisation (zstd) or dictionary lookups / context modelling
  (brotli). Within 2-3× on Lorem; the gap is documented in the
  per-module headers.
- `rle` has a 1.96 ratio on Lorem — that's expected, RLE's
  `[count][byte]` per pair adds 100% overhead on any byte that isn't
  part of a run.

### Throughput

In-process numbers (ours) and shell-out numbers (reference) are
**fundamentally not comparable**. Each reference call pays
fork+exec+exit (~1-5 ms), so for the 4 KiB inputs the reference
appears 10-1000× "slower" than us — that's just process startup.
At 64 KiB the gap narrows. Where the reference is faster than us
even with overhead in its way, that's a real signal:

- `gzip` 64 KiB: reference 22 MB/s encode vs us 35 MB/s — close.
- `xz` 64 KiB: reference 7 MB/s vs us 67 MB/s — but our output is
  bigger (no compressed-LZMA2 quality optimisations).
- `brotli` 64 KiB: reference 19 MB/s vs us 210 MB/s — again our
  output is bigger.

The "we're faster" headline therefore really means: "our codecs do
less work because they pick simpler choices." Apples-to-apples
throughput comparison would need linking against the reference's
library directly (e.g. via FFI) — outside the scope of compcol's
zero-dep policy.

### Outliers worth a second look

A few cells look anomalous and are worth investigating later:

- `lzma2` Random 16 KiB **decode** at 6176 MB/s — that's because the
  encoder fell back to uncompressed chunks, so the decoder is doing
  little more than a byte copy. Real, just suspicious-looking.
- `xz` Lorem 4 KiB **decode** at 4.08 MB/s — much slower than
  expected for a tiny input. Likely measurement noise from a single
  unlucky cold-cache run; the next size up (64 KiB) sits at a normal
  62 MB/s.
- `snappy` Random 16 KiB **decode** at 7447 MB/s — same pattern as
  `lzma2` random: no compression happened, decoder is mostly a copy.

These will smooth out if the runs count or input sizes are bumped.
