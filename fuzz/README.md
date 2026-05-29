# `compcol` fuzz targets

This crate is a separate workspace member that houses `cargo-fuzz`
targets for the decoders. It is **not** built by the main crate's
test suite or by `cargo build` at the repo root — you only enter it
when actively fuzzing.

## Setup (one-time)

```sh
cargo install cargo-fuzz
rustup toolchain install nightly  # cargo-fuzz needs nightly for -Z flags
```

## Running a target

```sh
cd fuzz
cargo +nightly fuzz run decoder_gzip
```

Targets currently shipped (one binary each):

| Target               | What it drives                                          |
|----------------------|---------------------------------------------------------|
| `decoder_dispatch`   | All algorithms. Byte 0 picks one via `factory::names()` |
| `decoder_gzip`       | RFC 1952 gzip decoder                                   |
| `decoder_zlib`       | RFC 1950 zlib decoder                                   |
| `decoder_deflate`    | RFC 1951 raw deflate decoder                            |
| `decoder_zstd`       | Zstandard decoder                                       |
| `decoder_brotli`     | Brotli decoder                                          |
| `decoder_lzma`       | Legacy `.lzma` decoder                                  |
| `decoder_xz`         | `.xz` container decoder                                 |
| `decoder_lz4`        | LZ4 block format decoder                                |

Every target drives the decoder over arbitrary input bytes and
asserts no panic, abort, or undefined behavior. The decoder is
allowed to return any `compcol::Error`; the property is purely "does
not crash". This catches index-out-of-bounds, integer overflow,
denial-of-service infinite loops (via a `steps > 4096` guard), and
stack overflows.

## CI

`.github/workflows/fuzz.yml` runs each target for 30 seconds on every
PR. That's enough to catch regressions but not enough for deep coverage
— for serious fuzz campaigns, run locally with `-max_total_time=3600`
or longer, or wire up an OSS-Fuzz integration. The CI run caps each
fuzz iteration at 512 MiB resident so a decoder coaxed into allocating
gigabytes (which is a finding) doesn't kill the runner.

## Adding a target

1. Drop a new file under `fuzz_targets/decoder_<algo>.rs` modeled on
   any of the existing ones (they are six lines of boilerplate plus a
   small loop driver).
2. Add a `[[bin]]` entry to `fuzz/Cargo.toml`.
3. Add the target name to the CI matrix in `.github/workflows/fuzz.yml`.

## Triaging a crash

`cargo fuzz` writes crash inputs to
`fuzz/artifacts/<target>/crash-<sha>`. Reproduce with:

```sh
cargo +nightly fuzz run <target> fuzz/artifacts/<target>/crash-<sha>
```

Then minimize:

```sh
cargo +nightly fuzz tmin <target> fuzz/artifacts/<target>/crash-<sha>
```
