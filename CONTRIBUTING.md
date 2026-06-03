# Contributing to compcol

Thanks for your interest. This crate has a few hard constraints that every
change must respect — please read them before opening a PR.

## Non-negotiable crate properties

- **`no_std`.** The library is `#![no_std]`. Use `core` and, when you need
  the heap, `alloc` (gated behind the `alloc` feature). Never reach for
  `std` outside the `std`/`tokio` feature-gated modules (`compcol::io`,
  `compcol::tokio_io`).
- **`#![forbid(unsafe_code)]`.** No `unsafe`, anywhere, ever. It is set
  crate-wide via `[lints.rust] unsafe_code = "forbid"`.
- **Zero runtime dependencies.** `[dependencies]` carries only `tokio`,
  and that is optional (pulled in solely by the `tokio` feature). Do not
  add runtime dependencies. Dev-dependencies for tests are acceptable when
  justified.

## DoS discipline (decoders)

Decoders process **untrusted input** and must never panic, read out of
bounds, or allocate unboundedly on malformed data:

- Use **checked arithmetic** (`checked_add`, `checked_mul`, …) and
  bounds-checked indexing/slicing — no `unwrap()`/`expect()` on
  attacker-controlled lengths, offsets, or counts.
- **Reject** malformed input by returning an appropriate
  [`crate::Error`] variant (`Corrupt`, `BadHeader`, `InvalidHuffmanTree`,
  `InvalidDistance`, `Unsupported`, …) — never by panicking.
- **Bound output.** Don't pre-allocate from an attacker-supplied size
  field without a sanity cap. Output limiting for callers is provided by
  `compcol::limit::LimitedDecoder`; your decoder must still not blow up
  internally.
- Every decoder gets a fuzz target asserting "no panic on arbitrary
  input" (see below).

## Adding a new codec

1. **Module:** create `src/<codec>/` (or `src/<codec>.rs` for a tiny one).
2. **Internal traits:** implement the private `RawEncoder` / `RawDecoder`
   from `src/traits.rs`. A blanket impl auto-derives the public
   `Encoder` / `Decoder` from these — do **not** implement the public
   traits directly. If the format has no encoder (decoder-only, or
   license-restricted), the encoder's `raw_encode`/`raw_finish` return
   `Error::Unsupported`.
3. **Marker type:** add a zero-sized type implementing `Algorithm`
   (`const NAME`, `type Encoder/Decoder`, `type EncoderConfig/DecoderConfig`,
   `encoder_with`/`decoder_with`). Use `()` for configs with no tunables.
   See `src/rle.rs` for the smallest complete example.
4. **Cargo feature:** add a `<codec> = ["alloc"]` entry in `Cargo.toml`
   (or `= []` if genuinely `alloc`-free like `rle`), with a doc comment,
   and add the feature to the `all` meta-feature list.
5. **Declare it:** add `#[cfg(feature = "<codec>")] pub mod <codec>;` to
   `src/lib.rs`.
6. **Register it:** in `src/factory.rs`, add `#[cfg(feature = "<codec>")]`
   arms for the marker type's `NAME` in `encoder_by_name`, `decoder_by_name`
   (and `encoder_by_name_with_level` if it has a level), and add it to both
   `names()` and `extension()` so it shows up in by-name listing and gets a
   CLI output suffix.
7. **Tests:** add `tests/<codec>.rs` (round-trip if there's an encoder;
   reference-tool cross-validation or hex fixtures for decoder-only
   formats).
8. **Fuzz:** add `fuzz/fuzz_targets/decoder_<codec>.rs` driving the
   decoder over arbitrary bytes and asserting it never panics (copy an
   existing target, e.g. `decoder_lz4.rs`, as the template).

## Clean-room / licensing policy

The crate is MIT and stays clean-room:

- Implement codecs from **public specifications** and facts-only
  functional descriptions only.
- **Do not copy code or data tables** from LGPL/GPL sources — notably
  The Unarchiver / XADMaster — or from RARLAB's `unRAR` distribution.
  RARLAB's license forbids using its source to recreate the RAR
  *compression* algorithm, which is why every RAR encoder is permanently
  `Unsupported`.
- If a codec genuinely needs a fixed interoperability table that exists
  only in a license-incompatible source, treat it like the existing
  `rar1` / StuffIt situations: ship the well-defined building blocks
  clean-room, keep any non-clean-room table out of the spec-derived
  material, and either leave the decoder `Unsupported` (the `rar1` case)
  or supply the table as a separately-licensed, maintainer-sanctioned
  adjunct kept out of the clean-room corpus (the `sit13` case). Document
  the provenance in the module docs, as `src/rar1/` and `src/sit13/` do.

## CI gates (must pass)

CI (`.github/workflows/ci.yml`) runs on Linux/macOS/Windows and denies
warnings. Before pushing:

```sh
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo build --no-default-features                       # bare no_std
cargo build --no-default-features --features all        # every algo, still no_std
RUSTDOCFLAGS="-D warnings -D rustdoc::broken-intra-doc-links" cargo doc --no-deps --all-features
```

CI also runs clippy on narrow feature subsets (`lz4`-only, `zstd`-only)
to catch dead-code regressions in the shared `bits` / `checksum` /
`huffman` modules — keep those `#[cfg]`-gated correctly.

Do not edit `CHANGELOG.md` in your PR; releases are managed by
release-plz.
