//! Embedded-target mode — the `embed` feature.
//!
//! With `embed` enabled, the algorithms that have a small variant are built
//! as that variant **under their usual names**: `compcol::gzip::Gzip`,
//! `compcol::zlib::Encoder`, `compcol::deflate::Decoder` and so on keep their
//! paths and their [`Encoder`](crate::Encoder) / [`Decoder`](crate::Decoder)
//! contracts, so the same downstream code compiles either way. What changes
//! is what is behind them: no heap, little stack, little code.
//!
//! `embed` is a *mode*, not an addition. It pulls nothing in by itself (no
//! `alloc`), and is meant for `--no-default-features --features embed,gzip`
//! style builds. Enabling it in a crate graph switches every user of that
//! graph to the small variants, as Cargo features unify.
//!
//! # The deflate family: `deflate`, `zlib`, `gzip`
//!
//! Backed by the [`minizlib`](https://crates.io/crates/minizlib) crate (same
//! author, MIT, `no_std`, no `unsafe`, no dependencies): a push decoder in
//! the manner of zlib's `puff`, which decodes Huffman codes one bit at a
//! time from the count of codes of each length and keeps about 1.1 KiB of
//! state between pieces; and a greedy LZ77 encoder over a single-probe hash
//! table, coded with deflate's fixed Huffman codes.
//!
//! What it gives up compared to the standard build:
//!
//! - **Ratio.** The encoder emits fixed-Huffman blocks only, finds matches
//!   within [`BLOCK`]-byte blocks only, and does no lazy matching: expect
//!   roughly 40–45 % on text where `gzip -6` gets 20 %. `EncoderConfig::level`
//!   is accepted and ignored.
//! - **Speed.** The decoder runs at tens of MB/s where the standard one does
//!   hundreds; small code was the goal.
//! - **Sync flush.** [`Encoder::flush`](crate::Encoder::flush) returns
//!   [`Error::Unsupported`](crate::Error::Unsupported): the encoder cannot
//!   byte-align its bitstream mid-stream. Use `finish`.
//! - **Preset dictionaries** (zlib `FDICT`) are not supported, and
//!   `zlib::DecoderConfig` has no `dictionary` field.
//! - **Concatenated gzip members** are not decoded as one stream: the
//!   decoder stops, with `Status::StreamEnd`, at the end of the first.
//! - **Window size.** The decoder's window is a fixed [`WINDOW`] (32 KiB)
//!   inline in the decoder; `deflate::DecoderConfig::window_size` only
//!   tightens the distance check.
//!
//! # Memory
//!
//! Nothing is allocated, so everything lives inside the codec structs, and
//! the codec structs are big: place them in a `static`, in a `Box` if there
//! is an allocator, or on a stack that has the room. Both constructors are
//! `const fn` and build an all-zero state, so `static DEC: Decoder =
//! Decoder::new()` is possible (behind the `Mutex`, `RefCell` or `static
//! mut` of your platform's choosing), lands in `.bss`, costs no flash, and
//! nothing transits the stack. An unoptimised `Box::new(Decoder::new())`
//! does build the struct on the stack first.
//!
//! | struct             | size (bytes)        | of which                                       |
//! |--------------------|--------------------:|------------------------------------------------|
//! | `*::Decoder`       | ≈ 33 900 (≤ [`DECODER_SIZE`]) | 32 KiB window + ~1.1 KiB codes/state |
//! | `*::Encoder`       | ≈ 10 850 (≤ [`ENCODER_SIZE`]) | 4 KiB block + 4.6 KiB output + 2 KiB table |
//!
//! Stack use per call is under a hundred bytes for either direction; see
//! the ceilings below.
//!
//! # Sizes CI holds the build to
//!
//! `tools/footprint/check.sh` builds a bare-metal `thumbv7em-none-eabi`
//! binary around each codec with `opt-level = "z"` and LTO, and fails if any
//! of these is exceeded, if any panic machinery gets linked, if any static
//! RAM is needed besides the codec struct itself, or if that struct does not
//! land in `.bss`:
//!
//! | configuration                  | code (bytes) | stack (bytes) |
//! |--------------------------------|-------------:|--------------:|
//! | gzip decode                    | ≤ 4 600      | ≤ 256         |
//! | zlib decode                    | ≤ 4 600      | ≤ 256         |
//! | raw deflate decode             | ≤ 4 300      | ≤ 256         |
//! | gzip encode                    | ≤ 2 000      | ≤ 256         |
//! | zlib encode                    | ≤ 2 000      | ≤ 256         |
//! | raw deflate encode             | ≤ 1 700      | ≤ 256         |
//! | gzip encode + decode           | ≤ 6 500      | ≤ 256         |
//!
//! "Stack" is the deepest call path from the entry point, every function's
//! frame read off the disassembly (`tools/footprint/stack.py`); nothing
//! recurses and nothing is called indirectly, so it is the bound. Measured
//! on rustc 1.98: decoders at 4 300–4 400 bytes of code, encoders at
//! 1 550–1 900, under 100 bytes of stack either way. The table is a
//! contract, not a report; the constants in this module are the same
//! ceilings for the host-side tests.
#![cfg_attr(docsrs, doc(cfg(feature = "embed")))]

#[cfg(feature = "deflate")]
pub(crate) mod codec;

/// The decoder's history window, in bytes: deflate's full 32 KiB reach, so
/// every stream decodes.
pub const WINDOW: usize = 32 * 1024;

/// The encoder's block size, in bytes: input is compressed a block at a
/// time, and matches are only found within a block.
pub const BLOCK: usize = 4 * 1024;

/// The encoder's hash table, in entries of `u16`.
pub const TABLE: usize = 1024;

/// The encoder's compressed-output buffer, in bytes: what one [`BLOCK`] can
/// compress to at most (fixed Huffman: 9 bits per literal, a 3-bit block
/// header, a 7-bit end of block), plus the container header and some slack
/// for the trailer.
pub const OUT: usize = BLOCK + BLOCK / 8 + 32;

/// Ceiling on `size_of::<Decoder>()` for the deflate-family decoders, in
/// bytes. Asserted by the test suite.
pub const DECODER_SIZE: usize = WINDOW + 2048;

/// Ceiling on `size_of::<Encoder>()` for the deflate-family encoders, in
/// bytes. Asserted by the test suite.
pub const ENCODER_SIZE: usize = BLOCK + OUT + 2 * TABLE + 256;
