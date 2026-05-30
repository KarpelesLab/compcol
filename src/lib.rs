//! `compcol` — a collection of pure-Rust, `no_std`, 100% safe compression
//! algorithms behind a uniform streaming trait.
//!
//! Each algorithm sits behind its own Cargo feature so downstream crates
//! only pay for what they use. An optional [`factory`] module provides
//! runtime by-name lookup when the `factory` (and thus `alloc`) feature is
//! enabled.
//!
//! See [`Encoder`], [`Decoder`], and [`Algorithm`] for the contract every
//! algorithm in this crate implements.

#![no_std]
#![forbid(unsafe_code)]

#[cfg(feature = "alloc")]
extern crate alloc;

mod error;
mod traits;

pub use error::Error;
pub use traits::{Algorithm, Decoder, Encoder, Flush, Progress, Status};

pub mod limit;

#[cfg(feature = "alloc")]
pub mod vec;

#[cfg(feature = "std")]
pub mod io;

#[cfg(feature = "tokio")]
pub mod tokio_io;

// Shared internals used by the deflate-family codecs. Kept private; the
// surface that downstream crates see is the per-algorithm modules below.
// Gated on the features that consume them so a narrow build (e.g. just
// `lz4`) doesn't pull them in via `cfg(test)`.
#[cfg(any(feature = "deflate", feature = "deflate64"))]
mod bits;
#[cfg(any(feature = "zlib", feature = "gzip"))]
mod checksum;
#[cfg(any(feature = "deflate", feature = "deflate64"))]
mod huffman;

#[cfg(feature = "rle")]
pub mod rle;

#[cfg(feature = "deflate")]
pub mod deflate;

#[cfg(feature = "deflate64")]
pub mod deflate64;

#[cfg(feature = "zlib")]
pub mod zlib;

#[cfg(feature = "gzip")]
pub mod gzip;

#[cfg(feature = "lzma")]
pub mod lzma;

#[cfg(feature = "xz")]
pub mod xz;

#[cfg(feature = "zstd")]
pub mod zstd;

#[cfg(feature = "brotli")]
pub mod brotli;

#[cfg(feature = "lz4")]
pub mod lz4;

#[cfg(feature = "lz5")]
pub mod lz5;

#[cfg(feature = "snappy")]
pub mod snappy;

#[cfg(feature = "lzw")]
pub mod lzw;

#[cfg(feature = "lzss")]
pub mod lzss;

#[cfg(feature = "lzo")]
pub mod lzo;

// The `amiga_lzx` codec reuses the `tables`/`bitreader`/`huffman` submodules
// of `lzx`, so the lzx module is declared whenever either feature is enabled.
// When `lzx` itself is disabled, only the shared internals are compiled in
// (the public `Lzx`, `Decoder`, `Encoder`, and the verbose decoder/encoder
// state machines remain gated on `feature = "lzx"` inside `lzx/mod.rs`).
#[cfg(any(feature = "lzx", feature = "amiga_lzx"))]
pub mod lzx;

#[cfg(feature = "amiga_lzx")]
pub mod amiga_lzx;

#[cfg(feature = "quantum")]
pub mod quantum;

#[cfg(feature = "lzfse")]
pub mod lzfse;

#[cfg(feature = "adc")]
pub mod adc;

#[cfg(feature = "lznt1")]
pub mod lznt1;
#[cfg(feature = "ppmd")]
pub mod ppmd;

#[cfg(feature = "bzip2")]
pub mod bzip2;

#[cfg(feature = "lzs")]
pub mod lzs;
#[cfg(feature = "packbits")]
pub mod packbits;

#[cfg(feature = "xpress")]
pub mod xpress;
#[cfg(feature = "xpress_huffman")]
pub mod xpress_huffman;

#[cfg(feature = "lzham")]
pub mod lzham;
#[cfg(feature = "zip_implode")]
pub mod zip_implode;

#[cfg(feature = "rar1")]
pub mod rar1;

#[cfg(feature = "rar2")]
pub mod rar2;

#[cfg(feature = "rar3")]
pub mod rar3;

#[cfg(feature = "rar5")]
pub mod rar5;

#[cfg(feature = "zip_reduce")]
pub mod zip_reduce;
#[cfg(feature = "zip_shrink")]
pub mod zip_shrink;

#[cfg(feature = "arc_crunch")]
pub mod arc_crunch;
#[cfg(feature = "arc_squeeze")]
pub mod arc_squeeze;
#[cfg(feature = "lha")]
pub mod lha;

#[cfg(feature = "factory")]
pub mod factory;

#[cfg(feature = "bcj")]
pub mod bcj;

#[cfg(feature = "delta")]
pub mod delta;
