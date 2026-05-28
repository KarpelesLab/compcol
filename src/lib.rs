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
pub use traits::{Algorithm, Decoder, Encoder, Progress, Status};

// Shared internals used by the deflate-family codecs. Kept private; the
// surface that downstream crates see is the per-algorithm modules below.
// Gated on the features that consume them so a narrow build (e.g. just
// `lz4`) doesn't pull them in via `cfg(test)`.
#[cfg(feature = "deflate")]
mod bits;
#[cfg(any(feature = "zlib", feature = "gzip"))]
mod checksum;
#[cfg(feature = "deflate")]
mod huffman;

#[cfg(feature = "rle")]
pub mod rle;

#[cfg(feature = "deflate")]
pub mod deflate;

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

#[cfg(feature = "snappy")]
pub mod snappy;

#[cfg(feature = "lzw")]
pub mod lzw;

#[cfg(feature = "lzo")]
pub mod lzo;

#[cfg(feature = "lzx")]
pub mod lzx;

#[cfg(feature = "quantum")]
pub mod quantum;

#[cfg(feature = "rar1")]
pub mod rar1;

#[cfg(feature = "rar2")]
pub mod rar2;

#[cfg(feature = "rar3")]
pub mod rar3;

#[cfg(feature = "rar5")]
pub mod rar5;

#[cfg(feature = "factory")]
pub mod factory;
