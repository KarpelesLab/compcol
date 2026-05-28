//! Runtime by-name lookup of algorithms.
//!
//! Only the algorithms whose Cargo features are enabled appear in
//! [`names`] and are resolvable by [`encoder_by_name`] / [`decoder_by_name`].
//! Requires the `alloc` feature (pulled in automatically by the `factory`
//! feature) because the returned trait objects are heap-allocated.

extern crate alloc;
use alloc::boxed::Box;

use crate::traits::{Algorithm, Decoder, Encoder};

/// Build an encoder for the algorithm named `name`, or `None` if no algorithm
/// is compiled in under that name.
pub fn encoder_by_name(name: &str) -> Option<Box<dyn Encoder>> {
    match name {
        #[cfg(feature = "rle")]
        crate::rle::Rle::NAME => Some(Box::new(<crate::rle::Rle as Algorithm>::encoder())),
        #[cfg(feature = "deflate")]
        crate::deflate::Deflate::NAME => {
            Some(Box::new(<crate::deflate::Deflate as Algorithm>::encoder()))
        }
        #[cfg(feature = "zlib")]
        crate::zlib::Zlib::NAME => Some(Box::new(<crate::zlib::Zlib as Algorithm>::encoder())),
        #[cfg(feature = "gzip")]
        crate::gzip::Gzip::NAME => Some(Box::new(<crate::gzip::Gzip as Algorithm>::encoder())),
        #[cfg(feature = "lzma")]
        crate::lzma::Lzma::NAME => Some(Box::new(<crate::lzma::Lzma as Algorithm>::encoder())),
        #[cfg(feature = "xz")]
        crate::xz::Xz::NAME => Some(Box::new(<crate::xz::Xz as Algorithm>::encoder())),
        #[cfg(feature = "zstd")]
        crate::zstd::Zstd::NAME => Some(Box::new(<crate::zstd::Zstd as Algorithm>::encoder())),
        #[cfg(feature = "brotli")]
        crate::brotli::Brotli::NAME => {
            Some(Box::new(<crate::brotli::Brotli as Algorithm>::encoder()))
        }
        #[cfg(feature = "lz4")]
        crate::lz4::Lz4::NAME => Some(Box::new(<crate::lz4::Lz4 as Algorithm>::encoder())),
        #[cfg(feature = "snappy")]
        crate::snappy::Snappy::NAME => {
            Some(Box::new(<crate::snappy::Snappy as Algorithm>::encoder()))
        }
        #[cfg(feature = "lzw")]
        crate::lzw::Lzw::NAME => Some(Box::new(<crate::lzw::Lzw as Algorithm>::encoder())),
        _ => None,
    }
}

/// Build a decoder for the algorithm named `name`, or `None` if no algorithm
/// is compiled in under that name.
pub fn decoder_by_name(name: &str) -> Option<Box<dyn Decoder>> {
    match name {
        #[cfg(feature = "rle")]
        crate::rle::Rle::NAME => Some(Box::new(<crate::rle::Rle as Algorithm>::decoder())),
        #[cfg(feature = "deflate")]
        crate::deflate::Deflate::NAME => {
            Some(Box::new(<crate::deflate::Deflate as Algorithm>::decoder()))
        }
        #[cfg(feature = "zlib")]
        crate::zlib::Zlib::NAME => Some(Box::new(<crate::zlib::Zlib as Algorithm>::decoder())),
        #[cfg(feature = "gzip")]
        crate::gzip::Gzip::NAME => Some(Box::new(<crate::gzip::Gzip as Algorithm>::decoder())),
        #[cfg(feature = "lzma")]
        crate::lzma::Lzma::NAME => Some(Box::new(<crate::lzma::Lzma as Algorithm>::decoder())),
        #[cfg(feature = "xz")]
        crate::xz::Xz::NAME => Some(Box::new(<crate::xz::Xz as Algorithm>::decoder())),
        #[cfg(feature = "zstd")]
        crate::zstd::Zstd::NAME => Some(Box::new(<crate::zstd::Zstd as Algorithm>::decoder())),
        #[cfg(feature = "brotli")]
        crate::brotli::Brotli::NAME => {
            Some(Box::new(<crate::brotli::Brotli as Algorithm>::decoder()))
        }
        #[cfg(feature = "lz4")]
        crate::lz4::Lz4::NAME => Some(Box::new(<crate::lz4::Lz4 as Algorithm>::decoder())),
        #[cfg(feature = "snappy")]
        crate::snappy::Snappy::NAME => {
            Some(Box::new(<crate::snappy::Snappy as Algorithm>::decoder()))
        }
        #[cfg(feature = "lzw")]
        crate::lzw::Lzw::NAME => Some(Box::new(<crate::lzw::Lzw as Algorithm>::decoder())),
        _ => None,
    }
}

/// Conventional filename extension (without the leading `.`) for the given
/// algorithm, or `None` if the algorithm isn't compiled in or has no
/// conventional extension.
///
/// Used by the `compcol` CLI to derive `<input>.<ext>` output paths in
/// gzip-style in-place mode.
pub const fn extension(name: &str) -> Option<&'static str> {
    // String literals match on byte-identical content, which `const fn`
    // allows; can't use enum dispatch through trait objects in const context.
    if str_eq(name, "rle") && cfg!(feature = "rle") {
        return Some("rle");
    }
    if str_eq(name, "deflate") && cfg!(feature = "deflate") {
        return Some("deflate");
    }
    if str_eq(name, "zlib") && cfg!(feature = "zlib") {
        return Some("zz");
    }
    if str_eq(name, "gzip") && cfg!(feature = "gzip") {
        return Some("gz");
    }
    if str_eq(name, "lzma") && cfg!(feature = "lzma") {
        return Some("lzma");
    }
    if str_eq(name, "xz") && cfg!(feature = "xz") {
        return Some("xz");
    }
    if str_eq(name, "zstd") && cfg!(feature = "zstd") {
        return Some("zst");
    }
    if str_eq(name, "brotli") && cfg!(feature = "brotli") {
        return Some("br");
    }
    if str_eq(name, "lz4") && cfg!(feature = "lz4") {
        return Some("lz4");
    }
    if str_eq(name, "snappy") && cfg!(feature = "snappy") {
        return Some("sz");
    }
    if str_eq(name, "lzw") && cfg!(feature = "lzw") {
        return Some("lzw");
    }
    None
}

/// Const-eval-friendly byte comparison.
const fn str_eq(a: &str, b: &str) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// The names of every algorithm compiled into the current build, in stable
/// order. Useful for diagnostics, CLI `--list`, etc.
pub const fn names() -> &'static [&'static str] {
    &[
        #[cfg(feature = "rle")]
        crate::rle::Rle::NAME,
        #[cfg(feature = "deflate")]
        crate::deflate::Deflate::NAME,
        #[cfg(feature = "zlib")]
        crate::zlib::Zlib::NAME,
        #[cfg(feature = "gzip")]
        crate::gzip::Gzip::NAME,
        #[cfg(feature = "lzma")]
        crate::lzma::Lzma::NAME,
        #[cfg(feature = "xz")]
        crate::xz::Xz::NAME,
        #[cfg(feature = "zstd")]
        crate::zstd::Zstd::NAME,
        #[cfg(feature = "brotli")]
        crate::brotli::Brotli::NAME,
        #[cfg(feature = "lz4")]
        crate::lz4::Lz4::NAME,
        #[cfg(feature = "snappy")]
        crate::snappy::Snappy::NAME,
        #[cfg(feature = "lzw")]
        crate::lzw::Lzw::NAME,
    ]
}
