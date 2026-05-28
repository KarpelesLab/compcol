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
        _ => None,
    }
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
    ]
}
