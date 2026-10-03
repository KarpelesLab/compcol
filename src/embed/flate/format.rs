//! The containers, as types: what goes around a deflate stream, and the
//! checksum of the data that goes with it.

use super::Checksum;
#[cfg(feature = "zlib")]
use super::checksum::Adler32;
#[cfg(feature = "gzip")]
use super::checksum::Crc32;

mod sealed {
    pub trait Sealed {}
}

/// A container for compressed data, to decompress from:
/// [`Gzip`](struct.Gzip.html), [`Zlib`](struct.Zlib.html), [`Raw`], or
/// [`Detect`](struct.Detect.html) for whichever of the first two comes.
pub trait Container: sealed::Sealed + Checksum + Sized {
    /// How many of the `trailer` words there are, at most. Zero means no
    /// header either.
    #[doc(hidden)]
    const TRAILER: usize;
    /// A fresh container: no data seen yet. A constant, so that the codecs
    /// can be built in `const` context, and all zeros, so that one built in
    /// a `static` lands in `.bss`.
    #[doc(hidden)]
    const INIT: Self;
    #[doc(hidden)]
    fn new() -> Self {
        Self::INIT
    }
    /// Whether a stream starting with `first` is a gzip one.
    #[doc(hidden)]
    fn detect(&mut self, first: u8) -> bool;
    /// The trailer, as little-endian words, given the length of the data
    /// modulo 2<sup>32</sup>.
    #[doc(hidden)]
    fn trailer(&self, size: u32) -> [u32; 2];
}

/// A container for compressed data, to compress to:
/// [`Gzip`](struct.Gzip.html), [`Zlib`](struct.Zlib.html) or [`Raw`].
pub trait Format: Container {
    #[doc(hidden)]
    const HEADER: &'static [u8];
}

/// The gzip format (RFC 1952), as produced by `gzip`.
#[cfg(feature = "gzip")]
pub struct Gzip(Crc32);

#[cfg(feature = "gzip")]
impl sealed::Sealed for Gzip {}

#[cfg(feature = "gzip")]
impl Checksum for Gzip {
    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
}

#[cfg(feature = "gzip")]
impl Container for Gzip {
    const TRAILER: usize = 2;
    const INIT: Self = Gzip(Crc32::new());

    fn detect(&mut self, _: u8) -> bool {
        true
    }

    fn trailer(&self, size: u32) -> [u32; 2] {
        [self.0.value(), size]
    }
}

#[cfg(feature = "gzip")]
impl Format for Gzip {
    // Deflate, no flags, no modification time, no extra flags, unknown OS.
    const HEADER: &'static [u8] = &[0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff];
}

/// The zlib format (RFC 1950).
#[cfg(feature = "zlib")]
pub struct Zlib(Adler32);

#[cfg(feature = "zlib")]
impl sealed::Sealed for Zlib {}

#[cfg(feature = "zlib")]
impl Checksum for Zlib {
    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
}

#[cfg(feature = "zlib")]
impl Container for Zlib {
    const TRAILER: usize = 1;
    const INIT: Self = Zlib(Adler32::new());

    fn detect(&mut self, _: u8) -> bool {
        false
    }

    fn trailer(&self, _: u32) -> [u32; 2] {
        // Big-endian.
        [self.0.value().swap_bytes(), 0]
    }
}

#[cfg(feature = "zlib")]
impl Format for Zlib {
    // Deflate with a 32 KiB window, fastest algorithm, no dictionary.
    const HEADER: &'static [u8] = &[0x78, 0x01];
}

/// A raw deflate stream (RFC 1951): no header, no checksum.
pub struct Raw;

impl sealed::Sealed for Raw {}

impl Checksum for Raw {
    #[inline(always)]
    fn update(&mut self, _: &[u8]) {}
}

impl Container for Raw {
    const TRAILER: usize = 0;
    const INIT: Self = Raw;

    fn detect(&mut self, _: u8) -> bool {
        false
    }

    fn trailer(&self, _: u32) -> [u32; 2] {
        [0; 2]
    }
}

impl Format for Raw {
    const HEADER: &'static [u8] = &[];
}

/// Gzip or zlib, whichever the stream turns out to be. Only to decompress.
#[cfg(all(feature = "gzip", feature = "zlib"))]
pub struct Detect {
    gzip: Gzip,
    zlib: Zlib,
    is_gzip: bool,
}

#[cfg(all(feature = "gzip", feature = "zlib"))]
impl sealed::Sealed for Detect {}

#[cfg(all(feature = "gzip", feature = "zlib"))]
impl Checksum for Detect {
    fn update(&mut self, data: &[u8]) {
        match self.is_gzip {
            true => self.gzip.update(data),
            false => self.zlib.update(data),
        }
    }
}

#[cfg(all(feature = "gzip", feature = "zlib"))]
impl Container for Detect {
    const TRAILER: usize = 2;
    const INIT: Self = Detect {
        gzip: Gzip::INIT,
        zlib: Zlib::INIT,
        is_gzip: false,
    };

    fn detect(&mut self, first: u8) -> bool {
        // A zlib stream cannot start with 0x1f: the low nibble of its first
        // byte is the compression method, 8.
        self.is_gzip = first == 0x1f;
        self.is_gzip
    }

    fn trailer(&self, size: u32) -> [u32; 2] {
        match self.is_gzip {
            true => self.gzip.trailer(size),
            false => self.zlib.trailer(size),
        }
    }
}
