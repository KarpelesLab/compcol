//! The containers around a deflate stream, as types: the header the
//! encoder writes, the trailer both sides compute, and the checksum of the
//! data that goes in it.

#[cfg(feature = "zlib")]
use super::checksum::Adler32;
#[cfg(feature = "gzip")]
use super::checksum::Crc32;

/// A container: raw deflate, zlib or gzip.
pub(crate) trait Format: Sized {
    /// What the encoder writes before the first block.
    const HEADER: &'static [u8];
    /// How many 32-bit words follow the last block: none, the zlib
    /// Adler-32, or the gzip CRC-32 and length.
    const TRAILER: usize;
    /// Whether the decoder parses a gzip header and members.
    const GZIP: bool;
    /// A fresh container, all zeros, so that a codec holding one can be
    /// built in a `static` that lands in `.bss`.
    const INIT: Self;
    /// Feeds data to the checksum.
    fn update(&mut self, data: &[u8]);
    /// The trailer, as the little-endian words the encoder writes, given
    /// the length of the data modulo 2<sup>32</sup>.
    fn trailer(&self, size: u32) -> [u32; 2];
}

/// A raw deflate stream (RFC 1951): no header, no checksum.
pub(crate) struct Raw;

impl Format for Raw {
    const HEADER: &'static [u8] = &[];
    const TRAILER: usize = 0;
    const GZIP: bool = false;
    const INIT: Self = Raw;

    #[inline(always)]
    fn update(&mut self, _: &[u8]) {}

    fn trailer(&self, _: u32) -> [u32; 2] {
        [0; 2]
    }
}

/// The zlib format (RFC 1950).
#[cfg(feature = "zlib")]
pub(crate) struct Zlib(Adler32);

#[cfg(feature = "zlib")]
impl Format for Zlib {
    // Deflate with a 32 KiB window, fastest algorithm, no dictionary.
    const HEADER: &'static [u8] = &[0x78, 0x01];
    const TRAILER: usize = 1;
    const GZIP: bool = false;
    const INIT: Self = Zlib(Adler32::new());

    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    fn trailer(&self, _: u32) -> [u32; 2] {
        // Big-endian on the wire.
        [self.0.value().swap_bytes(), 0]
    }
}

/// The gzip format (RFC 1952).
#[cfg(feature = "gzip")]
pub(crate) struct Gzip(Crc32);

#[cfg(feature = "gzip")]
impl Format for Gzip {
    // Deflate, no flags, no modification time, no extra flags, unknown OS.
    const HEADER: &'static [u8] = &[0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff];
    const TRAILER: usize = 2;
    const GZIP: bool = true;
    const INIT: Self = Gzip(Crc32::new());

    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    fn trailer(&self, size: u32) -> [u32; 2] {
        [self.0.value(), size]
    }
}
