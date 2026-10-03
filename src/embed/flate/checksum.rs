//! Running checksums over the decompressed data.

/// A running checksum fed by an [`Output`](super::Output).
///
/// Outputs hand every decompressed byte to `update` exactly once, in order,
/// in whatever chunking is convenient for them.
pub trait Checksum {
    /// Feeds `data` into the checksum.
    fn update(&mut self, data: &[u8]);
}

/// No checksum: raw deflate.
impl Checksum for () {
    #[inline(always)]
    fn update(&mut self, _: &[u8]) {}
}

// `embed`'s own checksums, whose initial state is zero: a codec built in a
// `static` then lands in `.bss` rather than in `.data`, and costs no flash.
#[cfg(feature = "zlib")]
pub(crate) use super::super::checksum::Adler32;
#[cfg(feature = "gzip")]
pub(crate) use super::super::checksum::Crc32;

#[cfg(feature = "gzip")]
impl Checksum for Crc32 {
    #[inline]
    fn update(&mut self, data: &[u8]) {
        Crc32::update(self, data);
    }
}

#[cfg(feature = "zlib")]
impl Checksum for Adler32 {
    #[inline]
    fn update(&mut self, data: &[u8]) {
        Adler32::update(self, data);
    }
}
