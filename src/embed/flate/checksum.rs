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

// The running values start out as the algorithms define them, rather than
// all zeros as `embed`'s own codecs keep them: next to the `u64` fields of a
// `Decompressor`, zeros would have its initialisation done by `memclr8`, one
// more routine of `compiler_builtins` to link.

/// CRC-32 (IEEE, reflected), a nibble at a time, with `embed`'s table.
#[cfg(feature = "gzip")]
pub(crate) struct Crc32(u32);

#[cfg(feature = "gzip")]
impl Crc32 {
    pub(crate) fn new() -> Self {
        Crc32(!0)
    }

    pub(crate) fn value(&self) -> u32 {
        !self.0
    }
}

#[cfg(feature = "gzip")]
impl Checksum for Crc32 {
    fn update(&mut self, data: &[u8]) {
        let table = &super::super::checksum::TABLE;
        let mut c = self.0;
        for &b in data {
            c ^= b as u32;
            c = table[(c & 0xf) as usize] ^ (c >> 4);
            c = table[(c & 0xf) as usize] ^ (c >> 4);
        }
        self.0 = c;
    }
}

/// Adler-32 (RFC 1950).
#[cfg(feature = "zlib")]
pub(crate) struct Adler32 {
    a: u32,
    b: u32,
}

#[cfg(feature = "zlib")]
impl Adler32 {
    pub(crate) fn new() -> Self {
        Adler32 { a: 1, b: 0 }
    }

    pub(crate) fn value(&self) -> u32 {
        self.b << 16 | self.a
    }
}

#[cfg(feature = "zlib")]
impl Checksum for Adler32 {
    fn update(&mut self, data: &[u8]) {
        // 5552 is the most bytes that can be summed before `b` overflows.
        for chunk in data.chunks(5552) {
            for &x in chunk {
                self.a += x as u32;
                self.b += self.a;
            }
            self.a %= 65521;
            self.b %= 65521;
        }
    }
}
