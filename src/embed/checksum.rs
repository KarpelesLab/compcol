//! Running checksums for the `embed` deflate family, sized for code rather
//! than speed: a 64-byte CRC-32 table where `crate::checksum` keeps 8 KiB.
//!
//! Both start from an all-zero state, so that a codec holding one can be
//! built in a `static` that lands in `.bss`: the CRC is stored complemented
//! and the Adler-32 `a` one less than it is, at no per-byte cost.

#[cfg(feature = "gzip")]
const POLY: u32 = 0xedb8_8320;

#[cfg(feature = "gzip")]
const fn table() -> [u32; 16] {
    let mut table = [0; 16];
    let mut i = 0;
    while i < 16 {
        let mut c = i as u32;
        let mut bit = 0;
        while bit < 4 {
            c = if c & 1 != 0 { POLY ^ (c >> 1) } else { c >> 1 };
            bit += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
}

#[cfg(feature = "gzip")]
static TABLE: [u32; 16] = table();

/// CRC-32 (IEEE, reflected), a nibble at a time.
#[cfg(feature = "gzip")]
pub(crate) struct Crc32(u32);

#[cfg(feature = "gzip")]
impl Crc32 {
    pub(crate) const fn new() -> Self {
        Crc32(0)
    }

    pub(crate) fn value(&self) -> u32 {
        self.0
    }

    pub(crate) fn update(&mut self, data: &[u8]) {
        let mut c = !self.0;
        for &b in data {
            c ^= b as u32;
            c = TABLE[(c & 0xf) as usize] ^ (c >> 4);
            c = TABLE[(c & 0xf) as usize] ^ (c >> 4);
        }
        self.0 = !c;
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
    pub(crate) const fn new() -> Self {
        Adler32 { a: 0, b: 0 }
    }

    pub(crate) fn value(&self) -> u32 {
        self.b << 16 | self.a.wrapping_add(1)
    }

    pub(crate) fn update(&mut self, data: &[u8]) {
        let mut a = self.a.wrapping_add(1);
        let mut b = self.b;
        // 5552 is the most bytes that can be summed before `b` overflows.
        for chunk in data.chunks(5552) {
            for &x in chunk {
                a += x as u32;
                b += a;
            }
            a %= 65521;
            b %= 65521;
        }
        self.a = a.wrapping_sub(1);
        self.b = b;
    }
}
