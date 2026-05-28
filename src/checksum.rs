//! Adler-32 (RFC 1950 §9) and CRC-32 (RFC 1952 §8) running checksums.
//!
//! Each impl is gated to the feature that actually consumes it so that a
//! `zlib`-only or `gzip`-only build doesn't carry the other's table.

/// Adler-32 checksum, used in the zlib trailer.
#[cfg(any(feature = "zlib", test))]
#[derive(Debug, Clone, Copy)]
pub struct Adler32 {
    a: u32,
    b: u32,
}

#[cfg(any(feature = "zlib", test))]
impl Adler32 {
    /// Initial state defined by RFC 1950 §9 (a = 1, b = 0).
    pub const fn new() -> Self {
        Self { a: 1, b: 0 }
    }

    /// Update with a chunk of bytes. RFC 1950 specifies `mod 65521`; we run
    /// in `u32` and reduce after at most 5552 bytes so neither accumulator
    /// can overflow (5552 * 255 + 65520 < 2^32).
    pub fn update(&mut self, mut data: &[u8]) {
        const NMAX: usize = 5552;
        const MOD: u32 = 65521;
        while !data.is_empty() {
            let chunk_len = data.len().min(NMAX);
            let (chunk, rest) = data.split_at(chunk_len);
            for &byte in chunk {
                self.a = self.a.wrapping_add(byte as u32);
                self.b = self.b.wrapping_add(self.a);
            }
            self.a %= MOD;
            self.b %= MOD;
            data = rest;
        }
    }

    pub const fn finalize(&self) -> u32 {
        (self.b << 16) | self.a
    }

    pub fn reset(&mut self) {
        *self = Self::new();
    }
}

#[cfg(any(feature = "zlib", test))]
impl Default for Adler32 {
    fn default() -> Self {
        Self::new()
    }
}

// ─── CRC-32 ────────────────────────────────────────────────────────────────

/// IEEE / gzip CRC-32. Polynomial `0xEDB88320` (reflected), initial value
/// `0xFFFFFFFF`, final XOR `0xFFFFFFFF`.
#[cfg(any(feature = "gzip", test))]
#[derive(Debug, Clone, Copy)]
pub struct Crc32 {
    state: u32,
}

#[cfg(any(feature = "gzip", test))]
impl Crc32 {
    pub const fn new() -> Self {
        Self { state: 0xFFFF_FFFF }
    }

    pub fn update(&mut self, data: &[u8]) {
        let mut s = self.state;
        for &b in data {
            let idx = ((s ^ b as u32) & 0xFF) as usize;
            s = (s >> 8) ^ CRC32_TABLE[idx];
        }
        self.state = s;
    }

    pub const fn finalize(&self) -> u32 {
        self.state ^ 0xFFFF_FFFF
    }

    pub fn reset(&mut self) {
        *self = Self::new();
    }
}

#[cfg(any(feature = "gzip", test))]
impl Default for Crc32 {
    fn default() -> Self {
        Self::new()
    }
}

/// Build the standard 256-entry table at compile time.
#[cfg(any(feature = "gzip", test))]
const CRC32_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0u32;
    while i < 256 {
        let mut c = i;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
            k += 1;
        }
        table[i as usize] = c;
        i += 1;
    }
    table
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adler32_known_vectors() {
        // RFC 1950 examples: Adler-32("") = 1, Adler-32("a") = 0x00620062.
        let mut a = Adler32::new();
        a.update(b"");
        assert_eq!(a.finalize(), 1);

        let mut a = Adler32::new();
        a.update(b"a");
        assert_eq!(a.finalize(), 0x0062_0062);

        // "Wikipedia" → 0x11E60398 per Wikipedia's article.
        let mut a = Adler32::new();
        a.update(b"Wikipedia");
        assert_eq!(a.finalize(), 0x11E6_0398);
    }

    #[test]
    fn crc32_known_vectors() {
        // CRC-32("") = 0; CRC-32("123456789") = 0xCBF43926 (the classic check
        // value from the CRC catalogue).
        let mut c = Crc32::new();
        c.update(b"");
        assert_eq!(c.finalize(), 0);

        let mut c = Crc32::new();
        c.update(b"123456789");
        assert_eq!(c.finalize(), 0xCBF4_3926);
    }

    #[test]
    fn crc32_chunked_matches_oneshot() {
        let data: alloc::vec::Vec<u8> = (0..1024u32).map(|i| (i % 251) as u8).collect();
        let mut whole = Crc32::new();
        whole.update(&data);

        let mut chunked = Crc32::new();
        for chunk in data.chunks(7) {
            chunked.update(chunk);
        }
        assert_eq!(whole.finalize(), chunked.finalize());
    }
}
