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
#[cfg(any(feature = "gzip", feature = "rar3", test))]
#[derive(Debug, Clone, Copy)]
pub struct Crc32 {
    state: u32,
}

#[cfg(any(feature = "gzip", feature = "rar3", test))]
impl Crc32 {
    pub const fn new() -> Self {
        Self { state: 0xFFFF_FFFF }
    }

    pub fn update(&mut self, data: &[u8]) {
        let mut s = self.state;

        // Slice-by-8: consume eight bytes per iteration using eight
        // precomputed tables. This shortens the per-byte dependency chain
        // and branch/load count versus the byte-at-a-time loop while
        // producing identical CRCs.
        let mut chunks = data.chunks_exact(8);
        for c in &mut chunks {
            let lo = u32::from_le_bytes([c[0], c[1], c[2], c[3]]) ^ s;
            let hi = u32::from_le_bytes([c[4], c[5], c[6], c[7]]);
            s = CRC32_TABLE8[7][(lo & 0xFF) as usize]
                ^ CRC32_TABLE8[6][((lo >> 8) & 0xFF) as usize]
                ^ CRC32_TABLE8[5][((lo >> 16) & 0xFF) as usize]
                ^ CRC32_TABLE8[4][(lo >> 24) as usize]
                ^ CRC32_TABLE8[3][(hi & 0xFF) as usize]
                ^ CRC32_TABLE8[2][((hi >> 8) & 0xFF) as usize]
                ^ CRC32_TABLE8[1][((hi >> 16) & 0xFF) as usize]
                ^ CRC32_TABLE8[0][(hi >> 24) as usize];
        }

        // Tail: fewer than 8 bytes remain.
        for &b in chunks.remainder() {
            let idx = ((s ^ b as u32) & 0xFF) as usize;
            s = (s >> 8) ^ CRC32_TABLE8[0][idx];
        }
        self.state = s;
    }

    pub const fn finalize(&self) -> u32 {
        self.state ^ 0xFFFF_FFFF
    }

    /// Only the gzip codec re-arms a CRC mid-stream; rar3's filter
    /// recognition uses one-shot instances.
    #[cfg(any(feature = "gzip", test))]
    pub fn reset(&mut self) {
        *self = Self::new();
    }
}

#[cfg(any(feature = "gzip", feature = "rar3", test))]
impl Default for Crc32 {
    fn default() -> Self {
        Self::new()
    }
}

/// Slice-by-8 tables, built at compile time. `CRC32_TABLE8[0]` is the
/// standard 256-entry CRC-32 table; `CRC32_TABLE8[n]` for `n >= 1` advances
/// the CRC by an extra byte position, so eight bytes can be folded per
/// iteration. See Intel's "Slicing-by-8" technique.
#[cfg(any(feature = "gzip", feature = "rar3", test))]
const CRC32_TABLE8: [[u32; 256]; 8] = {
    let mut tables = [[0u32; 256]; 8];

    // Base table (slice 0): the standard reflected CRC-32 step.
    let mut i = 0usize;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
            k += 1;
        }
        tables[0][i] = c;
        i += 1;
    }

    // Each subsequent table folds in one more zero byte:
    // table[n][i] = (table[n-1][i] >> 8) ^ table[0][table[n-1][i] & 0xFF].
    let mut n = 1usize;
    while n < 8 {
        let mut j = 0usize;
        while j < 256 {
            let prev = tables[n - 1][j];
            tables[n][j] = (prev >> 8) ^ tables[0][(prev & 0xFF) as usize];
            j += 1;
        }
        n += 1;
    }

    tables
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
