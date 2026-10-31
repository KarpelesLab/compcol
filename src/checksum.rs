//! Adler-32 (RFC 1950 §9) and CRC-32 (RFC 1952 §8) running checksums.
//!
//! These back the zlib and gzip trailers and rar3's filter recognition. They
//! are public API only when the `checksum` feature is on; otherwise the module
//! stays crate-private and is compiled just for the codecs that need it.
//!
//! The codecs in this crate decode *data streams*, not container framing, so a
//! caller that parses the container itself (a ZIP local header, a PNG `IDAT`
//! chunk, a RAR file header) has to verify those checksum fields on its own.
//! That is what this module is for — no need to pull in a second crate, or to
//! enable `gzip` just to reach a CRC-32.
//!
//! Each impl is additionally gated to the feature that consumes it, so a
//! `zlib`-only or `gzip`-only build doesn't carry the other's table.
//!
//! ```
//! # #[cfg(feature = "checksum")] {
//! use compcol::checksum::Crc32;
//!
//! let mut crc = Crc32::new();
//! crc.update(b"123456789");
//! assert_eq!(crc.finalize(), 0xCBF4_3926); // the CRC catalogue check value
//!
//! // Streaming in pieces gives the same answer as one shot.
//! let mut split = Crc32::new();
//! split.update(b"12345");
//! split.update(b"6789");
//! assert_eq!(split.finalize(), 0xCBF4_3926);
//! # }
//! ```

/// Adler-32 checksum, used in the zlib trailer.
#[cfg(any(
    all(feature = "zlib", not(feature = "embed")),
    feature = "checksum",
    test
))]
#[derive(Debug, Clone, Copy)]
pub struct Adler32 {
    a: u32,
    b: u32,
}

#[cfg(any(
    all(feature = "zlib", not(feature = "embed")),
    feature = "checksum",
    test
))]
impl Adler32 {
    /// Initial state defined by RFC 1950 §9 (a = 1, b = 0).
    pub const fn new() -> Self {
        Self { a: 1, b: 0 }
    }

    /// Update with a chunk of bytes. RFC 1950 specifies `mod 65521`; we
    /// reduce after at most 5552 bytes (zlib's `NMAX`) so no accumulator can
    /// overflow.
    pub fn update(&mut self, data: &[u8]) {
        // 5552 = 347 * 16: every chunk but the last is whole 16-byte blocks.
        const NMAX: usize = 5552;
        const MOD: u32 = 65521;
        const W: usize = 16;
        let (mut a, mut b) = (self.a, self.b);
        for chunk in data.chunks(NMAX) {
            let (blocks, tail) = chunk.as_chunks::<W>();
            if !blocks.is_empty() {
                // Sixteen independent lanes (vectorisable): `sums[j]` adds
                // up byte `j` of every block, and `acc[j]` adds up the
                // `sums[j]` seen before each block. Over `k` blocks, byte
                // `j` of block `i` then weighs `16 * (k - 1 - i)` in
                // `16 * acc` and `16 - j` in the final fold below — together
                // the `n - pos` weight it has in `b` over these `n` bytes.
                let mut sums = [0u32; W];
                let mut acc = [0u32; W];
                for block in blocks {
                    for j in 0..W {
                        acc[j] += sums[j];
                        sums[j] += u32::from(block[j]);
                    }
                }
                let n = (blocks.len() * W) as u64;
                let mut sa = 0u64;
                let mut sb = 0u64;
                for j in 0..W {
                    sa += u64::from(sums[j]);
                    sb += W as u64 * u64::from(acc[j]) + (W - j) as u64 * u64::from(sums[j]);
                }
                b = ((u64::from(b) + n * u64::from(a) + sb) % u64::from(MOD)) as u32;
                a = ((u64::from(a) + sa) % u64::from(MOD)) as u32;
            }
            for &byte in tail {
                a += u32::from(byte);
                b += a;
            }
            a %= MOD;
            b %= MOD;
        }
        self.a = a;
        self.b = b;
    }

    /// The checksum of everything fed so far, as `b << 16 | a`.
    pub const fn finalize(&self) -> u32 {
        (self.b << 16) | self.a
    }

    /// Re-arm for a fresh stream.
    // Only the standard deflate-family codecs reset a checksum in place.
    #[cfg_attr(not(feature = "checksum"), allow(dead_code))]
    pub fn reset(&mut self) {
        *self = Self::new();
    }
}

#[cfg(any(
    all(feature = "zlib", not(feature = "embed")),
    feature = "checksum",
    test
))]
impl Default for Adler32 {
    fn default() -> Self {
        Self::new()
    }
}

// ─── CRC-32 ────────────────────────────────────────────────────────────────

/// IEEE / gzip CRC-32. Polynomial `0xEDB88320` (reflected), initial value
/// `0xFFFFFFFF`, final XOR `0xFFFFFFFF`.
#[cfg(any(
    all(feature = "gzip", not(feature = "embed")),
    feature = "rar3",
    feature = "checksum",
    test
))]
#[derive(Debug, Clone, Copy)]
pub struct Crc32 {
    state: u32,
}

#[cfg(any(
    all(feature = "gzip", not(feature = "embed")),
    feature = "rar3",
    feature = "checksum",
    test
))]
impl Crc32 {
    /// A fresh checksum over the empty input.
    pub const fn new() -> Self {
        Self { state: 0xFFFF_FFFF }
    }

    /// Fold `data` into the running checksum. Splitting the input across
    /// calls yields the same result as one call over the concatenation.
    pub fn update(&mut self, data: &[u8]) {
        let mut s = self.state;
        let t = &CRC32_TABLES;

        // Slice-by-16: consume sixteen bytes per iteration using sixteen
        // precomputed tables. The sixteen lookups are independent, so the
        // per-byte dependency chain is much shorter than byte-at-a-time
        // while producing identical CRCs.
        let (chunks, remainder) = data.as_chunks::<16>();
        for c in chunks {
            let w0 = u32::from_le_bytes([c[0], c[1], c[2], c[3]]) ^ s;
            let w1 = u32::from_le_bytes([c[4], c[5], c[6], c[7]]);
            let w2 = u32::from_le_bytes([c[8], c[9], c[10], c[11]]);
            let w3 = u32::from_le_bytes([c[12], c[13], c[14], c[15]]);
            let x = |w: u32, k: usize| {
                t[k + 3][(w & 0xFF) as usize]
                    ^ t[k + 2][((w >> 8) & 0xFF) as usize]
                    ^ t[k + 1][((w >> 16) & 0xFF) as usize]
                    ^ t[k][(w >> 24) as usize]
            };
            s = x(w0, 12) ^ x(w1, 8) ^ x(w2, 4) ^ x(w3, 0);
        }

        // Tail: fewer than 16 bytes remain.
        for &b in remainder {
            let idx = ((s ^ b as u32) & 0xFF) as usize;
            s = (s >> 8) ^ t[0][idx];
        }
        self.state = s;
    }

    /// The checksum of everything fed so far. Non-consuming: the value can be
    /// read mid-stream and `update` may continue afterwards.
    pub const fn finalize(&self) -> u32 {
        self.state ^ 0xFFFF_FFFF
    }

    /// Re-arm for a fresh stream. Within the crate only the gzip codec does
    /// this mid-stream (rar3's filter recognition uses one-shot instances),
    /// but it is part of the public surface so a caller can reuse one
    /// instance across many members.
    #[cfg(any(
        all(feature = "gzip", not(feature = "embed")),
        feature = "checksum",
        test
    ))]
    // Only the standard deflate-family codecs reset a checksum in place.
    #[cfg_attr(not(feature = "checksum"), allow(dead_code))]
    pub fn reset(&mut self) {
        *self = Self::new();
    }
}

#[cfg(any(
    all(feature = "gzip", not(feature = "embed")),
    feature = "rar3",
    feature = "checksum",
    test
))]
impl Default for Crc32 {
    fn default() -> Self {
        Self::new()
    }
}

/// Slice-by-16 tables, built at compile time. `CRC32_TABLES[0]` is the
/// standard 256-entry CRC-32 table; `CRC32_TABLES[n]` for `n >= 1` advances
/// the CRC by an extra byte position, so sixteen bytes can be folded per
/// iteration. See Intel's "Slicing-by-8" technique, here doubled.
#[cfg(any(
    all(feature = "gzip", not(feature = "embed")),
    feature = "rar3",
    feature = "checksum",
    test
))]
static CRC32_TABLES: [[u32; 256]; 16] = {
    let mut tables = [[0u32; 256]; 16];

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
    while n < 16 {
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

    /// Pseudo-random bytes, with long runs of 0xFF to stress the Adler-32
    /// accumulators' overflow bounds.
    fn test_bytes(n: usize) -> alloc::vec::Vec<u8> {
        let mut s: u32 = 0x1234_5678;
        (0..n)
            .map(|i| {
                s = s.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                if (i / 7000) % 2 == 1 {
                    0xFF
                } else {
                    (s >> 24) as u8
                }
            })
            .collect()
    }

    #[test]
    fn adler32_matches_bytewise_reference() {
        let data = test_bytes(40_000);
        for &len in &[0usize, 1, 15, 16, 17, 5551, 5552, 5553, 11_104, 40_000] {
            let (mut a, mut b) = (1u32, 0u32);
            for &x in &data[..len] {
                a = (a + u32::from(x)) % 65521;
                b = (b + a) % 65521;
            }
            let mut fast = Adler32::new();
            fast.update(&data[..len]);
            assert_eq!(fast.finalize(), (b << 16) | a, "len {len}");
            // Same in odd-sized pieces.
            let mut split = Adler32::new();
            for piece in data[..len].chunks(4097) {
                split.update(piece);
            }
            assert_eq!(split.finalize(), (b << 16) | a, "split len {len}");
        }
    }

    #[test]
    fn crc32_matches_bitwise_reference() {
        let data = test_bytes(1000);
        for len in [0usize, 1, 7, 15, 16, 17, 31, 32, 33, 1000] {
            let mut r = 0xFFFF_FFFFu32;
            for &x in &data[..len] {
                r ^= u32::from(x);
                for _ in 0..8 {
                    r = if r & 1 != 0 {
                        0xEDB8_8320 ^ (r >> 1)
                    } else {
                        r >> 1
                    };
                }
            }
            let mut c = Crc32::new();
            c.update(&data[..len]);
            assert_eq!(c.finalize(), !r, "len {len}");
        }
    }
}
