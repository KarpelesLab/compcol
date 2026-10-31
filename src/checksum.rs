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

    /// Update with a chunk of bytes.
    pub fn update(&mut self, data: &[u8]) {
        const MOD: u32 = 65521;
        // Bytes per block between reductions: whole 32-byte chunks, few
        // enough that the per-lane sums below cannot overflow a `u32`
        // (255 · k(k+1)/2 < 2^32 for k = 4096 chunks).
        const BLOCK: usize = 32 * 4096;
        let mut a = self.a;
        let mut b = self.b;
        for block in data.chunks(BLOCK) {
            let (chunks, tail) = block.as_chunks::<32>();
            if !chunks.is_empty() {
                // Lane `i` sees bytes `32c + i` of the block: `s[i]` sums
                // them and `t[i]` sums `s[i]` after each chunk, i.e. weighs
                // the byte of chunk `c` by `k - c`. The 32 independent lanes
                // vectorise; their totals are folded back into `a` and `b`
                // below.
                let mut s = [0u32; 32];
                let mut t = [0u32; 32];
                for c in chunks {
                    for i in 0..32 {
                        s[i] += c[i] as u32;
                        t[i] += s[i];
                    }
                }
                // A byte at offset `32c + i` of an `n = 32k`-byte run adds
                // `n - (32c + i) = 32(k - c) - i` times its value to `b`.
                let n = (chunks.len() * 32) as u64;
                let mut sum_s = 0u64;
                let mut sum_t = 0u64;
                let mut weighted = 0u64;
                for i in 0..32 {
                    sum_s += s[i] as u64;
                    sum_t += t[i] as u64;
                    weighted += i as u64 * s[i] as u64;
                }
                let bb = b as u64 + n * a as u64 + 32 * sum_t - weighted;
                a = ((a as u64 + sum_s) % MOD as u64) as u32;
                b = (bb % MOD as u64) as u32;
            }
            // Under 32 bytes left: one at a time (no overflow possible).
            for &byte in tail {
                a += byte as u32;
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
        let mut data = data;

        // Long inputs: four independent slice-by-8 chains over four
        // consecutive `LANE`-byte stretches, so the table loads of one
        // chain overlap the others' instead of waiting on a single
        // dependency chain. CRC-32 is linear, so the stretches' CRCs (all
        // but the first started from a zero register) join up by advancing
        // a register over `LANE` zero bytes — a multiplication by the
        // constant `x^(8·LANE)` mod P — and XORing in the next one.
        while data.len() >= 4 * LANE {
            let (block, rest) = data.split_at(4 * LANE);
            let (l0, l1) = block.split_at(LANE);
            let (l1, l2) = l1.split_at(LANE);
            let (l2, l3) = l2.split_at(LANE);
            let (c0, _) = l0.as_chunks::<8>();
            let (c1, _) = l1.as_chunks::<8>();
            let (c2, _) = l2.as_chunks::<8>();
            let (c3, _) = l3.as_chunks::<8>();
            let (mut s0, mut s1, mut s2, mut s3) = (s, 0, 0, 0);
            for (((a, b), c), d) in c0.iter().zip(c1).zip(c2).zip(c3) {
                s0 = crc32_step8(s0, a);
                s1 = crc32_step8(s1, b);
                s2 = crc32_step8(s2, c);
                s3 = crc32_step8(s3, d);
            }
            s = multmodp(X_POW_LANE, s0) ^ s1;
            s = multmodp(X_POW_LANE, s) ^ s2;
            s = multmodp(X_POW_LANE, s) ^ s3;
            data = rest;
        }

        let (chunks, remainder) = data.as_chunks::<8>();
        for c in chunks {
            s = crc32_step8(s, c);
        }
        // Tail: fewer than 8 bytes remain.
        for &b in remainder {
            let idx = ((s ^ b as u32) & 0xFF) as usize;
            s = (s >> 8) ^ CRC32_TABLE8[0][idx];
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

/// Slice-by-8 tables, built at compile time. `CRC32_TABLE8[0]` is the
/// standard 256-entry CRC-32 table; `CRC32_TABLE8[n]` for `n >= 1` advances
/// the CRC by an extra byte position, so eight bytes can be folded per
/// iteration. See Intel's "Slicing-by-8" technique.
#[cfg(any(
    all(feature = "gzip", not(feature = "embed")),
    feature = "rar3",
    feature = "checksum",
    test
))]
static CRC32_TABLE8: [[u32; 256]; 8] = {
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

/// Fold eight bytes into the CRC register `s` (slice-by-8).
#[cfg(any(
    all(feature = "gzip", not(feature = "embed")),
    feature = "rar3",
    feature = "checksum",
    test
))]
#[inline(always)]
fn crc32_step8(s: u32, c: &[u8; 8]) -> u32 {
    let t = &CRC32_TABLE8;
    let lo = u32::from_le_bytes([c[0], c[1], c[2], c[3]]) ^ s;
    let hi = u32::from_le_bytes([c[4], c[5], c[6], c[7]]);
    t[7][(lo & 0xFF) as usize]
        ^ t[6][((lo >> 8) & 0xFF) as usize]
        ^ t[5][((lo >> 16) & 0xFF) as usize]
        ^ t[4][(lo >> 24) as usize]
        ^ t[3][(hi & 0xFF) as usize]
        ^ t[2][((hi >> 8) & 0xFF) as usize]
        ^ t[1][((hi >> 16) & 0xFF) as usize]
        ^ t[0][(hi >> 24) as usize]
}

/// The reflected CRC-32 polynomial.
#[cfg(any(
    all(feature = "gzip", not(feature = "embed")),
    feature = "rar3",
    feature = "checksum",
    test
))]
const CRC32_POLY: u32 = 0xEDB8_8320;

/// Bytes per stretch of [`Crc32::update`]'s four-way loop (a multiple of 8).
#[cfg(any(
    all(feature = "gzip", not(feature = "embed")),
    feature = "rar3",
    feature = "checksum",
    test
))]
const LANE: usize = 2048;

/// `x^(8·LANE)` mod P in the reflected representation (`x^0` is bit 31):
/// multiplying a CRC register by it advances the register over `LANE` zero
/// bytes.
#[cfg(any(
    all(feature = "gzip", not(feature = "embed")),
    feature = "rar3",
    feature = "checksum",
    test
))]
const X_POW_LANE: u32 = {
    let mut p = 1u32 << 31;
    let mut i = 0;
    while i < 8 * LANE {
        p = if p & 1 != 0 {
            (p >> 1) ^ CRC32_POLY
        } else {
            p >> 1
        };
        i += 1;
    }
    p
};

/// `a · b` mod P, both in the reflected representation.
#[cfg(any(
    all(feature = "gzip", not(feature = "embed")),
    feature = "rar3",
    feature = "checksum",
    test
))]
fn multmodp(a: u32, mut b: u32) -> u32 {
    let mut p = 0u32;
    let mut m = 1u32 << 31;
    while m != 0 {
        if a & m != 0 {
            p ^= b;
        }
        b = if b & 1 != 0 {
            (b >> 1) ^ CRC32_POLY
        } else {
            b >> 1
        };
        m >>= 1;
    }
    p
}

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
    /// Bit-at-a-time CRC-32 and byte-at-a-time Adler-32, straight from the
    /// RFCs, to check the fast paths against.
    fn crc32_ref(data: &[u8]) -> u32 {
        let mut c = 0xFFFF_FFFFu32;
        for &b in data {
            c ^= b as u32;
            for _ in 0..8 {
                c = if c & 1 != 0 {
                    (c >> 1) ^ 0xEDB8_8320
                } else {
                    c >> 1
                };
            }
        }
        !c
    }

    fn adler32_ref(data: &[u8]) -> u32 {
        let (mut a, mut b) = (1u32, 0u32);
        for &x in data {
            a = (a + x as u32) % 65521;
            b = (b + a) % 65521;
        }
        b << 16 | a
    }

    #[test]
    fn fast_paths_match_reference() {
        let mut x = 0x1234_5678u32;
        let data: alloc::vec::Vec<u8> = (0..300_000)
            .map(|i| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                // A run of 0xFF over a whole block pushes the Adler lane sums
                // to their maximum.
                if i < 150_000 { 0xFF } else { x as u8 }
            })
            .collect();
        let lens = [
            0, 1, 7, 8, 15, 31, 32, 33, 4095, 8191, 8192, 8193, 5552, 65536, 131_072, 140_000,
            300_000,
        ];
        for &n in &lens {
            let d = &data[..n];
            let mut c = Crc32::new();
            c.update(d);
            assert_eq!(c.finalize(), crc32_ref(d), "crc32 len {n}");
            let mut a = Adler32::new();
            a.update(d);
            assert_eq!(a.finalize(), adler32_ref(d), "adler32 len {n}");
        }
        // Uneven splits give the same result as one call.
        for step in [1usize, 3, 1000, 8191, 70_001] {
            let mut c = Crc32::new();
            let mut a = Adler32::new();
            for piece in data.chunks(step) {
                c.update(piece);
                a.update(piece);
            }
            assert_eq!(c.finalize(), crc32_ref(&data), "crc32 step {step}");
            assert_eq!(a.finalize(), adler32_ref(&data), "adler32 step {step}");
        }
    }
}
