//! Streaming XXH64, the hash zstd uses for the optional frame
//! `Content_Checksum`.
//!
//! A zstd frame whose `Content_Checksum_Flag` is set (the `zstd` CLI writes one
//! by default) appends the low 32 bits of `XXH64(decompressed_content, seed=0)`,
//! little-endian, after the last block. The decoder feeds every decompressed
//! byte through [`Xxh64::update`] and compares [`Xxh64::digest`] against that
//! trailer.
//!
//! This is the canonical XXH64 (Yann Collet) with seed 0; verified against the
//! reference test vectors below and, end-to-end, against checksums produced by
//! the `zstd` CLI.

const PRIME64_1: u64 = 0x9E37_79B1_85EB_CA87;
const PRIME64_2: u64 = 0xC2B2_AE3D_27D4_EB4F;
const PRIME64_3: u64 = 0x1656_67B1_9E37_79F9;
const PRIME64_4: u64 = 0x85EB_CA77_C2B2_AE63;
const PRIME64_5: u64 = 0x27D4_EB2F_1656_67C5;

/// Running XXH64 state (seed fixed at 0, which is all zstd needs).
#[derive(Clone)]
pub(crate) struct Xxh64 {
    /// Four parallel accumulators, used once `total_len >= 32`.
    acc: [u64; 4],
    /// Total bytes consumed across all `update` calls.
    total_len: u64,
    /// Partial stripe carried between `update` calls (`0..32` valid bytes).
    buf: [u8; 32],
    buf_len: usize,
}

impl Xxh64 {
    pub(crate) fn new() -> Self {
        Self {
            acc: [
                PRIME64_1.wrapping_add(PRIME64_2),
                PRIME64_2,
                0,
                0u64.wrapping_sub(PRIME64_1),
            ],
            total_len: 0,
            buf: [0u8; 32],
            buf_len: 0,
        }
    }

    #[inline]
    fn round(acc: u64, lane: u64) -> u64 {
        acc.wrapping_add(lane.wrapping_mul(PRIME64_2))
            .rotate_left(31)
            .wrapping_mul(PRIME64_1)
    }

    #[inline]
    fn merge_round(acc: u64, lane: u64) -> u64 {
        let acc = acc ^ Self::round(0, lane);
        acc.wrapping_mul(PRIME64_1).wrapping_add(PRIME64_4)
    }

    #[inline]
    fn read_u64(b: &[u8]) -> u64 {
        u64::from_le_bytes(b[..8].try_into().unwrap())
    }

    /// Consume one full 32-byte stripe into the four accumulators.
    #[inline]
    fn process_stripe(acc: &mut [u64; 4], stripe: &[u8]) {
        acc[0] = Self::round(acc[0], Self::read_u64(&stripe[0..8]));
        acc[1] = Self::round(acc[1], Self::read_u64(&stripe[8..16]));
        acc[2] = Self::round(acc[2], Self::read_u64(&stripe[16..24]));
        acc[3] = Self::round(acc[3], Self::read_u64(&stripe[24..32]));
    }

    /// Feed `data` into the running hash.
    pub(crate) fn update(&mut self, mut data: &[u8]) {
        self.total_len = self.total_len.wrapping_add(data.len() as u64);

        // Top off a partially filled stripe first.
        if self.buf_len > 0 {
            let need = 32 - self.buf_len;
            if data.len() < need {
                self.buf[self.buf_len..self.buf_len + data.len()].copy_from_slice(data);
                self.buf_len += data.len();
                return;
            }
            let (head, rest) = data.split_at(need);
            self.buf[self.buf_len..].copy_from_slice(head);
            let buf = self.buf;
            Self::process_stripe(&mut self.acc, &buf);
            self.buf_len = 0;
            data = rest;
        }

        // Bulk stripes straight from the input.
        let mut chunks = data.chunks_exact(32);
        for stripe in &mut chunks {
            Self::process_stripe(&mut self.acc, stripe);
        }

        // Carry the trailing partial stripe.
        let rem = chunks.remainder();
        if !rem.is_empty() {
            self.buf[..rem.len()].copy_from_slice(rem);
            self.buf_len = rem.len();
        }
    }

    /// Finalize without disturbing the running state, returning the full 64-bit
    /// digest. zstd compares the low 32 bits.
    pub(crate) fn digest(&self) -> u64 {
        let mut h = if self.total_len >= 32 {
            let mut h = self.acc[0]
                .rotate_left(1)
                .wrapping_add(self.acc[1].rotate_left(7))
                .wrapping_add(self.acc[2].rotate_left(12))
                .wrapping_add(self.acc[3].rotate_left(18));
            h = Self::merge_round(h, self.acc[0]);
            h = Self::merge_round(h, self.acc[1]);
            h = Self::merge_round(h, self.acc[2]);
            h = Self::merge_round(h, self.acc[3]);
            h
        } else {
            // Short input: only the seed-derived constant participates.
            PRIME64_5
        };

        h = h.wrapping_add(self.total_len);

        // Consume the leftover (< 32) bytes: 8 at a time, then 4, then 1.
        let mut p = &self.buf[..self.buf_len];
        while p.len() >= 8 {
            let k1 = Self::round(0, Self::read_u64(p));
            h = (h ^ k1)
                .rotate_left(27)
                .wrapping_mul(PRIME64_1)
                .wrapping_add(PRIME64_4);
            p = &p[8..];
        }
        if p.len() >= 4 {
            let k = u32::from_le_bytes(p[..4].try_into().unwrap()) as u64;
            h = (h ^ k.wrapping_mul(PRIME64_1))
                .rotate_left(23)
                .wrapping_mul(PRIME64_2)
                .wrapping_add(PRIME64_3);
            p = &p[4..];
        }
        for &b in p {
            h = (h ^ (b as u64).wrapping_mul(PRIME64_5))
                .rotate_left(11)
                .wrapping_mul(PRIME64_1);
        }

        // Final avalanche.
        h ^= h >> 33;
        h = h.wrapping_mul(PRIME64_2);
        h ^= h >> 29;
        h = h.wrapping_mul(PRIME64_3);
        h ^= h >> 32;
        h
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn xxh64(data: &[u8]) -> u64 {
        let mut h = Xxh64::new();
        h.update(data);
        h.digest()
    }

    #[test]
    fn reference_vectors() {
        // Canonical XXH64 vectors (seed 0) from the reference implementation.
        assert_eq!(xxh64(b""), 0xEF46_DB37_51D8_E999);
        assert_eq!(xxh64(b"a"), 0xD24E_C4F1_A98C_6E5B);
        assert_eq!(xxh64(b"abc"), 0x44BC_2CF5_AD77_0999);
        // 64 bytes ⇒ exercises the multi-stripe accumulator path.
        let long: alloc::vec::Vec<u8> = (0..64u8).collect();
        assert_eq!(xxh64(&long), 0xF7C6_7301_DB67_13F0);
    }

    #[test]
    fn streaming_matches_one_shot() {
        let data: alloc::vec::Vec<u8> = (0..250u32).map(|i| (i.wrapping_mul(37)) as u8).collect();
        let one = xxh64(&data);
        // Feed in awkward chunk sizes that straddle stripe boundaries.
        for chunk in [1usize, 3, 7, 8, 16, 31, 32, 33] {
            let mut h = Xxh64::new();
            for part in data.chunks(chunk) {
                h.update(part);
            }
            assert_eq!(h.digest(), one, "chunk size {chunk}");
        }
    }
}
