//! xxHash-32 (Yann Collet) — the only hash the Lizard frame format uses.
//!
//! Used here to compute and verify the 1-byte header checksum embedded
//! in the frame descriptor (`(xxh32(descriptor, seed=0) >> 8) & 0xFF`),
//! and, through the incremental [`Xxh32`], the optional 4-byte content
//! checksum that closes a frame (xxh32 of the decoded content, seed 0).
//! The implementation is straightforward — no SIMD, no `unsafe` — and
//! matches the reference vectors at `seed=0` for inputs of any length
//! up to the bound checked in unit tests.

const P1: u32 = 0x9E37_79B1;
const P2: u32 = 0x85EB_CA77;
const P3: u32 = 0xC2B2_AE3D;
const P4: u32 = 0x27D4_EB2F;
const P5: u32 = 0x1656_67B1;

#[inline]
fn rotl(x: u32, r: u32) -> u32 {
    x.rotate_left(r)
}

#[inline]
fn round(acc: u32, lane: u32) -> u32 {
    rotl(acc.wrapping_add(lane.wrapping_mul(P2)), 13).wrapping_mul(P1)
}

/// Compute xxh32 of `data` with `seed`.
pub fn xxh32(data: &[u8], seed: u32) -> u32 {
    let len = data.len();
    let mut h: u32;
    let mut i = 0usize;

    if len >= 16 {
        let mut a = seed.wrapping_add(P1).wrapping_add(P2);
        let mut b = seed.wrapping_add(P2);
        let mut c = seed;
        let mut d = seed.wrapping_sub(P1);
        while i + 16 <= len {
            let l0 = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
            let l1 = u32::from_le_bytes([data[i + 4], data[i + 5], data[i + 6], data[i + 7]]);
            let l2 = u32::from_le_bytes([data[i + 8], data[i + 9], data[i + 10], data[i + 11]]);
            let l3 = u32::from_le_bytes([data[i + 12], data[i + 13], data[i + 14], data[i + 15]]);
            a = round(a, l0);
            b = round(b, l1);
            c = round(c, l2);
            d = round(d, l3);
            i += 16;
        }
        h = rotl(a, 1)
            .wrapping_add(rotl(b, 7))
            .wrapping_add(rotl(c, 12))
            .wrapping_add(rotl(d, 18));
    } else {
        h = seed.wrapping_add(P5);
    }

    h = h.wrapping_add(len as u32);

    while i + 4 <= len {
        let lane = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
        h = rotl(h.wrapping_add(lane.wrapping_mul(P3)), 17).wrapping_mul(P4);
        i += 4;
    }
    while i < len {
        h = rotl(h.wrapping_add((data[i] as u32).wrapping_mul(P5)), 11).wrapping_mul(P1);
        i += 1;
    }

    h ^= h >> 15;
    h = h.wrapping_mul(P2);
    h ^= h >> 13;
    h = h.wrapping_mul(P3);
    h ^= h >> 16;
    h
}

/// Incremental xxh32, for the frame's content checksum: the decoded
/// content arrives a block at a time and is never held in one piece.
/// Produces the same value as [`xxh32`] over the concatenated input.
#[derive(Clone)]
pub struct Xxh32 {
    seed: u32,
    acc: [u32; 4],
    /// Bytes not yet folded into `acc` (always fewer than 16 between calls).
    buf: [u8; 16],
    buf_len: usize,
    total_len: u64,
}

impl Xxh32 {
    pub fn new(seed: u32) -> Self {
        Self {
            seed,
            acc: [
                seed.wrapping_add(P1).wrapping_add(P2),
                seed.wrapping_add(P2),
                seed,
                seed.wrapping_sub(P1),
            ],
            buf: [0; 16],
            buf_len: 0,
            total_len: 0,
        }
    }

    fn stripe(&mut self, s: &[u8]) {
        for (lane, acc) in self.acc.iter_mut().enumerate() {
            let i = lane * 4;
            let word = u32::from_le_bytes([s[i], s[i + 1], s[i + 2], s[i + 3]]);
            *acc = round(*acc, word);
        }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.total_len = self.total_len.wrapping_add(data.len() as u64);
        if self.buf_len > 0 {
            let take = (16 - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len < 16 {
                return;
            }
            let buf = self.buf;
            self.stripe(&buf);
            self.buf_len = 0;
        }
        let (stripes, rest) = data.as_chunks::<16>();
        for s in stripes {
            self.stripe(s);
        }
        self.buf[..rest.len()].copy_from_slice(rest);
        self.buf_len = rest.len();
    }

    pub fn digest(&self) -> u32 {
        let mut h = if self.total_len >= 16 {
            rotl(self.acc[0], 1)
                .wrapping_add(rotl(self.acc[1], 7))
                .wrapping_add(rotl(self.acc[2], 12))
                .wrapping_add(rotl(self.acc[3], 18))
        } else {
            self.seed.wrapping_add(P5)
        };
        h = h.wrapping_add(self.total_len as u32);

        let (words, rest) = self.buf[..self.buf_len].as_chunks::<4>();
        for w in words {
            let lane = u32::from_le_bytes(*w);
            h = rotl(h.wrapping_add(lane.wrapping_mul(P3)), 17).wrapping_mul(P4);
        }
        for &b in rest {
            h = rotl(h.wrapping_add((b as u32).wrapping_mul(P5)), 11).wrapping_mul(P1);
        }

        h ^= h >> 15;
        h = h.wrapping_mul(P2);
        h ^= h >> 13;
        h = h.wrapping_mul(P3);
        h ^= h >> 16;
        h
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn streaming_matches_oneshot() {
        let data: alloc::vec::Vec<u8> = (0..1000u32).map(|i| (i * 7 + (i >> 3)) as u8).collect();
        for seed in [0u32, 1, 0x9E37_79B1] {
            // Every prefix length around the 16-byte stripe boundaries.
            for len in (0..70).chain([127, 128, 129, 999, 1000]) {
                let want = xxh32(&data[..len], seed);
                for chunk in [1usize, 3, 15, 16, 17, 33, 1000] {
                    let mut h = Xxh32::new(seed);
                    for piece in data[..len].chunks(chunk) {
                        h.update(piece);
                    }
                    assert_eq!(h.digest(), want, "len {len} chunk {chunk} seed {seed}");
                }
            }
        }
    }

    #[test]
    fn hello_seed0() {
        assert_eq!(xxh32(b"hello", 0), 0xFB00_77F9);
        assert_eq!(xxh32(b"hello world", 0), 0xCEBB_6622);
    }

    // Reference vectors from xxhash.h documentation and lizard's own
    // header-checksum table. The Lizard CLI at version 2.1.0 emits a
    // FLG=0x60 BD=0x10 descriptor with HC = 0x8E; verify our impl
    // matches that and the canonical empty/`abc` test vectors at
    // seed = 0.
    #[test]
    fn empty_seed0() {
        assert_eq!(xxh32(&[], 0), 0x02CC_5D05);
    }

    #[test]
    fn abc_seed0() {
        assert_eq!(xxh32(b"abc", 0), 0x32D1_53FF);
    }

    #[test]
    fn lizard_descriptor() {
        // Lizard frame: FLG=0x60 (version 01, block independence),
        // BD=0x10 (block_max code 1 = 128 KiB). The reference CLI
        // emits HC = 0x8E for this descriptor; equivalently
        // `(xxh32(&[0x60, 0x10], 0) >> 8) & 0xFF == 0x8E`.
        let h = xxh32(&[0x60, 0x10], 0);
        assert_eq!(((h >> 8) & 0xFF) as u8, 0x8E);
    }
}
