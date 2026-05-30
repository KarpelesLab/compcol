//! xxHash-32 (Yann Collet) — the only hash the Lizard frame format uses.
//!
//! Used here to compute and verify the 1-byte header checksum embedded
//! in the frame descriptor (`(xxh32(descriptor, seed=0) >> 8) & 0xFF`).
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

#[cfg(test)]
mod tests {
    use super::*;

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
