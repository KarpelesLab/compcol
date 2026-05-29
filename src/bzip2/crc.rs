#![allow(dead_code)] // reset() exposed for parity with crate::checksum::Crc32

//! CRC-32 used by bzip2's block and combined-stream checksums.
//!
//! Same polynomial as gzip's CRC-32 (0x04C11DB7) and same final XOR
//! step, but the bit ordering differs:
//!
//! - **Non-reflected** (input bytes feed MSB-first; the gzip variant
//!   reflects each input byte so it ends up consuming the LSB first).
//! - **Final XOR with 0xFFFFFFFF**: same as gzip — the running
//!   register is complemented at the end.
//!
//! Equivalent to the standard CRC-32/BZIP2 (sometimes also called the
//! "AAL5" CRC-32). The task's initial spec said "no final XOR"; the
//! reference bzip2 source (`BZ_FINALISE_CRC(c) c = ~(c)`) and observed
//! interop with system `bzip2 -c` make clear the final XOR IS applied.
//! We follow the reference.
//!
//! Reference: the bzip2 source ships a 256-entry `BZ2_crc32Table` that is
//! the standard CRC-32/MPEG-2 forward table — identical to what we build
//! here at runtime via the bit-by-bit definition.

/// Polynomial used by both gzip and bzip2 (the IEEE 802.3 polynomial,
/// also called the "Ethernet" polynomial). The two codecs disagree only
/// on bit ordering and the final XOR step.
const POLY: u32 = 0x04C1_1DB7;

// 256-entry table for forward (non-reflected) CRC-32 would be one
// option but for our use the bit-by-bit per-byte loop is already very
// fast (~32 ops per byte) and keeps the code shorter. No static state
// is needed.

/// Rolling CRC-32/MPEG-2 state.
#[derive(Clone, Copy)]
pub(crate) struct Crc32 {
    state: u32,
}

impl Crc32 {
    pub(crate) const fn new() -> Self {
        // CRC-32/MPEG-2 initial register value.
        Self { state: 0xFFFF_FFFF }
    }

    /// Feed a slice of bytes through the register.
    pub(crate) fn update(&mut self, bytes: &[u8]) {
        let mut s = self.state;
        for &b in bytes {
            // XOR the byte into the **high** byte of the register
            // (non-reflected), then process 8 bits MSB-first.
            s ^= (b as u32) << 24;
            for _ in 0..8 {
                let msb_set = s & 0x8000_0000 != 0;
                s <<= 1;
                if msb_set {
                    s ^= POLY;
                }
            }
        }
        self.state = s;
    }

    /// Final value after applying the standard final XOR with all-ones.
    pub(crate) fn value(&self) -> u32 {
        self.state ^ 0xFFFF_FFFF
    }

    pub(crate) fn reset(&mut self) {
        self.state = 0xFFFF_FFFF;
    }
}

/// One-shot helper for tests and small payloads.
#[cfg(test)]
pub(crate) fn crc32_mpeg2(bytes: &[u8]) -> u32 {
    let mut c = Crc32::new();
    c.update(bytes);
    c.value()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_is_zero_after_final_xor() {
        // Initial register is all-ones; after the final XOR with
        // 0xFFFFFFFF the empty-input value is 0.
        assert_eq!(crc32_mpeg2(b""), 0);
    }

    #[test]
    fn known_vectors() {
        // CRC-32/BZIP2 of "123456789" is 0xFC891918, per the standard
        // CRC catalogue. (Same poly as CRC-32/MPEG-2 but with final XOR.)
        assert_eq!(crc32_mpeg2(b"123456789"), 0xFC89_1918);
        // Cross-check against reference bzip2 output for "hello world".
        assert_eq!(crc32_mpeg2(b"hello world"), 0x44F7_1378);
    }
}
