//! Static lookup tables for Quantum position slots and variable-length
//! match codes.
//!
//! These mirror the tables in libmspack's `qtmd.c`. The generating
//! formula (also from `qtmd.c`):
//!
//! ```text
//! for (i = 0, offset = 0; i < 42; i++) {
//!     position_base[i] = offset;
//!     extra_bits[i]    = ((i < 2) ? 0 : (i - 2)) >> 1;
//!     offset += 1 << extra_bits[i];
//! }
//! for (i = 0, offset = 0; i < 26; i++) {
//!     length_base[i]  = offset;
//!     length_extra[i] = (i < 2 ? 0 : i - 2) >> 2;
//!     offset += 1 << length_extra[i];
//! }
//! length_base[26]  = 254;
//! length_extra[26] = 0;
//! ```

/// Base offset for each of the 42 Quantum position slots.
pub(crate) const POSITION_BASE: [u32; 42] = [
    0, 1, 2, 3, 4, 6, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512, 768, 1024, 1536,
    2048, 3072, 4096, 6144, 8192, 12288, 16384, 24576, 32768, 49152, 65536, 98304, 131072, 196608,
    262144, 393216, 524288, 786432, 1048576, 1572864,
];

/// Number of "extra bits" read from the bitstream to refine each position slot.
pub(crate) const EXTRA_BITS: [u8; 42] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13, 14, 14, 15, 15, 16, 16, 17, 17, 18, 18, 19, 19,
];

/// Base value for each of the 27 variable-length match-length codes (selector 6).
pub(crate) const LENGTH_BASE: [u8; 27] = [
    0, 1, 2, 3, 4, 5, 6, 8, 10, 12, 14, 18, 22, 26, 30, 38, 46, 54, 62, 78, 94, 110, 126, 158, 190,
    222, 254,
];

/// Number of "extra bits" read from the bitstream to refine each length code.
pub(crate) const LENGTH_EXTRA: [u8; 27] = [
    0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn position_base_matches_formula() {
        let mut offset: u32 = 0;
        for i in 0..42 {
            assert_eq!(POSITION_BASE[i], offset, "position_base[{i}]");
            let eb: u32 = if i < 2 { 0 } else { ((i as u32) - 2) >> 1 };
            assert_eq!(EXTRA_BITS[i] as u32, eb, "extra_bits[{i}]");
            offset += 1 << eb;
        }
    }

    #[test]
    fn length_base_matches_formula() {
        let mut offset: u32 = 0;
        for i in 0..26 {
            assert_eq!(LENGTH_BASE[i] as u32, offset, "length_base[{i}]");
            let le: u32 = if i < 2 { 0 } else { ((i as u32) - 2) >> 2 };
            assert_eq!(LENGTH_EXTRA[i] as u32, le, "length_extra[{i}]");
            offset += 1 << le;
        }
        // The 27th entry is a hand-tweaked sentinel for the longest match length.
        assert_eq!(LENGTH_BASE[26], 254);
        assert_eq!(LENGTH_EXTRA[26], 0);
    }
}
