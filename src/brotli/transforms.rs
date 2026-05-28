//! Brotli word transforms (RFC 7932 §8 / Appendix B).
//!
//! 121 transforms apply to each dictionary word producing the actual
//! byte string referenced from a `distance >= num_dist_codes` symbol.
//! Each transform is a `(prefix_id, kind, suffix_id)` triple. The
//! `prefix_id` / `suffix_id` indexes a 50-entry table of literal
//! prefix/suffix byte strings.

use alloc::vec::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum Tr {
    Identity,
    OmitLast1,
    OmitLast2,
    OmitLast3,
    OmitLast4,
    OmitLast5,
    OmitLast6,
    OmitLast7,
    OmitLast8,
    OmitLast9,
    UppercaseFirst,
    UppercaseAll,
    OmitFirst1,
    OmitFirst2,
    OmitFirst3,
    OmitFirst4,
    OmitFirst5,
    OmitFirst6,
    OmitFirst7,
    /// Reserved by the RFC but unused in the 121 transforms; included
    /// for symmetry.
    OmitFirst8,
    OmitFirst9,
    ShiftFirst,
    ShiftAll,
}

/// `(prefix_id, transform, suffix_id)` for each of the 121 transforms.
pub(crate) const TRANSFORMS: [(u8, Tr, u8); 121] = [
    (49, Tr::Identity, 49),
    (49, Tr::Identity, 0),
    (0, Tr::Identity, 0),
    (49, Tr::OmitFirst1, 49),
    (49, Tr::UppercaseFirst, 0),
    (49, Tr::Identity, 47),
    (0, Tr::Identity, 49),
    (4, Tr::Identity, 0),
    (49, Tr::Identity, 3),
    (49, Tr::UppercaseFirst, 49),
    (49, Tr::Identity, 6),
    (49, Tr::OmitFirst2, 49),
    (49, Tr::OmitLast1, 49),
    (1, Tr::Identity, 0),
    (49, Tr::Identity, 1),
    (0, Tr::UppercaseFirst, 0),
    (49, Tr::Identity, 7),
    (49, Tr::Identity, 9),
    (48, Tr::Identity, 0),
    (49, Tr::Identity, 8),
    (49, Tr::Identity, 5),
    (49, Tr::Identity, 10),
    (49, Tr::Identity, 11),
    (49, Tr::OmitLast3, 49),
    (49, Tr::Identity, 13),
    (49, Tr::Identity, 14),
    (49, Tr::OmitFirst3, 49),
    (49, Tr::OmitLast2, 49),
    (49, Tr::Identity, 15),
    (49, Tr::Identity, 16),
    (0, Tr::UppercaseFirst, 49),
    (49, Tr::Identity, 12),
    (5, Tr::Identity, 49),
    (0, Tr::Identity, 1),
    (49, Tr::OmitFirst4, 49),
    (49, Tr::Identity, 18),
    (49, Tr::Identity, 17),
    (49, Tr::Identity, 19),
    (49, Tr::Identity, 20),
    (49, Tr::OmitFirst5, 49),
    (49, Tr::OmitFirst6, 49),
    (47, Tr::Identity, 49),
    (49, Tr::OmitLast4, 49),
    (49, Tr::Identity, 22),
    (49, Tr::UppercaseAll, 49),
    (49, Tr::Identity, 23),
    (49, Tr::Identity, 24),
    (49, Tr::Identity, 25),
    (49, Tr::OmitLast7, 49),
    (49, Tr::OmitLast1, 26),
    (49, Tr::Identity, 27),
    (49, Tr::Identity, 28),
    (0, Tr::Identity, 12),
    (49, Tr::Identity, 29),
    (49, Tr::OmitFirst9, 49),
    (49, Tr::OmitFirst7, 49),
    (49, Tr::OmitLast6, 49),
    (49, Tr::Identity, 21),
    (49, Tr::UppercaseFirst, 1),
    (49, Tr::OmitLast8, 49),
    (49, Tr::Identity, 31),
    (49, Tr::Identity, 32),
    (47, Tr::Identity, 3),
    (49, Tr::OmitLast5, 49),
    (49, Tr::OmitLast9, 49),
    (0, Tr::UppercaseFirst, 1),
    (49, Tr::UppercaseFirst, 8),
    (5, Tr::Identity, 21),
    (49, Tr::UppercaseAll, 0),
    (49, Tr::UppercaseFirst, 10),
    (49, Tr::Identity, 30),
    (0, Tr::Identity, 5),
    (35, Tr::Identity, 49),
    (47, Tr::Identity, 2),
    (49, Tr::UppercaseFirst, 17),
    (49, Tr::Identity, 36),
    (49, Tr::Identity, 33),
    (5, Tr::Identity, 0),
    (49, Tr::UppercaseFirst, 21),
    (49, Tr::UppercaseFirst, 5),
    (49, Tr::Identity, 37),
    (0, Tr::Identity, 30),
    (49, Tr::Identity, 38),
    (0, Tr::UppercaseAll, 0),
    (49, Tr::Identity, 39),
    (0, Tr::UppercaseAll, 49),
    (49, Tr::Identity, 34),
    (49, Tr::UppercaseAll, 8),
    (49, Tr::UppercaseFirst, 12),
    (0, Tr::Identity, 21),
    (49, Tr::Identity, 40),
    (0, Tr::UppercaseFirst, 12),
    (49, Tr::Identity, 41),
    (49, Tr::Identity, 42),
    (49, Tr::UppercaseAll, 17),
    (49, Tr::Identity, 43),
    (0, Tr::UppercaseFirst, 5),
    (49, Tr::UppercaseAll, 10),
    (0, Tr::Identity, 34),
    (49, Tr::UppercaseFirst, 33),
    (49, Tr::Identity, 44),
    (49, Tr::UppercaseAll, 5),
    (45, Tr::Identity, 49),
    (0, Tr::Identity, 33),
    (49, Tr::UppercaseFirst, 30),
    (49, Tr::UppercaseAll, 30),
    (49, Tr::Identity, 46),
    (49, Tr::UppercaseAll, 1),
    (49, Tr::UppercaseFirst, 34),
    (0, Tr::UppercaseFirst, 33),
    (0, Tr::UppercaseAll, 30),
    (0, Tr::UppercaseAll, 1),
    (49, Tr::UppercaseAll, 33),
    (49, Tr::UppercaseAll, 21),
    (49, Tr::UppercaseAll, 12),
    (0, Tr::UppercaseAll, 5),
    (49, Tr::UppercaseAll, 34),
    (0, Tr::UppercaseAll, 12),
    (0, Tr::UppercaseFirst, 30),
    (0, Tr::UppercaseAll, 34),
    (0, Tr::UppercaseFirst, 34),
];

/// The 50 prefix/suffix byte strings indexed by `prefix_id` / `suffix_id`.
/// Entry 45 contains the UTF-8 non-breaking space (`\xc2\xa0`).
#[rustfmt::skip]
pub(crate) const PREFIX_SUFFIX: [&[u8]; 50] = [
    /*  0 */ b" ",
    /*  1 */ b", ",
    /*  2 */ b" of the ",
    /*  3 */ b" of ",
    /*  4 */ b"s ",
    /*  5 */ b".",
    /*  6 */ b" and ",
    /*  7 */ b" in ",
    /*  8 */ b"\"",
    /*  9 */ b" to ",
    /* 10 */ b"\">",
    /* 11 */ b"\n",
    /* 12 */ b". ",
    /* 13 */ b"]",
    /* 14 */ b" for ",
    /* 15 */ b" a ",
    /* 16 */ b" that ",
    /* 17 */ b"'",
    /* 18 */ b" with ",
    /* 19 */ b" from ",
    /* 20 */ b" by ",
    /* 21 */ b"(",
    /* 22 */ b". The ",
    /* 23 */ b" on ",
    /* 24 */ b" as ",
    /* 25 */ b" is ",
    /* 26 */ b"ing ",
    /* 27 */ b"\n\t",
    /* 28 */ b":",
    /* 29 */ b"ed ",
    /* 30 */ b"=\"",
    /* 31 */ b" at ",
    /* 32 */ b"ly ",
    /* 33 */ b",",
    /* 34 */ b"='",
    /* 35 */ b".com/",
    /* 36 */ b". This ",
    /* 37 */ b" not ",
    /* 38 */ b"er ",
    /* 39 */ b"al ",
    /* 40 */ b"ful ",
    /* 41 */ b"ive ",
    /* 42 */ b"less ",
    /* 43 */ b"est ",
    /* 44 */ b"ize ",
    /* 45 */ b"\xc2\xa0",
    /* 46 */ b"ous ",
    /* 47 */ b" the ",
    /* 48 */ b"e ",
    /* 49 */ b"",
];

/// Apply the simplified UTF-8 uppercase model from §8.1 at `dst[off..]`,
/// returning how many bytes were consumed (1..=3).
fn to_uppercase(dst: &mut [u8], off: usize) -> usize {
    let b0 = dst[off];
    if b0 < 0xC0 {
        if b0.is_ascii_lowercase() {
            dst[off] = b0 ^ 32;
        }
        return 1;
    }
    if b0 < 0xE0 {
        if off + 1 < dst.len() {
            dst[off + 1] ^= 32;
        }
        return 2;
    }
    // 3-byte rune: flip bit 5 of the third byte.
    if off + 2 < dst.len() {
        dst[off + 2] ^= 5;
    }
    3
}

/// Apply transform `idx` to `word` (length `len`), appending the
/// resulting bytes to `dst`. Returns the number of bytes written.
///
/// Following the reference C implementation but in safe Rust.
pub(crate) fn apply_transform(dst: &mut Vec<u8>, word: &[u8], idx: usize) -> usize {
    let (pre_id, kind, suf_id) = TRANSFORMS[idx];
    let prefix = PREFIX_SUFFIX[pre_id as usize];
    let suffix = PREFIX_SUFFIX[suf_id as usize];

    let start = dst.len();
    dst.extend_from_slice(prefix);

    let body_start = dst.len();
    // Apply OMIT_FIRST_n / OMIT_LAST_n to bounds. ShiftFirst/ShiftAll
    // are not used in RFC 7932 (only large-window mode), so we treat
    // them as identity if they appear.
    let mut word = word;
    let mut len = word.len();
    match kind {
        Tr::OmitLast1 => {
            len = len.saturating_sub(1);
        }
        Tr::OmitLast2 => {
            len = len.saturating_sub(2);
        }
        Tr::OmitLast3 => {
            len = len.saturating_sub(3);
        }
        Tr::OmitLast4 => {
            len = len.saturating_sub(4);
        }
        Tr::OmitLast5 => {
            len = len.saturating_sub(5);
        }
        Tr::OmitLast6 => {
            len = len.saturating_sub(6);
        }
        Tr::OmitLast7 => {
            len = len.saturating_sub(7);
        }
        Tr::OmitLast8 => {
            len = len.saturating_sub(8);
        }
        Tr::OmitLast9 => {
            len = len.saturating_sub(9);
        }
        Tr::OmitFirst1 => {
            let s = 1.min(len);
            word = &word[s..];
            len -= s;
        }
        Tr::OmitFirst2 => {
            let s = 2.min(len);
            word = &word[s..];
            len -= s;
        }
        Tr::OmitFirst3 => {
            let s = 3.min(len);
            word = &word[s..];
            len -= s;
        }
        Tr::OmitFirst4 => {
            let s = 4.min(len);
            word = &word[s..];
            len -= s;
        }
        Tr::OmitFirst5 => {
            let s = 5.min(len);
            word = &word[s..];
            len -= s;
        }
        Tr::OmitFirst6 => {
            let s = 6.min(len);
            word = &word[s..];
            len -= s;
        }
        Tr::OmitFirst7 => {
            let s = 7.min(len);
            word = &word[s..];
            len -= s;
        }
        Tr::OmitFirst8 => {
            let s = 8.min(len);
            word = &word[s..];
            len -= s;
        }
        Tr::OmitFirst9 => {
            let s = 9.min(len);
            word = &word[s..];
            len -= s;
        }
        _ => {}
    }
    dst.extend_from_slice(&word[..len]);

    match kind {
        Tr::UppercaseFirst if len > 0 => {
            to_uppercase(&mut dst[body_start..], 0);
        }
        Tr::UppercaseAll => {
            let mut i = 0;
            let body_len = dst.len() - body_start;
            while i < body_len {
                let step = to_uppercase(&mut dst[body_start..], i);
                i += step;
            }
        }
        _ => {}
    }

    dst.extend_from_slice(suffix);
    dst.len() - start
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_transform_zero_prefix_zero_suffix() {
        // Transform 2 = (0, Identity, 0): prefix " ", suffix " "
        let word = b"hello";
        let mut dst = Vec::new();
        let n = apply_transform(&mut dst, word, 2);
        assert_eq!(n, dst.len());
        assert_eq!(dst, b" hello ");
    }

    #[test]
    fn uppercase_first_transform() {
        // Transform 4 = (49, UppercaseFirst, 0): empty prefix, " " suffix
        let word = b"hello";
        let mut dst = Vec::new();
        apply_transform(&mut dst, word, 4);
        assert_eq!(dst, b"Hello ");
    }

    #[test]
    fn omit_first_transform() {
        // Transform 3 = (49, OmitFirst1, 49): drops first byte, no fix-ups.
        let word = b"thello";
        let mut dst = Vec::new();
        apply_transform(&mut dst, word, 3);
        assert_eq!(dst, b"hello");
    }

    #[test]
    fn omit_last_transform() {
        // Transform 12 = (49, OmitLast1, 49)
        let word = b"hello!";
        let mut dst = Vec::new();
        apply_transform(&mut dst, word, 12);
        assert_eq!(dst, b"hello");
    }
}
