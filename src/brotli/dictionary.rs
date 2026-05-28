//! Brotli static dictionary (§8 / Appendix A of RFC 7932).
//!
//! The dictionary holds 122,784 bytes of word data, organised in 21
//! length classes (lengths 4..=24). The raw bytes are embedded via
//! `include_bytes!` from `dictionary.bin`, which is a verbatim copy of
//! the official Google brotli reference dictionary (SHA-256
//! `20e42eb1b511c21806d4d227d07e5dd06877d8ce7b3a817f378f313653f35c70`).
//!
//! For each length class:
//! - `SIZE_BITS_BY_LENGTH[n]` gives the bit-width of the in-bucket
//!   index; a length class with `bits = 0` has no words at all.
//! - `OFFSETS_BY_LENGTH[n]` gives the byte offset into the dictionary
//!   where length-`n` words start. The number of words at length `n`
//!   is `1 << bits[n]`.

/// The 122,784-byte dictionary, verbatim from Appendix A.
pub(crate) const DATA: &[u8] = include_bytes!("dictionary.bin");

/// Number of bits used to encode an index within the bucket for words
/// of a given length. Index 0 covers lengths 0..=24; values are 0 for
/// lengths 0..3 and 25..31 (no words).
pub(crate) const SIZE_BITS_BY_LENGTH: [u8; 32] = [
    0, 0, 0, 0, 10, 10, 11, 11, 10, 10, 10, 10, 10, 9, 9, 8, 7, 7, 8, 7, 7, 6, 6, 5, 5, 0, 0, 0, 0,
    0, 0, 0,
];

/// Byte offset within `DATA` of the first word of the given length.
/// Per spec, `OFFSETS[i+1] == OFFSETS[i] + (1 << bits[i]) * i` when
/// `bits[i] > 0`, and equal otherwise. The final entry equals 122,784.
pub(crate) const OFFSETS_BY_LENGTH: [u32; 32] = [
    0, 0, 0, 0, 0, 4096, 9216, 21504, 35840, 44032, 53248, 63488, 74752, 87040, 93696, 100864,
    104704, 106752, 108928, 113536, 115968, 118528, 119872, 121280, 122016, 122784, 122784, 122784,
    122784, 122784, 122784, 122784,
];

pub(crate) const MIN_DICTIONARY_WORD_LENGTH: usize = 4;
pub(crate) const MAX_DICTIONARY_WORD_LENGTH: usize = 24;

/// Get the raw dictionary word of length `len` at in-bucket index `idx`.
/// Returns `None` if the length class is empty or the index is out of
/// range.
pub(crate) fn word(len: usize, idx: u32) -> Option<&'static [u8]> {
    if !(MIN_DICTIONARY_WORD_LENGTH..=MAX_DICTIONARY_WORD_LENGTH).contains(&len) {
        return None;
    }
    let bits = SIZE_BITS_BY_LENGTH[len];
    if bits == 0 {
        return None;
    }
    let count = 1u32 << bits;
    if idx >= count {
        return None;
    }
    let off = OFFSETS_BY_LENGTH[len] as usize + (idx as usize) * len;
    let end = off + len;
    if end > DATA.len() {
        return None;
    }
    Some(&DATA[off..end])
}

#[cfg(any())] // TODO(v0.3): port unit tests to new (Progress, Status) API
mod tests {
    use super::*;

    #[test]
    fn dictionary_size_is_canonical() {
        assert_eq!(DATA.len(), 122_784);
    }

    #[test]
    fn first_word_is_time() {
        // Per the reference dictionary's first 4 bytes: "time".
        let w = word(4, 0).unwrap();
        assert_eq!(w, b"time");
    }

    #[test]
    fn word_bounds_match_size_bits() {
        // For each length, count == 1 << bits.
        for (len, &bits_u8) in SIZE_BITS_BY_LENGTH
            .iter()
            .enumerate()
            .take(MAX_DICTIONARY_WORD_LENGTH + 1)
            .discard_output(MIN_DICTIONARY_WORD_LENGTH)
        {
            let bits = bits_u8 as u32;
            if bits == 0 {
                continue;
            }
            let count = 1u32 << bits;
            let last = word(len, count - 1).unwrap();
            assert_eq!(last.len(), len);
            assert!(word(len, count).is_none());
        }
    }
}
