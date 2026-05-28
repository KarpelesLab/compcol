//! Constant tables from RFC 1951.

/// Base length for each length code 257..285 (indexed as `code - 257`).
/// RFC 1951 §3.2.5.
pub const LENGTH_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];

/// Number of extra bits for each length code.
pub const LENGTH_EXTRA: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];

/// Base distance for each distance code 0..29.
/// RFC 1951 §3.2.5.
pub const DIST_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];

/// Number of extra bits for each distance code.
pub const DIST_EXTRA: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];

/// Permutation used when reading the code-length code lengths in a
/// dynamic-Huffman block header. RFC 1951 §3.2.7.
pub const CODE_LENGTH_ORDER: [usize; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

/// Fixed literal/length code lengths used by BTYPE=01 blocks. RFC 1951 §3.2.6.
pub const FIXED_LIT_LENGTHS: [u8; 288] = {
    let mut lens = [0u8; 288];
    let mut i = 0usize;
    while i < 144 {
        lens[i] = 8;
        i += 1;
    }
    while i < 256 {
        lens[i] = 9;
        i += 1;
    }
    while i < 280 {
        lens[i] = 7;
        i += 1;
    }
    while i < 288 {
        lens[i] = 8;
        i += 1;
    }
    lens
};

/// Fixed distance code lengths (all 5 bits). Symbols 30 and 31 are encoded
/// but reserved — decoders that see them must report corrupt input.
pub const FIXED_DIST_LENGTHS: [u8; 32] = [5u8; 32];

/// Sliding-window size mandated by deflate.
pub const WINDOW_SIZE: usize = 32768;

/// Smallest LZ77 match length.
pub const MIN_MATCH: usize = 3;

/// Largest LZ77 match length.
pub const MAX_MATCH: usize = 258;

/// End-of-block marker symbol in the literal/length alphabet.
pub const END_OF_BLOCK: u16 = 256;
