//! Constant tables for PKWARE deflate64 (APPNOTE 6.3.9 §"Enhanced Deflating").
//!
//! Deflate64 reuses RFC 1951's bit-stream framing and code-length encoding,
//! but extends both alphabets:
//!
//!  * length code 285 — formerly the "no extra bits, length=258" terminal —
//!    becomes a 16-extra-bit code mapping to 3..=65538 byte matches.
//!  * distance codes 30 and 31 are activated, each carrying 14 extra bits,
//!    extending the addressable window to 65536 bytes.
//!
//! Code values 257..284 keep RFC 1951's base / extra mappings unchanged.

/// Base length for each length code 257..285 (indexed as `code - 257`).
/// Code 285 carries 16 extra bits and a base of 3 (matches up to 65538).
pub const LENGTH_BASE: [u32; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 3,
];

/// Number of extra bits for each length code.
pub const LENGTH_EXTRA: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 16,
];

/// Base distance for each distance code 0..31. Codes 0..29 match RFC 1951;
/// codes 30 and 31 extend addressing into the 64 KiB window.
pub const DIST_BASE: [u32; 32] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577, 32769, 49153,
];

/// Number of extra bits for each distance code.
pub const DIST_EXTRA: [u8; 32] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13, 14, 14,
];

/// Permutation used when reading the code-length code lengths in a
/// dynamic-Huffman block header. Identical to RFC 1951 §3.2.7.
pub const CODE_LENGTH_ORDER: [usize; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

/// Fixed literal/length code lengths used by BTYPE=01 blocks. Same as RFC 1951.
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

/// Fixed distance code lengths (all 5 bits). In deflate64 every symbol
/// 0..=31 carries a real meaning; nothing is reserved.
pub const FIXED_DIST_LENGTHS: [u8; 32] = [5u8; 32];

/// Sliding-window size for deflate64. Double the classical deflate window.
pub const WINDOW_SIZE: usize = 65536;

/// Smallest LZ77 match length.
pub const MIN_MATCH: usize = 3;

/// Largest LZ77 match length (length code 285 with all 16 extra bits set).
pub const MAX_MATCH: usize = 65538;

/// End-of-block marker symbol in the literal/length alphabet.
pub const END_OF_BLOCK: u16 = 256;

/// Number of distance symbols actually defined.
pub const NUM_DIST_SYMBOLS: usize = 32;

/// Number of literal/length symbols actually defined (256 literals + EOB + 29 length codes).
pub const NUM_LITLEN_SYMBOLS: usize = 286;
