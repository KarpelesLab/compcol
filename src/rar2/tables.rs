//! RAR 2.x decoder constants.
//!
//! The length-base / length-extra-bits / offset-base / offset-extra-bits
//! tables, plus short-match-base / short-match-extra-bits, are dictated by
//! the wire format. See XADMaster's XADRAR20Handle.m for the same constants
//! (LGPL — we don't copy code, but the constants are facts).

/// 1 MiB sliding window — XADMaster initializes `XADFastLZSSHandle` with
/// `windowSize:0x100000` for RAR2 streams. The window size is *fixed* in
/// RAR2; unlike RAR3/RAR5 it isn't negotiated in the stream header.
pub const WINDOW_SIZE: usize = 0x100000;
pub const WINDOW_MASK: usize = WINDOW_SIZE - 1;

/// Main-tree alphabet size (literals 0..=255 + 42 specials).
pub const MAIN_TREE_SIZE: usize = 298;
/// Length-tree alphabet size for matches following an offset symbol.
pub const LENGTH_TREE_SIZE: usize = 28;
/// Offset-tree alphabet size.
pub const OFFSET_TREE_SIZE: usize = 48;
/// Pretree alphabet (the 4-bit-length prefix code that decodes the others).
pub const PRETREE_SIZE: usize = 19;
/// Audio per-channel tree alphabet (0..=255 + EOF/restart sentinel = 257).
pub const AUDIO_TREE_SIZE: usize = 257;

/// `numchannels * AUDIO_TREE_SIZE` upper bound (1..=4 channels).
pub const MAX_AUDIO_LENGTHS: usize = 4 * AUDIO_TREE_SIZE; // 1028

/// Sum of MAIN_TREE_SIZE + OFFSET_TREE_SIZE + LENGTH_TREE_SIZE.
pub const NON_AUDIO_LENGTHS: usize = MAIN_TREE_SIZE + OFFSET_TREE_SIZE + LENGTH_TREE_SIZE; // 374

/// Same size as XADRAR20Handle's `lengthtable[1028]`. The non-audio path
/// uses the first 374 entries; the audio path uses up to 1028 (4 × 257).
pub const LENGTH_TABLE_SIZE: usize = MAX_AUDIO_LENGTHS;

// --- Long-match (symbols >= 270) length & offset tables ---------------------

/// Length base for the 28 long-match length symbols. Indexed by
/// `symbol - 270` (or `symbol - 256` for the 4-way "old-offset" branch).
/// Symbols 0..=7 are exact (no extra bits); higher indices carry extra bits
/// per [`LENGTH_EXTRA`].
pub const LENGTH_BASE: [u16; 28] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 14, 16, 20, 24, 28, 32, 40, 48, 56, 64, 80, 96, 112, 128,
    160, 192, 224,
];

/// Number of extra raw bits to read after each long-match length symbol.
pub const LENGTH_EXTRA: [u8; 28] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5,
];

/// Offset base for the 48 long-match offset symbols.
pub const OFFSET_BASE: [u32; 48] = [
    0, 1, 2, 3, 4, 6, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512, 768, 1024, 1536,
    2048, 3072, 4096, 6144, 8192, 12288, 16384, 24576, 32768, 49152, 65536, 98304, 131072, 196608,
    262144, 327680, 393216, 458752, 524288, 589824, 655360, 720896, 786432, 851968, 917504, 983040,
];

/// Extra-bit count for each long-match offset symbol.
pub const OFFSET_EXTRA: [u8; 48] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13, 14, 14, 15, 15, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
];

// --- Short-match (symbols 261..=268) tables ---------------------------------

/// Base offsets for the 8 short-match symbols (261..=268). Indexed by
/// `symbol - 261`.
pub const SHORT_BASE: [u32; 8] = [0, 4, 8, 16, 32, 64, 128, 192];

/// Extra bits for each short-match symbol.
pub const SHORT_EXTRA: [u8; 8] = [2, 2, 3, 4, 5, 6, 6, 6];

// --- Special main-tree symbol numbers ---------------------------------------

/// First main-tree symbol indicating an "old-offset" reuse (256..=260).
pub const SYM_REPEAT_LAST: u16 = 256;
/// 256..=260 are the five repeat-offset slots (the most recent four +
/// "the very last match again").
pub const SYM_OLD_OFFSET_END: u16 = 260;
/// Start of the short-match range (261..=268).
pub const SYM_SHORT_FIRST: u16 = 261;
pub const SYM_SHORT_LAST: u16 = 268;
/// 269 = "re-read the per-block trees and continue".
pub const SYM_REREAD_TREES: u16 = 269;
/// First long-match symbol; the length-base index is `symbol - 270`.
pub const SYM_LONG_FIRST: u16 = 270;
