//! Static tables for LZX, derived from [MS-PATCH] §2 and the libmspack
//! reference implementation.

// ─── Alphabet sizes ─────────────────────────────────────────────────────

/// Single-byte literals 0..=255 occupy the first 256 main-tree slots.
pub const NUM_CHARS: usize = 256;

/// Low 3 bits of a match main symbol encode a "length header" in 0..=7.
/// Value 7 means "consult LENGTH_TREE for the remaining length footer".
pub const NUM_PRIMARY_LENGTHS: u16 = 7;

/// LENGTH_TREE alphabet size — match lengths longer than NUM_PRIMARY_LENGTHS
/// are encoded via this secondary tree.
pub const NUM_SECONDARY_LENGTHS: usize = 249;

/// Smallest match the decoder ever emits.
pub const MIN_MATCH: u16 = 2;

/// Largest unextended match length.
#[allow(dead_code)]
pub const MAX_MATCH: u16 = 257;

/// Pre-tree alphabet size — 20 symbols, each carrying a 4-bit length, used
/// to decode the delta-encoded code lengths of MAIN_TREE / LENGTH_TREE.
pub const PRETREE_NUM_ELEMENTS: usize = 20;

/// ALIGNED_TREE alphabet size — fixed.
pub const ALIGNED_NUM_ELEMENTS: usize = 8;

/// All frames are 32 KiB except possibly the last in a stream.
pub const FRAME_SIZE: usize = 32_768;

/// Smallest supported window (per CAB LZX).
pub const MIN_WINDOW_BITS: u8 = 15;

/// Largest supported window (per CAB LZX). LZX DELTA goes higher but we stick
/// to the CAB profile.
pub const MAX_WINDOW_BITS: u8 = 21;

// ─── Block types (3-bit field at the start of every block) ──────────────

pub const BLOCKTYPE_VERBATIM: u8 = 1;
pub const BLOCKTYPE_ALIGNED: u8 = 2;
pub const BLOCKTYPE_UNCOMPRESSED: u8 = 3;

// ─── Position slot tables ───────────────────────────────────────────────

/// Number of position slots per window size, indexed by `window_bits - 15`.
pub const POSITION_SLOTS: [u16; 7] = [30, 32, 34, 36, 38, 42, 50];

/// `EXTRA_BITS[slot]` — number of verbatim bits that follow a position-slot
/// main-element (capped at 17 per spec).
pub const EXTRA_BITS: [u8; 51] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13, 14, 14, 15, 15, 16, 16, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17,
];

/// `POSITION_BASE[slot]` — accumulated base offset for each position slot.
/// Generated from `EXTRA_BITS` by `POSITION_BASE[0] = 0;
/// POSITION_BASE[i] = POSITION_BASE[i-1] + (1 << EXTRA_BITS[i-1])`.
pub const POSITION_BASE: [u32; 51] = [
    0, 1, 2, 3, 4, 6, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512, 768, 1024, 1536,
    2048, 3072, 4096, 6144, 8192, 12288, 16384, 24576, 32768, 49152, 65536, 98304, 131072, 196608,
    262144, 393216, 524288, 655360, 786432, 917504, 1048576, 1179648, 1310720, 1441792, 1572864,
    1703936, 1835008, 1966080, 2097152,
];

/// Number of position slots used for a `window_bits` setting in CAB range
/// 15..=21.
pub const fn position_slots_for(window_bits: u8) -> u16 {
    POSITION_SLOTS[(window_bits - MIN_WINDOW_BITS) as usize]
}

/// MAIN_TREE alphabet size for a given window: 256 literals + 8 length-headers
/// per position slot.
pub const fn main_tree_size(window_bits: u8) -> usize {
    NUM_CHARS + (position_slots_for(window_bits) as usize) * 8
}

/// Compile-time upper bound on MAIN_TREE size — large enough for any window
/// in our supported range.
pub const MAIN_TREE_MAX: usize = NUM_CHARS + (50 * 8); // = 656 for window_bits=21
