//! LZNT1 — NTFS native file compression.
//!
//! Block-structured LZ77 with no entropy coding. Documented in Microsoft
//! [MS-XCA] section 2.5. The stream is a sequence of independent 4 KiB
//! chunks; each chunk carries a 2-byte little-endian header followed by
//! either the chunk's raw bytes (uncompressed chunks) or a sequence of
//! "flag groups" of literals and back-references (compressed chunks).
//!
//! ## Chunk header
//!
//! ```text
//!  15 14 13 12 11 10  9  8  7  6  5  4  3  2  1  0
//! +--+-----------+--------------------------------+
//! |C |  sig=011  |       chunk_size - 1            |
//! +--+-----------+--------------------------------+
//! ```
//!
//! - Bit 15 = compressed flag (`C`).
//! - Bits 14..=12 = block signature, fixed to `0b011 = 3`.
//! - Bits 11..=0 = `chunk_size - 1`, where `chunk_size` counts only the
//!   body bytes that follow the header (uncompressed chunks always carry
//!   exactly 4096 body bytes except for the final tail chunk).
//!
//! An all-zero 2-byte word (or end-of-input) terminates the stream.
//!
//! ## Compressed chunk body
//!
//! A compressed chunk body is a sequence of "flag groups". Each group is
//! a single flag byte followed by up to 8 tokens. Bit `i` of the flag byte
//! selects token type: `0` = 1-byte literal, `1` = 2-byte little-endian
//! match. Token order is LSB-first (bit 0 = first token).
//!
//! ## Match encoding
//!
//! Each match is 16 bits little-endian. The split between offset and
//! length bits varies with the number of bytes emitted so far in the
//! current chunk, growing the offset field as more history is available:
//!
//! | bytes emitted | offset bits | length bits | offset range | length range |
//! |---------------|-------------|-------------|--------------|--------------|
//! | 1..=16        | 12          | 4           | 1..=4096     | 3..=18       |
//! | 17..=32       | 11          | 5           | 1..=2048     | 3..=34       |
//! | 33..=64       | 10          | 6           | 1..=1024     | 3..=66       |
//! | 65..=128      | 9           | 7           | 1..=512      | 3..=130      |
//! | 129..=256     | 8           | 8           | 1..=256      | 3..=258      |
//! | 257..=512     | 7           | 9           | 1..=128      | 3..=514      |
//! | 513..=1024    | 6           | 10          | 1..=64       | 3..=1026     |
//! | 1025..=2048   | 5           | 11          | 1..=32       | 3..=2050     |
//! | 2049..=4096   | 4           | 12          | 1..=16       | 3..=4098     |
//!
//! The encoded value is `((offset - 1) << length_bits) | (length - 3)`.
//! Decoding inverts: `length = (token & length_mask) + 3`,
//! `offset = (token >> length_bits) + 1`.
//!
//! ## Sliding window
//!
//! Per-chunk: each chunk is encoded and decoded independently with a
//! fresh history. Back-references cannot cross chunk boundaries.

#![cfg_attr(docsrs, doc(cfg(feature = "lznt1")))]

use crate::traits::Algorithm;

mod decoder;
mod encoder;

pub use decoder::Decoder;
pub use encoder::{Encoder, EncoderConfig};

/// Maximum uncompressed bytes per chunk (4096 = 2^12).
pub(crate) const CHUNK_SIZE: usize = 4096;

/// Pick the (offset_bits, length_bits) split for a position. `pos` is
/// the number of bytes already emitted into the current chunk before
/// the match. Implements the MS-XCA 2.5 table:
///
/// | pos       | offset_bits | length_bits |
/// |-----------|-------------|-------------|
/// | 1..=15    | 12          | 4           |
/// | 16..=31   | 11          | 5           |
/// | 32..=63   | 10          | 6           |
/// | 64..=127  | 9           | 7           |
/// | 128..=255 | 8           | 8           |
/// | 256..=511 | 7           | 9           |
/// | 512..=1023| 6           | 10          |
/// | 1024..=2047| 5          | 11          |
/// | 2048..    | 4           | 12          |
#[inline]
pub(crate) fn split_for_pos(pos: usize) -> (u32, u32) {
    let length_bits = if pos < 0x10 {
        4
    } else if pos < 0x20 {
        5
    } else if pos < 0x40 {
        6
    } else if pos < 0x80 {
        7
    } else if pos < 0x100 {
        8
    } else if pos < 0x200 {
        9
    } else if pos < 0x400 {
        10
    } else if pos < 0x800 {
        11
    } else {
        12
    };
    (16 - length_bits, length_bits)
}

/// Zero-sized marker type implementing [`Algorithm`] for LZNT1.
#[derive(Debug, Clone, Copy, Default)]
pub struct Lznt1;

impl Algorithm for Lznt1 {
    const NAME: &'static str = "lznt1";
    type Encoder = Encoder;
    type Decoder = Decoder;
    type EncoderConfig = EncoderConfig;
    type DecoderConfig = ();

    fn encoder_with(c: Self::EncoderConfig) -> Encoder {
        Encoder::with_config(c)
    }
    fn decoder_with(_: ()) -> Decoder {
        Decoder::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_table_matches_spec() {
        // Each row: (pos, expected_offset_bits, expected_length_bits)
        let cases: &[(usize, u32, u32)] = &[
            (1, 12, 4),
            (15, 12, 4),
            (16, 11, 5),
            (31, 11, 5),
            (32, 10, 6),
            (63, 10, 6),
            (64, 9, 7),
            (127, 9, 7),
            (128, 8, 8),
            (255, 8, 8),
            (256, 7, 9),
            (511, 7, 9),
            (512, 6, 10),
            (1023, 6, 10),
            (1024, 5, 11),
            (2047, 5, 11),
            (2048, 4, 12),
            (4095, 4, 12),
        ];
        for &(pos, off_bits, len_bits) in cases {
            let (o, l) = split_for_pos(pos);
            assert_eq!(
                (o, l),
                (off_bits, len_bits),
                "pos={pos}: expected ({off_bits},{len_bits}), got ({o},{l})"
            );
        }
    }
}
