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
//! length bits varies with the number of bytes `U` already emitted in the
//! current chunk (MS-XCA 2.5.1.4): the offset field has `M` bits, where `M`
//! is the largest value in `4..=12` with `2^(M-1) < U` (or 4), and the
//! length field has the remaining `16 - M` bits. The offset field grows as
//! more history becomes reachable:
//!
//! | bytes emitted | offset bits | length bits | offset range | length range |
//! |---------------|-------------|-------------|--------------|--------------|
//! | 1..=16        | 4           | 12          | 1..=16       | 3..=4098     |
//! | 17..=32       | 5           | 11          | 1..=32       | 3..=2050     |
//! | 33..=64       | 6           | 10          | 1..=64       | 3..=1026     |
//! | 65..=128      | 7           | 9           | 1..=128      | 3..=514      |
//! | 129..=256     | 8           | 8           | 1..=256      | 3..=258      |
//! | 257..=512     | 9           | 7           | 1..=512      | 3..=130      |
//! | 513..=1024    | 10          | 6           | 1..=1024     | 3..=66       |
//! | 1025..=2048   | 11          | 5           | 1..=2048     | 3..=34       |
//! | 2049..=4096   | 12          | 4           | 1..=4096     | 3..=18       |
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
/// the match (MS-XCA's `U`). Implements MS-XCA 2.5.1.4: the offset field
/// has `M` bits, the largest `M` in `4..=12` with `2^(M-1) < pos` (or 4),
/// and the length field the remaining `16 - M`:
///
/// | pos          | offset_bits | length_bits |
/// |--------------|-------------|-------------|
/// | 0..=16       | 4           | 12          |
/// | 17..=32      | 5           | 11          |
/// | 33..=64      | 6           | 10          |
/// | 65..=128     | 7           | 9           |
/// | 129..=256    | 8           | 8           |
/// | 257..=512    | 9           | 7           |
/// | 513..=1024   | 10          | 6           |
/// | 1025..=2048  | 11          | 5           |
/// | 2049..       | 12          | 4           |
#[inline]
pub(crate) fn split_for_pos(pos: usize) -> (u32, u32) {
    let mut offset_bits = 4;
    while offset_bits < 12 && (1usize << offset_bits) < pos {
        offset_bits += 1;
    }
    (offset_bits, 16 - offset_bits)
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
        // Each row: (pos, expected_offset_bits, expected_length_bits), per
        // MS-XCA 2.5.1.4: offset bits = largest M in 4..=12 with
        // 2^(M-1) < pos, else 4.
        let cases: &[(usize, u32, u32)] = &[
            (0, 4, 12),
            (1, 4, 12),
            (16, 4, 12),
            (17, 5, 11),
            (32, 5, 11),
            (33, 6, 10),
            (64, 6, 10),
            (65, 7, 9),
            (128, 7, 9),
            (129, 8, 8),
            (256, 8, 8),
            (257, 9, 7),
            (512, 9, 7),
            (513, 10, 6),
            (1024, 10, 6),
            (1025, 11, 5),
            (2048, 11, 5),
            (2049, 12, 4),
            (4095, 12, 4),
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
