//! RAR5 post-decompression filters.
//!
//! RAR5 defines several filters that the decompressed stream can be post-
//! processed through. They were introduced to improve compression ratio on
//! certain content (call/jump instructions in executables, RGB pixels in
//! images, ARM branches, etc.).
//!
//! ## Filter types
//!
//! - `0` — Delta. Channel de-interleave (bitmap/audio pre-processing).
//! - `1` — x86 E8 call-translation. Rewrites the 4-byte relative target of
//!   every `0xE8` opcode.
//! - `2` — x86 E8/E9 call+jump-translation. Same as `1` but also fires on
//!   `0xE9`.
//! - `3` — ARM call-translation. Branch instructions get a similar fixup.
//! - `4..=7` — Audio, RGB, Itanium, PPM. Not used in any RAR5 stream we have
//!   seen in the wild; treated as `Unsupported`.
//!
//! This crate implements filters `0`, `1` and `2` and rejects ARM and the
//! rest with `Error::Unsupported`. Adding more filters means extending the
//! dispatch in [`apply`]. The byte transforms themselves live in
//! [`crate::rar_filters`], shared with the RAR3 decoder.
//!
//! ## Activation
//!
//! When the LZ77 main code emits symbol `256`, the bitstream contains a
//! filter descriptor: `(block_start, block_length, filter_type[, channels])`.
//! The decoder stores the descriptor as a [`Filter`] and applies it once the
//! output stream has covered the range `[block_start, block_start +
//! block_length)`.

use crate::error::Error;
use crate::rar_filters::{delta_decode, x86_e8_decode};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterKind {
    /// 0 — Delta. `channels` is the channel count (1..=32).
    Delta { channels: u8 },
    /// 1 — x86 `0xE8` (CALL) relative-address rewrite.
    X86Call,
    /// 2 — x86 `0xE8`/`0xE9` (CALL/JMP) relative-address rewrite.
    X86CallJmp,
    /// 3 — ARM branch instruction rewrite.
    Arm,
}

/// A pending filter descriptor read out of the bitstream.
#[derive(Debug, Clone, Copy)]
pub struct Filter {
    /// Absolute byte offset in the unpacked stream where the filter starts.
    pub start: u64,
    /// Length in bytes of the region the filter operates on.
    pub length: u32,
    pub kind: FilterKind,
}

/// Apply a filter to `buf[..length]`. `start` is the absolute offset of the
/// first byte in the unpacked stream, used by the x86 transforms to fix up
/// program-counter-relative addresses. `length` may be shorter than
/// `buf.len()` (the caller passes the actual region to process).
pub fn apply(filter: &Filter, buf: &mut [u8]) -> Result<(), Error> {
    if (buf.len() as u64) < filter.length as u64 {
        return Err(Error::Corrupt);
    }
    let region = &mut buf[..filter.length as usize];
    match filter.kind {
        FilterKind::X86Call => {
            x86_e8_decode(filter.start, region, false);
            Ok(())
        }
        FilterKind::X86CallJmp => {
            x86_e8_decode(filter.start, region, true);
            Ok(())
        }
        FilterKind::Delta { channels } => {
            if channels == 0 {
                // The wire format encodes channels-1 in 5 bits, so 0 can't
                // be parsed off the stream; guard against caller misuse.
                return Err(Error::Corrupt);
            }
            delta_decode(channels as usize, region);
            Ok(())
        }
        // Recognised on the wire but not implemented. Rejecting is honest:
        // the caller can fall back to the official unrar instead of us
        // silently mangling the stream.
        FilterKind::Arm => Err(Error::Unsupported),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn e8_filter_rewrites_call_target() {
        // Synthetic stream: prefix bytes, then E8 with a small positive
        // relative target, then trailing bytes.
        let start: u64 = 0;
        let mut buf = alloc::vec![0x00, 0x00, 0xE8, 0x10, 0x00, 0x00, 0x00, 0x90, 0x90];
        let f = Filter {
            start,
            length: buf.len() as u32,
            kind: FilterKind::X86Call,
        };
        apply(&f, &mut buf).unwrap();
        // After filtering, the 4 bytes at idx 3..7 hold (rel - off) where
        // off = start + i_of_opcode + 1 = 3.
        // rel = 0x10, FILE_SIZE = 0x01000000. Since rel-FILE_SIZE has its
        // high bit set, the rewrite path is `rel - off` = 0x10 - 3 = 0x0D.
        let expected = (0x10u32).wrapping_sub(3).to_le_bytes();
        assert_eq!(&buf[3..7], &expected);
        // The transform is NOT self-inverse for the decoder direction (it's
        // applied at decode time to undo what the encoder did). Reapplying
        // it does NOT restore the original — encoder and decoder differ
        // by the sign of the offset.
    }

    #[test]
    fn e8_filter_ignores_non_opcode_bytes() {
        let mut buf = alloc::vec![0xC3, 0x90, 0xCC, 0xFF, 0x90, 0x90, 0x90, 0x90, 0x90];
        let original = buf.clone();
        let f = Filter {
            start: 0,
            length: buf.len() as u32,
            kind: FilterKind::X86Call,
        };
        apply(&f, &mut buf).unwrap();
        assert_eq!(buf, original);
    }

    /// Regression: a "false positive" E8 byte (ModRM/displacement bytes in
    /// real x86 code, not a CALL opcode) followed by an operand whose signed
    /// value is negative and stays negative after adding the position must
    /// be left alone — unrar's filter only adds FILE_SIZE when the sum goes
    /// non-negative, and only subtracts the position from values in
    /// `0..FILE_SIZE`. Case taken verbatim from a WinRAR 7.23 archive of
    /// notepad.exe's first 32 KiB: at offset 5496 the byte 0xE8 (part of
    /// `mov rcx,[rsp+...]` encoding, not a call) is followed by the operand
    /// 0xCC000006; the buggy flat `else if` subtracted the position and
    /// corrupted the output (48 bytes across 15 sites in one 32 KiB slice).
    #[test]
    fn e8_filter_leaves_negative_out_of_range_operand_alone() {
        // E8 at index 0, start chosen so off = 5497 (the real archive's
        // position), operand 0xCC000006 little-endian.
        let mut buf = alloc::vec![0xE8, 0x06, 0x00, 0x00, 0xCC, 0x90, 0x90];
        let original = buf.clone();
        let f = Filter {
            start: 5496,
            length: buf.len() as u32,
            kind: FilterKind::X86Call,
        };
        apply(&f, &mut buf).unwrap();
        assert_eq!(
            buf, original,
            "negative out-of-range operand must not be rewritten"
        );
    }

    /// The companion positive case: a negative operand that becomes
    /// non-negative when the position is added IS rewritten (+FILE_SIZE).
    #[test]
    fn e8_filter_wraps_negative_in_range_operand() {
        // rel = -16 (0xFFFFFFF0), off = 0x20 -> rel + off = 0x10 >= 0,
        // so the decoder adds FILE_SIZE.
        let mut buf = alloc::vec![0xE8, 0xF0, 0xFF, 0xFF, 0xFF, 0x90, 0x90];
        let f = Filter {
            start: 0x1F, // off = start + 0 + 1 = 0x20
            length: buf.len() as u32,
            kind: FilterKind::X86Call,
        };
        apply(&f, &mut buf).unwrap();
        let expected = 0xFFFF_FFF0u32.wrapping_add(0x0100_0000).to_le_bytes();
        assert_eq!(&buf[1..5], &expected);
    }

    /// A non-negative operand at or above FILE_SIZE is also left alone.
    #[test]
    fn e8_filter_leaves_large_positive_operand_alone() {
        // rel = 0x01000000 == FILE_SIZE: not in 0..FILE_SIZE, untouched.
        let mut buf = alloc::vec![0xE8, 0x00, 0x00, 0x00, 0x01, 0x90, 0x90];
        let original = buf.clone();
        let f = Filter {
            start: 100,
            length: buf.len() as u32,
            kind: FilterKind::X86Call,
        };
        apply(&f, &mut buf).unwrap();
        assert_eq!(buf, original);
    }

    #[test]
    fn delta_three_channels_reinterleaves() {
        // Planar deltas: ch0=[1,1], ch1=[2,2], ch2=[3,3] over a 6-byte
        // region. Decode integrates each channel with prev - delta.
        let mut buf = alloc::vec![1u8, 1, 2, 2, 3, 3];
        let f = Filter {
            start: 0,
            length: buf.len() as u32,
            kind: FilterKind::Delta { channels: 3 },
        };
        apply(&f, &mut buf).unwrap();
        assert_eq!(buf, [0xFF, 0xFE, 0xFD, 0xFE, 0xFC, 0xFA]);
    }

    #[test]
    fn arm_returns_unsupported() {
        let mut buf = alloc::vec![0; 16];
        let f = Filter {
            start: 0,
            length: buf.len() as u32,
            kind: FilterKind::Arm,
        };
        assert_eq!(apply(&f, &mut buf), Err(Error::Unsupported));
    }
}
