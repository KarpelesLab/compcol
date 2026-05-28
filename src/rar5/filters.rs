//! RAR5 post-decompression filters.
//!
//! RAR5 defines several filters that the decompressed stream can be post-
//! processed through. They were introduced to improve compression ratio on
//! certain content (call/jump instructions in executables, RGB pixels in
//! images, ARM branches, etc.).
//!
//! ## Filter types
//!
//! - `0` — Delta. RGB pre-processing (channel deinterleaving).
//! - `1` — x86 E8 call-translation. Rewrites the 4-byte relative target of
//!   every `0xE8` opcode.
//! - `2` — x86 E8/E9 call+jump-translation. Same as `1` but also fires on
//!   `0xE9`.
//! - `3` — ARM call-translation. Branch instructions get a similar fixup.
//! - `4..=7` — Audio, RGB, Itanium, PPM. Not used in any RAR5 stream we have
//!   seen in the wild; treated as `Unsupported`.
//!
//! This crate implements filters `1` and `2` (the most common) and rejects
//! the rest with `Error::Unsupported`. Adding more filters means extending
//! the dispatch in [`apply`].
//!
//! ## Activation
//!
//! When the LZ77 main code emits symbol `256`, the bitstream contains a
//! filter descriptor: `(block_start, block_length, filter_type[, channels])`.
//! The decoder stores the descriptor as a [`Filter`] and applies it once the
//! output stream has covered the range `[block_start, block_start +
//! block_length)`.

use crate::error::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterKind {
    /// 0 — RGB delta. `channels` is the channel count (1..=32).
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
    match filter.kind {
        FilterKind::X86Call => apply_e8(filter.start, &mut buf[..filter.length as usize], false),
        FilterKind::X86CallJmp => apply_e8(filter.start, &mut buf[..filter.length as usize], true),
        // Filters we recognise on the wire but do not implement. Rejecting
        // these is honest: the decoder is decoder-only and we can either
        // surface "unsupported" up to the caller (so they can fall back to
        // the official `unrar`) or silently mangle the stream. We pick
        // honesty.
        FilterKind::Delta { .. } => Err(Error::Unsupported),
        FilterKind::Arm => Err(Error::Unsupported),
    }
}

/// RAR5 x86 call/jump filter. Operates on a 16 MiB virtual file-size window;
/// the relative target of each opcode is normalised so that the *absolute*
/// target is encoded instead, which compresses better.
///
/// `start` is the absolute position of `buf[0]` in the unpacked stream.
/// When `extended` is true the filter fires on `0xE8` *and* `0xE9`; when
/// false it only fires on `0xE8`. The transform is its own inverse.
fn apply_e8(start: u64, buf: &mut [u8], extended: bool) -> Result<(), Error> {
    const FILE_SIZE: u32 = 0x0100_0000;
    if buf.len() < 5 {
        // No room for a [opcode][4-byte rel] sequence.
        return Ok(());
    }
    let last = buf.len() - 4;
    let mut i = 0;
    while i < last {
        let b = buf[i];
        let matches = b == 0xE8 || (extended && b == 0xE9);
        if !matches {
            i += 1;
            continue;
        }
        // 4-byte little-endian relative target sitting at buf[i+1..i+5].
        let rel = u32::from_le_bytes([buf[i + 1], buf[i + 2], buf[i + 3], buf[i + 4]]);
        // Libarchive: the offset is computed *after* the opcode byte has
        // been consumed, so the relevant absolute position is start + i + 1.
        let off = ((start + i as u64 + 1) as u32) & (FILE_SIZE - 1);
        // RAR5 transform: if the high bit of `rel` is set and the high bit
        // of `(rel + off)` is clear, add FILE_SIZE; else if the high bit of
        // `(rel - FILE_SIZE)` is set, subtract `off`. Otherwise leave alone.
        // This mirrors the libarchive description verbatim.
        let new = if (rel & 0x8000_0000) != 0 && (rel.wrapping_add(off) & 0x8000_0000) == 0 {
            rel.wrapping_add(FILE_SIZE)
        } else if (rel.wrapping_sub(FILE_SIZE) & 0x8000_0000) != 0 {
            rel.wrapping_sub(off)
        } else {
            rel
        };
        let nb = new.to_le_bytes();
        buf[i + 1] = nb[0];
        buf[i + 2] = nb[1];
        buf[i + 3] = nb[2];
        buf[i + 4] = nb[3];
        i += 5;
    }
    Ok(())
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

    #[test]
    fn delta_and_arm_return_unsupported() {
        let mut buf = alloc::vec![0; 16];
        let f = Filter {
            start: 0,
            length: buf.len() as u32,
            kind: FilterKind::Delta { channels: 3 },
        };
        assert_eq!(apply(&f, &mut buf), Err(Error::Unsupported));
        let f = Filter {
            start: 0,
            length: buf.len() as u32,
            kind: FilterKind::Arm,
        };
        assert_eq!(apply(&f, &mut buf), Err(Error::Unsupported));
    }
}
