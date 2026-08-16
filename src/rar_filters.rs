//! Byte transforms for RAR's *standard* post-decompression filters, shared
//! by the RAR3 (in-band RarVM programs, main symbol 257) and RAR5 (filter
//! descriptors after main symbol 256) decoders.
//!
//! RAR compressors optionally pre-process content before LZ compression so
//! it compresses better (relative call targets in executables, interleaved
//! channel data in bitmaps/audio). The decoder undoes the transform over a
//! declared `(start, length)` window of the unpacked stream after
//! decompressing it. Both container generations use the same two transforms
//! implemented here:
//!
//! - **x86 E8 / E8E9** call(/jump) translation, [`x86_e8_decode`].
//! - **Delta** channel de-interleave + integrate, [`delta_decode`].
//!
//! ## Provenance
//!
//! Semantics derived from public format documentation and validated
//! byte-for-byte against WinRAR-produced archives (differential harness vs
//! `UnRAR.exe` 7.23: RAR4 delta ch=2/3/12 and E8 windows, RAR5 E8/E8E9).
//! Structure cross-checked against libarchive (BSD); no code copied from
//! RARLAB's unRAR or The Unarchiver.

use alloc::vec::Vec;

/// x86 call/jump filter, decode direction. Operates on a 16 MiB virtual
/// file-size window; the encoder rewrote each `E8` (and, for the extended
/// variant, `E9`) opcode's 4-byte relative target into absolute form, and
/// this pass restores the original relative value.
///
/// `start` is the absolute position of `buf[0]` in the unpacked stream
/// (file-relative for both generations). When `also_e9` is true the filter
/// fires on `0xE8` *and* `0xE9`; when false only on `0xE8`.
///
/// `wrap_16m` selects the position-base arithmetic, where the two container
/// generations differ: RAR5 reduces the position modulo the 16 MiB virtual
/// file size (validated against real WinRAR archives in the differential
/// harness), while RAR3's VM filter uses the unmasked 32-bit position (per
/// libarchive's RAR3 reader; the two agree below 16 MiB, so windows past
/// 16 MiB of a large executable are where masking would corrupt RAR3
/// output).
pub(crate) fn x86_e8_decode(start: u64, buf: &mut [u8], also_e9: bool, wrap_16m: bool) {
    const FILE_SIZE: u32 = 0x0100_0000;
    if buf.len() < 5 {
        // No room for a [opcode][4-byte rel] sequence.
        return;
    }
    let last = buf.len() - 4;
    let mut i = 0;
    while i < last {
        let b = buf[i];
        let matches = b == 0xE8 || (also_e9 && b == 0xE9);
        if !matches {
            i += 1;
            continue;
        }
        // 4-byte little-endian relative target sitting at buf[i+1..i+5].
        let rel = u32::from_le_bytes([buf[i + 1], buf[i + 2], buf[i + 3], buf[i + 4]]);
        // The offset is computed *after* the opcode byte has been consumed,
        // so the relevant absolute position is start + i + 1.
        let mut off = (start + i as u64 + 1) as u32;
        if wrap_16m {
            off &= FILE_SIZE - 1;
        }
        // Decode direction. The two range checks are NESTED on the sign of
        // `rel`, exactly as in unrar/libarchive:
        //
        //   if (addr < 0)          { if (addr + off >= 0)   addr += FILE_SIZE; }
        //   else                   { if (addr < FILE_SIZE)  addr -= off;       }
        //
        // Flattening the second check into an `else if` is a bug: a
        // negative `rel` that stays negative after adding `off` (a byte
        // pattern the encoder never rewrote — e.g. a stray 0xE8 inside a
        // ModRM/displacement sequence followed by high bytes) also passes
        // `(rel - FILE_SIZE) & 0x8000_0000 != 0` and would be wrongly
        // rewritten, corrupting real x86 code on decode.
        let new = if (rel & 0x8000_0000) != 0 {
            if (rel.wrapping_add(off) & 0x8000_0000) == 0 {
                rel.wrapping_add(FILE_SIZE)
            } else {
                rel
            }
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
}

/// Delta filter, decode direction. The encoder de-interleaved the region
/// into `channels` planes of successive byte differences; this pass
/// re-interleaves and integrates them: each output byte is the previous
/// output byte of the same channel *minus* the next source byte.
///
/// `channels == 0` is a caller error and leaves the buffer untouched
/// (callers validate the channel count when parsing the declaration).
pub(crate) fn delta_decode(channels: usize, data: &mut [u8]) {
    debug_assert!(channels >= 1);
    if channels == 0 || data.is_empty() {
        return;
    }
    // The source (planar deltas) is consumed sequentially while the
    // destination is written strided, so a scratch copy of the source is
    // needed.
    let src: Vec<u8> = data.to_vec();
    let mut sp = 0usize;
    for ch in 0..channels {
        let mut prev = 0u8;
        let mut i = ch;
        while i < data.len() {
            prev = prev.wrapping_sub(src[sp]);
            data[i] = prev;
            sp += 1;
            i += channels;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use std::vec;

    #[test]
    fn delta_two_channels_hand_computed() {
        // Two channels, planar source: channel 0 deltas [1, 2], channel 1
        // deltas [3, 4]. Integration is prev - delta starting from 0.
        // ch0: 0-1=0xFF, 0xFF-2=0xFD ; ch1: 0-3=0xFD, 0xFD-4=0xF9.
        let mut data = vec![1u8, 2, 3, 4];
        delta_decode(2, &mut data);
        assert_eq!(data, [0xFF, 0xFD, 0xFD, 0xF9]);
    }

    #[test]
    fn delta_single_channel_is_running_negated_sum() {
        let mut data = vec![0u8, 0xFF, 0xFF];
        delta_decode(1, &mut data);
        assert_eq!(data, [0, 1, 2]);
    }

    #[test]
    fn delta_length_not_divisible_by_channels() {
        // 5 bytes, 2 channels: channel 0 covers indices 0,2,4 (3 source
        // bytes), channel 1 covers 1,3 (2 source bytes) — source is planar
        // in that order.
        let mut data = vec![1u8, 1, 1, 2, 2];
        delta_decode(2, &mut data);
        // ch0 deltas [1,1,1] -> FF,FE,FD at 0,2,4; ch1 deltas [2,2] -> FE,FC.
        assert_eq!(data, [0xFF, 0xFE, 0xFE, 0xFC, 0xFD]);
    }

    #[test]
    fn e8_rewrites_call_target() {
        let mut buf = vec![0x00, 0x00, 0xE8, 0x10, 0x00, 0x00, 0x00, 0x90, 0x90];
        x86_e8_decode(0, &mut buf, false, true);
        // off = 2 + 1 = 3; rel = 0x10 in 0..FILE_SIZE => rel - off.
        let expected = 0x10u32.wrapping_sub(3).to_le_bytes();
        assert_eq!(&buf[3..7], &expected);
    }

    #[test]
    fn e8_ignores_e9_unless_extended() {
        let mut buf = vec![0xE9, 0x10, 0x00, 0x00, 0x00];
        let orig = buf.clone();
        x86_e8_decode(0, &mut buf, false, true);
        assert_eq!(buf, orig);
        x86_e8_decode(0, &mut buf, true, true);
        assert_ne!(buf, orig);
    }

    /// RAR3 (unmasked) and RAR5 (16 MiB-wrapped) position bases agree below
    /// 16 MiB and diverge above — a >16 MiB window must subtract the full
    /// offset on the RAR3 path.
    #[test]
    fn e8_base_masking_diverges_past_16mib() {
        const START: u64 = 0x0100_0000; // exactly 16 MiB
        let src = vec![0xE8, 0x10, 0x00, 0x00, 0x00];

        let mut unmasked = src.clone();
        x86_e8_decode(START, &mut unmasked, false, false);
        // off = 16 MiB + 1; rel = 0x10 < FILE_SIZE => rel - off (wrapping).
        let want = 0x10u32.wrapping_sub(0x0100_0001).to_le_bytes();
        assert_eq!(&unmasked[1..5], &want);

        let mut masked = src.clone();
        x86_e8_decode(START, &mut masked, false, true);
        // off wraps to 1 => rel - 1.
        assert_eq!(&masked[1..5], &0x0Fu32.to_le_bytes());
    }
}
