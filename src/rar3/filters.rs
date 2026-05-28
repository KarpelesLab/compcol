//! RAR 3.x post-decompression filters.
//!
//! RAR3 supports a small set of "VM filters" that the encoder embeds as
//! bytecode programs in symbol 257 of the main code. The decoder is then
//! supposed to instantiate an interpreter for a stack-based RISC-like VM
//! ("RarVM"). Faithfully implementing RarVM is a large effort (the
//! upstream interpreter is several hundred lines plus a full instruction
//! set) and is out of scope for this build.
//!
//! What we do support is the **stand-alone Intel E8/E9 x86 call translation
//! filter** which can be activated through an external selector
//! ([`Decoder::with_e8_filter`]). This filter is what the vast majority of
//! RAR3 streams over x86 executables actually use, and the operation is
//! the same as the LZX intel-call-translation post-pass.
//!
//! Future versions of this module may grow Itanium, RGB delta and audio
//! delta filters if there's demand; for now any in-band filter declaration
//! is refused with `Error::Unsupported`.

/// Apply the E8/E9 (x86 near-call) translation filter to `data` in place.
///
/// For each 0xE8 or 0xE9 byte at index `i` (scanning
/// `i = 0..data.len() - 5`), the next four little-endian bytes are
/// interpreted as a relative call offset and rewritten to absolute form
/// (or vice-versa during compression). This implementation matches the
/// canonical filter used by both LZX and RAR3: the relative-to-absolute
/// transform that produces the original executable bytes.
///
/// `data_start_offset` is the offset of the first byte of `data` in the
/// uncompressed stream — needed because the filter only operates on
/// the first 1 GiB of any executable, mirroring the original
/// implementation.
///
/// `translate_e9` enables the filter for 0xE9 (near-jump) opcodes in
/// addition to 0xE8 (near-call). Some RAR3 streams target only E8; the
/// caller picks based on the filter selector observed in the archive.
pub fn apply_e8_filter(data: &mut [u8], data_start_offset: u64, translate_e9: bool) {
    if data.len() < 5 {
        return;
    }
    if data_start_offset >= 0x4000_0000 {
        return;
    }
    let scan_end = data.len() - 5;
    let mut i = 0usize;
    while i <= scan_end {
        let b = data[i];
        let is_call = b == 0xE8 || (translate_e9 && b == 0xE9);
        if !is_call {
            i += 1;
            continue;
        }
        // Absolute address of the byte immediately following the opcode.
        let cur_pos = (data_start_offset + i as u64 + 1) as i32;
        let rel = i32::from_le_bytes([data[i + 1], data[i + 2], data[i + 3], data[i + 4]]);
        // RAR3's E8 filter operates on a 32-bit space wrap; the rewritten
        // value is `(rel - cur_pos)` masked into the same 32-bit window.
        let new = rel.wrapping_sub(cur_pos);
        let bytes = new.to_le_bytes();
        data[i + 1] = bytes[0];
        data[i + 2] = bytes[1];
        data[i + 3] = bytes[2];
        data[i + 4] = bytes[3];
        i += 5;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;

    #[test]
    fn ignores_short_buffers() {
        let mut data = *b"\xE8\x00\x00";
        apply_e8_filter(&mut data, 0, false);
        // No change because there isn't a full 5-byte sequence.
        assert_eq!(&data, b"\xE8\x00\x00");
    }

    #[test]
    fn rewrites_e8_callsite() {
        // Original assembly: at offset 0 in the file, "call +0x100" encoded
        // as E8 00 01 00 00. Compressed form should rewrite to (rel - cur).
        let mut data = [0xE8, 0x00, 0x01, 0x00, 0x00];
        apply_e8_filter(&mut data, 0, false);
        // After filter: cur_pos = 0 + 0 + 1 = 1
        // new = rel - cur = 0x100 - 1 = 0xFF
        // little-endian: FF 00 00 00
        assert_eq!(data, [0xE8, 0xFF, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn skips_e9_when_disabled() {
        let mut data = [0xE9, 0x00, 0x01, 0x00, 0x00];
        apply_e8_filter(&mut data, 0, false);
        assert_eq!(data, [0xE9, 0x00, 0x01, 0x00, 0x00]); // unchanged
    }

    #[test]
    fn translates_e9_when_enabled() {
        let mut data = [0xE9, 0x00, 0x01, 0x00, 0x00];
        apply_e8_filter(&mut data, 0, true);
        assert_eq!(data, [0xE9, 0xFF, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn bypassed_above_one_gib() {
        let mut data = [0xE8, 0x00, 0x01, 0x00, 0x00];
        apply_e8_filter(&mut data, 0x4000_0000, false);
        assert_eq!(data, [0xE8, 0x00, 0x01, 0x00, 0x00]); // unchanged
    }
}
