//! RAR 3.x post-decompression filters.
//!
//! ## In-band standard filters (main symbol 257)
//!
//! RAR3 embeds filters as bytecode programs for a stack-based RISC-like VM
//! ("RarVM") in symbol 257 of the main code. We do **not** interpret
//! arbitrary programs: WinRAR's compressor only ever emits a fixed set of
//! standard programs, so — like libarchive and unrar in practice — we
//! recognize the standard programs (by bytecode length + CRC-32,
//! [`recognize_program`]) and run native transforms:
//!
//! - **Delta** (channel de-interleave; emitted for bitmaps, WAV audio and
//!   other channel-interleaved content; channel count arrives in VM
//!   register 0),
//! - **x86 E8** and **E8/E9** call(-jump) translation.
//!
//! The transforms themselves live in [`crate::rar_filters`], shared with
//! the RAR5 decoder, and were validated byte-for-byte against WinRAR
//! archives (UnRAR 7.23 ground truth). Streams declaring any other program
//! (custom bytecode, or the legacy Itanium/RGB/audio-predictor standard
//! programs, which current archivers no longer emit) fail with
//! `Error::Unsupported` — never wrong bytes.
//!
//! ## Stand-alone E8/E9 pass
//!
//! Separately, the **stand-alone Intel E8/E9 call translation pass**
//! ([`apply_e8_filter`]) can be activated by the caller via
//! `Decoder::with_e8_filter`. It predates in-band filter support and is an
//! LZX-style whole-output transform, *not* the same arithmetic as the
//! in-band x86 filter; it is kept for callers that relied on it.

use crate::checksum::Crc32;
use crate::error::Error;
use crate::rar_filters::{delta_decode, x86_e8_decode};

/// A standard RarVM filter program we recognize and can run natively.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum StdProgram {
    /// Channel de-interleave; channel count comes from VM register 0.
    Delta,
    /// x86 `0xE8` (CALL) relative-address restore.
    X86Call,
    /// x86 `0xE8`/`0xE9` (CALL/JMP) relative-address restore.
    X86CallJmp,
}

/// Identify a standard filter program from its bytecode.
///
/// WinRAR's compressor emits each standard filter as a fixed byte string,
/// so `(length, CRC-32)` is a stable fingerprint — the same recognition
/// scheme libarchive uses. The Delta and x86-E8 fingerprints below were
/// computed from programs extracted out of real rar 6.24 archives (this
/// crate's differential corpus); the E8E9 fingerprint (emitted by older
/// WinRAR 3.x builds) matches the value documented in libarchive
/// (BSD-licensed `archive_read_support_format_rar.c`).
///
/// Returns `None` for anything else — including the legacy Itanium / RGB /
/// audio-predictor standard programs, which no current archiver emits.
pub(super) fn recognize_program(code: &[u8]) -> Option<StdProgram> {
    let mut crc = Crc32::new();
    crc.update(code);
    match (code.len(), crc.finalize()) {
        (29, 0x0E06_077D) => Some(StdProgram::Delta),
        (53, 0xAD57_6887) => Some(StdProgram::X86Call),
        (57, 0x3CD7_E57E) => Some(StdProgram::X86CallJmp),
        _ => None,
    }
}

/// A parsed, scheduled instance of a standard filter: it rewrites the
/// window `[start, start + length)` of the unpacked stream.
#[derive(Debug, Clone, Copy)]
pub(super) struct PendingFilter {
    /// Absolute byte offset in the unpacked stream.
    pub start: u64,
    pub length: u32,
    pub program: StdProgram,
    /// VM register 0 at declaration time — the Delta channel count.
    pub channels: u32,
}

/// Delta channel-count ceiling, matching unrar's `MAX3_UNPACK_CHANNELS`
/// (1024). unrar refuses to *run* the transform beyond it and emits the
/// raw bytes with success; this crate fails closed instead (same policy as
/// unfinished filter windows — surfacing an error beats returning bytes
/// that only a container CRC could flag).
const MAX_DELTA_CHANNELS: u32 = 1024;

/// Run a scheduled filter over its region (already sliced by the caller).
///
/// The x86 transforms use the **unmasked** 32-bit position base (RAR3 VM
/// semantics — see [`x86_e8_decode`]); `filter.start` is file-relative,
/// which for solid archives means member-relative (unrar seeds the VM with
/// its per-member written-size counter).
pub(super) fn apply_pending(filter: &PendingFilter, region: &mut [u8]) -> Result<(), Error> {
    match filter.program {
        StdProgram::Delta => {
            if filter.channels == 0 || filter.channels > MAX_DELTA_CHANNELS {
                return Err(Error::Corrupt);
            }
            // More channels than bytes is well-defined (trailing planes are
            // empty) and unrar runs it; no length-based bound here.
            delta_decode(filter.channels as usize, region);
        }
        StdProgram::X86Call => x86_e8_decode(filter.start, region, false, false),
        StdProgram::X86CallJmp => x86_e8_decode(filter.start, region, true, false),
    }
    Ok(())
}

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
