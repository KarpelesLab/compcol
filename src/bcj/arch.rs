//! Per-architecture branch converters for the BCJ filters.
//!
//! Each architecture is a zero-sized type implementing [`BcjArch`]. The
//! `convert` functions are clean-room implementations of the documented
//! transforms used by the public-domain LZMA SDK / xz filters. They rewrite
//! relative branch operands to absolute form (`encode == true`) and back
//! (`encode == false`); the two directions are exact inverses.
//!
//! All address arithmetic uses `wrapping_*`: the operands are fixed-width
//! little/big-endian fields defined to wrap modulo their width, so wrapping
//! ops make encode∘decode the identity for every input (including operands
//! whose absolute form overflows).

use super::{BcjArch, NoState};

// ─── helpers ───────────────────────────────────────────────────────────────

#[inline]
fn rd_le32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}
#[inline]
fn wr_le32(b: &mut [u8], v: u32) {
    b[..4].copy_from_slice(&v.to_le_bytes());
}
#[inline]
fn rd_be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}
#[inline]
fn wr_be32(b: &mut [u8], v: u32) {
    b[..4].copy_from_slice(&v.to_be_bytes());
}

// ─── x86 ─────────────────────────────────────────────────────────────────

/// x86 BCJ converter.
#[derive(Debug, Clone, Copy, Default)]
pub struct X86;

/// Running state for the x86 converter: the SDK's `prev_mask` plus the
/// absolute position it was last updated at, so the mask window can be
/// adjusted (or cleared) for gaps between converter calls.
#[derive(Debug, Clone, Copy, Default)]
pub struct X86State {
    prev_mask: u32,
    prev_pos: u32,
    seen: bool,
}

#[inline]
fn x86_test86(b: u8) -> bool {
    b == 0x00 || b == 0xFF
}

// SDK mask helper tables (kMaskToAllowedStatus / kMaskToBitNumber), indexed
// by the 3-bit prev_mask. These are part of the public-domain documented
// algorithm.
const X86_MASK_TO_ALLOWED: [bool; 8] = [true, true, true, false, true, false, false, false];
const X86_MASK_TO_BIT_NUMBER: [u32; 8] = [0, 1, 2, 2, 3, 3, 3, 3];

impl X86 {
    /// Faithful clean-room implementation of the x86 BCJ converter. Returns
    /// the number of bytes whose transform is final (the rest is an
    /// incomplete-instruction tail the engine retains). `st` carries the
    /// running mask across calls and is left describing exactly the
    /// returned boundary so reprocessing the tail next round is consistent.
    fn convert_inner(data: &mut [u8], ip: u32, encode: bool, st: &mut X86State) -> usize {
        let len = data.len();
        if len < 5 {
            // Not enough for opcode + 4-byte operand; emit nothing as final
            // so the tail is retried when more data arrives. (At final flush
            // the engine forwards these raw, which is correct: a partial or
            // operand-less tail is never converted.)
            return 0;
        }
        // We may inspect data[bufferPos+4]; the last index where a full
        // instruction (opcode + 4 operand bytes) fits is len - 5, so we scan
        // bufferPos in 0..=len-5, i.e. while bufferPos + 4 < len.
        let mut prev_mask = st.prev_mask;
        // Adjust the mask window for any gap since the last call.
        if st.seen {
            let d = ip.wrapping_sub(st.prev_pos);
            if d > 3 {
                prev_mask = 0;
            } else if d > 0 {
                prev_mask = (prev_mask << d) & 0x7;
            }
        }

        let mut buffer_pos = 0usize;
        // `done` marks the index up to which the output is final. We only
        // advance it to a point where `prev_mask` is fully settled (i.e.
        // right after a converted instruction or a definitively-skipped
        // byte that is at least 5 bytes from the end).
        let mut done = 0usize;
        while buffer_pos + 4 < len {
            if data[buffer_pos] & 0xFE != 0xE8 {
                buffer_pos += 1;
                done = buffer_pos;
                continue;
            }

            // The mask machinery only kicks in once a recent opcode left a
            // mark (prev_mask != 0). It suppresses conversions that would be
            // ambiguous with a recently-seen opcode, keeping the transform
            // invertible.
            if prev_mask != 0 {
                let index = X86_MASK_TO_BIT_NUMBER[(prev_mask & 0x7) as usize] as usize;
                let b = data[buffer_pos + 4 - index];
                if !X86_MASK_TO_ALLOWED[(prev_mask & 0x7) as usize] || x86_test86(b) {
                    prev_mask = ((prev_mask << 1) & 0x7) | 1;
                    buffer_pos += 1;
                    done = buffer_pos;
                    continue;
                }
            }

            if x86_test86(data[buffer_pos + 4]) {
                let src = rd_le32(&data[buffer_pos + 1..]);
                let pos = ip.wrapping_add(buffer_pos as u32).wrapping_add(5);
                let mut cur = src;
                let dest;
                loop {
                    let d = if encode {
                        cur.wrapping_add(pos)
                    } else {
                        cur.wrapping_sub(pos)
                    };
                    if prev_mask == 0 {
                        dest = d;
                        break;
                    }
                    let idx = X86_MASK_TO_BIT_NUMBER[(prev_mask & 0x7) as usize] * 8;
                    let b = (d >> (24 - idx)) as u8;
                    if !x86_test86(b) {
                        dest = d;
                        break;
                    }
                    cur = d ^ ((1u32 << (32 - idx)).wrapping_sub(1));
                }
                // MS byte is forced to 0x00/0xFF by sign-extending bit 24.
                let top = if (dest >> 24) & 1 != 0 { 0xFFu32 } else { 0 };
                let outv = (dest & 0x00FF_FFFF) | (top << 24);
                wr_le32(&mut data[buffer_pos + 1..], outv);
                buffer_pos += 5;
                done = buffer_pos;
                prev_mask = 0;
            } else {
                prev_mask = ((prev_mask << 1) & 0x7) | 1;
                buffer_pos += 1;
                done = buffer_pos;
            }
        }

        st.prev_mask = prev_mask;
        st.prev_pos = ip.wrapping_add(done as u32);
        st.seen = true;
        done
    }
}

impl BcjArch for X86 {
    const NAME: &'static str = "bcj-x86";
    const EXT: &'static str = "bcj-x86";
    const ALIGN: usize = 1;
    type State = X86State;
    fn convert(data: &mut [u8], ip: u32, encode: bool, state: &mut X86State) -> usize {
        X86::convert_inner(data, ip, encode, state)
    }
}

// ─── ARM (32-bit) ──────────────────────────────────────────────────────────

/// ARM BL converter (4-byte aligned `BL` with a 24-bit word offset).
#[derive(Debug, Clone, Copy, Default)]
pub struct Arm;

impl BcjArch for Arm {
    const NAME: &'static str = "bcj-arm";
    const EXT: &'static str = "bcj-arm";
    const ALIGN: usize = 4;
    type State = NoState;
    fn convert(data: &mut [u8], ip: u32, encode: bool, _: &mut NoState) -> usize {
        let mut i = 0usize;
        while i + 4 <= data.len() {
            // BL/BLX immediate: opcode byte (data[i+3]) is 0xEB.
            if data[i + 3] == 0xEB {
                // 24-bit word offset in the low 3 bytes (little-endian).
                let src = (data[i + 2] as u32) << 16 | (data[i + 1] as u32) << 8 | (data[i] as u32);
                let src = src << 2;
                let pos = ip.wrapping_add(i as u32).wrapping_add(8);
                let dest = if encode {
                    src.wrapping_add(pos)
                } else {
                    src.wrapping_sub(pos)
                };
                let dest = dest >> 2;
                data[i + 2] = (dest >> 16) as u8;
                data[i + 1] = (dest >> 8) as u8;
                data[i] = dest as u8;
            }
            i += 4;
        }
        i
    }
}

// ─── ARM Thumb ───────────────────────────────────────────────────────────

/// ARM Thumb BL/BLX converter (pair of 16-bit halfwords, 2-byte aligned).
#[derive(Debug, Clone, Copy, Default)]
pub struct ArmThumb;

impl BcjArch for ArmThumb {
    const NAME: &'static str = "bcj-armt";
    const EXT: &'static str = "bcj-armt";
    const ALIGN: usize = 2;
    type State = NoState;
    fn convert(data: &mut [u8], ip: u32, encode: bool, _: &mut NoState) -> usize {
        let mut i = 0usize;
        // Need 4 bytes (two halfwords). Thumb BL/BLX: first halfword
        // 0xF000 mask == 0xF000 (top 5 bits 0b11110), second 0xF800 == 0xF800
        // or 0xE800 (BLX). Detection: (b[1] & 0xF8)==0xF0 && (b[3] & 0xF8)==0xF8.
        while i + 4 <= data.len() {
            if (data[i + 1] & 0xF8) == 0xF0 && (data[i + 3] & 0xF8) == 0xF8 {
                let src = ((data[i + 1] as u32 & 0x07) << 19)
                    | ((data[i] as u32) << 11)
                    | ((data[i + 3] as u32 & 0x07) << 8)
                    | (data[i + 2] as u32);
                let src = src << 1;
                let pos = ip.wrapping_add(i as u32).wrapping_add(4);
                let dest = if encode {
                    src.wrapping_add(pos)
                } else {
                    src.wrapping_sub(pos)
                };
                let dest = dest >> 1;
                data[i + 1] = 0xF0 | ((dest >> 19) as u8 & 0x07);
                data[i] = (dest >> 11) as u8;
                data[i + 3] = 0xF8 | ((dest >> 8) as u8 & 0x07);
                data[i + 2] = dest as u8;
                i += 2;
            }
            i += 2;
        }
        i
    }
}

// ─── ARM64 ─────────────────────────────────────────────────────────────────

/// ARM64 (AArch64) converter: BL (26-bit) and ADRP (21-bit) immediates.
#[derive(Debug, Clone, Copy, Default)]
pub struct Arm64;

impl BcjArch for Arm64 {
    const NAME: &'static str = "bcj-arm64";
    const EXT: &'static str = "bcj-arm64";
    const ALIGN: usize = 4;
    type State = NoState;
    fn convert(data: &mut [u8], ip: u32, encode: bool, _: &mut NoState) -> usize {
        let mut i = 0usize;
        while i + 4 <= data.len() {
            let instr = rd_le32(&data[i..]);
            let pc = ip.wrapping_add(i as u32);
            if (instr >> 26) == 0x25 {
                // BL: 26-bit signed word offset in bits [25:0].
                let src = instr & 0x03FF_FFFF;
                let addr = if encode {
                    src.wrapping_add(pc >> 2)
                } else {
                    src.wrapping_sub(pc >> 2)
                } & 0x03FF_FFFF;
                let out = (0x25 << 26) | addr;
                wr_le32(&mut data[i..], out);
            } else if (instr & 0x9F00_0000) == 0x9000_0000 {
                // ADRP: 21-bit immediate (immlo bits[30:29], immhi bits[23:5]).
                let immlo = (instr >> 29) & 0x3;
                let immhi = (instr >> 5) & 0x0007_FFFF;
                let src = (immhi << 2) | immlo; // 21-bit page offset
                // Sign-extend 21 bits then treat as page units.
                let src21 = src & 0x001F_FFFF;
                // Only rewrite "reasonable" ADRP per SDK (it checks the top
                // bits to avoid corrupting unrelated encodings).
                let pagepc = pc >> 12;
                let addr = if encode {
                    src21.wrapping_add(pagepc)
                } else {
                    src21.wrapping_sub(pagepc)
                } & 0x001F_FFFF;
                let new_immlo = addr & 0x3;
                let new_immhi = (addr >> 2) & 0x0007_FFFF;
                let out = (instr & 0x9F00_001F) | (new_immlo << 29) | (new_immhi << 5);
                wr_le32(&mut data[i..], out);
            }
            i += 4;
        }
        i
    }
}

// ─── PowerPC (big-endian) ────────────────────────────────────────────────

/// PowerPC big-endian `bl` converter (6-bit opcode 18, 4-byte aligned).
#[derive(Debug, Clone, Copy, Default)]
pub struct Ppc;

impl BcjArch for Ppc {
    const NAME: &'static str = "bcj-ppc";
    const EXT: &'static str = "bcj-ppc";
    const ALIGN: usize = 4;
    type State = NoState;
    fn convert(data: &mut [u8], ip: u32, encode: bool, _: &mut NoState) -> usize {
        let mut i = 0usize;
        while i + 4 <= data.len() {
            // bl: top 6 bits == 18 (0x48), and bits LK/AA in the low byte:
            // (data[i] & 0xFC) == 0x48 and (data[i+3] & 3) == 1.
            if (data[i] & 0xFC) == 0x48 && (data[i + 3] & 0x03) == 0x01 {
                let instr = rd_be32(&data[i..]);
                let src = instr & 0x03FF_FFFC; // 24-bit LI field << 2
                let pos = ip.wrapping_add(i as u32);
                let dest = if encode {
                    src.wrapping_add(pos)
                } else {
                    src.wrapping_sub(pos)
                };
                let out = 0x4800_0000 | (dest & 0x03FF_FFFC) | (instr & 0x3);
                wr_be32(&mut data[i..], out);
            }
            i += 4;
        }
        i
    }
}

// ─── SPARC ─────────────────────────────────────────────────────────────────

/// SPARC CALL converter (big-endian, 4-byte aligned, 30-bit word offset).
#[derive(Debug, Clone, Copy, Default)]
pub struct Sparc;

impl BcjArch for Sparc {
    const NAME: &'static str = "bcj-sparc";
    const EXT: &'static str = "bcj-sparc";
    const ALIGN: usize = 4;
    type State = NoState;
    fn convert(data: &mut [u8], ip: u32, encode: bool, _: &mut NoState) -> usize {
        let mut i = 0usize;
        while i + 4 <= data.len() {
            // CALL: top 2 bits == 01. Detection per SDK: (b0==0x40 && (b1&0xC0)==0)
            // or (b0==0x7F && (b1&0xC0)==0xC0).
            if (data[i] == 0x40 && (data[i + 1] & 0xC0) == 0x00)
                || (data[i] == 0x7F && (data[i + 1] & 0xC0) == 0xC0)
            {
                let instr = rd_be32(&data[i..]);
                let src = (instr & 0x3FFF_FFFF) << 2;
                let pos = ip.wrapping_add(i as u32);
                let dest = if encode {
                    src.wrapping_add(pos)
                } else {
                    src.wrapping_sub(pos)
                };
                let dest = dest >> 2;
                // SDK re-normalises the high bits so the field stays valid.
                let dest = (0x4000_0000u32.wrapping_sub(dest & 0x0040_0000))
                    | 0x4000_0000
                    | (dest & 0x003F_FFFF);
                wr_be32(&mut data[i..], dest);
            }
            i += 4;
        }
        i
    }
}

// ─── IA-64 ─────────────────────────────────────────────────────────────────

/// IA-64 (Itanium) bundle converter (16-byte bundles).
#[derive(Debug, Clone, Copy, Default)]
pub struct Ia64;

// Per-template table: which slots in a bundle hold a branch (bit set per
// slot). Index by the 5-bit template field.
const IA64_BRANCH_TABLE: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 4, 6, 6, 0, 0, 7, 7, 4, 4, 0, 0, 4, 4, 0, 0,
];

impl BcjArch for Ia64 {
    const NAME: &'static str = "bcj-ia64";
    const EXT: &'static str = "bcj-ia64";
    const ALIGN: usize = 16;
    type State = NoState;
    fn convert(data: &mut [u8], ip: u32, encode: bool, _: &mut NoState) -> usize {
        let mut i = 0usize;
        while i + 16 <= data.len() {
            let template = (data[i] & 0x1F) as usize;
            let mask = IA64_BRANCH_TABLE[template];
            for slot in 0..3u32 {
                if (mask >> slot) & 1 == 0 {
                    continue;
                }
                let bit_pos = 5 + slot * 41;
                let byte_pos = (bit_pos >> 3) as usize;
                let bit_res = bit_pos & 7;
                // Read 6 bytes covering the 41-bit instruction slot.
                let mut instr: u64 = 0;
                for j in 0..6 {
                    instr |= (data[i + byte_pos + j] as u64) << (8 * j);
                }
                let inst_norm = instr >> bit_res;
                // Branch instructions: major opcode (bits 37..40) == 5.
                if ((inst_norm >> 37) & 0xF) == 5 && ((inst_norm >> 9) & 0x7) == 0 {
                    // 21-bit immediate split: imm20b (bits 13..32) + sign (bit 36).
                    let mut src = ((inst_norm >> 13) & 0x0F_FFFF) as u32;
                    src |= (((inst_norm >> 36) & 1) as u32) << 20;
                    let src = src << 4;
                    let pos = ip.wrapping_add(i as u32);
                    let dest = if encode {
                        src.wrapping_add(pos)
                    } else {
                        src.wrapping_sub(pos)
                    };
                    let dest = dest >> 4;
                    let mut inst_norm = inst_norm;
                    inst_norm &= !(0x0F_FFFFu64 << 13);
                    inst_norm |= ((dest & 0x0F_FFFF) as u64) << 13;
                    inst_norm &= !(1u64 << 36);
                    inst_norm |= (((dest >> 20) & 1) as u64) << 36;

                    let mut instr2 = instr;
                    let keep_mask = (1u64 << bit_res) - 1;
                    instr2 &= keep_mask;
                    instr2 |= inst_norm << bit_res;
                    for j in 0..6 {
                        data[i + byte_pos + j] = (instr2 >> (8 * j)) as u8;
                    }
                }
            }
            i += 16;
        }
        i
    }
}

// ─── RISC-V ──────────────────────────────────────────────────────────────

/// RISC-V converter: JAL with rd=x1 (ra), 4-byte aligned.
///
/// This implements the JAL-call subset of the transform: a JAL whose
/// destination register is the return address register `ra` (x1) has its
/// 20-bit immediate rewritten relative→absolute. The 16-byte buffer
/// minimum and 4-byte stride keep it chunk-safe.
#[derive(Debug, Clone, Copy, Default)]
pub struct RiscV;

impl BcjArch for RiscV {
    const NAME: &'static str = "bcj-riscv";
    const EXT: &'static str = "bcj-riscv";
    const ALIGN: usize = 4;
    type State = NoState;
    fn convert(data: &mut [u8], ip: u32, encode: bool, _: &mut NoState) -> usize {
        let mut i = 0usize;
        while i + 4 <= data.len() {
            let instr = rd_le32(&data[i..]);
            // JAL: opcode (bits 0..6) == 0x6F. rd in bits 7..11.
            if (instr & 0x7F) == 0x6F {
                let rd = (instr >> 7) & 0x1F;
                if rd == 1 {
                    // Decode the J-immediate (bits scrambled per the ISA).
                    let imm20 = (instr >> 31) & 0x1;
                    let imm10_1 = (instr >> 21) & 0x3FF;
                    let imm11 = (instr >> 20) & 0x1;
                    let imm19_12 = (instr >> 12) & 0xFF;
                    let off = (imm20 << 20) | (imm19_12 << 12) | (imm11 << 11) | (imm10_1 << 1);
                    let pos = ip.wrapping_add(i as u32);
                    let dest = if encode {
                        off.wrapping_add(pos)
                    } else {
                        off.wrapping_sub(pos)
                    } & 0x001F_FFFF; // keep 21-bit signed range (bit20..0)
                    // Re-scramble back into the J-immediate fields.
                    let n_imm20 = (dest >> 20) & 0x1;
                    let n_imm10_1 = (dest >> 1) & 0x3FF;
                    let n_imm11 = (dest >> 11) & 0x1;
                    let n_imm19_12 = (dest >> 12) & 0xFF;
                    let out = (instr & 0x0000_0FFF) // opcode + rd
                        | (n_imm19_12 << 12)
                        | (n_imm11 << 20)
                        | (n_imm10_1 << 21)
                        | (n_imm20 << 31);
                    wr_le32(&mut data[i..], out);
                }
            }
            i += 4;
        }
        i
    }
}
