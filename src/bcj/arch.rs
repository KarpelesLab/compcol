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

/// Running state for the x86 converter: xz's `prev_mask` plus `prev_pos`,
/// the absolute position of the last `E8`/`E9` opcode seen, so the mask
/// decays by the true distance between opcodes — including across converter
/// calls.
#[derive(Debug, Clone, Copy, Default)]
pub struct X86State {
    prev_mask: u32,
    prev_pos: u32,
    /// `false` until the first call; xz initialises `prev_pos` to
    /// `start - 5` (i.e. "no recent opcode").
    seen: bool,
}

#[inline]
fn x86_test86(b: u8) -> bool {
    b == 0x00 || b == 0xFF
}

// Mask helper tables, indexed by `prev_mask >> 1` (xz `simple/x86.c`).
const X86_MASK_TO_ALLOWED: [bool; 8] = [true, true, true, false, true, false, false, false];
const X86_MASK_TO_BIT_NUMBER: [u32; 8] = [0, 1, 2, 2, 3, 3, 3, 3];

impl X86 {
    /// Port of xz's `x86_code` (`liblzma/simple/x86.c`). Returns the number
    /// of bytes whose transform is final (the rest is an incomplete tail the
    /// engine retains). `st` is left describing exactly the returned
    /// boundary, so the result is independent of how the input is chunked.
    fn convert_inner(data: &mut [u8], ip: u32, encode: bool, st: &mut X86State) -> usize {
        let len = data.len();
        if len < 5 {
            // Not enough for opcode + 4-byte operand; emit nothing as final
            // so the tail is retried when more data arrives. (At final flush
            // the engine forwards these raw, which is correct: a partial or
            // operand-less tail is never converted.)
            return 0;
        }
        let mut prev_mask = st.prev_mask;
        let mut prev_pos = if st.seen {
            st.prev_pos
        } else {
            ip.wrapping_sub(5)
        };
        if ip.wrapping_sub(prev_pos) > 5 {
            prev_pos = ip.wrapping_sub(5);
        }

        // Scan every opcode position whose 4-byte operand is buffered.
        let limit = len - 5;
        let mut buffer_pos = 0usize;
        while buffer_pos <= limit {
            let b = data[buffer_pos];
            if b != 0xE8 && b != 0xE9 {
                buffer_pos += 1;
                continue;
            }

            // Decay the mask by the distance since the previous opcode.
            let here = ip.wrapping_add(buffer_pos as u32);
            let offset = here.wrapping_sub(prev_pos);
            prev_pos = here;
            if offset > 5 {
                prev_mask = 0;
            } else {
                for _ in 0..offset {
                    prev_mask &= 0x77;
                    prev_mask <<= 1;
                }
            }

            let b4 = data[buffer_pos + 4];
            if x86_test86(b4)
                && X86_MASK_TO_ALLOWED[((prev_mask >> 1) & 0x7) as usize]
                && (prev_mask >> 1) < 0x10
            {
                let mut src = rd_le32(&data[buffer_pos + 1..]);
                let pos = here.wrapping_add(5);
                let mut dest;
                loop {
                    dest = if encode {
                        src.wrapping_add(pos)
                    } else {
                        src.wrapping_sub(pos)
                    };
                    if prev_mask == 0 {
                        break;
                    }
                    let i = X86_MASK_TO_BIT_NUMBER[(prev_mask >> 1) as usize];
                    let tb = (dest >> (24 - i * 8)) as u8;
                    if !x86_test86(tb) {
                        break;
                    }
                    src = dest ^ ((1u32 << (32 - i * 8)).wrapping_sub(1));
                }
                // MS byte is forced to 0x00/0xFF by sign-extending bit 24.
                let top = if (dest >> 24) & 1 != 0 { 0xFFu32 } else { 0 };
                let outv = (dest & 0x00FF_FFFF) | (top << 24);
                wr_le32(&mut data[buffer_pos + 1..], outv);
                buffer_pos += 5;
                prev_mask = 0;
            } else {
                buffer_pos += 1;
                prev_mask |= 1;
                if x86_test86(b4) {
                    prev_mask |= 0x10;
                }
            }
        }

        st.prev_mask = prev_mask;
        st.prev_pos = prev_pos;
        st.seen = true;
        buffer_pos
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
                // ADRP (xz `simple/arm64.c`): immlo bits[30:29], immhi
                // bits[23:5]. Only immediates within +/-512 MiB (the top
                // four bits of the 21-bit value all equal) are converted;
                // the converted value keeps 18 bits and sign-extends bit 17
                // into immhi's top three bits.
                let src = ((instr >> 29) & 0x3) | ((instr >> 3) & 0x001F_FFFC);
                if (src.wrapping_add(0x0002_0000) & 0x001C_0000) == 0 {
                    let pagepc = pc >> 12;
                    let dest = if encode {
                        src.wrapping_add(pagepc)
                    } else {
                        src.wrapping_sub(pagepc)
                    };
                    let out = (instr & 0x9000_001F)
                        | ((dest & 0x3) << 29)
                        | ((dest & 0x0003_FFFC) << 3)
                        | (0u32.wrapping_sub(dest & 0x0002_0000) & 0x00E0_0000);
                    wr_le32(&mut data[i..], out);
                }
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

/// RISC-V converter (xz `simple/riscv.c`, filter ID `0x0B`).
///
/// Converts `JAL` with `rd` = `x1`/`x5` (the absolute target is stored in a
/// byte order that compresses well) and `AUIPC` + `inst2` pairs (rewritten
/// into a "special" `AUIPC` with `rd` = `x0`/`x2` followed by the big-endian
/// absolute address). Instructions are 2-byte aligned (compressed ISA).
#[derive(Debug, Clone, Copy, Default)]
pub struct RiscV;

/// True when `auipc` + `inst2` is *not* a pair whose `inst2` is a 32-bit
/// instruction using the `AUIPC`'s `rd` as `rs1`.
#[inline]
fn riscv_not_auipc_pair(auipc: u32, inst2: u32) -> bool {
    ((auipc << 8) ^ inst2.wrapping_sub(3)) & 0xF8003 != 0
}

/// True when an `AUIPC` with `rd` = `x0`/`x2` is *not* one the encoder
/// could have produced as a "special" (converted) `AUIPC`.
#[inline]
fn riscv_not_special_auipc(auipc: u32, rs1: u32) -> bool {
    (auipc.wrapping_sub(0x3117) << 18) >= (rs1 & 0x1D)
}

impl RiscV {
    fn encode(data: &mut [u8], now_pos: u32) -> usize {
        if data.len() < 8 {
            return 0;
        }
        let size = data.len() - 8;
        let mut i = 0usize;
        while i <= size {
            let b0 = data[i] as u32;
            if b0 == 0xEF {
                // JAL
                let b1 = data[i + 1] as u32;
                if b1 & 0x0D != 0 {
                    i += 2;
                    continue;
                }
                let b2 = data[i + 2] as u32;
                let b3 = data[i + 3] as u32;
                let pc = now_pos.wrapping_add(i as u32);
                let addr = (((b1 & 0xF0) << 8)
                    | ((b2 & 0x0F) << 16)
                    | ((b2 & 0x10) << 7)
                    | ((b2 & 0xE0) >> 4)
                    | ((b3 & 0x7F) << 4)
                    | ((b3 & 0x80) << 13))
                    .wrapping_add(pc);
                data[i + 1] = ((b1 & 0x0F) | ((addr >> 13) & 0xF0)) as u8;
                data[i + 2] = (addr >> 9) as u8;
                data[i + 3] = (addr >> 1) as u8;
                i += 4;
            } else if b0 & 0x7F == 0x17 {
                // AUIPC
                let inst = rd_le32(&data[i..]);
                if inst & 0xE80 != 0 {
                    // rd is neither x0 nor x2.
                    let inst2 = rd_le32(&data[i + 4..]);
                    if riscv_not_auipc_pair(inst, inst2) {
                        i += 6;
                        continue;
                    }
                    let addr = (inst & 0xFFFF_F000)
                        .wrapping_add(inst2 >> 20)
                        .wrapping_sub((inst2 >> 19) & 0x1000)
                        .wrapping_add(now_pos.wrapping_add(i as u32));
                    wr_le32(&mut data[i..], 0x17 | (2 << 7) | (inst2 << 12));
                    wr_be32(&mut data[i + 4..], addr);
                } else {
                    // rd is x0 or x2: swap a "fake" pair so the decoder can
                    // tell it apart from a converted one.
                    let fake_rs1 = inst >> 27;
                    if riscv_not_special_auipc(inst, fake_rs1) {
                        i += 4;
                        continue;
                    }
                    let fake_addr = rd_le32(&data[i + 4..]);
                    let fake_inst2 = (inst >> 12) | (fake_addr << 20);
                    wr_le32(
                        &mut data[i..],
                        0x17 | (fake_rs1 << 7) | (fake_addr & 0xFFFF_F000),
                    );
                    wr_le32(&mut data[i + 4..], fake_inst2);
                }
                i += 8;
            } else {
                i += 2;
            }
        }
        i
    }

    fn decode(data: &mut [u8], now_pos: u32) -> usize {
        if data.len() < 8 {
            return 0;
        }
        let size = data.len() - 8;
        let mut i = 0usize;
        while i <= size {
            let b0 = data[i] as u32;
            if b0 == 0xEF {
                // JAL
                let b1 = data[i + 1] as u32;
                if b1 & 0x0D != 0 {
                    i += 2;
                    continue;
                }
                let b2 = data[i + 2] as u32;
                let b3 = data[i + 3] as u32;
                let pc = now_pos.wrapping_add(i as u32);
                let addr = (((b1 & 0xF0) << 13) | (b2 << 9) | (b3 << 1)).wrapping_sub(pc);
                data[i + 1] = ((b1 & 0x0F) | ((addr >> 8) & 0xF0)) as u8;
                data[i + 2] =
                    (((addr >> 16) & 0x0F) | ((addr >> 7) & 0x10) | ((addr << 4) & 0xE0)) as u8;
                data[i + 3] = (((addr >> 4) & 0x7F) | ((addr >> 13) & 0x80)) as u8;
                i += 4;
            } else if b0 & 0x7F == 0x17 {
                // AUIPC
                let mut inst = rd_le32(&data[i..]);
                let inst2;
                if inst & 0xE80 != 0 {
                    // rd is neither x0 nor x2: a "fake" pair the encoder
                    // swapped; swap it back.
                    let fake = rd_le32(&data[i + 4..]);
                    if riscv_not_auipc_pair(inst, fake) {
                        i += 6;
                        continue;
                    }
                    inst2 = (inst & 0xFFFF_F000).wrapping_add(fake >> 20);
                    inst = 0x17 | (2 << 7) | (fake << 12);
                } else {
                    // rd is x0 or x2: a converted pair.
                    let inst2_rs1 = inst >> 27;
                    if riscv_not_special_auipc(inst, inst2_rs1) {
                        i += 4;
                        continue;
                    }
                    let addr = rd_be32(&data[i + 4..]).wrapping_sub(now_pos.wrapping_add(i as u32));
                    inst2 = (inst >> 12) | (addr << 20);
                    inst = 0x17 | (inst2_rs1 << 7) | (addr.wrapping_add(0x800) & 0xFFFF_F000);
                }
                wr_le32(&mut data[i..], inst);
                wr_le32(&mut data[i + 4..], inst2);
                i += 8;
            } else {
                i += 2;
            }
        }
        i
    }
}

impl BcjArch for RiscV {
    const NAME: &'static str = "bcj-riscv";
    const EXT: &'static str = "bcj-riscv";
    const ALIGN: usize = 2;
    type State = NoState;
    fn convert(data: &mut [u8], ip: u32, encode: bool, _: &mut NoState) -> usize {
        if encode {
            RiscV::encode(data, ip)
        } else {
            RiscV::decode(data, ip)
        }
    }
}
