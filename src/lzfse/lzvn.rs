//! LZVN block decoder.
//!
//! Faithful port of Apple's `lzvn_decode_base.c` (BSD-3-Apple), restricted
//! to the single-call shape this crate uses (the input block is fully
//! buffered by the outer decoder before we run, so we don't need Apple's
//! mid-instruction save/resume machinery).
//!
//! The opcode dispatch table comes directly from Apple's reference; see
//! the comments next to each label for the bit-layout of that opcode.

use alloc::vec::Vec;

use crate::error::Error;

/// Decoded opcode classes (one per byte of the 256-entry dispatch table).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OpClass {
    /// "small distance" — `LLMMMDDD DDDDDDDD LITERAL` (2 + L bytes).
    SmlD,
    /// "medium distance" — `101LLMMM DDDDDDMM DDDDDDDD LITERAL` (3 + L bytes).
    MedD,
    /// "large distance" — `LLMMM111 DDDDDDDD DDDDDDDD LITERAL` (3 + L bytes).
    LrgD,
    /// "previous distance" — `LLMMM110 LITERAL` (1 + L bytes).
    PreD,
    /// "small literal" — `1110LLLL LITERAL` (1 + L bytes).
    SmlL,
    /// "large literal" — `11100000 LLLLLLLL LITERAL` (2 + L bytes).
    LrgL,
    /// "small match" — `1111MMMM` (1 byte).
    SmlM,
    /// "large match" — `11110000 MMMMMMMM` (2 bytes).
    LrgM,
    /// EOS marker. 8-byte total (the opcode 0x06 + 7 zero bytes).
    Eos,
    /// 1-byte no-op (opcodes 0x0e, 0x16).
    Nop,
    /// Undefined / reserved — error if encountered.
    Udef,
}

/// Apple's 256-entry opcode class table.
const OPC_TBL: [OpClass; 256] = {
    use OpClass::*;
    let mut t = [Udef; 256];
    // 0x00..=0x07
    t[0] = SmlD;
    t[1] = SmlD;
    t[2] = SmlD;
    t[3] = SmlD;
    t[4] = SmlD;
    t[5] = SmlD;
    t[6] = Eos;
    t[7] = LrgD;
    // 0x08..=0x0f
    t[8] = SmlD;
    t[9] = SmlD;
    t[10] = SmlD;
    t[11] = SmlD;
    t[12] = SmlD;
    t[13] = SmlD;
    t[14] = Nop;
    t[15] = LrgD;
    // 0x10..=0x17
    t[16] = SmlD;
    t[17] = SmlD;
    t[18] = SmlD;
    t[19] = SmlD;
    t[20] = SmlD;
    t[21] = SmlD;
    t[22] = Nop;
    t[23] = LrgD;
    // 0x18..=0x1f
    t[24] = SmlD;
    t[25] = SmlD;
    t[26] = SmlD;
    t[27] = SmlD;
    t[28] = SmlD;
    t[29] = SmlD;
    t[30] = Udef;
    t[31] = LrgD;
    // 0x20..=0x27
    t[32] = SmlD;
    t[33] = SmlD;
    t[34] = SmlD;
    t[35] = SmlD;
    t[36] = SmlD;
    t[37] = SmlD;
    t[38] = Udef;
    t[39] = LrgD;
    // 0x28..=0x2f
    t[40] = SmlD;
    t[41] = SmlD;
    t[42] = SmlD;
    t[43] = SmlD;
    t[44] = SmlD;
    t[45] = SmlD;
    t[46] = Udef;
    t[47] = LrgD;
    // 0x30..=0x37
    t[48] = SmlD;
    t[49] = SmlD;
    t[50] = SmlD;
    t[51] = SmlD;
    t[52] = SmlD;
    t[53] = SmlD;
    t[54] = Udef;
    t[55] = LrgD;
    // 0x38..=0x3f
    t[56] = SmlD;
    t[57] = SmlD;
    t[58] = SmlD;
    t[59] = SmlD;
    t[60] = SmlD;
    t[61] = SmlD;
    t[62] = Udef;
    t[63] = LrgD;
    // 0x40..=0x47
    t[64] = SmlD;
    t[65] = SmlD;
    t[66] = SmlD;
    t[67] = SmlD;
    t[68] = SmlD;
    t[69] = SmlD;
    t[70] = PreD;
    t[71] = LrgD;
    // 0x48..=0x4f
    t[72] = SmlD;
    t[73] = SmlD;
    t[74] = SmlD;
    t[75] = SmlD;
    t[76] = SmlD;
    t[77] = SmlD;
    t[78] = PreD;
    t[79] = LrgD;
    // 0x50..=0x57
    t[80] = SmlD;
    t[81] = SmlD;
    t[82] = SmlD;
    t[83] = SmlD;
    t[84] = SmlD;
    t[85] = SmlD;
    t[86] = PreD;
    t[87] = LrgD;
    // 0x58..=0x5f
    t[88] = SmlD;
    t[89] = SmlD;
    t[90] = SmlD;
    t[91] = SmlD;
    t[92] = SmlD;
    t[93] = SmlD;
    t[94] = PreD;
    t[95] = LrgD;
    // 0x60..=0x67
    t[96] = SmlD;
    t[97] = SmlD;
    t[98] = SmlD;
    t[99] = SmlD;
    t[100] = SmlD;
    t[101] = SmlD;
    t[102] = PreD;
    t[103] = LrgD;
    // 0x68..=0x6f
    t[104] = SmlD;
    t[105] = SmlD;
    t[106] = SmlD;
    t[107] = SmlD;
    t[108] = SmlD;
    t[109] = SmlD;
    t[110] = PreD;
    t[111] = LrgD;
    // 0x70..=0x7f: all undef
    // (already initialized to Udef)
    // 0x80..=0x87
    t[128] = SmlD;
    t[129] = SmlD;
    t[130] = SmlD;
    t[131] = SmlD;
    t[132] = SmlD;
    t[133] = SmlD;
    t[134] = PreD;
    t[135] = LrgD;
    // 0x88..=0x8f
    t[136] = SmlD;
    t[137] = SmlD;
    t[138] = SmlD;
    t[139] = SmlD;
    t[140] = SmlD;
    t[141] = SmlD;
    t[142] = PreD;
    t[143] = LrgD;
    // 0x90..=0x97
    t[144] = SmlD;
    t[145] = SmlD;
    t[146] = SmlD;
    t[147] = SmlD;
    t[148] = SmlD;
    t[149] = SmlD;
    t[150] = PreD;
    t[151] = LrgD;
    // 0x98..=0x9f
    t[152] = SmlD;
    t[153] = SmlD;
    t[154] = SmlD;
    t[155] = SmlD;
    t[156] = SmlD;
    t[157] = SmlD;
    t[158] = PreD;
    t[159] = LrgD;
    // 0xa0..=0xbf: med_d
    let mut i = 160;
    while i < 192 {
        t[i] = MedD;
        i += 1;
    }
    // 0xc0..=0xc7
    t[192] = SmlD;
    t[193] = SmlD;
    t[194] = SmlD;
    t[195] = SmlD;
    t[196] = SmlD;
    t[197] = SmlD;
    t[198] = PreD;
    t[199] = LrgD;
    // 0xc8..=0xcf
    t[200] = SmlD;
    t[201] = SmlD;
    t[202] = SmlD;
    t[203] = SmlD;
    t[204] = SmlD;
    t[205] = SmlD;
    t[206] = PreD;
    t[207] = LrgD;
    // 0xd0..=0xdf: udef
    // 0xe0..=0xef: literals
    t[224] = LrgL;
    let mut i = 225;
    while i < 240 {
        t[i] = SmlL;
        i += 1;
    }
    // 0xf0..=0xff: matches
    t[240] = LrgM;
    let mut i = 241;
    while i < 256 {
        t[i] = SmlM;
        i += 1;
    }
    t
};

/// Decode a complete LZVN block.
///
/// `src` is the LZVN payload (caller-buffered, exactly `n_payload` bytes
/// long when called by our outer decoder). `expected_decoded_size` is the
/// `n_raw_bytes` field from the `bvxn` header — Apple's encoder produces
/// blocks whose decoded length matches this exactly.
pub(crate) fn decode_block(
    src: &[u8],
    n_payload: usize,
    expected_decoded_size: usize,
    out: &mut Vec<u8>,
) -> Result<(), Error> {
    if src.len() < n_payload {
        return Err(Error::UnexpectedEnd);
    }
    let src = &src[..n_payload];
    let start_out_len = out.len();
    let mut sp = 0usize;
    let mut d_prev: usize = 0;

    loop {
        if sp >= src.len() {
            // No more bytes. Either the block ended cleanly via Eos or it's
            // truncated.
            if out.len() - start_out_len == expected_decoded_size {
                return Ok(());
            }
            return Err(Error::Corrupt);
        }
        let op = src[sp];
        let class = OPC_TBL[op as usize];

        match class {
            OpClass::SmlD => {
                // op = LLMMMDDD; followed by 1 byte D_low; then L literals.
                let l = ((op >> 6) & 0x3) as usize;
                let m = (((op >> 3) & 0x7) as usize) + 3;
                let opc_len = 2;
                // Need: opc_len + L + at least 1 byte for next opcode (or EOS).
                // For the last opcode the EOS check is not strict — but Apple
                // requires `src_len <= opc_len + L` for "truncated", i.e. we
                // need src_len > opc_len + L (strict).
                if sp + opc_len + l >= src.len() {
                    // Could be Eos coming next, but actually Apple's tight
                    // check is `<= opc_len + L`. We accept exactly the case
                    // where we have just enough for opc + literals AND we
                    // expect to land on Eos next.
                    if sp + opc_len + l > src.len() {
                        return Err(Error::Corrupt);
                    }
                    // Equal to src.len() — that means there's no next opcode
                    // byte. Apple treats this as truncated.
                    return Err(Error::Corrupt);
                }
                let d = (((op & 0x7) as usize) << 8) | src[sp + 1] as usize;
                sp += opc_len;
                // Copy literal.
                out.extend_from_slice(&src[sp..sp + l]);
                sp += l;
                // Match copy.
                lz_copy(out, d, m, start_out_len)?;
                d_prev = d;
            }
            OpClass::MedD => {
                // op = 101LLMMM; bytes [1..3] = DDDDDDMM DDDDDDDD (LE16).
                let l = ((op >> 3) & 0x3) as usize;
                let opc_len = 3;
                if sp + opc_len + l >= src.len() {
                    if sp + opc_len + l > src.len() {
                        return Err(Error::Corrupt);
                    }
                    return Err(Error::Corrupt);
                }
                let opc23 = (src[sp + 1] as u16) | ((src[sp + 2] as u16) << 8);
                let m = (((op & 0x7) as usize) << 2 | (opc23 & 0x3) as usize) + 3;
                let d = (opc23 >> 2) as usize;
                sp += opc_len;
                out.extend_from_slice(&src[sp..sp + l]);
                sp += l;
                lz_copy(out, d, m, start_out_len)?;
                d_prev = d;
            }
            OpClass::LrgD => {
                // op = LLMMM111; bytes [1..3] = D_lo D_hi (LE16).
                let l = ((op >> 6) & 0x3) as usize;
                let m = (((op >> 3) & 0x7) as usize) + 3;
                let opc_len = 3;
                if sp + opc_len + l >= src.len() {
                    if sp + opc_len + l > src.len() {
                        return Err(Error::Corrupt);
                    }
                    return Err(Error::Corrupt);
                }
                let d = (src[sp + 1] as usize) | ((src[sp + 2] as usize) << 8);
                sp += opc_len;
                out.extend_from_slice(&src[sp..sp + l]);
                sp += l;
                lz_copy(out, d, m, start_out_len)?;
                d_prev = d;
            }
            OpClass::PreD => {
                // op = LLMMM110; L literals follow, then implicit match of
                // length M at distance d_prev.
                let l = ((op >> 6) & 0x3) as usize;
                let m = (((op >> 3) & 0x7) as usize) + 3;
                let opc_len = 1;
                if sp + opc_len + l >= src.len() {
                    if sp + opc_len + l > src.len() {
                        return Err(Error::Corrupt);
                    }
                    return Err(Error::Corrupt);
                }
                sp += opc_len;
                out.extend_from_slice(&src[sp..sp + l]);
                sp += l;
                if d_prev == 0 {
                    return Err(Error::Corrupt);
                }
                lz_copy(out, d_prev, m, start_out_len)?;
            }
            OpClass::SmlL => {
                // op = 1110LLLL; L literals follow (no match).
                let l = (op & 0xF) as usize;
                let opc_len = 1;
                if sp + opc_len + l >= src.len() {
                    if sp + opc_len + l > src.len() {
                        return Err(Error::Corrupt);
                    }
                    return Err(Error::Corrupt);
                }
                sp += opc_len;
                out.extend_from_slice(&src[sp..sp + l]);
                sp += l;
            }
            OpClass::LrgL => {
                // op = 11100000; byte [1] = L - 16; then L literals.
                let opc_len = 2;
                if sp + opc_len > src.len() {
                    return Err(Error::Corrupt);
                }
                let l = (src[sp + 1] as usize) + 16;
                if sp + opc_len + l >= src.len() {
                    if sp + opc_len + l > src.len() {
                        return Err(Error::Corrupt);
                    }
                    return Err(Error::Corrupt);
                }
                sp += opc_len;
                out.extend_from_slice(&src[sp..sp + l]);
                sp += l;
            }
            OpClass::SmlM => {
                // op = 1111MMMM; no literal; match of length M at d_prev.
                let m = (op & 0xF) as usize;
                let opc_len = 1;
                if sp + opc_len > src.len() {
                    return Err(Error::Corrupt);
                }
                sp += opc_len;
                if d_prev == 0 {
                    return Err(Error::Corrupt);
                }
                lz_copy(out, d_prev, m, start_out_len)?;
            }
            OpClass::LrgM => {
                // op = 11110000 MMMMMMMM; M = byte[1] + 16; uses d_prev.
                let opc_len = 2;
                if sp + opc_len > src.len() {
                    return Err(Error::Corrupt);
                }
                let m = (src[sp + 1] as usize) + 16;
                sp += opc_len;
                if d_prev == 0 {
                    return Err(Error::Corrupt);
                }
                lz_copy(out, d_prev, m, start_out_len)?;
            }
            OpClass::Eos => {
                // op = 0x06; followed by 7 bytes (8 total = opc_len).
                let opc_len = 8;
                if sp + opc_len > src.len() {
                    return Err(Error::Corrupt);
                }
                // Done. We don't enforce a specific byte content for the
                // 7 trailing bytes — Apple's reference doesn't check either.
                if out.len() - start_out_len != expected_decoded_size {
                    return Err(Error::Corrupt);
                }
                return Ok(());
            }
            OpClass::Nop => {
                // 1-byte no-op.
                sp += 1;
            }
            OpClass::Udef => {
                return Err(Error::Corrupt);
            }
        }
    }
}

/// LZ77 match copy: at distance `d`, copy `n` bytes from `out[out.len() - d]`
/// onwards, byte-by-byte (so overlap of d < n splat-copies correctly).
fn lz_copy(out: &mut Vec<u8>, d: usize, n: usize, start: usize) -> Result<(), Error> {
    if d == 0 || d > out.len() - start {
        return Err(Error::Corrupt);
    }
    let src_pos = out.len() - d;
    for i in 0..n {
        let b = out[src_pos + i];
        out.push(b);
    }
    Ok(())
}
