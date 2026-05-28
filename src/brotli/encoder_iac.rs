//! Insert-and-copy command encoding helpers (RFC 7932 §5).
//!
//! The brotli encoder represents a stream of commands, each of the form
//! `(insert_len, copy_len[, distance])`. Insert/copy lengths are encoded
//! as a single symbol over the 704-symbol IC alphabet plus extra bits.
//! Distances live in a separate alphabet whose size depends on NPOSTFIX
//! and NDIRECT.
//!
//! These helpers are the encoder-side inverses of the decoder tables in
//! `mod.rs` (`INS_BASE`/`INS_EXTRA`, `COPY_BASE`/`COPY_EXTRA`,
//! `decode_ic_command`).

/// Insert length code → (base, extra_bits). Indexed by code 0..=23.
pub(crate) const INS_BASE: [u32; 24] = [
    0, 1, 2, 3, 4, 5, 6, 8, 10, 14, 18, 26, 34, 50, 66, 98, 130, 194, 322, 578, 1090, 2114, 6210,
    22594,
];
pub(crate) const INS_EXTRA: [u32; 24] = [
    0, 0, 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 7, 8, 9, 10, 12, 14, 24,
];

/// Copy length code → (base, extra_bits). Indexed by code 0..=23.
pub(crate) const COPY_BASE: [u32; 24] = [
    2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 14, 18, 22, 30, 38, 54, 70, 102, 134, 198, 326, 582, 1094, 2118,
];
pub(crate) const COPY_EXTRA: [u32; 24] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 7, 8, 9, 10, 24,
];

/// Find the insert-length code for `len`. Returns (code, extra_bits, extra_value).
pub(crate) fn insert_to_code(len: u32) -> (u32, u32, u32) {
    // Scan from the top — high lengths fall into the high codes.
    for c in (0..24).rev() {
        let base = INS_BASE[c];
        if len >= base {
            let extra = len - base;
            // Sanity: extra must fit in INS_EXTRA[c] bits.
            debug_assert!(extra < (1u32 << INS_EXTRA[c]) || INS_EXTRA[c] >= 32);
            return (c as u32, INS_EXTRA[c], extra);
        }
    }
    unreachable!("INS_BASE[0]=0, every u32 falls into some code")
}

/// Find the copy-length code for `len` (≥ 2). Returns (code, extra_bits, extra_value).
pub(crate) fn copy_to_code(len: u32) -> (u32, u32, u32) {
    debug_assert!(len >= 2, "copy length must be at least 2");
    for c in (0..24).rev() {
        let base = COPY_BASE[c];
        if len >= base {
            let extra = len - base;
            debug_assert!(extra < (1u32 << COPY_EXTRA[c]) || COPY_EXTRA[c] >= 32);
            return (c as u32, COPY_EXTRA[c], extra);
        }
    }
    unreachable!("COPY_BASE[0]=2, every len>=2 falls into some code")
}

/// Compute the IC command symbol (0..=703) for an (ins_code, copy_code,
/// use_last_dist) triple. Inverse of `decode_ic_command` in `mod.rs`.
///
/// Cells per §5:
///   cell 0: ins 0..7,   copy 0..7,   use_last=true
///   cell 1: ins 0..7,   copy 8..15,  use_last=true
///   cell 2: ins 0..7,   copy 0..7,   use_last=false
///   cell 3: ins 0..7,   copy 8..15,  use_last=false
///   cell 4: ins 8..15,  copy 0..7,   use_last=false
///   cell 5: ins 8..15,  copy 8..15,  use_last=false
///   cell 6: ins 0..7,   copy 16..23, use_last=false
///   cell 7: ins 16..23, copy 0..7,   use_last=false
///   cell 8: ins 8..15,  copy 16..23, use_last=false
///   cell 9: ins 16..23, copy 8..15,  use_last=false
///   cell 10: ins 16..23, copy 16..23, use_last=false
pub(crate) fn ic_command_sym(ins_code: u32, copy_code: u32, use_last_dist: bool) -> u32 {
    let ins_grp = if ins_code < 8 {
        0
    } else if ins_code < 16 {
        1
    } else {
        2
    };
    let copy_grp = if copy_code < 8 {
        0
    } else if copy_code < 16 {
        1
    } else {
        2
    };
    let cell: u32 = match (ins_grp, copy_grp, use_last_dist) {
        (0, 0, true) => 0,
        (0, 1, true) => 1,
        (0, 0, false) => 2,
        (0, 1, false) => 3,
        (1, 0, false) => 4,
        (1, 1, false) => 5,
        (0, 2, false) => 6,
        (2, 0, false) => 7,
        (1, 2, false) => 8,
        (2, 1, false) => 9,
        (2, 2, false) => 10,
        // use_last_dist=true with ins or copy in higher groups is illegal
        _ => panic!("use_last_dist=true only valid for ins<8 && copy<16"),
    };
    let ins_base: u32 = match ins_grp {
        0 => 0,
        1 => 8,
        2 => 16,
        _ => unreachable!(),
    };
    let copy_base: u32 = match copy_grp {
        0 => 0,
        1 => 8,
        2 => 16,
        _ => unreachable!(),
    };
    let cell_local = ((ins_code - ins_base) << 3) | (copy_code - copy_base);
    cell * 64 + cell_local
}

/// Encode a back-reference distance into the (dcode, ndistbits, dextra)
/// triple when NPOSTFIX=0 and NDIRECT=0.
///
/// The resulting code is the symbol over the 64-symbol distance alphabet
/// (codes 0..=15 are reserved for ring-buffer reuse, 16..=63 are
/// "normal" distances with `ndistbits` extra bits).
///
/// Returns None if the distance is unrepresentable (≤ 0 or absurdly
/// large).
pub(crate) fn distance_to_normal_code(dist: u32) -> Option<(u32, u32, u32)> {
    if dist == 0 {
        return None;
    }
    // The decoder formula for NPOSTFIX=0, NDIRECT=0:
    //   v = dcode - 16
    //   ndistbits = 1 + (v >> 1)
    //   offset = ((2 + (v & 1)) << ndistbits) - 4
    //   dist = (offset + dextra) + 1
    // So for each v we have a range [offset+1, offset+(1<<ndistbits)].
    for v in 0u32..48 {
        let ndistbits = 1 + (v >> 1);
        let offset = ((2u32 + (v & 1)) << ndistbits) - 4;
        let lo = offset + 1;
        let hi = offset + (1u32 << ndistbits);
        if dist >= lo && dist <= hi {
            let dextra = dist - lo;
            return Some((16 + v, ndistbits, dextra));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_code_roundtrip() {
        for len in [
            0u32, 1, 5, 6, 14, 22, 100, 322, 1090, 22594, 22595, 22600, 100_000,
        ] {
            let (c, eb, ex) = insert_to_code(len);
            let reconstructed = INS_BASE[c as usize] + ex;
            assert_eq!(reconstructed, len, "len {} → code {} extra {}", len, c, ex);
            if eb < 32 {
                assert!(ex < (1u32 << eb), "extra {} too big for {} bits", ex, eb);
            }
        }
    }

    #[test]
    fn copy_code_roundtrip() {
        for len in [
            2u32, 3, 9, 10, 14, 22, 100, 326, 1094, 2118, 2119, 10_000, 100_000,
        ] {
            let (c, eb, ex) = copy_to_code(len);
            let reconstructed = COPY_BASE[c as usize] + ex;
            assert_eq!(reconstructed, len, "len {} → code {} extra {}", len, c, ex);
            if eb < 32 {
                assert!(ex < (1u32 << eb), "extra {} too big for {} bits", ex, eb);
            }
        }
    }

    #[test]
    fn distance_code_roundtrip() {
        for d in [
            1u32, 2, 3, 4, 5, 12, 13, 28, 29, 100, 1000, 65520, 1_000_000, 16_777_000,
        ] {
            let (dcode, ndistbits, dextra) = distance_to_normal_code(d).unwrap();
            // Mirror decoder formula.
            let v = dcode - 16;
            let nb = 1 + (v >> 1);
            assert_eq!(nb, ndistbits);
            let offset = ((2u32 + (v & 1)) << nb) - 4;
            let recovered = offset + dextra + 1;
            assert_eq!(recovered, d, "dist {} → code {} extra {}", d, dcode, dextra);
            assert!(dextra < (1u32 << nb));
        }
    }

    #[test]
    fn ic_command_sym_known_values() {
        // ins=0, copy=2 (code 0,0), use_last=true → cmd 0 (matches the
        // 8-'a' fixture from tests/brotli.rs).
        assert_eq!(ic_command_sym(0, 0, true), 0);
        // ins=8 (ins_grp 1), copy=0 (copy_grp 0), use_last=false → cell 4.
        // cell_local = (8-8)<<3 | 0 = 0. cmd = 256.
        assert_eq!(ic_command_sym(8, 0, false), 256);
        // ins=23, copy=0, use_last=false → cell 7.
        // cell_local = (23-16)<<3 | 0 = 56. cmd = 7*64+56 = 504.
        assert_eq!(ic_command_sym(23, 0, false), 504);
    }
}
