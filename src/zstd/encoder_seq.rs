//! Sequence-section helpers for the Zstandard encoder.
//!
//! - Conversion `value → (code, extra_bits, extra_value)` for literal
//!   lengths, match lengths, and offsets (the inverse of the decoder's
//!   `*_base_extra` tables in [`crate::zstd::sequences`]).
//! - Encoding the variable-width `Number_of_Sequences` field that prefixes
//!   the sequence section (RFC 8478 §3.1.1.3.2.1).

use alloc::vec::Vec;

/// Convert a literal-length value to its FSE code, extra-bit count, and
/// extra-bit payload (the low bits to send after the FSE state).
pub fn ll_code(value: u32) -> (u8, u32, u32) {
    // Tables from RFC 8478 §3.1.1.3.2.1.1 / Appendix A.
    // Codes 0..=15 cover values 0..=15 directly (extra=0).
    if value < 16 {
        return (value as u8, 0, 0);
    }
    // Codes 16..=23 cover values via 1..=3-bit extras at specific bases.
    let bases: [u32; 36] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 18, 20, 22, 24, 28, 32, 40, 48,
        64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536,
    ];
    let extras: [u32; 36] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 3, 3, 4, 6, 7, 8, 9, 10,
        11, 12, 13, 14, 15, 16,
    ];
    // Linear scan from 16 — codes beyond 15 are at most 20 entries.
    for c in (16..36).rev() {
        if value >= bases[c] {
            let extra_val = value - bases[c];
            // sanity: must fit in `extras[c]` bits.
            debug_assert!(extras[c] == 0 || extra_val < (1u32 << extras[c]));
            return (c as u8, extras[c], extra_val);
        }
    }
    // unreachable for value < 65536+...
    (35, extras[35], value - bases[35])
}

/// Convert a match-length value to its FSE code, extra-bit count, and
/// extra-bit payload. ML in zstd starts at 3 (encoded as code 0).
pub fn ml_code(value: u32) -> (u8, u32, u32) {
    // ml_value = ml_base[code] + extra_bits
    if value < 3 {
        // Should never happen — minimum match is 3.
        return (0, 0, 0);
    }
    if value < 35 {
        // Codes 0..=31 cover values 3..=34 directly (extra=0).
        let code = (value - 3) as u8;
        return (code, 0, 0);
    }
    let bases: [u32; 53] = [
        3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
        27, 28, 29, 30, 31, 32, 33, 34, 35, 37, 39, 41, 43, 47, 51, 59, 67, 83, 99, 131, 259, 515,
        1027, 2051, 4099, 8195, 16387, 32771, 65539,
    ];
    let extras: [u32; 53] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 1, 1, 1, 1, 2, 2, 3, 3, 4, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
    ];
    for c in (32..53).rev() {
        if value >= bases[c] {
            let extra_val = value - bases[c];
            debug_assert!(extras[c] == 0 || extra_val < (1u32 << extras[c]));
            return (c as u8, extras[c], extra_val);
        }
    }
    (52, extras[52], value - bases[52])
}

/// Convert an offset_value (the encoded one used in the bitstream, including
/// repeat-offset aliasing) to its FSE code and extra-bit value. Unlike LL/ML,
/// offset codes are `floor(log2(offset_value))` and the extra bits store
/// `offset_value - (1 << code)`.
pub fn of_code(offset_value: u32) -> (u8, u32, u32) {
    // offset_value should be ≥ 1 (zero is reserved as a "no value" marker).
    if offset_value == 0 {
        return (0, 0, 0);
    }
    let code = 31 - offset_value.leading_zeros();
    let base = 1u32 << code;
    (code as u8, code, offset_value - base)
}

/// Encode the Number_of_Sequences header bytes. RFC 8478 §3.1.1.3.2.1:
///
/// - `0`             → 1 byte: `0x00`.
/// - `1..=127`       → 1 byte: `count`.
/// - `128..=32639`   → 2 bytes: `((count >> 8) | 0x80, count & 0xFF)` … or
///   per the spec, `( (count >> 8) + 0x80, count & 0xFF)` with the count
///   adjusted so the high byte encodes (count - 128) etc.
/// - `≥ 32640`       → 3 bytes: `0xFF, (count - 32512) & 0xFF, (count - 32512) >> 8`.
///
/// Returns the encoded bytes.
pub fn encode_sequence_count(count: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(3);
    if count < 128 {
        out.push(count as u8);
    } else if count < 0x7F00 {
        // 2-byte form: byte0 = (count >> 8) + 128, byte1 = count & 0xFF.
        // Decoder formula: value = ((b0 - 128) << 8) | b1.
        let b0 = ((count >> 8) | 0x80) as u8;
        let b1 = (count & 0xFF) as u8;
        out.push(b0);
        out.push(b1);
    } else {
        // 3-byte form: 0xFF, low byte, high byte. Decoder formula:
        //   value = 0x7F00 + b1 + (b2 << 8).
        let v = count - 0x7F00;
        out.push(0xFF);
        out.push((v & 0xFF) as u8);
        out.push(((v >> 8) & 0xFF) as u8);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // We test these encoder helpers by composing them with the decoder-side
    // base tables (replicated locally): encode a value, decode (base + extra),
    // expect the original value back.

    fn ll_decode(code: u8, extra_val: u32) -> u32 {
        let bases: [u32; 36] = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 18, 20, 22, 24, 28, 32, 40,
            48, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536,
        ];
        bases[code as usize] + extra_val
    }

    fn ml_decode(code: u8, extra_val: u32) -> u32 {
        let bases: [u32; 53] = [
            3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
            26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 37, 39, 41, 43, 47, 51, 59, 67, 83, 99, 131,
            259, 515, 1027, 2051, 4099, 8195, 16387, 32771, 65539,
        ];
        bases[code as usize] + extra_val
    }

    #[test]
    fn ll_round_trip_small() {
        for v in 0..=15u32 {
            let (code, _extra_bits, extra_val) = ll_code(v);
            assert_eq!(ll_decode(code, extra_val), v);
        }
    }

    #[test]
    fn ll_round_trip_medium() {
        for v in [16u32, 17, 18, 23, 24, 100, 500, 4096, 65535] {
            let (code, _eb, ev) = ll_code(v);
            assert_eq!(ll_decode(code, ev), v, "v={}", v);
        }
    }

    #[test]
    fn ml_round_trip() {
        for v in [3u32, 4, 10, 34, 35, 36, 100, 500, 65538] {
            let (code, _eb, ev) = ml_code(v);
            assert_eq!(ml_decode(code, ev), v, "v={}", v);
        }
    }

    #[test]
    fn of_round_trip() {
        for ov in [1u32, 2, 3, 4, 5, 100, 1024, 65536] {
            let (code, _eb, ev) = of_code(ov);
            // Decoder formula: offset_value = (1 << code) + ev (for code > 0)
            // or 1 (for code == 0).
            let decoded = if code == 0 { 1 } else { (1u32 << code) + ev };
            assert_eq!(decoded, ov, "ov={}", ov);
        }
    }

    #[test]
    fn n_seq_round_trip() {
        for &n in &[0u32, 1, 127, 128, 255, 1000, 32639, 32640, 70000] {
            let encoded = encode_sequence_count(n);
            // Decode via the same logic as decoder's parse_sequence_count
            let b0 = encoded[0];
            let v = if b0 == 0 {
                0u32
            } else if b0 < 128 {
                b0 as u32
            } else if b0 < 255 {
                (((b0 as u32) - 128) << 8) | (encoded[1] as u32)
            } else {
                ((encoded[1] as u32) | ((encoded[2] as u32) << 8)) + 0x7F00
            };
            assert_eq!(v, n, "round-trip failed for n={}", n);
        }
    }
}
