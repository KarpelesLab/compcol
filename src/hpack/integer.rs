//! HPACK integer representation — RFC 7541 §5.1.
//!
//! HPACK integers carry an `N`-bit prefix that shares its byte with
//! preceding flag bits. Values below `2^N − 1` fit entirely in the prefix;
//! larger values store `2^N − 1` in the prefix and the remainder as a
//! little-endian base-128 continuation (each byte's high bit = "more").

extern crate alloc;
use alloc::vec::Vec;

use crate::error::Error;

/// Encode `value` with an `n`-bit prefix (`1 <= n <= 8`), OR-ing `flags`
/// (the high `8 - n` bits already positioned) into the prefix byte.
///
/// Appends to `out`.
pub fn encode_int(out: &mut Vec<u8>, value: usize, n: u32, flags: u8) {
    debug_assert!((1..=8).contains(&n));
    let max_prefix = (1usize << n) - 1;
    if value < max_prefix {
        out.push(flags | value as u8);
        return;
    }
    out.push(flags | max_prefix as u8);
    let mut v = value - max_prefix;
    while v >= 128 {
        out.push((v & 0x7f) as u8 | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

/// Decode an `n`-bit-prefix integer starting at `buf[pos]` (`1 <= n <= 8`).
///
/// Returns `(value, next_pos)`. The prefix flag bits above the low `n` bits
/// of `buf[pos]` are ignored (the caller already dispatched on them).
///
/// Rejects continuations that would overflow `usize` or run past the buffer
/// (`Error::Corrupt` / `Error::UnexpectedEnd`) — the standard HPACK
/// integer-overflow guard.
pub fn decode_int(buf: &[u8], pos: usize, n: u32) -> Result<(usize, usize), Error> {
    debug_assert!((1..=8).contains(&n));
    let max_prefix = (1usize << n) - 1;
    let first = *buf.get(pos).ok_or(Error::UnexpectedEnd)? as usize;
    let mut value = first & max_prefix;
    let mut p = pos + 1;
    if value < max_prefix {
        return Ok((value, p));
    }
    // Continuation: base-128, high bit = "more". Cap the shift so a crafted
    // run of 0x80 bytes can't spin or overflow.
    let mut shift = 0u32;
    loop {
        let b = *buf.get(p).ok_or(Error::UnexpectedEnd)? as usize;
        p += 1;
        // 7 fresh bits at `shift`; guard against usize overflow.
        if shift >= usize::BITS {
            return Err(Error::Corrupt);
        }
        let add = (b & 0x7f).checked_shl(shift).ok_or(Error::Corrupt)?;
        value = value.checked_add(add).ok_or(Error::Corrupt)?;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
    }
    Ok((value, p))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_c1_examples() {
        // C.1.1: 10 with a 5-bit prefix → 0x0a
        let mut out = Vec::new();
        encode_int(&mut out, 10, 5, 0);
        assert_eq!(out, [0x0a]);
        assert_eq!(decode_int(&out, 0, 5).unwrap(), (10, 1));

        // C.1.2: 1337 with a 5-bit prefix → 0x1f 0x9a 0x0a
        let mut out = Vec::new();
        encode_int(&mut out, 1337, 5, 0);
        assert_eq!(out, [0x1f, 0x9a, 0x0a]);
        assert_eq!(decode_int(&out, 0, 5).unwrap(), (1337, 3));

        // C.1.3: 42 with an 8-bit prefix → 0x2a
        let mut out = Vec::new();
        encode_int(&mut out, 42, 8, 0);
        assert_eq!(out, [0x2a]);
        assert_eq!(decode_int(&out, 0, 8).unwrap(), (42, 1));
    }

    #[test]
    fn flags_preserved_and_ignored() {
        let mut out = Vec::new();
        encode_int(&mut out, 2, 6, 0b1100_0000);
        assert_eq!(out, [0b1100_0010]);
        // decode ignores the two high flag bits
        assert_eq!(decode_int(&out, 0, 6).unwrap(), (2, 1));
    }

    #[test]
    fn overlong_continuation_rejected() {
        // Many 0x80 bytes never terminate within usize → Corrupt, not a hang.
        let mut buf = alloc::vec![0xffu8]; // 5-bit prefix max
        buf.extend(core::iter::repeat_n(0x80, 64));
        buf.push(0x00);
        assert!(matches!(decode_int(&buf, 0, 5), Err(Error::Corrupt)));
    }

    #[test]
    fn truncated_continuation_rejected() {
        let buf = [0x1fu8, 0x9a]; // promises more but ends
        assert!(matches!(decode_int(&buf, 0, 5), Err(Error::UnexpectedEnd)));
    }
}
