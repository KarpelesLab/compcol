//! QPACK prefixed-integer representation — RFC 9204 §4.1.1.
//!
//! Identical in form to the HPACK integer (RFC 7541 §5.1): an `N`-bit prefix
//! shares its byte with preceding flag bits, values below `2^N − 1` fit in the
//! prefix, and larger values store `2^N − 1` in the prefix plus a
//! little-endian base-128 continuation (high bit = "more"). HPACK's copy is
//! private to that module, so QPACK carries its own (the spec mandates the
//! same primitive but the modules stay decoupled).

extern crate alloc;
use alloc::vec::Vec;

use crate::error::Error;

/// Encode `value` with an `n`-bit prefix (`1 <= n <= 8`), OR-ing `flags`
/// (the high `8 - n` bits, already positioned) into the prefix byte. Appends
/// to `out`.
pub(crate) fn encode_int(out: &mut Vec<u8>, value: usize, n: u32, flags: u8) {
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
/// Returns `(value, next_pos)`. Prefix flag bits above the low `n` bits of
/// `buf[pos]` are ignored (the caller already dispatched on them). Rejects
/// continuations that would overflow `usize` or run past the buffer
/// (`Error::Corrupt` / `Error::UnexpectedEnd`) — the standard integer-overflow
/// guard (§4.1.1 mandates support for values up to at least 62 bits; this
/// caps at `usize` and rejects anything longer rather than wrapping).
pub(crate) fn decode_int(buf: &[u8], pos: usize, n: u32) -> Result<(usize, usize), Error> {
    debug_assert!((1..=8).contains(&n));
    let max_prefix = (1usize << n) - 1;
    let first = *buf.get(pos).ok_or(Error::UnexpectedEnd)? as usize;
    let value = first & max_prefix;
    let mut p = pos + 1;
    if value < max_prefix {
        return Ok((value, p));
    }
    let mut value = value;
    let mut shift = 0u32;
    loop {
        let b = *buf.get(p).ok_or(Error::UnexpectedEnd)? as usize;
        p += 1;
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
