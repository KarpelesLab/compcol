//! Table-driven Huffman decoding for the deflate decoder.
//!
//! A [`Table`] resolves the next code with one lookup into a `2^BITS`-entry
//! root table indexed by the next `BITS` stream bits; codes longer than
//! `BITS` take a second lookup into a subtable sized for the longest code
//! that shares the root prefix. Each entry carries what the hot loop needs
//! without a second table: the code length, and for the literal/length
//! alphabet the literal byte or the length base and its extra-bit count
//! (likewise the distance base and extra bits for the distance alphabet).
//! The low byte is the code length plus the extra bits, so the hot loop
//! drops a whole length or distance field with one shift and reads the
//! extra bits from a copy of the buffer taken before it.
//!
//! Entry layout (`u32`):
//!
//! | bits   | meaning                                                    |
//! |--------|------------------------------------------------------------|
//! | 0..6   | bits to consume: code length plus extra bits (0 for a      |
//! |        | subtable pointer or an unused slot)                        |
//! | 7      | subtable pointer (with [`EXC`])                            |
//! | 8..12  | code length, or a subtable pointer's index width           |
//! | 12..14 | kind of an exceptional entry (see `K_*`)                   |
//! | 14     | [`LIT`]: a literal byte                                    |
//! | 15     | [`EXC`]: exceptional (subtable, end of block, bad symbol,  |
//! |        | no code)                                                   |
//! | 16..32 | literal byte, length base, distance base or subtable start |

use alloc::vec::Vec;

use super::tables::{DIST_BASE, DIST_EXTRA, LENGTH_BASE, LENGTH_EXTRA};
use crate::error::Error;

/// A literal; the byte is in bits 16..24.
pub(super) const LIT: u32 = 1 << 14;
/// Anything that is neither a literal nor a length/distance.
pub(super) const EXC: u32 = 1 << 15;
const K_MASK: u32 = 3 << 12;
/// A root entry pointing to a subtable (combined with [`EXC`]). Bit 7
/// is outside the consumed-bits field and lets `lookup` test it alone.
const SUB: u32 = 1 << 7;
/// Exceptional kinds (combined with [`EXC`]).
pub(super) const K_EOB: u32 = 1 << 12;
/// A symbol the code assigns but deflate reserves (literal/length 286 and
/// 287, distance 30 and 31): decoding it means the stream is corrupt.
pub(super) const K_BAD: u32 = 2 << 12;
/// No code has these bits (an incomplete code).
pub(super) const K_NONE: u32 = 3 << 12;
const UNUSED: u32 = EXC | K_NONE;

/// The exceptional kind of `e` (`K_EOB`, `K_BAD` or `K_NONE`); only
/// meaningful when `e & EXC != 0`.
#[inline(always)]
pub(super) const fn kind(e: u32) -> u32 {
    e & K_MASK
}

/// Bits to drop for an entry: its code plus, for a length or distance,
/// the extra bits. Bits 6 and 7 are always clear, so a shift by the entry
/// can use this directly (shift amounts are taken mod 64).
#[inline(always)]
pub(super) const fn total_len(e: u32) -> u32 {
    e & 0x3f
}

/// Code length of an entry.
#[inline(always)]
pub(super) const fn code_len(e: u32) -> u32 {
    (e >> 8) & 0xf
}

/// Extra-bit count of a length or distance entry.
#[inline(always)]
pub(super) const fn extra_bits(e: u32) -> u32 {
    total_len(e) - code_len(e)
}

/// The extra-bits value of a length or distance entry, from `saved`: the
/// bit buffer as it was before the entry was consumed.
#[inline(always)]
pub(super) const fn extra_value(e: u32, saved: u64) -> u32 {
    ((saved & ((1u64 << total_len(e)) - 1)) >> code_len(e)) as u32
}

/// Literal byte, length base or distance base.
#[inline(always)]
pub(super) const fn value(e: u32) -> u32 {
    e >> 16
}

/// Literal/length table entry payload for `sym`, and its extra-bit count.
fn lit_payload(sym: usize) -> (u32, u32) {
    match sym {
        0..=255 => (LIT | (sym as u32) << 16, 0),
        256 => (EXC | K_EOB, 0),
        257..=285 => {
            let i = sym - 257;
            ((LENGTH_BASE[i] as u32) << 16, LENGTH_EXTRA[i] as u32)
        }
        _ => (EXC | K_BAD, 0),
    }
}

/// Distance table entry payload for `sym`, and its extra-bit count.
fn dist_payload(sym: usize) -> (u32, u32) {
    if sym < 30 {
        ((DIST_BASE[sym] as u32) << 16, DIST_EXTRA[sym] as u32)
    } else {
        (EXC | K_BAD, 0)
    }
}

/// A complete entry: payload, code length and extra bits.
#[inline]
fn entry((payload, extra): (u32, u32), len: u32) -> u32 {
    payload | len << 8 | (len + extra)
}

/// Which alphabet a table decodes.
#[derive(Clone, Copy)]
pub(super) enum Alphabet {
    LitLen,
    Dist,
}

pub(super) struct Table<const SIZE: usize> {
    root: [u32; SIZE],
    sub: Vec<u32>,
    /// Longest code length present; 0 when the code is empty.
    max_len: u32,
}

impl<const SIZE: usize> Table<SIZE> {
    const BITS: u32 = SIZE.trailing_zeros();

    pub(super) fn new() -> Self {
        Self {
            root: [UNUSED; SIZE],
            sub: Vec::new(),
            max_len: 0,
        }
    }

    /// The entry for the code at the bottom of `bits`. Bits beyond the
    /// longest code are ignored.
    #[inline(always)]
    pub(super) fn lookup(&self, bits: u64) -> u32 {
        let e = self.root[(bits as usize) & (SIZE - 1)];
        if e & SUB != 0 {
            self.sub_entry(e, bits)
        } else {
            e
        }
    }

    #[inline(always)]
    fn sub_entry(&self, e: u32, bits: u64) -> u32 {
        let start = value(e) as usize;
        let width = code_len(e);
        let idx = ((bits >> Self::BITS) as usize) & ((1usize << width) - 1);
        self.sub[start + idx]
    }

    /// Decode from a reader holding only `avail` bits (`bits` zero above
    /// them): `Ok(None)` if more bits could still complete a code,
    /// [`Error::InvalidHuffmanTree`] if the bits match no code or the code
    /// is empty.
    pub(super) fn decode_short(&self, bits: u64, avail: u32) -> Result<Option<u32>, Error> {
        if self.max_len == 0 {
            return Err(Error::InvalidHuffmanTree);
        }
        let e = self.lookup(bits);
        let len = code_len(e);
        if !(e & EXC != 0 && kind(e) == K_NONE) && len <= avail {
            return Ok(Some(e));
        }
        if avail >= self.max_len {
            Err(Error::InvalidHuffmanTree)
        } else {
            Ok(None)
        }
    }

    /// Build the table for `lengths` per RFC 1951 §3.2.2. Rejects code
    /// lengths over 15 and over-subscribed codes; incomplete codes are
    /// accepted (their unused bit patterns decode as [`K_NONE`]).
    pub(super) fn build(&mut self, lengths: &[u8], alphabet: Alphabet) -> Result<(), Error> {
        debug_assert!(lengths.len() <= 288);
        let mut counts = [0u16; 16];
        let mut max_len = 0u32;
        for &len in lengths {
            if len > 15 {
                return Err(Error::InvalidHuffmanTree);
            }
            if len > 0 {
                counts[len as usize] += 1;
                max_len = max_len.max(len as u32);
            }
        }
        // Kraft inequality: Σ counts[l] · 2^(15-l) ≤ 2^15.
        let mut kraft: u32 = 0;
        for l in 1..=15u32 {
            kraft += (counts[l as usize] as u32) << (15 - l);
        }
        if kraft > (1 << 15) {
            return Err(Error::InvalidHuffmanTree);
        }

        self.root.fill(UNUSED);
        self.sub.clear();
        self.max_len = max_len;
        if max_len == 0 {
            return Ok(());
        }

        // Symbols in canonical order (by length, then symbol).
        let mut offs = [0u16; 17];
        for l in 1..16 {
            offs[l + 1] = offs[l] + counts[l];
        }
        let total = offs[16] as usize;
        let mut sorted = [0u16; 288];
        for (sym, &len) in lengths.iter().enumerate() {
            if len > 0 {
                sorted[offs[len as usize] as usize] = sym as u16;
                offs[len as usize] += 1;
            }
        }

        let payload = |sym: usize| match alphabet {
            Alphabet::LitLen => lit_payload(sym),
            Alphabet::Dist => dist_payload(sym),
        };

        // Walk the canonical codes. `code` is the MSB-first code value.
        // Long codes are recorded for the subtable pass.
        let mut long = [(0u16, 0u8, 0u16); 288]; // (stream-order code, len, sym)
        let mut nlong = 0usize;
        let mut code: u32 = 0;
        let mut i = 0usize;
        for len in 1..=max_len {
            for _ in 0..counts[len as usize] {
                let sym = sorted[i] as usize;
                i += 1;
                let rev = reverse(code, len);
                if len <= Self::BITS {
                    let e = entry(payload(sym), len);
                    let mut slot = rev as usize;
                    while slot < SIZE {
                        self.root[slot] = e;
                        slot += 1 << len;
                    }
                } else {
                    long[nlong] = (rev as u16, len as u8, sym as u16);
                    nlong += 1;
                }
                code += 1;
            }
            code <<= 1;
        }
        debug_assert_eq!(i, total);

        // Codes sharing a root prefix are consecutive in canonical order and
        // the last of them is the longest: it sets the subtable's width.
        let mask = SIZE as u16 - 1;
        let mut g = 0usize;
        while g < nlong {
            let prefix = long[g].0 & mask;
            let mut end = g + 1;
            while end < nlong && long[end].0 & mask == prefix {
                end += 1;
            }
            let width = long[end - 1].1 as u32 - Self::BITS;
            let start = self.sub.len();
            self.sub.resize(start + (1 << width), UNUSED);
            self.root[prefix as usize] = EXC | SUB | (start as u32) << 16 | width << 8;
            for &(rev, len, sym) in &long[g..end] {
                let e = entry(payload(sym as usize), len as u32);
                let step = 1usize << (len as u32 - Self::BITS);
                let mut slot = (rev >> Self::BITS) as usize;
                while slot < (1 << width) {
                    self.sub[start + slot] = e;
                    slot += step;
                }
            }
            g = end;
        }
        Ok(())
    }
}

/// Reverse the low `n` bits of `v`.
#[inline]
fn reverse(v: u32, n: u32) -> u32 {
    v.reverse_bits() >> (32 - n)
}
