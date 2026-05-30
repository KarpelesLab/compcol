//! Byte-level arena backing the PPMd context and state allocator.
//!
//! The reference Ppmd7 implementation places every `CPpmd7_Context` and
//! `CPpmd_State` into a single `Byte *Base` buffer and refers to them by
//! 32-bit offset (`CPpmd_*_Ref` is a `UInt32`). That packing is
//! load-bearing: the free-list pointer and the `Stats` ref are read out
//! of the same 4-byte slot a struct field would occupy, the `Node`
//! coalescer walks the buffer linearly assuming `UNIT_SIZE` granularity,
//! etc. We preserve the layout exactly in a single `Vec<u8>` and access
//! it through safe little-endian byte gets/puts.
//!
//! All field accessors are little-endian. The C code relies on the host
//! being little-endian (PPMd has no defined behaviour on big-endian
//! archive readers); we make that explicit so the codec round-trips on
//! any architecture.

use alloc::vec;
use alloc::vec::Vec;

// ─── packed layout constants ────────────────────────────────────────────

pub(super) const UNIT_SIZE: usize = 12;
pub(super) const STATE_SIZE: usize = 6;

// CPpmd7_Context (packed, total = UNIT_SIZE = 12 bytes)
pub(super) const CTX_OFF_NUM_STATS: usize = 0; // u16
pub(super) const CTX_OFF_SUMM_FREQ: usize = 2; // u16
pub(super) const CTX_OFF_STATS: usize = 4; // u32 — CPpmd_State_Ref
pub(super) const CTX_OFF_SUFFIX: usize = 8; // u32 — CPpmd7_Context_Ref

// CPpmd_State (packed, total = STATE_SIZE = 6 bytes)
pub(super) const STATE_OFF_SYMBOL: usize = 0; // u8
pub(super) const STATE_OFF_FREQ: usize = 1; // u8
pub(super) const STATE_OFF_SUCC_LOW: usize = 2; // u16
pub(super) const STATE_OFF_SUCC_HIGH: usize = 4; // u16

// ─── arena ───────────────────────────────────────────────────────────────

/// `Vec<u8>` arena with little-endian struct accessors. Out-of-range
/// reads return `None` so the model can refuse a corrupt stream rather
/// than panic.
pub(super) struct Arena {
    data: Vec<u8>,
}

impl Arena {
    pub fn new(size: usize) -> Self {
        Self {
            data: vec![0u8; size],
        }
    }

    pub fn clear(&mut self) {
        self.data.fill(0);
    }

    // ── byte-level r/w (sole entry to the backing store) ───────────────

    #[inline]
    pub fn read_u8(&self, off: u32) -> Option<u8> {
        self.data.get(off as usize).copied()
    }

    #[inline]
    pub fn write_u8(&mut self, off: u32, v: u8) -> Option<()> {
        *self.data.get_mut(off as usize)? = v;
        Some(())
    }

    #[inline]
    pub fn read_u16(&self, off: u32) -> Option<u16> {
        let s = self.data.get(off as usize..off as usize + 2)?;
        Some(u16::from_le_bytes([s[0], s[1]]))
    }

    #[inline]
    pub fn write_u16(&mut self, off: u32, v: u16) -> Option<()> {
        let bytes = v.to_le_bytes();
        let slice = self.data.get_mut(off as usize..off as usize + 2)?;
        slice.copy_from_slice(&bytes);
        Some(())
    }

    #[inline]
    pub fn write_u32(&mut self, off: u32, v: u32) -> Option<()> {
        let bytes = v.to_le_bytes();
        let slice = self.data.get_mut(off as usize..off as usize + 4)?;
        slice.copy_from_slice(&bytes);
        Some(())
    }
}

// ─── context accessors ─────────────────────────────────────────────────

#[inline]
pub(super) fn ctx_num_stats(a: &Arena, ctx: u32) -> Option<u16> {
    a.read_u16(ctx + CTX_OFF_NUM_STATS as u32)
}
#[inline]
pub(super) fn ctx_set_num_stats(a: &mut Arena, ctx: u32, v: u16) -> Option<()> {
    a.write_u16(ctx + CTX_OFF_NUM_STATS as u32, v)
}
#[inline]
pub(super) fn ctx_summ_freq(a: &Arena, ctx: u32) -> Option<u16> {
    a.read_u16(ctx + CTX_OFF_SUMM_FREQ as u32)
}
#[inline]
pub(super) fn ctx_set_summ_freq(a: &mut Arena, ctx: u32, v: u16) -> Option<()> {
    a.write_u16(ctx + CTX_OFF_SUMM_FREQ as u32, v)
}
#[inline]
pub(super) fn ctx_set_stats(a: &mut Arena, ctx: u32, v: u32) -> Option<()> {
    a.write_u32(ctx + CTX_OFF_STATS as u32, v)
}
#[inline]
pub(super) fn ctx_set_suffix(a: &mut Arena, ctx: u32, v: u32) -> Option<()> {
    a.write_u32(ctx + CTX_OFF_SUFFIX as u32, v)
}

// ─── state accessors ───────────────────────────────────────────────────

#[inline]
pub(super) fn state_symbol(a: &Arena, st: u32) -> Option<u8> {
    a.read_u8(st + STATE_OFF_SYMBOL as u32)
}
#[inline]
pub(super) fn state_set_symbol(a: &mut Arena, st: u32, v: u8) -> Option<()> {
    a.write_u8(st + STATE_OFF_SYMBOL as u32, v)
}
#[inline]
pub(super) fn state_freq(a: &Arena, st: u32) -> Option<u8> {
    a.read_u8(st + STATE_OFF_FREQ as u32)
}
#[inline]
pub(super) fn state_set_freq(a: &mut Arena, st: u32, v: u8) -> Option<()> {
    a.write_u8(st + STATE_OFF_FREQ as u32, v)
}
#[inline]
pub(super) fn state_set_successor(a: &mut Arena, st: u32, v: u32) -> Option<()> {
    a.write_u16(st + STATE_OFF_SUCC_LOW as u32, (v & 0xFFFF) as u16)?;
    a.write_u16(st + STATE_OFF_SUCC_HIGH as u32, ((v >> 16) & 0xFFFF) as u16)
}

/// Swap two adjacent (or any two) states.
pub(super) fn swap_states(a: &mut Arena, st1: u32, st2: u32) -> Option<()> {
    let mut s1 = [0u8; STATE_SIZE];
    let mut s2 = [0u8; STATE_SIZE];
    for i in 0..STATE_SIZE {
        s1[i] = a.read_u8(st1 + i as u32)?;
        s2[i] = a.read_u8(st2 + i as u32)?;
    }
    for i in 0..STATE_SIZE {
        a.write_u8(st1 + i as u32, s2[i])?;
        a.write_u8(st2 + i as u32, s1[i])?;
    }
    Some(())
}

/// Write a full state from a tuple.
#[inline]
pub(super) fn state_store(a: &mut Arena, st: u32, sym: u8, freq: u8, succ: u32) -> Option<()> {
    state_set_symbol(a, st, sym)?;
    state_set_freq(a, st, freq)?;
    state_set_successor(a, st, succ)
}
