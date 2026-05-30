//! PPMII variant H context model — *order-0 subset*.
//!
//! Safe-Rust port of the order-0 portion of Igor Pavlov's public-domain
//! `Ppmd7.{c,h}` (LZMA SDK). The reference packs every `CPpmd7_Context`
//! and `CPpmd_State` into a single `Byte *Base` arena and walks it
//! through 32-bit offsets; we keep that layout in `arena.rs` so the
//! pointer arithmetic translates straight across.
//!
//! ### Implementation scope
//!
//! This file implements **only the order-0 model state** — the 256-state
//! root context that PPMd uses as the bottom of its suffix chain. It
//! decodes any symbol the range coder's threshold lands in, updates the
//! frequency table (with the same `+4` increment + `MAX_FREQ` rescale),
//! and promotes the chosen state when its frequency overtakes its
//! predecessor. This is exactly the behaviour of a fresh model that has
//! never seen `UpdateModel` extend the tree, i.e. the moment immediately
//! after `Ppmd7_Init`.
//!
//! The full PPMII machinery — the per-order context tree built up by
//! `CreateSuccessors`, the binary-context special case for `NumStats==1`
//! contexts, the masked-escape walk through the suffix chain, the SEE
//! (secondary escape estimation) adaptation, and `Rescale` over the
//! entire tree — is **not** implemented in this build. Payloads from
//! real PPMd encoders exercise all of these paths almost immediately,
//! so this decoder is *not* a drop-in replacement for `7z x` or
//! `ppmd-cffi.decompress`. Tests use hand-built order-0 fixtures.

extern crate alloc;

use crate::error::Error;

use super::arena::{
    Arena, STATE_SIZE, UNIT_SIZE, ctx_num_stats, ctx_set_num_stats, ctx_set_stats, ctx_set_suffix,
    ctx_set_summ_freq, ctx_summ_freq, state_freq, state_set_freq, state_store, state_symbol,
    swap_states,
};
use super::range_dec::{ByteSource, RangeDec};

const MAX_FREQ: u8 = 124;

/// Order-0 PPMII model. One 256-state context lives at offset
/// [`Model::CTX_OFFSET`] in the arena; states follow it.
pub(super) struct Model {
    arena: Arena,
    /// Offset of the order-0 context block (always zero in this build).
    ctx_off: u32,
    /// Offset of the state array (256 entries × `STATE_SIZE`).
    stats_off: u32,
}

impl Model {
    /// Pre-computed arena layout. The order-0 context starts at byte 0
    /// (one UNIT = 12 bytes) and the state array starts at byte
    /// `UNIT_SIZE`. With 256 states × 6 bytes = 1536 bytes of stats, the
    /// minimum usable arena is `UNIT_SIZE + 256 * STATE_SIZE = 1548`
    /// bytes. We round up to 2 KiB so the layout has some slack for any
    /// future model-update extension.
    const MIN_ARENA: usize = 2048;

    pub fn new(order: u32, mem_size_bytes: usize) -> Result<Self, Error> {
        if !(2..=16).contains(&order) {
            return Err(Error::BadHeader);
        }
        // The header's advertised memory size (`mem_size_bytes`, up to
        // 255 MiB) describes the arena the *full* PPMII tree would need.
        // This build only implements the order-0 subset, whose arena never
        // grows past root (`MIN_ARENA` = 2 KiB) — `arena.rs` has no growth
        // path and every offset stays within that window. So we cap the
        // eager `vec![0u8; size]` allocation to the actual working size
        // rather than honouring the advertised figure, which would let an
        // 11-byte header force a 255 MiB allocation (L9). The parsed header
        // value is still validated and retained by the decoder; only the
        // allocation size is capped here.
        let _ = mem_size_bytes;
        let size = Self::MIN_ARENA;
        let _ = order; // captured in the framing header only; the order-0
        // subset doesn't grow the tree past root.
        let mut m = Self {
            arena: Arena::new(size),
            ctx_off: 0,
            stats_off: UNIT_SIZE as u32,
        };
        m.restart()?;
        Ok(m)
    }

    /// Initialise the order-0 context with 256 equally-weighted states.
    pub fn restart(&mut self) -> Result<(), Error> {
        self.arena.clear();
        // Build context at offset 0.
        ctx_set_num_stats(&mut self.arena, self.ctx_off, 256).ok_or(Error::Corrupt)?;
        ctx_set_summ_freq(&mut self.arena, self.ctx_off, 256 + 1).ok_or(Error::Corrupt)?;
        ctx_set_stats(&mut self.arena, self.ctx_off, self.stats_off).ok_or(Error::Corrupt)?;
        ctx_set_suffix(&mut self.arena, self.ctx_off, 0).ok_or(Error::Corrupt)?;
        for i in 0..256u32 {
            let st = self.stats_off + i * STATE_SIZE as u32;
            state_store(&mut self.arena, st, i as u8, 1, 0).ok_or(Error::Corrupt)?;
        }
        Ok(())
    }

    /// Decode one symbol from the range coder. Mirrors `Ppmd7_DecodeSymbol`
    /// for the order-0 case (`NumStats == 256`, no binary fast path, no
    /// suffix walk, no SEE).
    pub fn decode_symbol(
        &mut self,
        rd: &mut RangeDec,
        src: &mut ByteSource<'_>,
    ) -> Result<u8, Error> {
        // Snapshot for "need more input" rollback.
        let rd_snap = rd.clone();
        let pos_snap = src.pos;

        match self.decode_inner(rd, src) {
            Ok(sym) => Ok(sym),
            Err(Error::UnexpectedEnd) => {
                *rd = rd_snap;
                src.pos = pos_snap;
                Err(Error::UnexpectedEnd)
            }
            Err(e) => Err(e),
        }
    }

    fn decode_inner(&mut self, rd: &mut RangeDec, src: &mut ByteSource<'_>) -> Result<u8, Error> {
        let nstats = ctx_num_stats(&self.arena, self.ctx_off).ok_or(Error::Corrupt)?;
        if nstats == 0 {
            return Err(Error::Corrupt);
        }
        let summ_freq = ctx_summ_freq(&self.arena, self.ctx_off).ok_or(Error::Corrupt)?;
        let total = summ_freq as u32;
        if total == 0 {
            return Err(Error::Corrupt);
        }
        let hi_count = rd.get_threshold(total);

        let mut acc: u32 = 0;
        for i in 0..nstats as u32 {
            let st = self.stats_off + i * STATE_SIZE as u32;
            let f = state_freq(&self.arena, st).ok_or(Error::Corrupt)? as u32;
            if acc + f > hi_count {
                rd.decode(src, acc, f)?;
                let sym = state_symbol(&self.arena, st).ok_or(Error::Corrupt)?;
                self.bump_freq(i, f, summ_freq)?;
                return Ok(sym);
            }
            acc += f;
        }
        Err(Error::Corrupt)
    }

    fn bump_freq(&mut self, i: u32, freq: u32, summ_freq: u16) -> Result<(), Error> {
        let new_freq = freq + 4;
        let new_summ = summ_freq as u32 + 4;
        if new_freq > MAX_FREQ as u32 || new_summ > 0xFFFF {
            self.rescale()?;
            return Ok(());
        }
        let st = self.stats_off + i * STATE_SIZE as u32;
        state_set_freq(&mut self.arena, st, new_freq as u8).ok_or(Error::Corrupt)?;
        ctx_set_summ_freq(&mut self.arena, self.ctx_off, new_summ as u16).ok_or(Error::Corrupt)?;
        // Promote: if this state's frequency now exceeds its predecessor's,
        // swap them (keeps the array roughly sorted by freq).
        if i > 0 {
            let prev = self.stats_off + (i - 1) * STATE_SIZE as u32;
            let prev_f = state_freq(&self.arena, prev).ok_or(Error::Corrupt)? as u32;
            if new_freq > prev_f {
                swap_states(&mut self.arena, st, prev).ok_or(Error::Corrupt)?;
            }
        }
        Ok(())
    }

    fn rescale(&mut self) -> Result<(), Error> {
        // Halve every frequency, dropping zero-frequency states (the
        // reference's behaviour). We never go below one because order-0
        // must keep every symbol decodable.
        let nstats = ctx_num_stats(&self.arena, self.ctx_off).ok_or(Error::Corrupt)? as u32;
        let mut new_summ: u32 = 0;
        for i in 0..nstats {
            let st = self.stats_off + i * STATE_SIZE as u32;
            let f = state_freq(&self.arena, st).ok_or(Error::Corrupt)? as u32;
            let new_f = ((f + 1) >> 1).max(1) as u8;
            state_set_freq(&mut self.arena, st, new_f).ok_or(Error::Corrupt)?;
            new_summ += new_f as u32;
        }
        ctx_set_summ_freq(&mut self.arena, self.ctx_off, new_summ.min(0xFFFF) as u16)
            .ok_or(Error::Corrupt)?;
        Ok(())
    }
}
