//! PPMII variant H context model (`Ppmd7`) — full decoder.
//!
//! Safe-Rust port of Igor Pavlov's public-domain `Ppmd7.{c,h}` (LZMA SDK,
//! itself based on Dmitry Shkarin's PPMd var.H, 2001 — both public domain).
//! The reference packs every `CPpmd7_Context` (12 bytes) and `CPpmd_State`
//! (6 bytes) into a single `Byte *Base` arena and refers to them by 32-bit
//! offset; we keep that byte-exact layout in one `Vec<u8>` and reach it
//! through little-endian accessors. Offsets ("refs") are `u32`; ref `0` is
//! reserved as the null pointer (the arena's live region starts at
//! `align_offset`, always `>= 1`).
//!
//! The range coder is external (see [`super::range_dec::RangeDec`]); the
//! model calls `get_threshold` / `decode` / `decode_bit` on it, so the same
//! model core drives both the 7z framing (standalone `.ppmd`) and RAR's
//! carry-less range decoder.
//!
//! This is a faithful, spec-derived port — not a transliteration of any
//! license-restricted RAR source. `Ppmd7.c` is public domain and may be
//! followed closely; libarchive's BSD RAR reader was consulted only for the
//! RAR range-decoder *description*, not copied.

// The model walks a flat byte arena by 32-bit offset; explicit index loops
// (`for i in 0..n { ... base[off + i] ... }`) mirror the reference's pointer
// arithmetic and read more clearly than iterator adapters here.
#![allow(clippy::needless_range_loop)]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;

use super::range_dec::RangeDec;

const UNIT_SIZE: u32 = 12;
const MAX_FREQ: u8 = 124;
const PPMD_NUM_INDEXES: usize = 38; // N1+N2+N3+N4 with N1=N2=N3=4
const PPMD_BIN_SCALE: u32 = 1 << 14;
const PPMD_INT_BITS: u32 = 7;
const PPMD_PERIOD_BITS: u32 = 7;
const MAX_ORDER: usize = 64;

const K_INIT_BIN_ESC: [u16; 8] = [
    0x3CDD, 0x1F3F, 0x59BF, 0x48F3, 0x64A1, 0x5ABC, 0x6632, 0x6051,
];
const K_EXP_ESCAPE: [u8; 16] = [25, 14, 9, 7, 5, 5, 4, 4, 4, 3, 3, 3, 2, 2, 2, 2];

#[inline]
fn get_mean(summ: u32) -> u32 {
    (summ + (1 << (PPMD_PERIOD_BITS - 2))) >> PPMD_PERIOD_BITS
}

/// One SEE (secondary escape estimation) cell.
#[derive(Clone, Copy, Default)]
struct See {
    summ: u16,
    shift: u8,
    count: u8,
}

impl See {
    /// `Ppmd_See_Update`.
    #[inline]
    fn update(&mut self) {
        if (self.shift as u32) < PPMD_PERIOD_BITS && {
            self.count = self.count.wrapping_sub(1);
            self.count == 0
        } {
            self.summ = self.summ.wrapping_shl(1);
            self.count = 3u8.wrapping_shl(self.shift as u32);
            self.shift += 1;
        }
    }
}

/// Which SEE cell `make_esc_freq` selected — used so the caller can update
/// the same cell after decoding.
#[derive(Clone, Copy)]
enum SeeRef {
    Dummy,
    Cell(usize, usize),
}

pub(crate) struct Ppmd7 {
    base: Vec<u8>,
    size: u32,
    align_offset: u32,
    err: bool,

    // Pointers (byte offsets into `base`).
    min_context: u32,
    max_context: u32,
    found_state: u32,
    text: u32,
    lo_unit: u32,
    hi_unit: u32,
    units_start: u32,
    glue_count: u32,

    order_fall: u32,
    init_esc: u32,
    prev_success: u32,
    max_order: u32,
    hi_bits_flag: u32,
    run_length: i32,
    init_rl: i32,

    free_list: [u32; PPMD_NUM_INDEXES],

    indx2units: [u8; PPMD_NUM_INDEXES],
    units2indx: [u8; 128],
    ns2indx: [u8; 256],
    ns2bsindx: [u8; 256],
    hb2flag: [u8; 256],

    see: [[See; 16]; 25],
    dummy_see: See,
    bin_summ: [[u16; 64]; 128],
}

impl Ppmd7 {
    /// Build the model for `mem_size` bytes of arena. The order is supplied
    /// to [`Ppmd7::init`]. `mem_size` must be at least `UNIT_SIZE`.
    pub(crate) fn new(mem_size: u32) -> Result<Self, Error> {
        if mem_size < UNIT_SIZE {
            return Err(Error::BadHeader);
        }
        let align_offset = 4 - (mem_size & 3);
        let total = (align_offset + mem_size + UNIT_SIZE) as usize;
        let mut p = Self {
            base: vec![0u8; total],
            size: mem_size,
            align_offset,
            err: false,
            min_context: 0,
            max_context: 0,
            found_state: 0,
            text: 0,
            lo_unit: 0,
            hi_unit: 0,
            units_start: 0,
            glue_count: 0,
            order_fall: 0,
            init_esc: 0,
            prev_success: 0,
            max_order: 0,
            hi_bits_flag: 0,
            run_length: 0,
            init_rl: 0,
            free_list: [0; PPMD_NUM_INDEXES],
            indx2units: [0; PPMD_NUM_INDEXES],
            units2indx: [0; 128],
            ns2indx: [0; 256],
            ns2bsindx: [0; 256],
            hb2flag: [0; 256],
            see: [[See::default(); 16]; 25],
            dummy_see: See::default(),
            bin_summ: [[0u16; 64]; 128],
        };
        p.construct_tables();
        Ok(p)
    }

    /// `Ppmd7_Construct` — the fixed lookup tables.
    fn construct_tables(&mut self) {
        let mut k = 0usize;
        for i in 0..PPMD_NUM_INDEXES {
            let mut step = if i >= 12 { 4 } else { (i >> 2) + 1 };
            while step > 0 {
                self.units2indx[k] = i as u8;
                k += 1;
                step -= 1;
            }
            self.indx2units[i] = k as u8;
        }

        self.ns2bsindx[0] = 0;
        self.ns2bsindx[1] = 2;
        for v in self.ns2bsindx[2..11].iter_mut() {
            *v = 4;
        }
        for v in self.ns2bsindx[11..256].iter_mut() {
            *v = 6;
        }

        for i in 0..3 {
            self.ns2indx[i] = i as u8;
        }
        let mut m = 3u8;
        let mut kk = 1i32;
        for i in 3..256 {
            self.ns2indx[i] = m;
            kk -= 1;
            if kk == 0 {
                m += 1;
                kk = (m as i32) - 2;
            }
        }

        for v in self.hb2flag[0..0x40].iter_mut() {
            *v = 0;
        }
        for v in self.hb2flag[0x40..256].iter_mut() {
            *v = 8;
        }
    }

    // ─── raw arena accessors (little-endian, OOB-safe) ──────────────────

    #[inline]
    fn gu8(&mut self, off: u32) -> u8 {
        match self.base.get(off as usize) {
            Some(&b) => b,
            None => {
                self.err = true;
                0
            }
        }
    }
    #[inline]
    fn pu8(&mut self, off: u32, v: u8) {
        match self.base.get_mut(off as usize) {
            Some(b) => *b = v,
            None => self.err = true,
        }
    }
    #[inline]
    fn gu16(&mut self, off: u32) -> u16 {
        let o = off as usize;
        match self.base.get(o..o + 2) {
            Some(s) => u16::from_le_bytes([s[0], s[1]]),
            None => {
                self.err = true;
                0
            }
        }
    }
    #[inline]
    fn pu16(&mut self, off: u32, v: u16) {
        let o = off as usize;
        match self.base.get_mut(o..o + 2) {
            Some(s) => s.copy_from_slice(&v.to_le_bytes()),
            None => self.err = true,
        }
    }
    #[inline]
    fn gu32(&mut self, off: u32) -> u32 {
        let o = off as usize;
        match self.base.get(o..o + 4) {
            Some(s) => u32::from_le_bytes([s[0], s[1], s[2], s[3]]),
            None => {
                self.err = true;
                0
            }
        }
    }
    #[inline]
    fn pu32(&mut self, off: u32, v: u32) {
        let o = off as usize;
        match self.base.get_mut(o..o + 4) {
            Some(s) => s.copy_from_slice(&v.to_le_bytes()),
            None => self.err = true,
        }
    }

    // ─── context / state field accessors ────────────────────────────────

    #[inline]
    fn ctx_num_stats(&mut self, c: u32) -> u32 {
        self.gu16(c) as u32
    }
    #[inline]
    fn ctx_set_num_stats(&mut self, c: u32, v: u32) {
        self.pu16(c, v as u16);
    }
    #[inline]
    fn ctx_summ_freq(&mut self, c: u32) -> u32 {
        self.gu16(c + 2) as u32
    }
    #[inline]
    fn ctx_set_summ_freq(&mut self, c: u32, v: u32) {
        self.pu16(c + 2, v as u16);
    }
    #[inline]
    fn ctx_stats(&mut self, c: u32) -> u32 {
        self.gu32(c + 4)
    }
    #[inline]
    fn ctx_set_stats(&mut self, c: u32, v: u32) {
        self.pu32(c + 4, v);
    }
    #[inline]
    fn ctx_suffix(&mut self, c: u32) -> u32 {
        self.gu32(c + 8)
    }
    #[inline]
    fn ctx_set_suffix(&mut self, c: u32, v: u32) {
        self.pu32(c + 8, v);
    }
    /// `Ppmd7Context_OneState` — the embedded single state overlaps
    /// SummFreq+Stats, i.e. offset `c + 2`.
    #[inline]
    fn one_state(c: u32) -> u32 {
        c + 2
    }

    #[inline]
    fn st_symbol(&mut self, s: u32) -> u8 {
        self.gu8(s)
    }
    #[inline]
    fn st_set_symbol(&mut self, s: u32, v: u8) {
        self.pu8(s, v);
    }
    #[inline]
    fn st_freq(&mut self, s: u32) -> u8 {
        self.gu8(s + 1)
    }
    #[inline]
    fn st_set_freq(&mut self, s: u32, v: u8) {
        self.pu8(s + 1, v);
    }
    /// `st.Freq += d` (read-modify-write; avoids `setter(getter())`).
    #[inline]
    fn st_add_freq(&mut self, s: u32, d: u8) {
        let f = self.st_freq(s);
        self.st_set_freq(s, f.wrapping_add(d));
    }
    /// `ctx.SummFreq += d`.
    #[inline]
    fn ctx_add_summ_freq(&mut self, c: u32, d: u32) {
        let f = self.ctx_summ_freq(c);
        self.ctx_set_summ_freq(c, f + d);
    }
    #[inline]
    fn st_successor(&mut self, s: u32) -> u32 {
        (self.gu16(s + 2) as u32) | ((self.gu16(s + 4) as u32) << 16)
    }
    #[inline]
    fn st_set_successor(&mut self, s: u32, v: u32) {
        self.pu16(s + 2, (v & 0xFFFF) as u16);
        self.pu16(s + 4, ((v >> 16) & 0xFFFF) as u16);
    }

    /// Copy state `src` onto state `dst` (6 bytes).
    #[inline]
    fn st_copy(&mut self, dst: u32, src: u32) {
        for i in 0..6 {
            let b = self.gu8(src + i);
            self.pu8(dst + i, b);
        }
    }
    /// Swap two 6-byte states.
    #[inline]
    fn st_swap(&mut self, a: u32, b: u32) {
        for i in 0..6 {
            let x = self.gu8(a + i);
            let y = self.gu8(b + i);
            self.pu8(a + i, y);
            self.pu8(b + i, x);
        }
    }

    #[inline]
    fn i2u(&self, indx: usize) -> u32 {
        self.indx2units[indx] as u32
    }
    #[inline]
    fn u2i(&self, nu: u32) -> usize {
        // nu in 1..=128
        self.units2indx[(nu as usize).wrapping_sub(1).min(127)] as usize
    }
    #[inline]
    fn u2b(nu: u32) -> u32 {
        nu * UNIT_SIZE
    }

    /// Copy `nu` units (12 bytes each) from `src` to `dst`.
    fn copy_units(&mut self, dst: u32, src: u32, nu: u32) {
        let n = (nu * UNIT_SIZE) as usize;
        let (d, s) = (dst as usize, src as usize);
        if d + n <= self.base.len() && s + n <= self.base.len() {
            self.base.copy_within(s..s + n, d);
        } else {
            self.err = true;
        }
    }

    // ─── allocator ──────────────────────────────────────────────────────

    fn insert_node(&mut self, node: u32, indx: usize) {
        let head = self.free_list[indx];
        self.pu32(node, head);
        self.free_list[indx] = node;
    }

    fn remove_node(&mut self, indx: usize) -> u32 {
        let node = self.free_list[indx];
        let next = self.gu32(node);
        self.free_list[indx] = next;
        node
    }

    fn split_block(&mut self, ptr: u32, old_indx: usize, new_indx: usize) {
        let nu = self.i2u(old_indx) - self.i2u(new_indx);
        let ptr = ptr + Self::u2b(self.i2u(new_indx));
        let mut i = self.u2i(nu);
        if self.i2u(i) != nu {
            i -= 1;
            let k = self.i2u(i);
            self.insert_node(ptr + Self::u2b(k), (nu - k - 1) as usize);
        }
        self.insert_node(ptr, i);
    }

    fn glue_free_blocks(&mut self) {
        // Node layout: Stamp u16 @0, NU u16 @2, Next u32 @4, Prev u32 @8.
        // The reference builds a doubly-linked list of all free blocks, sets
        // a head sentinel just past the arena, coalesces adjacent blocks,
        // and re-buckets them. We follow it directly.
        //
        // KNOWN LIMITATION (fails closed): this ports the classic LZMA SDK
        // GlueFreeBlocks. When a stream actually exhausts the suballocator —
        // e.g. a high-order model over a large, high-entropy payload in a
        // small (1 MiB) arena — a coalescing/re-bucketing difference from the
        // exact encoder build can make our allocator fail (and thus restart
        // the model) at a slightly different symbol than the encoder did,
        // desyncing the range coder. That surfaces as `Error::Corrupt`, never
        // wrong bytes and never an out-of-bounds access. Streams that don't
        // fill the arena (the overwhelming majority) are unaffected. Reaching
        // full allocator parity across every arena-exhausting input is
        // tracked as Phase 3 hardening.
        let head = self.align_offset + self.size; // sentinel node ref
        let mut n = head;
        self.glue_count = 255;

        for i in 0..PPMD_NUM_INDEXES {
            let nu = self.i2u(i) as u16;
            let mut next = self.free_list[i];
            self.free_list[i] = 0;
            while next != 0 {
                let node = next;
                // node->Next = n
                self.pu32(node + 4, n);
                // n = node->Prev = node  (NODE(n)->Prev = node; then n = node)
                self.pu32(n + 8, node);
                n = node;
                next = self.gu32(node); // *(Ref*)node — original free-list link
                self.pu16(node, 0); // Stamp = 0
                self.pu16(node + 2, nu); // NU
            }
        }

        // head node
        self.pu16(head, 1); // Stamp
        self.pu32(head + 4, n); // Next
        self.pu32(n + 8, head); // NODE(n)->Prev = head
        if self.lo_unit != self.hi_unit {
            self.pu16(self.lo_unit, 1); // Stamp guard
        }

        // Glue adjacent free blocks (walk head->Next round to head).
        let mut n = self.gu32(head + 4);
        while n != head {
            let node = n;
            let mut nu = self.gu16(node + 2) as u32;
            loop {
                let node2 = node + nu * UNIT_SIZE;
                let stamp = self.gu16(node2);
                let nu2 = self.gu16(node2 + 2) as u32;
                if stamp != 0 || nu + nu2 >= 0x10000 {
                    break;
                }
                nu += nu2;
                // unlink node2
                let prev = self.gu32(node2 + 8);
                let nxt = self.gu32(node2 + 4);
                self.pu32(prev + 4, nxt);
                self.pu32(nxt + 8, prev);
                self.pu16(node + 2, nu as u16);
            }
            n = self.gu32(node + 4);
            if self.err {
                return;
            }
        }

        // Refill free lists.
        let mut n = self.gu32(head + 4);
        while n != head {
            let mut node = n;
            let next = self.gu32(node + 4);
            let mut nu = self.gu16(node + 2) as u32;
            while nu > 128 {
                self.insert_node(node, PPMD_NUM_INDEXES - 1);
                nu -= 128;
                node += 128 * UNIT_SIZE;
            }
            let mut i = self.u2i(nu);
            if self.i2u(i) != nu {
                i -= 1;
                let k = self.i2u(i);
                self.insert_node(node + k * UNIT_SIZE, (nu - k - 1) as usize);
            }
            self.insert_node(node, i);
            n = next;
            if self.err {
                return;
            }
        }
    }

    fn alloc_units_rare(&mut self, indx: usize) -> u32 {
        if self.glue_count == 0 {
            self.glue_free_blocks();
            if self.free_list[indx] != 0 {
                return self.remove_node(indx);
            }
        }
        let mut i = indx;
        loop {
            i += 1;
            if i == PPMD_NUM_INDEXES {
                let num_bytes = Self::u2b(self.i2u(indx));
                self.glue_count = self.glue_count.wrapping_sub(1);
                return if self.units_start - self.text > num_bytes {
                    self.units_start -= num_bytes;
                    self.units_start
                } else {
                    0
                };
            }
            if self.free_list[i] != 0 {
                break;
            }
        }
        let ret = self.remove_node(i);
        self.split_block(ret, i, indx);
        ret
    }

    fn alloc_units(&mut self, indx: usize) -> u32 {
        if self.free_list[indx] != 0 {
            return self.remove_node(indx);
        }
        let num_bytes = Self::u2b(self.i2u(indx));
        if num_bytes <= self.hi_unit - self.lo_unit {
            let ret = self.lo_unit;
            self.lo_unit += num_bytes;
            return ret;
        }
        self.alloc_units_rare(indx)
    }

    fn shrink_units(&mut self, old_ptr: u32, old_nu: u32, new_nu: u32) -> u32 {
        let i0 = self.u2i(old_nu);
        let i1 = self.u2i(new_nu);
        if i0 == i1 {
            return old_ptr;
        }
        if self.free_list[i1] != 0 {
            let ptr = self.remove_node(i1);
            self.copy_units(ptr, old_ptr, new_nu);
            self.insert_node(old_ptr, i0);
            ptr
        } else {
            self.split_block(old_ptr, i0, i1);
            old_ptr
        }
    }

    // ─── init / restart ─────────────────────────────────────────────────

    pub(crate) fn init(&mut self, max_order: u32) {
        self.max_order = max_order;
        self.restart_model();
        self.dummy_see.shift = PPMD_PERIOD_BITS as u8;
        self.dummy_see.summ = 0;
        self.dummy_see.count = 64;
    }

    /// Seed `InitEsc` (RAR's header carries it explicitly). Only used by
    /// the RAR3/4 PPMd path.
    #[cfg_attr(not(feature = "rar3"), allow(dead_code))]
    pub(crate) fn set_init_esc(&mut self, v: u32) {
        self.init_esc = v;
    }

    fn restart_model(&mut self) {
        self.free_list = [0; PPMD_NUM_INDEXES];
        self.text = self.align_offset;
        self.hi_unit = self.text + self.size;
        let reserved = self.size / 8 / UNIT_SIZE * 7 * UNIT_SIZE;
        self.lo_unit = self.hi_unit - reserved;
        self.units_start = self.lo_unit;
        self.glue_count = 0;

        self.order_fall = self.max_order;
        let mo = if self.max_order < 12 {
            self.max_order
        } else {
            12
        };
        self.init_rl = -(mo as i32) - 1;
        self.run_length = self.init_rl;
        self.prev_success = 0;

        self.hi_unit -= UNIT_SIZE;
        let mc = self.hi_unit;
        self.min_context = mc;
        self.max_context = mc;
        self.ctx_set_suffix(mc, 0);
        self.ctx_set_num_stats(mc, 256);
        self.ctx_set_summ_freq(mc, 256 + 1);
        self.found_state = self.lo_unit;
        self.lo_unit += Self::u2b(256 / 2);
        let fs = self.found_state;
        self.ctx_set_stats(mc, fs);
        for i in 0..256u32 {
            let s = fs + i * 6;
            self.st_set_symbol(s, i as u8);
            self.st_set_freq(s, 1);
            self.st_set_successor(s, 0);
        }

        for i in 0..128 {
            for k in 0..8 {
                let val = (PPMD_BIN_SCALE - (K_INIT_BIN_ESC[k] as u32) / (i as u32 + 2)) as u16;
                let mut m = 0;
                while m < 64 {
                    self.bin_summ[i][k + m] = val;
                    m += 8;
                }
            }
        }

        for i in 0..25 {
            for k in 0..16 {
                let shift = (PPMD_PERIOD_BITS - 4) as u8;
                self.see[i][k] = See {
                    summ: ((5 * i as u32 + 10) << shift) as u16,
                    shift,
                    count: 4,
                };
            }
        }
    }

    // ─── model update helpers ───────────────────────────────────────────

    /// `CreateSuccessors`. Returns `Some(ctx)` or `None` (NULL → restart).
    fn create_successors(&mut self, skip: bool) -> Option<u32> {
        let mut c = self.min_context;
        let up_branch = self.st_successor(self.found_state);
        let mut ps: [u32; MAX_ORDER] = [0; MAX_ORDER];
        let mut num_ps = 0usize;

        if !skip {
            ps[num_ps] = self.found_state;
            num_ps += 1;
        }

        let found_sym = self.st_symbol(self.found_state);
        while self.ctx_suffix(c) != 0 {
            c = self.ctx_suffix(c);
            let s = if self.ctx_num_stats(c) != 1 {
                let mut ss = self.ctx_stats(c);
                while self.st_symbol(ss) != found_sym {
                    ss += 6;
                }
                ss
            } else {
                Self::one_state(c)
            };
            let successor = self.st_successor(s);
            if successor != up_branch {
                c = successor;
                if num_ps == 0 {
                    return Some(c);
                }
                break;
            }
            if num_ps >= MAX_ORDER {
                self.err = true;
                return None;
            }
            ps[num_ps] = s;
            num_ps += 1;
        }

        // upState
        let up_symbol = self.gu8(up_branch);
        let up_successor = up_branch + 1;
        let up_freq: u8 = if self.ctx_num_stats(c) == 1 {
            self.st_freq(Self::one_state(c))
        } else {
            let mut s = self.ctx_stats(c);
            while self.st_symbol(s) != up_symbol {
                s += 6;
            }
            let cf = self.st_freq(s) as u32 - 1;
            let s0 = self.ctx_summ_freq(c) - self.ctx_num_stats(c) - cf;
            (1 + if 2 * cf <= s0 {
                (5 * cf > s0) as u32
            } else {
                (2 * cf + 3 * s0 - 1) / (2 * s0)
            }) as u8
        };

        while num_ps != 0 {
            // AllocContext
            let c1 = if self.hi_unit != self.lo_unit {
                self.hi_unit -= UNIT_SIZE;
                self.hi_unit
            } else if self.free_list[0] != 0 {
                self.remove_node(0)
            } else {
                let r = self.alloc_units_rare(0);
                if r == 0 {
                    return None;
                }
                r
            };
            self.ctx_set_num_stats(c1, 1);
            let os = Self::one_state(c1);
            self.st_set_symbol(os, up_symbol);
            self.st_set_freq(os, up_freq);
            self.st_set_successor(os, up_successor);
            self.ctx_set_suffix(c1, c);
            num_ps -= 1;
            self.st_set_successor(ps[num_ps], c1);
            c = c1;
        }
        Some(c)
    }

    fn update_model(&mut self) {
        let f_successor = self.st_successor(self.found_state);
        let found_sym = self.st_symbol(self.found_state);
        let found_freq = self.st_freq(self.found_state);

        if found_freq < MAX_FREQ / 4 && self.ctx_suffix(self.min_context) != 0 {
            let c = self.ctx_suffix(self.min_context);
            if self.ctx_num_stats(c) == 1 {
                let s = Self::one_state(c);
                if self.st_freq(s) < 32 {
                    self.st_add_freq(s, 1);
                }
            } else {
                let mut s = self.ctx_stats(c);
                if self.st_symbol(s) != found_sym {
                    loop {
                        s += 6;
                        if self.st_symbol(s) == found_sym {
                            break;
                        }
                    }
                    if self.st_freq(s) >= self.st_freq(s - 6) {
                        self.st_swap(s, s - 6);
                        s -= 6;
                    }
                }
                if self.st_freq(s) < MAX_FREQ - 9 {
                    self.st_add_freq(s, 2);
                    self.ctx_add_summ_freq(c, 2);
                }
            }
        }

        if self.order_fall == 0 {
            match self.create_successors(true) {
                Some(mc) => {
                    self.min_context = mc;
                    self.max_context = mc;
                    self.st_set_successor(self.found_state, mc);
                }
                None => self.restart_model(),
            }
            return;
        }

        // *Text++ = found symbol
        self.pu8(self.text, found_sym);
        self.text += 1;
        let successor = self.text;
        if self.text >= self.units_start {
            self.restart_model();
            return;
        }

        let mut f_successor = f_successor;
        let mut successor = successor;
        if f_successor != 0 {
            if f_successor <= self.text {
                // f_successor points into the text region → materialise it.
                match self.create_successors(false) {
                    Some(cs) => f_successor = cs,
                    None => {
                        self.restart_model();
                        return;
                    }
                }
            }
            self.order_fall -= 1;
            if self.order_fall == 0 {
                successor = f_successor;
                if self.max_context != self.min_context {
                    self.text -= 1;
                }
            }
        } else {
            self.st_set_successor(self.found_state, successor);
            f_successor = self.min_context;
        }

        let ns = self.ctx_num_stats(self.min_context);
        let s0 = self.ctx_summ_freq(self.min_context) - ns - (found_freq as u32 - 1);

        let mut c = self.max_context;
        while c != self.min_context {
            let ns1 = self.ctx_num_stats(c);
            if ns1 != 1 {
                if ns1 & 1 == 0 {
                    // grow the stats block by one unit
                    let old_nu = ns1 >> 1;
                    let i = self.u2i(old_nu);
                    if i != self.u2i(old_nu + 1) {
                        let ptr = self.alloc_units(i + 1);
                        if ptr == 0 {
                            self.restart_model();
                            return;
                        }
                        let old_ptr = self.ctx_stats(c);
                        self.copy_units(ptr, old_ptr, old_nu);
                        self.insert_node(old_ptr, i);
                        self.ctx_set_stats(c, ptr);
                    }
                }
                let add = (2 * ns1 < ns) as u32
                    + 2 * ((4 * ns1 <= ns) as u32 & (self.ctx_summ_freq(c) <= 8 * ns1) as u32);
                self.ctx_add_summ_freq(c, add);
            } else {
                let s = self.alloc_units(0);
                if s == 0 {
                    self.restart_model();
                    return;
                }
                self.st_copy(s, Self::one_state(c));
                self.ctx_set_stats(c, s);
                let mut fr = self.st_freq(s);
                if fr < MAX_FREQ / 4 - 1 {
                    fr <<= 1;
                } else {
                    fr = MAX_FREQ - 4;
                }
                self.st_set_freq(s, fr);
                self.ctx_set_summ_freq(c, fr as u32 + self.init_esc + (ns > 3) as u32);
            }

            let cf = 2 * (found_freq as u32) * (self.ctx_summ_freq(c) + 6);
            let sf = s0 + self.ctx_summ_freq(c);
            let new_freq;
            if cf < 6 * sf {
                new_freq = 1 + (cf > sf) as u32 + (cf >= 4 * sf) as u32;
                self.ctx_add_summ_freq(c, 3);
            } else {
                new_freq =
                    4 + (cf >= 9 * sf) as u32 + (cf >= 12 * sf) as u32 + (cf >= 15 * sf) as u32;
                self.ctx_add_summ_freq(c, new_freq);
            }
            let stats = self.ctx_stats(c);
            let s = stats + ns1 * 6;
            self.st_set_successor(s, successor);
            self.st_set_symbol(s, found_sym);
            self.st_set_freq(s, new_freq as u8);
            self.ctx_set_num_stats(c, ns1 + 1);

            c = self.ctx_suffix(c);
            if self.err {
                return;
            }
        }

        self.max_context = f_successor;
        self.min_context = f_successor;
    }

    fn rescale(&mut self) {
        let stats = self.ctx_stats(self.min_context);
        let mut s = self.found_state;
        // Move found state to front (rotate).
        {
            let mut tmp = [0u8; 6];
            for i in 0..6 {
                tmp[i] = self.gu8(s + i as u32);
            }
            while s != stats {
                self.st_copy(s, s - 6);
                s -= 6;
            }
            for i in 0..6 {
                self.pu8(s + i as u32, tmp[i]);
            }
        }
        let mut esc_freq = self.ctx_summ_freq(self.min_context) - self.st_freq(s) as u32;
        self.st_add_freq(s, 4);
        let adder = (self.order_fall != 0) as u32;
        {
            let nf = ((self.st_freq(s) as u32 + adder) >> 1) as u8;
            self.st_set_freq(s, nf);
        }
        let mut sum_freq = self.st_freq(s) as u32;

        let mut i = self.ctx_num_stats(self.min_context) - 1;
        loop {
            s += 6;
            esc_freq -= self.st_freq(s) as u32;
            {
                let nf = ((self.st_freq(s) as u32 + adder) >> 1) as u8;
                self.st_set_freq(s, nf);
            }
            sum_freq += self.st_freq(s) as u32;
            if self.st_freq(s) > self.st_freq(s - 6) {
                let mut s1 = s;
                let mut tmp = [0u8; 6];
                for j in 0..6 {
                    tmp[j] = self.gu8(s1 + j as u32);
                }
                let tmp_freq = tmp[1];
                loop {
                    self.st_copy(s1, s1 - 6);
                    s1 -= 6;
                    if s1 == stats || tmp_freq <= self.st_freq(s1 - 6) {
                        break;
                    }
                }
                for j in 0..6 {
                    self.pu8(s1 + j as u32, tmp[j]);
                }
            }
            i -= 1;
            if i == 0 {
                break;
            }
        }

        if self.st_freq(s) == 0 {
            let mut cnt = 0u32;
            loop {
                cnt += 1;
                s -= 6;
                if self.st_freq(s) != 0 {
                    break;
                }
            }
            esc_freq += cnt;
            let num_stats = self.ctx_num_stats(self.min_context);
            let new_ns = num_stats - cnt;
            self.ctx_set_num_stats(self.min_context, new_ns);
            if new_ns == 1 {
                let mut tmp = [0u8; 6];
                for j in 0..6 {
                    tmp[j] = self.gu8(stats + j as u32);
                }
                let mut tmp_freq = tmp[1];
                loop {
                    tmp_freq = tmp_freq - (tmp_freq >> 1);
                    esc_freq >>= 1;
                    if esc_freq <= 1 {
                        break;
                    }
                }
                tmp[1] = tmp_freq;
                self.insert_node(stats, self.u2i((num_stats + 1) >> 1));
                let fs = Self::one_state(self.min_context);
                self.found_state = fs;
                for j in 0..6 {
                    self.pu8(fs + j as u32, tmp[j]);
                }
                return;
            }
            let n0 = (num_stats + 1) >> 1;
            let n1 = (new_ns + 1) >> 1;
            if n0 != n1 {
                let ns = self.shrink_units(stats, n0, n1);
                self.ctx_set_stats(self.min_context, ns);
            }
        }
        let stats = self.ctx_stats(self.min_context);
        self.ctx_set_summ_freq(self.min_context, sum_freq + esc_freq - (esc_freq >> 1));
        self.found_state = stats;
    }

    /// `Ppmd7_MakeEscFreq`. Returns the SEE ref and writes `esc_freq`.
    fn make_esc_freq(&mut self, num_masked: u32) -> (SeeRef, u32) {
        let num_stats = self.ctx_num_stats(self.min_context);
        if num_stats != 256 {
            let non_masked = num_stats - num_masked;
            let suffix = self.ctx_suffix(self.min_context);
            let suffix_ns = self.ctx_num_stats(suffix) as i64;
            let idx_row = self.ns2indx[(non_masked - 1) as usize] as usize;
            let diff = suffix_ns - num_stats as i64;
            let idx_col = ((non_masked as i64) < diff) as usize
                + 2 * (self.ctx_summ_freq(self.min_context) < 11 * num_stats) as usize
                + 4 * (num_masked > non_masked) as usize
                + self.hi_bits_flag as usize;
            let see = &mut self.see[idx_row][idx_col];
            let r = (see.summ >> see.shift) as u32;
            see.summ = see.summ.wrapping_sub(r as u16);
            let esc = r + (r == 0) as u32;
            (SeeRef::Cell(idx_row, idx_col), esc)
        } else {
            (SeeRef::Dummy, 1)
        }
    }

    #[inline]
    fn see_update(&mut self, sr: SeeRef) {
        if let SeeRef::Cell(i, k) = sr {
            self.see[i][k].update();
        }
    }
    #[inline]
    fn see_add_summ(&mut self, sr: SeeRef, v: u32) {
        if let SeeRef::Cell(i, k) = sr {
            let s = &mut self.see[i][k];
            s.summ = s.summ.wrapping_add(v as u16);
        }
    }

    fn next_context(&mut self) {
        let c = self.st_successor(self.found_state);
        if self.order_fall == 0 && c > self.text {
            self.min_context = c;
            self.max_context = c;
        } else {
            self.update_model();
        }
    }

    fn update1(&mut self) {
        let s = self.found_state;
        self.st_add_freq(s, 4);
        let c = self.min_context;
        self.ctx_add_summ_freq(c, 4);
        if self.st_freq(s) > self.st_freq(s - 6) {
            self.st_swap(s, s - 6);
            self.found_state = s - 6;
            if self.st_freq(s - 6) > MAX_FREQ {
                self.rescale();
            }
        }
        self.next_context();
    }

    fn update1_0(&mut self) {
        let s = self.found_state;
        self.prev_success =
            (2 * self.st_freq(s) as u32 > self.ctx_summ_freq(self.min_context)) as u32;
        self.run_length += self.prev_success as i32;
        let c = self.min_context;
        self.ctx_add_summ_freq(c, 4);
        self.st_add_freq(s, 4);
        if self.st_freq(s) > MAX_FREQ {
            self.rescale();
        }
        self.next_context();
    }

    fn update_bin(&mut self) {
        let s = self.found_state;
        let f = self.st_freq(s);
        self.st_set_freq(s, f + (f < 128) as u8);
        self.prev_success = 1;
        self.run_length += 1;
        self.next_context();
    }

    fn update2(&mut self) {
        let s = self.found_state;
        let c = self.min_context;
        self.ctx_add_summ_freq(c, 4);
        self.st_add_freq(s, 4);
        if self.st_freq(s) > MAX_FREQ {
            self.rescale();
        }
        self.run_length = self.init_rl;
        self.update_model();
    }

    // ─── decode ─────────────────────────────────────────────────────────

    /// Decode one byte symbol. `Err(Corrupt)` on model/stream inconsistency
    /// (the reference's `-1`/`-2` returns) or arena OOB.
    pub(crate) fn decode_symbol(&mut self, rc: &mut RangeDec) -> Result<u8, Error> {
        let mut char_mask = [0u8; 256];

        if self.ctx_num_stats(self.min_context) != 1 {
            let mut s = self.ctx_stats(self.min_context);
            let count = rc.get_threshold(self.ctx_summ_freq(self.min_context));
            let mut hi_cnt = self.st_freq(s) as u32;
            if count < hi_cnt {
                rc.decode(0, hi_cnt);
                self.found_state = s;
                let sym = self.st_symbol(s);
                self.update1_0();
                return self.finish(sym);
            }
            self.prev_success = 0;
            let mut i = self.ctx_num_stats(self.min_context) - 1;
            loop {
                s += 6;
                let f = self.st_freq(s) as u32;
                hi_cnt += f;
                if hi_cnt > count {
                    rc.decode(hi_cnt - f, f);
                    self.found_state = s;
                    let sym = self.st_symbol(s);
                    self.update1();
                    return self.finish(sym);
                }
                i -= 1;
                if i == 0 {
                    break;
                }
            }
            if count >= self.ctx_summ_freq(self.min_context) {
                return Err(Error::Corrupt);
            }
            self.hi_bits_flag = self.hb2flag[self.st_symbol(self.found_state) as usize] as u32;
            rc.decode(hi_cnt, self.ctx_summ_freq(self.min_context) - hi_cnt);
            for m in char_mask.iter_mut() {
                *m = 0xFF;
            }
            char_mask[self.st_symbol(s) as usize] = 0;
            let mut i = self.ctx_num_stats(self.min_context) - 1;
            while i != 0 {
                s -= 6;
                char_mask[self.st_symbol(s) as usize] = 0;
                i -= 1;
            }
        } else {
            let (row, col) = self.bin_summ_index();
            let prob = self.bin_summ[row][col] as u32;
            let bit = rc.decode_bit(prob);
            if self.err || rc.err() {
                return Err(Error::Corrupt);
            }
            if bit == 0 {
                self.bin_summ[row][col] = (prob + (1 << PPMD_INT_BITS) - get_mean(prob)) as u16;
                let s = Self::one_state(self.min_context);
                self.found_state = s;
                let sym = self.st_symbol(s);
                self.update_bin();
                return self.finish(sym);
            }
            let newp = prob - get_mean(prob);
            self.bin_summ[row][col] = newp as u16;
            self.init_esc = K_EXP_ESCAPE[(newp >> 10) as usize & 0xF] as u32;
            for m in char_mask.iter_mut() {
                *m = 0xFF;
            }
            let os = Self::one_state(self.min_context);
            char_mask[self.st_symbol(os) as usize] = 0;
            self.prev_success = 0;
        }

        // Escape loop.
        loop {
            if self.err || rc.err() {
                return Err(Error::Corrupt);
            }
            let mut num_masked = self.ctx_num_stats(self.min_context);
            loop {
                self.order_fall += 1;
                let suffix = self.ctx_suffix(self.min_context);
                if suffix == 0 {
                    return Err(Error::Corrupt);
                }
                self.min_context = suffix;
                if self.ctx_num_stats(self.min_context) != num_masked {
                    break;
                }
            }
            let mut hi_cnt = 0u32;
            let mut s = self.ctx_stats(self.min_context);
            let num = self.ctx_num_stats(self.min_context) - num_masked;
            let mut ps: [u32; 256] = [0; 256];
            let mut i = 0usize;
            loop {
                let sym = self.st_symbol(s) as usize;
                let masked = char_mask[sym];
                if masked != 0 {
                    hi_cnt += self.st_freq(s) as u32;
                    ps[i] = s;
                    i += 1;
                }
                s += 6;
                if i as u32 == num {
                    break;
                }
                if self.err {
                    return Err(Error::Corrupt);
                }
            }

            let (see_ref, mut freq_sum) = self.make_esc_freq(num_masked);
            freq_sum += hi_cnt;
            let count = rc.get_threshold(freq_sum);

            if count < hi_cnt {
                let mut acc = 0u32;
                let mut idx = 0usize;
                loop {
                    acc += self.st_freq(ps[idx]) as u32;
                    if acc > count {
                        break;
                    }
                    idx += 1;
                }
                let sstate = ps[idx];
                let f = self.st_freq(sstate) as u32;
                rc.decode(acc - f, f);
                self.see_update(see_ref);
                self.found_state = sstate;
                let sym = self.st_symbol(sstate);
                self.update2();
                return self.finish(sym);
            }
            if count >= freq_sum {
                return Err(Error::Corrupt);
            }
            rc.decode(hi_cnt, freq_sum - hi_cnt);
            self.see_add_summ(see_ref, freq_sum);
            let mut j = i;
            while j != 0 {
                j -= 1;
                char_mask[self.st_symbol(ps[j]) as usize] = 0;
            }
            num_masked = self.ctx_num_stats(self.min_context);
            let _ = num_masked;
        }
    }

    #[inline]
    fn finish(&mut self, sym: u8) -> Result<u8, Error> {
        if self.err {
            Err(Error::Corrupt)
        } else {
            Ok(sym)
        }
    }

    /// `Ppmd7_GetBinSumm` index computation (also sets `hi_bits_flag`).
    fn bin_summ_index(&mut self) -> (usize, usize) {
        let os = Self::one_state(self.min_context);
        let os_freq = self.st_freq(os);
        let suffix = self.ctx_suffix(self.min_context);
        let suffix_ns = self.ctx_num_stats(suffix);
        let found_sym = self.st_symbol(self.found_state);
        self.hi_bits_flag = self.hb2flag[found_sym as usize] as u32;
        let os_sym = self.st_symbol(os);
        let row = (os_freq - 1) as usize;
        let col = self.prev_success as usize
            + self.ns2bsindx[(suffix_ns - 1) as usize] as usize
            + self.hi_bits_flag as usize
            + 2 * self.hb2flag[os_sym as usize] as usize
            + ((self.run_length >> 26) & 0x20) as usize;
        (row.min(127), col.min(63))
    }
}
