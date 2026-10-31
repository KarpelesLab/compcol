//! PPMd variant I rev. 1 context model (`Ppmd8`) and its range decoder.
//!
//! Safe-Rust port of Igor Pavlov's public-domain `Ppmd8.c` / `Ppmd8Dec.c`
//! (LZMA SDK / 7-Zip), itself based on Dmitry Shkarin's PPMd var.I rev. 1
//! (2002) and Dmitry Subbotin's carry-less range coder (1999), all public
//! domain. This is the model ZIP method 98 uses.
//!
//! As in [`super::ppmd7`], every context (12 bytes), state (6 bytes) and
//! free-list node (12 bytes) lives in one byte arena, addressed by `u32`
//! offset ("ref") through little-endian accessors; ref `0` is null. The
//! layout matches the reference byte for byte, which matters: when memory
//! runs out the model restarts or prunes itself (`RestoreModel`), and the
//! allocator must make exactly the same choices as the encoder did.
//!
//! The freeze restore method (`PPMD8_FREEZE_SUPPORT`) is not ported; 7-Zip
//! does not build it either and rejects such streams.

// The model walks a flat byte arena by 32-bit offset; explicit index loops
// mirror the reference's pointer arithmetic.
#![allow(clippy::needless_range_loop)]

extern crate alloc;

use alloc::vec::Vec;

use crate::error::Error;

const UNIT_SIZE: u32 = 12;
const MAX_FREQ: u32 = 124;
const NUM_INDEXES: usize = 38;
const BIN_SCALE: u32 = 1 << 14;
const INT_BITS: u32 = 7;
const PERIOD_BITS: u32 = 7;
/// Highest model order ZIP method 98 can carry (4-bit field + 1).
pub(crate) const MAX_ORDER: u32 = 16;
const EMPTY_NODE: u32 = 0xFFFF_FFFF;

const FLAG_RESCALED: u8 = 1 << 2;
const FLAG_PREV_HIGH: u8 = 1 << 4;

pub(crate) const RESTORE_RESTART: u32 = 0;
pub(crate) const RESTORE_CUT_OFF: u32 = 1;

const K_EXP_ESCAPE: [u8; 16] = [25, 14, 9, 7, 5, 5, 4, 4, 4, 3, 3, 3, 2, 2, 2, 2];
const K_INIT_BIN_ESC: [u16; 8] = [
    0x3CDD, 0x1F3F, 0x59BF, 0x48F3, 0x64A1, 0x5ABC, 0x6632, 0x6051,
];

const SEE_ROWS: usize = 24;
const SEE_COLS: usize = 32;
const BIN_ROWS: usize = 25;
const BIN_COLS: usize = 64;

/// Upper bound on suffix-chain steps for one symbol. A valid model never
/// walks more than `MAX_ORDER + 1` contexts; the guard keeps a damaged
/// arena from looping.
const MAX_CHAIN: u32 = MAX_ORDER + 2;

#[inline]
fn hi_bits_flag3(sym: u32) -> u8 {
    (((sym + 0xC0) >> (8 - 3)) & (1 << 3)) as u8
}
#[inline]
fn hi_bits_flag4(sym: u32) -> u8 {
    (((sym + 0xC0) >> (8 - 4)) & (1 << 4)) as u8
}
#[inline]
fn get_mean(prob: u32) -> u32 {
    (prob + (1 << (PERIOD_BITS - 2))) >> PERIOD_BITS
}

// ─── range decoder ──────────────────────────────────────────────────────

const K_TOP: u32 = 1 << 24;
const K_BOT: u32 = 1 << 15;
/// A normalisation reads at most 4 bytes when the coder's invariants hold
/// (`low + range <= 2^32`, `range >= 1`). The cap only trips on a broken
/// state, and bounds how far one symbol can read ahead.
const MAX_NORM_STEPS: u32 = 8;
/// Upper bound on the input one symbol can consume: at most `MAX_CHAIN + 1`
/// normalisations of at most `MAX_NORM_STEPS` bytes each.
pub(crate) const MAX_BYTES_PER_SYMBOL: usize = ((MAX_CHAIN + 2) * MAX_NORM_STEPS) as usize;

/// Saved range-coder registers, kept between calls.
#[derive(Clone, Copy, Default)]
pub(crate) struct RcState {
    pub(crate) range: u32,
    pub(crate) code: u32,
    pub(crate) low: u32,
}

impl RcState {
    /// `Ppmd8_Init_RangeDec`: four big-endian bytes. A code of all ones
    /// can't come from the encoder.
    pub(crate) fn init(b: [u8; 4]) -> Result<Self, Error> {
        let code = u32::from_be_bytes(b);
        if code == 0xFFFF_FFFF {
            return Err(Error::Corrupt);
        }
        Ok(Self {
            range: 0xFFFF_FFFF,
            code,
            low: 0,
        })
    }
}

/// Range decoder over a borrowed input window. Reads past the end of the
/// window return zero and are noted by [`RangeDec::overran`].
pub(crate) struct RangeDec<'a> {
    pub(crate) st: RcState,
    buf: &'a [u8],
    pub(crate) pos: usize,
    err: bool,
}

impl<'a> RangeDec<'a> {
    pub(crate) fn new(st: RcState, buf: &'a [u8], pos: usize) -> Self {
        Self {
            st,
            buf,
            pos,
            err: false,
        }
    }

    #[inline]
    pub(crate) fn overran(&self) -> bool {
        self.pos > self.buf.len()
    }

    #[inline]
    fn read_byte(&mut self) -> u32 {
        let b = self.buf.get(self.pos).copied().unwrap_or(0);
        self.pos += 1;
        b as u32
    }

    /// `RC_GetThreshold`: `code / (range /= total)`.
    #[inline]
    fn threshold(&mut self, total: u32) -> u32 {
        if total == 0 {
            self.err = true;
            return 0;
        }
        self.st.range /= total;
        if self.st.range == 0 {
            self.err = true;
            return 0;
        }
        self.st.code / self.st.range
    }

    /// `RC_Decode` (the reference normalises lazily, see `decode_final`).
    #[inline]
    fn decode(&mut self, start: u32, size: u32) {
        let start = start.wrapping_mul(self.st.range);
        self.st.low = self.st.low.wrapping_add(start);
        self.st.code = self.st.code.wrapping_sub(start);
        self.st.range = self.st.range.wrapping_mul(size);
    }

    #[inline]
    fn decode_final(&mut self, start: u32, size: u32) {
        self.decode(start, size);
        self.normalize();
    }

    /// `RC_NORM`.
    #[inline]
    fn normalize(&mut self) {
        let mut steps = 0;
        loop {
            let st = &mut self.st;
            if (st.low ^ st.low.wrapping_add(st.range)) >= K_TOP {
                if st.range >= K_BOT {
                    return;
                }
                st.range = st.low.wrapping_neg() & (K_BOT - 1);
            }
            if steps == MAX_NORM_STEPS {
                self.err = true;
                return;
            }
            steps += 1;
            let b = self.read_byte();
            let st = &mut self.st;
            st.code = (st.code << 8) | b;
            st.range <<= 8;
            st.low <<= 8;
        }
    }
}

// ─── model ──────────────────────────────────────────────────────────────

/// One SEE (secondary escape estimation) cell.
#[derive(Clone, Copy, Default)]
struct See {
    summ: u16,
    shift: u8,
    count: u8,
}

impl See {
    /// `Ppmd_See_UPDATE`.
    #[inline]
    fn update(&mut self) {
        if (self.shift as u32) < PERIOD_BITS {
            self.count = self.count.wrapping_sub(1);
            if self.count == 0 {
                self.summ = self.summ.wrapping_shl(1);
                self.count = 3u8.wrapping_shl(self.shift as u32);
                self.shift += 1;
            }
        }
    }
}

/// Which SEE cell `make_esc_freq` picked.
#[derive(Clone, Copy)]
enum SeeRef {
    Dummy,
    Cell(usize),
}

/// Result of decoding one symbol.
pub(crate) enum Sym {
    Byte(u8),
    /// The encoder's end marker (an escape out of the order-0 context).
    End,
}

/// `Ppmd8_GlueFreeBlocks` and `ExpandTextArea` keep a pointer to the
/// "next" field being patched: either a local head or a node's `Next`.
#[derive(Clone, Copy)]
enum Link {
    Local,
    FreeList(usize),
    Node(u32),
}

pub(crate) struct Ppmd8 {
    base: Vec<u8>,
    size: u32,
    align_offset: u32,
    err: bool,

    min_context: u32,
    max_context: u32,
    found_state: u32,
    order_fall: u32,
    init_esc: u32,
    prev_success: u32,
    max_order: u32,
    restore_method: u32,
    run_length: i32,
    init_rl: i32,

    glue_count: u32,
    text: u32,
    lo_unit: u32,
    hi_unit: u32,
    units_start: u32,

    indx2units: [u8; NUM_INDEXES],
    units2indx: [u8; 128],
    free_list: [u32; NUM_INDEXES],
    stamps: [u32; NUM_INDEXES],
    ns2bsindx: [u8; 256],
    ns2indx: [u8; 260],
    dummy_see: See,
    see: [See; SEE_ROWS * SEE_COLS],
    bin_summ: [u16; BIN_ROWS * BIN_COLS],
}

impl Ppmd8 {
    /// `Ppmd8_Construct` + `Ppmd8_Alloc`. The arena is allocated fallibly;
    /// failure returns [`Error::Unsupported`].
    pub(crate) fn new(mem_size: u32) -> Result<Self, Error> {
        if mem_size < 2048 {
            return Err(Error::BadHeader);
        }
        let align_offset = 4u32.wrapping_sub(mem_size) & 3;
        let total = (align_offset as usize) + mem_size as usize;
        let mut base = Vec::new();
        base.try_reserve_exact(total)
            .map_err(|_| Error::Unsupported)?;
        base.resize(total, 0);
        let mut p = Self {
            base,
            size: mem_size,
            align_offset,
            err: false,
            min_context: 0,
            max_context: 0,
            found_state: 0,
            order_fall: 0,
            init_esc: 0,
            prev_success: 0,
            max_order: 0,
            restore_method: 0,
            run_length: 0,
            init_rl: 0,
            glue_count: 0,
            text: 0,
            lo_unit: 0,
            hi_unit: 0,
            units_start: 0,
            indx2units: [0; NUM_INDEXES],
            units2indx: [0; 128],
            free_list: [0; NUM_INDEXES],
            stamps: [0; NUM_INDEXES],
            ns2bsindx: [0; 256],
            ns2indx: [0; 260],
            dummy_see: See::default(),
            see: [See::default(); SEE_ROWS * SEE_COLS],
            bin_summ: [0; BIN_ROWS * BIN_COLS],
        };
        p.construct_tables();
        Ok(p)
    }

    pub(crate) fn mem_size(&self) -> u32 {
        self.size
    }

    fn construct_tables(&mut self) {
        let mut k = 0usize;
        for i in 0..NUM_INDEXES {
            let step = if i >= 12 { 4 } else { (i >> 2) + 1 };
            for _ in 0..step {
                self.units2indx[k] = i as u8;
                k += 1;
            }
            self.indx2units[i] = k as u8;
        }
        self.ns2bsindx[0] = 0;
        self.ns2bsindx[1] = 2;
        self.ns2bsindx[2..11].fill(4);
        self.ns2bsindx[11..].fill(6);

        for i in 0..5 {
            self.ns2indx[i] = i as u8;
        }
        let mut m = 5u32;
        let mut k = 1u32;
        for i in 5..260 {
            self.ns2indx[i] = m as u8;
            k -= 1;
            if k == 0 {
                m += 1;
                k = m - 4;
            }
        }
    }

    /// `Ppmd8_Init`.
    pub(crate) fn init(&mut self, max_order: u32, restore_method: u32) {
        self.max_order = max_order;
        self.restore_method = restore_method;
        self.err = false;
        self.restart_model();
    }

    // ─── arena accessors (little-endian, bounds-checked) ────────────────

    #[inline]
    fn gu8(&mut self, off: u32) -> u32 {
        match self.base.get(off as usize) {
            Some(&b) => b as u32,
            None => {
                self.err = true;
                0
            }
        }
    }
    #[inline]
    fn pu8(&mut self, off: u32, v: u32) {
        match self.base.get_mut(off as usize) {
            Some(b) => *b = v as u8,
            None => self.err = true,
        }
    }
    #[inline]
    fn gu16(&mut self, off: u32) -> u32 {
        let o = off as usize;
        match self.base.get(o..o.wrapping_add(2)) {
            Some(s) => u16::from_le_bytes([s[0], s[1]]) as u32,
            None => {
                self.err = true;
                0
            }
        }
    }
    #[inline]
    fn pu16(&mut self, off: u32, v: u32) {
        let o = off as usize;
        match self.base.get_mut(o..o.wrapping_add(2)) {
            Some(s) => s.copy_from_slice(&(v as u16).to_le_bytes()),
            None => self.err = true,
        }
    }
    #[inline]
    fn gu32(&mut self, off: u32) -> u32 {
        let o = off as usize;
        match self.base.get(o..o.wrapping_add(4)) {
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
        match self.base.get_mut(o..o.wrapping_add(4)) {
            Some(s) => s.copy_from_slice(&v.to_le_bytes()),
            None => self.err = true,
        }
    }

    /// Copy `n` bytes inside the arena (`memmove`).
    #[inline]
    fn copy_bytes(&mut self, dst: u32, src: u32, n: u32) {
        let (d, s, n) = (dst as usize, src as usize, n as usize);
        let len = self.base.len();
        if d.checked_add(n).is_some_and(|e| e <= len) && s.checked_add(n).is_some_and(|e| e <= len)
        {
            self.base.copy_within(s..s + n, d);
        } else {
            self.err = true;
        }
    }

    // Context: NumStats u8 @0, Flags u8 @1, SummFreq u16 @2 (or the one
    // state's Symbol @2 / Freq @3), Stats u32 @4 (or the one state's
    // successor), Suffix u32 @8.
    #[inline]
    fn num_stats(&mut self, c: u32) -> u32 {
        self.gu8(c)
    }
    #[inline]
    fn set_num_stats(&mut self, c: u32, v: u32) {
        self.pu8(c, v);
    }
    #[inline]
    fn flags(&mut self, c: u32) -> u8 {
        self.gu8(c.wrapping_add(1)) as u8
    }
    #[inline]
    fn set_flags(&mut self, c: u32, v: u8) {
        self.pu8(c.wrapping_add(1), v as u32);
    }
    #[inline]
    fn summ_freq(&mut self, c: u32) -> u32 {
        self.gu16(c.wrapping_add(2))
    }
    #[inline]
    fn set_summ_freq(&mut self, c: u32, v: u32) {
        self.pu16(c.wrapping_add(2), v);
    }
    #[inline]
    fn stats(&mut self, c: u32) -> u32 {
        self.gu32(c.wrapping_add(4))
    }
    #[inline]
    fn set_stats(&mut self, c: u32, v: u32) {
        self.pu32(c.wrapping_add(4), v);
    }
    #[inline]
    fn suffix(&mut self, c: u32) -> u32 {
        self.gu32(c.wrapping_add(8))
    }
    #[inline]
    fn set_suffix(&mut self, c: u32, v: u32) {
        self.pu32(c.wrapping_add(8), v);
    }
    /// `Ppmd8Context_OneState`: the inline state of a binary context.
    #[inline]
    fn one_state(c: u32) -> u32 {
        c.wrapping_add(2)
    }

    // State: Symbol u8 @0, Freq u8 @1, Successor u32 @2 (two LE halves).
    #[inline]
    fn sym(&mut self, s: u32) -> u32 {
        self.gu8(s)
    }
    #[inline]
    fn set_sym(&mut self, s: u32, v: u32) {
        self.pu8(s, v);
    }
    #[inline]
    fn freq(&mut self, s: u32) -> u32 {
        self.gu8(s.wrapping_add(1))
    }
    #[inline]
    fn set_freq(&mut self, s: u32, v: u32) {
        self.pu8(s.wrapping_add(1), v);
    }
    #[inline]
    fn successor(&mut self, s: u32) -> u32 {
        self.gu32(s.wrapping_add(2))
    }
    #[inline]
    fn set_successor(&mut self, s: u32, v: u32) {
        self.pu32(s.wrapping_add(2), v);
    }
    #[inline]
    fn copy_state(&mut self, dst: u32, src: u32) {
        self.copy_bytes(dst, src, 6);
    }
    #[inline]
    fn read_state(&mut self, s: u32) -> [u8; 6] {
        let o = s as usize;
        match self.base.get(o..o.wrapping_add(6)) {
            Some(b) => [b[0], b[1], b[2], b[3], b[4], b[5]],
            None => {
                self.err = true;
                [0; 6]
            }
        }
    }
    #[inline]
    fn write_state(&mut self, s: u32, v: [u8; 6]) {
        let o = s as usize;
        match self.base.get_mut(o..o.wrapping_add(6)) {
            Some(b) => b.copy_from_slice(&v),
            None => self.err = true,
        }
    }
    #[inline]
    fn swap_states(&mut self, a: u32, b: u32) {
        let ta = self.read_state(a);
        let tb = self.read_state(b);
        self.write_state(a, tb);
        self.write_state(b, ta);
    }

    /// Find the state for `sym` in a multi-symbol context's stats.
    #[inline]
    fn find_state(&mut self, c: u32, sym: u32) -> u32 {
        let n = self.num_stats(c) + 1;
        let mut s = self.stats(c);
        for _ in 0..n {
            if self.sym(s) == sym {
                return s;
            }
            s = s.wrapping_add(6);
        }
        self.err = true;
        self.stats(c)
    }

    #[inline]
    fn i2u(&self, indx: usize) -> u32 {
        self.indx2units[indx.min(NUM_INDEXES - 1)] as u32
    }
    #[inline]
    fn u2i(&mut self, nu: u32) -> usize {
        if !(1..=128).contains(&nu) {
            self.err = true;
            return 0;
        }
        self.units2indx[nu as usize - 1] as usize
    }
    #[inline]
    fn u2b(nu: u32) -> u32 {
        nu.wrapping_mul(UNIT_SIZE)
    }

    // ─── allocator ──────────────────────────────────────────────────────
    //
    // Free node: Stamp u32 @0 (EMPTY_NODE), Next u32 @4, NU u32 @8.

    fn insert_node(&mut self, node: u32, indx: usize) {
        let indx = indx.min(NUM_INDEXES - 1);
        self.pu32(node, EMPTY_NODE);
        self.pu32(node.wrapping_add(4), self.free_list[indx]);
        let nu = self.i2u(indx);
        self.pu32(node.wrapping_add(8), nu);
        self.free_list[indx] = node;
        self.stamps[indx] = self.stamps[indx].wrapping_add(1);
    }

    fn remove_node(&mut self, indx: usize) -> u32 {
        let node = self.free_list[indx];
        self.free_list[indx] = self.gu32(node.wrapping_add(4));
        self.stamps[indx] = self.stamps[indx].wrapping_sub(1);
        node
    }

    fn split_block(&mut self, ptr: u32, old_indx: usize, new_indx: usize) {
        let nu = self.i2u(old_indx).wrapping_sub(self.i2u(new_indx));
        let ptr = ptr.wrapping_add(Self::u2b(self.i2u(new_indx)));
        let mut i = self.u2i(nu);
        if self.i2u(i) != nu {
            i = i.wrapping_sub(1);
            let k = self.i2u(i);
            self.insert_node(
                ptr.wrapping_add(Self::u2b(k)),
                nu.wrapping_sub(k).wrapping_sub(1) as usize,
            );
        }
        self.insert_node(ptr, i);
    }

    fn set_link(&mut self, link: Link, local: &mut u32, v: u32) {
        match link {
            Link::Local => *local = v,
            Link::FreeList(i) => self.free_list[i] = v,
            Link::Node(n) => self.pu32(n.wrapping_add(4), v),
        }
    }

    /// Iteration bound for allocator walks: more steps than the arena has
    /// units means the lists are damaged.
    fn walk_limit(&self) -> u32 {
        self.size / UNIT_SIZE + 2 * NUM_INDEXES as u32 + 16
    }

    fn glue_free_blocks(&mut self) {
        self.glue_count = 1 << 13;
        self.stamps = [0; NUM_INDEXES];
        if self.lo_unit != self.hi_unit {
            self.pu32(self.lo_unit, 0);
        }

        let limit = self.walk_limit();
        let mut steps = 0u32;
        let mut head = 0u32;
        let mut prev = Link::Local;
        for i in 0..NUM_INDEXES {
            let mut next = self.free_list[i];
            self.free_list[i] = 0;
            while next != 0 {
                steps += 1;
                if steps > limit || self.err {
                    self.err = true;
                    return;
                }
                let node = next;
                let mut nu = self.gu32(node.wrapping_add(8));
                self.set_link(prev, &mut head, next);
                next = self.gu32(node.wrapping_add(4));
                if nu != 0 {
                    prev = Link::Node(node);
                    loop {
                        let node2 = node.wrapping_add(Self::u2b(nu));
                        if self.gu32(node2) != EMPTY_NODE || self.err {
                            break;
                        }
                        steps += 1;
                        if steps > limit {
                            self.err = true;
                            return;
                        }
                        nu = nu.wrapping_add(self.gu32(node2.wrapping_add(8)));
                        self.pu32(node2.wrapping_add(8), 0);
                        self.pu32(node.wrapping_add(8), nu);
                    }
                }
            }
        }
        self.set_link(prev, &mut head, 0);

        let mut n = head;
        while n != 0 {
            steps += 1;
            if steps > limit || self.err {
                self.err = true;
                return;
            }
            let mut node = n;
            let mut nu = self.gu32(node.wrapping_add(8));
            n = self.gu32(node.wrapping_add(4));
            if nu == 0 {
                continue;
            }
            while nu > 128 {
                self.insert_node(node, NUM_INDEXES - 1);
                nu -= 128;
                node = node.wrapping_add(128 * UNIT_SIZE);
            }
            let mut i = self.u2i(nu);
            if self.i2u(i) != nu {
                i = i.wrapping_sub(1);
                let k = self.i2u(i);
                self.insert_node(
                    node.wrapping_add(Self::u2b(k)),
                    nu.wrapping_sub(k).wrapping_sub(1) as usize,
                );
            }
            self.insert_node(node, i);
        }
    }

    /// `Ppmd8_AllocUnitsRare`. Returns 0 when memory is exhausted.
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
            if i == NUM_INDEXES {
                let num_bytes = Self::u2b(self.i2u(indx));
                let us = self.units_start;
                self.glue_count = self.glue_count.wrapping_sub(1);
                return if us.wrapping_sub(self.text) > num_bytes {
                    self.units_start = us.wrapping_sub(num_bytes);
                    self.units_start
                } else {
                    0
                };
            }
            if self.free_list[i] != 0 {
                break;
            }
        }
        let block = self.remove_node(i);
        self.split_block(block, i, indx);
        block
    }

    fn alloc_units(&mut self, indx: usize) -> u32 {
        if self.free_list[indx] != 0 {
            return self.remove_node(indx);
        }
        let num_bytes = Self::u2b(self.i2u(indx));
        let lo = self.lo_unit;
        if self.hi_unit.wrapping_sub(lo) >= num_bytes {
            self.lo_unit = lo.wrapping_add(num_bytes);
            return lo;
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
            self.copy_bytes(ptr, old_ptr, Self::u2b(new_nu));
            self.insert_node(old_ptr, i0);
            return ptr;
        }
        self.split_block(old_ptr, i0, i1);
        old_ptr
    }

    fn free_units(&mut self, ptr: u32, nu: u32) {
        let i = self.u2i(nu);
        self.insert_node(ptr, i);
    }

    fn special_free_unit(&mut self, ptr: u32) {
        if ptr != self.units_start {
            self.insert_node(ptr, 0);
        } else {
            self.units_start = self.units_start.wrapping_add(UNIT_SIZE);
        }
    }

    fn expand_text_area(&mut self) {
        let mut count = [0u32; NUM_INDEXES];
        if self.lo_unit != self.hi_unit {
            self.pu32(self.lo_unit, 0);
        }
        let limit = self.walk_limit();
        let mut steps = 0u32;
        let mut node = self.units_start;
        while self.gu32(node) == EMPTY_NODE {
            steps += 1;
            if steps > limit || self.err {
                self.err = true;
                return;
            }
            let nu = self.gu32(node.wrapping_add(8));
            self.pu32(node, 0);
            let i = self.u2i(nu);
            count[i] += 1;
            node = node.wrapping_add(Self::u2b(nu));
        }
        self.units_start = node;

        for i in 0..NUM_INDEXES {
            let mut cnt = count[i];
            if cnt == 0 {
                continue;
            }
            let mut prev = Link::FreeList(i);
            let mut n = self.free_list[i];
            self.stamps[i] = self.stamps[i].wrapping_sub(cnt);
            let mut dummy = 0u32;
            loop {
                steps += 1;
                if n == 0 || steps > limit || self.err {
                    self.err = true;
                    return;
                }
                let node = n;
                n = self.gu32(node.wrapping_add(4));
                if self.gu32(node) != 0 {
                    prev = Link::Node(node);
                    continue;
                }
                self.set_link(prev, &mut dummy, n);
                cnt -= 1;
                if cnt == 0 {
                    break;
                }
            }
        }
    }

    // ─── model maintenance ──────────────────────────────────────────────

    fn restart_model(&mut self) {
        self.free_list = [0; NUM_INDEXES];
        self.stamps = [0; NUM_INDEXES];
        self.text = self.align_offset;
        self.hi_unit = self.text + self.size;
        self.units_start = self.hi_unit - self.size / 8 / UNIT_SIZE * 7 * UNIT_SIZE;
        self.lo_unit = self.units_start;
        self.glue_count = 0;

        self.order_fall = self.max_order;
        self.init_rl = -(self.max_order.min(12) as i32) - 1;
        self.run_length = self.init_rl;
        self.prev_success = 0;

        self.hi_unit -= UNIT_SIZE;
        let mc = self.hi_unit;
        let s = self.lo_unit;
        self.lo_unit += Self::u2b(256 / 2);
        self.max_context = mc;
        self.min_context = mc;
        self.found_state = s;
        self.set_flags(mc, 0);
        self.set_num_stats(mc, 255);
        self.set_summ_freq(mc, 256 + 1);
        self.set_stats(mc, s);
        self.set_suffix(mc, 0);
        for i in 0..256u32 {
            let st = s + i * 6;
            self.set_sym(st, i);
            self.set_freq(st, 1);
            self.set_successor(st, 0);
        }

        let mut i = 0usize;
        for m in 0..BIN_ROWS {
            while self.ns2indx[i] as usize == m {
                i += 1;
            }
            for k in 0..8 {
                let val = (BIN_SCALE - K_INIT_BIN_ESC[k] as u32 / (i as u32 + 1)) as u16;
                for r in (0..64).step_by(8) {
                    self.bin_summ[m * BIN_COLS + k + r] = val;
                }
            }
        }

        let mut i = 0usize;
        for m in 0..SEE_ROWS {
            while self.ns2indx[i + 3] as usize == m + 3 {
                i += 1;
            }
            let summ = ((2 * i as u32 + 5) << (PERIOD_BITS - 4)) as u16;
            for k in 0..SEE_COLS {
                self.see[m * SEE_COLS + k] = See {
                    summ,
                    shift: (PERIOD_BITS - 4) as u8,
                    count: 7,
                };
            }
        }

        self.dummy_see = See {
            summ: 0,
            shift: PERIOD_BITS as u8,
            count: 64,
        };
    }

    /// Turn a context whose last remaining stat is `s` into a binary
    /// context holding it (shared by `CutOff` and `RestoreModel`).
    fn make_binary(&mut self, c: u32, s: u32) {
        let sym = self.sym(s);
        let f = self.flags(c);
        self.set_flags(c, (f & FLAG_PREV_HIGH) + hi_bits_flag3(sym));
        let freq = self.freq(s);
        let succ = self.successor(s);
        self.pu8(c.wrapping_add(2), sym);
        self.pu8(c.wrapping_add(3), (freq + 11) >> 3);
        self.pu32(c.wrapping_add(4), succ);
    }

    fn refresh(&mut self, ctx: u32, old_nu: u32, mut scale: u32) {
        let i = self.num_stats(ctx);
        let st = self.stats(ctx);
        let mut s = self.shrink_units(st, old_nu, (i + 2) >> 1);
        self.set_stats(ctx, s);

        scale |= (self.summ_freq(ctx) >= (1 << 15)) as u32;

        let mut flags = self.sym(s) + 0xC0;
        let freq = self.freq(s);
        let mut esc_freq = self.summ_freq(ctx).wrapping_sub(freq);
        let freq = (freq + scale) >> scale;
        let mut sum_freq = freq;
        self.set_freq(s, freq);
        for _ in 0..i {
            s = s.wrapping_add(6);
            let freq = self.freq(s);
            esc_freq = esc_freq.wrapping_sub(freq);
            let freq = (freq + scale) >> scale;
            sum_freq += freq;
            self.set_freq(s, freq);
            flags |= self.sym(s) + 0xC0;
        }
        self.set_summ_freq(
            ctx,
            sum_freq.wrapping_add(esc_freq.wrapping_add(scale) >> scale),
        );
        let f = self.flags(ctx);
        let keep = FLAG_PREV_HIGH + FLAG_RESCALED * scale as u8;
        self.set_flags(
            ctx,
            (f & keep).wrapping_add((((flags) >> (8 - 3)) & (1 << 3)) as u8),
        );
    }

    fn cut_off(&mut self, ctx: u32, order: u32) -> u32 {
        if self.err {
            return 0;
        }
        let mut ns = self.num_stats(ctx) as i32;
        if ns == 0 {
            let s = Self::one_state(ctx);
            let mut successor = self.successor(s);
            if successor >= self.units_start {
                successor = if order < self.max_order {
                    self.cut_off(successor, order + 1)
                } else {
                    0
                };
                self.set_successor(s, successor);
                if successor != 0 || order <= 9 {
                    return ctx;
                }
            }
            self.special_free_unit(ctx);
            return 0;
        }

        let nu = (ns as u32 + 2) >> 1;
        let indx = self.u2i(nu);
        let mut stats = self.stats(ctx);
        if stats.wrapping_sub(self.units_start) <= (1 << 14) && stats <= self.free_list[indx] {
            let ptr = self.remove_node(indx);
            self.set_stats(ctx, ptr);
            self.copy_bytes(ptr, stats, Self::u2b(nu));
            if stats != self.units_start {
                self.insert_node(stats, indx);
            } else {
                self.units_start = self.units_start.wrapping_add(Self::u2b(self.i2u(indx)));
            }
            stats = ptr;
        }

        let mut s = stats.wrapping_add(ns as u32 * 6);
        loop {
            let successor = self.successor(s);
            if successor < self.units_start {
                let s2 = stats.wrapping_add(ns as u32 * 6);
                ns -= 1;
                if order != 0 {
                    if s != s2 {
                        self.copy_state(s, s2);
                    }
                } else {
                    self.swap_states(s, s2);
                    self.set_successor(s2, 0);
                }
            } else if order < self.max_order {
                let r = self.cut_off(successor, order + 1);
                self.set_successor(s, r);
            } else {
                self.set_successor(s, 0);
            }
            if s == stats || self.err {
                break;
            }
            s = s.wrapping_sub(6);
        }

        if ns != self.num_stats(ctx) as i32 && order != 0 {
            if ns < 0 {
                self.free_units(stats, nu);
                self.special_free_unit(ctx);
                return 0;
            }
            self.set_num_stats(ctx, ns as u32);
            if ns == 0 {
                self.make_binary(ctx, stats);
                self.free_units(stats, nu);
            } else {
                let scale = (self.summ_freq(ctx) > 16 * ns as u32) as u32;
                self.refresh(ctx, nu, scale);
            }
        }
        ctx
    }

    fn get_used_memory(&self) -> u32 {
        let mut v = 0u32;
        for i in 0..NUM_INDEXES {
            v = v.wrapping_add(self.stamps[i].wrapping_mul(self.i2u(i)));
        }
        self.size
            .wrapping_sub(self.hi_unit.wrapping_sub(self.lo_unit))
            .wrapping_sub(self.units_start.wrapping_sub(self.text))
            .wrapping_sub(Self::u2b(v))
    }

    fn restore_model(&mut self, ctx_error: u32) {
        self.text = self.align_offset;

        let mut c = self.max_context;
        let mut steps = 0;
        while c != ctx_error {
            steps += 1;
            if steps > MAX_CHAIN || self.err {
                self.err = true;
                return;
            }
            let ns = self.num_stats(c).wrapping_sub(1) & 0xFF;
            self.set_num_stats(c, ns);
            if ns == 0 {
                let s = self.stats(c);
                self.make_binary(c, s);
                self.special_free_unit(s);
            } else {
                self.refresh(c, (ns + 3) >> 1, 0);
            }
            c = self.suffix(c);
        }

        while c != self.min_context {
            steps += 1;
            if steps > MAX_CHAIN || self.err {
                self.err = true;
                return;
            }
            let ns = self.num_stats(c);
            if ns == 0 {
                let f = self.gu8(c.wrapping_add(3));
                self.pu8(c.wrapping_add(3), (f + 1) >> 1);
            } else {
                let sf = (self.summ_freq(c) + 4) & 0xFFFF;
                self.set_summ_freq(c, sf);
                if sf > 128 + 4 * ns {
                    self.refresh(c, (ns + 2) >> 1, 1);
                }
            }
            c = self.suffix(c);
        }

        if self.restore_method == RESTORE_RESTART || self.get_used_memory() < (self.size >> 1) {
            self.restart_model();
        } else {
            let mut steps = 0;
            loop {
                let s = self.suffix(self.max_context);
                if s == 0 {
                    break;
                }
                steps += 1;
                if steps > 256 || self.err {
                    self.err = true;
                    return;
                }
                self.max_context = s;
            }
            let mut rounds = 0;
            loop {
                self.cut_off(self.max_context, 0);
                self.expand_text_area();
                rounds += 1;
                if self.err || rounds > 64 {
                    self.err = true;
                    return;
                }
                if self.get_used_memory() <= 3 * (self.size >> 2) {
                    break;
                }
            }
            self.glue_count = 0;
            self.order_fall = self.max_order;
        }
        self.min_context = self.max_context;
    }

    /// `Ppmd8_CreateSuccessors`. Returns 0 when memory is exhausted.
    fn create_successors(&mut self, skip: bool, mut s1: u32, mut c: u32) -> u32 {
        let mut up_branch = self.successor(self.found_state);
        let mut ps = [0u32; MAX_ORDER as usize + 1];
        let mut num_ps = 0usize;
        if !skip {
            ps[num_ps] = self.found_state;
            num_ps += 1;
        }

        while self.suffix(c) != 0 {
            if self.err {
                return 0;
            }
            c = self.suffix(c);
            let s;
            if s1 != 0 {
                s = s1;
                s1 = 0;
            } else if self.num_stats(c) != 0 {
                let sym = self.sym(self.found_state);
                s = self.find_state(c, sym);
                if self.freq(s) < MAX_FREQ - 9 {
                    let f = self.freq(s);
                    self.set_freq(s, f + 1);
                    let sf = self.summ_freq(c);
                    self.set_summ_freq(c, sf + 1);
                }
            } else {
                let sfx = self.suffix(c);
                let temp = self.num_stats(sfx) == 0;
                s = Self::one_state(c);
                let f = self.freq(s);
                self.set_freq(s, f + (temp && f < 24) as u32);
            }
            let successor = self.successor(s);
            if successor != up_branch {
                c = successor;
                if num_ps == 0 {
                    return c;
                }
                break;
            }
            if num_ps >= ps.len() {
                self.err = true;
                return 0;
            }
            ps[num_ps] = s;
            num_ps += 1;
        }

        let new_sym = self.gu8(up_branch);
        up_branch = up_branch.wrapping_add(1);
        let fsym = self.sym(self.found_state);
        let flags = hi_bits_flag4(fsym) + hi_bits_flag3(new_sym);

        let new_freq = if self.num_stats(c) == 0 {
            self.gu8(c.wrapping_add(3))
        } else {
            let s = self.find_state(c, new_sym);
            let cf = self.freq(s).wrapping_sub(1);
            let s0 = self
                .summ_freq(c)
                .wrapping_sub(self.num_stats(c))
                .wrapping_sub(cf);
            let add = if cf.wrapping_mul(2) <= s0 {
                (cf.wrapping_mul(5) > s0) as u32
            } else {
                match cf
                    .wrapping_add(s0.wrapping_mul(2))
                    .wrapping_sub(3)
                    .checked_div(s0)
                {
                    Some(v) => v,
                    None => {
                        self.err = true;
                        return 0;
                    }
                }
            };
            add.wrapping_add(1) & 0xFF
        };

        if num_ps == 0 {
            self.err = true;
            return 0;
        }
        loop {
            let c1 = if self.hi_unit != self.lo_unit {
                self.hi_unit = self.hi_unit.wrapping_sub(UNIT_SIZE);
                self.hi_unit
            } else if self.free_list[0] != 0 {
                self.remove_node(0)
            } else {
                let r = self.alloc_units_rare(0);
                if r == 0 {
                    return 0;
                }
                r
            };
            self.set_flags(c1, flags);
            self.set_num_stats(c1, 0);
            self.pu8(c1.wrapping_add(2), new_sym);
            self.pu8(c1.wrapping_add(3), new_freq);
            self.set_successor(Self::one_state(c1), up_branch);
            self.set_suffix(c1, c);
            num_ps -= 1;
            self.set_successor(ps[num_ps], c1);
            c = c1;
            if num_ps == 0 {
                break;
            }
        }
        c
    }

    fn reduce_order(&mut self, mut s1: u32, mut c: u32) -> u32 {
        let mut s;
        let c1 = c;
        let up_branch = self.text;

        self.set_successor(self.found_state, up_branch);
        self.order_fall = self.order_fall.wrapping_add(1);

        let fsym = self.sym(self.found_state);
        let mut steps = 0;
        loop {
            steps += 1;
            if steps > MAX_CHAIN || self.err {
                self.err = true;
                return 0;
            }
            if s1 != 0 {
                c = self.suffix(c);
                s = s1;
                s1 = 0;
            } else {
                if self.suffix(c) == 0 {
                    return c;
                }
                c = self.suffix(c);
                if self.num_stats(c) != 0 {
                    s = self.find_state(c, fsym);
                    if self.freq(s) < MAX_FREQ - 9 {
                        let f = self.freq(s);
                        self.set_freq(s, f + 2);
                        let sf = self.summ_freq(c);
                        self.set_summ_freq(c, sf + 2);
                    }
                } else {
                    s = Self::one_state(c);
                    let f = self.freq(s);
                    self.set_freq(s, f + (f < 32) as u32);
                }
            }
            if self.successor(s) != 0 {
                break;
            }
            self.set_successor(s, up_branch);
            self.order_fall = self.order_fall.wrapping_add(1);
        }

        if self.successor(s) <= up_branch {
            let s2 = self.found_state;
            self.found_state = s;
            let successor = self.create_successors(false, 0, c);
            self.set_successor(s, successor);
            self.found_state = s2;
        }

        let successor = self.successor(s);
        if self.order_fall == 1 && c1 == self.max_context {
            self.set_successor(self.found_state, successor);
            self.text = self.text.wrapping_sub(1);
        }
        successor
    }

    fn update_model(&mut self) {
        let fs = self.found_state;
        let mut min_successor = self.successor(fs);
        let f_freq = self.freq(fs);
        let f_symbol = self.sym(fs);
        let mut s = 0u32;

        if f_freq < MAX_FREQ / 4 && self.suffix(self.min_context) != 0 {
            let c = self.suffix(self.min_context);
            if self.num_stats(c) == 0 {
                s = Self::one_state(c);
                let f = self.freq(s);
                if f < 32 {
                    self.set_freq(s, f + 1);
                }
            } else {
                s = self.stats(c);
                if self.sym(s) != f_symbol {
                    s = self.find_state(c, f_symbol);
                    let prev = s.wrapping_sub(6);
                    if self.freq(s) >= self.freq(prev) {
                        self.swap_states(s, prev);
                        s = prev;
                    }
                }
                if self.freq(s) < MAX_FREQ - 9 {
                    let f = self.freq(s);
                    self.set_freq(s, f + 2);
                    let sf = self.summ_freq(c);
                    self.set_summ_freq(c, sf + 2);
                }
            }
        }

        let mut c = self.max_context;
        if self.order_fall == 0 && min_successor != 0 {
            let cs = self.create_successors(true, s, self.min_context);
            if cs == 0 {
                self.set_successor(self.found_state, 0);
                self.restore_model(c);
                return;
            }
            self.set_successor(self.found_state, cs);
            self.min_context = cs;
            self.max_context = cs;
            return;
        }

        let fsym = self.sym(self.found_state);
        self.pu8(self.text, fsym);
        self.text = self.text.wrapping_add(1);
        if self.text >= self.units_start {
            self.restore_model(c);
            return;
        }
        let mut max_successor = self.text;

        if min_successor == 0 {
            let cs = self.reduce_order(s, self.min_context);
            if cs == 0 {
                self.restore_model(c);
                return;
            }
            min_successor = cs;
        } else if min_successor < self.units_start {
            let cs = self.create_successors(false, s, self.min_context);
            if cs == 0 {
                self.restore_model(c);
                return;
            }
            min_successor = cs;
        }

        self.order_fall = self.order_fall.wrapping_sub(1);
        if self.order_fall == 0 {
            max_successor = min_successor;
            self.text = self
                .text
                .wrapping_sub((self.max_context != self.min_context) as u32);
        }

        let flag = hi_bits_flag3(f_symbol);
        let ns = self.num_stats(self.min_context);
        let s0 = self
            .summ_freq(self.min_context)
            .wrapping_sub(ns)
            .wrapping_sub(f_freq);

        let mut steps = 0;
        while c != self.min_context {
            steps += 1;
            if steps > MAX_CHAIN || self.err {
                self.err = true;
                return;
            }
            let ns1 = self.num_stats(c);
            let mut sum;
            if ns1 != 0 {
                if ns1 & 1 != 0 {
                    let old_nu = (ns1 + 1) >> 1;
                    let i = self.u2i(old_nu);
                    if i != self.u2i(old_nu + 1) {
                        let ptr = self.alloc_units(i + 1);
                        if ptr == 0 {
                            self.restore_model(c);
                            return;
                        }
                        let old_ptr = self.stats(c);
                        self.copy_bytes(ptr, old_ptr, Self::u2b(old_nu));
                        self.insert_node(old_ptr, i);
                        self.set_stats(c, ptr);
                    }
                }
                sum = self.summ_freq(c);
                sum += (3 * ns1 + 1 < ns) as u32;
            } else {
                let st = self.alloc_units(0);
                if st == 0 {
                    self.restore_model(c);
                    return;
                }
                let mut freq = self.gu8(c.wrapping_add(3));
                let sym = self.gu8(c.wrapping_add(2));
                let succ = self.gu32(c.wrapping_add(4));
                self.set_sym(st, sym);
                self.set_successor(st, succ);
                self.set_stats(c, st);
                if freq < MAX_FREQ / 4 - 1 {
                    freq <<= 1;
                } else {
                    freq = MAX_FREQ - 4;
                }
                self.set_freq(st, freq);
                sum = freq + self.init_esc + (ns > 2) as u32;
            }

            let st = self.stats(c).wrapping_add((ns1 + 1) * 6);
            let mut cf = 2 * (sum + 6) * f_freq;
            let sf = s0.wrapping_add(sum);
            self.set_sym(st, f_symbol);
            self.set_num_stats(c, ns1 + 1);
            self.set_successor(st, max_successor);
            let fl = self.flags(c);
            self.set_flags(c, fl | flag);
            if cf < sf.wrapping_mul(6) {
                cf = 1 + (cf > sf) as u32 + (cf >= sf.wrapping_mul(4)) as u32;
                sum += 4;
            } else {
                cf = 4
                    + (cf > sf.wrapping_mul(9)) as u32
                    + (cf > sf.wrapping_mul(12)) as u32
                    + (cf > sf.wrapping_mul(15)) as u32;
                sum += cf;
            }
            self.set_summ_freq(c, sum);
            self.set_freq(st, cf);
            c = self.suffix(c);
        }
        self.min_context = min_successor;
        self.max_context = min_successor;
    }

    fn rescale(&mut self) {
        let mc = self.min_context;
        let stats = self.stats(mc);
        let mut s = self.found_state;

        // Move the found state to the front.
        if s != stats {
            let tmp = self.read_state(s);
            let n = s.wrapping_sub(stats);
            if !n.is_multiple_of(6) || n > 255 * 6 {
                self.err = true;
                return;
            }
            self.copy_bytes(stats.wrapping_add(6), stats, n);
            s = stats;
            self.write_state(s, tmp);
        }

        let mut sum_freq = self.freq(s);
        let mut esc_freq = self.summ_freq(mc).wrapping_sub(sum_freq);
        let adder = (self.order_fall != 0) as u32;
        sum_freq = (sum_freq + 4 + adder) >> 1;
        let i = self.num_stats(mc);
        self.set_freq(s, sum_freq);

        for _ in 0..i {
            s = s.wrapping_add(6);
            let freq = self.freq(s);
            esc_freq = esc_freq.wrapping_sub(freq);
            let freq = (freq + adder) >> 1;
            sum_freq += freq;
            self.set_freq(s, freq);
            if freq > self.freq(s - 6) {
                let tmp = self.read_state(s);
                let mut s1 = s;
                loop {
                    self.copy_state(s1, s1 - 6);
                    s1 -= 6;
                    if s1 == stats || freq <= self.freq(s1 - 6) {
                        break;
                    }
                }
                self.write_state(s1, tmp);
            }
        }

        if self.freq(s) == 0 {
            let mut i = 0u32;
            loop {
                i += 1;
                if s == stats {
                    self.err = true;
                    return;
                }
                s -= 6;
                if self.freq(s) != 0 {
                    break;
                }
            }
            esc_freq = esc_freq.wrapping_add(i);
            let num_stats = self.num_stats(mc);
            let num_stats_new = num_stats.wrapping_sub(i);
            self.set_num_stats(mc, num_stats_new);
            let n0 = (num_stats + 2) >> 1;

            if num_stats_new == 0 {
                let f0 = self.freq(stats);
                let mut freq = match (2 * f0)
                    .wrapping_add(esc_freq)
                    .wrapping_sub(1)
                    .checked_div(esc_freq)
                {
                    Some(v) => v,
                    None => {
                        self.err = true;
                        return;
                    }
                };
                if freq > MAX_FREQ / 3 {
                    freq = MAX_FREQ / 3;
                }
                let sym = self.sym(stats);
                let f = self.flags(mc);
                self.set_flags(mc, (f & FLAG_PREV_HIGH) + hi_bits_flag3(sym));
                let one = Self::one_state(mc);
                self.copy_state(one, stats);
                self.set_freq(one, freq);
                self.found_state = one;
                let i0 = self.u2i(n0);
                self.insert_node(stats, i0);
                return;
            }

            let n1 = (num_stats_new + 2) >> 1;
            if n0 != n1 {
                let ns = self.shrink_units(stats, n0, n1);
                self.set_stats(mc, ns);
            }
        }

        self.set_summ_freq(
            mc,
            sum_freq.wrapping_add(esc_freq).wrapping_sub(esc_freq >> 1),
        );
        let f = self.flags(mc);
        self.set_flags(mc, f | FLAG_RESCALED);
        self.found_state = self.stats(mc);
    }

    fn make_esc_freq(&mut self, num_masked: u32) -> (SeeRef, u32) {
        let mc = self.min_context;
        let ns = self.num_stats(mc);
        if ns != 0xFF {
            let row = (self.ns2indx[(ns + 2) as usize] as usize).wrapping_sub(3);
            let sfx = self.suffix(mc);
            let sfx_ns = self.num_stats(sfx);
            let col = (self.summ_freq(mc) > 11 * (ns + 1)) as usize
                + 2 * ((2 * ns) < sfx_ns + num_masked) as usize
                + self.flags(mc) as usize;
            let idx = row.wrapping_mul(SEE_COLS).wrapping_add(col);
            let Some(see) = self.see.get_mut(idx) else {
                self.err = true;
                return (SeeRef::Dummy, 1);
            };
            let summ = see.summ as u32;
            let r = summ >> see.shift;
            see.summ = (summ - r) as u16;
            (SeeRef::Cell(idx), r + (r == 0) as u32)
        } else {
            (SeeRef::Dummy, 1)
        }
    }

    #[inline]
    fn see_mut(&mut self, r: SeeRef) -> &mut See {
        match r {
            SeeRef::Dummy => &mut self.dummy_see,
            SeeRef::Cell(i) => &mut self.see[i],
        }
    }

    fn next_context(&mut self) {
        let c = self.successor(self.found_state);
        if self.order_fall == 0 && c >= self.units_start {
            self.min_context = c;
            self.max_context = c;
        } else {
            self.update_model();
        }
    }

    fn update1(&mut self) {
        let s = self.found_state;
        let freq = self.freq(s) + 4;
        let mc = self.min_context;
        let sf = self.summ_freq(mc);
        self.set_summ_freq(mc, sf + 4);
        self.set_freq(s, freq);
        let prev = s.wrapping_sub(6);
        if freq > self.freq(prev) {
            self.swap_states(s, prev);
            self.found_state = prev;
            if freq > MAX_FREQ {
                self.rescale();
            }
        }
        self.next_context();
    }

    fn update1_0(&mut self) {
        let s = self.found_state;
        let mc = self.min_context;
        let freq = self.freq(s);
        let summ_freq = self.summ_freq(mc);
        self.prev_success = (2 * freq >= summ_freq) as u32;
        self.run_length = self.run_length.wrapping_add(self.prev_success as i32);
        self.set_summ_freq(mc, summ_freq + 4);
        let freq = freq + 4;
        self.set_freq(s, freq);
        if freq > MAX_FREQ {
            self.rescale();
        }
        self.next_context();
    }

    fn update2(&mut self) {
        let s = self.found_state;
        let freq = self.freq(s) + 4;
        self.run_length = self.init_rl;
        let mc = self.min_context;
        let sf = self.summ_freq(mc);
        self.set_summ_freq(mc, sf + 4);
        self.set_freq(s, freq);
        if freq > MAX_FREQ {
            self.rescale();
        }
        self.update_model();
    }

    /// `Ppmd8_DecodeSymbol`. `Err(Corrupt)` is the reference's
    /// `PPMD8_SYM_ERROR` (or a damaged arena).
    pub(crate) fn decode_symbol(&mut self, rc: &mut RangeDec<'_>) -> Result<Sym, Error> {
        let r = self.decode_symbol_inner(rc);
        if self.err || rc.err {
            return Err(Error::Corrupt);
        }
        r
    }

    fn decode_symbol_inner(&mut self, rc: &mut RangeDec<'_>) -> Result<Sym, Error> {
        let mut mask = [0xFFu8; 256];
        let mc = self.min_context;
        let ns = self.num_stats(mc);
        if ns != 0 {
            let mut s = self.stats(mc);
            let summ_freq = self.summ_freq(mc).min(rc.st.range);
            let mut count = rc.threshold(summ_freq);
            let mut hi_cnt = count;

            let f = self.freq(s);
            count = count.wrapping_sub(f);
            if (count as i32) < 0 {
                rc.decode_final(0, f);
                self.found_state = s;
                let sym = self.sym(s);
                self.update1_0();
                return Ok(Sym::Byte(sym as u8));
            }
            self.prev_success = 0;
            for _ in 0..ns {
                s = s.wrapping_add(6);
                let f = self.freq(s);
                count = count.wrapping_sub(f);
                if (count as i32) < 0 {
                    rc.decode_final(hi_cnt.wrapping_sub(count).wrapping_sub(f), f);
                    self.found_state = s;
                    let sym = self.sym(s);
                    self.update1();
                    return Ok(Sym::Byte(sym as u8));
                }
            }
            if hi_cnt >= summ_freq {
                return Err(Error::Corrupt);
            }
            hi_cnt = hi_cnt.wrapping_sub(count);
            rc.decode(hi_cnt, summ_freq.wrapping_sub(hi_cnt));

            let mut s2 = self.stats(mc);
            for _ in 0..=ns {
                let sym = self.sym(s2);
                mask[sym as usize] = 0;
                s2 = s2.wrapping_add(6);
            }
        } else {
            let s = Self::one_state(mc);
            let freq = self.freq(s);
            let sfx = self.suffix(mc);
            let sfx_ns = self.num_stats(sfx) as usize;
            let row = self.ns2indx[(freq as usize).wrapping_sub(1).min(259)] as usize;
            let col = self.prev_success as usize
                + ((self.run_length >> 26) & 0x20) as usize
                + self.ns2bsindx[sfx_ns.min(255)] as usize
                + self.flags(mc) as usize;
            let idx = row * BIN_COLS + col;
            let Some(&p) = self.bin_summ.get(idx) else {
                return Err(Error::Corrupt);
            };
            let mut pr = p as u32;
            let size0 = (rc.st.range >> 14).wrapping_mul(pr);
            pr = pr.wrapping_sub(get_mean(pr));

            if rc.st.code < size0 {
                self.bin_summ[idx] = (pr + (1 << INT_BITS)) as u16;
                rc.st.range = size0;
                rc.normalize();

                let c = self.successor(s);
                let sym = self.sym(s);
                self.found_state = s;
                self.prev_success = 1;
                self.run_length = self.run_length.wrapping_add(1);
                self.set_freq(s, freq + (freq < 196) as u32);
                if self.order_fall == 0 && c >= self.units_start {
                    self.min_context = c;
                    self.max_context = c;
                } else {
                    self.update_model();
                }
                return Ok(Sym::Byte(sym as u8));
            }

            self.bin_summ[idx] = pr as u16;
            self.init_esc = K_EXP_ESCAPE[((pr >> 10) & 15) as usize] as u32;
            rc.st.low = rc.st.low.wrapping_add(size0);
            rc.st.code = rc.st.code.wrapping_sub(size0);
            rc.st.range = (rc.st.range & !(BIN_SCALE - 1)).wrapping_sub(size0);

            let sym = self.sym(s);
            mask[sym as usize] = 0;
            self.prev_success = 0;
        }

        let mut chain = 0;
        loop {
            rc.normalize();
            let mut mc = self.min_context;
            let num_masked = self.num_stats(mc);
            loop {
                chain += 1;
                if chain > MAX_CHAIN || self.err || rc.err {
                    return Err(Error::Corrupt);
                }
                self.order_fall = self.order_fall.wrapping_add(1);
                let sfx = self.suffix(mc);
                if sfx == 0 {
                    return Ok(Sym::End);
                }
                mc = sfx;
                if self.num_stats(mc) != num_masked {
                    break;
                }
            }

            let ns = self.num_stats(mc);
            let stats = self.stats(mc);
            self.min_context = mc;
            let mut hi_cnt = 0u32;
            let mut s = stats;
            for _ in 0..=ns {
                let sym = self.sym(s);
                hi_cnt += self.freq(s) & mask[sym as usize] as u32;
                s = s.wrapping_add(6);
            }

            let (see, esc) = self.make_esc_freq(num_masked);
            let freq_sum = esc.wrapping_add(hi_cnt);
            let freq_sum2 = freq_sum.min(rc.st.range);
            let mut count = rc.threshold(freq_sum2);

            if count < hi_cnt {
                let mut s = stats;
                let hi = count;
                let mut found = false;
                for _ in 0..=ns {
                    let sym = self.sym(s);
                    count = count.wrapping_sub(self.freq(s) & mask[sym as usize] as u32);
                    s = s.wrapping_add(6);
                    if (count as i32) < 0 {
                        found = true;
                        break;
                    }
                }
                if !found {
                    return Err(Error::Corrupt);
                }
                s = s.wrapping_sub(6);
                let f = self.freq(s);
                rc.decode_final(hi.wrapping_sub(count).wrapping_sub(f), f);
                self.see_mut(see).update();
                self.found_state = s;
                let sym = self.sym(s);
                self.update2();
                return Ok(Sym::Byte(sym as u8));
            }

            if count >= freq_sum2 {
                return Err(Error::Corrupt);
            }
            rc.decode(hi_cnt, freq_sum2.wrapping_sub(hi_cnt));
            let cell = self.see_mut(see);
            cell.summ = cell.summ.wrapping_add(freq_sum as u16);

            let mut s = stats;
            for _ in 0..=ns {
                let sym = self.sym(s);
                mask[sym as usize] = 0;
                s = s.wrapping_add(6);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tables_stay_in_range() {
        let p = Ppmd8::new(1 << 20).unwrap();
        // Binary contexts have Freq <= 196; NS2Indx must pick a BinSumm row.
        assert!((p.ns2indx[195] as usize) < BIN_ROWS);
        // Multi-symbol contexts have NumStats <= 254 (+2 -> 256).
        assert!((p.ns2indx[256] as usize) - 3 < SEE_ROWS);
        assert_eq!(p.indx2units[NUM_INDEXES - 1], 128);
    }
}
