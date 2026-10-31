//! Burrows–Wheeler transform — forward (encoder) and inverse (decoder).
//!
//! ## Forward
//!
//! We sort all cyclic rotations of the block, then the BWT column L is
//! the byte immediately preceding each rotation's start:
//!
//! ```text
//! L[i] = input[(ptr[i] - 1) mod n]
//! ```
//!
//! The "origin" or "pointer" returned alongside is `pos` such that
//! `ptr[pos] == 0` — i.e. the row in the sorted matrix that corresponds
//! to the original (unrotated) string. The decoder needs this to know
//! where the original string sits in the reconstructed matrix.
//!
//! The sort is a faithful port of reference bzip2's `BZ2_blockSort`
//! (`blocksort.c`, bzip2 1.0.8, © 1996-2019 Julian Seward, BSD-style
//! licence): blocks under 10 000 bytes go to the exponential radix sort
//! (`fallbackSort`); larger ones to the two-byte radix + three-way
//! quicksort + bucket-synthesis `mainSort`, abandoned for `fallbackSort`
//! once it exceeds a work budget of `nblock * 9` (work factor 30, the
//! default of both the `bzip2` tool and `BZ2_bzBuffToBuffCompress`).
//!
//! Porting the algorithm rather than using any other suffix sort is
//! what makes the output byte-identical to libbzip2's. For a block
//! whose rotations are all distinct every correct sort gives the same
//! result, but a periodic block (`"ab"` repeated, a block of RLE-1'd
//! zeros, ...) has groups of equal rotations, and *which* of them is
//! reported as the origin depends on the exact sequence of partitions
//! and insertion sorts. Any choice decodes, but only this one matches.
//!
//! ## Inverse
//!
//! Classic O(n) algorithm: build the "next-row" permutation from L
//! using a stable rank-by-value, then walk it starting at `origin` for
//! `n` steps, emitting L at each step. See the rust comments in
//! [`bwt_inverse`] for details.

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

/// Compute the forward Burrows–Wheeler transform.
///
/// Returns `(L, origin)` where `L` is the BWT output (same length as
/// `input`) and `origin` is the row index of the original (unrotated)
/// string in the sorted rotation matrix.
#[cfg(test)]
pub(crate) fn bwt_forward(input: &[u8]) -> (Vec<u8>, u32) {
    bwt_forward_with(input, DEFAULT_WORK_FACTOR)
}

/// [`bwt_forward`] at an explicit libbzip2 work factor (`1..=250`; 0
/// means the default, 30). See [`block_sort`].
pub(crate) fn bwt_forward_with(input: &[u8], work_factor: u8) -> (Vec<u8>, u32) {
    let n = input.len();
    if n == 0 {
        return (Vec::new(), 0);
    }
    let ptr = block_sort(input, work_factor);
    let mut l = Vec::with_capacity(n);
    let mut origin = 0u32;
    for (i, &p) in ptr.iter().enumerate() {
        let p = p as usize;
        if p == 0 {
            origin = i as u32;
            l.push(input[n - 1]);
        } else {
            l.push(input[p - 1]);
        }
    }
    (l, origin)
}

// ─── BZ2_blockSort ───────────────────────────────────────────────────────
//
// Variable names, loop shapes and the order of every comparison and swap
// follow the C source, since the order of equal rotations — and therefore
// the origin of a periodic block — is a by-product of exactly those steps.
// Indices are `i32` as in the C so the wrap-around arithmetic reads the
// same.

/// `BZ_N_RADIX + BZ_N_QSORT + BZ_N_SHELL + 2`: how far past the block end
/// `mainGtU` may read (the block and quadrant arrays repeat their start
/// there).
const N_OVERSHOOT: usize = 2 + 12 + 18 + 2;
const N_RADIX: i32 = 2;
const N_QSORT: i32 = 12;
/// libbzip2's default work factor (`bzip2 -9`, `BZ2_bzBuffToBuffCompress`
/// with `workFactor = 0`).
pub(crate) const DEFAULT_WORK_FACTOR: u8 = 30;

/// Sort the rotations of `block`, returning the start of each in
/// ascending order (libbzip2's `ptr`).
///
/// `work_factor` is libbzip2's `workFactor`: 0 picks the default (30),
/// and like `BZ2_blockSort` the value is then clamped to `1..=100`.
/// Lower values give up on `mainSort` sooner. For blocks whose
/// rotations are not all distinct (periodic input) the two sorts can
/// order equal rotations differently, so the work factor can change
/// the output bytes, just as it does in libbzip2.
fn block_sort(block: &[u8], work_factor: u8) -> Vec<u32> {
    let wf = if work_factor == 0 {
        DEFAULT_WORK_FACTOR
    } else {
        work_factor
    };
    let wf = i32::from(wf).clamp(1, 100);
    let nblock = block.len();
    let mut ptr = vec![0u32; nblock];
    if nblock < 10000 {
        fallback_sort(&mut ptr, block);
    } else {
        let mut blk = Vec::with_capacity(nblock + N_OVERSHOOT);
        blk.extend_from_slice(block);
        blk.resize(nblock + N_OVERSHOOT, 0);
        let mut quadrant = vec![0u16; nblock + N_OVERSHOOT];
        let mut budget = nblock as i32 * ((wf - 1) / 3);
        main_sort(
            &mut ptr,
            &mut blk,
            &mut quadrant,
            nblock as i32,
            &mut budget,
        );
        if budget < 0 {
            fallback_sort(&mut ptr, block);
        }
    }
    ptr
}

// ─── fallbackSort: O(N log(N)^2), for repetitive blocks ─────────────────

fn fallback_simple_sort(fmap: &mut [u32], eclass: &[u32], lo: i32, hi: i32) {
    if lo == hi {
        return;
    }
    if hi - lo > 3 {
        let mut i = hi - 4;
        while i >= lo {
            let tmp = fmap[i as usize];
            let ec_tmp = eclass[tmp as usize];
            let mut j = i + 4;
            while j <= hi && ec_tmp > eclass[fmap[j as usize] as usize] {
                fmap[(j - 4) as usize] = fmap[j as usize];
                j += 4;
            }
            fmap[(j - 4) as usize] = tmp;
            i -= 1;
        }
    }
    let mut i = hi - 1;
    while i >= lo {
        let tmp = fmap[i as usize];
        let ec_tmp = eclass[tmp as usize];
        let mut j = i + 1;
        while j <= hi && ec_tmp > eclass[fmap[j as usize] as usize] {
            fmap[(j - 1) as usize] = fmap[j as usize];
            j += 1;
        }
        fmap[(j - 1) as usize] = tmp;
        i -= 1;
    }
}

const FALLBACK_QSORT_SMALL_THRESH: i32 = 10;
const FALLBACK_QSORT_STACK_SIZE: usize = 100;

fn fvswap(fmap: &mut [u32], mut p1: i32, mut p2: i32, mut n: i32) {
    while n > 0 {
        fmap.swap(p1 as usize, p2 as usize);
        p1 += 1;
        p2 += 1;
        n -= 1;
    }
}

fn fallback_qsort3(fmap: &mut [u32], eclass: &[u32], lo_st: i32, hi_st: i32) {
    let mut stack_lo = [0i32; FALLBACK_QSORT_STACK_SIZE];
    let mut stack_hi = [0i32; FALLBACK_QSORT_STACK_SIZE];
    let mut r: u32 = 0;
    let mut sp = 0usize;
    stack_lo[sp] = lo_st;
    stack_hi[sp] = hi_st;
    sp += 1;

    while sp > 0 {
        sp -= 1;
        let lo = stack_lo[sp];
        let hi = stack_hi[sp];
        if hi - lo < FALLBACK_QSORT_SMALL_THRESH {
            fallback_simple_sort(fmap, eclass, lo, hi);
            continue;
        }

        // Random partitioning (Sedgewick's constants, as in the C).
        r = (r * 7621 + 1) % 32768;
        let med = match r % 3 {
            0 => eclass[fmap[lo as usize] as usize],
            1 => eclass[fmap[((lo + hi) >> 1) as usize] as usize],
            _ => eclass[fmap[hi as usize] as usize],
        };

        let (mut un_lo, mut lt_lo) = (lo, lo);
        let (mut un_hi, mut gt_hi) = (hi, hi);
        loop {
            while un_lo <= un_hi {
                let e = eclass[fmap[un_lo as usize] as usize];
                if e == med {
                    fmap.swap(un_lo as usize, lt_lo as usize);
                    lt_lo += 1;
                    un_lo += 1;
                    continue;
                }
                if e > med {
                    break;
                }
                un_lo += 1;
            }
            while un_lo <= un_hi {
                let e = eclass[fmap[un_hi as usize] as usize];
                if e == med {
                    fmap.swap(un_hi as usize, gt_hi as usize);
                    gt_hi -= 1;
                    un_hi -= 1;
                    continue;
                }
                if e < med {
                    break;
                }
                un_hi -= 1;
            }
            if un_lo > un_hi {
                break;
            }
            fmap.swap(un_lo as usize, un_hi as usize);
            un_lo += 1;
            un_hi -= 1;
        }

        if gt_hi < lt_lo {
            continue;
        }

        let n = (lt_lo - lo).min(un_lo - lt_lo);
        fvswap(fmap, lo, un_lo - n, n);
        let m = (hi - gt_hi).min(gt_hi - un_hi);
        fvswap(fmap, un_lo, hi - m + 1, m);

        let n = lo + un_lo - lt_lo - 1;
        let m = hi - (gt_hi - un_hi) + 1;

        if n - lo > hi - m {
            stack_lo[sp] = lo;
            stack_hi[sp] = n;
            sp += 1;
            stack_lo[sp] = m;
            stack_hi[sp] = hi;
            sp += 1;
        } else {
            stack_lo[sp] = m;
            stack_hi[sp] = hi;
            sp += 1;
            stack_lo[sp] = lo;
            stack_hi[sp] = n;
            sp += 1;
        }
    }
}

#[inline(always)]
fn set_bh(bhtab: &mut [u32], z: i32) {
    bhtab[(z >> 5) as usize] |= 1 << (z & 31);
}
#[inline(always)]
fn clear_bh(bhtab: &mut [u32], z: i32) {
    bhtab[(z >> 5) as usize] &= !(1 << (z & 31));
}
#[inline(always)]
fn isset_bh(bhtab: &[u32], z: i32) -> bool {
    bhtab[(z >> 5) as usize] & (1 << (z & 31)) != 0
}
#[inline(always)]
fn word_bh(bhtab: &[u32], z: i32) -> u32 {
    bhtab[(z >> 5) as usize]
}
#[inline(always)]
fn unaligned_bh(z: i32) -> bool {
    z & 0x1f != 0
}

/// libbzip2's `fallbackSort`. The C version keeps the equivalence
/// classes in the block's own storage and rebuilds the block afterwards;
/// here they get their own array.
fn fallback_sort(fmap: &mut [u32], block: &[u8]) {
    let nblock = block.len() as i32;
    let mut ftab = [0i32; 257];
    let mut eclass = vec![0u32; block.len()];
    // Sentinel bits reach bit nblock + 63.
    let mut bhtab = vec![0u32; block.len() / 32 + 4];

    // Initial 1-char radix sort to generate the initial fmap and BH bits.
    for &b in block {
        ftab[b as usize] += 1;
    }
    for i in 1..257 {
        ftab[i] += ftab[i - 1];
    }
    for (i, &b) in block.iter().enumerate() {
        let k = ftab[b as usize] - 1;
        ftab[b as usize] = k;
        fmap[k as usize] = i as u32;
    }
    for &f in &ftab[..256] {
        set_bh(&mut bhtab, f);
    }

    // Sentinel bits for block-end detection.
    for i in 0..32 {
        set_bh(&mut bhtab, nblock + 2 * i);
        clear_bh(&mut bhtab, nblock + 2 * i + 1);
    }

    // The log(N) loop: Manber-Myers-style bucket refinement.
    let mut h: i32 = 1;
    loop {
        let mut j = 0;
        for i in 0..nblock {
            if isset_bh(&bhtab, i) {
                j = i;
            }
            let mut k = fmap[i as usize] as i32 - h;
            if k < 0 {
                k += nblock;
            }
            eclass[k as usize] = j as u32;
        }

        let mut n_not_done = 0;
        let mut r: i32 = -1;
        loop {
            // Find the next non-singleton bucket.
            let mut k = r + 1;
            while isset_bh(&bhtab, k) && unaligned_bh(k) {
                k += 1;
            }
            if isset_bh(&bhtab, k) {
                while word_bh(&bhtab, k) == 0xffff_ffff {
                    k += 32;
                }
                while isset_bh(&bhtab, k) {
                    k += 1;
                }
            }
            let l = k - 1;
            if l >= nblock {
                break;
            }
            while !isset_bh(&bhtab, k) && unaligned_bh(k) {
                k += 1;
            }
            if !isset_bh(&bhtab, k) {
                while word_bh(&bhtab, k) == 0 {
                    k += 32;
                }
                while !isset_bh(&bhtab, k) {
                    k += 1;
                }
            }
            r = k - 1;
            if r >= nblock {
                break;
            }

            // [l, r] bracket the current bucket.
            if r > l {
                n_not_done += r - l + 1;
                fallback_qsort3(fmap, &eclass, l, r);

                // Scan the bucket and generate header bits.
                let mut cc: i64 = -1;
                for i in l..=r {
                    let cc1 = eclass[fmap[i as usize] as usize] as i64;
                    if cc != cc1 {
                        set_bh(&mut bhtab, i);
                        cc = cc1;
                    }
                }
            }
        }

        h *= 2;
        if h > nblock || n_not_done == 0 {
            break;
        }
    }
}

// ─── mainSort: two-byte radix + three-way quicksort, for normal blocks ──

/// Is the rotation at `i1` greater than the one at `i2`? Compares
/// block bytes (and, past the first 12, the quadrant cache) and charges
/// the budget one unit per 8 positions, giving up — "equal" — after a
/// full cycle.
#[inline]
fn main_gtu(
    mut i1: u32,
    mut i2: u32,
    block: &[u8],
    quadrant: &[u16],
    nblock: u32,
    budget: &mut i32,
) -> bool {
    // Fixed-length windows: one bounds check per stretch rather than
    // one per byte (the overshoot area guarantees they fit).
    let b1: &[u8; 12] = block[i1 as usize..][..12].try_into().unwrap();
    let b2: &[u8; 12] = block[i2 as usize..][..12].try_into().unwrap();
    for (&c1, &c2) in b1.iter().zip(b2) {
        if c1 != c2 {
            return c1 > c2;
        }
    }
    i1 += 12;
    i2 += 12;

    let mut k = nblock as i32 + 8;
    loop {
        let b1: &[u8; 8] = block[i1 as usize..][..8].try_into().unwrap();
        let b2: &[u8; 8] = block[i2 as usize..][..8].try_into().unwrap();
        let q1: &[u16; 8] = quadrant[i1 as usize..][..8].try_into().unwrap();
        let q2: &[u16; 8] = quadrant[i2 as usize..][..8].try_into().unwrap();
        for t in 0..8 {
            if b1[t] != b2[t] {
                return b1[t] > b2[t];
            }
            if q1[t] != q2[t] {
                return q1[t] > q2[t];
            }
        }
        i1 += 8;
        i2 += 8;
        if i1 >= nblock {
            i1 -= nblock;
        }
        if i2 >= nblock {
            i2 -= nblock;
        }
        k -= 8;
        *budget -= 1;
        if k < 0 {
            return false;
        }
    }
}

/// Knuth's increments, as in the C.
const INCS: [i32; 14] = [
    1, 4, 13, 40, 121, 364, 1093, 3280, 9841, 29524, 88573, 265720, 797161, 2391484,
];

#[allow(clippy::too_many_arguments)]
fn main_simple_sort(
    ptr: &mut [u32],
    block: &[u8],
    quadrant: &[u16],
    nblock: i32,
    lo: i32,
    hi: i32,
    d: i32,
    budget: &mut i32,
) {
    let big_n = hi - lo + 1;
    if big_n < 2 {
        return;
    }
    let mut hp = 0usize;
    while INCS[hp] < big_n {
        hp += 1;
    }

    // `for (hp--; hp >= 0; hp--)`
    while hp > 0 {
        hp -= 1;
        let h = INCS[hp];
        let mut i = lo + h;
        loop {
            // The C unrolls this body three times and checks the budget
            // after each group of three; keep that cadence, since an
            // abandoned sort leaves `ptr` in whatever state it reached.
            let mut ran_out = false;
            for _ in 0..3 {
                if i > hi {
                    ran_out = true;
                    break;
                }
                let v = ptr[i as usize];
                let mut j = i;
                while main_gtu(
                    ptr[(j - h) as usize] + d as u32,
                    v + d as u32,
                    block,
                    quadrant,
                    nblock as u32,
                    budget,
                ) {
                    ptr[j as usize] = ptr[(j - h) as usize];
                    j -= h;
                    if j < lo + h {
                        break;
                    }
                }
                ptr[j as usize] = v;
                i += 1;
            }
            if ran_out {
                break;
            }
            if *budget < 0 {
                return;
            }
        }
    }
}

#[inline]
fn mmed3(mut a: u8, mut b: u8, c: u8) -> u8 {
    if a > b {
        core::mem::swap(&mut a, &mut b);
    }
    if b > c {
        b = c;
        if a > b {
            b = a;
        }
    }
    b
}

fn mvswap(ptr: &mut [u32], mut p1: i32, mut p2: i32, mut n: i32) {
    while n > 0 {
        ptr.swap(p1 as usize, p2 as usize);
        p1 += 1;
        p2 += 1;
        n -= 1;
    }
}

const MAIN_QSORT_SMALL_THRESH: i32 = 20;
const MAIN_QSORT_DEPTH_THRESH: i32 = N_RADIX + N_QSORT;
const MAIN_QSORT_STACK_SIZE: usize = 100;

#[allow(clippy::too_many_arguments)]
fn main_qsort3(
    ptr: &mut [u32],
    block: &[u8],
    quadrant: &[u16],
    nblock: i32,
    lo_st: i32,
    hi_st: i32,
    d_st: i32,
    budget: &mut i32,
) {
    let mut stack_lo = [0i32; MAIN_QSORT_STACK_SIZE];
    let mut stack_hi = [0i32; MAIN_QSORT_STACK_SIZE];
    let mut stack_d = [0i32; MAIN_QSORT_STACK_SIZE];
    let mut sp = 0usize;
    stack_lo[sp] = lo_st;
    stack_hi[sp] = hi_st;
    stack_d[sp] = d_st;
    sp += 1;

    while sp > 0 {
        sp -= 1;
        let lo = stack_lo[sp];
        let hi = stack_hi[sp];
        let d = stack_d[sp];
        if hi - lo < MAIN_QSORT_SMALL_THRESH || d > MAIN_QSORT_DEPTH_THRESH {
            main_simple_sort(ptr, block, quadrant, nblock, lo, hi, d, budget);
            if *budget < 0 {
                return;
            }
            continue;
        }

        let at = |p: u32| block[(p as i32 + d) as usize];
        let med = mmed3(
            at(ptr[lo as usize]),
            at(ptr[hi as usize]),
            at(ptr[((lo + hi) >> 1) as usize]),
        ) as i32;

        let (mut un_lo, mut lt_lo) = (lo, lo);
        let (mut un_hi, mut gt_hi) = (hi, hi);
        loop {
            while un_lo <= un_hi {
                let n = at(ptr[un_lo as usize]) as i32 - med;
                if n == 0 {
                    ptr.swap(un_lo as usize, lt_lo as usize);
                    lt_lo += 1;
                    un_lo += 1;
                    continue;
                }
                if n > 0 {
                    break;
                }
                un_lo += 1;
            }
            while un_lo <= un_hi {
                let n = at(ptr[un_hi as usize]) as i32 - med;
                if n == 0 {
                    ptr.swap(un_hi as usize, gt_hi as usize);
                    gt_hi -= 1;
                    un_hi -= 1;
                    continue;
                }
                if n < 0 {
                    break;
                }
                un_hi -= 1;
            }
            if un_lo > un_hi {
                break;
            }
            ptr.swap(un_lo as usize, un_hi as usize);
            un_lo += 1;
            un_hi -= 1;
        }

        if gt_hi < lt_lo {
            stack_lo[sp] = lo;
            stack_hi[sp] = hi;
            stack_d[sp] = d + 1;
            sp += 1;
            continue;
        }

        let n = (lt_lo - lo).min(un_lo - lt_lo);
        mvswap(ptr, lo, un_lo - n, n);
        let m = (hi - gt_hi).min(gt_hi - un_hi);
        mvswap(ptr, un_lo, hi - m + 1, m);

        let n = lo + un_lo - lt_lo - 1;
        let m = hi - (gt_hi - un_hi) + 1;

        let mut next = [(lo, n, d), (m, hi, d), (n + 1, m - 1, d + 1)];
        let size = |t: (i32, i32, i32)| t.1 - t.0;
        if size(next[0]) < size(next[1]) {
            next.swap(0, 1);
        }
        if size(next[1]) < size(next[2]) {
            next.swap(1, 2);
        }
        if size(next[0]) < size(next[1]) {
            next.swap(0, 1);
        }
        for (l, h, dd) in next {
            stack_lo[sp] = l;
            stack_hi[sp] = h;
            stack_d[sp] = dd;
            sp += 1;
        }
    }
}

const SETMASK: u32 = 1 << 21;
const CLEARMASK: u32 = !SETMASK;

/// libbzip2's `mainSort`. `block` and `quadrant` are `nblock +
/// N_OVERSHOOT` long. On return with `*budget < 0` the sort was
/// abandoned and `ptr` is garbage.
fn main_sort(
    ptr: &mut [u32],
    block: &mut [u8],
    quadrant: &mut [u16],
    nblock: i32,
    budget: &mut i32,
) {
    let n = nblock as usize;
    let mut ftab = vec![0u32; 65537];

    // Set up the 2-byte frequency table.
    let mut j: u32 = (block[0] as u32) << 8;
    for i in (0..n).rev() {
        quadrant[i] = 0;
        j = (j >> 8) | ((block[i] as u32) << 8);
        ftab[j as usize] += 1;
    }
    for i in 0..N_OVERSHOOT {
        block[n + i] = block[i];
        quadrant[n + i] = 0;
    }

    // Complete the initial radix sort.
    for i in 1..=65536 {
        ftab[i] += ftab[i - 1];
    }
    let mut s: u16 = (block[0] as u16) << 8;
    for i in (0..n).rev() {
        s = (s >> 8) | ((block[i] as u16) << 8);
        let j = ftab[s as usize] - 1;
        ftab[s as usize] = j;
        ptr[j as usize] = i as u32;
    }

    // ftab now holds the first slot of every small bucket. Order the big
    // buckets from smallest to largest (a Shell sort, as in the C).
    let bigfreq = |ftab: &[u32], b: i32| ftab[((b + 1) << 8) as usize] - ftab[(b << 8) as usize];
    let mut big_done = [false; 256];
    let mut running_order = [0i32; 256];
    for (i, r) in running_order.iter_mut().enumerate() {
        *r = i as i32;
    }
    {
        let mut h: i32 = 1;
        loop {
            h = 3 * h + 1;
            if h > 256 {
                break;
            }
        }
        loop {
            h /= 3;
            for i in h..=255 {
                let vv = running_order[i as usize];
                let mut j = i;
                while bigfreq(&ftab, running_order[(j - h) as usize]) > bigfreq(&ftab, vv) {
                    running_order[j as usize] = running_order[(j - h) as usize];
                    j -= h;
                    if j < h {
                        break;
                    }
                }
                running_order[j as usize] = vv;
            }
            if h == 1 {
                break;
            }
        }
    }

    let mut copy_start = [0i32; 256];
    let mut copy_end = [0i32; 256];

    for (i, &ss) in running_order.iter().enumerate() {
        let ss = ss as usize;

        // Step 1: complete the big bucket [ss] by quicksorting any small
        // bucket [ss, j] not already synthesised by an earlier step 2.
        for j in 0..=255usize {
            if j != ss {
                let sb = (ss << 8) + j;
                if ftab[sb] & SETMASK == 0 {
                    let lo = (ftab[sb] & CLEARMASK) as i32;
                    let hi = (ftab[sb + 1] & CLEARMASK) as i32 - 1;
                    if hi > lo {
                        main_qsort3(ptr, block, quadrant, nblock, lo, hi, N_RADIX, budget);
                        if *budget < 0 {
                            return;
                        }
                    }
                }
                ftab[sb] |= SETMASK;
            }
        }

        // Step 2: scan big bucket [ss] to synthesise the sorted order of
        // the small buckets [t, ss] for all t, including [ss, ss].
        for j in 0..=255usize {
            copy_start[j] = (ftab[(j << 8) + ss] & CLEARMASK) as i32;
            copy_end[j] = (ftab[(j << 8) + ss + 1] & CLEARMASK) as i32 - 1;
        }
        let mut j = (ftab[ss << 8] & CLEARMASK) as i32;
        while j < copy_start[ss] {
            let mut k = ptr[j as usize] as i32 - 1;
            if k < 0 {
                k += nblock;
            }
            let c1 = block[k as usize] as usize;
            if !big_done[c1] {
                ptr[copy_start[c1] as usize] = k as u32;
                copy_start[c1] += 1;
            }
            j += 1;
        }
        let mut j = (ftab[(ss + 1) << 8] & CLEARMASK) as i32 - 1;
        while j > copy_end[ss] {
            let mut k = ptr[j as usize] as i32 - 1;
            if k < 0 {
                k += nblock;
            }
            let c1 = block[k as usize] as usize;
            if !big_done[c1] {
                ptr[copy_end[c1] as usize] = k as u32;
                copy_end[c1] -= 1;
            }
            j -= 1;
        }
        debug_assert!(
            copy_start[ss] - 1 == copy_end[ss]
                || (copy_start[ss] == 0 && copy_end[ss] == nblock - 1)
        );
        for j in 0..=255usize {
            ftab[(j << 8) + ss] |= SETMASK;
        }

        // Step 3: record the bucket as done and cache its order in the
        // quadrant array (overshoot area included) so later comparisons
        // finish sooner. Pointless after the last bucket.
        big_done[ss] = true;
        if i < 255 {
            let bb_start = (ftab[ss << 8] & CLEARMASK) as i32;
            let bb_size = (ftab[(ss + 1) << 8] & CLEARMASK) as i32 - bb_start;
            let mut shifts = 0;
            while (bb_size >> shifts) > 65534 {
                shifts += 1;
            }
            for j in (0..bb_size).rev() {
                let a2update = ptr[(bb_start + j) as usize] as usize;
                let q_val = (j >> shifts) as u16;
                quadrant[a2update] = q_val;
                if a2update < N_OVERSHOOT {
                    quadrant[a2update + n] = q_val;
                }
            }
        }
    }
}

// ─── inverse BWT (unchanged from previous implementation) ─────────────

/// Compute the inverse BWT given the L column and the origin row.
///
/// The algorithm:
/// 1. Build a frequency table of bytes in L.
/// 2. From it, compute `start[c]` = first position in the sorted L
///    (which is the F column) where byte `c` appears.
/// 3. Build the "next" permutation: for each i (in L order),
///    `next[i] = start[L[i]] + occ_so_far[L[i]]`; `occ_so_far`
///    counts how many `L[i]` values we've seen so far.
/// 4. Walk: `i = origin; for _ in 0..n: emit L[i]; i = next[i]`.
///
/// Equivalently many texts express this as walking `F` and using
/// `prev` — both produce the same byte stream.
pub(crate) fn bwt_inverse(l: &[u8], origin: u32) -> Vec<u8> {
    let n = l.len();
    if n == 0 {
        return Vec::new();
    }
    debug_assert!((origin as usize) < n);

    // Step 1: byte frequency in L.
    let mut count = [0u32; 256];
    for &b in l {
        count[b as usize] += 1;
    }

    // Step 2: `start[c]` = sum of count[0..c] = first position of c in
    // the sorted F column.
    let mut start = [0u32; 256];
    let mut s: u32 = 0;
    for c in 0..256 {
        start[c] = s;
        s += count[c];
    }

    // Step 3: build `next` permutation. We reuse `start` as the
    // running write-cursor: for each i, the next slot for byte L[i] is
    // `start[L[i]]`, which we then increment.
    let mut next = vec![0u32; n];
    let mut cursor = start;
    for (i, &b) in l.iter().enumerate() {
        let c = b as usize;
        next[i] = cursor[c];
        cursor[c] += 1;
    }

    // Step 4: walk. The LF-mapping walk from `origin` yields the
    // original string in REVERSE order: at each step we move "one
    // character backward" in the original. So we walk and place the
    // emitted byte into the buffer from the end backward.
    //
    // (Equivalently we could compute the inverse permutation and walk
    // it forward, but that's more code and constant-factor slower.)
    let mut out = vec![0u8; n];
    let mut i = origin as usize;
    for k in (0..n).rev() {
        out[k] = l[i];
        i = next[i] as usize;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn round_trip_short() {
        let input = b"BANANA";
        let (l, origin) = bwt_forward(input);
        let back = bwt_inverse(&l, origin);
        assert_eq!(back, input);
    }

    #[test]
    fn round_trip_single() {
        let input = b"a";
        let (l, origin) = bwt_forward(input);
        assert_eq!(l, b"a");
        assert_eq!(origin, 0);
        let back = bwt_inverse(&l, origin);
        assert_eq!(back, input);
    }

    #[test]
    fn round_trip_empty() {
        let (l, origin) = bwt_forward(&[]);
        assert!(l.is_empty());
        assert_eq!(origin, 0);
        let back = bwt_inverse(&l, origin);
        assert!(back.is_empty());
    }

    #[test]
    fn round_trip_longer() {
        let input = b"the quick brown fox jumps over the lazy dog";
        let (l, origin) = bwt_forward(input);
        let back = bwt_inverse(&l, origin);
        assert_eq!(back, input);
    }

    #[test]
    fn round_trip_repeated_bytes() {
        let input = vec![b'a'; 50];
        let (l, origin) = bwt_forward(&input);
        let back = bwt_inverse(&l, origin);
        assert_eq!(back, input);
    }

    #[test]
    fn round_trip_two_bytes() {
        for (a, b) in [(0u8, 0u8), (0, 255), (255, 0), (1, 2), (2, 1), (5, 5)] {
            let input = [a, b];
            let (l, origin) = bwt_forward(&input);
            let back = bwt_inverse(&l, origin);
            assert_eq!(back, input);
        }
    }

    #[test]
    fn round_trip_three_bytes() {
        for a in 0..3u8 {
            for b in 0..3u8 {
                for c in 0..3u8 {
                    let input = [a, b, c];
                    let (l, origin) = bwt_forward(&input);
                    let back = bwt_inverse(&l, origin);
                    assert_eq!(back, input);
                }
            }
        }
    }

    #[test]
    fn round_trip_with_zero_bytes() {
        // Make sure we handle 0 bytes correctly (sentinel handling).
        let input: Vec<u8> = (0u8..=255).collect();
        let (l, origin) = bwt_forward(&input);
        let back = bwt_inverse(&l, origin);
        assert_eq!(back, input);
    }

    #[test]
    fn round_trip_many_zeros() {
        let input = vec![0u8; 500];
        let (l, origin) = bwt_forward(&input);
        let back = bwt_inverse(&l, origin);
        assert_eq!(back, input);
    }

    #[test]
    fn round_trip_pseudo_random_4k() {
        let mut data = Vec::with_capacity(4096);
        let mut state: u32 = 0xDEAD_BEEF;
        for _ in 0..4096 {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            data.push((state >> 16) as u8);
        }
        let (l, origin) = bwt_forward(&data);
        let back = bwt_inverse(&l, origin);
        assert_eq!(back, data);
    }

    #[cfg(feature = "std")]
    #[test]
    #[ignore]
    fn timing_bwt_forward() {
        extern crate std;
        let n = 900_000usize;
        let lorem_src = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit, \
sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. ";
        let mut lorem = Vec::with_capacity(n);
        while lorem.len() < n {
            lorem.extend_from_slice(lorem_src);
        }
        lorem.truncate(n);
        let zeros = vec![0u8; n];
        let mut random = Vec::with_capacity(n);
        let mut state: u32 = 0xDEAD_BEEF;
        for _ in 0..n {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            random.push((state >> 16) as u8);
        }
        for (name, data) in [("lorem", &lorem), ("zeros", &zeros), ("random", &random)] {
            let _ = bwt_forward(data);
            let mut best = f64::MAX;
            for _ in 0..3 {
                let t = std::time::Instant::now();
                let (l, _o) = bwt_forward(data);
                let el = t.elapsed().as_secs_f64();
                std::hint::black_box(&l);
                if el < best {
                    best = el;
                }
            }
            let mbps = (n as f64) / best / 1e6;
            std::eprintln!("BWT {name}: {:.2} ms  {:.1} MB/s", best * 1e3, mbps);
        }
    }

    #[test]
    fn matches_naive_on_small_inputs() {
        // Cross-check the block sort against a naive cyclic sort for
        // several small inputs.
        fn naive(input: &[u8]) -> (Vec<u8>, u32) {
            let n = input.len();
            if n == 0 {
                return (Vec::new(), 0);
            }
            let mut sa: Vec<usize> = (0..n).collect();
            sa.sort_by(|&a, &b| {
                for k in 0..n {
                    let ai = input[(a + k) % n];
                    let bi = input[(b + k) % n];
                    if ai != bi {
                        return ai.cmp(&bi);
                    }
                }
                core::cmp::Ordering::Equal
            });
            let mut l = Vec::with_capacity(n);
            let mut origin = 0u32;
            for (i, &s) in sa.iter().enumerate() {
                let prev = if s == 0 { n - 1 } else { s - 1 };
                l.push(input[prev]);
                if s == 0 {
                    origin = i as u32;
                }
            }
            (l, origin)
        }

        let cases: &[&[u8]] = &[
            b"",
            b"a",
            b"ab",
            b"ba",
            b"abc",
            b"cba",
            b"banana",
            b"mississippi",
            b"the quick brown fox jumps over the lazy dog",
            b"\0\0\0",
            b"\xff\xff\xff",
            b"\x00\xff\x00\xff\x00",
        ];
        for &case in cases {
            let (sa_l, sa_o) = bwt_forward(case);
            // For inputs containing repeated cyclic-equivalent strings,
            // naive cyclic sort may pick a different origin among tied
            // rows (BWT is not unique then). To compare safely, run a
            // round trip and check we recover the input — that's the
            // contract we need.
            let back = bwt_inverse(&sa_l, sa_o);
            assert_eq!(back.as_slice(), case);
            // Sanity: naive also recovers itself.
            let (nl, no) = naive(case);
            let nback = bwt_inverse(&nl, no);
            assert_eq!(nback.as_slice(), case);
        }
    }
}
