//! Streaming PKWARE deflate64 encoder.
//!
//! Structurally mirrors the RFC 1951 deflate encoder: 64 KiB sliding
//! window with LZ77 (hash-chain match finder, optional lazy matching)
//! feeding length-limited dynamic Huffman coding. Per block the cheapest
//! of stored / fixed / dynamic is selected.
//!
//! Compared to deflate the alphabet is widened: length code 285 now
//! addresses matches up to 65538 bytes via 16 extra bits, and the
//! distance alphabet uses the full 32 symbols so back-references span
//! the entire 64 KiB window.

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::bits::{BitWriter, reverse_bits};
use crate::error::Error;
use crate::huffman::{canonical_codes_from_lengths, length_limited_huffman};
use crate::traits::{Flush, RawEncoder, RawProgress};

use super::lz77::MatchFinder;
use super::tables::{
    CODE_LENGTH_ORDER, DIST_BASE, DIST_EXTRA, END_OF_BLOCK, FIXED_DIST_LENGTHS, FIXED_LIT_LENGTHS,
    LENGTH_BASE, LENGTH_EXTRA, MAX_MATCH, MIN_MATCH, NUM_DIST_SYMBOLS, NUM_LITLEN_SYMBOLS,
    WINDOW_SIZE,
};

/// Per-block compression target. With a 64 KiB window we let blocks grow
/// to 32 KiB of fresh input — twice deflate's target, in proportion with
/// the larger window.
const BLOCK_SIZE: usize = 32 * 1024;

/// Maximum window-buffer growth before sliding.
const WINDOW_MAX: usize = 2 * WINDOW_SIZE;

/// Tunables for the deflate64 encoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncoderConfig {
    /// Compression level in `1..=9`.
    pub level: u8,
}

impl Default for EncoderConfig {
    fn default() -> Self {
        Self { level: 6 }
    }
}

#[derive(Debug, Clone, Copy)]
struct LevelParams {
    max_chain: usize,
    nice_match: usize,
    good_match: usize,
    use_lazy: bool,
}

impl LevelParams {
    fn from_level(level: u8) -> Self {
        // Same shape as zlib's configuration_table — tuned for the
        // larger MAX_MATCH at the top end so high levels can chase
        // long deflate64-only matches.
        let level = level.clamp(1, 9);
        match level {
            1 => Self {
                max_chain: 4,
                nice_match: 8,
                good_match: 4,
                use_lazy: false,
            },
            2 => Self {
                max_chain: 8,
                nice_match: 16,
                good_match: 5,
                use_lazy: false,
            },
            3 => Self {
                max_chain: 32,
                nice_match: 32,
                good_match: 6,
                use_lazy: false,
            },
            4 => Self {
                max_chain: 16,
                nice_match: 16,
                good_match: 4,
                use_lazy: true,
            },
            5 => Self {
                max_chain: 32,
                nice_match: 32,
                good_match: 8,
                use_lazy: true,
            },
            6 => Self {
                max_chain: 128,
                nice_match: 128,
                good_match: 16,
                use_lazy: true,
            },
            7 => Self {
                max_chain: 256,
                nice_match: 258,
                good_match: 32,
                use_lazy: true,
            },
            8 => Self {
                max_chain: 1024,
                nice_match: 1024,
                good_match: 32,
                use_lazy: true,
            },
            // 9 (and clamp-from-above)
            _ => Self {
                max_chain: 4096,
                nice_match: 4096,
                good_match: 32,
                use_lazy: true,
            },
        }
    }
}

// ─── precomputed fixed Huffman tables (const) ───────────────────────────

const FIXED_LIT_REV: [u32; 288] = compute_canonical_reversed::<288>(&FIXED_LIT_LENGTHS);
const FIXED_DIST_REV: [u32; 32] = compute_canonical_reversed::<32>(&FIXED_DIST_LENGTHS);

const fn compute_canonical_reversed<const N: usize>(lengths: &[u8; N]) -> [u32; N] {
    let mut count = [0u32; 16];
    let mut i = 0;
    while i < N {
        let l = lengths[i] as usize;
        if l > 0 {
            count[l] += 1;
        }
        i += 1;
    }
    let mut next_code = [0u32; 16];
    let mut code: u32 = 0;
    let mut bits = 1;
    while bits <= 15 {
        code = (code + count[bits - 1]) << 1;
        next_code[bits] = code;
        bits += 1;
    }
    let mut out = [0u32; N];
    let mut i = 0;
    while i < N {
        let len = lengths[i] as u32;
        if len > 0 {
            let c = next_code[len as usize];
            let mut v = c;
            let mut rev: u32 = 0;
            let mut j = 0;
            while j < len {
                rev = (rev << 1) | (v & 1);
                v >>= 1;
                j += 1;
            }
            out[i] = rev;
            next_code[len as usize] = c + 1;
        }
        i += 1;
    }
    out
}

/// Map a match length 3..=65538 to (code, extra_value, extra_bits). For
/// lengths 3..=258 this is the same mapping deflate uses with codes
/// 257..=284; for lengths 259..=65538 we fall through to code 285 which
/// carries 16 extra bits.
#[inline(always)]
fn length_to_code(length: u32) -> (u16, u32, u8) {
    if length <= 258 {
        // Mirror deflate: codes 257..=284 cover 3..=258. Code 285 is
        // intentionally not used here — it costs 16 extra bits vs the
        // 0..=5 of the regular length codes.
        // Walk LENGTH_BASE[0..28] (skip the 285 slot at index 28) from
        // the back to find the largest base <= length.
        let mut c = 27usize;
        while c > 0 && LENGTH_BASE[c] > length {
            c -= 1;
        }
        let code = c as u16 + 257;
        let extra_value = length - LENGTH_BASE[c];
        let extra_bits = LENGTH_EXTRA[c];
        (code, extra_value, extra_bits)
    } else {
        // Code 285: base 3, 16 extra bits. Covers up to 3 + 0xFFFF = 65538.
        let extra_value = length - 3;
        (285, extra_value, 16)
    }
}

/// Map a distance 1..=65536 to (code, extra_value, extra_bits).
#[inline(always)]
fn distance_to_code(distance: u32) -> (u16, u32, u8) {
    let mut c = 31usize;
    while c > 0 && DIST_BASE[c] > distance {
        c -= 1;
    }
    let extra_value = distance - DIST_BASE[c];
    let extra_bits = DIST_EXTRA[c];
    (c as u16, extra_value, extra_bits)
}

#[derive(Clone, Copy)]
enum Symbol {
    Literal(u8),
    Match { length: u32, distance: u32 },
}

#[derive(Clone, Copy)]
struct ClSymbol {
    sym: u8,
    extra_value: u16,
    extra_bits: u8,
}

fn rle_encode_lengths_into(lengths: &[u8], out: &mut Vec<ClSymbol>) {
    out.clear();
    let mut i = 0usize;
    while i < lengths.len() {
        let cur = lengths[i];
        let mut run = 1usize;
        while i + run < lengths.len() && lengths[i + run] == cur {
            run += 1;
        }

        if cur == 0 {
            let mut left = run;
            while left > 0 {
                if left >= 11 {
                    let n = left.min(138);
                    out.push(ClSymbol {
                        sym: 18,
                        extra_value: (n - 11) as u16,
                        extra_bits: 7,
                    });
                    left -= n;
                } else if left >= 3 {
                    out.push(ClSymbol {
                        sym: 17,
                        extra_value: (left - 3) as u16,
                        extra_bits: 3,
                    });
                    left = 0;
                } else {
                    out.push(ClSymbol {
                        sym: 0,
                        extra_value: 0,
                        extra_bits: 0,
                    });
                    left -= 1;
                }
            }
        } else {
            out.push(ClSymbol {
                sym: cur,
                extra_value: 0,
                extra_bits: 0,
            });
            let mut left = run - 1;
            while left >= 3 {
                let n = left.min(6);
                out.push(ClSymbol {
                    sym: 16,
                    extra_value: (n - 3) as u16,
                    extra_bits: 2,
                });
                left -= n;
            }
            while left > 0 {
                out.push(ClSymbol {
                    sym: cur,
                    extra_value: 0,
                    extra_bits: 0,
                });
                left -= 1;
            }
        }

        i += run;
    }
}

#[inline]
fn huffman_cost_from_histogram(
    lit_freq: &[u32; NUM_LITLEN_SYMBOLS],
    dist_freq: &[u32; NUM_DIST_SYMBOLS],
    lit_lengths: &[u8],
    dist_lengths: &[u8],
) -> u64 {
    let mut bits: u64 = 0;
    for i in 0..NUM_LITLEN_SYMBOLS {
        bits += lit_freq[i] as u64 * lit_lengths[i] as u64;
    }
    for i in 0..NUM_DIST_SYMBOLS {
        bits += dist_freq[i] as u64 * dist_lengths[i] as u64;
    }
    bits
}

enum EncState {
    Accepting,
    Emitting,
    Done,
}

pub struct Encoder {
    window: Vec<u8>,
    cursor: usize,
    window_start_abs: u64,
    match_finder: Box<MatchFinder>,
    block_symbols: Vec<Symbol>,
    block_bytes: Vec<u8>,
    bit_writer: BitWriter,
    out_buffer: Vec<u8>,
    out_pos: usize,
    state: EncState,
    final_emitted: bool,
    mid_flush: bool,
    params: LevelParams,

    lit_freq: [u32; NUM_LITLEN_SYMBOLS],
    dist_freq: [u32; NUM_DIST_SYMBOLS],
    lit_lengths: [u8; NUM_LITLEN_SYMBOLS],
    dist_lengths: [u8; NUM_DIST_SYMBOLS],
    cl_lengths: [u8; 19],
    cl_freq: [u32; 19],
    rle_buf: Vec<ClSymbol>,
    combined_lengths: Vec<u8>,
    hlit_count: usize,
    hdist_count: usize,
    hclen_count: usize,
}

impl Encoder {
    pub fn new() -> Self {
        Self::with_config(EncoderConfig::default())
    }

    pub fn with_config(config: EncoderConfig) -> Self {
        Self {
            window: Vec::with_capacity(WINDOW_MAX),
            cursor: 0,
            window_start_abs: 0,
            match_finder: Box::new(MatchFinder::new()),
            block_symbols: Vec::new(),
            block_bytes: Vec::new(),
            bit_writer: BitWriter::new(),
            out_buffer: Vec::new(),
            out_pos: 0,
            state: EncState::Accepting,
            final_emitted: false,
            mid_flush: false,
            params: LevelParams::from_level(config.level),
            lit_freq: [0u32; NUM_LITLEN_SYMBOLS],
            dist_freq: [0u32; NUM_DIST_SYMBOLS],
            lit_lengths: [0u8; NUM_LITLEN_SYMBOLS],
            dist_lengths: [0u8; NUM_DIST_SYMBOLS],
            cl_lengths: [0u8; 19],
            cl_freq: [0u32; 19],
            rle_buf: Vec::new(),
            combined_lengths: Vec::new(),
            hlit_count: 0,
            hdist_count: 0,
            hclen_count: 0,
        }
    }

    fn drain(&mut self, output: &mut [u8], written: &mut usize) -> bool {
        while self.out_pos < self.out_buffer.len() && *written < output.len() {
            output[*written] = self.out_buffer[self.out_pos];
            self.out_pos += 1;
            *written += 1;
        }
        self.out_pos >= self.out_buffer.len()
    }

    fn maybe_slide(&mut self) {
        if self.cursor > WINDOW_SIZE {
            let drop = self.cursor - WINDOW_SIZE;
            self.window.drain(..drop);
            self.cursor -= drop;
            self.window_start_abs += drop as u64;
        }
    }

    fn lz77_pass(&mut self, end: usize) {
        let abs_base = self.window_start_abs;
        let max_chain = self.params.max_chain;
        let nice_match = self.params.nice_match;
        let good_match = self.params.good_match;
        let use_lazy = self.params.use_lazy;
        let mut pos = self.cursor;

        let mut have_pending = false;
        let mut prev_match_len: u32 = 0;
        let mut prev_match_dist: u32 = 0;
        let mut prev_match_start: usize = 0;

        while pos < end {
            if pos + 3 <= self.window.len() {
                let abs = abs_base + pos as u64;
                self.match_finder.insert(
                    abs as u32,
                    self.window[pos],
                    self.window[pos + 1],
                    self.window[pos + 2],
                );
            }

            let cur = if pos + MIN_MATCH <= end {
                let abs = abs_base + pos as u64;
                let have_good = have_pending && (prev_match_len as usize) >= good_match;
                self.match_finder.find_match(
                    &self.window,
                    pos,
                    abs as u32,
                    have_good,
                    max_chain,
                    nice_match,
                )
            } else {
                None
            };

            if have_pending {
                let strictly_better = match cur {
                    Some((cl, _)) => cl > prev_match_len,
                    None => false,
                };
                if strictly_better {
                    let lit = self.window[prev_match_start];
                    self.block_symbols.push(Symbol::Literal(lit));
                    self.block_bytes.push(lit);
                    let (cl, cd) = cur.unwrap();
                    prev_match_len = cl;
                    prev_match_dist = cd;
                    prev_match_start = pos;
                    have_pending = true;
                    pos += 1;
                } else {
                    self.block_symbols.push(Symbol::Match {
                        length: prev_match_len,
                        distance: prev_match_dist,
                    });
                    let match_end = prev_match_start + prev_match_len as usize;
                    self.block_bytes
                        .extend_from_slice(&self.window[prev_match_start..match_end]);
                    let mut k = pos + 1;
                    while k < match_end {
                        if k + 3 <= self.window.len() {
                            let abs = abs_base + k as u64;
                            self.match_finder.insert(
                                abs as u32,
                                self.window[k],
                                self.window[k + 1],
                                self.window[k + 2],
                            );
                        }
                        k += 1;
                    }
                    pos = match_end;
                    have_pending = false;
                }
            } else if let Some((cl, cd)) = cur {
                if !use_lazy {
                    self.block_symbols.push(Symbol::Match {
                        length: cl,
                        distance: cd,
                    });
                    let match_end = pos + cl as usize;
                    self.block_bytes
                        .extend_from_slice(&self.window[pos..match_end]);
                    let mut k = pos + 1;
                    while k < match_end {
                        if k + 3 <= self.window.len() {
                            let abs = abs_base + k as u64;
                            self.match_finder.insert(
                                abs as u32,
                                self.window[k],
                                self.window[k + 1],
                                self.window[k + 2],
                            );
                        }
                        k += 1;
                    }
                    pos = match_end;
                } else {
                    prev_match_len = cl;
                    prev_match_dist = cd;
                    prev_match_start = pos;
                    have_pending = true;
                    if (cl as usize) >= MAX_MATCH {
                        self.block_symbols.push(Symbol::Match {
                            length: cl,
                            distance: cd,
                        });
                        let match_end = pos + cl as usize;
                        self.block_bytes
                            .extend_from_slice(&self.window[pos..match_end]);
                        let mut k = pos + 1;
                        while k < match_end {
                            if k + 3 <= self.window.len() {
                                let abs = abs_base + k as u64;
                                self.match_finder.insert(
                                    abs as u32,
                                    self.window[k],
                                    self.window[k + 1],
                                    self.window[k + 2],
                                );
                            }
                            k += 1;
                        }
                        pos = match_end;
                        have_pending = false;
                    } else {
                        pos += 1;
                    }
                }
            } else {
                let lit = self.window[pos];
                self.block_symbols.push(Symbol::Literal(lit));
                self.block_bytes.push(lit);
                pos += 1;
            }
        }

        if have_pending {
            self.block_symbols.push(Symbol::Match {
                length: prev_match_len,
                distance: prev_match_dist,
            });
            let match_end = prev_match_start + prev_match_len as usize;
            self.block_bytes
                .extend_from_slice(&self.window[prev_match_start..match_end]);
            let mut k = end;
            while k < match_end {
                if k + 3 <= self.window.len() {
                    let abs = abs_base + k as u64;
                    self.match_finder.insert(
                        abs as u32,
                        self.window[k],
                        self.window[k + 1],
                        self.window[k + 2],
                    );
                }
                k += 1;
            }
            pos = match_end;
        }

        self.cursor = pos;
    }

    fn build_dynamic(&mut self, extra_bits_total: u64) -> (u64, u64) {
        let lit_lengths_vec = length_limited_huffman(&self.lit_freq, 15);
        let dist_lengths_vec = length_limited_huffman(&self.dist_freq, 15);

        debug_assert_eq!(lit_lengths_vec.len(), NUM_LITLEN_SYMBOLS);
        debug_assert_eq!(dist_lengths_vec.len(), NUM_DIST_SYMBOLS);
        self.lit_lengths.copy_from_slice(&lit_lengths_vec);
        self.dist_lengths.copy_from_slice(&dist_lengths_vec);

        let mut hlit_count = NUM_LITLEN_SYMBOLS;
        while hlit_count > 257 && self.lit_lengths[hlit_count - 1] == 0 {
            hlit_count -= 1;
        }
        let mut hdist_count = NUM_DIST_SYMBOLS;
        while hdist_count > 1 && self.dist_lengths[hdist_count - 1] == 0 {
            hdist_count -= 1;
        }
        self.hlit_count = hlit_count;
        self.hdist_count = hdist_count;

        self.combined_lengths.clear();
        self.combined_lengths
            .extend_from_slice(&self.lit_lengths[..hlit_count]);
        self.combined_lengths
            .extend_from_slice(&self.dist_lengths[..hdist_count]);
        rle_encode_lengths_into(&self.combined_lengths, &mut self.rle_buf);

        self.cl_freq = [0u32; 19];
        for s in &self.rle_buf {
            self.cl_freq[s.sym as usize] += 1;
        }
        let cl_lengths_vec = length_limited_huffman(&self.cl_freq, 7);
        debug_assert_eq!(cl_lengths_vec.len(), 19);
        self.cl_lengths.copy_from_slice(&cl_lengths_vec);

        let mut hclen_count = 19usize;
        while hclen_count > 4 && self.cl_lengths[CODE_LENGTH_ORDER[hclen_count - 1]] == 0 {
            hclen_count -= 1;
        }
        self.hclen_count = hclen_count;

        let mut header_bits: u64 = 3 + 5 + 5 + 4 + 3 * hclen_count as u64;
        for s in &self.rle_buf {
            header_bits += self.cl_lengths[s.sym as usize] as u64 + s.extra_bits as u64;
        }

        let payload_bits = huffman_cost_from_histogram(
            &self.lit_freq,
            &self.dist_freq,
            &self.lit_lengths,
            &self.dist_lengths,
        ) + extra_bits_total;

        (header_bits, payload_bits)
    }

    fn fixed_cost_bits(&self, extra_bits_total: u64) -> u64 {
        let payload_bits = huffman_cost_from_histogram(
            &self.lit_freq,
            &self.dist_freq,
            &FIXED_LIT_LENGTHS[..NUM_LITLEN_SYMBOLS],
            &FIXED_DIST_LENGTHS[..NUM_DIST_SYMBOLS],
        ) + extra_bits_total;
        3 + payload_bits
    }

    /// Stored encoding requires the block fit in u16. Deflate64 blocks
    /// can be larger than that (BLOCK_SIZE = 32 KiB still fits, but a
    /// single match of 65538 bytes could push block_bytes above 64 KiB);
    /// callers must check the precondition.
    fn stored_cost_bits(&self) -> u64 {
        let pending = self.bit_writer.pending_bits() as u64;
        let after_header = (pending + 3) & 7;
        let pad = (8 - after_header) & 7;
        3 + pad + 32 + (self.block_bytes.len() as u64) * 8
    }

    fn emit_fixed_block(&mut self, bfinal: bool) {
        let bw = &mut self.bit_writer;
        let out = &mut self.out_buffer;

        bw.write(if bfinal { 1 } else { 0 }, 1, out);
        bw.write(1, 2, out);

        let lit_rev = &FIXED_LIT_REV;
        let lit_len_tbl = &FIXED_LIT_LENGTHS;
        let dist_rev = &FIXED_DIST_REV;
        let dist_len_tbl = &FIXED_DIST_LENGTHS;

        for s in &self.block_symbols {
            match s {
                Symbol::Literal(b) => {
                    let bi = *b as usize;
                    bw.write(lit_rev[bi], lit_len_tbl[bi] as u32, out);
                }
                Symbol::Match { length, distance } => {
                    let (lc, lex, leb) = length_to_code(*length);
                    let lci = lc as usize;
                    bw.write(lit_rev[lci], lit_len_tbl[lci] as u32, out);
                    if leb > 0 {
                        bw.write(lex, leb as u32, out);
                    }
                    let (dc, dex, deb) = distance_to_code(*distance);
                    let dci = dc as usize;
                    bw.write(dist_rev[dci], dist_len_tbl[dci] as u32, out);
                    if deb > 0 {
                        bw.write(dex, deb as u32, out);
                    }
                }
            }
        }
        let eob = END_OF_BLOCK as usize;
        bw.write(lit_rev[eob], lit_len_tbl[eob] as u32, out);

        if bfinal {
            bw.align(out);
        }
    }

    fn emit_sync_marker(&mut self) {
        let bw = &mut self.bit_writer;
        let out = &mut self.out_buffer;
        bw.write(0, 1, out);
        bw.write(0, 2, out);
        bw.align(out);
        out.push(0x00);
        out.push(0x00);
        out.push(0xFF);
        out.push(0xFF);
    }

    fn emit_stored_block(&mut self, bfinal: bool) {
        let bw = &mut self.bit_writer;
        let out = &mut self.out_buffer;

        bw.write(if bfinal { 1 } else { 0 }, 1, out);
        bw.write(0, 2, out);
        bw.align(out);

        let len = self.block_bytes.len() as u16;
        let nlen = !len;
        out.push((len & 0xff) as u8);
        out.push((len >> 8) as u8);
        out.push((nlen & 0xff) as u8);
        out.push((nlen >> 8) as u8);
        out.extend_from_slice(&self.block_bytes);
        let _ = bfinal;
    }

    fn emit_dynamic_block(&mut self, bfinal: bool) {
        let hlit_count = self.hlit_count;
        let hdist_count = self.hdist_count;
        let hclen_count = self.hclen_count;
        let hlit = (hlit_count - 257) as u8;
        let hdist = (hdist_count - 1) as u8;
        let hclen = (hclen_count - 4) as u8;

        let lit_codes = canonical_codes_from_lengths(&self.lit_lengths);
        let dist_codes = canonical_codes_from_lengths(&self.dist_lengths);
        let cl_codes = canonical_codes_from_lengths(&self.cl_lengths);

        let mut lit_rev = [0u32; NUM_LITLEN_SYMBOLS];
        for i in 0..hlit_count {
            let l = self.lit_lengths[i] as u32;
            if l > 0 {
                lit_rev[i] = reverse_bits(lit_codes[i] as u32, l);
            }
        }
        let mut dist_rev = [0u32; NUM_DIST_SYMBOLS];
        for i in 0..hdist_count {
            let l = self.dist_lengths[i] as u32;
            if l > 0 {
                dist_rev[i] = reverse_bits(dist_codes[i] as u32, l);
            }
        }
        let mut cl_rev = [0u32; 19];
        for i in 0..19 {
            let l = self.cl_lengths[i] as u32;
            if l > 0 {
                cl_rev[i] = reverse_bits(cl_codes[i] as u32, l);
            }
        }

        let bw = &mut self.bit_writer;
        let out = &mut self.out_buffer;

        bw.write(if bfinal { 1 } else { 0 }, 1, out);
        bw.write(2, 2, out);

        bw.write(hlit as u32, 5, out);
        bw.write(hdist as u32, 5, out);
        bw.write(hclen as u32, 4, out);

        for &idx in CODE_LENGTH_ORDER.iter().take(hclen_count) {
            let len = self.cl_lengths[idx];
            bw.write(len as u32, 3, out);
        }

        for s in &self.rle_buf {
            let si = s.sym as usize;
            bw.write(cl_rev[si], self.cl_lengths[si] as u32, out);
            if s.extra_bits > 0 {
                bw.write(s.extra_value as u32, s.extra_bits as u32, out);
            }
        }

        for s in &self.block_symbols {
            match s {
                Symbol::Literal(b) => {
                    let bi = *b as usize;
                    debug_assert!(self.lit_lengths[bi] > 0);
                    bw.write(lit_rev[bi], self.lit_lengths[bi] as u32, out);
                }
                Symbol::Match { length, distance } => {
                    let (lc, lex, leb) = length_to_code(*length);
                    let lci = lc as usize;
                    bw.write(lit_rev[lci], self.lit_lengths[lci] as u32, out);
                    if leb > 0 {
                        bw.write(lex, leb as u32, out);
                    }
                    let (dc, dex, deb) = distance_to_code(*distance);
                    let dci = dc as usize;
                    bw.write(dist_rev[dci], self.dist_lengths[dci] as u32, out);
                    if deb > 0 {
                        bw.write(dex, deb as u32, out);
                    }
                }
            }
        }

        let eob = END_OF_BLOCK as usize;
        bw.write(lit_rev[eob], self.lit_lengths[eob] as u32, out);

        if bfinal {
            bw.align(out);
        }
    }

    fn compress_and_emit_block(&mut self, end_rel: usize, bfinal: bool) {
        self.block_symbols.clear();
        self.block_bytes.clear();

        self.lz77_pass(end_rel);

        for f in self.lit_freq.iter_mut() {
            *f = 0;
        }
        for f in self.dist_freq.iter_mut() {
            *f = 0;
        }
        let mut extra_bits_total: u64 = 0;
        for s in &self.block_symbols {
            match s {
                Symbol::Literal(b) => self.lit_freq[*b as usize] += 1,
                Symbol::Match { length, distance } => {
                    let (lc, _, leb) = length_to_code(*length);
                    self.lit_freq[lc as usize] += 1;
                    let (dc, _, deb) = distance_to_code(*distance);
                    self.dist_freq[dc as usize] += 1;
                    extra_bits_total += leb as u64 + deb as u64;
                }
            }
        }
        self.lit_freq[END_OF_BLOCK as usize] += 1;

        let (dyn_header_bits, dyn_payload_bits) = self.build_dynamic(extra_bits_total);
        let dynamic_total = dyn_header_bits + dyn_payload_bits;

        let fixed_total = self.fixed_cost_bits(extra_bits_total);

        let stored_total = if self.block_bytes.len() <= u16::MAX as usize {
            self.stored_cost_bits()
        } else {
            u64::MAX
        };

        if stored_total <= dynamic_total && stored_total <= fixed_total {
            self.emit_stored_block(bfinal);
        } else if fixed_total <= dynamic_total {
            self.emit_fixed_block(bfinal);
        } else {
            self.emit_dynamic_block(bfinal);
        }

        self.maybe_slide();
    }
}

impl Default for Encoder {
    fn default() -> Self {
        Self::new()
    }
}

impl RawEncoder for Encoder {
    fn raw_encode(&mut self, input: &[u8], output: &mut [u8]) -> Result<RawProgress, Error> {
        if matches!(self.state, EncState::Done) || self.final_emitted {
            return Err(Error::Corrupt);
        }
        let mut consumed = 0usize;
        let mut written = 0usize;

        loop {
            if matches!(self.state, EncState::Emitting) {
                if self.drain(output, &mut written) {
                    self.out_buffer.clear();
                    self.out_pos = 0;
                    self.state = EncState::Accepting;
                } else {
                    break;
                }
            }

            if matches!(self.state, EncState::Accepting) {
                let space = WINDOW_MAX.saturating_sub(self.window.len());
                let to_copy = (input.len() - consumed).min(space);
                self.window
                    .extend_from_slice(&input[consumed..consumed + to_copy]);
                consumed += to_copy;

                let lookahead = self.window.len() - self.cursor;
                if lookahead >= BLOCK_SIZE {
                    let end_rel = self.cursor + BLOCK_SIZE;
                    self.compress_and_emit_block(end_rel, false);
                    self.state = EncState::Emitting;
                } else if to_copy == 0 {
                    break;
                }
            }
        }

        Ok(RawProgress {
            consumed,
            written,
            done: false,
        })
    }

    fn raw_finish(&mut self, output: &mut [u8]) -> Result<RawProgress, Error> {
        let mut written = 0usize;
        if matches!(self.state, EncState::Done) {
            return Ok(RawProgress {
                consumed: 0,
                written: 0,
                done: true,
            });
        }

        loop {
            if matches!(self.state, EncState::Emitting) {
                if self.drain(output, &mut written) {
                    self.out_buffer.clear();
                    self.out_pos = 0;
                    if self.final_emitted {
                        self.state = EncState::Done;
                        return Ok(RawProgress {
                            consumed: 0,
                            written,
                            done: true,
                        });
                    }
                    self.state = EncState::Accepting;
                } else {
                    break;
                }
            }

            if matches!(self.state, EncState::Accepting) {
                let remaining = self.window.len() - self.cursor;
                if remaining >= BLOCK_SIZE {
                    let end_rel = self.cursor + BLOCK_SIZE;
                    self.compress_and_emit_block(end_rel, false);
                    self.state = EncState::Emitting;
                } else {
                    let end_rel = self.window.len();
                    self.compress_and_emit_block(end_rel, true);
                    self.final_emitted = true;
                    self.state = EncState::Emitting;
                }
            }
        }

        Ok(RawProgress {
            consumed: 0,
            written,
            done: false,
        })
    }

    fn raw_reset(&mut self) {
        self.window.clear();
        self.cursor = 0;
        self.window_start_abs = 0;
        self.match_finder.reset();
        self.block_symbols.clear();
        self.block_bytes.clear();
        self.bit_writer = BitWriter::new();
        self.out_buffer.clear();
        self.out_pos = 0;
        self.state = EncState::Accepting;
        self.final_emitted = false;
        self.mid_flush = false;
    }

    fn raw_flush(&mut self, output: &mut [u8], mode: Flush) -> Result<RawProgress, Error> {
        if matches!(self.state, EncState::Done) || self.final_emitted {
            return Err(Error::Corrupt);
        }

        let mut written = 0usize;

        loop {
            if matches!(self.state, EncState::Emitting) {
                if self.drain(output, &mut written) {
                    self.out_buffer.clear();
                    self.out_pos = 0;
                    self.state = EncState::Accepting;
                    if self.mid_flush {
                        self.mid_flush = false;
                        return Ok(RawProgress {
                            consumed: 0,
                            written,
                            done: true,
                        });
                    }
                } else {
                    return Ok(RawProgress {
                        consumed: 0,
                        written,
                        done: false,
                    });
                }
            }

            debug_assert!(!self.mid_flush);
            let remaining = self.window.len() - self.cursor;
            if remaining > 0 {
                let end_rel = self.window.len();
                self.compress_and_emit_block(end_rel, false);
            }
            self.emit_sync_marker();
            if matches!(mode, Flush::Full) {
                self.match_finder.reset();
            }
            self.mid_flush = true;
            self.state = EncState::Emitting;
        }
    }
}
