//! Streaming RFC 1951 deflate encoder.
//!
//! Buffers input into 16 KiB blocks. For each block: runs LZ77 over the
//! buffer to produce a sequence of literals and (length, distance) matches,
//! tallies frequencies, builds three length-limited Huffman codes (literal/
//! length, distance, and code-length), and emits a dynamic-Huffman block
//! (BTYPE=10) per RFC 1951 §3.2.7.
//!
//! v1 limitation: each block resets the match finder, so back-references
//! never cross block boundaries. Compression of data spanning blocks is
//! consequently weaker than a slide-and-rehash encoder; the wire format is
//! still valid deflate. Adding cross-block matching is a self-contained
//! follow-up.

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::bits::{reverse_bits, BitWriter};
use crate::error::Error;
use crate::huffman::{canonical_codes_from_lengths, length_limited_huffman};
use crate::traits::{Encoder as EncoderTrait, Progress};

use super::lz77::MatchFinder;
use super::tables::{
    CODE_LENGTH_ORDER, DIST_BASE, DIST_EXTRA, END_OF_BLOCK, LENGTH_BASE, LENGTH_EXTRA, MAX_MATCH,
    MIN_MATCH,
};

const BLOCK_SIZE: usize = 16 * 1024;

// ─── helpers for the length/distance -> code mapping ─────────────────────

/// Maps a match length in 3..=258 to its base code (subtract 257 to get
/// `LENGTH_BASE`/`LENGTH_EXTRA` index). Built at compile time.
const LENGTH_CODE_OFFSET: [u8; 256] = {
    let mut t = [0u8; 256];
    let mut len = MIN_MATCH;
    while len <= MAX_MATCH {
        let mut c = 0usize;
        while c < 28 && (LENGTH_BASE[c + 1] as usize) <= len {
            c += 1;
        }
        t[len - MIN_MATCH] = c as u8;
        len += 1;
    }
    t
};

fn length_to_code(length: u16) -> (u16, u16, u8) {
    let l = (length as usize) - MIN_MATCH;
    let c = LENGTH_CODE_OFFSET[l] as usize;
    let code = c as u16 + 257;
    let extra_value = length - LENGTH_BASE[c];
    let extra_bits = LENGTH_EXTRA[c];
    (code, extra_value, extra_bits)
}

fn distance_to_code(distance: u16) -> (u16, u16, u8) {
    // 30 candidates; small enough for a linear scan from the top.
    let mut c = 29usize;
    loop {
        if distance >= DIST_BASE[c] {
            let extra_value = distance - DIST_BASE[c];
            let extra_bits = DIST_EXTRA[c];
            return (c as u16, extra_value, extra_bits);
        }
        if c == 0 {
            break;
        }
        c -= 1;
    }
    // Distance was 0, which the caller should never pass.
    (0, 0, 0)
}

// ─── per-block symbol stream ─────────────────────────────────────────────

#[derive(Clone, Copy)]
enum Symbol {
    Literal(u8),
    Match { length: u16, distance: u16 },
}

// ─── code-length RLE encoding (RFC 1951 §3.2.7) ──────────────────────────

#[derive(Clone, Copy)]
struct ClSymbol {
    sym: u8,           // 0..=18
    extra_value: u16,  // 0..=127
    extra_bits: u8,    // 0, 2, 3, or 7
}

fn rle_encode_lengths(lengths: &[u8]) -> Vec<ClSymbol> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < lengths.len() {
        let cur = lengths[i];
        // Count consecutive identical values.
        let mut run = 1usize;
        while i + run < lengths.len() && lengths[i + run] == cur {
            run += 1;
        }

        if cur == 0 {
            // Zero runs use codes 17 (3..=10 zeros) and 18 (11..=138 zeros).
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
            // Always emit the first occurrence literally; code 16 ("repeat
            // previous") covers the next 3..=6 occurrences.
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
    out
}

// ─── encoder state ───────────────────────────────────────────────────────

enum EncState {
    Accepting,
    Emitting,
    Done,
}

pub struct Encoder {
    buffer: Box<[u8; BLOCK_SIZE]>,
    buffer_len: usize,
    match_finder: MatchFinder,
    bit_writer: BitWriter,
    out_buffer: Vec<u8>,
    out_pos: usize,
    state: EncState,
    /// True once we've emitted a BFINAL=1 block; finish() will not produce more.
    final_emitted: bool,
}

impl Encoder {
    pub fn new() -> Self {
        Self {
            buffer: Box::new([0u8; BLOCK_SIZE]),
            buffer_len: 0,
            match_finder: MatchFinder::new(),
            bit_writer: BitWriter::new(),
            out_buffer: Vec::new(),
            out_pos: 0,
            state: EncState::Accepting,
            final_emitted: false,
        }
    }

    /// Drain accumulated block bytes into the caller's output. Returns true
    /// when the current `out_buffer` has been fully forwarded.
    fn drain(&mut self, output: &mut [u8], written: &mut usize) -> bool {
        while self.out_pos < self.out_buffer.len() && *written < output.len() {
            output[*written] = self.out_buffer[self.out_pos];
            self.out_pos += 1;
            *written += 1;
        }
        self.out_pos >= self.out_buffer.len()
    }

    /// Compress whatever's in `self.buffer[..self.buffer_len]` into a single
    /// block, appending the bytes to `self.out_buffer` via `self.bit_writer`.
    /// If `bfinal` is true, sets BFINAL=1 and flushes the partial byte.
    fn compress_current_block(&mut self, bfinal: bool) {
        self.match_finder.reset();

        // ── LZ77 pass ──
        let buffer = &self.buffer[..self.buffer_len];
        let mut symbols: Vec<Symbol> = Vec::with_capacity(buffer.len());
        let mut pos = 0usize;
        while pos < buffer.len() {
            // Splice this position into the hash chain so future positions
            // in this block can reference us.
            self.match_finder.insert(buffer, pos);

            if pos + MIN_MATCH <= buffer.len()
                && let Some((len, dist)) = self.match_finder.find_match(buffer, pos)
            {
                symbols.push(Symbol::Match {
                    length: len,
                    distance: dist,
                });
                // Also insert every position covered by the match so a
                // later position can reference into the middle of it.
                for j in 1..(len as usize) {
                    let p = pos + j;
                    if p + 3 <= buffer.len() {
                        self.match_finder.insert(buffer, p);
                    }
                }
                pos += len as usize;
                continue;
            }
            symbols.push(Symbol::Literal(buffer[pos]));
            pos += 1;
        }

        // ── tally frequencies ──
        let mut lit_freq = [0u32; 286];
        let mut dist_freq = [0u32; 30];
        for s in &symbols {
            match s {
                Symbol::Literal(b) => lit_freq[*b as usize] += 1,
                Symbol::Match { length, distance } => {
                    let (lc, _, _) = length_to_code(*length);
                    lit_freq[lc as usize] += 1;
                    let (dc, _, _) = distance_to_code(*distance);
                    dist_freq[dc as usize] += 1;
                }
            }
        }
        lit_freq[END_OF_BLOCK as usize] += 1;

        // ── build length-limited Huffman code lengths ──
        // Sentinel: ensure at least two nonzero distance entries so package-
        // merge produces a valid two-symbol code. If only one (or zero)
        // distance code is needed, deflate spec §3.2.7 lets us signal "no
        // distance codes used" by sending HDIST=0 with a single 0-length
        // entry; package-merge naturally produces that since dist_freq is
        // then all-zero. Same for literal/length: EOB is always present so
        // there's at least one symbol.
        let lit_lengths_vec = length_limited_huffman(&lit_freq, 15);
        let dist_lengths_vec = length_limited_huffman(&dist_freq, 15);

        let mut lit_lengths = [0u8; 286];
        lit_lengths.copy_from_slice(&lit_lengths_vec);
        let mut dist_lengths = [0u8; 30];
        dist_lengths.copy_from_slice(&dist_lengths_vec);

        // If we ended up with exactly one distance code, deflate requires us
        // to bump it to a 1-bit code (so a 1-symbol prefix-code is valid).
        // package-merge already returns length 1 for the single-symbol case.
        // If zero distance codes are used, dist_lengths is all-zero; we'll
        // send HDIST = 0 (one entry) with that 0 length to mark "no distances".

        // ── determine HLIT / HDIST counts (trim trailing zeros) ──
        let mut hlit_count = 286usize;
        while hlit_count > 257 && lit_lengths[hlit_count - 1] == 0 {
            hlit_count -= 1;
        }
        let hlit = (hlit_count - 257) as u8;

        let mut hdist_count = 30usize;
        while hdist_count > 1 && dist_lengths[hdist_count - 1] == 0 {
            hdist_count -= 1;
        }
        let hdist = (hdist_count - 1) as u8;

        // ── RLE-encode the combined code-lengths ──
        let mut combined: Vec<u8> = Vec::with_capacity(hlit_count + hdist_count);
        combined.extend_from_slice(&lit_lengths[..hlit_count]);
        combined.extend_from_slice(&dist_lengths[..hdist_count]);
        let rle = rle_encode_lengths(&combined);

        // ── build the code-length-code Huffman (max length 7) ──
        let mut cl_freq = [0u32; 19];
        for s in &rle {
            cl_freq[s.sym as usize] += 1;
        }
        let cl_lengths_vec = length_limited_huffman(&cl_freq, 7);
        let mut cl_lengths = [0u8; 19];
        cl_lengths.copy_from_slice(&cl_lengths_vec);

        // ── HCLEN: trim trailing zeros from cl_lengths in CODE_LENGTH_ORDER permutation ──
        let mut hclen_count = 19usize;
        while hclen_count > 4 && cl_lengths[CODE_LENGTH_ORDER[hclen_count - 1]] == 0 {
            hclen_count -= 1;
        }
        let hclen = (hclen_count - 4) as u8;

        // ── canonical code values ──
        let lit_codes = canonical_codes_from_lengths(&lit_lengths);
        let dist_codes = canonical_codes_from_lengths(&dist_lengths);
        let cl_codes = canonical_codes_from_lengths(&cl_lengths);

        // ── emit ──
        let bw = &mut self.bit_writer;
        let out = &mut self.out_buffer;

        bw.write(if bfinal { 1 } else { 0 }, 1, out);
        bw.write(2, 2, out); // BTYPE = 10 (dynamic Huffman)

        bw.write(hlit as u32, 5, out);
        bw.write(hdist as u32, 5, out);
        bw.write(hclen as u32, 4, out);

        for i in 0..hclen_count {
            let len = cl_lengths[CODE_LENGTH_ORDER[i]];
            bw.write(len as u32, 3, out);
        }

        for s in &rle {
            let code = cl_codes[s.sym as usize];
            let len = cl_lengths[s.sym as usize];
            let rev = reverse_bits(code as u32, len as u32);
            bw.write(rev, len as u32, out);
            if s.extra_bits > 0 {
                bw.write(s.extra_value as u32, s.extra_bits as u32, out);
            }
        }

        // Data symbols.
        for s in &symbols {
            match s {
                Symbol::Literal(b) => {
                    let code = lit_codes[*b as usize];
                    let len = lit_lengths[*b as usize];
                    debug_assert!(len > 0, "literal {} has zero-length Huffman code", b);
                    let rev = reverse_bits(code as u32, len as u32);
                    bw.write(rev, len as u32, out);
                }
                Symbol::Match { length, distance } => {
                    let (lc, lex, leb) = length_to_code(*length);
                    let code = lit_codes[lc as usize];
                    let len = lit_lengths[lc as usize];
                    let rev = reverse_bits(code as u32, len as u32);
                    bw.write(rev, len as u32, out);
                    if leb > 0 {
                        bw.write(lex as u32, leb as u32, out);
                    }
                    let (dc, dex, deb) = distance_to_code(*distance);
                    let code = dist_codes[dc as usize];
                    let len = dist_lengths[dc as usize];
                    let rev = reverse_bits(code as u32, len as u32);
                    bw.write(rev, len as u32, out);
                    if deb > 0 {
                        bw.write(dex as u32, deb as u32, out);
                    }
                }
            }
        }

        // End-of-block.
        let code = lit_codes[END_OF_BLOCK as usize];
        let len = lit_lengths[END_OF_BLOCK as usize];
        let rev = reverse_bits(code as u32, len as u32);
        bw.write(rev, len as u32, out);

        if bfinal {
            bw.align(out);
        }

        // Block bytes are now ready in self.out_buffer for draining.
        self.buffer_len = 0;
    }
}

impl Default for Encoder {
    fn default() -> Self {
        Self::new()
    }
}

impl EncoderTrait for Encoder {
    fn encode(&mut self, input: &[u8], output: &mut [u8]) -> Result<Progress, Error> {
        if matches!(self.state, EncState::Done) || self.final_emitted {
            return Err(Error::Corrupt);
        }
        let mut consumed = 0usize;
        let mut written = 0usize;

        loop {
            if matches!(self.state, EncState::Emitting) {
                if self.drain(output, &mut written) {
                    // Block fully drained; clear buffer and go back to accepting.
                    self.out_buffer.clear();
                    self.out_pos = 0;
                    self.state = EncState::Accepting;
                } else {
                    break; // caller's output is full
                }
            }

            if matches!(self.state, EncState::Accepting) {
                let space = BLOCK_SIZE - self.buffer_len;
                let to_copy = (input.len() - consumed).min(space);
                self.buffer[self.buffer_len..self.buffer_len + to_copy]
                    .copy_from_slice(&input[consumed..consumed + to_copy]);
                self.buffer_len += to_copy;
                consumed += to_copy;

                if self.buffer_len == BLOCK_SIZE {
                    self.compress_current_block(false);
                    self.state = EncState::Emitting;
                } else {
                    // Input exhausted, buffer not yet full.
                    break;
                }
            }
        }

        Ok(Progress {
            consumed,
            written,
            done: false,
        })
    }

    fn finish(&mut self, output: &mut [u8]) -> Result<Progress, Error> {
        let mut written = 0usize;
        if matches!(self.state, EncState::Done) {
            return Ok(Progress {
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
                        return Ok(Progress {
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
                self.compress_current_block(true);
                self.final_emitted = true;
                self.state = EncState::Emitting;
            }
        }

        Ok(Progress {
            consumed: 0,
            written,
            done: false,
        })
    }

    fn reset(&mut self) {
        self.buffer_len = 0;
        self.match_finder.reset();
        self.bit_writer = BitWriter::new();
        self.out_buffer.clear();
        self.out_pos = 0;
        self.state = EncState::Accepting;
        self.final_emitted = false;
    }
}

