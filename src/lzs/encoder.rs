//! Streaming encoder for the RFC 1974 LZS bitstream.
//!
//! Strategy: accumulate raw input into a `Vec<u8>` during `encode`,
//! produce the compressed payload on the first `finish` call, then
//! drain the staged buffer to the caller across however many further
//! `finish` calls are needed.
//!
//! The matcher is a single-hashtable LZ77 (one hit per slot, no chain)
//! against the 2 KiB sliding window. This keeps the encoder small and
//! predictable while still giving useful ratios on data with short-
//! period repetition. The output is a conformant RFC 1974 §2 payload,
//! but the codec is not byte-for-byte compatible with reference
//! Stac/Hifn encoders (those use richer match searchers).

use alloc::vec::Vec;

use crate::error::Error;
use crate::traits::{RawEncoder, RawProgress};

use super::bits::BitWriter;
use super::{MAX_DISTANCE, MIN_MATCH};

/// LZ77 hash-table size for the 2 KiB window. 4 KiB slots are enough
/// to keep collision rates low without bloating memory.
const HASH_BITS: u32 = 12;
const HASH_SIZE: usize = 1 << HASH_BITS;
const HASH_EMPTY: u32 = u32::MAX;

/// Encoder phase.
#[derive(Clone, Copy, PartialEq, Eq)]
enum EncPhase {
    Buffering,
    Draining,
    Done,
}

/// RFC 1974 LZS encoder. No tunables — the codec has no level knob.
pub struct Encoder {
    raw: Vec<u8>,
    staged: Vec<u8>,
    staged_idx: usize,
    phase: EncPhase,
}

impl Default for Encoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Encoder {
    pub const fn new() -> Self {
        Self {
            raw: Vec::new(),
            staged: Vec::new(),
            staged_idx: 0,
            phase: EncPhase::Buffering,
        }
    }

    fn drain_staged(&mut self, output: &mut [u8], written: &mut usize) {
        let avail = self.staged.len() - self.staged_idx;
        let space = output.len() - *written;
        let n = avail.min(space);
        if n > 0 {
            output[*written..*written + n]
                .copy_from_slice(&self.staged[self.staged_idx..self.staged_idx + n]);
            self.staged_idx += n;
            *written += n;
        }
        if self.staged_idx == self.staged.len() {
            self.staged.clear();
            self.staged_idx = 0;
            self.phase = EncPhase::Done;
        }
    }

    /// Produce the framed payload into `self.staged`.
    fn build_stream(&mut self) {
        self.staged.clear();
        self.staged
            .extend_from_slice(&(self.raw.len() as u64).to_le_bytes());

        let mut bw = BitWriter::new();
        encode_payload(&self.raw, &mut bw);
        // End-of-stream marker: 9 bits = `11` + 7 zero bits (short
        // offset 0). Pad the final partial byte to a byte boundary with
        // 1 bits per RFC 1974 §2.
        bw.write_bits(9, 0b1_1000_0000);
        bw.pad_with_ones_to_byte();
        let payload = bw.into_bytes();
        self.staged.extend_from_slice(&payload);
    }
}

impl RawEncoder for Encoder {
    fn raw_encode(&mut self, input: &[u8], output: &mut [u8]) -> Result<RawProgress, Error> {
        let _ = output;
        if self.phase != EncPhase::Buffering {
            return Ok(RawProgress {
                consumed: 0,
                written: 0,
                done: false,
            });
        }
        self.raw.extend_from_slice(input);
        Ok(RawProgress {
            consumed: input.len(),
            written: 0,
            done: false,
        })
    }

    fn raw_finish(&mut self, output: &mut [u8]) -> Result<RawProgress, Error> {
        let mut written = 0usize;
        loop {
            match self.phase {
                EncPhase::Buffering => {
                    self.build_stream();
                    self.staged_idx = 0;
                    self.phase = EncPhase::Draining;
                }
                EncPhase::Draining => {
                    self.drain_staged(output, &mut written);
                    if self.phase == EncPhase::Draining {
                        return Ok(RawProgress {
                            consumed: 0,
                            written,
                            done: false,
                        });
                    }
                }
                EncPhase::Done => {
                    return Ok(RawProgress {
                        consumed: 0,
                        written,
                        done: true,
                    });
                }
            }
        }
    }

    fn raw_reset(&mut self) {
        self.raw.clear();
        self.staged.clear();
        self.staged_idx = 0;
        self.phase = EncPhase::Buffering;
    }
}

/// 2-byte rolling hash used to seed the match-finder.
#[inline]
fn hash2(a: u8, b: u8) -> usize {
    let v = ((a as u32) << 8) | b as u32;
    (v.wrapping_mul(2_654_435_761) >> (32 - HASH_BITS)) as usize
}

/// Encode `input` as an LZS bitstream (no end marker, no padding) into
/// `bw`.
fn encode_payload(input: &[u8], bw: &mut BitWriter) {
    if input.is_empty() {
        return;
    }

    let mut table = alloc::vec![HASH_EMPTY; HASH_SIZE];
    let mut i: usize = 0;

    while i < input.len() {
        let remaining = input.len() - i;
        let mut best_len: usize = 0;
        let mut best_dist: usize = 0;

        if remaining >= MIN_MATCH {
            let key = hash2(input[i], input[i + 1]);
            let prev = table[key];
            table[key] = i as u32;
            if prev != HASH_EMPTY {
                let p = prev as usize;
                if p < i {
                    let dist = i - p;
                    if (1..=MAX_DISTANCE).contains(&dist) {
                        // Verify and extend.
                        let max_len = remaining;
                        let mut len = 0usize;
                        while len < max_len && input[p + len] == input[i + len] {
                            len += 1;
                        }
                        if len >= MIN_MATCH {
                            best_len = len;
                            best_dist = dist;
                        }
                    }
                }
            }
        } else if remaining == 1 {
            // Single byte left: emit as literal.
        }

        if best_len >= MIN_MATCH {
            // Emit match. Offset prefix selection:
            //   1..=127  → `11` + 7 bits
            //   128..=2047 → `10` + 11 bits
            // (Offset 0 is reserved for the end-of-stream marker.)
            if best_dist <= 127 {
                bw.write_bits(2, 0b11);
                bw.write_bits(7, best_dist as u32);
            } else {
                bw.write_bits(2, 0b10);
                bw.write_bits(11, best_dist as u32);
            }
            write_length(bw, best_len);

            // Update hash table for the matched span so future positions
            // benefit. The single-slot table is overwritten freely.
            for k in 1..best_len {
                if i + k + 1 < input.len() {
                    let h = hash2(input[i + k], input[i + k + 1]);
                    table[h] = (i + k) as u32;
                }
            }
            i += best_len;
        } else {
            // Literal byte: `0` + 8-bit byte.
            bw.write_bits(1, 0);
            bw.write_bits(8, input[i] as u32);
            i += 1;
        }
    }
}

/// Encode a match length per RFC 1974 §2:
///
/// ```text
///   2  → 00
///   3  → 01
///   4  → 10
///   5  → 1100
///   6  → 1101
///   7  → 1110
///   8+ → 1111 (+ optional further 1111s) + final 4-bit tail
/// ```
fn write_length(bw: &mut BitWriter, len: usize) {
    debug_assert!(len >= 2);
    match len {
        2 => bw.write_bits(2, 0b00),
        3 => bw.write_bits(2, 0b01),
        4 => bw.write_bits(2, 0b10),
        5 => bw.write_bits(4, 0b1100),
        6 => bw.write_bits(4, 0b1101),
        7 => bw.write_bits(4, 0b1110),
        _ => {
            // Lengths >= 8: chains of `1111` (each adds 15) followed
            // by a final non-`1111` nibble. Length 8 → `1111 0000`,
            // length 22 → `1111 1110`, length 23 → `1111 1111 0000`, …
            let mut remaining = len - 8;
            while remaining >= 15 {
                bw.write_bits(4, 0b1111);
                remaining -= 15;
            }
            bw.write_bits(4, 0b1111);
            bw.write_bits(4, remaining as u32);
        }
    }
}
