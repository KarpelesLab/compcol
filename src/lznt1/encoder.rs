//! LZNT1 encoder: buffer-everything-then-emit, chunk by chunk.
//!
//! `raw_encode` accumulates input into an internal buffer; emission
//! happens in `raw_finish`. This sidesteps the cross-call state that a
//! true streaming match finder would need (committed-vs-tentative
//! literals, flag-byte half-emitted across chunk boundaries), at the
//! cost of holding the full input in memory until the producer signals
//! end-of-stream. Memory is proportional to input size; this is the
//! same pattern used by `snappy` and `adc` in this crate.

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;
use crate::traits::{Flush, RawEncoder, RawProgress};

use super::{CHUNK_SIZE, split_for_pos};

/// Per-encoder configuration. LZNT1 has no compression level knob in the
/// MS-XCA format; this is a unit type today and exists so the public
/// `Encoder` signature can grow knobs (e.g. a "fast vs. best" match
/// strategy) without a breaking change.
#[derive(Debug, Clone, Default)]
pub struct EncoderConfig;

/// Minimum match length the encoder will emit.
const MIN_MATCH: usize = 3;

/// Hash table size for the per-chunk match finder. 12 bits = 4096
/// entries is large enough to cover the maximum chunk while staying
/// cache-friendly.
const HASH_LOG: u32 = 12;
const HASH_TABLE_SIZE: usize = 1 << HASH_LOG;
const HASH_EMPTY: i32 = -1;

#[inline]
fn hash3(b0: u8, b1: u8, b2: u8) -> usize {
    let v = (b0 as u32) | ((b1 as u32) << 8) | ((b2 as u32) << 16);
    ((v.wrapping_mul(2_654_435_761)) >> (32 - HASH_LOG)) as usize
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Accepting input bytes into `input`.
    Buffering,
    /// All input has been compressed into `encoded`; bytes are being
    /// drained to the caller's output buffer.
    Flushing,
    /// `encoded` fully drained.
    Done,
}

pub struct Encoder {
    // Reserved for future tunables; held so a non-default config passed
    // at construction survives across `reset` (parity with other
    // encoders in this crate).
    _cfg: EncoderConfig,
    input: Vec<u8>,
    encoded: Vec<u8>,
    encoded_idx: usize,
    phase: Phase,
}

impl Encoder {
    pub fn new() -> Self {
        Self::with_config(EncoderConfig)
    }

    pub fn with_config(cfg: EncoderConfig) -> Self {
        Self {
            _cfg: cfg,
            input: Vec::new(),
            encoded: Vec::new(),
            encoded_idx: 0,
            phase: Phase::Buffering,
        }
    }

    /// Encode `self.input` into `self.encoded` by chunking and emitting
    /// each chunk independently. Transitions `phase` to `Flushing` if
    /// any bytes were produced, or `Done` if the input was empty.
    fn build(&mut self) {
        self.encoded.clear();
        self.encoded_idx = 0;
        if self.input.is_empty() {
            self.phase = Phase::Done;
            return;
        }
        let mut i = 0;
        // Take ownership of `input` to release the borrow on `self`
        // before calling `emit_chunk`. We restore an empty buffer at
        // the same allocation when done (it would be cleared on reset
        // anyway).
        let buf = core::mem::take(&mut self.input);
        while i < buf.len() {
            let end = (i + CHUNK_SIZE).min(buf.len());
            let chunk = &buf[i..end];
            self.emit_chunk(chunk);
            i = end;
        }
        // Per MS-XCA the stream is terminated by either end-of-input or
        // a 2-byte zero word. Many real-world consumers expect the
        // trailing zero header, so emit it.
        self.encoded.push(0);
        self.encoded.push(0);
        self.phase = Phase::Flushing;
    }

    /// Emit one chunk's header + body. Tries the compressed body first;
    /// if the compressed body would be no smaller than the raw bytes,
    /// falls back to an uncompressed chunk.
    fn emit_chunk(&mut self, chunk: &[u8]) {
        // Compressed body candidate.
        let mut compressed_body: Vec<u8> = Vec::with_capacity(chunk.len() + 16);
        let compressible = compress_chunk_body(chunk, &mut compressed_body);
        // Only accept the compressed form if it actually shrinks the
        // chunk. Uncompressed body is `chunk.len()` bytes; compressed
        // is `compressed_body.len()` bytes.
        let use_compressed = compressible && compressed_body.len() < chunk.len();

        if use_compressed {
            let body_size = compressed_body.len();
            debug_assert!((1..=CHUNK_SIZE).contains(&body_size));
            let hdr: u16 = 0xB000 | ((body_size as u16) - 1);
            self.encoded.push((hdr & 0xFF) as u8);
            self.encoded.push((hdr >> 8) as u8);
            self.encoded.extend_from_slice(&compressed_body);
        } else {
            // Uncompressed: signature 0b011, compressed flag 0, size =
            // chunk.len() - 1.
            let body_size = chunk.len();
            let hdr: u16 = 0x3000 | ((body_size as u16) - 1);
            self.encoded.push((hdr & 0xFF) as u8);
            self.encoded.push((hdr >> 8) as u8);
            self.encoded.extend_from_slice(chunk);
        }
    }

    fn drain_encoded(&mut self, output: &mut [u8], written: &mut usize) {
        let avail = self.encoded.len() - self.encoded_idx;
        let room = output.len() - *written;
        let n = avail.min(room);
        if n > 0 {
            output[*written..*written + n]
                .copy_from_slice(&self.encoded[self.encoded_idx..self.encoded_idx + n]);
            self.encoded_idx += n;
            *written += n;
        }
        if self.encoded_idx == self.encoded.len() {
            self.phase = Phase::Done;
        }
    }
}

impl Default for Encoder {
    fn default() -> Self {
        Self::new()
    }
}

impl RawEncoder for Encoder {
    fn raw_encode(&mut self, input: &[u8], output: &mut [u8]) -> Result<RawProgress, Error> {
        let _ = output;
        if self.phase != Phase::Buffering {
            return Ok(RawProgress {
                consumed: 0,
                written: 0,
                done: false,
            });
        }
        self.input.extend_from_slice(input);
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
                Phase::Buffering => self.build(),
                Phase::Flushing => {
                    self.drain_encoded(output, &mut written);
                    if self.phase == Phase::Flushing {
                        return Ok(RawProgress {
                            consumed: 0,
                            written,
                            done: false,
                        });
                    }
                }
                Phase::Done => {
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
        self.input.clear();
        self.encoded.clear();
        self.encoded_idx = 0;
        self.phase = Phase::Buffering;
    }

    fn raw_flush(&mut self, output: &mut [u8], _mode: Flush) -> Result<RawProgress, Error> {
        // LZNT1 has no in-band sync marker. Conform to the default
        // contract: report the flush call complete with zero bytes.
        let _ = output;
        Ok(RawProgress {
            consumed: 0,
            written: 0,
            done: true,
        })
    }
}

// ─── per-chunk compressed-body builder ────────────────────────────────

/// Build the compressed body of one chunk into `out`. Returns `true` if
/// the body was fully encoded; `false` if the encoder gave up partway
/// because the body would have exceeded `CHUNK_SIZE` (in which case the
/// caller should fall back to an uncompressed chunk).
///
/// On `false` return `out` may contain partial data; the caller is
/// expected to discard it.
fn compress_chunk_body(chunk: &[u8], out: &mut Vec<u8>) -> bool {
    out.clear();
    if chunk.is_empty() {
        return true;
    }

    // Hash table mapping 3-byte-prefix hash → last position seen.
    // Sentinel HASH_EMPTY = -1.
    let mut hash_table: Vec<i32> = vec![HASH_EMPTY; HASH_TABLE_SIZE];
    let n = chunk.len();

    // Buffer tokens for one flag group (up to 8); flag byte is written
    // first, then the tokens.
    let mut group: Vec<u8> = Vec::with_capacity(8 * 2 + 1);
    let mut flag: u8 = 0;
    let mut group_count: u32 = 0;

    // Helper that finalises the current 8-token group and writes it
    // into `out`. Returns false if the body would no longer fit.
    let flush_group = |out: &mut Vec<u8>, flag: u8, group: &[u8]| -> bool {
        out.push(flag);
        out.extend_from_slice(group);
        out.len() <= CHUNK_SIZE
    };

    let mut i: usize = 0;

    while i < n {
        // Find a match starting at i, of length ≥ MIN_MATCH.
        let mut best_len: usize = 0;
        let mut best_off: usize = 0;

        if i + MIN_MATCH <= n {
            let pos_for_split = i; // bytes emitted before this match
            let (off_bits, length_bits) = split_for_pos(pos_for_split);
            let max_offset: usize = 1 << off_bits;
            let max_length: usize = (1usize << length_bits) + 2; // 3 + (2^L - 1)
            let h = hash3(chunk[i], chunk[i + 1], chunk[i + 2]);
            let prev = hash_table[h];
            if prev >= 0 {
                let prev_pos = prev as usize;
                if prev_pos < i {
                    let dist = i - prev_pos;
                    if dist >= 1 && dist <= max_offset && dist <= i {
                        // LZNT1 allows self-overlap (length > offset);
                        // the decoder copies byte-by-byte from the
                        // emitted output so we model that by indexing
                        // `prev_pos + (len % dist)` in the source.
                        let real_limit = (n - i).min(max_length);
                        let mut len = 0usize;
                        while len < real_limit && chunk[i + len] == chunk[prev_pos + (len % dist)] {
                            len += 1;
                        }
                        if len >= MIN_MATCH {
                            best_len = len;
                            best_off = dist;
                        }
                    }
                }
            }
            // Update hash table with current position regardless.
            hash_table[h] = i as i32;
        }

        if best_len >= MIN_MATCH {
            // Match token: 2 bytes little-endian. Use the same `pos`
            // the decoder will compute (bytes emitted before this
            // match) so the offset/length split matches.
            let pos_for_split = i;
            let (_off_bits, length_bits) = split_for_pos(pos_for_split);
            let off_code = (best_off - 1) as u16;
            let len_code = (best_len - MIN_MATCH) as u16;
            let token: u16 = (off_code << length_bits) | len_code;
            group.push((token & 0xFF) as u8);
            group.push((token >> 8) as u8);
            flag |= 1u8 << group_count;
            group_count += 1;
            // Insert hash entries for the bytes we skipped over (so
            // future matches can find them).
            let match_end = i + best_len;
            let mut j = i + 1;
            while j + MIN_MATCH <= match_end && j + MIN_MATCH <= n {
                let h2 = hash3(chunk[j], chunk[j + 1], chunk[j + 2]);
                hash_table[h2] = j as i32;
                j += 1;
            }
            i = match_end;
        } else {
            // Literal: bit stays 0 in the flag byte; just append the
            // raw byte to the current group.
            group.push(chunk[i]);
            group_count += 1;
            i += 1;
        }

        if group_count == 8 {
            if !flush_group(out, flag, &group) {
                return false;
            }
            flag = 0;
            group_count = 0;
            group.clear();
        }
    }

    // Flush the final partial group (if any).
    if group_count > 0 && !flush_group(out, flag, &group) {
        return false;
    }

    out.len() <= CHUNK_SIZE
}
