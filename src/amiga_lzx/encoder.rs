//! Streaming Amiga-LZX encoder — uncompressed-block-only fallback.
//!
//! Produces a valid Amiga-LZX bitstream that [`super::Decoder`] accepts but
//! never emits verbatim or aligned-offset blocks; every input chunk is sent
//! as a `BLOCKTYPE=3` (uncompressed) block of at most 32 KiB. The output is
//! therefore *larger* than the input by ~16 bytes per chunk of framing
//! overhead. The purpose is to exercise the streaming `Encoder` trait and
//! round-trip the decoder; a production-grade encoder would emit verbatim
//! or aligned-offset blocks with LZ77 + Huffman.
//!
//! Block layout produced:
//!   - 3 bits  : `BLOCKTYPE = 011` (3 = uncompressed)
//!   - 24 bits : `BLOCK_SIZE` — the number of payload bytes that follow
//!   - 5 zero bits of pad to reach a 16-bit-word boundary
//!   - 12 bytes: R0/R1/R2 = 0/0/0 (we never compress so the LRU never matters)
//!   - `BLOCK_SIZE` bytes of raw payload (and a 1-byte zero pad iff the
//!     declared block length is odd)
//!
//! Unlike the MS-CAB profile, there is **no** leading "intel translation"
//! preamble bit; the bitstream begins directly with the first block's
//! `BLOCKTYPE` field.
//!
//! ## Buffering
//!
//! The 4-byte stream framing header (LE total uncompressed length) can only
//! be filled in once we know the total length — i.e. at `finish` time. The
//! encoder therefore buffers all input until `finish`. For large inputs
//! this is `O(input)` memory; callers that need streaming at constant
//! memory should use a real LZ77+Huffman encoder.

use alloc::vec::Vec;

use crate::error::Error;
use crate::traits::{RawEncoder, RawProgress};

use crate::lzx::tables::BLOCKTYPE_UNCOMPRESSED;

/// Maximum payload per uncompressed block. Picked to be even so we never
/// trigger the odd-length pad-byte branch.
const CHUNK_BYTES: usize = 32 * 1024;

#[derive(Debug)]
pub struct Encoder {
    state: EncState,
    /// Accumulator for input bytes; flushed into `out_buf` during `finish`.
    raw: Vec<u8>,
    /// Encoded output bytes waiting to be drained.
    out_buf: Vec<u8>,
    out_pos: usize,
}

#[derive(Debug, Clone, Copy)]
enum EncState {
    Accumulating,
    Draining,
    Done,
}

impl Encoder {
    pub fn new() -> Self {
        Self {
            state: EncState::Accumulating,
            raw: Vec::new(),
            out_buf: Vec::new(),
            out_pos: 0,
        }
    }

    fn drain(&mut self, output: &mut [u8], written: &mut usize) {
        while self.out_pos < self.out_buf.len() && *written < output.len() {
            let n = (self.out_buf.len() - self.out_pos).min(output.len() - *written);
            output[*written..*written + n]
                .copy_from_slice(&self.out_buf[self.out_pos..self.out_pos + n]);
            *written += n;
            self.out_pos += n;
        }
        if self.out_pos == self.out_buf.len() {
            self.out_buf.clear();
            self.out_pos = 0;
        }
    }

    /// Build the full encoded stream into `self.out_buf`. Idempotent across
    /// re-entry into `finish`.
    fn build_stream(&mut self) {
        // 4-byte framing header: LE u32 total uncompressed length.
        let total = self.raw.len() as u32;
        self.out_buf.extend_from_slice(&total.to_le_bytes());

        if self.raw.is_empty() {
            return;
        }

        // Pre-compute block boundaries to avoid borrow conflicts while we
        // both read from self.raw and append to self.out_buf.
        let mut chunks: alloc::vec::Vec<(usize, usize, bool)> = alloc::vec::Vec::new();
        let mut start = 0usize;
        while start < self.raw.len() {
            let mut end = (start + CHUNK_BYTES).min(self.raw.len());
            let mut pad = false;
            if (end - start) % 2 == 1 {
                if end == self.raw.len() {
                    pad = true;
                } else {
                    end -= 1;
                }
            }
            chunks.push((start, end, pad));
            start = end;
        }
        for (s, e, pad) in chunks {
            self.append_uncompressed_block_range(s, e, pad);
        }
    }

    fn append_uncompressed_block_range(&mut self, start: usize, end: usize, pad: bool) {
        let payload_len = (end - start) as u32;
        // BLOCK_SIZE on the wire = number of uncompressed bytes this block
        // contributes. Padded blocks declare payload.len() + 1.
        let declared = if pad { payload_len + 1 } else { payload_len };
        debug_assert!(declared > 0 && declared <= 0x00FF_FFFF);

        // Build the MSB-first 32-bit block header:
        //   [BLOCKTYPE (3 bits) | BLOCK_SIZE (24 bits) | 5 zero bits of pad] = 32 bits
        // The 5-bit pad reaches the 16-bit-word boundary that the
        // uncompressed-block R-dump expects.
        let hi16 = (declared >> 8) & 0xFFFF;
        let lo8 = declared & 0xFF;
        let header27: u32 = ((BLOCKTYPE_UNCOMPRESSED as u32) << 24) | (hi16 << 8) | lo8;
        let padded32: u32 = header27 << 5;
        let word0 = ((padded32 >> 16) & 0xFFFF) as u16;
        let word1 = (padded32 & 0xFFFF) as u16;
        push_word_le(&mut self.out_buf, word0);
        push_word_le(&mut self.out_buf, word1);

        // 12 bytes of R0/R1/R2 = 0/0/0. Per the LZX spec the uncompressed
        // block must restore the LRU offsets; with no prior matches this is
        // 0/0/0.
        for r in [0u32, 0, 0] {
            self.out_buf.extend_from_slice(&r.to_le_bytes());
        }

        // Payload bytes. We do this via a copy-without-borrowing dance because
        // self.raw and self.out_buf are both fields.
        let payload_start = self.out_buf.len();
        self.out_buf.resize(payload_start + (end - start), 0);
        self.out_buf[payload_start..payload_start + (end - start)]
            .copy_from_slice(&self.raw[start..end]);
        if pad {
            self.out_buf.push(0);
        }
    }
}

fn push_word_le(buf: &mut Vec<u8>, word: u16) {
    buf.push((word & 0xFF) as u8);
    buf.push((word >> 8) as u8);
}

impl Default for Encoder {
    fn default() -> Self {
        Self::new()
    }
}

impl RawEncoder for Encoder {
    fn raw_encode(&mut self, input: &[u8], output: &mut [u8]) -> Result<RawProgress, Error> {
        let mut consumed = 0usize;
        let mut written = 0usize;
        // Drain whatever might already be queued.
        self.drain(output, &mut written);

        match self.state {
            EncState::Accumulating => {
                if !input.is_empty() {
                    self.raw.extend_from_slice(input);
                    consumed = input.len();
                }
            }
            EncState::Draining | EncState::Done => {}
        }

        Ok(RawProgress {
            consumed,
            written,
            done: false,
        })
    }

    fn raw_finish(&mut self, output: &mut [u8]) -> Result<RawProgress, Error> {
        let mut written = 0usize;
        loop {
            self.drain(output, &mut written);
            match self.state {
                EncState::Accumulating => {
                    self.build_stream();
                    self.state = EncState::Draining;
                }
                EncState::Draining => {
                    if self.out_pos == self.out_buf.len() {
                        self.state = EncState::Done;
                    } else if written == output.len() {
                        return Ok(RawProgress {
                            consumed: 0,
                            written,
                            done: false,
                        });
                    }
                }
                EncState::Done => {
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
        self.state = EncState::Accumulating;
        self.raw.clear();
        self.out_buf.clear();
        self.out_pos = 0;
    }
}
