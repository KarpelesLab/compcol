//! Burrows–Wheeler Transform (BWT) — a standalone, reversible block codec.
//!
//! The BWT is a *permutation* of the input, not a compressor: its output is
//! exactly as long as its input (plus a small per-block header). What it buys
//! you is **local clustering** — runs of bytes that share a following context
//! end up adjacent, which makes the output far more compressible by a
//! downstream entropy stage (move-to-front + RLE + Huffman, as in bzip2). It
//! is shipped here as a first-class codec alongside the other transform-only
//! filters in this crate (`delta`, `bcj`).
//!
//! The crate already computes a BWT *inside* the bzip2 pipeline, but never
//! exposes it on its own. This module is an independent, clean-room
//! implementation (it shares no code with `src/bzip2/bwt.rs`) that round-trips
//! arbitrary data on its own.
//!
//! ## Framing — block stream
//!
//! The input is split into fixed-size blocks (the last block may be shorter).
//! Each block is emitted as:
//!
//! ```text
//! ┌────────────┬───────────────┬─────────────────────────────────┐
//! │ len  u32LE │ primary u32LE │  L (BWT last column), len bytes  │
//! └────────────┴───────────────┴─────────────────────────────────┘
//! ```
//!
//! * `len` — number of bytes in this block (`1..=block_size`). A `len` of 0 is
//!   never emitted; empty input produces zero blocks (an empty stream).
//! * `primary` — the row index, in the sorted rotation matrix, of the row that
//!   is the original block (the BWT "primary index"). Must be `< len`.
//! * `L` — the last column of the sorted rotation matrix: `len` bytes.
//!
//! The stream is **self-delimiting**: the decoder reads blocks back-to-back
//! until the input is exhausted. There is no overall header or trailer, so the
//! codec composes cleanly in front of an entropy coder.
//!
//! ## Forward transform
//!
//! For each block we build the order of its cyclic rotations with a
//! prefix-doubling (Manber–Myers) sort — `O(n log n)` ranking rounds, each an
//! `O(n)` counting sort on the `(rank[i], rank[i + k])` pairs. From the sorted
//! rotation order `sa` (where `sa[r]` is the starting offset of the rotation
//! ranked `r`) the BWT last column is `L[r] = block[(sa[r] + n - 1) mod n]`,
//! and the primary index is the rank of the rotation that starts at offset 0.
//!
//! The prefix-doubling sort is `O(n log n)` and handles the pathological cases
//! (all-equal bytes, long repeats) without degrading to `O(n² log n)`.
//!
//! ## Inverse transform
//!
//! Standard LF-mapping reconstruction: counting-sort the last column to get
//! each symbol's starting offset in the first column, build the `next` vector
//! that links each row to its predecessor in the original order, then walk
//! `len` steps from the primary index, emitting one byte per step.
//!
//! ## Edge cases
//!
//! Empty input → zero blocks. One-byte block → `primary = 0`, `L = [b]`.
//! All-equal bytes and highly repetitive blocks are handled by the stable
//! rank-based sort. The decoder rejects a `primary >= len`, a `len` of zero,
//! or a truncated block with [`Error::Corrupt`] / [`Error::UnexpectedEnd`] and
//! never panics.
//!
//! ## Licensing
//!
//! Clean-room from the published BWT algorithm description (Burrows & Wheeler,
//! 1994) and the textbook prefix-doubling rotation sort. No code was copied
//! from `src/bzip2/` or any third-party source.

#![cfg_attr(docsrs, doc(cfg(feature = "bwt")))]

extern crate alloc;
use alloc::vec::Vec;

use crate::error::Error;
use crate::traits::{Algorithm, RawDecoder, RawEncoder, RawProgress};

mod transform;

#[cfg(test)]
mod tests;

/// Default block size: 256 KiB. Large enough to give the transform good
/// context for typical text/binary inputs, small enough that the `u32`
/// length/primary fields and the `O(n log n)` sort stay comfortable.
pub const DEFAULT_BLOCK_SIZE: usize = 256 * 1024;

/// Minimum permitted block size. A block must hold at least one byte.
pub const MIN_BLOCK_SIZE: usize = 1;

/// Maximum permitted block size. Bounded so the per-block `u32` length and
/// primary-index fields cannot overflow, with margin to spare.
pub const MAX_BLOCK_SIZE: usize = 64 * 1024 * 1024;

/// Zero-sized marker type implementing [`Algorithm`] for the BWT codec.
#[derive(Debug, Clone, Copy, Default)]
pub struct Bwt;

/// Encoder configuration: the block size in bytes.
///
/// `#[non_exhaustive]`: construct via [`EncoderConfig::default`] and the
/// `with_*` builders rather than a struct literal, so new tuning knobs can be
/// added later without breaking downstream code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct EncoderConfig {
    /// Block size in bytes. Clamped to `MIN_BLOCK_SIZE..=MAX_BLOCK_SIZE` at
    /// encoder construction time. Default is [`DEFAULT_BLOCK_SIZE`].
    pub block_size: usize,
}

impl Default for EncoderConfig {
    fn default() -> Self {
        Self {
            block_size: DEFAULT_BLOCK_SIZE,
        }
    }
}

impl EncoderConfig {
    /// Default configuration (256 KiB blocks).
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the block size in bytes (clamped to
    /// `MIN_BLOCK_SIZE..=MAX_BLOCK_SIZE` at encoder build time).
    #[must_use]
    pub fn with_block_size(mut self, block_size: usize) -> Self {
        self.block_size = block_size;
        self
    }
}

impl Algorithm for Bwt {
    const NAME: &'static str = "bwt";
    type Encoder = Encoder;
    type Decoder = Decoder;
    type EncoderConfig = EncoderConfig;
    type DecoderConfig = ();

    fn encoder_with(cfg: EncoderConfig) -> Encoder {
        Encoder::new(cfg.block_size)
    }
    fn decoder_with(_: ()) -> Decoder {
        Decoder::new()
    }
}

// ─── encoder ─────────────────────────────────────────────────────────────

/// Streaming BWT encoder.
///
/// Buffers all input, then on `finish` splits it into blocks and emits the
/// block stream described in the [module docs](crate::bwt). The whole input is
/// buffered because the transform operates on complete blocks; memory cost is
/// `O(input)`.
#[derive(Debug)]
pub struct Encoder {
    block_size: usize,
    input: Vec<u8>,
    output: Vec<u8>,
    out_cursor: usize,
    finalized: bool,
}

impl Encoder {
    /// Construct an encoder with the given block size (clamped to
    /// `MIN_BLOCK_SIZE..=MAX_BLOCK_SIZE`).
    pub fn new(block_size: usize) -> Self {
        Self {
            block_size: block_size.clamp(MIN_BLOCK_SIZE, MAX_BLOCK_SIZE),
            input: Vec::new(),
            output: Vec::new(),
            out_cursor: 0,
            finalized: false,
        }
    }

    fn finalize(&mut self) {
        for block in self.input.chunks(self.block_size) {
            // `block` is never empty: chunks() of a non-empty slice yields
            // non-empty chunks, and an empty input yields no chunks at all.
            let (last_col, primary) = transform::forward(block);
            let len = block.len() as u32;
            self.output.extend_from_slice(&len.to_le_bytes());
            self.output
                .extend_from_slice(&(primary as u32).to_le_bytes());
            self.output.extend_from_slice(&last_col);
        }
    }
}

impl RawEncoder for Encoder {
    fn raw_encode(&mut self, input: &[u8], _output: &mut [u8]) -> Result<RawProgress, Error> {
        self.input.extend_from_slice(input);
        Ok(RawProgress {
            consumed: input.len(),
            written: 0,
            done: false,
        })
    }

    fn raw_finish(&mut self, output: &mut [u8]) -> Result<RawProgress, Error> {
        if !self.finalized {
            self.finalize();
            self.finalized = true;
        }
        let remaining = self.output.len() - self.out_cursor;
        let take = remaining.min(output.len());
        output[..take].copy_from_slice(&self.output[self.out_cursor..self.out_cursor + take]);
        self.out_cursor += take;
        Ok(RawProgress {
            consumed: 0,
            written: take,
            done: self.out_cursor >= self.output.len(),
        })
    }

    fn raw_reset(&mut self) {
        self.input.clear();
        self.output.clear();
        self.out_cursor = 0;
        self.finalized = false;
    }
}

// ─── decoder ─────────────────────────────────────────────────────────────

/// Streaming BWT decoder (inverse of [`Encoder`]).
///
/// Buffers the whole encoded stream, then decodes every block in one pass on
/// `finish` and drains the reconstructed bytes into the caller's output across
/// calls. Output size per block is bounded by that block's declared `len`, so
/// a crafted small input cannot expand without limit.
#[derive(Debug)]
pub struct Decoder {
    input: Vec<u8>,
    output: Vec<u8>,
    out_cursor: usize,
    decoded: bool,
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder {
    /// Construct a fresh decoder.
    pub fn new() -> Self {
        Self {
            input: Vec::new(),
            output: Vec::new(),
            out_cursor: 0,
            decoded: false,
        }
    }

    /// Decode the buffered block stream into `self.output`. Idempotent.
    fn decode_all(&mut self) -> Result<(), Error> {
        if self.decoded {
            return Ok(());
        }
        let buf = &self.input[..];
        let mut pos = 0usize;
        while pos < buf.len() {
            // Each block header is 8 bytes: len (u32-LE) + primary (u32-LE).
            if buf.len() - pos < 8 {
                return Err(Error::UnexpectedEnd);
            }
            let len =
                u32::from_le_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]]) as usize;
            let primary =
                u32::from_le_bytes([buf[pos + 4], buf[pos + 5], buf[pos + 6], buf[pos + 7]])
                    as usize;
            pos += 8;

            // A zero-length block is never emitted by the encoder, and a
            // primary index must address a real row.
            if len == 0 || primary >= len {
                return Err(Error::Corrupt);
            }
            // The last column must be fully present.
            if buf.len() - pos < len {
                return Err(Error::UnexpectedEnd);
            }
            let last_col = &buf[pos..pos + len];
            pos += len;

            transform::inverse(last_col, primary, &mut self.output)?;
        }
        self.decoded = true;
        Ok(())
    }

    fn drain(&mut self, output: &mut [u8]) -> RawProgress {
        let remaining = self.output.len() - self.out_cursor;
        let take = remaining.min(output.len());
        output[..take].copy_from_slice(&self.output[self.out_cursor..self.out_cursor + take]);
        self.out_cursor += take;
        RawProgress {
            consumed: 0,
            written: take,
            done: self.out_cursor >= self.output.len(),
        }
    }
}

impl RawDecoder for Decoder {
    fn raw_decode(&mut self, input: &[u8], output: &mut [u8]) -> Result<RawProgress, Error> {
        if !self.decoded {
            self.input.extend_from_slice(input);
            return Ok(RawProgress {
                consumed: input.len(),
                written: 0,
                done: false,
            });
        }
        let p = self.drain(output);
        Ok(RawProgress {
            consumed: 0,
            written: p.written,
            done: p.done,
        })
    }

    fn raw_finish(&mut self, output: &mut [u8]) -> Result<RawProgress, Error> {
        self.decode_all()?;
        Ok(self.drain(output))
    }

    fn raw_reset(&mut self) {
        self.input.clear();
        self.output.clear();
        self.out_cursor = 0;
        self.decoded = false;
    }
}
