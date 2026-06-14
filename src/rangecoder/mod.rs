//! Adaptive order-0 binary range coder — a standalone entropy codec.
//!
//! Most range/arithmetic coders in this crate are buried inside larger
//! container codecs (LZMA, zstd, arsenic). This module exposes a clean,
//! self-contained one: a carry-less binary range coder driving an
//! order-0 adaptive bit-tree model over bytes. It is the literal-coder
//! core of LZMA, stripped of the LZ layer and any context — useful as a
//! building block, a teaching reference, and a quick entropy stage for
//! skewed byte streams.
//!
//! ## The coder
//!
//! A LZMA-style **binary range coder**: a 32-bit `range` and a 32-bit
//! `low` accumulator (kept in a 64-bit field on the encoder so carries
//! propagate cleanly). Each coded bit narrows `range` by a probability
//! split; whenever `range` drops below `2^24` the coder renormalizes by
//! shifting out one byte and scaling `range` up by 256. The encoder
//! handles carry propagation with the classic cache / cache-size /
//! pending-`0xFF` scheme so a late carry ripples through any run of
//! `0xFF` bytes already staged. The decoder mirrors the renormalization
//! exactly, so encoder and decoder are exact inverses.
//!
//! ## The model
//!
//! Order-0, context-free. Each byte is coded as 8 binary decisions
//! walking a 255-node probability tree (indices `1..=255`, the classic
//! "bit-tree" shape): start at node 1, and for each of the 8 bits
//! (most-significant first) code the bit against `probs[node]`, then
//! descend to `node*2 + bit`. After 8 bits `node` holds `256 + byte`,
//! confirming the walk visited a distinct node per prefix.
//!
//! Probabilities are 11-bit adaptive counters (`kProb = 2048`, the
//! midpoint, is the initial value). After coding a bit they adapt by the
//! standard LZMA rule with a move-shift of 5:
//!
//! * bit 0: `prob += (2048 - prob) >> 5`
//! * bit 1: `prob -= prob >> 5`
//!
//! Both encoder and decoder run the identical update, so their models
//! stay in lock-step without transmitting any model data.
//!
//! ## Byte layout
//!
//! ```text
//! ┌────────────────────────┬───────────────────────────────┐
//! │ u64 length (LE)        │ range-coded payload           │
//! │ 8 bytes                │ variable                      │
//! └────────────────────────┴───────────────────────────────┘
//! ```
//!
//! * **Bytes 0..8** — the original (decoded) length as a little-endian
//!   `u64`. The decoder reads this first so it knows exactly how many
//!   bytes to emit; the payload itself carries no end marker.
//! * **Bytes 8..** — the range-coder output. The encoder flushes 5
//!   trailing bytes at end-of-stream (one cache byte + four to drain
//!   `low`), so a non-empty payload is always ≥ 5 bytes. An empty input
//!   produces just the 8-byte header and no payload.
//!
//! Because the model adapts from a uniform start, the first few bytes of
//! any stream cost close to 8 bits each; the win comes once the counters
//! have skewed. On 64 KiB of zeros the payload collapses by well over
//! 40x; on English text it lands well under 8 bits/byte; on
//! incompressible input it is at most a few bytes larger than the
//! original plus the 8-byte header — round-tripping is always lossless.
//!
//! ## Errors
//!
//! The decoder never panics on malformed input. A header shorter than 8
//! bytes, or a declared length the payload cannot satisfy, yields
//! [`Error::UnexpectedEnd`]; a length so large it could not have been
//! produced by this coder yields [`Error::Corrupt`].

#![cfg_attr(docsrs, doc(cfg(feature = "rangecoder")))]

extern crate alloc;
use alloc::vec::Vec;

use crate::error::Error;
use crate::traits::{Algorithm, RawDecoder, RawEncoder, RawProgress};

/// Number of probability counters in the bit-tree: indices `1..=255` are
/// used (index 0 is dead), one per internal node of the 8-level tree.
const TREE_NODES: usize = 256;
/// Initial (and midpoint) probability for an 11-bit counter: kProb/2 = 1024.
const PROB_INIT: u16 = 1 << 10;
/// Total probability scale exponent (kProb = 2048). Splits use the top
/// 11 bits of range.
const PROB_BITS: u32 = 11;
/// Adaptation move-shift.
const MOVE_BITS: u32 = 5;
/// Renormalization threshold: keep `range >= 2^24`.
const TOP: u32 = 1 << 24;

/// Zero-sized marker type implementing [`Algorithm`] for the range coder.
#[derive(Debug, Clone, Copy, Default)]
pub struct RangeCoder;

impl Algorithm for RangeCoder {
    const NAME: &'static str = "range";
    type Encoder = Encoder;
    type Decoder = Decoder;
    type EncoderConfig = ();
    type DecoderConfig = ();
    fn encoder_with(_: ()) -> Encoder {
        Encoder::new()
    }
    fn decoder_with(_: ()) -> Decoder {
        Decoder::new()
    }
}

// ─── adaptive bit-tree model ──────────────────────────────────────────────

/// The order-0 model: a flat array of 11-bit probability counters indexed
/// by bit-tree node. Shared (by identical construction + update) between
/// encoder and decoder.
#[derive(Debug, Clone)]
struct Model {
    probs: [u16; TREE_NODES],
}

impl Model {
    fn new() -> Self {
        Self {
            probs: [PROB_INIT; TREE_NODES],
        }
    }
}

#[inline]
fn adapt(prob: &mut u16, bit: u32) {
    if bit == 0 {
        *prob += ((1u16 << PROB_BITS) - *prob) >> MOVE_BITS;
    } else {
        *prob -= *prob >> MOVE_BITS;
    }
}

// ─── encoder ──────────────────────────────────────────────────────────────

/// Streaming adaptive order-0 range encoder.
///
/// Buffers the entire input (the framing needs the original length up front
/// for the header, and the range coder produces output only at flush), then
/// emits the framed stream on [`finish`](crate::Encoder::finish). This is
/// the same buffer-then-transform shape used by the block codecs in this
/// crate.
#[derive(Debug)]
pub struct Encoder {
    input: Vec<u8>,
    /// Encoded stream (header + payload), produced lazily on first finish.
    out: Vec<u8>,
    head: usize,
    finished: bool,
}

impl Encoder {
    /// Construct a fresh encoder.
    pub fn new() -> Self {
        Self {
            input: Vec::new(),
            out: Vec::new(),
            head: 0,
            finished: false,
        }
    }

    /// Range-encode `self.input` into `self.out` (header + payload).
    fn encode_all(&mut self) {
        self.out.clear();
        self.out
            .extend_from_slice(&(self.input.len() as u64).to_le_bytes());

        if self.input.is_empty() {
            return;
        }

        let mut rc = RangeEncoder::new();
        let mut model = Model::new();
        // Take the input out so we can borrow `self.out` mutably while
        // reading the bytes; swap a placeholder in to avoid cloning.
        let input = core::mem::take(&mut self.input);
        for &byte in &input {
            // Bit-tree walk, MSB first.
            let mut node = 1usize;
            for i in (0..8).rev() {
                let bit = ((byte >> i) & 1) as u32;
                let prob = &mut model.probs[node];
                rc.encode_bit(&mut self.out, prob, bit);
                node = (node << 1) | (bit as usize);
            }
        }
        rc.flush(&mut self.out);
        self.input = input;
    }

    fn drain(&mut self, output: &mut [u8]) -> usize {
        let avail = self.out.len() - self.head;
        let n = avail.min(output.len());
        output[..n].copy_from_slice(&self.out[self.head..self.head + n]);
        self.head += n;
        n
    }
}

impl Default for Encoder {
    fn default() -> Self {
        Self::new()
    }
}

impl RawEncoder for Encoder {
    fn raw_encode(&mut self, input: &[u8], _output: &mut [u8]) -> Result<RawProgress, Error> {
        // Pure buffering — no output until finish.
        self.input.extend_from_slice(input);
        Ok(RawProgress {
            consumed: input.len(),
            written: 0,
            done: false,
        })
    }

    fn raw_finish(&mut self, output: &mut [u8]) -> Result<RawProgress, Error> {
        if !self.finished {
            self.encode_all();
            self.finished = true;
        }
        let written = self.drain(output);
        let done = self.head >= self.out.len();
        Ok(RawProgress {
            consumed: 0,
            written,
            done,
        })
    }

    fn raw_reset(&mut self) {
        self.input.clear();
        self.out.clear();
        self.head = 0;
        self.finished = false;
    }
}

/// The carry-handling binary range encoder.
struct RangeEncoder {
    low: u64,
    range: u32,
    cache: u8,
    cache_size: u64,
}

impl RangeEncoder {
    fn new() -> Self {
        // cache_size starts at 1: the first shift_low produces a leading
        // cache byte that is always 0 (LZMA's well-known leading zero),
        // which the decoder reads and discards on init.
        Self {
            low: 0,
            range: 0xFFFF_FFFF,
            cache: 0,
            cache_size: 1,
        }
    }

    #[inline]
    fn encode_bit(&mut self, out: &mut Vec<u8>, prob: &mut u16, bit: u32) {
        // bound = (range >> 11) * prob  — the size of the "bit 0" subrange.
        let bound = (self.range >> PROB_BITS) * (*prob as u32);
        if bit == 0 {
            self.range = bound;
        } else {
            self.low += bound as u64;
            self.range -= bound;
        }
        adapt(prob, bit);
        while self.range < TOP {
            self.range <<= 8;
            self.shift_low(out);
        }
    }

    #[inline]
    fn shift_low(&mut self, out: &mut Vec<u8>) {
        // If the top byte of low is not 0xFF (or a carry is pending),
        // flush the cached byte plus any staged 0xFF run, adjusted by the
        // carry bit (low >> 32).
        if self.low < 0xFF00_0000 || self.low > 0xFFFF_FFFF {
            let carry = (self.low >> 32) as u8;
            let mut temp = self.cache;
            loop {
                out.push(temp.wrapping_add(carry));
                temp = 0xFF;
                self.cache_size -= 1;
                if self.cache_size == 0 {
                    break;
                }
            }
            self.cache = (self.low >> 24) as u8;
        }
        self.cache_size += 1;
        self.low = (self.low << 8) & 0xFFFF_FFFF;
    }

    fn flush(&mut self, out: &mut Vec<u8>) {
        // Drain the 32-bit low accumulator: 5 shift_low calls move every
        // byte (plus the cache) out to the stream.
        for _ in 0..5 {
            self.shift_low(out);
        }
    }
}

// ─── decoder ──────────────────────────────────────────────────────────────

/// Streaming adaptive order-0 range decoder.
///
/// Buffers the entire compressed stream, then decodes the framed payload on
/// [`finish`](crate::Decoder::finish). Truncated or malformed input is
/// reported as an [`Error`] — the decoder never panics.
#[derive(Debug)]
pub struct Decoder {
    input: Vec<u8>,
    out: Vec<u8>,
    head: usize,
    finished: bool,
}

impl Decoder {
    /// Construct a fresh decoder.
    pub fn new() -> Self {
        Self {
            input: Vec::new(),
            out: Vec::new(),
            head: 0,
            finished: false,
        }
    }

    fn decode_all(&mut self) -> Result<(), Error> {
        self.out.clear();
        if self.input.len() < 8 {
            // A valid stream always carries the 8-byte length header.
            // An empty stream (0 bytes) is also too short — there is no
            // unambiguous "empty" encoding without the header.
            return Err(Error::UnexpectedEnd);
        }
        let mut len_bytes = [0u8; 8];
        len_bytes.copy_from_slice(&self.input[..8]);
        let out_len = u64::from_le_bytes(len_bytes);

        if out_len == 0 {
            // Header says zero bytes — payload must be empty.
            if self.input.len() != 8 {
                return Err(Error::Corrupt);
            }
            return Ok(());
        }

        // Guard against an absurd declared length that no real payload of
        // this size could produce (decompression-bomb / corruption guard).
        // Each output byte needs at least ~1 bit; the payload is
        // `input.len() - 8` bytes. Allow generous slack (256x) before
        // rejecting, since low-entropy data compresses hugely.
        let payload_len = self.input.len() - 8;
        let max_plausible = (payload_len as u64)
            .saturating_mul(256)
            .saturating_add(1024);
        if out_len > max_plausible {
            return Err(Error::Corrupt);
        }
        let out_len = out_len as usize;
        self.out.reserve(out_len);

        let payload = core::mem::take(&mut self.input);
        let result = (|| {
            let mut rc = RangeDecoder::new(&payload[8..])?;
            let mut model = Model::new();
            for _ in 0..out_len {
                let mut node = 1usize;
                for _ in 0..8 {
                    let prob = &mut model.probs[node];
                    let bit = rc.decode_bit(prob)?;
                    node = (node << 1) | (bit as usize);
                }
                // node now holds 256 + byte.
                self.out.push((node & 0xFF) as u8);
            }
            Ok(())
        })();
        self.input = payload;
        result
    }

    fn drain(&mut self, output: &mut [u8]) -> usize {
        let avail = self.out.len() - self.head;
        let n = avail.min(output.len());
        output[..n].copy_from_slice(&self.out[self.head..self.head + n]);
        self.head += n;
        n
    }
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

impl RawDecoder for Decoder {
    fn raw_decode(&mut self, input: &[u8], _output: &mut [u8]) -> Result<RawProgress, Error> {
        // Pure buffering — output is produced on finish.
        self.input.extend_from_slice(input);
        Ok(RawProgress {
            consumed: input.len(),
            written: 0,
            done: false,
        })
    }

    fn raw_finish(&mut self, output: &mut [u8]) -> Result<RawProgress, Error> {
        if !self.finished {
            self.decode_all()?;
            self.finished = true;
        }
        let written = self.drain(output);
        let done = self.head >= self.out.len();
        Ok(RawProgress {
            consumed: 0,
            written,
            done,
        })
    }

    fn raw_reset(&mut self) {
        self.input.clear();
        self.out.clear();
        self.head = 0;
        self.finished = false;
    }
}

/// The binary range decoder, mirror of [`RangeEncoder`].
struct RangeDecoder<'a> {
    payload: &'a [u8],
    pos: usize,
    range: u32,
    code: u32,
    /// Set once a renormalization tried to read past the end of the
    /// payload. A correct, complete stream never sets this; a stream
    /// truncated relative to its declared length does.
    overran: bool,
}

impl<'a> RangeDecoder<'a> {
    fn new(payload: &'a [u8]) -> Result<Self, Error> {
        // The encoder's first shift_low emits a leading 0x00 cache byte;
        // the decoder reads (and ignores) it, then primes `code` with the
        // next 4 bytes. So a non-empty payload is always at least 5 bytes.
        if payload.len() < 5 {
            return Err(Error::UnexpectedEnd);
        }
        // First byte is the leading zero — skip it.
        let mut d = Self {
            payload,
            pos: 1,
            range: 0xFFFF_FFFF,
            code: 0,
            overran: false,
        };
        for _ in 0..4 {
            d.code = (d.code << 8) | d.next_byte() as u32;
        }
        Ok(d)
    }

    #[inline]
    fn next_byte(&mut self) -> u8 {
        // Past-end reads return 0 and flag `overran`. A correct, complete
        // stream never over-reads (the encoder's 5 flush bytes cover every
        // renormalization the decoder performs). A stream truncated
        // relative to its declared length will over-read, which the caller
        // turns into `Error::UnexpectedEnd`. Bounds are always respected
        // (no panic, no out-of-range index).
        match self.payload.get(self.pos) {
            Some(&b) => {
                self.pos += 1;
                b
            }
            None => {
                self.pos += 1;
                self.overran = true;
                0
            }
        }
    }

    #[inline]
    fn decode_bit(&mut self, prob: &mut u16) -> Result<u32, Error> {
        let bound = (self.range >> PROB_BITS) * (*prob as u32);
        let bit;
        if self.code < bound {
            self.range = bound;
            bit = 0;
        } else {
            self.code -= bound;
            self.range -= bound;
            bit = 1;
        }
        adapt(prob, bit);
        while self.range < TOP {
            self.range <<= 8;
            self.code = (self.code << 8) | self.next_byte() as u32;
        }
        if self.overran {
            return Err(Error::UnexpectedEnd);
        }
        Ok(bit)
    }
}

#[cfg(test)]
mod tests;
