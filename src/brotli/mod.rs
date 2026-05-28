//! Brotli (RFC 7932) — partial implementation.
//!
//! Reference: <https://datatracker.ietf.org/doc/html/rfc7932>.
//!
//! # Scope of this build
//!
//! Brotli is a research-grade format whose full decoder needs a
//! ~170 KiB built-in static dictionary, complex Huffman codes, context
//! modelling and distance tables. This build implements **only the
//! uncompressed subset**:
//!
//! - **Encoder**: emits a stream header followed by one or more
//!   *uncompressed* meta-blocks plus a final empty meta-block. The
//!   output is a valid Brotli stream (the reference `brotli -d` accepts
//!   it), but it is literally larger than the input — uncompressed-only
//!   is a correctness-first fallback, not a compression strategy.
//! - **Decoder**: parses the stream header and walks the meta-block
//!   chain; uncompressed meta-blocks, metadata meta-blocks (skipped),
//!   and the empty last meta-block are fully decoded. Any meta-block
//!   whose `ISUNCOMPRESSED` bit is `0` (i.e. a real compressed
//!   meta-block produced by another encoder) returns
//!   [`Error::Unsupported`]. A non-empty last meta-block also returns
//!   `Unsupported` — per §9.2 the final meta-block can only be empty or
//!   compressed, never uncompressed, so we can never produce one with
//!   this encoder either.
//!
//! The bit stream is LSB-first within each byte, identical to deflate.
//! Because the shared `bits` module in this crate is gated to the
//! deflate-family features, this file ships its own minimal bit reader /
//! bit writer rather than reaching for it.

use alloc::vec::Vec;

use crate::error::Error;
use crate::traits::{Algorithm, Decoder as DecoderTrait, Encoder as EncoderTrait, Progress};

/// Zero-sized marker type implementing [`Algorithm`] for Brotli.
#[derive(Debug, Clone, Copy, Default)]
pub struct Brotli;

impl Algorithm for Brotli {
    const NAME: &'static str = "brotli";
    type Encoder = Encoder;
    type Decoder = Decoder;
    fn encoder() -> Encoder {
        Encoder::new()
    }
    fn decoder() -> Decoder {
        Decoder::new()
    }
}

// ─── shared bit primitives ───────────────────────────────────────────────
//
// Both directions are LSB-first. The buffered bit reader holds up to 56
// pending bits in a u64 accumulator; the bit writer drains every whole
// byte into its output sink as bits are pushed in.

#[derive(Debug, Clone, Copy, Default)]
struct BitReader {
    acc: u64,
    nbits: u32,
}

impl BitReader {
    const fn new() -> Self {
        Self { acc: 0, nbits: 0 }
    }
    fn feed(&mut self, byte: u8) {
        // Caller must have ensured at most 56 bits are buffered.
        self.acc |= (byte as u64) << self.nbits;
        self.nbits += 8;
    }
    const fn bits_available(&self) -> u32 {
        self.nbits
    }
    fn peek(&self, n: u32) -> u64 {
        if n == 0 {
            0
        } else {
            self.acc & ((1u64 << n) - 1)
        }
    }
    fn drop_bits(&mut self, n: u32) {
        self.acc >>= n;
        self.nbits -= n;
    }
    fn align_to_byte(&mut self) {
        let drop = self.nbits & 7;
        self.drop_bits(drop);
    }
    fn reset(&mut self) {
        self.acc = 0;
        self.nbits = 0;
    }
}

/// LSB-first bit writer that accumulates into a u64 and drains whole
/// bytes into a `Vec<u8>`. Used only by the encoder.
#[derive(Debug, Clone, Default)]
struct BitWriter {
    acc: u64,
    nbits: u32,
}

impl BitWriter {
    const fn new() -> Self {
        Self { acc: 0, nbits: 0 }
    }
    /// Append `n` LSB-first bits of `value`. Requires `n <= 32`.
    fn write(&mut self, value: u32, n: u32, out: &mut Vec<u8>) {
        debug_assert!(n <= 32);
        let masked: u64 = if n == 0 {
            0
        } else {
            (value as u64) & ((1u64 << n) - 1)
        };
        self.acc |= masked << self.nbits;
        self.nbits += n;
        while self.nbits >= 8 {
            out.push(self.acc as u8);
            self.acc >>= 8;
            self.nbits -= 8;
        }
    }
    /// Pad with zero bits to the next byte boundary, flushing the final
    /// byte if any bits are pending.
    fn align(&mut self, out: &mut Vec<u8>) {
        if self.nbits > 0 {
            out.push(self.acc as u8);
            self.acc = 0;
            self.nbits = 0;
        }
    }
    const fn pending_bits(&self) -> u32 {
        self.nbits
    }
}

// ─── encoder ────────────────────────────────────────────────────────────
//
// Wire format produced:
//
//   WBITS = 16            (1 bit  = 0)
//   [meta-block]*         (zero or more non-final uncompressed meta-blocks)
//   ISLAST=1, ISLASTEMPTY=1, pad to byte
//
// Each non-final uncompressed meta-block:
//
//   ISLAST           = 0  (1 bit)
//   MNIBBLES         = 0  (2 bits, encodes 4 nibbles -> 16-bit MLEN-1)
//   MLEN-1 in 16 bits     (LSB-first; MLEN in 1..=65536)
//   ISUNCOMPRESSED   = 1  (1 bit)
//   pad to byte boundary
//   MLEN raw payload bytes
//
// Input is buffered up to MAX_BLOCK bytes per meta-block. `encode` only
// emits whole meta-blocks; `finish` flushes the partial-block tail and
// writes the terminator. Note: the spec forbids an uncompressed
// *final* meta-block, so the terminator is always the empty-last form.

/// Largest uncompressed meta-block this encoder will emit. The format
/// allows up to 16 MiB (24-nibble MLEN), but capping at 64 KiB keeps
/// the MLEN field a fixed 4 nibbles and trims the per-block transient
/// buffer.
const MAX_BLOCK: usize = 1 << 16; // 65_536

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EncStage {
    /// About to write WBITS (the 1-bit stream header).
    NeedHeader,
    /// Header written; buffering payload for the next meta-block.
    Buffering,
    /// `finish` was called and the terminator + tail are queued in `out`.
    Draining,
    /// `Draining` finished; encoder must be `reset` before reuse.
    Done,
}

#[derive(Debug, Clone)]
pub struct Encoder {
    /// Pending input bytes that haven't yet been wrapped into a meta-block.
    pending: Vec<u8>,
    /// Bytes ready for the caller to copy out.
    out: Vec<u8>,
    /// How many bytes of `out` have already been delivered.
    out_pos: usize,
    /// Bit-level writer feeding `out`. Only ever non-byte-aligned between
    /// the WBITS header and a meta-block's raw-payload start; meta-block
    /// bodies are byte-aligned before raw bytes are concatenated.
    bw: BitWriter,
    stage: EncStage,
}

impl Encoder {
    pub fn new() -> Self {
        Self {
            pending: Vec::new(),
            out: Vec::new(),
            out_pos: 0,
            bw: BitWriter::new(),
            stage: EncStage::NeedHeader,
        }
    }

    /// Drop everything from `out` that the caller has already received,
    /// so the buffer doesn't grow unboundedly across streaming calls.
    fn compact_out(&mut self) {
        if self.out_pos == 0 {
            return;
        }
        if self.out_pos >= self.out.len() {
            self.out.clear();
        } else {
            self.out.drain(..self.out_pos);
        }
        self.out_pos = 0;
    }

    /// Copy as much of `self.out[self.out_pos..]` into `dst` as fits.
    fn drain_out_into(&mut self, dst: &mut [u8]) -> usize {
        let avail = self.out.len() - self.out_pos;
        let n = avail.min(dst.len());
        if n > 0 {
            dst[..n].copy_from_slice(&self.out[self.out_pos..self.out_pos + n]);
            self.out_pos += n;
        }
        n
    }

    /// Write the 1-bit WBITS=16 header. Idempotent: only runs when stage
    /// is `NeedHeader`.
    fn ensure_header(&mut self) {
        if self.stage == EncStage::NeedHeader {
            // Single 0 bit selects WBITS=16. No byte alignment yet —
            // the first meta-block's bits will pack right next to it.
            self.bw.write(0, 1, &mut self.out);
            self.stage = EncStage::Buffering;
        }
    }

    /// Emit one non-final uncompressed meta-block carrying exactly the
    /// first `mlen` bytes of `self.pending`. Caller ensures
    /// `1 <= mlen <= MAX_BLOCK` and `mlen <= self.pending.len()`.
    fn emit_uncompressed_block(&mut self, mlen: usize) {
        debug_assert!((1..=MAX_BLOCK).contains(&mlen));
        debug_assert!(mlen <= self.pending.len());
        // ISLAST = 0
        self.bw.write(0, 1, &mut self.out);
        // MNIBBLES = 0 (encodes 4 nibbles)
        self.bw.write(0, 2, &mut self.out);
        // MLEN - 1 in 4 nibbles = 16 bits, LSB-first
        let mlen_m1 = (mlen - 1) as u32;
        self.bw.write(mlen_m1, 16, &mut self.out);
        // ISUNCOMPRESSED = 1 (present because ISLAST = 0)
        self.bw.write(1, 1, &mut self.out);
        // Pad to next byte boundary before raw bytes.
        self.bw.align(&mut self.out);
        // Raw payload.
        self.out.extend_from_slice(&self.pending[..mlen]);
        self.pending.drain(..mlen);
    }

    /// Drain `self.pending` of every full-sized meta-block.
    fn flush_full_blocks(&mut self) {
        while self.pending.len() >= MAX_BLOCK {
            self.emit_uncompressed_block(MAX_BLOCK);
        }
    }

    /// Append the terminator. If `pending` is non-empty, first emit it
    /// as one final non-last uncompressed meta-block (always non-last
    /// since the spec forbids uncompressed final meta-blocks).
    fn emit_terminator(&mut self) {
        if !self.pending.is_empty() {
            let n = self.pending.len();
            // `flush_full_blocks` already drained anything >= MAX_BLOCK.
            debug_assert!(n < MAX_BLOCK);
            self.emit_uncompressed_block(n);
        }
        // ISLAST = 1
        self.bw.write(1, 1, &mut self.out);
        // ISLASTEMPTY = 1
        self.bw.write(1, 1, &mut self.out);
        // Flush trailing bits to a byte boundary.
        self.bw.align(&mut self.out);
        debug_assert_eq!(self.bw.pending_bits(), 0);
    }
}

impl Default for Encoder {
    fn default() -> Self {
        Self::new()
    }
}

impl EncoderTrait for Encoder {
    fn encode(&mut self, input: &[u8], output: &mut [u8]) -> Result<Progress, Error> {
        if self.stage == EncStage::Done {
            return Err(Error::Corrupt);
        }

        // Hand back anything still queued from a previous call before we
        // ingest more input. Keeps `self.out` from growing unboundedly
        // when the caller drives us with a tiny output buffer.
        let mut written = 0usize;
        if self.out_pos < self.out.len() {
            written += self.drain_out_into(&mut output[written..]);
            if written == output.len() {
                return Ok(Progress {
                    consumed: 0,
                    written,
                    done: false,
                });
            }
        }
        self.compact_out();

        self.ensure_header();

        // Ingest input in one shot. `pending` is a Vec and growing it is
        // cheap; consuming all input on every call keeps streaming
        // semantics simple.
        self.pending.extend_from_slice(input);
        let consumed = input.len();

        // Emit any full-sized meta-blocks now buffered.
        self.flush_full_blocks();

        // Drain into the caller's output buffer.
        written += self.drain_out_into(&mut output[written..]);
        self.compact_out();

        Ok(Progress {
            consumed,
            written,
            done: false,
        })
    }

    fn finish(&mut self, output: &mut [u8]) -> Result<Progress, Error> {
        if self.stage == EncStage::Done {
            return Ok(Progress {
                consumed: 0,
                written: 0,
                done: true,
            });
        }

        // Drain any leftover bytes from a previous call before we add
        // more (otherwise we'd queue terminator bytes ahead of an
        // already-queued payload tail).
        let mut written = 0usize;
        if self.out_pos < self.out.len() {
            written += self.drain_out_into(&mut output[written..]);
            if written == output.len() {
                return Ok(Progress {
                    consumed: 0,
                    written,
                    done: false,
                });
            }
        }
        self.compact_out();

        // Produce the rest of the stream the first time finish is called.
        if self.stage != EncStage::Draining {
            self.ensure_header();
            // Push out any full blocks that built up since the last
            // encode/finish (encode flushes them already, but a caller
            // who only ever calls finish wouldn't have).
            self.flush_full_blocks();
            self.emit_terminator();
            self.stage = EncStage::Draining;
        }

        written += self.drain_out_into(&mut output[written..]);
        self.compact_out();

        let done = self.out_pos == self.out.len();
        if done {
            self.stage = EncStage::Done;
        }
        Ok(Progress {
            consumed: 0,
            written,
            done,
        })
    }

    fn reset(&mut self) {
        self.pending.clear();
        self.out.clear();
        self.out_pos = 0;
        self.bw = BitWriter::new();
        self.stage = EncStage::NeedHeader;
    }
}

// ─── decoder ────────────────────────────────────────────────────────────
//
// State machine walks the meta-block chain. We hold a bit-reader that
// the per-call `refill` loop tops up from the caller's input slice.
// Each state arm peeks the bits it needs; if there aren't enough it
// just returns to the outer loop, which decides whether to refill or
// stop.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DecState {
    /// Read the variable-length WBITS field (1..=7 bits).
    Header,
    /// Read the 1-bit ISLAST of the next meta-block.
    MetaIsLast,
    /// ISLAST=1 was just read; read the 1-bit ISLASTEMPTY.
    MetaIsLastEmpty,
    /// Read MNIBBLES (2 bits). `is_last` carries the just-read ISLAST.
    MetaNibbles { is_last: bool },
    /// Reading MLEN-1, accumulating nibble-by-nibble.
    MetaMlen {
        is_last: bool,
        nibbles_left: u8,
        nibbles_total: u8,
        acc: u32,
    },
    /// MLEN known. Read ISUNCOMPRESSED (only on non-last blocks).
    MetaIsUncompressed { mlen: u32 },
    /// Copying `remaining` raw payload bytes out.
    Uncompressed { remaining: u32 },
    /// MNIBBLES=3 metadata path: read the 1-bit reserved (must be 0).
    MetaReserved { is_last: bool },
    /// Read MSKIPBYTES (2 bits).
    MetaSkipBytes { is_last: bool },
    /// Reading MSKIPLEN-1 byte-by-byte (only when MSKIPBYTES > 0).
    MetaSkipLen {
        is_last: bool,
        bytes_left: u8,
        bytes_total: u8,
        acc: u32,
    },
    /// Discarding `remaining` metadata bytes. Not emitted.
    Metadata { is_last: bool, remaining: u32 },
    /// Stream is fully consumed. `finish` returns `done = true`.
    Done,
}

#[derive(Debug)]
pub struct Decoder {
    br: BitReader,
    state: DecState,
    poisoned: bool,
}

impl Decoder {
    pub fn new() -> Self {
        Self {
            br: BitReader::new(),
            state: DecState::Header,
            poisoned: false,
        }
    }

    /// Top up the bit-reader from the caller's input slice.
    fn refill(&mut self, input: &[u8], consumed: &mut usize) {
        while *consumed < input.len() && self.br.bits_available() <= 56 {
            self.br.feed(input[*consumed]);
            *consumed += 1;
        }
    }

    /// Poison and return the given error.
    fn poison(&mut self, e: Error) -> Error {
        self.poisoned = true;
        e
    }

    /// Read the variable-length WBITS field per §9.1.
    ///
    /// Returns `Ok(true)` when a complete value was consumed (we ignore
    /// the numeric window size — uncompressed-only decoding never
    /// references a sliding window), `Ok(false)` when more bits are
    /// needed, or `Err(_)` on a structurally invalid encoding (the
    /// large-window flag is rejected as `Unsupported`).
    fn read_wbits(&mut self) -> Result<bool, Error> {
        if self.br.bits_available() < 1 {
            return Ok(false);
        }
        let first = self.br.peek(1) as u8;
        if first == 0 {
            self.br.drop_bits(1);
            return Ok(true);
        }
        // First bit is 1: need at least 4 bits total.
        if self.br.bits_available() < 4 {
            return Ok(false);
        }
        let n = ((self.br.peek(4) >> 1) & 0x7) as u8;
        if n != 0 {
            // window_bits = 17 + n  ->  18..=24. Discarded.
            self.br.drop_bits(4);
            return Ok(true);
        }
        // First bit = 1, next 3 = 0: need 3 more bits.
        if self.br.bits_available() < 7 {
            return Ok(false);
        }
        let m = ((self.br.peek(7) >> 4) & 0x7) as u8;
        self.br.drop_bits(7);
        match m {
            0 => Ok(true),                // window_bits = 17
            1 => Err(Error::Unsupported), // large-window flag
            _ => Ok(true),                // 2..=7 -> window_bits = 8+m -> 10..=15
        }
    }

    /// Advance the state machine by one step. Returns `Ok(true)` if
    /// state changed or bytes moved, `Ok(false)` if we couldn't make
    /// any progress (need more input or more output room).
    fn step(
        &mut self,
        input: &[u8],
        consumed: &mut usize,
        output: &mut [u8],
        written: &mut usize,
    ) -> Result<bool, Error> {
        let pre_state = self.state;
        let pre_bits = self.br.bits_available();
        let pre_consumed = *consumed;
        let pre_written = *written;

        match self.state {
            DecState::Done => return Ok(false),

            DecState::Header => match self.read_wbits() {
                Ok(true) => self.state = DecState::MetaIsLast,
                Ok(false) => {}
                Err(e) => return Err(self.poison(e)),
            },

            DecState::MetaIsLast => {
                if self.br.bits_available() >= 1 {
                    let is_last = self.br.peek(1) != 0;
                    self.br.drop_bits(1);
                    self.state = if is_last {
                        DecState::MetaIsLastEmpty
                    } else {
                        DecState::MetaNibbles { is_last: false }
                    };
                }
            }

            DecState::MetaIsLastEmpty => {
                if self.br.bits_available() >= 1 {
                    let is_empty = self.br.peek(1) != 0;
                    self.br.drop_bits(1);
                    self.state = if is_empty {
                        // §9.2 says any trailing bits in the final byte
                        // must be zero. We don't enforce that — it's a
                        // soft requirement and the stream ends here
                        // either way.
                        DecState::Done
                    } else {
                        DecState::MetaNibbles { is_last: true }
                    };
                }
            }

            DecState::MetaNibbles { is_last } => {
                if self.br.bits_available() >= 2 {
                    let v = self.br.peek(2) as u8;
                    self.br.drop_bits(2);
                    // 0 -> 4 nibbles, 1 -> 5, 2 -> 6, 3 -> metadata
                    self.state = if v == 3 {
                        DecState::MetaReserved { is_last }
                    } else {
                        let nibbles = v + 4;
                        DecState::MetaMlen {
                            is_last,
                            nibbles_left: nibbles,
                            nibbles_total: nibbles,
                            acc: 0,
                        }
                    };
                }
            }

            DecState::MetaMlen {
                is_last,
                mut nibbles_left,
                nibbles_total,
                mut acc,
            } => {
                while nibbles_left > 0 && self.br.bits_available() >= 4 {
                    let nb = self.br.peek(4) as u32;
                    self.br.drop_bits(4);
                    let pos = (nibbles_total - nibbles_left) as u32;
                    acc |= nb << (pos * 4);
                    nibbles_left -= 1;
                }
                if nibbles_left == 0 {
                    if nibbles_total > 4 {
                        let top_shift = (nibbles_total as u32 - 1) * 4;
                        if ((acc >> top_shift) & 0xF) == 0 {
                            return Err(self.poison(Error::Corrupt));
                        }
                    }
                    let mlen = acc + 1;
                    if is_last {
                        // Non-empty final meta-block: spec says it must
                        // be compressed; we can't decompress.
                        return Err(self.poison(Error::Unsupported));
                    }
                    self.state = DecState::MetaIsUncompressed { mlen };
                } else {
                    self.state = DecState::MetaMlen {
                        is_last,
                        nibbles_left,
                        nibbles_total,
                        acc,
                    };
                }
            }

            DecState::MetaIsUncompressed { mlen } => {
                if self.br.bits_available() >= 1 {
                    let is_unc = self.br.peek(1) != 0;
                    self.br.drop_bits(1);
                    if !is_unc {
                        // Compressed meta-block — not supported.
                        return Err(self.poison(Error::Unsupported));
                    }
                    // Pad to byte boundary before raw payload.
                    self.br.align_to_byte();
                    self.state = DecState::Uncompressed { remaining: mlen };
                }
            }

            DecState::Uncompressed { mut remaining } => {
                // Drain leftover bytes still in the bit-reader's
                // accumulator before pulling fresh ones straight from
                // `input`. Both loops together guarantee we emit either
                // until `remaining == 0`, or until output is full, or
                // until input is exhausted.
                while remaining > 0 && self.br.bits_available() >= 8 && *written < output.len() {
                    let b = self.br.peek(8) as u8;
                    self.br.drop_bits(8);
                    output[*written] = b;
                    *written += 1;
                    remaining -= 1;
                }
                while remaining > 0 && *consumed < input.len() && *written < output.len() {
                    output[*written] = input[*consumed];
                    *consumed += 1;
                    *written += 1;
                    remaining -= 1;
                }
                self.state = if remaining == 0 {
                    DecState::MetaIsLast
                } else {
                    DecState::Uncompressed { remaining }
                };
            }

            DecState::MetaReserved { is_last } => {
                if self.br.bits_available() >= 1 {
                    let r = self.br.peek(1);
                    self.br.drop_bits(1);
                    if r != 0 {
                        return Err(self.poison(Error::Corrupt));
                    }
                    self.state = DecState::MetaSkipBytes { is_last };
                }
            }

            DecState::MetaSkipBytes { is_last } => {
                if self.br.bits_available() >= 2 {
                    let sb = self.br.peek(2) as u8;
                    self.br.drop_bits(2);
                    if sb == 0 {
                        // Empty metadata block. Pad to byte boundary
                        // (no payload follows) and loop.
                        self.br.align_to_byte();
                        self.state = if is_last {
                            DecState::Done
                        } else {
                            DecState::MetaIsLast
                        };
                    } else {
                        self.state = DecState::MetaSkipLen {
                            is_last,
                            bytes_left: sb,
                            bytes_total: sb,
                            acc: 0,
                        };
                    }
                }
            }

            DecState::MetaSkipLen {
                is_last,
                mut bytes_left,
                bytes_total,
                mut acc,
            } => {
                while bytes_left > 0 && self.br.bits_available() >= 8 {
                    let b = self.br.peek(8) as u32;
                    self.br.drop_bits(8);
                    let pos = (bytes_total - bytes_left) as u32;
                    acc |= b << (pos * 8);
                    bytes_left -= 1;
                }
                if bytes_left == 0 {
                    if bytes_total > 1 {
                        let top_shift = (bytes_total as u32 - 1) * 8;
                        if ((acc >> top_shift) & 0xFF) == 0 {
                            return Err(self.poison(Error::Corrupt));
                        }
                    }
                    let mskiplen = acc + 1;
                    self.br.align_to_byte();
                    self.state = DecState::Metadata {
                        is_last,
                        remaining: mskiplen,
                    };
                } else {
                    self.state = DecState::MetaSkipLen {
                        is_last,
                        bytes_left,
                        bytes_total,
                        acc,
                    };
                }
            }

            DecState::Metadata {
                is_last,
                mut remaining,
            } => {
                // Metadata bytes are not emitted. They're after byte
                // alignment so we just consume them from the bit reader
                // first, then from raw input.
                while remaining > 0 && self.br.bits_available() >= 8 {
                    self.br.drop_bits(8);
                    remaining -= 1;
                }
                while remaining > 0 && *consumed < input.len() {
                    *consumed += 1;
                    remaining -= 1;
                }
                self.state = if remaining == 0 {
                    if is_last {
                        DecState::Done
                    } else {
                        DecState::MetaIsLast
                    }
                } else {
                    DecState::Metadata { is_last, remaining }
                };
            }
        }

        // Progress detection: state changed, bits were consumed from
        // the reader, or bytes moved in/out.
        let made_progress = self.state != pre_state
            || self.br.bits_available() != pre_bits
            || *consumed != pre_consumed
            || *written != pre_written;
        Ok(made_progress)
    }
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

impl DecoderTrait for Decoder {
    fn decode(&mut self, input: &[u8], output: &mut [u8]) -> Result<Progress, Error> {
        if self.poisoned {
            return Err(Error::Corrupt);
        }
        let mut consumed = 0usize;
        let mut written = 0usize;

        loop {
            if matches!(self.state, DecState::Done) {
                break;
            }
            // Top up the bit reader at the start of every iteration so
            // arms that need 2..7 bits don't stall just because they
            // landed on a byte boundary.
            self.refill(input, &mut consumed);

            let progressed = self.step(input, &mut consumed, output, &mut written)?;
            if !progressed {
                // Either the output filled, the input exhausted, or
                // both — the caller must drain or supply more bytes.
                break;
            }
        }

        Ok(Progress {
            consumed,
            written,
            done: false,
        })
    }

    fn finish(&mut self, _output: &mut [u8]) -> Result<Progress, Error> {
        if self.poisoned {
            return Err(Error::Corrupt);
        }
        match self.state {
            DecState::Done => Ok(Progress {
                consumed: 0,
                written: 0,
                done: true,
            }),
            _ => Err(self.poison(Error::UnexpectedEnd)),
        }
    }

    fn reset(&mut self) {
        self.br.reset();
        self.state = DecState::Header;
        self.poisoned = false;
    }
}
