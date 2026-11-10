//! XPress Huffman streaming decoder.
//!
//! Compressed bytes are appended to an internal `Vec<u8>` and consumed by
//! a register-based bit reader. The MS-XCA bit stream is variable-rate
//! and intermixes raw escape bytes with bit-packed Huffman codes, but a
//! single symbol never needs more than [`MAX_SYMBOL_INPUT_BYTES`] further
//! input bytes. Decoding is therefore resumable per symbol: before a
//! symbol is consumed the decoder checks that everything it needs is
//! buffered, and otherwise stops there — with all earlier symbols already
//! committed — until more input arrives.
//!
//! Multi-block streams are handled inline: when 65,536 output bytes
//! have been produced for the current block we hand the next 256
//! bytes to [`super::huffman::build_decode_table`] and restart the
//! 32-bit register from the bytes immediately following.

extern crate alloc;
use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::error::Error;
use crate::traits::{RawDecoder, RawProgress};

use super::huffman::{DecodeTable, build_decode_table, unpack_lengths};

const BLOCK_OUTPUT_BYTES: usize = 65536;
/// Maximum back-reference distance. XPRESS-Huffman distances are bounded
/// by `dist_low + (1 << dist_hi)` with `dist_hi <= 15`, so the largest
/// representable distance is `2^16 = 65536`. We retain at least this many
/// of the most-recently emitted bytes so any legal match can be resolved
/// even after the streaming output buffer (`decoded`) has been drained.
const MAX_DISTANCE: usize = 65536;
/// Length-table byte count per block.
const TABLE_BYTES: usize = 256;
/// Each block reserves at least the table plus the initial 4 bytes for the
/// 32-bit register prefill.
const MIN_BLOCK_BYTES: usize = TABLE_BYTES + 4;
/// Upper bound on the input bytes one symbol can pull in beyond what is
/// already in the bit register: a refill word after the Huffman code (2),
/// the length-escape byte (1) and its 16-bit extension (2), and a refill
/// word after the distance bits (2). The code itself (≤ 15 bits) and the
/// distance bits (≤ 15) always come out of the register, which holds at
/// least 16 valid bits before each of them.
const MAX_SYMBOL_INPUT_BYTES: usize = 7;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Phase {
    /// Reading the 4-byte LE u32 framing header (total uncompressed length).
    Header,
    /// Inside a block: bit-stream consumption. May transition between
    /// blocks (new length table) when `BlockEnd` is reached.
    Decoding,
    /// All `total_output` bytes emitted; drain any decoded tail then
    /// transition to `Done`.
    DrainTail,
    Done,
}

/// Why [`Decoder::decode_loop`] returned without an error.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Stop {
    /// The buffered input cannot complete the next block header or symbol.
    NeedInput,
    /// The undrained backlog reached the cap; drain and call again.
    Backlog,
    /// All `total_output` bytes have been produced.
    Finished,
}

pub struct Decoder {
    in_buf: Vec<u8>,
    in_pos: usize,

    decoded: Vec<u8>,
    decoded_idx: usize,

    /// Sliding window of the most-recently emitted output bytes, used as
    /// the source for back-reference match copies. Unlike `decoded` (which
    /// is cleared by `drain_decoded_into` once handed to the caller), this
    /// buffer is retained across drains so cross-block / cross-drain
    /// back-references resolve correctly. Trimmed to the last
    /// `MAX_DISTANCE` bytes so it never grows without bound.
    out_history: Vec<u8>,

    phase: Phase,
    poisoned: bool,

    total_output: u64,
    output_emitted: u64,

    // Per-block state, valid only while Phase::Decoding.
    table: Option<Box<DecodeTable>>,
    next_bits: u32,
    extra_bit_count: i32,
    block_end_emitted: u64,
    /// Set in `raw_finish`: no further input will arrive, so a refill that
    /// finds the input exhausted may be satisfied by the single virtual
    /// lookahead word described on `virtual_word`.
    finishing: bool,
    /// Whether the one permitted virtual zero word has been shifted into the
    /// register. MS-XCA refills eagerly after every symbol, so a decoder
    /// legitimately reads up to 16 bits past the last symbol's bits and a
    /// complete stream may end without that final lookahead word. Exactly
    /// one such word is tolerated, and only as lookahead: it enters below
    /// the register's remaining real bits, so decoding can only touch it by
    /// driving `extra_bit_count` negative again — which demands a second
    /// refill, and that one is refused with `UnexpectedEnd`. Hence no
    /// fabricated bit is ever consumed as data. Once set, the input is
    /// treated as exhausted for raw byte/word reads too.
    virtual_word: bool,
}

impl Decoder {
    pub fn new() -> Self {
        Self {
            in_buf: Vec::new(),
            in_pos: 0,
            decoded: Vec::new(),
            decoded_idx: 0,
            out_history: Vec::new(),
            phase: Phase::Header,
            poisoned: false,
            total_output: 0,
            output_emitted: 0,
            table: None,
            next_bits: 0,
            extra_bit_count: 0,
            block_end_emitted: 0,
            finishing: false,
            virtual_word: false,
        }
    }

    fn poison(&mut self, e: Error) -> Error {
        self.poisoned = true;
        e
    }

    fn drain_decoded_into(&mut self, output: &mut [u8]) -> usize {
        let avail = self.decoded.len() - self.decoded_idx;
        let n = avail.min(output.len());
        output[..n].copy_from_slice(&self.decoded[self.decoded_idx..self.decoded_idx + n]);
        self.decoded_idx += n;
        if self.decoded_idx == self.decoded.len() {
            // Reset for next batch — saves growing the Vec unboundedly.
            self.decoded.clear();
            self.decoded_idx = 0;
        }
        n
    }

    /// Emit a single produced byte: append it to the caller-facing
    /// `decoded` queue, append it to the retained back-reference history
    /// (`out_history`, trimmed to the last `MAX_DISTANCE` bytes), and bump
    /// the whole-stream emitted counter.
    fn emit_byte(&mut self, b: u8) {
        self.decoded.push(b);
        self.out_history.push(b);
        // Trim the retained history so it never grows without bound, but do
        // it amortized: a naive `drain` back to `MAX_DISTANCE` on every byte
        // shifts the whole 64 KiB buffer per emit, which is O(n²) over the
        // stream. Instead let it grow to `2 * MAX_DISTANCE` and only then drop
        // the oldest half, keeping at least the last `MAX_DISTANCE` bytes.
        // Every read into `out_history` is relative to its current `len()` and
        // bounded by `MAX_DISTANCE` (validated above against `out_history.len()`),
        // so retaining that many is always sufficient. Amortized O(1) per byte.
        if self.out_history.len() >= 2 * MAX_DISTANCE {
            let drop = self.out_history.len() - MAX_DISTANCE;
            self.out_history.drain(0..drop);
        }
        self.output_emitted += 1;
    }

    /// Try to start (or restart) a block by parsing the 256-byte length
    /// table and the initial two 16-bit words. Returns `Ok(true)` if the
    /// block was successfully primed, `Ok(false)` if more input is needed
    /// (nothing is consumed in that case), or `Err` on a malformed table.
    fn try_start_block(&mut self) -> Result<bool, Error> {
        let available = self.in_buf.len() - self.in_pos;
        if available < MIN_BLOCK_BYTES {
            // MS-XCA: if we're at the end of the output buffer, this is
            // legal end-of-stream. Otherwise it's truncated input.
            // We return `false` (need more input) and let the caller (or
            // finish()) decide.
            return Ok(false);
        }
        let mut packed = [0u8; TABLE_BYTES];
        packed.copy_from_slice(&self.in_buf[self.in_pos..self.in_pos + TABLE_BYTES]);
        self.in_pos += TABLE_BYTES;
        let lengths = unpack_lengths(&packed);
        self.table = Some(build_decode_table(&lengths)?);

        // Prefill the 32-bit register with two 16-bit LE words.
        let lo_a = self.in_buf[self.in_pos] as u32;
        let hi_a = self.in_buf[self.in_pos + 1] as u32;
        let lo_b = self.in_buf[self.in_pos + 2] as u32;
        let hi_b = self.in_buf[self.in_pos + 3] as u32;
        self.in_pos += 4;
        let word_a = (hi_a << 8) | lo_a;
        let word_b = (hi_b << 8) | lo_b;
        self.next_bits = (word_a << 16) | word_b;
        self.extra_bit_count = 16;
        self.block_end_emitted = self.output_emitted + BLOCK_OUTPUT_BYTES as u64;
        Ok(true)
    }

    /// Read a 16-bit LE word at the current in_pos. Returns `None` if
    /// the input is too short — caller treats this as truncated input.
    fn read_word(&mut self) -> Option<u16> {
        if self.virtual_word || self.in_pos + 2 > self.in_buf.len() {
            return None;
        }
        let lo = self.in_buf[self.in_pos] as u16;
        let hi = self.in_buf[self.in_pos + 1] as u16;
        self.in_pos += 2;
        Some((hi << 8) | lo)
    }

    fn read_byte(&mut self) -> Option<u8> {
        if self.virtual_word || self.in_pos >= self.in_buf.len() {
            return None;
        }
        let b = self.in_buf[self.in_pos];
        self.in_pos += 1;
        Some(b)
    }

    /// Top the register back up after bits were dropped: when
    /// `extra_bit_count` went negative, shift in the next 16-bit word.
    ///
    /// If the input is exhausted and the stream is finishing, the first
    /// such refill is satisfied with a virtual zero word (pure lookahead,
    /// see `virtual_word`); any later one means real data bits are missing
    /// and yields `UnexpectedEnd`.
    fn refill(&mut self) -> Result<(), Error> {
        if self.extra_bit_count < 0 {
            let w: u32 = match self.read_word() {
                Some(w) => w as u32,
                None if self.finishing && !self.virtual_word => {
                    self.virtual_word = true;
                    0
                }
                None => return Err(Error::UnexpectedEnd),
            };
            self.next_bits |= w << (-self.extra_bit_count);
            self.extra_bit_count += 16;
        }
        Ok(())
    }

    /// Whether the buffered input holds every byte that decoding `symbol`
    /// (whose code is `len` bits and sits at the top of the register) will
    /// read: the refill word after the code, the length-escape byte(s), and
    /// the refill word after the distance bits. This mirrors the reads in
    /// [`Self::decode_loop`] exactly, so when it returns `true` none of them
    /// can fail and the symbol can be consumed without any way back.
    fn symbol_input_buffered(&self, symbol: u16, len: u32) -> bool {
        let avail = self.in_buf.len() - self.in_pos;
        if avail >= MAX_SYMBOL_INPUT_BYTES {
            return true;
        }
        let mut need = 0usize;
        let mut bits = self.extra_bit_count - len as i32;
        if bits < 0 {
            need += 2;
            bits += 16;
        }
        if symbol >= 256 {
            let match_sym = symbol as usize - 256;
            if match_sym & 15 == 15 {
                // The escape byte sits right after the refill word (if any);
                // its value decides whether a 16-bit extension follows.
                match self.in_buf.get(self.in_pos + need) {
                    None => return false,
                    Some(&255) => need += 3,
                    Some(_) => need += 1,
                }
            }
            if bits - ((match_sym >> 4) as i32) < 0 {
                need += 2;
            }
        }
        avail >= need
    }

    /// Decode as many symbols as the buffered input allows, appending to
    /// `self.decoded`. Every symbol is consumed whole or not at all, so
    /// whatever this returns — including [`Stop::NeedInput`] — the decoder
    /// state is consistent and a later call resumes exactly where this one
    /// stopped.
    fn decode_loop(&mut self, cap: usize) -> Result<Stop, Error> {
        loop {
            if self.output_emitted == self.total_output {
                self.phase = Phase::DrainTail;
                return Ok(Stop::Finished);
            }
            // Output back-pressure: `decode_loop` would otherwise keep
            // decoding across every buffered block (the block-boundary
            // `continue` below never returns), accumulating the entire
            // concatenated output of all blocks into `self.decoded` before
            // `raw_decode` gets a chance to drain it — a tiny-input → GiB
            // OOM. Once the undrained backlog reaches `cap` (the caller's
            // remaining output room plus one block of slack), return so
            // `raw_decode` can drain into `output` and resume on the next
            // call. State lives on `self`, so resuming is seamless.
            if self.decoded.len() - self.decoded_idx >= cap {
                return Ok(Stop::Backlog);
            }
            if self.output_emitted >= self.block_end_emitted {
                // Block boundary: try to start the next block. If input
                // isn't sufficient yet, exit and wait for more.
                self.table = None;
                if !self.try_start_block()? {
                    return Ok(Stop::NeedInput);
                }
                continue;
            }

            // Peek the next symbol. The register always holds at least 16
            // valid bits here (`extra_bit_count >= 0` after every refill),
            // so the ≤ 15-bit code at its top is fully determined.
            //
            // Invariant: a block is always primed before the symbol loop is
            // entered. Treat a missing table as corrupt input rather than
            // panicking, so the no-panic-on-untrusted-input guarantee holds
            // structurally even if that invariant is ever weakened.
            let table = match self.table.as_ref() {
                Some(t) => t,
                None => return Err(Error::Corrupt),
            };
            let idx = (self.next_bits >> (32 - 15)) as usize;
            let (symbol, len) = table[idx];
            let len = len as u32;

            // Commit point. While more input may still arrive, only consume
            // a symbol whose every read is already buffered; otherwise stop
            // *before* it, keeping all earlier symbols. When finishing there
            // is nothing to wait for: go ahead, and a read that falls off
            // the end of the input is a genuine `UnexpectedEnd`.
            if !self.finishing && !self.symbol_input_buffered(symbol, len) {
                return Ok(Stop::NeedInput);
            }

            // Drop the code bits.
            self.next_bits = self.next_bits.wrapping_shl(len);
            self.extra_bit_count -= len as i32;
            self.refill()?;

            if (symbol as usize) < 256 {
                self.emit_byte(symbol as u8);
                continue;
            }

            // Match symbol. Symbol 256 doubles as the end-of-stream marker,
            // but only once the expected output length has been reached —
            // and the check at the top of the loop stops decoding at that
            // point, so here (output still pending) it is always a real
            // match of length 3, distance 1.
            let match_sym = symbol as usize - 256;
            let length_class = (match_sym & 15) as u32;
            let dist_hi = (match_sym >> 4) as u32;

            let mut match_length: u32 = length_class;
            if length_class == 15 {
                let byte = self.read_byte().ok_or(Error::UnexpectedEnd)?;
                let mut len_extra = byte as u32;
                if len_extra == 255 {
                    let word = self.read_word().ok_or(Error::UnexpectedEnd)?;
                    let word = word as u32;
                    if word < 15 {
                        return Err(Error::Corrupt);
                    }
                    len_extra = word - 15;
                }
                match_length = len_extra + 15;
            }
            match_length += 3;

            // Distance extras.
            let dist_low: u32 = if dist_hi == 0 {
                0
            } else {
                let v = self.next_bits >> (32 - dist_hi);
                self.next_bits = self.next_bits.wrapping_shl(dist_hi);
                self.extra_bit_count -= dist_hi as i32;
                self.refill()?;
                v
            };
            let match_offset = dist_low + (1u32 << dist_hi);
            // Validate against the retained history we can actually copy
            // from. `out_history` holds the last `MAX_DISTANCE` emitted
            // bytes (or fewer near the start of the stream), so this both
            // rejects distances that reach before the start of the stream
            // and prevents an underflow when `decoded` has been drained.
            if (match_offset as usize) > self.out_history.len() {
                return Err(Error::InvalidDistance);
            }

            // Byte-by-byte copy: match length may exceed match offset
            // (run-length expansion), so we cannot do bulk memcpy. Source
            // bytes are read from the retained history (which is appended
            // to as we emit), allowing the copy to extend itself. MS-XCA
            // §2.2.4 only tests `BlockEnd` before each symbol, so a match
            // may run past the block end; the next block's end is then
            // counted from where the match stopped.
            for _ in 0..match_length {
                let src = self.out_history.len() - match_offset as usize;
                let b = self.out_history[src];
                self.emit_byte(b);
                if self.output_emitted == self.total_output {
                    break;
                }
            }
        }
    }
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

impl RawDecoder for Decoder {
    fn raw_decode(&mut self, input: &[u8], output: &mut [u8]) -> Result<RawProgress, Error> {
        if self.poisoned {
            return Err(Error::Corrupt);
        }
        let mut consumed_in = 0usize;
        let mut written = 0usize;

        // First, drain any previously decoded bytes.
        written += self.drain_decoded_into(&mut output[written..]);
        if written == output.len() && self.phase != Phase::Done {
            return Ok(RawProgress {
                consumed: 0,
                written,
                done: false,
            });
        }

        // Accept new input bytes into the internal buffer.
        if !input.is_empty() {
            self.in_buf.extend_from_slice(input);
            consumed_in = input.len();
        }

        // Drive state machine.
        loop {
            match self.phase {
                Phase::Header => {
                    if self.in_buf.len() - self.in_pos < 4 {
                        break;
                    }
                    let mut buf = [0u8; 4];
                    buf.copy_from_slice(&self.in_buf[self.in_pos..self.in_pos + 4]);
                    self.in_pos += 4;
                    self.total_output = u32::from_le_bytes(buf) as u64;
                    if self.total_output == 0 {
                        self.phase = Phase::Done;
                    } else {
                        // The first block is primed by `Phase::Decoding`.
                        self.phase = Phase::Decoding;
                    }
                }
                Phase::Decoding => {
                    if self.table.is_none() {
                        match self.try_start_block() {
                            Ok(true) => {}
                            Ok(false) => break,
                            Err(e) => return Err(self.poison(e)),
                        }
                    }
                    // Bound the backlog `decode_loop` may build up to what the
                    // caller can drain this round, plus one block of slack (a
                    // single match copy can emit up to a block before the cap
                    // is re-checked).
                    let cap = (output.len() - written).saturating_add(BLOCK_OUTPUT_BYTES);
                    // Decoding commits symbol by symbol, so there is nothing
                    // to roll back: an error here is final.
                    let stop = match self.decode_loop(cap) {
                        Ok(stop) => stop,
                        Err(e) => return Err(self.poison(e)),
                    };

                    // Drain newly decoded bytes.
                    written += self.drain_decoded_into(&mut output[written..]);
                    if written == output.len() && self.phase != Phase::Done {
                        break;
                    }
                    if stop == Stop::NeedInput {
                        break;
                    }
                    // `Backlog` with room left in `output` (the backlog was
                    // just drained) or `Finished`: go around again.
                }
                Phase::DrainTail => {
                    written += self.drain_decoded_into(&mut output[written..]);
                    if self.decoded.is_empty() {
                        self.phase = Phase::Done;
                    }
                    if written == output.len() {
                        break;
                    }
                    if self.phase == Phase::Done {
                        break;
                    }
                }
                Phase::Done => break,
            }
        }

        // Compact in_buf periodically to avoid unbounded growth.
        if self.in_pos > 4096 {
            self.in_buf.drain(..self.in_pos);
            self.in_pos = 0;
        }

        let done = matches!(self.phase, Phase::Done);
        Ok(RawProgress {
            consumed: consumed_in,
            written,
            done,
        })
    }

    fn raw_finish(&mut self, output: &mut [u8]) -> Result<RawProgress, Error> {
        if self.poisoned {
            return Err(Error::Corrupt);
        }
        self.finishing = true;
        let mut written = self.drain_decoded_into(output);
        if !self.decoded.is_empty() {
            return Ok(RawProgress {
                consumed: 0,
                written,
                done: false,
            });
        }
        // Try to push state forward with no new input.
        self.raw_decode(&[], &mut output[written..]).map(|p| {
            written += p.written;
        })?;
        let done = matches!(self.phase, Phase::Done);
        if !done && written == 0 && self.decoded.is_empty() && !output.is_empty() {
            // No further input is coming, there was room to write, and yet
            // nothing was produced and nothing is queued: the stream stops
            // short of a header, a block table or a symbol. Leftover bytes in
            // `in_buf` do not change that — they can never be completed — so
            // this is a genuine unexpected end, not a "call again".
            return Err(self.poison(Error::UnexpectedEnd));
        }
        Ok(RawProgress {
            consumed: 0,
            written,
            done,
        })
    }

    fn raw_reset(&mut self) {
        self.in_buf.clear();
        self.in_pos = 0;
        self.decoded.clear();
        self.decoded_idx = 0;
        self.out_history.clear();
        self.phase = Phase::Header;
        self.poisoned = false;
        self.total_output = 0;
        self.output_emitted = 0;
        self.table = None;
        self.next_bits = 0;
        self.extra_bit_count = 0;
        self.block_end_emitted = 0;
        self.finishing = false;
        self.virtual_word = false;
    }
}
