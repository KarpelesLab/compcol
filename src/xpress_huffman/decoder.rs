//! XPress Huffman streaming decoder.
//!
//! Strategy mirrors [`crate::lzx::decoder`]: buffer compressed bytes
//! into a `Vec<u8>` and parse speculatively. The MS-XCA bit stream is
//! variable-rate and intermixes raw escape bytes with bit-packed
//! Huffman codes, so we keep the entire current block in memory and
//! drive a register-based decoder against it.
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

use super::huffman::{DecodeTable, NUM_SYMBOLS, build_decode_table, unpack_lengths};

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
    lengths: [u8; NUM_SYMBOLS],
    next_bits: u32,
    extra_bit_count: i32,
    block_end_emitted: u64,
    /// Set in `raw_finish` to let the bit-stream refill treat missing
    /// trailing bytes as zero (the encoder emits trailing zero words for
    /// the spec's eager-refill behaviour, but in case it falls short the
    /// finishing path still drains correctly).
    finishing: bool,
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
            lengths: [0u8; NUM_SYMBOLS],
            next_bits: 0,
            extra_bit_count: 0,
            block_end_emitted: 0,
            finishing: false,
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
        if self.out_history.len() > MAX_DISTANCE {
            let drop = self.out_history.len() - MAX_DISTANCE;
            self.out_history.drain(0..drop);
        }
        self.output_emitted += 1;
    }

    /// Try to start (or restart) a block by parsing the 256-byte length
    /// table and the initial two 16-bit words. Returns `Ok(true)` if the
    /// block was successfully primed, `Ok(false)` if more input is needed,
    /// or `Err` on a malformed table.
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
        self.lengths = unpack_lengths(&packed);
        self.table = Some(build_decode_table(&self.lengths)?);

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
        if self.in_pos + 2 > self.in_buf.len() {
            return None;
        }
        let lo = self.in_buf[self.in_pos] as u16;
        let hi = self.in_buf[self.in_pos + 1] as u16;
        self.in_pos += 2;
        Some((hi << 8) | lo)
    }

    fn read_byte(&mut self) -> Option<u8> {
        if self.in_pos >= self.in_buf.len() {
            return None;
        }
        let b = self.in_buf[self.in_pos];
        self.in_pos += 1;
        Some(b)
    }

    /// Decode as many symbols as the buffered input allows, appending to
    /// `self.decoded`. Stops at end-of-block (transitions to a new block
    /// or to `DrainTail`), at exhausted input (returns `Ok(())`), or on
    /// malformed input.
    fn decode_loop(&mut self) -> Result<(), Error> {
        loop {
            if self.output_emitted == self.total_output {
                self.phase = Phase::DrainTail;
                return Ok(());
            }
            if self.output_emitted >= self.block_end_emitted {
                // Block boundary: try to start the next block. If input
                // isn't sufficient yet, exit and wait for more.
                self.table = None;
                if !self.try_start_block()? {
                    return Ok(());
                }
                continue;
            }

            // Need 15 bits available in NextBits to peek a symbol.
            // The register always carries `extra_bit_count + 16` valid
            // bits in its top portion; we have a symbol's worth when
            // that count is at least 15 plus whatever we've already
            // dropped beyond. The pseudocode just peeks blindly because
            // refills are triggered by ExtraBitCount going below zero
            // AFTER a drop. We follow the same shape — but we need to
            // guarantee the next refill is buffered (2 bytes per word)
            // so we don't panic on partial input.
            let table = self
                .table
                .as_ref()
                .expect("decode_loop entered without a primed block");
            let idx = (self.next_bits >> (32 - 15)) as usize;
            let (symbol, len) = table[idx];
            let len = len as u32;
            // Drop the code bits.
            self.next_bits = self.next_bits.wrapping_shl(len);
            self.extra_bit_count -= len as i32;
            if self.extra_bit_count < 0 {
                let w: u32 = match self.read_word() {
                    Some(w) => w as u32,
                    None if self.finishing || self.output_emitted == self.total_output => {
                        // No more input; zero-fill the refill so the
                        // top-of-loop end-of-output check can fire.
                        0
                    }
                    None => return Err(Error::UnexpectedEnd),
                };
                self.next_bits |= w << (-self.extra_bit_count);
                self.extra_bit_count += 16;
            }

            if (symbol as usize) < 256 {
                if self.output_emitted >= self.total_output {
                    // Garbage symbol past expected end — ignore.
                    continue;
                }
                self.emit_byte(symbol as u8);
                continue;
            }

            // Match symbol.
            let match_sym = symbol as usize - 256;
            let length_class = (match_sym & 15) as u32;
            let dist_hi = (match_sym >> 4) as u32;

            let length_short_or_escape = length_class;
            let mut match_length: u32 = length_short_or_escape;
            if length_short_or_escape == 15 {
                let byte = self.read_byte().ok_or(Error::UnexpectedEnd)?;
                let mut len_extra = byte as u32;
                if len_extra == 255 {
                    let word = self.read_word().ok_or(Error::UnexpectedEnd)?;
                    let word = word as u32;
                    if word < 15 {
                        return Err(self.poison(Error::Corrupt));
                    }
                    len_extra = word - 15;
                }
                match_length = len_extra + 15;
            }
            match_length += 3;

            if symbol == 256 && self.output_emitted == self.total_output {
                // EOF sentinel. Per MS-XCA the decoder accepts this only
                // when the entire input buffer has been read AND the
                // expected output length is met. Our framing carries the
                // expected length explicitly, so we treat EOF as a
                // padding marker that just consumes one symbol. Real
                // termination is driven by `output_emitted == total_output`.
                continue;
            }
            // Sym=256 with output still pending is a real match of
            // (length=3, distance=1). Falls through to distance-extra
            // decoding below.

            // Distance extras.
            let dist_low: u32 = if dist_hi == 0 {
                0
            } else {
                let v = self.next_bits >> (32 - dist_hi);
                self.next_bits = self.next_bits.wrapping_shl(dist_hi);
                self.extra_bit_count -= dist_hi as i32;
                if self.extra_bit_count < 0 {
                    let w = self.read_word().ok_or(Error::UnexpectedEnd)? as u32;
                    self.next_bits |= w << (-self.extra_bit_count);
                    self.extra_bit_count += 16;
                }
                v
            };
            let match_offset = dist_low + (1u32 << dist_hi);
            // Validate against the retained history we can actually copy
            // from. `out_history` holds the last `MAX_DISTANCE` emitted
            // bytes (or fewer near the start of the stream), so this both
            // rejects distances that reach before the start of the stream
            // and prevents an underflow when `decoded` has been drained.
            if (match_offset as usize) > self.out_history.len() {
                return Err(self.poison(Error::InvalidDistance));
            }

            // Byte-by-byte copy: match length may exceed match offset
            // (run-length expansion), so we cannot do bulk memcpy. Source
            // bytes are read from the retained history (which is appended
            // to as we emit), allowing the copy to extend itself.
            for _ in 0..match_length {
                let src = self.out_history.len() - match_offset as usize;
                let b = self.out_history[src];
                self.emit_byte(b);
                if self.output_emitted >= self.block_end_emitted {
                    break;
                }
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
                        // Prime the first block.
                        if !self.try_start_block()? {
                            self.phase = Phase::Decoding;
                            // re-enter loop, will re-attempt or break
                            // depending on state.
                            // Actually try_start_block returns false only
                            // when input insufficient; we should break.
                            break;
                        }
                        self.phase = Phase::Decoding;
                    }
                }
                Phase::Decoding => {
                    if self.table.is_none() && !self.try_start_block()? {
                        break;
                    }
                    // Snapshot for rewind in case decode_loop hits EOF mid-symbol.
                    // Also snapshot phase/table so a block transition mid-
                    // decode_loop can be rolled back if the new block's
                    // bit stream is truncated.
                    let snap_in_pos = self.in_pos;
                    let snap_next_bits = self.next_bits;
                    let snap_extra = self.extra_bit_count;
                    let snap_decoded_len = self.decoded.len();
                    let snap_output_emitted = self.output_emitted;
                    let snap_block_end = self.block_end_emitted;
                    let snap_phase = self.phase;
                    let snap_table = self.table.clone();
                    let snap_lengths = self.lengths;
                    // The retained history is mutated in place (appended to
                    // and trimmed), so unlike `decoded` it cannot be undone
                    // with a `truncate`. Snapshot it so an `UnexpectedEnd`
                    // rollback restores it exactly. It is bounded by
                    // `MAX_DISTANCE`, and this clone happens at most once per
                    // `raw_decode` call, not per symbol.
                    let snap_out_history = self.out_history.clone();
                    match self.decode_loop() {
                        Ok(()) => {}
                        Err(Error::UnexpectedEnd) => {
                            // Roll back: not a real error, just need more
                            // input.
                            self.in_pos = snap_in_pos;
                            self.next_bits = snap_next_bits;
                            self.extra_bit_count = snap_extra;
                            self.decoded.truncate(snap_decoded_len);
                            self.output_emitted = snap_output_emitted;
                            self.block_end_emitted = snap_block_end;
                            self.phase = snap_phase;
                            self.table = snap_table;
                            self.lengths = snap_lengths;
                            self.out_history = snap_out_history;
                            break;
                        }
                        Err(e) => return Err(self.poison(e)),
                    }

                    // Drain newly decoded bytes.
                    written += self.drain_decoded_into(&mut output[written..]);
                    if written == output.len() && self.phase != Phase::Done {
                        break;
                    }
                    if self.phase == Phase::Decoding {
                        // decode_loop exited because of input exhaustion or
                        // block transition (handled inside) — re-loop
                        // unless decoded is empty and we made no progress.
                        if snap_in_pos == self.in_pos && snap_decoded_len == self.decoded.len() {
                            break;
                        }
                    }
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
        if !done && self.decoded.is_empty() && self.in_buf.len() == self.in_pos {
            // Genuine unexpected end.
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
        self.lengths = [0u8; NUM_SYMBOLS];
        self.next_bits = 0;
        self.extra_bit_count = 0;
        self.block_end_emitted = 0;
        self.finishing = false;
    }
}
