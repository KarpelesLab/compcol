//! ARC "Squashed" — System Enhancement Associates ARC archiver method 9.
//!
//! "Squashed" is the LZW variant introduced by the `PKARC`/`PKPAK` tools as a
//! faster, simpler relative of ARC's method-8 "Crunch". Where Crunch uses
//! `compress(1)`-style **variable-width** codes (9 bits climbing to a
//! per-stream maximum advertised by a one-byte `maxbits` header), Squashed
//! fixes the code width at **13 bits** for the entire stream and carries **no
//! header byte**. There is also no RLE pre-pass (the method-8 "Crunch" family
//! is sometimes paired with an RLE90 stage; Squashed is plain LZW).
//!
//! ## Wire format (raw method payload)
//!
//! ```text
//! +==================================+
//! | LZW codestream, 13-bit LSB-first |
//! +==================================+
//! ```
//!
//! Every code is exactly 13 bits, packed least-significant-bit first (the same
//! bit order as Crunch / `compress`). Codes 0..=255 are literals, code 256 is
//! the `CLEAR` code that resets the dictionary, and assignable codes begin at
//! 257. The dictionary holds at most `1 << 13 = 8192` entries; when it fills,
//! a `CLEAR` is emitted and decoding/encoding restarts from the literal table.
//!
//! This module implements the **raw method payload only** (no ARC archive
//! header, no filename, no CRC) — exactly like the zip-method codecs in this
//! crate. Splice this payload into / out of an ARC entry yourself.
//!
//! ## Scope
//!
//! Both directions are implemented and validated by round-trip. The method-8
//! RLE90 pre-pass is **not** part of Squashed and is not implemented here.
//!
//! ## DoS hygiene
//!
//! Crafted streams never panic: the classic LZW KwKwK case and any
//! out-of-range / not-yet-assigned code return [`Error::Corrupt`]; the
//! dictionary and the decoded-string stack are bounded by `1 << 13`; every
//! dictionary index is bounds-checked.
//!
//! ## References
//!
//! * ARC file format notes (the "Squashed" method 9 / fixed 13-bit LZW),
//!   widely archived alongside the `arc` and `nomarch` source.
//! * `nomarch` (GPL — used only as a *format* reference, no code copied).
//! * Unix `compress(1)` LZW, of which the ARC LZW methods are descendants.

#![cfg_attr(docsrs, doc(cfg(feature = "arc_squash")))]

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;
use crate::traits::{Algorithm, RawDecoder, RawEncoder, RawProgress};

/// Zero-sized marker type implementing [`Algorithm`] for ARC Squashed.
#[derive(Debug, Clone, Copy, Default)]
pub struct ArcSquash;

impl Algorithm for ArcSquash {
    const NAME: &'static str = "squashed";
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

// ─── shared constants ────────────────────────────────────────────────────

/// Fixed code width for Squashed (no header, no widening).
const BITS: u8 = 13;
/// Reserved CLEAR code.
const CLEAR: u32 = 256;
/// First assignable code.
const FIRST: u32 = 257;
/// Dictionary capacity (`1 << BITS`).
const MAX_CODE: u32 = 1 << BITS;
/// Encoder hash table size (power of two, > 2 × `MAX_CODE`).
const HASH_SIZE: usize = 1 << 14;
const HASH_MASK: u32 = (HASH_SIZE as u32) - 1;

#[inline]
fn hash(prefix: u32, byte: u8) -> u32 {
    let key = (prefix << 8) | byte as u32;
    key.wrapping_mul(2_654_435_761) & HASH_MASK
}

// ─── byte queue for pending output ───────────────────────────────────────

#[derive(Debug, Default)]
struct ByteQueue {
    buf: Vec<u8>,
    head: usize,
}

impl ByteQueue {
    fn new() -> Self {
        Self {
            buf: Vec::new(),
            head: 0,
        }
    }
    fn push(&mut self, b: u8) {
        self.buf.push(b);
    }
    fn len(&self) -> usize {
        self.buf.len() - self.head
    }
    fn is_empty(&self) -> bool {
        self.head == self.buf.len()
    }
    fn drain_into(&mut self, out: &mut [u8]) -> usize {
        let n = self.len().min(out.len());
        out[..n].copy_from_slice(&self.buf[self.head..self.head + n]);
        self.head += n;
        if self.head == self.buf.len() {
            self.buf.clear();
            self.head = 0;
        }
        n
    }
    fn clear(&mut self) {
        self.buf.clear();
        self.head = 0;
    }
}

// ─── encoder ─────────────────────────────────────────────────────────────

/// Streaming ARC Squashed encoder. Emits a fixed 13-bit LZW stream.
#[derive(Debug)]
pub struct Encoder {
    ht_key: Vec<u32>,
    ht_code: Vec<u32>,
    next_code: u32,
    bit_acc: u64,
    bit_count: u8,
    /// Current prefix code; `u32::MAX` means "no prefix yet".
    w_code: u32,
    pending: ByteQueue,
    completed: bool,
}

impl Encoder {
    /// Construct a fresh encoder.
    pub fn new() -> Self {
        Self {
            ht_key: vec![0u32; HASH_SIZE],
            ht_code: vec![0u32; HASH_SIZE],
            next_code: FIRST,
            bit_acc: 0,
            bit_count: 0,
            w_code: u32::MAX,
            pending: ByteQueue::new(),
            completed: false,
        }
    }

    fn reset_dict(&mut self) {
        for slot in self.ht_key.iter_mut() {
            *slot = 0;
        }
        for slot in self.ht_code.iter_mut() {
            *slot = 0;
        }
        self.next_code = FIRST;
    }

    fn emit_code(&mut self, code: u32) {
        self.bit_acc |= (code as u64) << self.bit_count;
        self.bit_count += BITS;
        while self.bit_count >= 8 {
            self.pending.push(self.bit_acc as u8);
            self.bit_acc >>= 8;
            self.bit_count -= 8;
        }
    }

    fn lookup(&self, prefix: u32, byte: u8) -> Result<u32, usize> {
        let key = (prefix << 8) | byte as u32;
        let mut idx = hash(prefix, byte) as usize;
        loop {
            let slot_code = self.ht_code[idx];
            if slot_code == 0 {
                return Err(idx);
            }
            if self.ht_key[idx] == key {
                return Ok(slot_code);
            }
            idx = (idx + 1) & (HASH_SIZE - 1);
        }
    }

    fn insert(&mut self, slot: usize, prefix: u32, byte: u8, code: u32) {
        self.ht_key[slot] = (prefix << 8) | byte as u32;
        self.ht_code[slot] = code;
    }

    /// After inserting a new entry, emit a `CLEAR` and reset the dictionary if
    /// it just filled (the decoder resets in lockstep upon seeing `CLEAR`).
    fn maybe_clear(&mut self) {
        if self.next_code >= MAX_CODE {
            self.emit_code(CLEAR);
            self.reset_dict();
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
        let mut consumed = 0usize;
        let mut written = 0usize;

        if !self.pending.is_empty() {
            written += self.pending.drain_into(&mut output[written..]);
        }

        while consumed < input.len() {
            // Bound how much we buffer per call so tiny output slices don't
            // make `pending` grow without limit.
            if self.pending.len() >= output.len().saturating_sub(written) + 64 {
                break;
            }

            let b = input[consumed];

            if self.w_code == u32::MAX {
                self.w_code = b as u32;
                consumed += 1;
                continue;
            }

            match self.lookup(self.w_code, b) {
                Ok(existing) => {
                    self.w_code = existing;
                    consumed += 1;
                }
                Err(slot) => {
                    let prefix = self.w_code;
                    self.emit_code(prefix);
                    if self.next_code < MAX_CODE {
                        self.insert(slot, prefix, b, self.next_code);
                        self.next_code += 1;
                    }
                    self.maybe_clear();
                    self.w_code = b as u32;
                    consumed += 1;
                }
            }

            if !self.pending.is_empty() && written < output.len() {
                written += self.pending.drain_into(&mut output[written..]);
            }
        }

        if !self.pending.is_empty() && written < output.len() {
            written += self.pending.drain_into(&mut output[written..]);
        }

        Ok(RawProgress {
            consumed,
            written,
            done: false,
        })
    }

    fn raw_finish(&mut self, output: &mut [u8]) -> Result<RawProgress, Error> {
        if self.completed {
            return Ok(RawProgress {
                consumed: 0,
                written: 0,
                done: true,
            });
        }

        if self.w_code != u32::MAX {
            let c = self.w_code;
            self.emit_code(c);
            self.w_code = u32::MAX;
        }

        // Flush leftover bits in the accumulator (zero-padded final byte).
        if self.bit_count > 0 {
            self.pending.push(self.bit_acc as u8);
            self.bit_acc = 0;
            self.bit_count = 0;
        }

        let mut written = 0usize;
        if !self.pending.is_empty() {
            written += self.pending.drain_into(&mut output[written..]);
        }
        let done = self.pending.is_empty();
        if done {
            self.completed = true;
        }
        Ok(RawProgress {
            consumed: 0,
            written,
            done,
        })
    }

    fn raw_reset(&mut self) {
        for slot in self.ht_key.iter_mut() {
            *slot = 0;
        }
        for slot in self.ht_code.iter_mut() {
            *slot = 0;
        }
        self.next_code = FIRST;
        self.bit_acc = 0;
        self.bit_count = 0;
        self.w_code = u32::MAX;
        self.pending.clear();
        self.completed = false;
    }
}

// ─── decoder ─────────────────────────────────────────────────────────────

/// Streaming ARC Squashed decoder. Fixed 13-bit codes.
#[derive(Debug)]
pub struct Decoder {
    /// Dictionary: `prefix[c]` = parent code, `suffix[c]` = last byte.
    prefix: Vec<u16>,
    suffix: Vec<u8>,
    next_code: u32,
    bit_acc: u64,
    bit_count: u8,
    /// Previous code; `u32::MAX` = no previous (start / after CLEAR).
    prev_code: u32,
    finchar: u8,
    /// Decoded characters waiting to flush, forward order.
    emit_buf: Vec<u8>,
    emit_head: usize,
    /// Scratch stack used while reversing a decoded string.
    stack: Vec<u8>,
    completed: bool,
}

impl Decoder {
    /// Construct a fresh decoder.
    pub fn new() -> Self {
        let max_size = MAX_CODE as usize;
        Self {
            prefix: vec![0u16; max_size],
            suffix: vec![0u8; max_size],
            next_code: FIRST,
            bit_acc: 0,
            bit_count: 0,
            prev_code: u32::MAX,
            finchar: 0,
            emit_buf: Vec::new(),
            emit_head: 0,
            stack: Vec::with_capacity(max_size),
            completed: false,
        }
    }

    fn reset_dict(&mut self) {
        self.next_code = FIRST;
        self.prev_code = u32::MAX;
    }

    fn try_read_code(&mut self, input: &[u8], in_cursor: &mut usize) -> Option<u32> {
        while self.bit_count < BITS {
            if *in_cursor >= input.len() {
                return None;
            }
            self.bit_acc |= (input[*in_cursor] as u64) << self.bit_count;
            self.bit_count += 8;
            *in_cursor += 1;
        }
        let mask = (1u64 << BITS) - 1;
        let code = (self.bit_acc & mask) as u32;
        self.bit_acc >>= BITS;
        self.bit_count -= BITS;
        Some(code)
    }

    /// Decode `code` into `emit_buf` (forward order); updates `finchar`.
    /// Returns `Err(Corrupt)` if the parent chain is malformed (too long or
    /// out of range) — defends against crafted streams.
    fn decode_string(&mut self, mut code: u32) -> Result<(), Error> {
        self.stack.clear();
        let limit = MAX_CODE as usize;
        let mut hops = 0usize;
        while code >= 256 {
            if code as usize >= self.prefix.len() {
                return Err(Error::Corrupt);
            }
            self.stack.push(self.suffix[code as usize]);
            code = self.prefix[code as usize] as u32;
            hops += 1;
            if hops > limit {
                return Err(Error::Corrupt);
            }
        }
        let first = code as u8;
        self.finchar = first;
        self.emit_buf.push(first);
        while let Some(b) = self.stack.pop() {
            self.emit_buf.push(b);
        }
        Ok(())
    }

    fn drain_emit(&mut self, out: &mut [u8]) -> usize {
        let available = self.emit_buf.len() - self.emit_head;
        let n = available.min(out.len());
        out[..n].copy_from_slice(&self.emit_buf[self.emit_head..self.emit_head + n]);
        self.emit_head += n;
        if self.emit_head == self.emit_buf.len() {
            self.emit_buf.clear();
            self.emit_head = 0;
        }
        n
    }
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

impl RawDecoder for Decoder {
    fn raw_decode(&mut self, input: &[u8], output: &mut [u8]) -> Result<RawProgress, Error> {
        let mut in_cursor = 0usize;
        let mut written = 0usize;

        loop {
            // Drain decoded bytes first.
            if self.emit_head < self.emit_buf.len() {
                written += self.drain_emit(&mut output[written..]);
                if self.emit_head < self.emit_buf.len() {
                    return Ok(RawProgress {
                        consumed: in_cursor,
                        written,
                        done: false,
                    });
                }
            }

            let code = match self.try_read_code(input, &mut in_cursor) {
                Some(c) => c,
                None => {
                    return Ok(RawProgress {
                        consumed: in_cursor,
                        written,
                        done: false,
                    });
                }
            };

            if code == CLEAR {
                self.reset_dict();
                continue;
            }

            if self.prev_code == u32::MAX {
                // First code after start / CLEAR: must be a literal.
                if code >= 256 {
                    return Err(Error::Corrupt);
                }
                self.finchar = code as u8;
                self.emit_buf.push(code as u8);
                self.prev_code = code;
                continue;
            }

            // Reject codes beyond the next assignable slot.
            if code > self.next_code {
                return Err(Error::Corrupt);
            }
            if code == self.next_code {
                // KwKwK: prev_code's string + its first char.
                let prev = self.prev_code;
                self.decode_string(prev)?;
                self.emit_buf.push(self.finchar);
            } else {
                self.decode_string(code)?;
            }

            // Add dictionary entry (prev_code, finchar) -> next_code.
            if self.next_code < MAX_CODE {
                let nc = self.next_code as usize;
                self.prefix[nc] = self.prev_code as u16;
                self.suffix[nc] = self.finchar;
                self.next_code += 1;
            }
            self.prev_code = code;
        }
    }

    fn raw_finish(&mut self, output: &mut [u8]) -> Result<RawProgress, Error> {
        if self.completed {
            return Ok(RawProgress {
                consumed: 0,
                written: 0,
                done: true,
            });
        }

        let mut written = 0usize;
        if self.emit_head < self.emit_buf.len() {
            written += self.drain_emit(&mut output[written..]);
            if self.emit_head < self.emit_buf.len() {
                return Ok(RawProgress {
                    consumed: 0,
                    written,
                    done: false,
                });
            }
        }

        self.completed = true;
        Ok(RawProgress {
            consumed: 0,
            written,
            done: true,
        })
    }

    fn raw_reset(&mut self) {
        self.next_code = FIRST;
        self.bit_acc = 0;
        self.bit_count = 0;
        self.prev_code = u32::MAX;
        self.finchar = 0;
        self.emit_buf.clear();
        self.emit_head = 0;
        self.stack.clear();
        self.completed = false;
    }
}
