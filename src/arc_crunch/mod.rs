//! ARC "Crunch" — System Enhancement Associates ARC archiver method 8.
//!
//! Crunch is the LZW variant used by the ARC archiver (and the contemporary
//! `PKARC`/`PKPAK` tools) from circa 1985. It is a close relative of Unix
//! `compress(1)`: variable-width LZW codes packed **LSB-first**, a reserved
//! `CLEAR` code (256) that resets the dictionary in *block mode*, and a code
//! width that climbs from 9 bits up to a per-stream maximum.
//!
//! ## Wire format (raw method payload)
//!
//! The ARC container stores a one-byte sub-method header in front of the LZW
//! codestream. For method 8 ("Crunched") that byte is the maximum code width
//! in bits:
//!
//! ```text
//! +----------+============================+
//! | maxbits  | LZW codestream (LSB-first) |
//! +----------+============================+
//! ```
//!
//! `maxbits` is in the range 9..=16; the historical ARC default is 12 (so the
//! dictionary holds at most 4096 entries). Codes 0..=255 are literals, code
//! 256 is `CLEAR`, and assignable codes begin at 257. As in `compress(1)`'s
//! block mode, after a `CLEAR` the width drops back to 9 bits and the next
//! free code returns to 257.
//!
//! This module implements the **raw method payload only** (no ARC archive
//! header, no filename, no CRC) — exactly like the zip-method codecs in this
//! crate. Splice this payload into / out of an ARC entry yourself.
//!
//! ## Scope
//!
//! Both directions are implemented and validated by round-trip. The encoder
//! emits `maxbits = 12` streams and issues a `CLEAR` when the dictionary
//! fills (matching ARC's "dynamic" Crunch behaviour). The decoder accepts any
//! `maxbits` in 9..=16.
//!
//! ## DoS hygiene
//!
//! Crafted streams never panic: the classic LZW KwKwK case and any
//! out-of-range / not-yet-assigned code return [`Error::Corrupt`]; the
//! dictionary and the decoded-string scratch are bounded by `1 << maxbits`;
//! every dictionary index is bounds-checked and width arithmetic is checked.
//!
//! ## References
//!
//! * ARC file format notes (the "Crunched" method 8 / dynamic LZW), widely
//!   archived alongside the `arc` and `nomarch` source.
//! * `nomarch` (GPL — used only as a *format* reference, no code copied).
//! * Unix `compress(1)` LZW, of which Crunch is a direct ancestor variant.

#![cfg_attr(docsrs, doc(cfg(feature = "arc_crunch")))]

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;
use crate::traits::{Algorithm, RawDecoder, RawEncoder, RawProgress};

/// Zero-sized marker type implementing [`Algorithm`] for ARC Crunch.
#[derive(Debug, Clone, Copy, Default)]
pub struct ArcCrunch;

impl Algorithm for ArcCrunch {
    const NAME: &'static str = "crunch";
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

const INIT_BITS: u8 = 9;
const MIN_BITS: u8 = 9;
const MAX_BITS: u8 = 16;
/// Code width the encoder advertises. ARC's historical default is 12.
const ENC_MAX_BITS: u8 = 12;
/// Reserved CLEAR code.
const CLEAR: u32 = 256;
/// First assignable code (block mode).
const FIRST: u32 = 257;
/// Encoder hash table size (power of two, > 2 × `1 << ENC_MAX_BITS`).
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

/// Streaming ARC Crunch encoder. Emits a `maxbits = 12` LZW stream.
#[derive(Debug)]
pub struct Encoder {
    ht_key: Vec<u32>,
    ht_code: Vec<u32>,
    next_code: u32,
    nbits: u8,
    bit_acc: u64,
    bit_count: u8,
    /// Current prefix code; `u32::MAX` means "no prefix yet".
    w_code: u32,
    /// Header (the single maxbits byte) still pending?
    header_pending: bool,
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
            nbits: INIT_BITS,
            bit_acc: 0,
            bit_count: 0,
            w_code: u32::MAX,
            header_pending: true,
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
        self.nbits = INIT_BITS;
    }

    fn emit_code(&mut self, code: u32) {
        let n = self.nbits as u32;
        self.bit_acc |= (code as u64) << self.bit_count;
        self.bit_count += n as u8;
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

    fn ensure_header(&mut self) {
        if self.header_pending {
            self.pending.push(ENC_MAX_BITS);
            self.header_pending = false;
        }
    }

    /// After bumping `next_code`, widen `nbits` if needed, or CLEAR when the
    /// dictionary is full at `ENC_MAX_BITS`.
    fn maybe_widen(&mut self) {
        if self.nbits < ENC_MAX_BITS {
            // Bump once the next free code no longer fits at the current
            // width. compress-style: extcode = (1 << nbits) + 1. The decoder
            // lags the encoder's dictionary by exactly one entry, so it
            // bumps at `next_code >= (1 << nbits)` — one less — to stay in
            // lockstep (see `Decoder::raw_decode`).
            if self.next_code > (1u32 << self.nbits) {
                self.nbits += 1;
            }
        } else if self.next_code >= (1u32 << ENC_MAX_BITS) {
            // Dictionary full: emit CLEAR and reset (dynamic Crunch).
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
        self.ensure_header();

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
                    if self.next_code < (1u32 << ENC_MAX_BITS) {
                        self.insert(slot, prefix, b, self.next_code);
                        self.next_code += 1;
                    }
                    self.maybe_widen();
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

        self.ensure_header();

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
        self.nbits = INIT_BITS;
        self.bit_acc = 0;
        self.bit_count = 0;
        self.w_code = u32::MAX;
        self.header_pending = true;
        self.pending.clear();
        self.completed = false;
    }
}

// ─── decoder ─────────────────────────────────────────────────────────────

/// Streaming ARC Crunch decoder. Accepts `maxbits` in 9..=16.
#[derive(Debug)]
pub struct Decoder {
    /// Header (maxbits byte) parsed yet?
    header_done: bool,
    maxbits: u8,
    /// Dictionary: `prefix[c]` = parent code, `suffix[c]` = last byte.
    prefix: Vec<u16>,
    suffix: Vec<u8>,
    next_code: u32,
    nbits: u8,
    bit_acc: u64,
    bit_count: u8,
    /// Previous code; `u32::MAX` = no previous (start / after CLEAR).
    prev_code: u32,
    finchar: u8,
    /// Decoded characters waiting to flush, forward order.
    emit_buf: Vec<u8>,
    emit_head: usize,
    /// Scratch buffer used while reversing a decoded string.
    stack: Vec<u8>,
    completed: bool,
}

impl Decoder {
    /// Construct a fresh decoder.
    pub fn new() -> Self {
        let max_size = 1usize << MAX_BITS;
        Self {
            header_done: false,
            maxbits: ENC_MAX_BITS,
            prefix: vec![0u16; max_size],
            suffix: vec![0u8; max_size],
            next_code: FIRST,
            nbits: INIT_BITS,
            bit_acc: 0,
            bit_count: 0,
            prev_code: u32::MAX,
            finchar: 0,
            emit_buf: Vec::new(),
            emit_head: 0,
            // Fixed-size reverse-assembly scratch: a decoded string is at most
            // `1 << maxbits` ≤ `max_size` bytes, so its tail always fits.
            stack: vec![0u8; max_size],
            completed: false,
        }
    }

    fn reset_dict(&mut self) {
        self.next_code = FIRST;
        self.nbits = INIT_BITS;
        self.prev_code = u32::MAX;
    }

    fn try_read_code(&mut self, input: &[u8], in_cursor: &mut usize) -> Option<u32> {
        let need = self.nbits as u32;
        while self.bit_count < need as u8 {
            if *in_cursor >= input.len() {
                return None;
            }
            self.bit_acc |= (input[*in_cursor] as u64) << self.bit_count;
            self.bit_count += 8;
            *in_cursor += 1;
        }
        let mask = (1u64 << need) - 1;
        let code = (self.bit_acc & mask) as u32;
        self.bit_acc >>= need;
        self.bit_count -= need as u8;
        Some(code)
    }

    /// Decode `code` into `emit_buf` (forward order); updates `finchar`.
    /// Returns `Err(Corrupt)` if the parent chain is malformed (too long or
    /// out of range) — defends against crafted streams.
    ///
    /// The chain is walked once, writing the reversed string straight into a
    /// reserved tail region of `emit_buf` (deepest suffix last). This avoids
    /// the previous scratch-stack round trip (every byte was written twice:
    /// once pushed, once popped) — each output byte is now written exactly
    /// once.
    fn decode_string(&mut self, mut code: u32) -> Result<(), Error> {
        // `stack` is a fixed-size scratch (length == 1 << MAX_BITS, allocated
        // once). We walk the prefix chain writing the string back-to-front into
        // its tail, then bulk-copy the assembled forward-order slice into
        // `emit_buf` with a single vectorised `extend_from_slice`. This avoids
        // both the old per-byte `emit_buf.push` (a capacity check per byte) and
        // any per-call zero-initialisation.
        // Fast path: a bare literal (very common on incompressible input) is a
        // length-1 string — emit it directly and skip the reverse-assembly.
        if code < 256 {
            let first = code as u8;
            self.finchar = first;
            self.emit_buf.push(first);
            return Ok(());
        }
        let scratch = &mut self.stack[..];
        let mut i = scratch.len();
        while code >= 256 {
            // `i` reaching 0 means the chain is longer than any valid string
            // (> 1 << maxbits): a malformed / cyclic prefix table. Reject
            // rather than underflow.
            if code as usize >= self.prefix.len() || i == 0 {
                return Err(Error::Corrupt);
            }
            i -= 1;
            scratch[i] = self.suffix[code as usize];
            code = self.prefix[code as usize] as u32;
        }
        if i == 0 {
            return Err(Error::Corrupt);
        }
        let first = code as u8;
        self.finchar = first;
        i -= 1;
        scratch[i] = first;
        self.emit_buf.extend_from_slice(&scratch[i..]);
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

        // Parse the single maxbits header byte.
        if !self.header_done {
            if in_cursor >= input.len() {
                return Ok(RawProgress {
                    consumed: in_cursor,
                    written,
                    done: false,
                });
            }
            let mb = input[in_cursor];
            in_cursor += 1;
            if !(MIN_BITS..=MAX_BITS).contains(&mb) {
                return Err(Error::Unsupported);
            }
            self.maxbits = mb;
            self.header_done = true;
        }

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

            // Keep emit_buf bounded: a single decoded string is at most
            // `1 << maxbits` bytes. Stop buffering more codes if the caller's
            // output is full and we still have something queued.
            if self.emit_head < self.emit_buf.len() {
                continue;
            }

            // Width-bump check (no inter-code padding in Crunch / ARC).
            if self.nbits < self.maxbits && self.next_code >= (1u32 << self.nbits) {
                self.nbits += 1;
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
            if self.next_code < (1u32 << self.maxbits) {
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
        self.header_done = false;
        self.maxbits = ENC_MAX_BITS;
        self.next_code = FIRST;
        self.nbits = INIT_BITS;
        self.bit_acc = 0;
        self.bit_count = 0;
        self.prev_code = u32::MAX;
        self.finchar = 0;
        self.emit_buf.clear();
        self.emit_head = 0;
        // `stack` is fixed-size scratch overwritten on every use; leave it.
        self.completed = false;
    }
}
