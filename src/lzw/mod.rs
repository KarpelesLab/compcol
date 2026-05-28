//! Lempel–Ziv–Welch — the Unix `compress(1)` (`.Z`) flavour.
//!
//! Wire format (compatible with `compress` / `uncompress` / `gzip -d`):
//!
//! ```text
//! +------+------+------+================+
//! | 0x1F | 0x9D | 0xMM | LZW codestream |
//! +------+------+------+================+
//! ```
//!
//! `0xMM` is `block_mode_bit (0x80) | maxbits (5 bits)`. This implementation
//! emits `0x90` (block mode on, maxbits = 16). Codes are packed LSB-first.
//! The classic compress(1) quirk applies: when `n_bits` is bumped, or when a
//! `CLEAR` (code 256) is emitted in block mode, the stream is padded out to
//! the next `n_bits`-byte boundary so encoder and decoder stay in lockstep.
//!
//! Encoder behaviour:
//!  - `n_bits` starts at 9 and grows up to 16 as the dictionary fills.
//!  - When the dictionary reaches the maximum size (65536 entries), the
//!    encoder emits a `CLEAR` code and resets back to 9 bits / 257 free codes.
//!  - No ratio-based reset (the optional "ratio bumped" reset compress(1)
//!    does is omitted; the resulting `.Z` is still decompressable, just not
//!    always byte-identical to GNU compress's output).
//!
//! Decoder behaviour:
//!  - Reads the 3-byte header, supports `maxbits` 9..=16 and both block-mode
//!    on and off.
//!
//! Reference: <https://en.wikipedia.org/wiki/Lempel%E2%80%93Ziv%E2%80%93Welch>.

use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;
use crate::traits::{Algorithm, RawDecoder, RawEncoder, RawProgress};

/// Zero-sized marker type implementing [`Algorithm`] for LZW (compress(1) flavour).
#[derive(Debug, Clone, Copy, Default)]
pub struct Lzw;

impl Algorithm for Lzw {
    const NAME: &'static str = "lzw";
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

const MAGIC_1: u8 = 0x1F;
const MAGIC_2: u8 = 0x9D;

const INIT_BITS: u8 = 9;
const MAX_BITS: u8 = 16;
const HEADER_BYTE: u8 = 0x80 | MAX_BITS; // 0x90: block mode + 16 maxbits

/// Reserved CLEAR code.
const CLEAR: u32 = 256;
/// First assignable code in block mode.
const FIRST: u32 = 257;
/// Hash table size (power of two, > 2 × `1 << MAX_BITS`).
const HASH_SIZE: usize = 1 << 17;
const HASH_MASK: u32 = (HASH_SIZE as u32) - 1;

#[inline]
fn hash(prefix: u32, byte: u8) -> u32 {
    // Knuth-style multiplicative hash on the packed (prefix, byte) key.
    let key = (prefix << 8) | byte as u32;
    key.wrapping_mul(2_654_435_761) & HASH_MASK
}

// ─── ring buffer for pending output bytes ────────────────────────────────
//
// The encoder must be able to emit padding bytes mid-stream, and the
// caller's output slice may run out at any point. We accumulate bytes here
// and drain them lazily on each `encode` / `finish` call.

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

    /// Drain into `out` (which is the *remaining* slice the caller still
    /// has space in). Returns the number of bytes written.
    fn drain_into(&mut self, out: &mut [u8]) -> usize {
        let n = self.len().min(out.len());
        out[..n].copy_from_slice(&self.buf[self.head..self.head + n]);
        self.head += n;
        if self.head == self.buf.len() {
            // Reclaim once everything has been consumed.
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

/// Streaming LZW encoder (compress(1) format).
#[derive(Debug)]
pub struct Encoder {
    /// Hash table: each slot holds (`key`, `code`). `code == 0` means empty.
    ht_key: Vec<u32>,
    ht_code: Vec<u32>,
    next_code: u32,
    nbits: u8,
    bit_acc: u64,
    bit_count: u8,
    /// Current prefix code; `u32::MAX` means "no prefix yet".
    w_code: u32,
    /// Codes emitted at the current width since the last alignment (0..7).
    codes_in_group: u8,
    /// Bytes of header still to emit (3 → 0).
    header_remaining: u8,
    pending: ByteQueue,
    /// Set once `finish` has finished draining.
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
            codes_in_group: 0,
            header_remaining: 3,
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

    /// Push `code` (width = `self.nbits`) onto the bit stream and drain
    /// whole bytes into `self.pending`.
    fn emit_code(&mut self, code: u32) {
        let n = self.nbits as u32;
        self.bit_acc |= (code as u64) << self.bit_count;
        self.bit_count += n as u8;
        while self.bit_count >= 8 {
            self.pending.push(self.bit_acc as u8);
            self.bit_acc >>= 8;
            self.bit_count -= 8;
        }
        self.codes_in_group = (self.codes_in_group + 1) & 7;
    }

    /// Pad with zero codes at the current width until the current 8-code
    /// group is complete. After this call the bit accumulator is empty and
    /// `codes_in_group` is zero.
    fn pad_to_group_boundary(&mut self) {
        while self.codes_in_group != 0 {
            self.emit_code(0);
        }
        debug_assert_eq!(self.bit_count, 0);
        debug_assert_eq!(self.bit_acc, 0);
    }

    /// Try to look up the (prefix, byte) extension. Returns the assigned
    /// code if present, or the empty slot to fill if absent.
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

    /// Emit the 3-byte header into `pending` if not yet written.
    fn ensure_header(&mut self) {
        while self.header_remaining > 0 {
            let b = match self.header_remaining {
                3 => MAGIC_1,
                2 => MAGIC_2,
                1 => HEADER_BYTE,
                _ => unreachable!(),
            };
            self.pending.push(b);
            self.header_remaining -= 1;
        }
    }

    /// After bumping `next_code`, check whether we need to widen `nbits` or
    /// emit a `CLEAR` to reset the dictionary. Performs alignment in either
    /// case.
    fn maybe_widen_or_clear(&mut self) {
        if self.nbits < MAX_BITS {
            // Bump when next_code can no longer be encoded at the current
            // width. compress(1) uses extcode = (1<<nbits) + 1 while
            // nbits < maxbits.
            let threshold = (1u32 << self.nbits) + 1;
            if self.next_code >= threshold {
                self.pad_to_group_boundary();
                self.nbits += 1;
            }
        } else if self.next_code >= (1u32 << MAX_BITS) {
            // Dictionary full at max width: emit CLEAR and reset.
            self.emit_code(CLEAR);
            self.pad_to_group_boundary();
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

        // Drain any already-queued output before doing more work, otherwise
        // the queue grows unboundedly when the caller keeps the output slice
        // small.
        if !self.pending.is_empty() {
            written += self.pending.drain_into(&mut output[written..]);
        }

        while consumed < input.len() {
            // Bound how much we let `pending` grow per call so the caller
            // can keep memory pressure low when streaming with tiny output
            // slices. Once pending is bigger than the caller's remaining
            // output space, stop and let them drain.
            if self.pending.len() >= output.len().saturating_sub(written) + 64 {
                break;
            }

            let b = input[consumed];

            if self.w_code == u32::MAX {
                // First byte of the stream: prefix is just the literal.
                self.w_code = b as u32;
                consumed += 1;
                continue;
            }

            match self.lookup(self.w_code, b) {
                Ok(existing) => {
                    // Extend prefix.
                    self.w_code = existing;
                    consumed += 1;
                }
                Err(slot) => {
                    // Emit prefix, add new entry, reset prefix to b.
                    let prefix = self.w_code;
                    self.emit_code(prefix);
                    if self.next_code < (1u32 << MAX_BITS) {
                        self.insert(slot, prefix, b, self.next_code);
                        self.next_code += 1;
                    }
                    self.maybe_widen_or_clear();
                    self.w_code = b as u32;
                    consumed += 1;
                }
            }

            // Spill pending bytes into the caller's output as soon as we
            // have any, so we don't sit on data we could deliver.
            if !self.pending.is_empty() && written < output.len() {
                written += self.pending.drain_into(&mut output[written..]);
            }
        }

        // Final drain attempt.
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

        // First: if we still hold a prefix code, emit it as the final code.
        if self.w_code != u32::MAX {
            let c = self.w_code;
            self.emit_code(c);
            self.w_code = u32::MAX;
        }

        // Flush any leftover bits in the accumulator. compress(1) just
        // packs zero bits into the final byte — no group-level padding at
        // EOF.
        if self.bit_count > 0 {
            self.pending.push(self.bit_acc as u8);
            self.bit_acc = 0;
            self.bit_count = 0;
            self.codes_in_group = 0;
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
        self.codes_in_group = 0;
        self.header_remaining = 3;
        self.pending.clear();
        self.completed = false;
    }
}

// ─── decoder ─────────────────────────────────────────────────────────────

/// Streaming LZW decoder (compress(1) format).
#[derive(Debug)]
pub struct Decoder {
    /// Header bytes parsed so far (0..3).
    header_pos: u8,
    block_mode: bool,
    maxbits: u8,
    /// Dictionary: `prefix[c]` = parent code, `suffix[c]` = last byte.
    /// Literals (0..=255) are implicit: prefix is unused, suffix is `c`.
    prefix: Vec<u16>,
    suffix: Vec<u8>,
    next_code: u32,
    nbits: u8,
    bit_acc: u64,
    bit_count: u8,
    /// Previous code; `u32::MAX` = no previous (first code after start/CLEAR).
    prev_code: u32,
    /// First character of the previously-emitted string.
    finchar: u8,
    /// Codes read at the current width since the last alignment (0..7).
    codes_in_group: u8,
    /// Decoded characters waiting to be flushed into the caller's output,
    /// in forward order. `emit_head` is the read cursor.
    emit_buf: Vec<u8>,
    emit_head: usize,
    /// Scratch stack used while reversing a decoded string.
    stack: Vec<u8>,
    /// Once `finish` has nothing more to flush.
    completed: bool,
}

impl Decoder {
    pub fn new() -> Self {
        let max_size = 1usize << MAX_BITS;
        Self {
            header_pos: 0,
            block_mode: true,
            maxbits: MAX_BITS,
            prefix: vec![0u16; max_size],
            suffix: vec![0u8; max_size],
            next_code: FIRST,
            nbits: INIT_BITS,
            bit_acc: 0,
            bit_count: 0,
            prev_code: u32::MAX,
            finchar: 0,
            codes_in_group: 0,
            emit_buf: Vec::new(),
            emit_head: 0,
            stack: Vec::with_capacity(max_size),
            completed: false,
        }
    }

    fn reset_dict(&mut self) {
        self.next_code = if self.block_mode { FIRST } else { 256 };
        self.nbits = INIT_BITS;
        self.prev_code = u32::MAX;
        self.codes_in_group = 0;
    }

    /// Try to read one code at the current width. Returns `None` if
    /// insufficient bits are available.
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
        let mask = if need == 64 {
            u64::MAX
        } else {
            (1u64 << need) - 1
        };
        let code = (self.bit_acc & mask) as u32;
        self.bit_acc >>= need;
        self.bit_count -= need as u8;
        self.codes_in_group = (self.codes_in_group + 1) & 7;
        Some(code)
    }

    /// Skip enough input bits / bytes to align to the next 8-code group at
    /// the current width. Returns `Ok(true)` if alignment fully completed,
    /// `Ok(false)` if more input is needed.
    fn skip_to_group_boundary(&mut self, input: &[u8], in_cursor: &mut usize) -> bool {
        while self.codes_in_group != 0 {
            if self.try_read_code(input, in_cursor).is_none() {
                return false;
            }
        }
        true
    }

    /// Parse one more header byte from `input`. Returns whether the header
    /// is now complete.
    fn ensure_header(&mut self, input: &[u8], in_cursor: &mut usize) -> Result<bool, Error> {
        while self.header_pos < 3 && *in_cursor < input.len() {
            let b = input[*in_cursor];
            *in_cursor += 1;
            match self.header_pos {
                0 => {
                    if b != MAGIC_1 {
                        return Err(Error::BadHeader);
                    }
                }
                1 => {
                    if b != MAGIC_2 {
                        return Err(Error::BadHeader);
                    }
                }
                2 => {
                    let mb = b & 0x1F;
                    self.block_mode = (b & 0x80) != 0;
                    // compress(1) silently treats reserved high bits as
                    // junk, but unset bits 0x60 are well-defined: they're
                    // 0 in well-formed files. Allow anything in those bits.
                    if !(INIT_BITS..=MAX_BITS).contains(&mb) {
                        return Err(Error::Unsupported);
                    }
                    self.maxbits = mb;
                    self.next_code = if self.block_mode { FIRST } else { 256 };
                }
                _ => unreachable!(),
            }
            self.header_pos += 1;
        }
        Ok(self.header_pos >= 3)
    }

    /// Decode the string represented by `code`, pushing characters forward
    /// into `self.emit_buf`. Updates `self.finchar` to the first character.
    fn decode_string_to_emit_buf(&mut self, mut code: u32) {
        self.stack.clear();
        while code >= 256 {
            self.stack.push(self.suffix[code as usize]);
            code = self.prefix[code as usize] as u32;
        }
        let first = code as u8;
        self.finchar = first;
        self.emit_buf.push(first);
        while let Some(b) = self.stack.pop() {
            self.emit_buf.push(b);
        }
    }

    /// Drain `self.emit_buf` (from `self.emit_head`) into `out`, returning
    /// the number of bytes written.
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

        // Parse header bytes if any are still pending.
        if self.header_pos < 3 {
            self.ensure_header(input, &mut in_cursor)?;
        }

        loop {
            // Drain anything we've already decoded into the caller's output.
            if self.emit_head < self.emit_buf.len() {
                written += self.drain_emit(&mut output[written..]);
                if self.emit_head < self.emit_buf.len() {
                    // Caller's output is full but we still owe bytes.
                    return Ok(RawProgress {
                        consumed: in_cursor,
                        written,
                        done: false,
                    });
                }
            }

            if self.header_pos < 3 {
                // Need more input to finish reading the header.
                return Ok(RawProgress {
                    consumed: in_cursor,
                    written,
                    done: false,
                });
            }

            // Width-bump / alignment check.
            let bump_threshold = if self.nbits < self.maxbits {
                (1u32 << self.nbits) - 1
            } else {
                u32::MAX
            };
            if self.next_code > bump_threshold && self.nbits < self.maxbits {
                if !self.skip_to_group_boundary(input, &mut in_cursor) {
                    return Ok(RawProgress {
                        consumed: in_cursor,
                        written,
                        done: false,
                    });
                }
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

            // Handle CLEAR.
            if self.block_mode && code == CLEAR {
                // Align to group boundary at the *current* width, then reset.
                if !self.skip_to_group_boundary(input, &mut in_cursor) {
                    // We've already partially consumed bits for this CLEAR;
                    // the codes_in_group counter remembers how far we got.
                    return Ok(RawProgress {
                        consumed: in_cursor,
                        written,
                        done: false,
                    });
                }
                self.reset_dict();
                continue;
            }

            if self.prev_code == u32::MAX {
                // First code after start or CLEAR: must be a literal.
                if code >= 256 {
                    return Err(Error::Corrupt);
                }
                self.finchar = code as u8;
                self.emit_buf.push(code as u8);
                self.prev_code = code;
                continue;
            }

            // Decode the string for this code. KwKwK special case: code ==
            // next_code is valid, and represents prev_string + first(prev_string).
            if code > self.next_code {
                return Err(Error::Corrupt);
            }
            if code == self.next_code {
                // KwKwK: decode prev_code, then append finchar of *that*.
                let prev = self.prev_code;
                self.decode_string_to_emit_buf(prev);
                // self.finchar is now the first char of dict[prev_code].
                self.emit_buf.push(self.finchar);
            } else {
                self.decode_string_to_emit_buf(code);
            }

            // Add new dictionary entry: (prev_code, finchar) -> next_code.
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

        // Header must be complete; otherwise truncated.
        if self.header_pos < 3 && self.header_pos != 0 {
            return Err(Error::UnexpectedEnd);
        }

        // Trailing bits less than `nbits` are EOF padding; not an error.
        self.completed = true;
        Ok(RawProgress {
            consumed: 0,
            written,
            done: true,
        })
    }

    fn raw_reset(&mut self) {
        self.header_pos = 0;
        self.block_mode = true;
        self.maxbits = MAX_BITS;
        // Dictionary contents will be overwritten as codes are added; no
        // need to zero them.
        self.next_code = FIRST;
        self.nbits = INIT_BITS;
        self.bit_acc = 0;
        self.bit_count = 0;
        self.prev_code = u32::MAX;
        self.finchar = 0;
        self.codes_in_group = 0;
        self.emit_buf.clear();
        self.emit_head = 0;
        self.stack.clear();
        self.completed = false;
    }
}
