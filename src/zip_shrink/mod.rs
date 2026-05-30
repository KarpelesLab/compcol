//! ZIP method 1 — **Shrink**: dynamic LZW with a partial-clear marker.
//!
//! Shrink is the original PKZIP 1.x LZW variant. Codes are emitted at a
//! variable width starting at 9 bits and growing up to 13 bits as the
//! dictionary fills. Codes 0..=255 are literals. Code 256 is a control
//! escape; the next code at the current width is interpreted as a
//! sub-command:
//!
//! * `1` — increase the code width by one (capped at 13).
//! * `2` — **partial clear**: walk the dictionary and free every entry
//!   that has no successors (a leaf), keeping the prefix nodes intact.
//!
//! Bit packing is **LSB-first** within each byte, matching every other
//! PKZIP LZW variant. The dictionary is sized to 8192 entries (`HSIZE`).
//!
//! ## Wire format on our side
//!
//! ZIP method-1 payloads have no self-describing length. To make the
//! codec usable as a standalone streaming format, we wrap the raw payload
//! in a minimal four-byte header that carries the uncompressed length:
//!
//! ```text
//! +-----------+================+
//! | u32 LE n  | shrink payload |
//! +-----------+================+
//! ```
//!
//! `n` is the number of decompressed bytes the decoder will emit. This is
//! analogous to legacy `.lzma`'s "alone" framing (which uses an 8-byte
//! length). If you are extracting a method-1 entry from a real ZIP, splice
//! the length you already have from the central directory in front of the
//! raw payload and feed the result to this decoder.
//!
//! ## Scope
//!
//! Decoder only. The encoder is shipped as `Error::Unsupported` from every
//! method — implementing the partial-clear heuristic plus the leaf-aware
//! dictionary maintenance is well beyond the decoder, and producing
//! byte-identical streams to PKZIP 1.x's reference encoder isn't required
//! by any consumer we care about. Compress new data with a more modern
//! method (deflate, deflate64, lzma, zstd) instead.
//!
//! ## References
//!
//! * PKWARE APPNOTE.TXT — the historical "Shrinking" section (now mostly
//!   removed; see archived 1.x copies).
//! * Info-ZIP `unshrink.c` (BSD-style; reference for the partial-clear
//!   leaf-marking algorithm).

#![cfg_attr(docsrs, doc(cfg(feature = "zip_shrink")))]

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;
use crate::traits::{Algorithm, RawDecoder, RawEncoder, RawProgress};

/// Zero-sized marker type implementing [`Algorithm`] for ZIP Shrink.
#[derive(Debug, Clone, Copy, Default)]
pub struct ZipShrink;

impl Algorithm for ZipShrink {
    const NAME: &'static str = "zip-shrink";
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

/// Maximum dictionary size: 2^13 entries. Matches PKZIP / Info-ZIP.
const HSIZE: usize = 1 << 13;
/// Escape code; every other code is either a literal (<256) or a dynamic
/// dictionary entry (>256).
const BOGUS: u16 = 256;
/// Code width starts at 9 and grows up to this cap.
const INIT_BITS: u8 = 9;
const MAX_BITS: u8 = 13;

/// Sentinel `parent` values. Real parents are in `0..HSIZE`.
/// `FREE` means the slot is unused; `LITERAL` flags codes 0..=255.
const FREE: u16 = 0xFFFF;
const LITERAL: u16 = 0xFFFE;

// ─── encoder stub ────────────────────────────────────────────────────────

/// Encoder stub. ZIP Shrink encoding is out of scope for this build; every
/// method here returns [`Error::Unsupported`].
#[derive(Debug, Default)]
pub struct Encoder;

impl Encoder {
    pub const fn new() -> Self {
        Self
    }
}

impl RawEncoder for Encoder {
    fn raw_encode(&mut self, _input: &[u8], _output: &mut [u8]) -> Result<RawProgress, Error> {
        Err(Error::Unsupported)
    }
    fn raw_finish(&mut self, _output: &mut [u8]) -> Result<RawProgress, Error> {
        Err(Error::Unsupported)
    }
    fn raw_reset(&mut self) {}
}

// ─── decoder ─────────────────────────────────────────────────────────────

/// Streaming Shrink decoder.
///
/// Streaming model: input bytes accumulate in an internal `Vec`. Codes are
/// peeled off MSB-first into a small bit accumulator and resolved against
/// the dictionary. Decoded characters land in `emit_buf`, which is then
/// drained into the caller's `output` on each call. The bit stream is
/// LSB-first; codes can straddle byte boundaries so we always assemble
/// from the buffered input and only consume from it once a code is
/// fully resolved.
#[derive(Debug)]
pub struct Decoder {
    // ── framing ──
    /// Header bytes parsed so far (0..4). Once 4, `target_len` is set.
    header_pos: u8,
    /// Decoded length declared by the header (u32 LE).
    target_len: u64,

    // ── bit reader state ──
    bit_acc: u32,
    bit_count: u8,
    /// Buffered input we haven't yet drained into `bit_acc`.
    in_buf: Vec<u8>,
    in_pos: usize,
    /// Active code width.
    n_bits: u8,

    // ── dictionary ──
    /// `parent[c]` — the parent code of `c`, or `FREE` / `LITERAL`.
    parent: Vec<u16>,
    /// `value[c]` — the byte to emit when walking out of `c`.
    value: Vec<u8>,
    /// Where to start scanning for the next free slot (matches
    /// `unshrink.c`'s `lastfreecode`).
    last_free: u16,

    // ── LZW state ──
    /// Previous code; `u16::MAX` means "no previous yet".
    old_code: u16,
    /// First character of the previously-emitted string. Used to resolve
    /// the LZW KwKwK case and to populate the new dictionary entry.
    final_char: u8,

    /// Bytes already decoded, waiting to be flushed into the caller's
    /// output. Kept in *forward* order; `emit_head` is the read cursor.
    emit_buf: Vec<u8>,
    emit_head: usize,
    /// Total decoded bytes produced so far.
    out_pos: u64,

    /// Scratch stack used while reversing a decoded string.
    stack: Vec<u8>,
    /// Scratch markers for partial-clear leaf detection.
    has_child: Vec<bool>,

    /// After we have seen exactly `target_len` bytes the decoder is done;
    /// further calls are no-ops.
    completed: bool,
    /// Pending control-byte read: set when we have just consumed a 256
    /// escape and need to read one more code at the current width.
    pending_control: bool,
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder {
    pub fn new() -> Self {
        let mut parent = vec![FREE; HSIZE];
        let mut value = vec![0u8; HSIZE];
        // Codes 0..=255 are literal: parent = LITERAL, value = code.
        for c in 0..256u16 {
            parent[c as usize] = LITERAL;
            value[c as usize] = c as u8;
        }
        // Code 256 is the escape; never resolved as a string.
        parent[BOGUS as usize] = LITERAL;
        Self {
            header_pos: 0,
            target_len: 0,
            bit_acc: 0,
            bit_count: 0,
            in_buf: Vec::new(),
            in_pos: 0,
            n_bits: INIT_BITS,
            parent,
            value,
            last_free: BOGUS,
            old_code: u16::MAX,
            final_char: 0,
            emit_buf: Vec::new(),
            emit_head: 0,
            out_pos: 0,
            stack: Vec::with_capacity(HSIZE),
            has_child: vec![false; HSIZE],
            completed: false,
            pending_control: false,
        }
    }

    /// Compact the input buffer once we have consumed a healthy prefix —
    /// avoids unbounded growth when the caller streams many small chunks
    /// through a long payload.
    fn compact_in_buf(&mut self) {
        if self.in_pos >= 4096 && self.in_pos == self.in_buf.len() {
            self.in_buf.clear();
            self.in_pos = 0;
        } else if self.in_pos >= 64 * 1024 {
            self.in_buf.drain(0..self.in_pos);
            self.in_pos = 0;
        }
    }

    /// Try to read one code at the current width. LSB-first.
    fn try_read_code(&mut self) -> Option<u16> {
        let need = self.n_bits as u32;
        while self.bit_count < need as u8 {
            if self.in_pos >= self.in_buf.len() {
                return None;
            }
            self.bit_acc |= (self.in_buf[self.in_pos] as u32) << self.bit_count;
            self.bit_count += 8;
            self.in_pos += 1;
        }
        let mask = (1u32 << need) - 1;
        let code = (self.bit_acc & mask) as u16;
        self.bit_acc >>= need;
        self.bit_count -= need as u8;
        Some(code)
    }

    /// Walk a code into `emit_buf` (forward order). Returns the first
    /// character of the decoded string (the new `final_char`).
    ///
    /// Handles the LZW KwKwK case implicitly via the `FREE`/orphan walk:
    /// if a parent link points at a freed slot, substitute the old
    /// prefix's first character — matching `unshrink.c`'s loop.
    fn emit_string(&mut self, code: u16) -> Result<u8, Error> {
        self.stack.clear();
        let mut c = code;

        // KwKwK seed: caller passes the freshly-allocated code whose slot
        // is still FREE. Treat as "string = old_code's string + final_char".
        if self.parent[c as usize] == FREE {
            self.stack.push(self.final_char);
            c = self.old_code;
            if c == u16::MAX {
                return Err(Error::Corrupt);
            }
        }

        // Walk the parent chain until we hit a literal terminus.
        let mut hops = 0usize;
        loop {
            let p = self.parent[c as usize];
            if p == LITERAL {
                self.stack.push(self.value[c as usize]);
                break;
            }
            if p == FREE {
                // Orphan link encountered mid-walk — same substitution as
                // the entry-point KwKwK case.
                self.stack.push(self.final_char);
                c = self.old_code;
                if c == u16::MAX {
                    return Err(Error::Corrupt);
                }
            } else {
                self.stack.push(self.value[c as usize]);
                c = p;
            }
            hops += 1;
            if hops > HSIZE {
                return Err(Error::Corrupt);
            }
        }

        // `stack` now holds the string in reverse; pop into emit_buf.
        let first = *self.stack.last().ok_or(Error::Corrupt)?;
        while let Some(b) = self.stack.pop() {
            self.emit_buf.push(b);
        }
        Ok(first)
    }

    /// Reverse-engineer-friendly partial clear, exactly as in unshrink.c:
    ///
    /// * pass 1: every used code marks its parent as "has child";
    /// * pass 2: anything not marked is freed; everything else has its
    ///   mark cleared so the next partial-clear pass starts fresh.
    fn partial_clear(&mut self) {
        // Reset marks across the whole dictionary first — has_child is a
        // Vec<bool> of length HSIZE so we just zero what we'll touch.
        for m in self.has_child.iter_mut() {
            *m = false;
        }
        let last = self.last_free as usize;
        for code in (BOGUS as usize + 1)..=last {
            let par = self.parent[code];
            if par == FREE || par == LITERAL {
                continue;
            }
            if par > BOGUS {
                self.has_child[par as usize] = true;
            }
        }
        for code in (BOGUS as usize + 1)..=last {
            if !self.has_child[code] {
                self.parent[code] = FREE;
            }
        }
        // Rescan from the bottom on the next miss.
        self.last_free = BOGUS;
    }

    /// Find the next free dictionary slot, or `None` if the table is
    /// completely full. Matches the linear scan in `unshrink.c`.
    fn next_free_slot(&mut self) -> Option<u16> {
        let mut s = self.last_free as usize + 1;
        while s < HSIZE && self.parent[s] != FREE {
            s += 1;
        }
        if s >= HSIZE { None } else { Some(s as u16) }
    }

    /// Drain `self.emit_buf` (from `self.emit_head`) into `out`.
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

    /// Process as much of the buffered input as we can without writing
    /// more decoded bytes than `target_len`. Returns when we either need
    /// more input, hit `target_len`, or fill `emit_buf`.
    fn pump(&mut self) -> Result<(), Error> {
        loop {
            if self.completed {
                return Ok(());
            }
            // Keep emit_buf bounded so we don't allocate gigabytes when the
            // caller hands us a tiny output slice. 16 KiB is comfortably
            // larger than the longest possible Shrink string (HSIZE bytes,
            // 8 KiB) so a single code can always be emitted.
            if self.emit_buf.len() - self.emit_head > 16 * 1024 {
                return Ok(());
            }

            // Save bit-reader state so we can roll back on input
            // exhaustion mid-code.
            let saved_acc = self.bit_acc;
            let saved_cnt = self.bit_count;
            let saved_pos = self.in_pos;

            let code = match self.try_read_code() {
                Some(c) => c,
                None => {
                    // Restore and ask for more input.
                    self.bit_acc = saved_acc;
                    self.bit_count = saved_cnt;
                    self.in_pos = saved_pos;
                    return Ok(());
                }
            };

            if self.pending_control {
                // The previous code was the 256 escape; this code is the
                // control sub-command.
                self.pending_control = false;
                match code {
                    1 => {
                        if self.n_bits >= MAX_BITS {
                            return Err(Error::Corrupt);
                        }
                        self.n_bits += 1;
                    }
                    2 => {
                        self.partial_clear();
                    }
                    _ => return Err(Error::Corrupt),
                }
                continue;
            }

            if code == BOGUS {
                self.pending_control = true;
                continue;
            }

            // Bound: codes that haven't yet been allocated and aren't the
            // freshly-allocatable next slot are illegal. unshrink.c is
            // lenient and lets `parent == FREE` flow through the KwKwK
            // path; we mirror that.
            if (code as usize) >= HSIZE {
                return Err(Error::Corrupt);
            }

            if self.old_code == u16::MAX {
                // First code in the stream must be a literal — start the
                // dictionary chain at this byte.
                if code >= BOGUS {
                    return Err(Error::Corrupt);
                }
                self.final_char = code as u8;
                self.emit_buf.push(self.final_char);
                self.old_code = code;
                continue;
            }

            // Decode the string for this code into emit_buf.
            let new_final = self.emit_string(code)?;

            // Append new dictionary entry: (old_code, new_final) at next
            // free slot. The new code's value is the first character of
            // the just-decoded string (`new_final`).
            let new_code = self.next_free_slot();
            if let Some(nc) = new_code {
                self.parent[nc as usize] = self.old_code;
                self.value[nc as usize] = new_final;
                self.last_free = nc;
            } else {
                // Dictionary completely full and no partial-clear control
                // was issued. unshrink.c errors out here too.
                return Err(Error::Corrupt);
            }

            self.final_char = new_final;
            self.old_code = code;
            // `out_pos` (the count of bytes delivered to the caller) is
            // advanced only by `drain_emit`. The 16 KiB cap at the top of
            // this loop bounds how much we'll buffer before the caller
            // gets a chance to drain.
        }
    }
}

impl RawDecoder for Decoder {
    fn raw_decode(&mut self, input: &[u8], output: &mut [u8]) -> Result<RawProgress, Error> {
        let mut consumed = 0usize;
        let mut written = 0usize;

        // ── parse the 4-byte LE length header ──
        while self.header_pos < 4 && consumed < input.len() {
            let b = input[consumed];
            consumed += 1;
            self.target_len |= (b as u64) << (8 * self.header_pos as u64);
            self.header_pos += 1;
        }
        if self.header_pos < 4 {
            return Ok(RawProgress {
                consumed,
                written,
                done: false,
            });
        }
        if self.target_len == 0 {
            self.completed = true;
        }

        // Stash the rest of `input` (after the header bytes consumed
        // above) into our buffer for the bit reader.
        self.in_buf.extend_from_slice(&input[consumed..]);
        consumed = input.len();

        // Run the LZW state machine.
        self.pump()?;

        // Drain to the caller, capped at target_len.
        let remaining_target = self.target_len.saturating_sub(self.out_pos);
        let cap = output.len().min(remaining_target as usize);
        if cap > 0 && self.emit_head < self.emit_buf.len() {
            let n = self.drain_emit(&mut output[..cap]);
            written += n;
            self.out_pos += n as u64;
            if self.out_pos >= self.target_len {
                self.completed = true;
            }
        }

        self.compact_in_buf();

        Ok(RawProgress {
            consumed,
            written,
            done: self.completed,
        })
    }

    fn raw_finish(&mut self, output: &mut [u8]) -> Result<RawProgress, Error> {
        let mut written = 0usize;
        if self.header_pos < 4 {
            if self.header_pos == 0 && self.in_buf.is_empty() && self.emit_buf.is_empty() {
                // No data at all → empty stream is permissible only after
                // the full header has been seen. Strict: missing header is
                // an error.
                return Err(Error::UnexpectedEnd);
            }
            return Err(Error::UnexpectedEnd);
        }

        // Best-effort pump: there may be a pending code whose width was
        // bumped just before EOF, and we may still be able to drain
        // emit_buf into the caller.
        if !self.completed {
            self.pump()?;
        }

        let remaining_target = self.target_len.saturating_sub(self.out_pos);
        let cap = output.len().min(remaining_target as usize);
        if cap > 0 && self.emit_head < self.emit_buf.len() {
            let n = self.drain_emit(&mut output[..cap]);
            written += n;
            self.out_pos += n as u64;
        }

        if self.out_pos >= self.target_len {
            self.completed = true;
            return Ok(RawProgress {
                consumed: 0,
                written,
                done: true,
            });
        }

        // More output owed than we have buffered, and the input is gone.
        if self.emit_head >= self.emit_buf.len() {
            return Err(Error::UnexpectedEnd);
        }
        Ok(RawProgress {
            consumed: 0,
            written,
            done: false,
        })
    }

    fn raw_reset(&mut self) {
        self.header_pos = 0;
        self.target_len = 0;
        self.bit_acc = 0;
        self.bit_count = 0;
        self.in_buf.clear();
        self.in_pos = 0;
        self.n_bits = INIT_BITS;
        for c in 0..HSIZE {
            self.parent[c] = FREE;
            self.value[c] = 0;
        }
        for c in 0..256u16 {
            self.parent[c as usize] = LITERAL;
            self.value[c as usize] = c as u8;
        }
        self.parent[BOGUS as usize] = LITERAL;
        self.last_free = BOGUS;
        self.old_code = u16::MAX;
        self.final_char = 0;
        self.emit_buf.clear();
        self.emit_head = 0;
        self.out_pos = 0;
        self.stack.clear();
        for m in self.has_child.iter_mut() {
            *m = false;
        }
        self.completed = false;
        self.pending_control = false;
    }
}
