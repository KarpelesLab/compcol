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
//! raw payload and feed the result to this decoder — or skip the header
//! entirely with [`Decoder::raw`], below.
//!
//! ## Raw ZIP entries
//!
//! [`Decoder::raw`] takes the uncompressed size (a `u64`, so ZIP64 sizes
//! fit) up front and consumes the bare method-1 payload, exactly the bytes
//! a ZIP archive stores for the entry. End-of-stream handling is the same
//! as the framed path: the decoder reports `StreamEnd` once
//! `uncompressed_len` bytes have been produced, and nothing after the code
//! that produced the last of them is decoded or validated. Parsing the ZIP
//! local or central header to get that size is the caller's job.
//!
//! ## End of stream and `consumed`
//!
//! In both modes `decode` takes input only as the codes need it. When it
//! reports `StreamEnd`, the `consumed` counts of all `decode` calls add up
//! to exactly the length of the stream: the header (framed mode) plus the
//! payload through the byte holding the last bit of the code that produced
//! the last declared byte. Any bytes after that are left unconsumed, for
//! any slicing of the input and output, so a caller reading a container
//! knows where the entry ended. As with every decoder here, a call can
//! return `OutputFull` having consumed only part of its input; offer the
//! rest again.
//!
//! ```
//! use compcol::zip_shrink::Decoder;
//! use compcol::{Decoder as _, Status};
//!
//! // Bytes of a method-1 entry (from after its local header), and the
//! // uncompressed size taken from the ZIP header.
//! let entry: &[u8] = &[
//!     0x68, 0xca, 0xb0, 0x61, 0xf3, 0x06, 0xc4, 0x9d, 0x37, 0x72, 0xd8, 0x90, 0x01,
//! ];
//! let uncompressed_size: u64 = 11;
//!
//! let mut dec = Decoder::raw(uncompressed_size);
//! let mut out = [0u8; 64];
//! let (p, _) = dec.decode(entry, &mut out).unwrap();
//! let mut n = p.written;
//! let (p, status) = dec.finish(&mut out[n..]).unwrap();
//! n += p.written;
//! assert_eq!(status, Status::StreamEnd);
//! assert_eq!(&out[..n], b"hello world");
//! ```
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
/// Streaming model: codes are read straight from the caller's input slice
/// through a small bit accumulator (the stream is LSB-first) and resolved
/// against the dictionary. Decoded characters land in `emit_buf`, which is
/// then drained into the caller's `output` on each call.
///
/// No input is buffered beyond the accumulator, and a byte is taken from
/// the caller only when the code being read still needs bits. So when the
/// declared length is reached, the input consumed over all `decode` calls
/// is exactly the stream — through the byte holding the last bit of the
/// last code decoded — however the input and output were sliced. Whatever
/// follows is left with the caller.
#[derive(Debug)]
pub struct Decoder {
    // ── framing ──
    /// Header bytes parsed so far (0..4). Once 4, `target_len` is set.
    /// A raw decoder starts (and resets) at 4.
    header_pos: u8,
    /// Decoded length: declared by the header (u32 LE), or given to
    /// [`Decoder::raw`].
    target_len: u64,
    /// `Some(len)` for a raw (headerless) decoder; kept across resets.
    raw_len: Option<u64>,

    // ── bit reader state ──
    /// Input bits taken from the caller and not yet used by a code. Between
    /// codes this holds fewer than 8 bits (the rest of the byte the last
    /// code ended in); while a code is incomplete, fewer than `n_bits`.
    bit_acc: u32,
    bit_count: u8,
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
    /// Decoder for the framed format: a 4-byte LE uncompressed length,
    /// then the Shrink payload.
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
            raw_len: None,
            bit_acc: 0,
            bit_count: 0,
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

    /// Decoder for a bare ZIP method-1 payload with no header.
    ///
    /// `uncompressed_len` is the entry's uncompressed size from the ZIP
    /// local or central header (or its ZIP64 extra field). Feed the
    /// entry's compressed bytes as-is. [`reset`](crate::Decoder::reset)
    /// keeps the decoder in raw mode with the same length.
    pub fn raw(uncompressed_len: u64) -> Self {
        let mut d = Self::new();
        d.raw_len = Some(uncompressed_len);
        d.header_pos = 4;
        d.target_len = uncompressed_len;
        d
    }

    /// Bytes still owed to the caller, clamped to `usize`.
    fn remaining(&self) -> usize {
        usize::try_from(self.target_len.saturating_sub(self.out_pos)).unwrap_or(usize::MAX)
    }

    /// Decode `input` from `*pos` on and hand the result to `output` until
    /// `output` is full, the declared length has been delivered, or
    /// `input` holds no further complete code. Advances `*pos` past the
    /// input bytes taken and returns the number of bytes written.
    ///
    /// [`pump`](Self::pump) decodes in bursts of about 16 KiB, so a single
    /// pump-then-drain is not enough: it has to be repeated for as long as
    /// it makes progress. On return with `written < output.len()` and
    /// `!self.completed`, `emit_buf` is empty and `input` is used up. When
    /// `output` fills first, the rest of `input` is left untaken for the
    /// caller to offer again.
    fn pump_into(
        &mut self,
        input: &[u8],
        pos: &mut usize,
        output: &mut [u8],
    ) -> Result<usize, Error> {
        let mut written = 0usize;
        loop {
            // Run the LZW state machine (a no-op once completed, or while
            // a full burst is still waiting to be drained).
            self.pump(input, pos)?;

            // Drain to the caller, capped at target_len.
            let cap = (output.len() - written).min(self.remaining());
            let n = if cap > 0 && self.emit_head < self.emit_buf.len() {
                self.drain_emit(&mut output[written..written + cap])
            } else {
                0
            };
            written += n;
            self.out_pos += n as u64;
            if self.out_pos >= self.target_len {
                self.completed = true;
            }
            // `n == 0` with room left in `output` means pump produced
            // nothing: it ran out of input.
            if self.completed || written == output.len() || n == 0 {
                return Ok(written);
            }
        }
    }

    /// Try to read one code at the current width, LSB-first, taking bytes
    /// from `input[*pos..]` only while the code is short of bits.
    ///
    /// Returns `None` when `input` runs out first; the bits gathered so
    /// far stay in the accumulator (fewer than `n_bits`, so at most 12)
    /// and the next call carries on from there. After a code is returned
    /// fewer than 8 bits are left over, all from the byte that code ended
    /// in: no byte beyond the code is ever taken.
    fn try_read_code(&mut self, input: &[u8], pos: &mut usize) -> Option<u16> {
        let need = self.n_bits as u32;
        while self.bit_count < need as u8 {
            let &b = input.get(*pos)?;
            self.bit_acc |= (b as u32) << self.bit_count;
            self.bit_count += 8;
            *pos += 1;
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

        // `stack` now holds the string reversed. The forward-order first byte
        // is the last one pushed (`stack.last()`). Reverse once and bulk-copy
        // into `emit_buf` with a single `extend_from_slice`, instead of the
        // per-byte pop/push loop (which wrote every output byte twice).
        let first = *self.stack.last().ok_or(Error::Corrupt)?;
        self.stack.reverse();
        self.emit_buf.extend_from_slice(&self.stack);
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

    /// Decode codes from `input[*pos..]` into `emit_buf`, advancing `*pos`
    /// past the bytes taken. Returns when we either need more input, reach
    /// `target_len`, or fill `emit_buf`.
    fn pump(&mut self, input: &[u8], pos: &mut usize) -> Result<(), Error> {
        loop {
            if self.completed {
                return Ok(());
            }
            // Stop at the code that reaches the declared length. The stream
            // ends there: whatever follows is not part of it and must not
            // be decoded (let alone rejected as corrupt), nor taken from
            // the caller. Counting the bytes still waiting in `emit_buf`,
            // not just those already delivered, makes this independent of
            // how the input is sliced and of how fast the caller drains.
            let buffered = (self.emit_buf.len() - self.emit_head) as u64;
            if self.out_pos.saturating_add(buffered) >= self.target_len {
                return Ok(());
            }
            // Keep emit_buf bounded so we don't allocate gigabytes when the
            // caller hands us a tiny output slice. 16 KiB is comfortably
            // larger than the longest possible Shrink string (HSIZE bytes,
            // 8 KiB) so a single code can always be emitted.
            if self.emit_buf.len() - self.emit_head > 16 * 1024 {
                return Ok(());
            }

            // Out of input mid-code: the partial code stays in the bit
            // accumulator until the caller brings more.
            let Some(code) = self.try_read_code(input, pos) else {
                return Ok(());
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
                written: 0,
                done: false,
            });
        }
        if self.target_len == 0 {
            self.completed = true;
        }

        // Run the LZW state machine until `output` is full, the stream
        // ends or `input` is used up. Only the bytes the decoded codes
        // occupy are consumed: when `output` fills first the caller offers
        // the rest again, and what follows the end of the stream is never
        // taken at all.
        let written = self.pump_into(input, &mut consumed, output)?;

        Ok(RawProgress {
            consumed,
            written,
            done: self.completed,
        })
    }

    fn raw_finish(&mut self, output: &mut [u8]) -> Result<RawProgress, Error> {
        if self.header_pos < 4 {
            // Strict: a missing or partial header is an error, including
            // no data at all.
            return Err(Error::UnexpectedEnd);
        }

        // No input is buffered (at most part of one code), so this only
        // drains what has been decoded already.
        let written = self.pump_into(&[], &mut 0, output)?;

        if self.completed {
            return Ok(RawProgress {
                consumed: 0,
                written,
                done: true,
            });
        }

        // More output is owed. If `output` filled up, the caller drains it
        // and calls again. Otherwise nothing is left to drain and the
        // input ran out (less than one code is pending) short of the
        // declared length.
        let drained = self.emit_head >= self.emit_buf.len();
        if written < output.len() || (output.is_empty() && drained) {
            return Err(Error::UnexpectedEnd);
        }
        Ok(RawProgress {
            consumed: 0,
            written,
            done: false,
        })
    }

    fn raw_reset(&mut self) {
        match self.raw_len {
            Some(n) => {
                self.header_pos = 4;
                self.target_len = n;
            }
            None => {
                self.header_pos = 0;
                self.target_len = 0;
            }
        }
        self.bit_acc = 0;
        self.bit_count = 0;
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
