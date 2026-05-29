//! ADC (Apple Data Compression).
//!
//! The simple LZSS-like codec used inside Apple disk images (`.dmg`) and HFS+
//! compressed resource forks. The stream is a flat sequence of token bytes
//! followed by their parameters — there is **no header, no trailer, no
//! checksum, no framing**. A stream simply ends when the producer stops
//! emitting bytes; the consumer stops decoding at input exhaustion.
//!
//! ## Wire format
//!
//! Each token starts with a single tag byte whose top bits select the form:
//!
//! ```text
//! 1lll_llll  (0x80..=0xFF)  raw literal run, length = (lll_llll & 0x7F) + 1
//!                           (1..=128), followed by that many literal bytes.
//!
//! 01ll_llll  (0x40..=0x7F)  "long match" — length = (lll_lll & 0x3F) + 4
//!                           (4..=67), followed by a big-endian 16-bit offset
//!                           where the actual distance back is `offset + 1`
//!                           (so 0..=65535 codes 1..=65536).
//!
//! 00ll_llHH  (0x00..=0x3F)  "short match" — length = ((b & 0x3C) >> 2) + 3
//!                           (3..=18), `HH` are the top 2 bits of a 10-bit
//!                           offset, followed by 1 byte LL holding the low
//!                           8 bits; distance = (HH<<8 | LL) + 1, 1..=1024.
//! ```
//!
//! After a match token the decoder copies from its already-decoded output
//! buffer; for runs longer than the offset, the copy is byte-by-byte and
//! repeats the window (the canonical LZ77 self-overlap trick).
//!
//! ## Streaming model
//!
//! The encoder buffers all input it has seen so far and only emits encoded
//! tokens from `raw_finish`. This is the same pattern used by `snappy` in
//! this crate — it sidesteps the otherwise tricky problem of carrying a
//! lookahead-and-deferred-emit state across `raw_encode` calls without
//! introducing an output framing layer ADC does not have. Memory cost is
//! `O(input)`; suitable for the typical ADC use case (single resource fork
//! or DMG sector, all well below tens of MiB).
//!
//! The decoder is a strict state machine — it accepts the input one byte at
//! a time and maintains a 64 KiB sliding window of already-emitted bytes
//! for match copying.

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;
use crate::traits::{Algorithm, RawDecoder, RawEncoder, RawProgress};

/// Zero-sized marker type implementing [`Algorithm`] for ADC.
#[derive(Debug, Clone, Copy, Default)]
pub struct Adc;

impl Algorithm for Adc {
    const NAME: &'static str = "adc";
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

// ─── encoder ──────────────────────────────────────────────────────────────

/// Maximum back-distance supported by the "long match" form.
const MAX_LONG_OFFSET: usize = 65536;
/// Maximum back-distance supported by the "short match" form.
const MAX_SHORT_OFFSET: usize = 1024;
/// Maximum length of a "long match" token.
const MAX_LONG_MATCH: usize = 67;
/// Maximum length of a "short match" token.
const MAX_SHORT_MATCH: usize = 18;
/// Minimum match length we will emit.
const MIN_MATCH: usize = 3;
/// Maximum bytes a single raw-literal token can hold.
const MAX_LITERAL_RUN: usize = 128;

/// Hash table size for the match finder. 13 bits = 8192 entries, hashed on
/// 3-byte prefixes.
const HASH_LOG: u32 = 13;
const HASH_TABLE_SIZE: usize = 1 << HASH_LOG;
const HASH_EMPTY: u32 = u32::MAX;

#[inline]
fn hash3(b0: u8, b1: u8, b2: u8) -> usize {
    let v = (b0 as u32) | ((b1 as u32) << 8) | ((b2 as u32) << 16);
    ((v.wrapping_mul(2_654_435_761)) >> (32 - HASH_LOG)) as usize
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum EncPhase {
    /// Accepting raw input bytes into `input`; nothing has been encoded yet.
    Buffering,
    /// All input has been encoded into `encoded`; bytes are being drained
    /// to the caller's output buffer.
    Flushing,
    /// Everything has been drained.
    Done,
}

pub struct Encoder {
    /// Accumulated raw input. Grows across `raw_encode` calls.
    input: Vec<u8>,
    /// Output bytes produced once `raw_finish` runs the match finder.
    encoded: Vec<u8>,
    encoded_idx: usize,
    phase: EncPhase,
}

impl Encoder {
    pub fn new() -> Self {
        Self {
            input: Vec::new(),
            encoded: Vec::new(),
            encoded_idx: 0,
            phase: EncPhase::Buffering,
        }
    }

    /// Match-find and encode `self.input` into `self.encoded`.
    fn build(&mut self) {
        self.encoded.clear();
        self.encoded_idx = 0;
        if self.input.is_empty() {
            self.phase = EncPhase::Done;
            return;
        }

        // Hash table: position of the most recent occurrence of each 3-byte
        // prefix hash. Sentinel = HASH_EMPTY.
        let mut hash_table = vec![HASH_EMPTY; HASH_TABLE_SIZE];

        let input = &self.input;
        let n = input.len();

        // Buffer of pending literal bytes that have no useful match.
        let mut pending_lit_start: usize = 0;
        let mut pending_lit_len: usize = 0;
        let mut i: usize = 0;

        // Helper: flush `pending_lit_len` literal bytes starting at
        // `pending_lit_start` into `encoded`, splitting into runs of
        // MAX_LITERAL_RUN.
        let flush_literals = |encoded: &mut Vec<u8>,
                              input: &[u8],
                              pending_lit_start: usize,
                              pending_lit_len: usize| {
            let mut off = pending_lit_start;
            let mut rem = pending_lit_len;
            while rem > 0 {
                let take = rem.min(MAX_LITERAL_RUN);
                encoded.push(0x80 | ((take - 1) as u8));
                encoded.extend_from_slice(&input[off..off + take]);
                off += take;
                rem -= take;
            }
        };

        while i + MIN_MATCH <= n {
            let h = hash3(input[i], input[i + 1], input[i + 2]);
            let prev_pos = hash_table[h] as usize;
            let prev_pos_valid = hash_table[h] != HASH_EMPTY && prev_pos < i;

            let mut best_len: usize = 0;
            let mut best_dist: usize = 0;

            if prev_pos_valid {
                let dist = i - prev_pos;
                if (1..=MAX_LONG_OFFSET).contains(&dist) {
                    // Verify the prefix matches at this hash slot, then extend.
                    if input[prev_pos] == input[i]
                        && input[prev_pos + 1] == input[i + 1]
                        && input[prev_pos + 2] == input[i + 2]
                    {
                        // Extend match length up to the maximum encodable
                        // (long form caps at 67; short form caps at 18, but
                        // we may still want the long form for offset ≤ 1024
                        // if length > 18).
                        let mut len = 3usize;
                        let limit = (n - i).min(MAX_LONG_MATCH);
                        while len < limit && input[prev_pos + len] == input[i + len] {
                            len += 1;
                        }
                        // Reject matches we cannot encode: short form needs
                        // 3+ and short offset; long form needs 4+.
                        if dist <= MAX_SHORT_OFFSET {
                            // short form covers length 3..=18, long form 4..=67.
                            // Always usable; pick at emit time.
                            best_len = len;
                            best_dist = dist;
                        } else if len >= 4 {
                            best_len = len;
                            best_dist = dist;
                        }
                    }
                }
            }

            // Update hash table for current position regardless.
            hash_table[h] = i as u32;

            if best_len >= MIN_MATCH {
                // Flush pending literals first.
                if pending_lit_len > 0 {
                    flush_literals(&mut self.encoded, input, pending_lit_start, pending_lit_len);
                    pending_lit_len = 0;
                }

                // Pick token form based on distance + length.
                // Use the SHORT form when both the offset and length fit
                // (offset ≤ 1024 AND length ≤ 18); else LONG form.
                if best_dist <= MAX_SHORT_OFFSET && best_len <= MAX_SHORT_MATCH {
                    // 00ll_llHH; length code = best_len - 3 (0..=15), offset
                    // = best_dist - 1 (0..=1023).
                    let off_code = (best_dist - 1) as u16;
                    let len_code = (best_len - MIN_MATCH) as u8; // 0..=15
                    let tag = ((len_code & 0x0F) << 2) | ((off_code >> 8) as u8 & 0x03);
                    self.encoded.push(tag);
                    self.encoded.push((off_code & 0xFF) as u8);
                } else {
                    // Long form. Need length 4..=67.
                    // Cap best_len at 67 in case caller above produced 19..=67
                    // with a short-offset (we still want the long form because
                    // the short form maxes at 18).
                    let len = best_len.min(MAX_LONG_MATCH);
                    let len_code = (len - 4) as u8; // 0..=63
                    let tag = 0x40 | (len_code & 0x3F);
                    let off_code = (best_dist - 1) as u16;
                    self.encoded.push(tag);
                    self.encoded.push((off_code >> 8) as u8);
                    self.encoded.push((off_code & 0xFF) as u8);
                }

                // Update hash table for the bytes covered by the match (we
                // skip the first byte — its hash was already recorded above).
                let match_end = i + best_len;
                let mut j = i + 1;
                while j + MIN_MATCH <= match_end.min(n) && j < n - 2 {
                    let h2 = hash3(input[j], input[j + 1], input[j + 2]);
                    hash_table[h2] = j as u32;
                    j += 1;
                }
                i = match_end;
                pending_lit_start = i;
            } else {
                pending_lit_len += 1;
                i += 1;
            }
        }

        // Anything in the tail (last MIN_MATCH-1 bytes) is a literal.
        if i < n {
            pending_lit_len += n - i;
        }
        if pending_lit_len > 0 {
            flush_literals(&mut self.encoded, input, pending_lit_start, pending_lit_len);
        }

        self.phase = EncPhase::Flushing;
    }

    fn drain_encoded(&mut self, output: &mut [u8], written: &mut usize) {
        let avail = self.encoded.len() - self.encoded_idx;
        let space = output.len() - *written;
        let n = avail.min(space);
        if n > 0 {
            output[*written..*written + n]
                .copy_from_slice(&self.encoded[self.encoded_idx..self.encoded_idx + n]);
            self.encoded_idx += n;
            *written += n;
        }
        if self.encoded_idx == self.encoded.len() {
            self.phase = EncPhase::Done;
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
        if self.phase != EncPhase::Buffering {
            // Past finish — nothing further to accept.
            return Ok(RawProgress {
                consumed: 0,
                written: 0,
                done: false,
            });
        }
        let _ = output;
        self.input.extend_from_slice(input);
        Ok(RawProgress {
            consumed: input.len(),
            written: 0,
            done: false,
        })
    }

    fn raw_finish(&mut self, output: &mut [u8]) -> Result<RawProgress, Error> {
        let mut written = 0usize;
        loop {
            match self.phase {
                EncPhase::Buffering => {
                    self.build();
                    // build() transitions to Flushing or Done.
                }
                EncPhase::Flushing => {
                    self.drain_encoded(output, &mut written);
                    if self.phase == EncPhase::Flushing {
                        return Ok(RawProgress {
                            consumed: 0,
                            written,
                            done: false,
                        });
                    }
                }
                EncPhase::Done => {
                    return Ok(RawProgress {
                        consumed: 0,
                        written,
                        done: true,
                    });
                }
            }
        }
    }

    fn raw_reset(&mut self) {
        self.input.clear();
        self.encoded.clear();
        self.encoded_idx = 0;
        self.phase = EncPhase::Buffering;
    }
}

// ─── decoder ──────────────────────────────────────────────────────────────

/// Decoder window size. 64 KiB covers the maximum supported back-distance.
const WINDOW_SIZE: usize = 65536;

#[derive(Clone, Copy, PartialEq, Eq)]
enum DecPhase {
    /// Ready to read the next token tag byte.
    Tag,
    /// In a raw literal run; `remaining` literal bytes still to read from
    /// input and copy to output.
    Literal {
        remaining: u16,
    },
    /// In a long match: have the tag, need 2 more bytes for the big-endian
    /// offset. `length` is already decoded.
    LongMatchOffHi {
        length: u8,
    },
    LongMatchOffLo {
        length: u8,
        off_hi: u8,
    },
    /// In a short match: have the tag, need 1 byte for the low offset.
    /// `length` and `off_hi` already decoded.
    ShortMatchOffLo {
        length: u8,
        off_hi: u8,
    },
    /// Copying `remaining` bytes from `distance` bytes before the current
    /// output position. Stays here as long as the caller's output buffer
    /// is too small for the copy.
    Copying {
        distance: u32,
        remaining: u16,
    },
}

pub struct Decoder {
    /// Sliding window of the most recently emitted decoded bytes. Sized to
    /// `WINDOW_SIZE`; `window_pos` indexes the next byte to write.
    window: Vec<u8>,
    window_pos: usize,
    /// Total emitted byte count, used to know whether we have enough history
    /// to honor a requested back-distance.
    emitted: u64,
    phase: DecPhase,
    poisoned: bool,
}

impl Decoder {
    pub fn new() -> Self {
        Self {
            window: vec![0u8; WINDOW_SIZE],
            window_pos: 0,
            emitted: 0,
            phase: DecPhase::Tag,
            poisoned: false,
        }
    }

    /// Emit a single byte: write to output and append to window.
    fn emit_byte(&mut self, b: u8, output: &mut [u8], written: &mut usize) {
        output[*written] = b;
        *written += 1;
        self.window[self.window_pos] = b;
        self.window_pos = (self.window_pos + 1) % WINDOW_SIZE;
        self.emitted += 1;
    }

    /// Read the byte that sits `distance` positions before the current
    /// output cursor, from the sliding window.
    fn window_lookback(&self, distance: u32) -> u8 {
        // window_pos is the *next* write slot; the byte at offset 1 is
        // window[(window_pos - 1) mod N], etc.
        let d = distance as usize;
        // d ≥ 1, d ≤ WINDOW_SIZE
        let idx = (self.window_pos + WINDOW_SIZE - d) % WINDOW_SIZE;
        self.window[idx]
    }

    /// Bulk-emit `n` literal bytes from `src` into output and the sliding
    /// window. Caller guarantees `n` bytes of output room and `n` bytes
    /// of input. Splits the window write at the wrap boundary.
    fn emit_literal_bulk(&mut self, src: &[u8], output: &mut [u8], written: &mut usize) {
        let n = src.len();
        output[*written..*written + n].copy_from_slice(src);
        *written += n;
        // Window write: may need to split at wrap.
        let first = (WINDOW_SIZE - self.window_pos).min(n);
        self.window[self.window_pos..self.window_pos + first].copy_from_slice(&src[..first]);
        if first < n {
            let rem = n - first;
            self.window[..rem].copy_from_slice(&src[first..]);
        }
        self.window_pos = (self.window_pos + n) % WINDOW_SIZE;
        self.emitted += n as u64;
    }

    /// Bulk-copy `n` bytes from `distance` back. Caller must have
    /// verified `n <= distance` (non-overlapping) and `n` bytes of output
    /// room. Splits the read AND write at the wrap boundary.
    fn copy_match_bulk(&mut self, distance: u32, n: usize, output: &mut [u8], written: &mut usize) {
        let d = distance as usize;
        let src_idx = (self.window_pos + WINDOW_SIZE - d) % WINDOW_SIZE;
        // Source may wrap at WINDOW_SIZE.
        let src_first = (WINDOW_SIZE - src_idx).min(n);
        // Write into output (which is linear).
        output[*written..*written + src_first]
            .copy_from_slice(&self.window[src_idx..src_idx + src_first]);
        if src_first < n {
            let rem = n - src_first;
            output[*written + src_first..*written + n].copy_from_slice(&self.window[..rem]);
        }
        // Now copy those bytes back into the window at window_pos (may wrap).
        let dst_first = (WINDOW_SIZE - self.window_pos).min(n);
        // Read from the contiguous output we just wrote.
        let out_slice = &output[*written..*written + n];
        self.window[self.window_pos..self.window_pos + dst_first]
            .copy_from_slice(&out_slice[..dst_first]);
        if dst_first < n {
            let rem = n - dst_first;
            self.window[..rem].copy_from_slice(&out_slice[dst_first..]);
        }
        self.window_pos = (self.window_pos + n) % WINDOW_SIZE;
        *written += n;
        self.emitted += n as u64;
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
        let mut consumed = 0usize;
        let mut written = 0usize;

        loop {
            // Always drain any in-progress copy first; it needs output room.
            if let DecPhase::Copying {
                distance,
                remaining,
            } = self.phase
            {
                let mut rem = remaining;
                let out_room = output.len() - written;
                let chunk = (rem as usize).min(out_room);
                if chunk > 0 && (distance as usize) >= chunk {
                    // Non-overlapping: bulk-copy.
                    self.copy_match_bulk(distance, chunk, output, &mut written);
                    rem -= chunk as u16;
                }
                while rem > 0 {
                    if written == output.len() {
                        self.phase = DecPhase::Copying {
                            distance,
                            remaining: rem,
                        };
                        return Ok(RawProgress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                    let b = self.window_lookback(distance);
                    self.emit_byte(b, output, &mut written);
                    rem -= 1;
                }
                self.phase = DecPhase::Tag;
                continue;
            }

            // Literal run also wants output room (and input).
            if let DecPhase::Literal { remaining } = self.phase {
                let mut rem = remaining;
                let in_room = input.len() - consumed;
                let out_room = output.len() - written;
                let chunk = (rem as usize).min(in_room).min(out_room);
                if chunk > 0 {
                    let src = &input[consumed..consumed + chunk];
                    self.emit_literal_bulk(src, output, &mut written);
                    consumed += chunk;
                    rem -= chunk as u16;
                }
                if rem > 0 {
                    self.phase = DecPhase::Literal { remaining: rem };
                    return Ok(RawProgress {
                        consumed,
                        written,
                        done: false,
                    });
                }
                self.phase = DecPhase::Tag;
                continue;
            }

            // Need an input byte for anything else.
            if consumed == input.len() {
                return Ok(RawProgress {
                    consumed,
                    written,
                    done: false,
                });
            }

            match self.phase {
                DecPhase::Tag => {
                    let tag = input[consumed];
                    consumed += 1;
                    if tag & 0x80 != 0 {
                        // Raw literal run, 1..=128 bytes.
                        let len = ((tag & 0x7F) as u16) + 1;
                        self.phase = DecPhase::Literal { remaining: len };
                    } else if tag & 0x40 != 0 {
                        // Long match: length now, offset next 2 bytes BE.
                        let length = (tag & 0x3F) + 4; // 4..=67
                        self.phase = DecPhase::LongMatchOffHi { length };
                    } else {
                        // Short match: length and high offset now, low next byte.
                        let length = ((tag & 0x3C) >> 2) + 3; // 3..=18
                        let off_hi = tag & 0x03;
                        self.phase = DecPhase::ShortMatchOffLo { length, off_hi };
                    }
                }
                DecPhase::LongMatchOffHi { length } => {
                    let off_hi = input[consumed];
                    consumed += 1;
                    self.phase = DecPhase::LongMatchOffLo { length, off_hi };
                }
                DecPhase::LongMatchOffLo { length, off_hi } => {
                    let off_lo = input[consumed];
                    consumed += 1;
                    let offset = ((off_hi as u32) << 8) | (off_lo as u32);
                    let distance = offset + 1; // 1..=65536
                    if (distance as u64) > self.emitted {
                        self.poisoned = true;
                        return Err(Error::InvalidDistance);
                    }
                    self.phase = DecPhase::Copying {
                        distance,
                        remaining: length as u16,
                    };
                }
                DecPhase::ShortMatchOffLo { length, off_hi } => {
                    let off_lo = input[consumed];
                    consumed += 1;
                    let distance = (((off_hi as u32) << 8) | (off_lo as u32)) + 1;
                    if (distance as u64) > self.emitted {
                        self.poisoned = true;
                        return Err(Error::InvalidDistance);
                    }
                    self.phase = DecPhase::Copying {
                        distance,
                        remaining: length as u16,
                    };
                }
                DecPhase::Literal { .. } | DecPhase::Copying { .. } => {
                    // Already handled above.
                    debug_assert!(false, "should have been handled at top of loop");
                }
            }
        }
    }

    fn raw_finish(&mut self, output: &mut [u8]) -> Result<RawProgress, Error> {
        if self.poisoned {
            return Err(Error::Corrupt);
        }
        let mut written = 0usize;

        // Drain any in-flight copy.
        if let DecPhase::Copying {
            distance,
            remaining,
        } = self.phase
        {
            let mut rem = remaining;
            let out_room = output.len() - written;
            let chunk = (rem as usize).min(out_room);
            if chunk > 0 && (distance as usize) >= chunk {
                self.copy_match_bulk(distance, chunk, output, &mut written);
                rem -= chunk as u16;
            }
            while rem > 0 {
                if written == output.len() {
                    self.phase = DecPhase::Copying {
                        distance,
                        remaining: rem,
                    };
                    return Ok(RawProgress {
                        consumed: 0,
                        written,
                        done: false,
                    });
                }
                let b = self.window_lookback(distance);
                self.emit_byte(b, output, &mut written);
                rem -= 1;
            }
            self.phase = DecPhase::Tag;
        }

        match self.phase {
            DecPhase::Tag => Ok(RawProgress {
                consumed: 0,
                written,
                done: true,
            }),
            DecPhase::Literal { .. }
            | DecPhase::LongMatchOffHi { .. }
            | DecPhase::LongMatchOffLo { .. }
            | DecPhase::ShortMatchOffLo { .. } => Err(Error::UnexpectedEnd),
            DecPhase::Copying { .. } => Ok(RawProgress {
                consumed: 0,
                written,
                done: false,
            }),
        }
    }

    fn raw_reset(&mut self) {
        // Zero the window so a fresh stream cannot accidentally lookback
        // into the previous run's data.
        for b in self.window.iter_mut() {
            *b = 0;
        }
        self.window_pos = 0;
        self.emitted = 0;
        self.phase = DecPhase::Tag;
        self.poisoned = false;
    }
}
