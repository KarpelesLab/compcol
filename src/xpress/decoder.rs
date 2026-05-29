//! Streaming decoder for the Plain LZ77 codec.

use alloc::vec::Vec;

use crate::error::Error;
use crate::traits::{RawDecoder, RawProgress};

use super::MAX_DISTANCE;

/// Cap on the size of any single match-length tier-4 read. Used as the
/// upper bound for the validated `w`/`dw` "raw length" field.
///
/// Matches don't have a hard maximum in the spec, but anything beyond a
/// few MB in a single match is a strong corruption signal and lets us
/// reject obviously-broken streams without allocating gigabytes.
const SANITY_MATCH_LEN: u32 = 1 << 28;

/// Two-stage assembly state for the framing header.
#[derive(Clone, Copy, PartialEq, Eq)]
enum HeaderPhase {
    /// Collecting the 8-byte little-endian uncompressed-size prefix.
    Reading { idx: u8 },
    /// Header consumed; main decode loop active. The `target` is the
    /// total decompressed byte count we will produce.
    Active { target: u64 },
    /// Target reached, stream complete.
    Done,
}

/// Streaming decoder for Plain LZ77 (with our 8-byte length-prefix
/// framing).
pub struct Decoder {
    /// 8-byte header buffer being assembled.
    header_buf: [u8; 8],
    header: HeaderPhase,

    /// Compressed input buffer. Bytes accumulate here until the decoder
    /// can make progress; the front prefix is dropped once the spec
    /// guarantees they cannot be revisited.
    buf: Vec<u8>,
    /// Read cursor into `buf`. Compacted periodically so it doesn't grow
    /// without bound.
    pos: usize,

    /// Output history (last 8 KiB) for back-references. Implemented as
    /// a `Vec<u8>` of all produced bytes; we slice the tail when a copy
    /// is requested.
    out_history: Vec<u8>,
    /// Total bytes produced and delivered. Tracked separately from
    /// `out_history.len()` because we periodically trim the head.
    produced: u64,

    /// Current 32-bit flag DWORD, **left-aligned**: bit 31 is the next
    /// flag to consume; we shift left by 1 after each consumption. The
    /// `has_flags` count tracks how many of the original 32 bits remain
    /// in `flags`.
    flags: u32,
    flag_bits_left: u8,

    /// Pending match copy that didn't fit in the previous call's
    /// `output` slice.
    pending_match: Option<PendingMatch>,
    /// Pending literal byte that didn't fit in the previous call's
    /// `output`.
    pending_literal: Option<u8>,

    /// Half-byte state for tier-2 length extension. When the decoder
    /// reads a half-byte and the owning byte still has an unused upper
    /// nibble, the byte's offset within `buf` (relative to its start at
    /// the time of read) is captured here. Subsequent half-byte reads
    /// pull from that byte's high nibble.
    ///
    /// The pointer is stored as an absolute "produced output position"
    /// equivalent — we use a token: when a half-byte is owed, we keep
    /// the actual byte value alongside it. This sidesteps the "buf got
    /// compacted under us" risk.
    half_byte: Option<u8>,

    /// Poison flag: once we returned `Err(_)` we refuse further work
    /// until reset.
    poisoned: bool,
}

#[derive(Debug, Clone, Copy)]
struct PendingMatch {
    /// Back-reference distance (1..=8192).
    distance: u32,
    /// Bytes still to emit for the in-flight match.
    remaining: u32,
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder {
    pub const fn new() -> Self {
        Self {
            header_buf: [0; 8],
            header: HeaderPhase::Reading { idx: 0 },
            buf: Vec::new(),
            pos: 0,
            out_history: Vec::new(),
            produced: 0,
            flags: 0,
            flag_bits_left: 0,
            pending_match: None,
            pending_literal: None,
            half_byte: None,
            poisoned: false,
        }
    }

    /// Drop the prefix of `buf` that has already been consumed once it
    /// has grown past the compaction threshold. Keeps `pos` consistent
    /// with the rebased buffer.
    fn compact_buf(&mut self) {
        // 64 KiB threshold mirrors the rationale in `src/lzma/mod.rs`:
        // small `drain(0..N)`s on every step degrade to O(N^2) on long
        // streams; defer until amortised.
        const THRESHOLD: usize = 64 * 1024;
        if self.pos >= THRESHOLD {
            self.buf.drain(0..self.pos);
            self.pos = 0;
        }
    }

    /// Drop the head of `out_history` once it has grown past 2 *
    /// MAX_DISTANCE, so it never exceeds ~16 KiB. Back-references can
    /// only ever look 8 KiB back, so anything past that is dead weight.
    fn trim_history(&mut self) {
        if self.out_history.len() > 2 * MAX_DISTANCE {
            let drop = self.out_history.len() - MAX_DISTANCE;
            self.out_history.drain(0..drop);
        }
    }

    /// Emit a single byte to both `out_history` and the caller's buffer.
    fn emit_byte(&mut self, byte: u8, output: &mut [u8], written: &mut usize) {
        self.out_history.push(byte);
        output[*written] = byte;
        *written += 1;
        self.produced += 1;
    }

    /// Available bytes from `buf[self.pos..]`.
    #[inline]
    fn buf_avail(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// Peek a 16-bit little-endian word starting `offset` bytes past
    /// `self.pos`. Returns `None` if not enough buffered.
    #[inline]
    fn peek_u16(&self, offset: usize) -> Option<u16> {
        if self.pos + offset + 2 > self.buf.len() {
            return None;
        }
        Some(u16::from_le_bytes([
            self.buf[self.pos + offset],
            self.buf[self.pos + offset + 1],
        ]))
    }

    /// Peek a 32-bit little-endian word starting `offset` bytes past
    /// `self.pos`. Returns `None` if not enough buffered.
    #[inline]
    fn peek_u32(&self, offset: usize) -> Option<u32> {
        if self.pos + offset + 4 > self.buf.len() {
            return None;
        }
        Some(u32::from_le_bytes([
            self.buf[self.pos + offset],
            self.buf[self.pos + offset + 1],
            self.buf[self.pos + offset + 2],
            self.buf[self.pos + offset + 3],
        ]))
    }
}

/// Half-byte slot mutation after consuming a length field.
enum HalfByteOp {
    /// No half-byte was touched (no tier-2 read happened).
    Unchanged,
    /// We consumed the existing slot.
    Clear,
    /// We read a new owner byte and parked its high nibble for the
    /// next long match.
    Set(u8),
}

impl Decoder {
    /// Apply a `HalfByteOp` to `self.half_byte`.
    fn apply_half_byte_op(&mut self, op: HalfByteOp) {
        match op {
            HalfByteOp::Unchanged => {}
            HalfByteOp::Clear => self.half_byte = None,
            HalfByteOp::Set(high) => self.half_byte = Some(high),
        }
    }

    /// Main decode loop. Drains as much as it can into `output` and
    /// returns once either: the output is full, more input is needed,
    /// or the target decompressed size is reached.
    ///
    /// `at_eof` is `true` when called from `raw_finish` and disables
    /// the tier-1 "need 2 bytes for sym" precheck — instead, any short
    /// read returns `UnexpectedEnd`.
    fn drain(&mut self, output: &mut [u8], written: &mut usize, at_eof: bool) -> Result<(), Error> {
        let target = match self.header {
            HeaderPhase::Active { target } => target,
            HeaderPhase::Done => return Ok(()),
            HeaderPhase::Reading { .. } => return Ok(()),
        };

        loop {
            // Stop if we've hit the target.
            if self.produced >= target {
                self.header = HeaderPhase::Done;
                return Ok(());
            }

            // 1. Drain any pending literal first.
            if let Some(b) = self.pending_literal.take() {
                if *written == output.len() {
                    self.pending_literal = Some(b);
                    return Ok(());
                }
                self.emit_byte(b, output, written);
                self.trim_history();
                if self.produced >= target {
                    self.header = HeaderPhase::Done;
                    return Ok(());
                }
                continue;
            }

            // 2. Drain any pending match.
            if let Some(mut pm) = self.pending_match.take() {
                while pm.remaining > 0 && *written < output.len() {
                    if (pm.distance as usize) > self.out_history.len() {
                        return Err(Error::InvalidDistance);
                    }
                    let src = self.out_history.len() - pm.distance as usize;
                    let b = self.out_history[src];
                    self.emit_byte(b, output, written);
                    pm.remaining -= 1;
                    if self.produced >= target {
                        // Match should not over-shoot target on valid
                        // streams; if it did the producer was buggy. We
                        // clamp silently and return.
                        self.header = HeaderPhase::Done;
                        return Ok(());
                    }
                }
                self.trim_history();
                if pm.remaining > 0 {
                    self.pending_match = Some(pm);
                    return Ok(());
                }
                continue;
            }

            // 3. Need a fresh flag DWORD?
            if self.flag_bits_left == 0 {
                if self.buf_avail() < 4 {
                    if at_eof {
                        return Err(Error::UnexpectedEnd);
                    }
                    return Ok(());
                }
                let f = self.peek_u32(0).expect("peek bounded by buf_avail check");
                self.flags = f;
                self.flag_bits_left = 32;
                self.pos += 4;
                self.compact_buf();
            }

            // 4. Inspect the top flag bit.
            let bit = self.flags & 0x8000_0000 != 0;
            // Don't shift / decrement yet — only after the symbol is
            // fully consumed so a partial read can be retried.

            if !bit {
                // Literal byte.
                if self.buf_avail() < 1 {
                    if at_eof {
                        return Err(Error::UnexpectedEnd);
                    }
                    return Ok(());
                }
                let b = self.buf[self.pos];
                self.pos += 1;
                self.compact_buf();
                self.flags <<= 1;
                self.flag_bits_left -= 1;
                if *written == output.len() {
                    self.pending_literal = Some(b);
                    return Ok(());
                }
                self.emit_byte(b, output, written);
                self.trim_history();
                if self.produced >= target {
                    self.header = HeaderPhase::Done;
                    return Ok(());
                }
                continue;
            }

            // Match symbol — try to decode it fully before committing.
            if self.buf_avail() < 2 {
                if at_eof {
                    return Err(Error::UnexpectedEnd);
                }
                return Ok(());
            }
            let sym = self.peek_u16(0).expect("buf_avail >= 2 checked");
            let distance = ((u32::from(sym) >> 3) + 1) as usize;
            let lc = u32::from(sym & 0x7);

            // Try to read the (potentially extended) length field.
            // Operates on a temporary cursor `self.pos + 2` virtually —
            // try_read_length is relative to (pos), so we need to slide
            // the half-byte read past the 2 sym bytes. We do that by
            // pretending we already consumed the sym for the length
            // read by calling try_read_length on a sub-view.

            // The cleanest approach is to bias `self.pos` temporarily,
            // but try_read_length takes &self. Implement the read by
            // explicit indices instead.
            let sym_consumed = 2usize;
            let (length, len_consumed, hb_op) =
                match try_read_length_at(self, self.pos + sym_consumed, lc)? {
                    Some(v) => v,
                    None => {
                        if at_eof {
                            return Err(Error::UnexpectedEnd);
                        }
                        return Ok(());
                    }
                };

            // Validate the match.
            if length < 3 {
                // Shouldn't happen — base_lc == 0..6 produces length
                // 3..9; tier 2+ produce length >= 10 (or >= 25 in tier 3
                // and >= w-22 in tier 4 where w >= 22). Belt-and-braces.
                return Err(Error::Corrupt);
            }
            if distance > MAX_DISTANCE {
                return Err(Error::InvalidDistance);
            }
            if (distance as u64) > self.produced {
                return Err(Error::InvalidDistance);
            }

            // Commit.
            self.pos += sym_consumed + len_consumed;
            self.compact_buf();
            self.apply_half_byte_op(hb_op);
            self.flags <<= 1;
            self.flag_bits_left -= 1;

            // Emit as a pending match.
            let mut pm = PendingMatch {
                distance: distance as u32,
                remaining: length,
            };
            while pm.remaining > 0 && *written < output.len() {
                if (pm.distance as usize) > self.out_history.len() {
                    return Err(Error::InvalidDistance);
                }
                let src = self.out_history.len() - pm.distance as usize;
                let b = self.out_history[src];
                self.emit_byte(b, output, written);
                pm.remaining -= 1;
                if self.produced >= target {
                    self.header = HeaderPhase::Done;
                    return Ok(());
                }
            }
            self.trim_history();
            if pm.remaining > 0 {
                self.pending_match = Some(pm);
                return Ok(());
            }
        }
    }
}

/// Free function variant of `try_read_length` that operates at an
/// arbitrary absolute buffer offset. Useful when reading the length
/// **after** a 2-byte sym — the half-byte read for tier 2 must come
/// from `pos + 2`, not `pos`.
fn try_read_length_at(
    dec: &Decoder,
    start: usize,
    base_lc: u32,
) -> Result<Option<(u32, usize, HalfByteOp)>, Error> {
    if base_lc < 7 {
        return Ok(Some((base_lc + 3, 0, HalfByteOp::Unchanged)));
    }

    let avail = dec.buf.len().saturating_sub(start);

    // Tier 2: half-byte.
    let (hb, hb_consumed, hb_op) = match dec.half_byte {
        Some(b) => (u32::from(b), 0, HalfByteOp::Clear),
        None => {
            if avail < 1 {
                return Ok(None);
            }
            let b = dec.buf[start];
            let low = u32::from(b & 0x0F);
            let high = b >> 4;
            (low, 1, HalfByteOp::Set(high))
        }
    };

    if hb < 15 {
        return Ok(Some((hb + 10, hb_consumed, hb_op)));
    }

    if avail < hb_consumed + 1 {
        return Ok(None);
    }
    let b8 = dec.buf[start + hb_consumed];
    if b8 < 255 {
        return Ok(Some((u32::from(b8) + 25, hb_consumed + 1, hb_op)));
    }

    if avail < hb_consumed + 1 + 2 {
        return Ok(None);
    }
    let w = u32::from(u16::from_le_bytes([
        dec.buf[start + hb_consumed + 1],
        dec.buf[start + hb_consumed + 2],
    ]));
    if w != 0 {
        // The reference decoder rejects `w < 22` because the cumulative
        // bias chain (`-22 + 15 + 7 + 3`) would otherwise overflow to
        // a length below 25 (the tier-3 minimum). After the bias
        // adjustments the actual match length is `w + 3`.
        if w < 22 {
            return Err(Error::Corrupt);
        }
        return Ok(Some((w + 3, hb_consumed + 1 + 2, hb_op)));
    }

    if avail < hb_consumed + 1 + 2 + 4 {
        return Ok(None);
    }
    let dw = u32::from_le_bytes([
        dec.buf[start + hb_consumed + 1 + 2],
        dec.buf[start + hb_consumed + 1 + 2 + 1],
        dec.buf[start + hb_consumed + 1 + 2 + 2],
        dec.buf[start + hb_consumed + 1 + 2 + 3],
    ]);
    if dw < 22 {
        return Err(Error::Corrupt);
    }
    if dw > SANITY_MATCH_LEN {
        return Err(Error::Corrupt);
    }
    Ok(Some((dw + 3, hb_consumed + 1 + 2 + 4, hb_op)))
}

impl RawDecoder for Decoder {
    fn raw_decode(&mut self, input: &[u8], output: &mut [u8]) -> Result<RawProgress, Error> {
        if self.poisoned {
            return Err(Error::Corrupt);
        }
        let mut written = 0usize;
        let mut consumed = 0usize;

        // 1. Header.
        if let HeaderPhase::Reading { mut idx } = self.header {
            while idx < 8 && consumed < input.len() {
                self.header_buf[idx as usize] = input[consumed];
                idx += 1;
                consumed += 1;
            }
            if idx < 8 {
                self.header = HeaderPhase::Reading { idx };
                return Ok(RawProgress {
                    consumed,
                    written,
                    done: false,
                });
            }
            let target = u64::from_le_bytes(self.header_buf);
            self.header = if target == 0 {
                HeaderPhase::Done
            } else {
                HeaderPhase::Active { target }
            };
        }

        // 2. Buffer the rest of `input` into `self.buf`. We absorb it
        //    eagerly — `drain` decides what to actually consume.
        self.buf.extend_from_slice(&input[consumed..]);
        consumed = input.len();

        // 3. Drain.
        if let HeaderPhase::Active { .. } = self.header
            && let Err(e) = self.drain(output, &mut written, false)
        {
            self.poisoned = true;
            return Err(e);
        }

        let done = matches!(self.header, HeaderPhase::Done);

        Ok(RawProgress {
            consumed,
            written,
            done,
        })
    }

    fn raw_finish(&mut self, output: &mut [u8]) -> Result<RawProgress, Error> {
        if self.poisoned {
            return Err(Error::Corrupt);
        }
        let mut written = 0usize;

        if let HeaderPhase::Active { .. } = self.header
            && let Err(e) = self.drain(output, &mut written, true)
        {
            self.poisoned = true;
            return Err(e);
        }

        let done = matches!(self.header, HeaderPhase::Done);
        if !done && self.pending_match.is_none() && self.pending_literal.is_none() {
            // Output buffer had room but we still aren't done — the
            // stream was truncated. The only legitimate "not done" case
            // here is when output is genuinely full.
            if written == 0 && !output.is_empty() {
                self.poisoned = true;
                return Err(Error::UnexpectedEnd);
            }
        }
        // Reading-header-with-zero-bytes-so-far is also a truncated
        // stream when finish is called.
        if matches!(self.header, HeaderPhase::Reading { idx } if idx > 0) {
            // Partial header — definite truncation.
            self.poisoned = true;
            return Err(Error::UnexpectedEnd);
        }
        Ok(RawProgress {
            consumed: 0,
            written,
            done,
        })
    }

    fn raw_reset(&mut self) {
        self.header_buf = [0; 8];
        self.header = HeaderPhase::Reading { idx: 0 };
        self.buf.clear();
        self.pos = 0;
        self.out_history.clear();
        self.produced = 0;
        self.flags = 0;
        self.flag_bits_left = 0;
        self.pending_match = None;
        self.pending_literal = None;
        self.half_byte = None;
        self.poisoned = false;
    }
}
