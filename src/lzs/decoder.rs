//! Streaming decoder for the RFC 1974 LZS bitstream.

use alloc::vec::Vec;

use crate::error::Error;
use crate::traits::{RawDecoder, RawProgress};

use super::MAX_DISTANCE;
use super::bits::BitReader;

/// Hard cap on a single match length. RFC 1974 places no upper limit
/// (the chained `1111` length code is open-ended), but a single match
/// longer than 16 MiB is overwhelmingly likely to be a corrupt or
/// adversarial stream — reject it rather than allocate.
const SANITY_MATCH_LEN: u32 = 1 << 24;

/// Header-parse phase.
#[derive(Clone, Copy, PartialEq, Eq)]
enum HeaderPhase {
    Reading { idx: u8 },
    Active { target: u64 },
    Done,
}

/// Pending match copy that didn't fit in the previous call's `output`.
#[derive(Debug, Clone, Copy)]
struct PendingMatch {
    distance: u32,
    remaining: u32,
}

/// Streaming decoder for LZS (with our 8-byte length-prefix framing).
pub struct Decoder {
    header_buf: [u8; 8],
    header: HeaderPhase,

    bits: BitReader,

    /// Output history for back-references. Kept ≤ 2 × MAX_DISTANCE by
    /// periodic trimming.
    history: Vec<u8>,
    produced: u64,

    pending_literal: Option<u8>,
    pending_match: Option<PendingMatch>,

    /// Whether we've seen the end-of-stream marker yet.
    saw_eos: bool,
    /// Poison flag: once we returned `Err(_)` we refuse further work
    /// until reset.
    poisoned: bool,
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder {
    pub fn new() -> Self {
        Self {
            header_buf: [0; 8],
            header: HeaderPhase::Reading { idx: 0 },
            bits: BitReader::new(),
            history: Vec::new(),
            produced: 0,
            pending_literal: None,
            pending_match: None,
            saw_eos: false,
            poisoned: false,
        }
    }

    /// Trim `history` to keep at most `2 * MAX_DISTANCE` recent bytes.
    fn trim_history(&mut self) {
        if self.history.len() > 2 * MAX_DISTANCE {
            let drop = self.history.len() - MAX_DISTANCE;
            self.history.drain(0..drop);
        }
    }

    fn emit_byte(&mut self, byte: u8, output: &mut [u8], written: &mut usize) {
        self.history.push(byte);
        output[*written] = byte;
        *written += 1;
        self.produced += 1;
    }

    /// Try to read one variable-length length code starting from the
    /// current bit position. Returns `None` if more bits are needed.
    ///
    /// On success returns the decoded length value (≥ 2).
    fn try_read_length(&mut self) -> Result<Option<u32>, Error> {
        // First 2 bits.
        let snap = self.bits.snapshot();
        let b0 = match self.bits.read_bits(2) {
            Some(v) => v,
            None => {
                self.bits.restore(snap);
                return Ok(None);
            }
        };
        match b0 {
            0b00 => Ok(Some(2)),
            0b01 => Ok(Some(3)),
            0b10 => Ok(Some(4)),
            0b11 => {
                // Need 2 more bits.
                let b1 = match self.bits.read_bits(2) {
                    Some(v) => v,
                    None => {
                        self.bits.restore(snap);
                        return Ok(None);
                    }
                };
                match b1 {
                    0b00 => Ok(Some(5)),
                    0b01 => Ok(Some(6)),
                    0b10 => Ok(Some(7)),
                    0b11 => {
                        // Chain: read nibbles until one is != 1111. Each
                        // 1111 adds 15. A single match can legitimately be as
                        // long as the whole declared output (highly repetitive
                        // input compresses to one long back-reference), so bound
                        // the accumulator by the declared total length rather
                        // than a fixed constant — otherwise valid streams whose
                        // longest match exceeds ~16 MiB are wrongly rejected.
                        let cap = match self.header {
                            HeaderPhase::Active { target } => target.min(u32::MAX as u64) as u32,
                            _ => SANITY_MATCH_LEN,
                        };
                        let mut acc: u32 = 8;
                        loop {
                            let nib = match self.bits.read_bits(4) {
                                Some(v) => v,
                                None => {
                                    self.bits.restore(snap);
                                    return Ok(None);
                                }
                            };
                            if nib != 0b1111 {
                                acc = match acc.checked_add(nib) {
                                    Some(v) => v,
                                    None => return Err(Error::Corrupt),
                                };
                                return Ok(Some(acc));
                            }
                            acc = match acc.checked_add(15) {
                                Some(v) => v,
                                None => return Err(Error::Corrupt),
                            };
                            if acc > cap {
                                return Err(Error::Corrupt);
                            }
                        }
                    }
                    _ => unreachable!(),
                }
            }
            _ => unreachable!(),
        }
    }

    /// Main decode loop. Drains as much as possible into `output`.
    ///
    /// `at_eof` is `true` when called from `raw_finish` — in that mode
    /// any short read is reported as `UnexpectedEnd` (unless we've
    /// already seen the end-of-stream marker).
    fn drain(&mut self, output: &mut [u8], written: &mut usize, at_eof: bool) -> Result<(), Error> {
        let target = match self.header {
            HeaderPhase::Active { target } => target,
            HeaderPhase::Done => return Ok(()),
            HeaderPhase::Reading { .. } => return Ok(()),
        };

        loop {
            if self.produced >= target && self.saw_eos {
                self.header = HeaderPhase::Done;
                return Ok(());
            }

            // 1. Pending literal.
            if let Some(b) = self.pending_literal.take() {
                if self.produced >= target {
                    return Err(Error::TrailerMismatch);
                }
                if *written == output.len() {
                    self.pending_literal = Some(b);
                    return Ok(());
                }
                self.emit_byte(b, output, written);
                self.trim_history();
                continue;
            }

            // 2. Pending match.
            if let Some(mut pm) = self.pending_match.take() {
                while pm.remaining > 0 && *written < output.len() {
                    if self.produced >= target {
                        return Err(Error::TrailerMismatch);
                    }
                    if (pm.distance as usize) > self.history.len() {
                        return Err(Error::InvalidDistance);
                    }
                    let src = self.history.len() - pm.distance as usize;
                    let byte = self.history[src];
                    self.emit_byte(byte, output, written);
                    pm.remaining -= 1;
                }
                self.trim_history();
                if pm.remaining > 0 {
                    self.pending_match = Some(pm);
                    return Ok(());
                }
                continue;
            }

            if self.saw_eos {
                // End-of-stream marker already consumed. We've drained
                // any pending output above; per the spec the decoded
                // length should match what the producer wrote, but our
                // framing carries an explicit length header so we
                // cross-check it.
                if self.produced != target {
                    return Err(Error::TrailerMismatch);
                }
                self.header = HeaderPhase::Done;
                return Ok(());
            }

            // 3. Read next token. Snapshot so we can roll back on
            // partial reads.
            let snap = self.bits.snapshot();
            let lead = match self.bits.read_bits(1) {
                Some(v) => v,
                None => {
                    if at_eof {
                        return Err(Error::UnexpectedEnd);
                    }
                    self.bits.restore(snap);
                    return Ok(());
                }
            };

            if lead == 0 {
                // Literal byte: 8 bits follow.
                let byte = match self.bits.read_bits(8) {
                    Some(v) => v,
                    None => {
                        if at_eof {
                            return Err(Error::UnexpectedEnd);
                        }
                        self.bits.restore(snap);
                        return Ok(());
                    }
                };
                self.bits.compact();
                if self.produced >= target {
                    return Err(Error::TrailerMismatch);
                }
                if *written == output.len() {
                    self.pending_literal = Some(byte as u8);
                    return Ok(());
                }
                self.emit_byte(byte as u8, output, written);
                self.trim_history();
                continue;
            }

            // Match: read offset-prefix bit.
            let offset_kind = match self.bits.read_bits(1) {
                Some(v) => v,
                None => {
                    if at_eof {
                        return Err(Error::UnexpectedEnd);
                    }
                    self.bits.restore(snap);
                    return Ok(());
                }
            };

            // `11` → 7-bit offset; `10` → 11-bit offset.
            let (offset_width, is_short) = if offset_kind == 1 {
                (7u32, true)
            } else {
                (11u32, false)
            };

            let offset = match self.bits.read_bits(offset_width) {
                Some(v) => v,
                None => {
                    if at_eof {
                        return Err(Error::UnexpectedEnd);
                    }
                    self.bits.restore(snap);
                    return Ok(());
                }
            };

            if is_short && offset == 0 {
                // End-of-stream marker: `110000000`. The remaining bits
                // (up to 7) in the current byte are padding `1`s — but
                // we don't actually need to consume them; the framing
                // header already told us the decompressed length.
                self.saw_eos = true;
                self.bits.compact();
                continue;
            }

            if offset == 0 {
                // Long-offset 0 is reserved/invalid in RFC 1974 § 2.
                return Err(Error::InvalidDistance);
            }

            // Length code.
            let length = match self.try_read_length()? {
                Some(v) => v,
                None => {
                    if at_eof {
                        return Err(Error::UnexpectedEnd);
                    }
                    self.bits.restore(snap);
                    return Ok(());
                }
            };

            if length < 2 {
                return Err(Error::Corrupt);
            }
            if (offset as u64) > self.produced {
                return Err(Error::InvalidDistance);
            }
            if offset as usize > MAX_DISTANCE {
                return Err(Error::InvalidDistance);
            }

            self.bits.compact();
            let mut pm = PendingMatch {
                distance: offset,
                remaining: length,
            };
            while pm.remaining > 0 && *written < output.len() {
                // A match must not push `produced` past the declared
                // `target`: doing so would deliver more bytes than the
                // framing header promised. Detect it here rather than
                // deferring to the EOS cross-check.
                if self.produced >= target {
                    return Err(Error::TrailerMismatch);
                }
                if (pm.distance as usize) > self.history.len() {
                    return Err(Error::InvalidDistance);
                }
                let src = self.history.len() - pm.distance as usize;
                let byte = self.history[src];
                self.emit_byte(byte, output, written);
                pm.remaining -= 1;
            }
            self.trim_history();
            if pm.remaining > 0 {
                self.pending_match = Some(pm);
                return Ok(());
            }
        }
    }
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
                // Empty stream: caller still owes us the end-of-stream
                // marker plus padding, but we don't need to consume any
                // payload to decode zero bytes. Skip straight to Done
                // and tolerate any trailing padding the producer wrote.
                HeaderPhase::Done
            } else {
                HeaderPhase::Active { target }
            };
        }

        // 2. Absorb remaining input into the bit reader.
        self.bits.push_bytes(&input[consumed..]);
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

        if !done {
            // We weren't able to finish. Either we still have pending
            // copy work and the output buffer was just too small (in
            // which case `written > 0` or the buffer was empty), or the
            // stream was genuinely truncated.
            if self.pending_match.is_none()
                && self.pending_literal.is_none()
                && written == 0
                && !output.is_empty()
            {
                self.poisoned = true;
                return Err(Error::UnexpectedEnd);
            }
        }

        if matches!(self.header, HeaderPhase::Reading { idx } if idx > 0) {
            // Partial header.
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
        self.bits.clear();
        self.history.clear();
        self.produced = 0;
        self.pending_literal = None;
        self.pending_match = None;
        self.saw_eos = false;
        self.poisoned = false;
    }
}
