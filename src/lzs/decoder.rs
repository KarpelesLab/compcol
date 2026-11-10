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

/// A match whose length code entered the open-ended `1111` chain but has
/// not yet seen its closing nibble. The nibbles read so far are committed
/// (never re-read), so the running total lives here across calls.
#[derive(Debug, Clone, Copy)]
struct PendingLength {
    distance: u32,
    /// Length accumulated so far (the initial 8 plus 15 per `1111`).
    acc: u32,
}

/// Outcome of reading the fixed-size head of a length code.
enum LengthHead {
    /// A complete short code: the length is known.
    Complete(u32),
    /// `1111`: the open-ended nibble chain follows.
    Extended,
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
    /// Set while the length-extension chain of a match is being read.
    pending_length: Option<PendingLength>,

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
            pending_length: None,
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

    /// Read the fixed-size head (2 or 4 bits) of a length code. Returns
    /// `None` if more bits are needed; the caller rolls the bit cursor
    /// back to the token start in that case (the head is at most 4 bits,
    /// so the rewind is bounded).
    fn try_read_length_head(&mut self) -> Option<LengthHead> {
        let b0 = self.bits.read_bits(2)?;
        if b0 != 0b11 {
            // `00` → 2, `01` → 3, `10` → 4.
            return Some(LengthHead::Complete(b0 + 2));
        }
        let b1 = self.bits.read_bits(2)?;
        if b1 != 0b11 {
            // `1100` → 5, `1101` → 6, `1110` → 7.
            return Some(LengthHead::Complete(b1 + 5));
        }
        Some(LengthHead::Extended)
    }

    /// Continue the `1111` nibble chain of `self.pending_length`. Each
    /// `1111` adds 15; the first other nibble adds its value and ends the
    /// code. Returns the match `(distance, length)`, or `None` if more
    /// bits are needed — in which case every nibble read so far stays
    /// consumed and the running total is kept in `self.pending_length`,
    /// so no input bit is read twice however the token is split across
    /// calls.
    ///
    /// A single match can legitimately be as long as the whole declared
    /// output (highly repetitive input compresses to one long
    /// back-reference), so the accumulator is bounded by the declared
    /// total length rather than a fixed constant — otherwise valid streams
    /// whose longest match exceeds ~16 MiB are wrongly rejected.
    fn try_read_length_chain(&mut self) -> Result<Option<(u32, u32)>, Error> {
        let Some(mut pl) = self.pending_length else {
            return Err(Error::Corrupt);
        };
        let cap = match self.header {
            HeaderPhase::Active { target } => target.min(u32::MAX as u64) as u32,
            _ => SANITY_MATCH_LEN,
        };
        loop {
            let Some(nib) = self.bits.read_bits(4) else {
                self.pending_length = Some(pl);
                // Everything before the cursor is committed: let the
                // reader drop it instead of pinning the whole token.
                self.bits.compact();
                return Ok(None);
            };
            if nib != 0b1111 {
                self.pending_length = None;
                return match pl.acc.checked_add(nib) {
                    Some(len) => Ok(Some((pl.distance, len))),
                    None => Err(Error::Corrupt),
                };
            }
            pl.acc = match pl.acc.checked_add(15) {
                Some(v) => v,
                None => return Err(Error::Corrupt),
            };
            if pl.acc > cap {
                return Err(Error::Corrupt);
            }
        }
    }

    /// Validate a fully-parsed match token and queue it as the pending
    /// match; the main loop copies it out, enforcing the declared length
    /// as it goes.
    fn start_match(&mut self, offset: u32, length: u32) -> Result<(), Error> {
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
        self.pending_match = Some(PendingMatch {
            distance: offset,
            remaining: length,
        });
        Ok(())
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

            // 3. A match whose length chain was cut short by the end of
            // the previous input: resume it where it stopped.
            if self.pending_length.is_some() {
                match self.try_read_length_chain()? {
                    Some((offset, length)) => {
                        self.start_match(offset, length)?;
                        continue;
                    }
                    None => {
                        if at_eof {
                            return Err(Error::UnexpectedEnd);
                        }
                        return Ok(());
                    }
                }
            }

            // 4. Read next token. Snapshot so we can roll back on
            // partial reads. Only the fixed-size part of a token (at most
            // 17 bits: flag, offset prefix, offset, length head) is ever
            // rolled back; the open-ended length chain is resumable.
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

            // Length code. A complete match is queued as the pending
            // match and copied out by step 2 on the next iteration.
            match self.try_read_length_head() {
                Some(LengthHead::Complete(length)) => {
                    self.start_match(offset, length)?;
                }
                Some(LengthHead::Extended) => {
                    // Commit the token head and switch to the resumable
                    // chain; step 3 reads it on the next iteration.
                    self.pending_length = Some(PendingLength {
                        distance: offset,
                        acc: 8,
                    });
                }
                None => {
                    if at_eof {
                        return Err(Error::UnexpectedEnd);
                    }
                    self.bits.restore(snap);
                    return Ok(());
                }
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
        self.pending_length = None;
        self.saw_eos = false;
        self.poisoned = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lzs::bits::BitWriter;
    use alloc::vec;

    /// `'A'`, then one match at distance 1 whose length code is `1111`
    /// followed by `k` more `1111` nibbles and a closing `0000`, then the
    /// end-of-stream marker. Decodes to `9 + 15 * k` bytes of `'A'`.
    fn long_token_stream(k: usize) -> (Vec<u8>, u64) {
        let total = 9 + 15 * k as u64;
        let mut w = BitWriter::new();
        w.write_bits(1, 0);
        w.write_bits(8, b'A' as u32);
        w.write_bits(2, 0b11);
        w.write_bits(7, 1);
        w.write_bits(4, 0b1111);
        for _ in 0..k {
            w.write_bits(4, 0b1111);
        }
        w.write_bits(4, 0);
        w.write_bits(9, 0b1_1000_0000);
        w.pad_with_ones_to_byte();
        let mut stream = total.to_le_bytes().to_vec();
        stream.extend_from_slice(&w.into_bytes());
        (stream, total)
    }

    /// Decode `stream` feeding `chunk` bytes per call. Returns the number
    /// of decoded bytes (asserting they are all `'A'`), the number of
    /// `raw_decode` calls, the peak number of bytes held by the bit
    /// reader, and the decoder for inspection.
    fn decode_all_a(stream: &[u8], chunk: usize) -> (u64, u64, usize, Decoder) {
        let mut dec = Decoder::new();
        let mut out = vec![0u8; 64 * 1024];
        let mut total = 0u64;
        let mut calls = 0u64;
        let mut peak = 0usize;
        let mut done = false;
        for piece in stream.chunks(chunk) {
            let mut input = piece;
            loop {
                let p = dec.raw_decode(input, &mut out).unwrap();
                calls += 1;
                peak = peak.max(dec.bits.buffered_bytes());
                assert_eq!(p.consumed, input.len());
                input = &[];
                assert!(out[..p.written].iter().all(|&b| b == b'A'));
                total += p.written as u64;
                done = p.done;
                if p.written < out.len() {
                    break;
                }
            }
        }
        while !done {
            let p = dec.raw_finish(&mut out).unwrap();
            assert!(out[..p.written].iter().all(|&b| b == b'A'));
            total += p.written as u64;
            done = p.done;
        }
        (total, calls, peak, dec)
    }

    /// A long extended-length token split across many input chunks must
    /// not be re-parsed from its start on every call: each payload bit is
    /// read once, plus at most a short token prefix re-read per call.
    #[test]
    fn long_length_token_reads_each_bit_once() {
        let k = 200_000;
        let (stream, total) = long_token_stream(k);
        let (got, calls, _, dec) = decode_all_a(&stream, 512);
        assert_eq!(got, total);
        let payload_bits = (stream.len() as u64 - 8) * 8;
        let bound = payload_bits + 32 * calls;
        assert!(
            dec.bits.bits_read <= bound,
            "read {} bits for a {}-bit payload in {} calls",
            dec.bits.bits_read,
            payload_bits,
            calls
        );
    }

    /// The same token decodes correctly when the input arrives one byte
    /// at a time, and the reader does not keep the whole token buffered.
    #[test]
    fn long_length_token_one_byte_at_a_time() {
        let (stream, total) = long_token_stream(20_000);
        let (got, _, peak, _) = decode_all_a(&stream, 1);
        assert_eq!(got, total);
        assert!(peak <= 2 * 4096, "bit reader pinned {peak} bytes");
    }

    /// Reset in the middle of a length extension discards the partial
    /// token.
    #[test]
    fn reset_clears_partial_length() {
        let (stream, total) = long_token_stream(1_000);
        let mut dec = Decoder::new();
        let mut out = vec![0u8; 64 * 1024];
        let p = dec.raw_decode(&stream[..200], &mut out).unwrap();
        assert!(!p.done);
        assert!(dec.pending_length.is_some());
        dec.raw_reset();
        assert!(dec.pending_length.is_none());
        let mut got = 0u64;
        let p = dec.raw_decode(&stream, &mut out).unwrap();
        got += p.written as u64;
        assert!(p.done);
        assert_eq!(got, total);
        assert!(out[..p.written].iter().all(|&b| b == b'A'));
    }
}
