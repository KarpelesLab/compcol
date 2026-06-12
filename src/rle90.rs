//! RLE90 — the `0x90`/DLE run-length variant shared by ARC method 3
//! ("packed") and classic StuffIt method 1.
//!
//! Wire format: a byte stream where the marker byte `0x90` (DLE)
//! introduces a run. After a literal byte `b` has been emitted, the
//! sequence `0x90 n` repeats `b` so that **`n` total copies** exist —
//! the literal `b` already counts as the first copy, so the decoder
//! emits `n - 1` additional copies. The count byte itself is special-
//! cased:
//!
//! * `0x90 0x00` — a literal `0x90` byte (escape for the marker).
//! * `0x90 0x01` — degenerate "1 total copy"; emits nothing further,
//!   since the single literal already on the wire is the whole run.
//! * `0x90 n` (`n >= 2`) — repeat the last literal to `n` total copies
//!   (emit `n - 1` more).
//!
//! A `0x90 n` sequence with `n != 0` and no preceding literal byte is
//! malformed and decodes to [`Error::Corrupt`]. A stream that ends with
//! a dangling `0x90` (the count byte never arrived) is
//! [`Error::UnexpectedEnd`] at [`finish`](crate::Decoder::finish).
//!
//! The stream has no header, no trailer, and no length prefix: decoding
//! ends at input exhaustion on a symbol boundary. This matches the
//! RLE pre-pass embedded in [`crate::arc_squeeze`] exactly, so the two
//! are byte-compatible.
//!
//! ## DoS hygiene
//!
//! A run count expands at most 255 output bytes per 3 input bytes
//! (`b 0x90 0xFF`). The decoder is a resumable state machine whose
//! per-call output is bounded by the caller's `output` slice — it never
//! materialises a whole run up front, so a malicious stream cannot force
//! an unbounded allocation here. Wrap it in
//! [`crate::limit::LimitedDecoder`] to bound total decompressed size.
//!
//! References:
//! * SEA ARC technical notes (method 3, "packed" / RLE90).
//! * The `0x90` DLE run-length scheme as used by SQ/USQ and StuffIt
//!   method 1.

#![cfg_attr(docsrs, doc(cfg(feature = "rle90")))]

use alloc::vec::Vec;

use crate::error::Error;
use crate::traits::{Algorithm, RawDecoder, RawEncoder, RawProgress};

/// RLE90 marker byte (DLE).
const FLAG: u8 = 0x90;

/// Minimum run length worth encoding as `b 0x90 n`. A 2-byte run costs
/// `b 0x90 0x02` (3 bytes out) vs. `b b` (2 bytes out) literally, so we
/// only switch to a coded run at length 3+.
const MIN_RUN: usize = 3;

/// Maximum total copies a single `0x90 n` can express (`n` is one byte).
const MAX_RUN: usize = 255;

/// Zero-sized marker type implementing [`Algorithm`] for RLE90.
#[derive(Debug, Clone, Copy, Default)]
pub struct Rle90;

impl Algorithm for Rle90 {
    const NAME: &'static str = "rle90";
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

// ─── encoder ─────────────────────────────────────────────────────────────

/// Streaming RLE90 encoder.
///
/// The state machine tracks at most one in-progress run (`run`) and a
/// small `pending` output queue, so callers can drive it with arbitrarily
/// small input or output slices. Runs of 3+ identical bytes are emitted
/// as `b 0x90 n`; shorter runs are emitted literally. A literal `0x90`
/// is escaped as `0x90 0x00`. Runs longer than 255 are split into
/// consecutive coded runs.
#[derive(Debug, Default)]
pub struct Encoder {
    /// The byte currently being counted, and how many copies have been
    /// seen so far (always `>= 1` while a run is tracked). `None` means
    /// no run in progress.
    run: Option<(u8, usize)>,
    /// Already-encoded output the caller hasn't drained yet.
    pending: Vec<u8>,
    head: usize,
    finished: bool,
}

impl Encoder {
    /// Construct a fresh encoder.
    pub const fn new() -> Self {
        Self {
            run: None,
            pending: Vec::new(),
            head: 0,
            finished: false,
        }
    }

    fn drain_pending(&mut self, out: &mut [u8]) -> usize {
        let avail = self.pending.len() - self.head;
        let n = avail.min(out.len());
        out[..n].copy_from_slice(&self.pending[self.head..self.head + n]);
        self.head += n;
        if self.head == self.pending.len() {
            self.pending.clear();
            self.head = 0;
        }
        n
    }

    /// Emit a single literal byte, escaping the marker as `0x90 0x00`.
    fn emit_literal(&mut self, b: u8) {
        self.pending.push(b);
        if b == FLAG {
            self.pending.push(0);
        }
    }

    /// Flush the tracked run to `pending`. Runs of `< MIN_RUN` are emitted
    /// as repeated literals; longer runs as `b 0x90 n`, split into chunks
    /// of at most `MAX_RUN` total copies each.
    fn flush_run(&mut self) {
        let Some((byte, count)) = self.run.take() else {
            return;
        };
        // The marker byte `0x90` can never be the leading literal of a coded
        // run — the decoder would read it as a marker, not a literal. So a
        // run of `0x90` is always emitted as repeated `0x90 0x00` escapes.
        if byte == FLAG || count < MIN_RUN {
            for _ in 0..count {
                self.emit_literal(byte);
            }
            return;
        }
        // Coded run(s). The leading literal `byte` is emitted once and counts
        // as the first copy; each `0x90 n` then tops the run up to `n` total
        // copies for that chunk. Subsequent chunks reuse the decoder's
        // remembered `last` byte, so only the first chunk carries a leading
        // literal.
        self.pending.push(byte);
        let mut emitted = 1usize;
        while count - emitted >= 1 {
            // Top up to at most MAX_RUN total copies per `0x90 n`.
            let chunk = (count - emitted + 1).min(MAX_RUN);
            self.pending.push(FLAG);
            self.pending.push(chunk as u8);
            emitted += chunk - 1;
        }
    }

    /// Push one input byte through the state machine.
    fn feed(&mut self, b: u8) {
        match self.run {
            Some((byte, count)) if byte == b && count < MAX_RUN => {
                self.run = Some((byte, count + 1));
            }
            Some(_) => {
                // Either `b` breaks the run, or we hit MAX_RUN. Flush the
                // current run and start a fresh one with `b`.
                self.flush_run();
                self.run = Some((b, 1));
            }
            None => {
                self.run = Some((b, 1));
            }
        }
    }

    /// Commit any pending run at end-of-stream. Idempotent.
    fn finalize(&mut self) {
        self.flush_run();
    }
}

impl RawEncoder for Encoder {
    fn raw_encode(&mut self, input: &[u8], output: &mut [u8]) -> Result<RawProgress, Error> {
        let mut consumed = 0usize;
        let mut written = 0usize;

        // Drain whatever is queued first.
        if self.head < self.pending.len() {
            written += self.drain_pending(&mut output[written..]);
        }

        while consumed < input.len() {
            // Bound how much `pending` grows per call: if the queue is
            // already as long as the remaining output room, stop feeding
            // and let the caller drain.
            if self.pending.len().saturating_sub(self.head) >= output.len().saturating_sub(written)
            {
                if written < output.len() {
                    written += self.drain_pending(&mut output[written..]);
                }
                if self.head < self.pending.len() {
                    break;
                }
            }

            self.feed(input[consumed]);
            consumed += 1;

            if self.head < self.pending.len() && written < output.len() {
                written += self.drain_pending(&mut output[written..]);
            }
        }

        if self.head < self.pending.len() && written < output.len() {
            written += self.drain_pending(&mut output[written..]);
        }

        Ok(RawProgress {
            consumed,
            written,
            done: false,
        })
    }

    fn raw_finish(&mut self, output: &mut [u8]) -> Result<RawProgress, Error> {
        if self.finished && self.head >= self.pending.len() {
            return Ok(RawProgress {
                consumed: 0,
                written: 0,
                done: true,
            });
        }

        if !self.finished {
            self.finalize();
            self.finished = true;
        }

        let mut written = 0usize;
        if self.head < self.pending.len() {
            written += self.drain_pending(&mut output[written..]);
        }
        let done = self.head >= self.pending.len();
        Ok(RawProgress {
            consumed: 0,
            written,
            done,
        })
    }

    fn raw_reset(&mut self) {
        self.run = None;
        self.pending.clear();
        self.head = 0;
        self.finished = false;
    }
}

// ─── decoder ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
enum DecState {
    /// Waiting for the next byte (literal or marker).
    Normal,
    /// We just consumed a `0x90` and await the count byte.
    AwaitCount,
    /// Mid-run: emit `byte` `remaining` more times.
    Run { byte: u8, remaining: u8 },
}

/// Streaming RLE90 decoder.
///
/// Resumable across arbitrarily small input/output slices. After any
/// `Err` return the decoder is poisoned; call [`reset`](crate::Decoder::reset)
/// before reuse.
#[derive(Debug, Clone, Copy)]
pub struct Decoder {
    state: DecState,
    /// Last literal byte emitted (the candidate a `0x90 n` repeats).
    last: u8,
    have_last: bool,
    poisoned: bool,
}

impl Decoder {
    /// Construct a fresh decoder.
    pub const fn new() -> Self {
        Self {
            state: DecState::Normal,
            last: 0,
            have_last: false,
            poisoned: false,
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
        let mut consumed = 0usize;
        let mut written = 0usize;

        loop {
            match self.state {
                DecState::Normal => {
                    if consumed == input.len() {
                        return Ok(RawProgress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                    let b = input[consumed];
                    if b == FLAG {
                        // Don't consume until we can act on the count.
                        consumed += 1;
                        self.state = DecState::AwaitCount;
                    } else {
                        if written == output.len() {
                            return Ok(RawProgress {
                                consumed,
                                written,
                                done: false,
                            });
                        }
                        // Bulk-copy a contiguous run of literal (non-FLAG)
                        // bytes, bounded by remaining input and output. This
                        // turns the common literal-heavy stream into a single
                        // memcpy instead of a per-byte state-machine cycle.
                        let in_avail = input.len() - consumed;
                        let out_avail = output.len() - written;
                        let limit = in_avail.min(out_avail);
                        let src = &input[consumed..consumed + limit];
                        // Length of the leading non-FLAG span.
                        let span = match src.iter().position(|&x| x == FLAG) {
                            Some(p) => p,
                            None => limit,
                        };
                        // `span >= 1` because src[0] == b != FLAG.
                        output[written..written + span].copy_from_slice(&src[..span]);
                        self.last = src[span - 1];
                        self.have_last = true;
                        written += span;
                        consumed += span;
                    }
                }
                DecState::AwaitCount => {
                    if consumed == input.len() {
                        return Ok(RawProgress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                    let n = input[consumed];
                    consumed += 1;
                    if n == 0 {
                        // Literal marker byte.
                        if written == output.len() {
                            // No room — roll back the consume so we re-enter
                            // AwaitCount-resolved next call. Instead, stash as
                            // a 1-byte run of FLAG to stay resumable.
                            self.state = DecState::Run {
                                byte: FLAG,
                                remaining: 1,
                            };
                            self.last = FLAG;
                            self.have_last = true;
                            return Ok(RawProgress {
                                consumed,
                                written,
                                done: false,
                            });
                        }
                        output[written] = FLAG;
                        written += 1;
                        self.last = FLAG;
                        self.have_last = true;
                        self.state = DecState::Normal;
                    } else {
                        // Repeat `last` to `n` total copies. One copy was
                        // already emitted, so emit `n - 1` more.
                        if !self.have_last {
                            self.poisoned = true;
                            return Err(Error::Corrupt);
                        }
                        self.state = DecState::Run {
                            byte: self.last,
                            remaining: n - 1,
                        };
                    }
                }
                DecState::Run { byte, remaining } => {
                    if remaining == 0 {
                        self.state = DecState::Normal;
                        continue;
                    }
                    if written == output.len() {
                        return Ok(RawProgress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                    let out_avail = output.len() - written;
                    let n = (remaining as usize).min(out_avail);
                    for slot in &mut output[written..written + n] {
                        *slot = byte;
                    }
                    written += n;
                    let new_remaining = remaining - n as u8;
                    self.state = if new_remaining == 0 {
                        DecState::Normal
                    } else {
                        DecState::Run {
                            byte,
                            remaining: new_remaining,
                        }
                    };
                }
            }
        }
    }

    fn raw_finish(&mut self, output: &mut [u8]) -> Result<RawProgress, Error> {
        if self.poisoned {
            return Err(Error::Corrupt);
        }
        let mut written = 0usize;

        // Drain any in-progress run.
        if let DecState::Run { byte, remaining } = self.state {
            let out_avail = output.len() - written;
            let n = (remaining as usize).min(out_avail);
            for slot in &mut output[written..written + n] {
                *slot = byte;
            }
            written += n;
            let new_remaining = remaining - n as u8;
            self.state = if new_remaining == 0 {
                DecState::Normal
            } else {
                DecState::Run {
                    byte,
                    remaining: new_remaining,
                }
            };
        }

        match self.state {
            DecState::Normal => Ok(RawProgress {
                consumed: 0,
                written,
                done: true,
            }),
            DecState::Run { .. } => Ok(RawProgress {
                consumed: 0,
                written,
                done: false,
            }),
            // A dangling `0x90` whose count byte never arrived: truncated.
            DecState::AwaitCount => {
                self.poisoned = true;
                Err(Error::UnexpectedEnd)
            }
        }
    }

    fn raw_reset(&mut self) {
        self.state = DecState::Normal;
        self.last = 0;
        self.have_last = false;
        self.poisoned = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::{Decoder as _, Encoder as _, Status};
    use alloc::vec;

    fn encode_all(input: &[u8]) -> Vec<u8> {
        let mut enc = Rle90::encoder();
        let mut out = Vec::new();
        let mut buf = [0u8; 64];
        let mut consumed = 0;
        while consumed < input.len() {
            let (p, status) = enc.encode(&input[consumed..], &mut buf).unwrap();
            out.extend_from_slice(&buf[..p.written]);
            consumed += p.consumed;
            match status {
                Status::OutputFull => continue,
                Status::InputEmpty => break,
                Status::StreamEnd => break,
            }
        }
        loop {
            let (p, status) = enc.finish(&mut buf).unwrap();
            out.extend_from_slice(&buf[..p.written]);
            if matches!(status, Status::StreamEnd) {
                break;
            }
        }
        out
    }

    fn decode_all(input: &[u8]) -> Result<Vec<u8>, Error> {
        let mut dec = Rle90::decoder();
        let mut out = Vec::new();
        let mut buf = [0u8; 64];
        let mut consumed = 0;
        loop {
            let (p, status) = dec.decode(&input[consumed..], &mut buf)?;
            out.extend_from_slice(&buf[..p.written]);
            consumed += p.consumed;
            match status {
                Status::OutputFull => continue,
                Status::InputEmpty => break,
                Status::StreamEnd => break,
            }
        }
        loop {
            let (p, status) = dec.finish(&mut buf)?;
            out.extend_from_slice(&buf[..p.written]);
            if matches!(status, Status::StreamEnd) {
                break;
            }
        }
        Ok(out)
    }

    /// 1-byte-in / 1-byte-out streaming decode, to exercise every state
    /// boundary. Feeds the input one byte at a time into a 1-byte output
    /// buffer, draining (with empty input) whenever the decoder still has
    /// buffered run output to emit.
    fn decode_byte_by_byte(input: &[u8]) -> Result<Vec<u8>, Error> {
        let mut dec = Rle90::decoder();
        let mut out = Vec::new();
        let mut buf = [0u8; 1];
        for i in 0..input.len() {
            let mut chunk = &input[i..i + 1];
            loop {
                let (p, _status) = dec.decode(chunk, &mut buf)?;
                out.extend_from_slice(&buf[..p.written]);
                // Once this byte is consumed, keep draining buffered run
                // output by calling with an empty slice until nothing more
                // is produced.
                if p.consumed > 0 {
                    chunk = &input[i + 1..i + 1];
                }
                if p.written == 0 && p.consumed == 0 {
                    break;
                }
            }
        }
        loop {
            let (p, status) = dec.finish(&mut buf)?;
            out.extend_from_slice(&buf[..p.written]);
            if matches!(status, Status::StreamEnd) {
                break;
            }
        }
        Ok(out)
    }

    fn round_trip(input: &[u8]) {
        let encoded = encode_all(input);
        let decoded = decode_all(&encoded).expect("decode");
        assert_eq!(decoded, input, "round-trip mismatch");
        let decoded_bb = decode_byte_by_byte(&encoded).expect("byte-by-byte decode");
        assert_eq!(decoded_bb, input, "byte-by-byte round-trip mismatch");
    }

    #[test]
    fn empty() {
        round_trip(&[]);
    }

    #[test]
    fn no_marker_data() {
        round_trip(b"hello, world!");
        round_trip(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    }

    #[test]
    fn literal_markers() {
        round_trip(&[FLAG]);
        round_trip(&[FLAG, FLAG, FLAG]);
        round_trip(&[1, FLAG, 2, FLAG, FLAG, 3]);
        round_trip(&[FLAG; 10]);
    }

    #[test]
    fn short_runs() {
        round_trip(&[7, 7]);
        round_trip(&[7, 7, 7]);
        round_trip(b"aabbccdd");
    }

    #[test]
    fn long_run() {
        round_trip(&[0x41; 100]);
        round_trip(&[0x00; 200]);
    }

    #[test]
    fn run_over_255_split() {
        round_trip(&[0x5a; 255]);
        round_trip(&[0x5a; 256]);
        round_trip(&[0x5a; 300]);
        round_trip(&[0x5a; 1000]);
        // A marker byte repeated many times.
        round_trip(&[FLAG; 600]);
    }

    #[test]
    fn all_256_bytes() {
        let data: Vec<u8> = (0..=255u8).collect();
        round_trip(&data);
        // Each byte repeated 4 times.
        let mut data2 = Vec::new();
        for b in 0..=255u8 {
            data2.extend_from_slice(&[b, b, b, b]);
        }
        round_trip(&data2);
    }

    #[test]
    fn pseudo_random() {
        // Simple LCG; deterministic, no deps.
        let mut state = 0x1234_5678u32;
        let mut data = Vec::with_capacity(4096);
        for _ in 0..4096 {
            state = state.wrapping_mul(1_103_515_245).wrapping_add(12345);
            data.push((state >> 16) as u8);
        }
        round_trip(&data);
    }

    #[test]
    fn mixed_runs_and_literals() {
        let mut data = Vec::new();
        data.extend_from_slice(b"abc");
        data.extend_from_slice(&[0xff; 50]);
        data.extend_from_slice(b"def");
        data.extend_from_slice(&[FLAG; 7]);
        data.extend_from_slice(&[0x00; 300]);
        data.push(0x90);
        round_trip(&data);
    }

    #[test]
    fn known_encoding() {
        // "aaaa" -> 'a' 0x90 0x04
        let encoded = encode_all(b"aaaa");
        assert_eq!(encoded, vec![b'a', FLAG, 0x04]);
        // literal 0x90 -> 0x90 0x00
        assert_eq!(encode_all(&[FLAG]), vec![FLAG, 0x00]);
    }

    #[test]
    fn decode_known_sequences() {
        // 'a' 0x90 0x04 -> "aaaa"
        assert_eq!(decode_all(&[b'a', FLAG, 0x04]).unwrap(), b"aaaa");
        // 0x90 0x00 -> literal 0x90
        assert_eq!(decode_all(&[FLAG, 0x00]).unwrap(), vec![FLAG]);
        // 'a' 0x90 0x01 -> just "a" (1 total copy)
        assert_eq!(decode_all(&[b'a', FLAG, 0x01]).unwrap(), b"a");
    }

    #[test]
    fn malformed_run_no_literal() {
        // A count with no preceding literal: 0x90 0x05.
        let r = decode_all(&[FLAG, 0x05]);
        assert_eq!(r, Err(Error::Corrupt));
    }

    #[test]
    fn malformed_dangling_flag() {
        // Stream ends right after a 0x90 marker.
        let r = decode_all(&[b'a', FLAG]);
        assert_eq!(r, Err(Error::UnexpectedEnd));
    }

    #[test]
    fn poisoned_after_error() {
        let mut dec = Rle90::decoder();
        let mut buf = [0u8; 16];
        // 0x90 0x05 with no literal -> Corrupt.
        let r = dec.decode(&[FLAG, 0x05], &mut buf);
        assert_eq!(r, Err(Error::Corrupt));
        // Subsequent calls keep returning Corrupt until reset.
        let r2 = dec.decode(b"a", &mut buf);
        assert_eq!(r2, Err(Error::Corrupt));
        dec.reset();
        let (p, _s) = dec.decode(b"a", &mut buf).unwrap();
        assert_eq!(p.written, 1);
    }

    #[test]
    fn cross_check_arc_squeeze_convention() {
        // The arc_squeeze RLE pre-pass uses the same `b 0x90 n` (n total)
        // convention with the same MIN_RUN=3 threshold and `0x90 0x00`
        // literal escape. Verify our decoder accepts that exact encoding
        // for a representative input.
        // Input "xxxxx" (5 x's): encoder emits 'x' 0x90 0x05.
        assert_eq!(encode_all(b"xxxxx"), vec![b'x', FLAG, 0x05]);
        assert_eq!(decode_all(&[b'x', FLAG, 0x05]).unwrap(), b"xxxxx");
    }
}
