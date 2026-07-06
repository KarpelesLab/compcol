//! LZSS sliding-window output buffer.
//!
//! RAR 1.x uses a 64 KiB LZSS dictionary
//! (`XADRAR15Handle.m` calls `initWithParentHandle:… windowSize:0x10000`).
//! Literals and match copies are emitted into the window; the window is
//! also a circular buffer that the consumer drains into the caller's
//! output slice on each [`crate::Decoder::decode`] call.
//!
//! This module provides:
//!
//! - [`Window`]: a fixed-size ring buffer with literal/match emission
//!   primitives that handle wrap-around and overlap (back-reference
//!   `offset == length`-style runs).
//! - [`Window::drain_into`]: copy already-emitted-but-not-yet-flushed bytes
//!   into a caller buffer, returning how many were written.
//!
//! The encoder always references bytes that are still inside the 64 KiB
//! window — RAR1 streams that try to read past the start return
//! [`Error::InvalidDistance`].

// Building-block; consumer is the future RAR1 state machine.
#![allow(dead_code)]

use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;

/// Fixed window size for RAR1: 64 KiB.
pub const WINDOW_SIZE: usize = 0x10000;

/// Sliding-window output buffer with a flush cursor.
///
/// The window is a circular buffer of fixed size `WINDOW_SIZE`. `write_pos`
/// is the next slot to write into, modulo `WINDOW_SIZE`. `flush_pos` is the
/// next slot the consumer needs to drain. `bytes_in_flight` is `write_pos -
/// flush_pos` taking wrap-around into account, and is `0..=WINDOW_SIZE`.
///
/// The total number of bytes that have ever been written is tracked in
/// `total_written`; this is used to validate back-references (a distance
/// pointing past the start of the original stream is corrupt).
pub struct Window {
    buf: Vec<u8>,
    /// Next slot to write into (modulo WINDOW_SIZE).
    write_pos: usize,
    /// Next slot the consumer wants to drain (modulo WINDOW_SIZE).
    flush_pos: usize,
    /// Number of emitted-but-undrained bytes (`write_pos - flush_pos` mod
    /// WINDOW_SIZE, but tracked directly to disambiguate "empty" from
    /// "full"). Always `0..=WINDOW_SIZE`.
    in_flight: usize,
    /// Total bytes emitted across the lifetime of this window. Used to
    /// detect back-references that point before the start of the stream.
    total_written: u64,
}

impl Window {
    /// Allocate a fresh window. The buffer is zero-initialised; back
    /// references reading any unwritten slot are caught by
    /// [`Window::emit_match`] via the `total_written` check.
    pub fn new() -> Self {
        Self {
            buf: vec![0u8; WINDOW_SIZE],
            write_pos: 0,
            flush_pos: 0,
            in_flight: 0,
            total_written: 0,
        }
    }

    /// Total bytes emitted (i.e. ever written into the window).
    pub fn total_written(&self) -> u64 {
        self.total_written
    }

    /// Bytes currently waiting to be drained.
    pub fn in_flight(&self) -> usize {
        self.in_flight
    }

    /// True iff the window has no room for more emitted bytes until the
    /// consumer drains some.
    pub fn is_full(&self) -> bool {
        self.in_flight == WINDOW_SIZE
    }

    /// Append one literal byte. Returns `Err(OutputTooSmall)` if the window
    /// is full and the consumer hasn't drained yet.
    pub fn emit_literal(&mut self, byte: u8) -> Result<(), Error> {
        if self.is_full() {
            return Err(Error::OutputTooSmall);
        }
        self.buf[self.write_pos] = byte;
        self.write_pos = (self.write_pos + 1) & (WINDOW_SIZE - 1);
        self.in_flight += 1;
        self.total_written += 1;
        Ok(())
    }

    /// Copy `length` bytes from `distance` positions back. Handles overlap
    /// (e.g. `distance == 1, length == 8` → emit the same byte 8 times).
    ///
    /// Returns:
    /// - `Err(InvalidDistance)` if `distance == 0`, `distance > WINDOW_SIZE`,
    ///   or the back-reference points before the start of the stream.
    /// - `Err(OutputTooSmall)` if the window can't fit the whole copy without
    ///   draining first. The window is left untouched in this case so the
    ///   caller can retry after draining. A partial emit is *not* attempted.
    pub fn emit_match(&mut self, distance: usize, length: usize) -> Result<(), Error> {
        if distance == 0 || distance > WINDOW_SIZE {
            return Err(Error::InvalidDistance);
        }
        if (distance as u64) > self.total_written {
            return Err(Error::InvalidDistance);
        }
        if length == 0 {
            return Ok(());
        }
        if self.in_flight + length > WINDOW_SIZE {
            return Err(Error::OutputTooSmall);
        }

        // Mask for wrap-around. Using bit-mask is fine because WINDOW_SIZE
        // is a power of two.
        let mask = WINDOW_SIZE - 1;
        let mut src = (self.write_pos + WINDOW_SIZE - distance) & mask;
        let mut dst = self.write_pos;
        if distance == 1 {
            // Distance-1 run: one repeated byte.
            let b = self.buf[src];
            for _ in 0..length {
                self.buf[dst] = b;
                dst = (dst + 1) & mask;
            }
        } else if distance >= length {
            // Non-overlapping: copy in contiguous window segments (no per-byte
            // mask test inside the run).
            let mut done = 0usize;
            while done < length {
                let run = (length - done)
                    .min(WINDOW_SIZE - src)
                    .min(WINDOW_SIZE - dst);
                // Non-overlapping, no wrap within the run: a single memmove.
                self.buf.copy_within(src..src + run, dst);
                src = (src + run) & mask;
                dst = (dst + run) & mask;
                done += run;
            }
        } else {
            // Overlapping match: each written byte feeds a later read.
            for _ in 0..length {
                let b = self.buf[src];
                self.buf[dst] = b;
                src = (src + 1) & mask;
                dst = (dst + 1) & mask;
            }
        }
        self.write_pos = dst;
        self.in_flight += length;
        self.total_written += length as u64;
        Ok(())
    }

    /// Copy up to `out.len()` bytes from the flush cursor into `out`,
    /// returning the number of bytes copied. Bytes that have been drained
    /// stay in the window for back-reference but are no longer "in flight".
    pub fn drain_into(&mut self, out: &mut [u8]) -> usize {
        let take = self.in_flight.min(out.len());
        if take == 0 {
            return 0;
        }
        let mask = WINDOW_SIZE - 1;
        let first_run = (WINDOW_SIZE - self.flush_pos).min(take);
        out[..first_run].copy_from_slice(&self.buf[self.flush_pos..self.flush_pos + first_run]);
        if first_run < take {
            // Wrapped around the ring.
            let rest = take - first_run;
            out[first_run..take].copy_from_slice(&self.buf[..rest]);
        }
        self.flush_pos = (self.flush_pos + take) & mask;
        self.in_flight -= take;
        take
    }

    /// Reset the window for re-use. The backing buffer is kept but cleared
    /// to zero so back-reference checks behave identically to a fresh
    /// window.
    pub fn reset(&mut self) {
        for b in self.buf.iter_mut() {
            *b = 0;
        }
        self.write_pos = 0;
        self.flush_pos = 0;
        self.in_flight = 0;
        self.total_written = 0;
    }
}

impl Default for Window {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_then_drain() {
        let mut w = Window::new();
        w.emit_literal(b'A').unwrap();
        w.emit_literal(b'B').unwrap();
        w.emit_literal(b'C').unwrap();
        assert_eq!(w.in_flight(), 3);
        assert_eq!(w.total_written(), 3);
        let mut out = [0u8; 5];
        assert_eq!(w.drain_into(&mut out), 3);
        assert_eq!(&out[..3], b"ABC");
        assert_eq!(w.in_flight(), 0);
        assert_eq!(w.total_written(), 3);
    }

    #[test]
    fn match_basic() {
        let mut w = Window::new();
        for &b in b"hello" {
            w.emit_literal(b).unwrap();
        }
        // 5 bytes back, copy 5 → reproduce "hello".
        w.emit_match(5, 5).unwrap();
        let mut out = [0u8; 10];
        let n = w.drain_into(&mut out);
        assert_eq!(n, 10);
        assert_eq!(&out[..10], b"hellohello");
    }

    #[test]
    fn match_with_overlap_run_length() {
        // distance == 1, length == 8 → "AAAAAAAA".
        let mut w = Window::new();
        w.emit_literal(b'A').unwrap();
        w.emit_match(1, 8).unwrap();
        let mut out = [0u8; 9];
        let n = w.drain_into(&mut out);
        assert_eq!(n, 9);
        assert_eq!(&out, b"AAAAAAAAA");
    }

    #[test]
    fn match_with_overlap_two_byte_period() {
        // distance == 2, length == 6 over "AB" → "ABABABAB".
        let mut w = Window::new();
        w.emit_literal(b'A').unwrap();
        w.emit_literal(b'B').unwrap();
        w.emit_match(2, 6).unwrap();
        let mut out = [0u8; 8];
        let n = w.drain_into(&mut out);
        assert_eq!(n, 8);
        assert_eq!(&out, b"ABABABAB");
    }

    #[test]
    fn invalid_distance_zero() {
        let mut w = Window::new();
        w.emit_literal(b'A').unwrap();
        assert_eq!(w.emit_match(0, 1).unwrap_err(), Error::InvalidDistance);
    }

    #[test]
    fn invalid_distance_too_large() {
        let mut w = Window::new();
        w.emit_literal(b'A').unwrap();
        assert_eq!(
            w.emit_match(WINDOW_SIZE + 1, 1).unwrap_err(),
            Error::InvalidDistance
        );
    }

    #[test]
    fn invalid_distance_before_stream_start() {
        let mut w = Window::new();
        w.emit_literal(b'A').unwrap();
        // distance 2 but only 1 byte written so far.
        assert_eq!(w.emit_match(2, 1).unwrap_err(), Error::InvalidDistance);
    }

    #[test]
    fn output_too_small_when_full() {
        let mut w = Window::new();
        // Fill the whole window with literals.
        for i in 0..WINDOW_SIZE {
            w.emit_literal((i & 0xFF) as u8).unwrap();
        }
        assert!(w.is_full());
        assert_eq!(w.emit_literal(0).unwrap_err(), Error::OutputTooSmall);
        // Match attempt with no room: same error.
        let mut tmp = [0u8; 1];
        w.drain_into(&mut tmp);
        // We drained 1 byte → there's now exactly 1 byte of room. A length-2
        // match should fail with OutputTooSmall (we don't do partial emits).
        assert_eq!(w.emit_match(2, 2).unwrap_err(), Error::OutputTooSmall);
    }

    #[test]
    fn drain_wraps_around() {
        let mut w = Window::new();
        // Fill window then drain half, write some more so the unflushed
        // region straddles the buffer end.
        for i in 0..WINDOW_SIZE {
            w.emit_literal((i & 0xFF) as u8).unwrap();
        }
        let mut sink = vec![0u8; WINDOW_SIZE / 2];
        let n = w.drain_into(&mut sink);
        assert_eq!(n, WINDOW_SIZE / 2);
        // Emit 100 more bytes (overwriting the freed slots).
        for i in 0..100 {
            w.emit_literal((i & 0xFF) as u8).unwrap();
        }
        // Drain everything that's left; should be (WINDOW_SIZE/2 + 100) bytes.
        let mut sink2 = vec![0u8; WINDOW_SIZE];
        let n2 = w.drain_into(&mut sink2);
        assert_eq!(n2, WINDOW_SIZE / 2 + 100);
    }

    #[test]
    fn back_reference_after_partial_drain_still_valid() {
        // After draining, the bytes must remain in the window for back
        // references — distance is measured from the *write* position, not
        // the flush position.
        let mut w = Window::new();
        for &b in b"abcdefgh" {
            w.emit_literal(b).unwrap();
        }
        let mut sink = [0u8; 4];
        assert_eq!(w.drain_into(&mut sink), 4);
        assert_eq!(&sink, b"abcd");
        // Reference 8 bytes back — we drained 4 but they're still in the
        // window. Should reproduce "abcdefgh".
        w.emit_match(8, 8).unwrap();
        let mut sink2 = [0u8; 12];
        let n = w.drain_into(&mut sink2);
        assert_eq!(n, 12);
        assert_eq!(&sink2, b"efghabcdefgh");
    }

    #[test]
    fn reset_clears_state() {
        let mut w = Window::new();
        w.emit_literal(b'A').unwrap();
        w.reset();
        assert_eq!(w.total_written(), 0);
        assert_eq!(w.in_flight(), 0);
        // After reset a distance-1 reference is invalid again.
        assert_eq!(w.emit_match(1, 1).unwrap_err(), Error::InvalidDistance);
    }
}
