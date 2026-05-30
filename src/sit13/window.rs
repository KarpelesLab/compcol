//! Bounds-checked LZSS sliding-window output buffer.
//!
//! A method-13 decoder emits literals and back-reference matches into a
//! sliding window, draining decoded bytes to the caller as it goes. This
//! module provides that window as a fixed-size power-of-two ring with a
//! flush cursor, plus the match-emission primitive that handles
//! wrap-around and overlapping (run-length) copies.
//!
//! Safety / DoS hygiene: every back-reference is validated. A distance of
//! zero, a distance larger than the window, or a distance pointing before
//! the start of produced output is rejected with
//! [`Error::InvalidDistance`]; an emit that would overflow the undrained
//! region returns [`Error::OutputTooSmall`] and leaves the window
//! untouched so the caller can drain and retry. No `unsafe`; no panic
//! reachable from any input.
//!
//! Shares its shape with [`crate::rar1::window`].

// Building block; the consumer is a future method-13 state machine.
#![allow(dead_code)]

use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;

/// Window size. 64 KiB, a power of two so wrap-around is a bit-mask. The
/// exact window size of StuffIt method 13 is part of the undocumented
/// format; 64 KiB is a conventional choice for an LZ+Huffman codec of this
/// era and is sufficient for the building-block's unit tests. A future
/// state machine that learns the true size can swap this constant.
pub const WINDOW_SIZE: usize = 0x10000;

const MASK: usize = WINDOW_SIZE - 1;

/// Sliding-window output buffer with a flush cursor.
pub struct Window {
    buf: Vec<u8>,
    /// Next slot to write into (modulo WINDOW_SIZE).
    write_pos: usize,
    /// Next slot the consumer wants to drain (modulo WINDOW_SIZE).
    flush_pos: usize,
    /// Emitted-but-undrained byte count. Always `0..=WINDOW_SIZE`.
    in_flight: usize,
    /// Total bytes ever emitted — used to reject back-references that point
    /// before the start of the produced stream.
    total_written: u64,
}

impl Window {
    pub fn new() -> Self {
        Self {
            buf: vec![0u8; WINDOW_SIZE],
            write_pos: 0,
            flush_pos: 0,
            in_flight: 0,
            total_written: 0,
        }
    }

    pub fn total_written(&self) -> u64 {
        self.total_written
    }

    pub fn in_flight(&self) -> usize {
        self.in_flight
    }

    pub fn is_full(&self) -> bool {
        self.in_flight == WINDOW_SIZE
    }

    /// Append one literal byte. `Err(OutputTooSmall)` if the window is full.
    pub fn emit_literal(&mut self, byte: u8) -> Result<(), Error> {
        if self.is_full() {
            return Err(Error::OutputTooSmall);
        }
        self.buf[self.write_pos] = byte;
        self.write_pos = (self.write_pos + 1) & MASK;
        self.in_flight += 1;
        self.total_written += 1;
        Ok(())
    }

    /// Copy `length` bytes from `distance` positions back, handling overlap.
    ///
    /// - `Err(InvalidDistance)` if `distance == 0`, `distance > WINDOW_SIZE`,
    ///   or the reference points before the start of the stream.
    /// - `Err(OutputTooSmall)` if the copy wouldn't fit without draining;
    ///   the window is left untouched (no partial emit).
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

        let mut src = (self.write_pos + WINDOW_SIZE - distance) & MASK;
        let mut dst = self.write_pos;
        for _ in 0..length {
            let b = self.buf[src];
            self.buf[dst] = b;
            src = (src + 1) & MASK;
            dst = (dst + 1) & MASK;
        }
        self.write_pos = dst;
        self.in_flight += length;
        self.total_written += length as u64;
        Ok(())
    }

    /// Drain up to `out.len()` undrained bytes into `out`, returning the
    /// count copied. Drained bytes stay in the window for back-reference.
    pub fn drain_into(&mut self, out: &mut [u8]) -> usize {
        let take = self.in_flight.min(out.len());
        if take == 0 {
            return 0;
        }
        let first_run = (WINDOW_SIZE - self.flush_pos).min(take);
        out[..first_run].copy_from_slice(&self.buf[self.flush_pos..self.flush_pos + first_run]);
        if first_run < take {
            let rest = take - first_run;
            out[first_run..take].copy_from_slice(&self.buf[..rest]);
        }
        self.flush_pos = (self.flush_pos + take) & MASK;
        self.in_flight -= take;
        take
    }

    /// Reset for re-use. Backing buffer is cleared so back-reference checks
    /// behave identically to a fresh window.
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
        for &b in b"ABC" {
            w.emit_literal(b).unwrap();
        }
        assert_eq!(w.in_flight(), 3);
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
        w.emit_match(5, 5).unwrap();
        let mut out = [0u8; 10];
        assert_eq!(w.drain_into(&mut out), 10);
        assert_eq!(&out[..10], b"hellohello");
    }

    #[test]
    fn match_overlap_run_length() {
        let mut w = Window::new();
        w.emit_literal(b'A').unwrap();
        w.emit_match(1, 8).unwrap();
        let mut out = [0u8; 9];
        assert_eq!(w.drain_into(&mut out), 9);
        assert_eq!(&out, b"AAAAAAAAA");
    }

    #[test]
    fn match_overlap_two_byte_period() {
        let mut w = Window::new();
        w.emit_literal(b'A').unwrap();
        w.emit_literal(b'B').unwrap();
        w.emit_match(2, 6).unwrap();
        let mut out = [0u8; 8];
        assert_eq!(w.drain_into(&mut out), 8);
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
        assert_eq!(w.emit_match(2, 1).unwrap_err(), Error::InvalidDistance);
    }

    #[test]
    fn output_too_small_when_full() {
        let mut w = Window::new();
        for i in 0..WINDOW_SIZE {
            w.emit_literal((i & 0xFF) as u8).unwrap();
        }
        assert!(w.is_full());
        assert_eq!(w.emit_literal(0).unwrap_err(), Error::OutputTooSmall);
        let mut tmp = [0u8; 1];
        w.drain_into(&mut tmp);
        assert_eq!(w.emit_match(2, 2).unwrap_err(), Error::OutputTooSmall);
    }

    #[test]
    fn back_reference_survives_partial_drain() {
        let mut w = Window::new();
        for &b in b"abcdefgh" {
            w.emit_literal(b).unwrap();
        }
        let mut sink = [0u8; 4];
        assert_eq!(w.drain_into(&mut sink), 4);
        assert_eq!(&sink, b"abcd");
        w.emit_match(8, 8).unwrap();
        let mut sink2 = [0u8; 12];
        assert_eq!(w.drain_into(&mut sink2), 12);
        assert_eq!(&sink2, b"efghabcdefgh");
    }

    #[test]
    fn reset_clears_state() {
        let mut w = Window::new();
        w.emit_literal(b'A').unwrap();
        w.reset();
        assert_eq!(w.total_written(), 0);
        assert_eq!(w.in_flight(), 0);
        assert_eq!(w.emit_match(1, 1).unwrap_err(), Error::InvalidDistance);
    }
}
