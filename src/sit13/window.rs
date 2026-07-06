//! Bounds-checked LZSS output buffer for StuffIt method 13.
//!
//! Method 13 is LZSS over a 64 KiB sliding window. Because the decoder
//! buffers the whole compressed payload and decodes in one pass (the
//! uncompressed size is known out of band — see [`super::decoder`]), the
//! "window" is simply the growing output vector: a back-reference of
//! distance `D` copies from `out.len() - D`. The 64 KiB window bound is
//! enforced by rejecting distances larger than the window, and the
//! "reaches before stream start" condition is rejected by requiring
//! `D <= out.len()`.
//!
//! The match copy is performed **one byte at a time** so overlapping
//! (run-length) copies extend correctly when `D < L`. Every back-reference is
//! validated; a distance of zero, larger than the window, or pointing before
//! the produced output is rejected with [`Error::InvalidDistance`]. No
//! `unsafe`; no panic reachable from any input.

extern crate alloc;

use alloc::vec::Vec;

use crate::error::Error;

/// Sliding-window size: 64 KiB (mask `0xFFFF`).
pub(crate) const WINDOW_SIZE: usize = 0x10000;

/// Append one literal byte to `out`.
pub(crate) fn emit_literal(out: &mut Vec<u8>, byte: u8) {
    out.push(byte);
}

/// Copy a match of `length` bytes from `distance` bytes back, overlap-safe.
///
/// Rejects `distance == 0`, `distance > WINDOW_SIZE`, and a distance that
/// reaches before the start of produced output, all as
/// [`Error::InvalidDistance`].
pub(crate) fn emit_match(out: &mut Vec<u8>, distance: usize, length: usize) -> Result<(), Error> {
    if distance == 0 || distance > WINDOW_SIZE || distance > out.len() {
        return Err(Error::InvalidDistance);
    }
    // Overlap-safe vectorized copy. `distance == 1` is a single-byte run:
    // splat the last byte. Otherwise copy in chunks of at most `out.len() - src`
    // bytes, so every source byte is already materialized before it is appended
    // (reproducing the cyclic byte sequence the naive per-byte loop would).
    if distance == 1 {
        let b = out[out.len() - 1];
        out.resize(out.len() + length, b);
    } else {
        let mut rem = length;
        let mut src = out.len() - distance;
        while rem > 0 {
            let n = rem.min(out.len() - src);
            out.extend_from_within(src..src + n);
            src += n;
            rem -= n;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn literal_then_match() {
        let mut out = vec![];
        for &b in b"hello" {
            emit_literal(&mut out, b);
        }
        emit_match(&mut out, 5, 5).unwrap();
        assert_eq!(&out, b"hellohello");
    }

    #[test]
    fn overlap_run() {
        let mut out = vec![];
        emit_literal(&mut out, b'A');
        emit_match(&mut out, 1, 8).unwrap();
        assert_eq!(&out, b"AAAAAAAAA");
    }

    #[test]
    fn overlap_two_byte_period() {
        let mut out = vec![];
        emit_literal(&mut out, b'A');
        emit_literal(&mut out, b'B');
        emit_match(&mut out, 2, 6).unwrap();
        assert_eq!(&out, b"ABABABAB");
    }

    #[test]
    fn rejects_zero_distance() {
        let mut out = vec![1u8];
        assert_eq!(emit_match(&mut out, 0, 1), Err(Error::InvalidDistance));
    }

    #[test]
    fn rejects_distance_before_start() {
        let mut out = vec![1u8];
        assert_eq!(emit_match(&mut out, 2, 1), Err(Error::InvalidDistance));
    }

    #[test]
    fn rejects_distance_over_window() {
        let mut out = vec![0u8; WINDOW_SIZE + 10];
        assert_eq!(
            emit_match(&mut out, WINDOW_SIZE + 1, 1),
            Err(Error::InvalidDistance)
        );
    }
}
