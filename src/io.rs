//! `std::io::Read` / `std::io::Write` adapters around any
//! [`Encoder`]/[`Decoder`].
//!
//! Four adapters, one per (direction × side):
//!
//! | Adapter           | Implements | Inner does       | Caller sees      |
//! |-------------------|------------|------------------|------------------|
//! | [`EncoderWriter`] | `Write`    | sinks bytes      | writes plaintext, inner gets compressed |
//! | [`EncoderReader`] | `Read`     | gives plaintext  | reads compressed |
//! | [`DecoderWriter`] | `Write`    | sinks bytes      | writes compressed, inner gets plaintext |
//! | [`DecoderReader`] | `Read`     | gives compressed | reads plaintext  |
//!
//! Each adapter has one `new(inner, codec)` constructor. The codec
//! comes from the algorithm: `Gzip::encoder()`, `Gzip::encoder_with(cfg)`,
//! `Gzip::decoder()`, etc.
//!
//! The two writer adapters call their codec's `finish` on `Drop` if not
//! already finished, swallowing any I/O or codec error. Call
//! [`EncoderWriter::finish`] / [`DecoderWriter::finish`] explicitly to
//! surface those errors.
//!
//! ```ignore
//! use std::io::Write;
//! use compcol::{Algorithm, gzip::Gzip, io::EncoderWriter};
//!
//! let file = std::fs::File::create("out.gz")?;
//! let mut w = EncoderWriter::new(file, Gzip::encoder());
//! w.write_all(b"hello, gzip\n")?;
//! let _file = w.finish()?;        // returns the inner File
//! ```

extern crate alloc;
extern crate std;

use alloc::vec;
use alloc::vec::Vec;
use std::io::{self, Read, Write};

use crate::{Decoder, Encoder, Status};

/// Per-call scratch buffer size. 64 KiB matches the CLI streaming
/// loop in `src/bin/compcol.rs` and is comfortably above the
/// minimum-output sizes of every algorithm in this crate.
const SCRATCH: usize = 64 * 1024;

// ─── EncoderWriter ──────────────────────────────────────────────────────

/// Wraps a `W: Write`, exposing a `Write` impl that compresses every
/// byte you write before forwarding it to `W`.
///
/// Call [`EncoderWriter::finish`] when you're done to drain the
/// encoder's tail bytes and recover the inner writer. If you drop
/// without calling `finish`, the destructor runs `finish` for you
/// but **discards any I/O or codec errors** — surface those by
/// calling `finish` explicitly.
pub struct EncoderWriter<W: Write, E: Encoder> {
    enc: E,
    // `Option` lets `finish` extract `W` by value without unsafe and
    // lets the `Drop` impl distinguish "already taken" (no-op) from
    // "still owned, must finish".
    inner: Option<W>,
    scratch: Vec<u8>,
    finished: bool,
}

impl<W: Write, E: Encoder> EncoderWriter<W, E> {
    /// Wrap `inner` with a caller-supplied encoder.
    pub fn new(inner: W, enc: E) -> Self {
        Self {
            enc,
            inner: Some(inner),
            scratch: vec![0u8; SCRATCH],
            finished: false,
        }
    }

    /// Borrow the inner writer.
    ///
    /// Panics if [`finish`](Self::finish) has already been called.
    pub fn get_ref(&self) -> &W {
        self.inner
            .as_ref()
            .expect("inner already taken by finish()")
    }

    /// Mutable-borrow the inner writer. Writing to it directly bypasses
    /// the encoder — use sparingly. Panics if `finish` has been called.
    pub fn get_mut(&mut self) -> &mut W {
        self.inner
            .as_mut()
            .expect("inner already taken by finish()")
    }

    /// Drain the encoder's tail bytes into the inner writer and return
    /// the (now-finished) inner writer.
    pub fn finish(mut self) -> io::Result<W> {
        self.do_finish()?;
        // Take ownership of the inner; Drop will see None and skip its
        // own finish pass.
        Ok(self
            .inner
            .take()
            .expect("inner present until finish() taken it"))
    }

    fn do_finish(&mut self) -> io::Result<()> {
        if self.finished {
            return Ok(());
        }
        let inner = match self.inner.as_mut() {
            Some(w) => w,
            None => return Ok(()),
        };
        loop {
            let (p, status) = self.enc.finish(&mut self.scratch)?;
            inner.write_all(&self.scratch[..p.written])?;
            if matches!(status, Status::StreamEnd) {
                break;
            }
            if p.written == 0 {
                return Err(io::Error::other("encoder stalled in finish"));
            }
        }
        self.finished = true;
        Ok(())
    }
}

impl<W: Write, E: Encoder> Write for EncoderWriter<W, E> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.finished {
            return Err(io::Error::other("encoder writer already finished"));
        }
        let inner = self
            .inner
            .as_mut()
            .ok_or_else(|| io::Error::other("encoder writer already finished"))?;
        let mut consumed = 0;
        while consumed < buf.len() {
            let (p, status) = self.enc.encode(&buf[consumed..], &mut self.scratch)?;
            inner.write_all(&self.scratch[..p.written])?;
            consumed += p.consumed;
            match status {
                Status::InputEmpty => break,
                Status::OutputFull => continue,
                Status::StreamEnd => break,
            }
        }
        Ok(consumed)
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.inner.as_mut() {
            Some(w) => w.flush(),
            None => Ok(()),
        }
    }
}

impl<W: Write, E: Encoder> Drop for EncoderWriter<W, E> {
    fn drop(&mut self) {
        // Best-effort: errors here can't propagate. Call `finish()`
        // explicitly if you need to know.
        let _ = self.do_finish();
    }
}

// ─── EncoderReader ──────────────────────────────────────────────────────

/// Wraps an `R: Read`, exposing a `Read` impl that returns compressed
/// bytes. Pulls plaintext from `R` on demand and streams it through
/// the encoder.
///
/// `Read::read` returns 0 once the underlying reader is exhausted *and*
/// the encoder's tail has been fully drained — the natural EOF signal.
pub struct EncoderReader<R: Read, E: Encoder> {
    enc: E,
    inner: R,
    in_buf: Vec<u8>,
    in_filled: usize,
    in_consumed: usize,
    inner_eof: bool,
    finished: bool,
}

impl<R: Read, E: Encoder> EncoderReader<R, E> {
    pub fn new(inner: R, enc: E) -> Self {
        Self {
            enc,
            inner,
            in_buf: vec![0u8; SCRATCH],
            in_filled: 0,
            in_consumed: 0,
            inner_eof: false,
            finished: false,
        }
    }

    pub fn get_ref(&self) -> &R {
        &self.inner
    }
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.inner
    }
    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Read, E: Encoder> Read for EncoderReader<R, E> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            // If the encoder has any tail bytes still to emit, drain
            // them first (one chunk per call, per Read contract).
            if self.finished {
                return Ok(0);
            }
            // If we have buffered plaintext, push it through encode().
            if self.in_consumed < self.in_filled {
                let (p, status) = self
                    .enc
                    .encode(&self.in_buf[self.in_consumed..self.in_filled], buf)?;
                self.in_consumed += p.consumed;
                if p.written > 0 {
                    let _ = status;
                    return Ok(p.written);
                }
                // No output this round — either input was fully consumed
                // (refill below) or output is too small (impossible: buf
                // is the caller's slice, which they sized).
                if matches!(status, Status::OutputFull) {
                    // Caller's slice can't hold any output. Treat as 0.
                    return Ok(0);
                }
                // Fall through to refill.
            }
            // Try to refill from the inner reader.
            if !self.inner_eof {
                self.in_consumed = 0;
                self.in_filled = self.inner.read(&mut self.in_buf)?;
                if self.in_filled == 0 {
                    self.inner_eof = true;
                }
                continue;
            }
            // Inner exhausted; drain encoder's tail.
            let (p, status) = self.enc.finish(buf)?;
            if matches!(status, Status::StreamEnd) {
                self.finished = true;
            }
            if p.written > 0 {
                return Ok(p.written);
            }
            if self.finished {
                return Ok(0);
            }
            // Codec asked for more output room but caller's buf is fixed.
            // Return 0 so caller can supply more space; another finish()
            // tick will run next call.
            return Ok(0);
        }
    }
}

// ─── DecoderWriter ──────────────────────────────────────────────────────

/// Wraps a `W: Write`, exposing a `Write` impl that takes compressed
/// bytes, decompresses them, and forwards the plaintext to `W`.
pub struct DecoderWriter<W: Write, D: Decoder> {
    dec: D,
    inner: Option<W>,
    scratch: Vec<u8>,
    finished: bool,
}

impl<W: Write, D: Decoder> DecoderWriter<W, D> {
    pub fn new(inner: W, dec: D) -> Self {
        Self {
            dec,
            inner: Some(inner),
            scratch: vec![0u8; SCRATCH],
            finished: false,
        }
    }

    /// Panics if `finish` has already been called.
    pub fn get_ref(&self) -> &W {
        self.inner
            .as_ref()
            .expect("inner already taken by finish()")
    }
    /// Panics if `finish` has already been called.
    pub fn get_mut(&mut self) -> &mut W {
        self.inner
            .as_mut()
            .expect("inner already taken by finish()")
    }

    /// Finalise the decoder (decompressing any final bytes from the
    /// internal buffer) and return the inner writer.
    pub fn finish(mut self) -> io::Result<W> {
        self.do_finish()?;
        Ok(self
            .inner
            .take()
            .expect("inner present until finish() takes it"))
    }

    fn do_finish(&mut self) -> io::Result<()> {
        if self.finished {
            return Ok(());
        }
        let inner = match self.inner.as_mut() {
            Some(w) => w,
            None => return Ok(()),
        };
        loop {
            let (p, status) = self.dec.finish(&mut self.scratch)?;
            inner.write_all(&self.scratch[..p.written])?;
            if matches!(status, Status::StreamEnd) {
                break;
            }
            if p.written == 0 {
                return Err(io::Error::other("decoder stalled in finish"));
            }
        }
        self.finished = true;
        Ok(())
    }
}

impl<W: Write, D: Decoder> Write for DecoderWriter<W, D> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.finished {
            return Err(io::Error::other("decoder writer already finished"));
        }
        let inner = self
            .inner
            .as_mut()
            .ok_or_else(|| io::Error::other("decoder writer already finished"))?;
        let mut consumed = 0;
        while consumed < buf.len() {
            let (p, status) = self.dec.decode(&buf[consumed..], &mut self.scratch)?;
            inner.write_all(&self.scratch[..p.written])?;
            consumed += p.consumed;
            match status {
                Status::InputEmpty => break,
                Status::OutputFull => continue,
                Status::StreamEnd => break,
            }
        }
        Ok(consumed)
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.inner.as_mut() {
            Some(w) => w.flush(),
            None => Ok(()),
        }
    }
}

impl<W: Write, D: Decoder> Drop for DecoderWriter<W, D> {
    fn drop(&mut self) {
        let _ = self.do_finish();
    }
}

// ─── DecoderReader ──────────────────────────────────────────────────────

/// Wraps an `R: Read`, exposing a `Read` impl that returns plaintext
/// bytes. Pulls compressed input from `R` on demand.
pub struct DecoderReader<R: Read, D: Decoder> {
    dec: D,
    inner: R,
    in_buf: Vec<u8>,
    in_filled: usize,
    in_consumed: usize,
    inner_eof: bool,
    finished: bool,
}

impl<R: Read, D: Decoder> DecoderReader<R, D> {
    pub fn new(inner: R, dec: D) -> Self {
        Self {
            dec,
            inner,
            in_buf: vec![0u8; SCRATCH],
            in_filled: 0,
            in_consumed: 0,
            inner_eof: false,
            finished: false,
        }
    }

    pub fn get_ref(&self) -> &R {
        &self.inner
    }
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.inner
    }
    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Read, D: Decoder> Read for DecoderReader<R, D> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            if self.finished {
                return Ok(0);
            }
            // Call decode() unconditionally — even when `in_buf` is empty.
            // Some decoders (notably deflate-family) eagerly absorb input
            // into a private bit-reader before emitting all of the output
            // it expands to, so the next read may need to drain that
            // pending output without supplying any new compressed bytes.
            // Passing an empty input slice when there's nothing buffered
            // is a no-op for decoders that don't carry internal state.
            let (p, status) = self
                .dec
                .decode(&self.in_buf[self.in_consumed..self.in_filled], buf)?;
            self.in_consumed += p.consumed;
            if matches!(status, Status::StreamEnd) {
                self.finished = true;
            }
            if p.written > 0 {
                return Ok(p.written);
            }
            if self.finished {
                return Ok(0);
            }
            // No output this round. If decode reported InputEmpty we can
            // try to refill; OutputFull is impossible here because `buf`
            // is non-empty and we just wrote zero bytes into it.
            if !self.inner_eof {
                self.in_consumed = 0;
                self.in_filled = self.inner.read(&mut self.in_buf)?;
                if self.in_filled == 0 {
                    self.inner_eof = true;
                }
                continue;
            }
            // Inner exhausted and decoder produced nothing — wrap up via
            // finish(). A well-formed stream reaches StreamEnd; a
            // truncated one surfaces UnexpectedEnd from the codec.
            let (p, status) = self.dec.finish(buf)?;
            if matches!(status, Status::StreamEnd) {
                self.finished = true;
            }
            if p.written > 0 {
                return Ok(p.written);
            }
            return Ok(0);
        }
    }
}
