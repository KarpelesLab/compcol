//! Async `tokio::io::AsyncRead` / `AsyncWrite` adapters.
//!
//! Mirrors the four blocking adapters in [`crate::io`] for the tokio
//! runtime. Same model, same constructor shape, same `finish` /
//! `into_inner` / `get_ref` accessors; only the trait bounds change.
//!
//! Gated on the new `tokio` Cargo feature, which itself pulls in
//! `std`. Adds a single optional dependency on the `tokio` crate
//! (default-features off, just the trait definitions are needed).
//!
//! ```ignore
//! use tokio::io::{AsyncReadExt, AsyncWriteExt};
//! use compcol::{Algorithm, gzip::Gzip};
//! use compcol::tokio_io::{EncoderWriter, DecoderReader};
//!
//! # async fn ex(file: tokio::fs::File, src: tokio::fs::File) -> std::io::Result<()> {
//! let mut w = EncoderWriter::new(file, Gzip::encoder());
//! w.write_all(b"hello, async gzip\n").await?;
//! let _file = w.shutdown_into_inner().await?;
//!
//! let mut r = DecoderReader::new(src, Gzip::decoder());
//! let mut bytes = Vec::new();
//! r.read_to_end(&mut bytes).await?;
//! # Ok(())
//! # }
//! ```

extern crate alloc;
extern crate std;

use alloc::vec;
use alloc::vec::Vec;
use core::pin::Pin;
use core::task::{Context, Poll};
use std::io;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{Decoder, Encoder, Error, Status};

const SCRATCH: usize = 64 * 1024;

// Shared `?`-style helper for Poll<io::Result<T>>.
macro_rules! ready_poll {
    ($e:expr) => {
        match $e {
            Poll::Ready(v) => v,
            Poll::Pending => return Poll::Pending,
        }
    };
}

// ─── EncoderWriter ──────────────────────────────────────────────────────

/// Async dual of [`crate::io::EncoderWriter`]. Wraps a
/// `W: AsyncWrite + Unpin` and exposes `AsyncWrite` itself: bytes you
/// write are compressed and forwarded to the inner.
///
/// Call [`shutdown_into_inner`](Self::shutdown_into_inner) to flush the
/// encoder's tail bytes and recover the inner writer. The standard
/// `AsyncWrite::poll_shutdown` does the flush but doesn't return the
/// inner — for the typical "compress to a file, then keep the handle"
/// flow, prefer `shutdown_into_inner`.
pub struct EncoderWriter<W: AsyncWrite + Unpin, E: Encoder + Unpin> {
    enc: E,
    inner: W,
    scratch: Vec<u8>,
    /// Encoded bytes waiting to be flushed to `inner`. `out_pos..out.len()`
    /// is the unwritten slice. Cleared once fully written.
    out: Vec<u8>,
    out_pos: usize,
    /// Position within the encoder's `finish` drain state during shutdown.
    finished: bool,
}

impl<W: AsyncWrite + Unpin, E: Encoder + Unpin> EncoderWriter<W, E> {
    /// Wrap `inner` with a caller-supplied encoder.
    pub fn new(inner: W, enc: E) -> Self {
        Self {
            enc,
            inner,
            scratch: vec![0u8; SCRATCH],
            out: Vec::with_capacity(SCRATCH),
            out_pos: 0,
            finished: false,
        }
    }

    pub fn get_ref(&self) -> &W {
        &self.inner
    }
    pub fn get_mut(&mut self) -> &mut W {
        &mut self.inner
    }

    /// Drain encoded tail bytes into `inner` and recover the inner writer.
    ///
    /// Async equivalent of the sync
    /// [`crate::io::EncoderWriter::finish`]. Calls `poll_shutdown` to
    /// completion, then returns ownership of `inner`.
    pub async fn shutdown_into_inner(mut self) -> io::Result<W> {
        // We call poll_shutdown directly via poll_fn so this works
        // without bringing the `tokio = ["io-util"]` extension trait
        // into the dep set.
        core::future::poll_fn(|cx| Pin::new(&mut self).poll_shutdown(cx)).await?;
        Ok(self.inner)
    }

    /// Best-effort sync drain used by both `poll_write` and `poll_shutdown`
    /// to push `self.out` out before doing more work.
    fn drain_out(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.out_pos < self.out.len() {
            let n =
                ready_poll!(Pin::new(&mut self.inner).poll_write(cx, &self.out[self.out_pos..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "inner returned 0 from poll_write",
                )));
            }
            self.out_pos += n;
        }
        self.out.clear();
        self.out_pos = 0;
        Poll::Ready(Ok(()))
    }
}

impl<W: AsyncWrite + Unpin, E: Encoder + Unpin> AsyncWrite for EncoderWriter<W, E> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = Pin::into_inner(self);
        if me.finished {
            return Poll::Ready(Err(io::Error::other("encoder writer already finished")));
        }
        // First, push any previously-encoded bytes out.
        ready_poll!(me.drain_out(cx))?;
        // Encode some of buf into scratch, stage in `out`. We don't
        // necessarily fully consume buf — a small encode call is fine,
        // tokio callers will simply re-poll.
        let (p, _status) = me.enc.encode(buf, &mut me.scratch)?;
        me.out.extend_from_slice(&me.scratch[..p.written]);
        Poll::Ready(Ok(p.consumed))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = Pin::into_inner(self);
        ready_poll!(me.drain_out(cx))?;
        Pin::new(&mut me.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = Pin::into_inner(self);
        // Drain whatever's already staged.
        ready_poll!(me.drain_out(cx))?;
        // Drive enc.finish until StreamEnd, staging into `out` as we go.
        while !me.finished {
            let (p, status) = me.enc.finish(&mut me.scratch)?;
            me.out.extend_from_slice(&me.scratch[..p.written]);
            ready_poll!(me.drain_out(cx))?;
            if matches!(status, Status::StreamEnd) {
                me.finished = true;
            } else if p.written == 0 {
                return Poll::Ready(Err(io::Error::other("encoder stalled in finish")));
            }
        }
        Pin::new(&mut me.inner).poll_shutdown(cx)
    }
}

// ─── DecoderWriter ──────────────────────────────────────────────────────

/// Async dual of [`crate::io::DecoderWriter`]: you write *compressed*
/// bytes, the wrapped `W` receives the decoded plaintext.
pub struct DecoderWriter<W: AsyncWrite + Unpin, D: Decoder + Unpin> {
    dec: D,
    inner: W,
    scratch: Vec<u8>,
    out: Vec<u8>,
    out_pos: usize,
    finished: bool,
}

impl<W: AsyncWrite + Unpin, D: Decoder + Unpin> DecoderWriter<W, D> {
    pub fn new(inner: W, dec: D) -> Self {
        Self {
            dec,
            inner,
            scratch: vec![0u8; SCRATCH],
            out: Vec::with_capacity(SCRATCH),
            out_pos: 0,
            finished: false,
        }
    }

    pub fn get_ref(&self) -> &W {
        &self.inner
    }
    pub fn get_mut(&mut self) -> &mut W {
        &mut self.inner
    }

    pub async fn shutdown_into_inner(mut self) -> io::Result<W> {
        core::future::poll_fn(|cx| Pin::new(&mut self).poll_shutdown(cx)).await?;
        Ok(self.inner)
    }

    fn drain_out(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.out_pos < self.out.len() {
            let n =
                ready_poll!(Pin::new(&mut self.inner).poll_write(cx, &self.out[self.out_pos..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "inner returned 0 from poll_write",
                )));
            }
            self.out_pos += n;
        }
        self.out.clear();
        self.out_pos = 0;
        Poll::Ready(Ok(()))
    }
}

impl<W: AsyncWrite + Unpin, D: Decoder + Unpin> AsyncWrite for DecoderWriter<W, D> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = Pin::into_inner(self);
        if me.finished {
            return Poll::Ready(Err(io::Error::other("decoder writer already finished")));
        }
        ready_poll!(me.drain_out(cx))?;
        let (p, _status) = me.dec.decode(buf, &mut me.scratch)?;
        me.out.extend_from_slice(&me.scratch[..p.written]);
        Poll::Ready(Ok(p.consumed))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = Pin::into_inner(self);
        ready_poll!(me.drain_out(cx))?;
        Pin::new(&mut me.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = Pin::into_inner(self);
        ready_poll!(me.drain_out(cx))?;
        while !me.finished {
            let (p, status) = me.dec.finish(&mut me.scratch)?;
            me.out.extend_from_slice(&me.scratch[..p.written]);
            ready_poll!(me.drain_out(cx))?;
            if matches!(status, Status::StreamEnd) {
                me.finished = true;
            } else if p.written == 0 {
                return Poll::Ready(Err(io::Error::other("decoder stalled in finish")));
            }
        }
        Pin::new(&mut me.inner).poll_shutdown(cx)
    }
}

// ─── EncoderReader ──────────────────────────────────────────────────────

/// Async dual of [`crate::io::EncoderReader`]: you read *compressed*
/// bytes; plaintext is pulled lazily from the wrapped `R`.
pub struct EncoderReader<R: AsyncRead + Unpin, E: Encoder + Unpin> {
    enc: E,
    inner: R,
    in_buf: Vec<u8>,
    in_filled: usize,
    in_consumed: usize,
    inner_eof: bool,
    finished: bool,
}

impl<R: AsyncRead + Unpin, E: Encoder + Unpin> EncoderReader<R, E> {
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

impl<R: AsyncRead + Unpin, E: Encoder + Unpin> AsyncRead for EncoderReader<R, E> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = Pin::into_inner(self);
        loop {
            if me.finished {
                return Poll::Ready(Ok(()));
            }
            // Drive plaintext through encode() into the caller's buf.
            if me.in_consumed < me.in_filled {
                let avail = buf.remaining();
                if avail == 0 {
                    return Poll::Ready(Ok(()));
                }
                // SAFETY-free: write into ReadBuf's initialize_unfilled().
                let dst = buf.initialize_unfilled_to(avail);
                let (p, status) = me
                    .enc
                    .encode(&me.in_buf[me.in_consumed..me.in_filled], dst)?;
                me.in_consumed += p.consumed;
                buf.advance(p.written);
                if p.written > 0 {
                    let _ = status;
                    return Poll::Ready(Ok(()));
                }
                if matches!(status, Status::OutputFull) {
                    return Poll::Ready(Ok(()));
                }
                // Fall through to refill / finish.
            }
            if !me.inner_eof {
                let mut tmp = ReadBuf::new(&mut me.in_buf);
                ready_poll!(Pin::new(&mut me.inner).poll_read(cx, &mut tmp))?;
                let filled = tmp.filled().len();
                if filled == 0 {
                    me.inner_eof = true;
                } else {
                    me.in_consumed = 0;
                    me.in_filled = filled;
                }
                continue;
            }
            // No more plaintext. Drain enc.finish into the caller's buf.
            let avail = buf.remaining();
            if avail == 0 {
                return Poll::Ready(Ok(()));
            }
            let dst = buf.initialize_unfilled_to(avail);
            let (p, status) = me.enc.finish(dst)?;
            buf.advance(p.written);
            if matches!(status, Status::StreamEnd) {
                me.finished = true;
            }
            if p.written > 0 {
                return Poll::Ready(Ok(()));
            }
            if me.finished {
                return Poll::Ready(Ok(()));
            }
            return Poll::Ready(Ok(()));
        }
    }
}

// ─── DecoderReader ──────────────────────────────────────────────────────

/// Async dual of [`crate::io::DecoderReader`]: you read *plaintext*;
/// the wrapped `R` provides compressed bytes.
pub struct DecoderReader<R: AsyncRead + Unpin, D: Decoder + Unpin> {
    dec: D,
    inner: R,
    in_buf: Vec<u8>,
    in_filled: usize,
    in_consumed: usize,
    inner_eof: bool,
    finished: bool,
}

impl<R: AsyncRead + Unpin, D: Decoder + Unpin> DecoderReader<R, D> {
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

impl<R: AsyncRead + Unpin, D: Decoder + Unpin> AsyncRead for DecoderReader<R, D> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = Pin::into_inner(self);
        loop {
            if me.finished {
                return Poll::Ready(Ok(()));
            }
            if me.in_consumed < me.in_filled {
                let avail = buf.remaining();
                if avail == 0 {
                    return Poll::Ready(Ok(()));
                }
                let dst = buf.initialize_unfilled_to(avail);
                let (p, status) = me
                    .dec
                    .decode(&me.in_buf[me.in_consumed..me.in_filled], dst)?;
                me.in_consumed += p.consumed;
                buf.advance(p.written);
                if matches!(status, Status::StreamEnd) {
                    me.finished = true;
                }
                if p.written > 0 {
                    return Poll::Ready(Ok(()));
                }
                if matches!(status, Status::OutputFull) {
                    return Poll::Ready(Ok(()));
                }
                if me.finished {
                    return Poll::Ready(Ok(()));
                }
            }
            if !me.inner_eof {
                let mut tmp = ReadBuf::new(&mut me.in_buf);
                ready_poll!(Pin::new(&mut me.inner).poll_read(cx, &mut tmp))?;
                let filled = tmp.filled().len();
                if filled == 0 {
                    me.inner_eof = true;
                } else {
                    me.in_consumed = 0;
                    me.in_filled = filled;
                }
                continue;
            }
            // EOF on inner — drain decoder tail.
            let avail = buf.remaining();
            if avail == 0 {
                return Poll::Ready(Ok(()));
            }
            let dst = buf.initialize_unfilled_to(avail);
            let (p, status) = me.dec.finish(dst)?;
            buf.advance(p.written);
            if matches!(status, Status::StreamEnd) {
                me.finished = true;
            }
            if p.written == 0 && !me.finished {
                // Inner is at EOF and finish() produced no output yet did
                // not reach StreamEnd: the stream is truncated. Returning
                // Ready(Ok) with nothing filled looks like a clean EOF and
                // would silently drop the missing tail, so surface it as
                // an error — mirroring the writer-path stall guard in
                // poll_shutdown().
                return Poll::Ready(Err(io::Error::from(Error::UnexpectedEnd)));
            }
            return Poll::Ready(Ok(()));
        }
    }
}
