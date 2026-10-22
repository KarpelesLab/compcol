//! Smoke tests for the four `compcol::tokio_io` async adapters.
//!
//! Mirrors the sync adapter coverage in `tests/io_adapters.rs` for the
//! tokio path. Each test runs on `tokio::runtime::Runtime::new()` so
//! the test binary doesn't need the `tokio = ["macros"]` dependency.

#![cfg(all(feature = "tokio", feature = "gzip"))]

use compcol::Algorithm;
use compcol::gzip::Gzip;
use compcol::tokio_io::{DecoderReader, DecoderWriter, EncoderReader, EncoderWriter};
use std::io::Cursor;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn payload(n: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(n);
    let phrase = b"The_quick_brown_fox_jumps_over_the_lazy_dog. ";
    let mut state: u32 = 0xC0FFEE_u32;
    while out.len() < n {
        for _ in 0..32 {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            out.push(b"abcdef"[(state as usize) % 6]);
        }
        out.extend_from_slice(phrase);
    }
    out.truncate(n);
    out
}

fn runtime() -> tokio::runtime::Runtime {
    // current_thread runtime; we don't need a worker pool for these
    // single-task tests, and it works on any platform without the
    // tokio = ["rt-multi-thread"] feature.
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

#[test]
fn encoder_writer_paired_with_decoder_reader() {
    let rt = runtime();
    let input = payload(96 * 1024);
    let cloned = input.clone();
    rt.block_on(async move {
        // Compress.
        let mut w = EncoderWriter::new(Vec::<u8>::new(), Gzip::encoder());
        w.write_all(&cloned).await.unwrap();
        let compressed = w.shutdown_into_inner().await.unwrap();
        assert!(compressed.len() < cloned.len());

        // Decompress.
        let mut r = DecoderReader::new(Cursor::new(compressed), Gzip::decoder());
        let mut decoded = Vec::new();
        r.read_to_end(&mut decoded).await.unwrap();
        assert_eq!(decoded, cloned);
    });
}

#[test]
fn encoder_reader_paired_with_decoder_writer() {
    let rt = runtime();
    let input = payload(64 * 1024);
    let cloned = input.clone();
    rt.block_on(async move {
        let mut r = EncoderReader::new(Cursor::new(cloned.clone()), Gzip::encoder());
        let mut compressed = Vec::new();
        r.read_to_end(&mut compressed).await.unwrap();

        let mut w = DecoderWriter::new(Vec::<u8>::new(), Gzip::decoder());
        w.write_all(&compressed).await.unwrap();
        let decoded = w.shutdown_into_inner().await.unwrap();
        assert_eq!(decoded, cloned);
    });
}

#[test]
fn one_mib_round_trip_via_encoder_writer_decoder_reader() {
    // Pins down the brotli-style large-stream regression at the async layer.
    let rt = runtime();
    let input = payload(1_000_000);
    let cloned = input.clone();
    rt.block_on(async move {
        let mut w = EncoderWriter::new(Vec::<u8>::new(), Gzip::encoder());
        w.write_all(&cloned).await.unwrap();
        let compressed = w.shutdown_into_inner().await.unwrap();

        let mut r = DecoderReader::new(Cursor::new(compressed), Gzip::decoder());
        let mut decoded = Vec::new();
        r.read_to_end(&mut decoded).await.unwrap();
        assert_eq!(decoded.len(), cloned.len());
        assert_eq!(decoded, cloned);
    });
}

// ─── zero-progress writes, pending decoder output ───────────────────────

fn noise(n: usize) -> Vec<u8> {
    let mut st = 7u32;
    (0..n)
        .map(|_| {
            st = st.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            (st >> 24) as u8
        })
        .collect()
}

fn sync_compress<E: compcol::Encoder>(enc: E, data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut w = compcol::io::EncoderWriter::new(Vec::new(), enc);
    w.write_all(data).unwrap();
    w.finish().unwrap()
}

// bzip2 emits a whole (900 kB) block in one go; a `poll_write` that
// only drains part of it into `scratch` consumes no input and used to
// return Ok(0), which `write_all` turns into `WriteZero`.
#[cfg(feature = "bzip2")]
#[test]
fn encoder_writer_write_all_with_block_larger_than_scratch() {
    use compcol::bzip2::Bzip2;
    let input = noise(3_000_000);
    runtime().block_on(async {
        let mut w = EncoderWriter::new(Vec::<u8>::new(), Bzip2::encoder());
        w.write_all(&input).await.unwrap();
        let compressed = w.shutdown_into_inner().await.unwrap();
        assert_eq!(
            compcol::vec::decompress_to_vec::<Bzip2>(&compressed).unwrap(),
            input
        );
    });
}

// A few hundred compressed bytes expanding to megabytes: the decoder
// returns 64 KiB of output per call without consuming input.
#[cfg(feature = "zstd")]
#[test]
fn decoder_writer_write_all_with_high_expansion() {
    use compcol::zstd::Zstd;
    let input = vec![0u8; 5_000_000];
    let compressed = sync_compress(Zstd::encoder(), &input);
    runtime().block_on(async {
        let mut w = DecoderWriter::new(Vec::<u8>::new(), Zstd::decoder());
        w.write_all(&compressed).await.unwrap();
        assert_eq!(w.shutdown_into_inner().await.unwrap(), input);
    });
}

// deflate64 absorbs all input while output is still pending; shutdown
// must drain it before `finish`, which rejects a half-drained stream.
#[cfg(feature = "deflate64")]
#[test]
fn decoder_writer_shutdown_drains_pending_output() {
    use compcol::deflate64::Deflate64;
    let input = vec![0u8; 5_000_000];
    let compressed = sync_compress(Deflate64::encoder(), &input);
    runtime().block_on(async {
        let mut w = DecoderWriter::new(Vec::<u8>::new(), Deflate64::decoder());
        w.write_all(&compressed).await.unwrap();
        assert_eq!(w.shutdown_into_inner().await.unwrap(), input);
    });
}

#[test]
fn decoder_reader_tiny_reads_raw_deflate() {
    use compcol::deflate::Deflate;
    let input = payload(50_000);
    let compressed = compcol::vec::compress_to_vec::<Deflate>(&input).unwrap();
    runtime().block_on(async {
        let mut r = DecoderReader::new(Cursor::new(compressed), Deflate::decoder());
        let mut decoded = Vec::new();
        let mut buf = [0u8; 3];
        loop {
            let n = r.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            decoded.extend_from_slice(&buf[..n]);
        }
        assert_eq!(decoded, input);
    });
}

/// Serves `data`, then stays `Pending` forever: a peer that sent its whole
/// message and now waits for a reply.
#[cfg(feature = "bzip2")]
struct IdleAfter {
    data: Vec<u8>,
    pos: usize,
}

#[cfg(feature = "bzip2")]
impl tokio::io::AsyncRead for IdleAfter {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.pos >= self.data.len() {
            return std::task::Poll::Pending;
        }
        let n = buf.remaining().min(self.data.len() - self.pos);
        let pos = self.pos;
        buf.put_slice(&self.data[pos..pos + n]);
        self.pos += n;
        std::task::Poll::Ready(Ok(()))
    }
}

#[cfg(feature = "bzip2")]
#[test]
fn decoder_reader_delivers_buffered_output_before_more_input() {
    use compcol::bzip2::Bzip2;
    use std::pin::Pin;
    use std::task::{Context, Poll, Waker};
    use tokio::io::{AsyncRead, ReadBuf};

    let input = vec![b'A'; 1_000_000];
    let compressed = sync_compress(Bzip2::encoder(), &input);
    let mut r = DecoderReader::new(
        IdleAfter {
            data: compressed,
            pos: 0,
        },
        Bzip2::decoder(),
    );
    let mut cx = Context::from_waker(Waker::noop());
    let mut got = 0usize;
    let mut buf = vec![0u8; 8192];
    loop {
        let mut rb = ReadBuf::new(&mut buf);
        match Pin::new(&mut r).poll_read(&mut cx, &mut rb) {
            Poll::Ready(Ok(())) if rb.filled().is_empty() => break,
            Poll::Ready(Ok(())) => got += rb.filled().len(),
            Poll::Ready(Err(e)) => panic!("{e}"),
            Poll::Pending => break,
        }
    }
    assert_eq!(got, input.len());
}
