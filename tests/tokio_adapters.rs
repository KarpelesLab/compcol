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
