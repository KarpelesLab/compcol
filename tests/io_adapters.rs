//! Integration tests for the four `std::io` adapters in `compcol::io`.
//!
//! Each adapter is tested through the canonical pattern its dual would
//! be used in (write through encoder → read back through decoder, and
//! vice versa), plus a Drop-runs-finish test for the two writer
//! adapters and a >256 KiB round-trip that pins down the brotli
//! `raw_finish` fix end-to-end.

#![cfg(all(feature = "std", feature = "gzip"))]

use std::io::{Cursor, Read, Write};

use compcol::Algorithm;
use compcol::gzip::Gzip;
use compcol::io::{DecoderReader, DecoderWriter, EncoderReader, EncoderWriter};

// A mixed corpus matching the vec-helpers tests so failures here can
// be cross-referenced against those.
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

// ─── EncoderWriter + DecoderReader (the most common pair) ───────────────

#[test]
fn encoder_writer_paired_with_decoder_reader() {
    let input = payload(96 * 1024);

    // Compress.
    let mut w = EncoderWriter::new(Vec::<u8>::new(), Gzip::encoder());
    w.write_all(&input).unwrap();
    let compressed = w.finish().unwrap();
    assert!(compressed.len() < input.len());

    // Decompress.
    let mut r = DecoderReader::new(Cursor::new(&compressed), Gzip::decoder());
    let mut decoded = Vec::new();
    r.read_to_end(&mut decoded).unwrap();
    assert_eq!(decoded, input);
}

// ─── EncoderReader + DecoderWriter (the other pair) ─────────────────────

#[test]
fn encoder_reader_paired_with_decoder_writer() {
    let input = payload(96 * 1024);

    // Compress by reading plaintext through an EncoderReader.
    let mut r = EncoderReader::new(Cursor::new(input.clone()), Gzip::encoder());
    let mut compressed = Vec::new();
    r.read_to_end(&mut compressed).unwrap();

    // Decompress by writing compressed bytes through a DecoderWriter.
    let mut w = DecoderWriter::new(Vec::<u8>::new(), Gzip::decoder());
    w.write_all(&compressed).unwrap();
    let decoded = w.finish().unwrap();
    assert_eq!(decoded, input);
}

// ─── drop runs finish (writers) ─────────────────────────────────────────

#[test]
fn encoder_writer_drop_runs_finish() {
    let input = b"hello, drop\n";
    // Hand the writer the *sink*, then read back via the cell after
    // drop. Easiest path: wrap a `Vec<u8>` and pull it out via the
    // Drop-skipping pattern below — but `finish()` is what the docs
    // recommend. We test the Drop path by sharing an `Rc<RefCell>`.
    use std::cell::RefCell;
    use std::rc::Rc;

    struct SharedSink(Rc<RefCell<Vec<u8>>>);
    impl Write for SharedSink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.borrow_mut().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let sink = Rc::new(RefCell::new(Vec::new()));
    {
        let mut w = EncoderWriter::new(SharedSink(sink.clone()), Gzip::encoder());
        w.write_all(input).unwrap();
        // No finish() — let Drop run it.
    }
    let compressed = sink.borrow().clone();
    assert!(!compressed.is_empty(), "Drop did not finish encoder");

    // Sanity: decompresses to original.
    let mut r = DecoderReader::new(Cursor::new(&compressed), Gzip::decoder());
    let mut decoded = Vec::new();
    r.read_to_end(&mut decoded).unwrap();
    assert_eq!(decoded, input);
}

#[test]
fn decoder_writer_drop_does_not_panic_on_partial_input() {
    // If the decoder is half-fed, Drop's best-effort finish swallows the
    // resulting Error::UnexpectedEnd rather than panicking.
    let _w = DecoderWriter::new(Vec::<u8>::new(), Gzip::decoder());
    // drop without writing
}

// ─── large round-trip (pins down the brotli raw_finish fix) ─────────────

#[cfg(feature = "brotli")]
#[test]
fn brotli_above_old_buggy_size_via_io_adapters() {
    use compcol::brotli::Brotli;
    let input = payload(1_000_000);

    let mut w = EncoderWriter::new(Vec::<u8>::new(), Brotli::encoder());
    w.write_all(&input).unwrap();
    let compressed = w.finish().unwrap();

    let mut r = DecoderReader::new(Cursor::new(&compressed), Brotli::decoder());
    let mut decoded = Vec::new();
    r.read_to_end(&mut decoded).unwrap();
    assert_eq!(decoded.len(), input.len());
    assert_eq!(decoded, input);
}

// ─── small read buffers force decoder to handle partial drains ──────────

#[test]
fn decoder_reader_handles_small_read_buffers() {
    let input = payload(64 * 1024);

    let mut w = EncoderWriter::new(Vec::<u8>::new(), Gzip::encoder());
    w.write_all(&input).unwrap();
    let compressed = w.finish().unwrap();

    let mut r = DecoderReader::new(Cursor::new(&compressed), Gzip::decoder());
    let mut decoded = Vec::new();
    // Drain 17 bytes at a time — exercises the "no progress this call,
    // try again" branches inside Read::read.
    let mut buf = [0u8; 17];
    loop {
        let n = r.read(&mut buf).unwrap();
        if n == 0 {
            break;
        }
        decoded.extend_from_slice(&buf[..n]);
    }
    assert_eq!(decoded, input);
}
