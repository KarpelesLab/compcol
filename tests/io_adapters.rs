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

// Regression for https://github.com/KarpelesLab/compcol/issues/17 — a tiny,
// highly-compressible zlib payload that fits its entire compressed form in
// the adapter's first refill. deflate's bit-reader absorbs every input byte
// into its accumulator on the first decode call, so the wrapping decoder
// reports `in_consumed == in_filled` immediately while still holding nearly
// all of the expansion as pending output. The adapter has to keep calling
// decode() — even with an empty input slice — to drain that pending output;
// the previous code skipped decode in this state and gave up to finish(),
// which errored with `UnexpectedEnd`.
#[cfg(feature = "zlib")]
#[test]
fn decoder_reader_drains_pending_output_when_input_exhausted_zlib() {
    use compcol::zlib::Zlib;
    let input = b"hello hfsplus decmpfs world!".repeat(8); // 224 bytes
    let compressed = compcol::vec::compress_to_vec::<Zlib>(&input).unwrap();
    assert!(compressed.len() < 64); // fits in one inner read

    let mut r = DecoderReader::new(Cursor::new(&compressed), Zlib::decoder());
    let mut decoded = Vec::new();
    let mut buf = [0u8; 32];
    loop {
        let n = r.read(&mut buf).unwrap();
        if n == 0 {
            break;
        }
        decoded.extend_from_slice(&buf[..n]);
    }
    assert_eq!(decoded, input);
}

// Same shape as the zlib regression but for raw deflate — the underlying
// bit-reader is the same, so the bug surfaces identically once any wrapper
// no longer leaves trailer/header bytes hanging in the input slice.
#[cfg(feature = "deflate")]
#[test]
fn decoder_reader_drains_pending_output_when_input_exhausted_deflate() {
    use compcol::deflate::Deflate;
    let input = b"hello hfsplus decmpfs world!".repeat(8);
    let compressed = compcol::vec::compress_to_vec::<Deflate>(&input).unwrap();

    let mut r = DecoderReader::new(Cursor::new(&compressed), Deflate::decoder());
    let mut decoded = Vec::new();
    let mut buf = [0u8; 32];
    loop {
        let n = r.read(&mut buf).unwrap();
        if n == 0 {
            break;
        }
        decoded.extend_from_slice(&buf[..n]);
    }
    assert_eq!(decoded, input);
}

// ─── inner reader errors must not replay buffered bytes ─────────────────

/// Serves `data` in `chunk`-sized pieces and fails every other call with
/// `kind` — the way a reader hit by signals (`Interrupted`) or a
/// non-blocking socket (`WouldBlock`) behaves.
struct FlakyReader<'a> {
    data: &'a [u8],
    pos: usize,
    chunk: usize,
    kind: std::io::ErrorKind,
    fail_next: bool,
}

impl Read for FlakyReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.fail_next = !self.fail_next;
        if self.fail_next {
            return Err(std::io::Error::new(self.kind, "flaky"));
        }
        let n = self.chunk.min(buf.len()).min(self.data.len() - self.pos);
        buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

fn read_retrying<R: Read>(r: &mut R, bufsz: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = vec![0u8; bufsz];
    loop {
        match r.read(&mut buf) {
            Ok(0) => return out,
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
                ) => {}
            Err(e) => panic!("read failed: {e}"),
        }
    }
}

#[test]
fn reader_adapters_survive_transient_inner_errors() {
    let input = payload(150_000);
    let compressed = compcol::vec::compress_to_vec::<Gzip>(&input).unwrap();
    for kind in [
        std::io::ErrorKind::Interrupted,
        std::io::ErrorKind::WouldBlock,
    ] {
        for (chunk, bufsz) in [(usize::MAX, 64 * 1024), (13, 5)] {
            let inner = FlakyReader {
                data: &compressed,
                pos: 0,
                chunk,
                kind,
                fail_next: false,
            };
            let mut r = DecoderReader::new(inner, Gzip::decoder());
            assert_eq!(
                read_retrying(&mut r, bufsz),
                input,
                "DecoderReader {kind:?}"
            );

            let inner = FlakyReader {
                data: &input,
                pos: 0,
                chunk,
                kind,
                fail_next: false,
            };
            let mut r = EncoderReader::new(inner, Gzip::encoder());
            let out = read_retrying(&mut r, bufsz);
            assert_eq!(
                compcol::vec::decompress_to_vec::<Gzip>(&out).unwrap(),
                input,
                "EncoderReader {kind:?}"
            );
        }
    }
}

// ─── writer adapters: a failed inner write must not lose or repeat bytes ─

/// Accepts everything, except that every `period`-th call fails with
/// `WouldBlock` and the call before it is a short write — the way a
/// non-blocking socket behaves under back-pressure.
struct BackPressure {
    out: Vec<u8>,
    calls: usize,
    period: usize,
}

impl Write for BackPressure {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.calls += 1;
        match self.calls % self.period {
            0 => Err(std::io::ErrorKind::WouldBlock.into()),
            1 => {
                let n = buf.len().div_ceil(2);
                self.out.extend_from_slice(&buf[..n]);
                Ok(n)
            }
            _ => {
                self.out.extend_from_slice(buf);
                Ok(buf.len())
            }
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// `write_all`, but retrying on `WouldBlock` like an event-loop caller.
fn write_all_retrying<W: Write>(w: &mut W, mut buf: &[u8]) {
    while !buf.is_empty() {
        match w.write(buf) {
            Ok(0) => panic!("write returned 0"),
            Ok(n) => buf = &buf[n..],
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => panic!("write failed: {e}"),
        }
    }
}

#[test]
fn writer_adapters_survive_inner_wouldblock() {
    let input = payload(400_000);
    for period in [2, 3, 7] {
        let sink = BackPressure {
            out: Vec::new(),
            calls: 0,
            period,
        };
        let mut w = EncoderWriter::new(sink, Gzip::encoder());
        for chunk in input.chunks(10_000) {
            write_all_retrying(&mut w, chunk);
        }
        // `finish` consumes the writer, so it can't be retried: stop the
        // back-pressure first (staged bytes from a failed write still have
        // to go out ahead of the tail).
        w.get_mut().period = usize::MAX;
        let compressed = w.finish().unwrap().out;
        assert_eq!(
            compcol::vec::decompress_to_vec::<Gzip>(&compressed).unwrap(),
            input,
            "EncoderWriter period {period}"
        );

        let sink = BackPressure {
            out: Vec::new(),
            calls: 0,
            period,
        };
        let mut w = DecoderWriter::new(sink, Gzip::decoder());
        for chunk in compressed.chunks(1_000) {
            write_all_retrying(&mut w, chunk);
        }
        w.get_mut().period = usize::MAX;
        assert_eq!(
            w.finish().unwrap().out,
            input,
            "DecoderWriter period {period}"
        );
    }
}
