//! Decompression-bomb defense tests for `compcol::limit::LimitedDecoder`.

#![cfg(all(feature = "alloc", feature = "gzip"))]

use compcol::gzip::Gzip;
use compcol::limit::LimitedDecoder;
use compcol::{Algorithm, Decoder as _, Encoder as _, Error, Status};

/// Compress `input` once with default-config gzip and return the bytes.
fn gzip_compress(input: &[u8]) -> Vec<u8> {
    let mut enc = Gzip::encoder();
    let mut out = Vec::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut consumed = 0;
    while consumed < input.len() {
        let (p, _) = enc.encode(&input[consumed..], &mut buf).unwrap();
        out.extend_from_slice(&buf[..p.written]);
        consumed += p.consumed;
        if p.consumed == 0 && p.written == 0 {
            break;
        }
    }
    loop {
        let (p, s) = enc.finish(&mut buf).unwrap();
        out.extend_from_slice(&buf[..p.written]);
        if matches!(s, Status::StreamEnd) {
            break;
        }
    }
    out
}

/// Drive a decoder to completion, returning the decoded bytes or the
/// first error.
fn drain<D: compcol::Decoder>(dec: &mut D, compressed: &[u8]) -> Result<Vec<u8>, Error> {
    let mut decoded = Vec::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut c = 0;
    while c < compressed.len() {
        let (p, s) = dec.decode(&compressed[c..], &mut buf)?;
        decoded.extend_from_slice(&buf[..p.written]);
        c += p.consumed;
        if matches!(s, Status::StreamEnd) {
            return Ok(decoded);
        }
        if matches!(s, Status::InputEmpty) && c == compressed.len() {
            break;
        }
        if p.consumed == 0 && p.written == 0 {
            break;
        }
    }
    loop {
        let (p, s) = dec.finish(&mut buf)?;
        decoded.extend_from_slice(&buf[..p.written]);
        if matches!(s, Status::StreamEnd) {
            break;
        }
    }
    Ok(decoded)
}

#[test]
fn within_limit_round_trips_normally() {
    let payload = b"a small payload that fits in any budget".to_vec();
    let compressed = gzip_compress(&payload);
    let mut dec = LimitedDecoder::new(Gzip::decoder(), 4096);
    let decoded = drain(&mut dec, &compressed).unwrap();
    assert_eq!(decoded, payload);
    assert_eq!(dec.bytes_written(), payload.len() as u64);
}

#[test]
fn exact_limit_succeeds() {
    // Limit set to the exact decompressed length succeeds.
    let payload = vec![b'A'; 1024];
    let compressed = gzip_compress(&payload);
    let mut dec = LimitedDecoder::new(Gzip::decoder(), payload.len() as u64);
    let decoded = drain(&mut dec, &compressed).unwrap();
    assert_eq!(decoded, payload);
    assert_eq!(dec.remaining(), 0);
}

#[test]
fn over_limit_errors_with_output_limit_exceeded() {
    // 64 KiB of zeros compresses to a tiny stream. With a 1 KiB limit
    // the wrapper aborts before the buffer fills.
    let payload = vec![0u8; 64 * 1024];
    let compressed = gzip_compress(&payload);
    let mut dec = LimitedDecoder::new(Gzip::decoder(), 1024);
    let err = drain(&mut dec, &compressed).unwrap_err();
    assert_eq!(err, Error::OutputLimitExceeded);
    // The wrapper should have absorbed exactly 1 KiB before erroring.
    assert!(dec.bytes_written() <= 1024);
}

#[test]
fn zero_limit_rejects_any_non_empty_payload() {
    let payload = b"x";
    let compressed = gzip_compress(payload);
    let mut dec = LimitedDecoder::new(Gzip::decoder(), 0);
    let err = drain(&mut dec, &compressed).unwrap_err();
    assert_eq!(err, Error::OutputLimitExceeded);
    assert_eq!(dec.bytes_written(), 0);
}

#[test]
fn zero_limit_accepts_empty_stream() {
    // An empty gzip stream emits zero output bytes, so a zero budget
    // succeeds (the limit was never approached).
    let compressed = gzip_compress(b"");
    let mut dec = LimitedDecoder::new(Gzip::decoder(), 0);
    let decoded = drain(&mut dec, &compressed).unwrap();
    assert!(decoded.is_empty());
    assert_eq!(dec.bytes_written(), 0);
}

#[test]
fn reset_restores_budget() {
    let payload = vec![b'B'; 4096];
    let compressed = gzip_compress(&payload);

    let mut dec = LimitedDecoder::new(Gzip::decoder(), payload.len() as u64);
    let _ = drain(&mut dec, &compressed).unwrap();
    assert_eq!(dec.remaining(), 0);

    dec.reset();
    assert_eq!(dec.bytes_written(), 0);
    assert_eq!(dec.remaining(), payload.len() as u64);

    // The freshly-reset wrapper can decode the same stream again.
    let decoded = drain(&mut dec, &compressed).unwrap();
    assert_eq!(decoded, payload);
}

#[cfg(feature = "factory")]
#[test]
fn wraps_boxed_decoder_from_factory() {
    use compcol::factory;

    let payload = vec![0u8; 4096];
    let compressed = gzip_compress(&payload);

    // Box<dyn Decoder> from the factory, wrapped with a budget.
    let inner = factory::decoder_by_name("gzip").unwrap();
    let mut dec = LimitedDecoder::new(inner, 1024);
    let err = drain(&mut dec, &compressed).unwrap_err();
    assert_eq!(err, Error::OutputLimitExceeded);
}

#[cfg(feature = "std")]
#[test]
fn composes_with_io_decoder_reader() {
    use std::io::{Cursor, Read};

    let payload = vec![0u8; 32 * 1024];
    let compressed = gzip_compress(&payload);

    let limited = LimitedDecoder::new(Gzip::decoder(), 4 * 1024);
    let mut r = compcol::io::DecoderReader::new(Cursor::new(&compressed), limited);
    let mut out = Vec::new();
    let err = r.read_to_end(&mut out).unwrap_err();
    // The wrapped codec error is bridged into io::Error via the
    // std-gated From impl on compcol::Error.
    let inner = err.into_inner().expect("inner error");
    let parsed = inner.downcast::<Error>().expect("compcol::Error downcast");
    assert_eq!(*parsed, Error::OutputLimitExceeded);
}
