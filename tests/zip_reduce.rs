//! Integration tests for the PKZip Reduce decoder.
//!
//! Fixtures are raw PKZip Reduce payloads wrapped in this crate's
//! 5-byte container header (factor + LE u32 uncompressed length). The
//! payloads themselves were produced offline by hwzip's reference
//! `hwreduce` (Hans Wennborg, public domain, <https://www.hanshq.net/zip2.html>):
//! the hamlet-2KB-factor-1..4 fixtures decode to the first 2048 bytes
//! of Project Gutenberg's Hamlet, and the smaller fixtures exercise
//! literal-only, single-DLE, hello-world, and highly-repetitive-input
//! code paths.
//!
//! The encoder is permanently `Error::Unsupported` and has its own
//! small section here for the trait contract.

#![cfg(feature = "zip_reduce")]

use compcol::zip_reduce::{Decoder, Encoder, ZipReduce};
use compcol::{Algorithm, Decoder as _, Encoder as _, Error, Status};

// ─── decoder drivers ──────────────────────────────────────────────────────

/// One-shot decode: feed the entire `input` then drain via empty calls.
fn decode_oneshot(input: &[u8]) -> Result<Vec<u8>, Error> {
    let mut dec = Decoder::new();
    decode_with(&mut dec, input)
}

fn decode_with(dec: &mut Decoder, input: &[u8]) -> Result<Vec<u8>, Error> {
    let mut decoded = Vec::new();
    let mut buf = vec![0u8; 8192];
    let mut consumed = 0usize;

    while consumed < input.len() {
        let (p, status) = dec.decode(&input[consumed..], &mut buf)?;
        decoded.extend_from_slice(&buf[..p.written]);
        consumed += p.consumed;
        match status {
            Status::StreamEnd | Status::InputEmpty => break,
            Status::OutputFull => continue,
        }
    }

    // Drain anything the decoder can still produce with no more input.
    loop {
        let (p, status) = dec.decode(&[], &mut buf)?;
        decoded.extend_from_slice(&buf[..p.written]);
        if p.written == 0 || matches!(status, Status::StreamEnd) {
            break;
        }
    }

    // Final finish to flush.
    loop {
        let (p, status) = dec.finish(&mut buf)?;
        decoded.extend_from_slice(&buf[..p.written]);
        if matches!(status, Status::StreamEnd) {
            break;
        }
        if p.written == 0 {
            break;
        }
    }
    Ok(decoded)
}

/// Chunked driver: feed `input` in `in_chunk` slices, drain via an
/// `out_chunk`-sized buffer. Designed to stress the snapshot/rewind
/// machinery in the bit reader and the pending-match copy logic.
fn decode_chunked(input: &[u8], in_chunk: usize, out_chunk: usize) -> Result<Vec<u8>, Error> {
    let mut dec = Decoder::new();
    let mut decoded = Vec::new();
    let mut buf = vec![0u8; out_chunk.max(1)];
    let mut i = 0;

    while i < input.len() {
        let end = (i + in_chunk).min(input.len());
        let chunk = &input[i..end];
        let mut consumed = 0;
        while consumed < chunk.len() {
            let (p, status) = dec.decode(&chunk[consumed..], &mut buf)?;
            decoded.extend_from_slice(&buf[..p.written]);
            consumed += p.consumed;
            match status {
                Status::StreamEnd | Status::InputEmpty => break,
                Status::OutputFull => continue,
            }
        }
        i = end;
        // After feeding, drain what's currently producible.
        loop {
            let (p, _status) = dec.decode(&[], &mut buf)?;
            decoded.extend_from_slice(&buf[..p.written]);
            if p.written == 0 {
                break;
            }
        }
    }
    loop {
        let (p, status) = dec.finish(&mut buf)?;
        decoded.extend_from_slice(&buf[..p.written]);
        if matches!(status, Status::StreamEnd) || p.written == 0 {
            break;
        }
    }
    Ok(decoded)
}

// ─── algorithm metadata ───────────────────────────────────────────────────

#[test]
fn algorithm_name_is_zip_reduce() {
    assert_eq!(<ZipReduce as Algorithm>::NAME, "zip-reduce");
}

#[test]
fn algorithm_factory_produces_codec() {
    let _ = <ZipReduce as Algorithm>::encoder();
    let _ = <ZipReduce as Algorithm>::decoder();
}

// ─── encoder is permanently unsupported ──────────────────────────────────

#[test]
fn encoder_encode_is_unsupported() {
    let mut enc = Encoder::new();
    let mut out = [0u8; 16];
    assert_eq!(
        enc.encode(b"hello", &mut out).unwrap_err(),
        Error::Unsupported
    );
}

#[test]
fn encoder_finish_is_unsupported() {
    let mut enc = Encoder::new();
    let mut out = [0u8; 16];
    assert_eq!(enc.finish(&mut out).unwrap_err(), Error::Unsupported);
}

#[test]
fn encoder_reset_is_a_no_op() {
    let mut enc = Encoder::new();
    enc.reset();
    let mut out = [0u8; 4];
    assert_eq!(enc.encode(b"x", &mut out).unwrap_err(), Error::Unsupported);
}

// ─── empty / minimal-input ────────────────────────────────────────────────

#[test]
fn empty_uncomp_decodes_to_empty() {
    // EMPTY_R4 is the follower-set header for an all-zeros input
    // followed by no LZ77 body. uncomp_len = 0 → decoder finishes after
    // parsing the header.
    let out = decode_oneshot(EMPTY_R4).unwrap();
    assert!(out.is_empty());
}

#[test]
fn empty_input_finish_is_unexpected_end() {
    // No header bytes at all → finish must surface UnexpectedEnd to
    // signal the input was truncated before the framing could be parsed.
    let mut dec = Decoder::new();
    let mut out = [0u8; 8];
    assert_eq!(dec.finish(&mut out).unwrap_err(), Error::UnexpectedEnd);
}

#[test]
fn one_byte_decodes_correctly_factor_4() {
    let out = decode_oneshot(ONE_BYTE_R4).unwrap();
    assert_eq!(out, b"h");
}

#[test]
fn dle_literal_decodes_correctly() {
    // The raw 0x90 byte is the DLE marker; encoders represent a literal
    // 0x90 by emitting DLE followed by V=0. Exercises that code path.
    let out = decode_oneshot(DLE_R4).unwrap();
    assert_eq!(out, &[0x90][..]);
}

#[test]
fn hello_world_decodes_correctly() {
    let out = decode_oneshot(HELLO_WORLD_R4).unwrap();
    assert_eq!(out, b"hello world");
}

// ─── all four factor levels, real-world Hamlet 2 KiB fixture ─────────────

#[test]
fn hamlet_2k_factor_1_oneshot() {
    let out = decode_oneshot(HAMLET2K_R1).unwrap();
    assert_eq!(out.len(), 2048);
    assert_eq!(out.as_slice(), HAMLET2K_PLAIN);
}

#[test]
fn hamlet_2k_factor_2_oneshot() {
    let out = decode_oneshot(HAMLET2K_R2).unwrap();
    assert_eq!(out.len(), 2048);
    assert_eq!(out.as_slice(), HAMLET2K_PLAIN);
}

#[test]
fn hamlet_2k_factor_3_oneshot() {
    let out = decode_oneshot(HAMLET2K_R3).unwrap();
    assert_eq!(out.len(), 2048);
    assert_eq!(out.as_slice(), HAMLET2K_PLAIN);
}

#[test]
fn hamlet_2k_factor_4_oneshot() {
    let out = decode_oneshot(HAMLET2K_R4).unwrap();
    assert_eq!(out.len(), 2048);
    assert_eq!(out.as_slice(), HAMLET2K_PLAIN);
}

#[test]
fn hamlet_2k_factor_4_chunked_one_byte_at_a_time() {
    // Drives the snapshot/rewind path on every single bit-read boundary.
    let out = decode_chunked(HAMLET2K_R4, 1, 1).unwrap();
    assert_eq!(out.as_slice(), HAMLET2K_PLAIN);
}

#[test]
fn hamlet_2k_factor_1_chunked_streaming() {
    let out = decode_chunked(HAMLET2K_R1, 17, 23).unwrap();
    assert_eq!(out.as_slice(), HAMLET2K_PLAIN);
}

// ─── 64 KiB repeating-pattern fixture — exercises long matches ───────────

#[test]
fn abc_repeated_64k_decodes() {
    // 22000 × "abc" = 66000 bytes. Exercises the long back-reference
    // path with explicit length-byte extension and the pending-match
    // continuation across output-buffer boundaries.
    let out = decode_oneshot(ABC_REPEATED_R4).unwrap();
    assert_eq!(out.len(), 66000);
    for (i, &b) in out.iter().enumerate() {
        let expected = b"abc"[i % 3];
        assert_eq!(b, expected, "mismatch at byte {i}");
    }
}

#[test]
fn abc_repeated_chunked_tiny_output_buffer() {
    let out = decode_chunked(ABC_REPEATED_R4, 64, 7).unwrap();
    assert_eq!(out.len(), 66000);
    for (i, &b) in out.iter().enumerate() {
        let expected = b"abc"[i % 3];
        assert_eq!(b, expected, "mismatch at byte {i}");
    }
}

// ─── error cases ──────────────────────────────────────────────────────────

#[test]
fn bad_header_factor_zero_rejected() {
    let mut bad = HAMLET2K_R4.to_vec();
    bad[0] = 0; // factor must be 1..=4
    let mut dec = Decoder::new();
    let mut out = vec![0u8; 4096];
    let err = match dec.decode(&bad, &mut out) {
        Ok(_) => dec.finish(&mut out).err(),
        Err(e) => Some(e),
    };
    assert_eq!(err, Some(Error::BadHeader));
}

#[test]
fn bad_header_factor_5_rejected() {
    let mut bad = HAMLET2K_R4.to_vec();
    bad[0] = 5; // factor 5 is out of range
    let mut dec = Decoder::new();
    let mut out = vec![0u8; 4096];
    let err = match dec.decode(&bad, &mut out) {
        Ok(_) => dec.finish(&mut out).err(),
        Err(e) => Some(e),
    };
    assert_eq!(err, Some(Error::BadHeader));
}

#[test]
fn truncated_header_returns_unexpected_end_on_finish() {
    // Two-byte header — not even the full 5-byte framing.
    let mut dec = Decoder::new();
    let mut out = vec![0u8; 32];
    let _ = dec.decode(&[0x04, 0x10], &mut out);
    assert_eq!(dec.finish(&mut out).unwrap_err(), Error::UnexpectedEnd);
}

#[test]
fn truncated_payload_returns_unexpected_end_on_finish() {
    // Header is present but payload is cut off mid follower-set table.
    let truncated = &HAMLET2K_R4[..50];
    let mut dec = Decoder::new();
    let mut out = vec![0u8; 4096];
    let _ = dec.decode(truncated, &mut out);
    let err = dec.finish(&mut out).unwrap_err();
    assert_eq!(err, Error::UnexpectedEnd);
}

#[test]
fn poisoned_decoder_keeps_returning_corrupt() {
    let mut bad = HAMLET2K_R4.to_vec();
    bad[0] = 0;
    let mut dec = Decoder::new();
    let mut out = vec![0u8; 32];
    let _ = dec.decode(&bad, &mut out);
    // Second call without reset: still errors.
    assert!(matches!(
        dec.decode(&[], &mut out),
        Err(Error::BadHeader | Error::Corrupt)
    ));
}

// ─── reset ────────────────────────────────────────────────────────────────

#[test]
fn reset_clears_state_for_new_stream() {
    let mut dec = Decoder::new();
    let first = decode_with(&mut dec, HAMLET2K_R4).unwrap();
    assert_eq!(first.as_slice(), HAMLET2K_PLAIN);

    dec.reset();

    // Decode a different fixture after reset and confirm no state leaks.
    let second = decode_with(&mut dec, HELLO_WORLD_R4).unwrap();
    assert_eq!(second, b"hello world");
}

#[test]
fn reset_after_error_unpoisons() {
    let mut bad = HAMLET2K_R4.to_vec();
    bad[0] = 0;
    let mut dec = Decoder::new();
    let mut out = vec![0u8; 32];
    let _ = dec.decode(&bad, &mut out);
    dec.reset();
    let ok = decode_with(&mut dec, HELLO_WORLD_R4).unwrap();
    assert_eq!(ok, b"hello world");
}

// ─── factory (only if the feature is enabled) ────────────────────────────

#[cfg(feature = "factory")]
mod factory {
    use compcol::factory;

    #[test]
    fn lookup_zip_reduce_encoder_and_decoder() {
        assert!(factory::encoder_by_name("zip-reduce").is_some());
        assert!(factory::decoder_by_name("zip-reduce").is_some());
    }

    #[test]
    fn lookup_unknown() {
        assert!(factory::encoder_by_name("not-a-real-reduce").is_none());
        assert!(factory::decoder_by_name("not-a-real-reduce").is_none());
    }

    #[test]
    fn names_contains_zip_reduce() {
        assert!(factory::names().contains(&"zip-reduce"));
    }

    #[test]
    fn extension_is_reduce() {
        assert_eq!(factory::extension("zip-reduce"), Some("reduce"));
    }

    #[test]
    fn boxed_encoder_is_unsupported() {
        use compcol::Error;
        let mut enc = factory::encoder_by_name("zip-reduce").unwrap();
        let mut out = [0u8; 16];
        assert_eq!(
            enc.encode(b"hello", &mut out).unwrap_err(),
            Error::Unsupported
        );
    }
}

// ─── fixtures (hwzip 2.1, public domain) ─────────────────────────────────

include!("zip_reduce_fixtures.in");
