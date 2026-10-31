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

// ─── raw (header-less) entry point ───────────────────────────────────────

/// Every framed fixture, so the raw path can be checked against each.
const FRAMED: &[&[u8]] = &[
    HAMLET2K_R1,
    HAMLET2K_R2,
    HAMLET2K_R3,
    HAMLET2K_R4,
    EMPTY_R4,
    ONE_BYTE_R4,
    HELLO_WORLD_R4,
    DLE_R4,
    ABC_REPEATED_R4,
];

/// Split a framed fixture into (factor, uncompressed length, bare payload).
fn split_framed(framed: &[u8]) -> (u8, u64, &[u8]) {
    let len = u32::from_le_bytes([framed[1], framed[2], framed[3], framed[4]]);
    (framed[0], u64::from(len), &framed[5..])
}

/// Like `decode_chunked`, but on a caller-supplied decoder. Also reports
/// whether the final status was `StreamEnd`.
fn decode_chunked_with(
    dec: &mut Decoder,
    input: &[u8],
    in_chunk: usize,
    out_chunk: usize,
) -> Result<(Vec<u8>, bool), Error> {
    let mut decoded = Vec::new();
    let mut buf = vec![0u8; out_chunk.max(1)];
    let mut ended = false;
    for chunk in input.chunks(in_chunk.max(1)) {
        let mut consumed = 0;
        while consumed < chunk.len() {
            let (p, status) = dec.decode(&chunk[consumed..], &mut buf)?;
            decoded.extend_from_slice(&buf[..p.written]);
            consumed += p.consumed;
            ended |= matches!(status, Status::StreamEnd);
            if !matches!(status, Status::OutputFull) {
                break;
            }
        }
        loop {
            let (p, status) = dec.decode(&[], &mut buf)?;
            decoded.extend_from_slice(&buf[..p.written]);
            ended |= matches!(status, Status::StreamEnd);
            if p.written == 0 {
                break;
            }
        }
    }
    loop {
        let (p, status) = dec.finish(&mut buf)?;
        decoded.extend_from_slice(&buf[..p.written]);
        if matches!(status, Status::StreamEnd) {
            ended = true;
            break;
        }
        if p.written == 0 {
            break;
        }
    }
    Ok((decoded, ended))
}

#[test]
fn raw_matches_framed_for_every_fixture() {
    for (i, framed) in FRAMED.iter().enumerate() {
        let (factor, len, payload) = split_framed(framed);
        let expected = decode_oneshot(framed).unwrap();
        assert_eq!(expected.len() as u64, len, "fixture {i}");
        for &(ic, oc) in &[
            (1, 1),
            (1, 7),
            (17, 23),
            (64, 7),
            (4096, 3),
            (1 << 20, 8192),
        ] {
            let mut dec = Decoder::raw(factor, len).unwrap();
            let (out, ended) = decode_chunked_with(&mut dec, payload, ic, oc).unwrap();
            assert!(ended, "fixture {i} in={ic} out={oc}: no StreamEnd");
            assert_eq!(out, expected, "fixture {i} in={ic} out={oc}");
        }
    }
}

#[test]
fn raw_oneshot_matches_framed() {
    for framed in FRAMED {
        let (factor, len, payload) = split_framed(framed);
        let mut dec = Decoder::raw(factor, len).unwrap();
        assert_eq!(
            decode_with(&mut dec, payload).unwrap(),
            decode_oneshot(framed).unwrap()
        );
    }
}

#[test]
fn raw_trailing_bytes_match_framed() {
    // Bytes past the end of the stream are handled identically.
    for framed in FRAMED {
        let (factor, len, payload) = split_framed(framed);
        let mut framed_tail = framed.to_vec();
        framed_tail.extend_from_slice(&[0xAB; 16]);
        let mut raw_tail = payload.to_vec();
        raw_tail.extend_from_slice(&[0xAB; 16]);
        let a = decode_chunked_with(&mut Decoder::new(), &framed_tail, 5, 13);
        let b = decode_chunked_with(&mut Decoder::raw(factor, len).unwrap(), &raw_tail, 5, 13);
        assert_eq!(a, b);
    }
}

#[test]
fn raw_truncated_errors_like_framed() {
    for framed in FRAMED {
        let (factor, len, payload) = split_framed(framed);
        if len == 0 {
            continue;
        }
        for cut in [0, 1, 50, payload.len() / 2, payload.len() - 1] {
            let framed_res = decode_chunked_with(&mut Decoder::new(), &framed[..5 + cut], 3, 11);
            let raw_res = decode_chunked_with(
                &mut Decoder::raw(factor, len).unwrap(),
                &payload[..cut],
                3,
                11,
            );
            assert_eq!(framed_res.as_ref().err(), Some(&Error::UnexpectedEnd));
            assert_eq!(framed_res, raw_res, "cut {cut}");
        }
    }
}

#[test]
fn raw_overlong_length_is_unexpected_end() {
    // Claiming more output than the payload holds is truncation.
    let (factor, len, payload) = split_framed(HELLO_WORLD_R4);
    let mut dec = Decoder::raw(factor, len + 1).unwrap();
    assert_eq!(
        decode_chunked_with(&mut dec, payload, 4, 4).unwrap_err(),
        Error::UnexpectedEnd
    );
}

#[test]
fn raw_length_zero() {
    let (factor, len, payload) = split_framed(EMPTY_R4);
    assert_eq!(len, 0);
    let mut dec = Decoder::raw(factor, 0).unwrap();
    let (out, ended) = decode_chunked_with(&mut dec, payload, 1, 1).unwrap();
    assert!(out.is_empty());
    assert!(ended);
}

#[test]
fn raw_empty_input_finish_is_unexpected_end() {
    let mut dec = Decoder::raw(4, 0).unwrap();
    let mut out = [0u8; 8];
    assert_eq!(dec.finish(&mut out).unwrap_err(), Error::UnexpectedEnd);
}

#[test]
fn raw_bad_factor_rejected() {
    for factor in [0u8, 5, 6, 255] {
        assert_eq!(Decoder::raw(factor, 10).err(), Some(Error::BadHeader));
    }
    for factor in 1..=4 {
        assert!(Decoder::raw(factor, 10).is_ok());
    }
}

#[test]
fn factor_for_method_maps_zip_methods() {
    use compcol::zip_reduce::factor_for_method;
    assert_eq!(factor_for_method(2), Some(1));
    assert_eq!(factor_for_method(3), Some(2));
    assert_eq!(factor_for_method(4), Some(3));
    assert_eq!(factor_for_method(5), Some(4));
    for m in [0u16, 1, 6, 8, 0xFFFF] {
        assert_eq!(factor_for_method(m), None);
    }
}

#[test]
fn raw_reset_keeps_raw_mode() {
    let (factor, len, payload) = split_framed(HAMLET2K_R2);
    let mut dec = Decoder::raw(factor, len).unwrap();
    let first = decode_with(&mut dec, payload).unwrap();
    assert_eq!(first.as_slice(), HAMLET2K_PLAIN);
    dec.reset();
    // Same factor and length, still no header expected.
    let (second, ended) = decode_chunked_with(&mut dec, payload, 1, 3).unwrap();
    assert!(ended);
    assert_eq!(second.as_slice(), HAMLET2K_PLAIN);
}

#[test]
fn raw_reset_mid_stream_and_after_error() {
    let (factor, len, payload) = split_framed(HAMLET2K_R3);
    let mut dec = Decoder::raw(factor, len).unwrap();
    let mut out = [0u8; 100];
    let _ = dec.decode(&payload[..300], &mut out).unwrap();
    dec.reset();
    assert_eq!(decode_with(&mut dec, payload).unwrap(), HAMLET2K_PLAIN);

    // Poison with a truncated stream, then reset.
    let _ = decode_chunked_with(&mut dec, &payload[..10], 4, 4);
    dec.reset();
    assert_eq!(decode_with(&mut dec, payload).unwrap(), HAMLET2K_PLAIN);
}

#[test]
fn framed_reset_stays_framed() {
    let mut dec = Decoder::new();
    let _ = decode_with(&mut dec, HELLO_WORLD_R4).unwrap();
    dec.reset();
    assert_eq!(decode_with(&mut dec, HAMLET2K_R1).unwrap(), HAMLET2K_PLAIN);
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
