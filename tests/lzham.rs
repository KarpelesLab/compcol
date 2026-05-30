//! Integration tests for the LZHAM `LZH0` container parser.
//!
//! This build ships header-parsing only — the inner LZHAM arithmetic-coded
//! bitstream is permanently [`Error::Unsupported`], as is the encoder
//! (see the module docs in `src/lzham/mod.rs` for the rationale). These
//! tests cover:
//!
//! - algorithm metadata + factory shape;
//! - encoder permanently `Unsupported`;
//! - the special case of a zero-length stream, which decodes successfully
//!   to an empty output without ever needing the inner codec;
//! - header validation (good magic, bad magic, partial header, dict-size
//!   bounds, byte-by-byte streaming);
//! - the documented gap: a non-empty payload returns `Unsupported`;
//! - poisoned-state recovery via `reset`;
//! - factory by-name lookup including the `factory` feature gate.

#![cfg(feature = "lzham")]

use compcol::lzham::{Decoder, Encoder, Lzham};
use compcol::{Algorithm, Decoder as _, Encoder as _, Error, Status};

// ─── helpers ─────────────────────────────────────────────────────────────

/// Build an `LZH0` header with the given fields and append `payload`.
fn make_header(dict_log2: u8, uncompressed_size: u64, payload: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(b"LZH0");
    b.push(dict_log2);
    b.extend_from_slice(&uncompressed_size.to_le_bytes());
    b.extend_from_slice(payload);
    b
}

/// Drive `decoder.decode` followed by `decoder.finish`, accumulating any
/// produced bytes. Returns the result so tests can assert on success or
/// the specific error variant.
fn drive_to_end(dec: &mut Decoder, input: &[u8]) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    let mut buf = vec![0u8; 256];
    let mut consumed = 0;
    while consumed < input.len() {
        let (p, status) = dec.decode(&input[consumed..], &mut buf)?;
        consumed += p.consumed;
        out.extend_from_slice(&buf[..p.written]);
        match status {
            Status::OutputFull => continue,
            Status::InputEmpty => break,
            Status::StreamEnd => return Ok(out),
        }
    }
    loop {
        let (p, status) = dec.finish(&mut buf)?;
        out.extend_from_slice(&buf[..p.written]);
        if matches!(status, Status::StreamEnd) {
            break;
        }
        if p.written == 0 {
            break;
        }
    }
    Ok(out)
}

// ─── algorithm metadata ──────────────────────────────────────────────────

#[test]
fn algorithm_name_is_lzham() {
    assert_eq!(<Lzham as Algorithm>::NAME, "lzham");
}

#[test]
fn algorithm_factory_constructs_codec() {
    let _enc = <Lzham as Algorithm>::encoder();
    let _dec = <Lzham as Algorithm>::decoder();
}

#[test]
fn decoder_new_does_not_panic() {
    let _ = Decoder::new();
}

#[test]
fn decoder_default_matches_new() {
    let _ = Decoder::default();
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

// ─── zero-length stream: header-only LZH0 decodes cleanly to empty ───────

#[test]
fn empty_stream_decodes_to_empty() {
    // dict_size_log2 = 15 (the minimum), uncompressed_size = 0, no payload.
    let stream = make_header(15, 0, b"");
    let mut dec = Decoder::new();
    let out = drive_to_end(&mut dec, &stream).unwrap();
    assert!(out.is_empty());
}

#[test]
fn empty_stream_with_max_dict_log2_decodes_to_empty() {
    // dict_size_log2 = 29 (the documented x64 max).
    let stream = make_header(29, 0, b"");
    let mut dec = Decoder::new();
    let out = drive_to_end(&mut dec, &stream).unwrap();
    assert!(out.is_empty());
}

#[test]
fn empty_stream_one_byte_at_a_time() {
    let stream = make_header(20, 0, b"");
    let mut dec = Decoder::new();
    let mut buf = [0u8; 16];
    let mut consumed = 0;
    while consumed < stream.len() {
        let (p, status) = dec
            .decode(&stream[consumed..consumed + 1], &mut buf)
            .unwrap();
        consumed += p.consumed;
        if matches!(status, Status::StreamEnd) {
            break;
        }
    }
    // Drain any pending done state via finish.
    let (_, status) = dec.finish(&mut buf).unwrap();
    assert!(matches!(status, Status::StreamEnd));
}

#[test]
fn empty_stream_calling_decode_after_done_is_a_noop() {
    let stream = make_header(15, 0, b"");
    let mut dec = Decoder::new();
    let out = drive_to_end(&mut dec, &stream).unwrap();
    assert!(out.is_empty());
    // Extra calls are idempotent.
    let mut buf = [0u8; 8];
    let (p, status) = dec.decode(b"trailing", &mut buf).unwrap();
    assert_eq!(p.consumed, 0);
    assert_eq!(p.written, 0);
    assert!(matches!(status, Status::StreamEnd));
}

// ─── non-empty payload returns the documented `Unsupported` ──────────────

#[test]
fn non_empty_payload_returns_unsupported() {
    let stream = make_header(20, 1234, b"some bytes that look like payload");
    let mut dec = Decoder::new();
    let err = drive_to_end(&mut dec, &stream).unwrap_err();
    assert_eq!(err, Error::Unsupported);
}

#[test]
fn non_empty_payload_unsupported_even_with_short_payload() {
    // uncompressed_size > 0 but no payload bytes attached — the decoder
    // still surfaces Unsupported the moment it learns the stream isn't
    // an empty-input fixture, since that's the only case it can serve.
    let stream = make_header(15, 5, b"");
    let mut dec = Decoder::new();
    let err = drive_to_end(&mut dec, &stream).unwrap_err();
    assert_eq!(err, Error::Unsupported);
}

// ─── header validation ──────────────────────────────────────────────────

#[test]
fn bad_magic_is_bad_header() {
    let mut stream = b"NOPE".to_vec();
    stream.push(15);
    stream.extend_from_slice(&0u64.to_le_bytes());
    let mut dec = Decoder::new();
    let mut buf = [0u8; 16];
    let r = dec.decode(&stream, &mut buf);
    assert_eq!(r.unwrap_err(), Error::BadHeader);
}

#[test]
fn dict_log2_below_minimum_is_bad_header() {
    // dict_size_log2 = 14 (below LZHAM_MIN_DICT_SIZE_LOG2 = 15).
    let stream = make_header(14, 0, b"");
    let mut dec = Decoder::new();
    let mut buf = [0u8; 16];
    let r = dec.decode(&stream, &mut buf);
    assert_eq!(r.unwrap_err(), Error::BadHeader);
}

#[test]
fn dict_log2_above_maximum_is_bad_header() {
    // dict_size_log2 = 30 (above LZHAM_MAX_DICT_SIZE_LOG2_X64 = 29).
    let stream = make_header(30, 0, b"");
    let mut dec = Decoder::new();
    let mut buf = [0u8; 16];
    let r = dec.decode(&stream, &mut buf);
    assert_eq!(r.unwrap_err(), Error::BadHeader);
}

// ─── truncated input ─────────────────────────────────────────────────────

#[test]
fn truncated_magic_only_yields_input_empty_then_unexpected_end() {
    let mut dec = Decoder::new();
    let mut buf = [0u8; 16];
    // Three bytes — not enough for the 4-byte magic.
    let (p, status) = dec.decode(b"LZH", &mut buf).unwrap();
    assert_eq!(p.consumed, 3);
    assert_eq!(p.written, 0);
    assert!(matches!(status, Status::InputEmpty));
    // finish: should report UnexpectedEnd since the header never landed.
    let r = dec.finish(&mut buf);
    assert_eq!(r.unwrap_err(), Error::UnexpectedEnd);
}

#[test]
fn truncated_full_magic_only_yields_unexpected_end_on_finish() {
    let mut dec = Decoder::new();
    let mut buf = [0u8; 16];
    let (p, status) = dec.decode(b"LZH0", &mut buf).unwrap();
    assert_eq!(p.consumed, 4);
    assert!(matches!(status, Status::InputEmpty));
    let r = dec.finish(&mut buf);
    assert_eq!(r.unwrap_err(), Error::UnexpectedEnd);
}

// ─── poisoning ───────────────────────────────────────────────────────────

#[test]
fn bad_header_poisons_decoder_until_reset() {
    let mut dec = Decoder::new();
    let mut buf = [0u8; 16];
    // Send a fully-invalid header.
    let mut bad = b"NOPE".to_vec();
    bad.push(15);
    bad.extend_from_slice(&0u64.to_le_bytes());
    assert_eq!(dec.decode(&bad, &mut buf).unwrap_err(), Error::BadHeader);
    // Subsequent calls without reset surface a poison error.
    assert!(dec.decode(b"x", &mut buf).is_err());
    // After reset, a fresh empty stream decodes cleanly.
    dec.reset();
    let stream = make_header(15, 0, b"");
    let out = drive_to_end(&mut dec, &stream).unwrap();
    assert!(out.is_empty());
}

#[test]
fn unsupported_payload_poisons_decoder_until_reset() {
    let stream = make_header(15, 10, b"abc");
    let mut dec = Decoder::new();
    let mut buf = [0u8; 16];
    assert_eq!(
        dec.decode(&stream, &mut buf).unwrap_err(),
        Error::Unsupported
    );
    // Reset recovers; second use works on a valid empty stream.
    dec.reset();
    let stream = make_header(15, 0, b"");
    let out = drive_to_end(&mut dec, &stream).unwrap();
    assert!(out.is_empty());
}

#[test]
fn reset_returns_decoder_to_header_state() {
    let stream = make_header(16, 0, b"");
    let mut dec = Decoder::new();
    let out = drive_to_end(&mut dec, &stream).unwrap();
    assert!(out.is_empty());
    dec.reset();
    // Second pass through with the same stream must work identically.
    let out2 = drive_to_end(&mut dec, &stream).unwrap();
    assert!(out2.is_empty());
}

// ─── factory (only if the feature is enabled) ────────────────────────────

#[cfg(feature = "factory")]
mod factory {
    use compcol::factory;

    #[test]
    fn lookup_lzham_encoder_and_decoder() {
        assert!(factory::encoder_by_name("lzham").is_some());
        assert!(factory::decoder_by_name("lzham").is_some());
    }

    #[test]
    fn lookup_unknown() {
        assert!(factory::encoder_by_name("not-a-real-lzham").is_none());
        assert!(factory::decoder_by_name("not-a-real-lzham").is_none());
    }

    #[test]
    fn names_contains_lzham() {
        assert!(factory::names().contains(&"lzham"));
    }

    #[test]
    fn boxed_encoder_is_unsupported() {
        use compcol::Error;
        let mut enc = factory::encoder_by_name("lzham").unwrap();
        let mut out = [0u8; 16];
        assert_eq!(
            enc.encode(b"hello", &mut out).unwrap_err(),
            Error::Unsupported
        );
    }

    #[test]
    fn extension_is_lzham() {
        assert_eq!(factory::extension("lzham"), Some("lzham"));
    }
}
