//! Integration tests for the PPMd (PPMII variant H) decoder.
//!
//! PPMd is decoder-only in this crate (the encoder always returns
//! [`Error::Unsupported`]). The round-trip fixtures are **real 7z Ppmd7
//! streams** produced by `pyppmd.Ppmd7Encoder(order=6, mem=16 MiB)` and
//! wrapped in this crate's 11-byte framing header (order, mem_mb,
//! restoration, u64 length). They live in `tests/fixtures/ppmd/` alongside
//! their expected plaintext (`<name>.bin`); see
//! `compcol-rar-corpus/probe/gen_ppmd_fixtures.py` for how they were
//! generated. Decoding them byte-for-byte exercises the full model:
//! context-tree construction, the binary-context path, masked escapes, SEE,
//! rescale, and the suballocator.

#![cfg(feature = "ppmd")]

use compcol::ppmd::{Decoder, Encoder, Ppmd};
use compcol::{Algorithm, Decoder as _, Encoder as _, Error, Status};

// ─── fixtures ─────────────────────────────────────────────────────────────

macro_rules! fixture {
    ($name:literal) => {
        (
            include_bytes!(concat!("fixtures/ppmd/", $name, ".ppmd")) as &[u8],
            include_bytes!(concat!("fixtures/ppmd/", $name, ".bin")) as &[u8],
        )
    };
}

// ─── helpers ─────────────────────────────────────────────────────────────

/// Build a framing header: order, mem_mb, restoration, len_le_u64.
fn make_header(order: u8, mem_mb: u8, restoration: u8, len: u64) -> Vec<u8> {
    let mut h = Vec::with_capacity(11);
    h.push(order);
    h.push(mem_mb);
    h.push(restoration);
    h.extend_from_slice(&len.to_le_bytes());
    h
}

/// Drive the decoder to completion using a small output buffer to exercise
/// the OutputFull / InputEmpty back-pressure paths.
fn drive_to_end(dec: &mut Decoder, input: &[u8]) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    let mut buf = vec![0u8; 4096];
    let mut consumed = 0;
    let mut spin = 0;
    loop {
        let (p, status) = dec.decode(&input[consumed..], &mut buf)?;
        consumed += p.consumed;
        out.extend_from_slice(&buf[..p.written]);
        match status {
            Status::OutputFull => {}
            Status::InputEmpty => {
                if consumed >= input.len() && p.written == 0 {
                    break;
                }
            }
            Status::StreamEnd => return Ok(out),
        }
        if p.consumed == 0 && p.written == 0 {
            break;
        }
        spin += 1;
        if spin > 1_000_000 {
            panic!("decoder spin (consumed={consumed}, out_len={})", out.len());
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
fn algorithm_name_is_ppmd() {
    assert_eq!(<Ppmd as Algorithm>::NAME, "ppmd");
}

#[test]
fn ppmd_algorithm_factory_produces_codec() {
    let _enc = <Ppmd as Algorithm>::encoder();
    let _dec = <Ppmd as Algorithm>::decoder();
}

#[test]
fn decoder_new_does_not_panic() {
    let _ = Decoder::new();
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
fn encoder_reset_is_a_noop() {
    let mut enc = Encoder::new();
    enc.reset();
    let mut out = [0u8; 4];
    assert_eq!(enc.encode(b"x", &mut out).unwrap_err(), Error::Unsupported);
}

// ─── round-trip against real Ppmd7 fixtures ──────────────────────────────

fn check(stream: &[u8], expected: &[u8]) {
    let mut dec = Decoder::new();
    let out = drive_to_end(&mut dec, stream).unwrap();
    assert_eq!(out.len(), expected.len(), "length mismatch");
    assert_eq!(out, expected, "byte mismatch");
}

#[test]
fn rt_hello() {
    let (stream, expected) = fixture!("hello");
    check(stream, expected);
}

#[test]
fn rt_repeat() {
    // Highly repetitive text — heavy match / context reuse.
    let (stream, expected) = fixture!("repeat");
    check(stream, expected);
}

#[test]
fn rt_text() {
    let (stream, expected) = fixture!("text");
    check(stream, expected);
}

#[test]
fn rt_english() {
    // Word-structured input — exercises the model's typical operating point.
    let (stream, expected) = fixture!("english");
    check(stream, expected);
}

#[test]
fn rt_mixed_high_entropy() {
    // 20 KiB of deterministic pseudo-random bytes — drives the escape /
    // masked-suffix / SEE paths and rescales hard.
    let (stream, expected) = fixture!("mixed");
    check(stream, expected);
}

// ─── streaming: one byte at a time ───────────────────────────────────────

#[test]
fn streaming_one_byte_at_a_time() {
    let (stream, expected) = fixture!("english");
    let mut dec = Decoder::new();
    let mut out = Vec::new();
    let mut buf = [0u8; 128];
    let mut consumed = 0;
    let mut spin = 0;
    while consumed < stream.len() {
        let take = (stream.len() - consumed).min(1);
        let (p, status) = dec
            .decode(&stream[consumed..consumed + take], &mut buf)
            .unwrap();
        consumed += p.consumed;
        out.extend_from_slice(&buf[..p.written]);
        if matches!(status, Status::StreamEnd) {
            assert_eq!(out, expected);
            return;
        }
        spin += 1;
        if spin > 1_000_000 {
            panic!("streaming spin");
        }
    }
    loop {
        let (p, status) = dec.finish(&mut buf).unwrap();
        out.extend_from_slice(&buf[..p.written]);
        if matches!(status, Status::StreamEnd) || p.written == 0 {
            break;
        }
    }
    assert_eq!(out, expected);
}

// ─── error cases ─────────────────────────────────────────────────────────

#[test]
fn truncated_header_returns_unexpected_end_on_finish() {
    let mut dec = Decoder::new();
    let mut buf = [0u8; 16];
    let (p, _status) = dec.decode(&[6, 16, 0, 0, 0], &mut buf).unwrap();
    assert_eq!(p.consumed, 5);
    let r = dec.finish(&mut buf);
    assert_eq!(r, Err(Error::UnexpectedEnd));
}

#[test]
fn header_order_too_small_is_bad_header() {
    let (stream, _) = fixture!("hello");
    let mut bad = make_header(1, 16, 0, 11);
    bad.extend_from_slice(&stream[11..]);
    let mut dec = Decoder::new();
    let mut buf = [0u8; 16];
    let _ = dec.decode(&bad, &mut buf);
    assert_eq!(dec.finish(&mut buf), Err(Error::BadHeader));
}

#[test]
fn header_zero_mem_is_bad_header() {
    let mut bad = make_header(6, 0, 0, 0);
    bad.extend_from_slice(&[0, 0, 0, 0, 0]);
    let mut dec = Decoder::new();
    let mut buf = [0u8; 16];
    let _ = dec.decode(&bad, &mut buf);
    assert_eq!(dec.finish(&mut buf), Err(Error::BadHeader));
}

#[test]
fn header_bad_restoration_is_bad_header() {
    let mut bad = make_header(6, 16, 9, 0);
    bad.extend_from_slice(&[0, 0, 0, 0, 0]);
    let mut dec = Decoder::new();
    let mut buf = [0u8; 16];
    let _ = dec.decode(&bad, &mut buf);
    assert_eq!(dec.finish(&mut buf), Err(Error::BadHeader));
}

/// A hostile stream with an obviously invalid header must be rejected as
/// soon as the 11 header bytes have arrived — from `decode` itself — not
/// after the caller has piped (and the decoder buffered) the whole payload.
#[test]
fn bad_header_is_rejected_at_decode_time() {
    let mut bad = make_header(0, 16, 0, 100); // order 0: invalid
    bad.extend_from_slice(&[0u8; 64]);
    let mut dec = Decoder::new();
    let mut buf = [0u8; 16];
    assert_eq!(dec.decode(&bad, &mut buf).unwrap_err(), Error::BadHeader);
    // The error is sticky and stays the same across calls.
    assert_eq!(dec.finish(&mut buf), Err(Error::BadHeader));
}

#[test]
fn unknown_declared_length_is_refused() {
    // PPMd has no in-band end-of-stream marker, so a stream framed with the
    // "unknown length" sentinel (u64::MAX) has no reliable stopping point:
    // decoding until the range coder exhausts input appends its finalisation
    // bytes as extra garbage symbols (reframing the 1280-byte `repeat`
    // fixture this way used to return 1466 bytes). It must be refused.
    let (stream, _) = fixture!("repeat");
    let mut bad = stream.to_vec();
    bad[3..11].copy_from_slice(&u64::MAX.to_le_bytes());
    let mut dec = Decoder::new();
    let mut buf = [0u8; 256];
    let _ = dec.decode(&bad, &mut buf);
    assert_eq!(dec.finish(&mut buf), Err(Error::Unsupported));
}

#[test]
fn absurd_declared_length_is_rejected_not_oomed() {
    // Regression: a fuzz-found stream with a valid header but a wildly
    // oversized declared length (~71 quadrillion bytes) used to drive the
    // known-length decode loop toward OOM — a high-probability PPMd symbol
    // can decode repeatedly without consuming input, so the range coder
    // never overruns. The decoder must reject it up front.
    let mut bad = make_header(6, 16, 0, 71_213_169_107_795_979);
    bad.extend_from_slice(&[0x00, 0xfd, 0x00, 0x00, 0x67, 0xfb, 0x83, 0x7d]);
    let mut dec = Decoder::new();
    let mut buf = [0u8; 16];
    let _ = dec.decode(&bad, &mut buf);
    assert_eq!(dec.finish(&mut buf), Err(Error::OutputLimitExceeded));
}

#[test]
fn payload_first_byte_must_be_zero() {
    let mut bad = make_header(6, 16, 0, 8);
    bad.extend_from_slice(&[0xFF; 16]);
    let mut dec = Decoder::new();
    let mut buf = [0u8; 16];
    let _ = dec.decode(&bad, &mut buf);
    assert_eq!(dec.finish(&mut buf), Err(Error::Corrupt));
}

#[test]
fn truncated_payload_is_unexpected_end() {
    let (stream, _) = fixture!("text");
    let truncated = &stream[..stream.len() - 3];
    let mut dec = Decoder::new();
    let mut buf = [0u8; 256];
    let _ = dec.decode(truncated, &mut buf);
    let r = dec.finish(&mut buf);
    assert!(matches!(r, Err(Error::UnexpectedEnd) | Err(Error::Corrupt)));
}

#[test]
fn garbage_after_header_does_not_panic() {
    let mut stream = make_header(6, 16, 0, 64);
    stream.extend_from_slice(&[0u8; 1]);
    stream.extend_from_slice(&[0xAA; 128]);
    let mut dec = Decoder::new();
    let mut buf = [0u8; 32];
    let _ = dec.decode(&stream, &mut buf);
    let _ = dec.finish(&mut buf);
}

// ─── reset behaviour ─────────────────────────────────────────────────────

#[test]
fn reset_returns_to_header_phase() {
    let (stream, expected) = fixture!("hello");
    let mut dec = Decoder::new();
    let out = drive_to_end(&mut dec, stream).unwrap();
    assert_eq!(out, expected);

    dec.reset();
    let out2 = drive_to_end(&mut dec, stream).unwrap();
    assert_eq!(out2, expected);
}

#[test]
fn reset_after_error_recovers() {
    let mut dec = Decoder::new();
    let mut buf = [0u8; 16];
    let mut bad = make_header(99, 16, 0, 0);
    bad.extend_from_slice(&[0, 0, 0, 0, 0]);
    let _ = dec.decode(&bad, &mut buf);
    assert_eq!(dec.finish(&mut buf), Err(Error::BadHeader));
    // Poisoned until reset.
    assert!(dec.decode(b"x", &mut buf).is_err());
    dec.reset();
    let (stream, expected) = fixture!("hello");
    let out = drive_to_end(&mut dec, stream).unwrap();
    assert_eq!(out, expected);
}

// ─── factory (only if the feature is enabled) ────────────────────────────

#[cfg(feature = "factory")]
mod factory {
    use compcol::factory;

    #[test]
    fn lookup_ppmd_encoder_and_decoder() {
        assert!(factory::encoder_by_name("ppmd").is_some());
        assert!(factory::decoder_by_name("ppmd").is_some());
    }

    #[test]
    fn lookup_unknown() {
        assert!(factory::encoder_by_name("not-ppmd").is_none());
        assert!(factory::decoder_by_name("not-ppmd").is_none());
    }

    #[test]
    fn names_contains_ppmd() {
        assert!(factory::names().contains(&"ppmd"));
    }

    #[test]
    fn boxed_encoder_is_unsupported() {
        use compcol::Error;
        let mut enc = factory::encoder_by_name("ppmd").unwrap();
        let mut out = [0u8; 16];
        assert_eq!(
            enc.encode(b"hello", &mut out).unwrap_err(),
            Error::Unsupported
        );
    }

    #[test]
    fn extension_is_ppmd() {
        assert_eq!(factory::extension("ppmd"), Some("ppmd"));
    }
}
