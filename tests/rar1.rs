//! Integration tests for the RAR1 module.
//!
//! RAR1 (the 1995-1996 original Roshal Archive compression algorithm) has
//! no working end-to-end decoder in this build — see `src/rar1/mod.rs` for
//! the rationale. These tests therefore exercise:
//!
//! 1. The public-surface contract: name, encoder permanently unsupported,
//!    decoder constructors, `unpack_size` plumbing, expected error
//!    behaviour on real RAR1-shaped inputs.
//! 2. Streaming-trait conformance: empty calls don't error, `finish`
//!    behaves correctly on freshly-constructed and consumed decoders,
//!    `reset` returns the decoder to its initial state.
//! 3. Building-block reachability: the bit reader, Huffman decoder, LZSS
//!    window, lookup tables, and offset history all carry their own
//!    in-module unit tests; this file additionally pins down the
//!    publicly-observable behaviour those building blocks support
//!    through the [`Decoder`] / [`Encoder`] API.
//!
//! Fixture famine: real RAR1 sample files are virtually non-existent on
//! the open internet in 2026. If a future contributor turns one up, embed
//! it as hex below and add a `decode_real_fixture` test pointing at it.

#![cfg(feature = "rar1")]

use compcol::rar1::{Decoder, Encoder, Rar1};
use compcol::{Algorithm, Decoder as _, Encoder as _, Error};

// ─── algorithm identity ───────────────────────────────────────────────────

#[test]
fn name_is_rar1() {
    assert_eq!(<Rar1 as Algorithm>::NAME, "rar1");
}

#[test]
fn factory_returns_decoder() {
    // The decoder factory just needs to compile-and-call cleanly — the
    // returned decoder's `decode` will refuse real input but it must
    // construct.
    let mut d = <Rar1 as Algorithm>::decoder();
    let mut out = [0u8; 1];
    // Empty input is permitted as a no-op.
    let p = d.decode(&[], &mut out).unwrap();
    assert_eq!(p.consumed, 0);
    assert_eq!(p.written, 0);
}

#[test]
fn factory_returns_encoder_that_errors() {
    let mut e = <Rar1 as Algorithm>::encoder();
    let mut out = [0u8; 1];
    assert_eq!(e.encode(b"x", &mut out), Err(Error::Unsupported));
}

// ─── encoder is permanently Unsupported ──────────────────────────────────

#[test]
fn encoder_encode_is_unsupported() {
    let mut e = Encoder::new();
    let mut out = [0u8; 16];
    assert_eq!(e.encode(b"hello world", &mut out), Err(Error::Unsupported));
}

#[test]
fn encoder_finish_is_unsupported() {
    let mut e = Encoder::new();
    let mut out = [0u8; 16];
    assert_eq!(e.finish(&mut out), Err(Error::Unsupported));
}

#[test]
fn encoder_encode_with_empty_input_still_unsupported() {
    // The encoder doesn't carve out an "empty input is OK" path; the whole
    // surface is permanently disabled and we want callers to find out
    // immediately.
    let mut e = Encoder::new();
    let mut out = [0u8; 16];
    assert_eq!(e.encode(&[], &mut out), Err(Error::Unsupported));
}

#[test]
fn encoder_reset_does_not_panic() {
    let mut e = Encoder::new();
    e.reset();
    // Still unsupported after reset.
    let mut out = [0u8; 16];
    assert_eq!(e.encode(b"x", &mut out), Err(Error::Unsupported));
}

// ─── decoder constructors ────────────────────────────────────────────────

#[test]
fn decoder_new_has_no_unpack_size() {
    let d = Decoder::new();
    assert_eq!(d.unpack_size(), None);
}

#[test]
fn decoder_with_unpack_size_records_value() {
    let d = Decoder::with_unpack_size(4_321);
    assert_eq!(d.unpack_size(), Some(4_321));
}

#[test]
fn decoder_with_unpack_size_zero_is_valid() {
    // A zero unpack size is a legal "empty file" payload in RAR1 (it
    // signals the entry exists but has no decompressed bytes). The
    // constructor must accept it.
    let d = Decoder::with_unpack_size(0);
    assert_eq!(d.unpack_size(), Some(0));
}

#[test]
fn decoder_with_unpack_size_large() {
    // A 4 GiB unpack size shouldn't overflow our internal counter.
    let d = Decoder::with_unpack_size(u64::from(u32::MAX));
    assert_eq!(d.unpack_size(), Some(u64::from(u32::MAX)));
}

// ─── decoder streaming-trait conformance ─────────────────────────────────

#[test]
fn decode_empty_input_is_noop() {
    let mut d = Decoder::new();
    let mut out = [0u8; 4];
    let p = d.decode(&[], &mut out).unwrap();
    assert_eq!(p.consumed, 0);
    assert_eq!(p.written, 0);
    assert!(!p.done);
}

#[test]
fn decode_empty_input_zero_output_is_noop() {
    // The all-zero case is the lowest-energy stress test of the trait
    // contract: no input, no output buffer, decoder shouldn't error.
    let mut d = Decoder::new();
    let mut out: [u8; 0] = [];
    let p = d.decode(&[], &mut out).unwrap();
    assert_eq!(p.consumed, 0);
    assert_eq!(p.written, 0);
    assert!(!p.done);
}

#[test]
fn decode_nonempty_input_returns_unsupported() {
    // The decoder has no static Huffman tables wired in (see module
    // docs) so any real input must be refused immediately.
    let mut d = Decoder::new();
    let mut out = [0u8; 16];
    assert_eq!(d.decode(b"\xCA\xFE", &mut out), Err(Error::Unsupported));
}

#[test]
fn decode_nonempty_input_with_unpack_size_still_unsupported() {
    // Supplying the declared decompressed length does not change the
    // verdict — the algorithm is structurally not yet implemented.
    let mut d = Decoder::with_unpack_size(128);
    let mut out = [0u8; 16];
    assert_eq!(d.decode(b"\x01", &mut out), Err(Error::Unsupported));
}

#[test]
fn finish_on_fresh_decoder_is_done() {
    let mut d = Decoder::new();
    let mut out = [0u8; 4];
    let p = d.finish(&mut out).unwrap();
    assert!(p.done);
    assert_eq!(p.consumed, 0);
    assert_eq!(p.written, 0);
}

#[test]
fn finish_on_fresh_decoder_with_unpack_size_is_done() {
    // Even if we declared an unpack size, an unstarted decoder is
    // trivially "done" — there is no in-flight data to flush.
    let mut d = Decoder::with_unpack_size(100);
    let mut out = [0u8; 4];
    let p = d.finish(&mut out).unwrap();
    assert!(p.done);
}

#[test]
fn reset_returns_to_initial_state() {
    let mut d = Decoder::with_unpack_size(42);
    // Trying to decode a non-empty input puts the decoder into the
    // "unsupported" state but `reset` should clear it back to fresh.
    let mut out = [0u8; 4];
    let _ = d.decode(&[0xFF], &mut out);
    d.reset();
    // After reset: no declared unpack_size, finish reports done.
    assert_eq!(d.unpack_size(), None);
    let p = d.finish(&mut out).unwrap();
    assert!(p.done);
}

#[test]
fn skip_default_implementation_does_not_panic() {
    // The default `Decoder::skip` implementation drives `decode`. For our
    // stub, that means the first non-empty `decode` call errors out and
    // skip should propagate that error rather than spinning.
    let mut d = Decoder::new();
    let result = d.skip(b"some-bytes", 100);
    assert!(matches!(result, Err(Error::Unsupported)));
}

#[test]
fn skip_with_empty_input_returns_zero_progress() {
    let mut d = Decoder::new();
    let p = d.skip(&[], 100).unwrap();
    // The default impl breaks out of its loop when both consumed and
    // written stay zero. Skipping zero from empty input → zero progress.
    assert_eq!(p.consumed, 0);
    assert_eq!(p.written, 0);
}

// ─── decoder-as-trait-object ─────────────────────────────────────────────

#[cfg(feature = "factory")]
#[test]
fn decoder_via_factory_by_name() {
    use compcol::factory::decoder_by_name;
    let mut d = decoder_by_name("rar1").expect("rar1 is in the factory");
    let mut out = [0u8; 4];
    // Same constraints apply via dyn dispatch.
    assert_eq!(d.decode(b"x", &mut out), Err(Error::Unsupported));
}

#[cfg(feature = "factory")]
#[test]
fn encoder_via_factory_by_name() {
    use compcol::factory::encoder_by_name;
    let mut e = encoder_by_name("rar1").expect("rar1 is in the factory");
    let mut out = [0u8; 4];
    assert_eq!(e.encode(b"x", &mut out), Err(Error::Unsupported));
}
